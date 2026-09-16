"""Source-controlled fail-fast enrichment recovery and independent replay."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from egsi.contracts.enrichment import EnrichmentRecord, committed_enrichment_record
from egsi.data.context import build_oracle_context
from egsi.generation.enrichment import (
    EnrichmentRunner,
    _evaluate_enrichment_attempt,
    _latency_integer,
    _load_store,
    _prompt_vocabulary,
    _receipt_validation,
    allowed_action_values,
    write_failure,
)
from egsi.generation.human_audit import (
    _frozen_v21_first_case_requests,
    _frozen_v22_recovery_requests,
    _scan_teacher_audit,
    load_historical_expectation_with_evidence,
)
from egsi.generation.pilot import (
    _dict_commitment,
    _read_record,
    _read_regular,
    _record_is_current,
    _sha256,
    _teacher_generation_mode,
    _write_provenance_manifest,
    catalog_index,
    read_case_ids,
    write_report,
)
from egsi.teacher.base import (
    Teacher,
    TeacherRequest,
    TeacherResponse,
    teacher_request_hash,
)
from egsi.teacher.prompts import enrichment_request
from egsi.strict_json import strict_json_loads
from egsi.generation.safeio import BatchLock, active_batch_lock
from egsi.generation.test_receipt import (
    _RECEIPT_FIELDS,
    _tree_commitment,
    test_receipt_commitment,
)


_REPORT_RELATIVE = Path("reports/remaining-p0/fail-fast-report.json")
_SUMMARY_RELATIVE = Path("reports/enrichment-summary.json")
_PROVENANCE_RELATIVE = Path("enrichment/_batch-provenance.json")
_REPAIR_VARIANTS: tuple[tuple[str | None, int], ...] = (
    (None, 0),
    ("invalid_structured_output", 1),
    ("invalid_structured_output", 2),
    ("semantic_validation_failed", 1),
    ("semantic_validation_failed", 2),
    ("invalid_canonical_path", 1),
    ("invalid_canonical_path", 2),
    ("invalid_teacher_response_metadata", 1),
    ("invalid_teacher_response_metadata", 2),
)
_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_ATTESTATION_PATTERN = re.compile(r"^[0-9a-f]{512}$")
_DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")
_EXPLICIT_REATTESTATION_TARGET = "ghsa-3wfj-vh84-732p"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_default=True)


class ArtifactEntry(_StrictModel):
    relative_path: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class AttemptEntry(_StrictModel):
    case_id: str
    variant_index: int = Field(ge=0, le=8)
    request_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    manifest_path: str
    manifest_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    audit_commitment_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    status: Literal["committed", "quarantined"]
    failure_code: str | None


class CanonicalReceiptEvidence(_StrictModel):
    name: Literal["focused", "full"]
    receipt_relative_path: str
    receipt_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    receipt_commitment_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    passed_count: int = Field(gt=0)
    code_commitments_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    attestation_relative_path: str
    attestation_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    native_contract_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    public_key_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class FailFastReport(_StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    report_kind: Literal["remaining_p0_fail_fast_enrichment"] = (
        "remaining_p0_fail_fast_enrichment"
    )
    status: Literal[
        "REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW",
        "REMAINING_P0_CASE_RECOVERY_STOPPED",
    ]
    stop_on_first_failure: Literal[True] = True
    generation_mode: Literal["fixture", "live"]
    provider: str
    model: str
    recovery_mode: Literal["forward_recovery", "explicit_reattestation"]
    target_reason: Literal[
        "next_incomplete_contiguous_p0_segment",
        "native_live_attestation_for_prompt_v2_3",
    ]
    case_file_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    scope_case_file_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    requested_case_ids: list[str]
    forbidden_case_ids: list[str]
    started_case_ids: list[str]
    completed_case_ids: list[str]
    failed_case_id: str | None
    not_started_case_ids: list[str]
    request_hashes: dict[str, list[str]]
    current_attempts: list[AttemptEntry] = Field(max_length=3)
    teacher_audit_artifact_set_sha256: str = Field(
        pattern=r"^sha256:[0-9a-f]{64}$"
    )
    teacher_current_bound_committed: int = Field(ge=0, le=3)
    canonical_test_receipts: list[CanonicalReceiptEvidence]
    artifact_inventory: list[ArtifactEntry]
    provenance_manifest_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    enrichment_summary_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    report_commitment_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def recovered_attempt_count_is_bounded(self) -> "FailFastReport":
        if (
            self.status == "REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW"
            and not 1 <= len(self.current_attempts) <= 3
        ):
            raise ValueError("a recovered report requires one to three current attempts")
        return self


def _report_commitment(value: dict[str, Any]) -> str:
    return _dict_commitment(value, "report_commitment_sha256")


def _safe_evidence_file(path: Path, *, limit: int) -> bytes:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ValueError("canonical receipt evidence file is unsafe")
    return _read_regular(path, limit=limit)


def _large_dict_commitment(value: dict[str, Any], field: str) -> str:
    """Commit bounded-on-read JSON objects that exceed the runtime DSL limit."""

    if type(value) is not dict or type(field) is not str or not field:
        raise ValueError("large commitment input is invalid")
    canonical = dict(value)
    canonical.pop(field, None)
    try:
        raw = json.dumps(
            canonical,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("large commitment input is not canonical JSON") from None
    return _sha256(raw)


def _compact_python_runtime_summary(value: object) -> dict[str, Any]:
    """Recompute the bounded public projection from the full build manifest."""

    if (
        type(value) is not dict
        or set(value) != {
            "schema_version", "invocation", "interpreter", "files",
            "preload_file_indices", "native_extension_roots", "startup_code", "limits",
            "closure_sha256",
        }
        or value.get("schema_version") != "3.0"
        or value.get("closure_sha256")
        != _large_dict_commitment(value, "closure_sha256")
        or type(value.get("files")) is not list
        or not 2 <= len(value["files"]) <= 256
    ):
        raise ValueError("full Python runtime contract is invalid")
    startup = value.get("startup_code")
    if (
        type(startup) is not dict
        or set(startup) != {
            "schema_version", "strategy", "pycache_prefix", "stdlib_root",
            "lib_dynload_root", "import_roots", "files", "directories",
            "absent_paths",
            "file_count", "directory_count", "absent_path_count",
            "total_bytes", "limits", "closure_sha256",
        }
        or startup.get("schema_version") != "2.0"
        or startup.get("closure_sha256")
        != _large_dict_commitment(startup, "closure_sha256")
        or type(startup.get("files")) is not list
        or type(startup.get("directories")) is not list
        or type(startup.get("absent_paths")) is not list
        or startup.get("file_count") != len(startup["files"])
        or startup.get("directory_count") != len(startup["directories"])
        or startup.get("absent_path_count") != len(startup["absent_paths"])
        or startup.get("total_bytes")
        != sum(
            item.get("identity", {}).get("size", -1)
            for item in startup["files"]
            if type(item) is dict
        )
    ):
        raise ValueError("full Python startup manifest is invalid")

    def root_summary(relative_path: str, path_field: str) -> dict[str, Any]:
        matches = [
            item for item in startup["directories"]
            if type(item) is dict
            and item.get("relative_path") == relative_path
            and item.get("path") == startup.get(path_field)
            and type(item.get("identity")) is dict
            and item["identity"].get("path") == item.get("path")
            and item["identity"].get("type") == "directory"
        ]
        if len(matches) != 1:
            raise ValueError("Python startup root identity is missing")
        return {
            "path": matches[0]["path"],
            "identity": matches[0]["identity"],
        }

    startup_summary: dict[str, Any] = {
        "schema_version": "2.0",
        "strategy": startup["strategy"],
        "pycache_prefix": startup["pycache_prefix"],
        "stdlib_root": root_summary("stdlib:.", "stdlib_root"),
        "lib_dynload_root": root_summary(
            "lib-dynload:.", "lib_dynload_root"
        ),
        "import_roots": startup["import_roots"],
        "file_count": startup["file_count"],
        "directory_count": startup["directory_count"],
        "absent_path_count": startup["absent_path_count"],
        "total_bytes": startup["total_bytes"],
        "limits": startup["limits"],
        "manifest_sha256": startup["closure_sha256"],
        "summary_sha256": "sha256:" + "0" * 64,
    }
    startup_summary["summary_sha256"] = _large_dict_commitment(
        startup_summary, "summary_sha256"
    )
    summary: dict[str, Any] = {
        "schema_version": "2.0",
        "invocation": value["invocation"],
        "interpreter": value["interpreter"],
        "files": value["files"],
        "preload_file_indices": value["preload_file_indices"],
        "native_extension_roots": value["native_extension_roots"],
        "startup_code": startup_summary,
        "limits": value["limits"],
        "manifest_sha256": value["closure_sha256"],
        "summary_sha256": "sha256:" + "0" * 64,
    }
    summary["summary_sha256"] = _large_dict_commitment(
        summary, "summary_sha256"
    )
    return summary


def _verify_pkcs1_v15_sha256(
    preimage: bytes, signature: bytes, modulus_hex: str, exponent: int
) -> None:
    if (
        len(signature) != 256
        or not re.fullmatch(r"[0-9a-f]{512}", modulus_hex)
        or exponent != 65537
    ):
        raise ValueError("native RSA parameters are invalid")
    modulus = int(modulus_hex, 16)
    encoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(
        256, "big"
    )
    digest_info = _DIGEST_INFO_SHA256 + hashlib.sha256(preimage).digest()
    expected = b"\x00\x01" + b"\xff" * (256 - len(digest_info) - 3) + b"\x00" + digest_info
    if encoded != expected:
        raise ValueError("native RSA attestation is invalid")


def _verify_receipt_attestation(
    raw: bytes,
    *,
    name: str,
    artifact_name: str,
    artifact_raw: bytes,
    native_contract_sha256: str,
    public_key_id: str,
    modulus_hex: str,
    exponent: int,
) -> None:
    lines = raw.splitlines(keepends=True)
    if len(lines) != 8 or any(not line.endswith(b"\n") for line in lines):
        raise ValueError("native receipt attestation is malformed")
    preimage = b"".join(lines[:-1])
    expected = [
        b"EGSI-NATIVE-ATTESTATION-V2\n",
        b"algorithm=rsa-2048-sha256-pkcs1-v1_5\n",
        f"domain=egsi.test-receipt.{name}.v1\n".encode(),
        f"artifact={artifact_name}\n".encode(),
        f"artifact_sha256={hashlib.sha256(artifact_raw).hexdigest()}\n".encode(),
        f"native_contract={native_contract_sha256.removeprefix('sha256:')}\n".encode(),
        f"key_id={public_key_id.removeprefix('sha256:')}\n".encode(),
    ]
    signature_line = lines[-1]
    if lines[:-1] != expected or not signature_line.startswith(b"signature="):
        raise ValueError("native receipt attestation binding is invalid")
    signature_hex = signature_line[len(b"signature=") : -1].decode("ascii")
    if _ATTESTATION_PATTERN.fullmatch(signature_hex) is None:
        raise ValueError("native receipt signature encoding is invalid")
    _verify_pkcs1_v15_sha256(
        preimage, bytes.fromhex(signature_hex), modulus_hex, exponent
    )


def _test_receipt_evidence(
    root: Path, output_root: Path
) -> list[CanonicalReceiptEvidence]:
    """Verify current canonical receipts and their native RSA attestations."""

    lock_path = root / "configs/offline-test-runner.lock.json"
    lock_raw = _read_regular(lock_path, limit=16 * 1024 * 1024)
    lock = strict_json_loads(lock_raw, max_bytes=16 * 1024 * 1024)
    build_path = root / "configs/native-signer-build-record.json"
    build_raw = _read_regular(build_path, limit=2 * 1024 * 1024)
    build = strict_json_loads(build_raw, max_bytes=2 * 1024 * 1024)
    if (
        type(lock) is not dict
        or lock.get("schema_version") != "8.0"
        or lock.get("lock_commitment_sha256")
        != _large_dict_commitment(lock, "lock_commitment_sha256")
        or type(build) is not dict
        or build.get("schema_version") != "3.0"
        or build.get("record_commitment_sha256")
        != _large_dict_commitment(build, "record_commitment_sha256")
    ):
        raise ValueError("native receipt trust roots are invalid")
    native = lock.get("native_launcher_contract")
    public_key = build.get("public_key")
    if (
        type(native) is not dict
        or native.get("contract_sha256")
        != _large_dict_commitment(native, "contract_sha256")
        or type(public_key) is not dict
        or public_key.get("exponent") != 65537
        or not re.fullmatch(r"[0-9a-f]{512}", str(public_key.get("modulus_hex")))
        or not _SHA256_PATTERN.fullmatch(str(public_key.get("key_id")))
        or native.get("binary_contract_sha256")
        != build.get("native_contract_sha256")
        or native.get("public_key_id") != public_key.get("key_id")
        or native.get("build_record_commitment_sha256")
        != build.get("record_commitment_sha256")
        or native.get("build_record_identity", {}).get("sha256")
        != _sha256(build_raw)
        or native.get("python_runtime_summary")
        != _compact_python_runtime_summary(build.get("python_runtime"))
    ):
        raise ValueError("native receipt trust roots disagree")
    current_code = {
        "source_tree_sha256": _tree_commitment(
            root, ("src/**/*.py", "scripts/*.py")
        ),
        "tests_tree_sha256": _tree_commitment(root, ("tests/**/*.py",)),
        "pyproject_toml_sha256": _sha256(
            _read_regular(root / "pyproject.toml", limit=1024 * 1024)
        ),
        "offline_test_runner_lock_sha256": _sha256(lock_raw),
        "historical_expectation_sha256": _sha256(
            _read_regular(
                root / "configs/historical-teacher-audit-expectation.v1.json",
                limit=1024 * 1024,
            )
        ),
        "first_case_historical_expectation_sha256": _sha256(
            _read_regular(
                root
                / "configs/first-case-historical-teacher-audit-expectation.v1.json",
                limit=1024 * 1024,
            )
        ),
        "canonical_test_contract_sha256": _sha256(
            _read_regular(
                root / "configs/canonical-test-contract.v1.json",
                limit=2 * 1024 * 1024,
            )
        ),
    }
    result: list[CanonicalReceiptEvidence] = []
    shared_code_commitments: dict[str, Any] | None = None
    for name in ("focused", "full"):
        artifact_name = f"offline-{name}-receipt.json"
        receipt_path = output_root / "reports" / artifact_name
        receipt_raw = _safe_evidence_file(receipt_path, limit=8 * 1024 * 1024)
        receipt = strict_json_loads(receipt_raw, max_bytes=8 * 1024 * 1024)
        if (
            type(receipt) is not dict
            or set(receipt) != _RECEIPT_FIELDS
            or receipt.get("schema_version") != "7.0"
            or receipt.get("receipt_kind") != "canonical_offline_pytest_run"
            or receipt.get("native_attested") is not False
            or receipt.get("name") != name
            or receipt.get("exit_code") != 0
            or receipt.get("failed_count") != 0
            or type(receipt.get("passed_count")) is not int
            or receipt["passed_count"] <= 0
            or receipt.get("receipt_commitment_sha256")
            != test_receipt_commitment(receipt)
            or type(receipt.get("code_commitments")) is not dict
            or any(
                receipt["code_commitments"].get(key) != value
                for key, value in current_code.items()
            )
        ):
            raise ValueError("canonical test receipt is invalid")
        if shared_code_commitments is None:
            shared_code_commitments = receipt["code_commitments"]
        elif receipt["code_commitments"] != shared_code_commitments:
            raise ValueError("canonical test receipts disagree")
        attestation_path = Path(str(receipt_path) + ".native-attestation")
        attestation_raw = _safe_evidence_file(
            attestation_path, limit=16 * 1024
        )
        _verify_receipt_attestation(
            attestation_raw,
            name=name,
            artifact_name=artifact_name,
            artifact_raw=receipt_raw,
            native_contract_sha256=build["native_contract_sha256"],
            public_key_id=public_key["key_id"],
            modulus_hex=public_key["modulus_hex"],
            exponent=public_key["exponent"],
        )
        result.append(
            CanonicalReceiptEvidence(
                name=name,
                receipt_relative_path=receipt_path.relative_to(output_root).as_posix(),
                receipt_sha256=_sha256(receipt_raw),
                receipt_commitment_sha256=receipt[
                    "receipt_commitment_sha256"
                ],
                passed_count=receipt["passed_count"],
                code_commitments_sha256=_sha256(
                    json.dumps(
                        receipt["code_commitments"],
                        allow_nan=False,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ),
                attestation_relative_path=attestation_path.relative_to(
                    output_root
                ).as_posix(),
                attestation_sha256=_sha256(attestation_raw),
                native_contract_sha256=build["native_contract_sha256"],
                public_key_id=public_key["key_id"],
            )
        )
    return result


def _request_variants_for_case(
    root: Path, case: Any
) -> list[tuple[str, TeacherRequest]]:
    context = build_oracle_context(root, case)
    vocabulary = _prompt_vocabulary(allowed_action_values(root))
    result: list[tuple[str, TeacherRequest]] = []
    for repair_error, repair_attempt in _REPAIR_VARIANTS:
        system, user, schema = enrichment_request(
            context,
            vocabulary,
            repair_error=repair_error,
            repair_attempt=repair_attempt,
        )
        request = TeacherRequest(
            system=system,
            user=user,
            schema=schema,
            temperature=0.0,
            max_tokens=8192,
        )
        result.append((teacher_request_hash(request), request))
    if len(result) != 9 or len({item[0] for item in result}) != 9:
        raise ValueError("current request variants are not unique")
    return result


def _request_hashes_for_case(root: Path, case: Any) -> list[str]:
    return [request_hash for request_hash, _ in _request_variants_for_case(root, case)]


def _request_state(
    root: Path, catalog: dict[str, Any], case_ids: list[str]
) -> tuple[dict[str, list[str]], dict[str, TeacherRequest]]:
    request_hashes: dict[str, list[str]] = {}
    expected_requests: dict[str, TeacherRequest] = {}
    for case_id in case_ids:
        variants = _request_variants_for_case(root, catalog[case_id])
        hashes = [request_hash for request_hash, _ in variants]
        if len(hashes) != 9 or len(set(hashes)) != 9:
            raise ValueError("current request variants are not unique")
        if set(hashes).intersection(expected_requests):
            raise ValueError("current request variants collide across cases")
        request_hashes[case_id] = hashes
        expected_requests.update(variants)
    return request_hashes, expected_requests


def _request_state_with_history(
    root: Path,
    catalog: dict[str, Any],
    case_ids: list[str],
    *,
    historical_expectation: dict[str, Any],
) -> tuple[
    dict[str, list[str]],
    dict[str, TeacherRequest],
    set[str],
    set[str],
    dict[str, Any],
]:
    """Add the three frozen v2.1 positives without making them current."""

    request_hashes, expected_requests = _request_state(root, catalog, case_ids)
    pre_batch = _frozen_v21_first_case_requests(root, catalog)
    pre_recovery = _frozen_v22_recovery_requests(root, catalog)
    if (
        set(pre_batch).intersection(expected_requests)
        or set(pre_recovery).intersection(expected_requests)
        or set(pre_batch).intersection(pre_recovery)
    ):
        raise ValueError("historical requests collide with current variants")
    expected_requests.update(pre_batch)
    expected_requests.update(pre_recovery)
    return (
        request_hashes,
        expected_requests,
        set(pre_batch),
        set(pre_recovery),
        historical_expectation,
    )


def _forbidden_case_ids(scope: list[str], requested: list[str]) -> list[str]:
    return _validate_scope_segment(
        scope=scope,
        requested=requested,
        completed=set(scope[: scope.index(requested[0])]),
        explicit_reattestation_target=None,
    )[0]


def _validate_scope_segment(
    *,
    scope: list[str],
    requested: list[str],
    completed: set[str],
    explicit_reattestation_target: str | None,
) -> tuple[list[str], str, str]:
    """Enforce one contiguous next-P0 segment or one exact re-attestation."""

    if (
        type(scope) is not list
        or type(requested) is not list
        or type(completed) is not set
        or not scope
        or not requested
        or len(scope) != len(set(scope))
        or len(requested) != len(set(requested))
        or any(type(item) is not str or not item for item in [*scope, *requested])
        or any(item not in scope for item in requested)
        or any(type(item) is not str or item not in scope for item in completed)
    ):
        raise ValueError("recovery scope is malformed")
    start = scope.index(requested[0])
    end = start + len(requested)
    if requested != scope[start:end]:
        raise ValueError("recovery scope segment is not contiguous")
    if not set(scope[:start]) <= completed:
        raise ValueError("recovery scope has an incomplete prefix gap")
    if explicit_reattestation_target is None:
        if requested[0] in completed:
            raise ValueError("recovery scope does not start at the next incomplete case")
        mode = "forward_recovery"
        reason = "next_incomplete_contiguous_p0_segment"
    else:
        if (
            type(explicit_reattestation_target) is not str
            or requested != [explicit_reattestation_target]
            or explicit_reattestation_target not in completed
        ):
            raise ValueError("recovery scope re-attestation target is invalid")
        mode = "explicit_reattestation"
        reason = "native_live_attestation_for_prompt_v2_3"
    return scope[end:], mode, reason


def _resolve_scope_contract(
    *,
    scope: list[str],
    requested: list[str],
    completion_kinds: dict[str, str],
) -> tuple[list[str], str, str]:
    """Resolve frozen/current positives into the only permitted recovery mode."""

    allowed_kinds = {
        "frozen_v21",
        "frozen_v22",
        "current_v23",
        "current_v23_reattested",
    }
    if (
        type(completion_kinds) is not dict
        or any(
            type(case_id) is not str
            or case_id not in scope
            or kind not in allowed_kinds
            for case_id, kind in completion_kinds.items()
        )
    ):
        raise ValueError("recovery scope completion state is malformed")
    has_explicit_evidence = completion_kinds.get(
        _EXPLICIT_REATTESTATION_TARGET
    ) in {"frozen_v22", "current_v23_reattested"}
    if (
        requested
        and requested[0] == _EXPLICIT_REATTESTATION_TARGET
        and has_explicit_evidence
        and requested != [_EXPLICIT_REATTESTATION_TARGET]
    ):
        raise ValueError("recovery scope re-attestation must be one exact case")
    explicit = (
        requested == [_EXPLICIT_REATTESTATION_TARGET]
        and has_explicit_evidence
    )
    if explicit:
        completed = {
            case_id
            for case_id, kind in completion_kinds.items()
            if kind
            in {
                "frozen_v21",
                "frozen_v22",
                "current_v23",
                "current_v23_reattested",
            }
        }
        target = _EXPLICIT_REATTESTATION_TARGET
    else:
        completed = {
            case_id
            for case_id, kind in completion_kinds.items()
            if kind
            in {"frozen_v21", "current_v23", "current_v23_reattested"}
        }
        target = None
    return _validate_scope_segment(
        scope=scope,
        requested=requested,
        completed=completed,
        explicit_reattestation_target=target,
    )


def _scope_completion_kinds(
    *,
    root: Path,
    output_root: Path,
    scope: list[str],
    catalog: dict[str, Any],
    provider: str,
    model: str,
    audit: dict[str, Any],
    active_current_case_ids: set[str] | None = None,
) -> dict[str, str]:
    """Classify only audit-bound positives usable by the recovery scope gate."""

    active_current_case_ids = (
        set()
        if active_current_case_ids is None
        else set(active_current_case_ids)
    )
    if not active_current_case_ids <= set(scope):
        raise ValueError("active completion case set is malformed")

    pre_batch_requests = (
        _frozen_v21_first_case_requests(root, catalog)
        if "ghsa-2m8h-fgr8-2q9w" in catalog
        else {}
    )
    pre_recovery_requests = (
        _frozen_v22_recovery_requests(root, catalog)
        if _EXPLICIT_REATTESTATION_TARGET in catalog
        else {}
    )
    pre_batch_prompts = {
        _sha256((request.system + request.user).encode("utf-8"))
        for request in pre_batch_requests.values()
    }
    pre_recovery_prompts = {
        _sha256((request.system + request.user).encode("utf-8"))
        for request in pre_recovery_requests.values()
    }
    current_by_response = audit.get("by_response")
    pre_batch_by_response = audit.get("pre_batch_by_response")
    pre_recovery_by_response = audit.get("pre_recovery_by_response")
    if any(
        type(value) is not dict
        for value in (
            current_by_response,
            pre_batch_by_response,
            pre_recovery_by_response,
        )
    ):
        raise ValueError("recovery scope audit state is malformed")
    result: dict[str, str] = {}
    for case_id in scope:
        path = output_root / "enrichment" / f"{case_id}.json"
        try:
            record = _read_record(path)
        except FileNotFoundError:
            continue
        case = catalog.get(case_id)
        if (
            case is None
            or record.case_id != case_id
            or record.provider != provider
            or record.model != model
            or record.requested_model != model
            or record.structured_output_valid is not True
            or record.validation.valid is not True
        ):
            raise ValueError("recovery scope positive is invalid")
        response_commitment = record.teacher_response_commitment_sha256
        if (
            response_commitment in current_by_response
            and _record_is_current(
                root, case, record, provider=provider, model=model
            )
        ):
            result[case_id] = (
                "current_v23_reattested"
                if case_id == _EXPLICIT_REATTESTATION_TARGET
                and bool(pre_recovery_by_response)
                else "current_v23"
            )
        elif (
            case_id == "ghsa-2m8h-fgr8-2q9w"
            and response_commitment in pre_batch_by_response
            and record.prompt_sha256 in pre_batch_prompts
        ):
            result[case_id] = "frozen_v21"
        elif (
            case_id == _EXPLICIT_REATTESTATION_TARGET
            and response_commitment in pre_recovery_by_response
            and record.prompt_sha256 in pre_recovery_prompts
        ):
            result[case_id] = "frozen_v22"
        else:
            raise ValueError("recovery scope positive is not audit-bound")

    # An explicit re-attestation archives the frozen v2.2 positive before it
    # invokes the provider.  A terminal provider failure therefore has no
    # active positive path from which replay can recover the preflight scope.
    # Accept only the content-addressed archived record for the case that is
    # known to have started in this invocation, and bind it back to the exact
    # frozen audit/cache response and prompt family.
    target = _EXPLICIT_REATTESTATION_TARGET
    if target in active_current_case_ids and target not in result:
        quarantine = output_root / "enrichment/quarantine"
        try:
            quarantine_info = quarantine.lstat()
        except FileNotFoundError:
            quarantine_info = None
        if quarantine_info is not None:
            if (
                not stat.S_ISDIR(quarantine_info.st_mode)
                or stat.S_ISLNK(quarantine_info.st_mode)
            ):
                raise ValueError("recovery scope quarantine is unsafe")
            candidates: list[EnrichmentRecord] = []
            prefix = f"{target}."
            with os.scandir(quarantine) as stream:
                entries = sorted(stream, key=lambda item: item.name)
            for entry in entries:
                if not entry.name.startswith(prefix) or not entry.name.endswith(
                    ".json"
                ):
                    continue
                digest = entry.name[len(prefix) : -len(".json")]
                if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                    continue
                path = quarantine / entry.name
                raw = _read_regular(path, limit=2 * 1024 * 1024)
                if _sha256(raw) != f"sha256:{digest}":
                    raise ValueError("recovery scope quarantine hash is invalid")
                record = _read_record(path)
                case = catalog.get(target)
                if (
                    case is not None
                    and record.case_id == target
                    and record.provider == provider
                    and record.model == model
                    and record.requested_model == model
                    and record.structured_output_valid is True
                    and record.validation.valid is True
                    and record.teacher_response_commitment_sha256
                    in pre_recovery_by_response
                    and record.prompt_sha256 in pre_recovery_prompts
                ):
                    candidates.append(record)
            if len(candidates) > 1:
                raise ValueError("recovery scope archived positive is ambiguous")
            if len(candidates) == 1:
                result[target] = "frozen_v22"
    return result


def _recovery_scope_state(
    *,
    root: Path,
    output_root: Path,
    scope: list[str],
    requested: list[str],
    catalog: dict[str, Any],
    provider: str,
    model: str,
    historical_expectation: dict[str, Any],
    active_current_case_ids: set[str] | None = None,
) -> tuple[
    list[str],
    str,
    str,
    dict[str, list[str]],
    dict[str, TeacherRequest],
    set[str],
    set[str],
    dict[str, Any],
    list[AttemptEntry],
    dict[str, Any],
]:
    """Recompute audit-bound completion and the resulting scope contract."""

    active_current_case_ids = (
        set()
        if active_current_case_ids is None
        else set(active_current_case_ids)
    )
    if not active_current_case_ids <= set(requested):
        raise ValueError("active recovery case set is malformed")
    (
        all_request_hashes,
        expected_requests,
        pre_batch_request_hashes,
        pre_recovery_request_hashes,
        historical_expectation,
    ) = _request_state_with_history(
        root,
        catalog,
        scope,
        historical_expectation=historical_expectation,
    )
    all_attempts, audit = _audit_state(
        output_root,
        provider=provider,
        model=model,
        request_hashes=all_request_hashes,
        expected_requests=expected_requests,
        pre_batch_request_hashes=pre_batch_request_hashes,
        pre_recovery_request_hashes=pre_recovery_request_hashes,
        historical_expectation=historical_expectation,
        active_current_case_ids=active_current_case_ids,
    )
    completion_kinds = _scope_completion_kinds(
        root=root,
        output_root=output_root,
        scope=scope,
        catalog=catalog,
        provider=provider,
        model=model,
        audit=audit,
        active_current_case_ids=active_current_case_ids,
    )
    for case_id in active_current_case_ids:
        kind = completion_kinds.get(case_id)
        if kind not in {"current_v23", "current_v23_reattested"}:
            continue
        if (
            case_id == _EXPLICIT_REATTESTATION_TARGET
            and audit.get("pre_recovery_bound_committed", 0) > 0
        ):
            completion_kinds[case_id] = "frozen_v22"
        else:
            completion_kinds.pop(case_id)
    forbidden, recovery_mode, target_reason = _resolve_scope_contract(
        scope=scope,
        requested=requested,
        completion_kinds=completion_kinds,
    )
    return (
        forbidden,
        recovery_mode,
        target_reason,
        all_request_hashes,
        expected_requests,
        pre_batch_request_hashes,
        pre_recovery_request_hashes,
        historical_expectation,
        all_attempts,
        audit,
    )


def _archive_existing(output_root: Path, path: Path, label: str) -> None:
    try:
        raw = _read_regular(path, limit=16 * 1024 * 1024)
    except FileNotFoundError:
        return
    digest = _sha256(raw).removeprefix("sha256:")
    history = output_root / "reports/remaining-p0/history"
    history.mkdir(parents=True, exist_ok=True)
    destination = history / f"{label}.{digest}.json"
    if destination.exists():
        if _read_regular(destination, limit=16 * 1024 * 1024) != raw:
            raise ValueError("historical archive collision")
        suffix = 1
        while True:
            candidate = history / f"{label}.{digest}.{suffix}.json"
            try:
                candidate.lstat()
            except FileNotFoundError:
                destination = candidate
                break
            suffix += 1
            if suffix > 10_000:
                raise ValueError("historical archive suffix bound exceeded")
    os.replace(path, destination)


def _current_attempt_count(
    root: Path, output_root: Path, case: Any
) -> int:
    """Count only current-prompt transactions for a safe fallback receipt."""

    count = 0
    for request_hash in _request_hashes_for_case(root, case):
        request_root = output_root / "audit/teacher" / request_hash
        if request_root.exists():
            count += len(list(request_root.glob("*/attempt-00/manifest.json")))
    return count


def _ensure_failure_receipt(
    *, root: Path, output_root: Path, output_dir: Path, case: Any
) -> None:
    if _failure_receipt(output_root, case.case_id) is not None:
        return
    attempts = _current_attempt_count(root, output_root, case)
    write_failure(
        output_dir,
        case.case_id,
        attempts,
        "enrichment runner failed before publishing a failure receipt",
        None,
        error_kind="orchestrator",
        failed_attempt=None,
        validation_attempt=None,
    )


def _inventory(output_root: Path) -> list[ArtifactEntry]:
    candidates: list[Path] = []
    for relative in (
        Path("audit/teacher"),
        Path("cache/teacher"),
        Path("enrichment"),
        Path("episodes"),
        Path("trajectories"),
        Path("reports/remaining-p0/history"),
    ):
        root = output_root / relative
        if root.exists():
            candidates.extend(path for path in root.rglob("*") if path.is_file())
    summary = output_root / _SUMMARY_RELATIVE
    if summary.exists():
        candidates.append(summary)
    result: list[ArtifactEntry] = []
    seen: set[str] = set()
    for path in sorted(candidates):
        relative = path.relative_to(output_root).as_posix()
        if relative in seen or Path(relative) == _REPORT_RELATIVE:
            continue
        seen.add(relative)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
            raise ValueError("artifact inventory contains an unsafe file")
        raw = _read_regular(path, limit=16 * 1024 * 1024)
        result.append(
            ArtifactEntry(relative_path=relative, size=len(raw), sha256=_sha256(raw))
        )
    return result


def _attempts(
    output_root: Path, request_hashes: dict[str, list[str]]
) -> list[AttemptEntry]:
    result: list[AttemptEntry] = []
    for case_id, hashes in request_hashes.items():
        case_attempts: list[tuple[int, AttemptEntry]] = []
        for variant_index, request_hash in enumerate(hashes):
            request_root = output_root / "audit/teacher" / request_hash
            if not request_root.exists():
                continue
            for path in sorted(request_root.glob("*/attempt-00/manifest.json")):
                raw = _read_regular(path, limit=2 * 1024 * 1024)
                value = strict_json_loads(raw, max_bytes=2 * 1024 * 1024)
                if (
                    type(value) is not dict
                    or value.get("request_hash") != request_hash
                    or value.get("audit_commitment_sha256")
                    != _dict_commitment(value, "audit_commitment_sha256")
                    or value.get("status") not in {"committed", "quarantined"}
                    or (
                        value.get("failure_code") is not None
                        and type(value.get("failure_code")) is not str
                    )
                ):
                    raise ValueError("current audit manifest is invalid")
                invocation = path.parent.parent
                invocation_info = invocation.lstat()
                if (
                    not stat.S_ISDIR(invocation_info.st_mode)
                    or stat.S_ISLNK(invocation_info.st_mode)
                    or invocation_info.st_mtime_ns < 0
                ):
                    raise ValueError("current audit invocation is invalid")
                case_attempts.append(
                    (
                        invocation_info.st_mtime_ns,
                        AttemptEntry(
                        case_id=case_id,
                        variant_index=variant_index,
                        request_hash=request_hash,
                        manifest_path=path.relative_to(output_root).as_posix(),
                        manifest_sha256=_sha256(raw),
                        audit_commitment_sha256=value["audit_commitment_sha256"],
                        status=value["status"],
                        failure_code=value.get("failure_code"),
                        ),
                    )
                )
        started = [item[0] for item in case_attempts]
        if len(started) != len(set(started)):
            raise ValueError("current audit invocation times are not strict")
        result.extend(item[1] for item in sorted(case_attempts, key=lambda item: item[0]))
    return result


def _current_committed_response_commitments(
    output_root: Path, attempts: list[AttemptEntry]
) -> set[str]:
    commitments: set[str] = set()
    for attempt in attempts:
        if attempt.status != "committed":
            continue
        value = strict_json_loads(
            _read_regular(
                output_root / attempt.manifest_path, limit=2 * 1024 * 1024
            ),
            max_bytes=2 * 1024 * 1024,
        )
        commitment = (
            value.get("response_commitment_sha256")
            if type(value) is dict
            else None
        )
        if (
            type(commitment) is not str
            or not commitment.startswith("sha256:")
            or len(commitment) != 71
            or commitment in commitments
        ):
            raise ValueError("current committed audit response is invalid")
        commitments.add(commitment)
    return commitments


def _audit_state_observation(
    output_root: Path,
    *,
    provider: str,
    model: str,
    request_hashes: dict[str, list[str]],
    expected_requests: dict[str, TeacherRequest],
    pre_batch_request_hashes: set[str] | None = None,
    pre_recovery_request_hashes: set[str] | None = None,
    active_current_case_ids: set[str] | None = None,
) -> tuple[list[AttemptEntry], dict[str, Any]]:
    pre_batch_request_hashes = (
        set() if pre_batch_request_hashes is None else pre_batch_request_hashes
    )
    active_current_case_ids = (
        set()
        if active_current_case_ids is None
        else set(active_current_case_ids)
    )
    if not active_current_case_ids <= set(request_hashes):
        raise ValueError("active current audit case set is invalid")
    attempts = _attempts(output_root, request_hashes)
    scan = _scan_teacher_audit(
        output_root,
        provider,
        model,
        expected_requests=expected_requests,
        pre_batch_request_hashes=pre_batch_request_hashes,
        pre_recovery_request_hashes=pre_recovery_request_hashes,
    )
    if (
        scan["malformed_invalid"] != 0
        or scan["identity_mismatches"] != 0
        or scan["tool_events"] != 0
        or set(scan["by_response"])
        != _current_committed_response_commitments(output_root, attempts)
        or scan["committed"]
        != len([attempt for attempt in attempts if attempt.status == "committed"])
    ):
        raise ValueError("teacher audit/cache state is invalid")
    current_quarantined_attempts = sorted(
        (
            attempt.manifest_path,
            attempt.audit_commitment_sha256,
        )
        for attempt in attempts
        if attempt.case_id in active_current_case_ids
        and attempt.status == "quarantined"
        and attempt.failure_code == "provider_failure_event"
    )
    current_quarantined_paths = [
        path for path, _ in current_quarantined_attempts
    ]
    provider_failure_records = scan.get("provider_failure_commitments")
    if type(provider_failure_records) is not list or any(
        type(item) is not dict
        or set(item) not in {
            frozenset({"failure_code", "audit_commitment_sha256"}),
            frozenset(
                {
                    "failure_code",
                    "audit_commitment_sha256",
                    "manifest_path",
                }
            ),
        }
        or item.get("failure_code") != "provider_failure_event"
        or _SHA256_PATTERN.fullmatch(
            str(item.get("audit_commitment_sha256"))
        )
        is None
        or (
            "manifest_path" in item
            and (
                type(item["manifest_path"]) is not str
                or not item["manifest_path"]
            )
        )
        for item in provider_failure_records
    ):
        raise ValueError("teacher provider failure set is invalid")
    records_by_path = {
        item["manifest_path"]: item
        for item in provider_failure_records
        if "manifest_path" in item
    }
    if (
        len(records_by_path)
        != len(
            [item for item in provider_failure_records if "manifest_path" in item]
        )
        or any(
            path not in records_by_path
            or records_by_path[path]["audit_commitment_sha256"] != commitment
            for path, commitment in current_quarantined_attempts
        )
    ):
        raise ValueError("current provider failure delta is invalid")
    current_paths = set(current_quarantined_paths)
    historical_provider_failures = [
        {
            "failure_code": item["failure_code"],
            "audit_commitment_sha256": item[
                "audit_commitment_sha256"
            ],
        }
        for item in provider_failure_records
        if item.get("manifest_path") not in current_paths
    ]
    historical_provider_failures.sort(
        key=lambda item: (
            item["failure_code"], item["audit_commitment_sha256"]
        )
    )
    historical_failure_codes = Counter(scan["failure_codes"])
    historical_failure_codes["provider_failure_event"] -= len(
        current_quarantined_paths
    )
    if historical_failure_codes["provider_failure_event"] < 0:
        raise ValueError("current provider failure count is invalid")
    historical_failure_codes += Counter()
    scan = dict(scan)
    scan["prior_provider_failure_count"] = len(
        historical_provider_failures
    )
    scan["failure_codes"] = dict(sorted(historical_failure_codes.items()))
    scan["provider_failure_audit_commitment_set_sha256"] = _sha256(
        json.dumps(
            historical_provider_failures,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    scan["current_quarantined_provider_failure_count"] = len(
        current_quarantined_paths
    )
    scan["current_quarantined_manifest_paths"] = current_quarantined_paths
    return attempts, scan


def _verify_historical_audit_expectation(
    *,
    provider: str,
    model: str,
    scan: dict[str, Any],
    pre_batch_request_hashes: set[str],
    pre_recovery_request_hashes: set[str],
    historical_expectation: dict[str, Any],
) -> None:
    """Bind one audit observation to every frozen historical trust root."""

    if (
        historical_expectation.get("provider") != provider
        or historical_expectation.get("model") != model
        or scan["pre_batch_bound_committed"] != 3
        or {
            item["request_hash"]
            for item in scan["pre_batch_by_response"].values()
        }
        != pre_batch_request_hashes
        or scan["pre_recovery_bound_committed"] != 1
        or not {
            item["request_hash"]
            for item in scan["pre_recovery_by_response"].values()
        }
        <= pre_recovery_request_hashes
        or scan["historical_unbound_committed"]
        != historical_expectation["historical_unbound_committed_count"]
        or scan["historical_unbound_set_sha256"]
        != historical_expectation[
            "historical_unbound_committed_set_sha256"
        ]
        or scan["historical_response_commitment_set_sha256"]
        != historical_expectation[
            "historical_response_commitment_set_sha256"
        ]
        or scan["prior_provider_failure_count"]
        != historical_expectation[
            "provider_failure_event_quarantine_count"
        ]
        or scan["failure_codes"]
        != historical_expectation["provider_failure_codes"]
        or scan["provider_failure_audit_commitment_set_sha256"]
        != historical_expectation[
            "provider_failure_audit_commitment_set_sha256"
        ]
    ):
        raise ValueError("historical teacher audit expectation mismatch")


def _audit_state(
    output_root: Path,
    *,
    provider: str,
    model: str,
    request_hashes: dict[str, list[str]],
    expected_requests: dict[str, TeacherRequest],
    historical_expectation: dict[str, Any],
    pre_batch_request_hashes: set[str] | None = None,
    pre_recovery_request_hashes: set[str] | None = None,
    active_current_case_ids: set[str] | None = None,
) -> tuple[list[AttemptEntry], dict[str, Any]]:
    """Return current audit state only after every historical check passes."""

    attempts, scan = _audit_state_observation(
        output_root,
        provider=provider,
        model=model,
        request_hashes=request_hashes,
        expected_requests=expected_requests,
        pre_batch_request_hashes=pre_batch_request_hashes,
        pre_recovery_request_hashes=pre_recovery_request_hashes,
        active_current_case_ids=active_current_case_ids,
    )
    _verify_historical_audit_expectation(
        provider=provider,
        model=model,
        scan=scan,
        pre_batch_request_hashes=(
            set()
            if pre_batch_request_hashes is None
            else pre_batch_request_hashes
        ),
        pre_recovery_request_hashes=(
            set()
            if pre_recovery_request_hashes is None
            else pre_recovery_request_hashes
        ),
        historical_expectation=historical_expectation,
    )
    return attempts, scan


def _verify_transport_stop_attempt(
    *,
    root: Path,
    output_root: Path,
    case: Any,
    receipt: dict[str, Any],
    sequence: list[AttemptEntry],
    audit: dict[str, Any],
) -> None:
    """Bind one current provider-error lifecycle with no response/cache."""

    if (
        len(sequence) != 1
        or sequence[0].variant_index != 0
        or sequence[0].status != "quarantined"
        or sequence[0].failure_code != "provider_failure_event"
        or audit.get("current_quarantined_provider_failure_count") != 1
        or audit.get("current_quarantined_manifest_paths")
        != [sequence[0].manifest_path]
    ):
        raise ValueError("stopped transport attempt is invalid")
    expected_hash, _ = _request_variants_for_case(root, case)[0]
    attempt = sequence[0]
    manifest_path = output_root / attempt.manifest_path
    manifest = strict_json_loads(
        _read_regular(manifest_path, limit=2 * 1024 * 1024),
        max_bytes=2 * 1024 * 1024,
    )
    if (
        type(manifest) is not dict
        or attempt.request_hash != expected_hash
        or manifest.get("request_hash") != expected_hash
        or manifest.get("status") != "quarantined"
        or manifest.get("failure_code") != "provider_failure_event"
        or manifest.get("audit_commitment_sha256")
        != attempt.audit_commitment_sha256
        or manifest.get("response_commitment_sha256") is not None
        or manifest.get("response_length") is not None
        or manifest.get("response_sha256") is not None
        or manifest.get("provider_response_model") is not None
        or manifest.get("usage") is not None
        or _SHA256_PATTERN.fullmatch(
            str(manifest.get("executable_identity_commitment_sha256"))
        )
        is None
    ):
        raise ValueError("stopped transport manifest is invalid")
    metadata = _read_regular(
        manifest_path.with_name("events.metadata.jsonl"),
        limit=2 * 1024 * 1024,
    )
    lifecycle = [
        strict_json_loads(line, max_bytes=2 * 1024 * 1024)
        for line in metadata.splitlines()
    ]
    if lifecycle != [
        {"index": 0, "type": "thread.started"},
        {"index": 1, "type": "turn.started"},
        {"index": 2, "type": "error"},
    ]:
        raise ValueError("stopped transport lifecycle is invalid")
    quarantine = strict_json_loads(
        _read_regular(
            manifest_path.with_name("quarantine.json"),
            limit=2 * 1024 * 1024,
        ),
        max_bytes=2 * 1024 * 1024,
    )
    if quarantine != {
        "schema_version": "1.0",
        "status": "quarantined",
        "failure_code": "provider_failure_event",
        "positive_transition_written": False,
    }:
        raise ValueError("stopped transport quarantine is invalid")
    if receipt != {
        "schema_version": "1.0",
        "case_id": case.case_id,
        "attempts": 1,
        "error": "teacher request failed",
        "error_kind": "transport",
        "failed_attempt": 1,
        "validation_attempt": None,
        "validation": None,
        "positive_transition_written": False,
    }:
        raise ValueError("stopped transport receipt is invalid")


def _verify_stopped_attempt_sequence(
    *,
    root: Path,
    output_root: Path,
    case: Any,
    generation_mode: str,
    receipt: dict[str, Any],
    attempts: list[AttemptEntry],
    audit: dict[str, Any],
) -> None:
    """Replay one failed current-v2.3 repair sequence and bind its receipt."""

    sequence = [item for item in attempts if item.case_id == case.case_id]
    if sequence and all(
        item.status == "quarantined"
        and item.failure_code == "provider_failure_event"
        for item in sequence
    ):
        if generation_mode not in {"fixture", "live"}:
            raise ValueError("stopped attempt sequence is invalid")
        _verify_transport_stop_attempt(
            root=root,
            output_root=output_root,
            case=case,
            receipt=receipt,
            sequence=sequence,
            audit=audit,
        )
        return
    if (
        generation_mode not in {"fixture", "live"}
        or not 1 <= len(sequence) <= 3
        or any(
            item.status != "committed" or item.failure_code is not None
            for item in sequence
        )
    ):
        raise ValueError("stopped attempt sequence is invalid")
    variants = _request_variants_for_case(root, case)
    if len(variants) != len(_REPAIR_VARIANTS):
        raise ValueError("stopped request variant set is invalid")
    context = build_oracle_context(root, case)
    vocabulary = allowed_action_values(root)
    store = _load_store(root, case)
    by_response = audit.get("by_response")
    if type(by_response) is not dict:
        raise ValueError("stopped response audit set is invalid")

    request_set: set[str] = set()
    prompt_set: set[str] = set()
    cache_set: set[str] = set()
    started_times: list[int] = []
    previous_repair_error: str | None = None
    last_validation: Any = None
    last_validation_attempt: int | None = None
    final_error_kind: str | None = None
    for index, attempt in enumerate(sequence):
        if not 0 <= attempt.variant_index < len(variants):
            raise ValueError("stopped attempt variant is invalid")
        expected_hash, request = variants[attempt.variant_index]
        repair_error, repair_attempt = _REPAIR_VARIANTS[attempt.variant_index]
        if expected_hash != attempt.request_hash:
            raise ValueError("stopped attempt request is mismatched")
        if index == 0:
            if (repair_error, repair_attempt) != (None, 0):
                raise ValueError("stopped sequence does not start at variant zero")
        elif (
            previous_repair_error is None
            or repair_attempt != index
            or repair_error != previous_repair_error
        ):
            raise ValueError("stopped repair transition is noncausal")

        manifest_path = output_root / attempt.manifest_path
        invocation_info = manifest_path.parent.parent.lstat()
        if (
            not stat.S_ISDIR(invocation_info.st_mode)
            or stat.S_ISLNK(invocation_info.st_mode)
        ):
            raise ValueError("stopped invocation directory is invalid")
        started_times.append(invocation_info.st_mtime_ns)
        manifest = strict_json_loads(
            _read_regular(manifest_path, limit=2 * 1024 * 1024),
            max_bytes=2 * 1024 * 1024,
        )
        if type(manifest) is not dict:
            raise ValueError("stopped attempt manifest is invalid")
        response_commitment = manifest.get("response_commitment_sha256")
        link = by_response.get(response_commitment)
        if (
            type(response_commitment) is not str
            or type(link) is not dict
            or link.get("request_hash") != attempt.request_hash
            or link.get("audit_commitment_sha256")
            != attempt.audit_commitment_sha256
            or link.get("cache_preimage_bound") is not True
        ):
            raise ValueError("stopped attempt response is unbound")
        cache_relative = link.get("cache_file")
        if type(cache_relative) is not str:
            raise ValueError("stopped attempt cache path is invalid")
        cache_path = Path(cache_relative)
        if cache_path.is_absolute() or ".." in cache_path.parts:
            raise ValueError("stopped attempt cache path is unsafe")
        response = TeacherResponse.model_validate_json(
            _read_regular(output_root / cache_path, limit=2 * 1024 * 1024)
        )
        if (
            response.response_commitment_sha256 != response_commitment
            or link.get("provider_invocation_id")
            != response.provider_request_id
        ):
            raise ValueError("stopped attempt cache response is mismatched")

        evaluation = _evaluate_enrichment_attempt(
            text=response.text,
            schema=request.schema,
            case=case,
            store=store,
            vocabulary=vocabulary,
        )
        prompt_sha256 = _sha256(
            (request.system + request.user).encode("utf-8")
        )
        request_set.add(attempt.request_hash)
        prompt_set.add(prompt_sha256)
        cache_set.add(cache_relative)
        if (
            len(request_set) != index + 1
            or len(prompt_set) != index + 1
            or len(cache_set) != index + 1
        ):
            raise ValueError("stopped attempt identities are not unique")

        transition_error = evaluation.repair_error
        if evaluation.structured_output_valid is not True:
            final_error_kind = "structured_invalid"
        else:
            payload = evaluation.payload
            validation = evaluation.validation
            if payload is None or validation is None:
                raise ValueError("stopped attempt evaluation is inconsistent")
            last_validation = validation
            last_validation_attempt = index + 1
            if not validation.valid:
                final_error_kind = "semantic_invalid"
            else:
                try:
                    committed_enrichment_record(
                        case_id=case.case_id,
                        generation_mode=generation_mode,
                        provider=response.provider,
                        model=response.model,
                        requested_model=response.requested_model,
                        provider_response_model=response.provider_response_model,
                        teacher_response_commitment_sha256=(
                            response.response_commitment_sha256
                        ),
                        provider_request_id=response.provider_request_id,
                        prompt_sha256=prompt_sha256,
                        source_context_sha256=context.sha256,
                        temperature=0.0,
                        max_tokens=8192,
                        latency_ms=_latency_integer(response.latency_ms),
                        usage=response.usage,
                        structured_output_valid=True,
                        payload=payload,
                        validation=validation,
                    )
                except ValidationError:
                    transition_error = "invalid_teacher_response_metadata"
                    final_error_kind = "teacher_response_metadata_invalid"
                else:
                    transition_error = None
                    final_error_kind = None
        if transition_error is None:
            raise ValueError("stopped sequence contains a valid attempt")
        previous_repair_error = transition_error

    if any(
        earlier >= later
        for earlier, later in zip(started_times, started_times[1:])
    ):
        raise ValueError("stopped invocation times are out of order")
    expected_receipt = {
        "schema_version": "1.0",
        "case_id": case.case_id,
        "attempts": len(sequence),
        "error": "teacher output remained invalid",
        "error_kind": final_error_kind,
        "failed_attempt": len(sequence),
        "validation_attempt": last_validation_attempt,
        "validation": _receipt_validation(last_validation),
        "positive_transition_written": False,
    }
    if receipt != expected_receipt:
        raise ValueError("stopped failure receipt does not match replay")


def _verify_recovered_attempt_sequence(
    *,
    root: Path,
    output_root: Path,
    case: Any,
    record: EnrichmentRecord,
    attempts: list[AttemptEntry],
    audit: dict[str, Any],
) -> None:
    """Replay the exact bounded repair state machine behind one positive."""

    sequence = [item for item in attempts if item.case_id == case.case_id]
    if not 1 <= len(sequence) <= 3:
        raise ValueError("recovered attempt sequence length is invalid")
    variants = _request_variants_for_case(root, case)
    if len(variants) != len(_REPAIR_VARIANTS):
        raise ValueError("recovered request variant set is invalid")
    context = build_oracle_context(root, case)
    vocabulary = allowed_action_values(root)
    store = _load_store(root, case)
    request_set: set[str] = set()
    prompt_set: set[str] = set()
    cache_set: set[str] = set()
    started_times: list[int] = []
    previous_repair_error: str | None = None
    final_response_commitment: str | None = None
    final_prompt_sha256: str | None = None
    final_evaluation: Any = None
    for index, attempt in enumerate(sequence):
        if attempt.status != "committed" or attempt.failure_code is not None:
            raise ValueError("recovered attempt is not committed")
        if not 0 <= attempt.variant_index < len(variants):
            raise ValueError("recovered attempt variant is invalid")
        expected_hash, request = variants[attempt.variant_index]
        repair_error, repair_attempt = _REPAIR_VARIANTS[attempt.variant_index]
        if expected_hash != attempt.request_hash:
            raise ValueError("recovered attempt request is mismatched")
        if index == 0:
            if (repair_error, repair_attempt) != (None, 0):
                raise ValueError("recovered sequence does not start at variant zero")
        elif (
            previous_repair_error is None
            or repair_attempt != index
            or repair_error != previous_repair_error
        ):
            raise ValueError("recovered repair transition is noncausal")
        manifest_path = output_root / attempt.manifest_path
        invocation_info = manifest_path.parent.parent.lstat()
        if (
            not stat.S_ISDIR(invocation_info.st_mode)
            or stat.S_ISLNK(invocation_info.st_mode)
        ):
            raise ValueError("recovered invocation directory is invalid")
        started_times.append(invocation_info.st_mtime_ns)
        manifest = strict_json_loads(
            _read_regular(manifest_path, limit=2 * 1024 * 1024),
            max_bytes=2 * 1024 * 1024,
        )
        if type(manifest) is not dict:
            raise ValueError("recovered attempt manifest is invalid")
        response_commitment = manifest.get("response_commitment_sha256")
        link = audit.get("by_response", {}).get(response_commitment)
        if (
            type(response_commitment) is not str
            or type(link) is not dict
            or link.get("request_hash") != attempt.request_hash
        ):
            raise ValueError("recovered attempt response is unbound")
        cache_relative = link.get("cache_file")
        if type(cache_relative) is not str:
            raise ValueError("recovered attempt cache path is invalid")
        cache_path = Path(cache_relative)
        if cache_path.is_absolute() or ".." in cache_path.parts:
            raise ValueError("recovered attempt cache path is unsafe")
        response_value = strict_json_loads(
            _read_regular(
                output_root / cache_path, limit=2 * 1024 * 1024
            ),
            max_bytes=2 * 1024 * 1024,
        )
        response = TeacherResponse.model_validate(response_value)
        if response.response_commitment_sha256 != response_commitment:
            raise ValueError("recovered attempt cache response is mismatched")
        evaluation = _evaluate_enrichment_attempt(
            text=response.text,
            schema=request.schema,
            case=case,
            store=store,
            vocabulary=vocabulary,
        )
        prompt_sha256 = _sha256((request.system + request.user).encode("utf-8"))
        request_set.add(attempt.request_hash)
        prompt_set.add(prompt_sha256)
        cache_set.add(cache_relative)
        if (
            len(request_set) != index + 1
            or len(prompt_set) != index + 1
            or len(cache_set) != index + 1
        ):
            raise ValueError("recovered attempt identities are not unique")
        if index + 1 < len(sequence) and evaluation.repair_error is None:
            raise ValueError("recovered sequence continues after a valid attempt")
        previous_repair_error = evaluation.repair_error
        final_response_commitment = response_commitment
        final_prompt_sha256 = prompt_sha256
        final_evaluation = evaluation
    if any(
        earlier >= later
        for earlier, later in zip(started_times, started_times[1:])
    ):
        raise ValueError("recovered invocation times are out of order")
    if (
        final_evaluation is None
        or final_evaluation.repair_error is not None
        or final_evaluation.structured_output_valid is not True
        or final_evaluation.payload is None
        or final_evaluation.validation is None
        or final_evaluation.validation.valid is not True
        or record.teacher_response_commitment_sha256
        != final_response_commitment
        or record.prompt_sha256 != final_prompt_sha256
        or record.payload != final_evaluation.payload
        or record.validation != final_evaluation.validation
    ):
        raise ValueError("recovered positive is not the final valid transition")


def _verify_recovered_record_binding(
    *,
    root: Path,
    output_root: Path,
    requested: list[str],
    cases: dict[str, Any],
    records: dict[str, EnrichmentRecord],
    attempts: list[AttemptEntry],
    audit: dict[str, Any],
) -> None:
    """Bind every recovered positive to one exact current audit/cache transaction."""

    if (
        not 1 <= len(attempts) <= 3
        or audit.get("committed") != len(attempts)
        or any(
            attempt.case_id not in requested or attempt.status != "committed"
            for attempt in attempts
        )
    ):
        raise ValueError("recovered current attempt set is invalid")
    by_response = audit.get("by_response")
    if type(by_response) is not dict or len(by_response) != len(attempts):
        raise ValueError("recovered response audit set is invalid")
    attempts_by_request = {attempt.request_hash: attempt for attempt in attempts}
    if len(attempts_by_request) != len(attempts):
        raise ValueError("recovered request attempts are duplicated")
    for case_id in requested:
        record = records.get(case_id)
        case = cases.get(case_id)
        if record is None or case is None:
            raise ValueError("recovered record is unavailable")
        _verify_recovered_attempt_sequence(
            root=root,
            output_root=output_root,
            case=case,
            record=record,
            attempts=attempts,
            audit=audit,
        )
        link = by_response.get(record.teacher_response_commitment_sha256)
        if type(link) is not dict:
            raise ValueError("recovered response is not current-audit bound")
        attempt = attempts_by_request.get(link.get("request_hash"))
        if attempt is None:
            raise ValueError("recovered response request is not a current variant")
        manifest = strict_json_loads(
            _read_regular(
                output_root / attempt.manifest_path, limit=2 * 1024 * 1024
            ),
            max_bytes=2 * 1024 * 1024,
        )
        if (
            type(manifest) is not dict
            or manifest.get("request_hash") != attempt.request_hash
            or manifest.get("response_commitment_sha256")
            != record.teacher_response_commitment_sha256
            or manifest.get("audit_commitment_sha256")
            != attempt.audit_commitment_sha256
            or link.get("audit_commitment_sha256")
            != attempt.audit_commitment_sha256
            or link.get("cache_preimage_bound") is not True
            or link.get("provider_invocation_id") != record.provider_request_id
            or link.get("provider_response_model")
            != record.provider_response_model
            or link.get("usage") != record.usage
            or math.floor(link.get("latency_ms")) != record.latency_ms
            or link.get("executable_id") != "codex-cli"
            or not _SHA256_PATTERN.fullmatch(
                str(link.get("executable_sha256"))
            )
            or not _SHA256_PATTERN.fullmatch(
                str(link.get("executable_identity_commitment_sha256"))
            )
            or link.get("executable_identity_commitment_sha256")
            != manifest.get("executable_identity_commitment_sha256")
        ):
            raise ValueError("recovered audit/cache/record binding is invalid")


def _failure_receipt(output_root: Path, case_id: str) -> dict[str, Any] | None:
    path = output_root / "enrichment/failures" / f"{case_id}.json"
    try:
        value = strict_json_loads(
            _read_regular(path, limit=2 * 1024 * 1024),
            max_bytes=2 * 1024 * 1024,
        )
    except FileNotFoundError:
        return None
    if (
        type(value) is not dict
        or value.get("case_id") != case_id
        or value.get("positive_transition_written") is not False
    ):
        raise ValueError("failure receipt is invalid")
    return value


def _expected_provenance_manifest(
    output_root: Path,
    *,
    requested: list[str],
    completed: list[str],
    failed_case_id: str | None,
    generation_mode: str,
    provider: str,
    model: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    records: list[EnrichmentRecord] = []
    for case_id in completed:
        path = output_root / "enrichment" / f"{case_id}.json"
        raw = _read_regular(path, limit=2 * 1024 * 1024)
        record = _read_record(path)
        if record.case_id != case_id:
            raise ValueError("provenance record case mismatch")
        records.append(record)
        entries.append(
            {
                "case_id": case_id,
                "relative_path": f"{case_id}.json",
                "file_sha256": _sha256(raw),
                "kind": "enrichment_record",
                "record_commitment_sha256": record.record_commitment_sha256,
                "requested_model": record.requested_model,
                "provider_response_model": record.provider_response_model,
                "teacher_response_commitment_sha256": (
                    record.teacher_response_commitment_sha256
                ),
            }
        )
    if failed_case_id is not None:
        receipt_path = (
            output_root / "enrichment/failures" / f"{failed_case_id}.json"
        )
        raw = _read_regular(receipt_path, limit=2 * 1024 * 1024)
        if _failure_receipt(output_root, failed_case_id) is None:
            raise ValueError("failure receipt is unavailable")
        entries.append(
            {
                "case_id": failed_case_id,
                "relative_path": f"failures/{failed_case_id}.json",
                "file_sha256": _sha256(raw),
                "kind": "failure_receipt",
                "record_commitment_sha256": None,
                "requested_model": None,
                "provider_response_model": None,
                "teacher_response_commitment_sha256": None,
            }
        )
    response_counts = dict(
        sorted(Counter(record.provider_response_model for record in records).items())
    )
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "stage": "enrichment_provenance",
        "generation_mode": generation_mode,
        "provider": provider,
        "model": model,
        "requested_provider": provider,
        "requested_model": model,
        "provider_response_models": sorted(response_counts),
        "provider_response_model_counts": response_counts,
        "requested_case_ids": requested,
        "artifacts": entries,
    }
    manifest["batch_commitment_sha256"] = _dict_commitment(
        manifest, "batch_commitment_sha256"
    )
    summary = {
        "generation_mode": generation_mode,
        "provider": provider,
        "model": model,
        "requested_provider": provider,
        "requested_model": model,
        "provider_response_models": manifest["provider_response_models"],
        "provider_response_model_counts": manifest[
            "provider_response_model_counts"
        ],
        "manifest_sha256": _sha256(
            _read_regular(
                output_root / _PROVENANCE_RELATIVE, limit=2 * 1024 * 1024
            )
        ),
        "batch_commitment_sha256": manifest["batch_commitment_sha256"],
    }
    return manifest, summary


def _verify_provenance_and_summary(
    output_root: Path,
    *,
    requested: list[str],
    completed: list[str],
    failed_case_id: str | None,
    not_started: list[str],
    status: str,
    generation_mode: str,
    provider: str,
    model: str,
) -> dict[str, Any]:
    expected_manifest, provenance_summary = _expected_provenance_manifest(
        output_root,
        requested=requested,
        completed=completed,
        failed_case_id=failed_case_id,
        generation_mode=generation_mode,
        provider=provider,
        model=model,
    )
    observed_manifest = strict_json_loads(
        _read_regular(
            output_root / _PROVENANCE_RELATIVE, limit=2 * 1024 * 1024
        ),
        max_bytes=2 * 1024 * 1024,
    )
    if observed_manifest != expected_manifest:
        raise ValueError("enrichment provenance is invalid")
    expected_summary: dict[str, Any] = {
        "schema_version": "2.0",
        "stage": "fail_fast_enrichment",
        "status": status,
        "stop_on_first_failure": True,
        "requested_case_ids": requested,
        "completed_case_ids": completed,
        "failed_case_id": failed_case_id,
        "not_started_case_ids": not_started,
        "provenance": provenance_summary,
    }
    expected_summary["summary_commitment_sha256"] = _dict_commitment(
        expected_summary, "summary_commitment_sha256"
    )
    observed_summary = strict_json_loads(
        _read_regular(output_root / _SUMMARY_RELATIVE, limit=2 * 1024 * 1024),
        max_bytes=2 * 1024 * 1024,
    )
    if observed_summary != expected_summary:
        raise ValueError("enrichment summary is invalid")
    return provenance_summary


def _publish_summary(
    output_root: Path,
    *,
    status: str,
    requested: list[str],
    completed: list[str],
    failed_case_id: str | None,
    not_started: list[str],
    provenance: dict[str, Any],
) -> None:
    value: dict[str, Any] = {
        "schema_version": "2.0",
        "stage": "fail_fast_enrichment",
        "status": status,
        "stop_on_first_failure": True,
        "requested_case_ids": requested,
        "completed_case_ids": completed,
        "failed_case_id": failed_case_id,
        "not_started_case_ids": not_started,
        "provenance": provenance,
    }
    value["summary_commitment_sha256"] = _dict_commitment(
        value, "summary_commitment_sha256"
    )
    write_report(output_root / _SUMMARY_RELATIVE, value)


def _build_report(
    *,
    root: Path,
    case_file: Path,
    scope_case_file: Path,
    output_root: Path,
    generation_mode: str,
    provider: str,
    model: str,
    started: list[str],
    completed: list[str],
    failed_case_id: str | None,
    historical_expectation: dict[str, Any],
) -> FailFastReport:
    requested = read_case_ids(case_file)
    scope = read_case_ids(scope_case_file)
    catalog = catalog_index(root)
    (
        forbidden,
        recovery_mode,
        target_reason,
        all_request_hashes,
        expected_requests,
        pre_batch_request_hashes,
        pre_recovery_request_hashes,
        historical_expectation,
        all_attempts,
        audit,
    ) = _recovery_scope_state(
        root=root,
        output_root=output_root,
        scope=scope,
        requested=requested,
        catalog=catalog,
        provider=provider,
        model=model,
        historical_expectation=historical_expectation,
        active_current_case_ids=set(started),
    )
    request_hashes = {
        case_id: all_request_hashes[case_id]
        for case_id in [*requested, *forbidden]
    }
    attempts = [item for item in all_attempts if item.case_id in requested]
    if any(item.case_id in forbidden for item in all_attempts):
        raise ValueError("forbidden recovery case has a current attempt")
    not_started = requested[len(started) :]
    status = (
        "REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW"
        if failed_case_id is None and completed == requested
        else "REMAINING_P0_CASE_RECOVERY_STOPPED"
    )
    _verify_provenance_and_summary(
        output_root,
        requested=requested,
        completed=completed,
        failed_case_id=failed_case_id,
        not_started=not_started,
        status=status,
        generation_mode=generation_mode,
        provider=provider,
        model=model,
    )
    if status == "REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW":
        _verify_recovered_record_binding(
            root=root,
            output_root=output_root,
            requested=requested,
            cases=catalog,
            records={
                case_id: _read_record(
                    output_root / "enrichment" / f"{case_id}.json"
                )
                for case_id in requested
            },
            attempts=attempts,
            audit=audit,
        )
    elif failed_case_id is not None:
        receipt = _failure_receipt(output_root, failed_case_id)
        failed_attempts = [
            item for item in attempts if item.case_id == failed_case_id
        ]
        if receipt is None:
            raise ValueError("stopped failure receipt is unavailable")
        if failed_attempts:
            _verify_stopped_attempt_sequence(
                root=root,
                output_root=output_root,
                case=catalog[failed_case_id],
                generation_mode=generation_mode,
                receipt=receipt,
                attempts=attempts,
                audit=audit,
            )
    data: dict[str, Any] = {
        "schema_version": "1.0",
        "report_kind": "remaining_p0_fail_fast_enrichment",
        "status": status,
        "stop_on_first_failure": True,
        "generation_mode": generation_mode,
        "provider": provider,
        "model": model,
        "recovery_mode": recovery_mode,
        "target_reason": target_reason,
        "case_file_sha256": _sha256(_read_regular(case_file, limit=64 * 1024)),
        "scope_case_file_sha256": _sha256(
            _read_regular(scope_case_file, limit=64 * 1024)
        ),
        "requested_case_ids": requested,
        "forbidden_case_ids": forbidden,
        "started_case_ids": started,
        "completed_case_ids": completed,
        "failed_case_id": failed_case_id,
        "not_started_case_ids": not_started,
        "request_hashes": request_hashes,
        "current_attempts": [item.model_dump(mode="json") for item in attempts],
        "teacher_audit_artifact_set_sha256": audit["artifact_set_sha256"],
        "teacher_current_bound_committed": audit["committed"],
        "canonical_test_receipts": [
            item.model_dump(mode="json")
            for item in _test_receipt_evidence(root, output_root)
        ],
        "artifact_inventory": [
            item.model_dump(mode="json") for item in _inventory(output_root)
        ],
        "provenance_manifest_sha256": _sha256(
            _read_regular(output_root / _PROVENANCE_RELATIVE, limit=2 * 1024 * 1024)
        ),
        "enrichment_summary_sha256": _sha256(
            _read_regular(output_root / _SUMMARY_RELATIVE, limit=2 * 1024 * 1024)
        ),
        "report_commitment_sha256": "sha256:" + "0" * 64,
    }
    data["report_commitment_sha256"] = _report_commitment(data)
    return FailFastReport.model_validate(data)


def run_fail_fast_batch(
    *,
    root: Path,
    case_file: Path,
    scope_case_file: Path,
    output_root: Path,
    teacher: Teacher,
) -> FailFastReport:
    """Run serially and stop at the first failure; this cannot be configured off."""

    root = Path(root).resolve(strict=True)
    case_file = Path(case_file).resolve(strict=True)
    scope_case_file = Path(scope_case_file).resolve(strict=True)
    output_root = Path(output_root).absolute()
    historical_expectation, _ = load_historical_expectation_with_evidence(root)
    with BatchLock(output_root):
        return _run_fail_fast_batch_locked(
            root=root,
            case_file=case_file,
            scope_case_file=scope_case_file,
            output_root=output_root,
            teacher=teacher,
            historical_expectation=historical_expectation,
        )


def _run_fail_fast_batch_locked(
    *,
    root: Path,
    case_file: Path,
    scope_case_file: Path,
    output_root: Path,
    teacher: Teacher,
    historical_expectation: dict[str, Any],
) -> FailFastReport:
    requested = read_case_ids(case_file)
    scope = read_case_ids(scope_case_file)
    if any(case_id not in scope for case_id in requested):
        raise ValueError("recovery case list is outside the frozen scope")
    catalog = catalog_index(root)
    if any(case_id not in catalog for case_id in requested):
        raise ValueError("recovery case is not in the catalog")
    (
        _,
        preflight_recovery_mode,
        preflight_target_reason,
        *_,
    ) = _recovery_scope_state(
        root=root,
        output_root=output_root,
        scope=scope,
        requested=requested,
        catalog=catalog,
        provider=teacher.provider,
        model=teacher.model,
        historical_expectation=historical_expectation,
        active_current_case_ids=set(),
    )
    output_dir = output_root / "enrichment"
    (output_dir / "failures").mkdir(parents=True, exist_ok=True)
    (output_root / "reports/remaining-p0").mkdir(parents=True, exist_ok=True)
    for path, label in (
        (output_root / _PROVENANCE_RELATIVE, "batch-provenance"),
        (output_root / _SUMMARY_RELATIVE, "enrichment-summary"),
        (output_root / _REPORT_RELATIVE, "fail-fast-report"),
    ):
        _archive_existing(output_root, path, label)
    runner = EnrichmentRunner(
        root,
        teacher,
        max_repairs=2,
        generation_mode=_teacher_generation_mode(teacher),
    )
    started: list[str] = []
    completed: list[str] = []
    records: list[EnrichmentRecord] = []
    failed_case_id: str | None = None
    for case_id in requested:
        _archive_existing(
            output_root,
            output_dir / "failures" / f"{case_id}.json",
            f"failure-{case_id}",
        )
        started.append(case_id)
        try:
            record = runner.run(catalog[case_id], output_dir)
            records.append(record)
            completed.append(case_id)
        except Exception:
            failed_case_id = case_id
            _ensure_failure_receipt(
                root=root,
                output_root=output_root,
                output_dir=output_dir,
                case=catalog[case_id],
            )
            break
    not_started = requested[len(started) :]
    failures = [failed_case_id] if failed_case_id is not None else []
    provenance = _write_provenance_manifest(
        output_dir,
        requested,
        records,
        failures,
        generation_mode=_teacher_generation_mode(teacher),
        provider=teacher.provider,
        model=teacher.model,
    )
    status = (
        "REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW"
        if failed_case_id is None and completed == requested
        else "REMAINING_P0_CASE_RECOVERY_STOPPED"
    )
    _publish_summary(
        output_root,
        status=status,
        requested=requested,
        completed=completed,
        failed_case_id=failed_case_id,
        not_started=not_started,
        provenance=provenance,
    )
    report = _build_report(
        root=root,
        case_file=case_file,
        scope_case_file=scope_case_file,
        output_root=output_root,
        generation_mode=_teacher_generation_mode(teacher),
        provider=teacher.provider,
        model=teacher.model,
        started=started,
        completed=completed,
        failed_case_id=failed_case_id,
        historical_expectation=historical_expectation,
    )
    if (
        report.recovery_mode != preflight_recovery_mode
        or report.target_reason != preflight_target_reason
    ):
        raise ValueError("recovery scope changed during fail-fast execution")
    write_report(output_root / _REPORT_RELATIVE, report.model_dump(mode="json"))
    return _verify_fail_fast_report_unlocked(
        root=root,
        case_file=case_file,
        scope_case_file=scope_case_file,
        output_root=output_root,
        historical_expectation=historical_expectation,
    )


def verify_fail_fast_report(
    *, root: Path, case_file: Path, scope_case_file: Path, output_root: Path
) -> FailFastReport:
    """Recompute current prompt/audit/artifact facts without trusting report booleans."""

    root = Path(root).resolve(strict=True)
    output_root = Path(output_root).absolute()
    historical_expectation, _ = load_historical_expectation_with_evidence(root)
    if active_batch_lock(output_root) is not None:
        return _verify_fail_fast_report_unlocked(
            root=root,
            case_file=case_file,
            scope_case_file=scope_case_file,
            output_root=output_root,
            historical_expectation=historical_expectation,
        )
    with BatchLock(output_root):
        return _verify_fail_fast_report_unlocked(
            root=root,
            case_file=case_file,
            scope_case_file=scope_case_file,
            output_root=output_root,
            historical_expectation=historical_expectation,
        )


def _verify_fail_fast_report_unlocked(
    *,
    root: Path,
    case_file: Path,
    scope_case_file: Path,
    output_root: Path,
    historical_expectation: dict[str, Any],
) -> FailFastReport:
    """Internal replay used while the caller holds the batch lock."""

    try:
        root = Path(root).resolve(strict=True)
        case_file = Path(case_file).resolve(strict=True)
        scope_case_file = Path(scope_case_file).resolve(strict=True)
        output_root = Path(output_root).resolve(strict=True)
        raw = _read_regular(output_root / _REPORT_RELATIVE, limit=16 * 1024 * 1024)
        report = FailFastReport.model_validate_json(raw)
        value = report.model_dump(mode="json")
        if report.report_commitment_sha256 != _report_commitment(value):
            raise ValueError
        requested = read_case_ids(case_file)
        scope = read_case_ids(scope_case_file)
        catalog = catalog_index(root)
        (
            forbidden,
            recovery_mode,
            target_reason,
            all_request_hashes,
            _,
            _,
            _,
            _,
            all_attempts,
            audit,
        ) = _recovery_scope_state(
            root=root,
            output_root=output_root,
            scope=scope,
            requested=requested,
            catalog=catalog,
            provider=report.provider,
            model=report.model,
            historical_expectation=historical_expectation,
            active_current_case_ids=set(report.started_case_ids),
        )
        request_hashes = {
            case_id: all_request_hashes[case_id]
            for case_id in [*requested, *forbidden]
        }
        attempts = [
            item for item in all_attempts if item.case_id in requested
        ]
        if (
            report.case_file_sha256 != _sha256(_read_regular(case_file, limit=64 * 1024))
            or report.scope_case_file_sha256
            != _sha256(_read_regular(scope_case_file, limit=64 * 1024))
            or report.requested_case_ids != requested
            or report.forbidden_case_ids != forbidden
            or report.recovery_mode != recovery_mode
            or report.target_reason != target_reason
        ):
            raise ValueError
        if report.request_hashes != request_hashes or report.current_attempts != attempts:
            raise ValueError
        if (
            report.teacher_audit_artifact_set_sha256
            != audit["artifact_set_sha256"]
            or report.teacher_current_bound_committed != audit["committed"]
            or report.canonical_test_receipts
            != _test_receipt_evidence(root, output_root)
        ):
            raise ValueError
        if any(item.case_id in forbidden for item in all_attempts):
            raise ValueError
        if any(
            len([item for item in attempts if item.case_id == case_id]) > 3
            or len(
                {
                    item.request_hash
                    for item in attempts
                    if item.case_id == case_id
                }
            )
            != len([item for item in attempts if item.case_id == case_id])
            for case_id in requested
        ):
            raise ValueError
        if report.artifact_inventory != _inventory(output_root):
            raise ValueError
        if any(
            item.relative_path.startswith(("episodes/", "trajectories/"))
            for item in report.artifact_inventory
        ):
            raise ValueError
        if report.provenance_manifest_sha256 != _sha256(
            _read_regular(output_root / _PROVENANCE_RELATIVE, limit=2 * 1024 * 1024)
        ) or report.enrichment_summary_sha256 != _sha256(
            _read_regular(output_root / _SUMMARY_RELATIVE, limit=2 * 1024 * 1024)
        ):
            raise ValueError
        if report.started_case_ids != requested[: len(report.started_case_ids)]:
            raise ValueError
        if report.not_started_case_ids != requested[len(report.started_case_ids) :]:
            raise ValueError
        if any(
            item.case_id not in report.started_case_ids for item in attempts
        ):
            raise ValueError
        if any(
            (output_root / "enrichment" / f"{case_id}.json").exists()
            for case_id in [*report.not_started_case_ids, *forbidden]
        ):
            raise ValueError
        _verify_provenance_and_summary(
            output_root,
            requested=requested,
            completed=report.completed_case_ids,
            failed_case_id=report.failed_case_id,
            not_started=report.not_started_case_ids,
            status=report.status,
            generation_mode=report.generation_mode,
            provider=report.provider,
            model=report.model,
        )
        if report.failed_case_id is None:
            if (
                report.status != "REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW"
                or report.completed_case_ids != requested
                or report.started_case_ids != requested
            ):
                raise ValueError
            for case_id in requested:
                record = _read_record(
                    output_root / "enrichment" / f"{case_id}.json"
                )
                if not _record_is_current(
                    root,
                    catalog[case_id],
                    record,
                    provider=report.provider,
                    model=report.model,
                ):
                    raise ValueError
            _verify_recovered_record_binding(
                root=root,
                output_root=output_root,
                requested=requested,
                cases=catalog,
                records={
                    case_id: _read_record(
                        output_root / "enrichment" / f"{case_id}.json"
                    )
                    for case_id in requested
                },
                attempts=attempts,
                audit=audit,
            )
        else:
            failure_receipt = _failure_receipt(
                output_root, report.failed_case_id
            )
            if (
                report.status != "REMAINING_P0_CASE_RECOVERY_STOPPED"
                or report.failed_case_id != report.started_case_ids[-1]
                or report.completed_case_ids != report.started_case_ids[:-1]
                or (
                    output_root
                    / "enrichment"
                    / f"{report.failed_case_id}.json"
                ).exists()
                or failure_receipt is None
            ):
                raise ValueError
            failed_attempts = [
                item
                for item in attempts
                if item.case_id == report.failed_case_id
            ]
            if failed_attempts:
                _verify_stopped_attempt_sequence(
                    root=root,
                    output_root=output_root,
                    case=catalog[report.failed_case_id],
                    generation_mode=report.generation_mode,
                    receipt=failure_receipt,
                    attempts=attempts,
                    audit=audit,
                )
        return report
    except Exception:
        raise ValueError("fail-fast report verification failed") from None

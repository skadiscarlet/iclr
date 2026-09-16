"""Independent, source-controlled verifier for the bounded first live P0 case."""

from __future__ import annotations

import argparse
import base64
import binascii
from collections import Counter
from dataclasses import dataclass
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any

from jsonschema import Draft202012Validator

from egsi.contracts.enrichment import (
    EnrichmentPayload,
    EnrichmentRecord,
    EnrichmentValidation,
    enrichment_record_commitment,
)
from egsi.data.context import build_oracle_context
from egsi.generation.enrichment import (
    _bounded_payload_validation,
    _load_store,
    _prompt_vocabulary,
    allowed_action_values,
)
from egsi.generation.human_audit import (
    _expected_transaction_files,
    _parse_object,
    _repair_info_v21,
    _scan_teacher_audit,
    _validate_manifest_contract,
    _validate_metadata_lifecycle,
    historical_baseline_commitment,
    historical_baseline_value,
    load_historical_expectation_with_evidence,
)
from egsi.generation.pilot import (
    _dict_commitment,
    _read_regular,
    _sha256,
    catalog_index,
    write_report,
)
from egsi.generation.test_receipt import (
    OFFICIAL_RECEIPT_TIMEOUT_SECONDS,
    load_runner_lock,
    validate_test_receipt,
)
from egsi.generation.safeio import AnchoredDirectory, open_directory_fd
from egsi.strict_json import strict_json_loads
from egsi.teacher.base import TeacherRequest, TeacherResponse, teacher_request_hash
from egsi.teacher.cache import TeacherCache, cache_key
from egsi.teacher.prompts import enrichment_request_v21


VERIFIER_VERSION = "5.2"
FROZEN_PROMPT_VERSION = "2.1"
PROVIDER = "codex_exec"
MODEL = "gpt-5.6-sol"
_FIRST_CASE_HISTORICAL_EXPECTATION_RELATIVE = Path(
    "configs/first-case-historical-teacher-audit-expectation.v1.json"
)
_FIRST_CASE_HISTORICAL_EXPECTATION_ID = (
    "p0-first-case-cumulative-history-v1"
)
_FIRST_CASE_HISTORICAL_COMMITTED_DELTA = {
    "request_hash": (
        "sha256:3ff08b742a87a01533425742332ca34b6adb3330b543e52db72da157adc7f4a3"
    ),
    "response_commitment_sha256": (
        "sha256:48b8fa67c281729ccd88eac6dbe5d6e5facc1d878bbd64ab45ba6cdb71659b1c"
    ),
    "audit_commitment_sha256": (
        "sha256:59d83cefe1a405ba74430e66f368509f83d701a5de835ae10527127d863fc7bc"
    ),
}
_FIRST_CASE_HISTORICAL_PROVIDER_FAILURE_DELTA = {
    "request_hash": (
        "sha256:7c7dbdb539baef3b02c5f7aac6118b161147da7b2d3d75678fe24d7e641df7b7"
    ),
    "audit_commitment_sha256": (
        "sha256:55c4eb61ee38fe4734e1d33d0a2379b20062c0e804eb452e026a2cda50a3ae10"
    ),
}
EXPECTED_ATTEMPTS: tuple[tuple[str | None, int], ...] = (
    (None, 0),
    ("semantic_validation_failed", 1),
    ("semantic_validation_failed", 2),
)
OFFICIAL_RECEIPT_CLEANUP_GRACE_SECONDS = 300
OFFICIAL_RECEIPT_LAUNCHER_TIMEOUT_SECONDS = (
    OFFICIAL_RECEIPT_TIMEOUT_SECONDS
    + OFFICIAL_RECEIPT_CLEANUP_GRACE_SECONDS
)
_OFFICIAL_RECEIPT_TERMINATION_GRACE_SECONDS = 5.0
_OFFICIAL_RECEIPT_CAPTURE_LIMIT_BYTES = 1024 * 1024


def _large_dict_commitment(value: dict[str, Any], field: str) -> str:
    """Commit bounded-on-read evidence objects above the DSL list limit."""
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


def _validate_frozen_v21_payload(
    case: Any,
    payload: EnrichmentPayload,
    store: Any,
    vocabulary: dict[str, Any],
) -> EnrichmentValidation:
    """Replay the exact pre-v2.2 semantic contract for frozen evidence only.

    Prompt v2.1 did not constrain ``target_location`` to a canonical blob path
    and did not validate source line/symbol ranges. Keeping this validator
    private to the first-case historical verifier preserves that evidence
    without weakening the live v2.2 validator or making old records reusable.
    """

    required = ("goals", "operations", "target_kinds", "tool_classes")
    validator = vocabulary.get("_validator")
    if any(
        key not in vocabulary or not isinstance(vocabulary[key], set)
        for key in required
    ) or not isinstance(validator, Draft202012Validator):
        raise ValueError("action vocabulary is malformed")

    bounded_validation = _bounded_payload_validation(payload)
    if bounded_validation is not None:
        return bounded_validation

    contains_cache: dict[tuple[str, str], bool] = {}

    def contains(commit: str, path: str) -> bool:
        key = (commit, path)
        if key not in contains_cache:
            try:
                contains_cache[key] = store.contains(commit, path)
            except ValueError:
                contains_cache[key] = False
        return contains_cache[key]

    def location_exists(path: str) -> bool:
        return contains(case.repository.vulnerable_commit, path) or contains(
            case.repository.fixed_commit, path
        )

    def vulnerable_blob(path: str) -> bool:
        return contains(case.repository.vulnerable_commit, path)

    invalid_locations = sorted(
        {item.path for item in payload.locations if not location_exists(item.path)}
    )
    invalid_trace_locations = sorted(
        {
            item.target_id
            for item in payload.trace
            if item.target_kind == "path" and not vulnerable_blob(item.target_id)
        }
    )
    invalid_goals = sorted(
        {item.goal for item in payload.trace if item.goal not in vocabulary["goals"]}
    )
    invalid_operations = sorted(
        {
            item.operation
            for item in payload.trace
            if item.operation not in vocabulary["operations"]
        }
    )
    invalid_target_kinds = sorted(
        {
            item.target_kind
            for item in payload.trace
            if item.target_kind not in vocabulary["target_kinds"]
        }
    )
    invalid_tool_classes = sorted(
        {
            item.tool_class
            for item in payload.trace
            if item.tool_class not in vocabulary["tool_classes"]
        }
    )
    invalid_operation_set = set(invalid_operations)
    obligation_ids = {item.obligation_id for item in payload.obligations}
    for item in payload.trace:
        action = {
            "schema_version": "1.0",
            "action_id": "A-teacher",
            "episode_id": "teacher",
            "branch_id": "teacher",
            "actor_role": "hypothesis_agent",
            "goal": item.goal,
            "operation": item.operation,
            "target": {
                "kind": item.target_kind,
                "id": item.target_id,
                "location": item.target_location,
            },
            "resolves_unknowns": item.resolves_unknowns,
            "preconditions": [],
            "expected_evidence_type": item.expected_evidence_type,
            "tool_class": item.tool_class,
            "budget_cap": {"seconds": 0, "tool_calls": 0, "tokens": 0},
            "idempotency_key": "sha256:" + "a" * 64,
        }
        if (
            list(dict.fromkeys(item.resolves_unknowns)) != item.resolves_unknowns
            or not set(item.resolves_unknowns) <= obligation_ids
            or any(validator.iter_errors(action))
        ):
            invalid_operation_set.add(item.operation)
    invalid_operations = sorted(invalid_operation_set)
    family_mismatch = payload.family != case.family
    valid = not any(
        (
            family_mismatch,
            invalid_locations,
            invalid_trace_locations,
            invalid_goals,
            invalid_operations,
            invalid_target_kinds,
            invalid_tool_classes,
        )
    )
    return EnrichmentValidation(
        valid=valid,
        family_mismatch=family_mismatch,
        invalid_locations=invalid_locations,
        invalid_trace_locations=invalid_trace_locations,
        invalid_goals=invalid_goals,
        invalid_operations=invalid_operations,
        invalid_target_kinds=invalid_target_kinds,
        invalid_tool_classes=invalid_tool_classes,
    )


def _record_is_frozen_v21(
    root: Path,
    case: Any,
    record: EnrichmentRecord,
    *,
    provider: str,
    model: str,
) -> bool:
    """Verify the immutable first-case v2.1 artifact without making it reusable."""

    try:
        context = build_oracle_context(root, case)
        vocabulary = allowed_action_values(root)
        prompt_vocabulary = _prompt_vocabulary(vocabulary)
        hashes = set()
        for repair_code, repair_attempt in [(None, 0)] + [
            (code, attempt)
            for code in (
                "invalid_structured_output",
                "semantic_validation_failed",
                "invalid_teacher_response_metadata",
            )
            for attempt in (1, 2)
        ]:
            system, user, _ = enrichment_request_v21(
                context,
                prompt_vocabulary,
                repair_error=repair_code,
                repair_attempt=repair_attempt,
            )
            hashes.add(_sha256((system + user).encode("utf-8")))
        repeated = _validate_frozen_v21_payload(
            case, record.payload, _load_store(root, case), vocabulary
        )
        return (
            record.case_id == case.case_id
            and record.source_context_sha256 == context.sha256
            and record.prompt_sha256 in hashes
            and record.provider == provider
            and record.model == model
            and record.requested_model == model
            and record.temperature == 0.0
            and record.max_tokens == 8192
            and repeated == record.validation
            and repeated.valid is True
        )
    except Exception:
        return False
_REPORT_FIELDS = {
    "schema_version", "verifier_version", "native_attested", "attestation_mode", "status", "case_id", "scope",
    "invocations", "prompt_contract", "hard_gates", "attempts", "final",
    "historical_evidence", "test_receipts", "verifier_evidence",
    "human_semantic_judgment", "human_audit_signed",
    "sensitive_material_included", "report_commitment_sha256",
}
_SCOPE_FIELDS = {
    "output_root", "remaining_p0_cases_run_in_this_smoke", "p1_started",
    "historical_remaining_p0_case_ids_attempted",
    "later_p0_cases_not_started", "gpu_started", "training_started",
    "stop_marker",
}
_INVOCATION_FIELDS = {
    "baseline_before_smoke", "added_by_smoke",
    "added_after_smoke_historical", "cumulative",
    "committed_cumulative", "quarantined_cumulative",
    "current_request_bound_committed", "historical_unbound_committed",
    "current_final_record_committed", "current_repair_attempt_committed",
    "malformed_invalid",
}
_PROMPT_CONTRACT_FIELDS = {
    "prompt_version", "context_version", "source_context_sha256",
    "final_prompt_sha256", "strict_schema_sha256",
}
_ATTEMPT_FIELDS = {
    "repair_attempt", "repair_code", "prompt_sha256", "request_hash",
    "cache_key", "cache_file", "cache_file_sha256", "audit_file",
    "audit_file_sha256", "invocation_id", "structured_output_valid",
    "semantic_validation_valid", "validation_diagnostic_counts",
}
_FINAL_FIELDS = {
    "provider", "model", "requested_model", "provider_response_model",
    "provider_invocation_id", "provider_request_id_kind",
    "teacher_response_commitment_sha256", "record_commitment_sha256",
    "teacher_request_hash", "record_file", "record_file_sha256",
    "latency_ms", "usage",
}
_HISTORY_FIELDS = {
    "provider_failure_event_quarantine_count",
    "provider_failure_codes",
    "provider_failure_audit_commitment_set_sha256",
    "semantic_invalid_committed_response_count",
    "historical_unbound_request_preimage_count",
    "historical_remaining_case_failure_receipt_count",
    "historical_evidence_deleted", "historical_unbound_committed_set_sha256",
    "historical_response_commitment_set_sha256",
    "baseline_file", "baseline_file_sha256", "baseline_commitment_sha256",
    "expectation_file", "expectation_file_sha256",
    "expectation_commitment_sha256",
}
_RECEIPT_SUMMARY_FIELDS = {
    "file", "file_sha256", "receipt_commitment_sha256", "passed_count",
    "failed_count", "exit_code", "started_at_utc", "code_commitments",
    "project_identity_pre_sha256", "project_identity_post_sha256",
    "runner_environment_commitment_sha256", "pytest_contract",
    "native_attested",
}
_VERIFIER_EVIDENCE_FIELDS = {
    "verifier_source_file", "verifier_source_sha256", "verifier_test_file",
    "verifier_test_sha256", "native_launcher_contract",
}
_PYTEST_CONTRACT_FIELDS = {
    "schema_version", "exit_status", "collection_count",
    "collection_nodeids_sha256", "executed_count",
    "executed_nodeids_sha256", "passed_count", "failed_count",
    "skipped_count", "contract_sha256",
}
_FULL_NATIVE_CONTRACT_FIELDS = {
    "schema_version", "source_file", "source_identity",
    "build_script_file", "build_script_identity", "key_builder_file",
    "key_builder_identity", "build_record_file", "build_record_identity",
    "build_record_commitment_sha256", "compiler_file", "compiler_identity",
    "compiler_flags", "mode_defines", "key_injection",
    "attestation_version", "attestation_algorithm", "public_key_id",
    "build_id", "binary_contract_sha256", "bootstrap_anchor",
    "python_runtime_summary", "launchers", "contract_sha256",
}
_NATIVE_CONTRACT_FIELDS = {
    "schema_version", "build_id", "public_key_id",
    "binary_contract_sha256", "build_record_file",
    "build_record_commitment_sha256", "contract_sha256",
    "bootstrap_anchor", "python_runtime_summary", "launchers",
}
_NATIVE_BOOTSTRAP_ANCHOR_FIELDS = {"path", "mode", "size", "sha256"}
_FULL_NATIVE_LAUNCHER_FIELDS = {
    "file", "role", "read_policy", "build_sha256", "identity",
    "elf_class", "elf_data", "elf_type", "machine", "pt_interp",
    "pt_dynamic", "dt_needed_count", "static",
}
_COMPACT_NATIVE_RUNTIME_FIELDS = {
    "schema_version", "invocation", "manifest_sha256", "summary_sha256",
    "startup_code",
}
_COMPACT_NATIVE_STARTUP_FIELDS = {
    "schema_version", "strategy", "manifest_sha256", "summary_sha256",
}
_COMPACT_NATIVE_LAUNCHER_FIELDS = {
    "file", "role", "read_policy", "build_sha256", "identity",
}
_NATIVE_CONTRACT_SCHEMA_VERSION = "8.0"
_NATIVE_LAUNCHER_NAMES = {
    "receipt",
    "report_signer",
    "verifier",
    "live_enrichment_signer",
    "live_enrichment_verifier",
}
_NATIVE_LAUNCHER_CONTRACT = {
    "receipt": (
        "scripts/run_test_receipt",
        "receipt_signer",
        "opaque-execute-only",
    ),
    "report_signer": (
        "scripts/rerun_first_case_hard_gate",
        "report_signer",
        "opaque-execute-only",
    ),
    "verifier": (
        "scripts/verify_first_case_hard_gate",
        "public_verifier",
        "readable-public-key-only",
    ),
    "live_enrichment_signer": (
        "scripts/run_fail_fast_enrich",
        "live_enrichment_signer",
        "opaque-execute-only",
    ),
    "live_enrichment_verifier": (
        "scripts/verify_fail_fast_enrich",
        "live_enrichment_verifier",
        "readable-public-key-only",
    ),
}
_RUNTIME_IDENTITY_FIELDS = {
    "path", "type", "mode", "device", "inode", "links", "uid", "gid",
    "size", "mtime_ns", "ctime_ns", "sha256",
}
_RUNTIME_ELF_FIELDS = {
    "elf_class", "elf_data", "elf_type", "machine", "pt_interp",
    "dt_needed", "dt_soname", "dt_runpath", "dt_rpath",
}
_RUNTIME_INTERPRETER_FIELDS = {
    "path", "mode", "size", "device", "inode", "sha256", "identity",
    "elf", "loader_path",
}
_RUNTIME_FILE_FIELDS = {
    "role", "needed_name", "path", "mode", "size", "device", "inode",
    "sha256", "identity", "elf",
}
_VALIDATION_COUNT_FIELDS = {
    "family_mismatch", "invalid_location_count", "invalid_trace_location_count",
    "invalid_goal_count", "invalid_operation_count", "invalid_target_kind_count",
    "invalid_tool_class_count",
}
_USAGE_FIELDS = {
    "input_tokens", "cached_input_tokens", "cache_write_input_tokens",
    "output_tokens", "reasoning_output_tokens",
}
_HARD_GATE_FIELDS = {
    "record_current", "record_self_commitment_valid", "context_current",
    "prompt_v2_1_current", "strict_schema_current",
    "repeated_validation_matches", "structured_output_valid",
    "semantic_validation_valid", "action_dsl_valid",
    "repair_attempts_exact_0_1_2", "prompt_hashes_unique",
    "request_hashes_unique", "cache_keys_unique", "invocation_ids_unique",
    "current_requests_audit_bound", "cache_preimages_bound",
    "current_audit_lifecycle_valid", "forbidden_tool_item_count_zero",
    "unknown_event_count_zero", "provider_invocation_id_bound",
    "provider_request_id_kind_codex_thread_id",
    "historical_provider_failures_preserved",
    "historical_semantic_invalid_preserved", "historical_unbound_classified",
    "historical_unbound_set_exact", "historical_source_expectation_bound",
    "malformed_invalid_zero",
    "current_repair_attempts_bound", "final_record_response_only",
    "first_case_failure_receipt_absent", "scope_bounded_before_later_eight_p0",
    "no_trajectory_p1_gpu_training_started", "focused_receipt_current",
    "full_receipt_current", "canonical_test_collections_bound",
    "verifier_source_bound", "human_audit_unsigned",
}
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPORT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$")
_HISTORICAL_BASELINE_NAME = "historical-teacher-audit-baseline.json"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _require(condition: object, message: str) -> None:
    if condition is not True:
        raise ValueError(message)


def _secure_regular(path: Path, *, mode: int = 0o600) -> os.stat_result:
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode), "artifact is not regular")
    _require(info.st_nlink == 1, "artifact has ambiguous links")
    _require(stat.S_IMODE(info.st_mode) == mode, "artifact mode mismatch")
    return info


def _under(path: Path, parent: Path) -> Path:
    resolved = path.resolve(strict=True)
    resolved.relative_to(parent.resolve(strict=True))
    return resolved


def _canonical_report_path(output_root: Path, path: Path) -> Path:
    """Perform the lexical path contract without touching the filesystem."""

    reports = output_root / "reports"
    candidate = Path(os.path.abspath(Path(path)))
    if (
        candidate.parent != reports
        or not _REPORT_NAME.fullmatch(candidate.name)
    ):
        raise ValueError("report path escapes output reports directory")
    return reports / candidate.name


def _anchored_report_file(
    output_root: Path, path: Path, *, create: bool
) -> Path:
    """Anchor one JSON destination directly below output_root/reports."""

    output_root = Path(output_root).resolve(strict=True)
    reports = output_root / "reports"
    anchored = _canonical_report_path(output_root, path)
    report_fd = open_directory_fd(reports, create=create)
    os.close(report_fd)
    report_info = reports.lstat()
    if not stat.S_ISDIR(report_info.st_mode) or stat.S_ISLNK(report_info.st_mode):
        raise ValueError("report directory is unsafe")
    try:
        info = anchored.lstat()
    except FileNotFoundError:
        return anchored
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
    ):
        raise ValueError("report destination is unsafe")
    return anchored


def _require_distinct_artifact_paths(paths: list[Path]) -> None:
    """Reject lexical aliases and any existing inode identity alias."""

    if len(set(paths)) != len(paths):
        raise ValueError("report and receipt paths alias")
    identities: set[tuple[int, int]] = set()
    for path in paths:
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise ValueError("report and receipt identities alias")
        identities.add(identity)


def _artifact_fingerprint(path: Path) -> tuple[int, int, str]:
    info = _secure_regular(path)
    return (
        info.st_dev,
        info.st_ino,
        _sha256(_read_regular(path, limit=16 * 1024 * 1024)),
    )


def _receipt_fingerprints(
    focused_receipt: Path, full_receipt: Path
) -> dict[Path, tuple[int, int, str]]:
    return {
        focused_receipt: _artifact_fingerprint(focused_receipt),
        full_receipt: _artifact_fingerprint(full_receipt),
    }


def _require_receipts_unchanged(
    expected: dict[Path, tuple[int, int, str]],
) -> None:
    _require(
        all(_artifact_fingerprint(path) == token for path, token in expected.items()),
        "test receipt changed during report publication",
    )


def _report_snapshot(
    path: Path,
) -> tuple[tuple[int, int, str], bytes] | None:
    try:
        fingerprint = _artifact_fingerprint(path)
    except FileNotFoundError:
        return None
    return fingerprint, _read_regular(path, limit=16 * 1024 * 1024)


def _require_report_snapshot_unchanged(
    path: Path,
    snapshot: tuple[tuple[int, int, str], bytes] | None,
) -> None:
    if snapshot is None:
        _require(
            not path.exists() and not path.is_symlink(),
            "report destination changed before publication",
        )
        return
    _require(
        _artifact_fingerprint(path) == snapshot[0],
        "report destination changed before publication",
    )


def _restore_report_snapshot(
    path: Path,
    snapshot: tuple[tuple[int, int, str], bytes] | None,
) -> None:
    with AnchoredDirectory(path.parent) as reports:
        relative = Path(path.name)
        if snapshot is None:
            reports.unlink_regular(relative, missing_ok=True)
        else:
            reports.atomic_bytes(
                relative,
                snapshot[1],
                limit=16 * 1024 * 1024,
            )


def _publish_pass_report(
    path: Path,
    report: dict[str, Any],
    snapshot: tuple[tuple[int, int, str], bytes] | None,
) -> dict[str, Any]:
    """Final failure-atomic operation; successful publication has no recheck."""

    try:
        write_report(path, report)
    except Exception:
        try:
            _restore_report_snapshot(path, snapshot)
        except Exception as restore_error:
            raise RuntimeError(
                "fatal: PASS report restoration failed"
            ) from restore_error
        raise
    return report


def _expected_historical_baseline(root: Path) -> dict[str, Any]:
    expectation, _ = load_historical_expectation_with_evidence(root)
    _require(
        expectation["provider"] == PROVIDER
        and expectation["model"] == MODEL,
        "historical source expectation identity mismatch",
    )
    return historical_baseline_value(
        provider=PROVIDER,
        model=MODEL,
        historical_unbound_committed_count=expectation[
            "historical_unbound_committed_count"
        ],
        historical_unbound_committed_set_sha256=expectation[
            "historical_unbound_committed_set_sha256"
        ],
        historical_response_commitment_set_sha256=expectation[
            "historical_response_commitment_set_sha256"
        ],
        provider_failure_event_quarantine_count=expectation[
            "provider_failure_event_quarantine_count"
        ],
        provider_failure_codes=expectation["provider_failure_codes"],
        provider_failure_audit_commitment_set_sha256=expectation[
            "provider_failure_audit_commitment_set_sha256"
        ],
    )


def _load_first_case_historical_expectation(
    root: Path,
) -> tuple[dict[str, Any], dict[str, str]]:
    return load_historical_expectation_with_evidence(
        root,
        relative=_FIRST_CASE_HISTORICAL_EXPECTATION_RELATIVE,
        expectation_id=_FIRST_CASE_HISTORICAL_EXPECTATION_ID,
    )


def _validate_first_case_historical_delta(
    scan: dict[str, Any],
    baseline: dict[str, Any],
    cumulative: dict[str, Any],
) -> None:
    """Prove the cumulative first-case history is baseline plus two exact deltas."""

    _require(
        baseline.get("provider") == PROVIDER
        and cumulative.get("provider") == PROVIDER
        and baseline.get("provider") == cumulative.get("provider")
        and baseline.get("model") == MODEL
        and cumulative.get("model") == MODEL
        and baseline.get("model") == cumulative.get("model"),
        "historical expectation identity mismatch",
    )
    historical = scan.get("historical_unbound")
    failures = scan.get("provider_failure_commitments")
    _require(
        type(historical) is list
        and all(type(item) is dict for item in historical)
        and type(failures) is list
        and all(type(item) is dict for item in failures),
        "historical audit delta structure mismatch",
    )
    committed_delta = [
        item
        for item in historical
        if item.get("request_hash")
        == _FIRST_CASE_HISTORICAL_COMMITTED_DELTA["request_hash"]
    ]
    _require(
        len(committed_delta) == 1
        and all(
            committed_delta[0].get(field) == value
            for field, value in _FIRST_CASE_HISTORICAL_COMMITTED_DELTA.items()
        ),
        "historical committed delta mismatch",
    )
    prior_historical = [
        item
        for item in historical
        if item.get("request_hash")
        != _FIRST_CASE_HISTORICAL_COMMITTED_DELTA["request_hash"]
    ]
    _require(
        len(prior_historical)
        == baseline["historical_unbound_committed_count"]
        and _sha256(_canonical(prior_historical))
        == baseline["historical_unbound_committed_set_sha256"]
        and _sha256(
            _canonical(
                sorted(
                    item["response_commitment_sha256"]
                    for item in prior_historical
                )
            )
        )
        == baseline["historical_response_commitment_set_sha256"],
        "historical committed baseline delta mismatch",
    )

    failure_delta: list[dict[str, Any]] = []
    prior_failures: list[dict[str, str]] = []
    for item in failures:
        path = item.get("manifest_path")
        parts = Path(path).parts if type(path) is str else ()
        request_hash = (
            parts[2]
            if len(parts) == 6
            and parts[:2] == ("audit", "teacher")
            and parts[-2:] == ("attempt-00", "manifest.json")
            else None
        )
        if (
            request_hash
            == _FIRST_CASE_HISTORICAL_PROVIDER_FAILURE_DELTA["request_hash"]
        ):
            failure_delta.append(item)
        else:
            prior_failures.append(
                {
                    "failure_code": item["failure_code"],
                    "audit_commitment_sha256": item[
                        "audit_commitment_sha256"
                    ],
                }
            )
    _require(
        len(failure_delta) == 1
        and failure_delta[0].get("failure_code")
        == "provider_failure_event"
        and failure_delta[0].get("audit_commitment_sha256")
        == _FIRST_CASE_HISTORICAL_PROVIDER_FAILURE_DELTA[
            "audit_commitment_sha256"
        ],
        "historical provider failure delta mismatch",
    )
    prior_failures.sort(
        key=lambda item: (
            item["failure_code"], item["audit_commitment_sha256"]
        )
    )
    _require(
        len(prior_failures)
        == baseline["provider_failure_event_quarantine_count"]
        and _sha256(_canonical(prior_failures))
        == baseline["provider_failure_audit_commitment_set_sha256"]
        and baseline["provider_failure_codes"]
        == {
            "provider_failure_event": len(prior_failures),
        },
        "historical provider failure baseline delta mismatch",
    )
    _require(
        cumulative["historical_unbound_committed_count"]
        == baseline["historical_unbound_committed_count"] + 1
        and cumulative["provider_failure_event_quarantine_count"]
        == baseline["provider_failure_event_quarantine_count"] + 1
        and cumulative["provider_failure_codes"]
        == {
            "provider_failure_event": (
                baseline["provider_failure_event_quarantine_count"] + 1
            )
        },
        "historical cumulative expectation delta mismatch",
    )


def _historical_baseline_summary(
    baseline_path: Path,
    baseline: dict[str, Any],
) -> dict[str, str]:
    raw = _canonical(baseline) + b"\n"
    return {
        "baseline_file": f"reports/{baseline_path.name}",
        "baseline_file_sha256": _sha256(raw),
        "baseline_commitment_sha256": baseline[
            "baseline_commitment_sha256"
        ],
    }


def _read_historical_baseline(path: Path, *, root: Path) -> dict[str, Any]:
    _secure_regular(path)
    raw = _read_regular(path, limit=2 * 1024 * 1024)
    value = strict_json_loads(raw, max_bytes=2 * 1024 * 1024)
    _require(
        type(value) is dict
        and value == _expected_historical_baseline(root)
        and value.get("baseline_commitment_sha256")
        == historical_baseline_commitment(value),
        "historical baseline mismatch",
    )
    return value


def _validation_counts(validation: Any) -> dict[str, int | bool]:
    return {
        "family_mismatch": validation.family_mismatch,
        "invalid_location_count": len(validation.invalid_locations),
        "invalid_trace_location_count": len(validation.invalid_trace_locations),
        "invalid_goal_count": len(validation.invalid_goals),
        "invalid_operation_count": len(validation.invalid_operations),
        "invalid_target_kind_count": len(validation.invalid_target_kinds),
        "invalid_tool_class_count": len(validation.invalid_tool_classes),
    }


def _valid_runtime_identity(value: object, expected: dict[str, Any]) -> bool:
    return (
        type(value) is dict
        and set(value) == _RUNTIME_IDENTITY_FIELDS
        and value.get("type") == "regular"
        and value.get("links") == 1
        and type(value.get("mode")) is int
        and value["mode"] & 0o022 == 0
        and all(
            type(value.get(field)) is int and value[field] >= 0
            for field in (
                "device", "inode", "uid", "gid", "size", "mtime_ns",
                "ctime_ns",
            )
        )
        and type(value.get("path")) is str
        and Path(value["path"]).is_absolute()
        and _SHA256.fullmatch(str(value.get("sha256"))) is not None
        and all(
            value.get(field) == expected.get(field)
            for field in ("path", "mode", "size", "device", "inode", "sha256")
        )
    )


def _valid_runtime_elf(value: object, *, interpreter: bool) -> bool:
    if type(value) is not dict or set(value) != _RUNTIME_ELF_FIELDS:
        return False
    pt_interp = value.get("pt_interp")
    return (
        value.get("elf_class") == "ELF64"
        and value.get("elf_data") == "little-endian"
        and value.get("elf_type") in {"ET_EXEC", "ET_DYN"}
        and value.get("machine") == "EM_X86_64"
        and (
            type(pt_interp) is str and Path(pt_interp).is_absolute()
            if interpreter
            else pt_interp is None
            or type(pt_interp) is str and Path(pt_interp).is_absolute()
        )
        and type(value.get("dt_needed")) is list
        and len(value["dt_needed"]) == len(set(value["dt_needed"]))
        and all(
            type(item) is str and item and "/" not in item
            for item in value["dt_needed"]
        )
        and (
            value.get("dt_soname") is None
            or type(value["dt_soname"]) is str
            and value["dt_soname"]
            and "/" not in value["dt_soname"]
        )
        and type(value.get("dt_runpath")) is list
        and type(value.get("dt_rpath")) is list
        and not (value["dt_runpath"] and value["dt_rpath"])
        and all(
            type(item) is str and item
            for item in (*value["dt_runpath"], *value["dt_rpath"])
        )
    )


def _valid_startup_identity(
    value: object, expected: dict[str, Any], *, kind: str
) -> bool:
    return (
        type(value) is dict
        and set(value) == _RUNTIME_IDENTITY_FIELDS
        and value.get("type") == kind
        and type(value.get("links")) is int
        and value["links"] >= (1 if kind == "directory" else 1)
        and (kind == "directory" or value["links"] == 1)
        and type(value.get("mode")) is int
        and value["mode"] & 0o022 == 0
        and all(
            type(value.get(field)) is int and value[field] >= 0
            for field in (
                "device", "inode", "uid", "gid", "size", "mtime_ns",
                "ctime_ns",
            )
        )
        and type(value.get("path")) is str
        and Path(value["path"]).is_absolute()
        and (
            value.get("sha256") is None
            if kind == "directory"
            else _SHA256.fullmatch(str(value.get("sha256"))) is not None
        )
        and value.get("path") == expected.get("path")
    )


def _valid_import_roots_evidence(
    value: object, stdlib_root: str, lib_dynload_root: str
) -> bool:
    if type(value) is not dict or set(value) != {
        "compiled_prefix", "stdlib_root", "lib_dynload_root",
        "site_packages_roots", "expected_isolated_state",
    }:
        return False

    def valid_root(item: object) -> bool:
        if (
            type(item) is not dict
            or set(item) != {"raw_path", "resolved_path", "ancestor_chain"}
            or type(item.get("raw_path")) is not str
            or not Path(item["raw_path"]).is_absolute()
            or item.get("resolved_path") != item["raw_path"]
            or type(item.get("ancestor_chain")) is not list
            or not 2 <= len(item["ancestor_chain"]) <= 32
        ):
            return False
        expected = [Path("/")]
        current = Path("/")
        for component in Path(item["raw_path"]).parts[1:]:
            current = current / component
            expected.append(current)
        return len(expected) == len(item["ancestor_chain"]) and all(
            type(entry) is dict
            and set(entry) == {"path", "identity"}
            and entry.get("path") == str(path)
            and type(entry.get("identity")) is dict
            and set(entry["identity"]) == _RUNTIME_IDENTITY_FIELDS
            and entry["identity"].get("type") == "directory"
            and entry["identity"].get("path") == entry["path"]
            and entry["identity"].get("sha256") is None
            for path, entry in zip(
                expected, item["ancestor_chain"], strict=True
            )
        )

    sites = value.get("site_packages_roots")
    if (
        not valid_root(value.get("compiled_prefix"))
        or not valid_root(value.get("stdlib_root"))
        or not valid_root(value.get("lib_dynload_root"))
        or type(sites) is not list
        or any(not valid_root(item) for item in sites)
    ):
        return False
    prefix = Path(value["compiled_prefix"]["raw_path"])
    stdlib = Path(value["stdlib_root"]["raw_path"])
    dynload = Path(value["lib_dynload_root"]["raw_path"])
    version = stdlib.name.removeprefix("python")
    return (
        str(stdlib) == stdlib_root
        and str(dynload) == lib_dynload_root
        and stdlib.parent.parent == prefix
        and dynload == stdlib / "lib-dynload"
        and value.get("expected_isolated_state") == {
            "sys_path": [
                str(prefix / "lib" / f"python{version.replace('.', '')}.zip"),
                str(stdlib),
                str(dynload),
            ],
            "sys_prefix": str(prefix),
            "sys_base_prefix": str(prefix),
        }
    )


def _valid_extension_roots_evidence(
    value: object, files: list[dict[str, Any]]
) -> bool:
    return (
        type(value) is list
        and bool(value)
        and len({item.get("path") for item in value if type(item) is dict})
        == len(value)
        and all(
            type(item) is dict
            and set(item) == {"path", "source", "file_index"}
            and item.get("source") in {"lib-dynload", "site-packages"}
            and type(item.get("file_index")) is int
            and 0 <= item["file_index"] < len(files)
            and files[item["file_index"]].get("path") == item.get("path")
            for item in value
        )
    )


def _valid_runtime_preload_evidence(
    value: object, files: list[dict[str, Any]]
) -> bool:
    if (
        type(value) is not list
        or not value
        or value != sorted(set(value))
        or any(
            type(index) is not int or not 1 <= index < len(files)
            for index in value
        )
    ):
        return False
    selected = set(value)
    if any(
        item.get("role") == "dependency" and index not in selected
        for index, item in enumerate(files)
    ):
        return False
    loader_name = files[0].get("needed_name")
    by_soname: dict[str, int] = {}
    for index in value:
        soname = files[index]["elf"].get("dt_soname")
        if soname is not None:
            if soname in by_soname:
                return False
            by_soname[soname] = index
    positions = {file_index: position for position, file_index in enumerate(value)}
    for index in value:
        for needed_name in files[index]["elf"]["dt_needed"]:
            if needed_name == loader_name:
                continue
            dependency_index = by_soname.get(needed_name)
            if (
                dependency_index is None
                or positions[dependency_index] >= positions[index]
            ):
                return False
    for index, item in enumerate(files[1:], start=1):
        if index in selected:
            continue
        soname = item["elf"].get("dt_soname")
        representative = by_soname.get(soname) if soname is not None else None
        if (
            item.get("role") != "extension-root"
            or representative is None
            or files[representative].get("sha256") != item.get("sha256")
        ):
            return False
    return True


def _valid_python_startup_evidence(value: object) -> bool:
    if type(value) is not dict or set(value) != {
        "schema_version", "strategy", "pycache_prefix", "stdlib_root",
        "lib_dynload_root", "import_roots", "file_count", "directory_count",
        "absent_path_count", "total_bytes", "limits", "manifest_sha256",
        "summary_sha256",
    }:
        return False
    stdlib_root = value.get("stdlib_root")
    lib_dynload_root = value.get("lib_dynload_root")
    return (
        value.get("schema_version") == "2.0"
        and value.get("strategy")
        == "source-tree-no-bytecode-native-closure-v2"
        and value.get("pycache_prefix")
        == "/nonexistent/egsi-locked-pycache"
        and type(stdlib_root) is dict
        and set(stdlib_root) == {"path", "identity"}
        and _valid_startup_identity(
            stdlib_root.get("identity"), stdlib_root, kind="directory"
        )
        and type(lib_dynload_root) is dict
        and set(lib_dynload_root) == {"path", "identity"}
        and _valid_startup_identity(
            lib_dynload_root.get("identity"),
            lib_dynload_root,
            kind="directory",
        )
        and lib_dynload_root["path"]
        == str(Path(stdlib_root["path"]) / "lib-dynload")
        and _valid_import_roots_evidence(
            value.get("import_roots"),
            stdlib_root["path"],
            lib_dynload_root["path"],
        )
        and type(value.get("file_count")) is int
        and 1 <= value["file_count"] <= 4096
        and type(value.get("directory_count")) is int
        and 1 <= value["directory_count"] <= 1024
        and type(value.get("absent_path_count")) is int
        and 1 <= value["absent_path_count"] <= 16
        and type(value.get("total_bytes")) is int
        and 0 < value["total_bytes"] <= 64 * 1024 * 1024
        and value.get("limits") == {
            "max_files": 4096,
            "max_directories": 1024,
            "max_absent_paths": 16,
            "max_file_bytes": 4 * 1024 * 1024,
            "max_total_bytes": 64 * 1024 * 1024,
        }
        and _SHA256.fullmatch(str(value.get("manifest_sha256"))) is not None
        and value.get("summary_sha256")
        == _large_dict_commitment(value, "summary_sha256")
    )


def _valid_python_runtime_evidence(value: object) -> bool:
    if (
        type(value) is not dict
        or set(value) != {
            "schema_version", "invocation", "interpreter", "files",
            "preload_file_indices", "native_extension_roots", "startup_code",
            "limits", "manifest_sha256", "summary_sha256",
        }
        or value.get("schema_version") != "2.0"
        or value.get("invocation") != "glibc-loader-fd-preload-v2"
        or value.get("limits") != {
            "max_files": 256,
            "max_depth": 16,
            "max_file_bytes": 64 * 1024 * 1024,
            "max_total_bytes": 512 * 1024 * 1024,
        }
        or _SHA256.fullmatch(str(value.get("manifest_sha256"))) is None
        or value.get("summary_sha256")
        != _large_dict_commitment(value, "summary_sha256")
        or not _valid_python_startup_evidence(value.get("startup_code"))
    ):
        return False
    interpreter = value.get("interpreter")
    files = value.get("files")
    if (
        type(interpreter) is not dict
        or set(interpreter) != _RUNTIME_INTERPRETER_FIELDS
        or not _valid_runtime_identity(interpreter.get("identity"), interpreter)
        or not _valid_runtime_elf(interpreter.get("elf"), interpreter=True)
        or type(files) is not list
        or not 2 <= len(files) <= 256
    ):
        return False
    for index, item in enumerate(files):
        expected_roles = (
            {"loader"} if index == 0
            else {"dependency", "extension-root"}
        )
        if (
            type(item) is not dict
            or set(item) != _RUNTIME_FILE_FIELDS
            or item.get("role") not in expected_roles
            or type(item.get("needed_name")) is not str
            or not item["needed_name"]
            or "/" in item["needed_name"]
            or not _valid_runtime_identity(item.get("identity"), item)
            or not _valid_runtime_elf(item.get("elf"), interpreter=False)
            or not 0 < item.get("size", 0) <= 64 * 1024 * 1024
        ):
            return False
    return (
        interpreter.get("loader_path") == files[0].get("path")
        and len({item["path"] for item in files}) == len(files)
        and 0 < interpreter.get("size", 0) <= 64 * 1024 * 1024
        and interpreter["size"] + sum(item["size"] for item in files)
        <= 512 * 1024 * 1024
        and _valid_runtime_preload_evidence(
            value.get("preload_file_indices"), files
        )
        and _valid_extension_roots_evidence(
            value.get("native_extension_roots"), files
        )
    )


def _compact_native_launcher_contract(value: object) -> dict[str, Any]:
    """Project a validated full runner contract into bounded report evidence."""

    _require(
        type(value) is dict and set(value) == _FULL_NATIVE_CONTRACT_FIELDS,
        "full native launcher contract fields mismatch",
    )
    runtime = value["python_runtime_summary"]
    _require(
        type(runtime) is dict and _valid_python_runtime_evidence(runtime),
        "full native runtime evidence is invalid",
    )
    startup = runtime["startup_code"]
    launchers = value["launchers"]
    _require(
        type(launchers) is dict
        and set(launchers) == _NATIVE_LAUNCHER_NAMES
        and all(
            type(item) is dict
            and set(item) == _FULL_NATIVE_LAUNCHER_FIELDS
            for item in launchers.values()
        ),
        "full native launcher evidence is invalid",
    )
    return {
        "schema_version": value["schema_version"],
        "build_id": value["build_id"],
        "public_key_id": value["public_key_id"],
        "binary_contract_sha256": value["binary_contract_sha256"],
        "build_record_file": value["build_record_file"],
        "build_record_commitment_sha256": value[
            "build_record_commitment_sha256"
        ],
        "contract_sha256": value["contract_sha256"],
        "bootstrap_anchor": {
            "path": value["bootstrap_anchor"]["path"],
            "mode": value["bootstrap_anchor"]["mode"],
            "size": value["bootstrap_anchor"]["size"],
            "sha256": value["bootstrap_anchor"]["sha256"],
        },
        "python_runtime_summary": {
            "schema_version": runtime["schema_version"],
            "invocation": runtime["invocation"],
            "manifest_sha256": runtime["manifest_sha256"],
            "summary_sha256": runtime["summary_sha256"],
            "startup_code": {
                "schema_version": startup["schema_version"],
                "strategy": startup["strategy"],
                "manifest_sha256": startup["manifest_sha256"],
                "summary_sha256": startup["summary_sha256"],
            },
        },
        "launchers": {
            name: {
                "file": launchers[name]["file"],
                "role": launchers[name]["role"],
                "read_policy": launchers[name]["read_policy"],
                "build_sha256": launchers[name]["build_sha256"],
                "identity": dict(launchers[name]["identity"]),
            }
            for name in sorted(_NATIVE_LAUNCHER_NAMES)
        },
    }


def _valid_compact_launcher_identity(
    value: object, *, expected_file: str, mode: int, build_sha256: str
) -> bool:
    return (
        type(value) is dict
        and set(value) == _RUNTIME_IDENTITY_FIELDS
        and value.get("path") == expected_file
        and value.get("type") == "regular"
        and type(value.get("links")) is int
        and value["links"] == 1
        and type(value.get("mode")) is int
        and value["mode"] == mode
        and value.get("sha256") == build_sha256
        and _SHA256.fullmatch(str(value.get("sha256"))) is not None
        and all(
            type(value.get(field)) is int and value[field] >= 0
            for field in (
                "device", "inode", "uid", "gid", "size", "mtime_ns",
                "ctime_ns",
            )
        )
    )


def _valid_compact_native_launcher_contract(value: object) -> bool:
    if type(value) is not dict or set(value) != _NATIVE_CONTRACT_FIELDS:
        return False
    bootstrap = value.get("bootstrap_anchor")
    runtime = value.get("python_runtime_summary")
    if (
        value.get("schema_version") != _NATIVE_CONTRACT_SCHEMA_VERSION
        or value.get("build_record_file")
        != "configs/native-signer-build-record.json"
        or any(
            _SHA256.fullmatch(str(value.get(field))) is None
            for field in (
                "build_id", "public_key_id", "binary_contract_sha256",
                "build_record_commitment_sha256", "contract_sha256",
            )
        )
        or type(bootstrap) is not dict
        or set(bootstrap) != _NATIVE_BOOTSTRAP_ANCHOR_FIELDS
        or bootstrap.get("path") != "scripts/locked_runtime_bootstrap.py"
        or type(bootstrap.get("mode")) is not int
        or bootstrap["mode"] not in {0o444, 0o644}
        or type(bootstrap.get("size")) is not int
        or not 1 <= bootstrap["size"] <= 1024 * 1024
        or _SHA256.fullmatch(str(bootstrap.get("sha256"))) is None
        or type(runtime) is not dict
        or set(runtime) != _COMPACT_NATIVE_RUNTIME_FIELDS
        or runtime.get("schema_version") != "2.0"
        or runtime.get("invocation") != "glibc-loader-fd-preload-v2"
        or _SHA256.fullmatch(str(runtime.get("manifest_sha256"))) is None
        or _SHA256.fullmatch(str(runtime.get("summary_sha256"))) is None
    ):
        return False
    startup = runtime.get("startup_code")
    if (
        type(startup) is not dict
        or set(startup) != _COMPACT_NATIVE_STARTUP_FIELDS
        or startup.get("schema_version") != "2.0"
        or startup.get("strategy")
        != "source-tree-no-bytecode-native-closure-v2"
        or _SHA256.fullmatch(str(startup.get("manifest_sha256"))) is None
        or _SHA256.fullmatch(str(startup.get("summary_sha256"))) is None
    ):
        return False
    launchers = value.get("launchers")
    if type(launchers) is not dict or set(launchers) != _NATIVE_LAUNCHER_NAMES:
        return False
    for name, expected in _NATIVE_LAUNCHER_CONTRACT.items():
        launcher = launchers[name]
        file, role, read_policy = expected
        mode = 0o111 if read_policy == "opaque-execute-only" else 0o555
        if (
            type(launcher) is not dict
            or set(launcher) != _COMPACT_NATIVE_LAUNCHER_FIELDS
            or (
                launcher.get("file"), launcher.get("role"),
                launcher.get("read_policy"),
            )
            != expected
            or _SHA256.fullmatch(str(launcher.get("build_sha256"))) is None
            or not _valid_compact_launcher_identity(
                launcher.get("identity"),
                expected_file=file,
                mode=mode,
                build_sha256=launcher["build_sha256"],
            )
        ):
            return False
    return True


def _validate_compact_native_launcher_contract(
    value: object, full_contract: object
) -> None:
    expected = _compact_native_launcher_contract(full_contract)
    _require(
        _valid_compact_native_launcher_contract(value)
        and _canonical(value) == _canonical(expected),
        "compact native launcher evidence mismatch",
    )


def first_case_report_commitment(value: dict[str, Any]) -> str:
    return _dict_commitment(value, "report_commitment_sha256")


def _validate_report_schema(value: dict[str, Any]) -> None:
    _require(set(value) == _REPORT_FIELDS, "report fields mismatch")
    _require(set(value["scope"]) == _SCOPE_FIELDS, "scope fields mismatch")
    _require(
        set(value["invocations"]) == _INVOCATION_FIELDS,
        "invocation fields mismatch",
    )
    _require(
        type(value.get("prompt_contract")) is dict
        and set(value["prompt_contract"]) == _PROMPT_CONTRACT_FIELDS,
        "prompt contract fields mismatch",
    )
    _require(
        type(value["attempts"]) is list
        and len(value["attempts"]) == 3
        and all(type(item) is dict and set(item) == _ATTEMPT_FIELDS for item in value["attempts"]),
        "attempt fields mismatch",
    )
    for index, item in enumerate(value["attempts"]):
        _require(
            item["repair_attempt"] == index
            and item["repair_code"]
            == (None if index == 0 else "semantic_validation_failed")
            and all(
                _SHA256.fullmatch(str(item[field]))
                for field in (
                    "prompt_sha256", "request_hash", "cache_key",
                    "cache_file_sha256", "audit_file_sha256",
                )
            )
            and type(item["structured_output_valid"]) is bool
            and type(item["semantic_validation_valid"]) is bool
            and type(item["validation_diagnostic_counts"]) is dict
            and set(item["validation_diagnostic_counts"])
            == _VALIDATION_COUNT_FIELDS,
            "attempt contract mismatch",
        )
    _require(set(value["final"]) == _FINAL_FIELDS, "final fields mismatch")
    _require(
        value["final"]["provider"] == PROVIDER
        and value["final"]["model"] == MODEL
        and value["final"]["requested_model"] == MODEL
        and value["final"]["provider_request_id_kind"] == "codex_thread_id"
        and type(value["final"]["provider_invocation_id"]) is str
        and bool(value["final"]["provider_invocation_id"])
        and type(value["final"]["usage"]) is dict
        and set(value["final"]["usage"]) == _USAGE_FIELDS
        and all(
            type(count) is int and count >= 0
            for count in value["final"]["usage"].values()
        ),
        "final contract mismatch",
    )
    _require(
        set(value["historical_evidence"]) == _HISTORY_FIELDS,
        "history fields mismatch",
    )
    _require(
        all(
            _SHA256.fullmatch(
                str(value["historical_evidence"].get(field))
            )
            for field in (
                "historical_unbound_committed_set_sha256",
                "historical_response_commitment_set_sha256",
                "provider_failure_audit_commitment_set_sha256",
                "expectation_file_sha256",
                "expectation_commitment_sha256",
            )
        )
        and type(
            value["historical_evidence"].get("provider_failure_codes")
        )
        is dict,
        "historical unbound commitment mismatch",
    )
    _require(
        value["historical_evidence"]["baseline_file"]
        == f"reports/{_HISTORICAL_BASELINE_NAME}"
        and _SHA256.fullmatch(
            str(value["historical_evidence"]["baseline_file_sha256"])
        ) is not None
        and _SHA256.fullmatch(
            str(
                value["historical_evidence"][
                    "baseline_commitment_sha256"
                ]
            )
        ) is not None,
        "historical baseline evidence mismatch",
    )
    _require(
        set(value["test_receipts"]) == {"focused", "full"}
        and all(
            type(item) is dict and set(item) == _RECEIPT_SUMMARY_FIELDS
            for item in value["test_receipts"].values()
        ),
        "receipt summary fields mismatch",
    )
    for item in value["test_receipts"].values():
        _require(
            item["native_attested"] is False
            and type(item["code_commitments"]) is dict
            and set(item["code_commitments"])
            == {
                "source_tree_sha256",
                "tests_tree_sha256",
                "pyproject_toml_sha256",
                "pytest_local_inventory_sha256",
                "offline_test_runner_lock_sha256",
                "historical_expectation_sha256",
                "first_case_historical_expectation_sha256",
                "project_identity_sha256",
                "canonical_test_contract_sha256",
            }
            and type(item["pytest_contract"]) is dict
            and set(item["pytest_contract"]) == _PYTEST_CONTRACT_FIELDS
            and item["pytest_contract"]["schema_version"] == "1.0"
            and item["pytest_contract"]["exit_status"] == item["exit_code"]
            and item["pytest_contract"]["passed_count"] == item["passed_count"]
            and item["pytest_contract"]["failed_count"] == item["failed_count"]
            and item["pytest_contract"]["skipped_count"] == 0
            and item["pytest_contract"]["collection_count"] > 1
            and item["pytest_contract"]["executed_count"]
            == item["pytest_contract"]["collection_count"]
            and item["pytest_contract"]["executed_nodeids_sha256"]
            == item["pytest_contract"]["collection_nodeids_sha256"]
            and all(
                _SHA256.fullmatch(str(item[field]))
                for field in (
                    "file_sha256", "receipt_commitment_sha256",
                    "runner_environment_commitment_sha256",
                    "project_identity_pre_sha256",
                    "project_identity_post_sha256",
                )
            ),
            "receipt summary contract mismatch",
        )
        _require(
            item["project_identity_pre_sha256"]
            == item["project_identity_post_sha256"]
            == item["code_commitments"]["project_identity_sha256"],
            "receipt project identity mismatch",
        )
    _require(
        set(value["verifier_evidence"]) == _VERIFIER_EVIDENCE_FIELDS,
        "verifier evidence fields mismatch",
    )
    _require(
        all(
            _SHA256.fullmatch(str(value["verifier_evidence"][field]))
            for field in value["verifier_evidence"]
            if field.endswith("_sha256")
        ),
        "verifier evidence contract mismatch",
    )
    native = value["verifier_evidence"]["native_launcher_contract"]
    _require(
        _valid_compact_native_launcher_contract(native),
        "native launcher evidence contract mismatch",
    )
    _require(
        value.get("schema_version") == "5.2"
        and value.get("verifier_version") == VERIFIER_VERSION
        and value.get("native_attested") is False
        and value.get("attestation_mode") == "rerun_tests"
        and value.get("status") == "FIRST_CASE_GATE_PASSED"
        and type(value.get("hard_gates")) is dict
        and set(value["hard_gates"]) == _HARD_GATE_FIELDS
        and all(type(item) is bool for item in value["hard_gates"].values())
        and all(value["hard_gates"].values())
        and value.get("human_semantic_judgment") is None
        and value.get("human_audit_signed") is False
        and value.get("sensitive_material_included") is False
        and _SHA256.fullmatch(str(value.get("report_commitment_sha256")))
        and value["report_commitment_sha256"]
        == first_case_report_commitment(value),
        "report contract mismatch",
    )


def _receipt_summary(
    receipt_path: Path,
    *,
    root: Path,
    output_root: Path,
    name: str,
) -> dict[str, Any]:
    path = _under(receipt_path, output_root)
    receipt = validate_test_receipt(path, root=root, expected_name=name)
    raw = _read_regular(path, limit=2 * 1024 * 1024)
    return {
        "file": path.relative_to(output_root).as_posix(),
        "file_sha256": _sha256(raw),
        "native_attested": receipt["native_attested"],
        "receipt_commitment_sha256": receipt["receipt_commitment_sha256"],
        "passed_count": receipt["passed_count"],
        "failed_count": receipt["failed_count"],
        "exit_code": receipt["exit_code"],
        "started_at_utc": receipt["started_at_utc"],
        "project_identity_pre_sha256": receipt[
            "project_identity_pre_sha256"
        ],
        "project_identity_post_sha256": receipt[
            "project_identity_post_sha256"
        ],
        "code_commitments": receipt["code_commitments"],
        "runner_environment_commitment_sha256": receipt[
            "runner_environment_commitment_sha256"
        ],
        "pytest_contract": receipt["pytest_contract"],
    }


def _source_identity(
    root: Path, path: Path, *, mode: int
) -> tuple[str, str, str]:
    path = Path(path)
    _require(path.is_absolute(), "source evidence path is not absolute")
    relative = path.relative_to(root).as_posix()
    _require(path.resolve(strict=True) == path, "source evidence path is indirect")
    before = _secure_regular(path, mode=mode)
    raw = _read_regular(path)
    after = _secure_regular(path, mode=mode)
    metadata = lambda info: (
        stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode), info.st_dev,
        info.st_ino, info.st_nlink, info.st_uid, info.st_gid, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns,
    )
    _require(metadata(before) == metadata(after), "source evidence changed")
    digest = _sha256(raw)
    identity = {
        "path": relative,
        "type": "regular",
        "mode": stat.S_IMODE(after.st_mode),
        "device": after.st_dev,
        "inode": after.st_ino,
        "links": after.st_nlink,
        "uid": after.st_uid,
        "gid": after.st_gid,
        "size": after.st_size,
        "mtime_ns": after.st_mtime_ns,
        "ctime_ns": after.st_ctime_ns,
        "sha256": digest,
    }
    return relative, digest, _sha256(_canonical(identity))


def _source_evidence(root: Path) -> dict[str, Any]:
    source = Path(__file__).resolve(strict=True)
    test = (root / "tests/generation/test_first_case_hard_gate.py").resolve(
        strict=True
    )
    for path in (source, test):
        path.relative_to(root)
        _secure_regular(path, mode=0o644)
    native_launcher_contract = _compact_native_launcher_contract(
        load_runner_lock(root)["native_launcher_contract"]
    )
    return {
        "verifier_source_file": source.relative_to(root).as_posix(),
        "verifier_source_sha256": _sha256(_read_regular(source)),
        "verifier_test_file": test.relative_to(root).as_posix(),
        "verifier_test_sha256": _sha256(_read_regular(test)),
        "native_launcher_contract": native_launcher_contract,
    }


def _validate_current_compact_native_launcher_contract(
    root: Path, value: object
) -> None:
    """Recompute bounded evidence from the fully revalidated runner lock."""

    full_contract = load_runner_lock(root)["native_launcher_contract"]
    _validate_compact_native_launcher_contract(value, full_contract)


class _BoundedProcessCapture:
    """Drain one child pipe while retaining at most ``limit + 1`` bytes."""

    def __init__(self, stream: Any, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self.buffer = bytearray()
        self.overflow = False
        self.failed = False
        self.finished = threading.Event()
        self.thread = threading.Thread(target=self._read, daemon=True)

    def _read(self) -> None:
        try:
            while len(self.buffer) <= self._limit:
                remaining = self._limit + 1 - len(self.buffer)
                chunk = os.read(self._stream.fileno(), min(65_536, remaining))
                if not chunk:
                    break
                self.buffer.extend(chunk)
                if len(self.buffer) > self._limit:
                    self.overflow = True
                    break
        except (OSError, ValueError):
            self.failed = True
        finally:
            self.finished.set()


@dataclass(frozen=True, order=True)
class _LinuxProcessIdentity:
    """One Linux PID generation, protected from numeric PID reuse."""

    pid: int
    starttime: int


_LINUX_PID_T_MAX = (1 << 31) - 1
_LINUX_FD_MAX = (1 << 31) - 1
_MAX_PROCESS_CAPTURE_LIMIT_BYTES = 16 * 1024 * 1024
_PROCESS_SUPERVISOR_STDERR_LIMIT_BYTES = 64 * 1024
_PROCESS_SUPERVISOR_RESULT_OVERHEAD_BYTES = 16 * 1024
_PROCESS_SUPERVISOR_CLEANUP_BUDGET_SECONDS = 120.0
_MAX_PROCESS_TERMINATION_GRACE_SECONDS = 30.0
_MAX_PROCESS_SUPERVISOR_SOURCE_BYTES = 1024 * 1024
_MAX_PINNED_PYTHON_INTERPRETER_BYTES = 512 * 1024 * 1024
_PROCESS_SUPERVISOR_SHA256 = (
    "sha256:6fdb7832bdf89e8ef314253861014036766448abf4b5a913af050342b0d5799b"
)
_PROCESS_SUPERVISOR_RESULT_FIELDS = {
    "schema_version",
    "status",
    "returncode",
    "stdout_base64",
    "stderr_base64",
    "error_code",
}
_PROCESS_SUPERVISOR_ERROR_MESSAGES = {
    "capture_failed": "process output capture failed",
    "capture_limit": "process capture limit exceeded",
    "cleanup_failed": "process containment cleanup failed",
    "internal_error": "process supervisor failed",
    "launch_failed": "process launch failed",
    "namespace_unavailable": "process namespace unavailable",
    "terminated": "process supervisor terminated",
    "timeout": "process group timed out",
}
_SUPERVISOR_TERMINATION_GRACEFUL = "graceful_exit"
_SUPERVISOR_TERMINATION_FORCED = "forced_fallback"
_SUPERVISOR_TERMINATION_FAILED = "failed"
_PROCESS_SUPERVISOR_ACK_SLACK_SECONDS = 1.0


def _require_process_supervisor_capabilities() -> None:
    """Fail before Popen unless exact pidfd signalling is operational."""

    if (
        sys.platform != "linux"
        or not Path("/proc/self").is_dir()
        or not callable(getattr(os, "pidfd_open", None))
        or not callable(getattr(signal, "pidfd_send_signal", None))
    ):
        raise ValueError("process supervisor capabilities are unavailable")
    descriptor: int | None = None
    try:
        descriptor = os.pidfd_open(os.getpid(), 0)
        signal.pidfd_send_signal(descriptor, 0, None, 0)
    except (AttributeError, OSError, ValueError):
        raise ValueError(
            "process supervisor capabilities are unavailable"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _linux_pid_namespace_record(
    raw: bytes,
) -> tuple[int, list[int]] | None:
    """Parse one strict bounded procfs ``Pid``/``NSpid`` record."""

    pid_values: list[bytes] = []
    nspid_values: list[bytes] = []
    for line in raw.splitlines():
        key, separator, value = line.partition(b":")
        if not separator:
            continue
        if key == b"Pid":
            pid_values.append(value.strip())
        elif key == b"NSpid":
            nspid_values.append(value.strip())
    if len(pid_values) != 1 or len(nspid_values) != 1:
        return None
    nspid_fields = nspid_values[0].split()
    if (
        not re.fullmatch(rb"[1-9][0-9]*", pid_values[0])
        or not nspid_fields
        or len(nspid_fields) > 64
        or any(
            re.fullmatch(rb"[1-9][0-9]*", field) is None
            for field in nspid_fields
        )
    ):
        return None
    try:
        proc_pid = int(pid_values[0])
        nspids = [int(field) for field in nspid_fields]
    except (ValueError, OverflowError):
        return None
    if (
        proc_pid > _LINUX_PID_T_MAX
        or any(value > _LINUX_PID_T_MAX for value in nspids)
        or proc_pid != nspids[0]
    ):
        return None
    return proc_pid, nspids


def _read_linux_proc_record(
    pid: int,
    *,
    pidfd: int | None = None,
) -> tuple[_LinuxProcessIdentity, int] | None:
    """Read one bounded process identity and parent PID.

    A caller in a nested PID namespace can inherit a ``/proc`` mount from an
    ancestor namespace.  In that case its numeric ``pid`` does not name the
    same task below ``/proc``.  A pidfd maps the caller-local PID to the
    procfs-visible PID through its bounded ``fdinfo`` ``NSpid`` record.
    """

    if type(pid) is not int or not 0 < pid <= _LINUX_PID_T_MAX:
        return None
    descriptor = pidfd
    owns_descriptor = descriptor is None
    if owns_descriptor:
        pidfd_open = getattr(os, "pidfd_open", None)
        if not callable(pidfd_open):
            return None
        try:
            descriptor = pidfd_open(pid, 0)
        except (OSError, ValueError):
            return None
    try:
        if (
            type(descriptor) is not int
            or not 0 <= descriptor <= _LINUX_FD_MAX
        ):
            return None
        try:
            with open(
                f"/proc/self/fdinfo/{descriptor}", "rb", buffering=0
            ) as handle:
                fdinfo = handle.read(4097)
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            return None
        if len(fdinfo) > 4096:
            return None
        namespace_record = _linux_pid_namespace_record(fdinfo)
        if namespace_record is None:
            return None
        proc_pid, nspids = namespace_record
        try:
            with open("/proc/self/status", "rb", buffering=0) as handle:
                caller_status = handle.read(65_537)
        except (FileNotFoundError, PermissionError, OSError):
            return None
        if len(caller_status) > 65_536:
            return None
        caller_namespace = _linux_pid_namespace_record(caller_status)
        caller_pid = os.getpid()
        if (
            caller_namespace is None
            or type(caller_pid) is not int
            or not 0 < caller_pid <= _LINUX_PID_T_MAX
        ):
            return None
        caller_nspids = caller_namespace[1]
        caller_depth = len(caller_nspids) - 1
        if (
            caller_nspids[-1] != caller_pid
            or len(nspids) <= caller_depth
            or nspids[caller_depth] != pid
        ):
            return None
        try:
            with open(f"/proc/{proc_pid}/stat", "rb", buffering=0) as handle:
                raw = handle.read(4097)
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            return None
        if len(raw) > 4096:
            return None
        closing = raw.rfind(b") ")
        if closing < 1 or not raw.startswith(f"{proc_pid} (".encode("ascii")):
            return None
        fields = raw[closing + 2 :].split()
        if len(fields) < 20:
            return None
        try:
            parent_pid = int(fields[1])
            starttime = int(fields[19])
        except (ValueError, OverflowError):
            return None
        if (
            not 0 <= parent_pid <= _LINUX_PID_T_MAX
            or starttime < 0
        ):
            return None
        proc_parent_pid = parent_pid
        if parent_pid > 0:
            try:
                with open(
                    f"/proc/{parent_pid}/status", "rb", buffering=0
                ) as handle:
                    parent_status = handle.read(65_537)
            except (
                FileNotFoundError,
                ProcessLookupError,
                PermissionError,
                OSError,
            ):
                return None
            if len(parent_status) > 65_536:
                return None
            parent_namespace = _linux_pid_namespace_record(parent_status)
            if parent_namespace is None or parent_namespace[0] != parent_pid:
                return None
            parent_nspids = parent_namespace[1]
            if len(parent_nspids) <= caller_depth:
                parent_pid = 0
            elif len(parent_nspids) > len(nspids):
                return None
            else:
                parent_pid = parent_nspids[caller_depth]
        try:
            with open(f"/proc/{proc_pid}/stat", "rb", buffering=0) as handle:
                confirmed_raw = handle.read(4097)
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            return None
        if len(confirmed_raw) > 4096:
            return None
        confirmed_closing = confirmed_raw.rfind(b") ")
        if (
            confirmed_closing < 1
            or not confirmed_raw.startswith(f"{proc_pid} (".encode("ascii"))
        ):
            return None
        confirmed_fields = confirmed_raw[confirmed_closing + 2 :].split()
        if (
            len(confirmed_fields) < 20
            or confirmed_fields[1] != fields[1]
            or confirmed_fields[19] != fields[19]
        ):
            return None
        try:
            confirmed_parent_pid = int(confirmed_fields[1])
            confirmed_starttime = int(confirmed_fields[19])
        except (ValueError, OverflowError):
            return None
        if (
            not 0 <= confirmed_parent_pid <= _LINUX_PID_T_MAX
            or confirmed_starttime < 0
            or confirmed_parent_pid != proc_parent_pid
            or confirmed_starttime != starttime
        ):
            return None
        try:
            with open(
                f"/proc/self/fdinfo/{descriptor}", "rb", buffering=0
            ) as handle:
                confirmed_fdinfo = handle.read(4097)
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            return None
        if len(confirmed_fdinfo) > 4096 or confirmed_fdinfo != fdinfo:
            return None
        if _linux_pid_namespace_record(confirmed_fdinfo) != namespace_record:
            return None
        return _LinuxProcessIdentity(pid=pid, starttime=starttime), parent_pid
    finally:
        if (
            owns_descriptor
            and type(descriptor) is int
            and 0 <= descriptor <= _LINUX_FD_MAX
        ):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _proc_identity_is_current(identity: _LinuxProcessIdentity) -> bool:
    current = _read_linux_proc_record(identity.pid)
    return current is not None and current[0] == identity


def _open_process_identity(
    identity: _LinuxProcessIdentity,
    *,
    pidfd: int | None = None,
) -> int | None:
    """Return a pidfd only if it still names the exact PID generation.

    ``pidfd`` is a borrowed descriptor already pinned by a direct-child
    caller.  Without it, the legacy procfs precheck remains fail-closed before
    opening a descriptor for a mismatched generation.
    """

    descriptor = pidfd
    owns_descriptor = descriptor is None
    if owns_descriptor:
        current = _read_linux_proc_record(identity.pid)
        if current is None or current[0] != identity:
            return None
        try:
            descriptor = os.pidfd_open(identity.pid, 0)
        except (OSError, ValueError):
            return None
    retain_owned_descriptor = False
    try:
        if (
            type(descriptor) is not int
            or not 0 <= descriptor <= _LINUX_FD_MAX
        ):
            return None
        current = _read_linux_proc_record(identity.pid, pidfd=descriptor)
        if current is not None and current[0] == identity:
            retain_owned_descriptor = True
            return descriptor
        return None
    finally:
        if (
            owns_descriptor
            and not retain_owned_descriptor
            and type(descriptor) is int
            and 0 <= descriptor <= _LINUX_FD_MAX
        ):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _terminate_supervisor_process(
    process: subprocess.Popen[bytes],
    *,
    grace_seconds: float,
    root_pidfd: int | None,
) -> str:
    """Request exact outer cleanup, distinguishing ack chance from fallback."""

    def signal_unreaped_child(signum: int) -> bool:
        if root_pidfd is not None:
            try:
                signal.pidfd_send_signal(root_pidfd, signum, None, 0)
                return True
            except ProcessLookupError:
                return True
            except (OSError, ValueError):
                pass
        try:
            os.kill(process.pid, signum)
            return True
        except ProcessLookupError:
            return True
        except OSError:
            return False

    wait_seconds = max(1.0, grace_seconds)
    acknowledgement_wait = (
        wait_seconds + _PROCESS_SUPERVISOR_ACK_SLACK_SECONDS
    )
    if not signal_unreaped_child(signal.SIGTERM):
        if not signal_unreaped_child(signal.SIGKILL):
            return _SUPERVISOR_TERMINATION_FAILED
        try:
            process.wait(timeout=wait_seconds)
        except (OSError, subprocess.TimeoutExpired):
            return _SUPERVISOR_TERMINATION_FAILED
        return _SUPERVISOR_TERMINATION_FORCED
    try:
        process.wait(timeout=acknowledgement_wait)
    except subprocess.TimeoutExpired:
        if not signal_unreaped_child(signal.SIGKILL):
            return _SUPERVISOR_TERMINATION_FAILED
        try:
            process.wait(timeout=wait_seconds)
        except (OSError, subprocess.TimeoutExpired):
            return _SUPERVISOR_TERMINATION_FAILED
        return _SUPERVISOR_TERMINATION_FORCED
    except OSError:
        return _SUPERVISOR_TERMINATION_FAILED
    return _SUPERVISOR_TERMINATION_GRACEFUL


def _await_supervisor_launch_ready(
    descriptor: int, *, timeout_seconds: float
) -> None:
    """Boundedly wait until the outer has armed pre-gate SIGTERM control."""

    os.set_blocking(descriptor, False)
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            raw = os.read(descriptor, 2)
        except BlockingIOError:
            raw = None
        except InterruptedError:
            continue
        if raw is not None:
            _require(raw == b"R", "process supervisor control pin failed")
            return
        remaining = deadline - time.monotonic()
        _require(remaining > 0, "process supervisor control pin failed")
        time.sleep(min(0.005, remaining))


def _release_supervisor_launch_gate(
    descriptor: int, state: list[bool]
) -> None:
    """Release one gate while retaining conservative interrupt state."""

    _require(
        type(state) is list
        and len(state) == 2
        and all(type(item) is bool for item in state),
        "process supervisor launch state is invalid",
    )
    state[0] = True
    written = os.write(descriptor, b"G")
    if written == 1:
        state[1] = True
    _require(written == 1, "process supervisor control pin failed")


def _cleanup_supervisor_control_setup(
    process: subprocess.Popen[bytes],
    *,
    root_pidfd: int | None,
    grace_seconds: float,
    capture_limit: int,
    gate_state: list[bool],
) -> bool:
    """Boundedly reap a setup-stage direct child and validate any released gate."""

    if process.stdout is None or process.stderr is None:
        return False
    captures = (
        _BoundedProcessCapture(
            process.stdout,
            _process_supervisor_result_limit(capture_limit),
        ),
        _BoundedProcessCapture(
            process.stderr,
            _PROCESS_SUPERVISOR_STDERR_LIMIT_BYTES,
        ),
    )
    for capture in captures:
        capture.thread.start()
    outcome = _terminate_supervisor_process(
        process,
        grace_seconds=grace_seconds,
        root_pidfd=root_pidfd,
    )
    for capture in captures:
        capture.thread.join(timeout=max(1.0, grace_seconds))
    complete = (
        outcome != _SUPERVISOR_TERMINATION_FAILED
        and process.returncode is not None
        and not any(capture.thread.is_alive() for capture in captures)
        and not any(
            capture.failed or capture.overflow for capture in captures
        )
    )
    _close_process_pipes(process)
    if not complete:
        return False
    if not gate_state[0]:
        return True
    if outcome != _SUPERVISOR_TERMINATION_GRACEFUL:
        return False
    raw = bytes(captures[0].buffer)
    if _supervisor_cleanup_acknowledged(raw, capture_limit=capture_limit):
        return True
    try:
        value = strict_json_loads(
            raw,
            max_bytes=_process_supervisor_result_limit(capture_limit),
        )
    except (TypeError, ValueError):
        return False
    return (
        type(value) is dict
        and set(value) == _PROCESS_SUPERVISOR_RESULT_FIELDS
        and value.get("schema_version") == "1.0"
        and value.get("status") == "error"
        and value.get("returncode") is None
        and value.get("stdout_base64") == ""
        and value.get("stderr_base64") == ""
        and value.get("error_code")
        in ({"namespace_unavailable"} if gate_state[1] else {"internal_error"})
    )


def _supervisor_cleanup_acknowledged(
    raw: bytes, *, capture_limit: int
) -> bool:
    """Accept only the PID-1 exact-reap relay emitted for outer SIGTERM."""

    try:
        value = strict_json_loads(
            raw,
            max_bytes=_process_supervisor_result_limit(capture_limit),
        )
    except (TypeError, ValueError):
        return False
    return value == {
        "schema_version": "1.0",
        "status": "error",
        "returncode": None,
        "stdout_base64": "",
        "stderr_base64": "",
        "error_code": "terminated",
    }


def _close_process_pipes(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                pass


def _close_owned_descriptor(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _process_supervisor_source_path() -> Path:
    return Path(__file__).resolve(strict=True).with_name(
        "process_supervisor.py"
    )


def _process_source_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _open_sealed_process_supervisor_source() -> tuple[Path, int]:
    """Hash a stable source inode and copy it into a sealed executable fd."""

    source = Path(__file__).resolve(strict=True)
    supervisor = _process_supervisor_source_path()
    source_descriptor: int | None = None
    sealed_descriptor: int | None = None
    try:
        resolved = supervisor.resolve(strict=True)
        before = supervisor.lstat()
        source_stat = source.stat()
        source_descriptor = os.open(
            supervisor,
            os.O_RDONLY
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
            | os.O_NONBLOCK,
        )
        opened = os.fstat(source_descriptor)
    except OSError:
        if source_descriptor is not None:
            try:
                os.close(source_descriptor)
            except OSError:
                pass
        raise ValueError("process supervisor source is unavailable") from None
    try:
        _require(
            resolved == supervisor
            and stat.S_ISREG(before.st_mode)
            and stat.S_ISREG(opened.st_mode)
            and before.st_nlink == opened.st_nlink == 1
            and before.st_uid == opened.st_uid == source_stat.st_uid
            and before.st_mode & 0o022 == 0
            and 0 < before.st_size <= _MAX_PROCESS_SUPERVISOR_SOURCE_BYTES
            and _process_source_identity(before)
            == _process_source_identity(opened),
            "process supervisor source is unsafe",
        )
        chunks: list[bytes] = []
        size = 0
        while size <= _MAX_PROCESS_SUPERVISOR_SOURCE_BYTES:
            chunk = os.read(
                source_descriptor,
                min(
                    65_536,
                    _MAX_PROCESS_SUPERVISOR_SOURCE_BYTES + 1 - size,
                ),
            )
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        raw = b"".join(chunks)
        after_fd = os.fstat(source_descriptor)
        after_path = supervisor.lstat()
        _require(
            len(raw) == opened.st_size
            and len(raw) <= _MAX_PROCESS_SUPERVISOR_SOURCE_BYTES
            and _process_source_identity(before)
            == _process_source_identity(after_fd)
            == _process_source_identity(after_path)
            and _sha256(raw) == _PROCESS_SUPERVISOR_SHA256,
            "process supervisor source identity mismatch",
        )
        sealed_descriptor = os.memfd_create(
            "egsi-process-supervisor",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        offset = 0
        while offset < len(raw):
            written = os.write(sealed_descriptor, raw[offset:])
            if written <= 0:
                raise OSError("short supervisor memfd write")
            offset += written
        required_seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        fcntl.fcntl(
            sealed_descriptor,
            fcntl.F_ADD_SEALS,
            required_seals,
        )
        _require(
            fcntl.fcntl(sealed_descriptor, fcntl.F_GET_SEALS)
            & required_seals
            == required_seals,
            "process supervisor source seal failed",
        )
        os.lseek(sealed_descriptor, 0, os.SEEK_SET)
        return supervisor, sealed_descriptor
    except (OSError, ValueError):
        if sealed_descriptor is not None:
            try:
                os.close(sealed_descriptor)
            except OSError:
                pass
        raise
    finally:
        if source_descriptor is not None:
            try:
                os.close(source_descriptor)
            except OSError:
                pass


def _interpreter_identity(
    path: Path, info: os.stat_result, digest: str
) -> dict[str, object]:
    return {
        "path": str(path),
        "type": "regular",
        "mode": stat.S_IMODE(info.st_mode),
        "device": info.st_dev,
        "inode": info.st_ino,
        "links": info.st_nlink,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
        "sha256": digest,
    }


def _open_pinned_python_interpreter(
    contract: dict[str, Any] | None = None,
) -> int:
    """Copy validated ``sys.executable`` bytes into an immutable exec memfd.

    The official caller is already running beneath the native locked-runtime
    launcher.  This pin freezes the interpreter ELF and supervisor source; it
    does not make dynamic-loader, libpython, or stdlib path resolution atomic
    against a pre-existing same-UID host process racing those runtime paths.
    """

    command_executable = sys.executable
    source_descriptor: int | None = None
    sealed_descriptor: int | None = None
    try:
        command_path = Path(command_executable)
        resolved = command_path.resolve(strict=True)
        if contract is not None:
            _require(
                type(contract) is dict
                and contract.get("command_executable") == command_executable
                and contract.get("resolved_executable") == str(resolved)
                and type(contract.get("executable_identity")) is dict,
                "process supervisor interpreter contract mismatch",
            )
        before = resolved.lstat()
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        source_descriptor = os.open(resolved, flags)
        opened = os.fstat(source_descriptor)
        _require(
            stat.S_ISREG(before.st_mode)
            and stat.S_ISREG(opened.st_mode)
            and before.st_nlink == opened.st_nlink == 1
            and 0 < before.st_size <= _MAX_PINNED_PYTHON_INTERPRETER_BYTES
            and before.st_mode & 0o111 != 0
            and _process_source_identity(before)
            == _process_source_identity(opened),
            "process supervisor interpreter is unsafe",
        )
        remaining = opened.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(
                source_descriptor, min(1_048_576, remaining)
            )
            _require(bool(chunk), "process supervisor interpreter short read")
            chunks.append(chunk)
            remaining -= len(chunk)
        _require(
            os.read(source_descriptor, 1) == b"",
            "process supervisor interpreter grew during read",
        )
        after_fd = os.fstat(source_descriptor)
        after_path = resolved.lstat()
        raw = b"".join(chunks)
        digest = _sha256(raw)
        observed = _interpreter_identity(resolved, after_fd, digest)
        _require(
            len(raw) == opened.st_size
            and _process_source_identity(before)
            == _process_source_identity(opened)
            == _process_source_identity(after_fd)
            == _process_source_identity(after_path),
            "process supervisor interpreter identity mismatch",
        )
        if contract is not None:
            _require(
                contract["executable_identity"] == observed,
                "process supervisor interpreter contract mismatch",
            )
        sealed_descriptor = os.memfd_create(
            "egsi-python-interpreter",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        offset = 0
        while offset < len(raw):
            written = os.write(sealed_descriptor, raw[offset:])
            if written <= 0:
                raise OSError("short interpreter memfd write")
            offset += written
        os.fchmod(sealed_descriptor, stat.S_IMODE(opened.st_mode))
        required_seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        fcntl.fcntl(
            sealed_descriptor,
            fcntl.F_ADD_SEALS,
            required_seals,
        )
        sealed = os.fstat(sealed_descriptor)
        _require(
            stat.S_ISREG(sealed.st_mode)
            and stat.S_IMODE(sealed.st_mode) == stat.S_IMODE(opened.st_mode)
            and sealed.st_size == len(raw)
            and sealed.st_mode & 0o111 != 0
            and fcntl.fcntl(sealed_descriptor, fcntl.F_GET_SEALS)
            & required_seals
            == required_seals
            and _sha256(
                os.pread(sealed_descriptor, len(raw) + 1, 0)
            )
            == digest,
            "process supervisor interpreter seal failed",
        )
        result = sealed_descriptor
        sealed_descriptor = None
        return result
    except (OSError, RuntimeError, ValueError):
        if sealed_descriptor is not None:
            try:
                os.close(sealed_descriptor)
            except OSError:
                pass
        raise ValueError("process supervisor interpreter is unavailable") from None
    finally:
        if source_descriptor is not None:
            try:
                os.close(source_descriptor)
            except OSError:
                pass


def _process_supervisor_result_limit(capture_limit: int) -> int:
    encoded_stream_limit = 4 * ((capture_limit + 2) // 3)
    return (
        2 * encoded_stream_limit
        + _PROCESS_SUPERVISOR_RESULT_OVERHEAD_BYTES
    )


def _decode_process_supervisor_result(
    raw: bytes,
    *,
    command: list[str],
    capture_limit: int,
) -> subprocess.CompletedProcess[bytes]:
    """Strictly validate the bounded structured supervisor result."""

    try:
        value = strict_json_loads(
            raw,
            max_bytes=_process_supervisor_result_limit(capture_limit),
        )
    except (TypeError, ValueError):
        raise ValueError("process supervisor result is invalid") from None
    _require(
        type(value) is dict
        and set(value) == _PROCESS_SUPERVISOR_RESULT_FIELDS
        and value.get("schema_version") == "1.0"
        and value.get("status") in {"completed", "error"}
        and type(value.get("stdout_base64")) is str
        and type(value.get("stderr_base64")) is str,
        "process supervisor result is invalid",
    )
    try:
        stdout = base64.b64decode(
            value["stdout_base64"].encode("ascii"), validate=True
        )
        stderr = base64.b64decode(
            value["stderr_base64"].encode("ascii"), validate=True
        )
    except (UnicodeError, binascii.Error, ValueError):
        raise ValueError("process supervisor result is invalid") from None
    _require(
        len(stdout) <= capture_limit and len(stderr) <= capture_limit,
        "process supervisor result is invalid",
    )
    if value["status"] == "completed":
        returncode = value.get("returncode")
        _require(
            type(returncode) is int
            and -255 <= returncode <= 255
            and value.get("error_code") is None,
            "process supervisor result is invalid",
        )
        return subprocess.CompletedProcess(
            command,
            returncode,
            stdout=stdout,
            stderr=stderr,
        )
    error_code = value.get("error_code")
    _require(
        value.get("returncode") is None
        and stdout == b""
        and stderr == b""
        and type(error_code) is str
        and error_code in _PROCESS_SUPERVISOR_ERROR_MESSAGES,
        "process supervisor result is invalid",
    )
    raise ValueError(_PROCESS_SUPERVISOR_ERROR_MESSAGES[error_code])


def _run_bounded_process_group(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    termination_grace_seconds: float,
    capture_limit: int,
    _interpreter_contract: dict[str, Any] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run a target through a pinned, PID-namespaced supervisor."""

    _require(
        type(command) is list
        and bool(command)
        and all(type(item) is str and bool(item) for item in command),
        "process command is invalid",
    )
    _require(
        type(timeout_seconds) in {int, float}
        and not isinstance(timeout_seconds, bool)
        and math.isfinite(timeout_seconds)
        and timeout_seconds > 0,
        "process timeout is invalid",
    )
    _require(
        type(termination_grace_seconds) in {int, float}
        and not isinstance(termination_grace_seconds, bool)
        and math.isfinite(termination_grace_seconds)
        and 0 < termination_grace_seconds
        <= _MAX_PROCESS_TERMINATION_GRACE_SECONDS,
        "process termination grace is invalid",
    )
    _require(
        type(capture_limit) is int
        and 0 < capture_limit <= _MAX_PROCESS_CAPTURE_LIMIT_BYTES,
        "process capture limit is invalid",
    )
    try:
        target_cwd = Path(cwd).resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError("process cwd is invalid") from None
    _require(target_cwd.is_dir(), "process cwd is invalid")
    _require_process_supervisor_capabilities()
    supervisor_path, supervisor_source_fd = (
        _open_sealed_process_supervisor_source()
    )
    try:
        supervisor_interpreter_fd = _open_pinned_python_interpreter(
            _interpreter_contract
        )
    except Exception:
        os.close(supervisor_source_fd)
        raise
    launch_gate_read_fd: int | None = None
    launch_gate_write_fd: int | None = None
    launch_ready_read_fd: int | None = None
    launch_ready_write_fd: int | None = None
    try:
        launch_gate_read_fd, launch_gate_write_fd = os.pipe2(os.O_CLOEXEC)
        launch_ready_read_fd, launch_ready_write_fd = os.pipe2(os.O_CLOEXEC)
    except OSError:
        for descriptor in (
            launch_gate_read_fd,
            launch_gate_write_fd,
            launch_ready_read_fd,
            launch_ready_write_fd,
            supervisor_interpreter_fd,
            supervisor_source_fd,
        ):
            _close_owned_descriptor(descriptor)
        raise ValueError("process supervisor launch gate is unavailable") from None
    assert launch_gate_read_fd is not None
    assert launch_gate_write_fd is not None
    assert launch_ready_read_fd is not None
    assert launch_ready_write_fd is not None
    supervisor_command = [
        f"/proc/self/fd/{supervisor_interpreter_fd}",
        "-I",
        "-B",
        "-S",
        f"/proc/self/fd/{supervisor_source_fd}",
        "--launch-gate-fd",
        str(launch_gate_read_fd),
        "--launch-ready-fd",
        str(launch_ready_write_fd),
        "--cwd",
        str(target_cwd),
        "--timeout-seconds",
        repr(float(timeout_seconds)),
        "--termination-grace-seconds",
        repr(float(termination_grace_seconds)),
        "--capture-limit",
        str(capture_limit),
        "--",
        *command,
    ]
    try:
        process = subprocess.Popen(
            supervisor_command,
            cwd=supervisor_path.parent,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
            text=False,
            bufsize=0,
            close_fds=True,
            pass_fds=(
                supervisor_interpreter_fd,
                supervisor_source_fd,
                launch_gate_read_fd,
                launch_ready_write_fd,
            ),
        )
    except BaseException:
        for descriptor in (
            supervisor_interpreter_fd,
            supervisor_source_fd,
            launch_gate_read_fd,
            launch_gate_write_fd,
            launch_ready_read_fd,
            launch_ready_write_fd,
        ):
            _close_owned_descriptor(descriptor)
        raise
    root_pidfd: int | None = None
    gate_state = [False, False]
    try:
        _close_owned_descriptor(supervisor_interpreter_fd)
        supervisor_interpreter_fd = None
        _close_owned_descriptor(supervisor_source_fd)
        supervisor_source_fd = None
        _close_owned_descriptor(launch_gate_read_fd)
        launch_gate_read_fd = None
        _close_owned_descriptor(launch_ready_write_fd)
        launch_ready_write_fd = None
        try:
            # ``process`` is our unreaped direct child, so its caller-local PID
            # cannot be reused before this pin is opened even when procfs was
            # mounted by an ancestor PID namespace.
            root_pidfd = os.pidfd_open(process.pid, 0)
        except (ProcessLookupError, OSError):
            root_pidfd = None
        root_record = (
            _read_linux_proc_record(process.pid, pidfd=root_pidfd)
            if root_pidfd is not None
            else None
        )
        root_identity = root_record[0] if root_record is not None else None
        root_control_pinned = False
        if root_identity is not None:
            try:
                root_control_pinned = (
                    _open_process_identity(
                        root_identity,
                        pidfd=root_pidfd,
                    )
                    == root_pidfd
                )
            except OSError:
                root_control_pinned = False
        if not root_control_pinned:
            raise ValueError("process supervisor control pin failed")
        _await_supervisor_launch_ready(
            launch_ready_read_fd,
            timeout_seconds=max(1.0, termination_grace_seconds),
        )
        _release_supervisor_launch_gate(
            launch_gate_write_fd, gate_state
        )
        _close_owned_descriptor(launch_gate_write_fd)
        launch_gate_write_fd = None
        _close_owned_descriptor(launch_ready_read_fd)
        launch_ready_read_fd = None
    except BaseException as setup_error:
        for descriptor in (
            supervisor_interpreter_fd,
            supervisor_source_fd,
            launch_gate_read_fd,
            launch_gate_write_fd,
            launch_ready_read_fd,
            launch_ready_write_fd,
        ):
            try:
                os.close(descriptor)
            except BaseException:
                pass
        try:
            cleaned = _cleanup_supervisor_control_setup(
                process,
                root_pidfd=root_pidfd,
                grace_seconds=termination_grace_seconds,
                capture_limit=capture_limit,
                gate_state=gate_state,
            )
        except BaseException:
            cleaned = False
        if root_pidfd is not None:
            try:
                os.close(root_pidfd)
            except BaseException:
                cleaned = False
        if not cleaned:
            raise ValueError("process containment cleanup failed") from setup_error
        raise
    captures: tuple[_BoundedProcessCapture, _BoundedProcessCapture] | None = None
    started: list[threading.Thread] = []
    cleanup_needed = True
    cleanup_unconfirmed = False
    failure: str | None = None
    deadline = (
        time.monotonic()
        + timeout_seconds
        + _PROCESS_SUPERVISOR_CLEANUP_BUDGET_SECONDS
    )
    try:
        _require(
            process.stdout is not None and process.stderr is not None,
            "process supervisor pipes are unavailable",
        )
        stdout = _BoundedProcessCapture(
            process.stdout,
            _process_supervisor_result_limit(capture_limit),
        )
        stderr = _BoundedProcessCapture(
            process.stderr,
            _PROCESS_SUPERVISOR_STDERR_LIMIT_BYTES,
        )
        captures = (stdout, stderr)
        for capture in captures:
            capture.thread.start()
            started.append(capture.thread)
        while True:
            if any(capture.overflow for capture in captures):
                failure = "process supervisor capture limit exceeded"
                break
            if any(capture.failed for capture in captures):
                failure = "process supervisor output capture failed"
                break
            returncode = process.poll()
            if (
                returncode is not None
                and all(capture.finished.is_set() for capture in captures)
            ):
                cleanup_needed = False
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "process group timed out"
                break
            time.sleep(min(0.01, remaining))

        if failure is not None:
            if process.poll() is None:
                termination_outcome = _terminate_supervisor_process(
                    process,
                    grace_seconds=termination_grace_seconds,
                    root_pidfd=root_pidfd,
                )
                cleanup_needed = False
                for capture in captures:
                    capture.thread.join(
                        timeout=max(1.0, termination_grace_seconds)
                    )
                cleaned = (
                    termination_outcome
                    == _SUPERVISOR_TERMINATION_GRACEFUL
                    and not any(
                        capture.thread.is_alive() for capture in captures
                    )
                    and not any(
                        capture.failed or capture.overflow
                        for capture in captures
                    )
                    and _supervisor_cleanup_acknowledged(
                        bytes(stdout.buffer), capture_limit=capture_limit
                    )
                )
                if not cleaned:
                    cleanup_unconfirmed = True
            else:
                cleanup_needed = False
                cleanup_unconfirmed = True
            if cleanup_unconfirmed:
                raise ValueError("process containment cleanup failed")
            raise ValueError(failure)

        _require(
            process.returncode == 0
            and not stderr.buffer,
            "process supervisor failed",
        )
        return _decode_process_supervisor_result(
            bytes(stdout.buffer),
            command=command,
            capture_limit=capture_limit,
        )
    finally:
        if cleanup_needed:
            termination_outcome = (
                _terminate_supervisor_process(
                    process,
                    grace_seconds=termination_grace_seconds,
                    root_pidfd=root_pidfd,
                )
                if process.poll() is None
                else _SUPERVISOR_TERMINATION_FAILED
            )
            for capture in captures or ():
                capture.thread.join(
                    timeout=max(1.0, termination_grace_seconds)
                )
            retry_cleaned = (
                termination_outcome == _SUPERVISOR_TERMINATION_GRACEFUL
                and captures is not None
                and not any(
                    capture.thread.is_alive() for capture in captures
                )
                and not any(
                    capture.failed or capture.overflow
                    for capture in captures
                )
                and _supervisor_cleanup_acknowledged(
                    bytes(captures[0].buffer),
                    capture_limit=capture_limit,
                )
            )
            cleanup_unconfirmed = not retry_cleaned or cleanup_unconfirmed
        _close_process_pipes(process)
        for thread in started:
            thread.join(timeout=termination_grace_seconds)
        if any(thread.is_alive() for thread in started):
            cleanup_unconfirmed = True
        if root_pidfd is not None:
            try:
                os.close(root_pidfd)
            except OSError:
                pass
        if cleanup_unconfirmed:
            raise ValueError("process containment cleanup failed")

def _run_official_receipt_launcher(
    *, root: Path, name: str, output: Path
) -> dict[str, Any]:
    """Issue a receipt only through the pinned static native launcher."""

    _require(name in {"focused", "full"}, "receipt suite is invalid")
    _require(
        root == Path(__file__).resolve(strict=True).parents[3],
        "receipt launcher root differs from verifier source root",
    )
    launcher = root / "scripts/run_test_receipt"
    _require(
        launcher.resolve(strict=True) == launcher,
        "receipt launcher path is indirect",
    )
    _secure_regular(launcher, mode=0o111)
    command = [
        str(launcher),
        "--name", name,
        "--output", str(output),
    ]
    completed = _run_bounded_process_group(
        command,
        cwd=root,
        timeout_seconds=OFFICIAL_RECEIPT_LAUNCHER_TIMEOUT_SECONDS,
        termination_grace_seconds=_OFFICIAL_RECEIPT_TERMINATION_GRACE_SECONDS,
        capture_limit=_OFFICIAL_RECEIPT_CAPTURE_LIMIT_BYTES,
        _interpreter_contract=load_runner_lock(root),
    )
    _require(
        completed.returncode == 0,
        "official receipt launcher failed",
    )
    return validate_test_receipt(
        output, root=root, expected_name=name, require_success=True
    )


def _build_report(
    *,
    root: Path,
    output_root: Path,
    case_id: str,
    focused_receipt: Path,
    full_receipt: Path,
    historical_baseline_path: Path,
    historical_baseline: dict[str, Any],
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    output_root = output_root.resolve(strict=True)
    _require(
        historical_baseline == _expected_historical_baseline(root),
        "historical baseline contract mismatch",
    )
    historical_expectation, expectation_summary = (
        _load_first_case_historical_expectation(root)
    )
    historical_committed_count = historical_expectation[
        "historical_unbound_committed_count"
    ]
    expected_failure_codes = historical_expectation[
        "provider_failure_codes"
    ]
    provider_failure_count = historical_expectation[
        "provider_failure_event_quarantine_count"
    ]
    expected_quarantine_count = sum(expected_failure_codes.values())
    current_attempt_count = len(EXPECTED_ATTEMPTS)
    _require(
        expected_failure_codes.get("provider_failure_event")
        == provider_failure_count,
        "historical expectation failure total mismatch",
    )
    expected_manifest_count = (
        current_attempt_count
        + historical_committed_count
        + expected_quarantine_count
    )
    baseline_summary = _historical_baseline_summary(
        historical_baseline_path, historical_baseline
    )
    catalog = catalog_index(root)
    _require(case_id in catalog, "case is missing")
    case = catalog[case_id]
    context = build_oracle_context(root, case)
    vocabulary = allowed_action_values(root)
    prompt_vocabulary = _prompt_vocabulary(vocabulary)
    store = _load_store(root, case)
    record_path = output_root / "enrichment" / f"{case_id}.json"
    _secure_regular(record_path)
    record_raw = _read_regular(record_path, limit=2_097_152)
    record = EnrichmentRecord.model_validate_json(record_raw)
    _require(record.case_id == case_id, "record case mismatch")
    _require(record.generation_mode == "live", "record is not live")
    _require(
        record.provider == PROVIDER
        and record.model == MODEL
        and record.requested_model == MODEL,
        "record provider mismatch",
    )
    _require(
        record.record_commitment_sha256
        == enrichment_record_commitment(record.model_dump(mode="json")),
        "record commitment mismatch",
    )
    _require(
        _record_is_frozen_v21(root, case, record, provider=PROVIDER, model=MODEL),
        "record is stale",
    )
    repeated = _validate_frozen_v21_payload(
        case, record.payload, store, vocabulary
    )
    _require(repeated == record.validation and repeated.valid is True, "record validation mismatch")
    _require(
        record.structured_output_valid is True
        and record.validation.valid is True
        and not any(_validation_counts(record.validation).values()),
        "final semantic gate failed",
    )

    cache = TeacherCache(output_root / "cache/teacher")
    requests: list[TeacherRequest] = []
    responses: list[TeacherResponse] = []
    request_hashes: list[str] = []
    prompt_hashes: list[str] = []
    cache_keys: list[str] = []
    invocation_ids: list[str] = []
    attempt_reports: list[dict[str, Any]] = []
    for position, (repair_code, repair_attempt) in enumerate(EXPECTED_ATTEMPTS):
        system, user, schema = enrichment_request_v21(
            context,
            prompt_vocabulary,
            repair_error=repair_code,
            repair_attempt=repair_attempt,
        )
        envelope = strict_json_loads(user, max_bytes=2 * 1024 * 1024)
        _require(type(envelope) is dict, "prompt envelope malformed")
        _require(
            envelope["prompt_version"] == "2.1"
            and envelope["context_version"] == context.context_version
            and envelope["schema"] == schema
            and envelope["action_vocabulary"]
            == {key: sorted(value) for key, value in prompt_vocabulary.items()},
            "prompt contract mismatch",
        )
        request = TeacherRequest(
            system=system,
            user=user,
            schema=schema,
            temperature=0.0,
            max_tokens=8192,
        )
        request_hash = teacher_request_hash(request)
        prompt_hash = _sha256((system + user).encode("utf-8"))
        key = cache_key(PROVIDER, MODEL, request)
        cache_path = cache.path_for(key)
        _secure_regular(cache_path)
        cache_raw = _read_regular(cache_path, limit=2 * 1024 * 1024)
        cache_value = strict_json_loads(cache_raw, max_bytes=2 * 1024 * 1024)
        _require(type(cache_value) is dict, "cache preimage malformed")
        response = TeacherResponse.model_validate(cache_value)
        decoded = strict_json_loads(response.text, max_bytes=1_048_576)
        _require(type(decoded) is dict, "teacher response malformed")
        _require(
            not any(Draft202012Validator(schema).iter_errors(decoded)),
            "teacher response schema mismatch",
        )
        payload = EnrichmentPayload.model_validate(decoded)
        validation = _validate_frozen_v21_payload(
            case, payload, store, vocabulary
        )
        semantic_expected = position == 2
        _require(
            validation.valid is semantic_expected,
            "repair sequence semantic result mismatch",
        )
        if not semantic_expected:
            _require(
                bool(validation.invalid_trace_locations),
                "repair sequence failure category mismatch",
            )
        audit_paths = sorted(
            (output_root / "audit/teacher" / request_hash).glob(
                "*/attempt-00/manifest.json"
            )
        )
        _require(len(audit_paths) == 1, "request audit multiplicity mismatch")
        audit_path = audit_paths[0]
        _secure_regular(audit_path)
        audit_raw = _read_regular(audit_path, limit=2 * 1024 * 1024)
        manifest = _parse_object(audit_raw, "first-case audit")
        _validate_manifest_contract(manifest)
        _require(
            manifest["audit_commitment_sha256"]
            == _dict_commitment(manifest, "audit_commitment_sha256")
            and manifest["request_hash"] == request_hash
            and manifest["status"] == "committed"
            and manifest["failure_code"] is None
            and manifest["response_commitment_sha256"]
            == response.response_commitment_sha256,
            "current audit binding mismatch",
        )
        metadata_raw = _read_regular(
            audit_path.with_name("events.metadata.jsonl"),
            limit=2 * 1024 * 1024,
        )
        _require(
            manifest["events_metadata_length"] == len(metadata_raw)
            and manifest["events_metadata_sha256"] == _sha256(metadata_raw),
            "current audit metadata mismatch",
        )
        _, tool_count = _validate_metadata_lifecycle(metadata_raw, manifest)
        _require(tool_count == 0, "current audit tool event")
        _require(
            {child.name for child in audit_path.parent.iterdir()}
            == _expected_transaction_files(manifest),
            "current audit transaction set mismatch",
        )
        requests.append(request)
        responses.append(response)
        request_hashes.append(request_hash)
        prompt_hashes.append(prompt_hash)
        cache_keys.append(key)
        invocation_ids.append(manifest["invocation_id"])
        attempt_reports.append(
            {
                "repair_attempt": repair_attempt,
                "repair_code": repair_code,
                "prompt_sha256": prompt_hash,
                "request_hash": request_hash,
                "cache_key": key,
                "cache_file": cache_path.relative_to(output_root).as_posix(),
                "cache_file_sha256": _sha256(cache_raw),
                "audit_file": audit_path.relative_to(output_root).as_posix(),
                "audit_file_sha256": _sha256(audit_raw),
                "invocation_id": manifest["invocation_id"],
                "structured_output_valid": True,
                "semantic_validation_valid": validation.valid,
                "validation_diagnostic_counts": _validation_counts(validation),
            }
        )

    _require(
        len(set(prompt_hashes)) == current_attempt_count,
        "prompt hashes reused",
    )
    _require(
        len(set(request_hashes)) == current_attempt_count,
        "request hashes reused",
    )
    _require(
        len(set(cache_keys)) == current_attempt_count,
        "cache keys reused",
    )
    _require(
        len(set(invocation_ids)) == current_attempt_count,
        "invocation IDs reused",
    )
    _require(record.prompt_sha256 == prompt_hashes[-1], "record prompt mismatch")
    repair = _repair_info_v21(context, prompt_vocabulary, record)
    _require(
        repair["request_variant_verified"] is True
        and repair["repair_code"] == "semantic_validation_failed"
        and repair["request_repair_attempt"] == 2
        and repair["expected_teacher_request_hash"] == request_hashes[-1],
        "final request reconstruction mismatch",
    )
    final_response = responses[-1]
    _require(
        final_response.provider_request_id == record.provider_request_id
        and final_response.response_commitment_sha256
        == record.teacher_response_commitment_sha256
        and final_response.provider == record.provider
        and final_response.model == record.model
        and final_response.requested_model == record.requested_model
        and final_response.provider_response_model == record.provider_response_model
        and final_response.usage == record.usage
        and math.floor(final_response.latency_ms) == record.latency_ms,
        "final cache/record binding mismatch",
    )

    expected_requests = {
        teacher_request_hash(request): request for request in requests
    }
    scan = _scan_teacher_audit(
        output_root,
        PROVIDER,
        MODEL,
        expected_requests=expected_requests,
    )
    _require(
        scan["manifest_count"] == expected_manifest_count,
        "audit history count mismatch",
    )
    _require(
        scan["committed"] == current_attempt_count,
        "current bound commit count mismatch",
    )
    _require(
        scan["quarantined"] == expected_quarantine_count,
        "provider failure count mismatch",
    )
    _require(scan["malformed_invalid"] == 0, "malformed audit count mismatch")
    _require(
        scan["historical_unbound_committed"] == historical_committed_count,
        "historical unbound count mismatch",
    )
    _require(
        scan["historical_unbound_set_sha256"]
        == historical_expectation[
            "historical_unbound_committed_set_sha256"
        ],
        "historical unbound set mismatch",
    )
    _require(
        scan["historical_response_commitment_set_sha256"]
        == historical_expectation[
            "historical_response_commitment_set_sha256"
        ]
        and scan["failure_codes"]
        == historical_expectation["provider_failure_codes"]
        and scan["provider_failure_audit_commitment_set_sha256"]
        == historical_expectation[
            "provider_failure_audit_commitment_set_sha256"
        ],
        "historical response or failure commitment mismatch",
    )
    _require(scan["identity_mismatches"] == 0, "audit identity mismatch")
    _require(scan["tool_events"] == 0, "audit tool event mismatch")
    _require(
        scan["failure_codes"] == expected_failure_codes
        and scan["prior_provider_failure_count"] == provider_failure_count,
        "provider failure codes mismatch",
    )
    _validate_first_case_historical_delta(
        scan, historical_baseline, historical_expectation
    )
    for response, request_hash in zip(responses, request_hashes, strict=True):
        link = scan["by_response"].get(response.response_commitment_sha256)
        _require(
            type(link) is dict
            and link["request_hash"] == request_hash
            and link["cache_preimage_bound"] is True
            and link["provider_invocation_id"] == response.provider_request_id
            and link["provider_request_id_kind"] == "codex_thread_id",
            "current cache preimage audit binding mismatch",
        )

    all_manifest_paths = sorted(
        (output_root / "audit/teacher").rglob("manifest.json")
    )
    all_manifests: list[tuple[Path, dict[str, Any]]] = []
    for path in all_manifest_paths:
        _secure_regular(path)
        raw = _read_regular(path, limit=2 * 1024 * 1024)
        all_manifests.append((path, _parse_object(raw, "audit manifest")))
    _require(
        sum(item["status"] == "committed" for _, item in all_manifests)
        == current_attempt_count + historical_committed_count,
        "raw committed count mismatch",
    )
    historical_manifests = [
        (path, item)
        for path, item in all_manifests
        if item["status"] == "committed"
        and item["request_hash"] not in set(request_hashes)
    ]
    _require(
        len(historical_manifests) == historical_committed_count,
        "historical commit count mismatch",
    )
    cache_paths = sorted((output_root / "cache/teacher").glob("*.json"))
    _require(
        len(cache_paths) == current_attempt_count + historical_committed_count,
        "cache history count mismatch",
    )
    for path in cache_paths:
        _secure_regular(path)
    current_cache_paths = {cache.path_for(key) for key in cache_keys}
    historical_cache_paths = [
        path for path in cache_paths if path not in current_cache_paths
    ]
    _require(
        len(historical_cache_paths) == historical_committed_count,
        "historical cache count mismatch",
    )
    historical_responses: dict[str, TeacherResponse] = {}
    for path in historical_cache_paths:
        raw = _read_regular(path, limit=2 * 1024 * 1024)
        value = strict_json_loads(raw, max_bytes=2 * 1024 * 1024)
        _require(type(value) is dict, "historical cache malformed")
        response = TeacherResponse.model_validate(value)
        payload_value = strict_json_loads(response.text, max_bytes=1_048_576)
        _require(type(payload_value) is dict, "historical response malformed")
        payload = EnrichmentPayload.model_validate(payload_value)
        validation = _validate_frozen_v21_payload(
            case, payload, store, vocabulary
        )
        _require(validation.valid is False, "historical response not semantic-invalid")
        historical_responses[response.response_commitment_sha256] = response
    for path, manifest in historical_manifests:
        _validate_manifest_contract(manifest)
        _require(
            manifest["audit_commitment_sha256"]
            == _dict_commitment(manifest, "audit_commitment_sha256"),
            "historical audit commitment mismatch",
        )
        metadata = _read_regular(
            path.with_name("events.metadata.jsonl"), limit=2 * 1024 * 1024
        )
        _validate_metadata_lifecycle(metadata, manifest)
        _require(
            {child.name for child in path.parent.iterdir()}
            == _expected_transaction_files(manifest),
            "historical transaction set mismatch",
        )
        response = historical_responses.get(
            manifest["response_commitment_sha256"]
        )
        _require(
            response is not None
            and response.usage == manifest["usage"]
            and response.latency_ms == manifest["latency_ms"]
            and len(response.text.encode("utf-8")) == manifest["response_length"]
            and _sha256(response.text.encode("utf-8"))
            == manifest["response_sha256"],
            "historical cache/audit mismatch",
        )

    failure_path = output_root / "enrichment/failures" / f"{case_id}.json"
    _require(not failure_path.exists() and not failure_path.is_symlink(), "stale first-case receipt")
    remaining_failures = sorted(
        (output_root / "enrichment/failures").glob("*.json")
    )
    _require(len(remaining_failures) == 9, "remaining failure history mismatch")
    for path in remaining_failures:
        _secure_regular(path)
    positives = sorted(
        path
        for path in (output_root / "enrichment").glob("*.json")
        if path.name != "_batch-provenance.json"
    )
    _require(positives == [record_path], "unexpected positive record")
    _require(
        not any(path.is_file() for path in (output_root / "episodes").rglob("*"))
        and not any(
            path.is_file() for path in (output_root / "trajectories").rglob("*")
        ),
        "post-first-case stage artifacts exist",
    )

    receipt_summaries = {
        "focused": _receipt_summary(
            focused_receipt,
            root=root,
            output_root=output_root,
            name="focused",
        ),
        "full": _receipt_summary(
            full_receipt,
            root=root,
            output_root=output_root,
            name="full",
        ),
    }
    verifier_evidence = _source_evidence(root)
    _validate_current_compact_native_launcher_contract(
        root, verifier_evidence["native_launcher_contract"]
    )
    gates = {
        "record_current": _record_is_frozen_v21(
            root, case, record, provider=PROVIDER, model=MODEL
        ),
        "record_self_commitment_valid": record.record_commitment_sha256
        == enrichment_record_commitment(record.model_dump(mode="json")),
        "context_current": record.source_context_sha256 == context.sha256,
        "prompt_v2_1_current": True,
        "strict_schema_current": True,
        "repeated_validation_matches": repeated == record.validation,
        "structured_output_valid": record.structured_output_valid,
        "semantic_validation_valid": repeated.valid,
        "action_dsl_valid": not any(_validation_counts(repeated).values()),
        "repair_attempts_exact_0_1_2": [
            item["repair_attempt"] for item in attempt_reports
        ] == [attempt for _, attempt in EXPECTED_ATTEMPTS],
        "prompt_hashes_unique": len(set(prompt_hashes))
        == current_attempt_count,
        "request_hashes_unique": len(set(request_hashes))
        == current_attempt_count,
        "cache_keys_unique": len(set(cache_keys)) == current_attempt_count,
        "invocation_ids_unique": len(set(invocation_ids))
        == current_attempt_count,
        "current_requests_audit_bound": len(scan["by_response"])
        == current_attempt_count,
        "current_repair_attempts_bound": all(
            response.response_commitment_sha256 in scan["by_response"]
            for response in responses[:-1]
        ),
        "final_record_response_only": (
            record.teacher_response_commitment_sha256
            == final_response.response_commitment_sha256
            and scan["by_response"].get(
                record.teacher_response_commitment_sha256, {}
            ).get("request_hash")
            == request_hashes[-1]
        ),
        "cache_preimages_bound": all(
            item["cache_preimage_bound"] is True
            for item in scan["by_response"].values()
        ),
        "current_audit_lifecycle_valid": scan["committed"]
        == current_attempt_count,
        "forbidden_tool_item_count_zero": scan["tool_events"] == 0,
        "unknown_event_count_zero": scan["committed"]
        == current_attempt_count,
        "provider_invocation_id_bound": final_response.provider_request_id
        == record.provider_request_id,
        "provider_request_id_kind_codex_thread_id": True,
        "historical_provider_failures_preserved": scan[
            "prior_provider_failure_count"
        ]
        == provider_failure_count,
        "historical_semantic_invalid_preserved": len(historical_responses)
        == historical_committed_count,
        "historical_unbound_classified": scan[
            "historical_unbound_committed"
        ]
        == historical_committed_count,
        "historical_unbound_set_exact": scan[
            "historical_unbound_set_sha256"
        ]
        == historical_expectation[
            "historical_unbound_committed_set_sha256"
        ],
        "historical_source_expectation_bound": (
            scan["historical_response_commitment_set_sha256"]
            == historical_expectation[
                "historical_response_commitment_set_sha256"
            ]
            and scan["failure_codes"]
            == historical_expectation["provider_failure_codes"]
            and scan["provider_failure_audit_commitment_set_sha256"]
            == historical_expectation[
                "provider_failure_audit_commitment_set_sha256"
            ]
        ),
        "malformed_invalid_zero": scan["malformed_invalid"] == 0,
        "first_case_failure_receipt_absent": not failure_path.exists(),
        "scope_bounded_before_later_eight_p0": positives == [record_path],
        "no_trajectory_p1_gpu_training_started": True,
        "focused_receipt_current": receipt_summaries["focused"]["exit_code"] == 0,
        "full_receipt_current": receipt_summaries["full"]["exit_code"] == 0,
        "canonical_test_collections_bound": all(
            summary["pytest_contract"]["collection_count"] > 1
            and summary["pytest_contract"]["executed_count"]
            == summary["pytest_contract"]["collection_count"]
            and summary["pytest_contract"]["executed_nodeids_sha256"]
            == summary["pytest_contract"]["collection_nodeids_sha256"]
            for summary in receipt_summaries.values()
        ),
        "verifier_source_bound": all(
            _SHA256.fullmatch(value)
            for key, value in verifier_evidence.items()
            if key.endswith("_sha256")
        ) and _valid_compact_native_launcher_contract(
            verifier_evidence["native_launcher_contract"]
        ),
        "human_audit_unsigned": True,
    }
    _require(all(gates.values()), "hard-gate boolean failed")
    report: dict[str, Any] = {
        "schema_version": "5.2",
        "verifier_version": VERIFIER_VERSION,
        "native_attested": False,
        "attestation_mode": "rerun_tests",
        "status": "FIRST_CASE_GATE_PASSED",
        "case_id": case_id,
        "scope": {
            "output_root": output_root.relative_to(root).as_posix()
            if output_root.is_relative_to(root)
            else output_root.name,
            "remaining_p0_cases_run_in_this_smoke": 0,
            "historical_remaining_p0_case_ids_attempted": [
                "ghsa-3wfj-vh84-732p"
            ],
            "later_p0_cases_not_started": 8,
            "p1_started": False,
            "gpu_started": False,
            "training_started": False,
            "stop_marker": (
                "STOPPED_WITH_HISTORICAL_3WFJ_ATTEMPTS_BEFORE_"
                "LATER_EIGHT_P0_P1_GPU"
            ),
        },
        "invocations": {
            "baseline_before_smoke": 22,
            "added_by_smoke": current_attempt_count,
            "added_after_smoke_historical": (
                len(all_manifest_paths) - 22 - current_attempt_count
            ),
            "cumulative": len(all_manifest_paths),
            "committed_cumulative": (
                current_attempt_count + historical_committed_count
            ),
            "quarantined_cumulative": scan["quarantined"],
            "current_request_bound_committed": current_attempt_count,
            "current_final_record_committed": 1,
            "current_repair_attempt_committed": 2,
            "historical_unbound_committed": historical_committed_count,
            "malformed_invalid": scan["malformed_invalid"],
        },
        "prompt_contract": {
            "prompt_version": FROZEN_PROMPT_VERSION,
            "context_version": context.context_version,
            "source_context_sha256": context.sha256,
            "final_prompt_sha256": record.prompt_sha256,
            "strict_schema_sha256": _sha256(_canonical(requests[-1].schema)),
        },
        "hard_gates": gates,
        "attempts": attempt_reports,
        "final": {
            "provider": record.provider,
            "model": record.model,
            "requested_model": record.requested_model,
            "provider_response_model": record.provider_response_model,
            "provider_invocation_id": record.provider_request_id,
            "provider_request_id_kind": "codex_thread_id",
            "teacher_response_commitment_sha256": record.teacher_response_commitment_sha256,
            "record_commitment_sha256": record.record_commitment_sha256,
            "teacher_request_hash": request_hashes[-1],
            "record_file": record_path.relative_to(output_root).as_posix(),
            "record_file_sha256": _sha256(record_raw),
            "latency_ms": record.latency_ms,
            "usage": record.usage,
        },
        "historical_evidence": {
            "provider_failure_event_quarantine_count": provider_failure_count,
            "provider_failure_codes": scan["failure_codes"],
            "provider_failure_audit_commitment_set_sha256": scan[
                "provider_failure_audit_commitment_set_sha256"
            ],
            "semantic_invalid_committed_response_count": len(
                historical_responses
            ),
            "historical_unbound_request_preimage_count": (
                historical_committed_count
            ),
            "historical_remaining_case_failure_receipt_count": len(
                remaining_failures
            ),
            "historical_evidence_deleted": False,
            "historical_unbound_committed_set_sha256": scan[
                "historical_unbound_set_sha256"
            ],
            "historical_response_commitment_set_sha256": scan[
                "historical_response_commitment_set_sha256"
            ],
            **baseline_summary,
            **expectation_summary,
        },
        "test_receipts": receipt_summaries,
        "verifier_evidence": verifier_evidence,
        "human_semantic_judgment": None,
        "human_audit_signed": False,
        "sensitive_material_included": False,
        "report_commitment_sha256": "sha256:" + "0" * 64,
    }
    report["report_commitment_sha256"] = first_case_report_commitment(report)
    _validate_report_schema(report)
    return report


def verify_first_case_hard_gate(
    *,
    root: Path,
    output_root: Path,
    case_id: str,
    focused_receipt: Path,
    full_receipt: Path,
    report_path: Path,
    mode: str,
) -> dict[str, Any]:
    """Recompute every gate; optionally rerun both canonical test suites first."""

    try:
        if mode not in {"verify-only", "rerun-tests"}:
            raise ValueError
        root = Path(root).resolve(strict=True)
        output_root = Path(output_root).resolve(strict=True)
        create = mode == "rerun-tests"
        candidates = [
            _canonical_report_path(output_root, Path(report_path)),
            _canonical_report_path(output_root, Path(focused_receipt)),
            _canonical_report_path(output_root, Path(full_receipt)),
            _canonical_report_path(
                output_root,
                output_root / "reports" / _HISTORICAL_BASELINE_NAME,
            ),
        ]
        _require_distinct_artifact_paths(candidates)
        report_path = _anchored_report_file(
            output_root, candidates[0], create=create
        )
        focused_receipt = _anchored_report_file(
            output_root, candidates[1], create=create
        )
        full_receipt = _anchored_report_file(
            output_root, candidates[2], create=create
        )
        historical_baseline_path = _anchored_report_file(
            output_root, candidates[3], create=create
        )
        _require_distinct_artifact_paths(
            [
                report_path,
                focused_receipt,
                full_receipt,
                historical_baseline_path,
            ]
        )
        prior_report = _report_snapshot(report_path)
        if mode == "rerun-tests":
            _run_official_receipt_launcher(
                root=root,
                name="focused",
                output=focused_receipt,
            )
            _run_official_receipt_launcher(
                root=root,
                name="full",
                output=full_receipt,
            )
            historical_baseline = _expected_historical_baseline(root)
            write_report(historical_baseline_path, historical_baseline)
            committed_baseline = _read_historical_baseline(
                historical_baseline_path, root=root
            )
            _require(
                committed_baseline == historical_baseline,
                "historical baseline readback mismatch",
            )
        else:
            historical_baseline = _read_historical_baseline(
                historical_baseline_path, root=root
            )
        receipt_fingerprints = _receipt_fingerprints(
            focused_receipt, full_receipt
        )
        expected = _build_report(
            root=root,
            output_root=output_root,
            case_id=case_id,
            focused_receipt=focused_receipt,
            full_receipt=full_receipt,
            historical_baseline_path=historical_baseline_path,
            historical_baseline=historical_baseline,
        )
        _require_receipts_unchanged(receipt_fingerprints)
        if mode == "rerun-tests":
            _require(
                _read_historical_baseline(
                    historical_baseline_path, root=root
                )
                == historical_baseline,
                "historical baseline changed before report publication",
            )
            _require_report_snapshot_unchanged(report_path, prior_report)
            _require_receipts_unchanged(receipt_fingerprints)
            return _publish_pass_report(
                report_path, expected, prior_report
            )
        _secure_regular(report_path)
        raw = _read_regular(report_path, limit=16 * 1024 * 1024)
        observed = strict_json_loads(raw, max_bytes=16 * 1024 * 1024)
        if type(observed) is not dict:
            raise ValueError
        _validate_report_schema(observed)
        _validate_current_compact_native_launcher_contract(
            root, observed["verifier_evidence"]["native_launcher_contract"]
        )
        if observed != expected:
            raise ValueError
        return observed
    except Exception:
        raise ValueError("first-case hard gate verification failed") from None


def first_case_cli_main(argv: list[str], *, root: Path) -> int:
    """Locked-bootstrap-only CLI implementation for the native launcher."""

    root = Path(root).resolve(strict=True)
    marker = getattr(sys, "_egsi_locked_runtime_bootstrap", None)
    native_mode = (
        marker[1]
        if type(marker) is tuple
        and len(marker) == 2
        and marker[0] == str(root)
        and marker[1] in {"rerun-first-case", "verify-first-case"}
        else None
    )
    parser = argparse.ArgumentParser(
        prog=(
            "rerun_first_case_hard_gate"
            if native_mode == "rerun-first-case"
            else "verify_first_case_hard_gate"
        )
    )
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--focused-receipt", type=Path, required=True)
    parser.add_argument("--full-receipt", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    operation = parser.add_mutually_exclusive_group(required=True)
    if native_mode != "rerun-first-case":
        operation.add_argument("--mode", choices=("verify-only",))
    if native_mode != "verify-first-case":
        operation.add_argument(
            "--rerun-tests",
            action="store_true",
            help=(
                "Independently rerun both canonical offline suites and "
                "regenerate receipts/report."
            ),
        )
    arguments = parser.parse_args(argv)
    rerun_tests = bool(getattr(arguments, "rerun_tests", False))
    try:
        report = verify_first_case_hard_gate(
            root=root,
            output_root=arguments.output_root,
            case_id=arguments.case_id,
            focused_receipt=arguments.focused_receipt,
            full_receipt=arguments.full_receipt,
            report_path=arguments.report,
            mode=(
                "rerun-tests"
                if rerun_tests
                else getattr(arguments, "mode", None)
            ),
        )
    except ValueError:
        return 1
    print(
        json.dumps(
            {
                "case_id": report["case_id"],
                "execution_replayed": rerun_tests,
                "hard_gate_count": len(report["hard_gates"]),
                "status": report["status"],
                "stop_marker": report["scope"]["stop_marker"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0

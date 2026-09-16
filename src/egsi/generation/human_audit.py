"""Independent artifact replay and unsigned human-audit packet generation."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any

from egsi.contracts.enrichment import EnrichmentRecord
from egsi.contracts.trajectory import EpisodeEvent, T1Transition
from egsi.data.context import build_oracle_context
from egsi.generation.enrichment import (
    _load_store,
    _prompt_vocabulary,
    allowed_action_values,
    validate_payload,
)
from egsi.generation.pilot import (
    _dict_commitment,
    _episode_metrics,
    _load_committed_provenance,
    _read_jsonl,
    _read_regular,
    _sha256,
    catalog_index,
    read_case_ids,
)
from egsi.generation.replay import replay_events
from egsi.generation.safeio import AnchoredDirectory
from egsi.generation.trajectory import (
    compile_t1_episode,
    episode_commitment,
    read_parquet,
)
from egsi.teacher.prompts import (
    enrichment_request,
    enrichment_request_v21,
    enrichment_request_v22,
)
from egsi.teacher.base import TeacherRequest, TeacherResponse, teacher_request_hash
from egsi.teacher.cache import TeacherCache, cache_key
from egsi.strict_json import strict_json_loads


_MAX_PACKET_BYTES = 4 * 1024 * 1024
_MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_MAX_AUDIT_FILES = 4096
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_CACHE_FILE = re.compile(r"^[0-9a-f]{64}\.json$")
_SAFE_INVOCATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_ARTIFACT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$")
_USAGE_FIELDS = (
    "input_tokens",
    "cached_input_tokens",
    "cache_write_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
)
_REPAIR_CODES: tuple[str | None, ...] = (
    None,
    "invalid_structured_output",
    "semantic_validation_failed",
    "invalid_canonical_path",
    "invalid_teacher_response_metadata",
)
_FROZEN_V21_FIRST_CASE_ID = "ghsa-2m8h-fgr8-2q9w"
_FROZEN_V21_FIRST_CASE_ATTEMPTS: tuple[tuple[str | None, int], ...] = (
    (None, 0),
    ("semantic_validation_failed", 1),
    ("semantic_validation_failed", 2),
)
_TOOL_ITEM_TYPES = {
    "command_execution",
    "file_change",
    "mcp_tool_call",
    "collab_tool_call",
    "web_search",
    "todo_list",
    "unknown",
}
_KNOWN_EVENT_TYPES = {
    "thread.started",
    "turn.started",
    "item.completed",
    "turn.completed",
    "error",
    "turn.failed",
}
_KNOWN_ITEM_TYPES = {"reasoning", "agent_message"}
_MANIFEST_BASE_FIELDS = {
    "schema_version", "provider", "model", "requested_model",
    "provider_response_model", "cli_version", "request_hash", "invocation_id",
    "attempt", "status", "failure_code", "redacted_argv", "stdin_length",
    "stdin_sha256", "system_length", "system_sha256", "schema_length",
    "schema_sha256", "stdout_length", "stdout_sha256", "stderr_length",
    "stderr_sha256", "stderr_truncated_in_memory", "exit_code", "signal",
    "event_counts", "usage", "latency_ms", "max_tokens",
    "max_tokens_enforced_by_cli", "response_length", "response_sha256",
    "response_commitment_sha256", "events_metadata_length",
    "events_metadata_sha256", "audit_commitment_sha256",
}
_MANIFEST_PROVIDER_SCHEMA_FIELDS = {
    "provider_output_schema_transform",
    "provider_output_schema_length",
    "provider_output_schema_sha256",
}
_MANIFEST_EXECUTABLE_FIELDS = {
    "executable_id",
    "executable_sha256",
    "executable_stat",
    "executable_identity_commitment_sha256",
}
_HISTORICAL_BASELINE_FIELDS = {
    "schema_version",
    "attestation_kind",
    "attestation_mode",
    "provider",
    "model",
    "historical_unbound_committed_count",
    "historical_unbound_committed_set_sha256",
    "historical_response_commitment_set_sha256",
    "provider_failure_event_quarantine_count",
    "provider_failure_codes",
    "provider_failure_audit_commitment_set_sha256",
    "baseline_commitment_sha256",
}
_HISTORICAL_BASELINE_FILE = "historical-teacher-audit-baseline.json"
_HISTORICAL_EXPECTATION_RELATIVE = Path(
    "configs/historical-teacher-audit-expectation.v1.json"
)
_HISTORICAL_EXPECTATION_FIELDS = {
    "schema_version",
    "expectation_kind",
    "expectation_id",
    "provider",
    "model",
    "historical_unbound_committed_count",
    "historical_unbound_committed_set_sha256",
    "historical_response_commitment_set_sha256",
    "provider_failure_event_quarantine_count",
    "provider_failure_codes",
    "provider_failure_audit_commitment_set_sha256",
    "expectation_commitment_sha256",
}


class _ForbiddenToolMetadata(ValueError):
    def __init__(self, tool_events: int) -> None:
        super().__init__("forbidden tool item in teacher audit metadata")
        self.tool_events = tool_events


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _packet_commitment(packet: dict[str, Any]) -> str:
    value = dict(packet)
    value.pop("packet_commitment_sha256", None)
    return _sha256(_canonical(value))


def historical_baseline_commitment(value: dict[str, Any]) -> str:
    return _dict_commitment(value, "baseline_commitment_sha256")


def historical_baseline_value(
    *,
    provider: str,
    model: str,
    historical_unbound_committed_count: int,
    historical_unbound_committed_set_sha256: str,
    historical_response_commitment_set_sha256: str,
    provider_failure_event_quarantine_count: int,
    provider_failure_codes: dict[str, int],
    provider_failure_audit_commitment_set_sha256: str,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": "2.0",
        "attestation_kind": "historical_teacher_audit_observation",
        "attestation_mode": "rerun_tests",
        "provider": provider,
        "model": model,
        "historical_unbound_committed_count": (
            historical_unbound_committed_count
        ),
        "historical_unbound_committed_set_sha256": (
            historical_unbound_committed_set_sha256
        ),
        "historical_response_commitment_set_sha256": (
            historical_response_commitment_set_sha256
        ),
        "provider_failure_event_quarantine_count": (
            provider_failure_event_quarantine_count
        ),
        "provider_failure_codes": dict(sorted(provider_failure_codes.items())),
        "provider_failure_audit_commitment_set_sha256": (
            provider_failure_audit_commitment_set_sha256
        ),
        "baseline_commitment_sha256": "sha256:" + "0" * 64,
    }
    value["baseline_commitment_sha256"] = historical_baseline_commitment(value)
    return value


def historical_expectation_commitment(value: dict[str, Any]) -> str:
    return _dict_commitment(value, "expectation_commitment_sha256")


def historical_expectation_value(
    *,
    provider: str,
    model: str,
    historical_unbound_committed_count: int,
    historical_unbound_committed_set_sha256: str,
    historical_response_commitment_set_sha256: str,
    provider_failure_event_quarantine_count: int,
    provider_failure_codes: dict[str, int],
    provider_failure_audit_commitment_set_sha256: str,
    expectation_id: str = "p0-first-case-history-v1",
) -> dict[str, Any]:
    """Build the source-controlled v1 historical trust-root value."""

    value: dict[str, Any] = {
        "schema_version": "1.0",
        "expectation_kind": "historical_teacher_audit_expectation",
        "expectation_id": expectation_id,
        "provider": provider,
        "model": model,
        "historical_unbound_committed_count": (
            historical_unbound_committed_count
        ),
        "historical_unbound_committed_set_sha256": (
            historical_unbound_committed_set_sha256
        ),
        "historical_response_commitment_set_sha256": (
            historical_response_commitment_set_sha256
        ),
        "provider_failure_event_quarantine_count": (
            provider_failure_event_quarantine_count
        ),
        "provider_failure_codes": dict(sorted(provider_failure_codes.items())),
        "provider_failure_audit_commitment_set_sha256": (
            provider_failure_audit_commitment_set_sha256
        ),
        "expectation_commitment_sha256": "sha256:" + "0" * 64,
    }
    value["expectation_commitment_sha256"] = (
        historical_expectation_commitment(value)
    )
    return value


def _validate_historical_expectation(
    value: dict[str, Any], *, expectation_id: str
) -> None:
    if (
        type(expectation_id) is not str
        or not expectation_id
        or set(value) != _HISTORICAL_EXPECTATION_FIELDS
        or value.get("schema_version") != "1.0"
        or value.get("expectation_kind")
        != "historical_teacher_audit_expectation"
        or value.get("expectation_id") != expectation_id
        or type(value.get("provider")) is not str
        or not value["provider"]
        or type(value.get("model")) is not str
        or not value["model"]
        or not _nonnegative_integer(
            value.get("historical_unbound_committed_count")
        )
        or not _nonnegative_integer(
            value.get("provider_failure_event_quarantine_count")
        )
        or type(value.get("provider_failure_codes")) is not dict
        or any(
            type(code) is not str
            or not code
            or not _nonnegative_integer(count)
            for code, count in value["provider_failure_codes"].items()
        )
        or any(
            not _SHA256.fullmatch(str(value.get(field)))
            for field in (
                "historical_unbound_committed_set_sha256",
                "historical_response_commitment_set_sha256",
                "provider_failure_audit_commitment_set_sha256",
            )
        )
        or value.get("expectation_commitment_sha256")
        != historical_expectation_commitment(value)
    ):
        raise ValueError("historical expectation is invalid")


def _historical_expectation_stat_identity(
    info: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    """Metadata that must stay stable across one expectation-file read."""

    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_nlink,
        stat.S_IMODE(info.st_mode),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_mode,
    )


def _safe_historical_expectation_leaf(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) in {0o600, 0o644}
        and 0 <= info.st_size <= _MAX_MANIFEST_BYTES
    )


def _open_historical_expectation_directory_chain(path: Path) -> list[int]:
    """Pin every directory from / through the expectation's parent."""

    if os.name != "posix" or not path.is_absolute() or path.anchor != "/":
        raise ValueError
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors: list[int] = []
    try:
        descriptors.append(os.open(path.anchor, flags))
        for component in path.parts[1:]:
            if component in {"", ".", ".."} or "/" in component:
                raise ValueError
            descriptor = os.open(
                component, flags, dir_fd=descriptors[-1]
            )
            descriptors.append(descriptor)
        if any(
            not stat.S_ISDIR(os.fstat(descriptor).st_mode)
            for descriptor in descriptors
        ):
            raise ValueError
        return descriptors
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _close_historical_expectation_directory_chain(
    descriptors: list[int],
) -> None:
    for descriptor in reversed(descriptors):
        os.close(descriptor)


def load_historical_expectation_with_evidence(
    root: Path,
    *,
    relative: Path = _HISTORICAL_EXPECTATION_RELATIVE,
    expectation_id: str = "p0-first-case-history-v1",
) -> tuple[dict[str, Any], dict[str, str]]:
    """Load and attest one stable source expectation in one fd transaction."""

    root = Path(root).resolve(strict=True)
    if (
        not isinstance(relative, Path)
        or relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("historical expectation path is invalid")
    path = root / relative
    directory_chain: list[int] = []
    revalidated_chain: list[int] = []
    fd: int | None = None
    try:
        directory_chain = _open_historical_expectation_directory_chain(
            path.parent
        )
        parent_fd = directory_chain[-1]
        chain_before = tuple(
            _historical_expectation_stat_identity(os.fstat(descriptor))
            for descriptor in directory_chain
        )

        path_before = os.stat(
            path.name, dir_fd=parent_fd, follow_symlinks=False
        )
        if not _safe_historical_expectation_leaf(path_before):
            raise ValueError

        fd = os.open(
            path.name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        fd_before = os.fstat(fd)
        expected_identity = _historical_expectation_stat_identity(path_before)
        if (
            not _safe_historical_expectation_leaf(fd_before)
            or _historical_expectation_stat_identity(fd_before)
            != expected_identity
        ):
            raise ValueError

        chunks: list[bytes] = []
        remaining = fd_before.st_size
        while remaining:
            chunk = os.read(fd, min(1_048_576, remaining))
            if not chunk:
                raise ValueError
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise ValueError
        raw = b"".join(chunks)

        fd_after = os.fstat(fd)
        path_after = os.stat(
            path.name, dir_fd=parent_fd, follow_symlinks=False
        )
        chain_after = tuple(
            _historical_expectation_stat_identity(os.fstat(descriptor))
            for descriptor in directory_chain
        )
        revalidated_chain = _open_historical_expectation_directory_chain(
            path.parent
        )
        revalidated_identity = tuple(
            _historical_expectation_stat_identity(os.fstat(descriptor))
            for descriptor in revalidated_chain
        )
        if (
            len(raw) != fd_before.st_size
            or not _safe_historical_expectation_leaf(fd_after)
            or not _safe_historical_expectation_leaf(path_after)
            or _historical_expectation_stat_identity(fd_after)
            != expected_identity
            or _historical_expectation_stat_identity(path_after)
            != expected_identity
            or chain_after != chain_before
            or revalidated_identity != chain_before
        ):
            raise ValueError
    except (OSError, ValueError, OverflowError):
        raise ValueError("historical expectation file is unsafe") from None
    finally:
        if fd is not None:
            os.close(fd)
        _close_historical_expectation_directory_chain(revalidated_chain)
        _close_historical_expectation_directory_chain(directory_chain)

    value = _parse_object(raw, "historical teacher audit expectation")
    _validate_historical_expectation(value, expectation_id=expectation_id)
    evidence = {
        "expectation_file": relative.as_posix(),
        "expectation_file_sha256": _sha256(raw),
        "expectation_commitment_sha256": value[
            "expectation_commitment_sha256"
        ],
    }
    return value, evidence


def load_historical_expectation(
    root: Path,
    *,
    relative: Path = _HISTORICAL_EXPECTATION_RELATIVE,
    expectation_id: str = "p0-first-case-history-v1",
) -> dict[str, Any]:
    """Compatibility wrapper for callers that need only the parsed value."""

    value, _ = load_historical_expectation_with_evidence(
        root, relative=relative, expectation_id=expectation_id
    )
    return value


def historical_expectation_evidence(
    root: Path,
    *,
    relative: Path = _HISTORICAL_EXPECTATION_RELATIVE,
    expectation_id: str = "p0-first-case-history-v1",
) -> dict[str, str]:
    _, evidence = load_historical_expectation_with_evidence(
        root, relative=relative, expectation_id=expectation_id
    )
    return evidence


def _historical_baseline(
    root: Path,
    trajectory_root: Path,
    *,
    provider: str,
    model: str,
) -> dict[str, Any]:
    """Load output observation and compare only to the source trust root."""

    path = trajectory_root / "reports" / _HISTORICAL_BASELINE_FILE
    empty_set = _sha256(_canonical([]))
    expectation, expectation_evidence = (
        load_historical_expectation_with_evidence(root)
    )
    source_identity_valid = (
        expectation["provider"] == provider
        and expectation["model"] == model
    )
    try:
        info = path.lstat()
    except FileNotFoundError:
        empty_expected = (
            source_identity_valid
            and expectation["historical_unbound_committed_count"] == 0
            and expectation["historical_unbound_committed_set_sha256"]
            == empty_set
            and expectation["historical_response_commitment_set_sha256"]
            == empty_set
            and expectation["provider_failure_event_quarantine_count"] == 0
            and expectation["provider_failure_codes"] == {}
            and expectation[
                "provider_failure_audit_commitment_set_sha256"
            ]
            == empty_set
        )
        return {
            "present": False,
            "valid": empty_expected,
            "file": None,
            "file_sha256": None,
            "baseline_commitment_sha256": None,
            "observed_count": 0,
            "observed_set_sha256": empty_set,
            "observed_response_set_sha256": empty_set,
            "observed_provider_failure_count": 0,
            "observed_provider_failure_codes": {},
            "observed_provider_failure_audit_set_sha256": empty_set,
            "expectation": expectation,
            **expectation_evidence,
        }
    try:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError
        raw = _read_regular(path, limit=_MAX_MANIFEST_BYTES)
        value = _parse_object(raw, "historical teacher audit baseline")
        if (
            set(value) != _HISTORICAL_BASELINE_FIELDS
            or value.get("schema_version") != "2.0"
            or value.get("attestation_kind")
            != "historical_teacher_audit_observation"
            or value.get("attestation_mode") != "rerun_tests"
            or value.get("provider") != provider
            or value.get("model") != model
            or not _nonnegative_integer(
                value.get("historical_unbound_committed_count")
            )
            or not _SHA256.fullmatch(
                str(
                    value.get(
                        "historical_unbound_committed_set_sha256"
                    )
                )
            )
            or not _SHA256.fullmatch(
                str(
                    value.get(
                        "historical_response_commitment_set_sha256"
                    )
                )
            )
            or not _nonnegative_integer(
                value.get("provider_failure_event_quarantine_count")
            )
            or type(value.get("provider_failure_codes")) is not dict
            or any(
                type(code) is not str
                or not code
                or not _nonnegative_integer(count)
                for code, count in value["provider_failure_codes"].items()
            )
            or not _SHA256.fullmatch(
                str(
                    value.get(
                        "provider_failure_audit_commitment_set_sha256"
                    )
                )
            )
            or value.get("baseline_commitment_sha256")
            != historical_baseline_commitment(value)
        ):
            raise ValueError
        observed_matches_source = all(
            value[observed] == expectation[expected]
            for observed, expected in (
                (
                    "historical_unbound_committed_count",
                    "historical_unbound_committed_count",
                ),
                (
                    "historical_unbound_committed_set_sha256",
                    "historical_unbound_committed_set_sha256",
                ),
                (
                    "historical_response_commitment_set_sha256",
                    "historical_response_commitment_set_sha256",
                ),
                (
                    "provider_failure_event_quarantine_count",
                    "provider_failure_event_quarantine_count",
                ),
                ("provider_failure_codes", "provider_failure_codes"),
                (
                    "provider_failure_audit_commitment_set_sha256",
                    "provider_failure_audit_commitment_set_sha256",
                ),
            )
        )
        return {
            "present": True,
            "valid": source_identity_valid and observed_matches_source,
            "file": f"reports/{_HISTORICAL_BASELINE_FILE}",
            "file_sha256": _sha256(raw),
            "baseline_commitment_sha256": value[
                "baseline_commitment_sha256"
            ],
            "observed_count": value[
                "historical_unbound_committed_count"
            ],
            "observed_set_sha256": value[
                "historical_unbound_committed_set_sha256"
            ],
            "observed_response_set_sha256": value[
                "historical_response_commitment_set_sha256"
            ],
            "observed_provider_failure_count": value[
                "provider_failure_event_quarantine_count"
            ],
            "observed_provider_failure_codes": value[
                "provider_failure_codes"
            ],
            "observed_provider_failure_audit_set_sha256": value[
                "provider_failure_audit_commitment_set_sha256"
            ],
            "expectation": expectation,
            **expectation_evidence,
        }
    except Exception:
        return {
            "present": True,
            "valid": False,
            "file": f"reports/{_HISTORICAL_BASELINE_FILE}",
            "file_sha256": None,
            "baseline_commitment_sha256": None,
            "observed_count": None,
            "observed_set_sha256": None,
            "observed_response_set_sha256": None,
            "observed_provider_failure_count": None,
            "observed_provider_failure_codes": None,
            "observed_provider_failure_audit_set_sha256": None,
            "expectation": expectation,
            **expectation_evidence,
        }


def _parse_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = strict_json_loads(raw, max_bytes=_MAX_MANIFEST_BYTES)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError(f"{label} is invalid") from None
    if type(value) is not dict:
        raise ValueError(f"{label} is invalid")
    return value


def _manifest_expectation(
    enrichment_root: Path, case_ids: list[str]
) -> tuple[dict[str, EnrichmentRecord], dict[str, Any], dict[str, Any], str]:
    raw = _read_regular(
        enrichment_root / "_batch-provenance.json", limit=_MAX_MANIFEST_BYTES
    )
    manifest_sha256 = _sha256(raw)
    manifest = _parse_object(raw, "enrichment provenance manifest")
    expected = {
        "generation_mode": manifest.get("generation_mode"),
        "provider": manifest.get("provider"),
        "model": manifest.get("model"),
        "requested_provider": manifest.get("requested_provider"),
        "requested_model": manifest.get("requested_model"),
        "provider_response_models": manifest.get("provider_response_models"),
        "provider_response_model_counts": manifest.get(
            "provider_response_model_counts"
        ),
        "manifest_sha256": manifest_sha256,
        "batch_commitment_sha256": manifest.get("batch_commitment_sha256"),
    }
    records, trusted = _load_committed_provenance(
        enrichment_root, case_ids, expected
    )
    entries = manifest.get("artifacts")
    coverage = {
        entry.get("case_id"): entry
        for entry in entries
        if type(entry) is dict and type(entry.get("case_id")) is str
    }
    return records, trusted, coverage, manifest_sha256


def _validate_trajectory_manifest(
    trajectory_root: Path,
    case_ids: list[str],
    provenance_sha256: str,
) -> tuple[dict[str, Any] | None, dict[tuple[str, str], dict[str, str]], dict[str, Any]]:
    path = trajectory_root / "reports/trajectory-artifact-manifest.json"
    try:
        raw = _read_regular(path, limit=_MAX_MANIFEST_BYTES)
    except FileNotFoundError:
        return None, {}, {
            "manifest_sha256": None,
            "manifest_valid": False,
            "artifact_commitment_sha256": None,
        }
    manifest = _parse_object(raw, "trajectory artifact manifest")
    required = {
        "schema_version",
        "stage",
        "requested_case_ids",
        "processed_case_ids",
        "provenance_manifest_sha256",
        "artifacts",
        "artifact_commitment_sha256",
    }
    valid = (
        set(manifest) == required
        and manifest.get("schema_version") == "1.0"
        and manifest.get("stage") == "trajectory_artifacts"
        and manifest.get("requested_case_ids") == case_ids
        and manifest.get("processed_case_ids")
        == [case_id for case_id in case_ids if case_id in manifest.get("processed_case_ids", [])]
        and manifest.get("provenance_manifest_sha256") == provenance_sha256
        and type(manifest.get("artifacts")) is list
        and _dict_commitment(manifest, "artifact_commitment_sha256")
        == manifest.get("artifact_commitment_sha256")
    )
    entries: dict[tuple[str, str], dict[str, str]] = {}
    if type(manifest.get("artifacts")) is list:
        for item in manifest["artifacts"]:
            if type(item) is not dict or set(item) != {
                "relative_path",
                "sha256",
                "case_id",
                "kind",
            }:
                valid = False
                continue
            relative = item.get("relative_path")
            sha256 = item.get("sha256")
            case_id = item.get("case_id")
            kind = item.get("kind")
            if (
                type(relative) is not str
                or not _SAFE_ARTIFACT.fullmatch(relative)
                or Path(relative).is_absolute()
                or ".." in Path(relative).parts
                or type(sha256) is not str
                or not _SHA256.fullmatch(sha256)
                or type(case_id) is not str
                or type(kind) is not str
                or kind
                not in {
                    "episode_events",
                    "episode_transitions",
                    "trajectory_parquet",
                }
            ):
                valid = False
                continue
            key = (case_id, kind)
            if key in entries:
                valid = False
                continue
            entries[key] = {
                "relative_path": relative,
                "sha256": sha256,
                "case_id": case_id,
                "kind": kind,
            }
    return manifest, entries, {
        "manifest_sha256": _sha256(raw),
        "manifest_valid": valid,
        "artifact_commitment_sha256": manifest.get(
            "artifact_commitment_sha256"
        ),
    }


def _bounded_percentile(values: list[int | float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    return float(
        ordered[lower]
        + (ordered[upper] - ordered[lower]) * (position - lower)
    )


def _latency_summary(values: list[int | float]) -> dict[str, int | float]:
    if not values:
        return {"min": 0, "median": 0.0, "p95": 0.0, "max": 0}
    return {
        "min": min(values),
        "median": _bounded_percentile(values, 0.5),
        "p95": _bounded_percentile(values, 0.95),
        "max": max(values),
    }


def _repair_info(
    context: Any,
    vocabulary: dict[str, set[str]],
    record: EnrichmentRecord,
) -> dict[str, Any]:
    unmatched = object()
    matched: tuple[str | None, int] | object = unmatched
    variants = [(None, 0)] + [
        (repair_code, repair_attempt)
        for repair_code in _REPAIR_CODES[1:]
        for repair_attempt in (1, 2)
    ]
    for repair_code, repair_attempt in variants:
        system, user, _ = enrichment_request(
            context,
            vocabulary,
            repair_error=repair_code,
            repair_attempt=repair_attempt,
        )
        digest = _sha256((system + user).encode("utf-8"))
        if digest == record.prompt_sha256:
            matched = (repair_code, repair_attempt)
            break
    if matched is unmatched:
        return {
            "request_variant_verified": False,
            "repair_prompt_used": None,
            "repair_code": None,
            "request_repair_attempt": None,
            "minimum_enrichment_attempts": None,
            "expected_teacher_request_hash": None,
        }
    repair_code, repair_attempt = matched
    system, user, schema = enrichment_request(
        context,
        vocabulary,
        repair_error=repair_code,
        repair_attempt=repair_attempt,
    )
    request_hash = teacher_request_hash(
        TeacherRequest(
            system=system,
            user=user,
            schema=schema,
            temperature=0.0,
            max_tokens=8192,
        )
    )
    return {
        "request_variant_verified": True,
        "repair_prompt_used": repair_code is not None,
        "repair_code": repair_code,
        "request_repair_attempt": repair_attempt,
        "minimum_enrichment_attempts": repair_attempt + 1,
        "expected_teacher_request_hash": request_hash,
    }


def _repair_info_v21(
    context: Any,
    vocabulary: dict[str, set[str]],
    record: EnrichmentRecord,
) -> dict[str, Any]:
    """Classify one frozen v2.1 record without making it current/reusable."""

    variants = [(None, 0)] + [
        (repair_code, repair_attempt)
        for repair_code in (
            "invalid_structured_output",
            "semantic_validation_failed",
            "invalid_teacher_response_metadata",
        )
        for repair_attempt in (1, 2)
    ]
    for repair_code, repair_attempt in variants:
        system, user, schema = enrichment_request_v21(
            context,
            vocabulary,
            repair_error=repair_code,
            repair_attempt=repair_attempt,
        )
        if _sha256((system + user).encode("utf-8")) != record.prompt_sha256:
            continue
        request_hash = teacher_request_hash(
            TeacherRequest(
                system=system,
                user=user,
                schema=schema,
                temperature=0.0,
                max_tokens=8192,
            )
        )
        return {
            "request_variant_verified": True,
            "repair_prompt_used": repair_code is not None,
            "repair_code": repair_code,
            "request_repair_attempt": repair_attempt,
            "minimum_enrichment_attempts": repair_attempt + 1,
            "expected_teacher_request_hash": request_hash,
        }
    return {
        "request_variant_verified": False,
        "repair_prompt_used": None,
        "repair_code": None,
        "request_repair_attempt": None,
        "minimum_enrichment_attempts": None,
        "expected_teacher_request_hash": None,
    }


def _request_for_record(
    context: Any,
    vocabulary: dict[str, set[str]],
    record: EnrichmentRecord,
) -> TeacherRequest | None:
    info = _repair_info(context, vocabulary, record)
    if info["request_variant_verified"] is not True:
        return None
    system, user, schema = enrichment_request(
        context,
        vocabulary,
        repair_error=info["repair_code"],
        repair_attempt=info["request_repair_attempt"],
    )
    request = TeacherRequest(
        system=system,
        user=user,
        schema=schema,
        temperature=0.0,
        max_tokens=8192,
    )
    if teacher_request_hash(request) != info["expected_teacher_request_hash"]:
        raise ValueError("teacher request reconstruction mismatch")
    return request


def _request_variants_for_record(
    context: Any,
    vocabulary: dict[str, set[str]],
    record: EnrichmentRecord,
) -> dict[str, TeacherRequest]:
    """Rebuild all nine current prompt variants for request-hash matching."""

    if _repair_info(context, vocabulary, record)["request_variant_verified"] is not True:
        return {}
    variants = [(None, 0)] + [
        (repair_code, repair_attempt)
        for repair_code in _REPAIR_CODES[1:]
        for repair_attempt in (1, 2)
    ]
    result: dict[str, TeacherRequest] = {}
    for repair_code, repair_attempt in variants:
        system, user, schema = enrichment_request(
            context,
            vocabulary,
            repair_error=repair_code,
            repair_attempt=repair_attempt,
        )
        request = TeacherRequest(
            system=system,
            user=user,
            schema=schema,
            temperature=0.0,
            max_tokens=8192,
        )
        digest = teacher_request_hash(request)
        if digest in result:
            raise ValueError("teacher request variants are not unique")
        result[digest] = request
    if len(result) != 9:
        raise ValueError("teacher request variant set is incomplete")
    return result


def _frozen_v21_first_case_requests(
    root: Path, catalog: dict[str, Any]
) -> dict[str, TeacherRequest]:
    """Rebuild the three accepted first-case requests as pre-batch evidence."""

    case = catalog.get(_FROZEN_V21_FIRST_CASE_ID)
    if case is None:
        raise ValueError("frozen v2.1 first case is missing")
    context = build_oracle_context(root, case)
    vocabulary = _prompt_vocabulary(allowed_action_values(root))
    result: dict[str, TeacherRequest] = {}
    for repair_error, repair_attempt in _FROZEN_V21_FIRST_CASE_ATTEMPTS:
        system, user, schema = enrichment_request_v21(
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
        digest = teacher_request_hash(request)
        if digest in result:
            raise ValueError("frozen v2.1 first-case requests are not unique")
        result[digest] = request
    if len(result) != 3:
        raise ValueError("frozen v2.1 first-case request set is incomplete")
    return result


def _frozen_v22_recovery_requests(
    root: Path, catalog: dict[str, Any]
) -> dict[str, TeacherRequest]:
    """Rebuild frozen v2.2 3wfj variants as pre-recovery evidence."""

    case = catalog.get("ghsa-3wfj-vh84-732p")
    if case is None:
        raise ValueError("frozen v2.2 recovery case is missing")
    context = build_oracle_context(root, case)
    vocabulary = _prompt_vocabulary(allowed_action_values(root))
    variants = [(None, 0)] + [
        (repair_code, repair_attempt)
        for repair_code in (
            "invalid_structured_output",
            "semantic_validation_failed",
            "invalid_canonical_path",
        )
        for repair_attempt in (1, 2)
    ]
    result: dict[str, TeacherRequest] = {}
    for repair_error, repair_attempt in variants:
        system, user, schema = enrichment_request_v22(
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
        digest = teacher_request_hash(request)
        if digest in result:
            raise ValueError("frozen v2.2 requests are not unique")
        result[digest] = request
    if len(result) != 7:
        raise ValueError("frozen v2.2 request set is incomplete")
    return result


def _walk_audit_manifests(audit_root: Path) -> list[Path]:
    """Enumerate only the exact request/invocation/attempt directory grammar."""

    try:
        root_info = audit_root.lstat()
    except FileNotFoundError:
        return []
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise ValueError("teacher audit root is unsafe")
    manifests: list[Path] = []
    entries_seen = 0
    for request_dir in sorted(audit_root.iterdir()):
        entries_seen += 1
        request_info = request_dir.lstat()
        if (
            entries_seen > _MAX_AUDIT_FILES
            or not _SHA256.fullmatch(request_dir.name)
            or not stat.S_ISDIR(request_info.st_mode)
            or stat.S_ISLNK(request_info.st_mode)
        ):
            raise ValueError("teacher audit request directory is unsafe")
        for invocation_dir in sorted(request_dir.iterdir()):
            entries_seen += 1
            invocation_info = invocation_dir.lstat()
            if (
                entries_seen > _MAX_AUDIT_FILES
                or not _SAFE_INVOCATION_ID.fullmatch(invocation_dir.name)
                or not stat.S_ISDIR(invocation_info.st_mode)
                or stat.S_ISLNK(invocation_info.st_mode)
            ):
                raise ValueError("teacher audit invocation directory is unsafe")
            invocation_entries = sorted(invocation_dir.iterdir())
            entries_seen += len(invocation_entries)
            if entries_seen > _MAX_AUDIT_FILES or len(invocation_entries) != 1:
                raise ValueError("teacher audit invocation set is not exact")
            attempt_dir = invocation_entries[0]
            attempt_info = attempt_dir.lstat()
            if (
                attempt_dir.name != "attempt-00"
                or not stat.S_ISDIR(attempt_info.st_mode)
                or stat.S_ISLNK(attempt_info.st_mode)
            ):
                raise ValueError("teacher audit attempt directory is unsafe")
            manifests.append(attempt_dir / "manifest.json")
    return sorted(manifests)


def _audit_tree_inventory(audit_root: Path) -> list[dict[str, Any]]:
    """Commit every tree entry without opening special files or following links."""

    try:
        root_info = audit_root.lstat()
    except FileNotFoundError:
        return []
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise ValueError("teacher audit root is unsafe")
    entries: list[dict[str, Any]] = []
    pending = [audit_root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir(), reverse=True):
            if len(entries) >= _MAX_AUDIT_FILES:
                raise ValueError("teacher audit tree exceeds safety limit")
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                kind = "regular"
            elif stat.S_ISDIR(info.st_mode):
                kind = "directory"
            elif stat.S_ISLNK(info.st_mode):
                kind = "symlink"
            elif stat.S_ISFIFO(info.st_mode):
                kind = "fifo"
            elif stat.S_ISSOCK(info.st_mode):
                kind = "socket"
            else:
                kind = "other"
            item: dict[str, Any] = {
                "path": path.relative_to(audit_root).as_posix(),
                "kind": kind,
                "mode": stat.S_IMODE(info.st_mode),
                "nlink": info.st_nlink,
                "size": info.st_size,
            }
            if kind == "regular" and info.st_nlink == 1:
                item["sha256"] = _sha256(
                    _read_regular(path, limit=_MAX_MANIFEST_BYTES)
                )
            else:
                item["sha256"] = None
            entries.append(item)
            if kind == "directory":
                pending.append(path)
    return sorted(entries, key=lambda item: item["path"])


def _empty_audit_request_count(audit_root: Path) -> int:
    """Count syntactically valid request directories with no invocation at all."""

    try:
        root_info = audit_root.lstat()
    except FileNotFoundError:
        return 0
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise ValueError("teacher audit root is unsafe")
    count = 0
    for request_dir in sorted(audit_root.iterdir()):
        info = request_dir.lstat()
        if (
            not _SHA256.fullmatch(request_dir.name)
            or not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
        ):
            continue
        if not any(request_dir.iterdir()):
            count += 1
    return count


def _cache_tree_inventory(trajectory_root: Path) -> list[dict[str, Any]]:
    """Commit every direct cache entry, including unsafe or malformed nodes."""

    directory = trajectory_root / "cache/teacher"
    try:
        directory_info = directory.lstat()
    except FileNotFoundError:
        return []
    if not stat.S_ISDIR(directory_info.st_mode) or stat.S_ISLNK(
        directory_info.st_mode
    ):
        raise ValueError("teacher cache directory is unsafe")
    entries = sorted(directory.iterdir())
    if len(entries) > _MAX_AUDIT_FILES:
        raise ValueError("teacher cache exceeds safety limit")
    inventory: list[dict[str, Any]] = []
    for path in entries:
        info = path.lstat()
        if stat.S_ISREG(info.st_mode):
            kind = "regular"
        elif stat.S_ISDIR(info.st_mode):
            kind = "directory"
        elif stat.S_ISLNK(info.st_mode):
            kind = "symlink"
        elif stat.S_ISFIFO(info.st_mode):
            kind = "fifo"
        elif stat.S_ISSOCK(info.st_mode):
            kind = "socket"
        else:
            kind = "other"
        digest = None
        if kind == "regular" and info.st_nlink == 1:
            digest = _sha256(
                _read_regular(path, limit=_MAX_MANIFEST_BYTES)
            )
        inventory.append(
            {
                "path": path.relative_to(trajectory_root).as_posix(),
                "kind": kind,
                "mode": stat.S_IMODE(info.st_mode),
                "nlink": info.st_nlink,
                "size": info.st_size,
                "sha256": digest,
            }
        )
    return inventory


def _validate_transaction_set(directory: Path, manifest: dict[str, Any]) -> None:
    expected = _expected_transaction_files(manifest)
    entries = sorted(directory.iterdir())
    if {entry.name for entry in entries} != expected:
        raise ValueError("teacher audit transaction set mismatch")
    for entry in entries:
        info = entry.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("teacher audit transaction entry is unsafe")


def _nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _validate_manifest_contract(manifest: dict[str, Any]) -> None:
    """Reject unknown/missing audit fields and malformed scalar commitments."""

    fields = set(manifest)
    status = manifest.get("status")
    failure_code = manifest.get("failure_code")
    legacy_provider_failure = (
        status == "quarantined" and failure_code == "provider_failure_event"
    )
    legacy_fields = _MANIFEST_BASE_FIELDS
    provider_fields = legacy_fields | _MANIFEST_PROVIDER_SCHEMA_FIELDS
    current_fields = provider_fields | _MANIFEST_EXECUTABLE_FIELDS
    if fields == legacy_fields:
        if not legacy_provider_failure:
            raise ValueError
    elif fields != provider_fields and fields != current_fields:
        raise ValueError
    if (
        manifest.get("schema_version") != "1.0"
        or type(manifest.get("provider")) is not str
        or not manifest["provider"]
        or type(manifest.get("model")) is not str
        or not manifest["model"]
        or manifest.get("requested_model") != manifest["model"]
        or type(manifest.get("cli_version")) is not str
        or not manifest["cli_version"]
        or manifest.get("attempt") != 0
        or status not in {"committed", "quarantined"}
        or type(manifest.get("redacted_argv")) is not list
        or not manifest["redacted_argv"]
        or any(type(item) is not str for item in manifest["redacted_argv"])
        or not all(
            _nonnegative_integer(manifest.get(field))
            for field in (
                "stdin_length", "system_length", "schema_length",
                "stdout_length", "stderr_length", "events_metadata_length",
            )
        )
        or any(
            not _SHA256.fullmatch(str(manifest.get(field)))
            for field in (
                "stdin_sha256", "system_sha256", "schema_sha256",
                "stdout_sha256", "stderr_sha256", "events_metadata_sha256",
                "audit_commitment_sha256",
            )
        )
        or type(manifest.get("stderr_truncated_in_memory")) is not bool
        or (
            manifest.get("exit_code") is not None
            and type(manifest.get("exit_code")) is not int
        )
        or (
            manifest.get("signal") is not None
            and type(manifest.get("signal")) is not int
        )
        or not _nonnegative_integer(manifest.get("max_tokens"))
        or manifest["max_tokens"] == 0
        or type(manifest.get("max_tokens_enforced_by_cli")) is not bool
        or type(manifest.get("event_counts")) is not dict
        or any(
            type(key) is not str or type(count) is not int or count <= 0
            for key, count in manifest["event_counts"].items()
        )
    ):
        raise ValueError
    latency = manifest.get("latency_ms")
    if type(latency) not in {int, float} or not math.isfinite(latency) or latency < 0:
        raise ValueError
    if fields == provider_fields or fields == current_fields:
        if (
            type(manifest.get("provider_output_schema_transform")) is not str
            or not manifest["provider_output_schema_transform"]
            or not _nonnegative_integer(manifest.get("provider_output_schema_length"))
            or not _SHA256.fullmatch(
                str(manifest.get("provider_output_schema_sha256"))
            )
        ):
            raise ValueError
    if fields == current_fields:
        executable_stat = manifest.get("executable_stat")
        identity = {
            "executable_id": manifest.get("executable_id"),
            "executable_sha256": manifest.get("executable_sha256"),
            "executable_stat": executable_stat,
            "cli_version": manifest.get("cli_version"),
        }
        if (
            manifest.get("executable_id") != "codex-cli"
            or not _SHA256.fullmatch(str(manifest.get("executable_sha256")))
            or type(executable_stat) is not dict
            or set(executable_stat)
            != {
                "device",
                "inode",
                "mode",
                "nlink",
                "size",
                "mtime_ns",
                "ctime_ns",
            }
            or any(
                not _nonnegative_integer(value)
                for value in executable_stat.values()
            )
            or executable_stat["nlink"] != 1
            or executable_stat["size"] == 0
            or manifest.get("executable_identity_commitment_sha256")
            != _sha256(_canonical(identity))
        ):
            raise ValueError
    usage = manifest.get("usage")
    if status == "committed":
        if (
            failure_code is not None
            or type(manifest.get("provider_response_model")) is not str
            or not manifest["provider_response_model"]
            or type(usage) is not dict
            or set(usage) != set(_USAGE_FIELDS)
            or any(not _nonnegative_integer(usage[field]) for field in _USAGE_FIELDS)
            or not _nonnegative_integer(manifest.get("response_length"))
            or not _SHA256.fullmatch(str(manifest.get("response_sha256")))
            or not _SHA256.fullmatch(
                str(manifest.get("response_commitment_sha256"))
            )
            or (fields != provider_fields and fields != current_fields)
        ):
            raise ValueError
    elif (
        type(failure_code) is not str
        or not failure_code
        or manifest.get("provider_response_model") is not None
        or usage is not None
        or manifest.get("response_length") is not None
        or manifest.get("response_sha256") is not None
        or manifest.get("response_commitment_sha256") is not None
    ):
        raise ValueError


def _validate_metadata_lifecycle(
    metadata: bytes, manifest: dict[str, Any]
) -> tuple[list[dict[str, Any]], int]:
    items: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    tool_events = 0
    for expected_index, line in enumerate(metadata.splitlines()):
        item = strict_json_loads(line, max_bytes=_MAX_MANIFEST_BYTES)
        if type(item) is not dict or item.get("index") != expected_index:
            raise ValueError
        event_type = item.get("type")
        if type(event_type) is not str or event_type not in _KNOWN_EVENT_TYPES:
            raise ValueError
        if event_type == "item.completed":
            if set(item) != {"index", "type", "item_type"}:
                raise ValueError
            item_type = item.get("item_type")
            if (
                type(item_type) is not str
                or item_type not in _KNOWN_ITEM_TYPES | _TOOL_ITEM_TYPES
            ):
                raise ValueError
            if item_type in _TOOL_ITEM_TYPES:
                tool_events += 1
        elif set(item) != {"index", "type"}:
            raise ValueError
        counts[event_type] += 1
        items.append(item)
    if not items or dict(sorted(counts.items())) != manifest.get("event_counts"):
        raise ValueError
    if tool_events:
        raise _ForbiddenToolMetadata(tool_events)
    status = manifest["status"]
    if status == "committed":
        if (
            len(items) < 4
            or items[0]["type"] != "thread.started"
            or items[1]["type"] != "turn.started"
            or items[-1]["type"] != "turn.completed"
            or items[-2] != {
                "index": len(items) - 2,
                "type": "item.completed",
                "item_type": "agent_message",
            }
            or any(
                item.get("type") != "item.completed"
                or item.get("item_type") != "reasoning"
                for item in items[2:-2]
            )
        ):
            raise ValueError
    elif manifest["failure_code"] == "provider_failure_event":
        if [item["type"] for item in items] != [
            "thread.started", "turn.started", "error"
        ]:
            raise ValueError
    else:
        raise ValueError
    return items, tool_events


def _expected_transaction_files(manifest: dict[str, Any]) -> set[str]:
    if manifest["status"] == "committed":
        return {"manifest.json", "events.metadata.jsonl"}
    return {"manifest.json", "events.metadata.jsonl", "quarantine.json"}


def _provider_request_id_kind(provider: str) -> str:
    return "codex_thread_id" if provider == "codex_exec" else "provider_request_id"


def _teacher_cache_response_index(
    trajectory_root: Path,
) -> tuple[
    dict[str, tuple[Path, bytes, TeacherResponse]],
    dict[Path, str | None],
]:
    directory = trajectory_root / "cache/teacher"
    try:
        directory_info = directory.lstat()
    except FileNotFoundError:
        return {}, {}
    if not stat.S_ISDIR(directory_info.st_mode) or stat.S_ISLNK(directory_info.st_mode):
        raise ValueError("teacher cache directory is unsafe")
    result: dict[str, tuple[Path, bytes, TeacherResponse]] = {}
    invalid: dict[Path, str | None] = {}
    entries = sorted(directory.iterdir())
    if len(entries) > _MAX_AUDIT_FILES:
        raise ValueError("teacher cache exceeds safety limit")
    for path in entries:
        value: object = None
        try:
            info = path.lstat()
            if (
                not _CACHE_FILE.fullmatch(path.name)
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ValueError
            raw = _read_regular(path, limit=_MAX_MANIFEST_BYTES)
            value = strict_json_loads(raw, max_bytes=_MAX_MANIFEST_BYTES)
            if type(value) is not dict:
                raise ValueError
            response = TeacherResponse.model_validate(value)
            commitment = response.response_commitment_sha256
            if commitment in result:
                raise ValueError
            result[commitment] = (path, raw, response)
        except Exception:
            commitment = (
                value.get("response_commitment_sha256")
                if type(value) is dict
                and _SHA256.fullmatch(
                    str(value.get("response_commitment_sha256"))
                )
                else None
            )
            invalid[path] = commitment
    return result, invalid


def _scan_teacher_audit(
    trajectory_root: Path,
    provider: str,
    model: str,
    *,
    expected_requests: dict[str, TeacherRequest] | None = None,
    pre_batch_request_hashes: set[str] | None = None,
    pre_recovery_request_hashes: set[str] | None = None,
) -> dict[str, Any]:
    """Validate complete audit transactions and bind commits to cache preimages."""

    audit_root = trajectory_root / "audit/teacher"
    audit_inventory = _audit_tree_inventory(audit_root)
    cache_inventory = _cache_tree_inventory(trajectory_root)
    manifests = _walk_audit_manifests(audit_root)
    expected_requests = {} if expected_requests is None else expected_requests
    pre_batch_request_hashes = (
        set() if pre_batch_request_hashes is None else pre_batch_request_hashes
    )
    pre_recovery_request_hashes = (
        set()
        if pre_recovery_request_hashes is None
        else pre_recovery_request_hashes
    )
    if type(expected_requests) is not dict or any(
        not _SHA256.fullmatch(str(key))
        or not isinstance(request, TeacherRequest)
        or teacher_request_hash(request) != key
        for key, request in expected_requests.items()
    ):
        raise ValueError("expected teacher requests are malformed")
    if (
        type(pre_batch_request_hashes) is not set
        or any(
            not _SHA256.fullmatch(str(item))
            for item in pre_batch_request_hashes
        )
        or not pre_batch_request_hashes <= set(expected_requests)
        or type(pre_recovery_request_hashes) is not set
        or any(
            not _SHA256.fullmatch(str(item))
            for item in pre_recovery_request_hashes
        )
        or not pre_recovery_request_hashes <= set(expected_requests)
        or bool(pre_batch_request_hashes & pre_recovery_request_hashes)
    ):
        raise ValueError("historical teacher requests are malformed")
    artifacts: list[dict[str, str]] = []
    by_response: dict[str, dict[str, Any]] = {}
    pre_batch_by_response: dict[str, dict[str, Any]] = {}
    pre_recovery_by_response: dict[str, dict[str, Any]] = {}
    committed = 0
    quarantined = 0
    malformed_invalid = _empty_audit_request_count(audit_root)
    historical_unbound: list[dict[str, Any]] = []
    identity_mismatches = 0
    tool_events = 0
    latencies_ms: list[float] = []
    quarantined_latencies_ms: list[float] = []
    usage: Counter[str] = Counter()
    usage_available_attempts = 0
    failure_codes: Counter[str] = Counter()
    provider_failure_commitments: list[dict[str, str]] = []
    cache = TeacherCache(trajectory_root / "cache/teacher")
    cache_responses, invalid_cache_entries = _teacher_cache_response_index(
        trajectory_root
    )
    consumed_invalid_cache_entries: set[Path] = set()
    cache_references: Counter[Path] = Counter()
    for path in manifests:
        manifest: dict[str, Any] | None = None
        relative: Path | None = None
        try:
            relative = path.relative_to(audit_root)
            if (
                len(relative.parts) != 4
                or not _SHA256.fullmatch(relative.parts[0])
                or not _SAFE_INVOCATION_ID.fullmatch(relative.parts[1])
                or relative.parts[2] != "attempt-00"
                or relative.parts[3] != "manifest.json"
            ):
                raise ValueError
            raw = _read_regular(path, limit=_MAX_MANIFEST_BYTES)
            manifest = _parse_object(raw, "teacher audit manifest")
            _validate_manifest_contract(manifest)
            if (
                manifest.get("audit_commitment_sha256")
                != _dict_commitment(manifest, "audit_commitment_sha256")
                or manifest.get("provider") != provider
                or manifest.get("model") != model
                or manifest.get("requested_model") != model
                or manifest.get("request_hash") != relative.parts[0]
                or manifest.get("invocation_id") != relative.parts[1]
            ):
                if (
                    manifest.get("provider") != provider
                    or manifest.get("model") != model
                    or manifest.get("requested_model") != model
                ):
                    identity_mismatches += 1
                raise ValueError
            _validate_transaction_set(path.parent, manifest)
            metadata_path = path.with_name("events.metadata.jsonl")
            metadata = _read_regular(metadata_path, limit=_MAX_MANIFEST_BYTES)
            if (
                len(metadata) != manifest.get("events_metadata_length")
                or _sha256(metadata) != manifest.get("events_metadata_sha256")
            ):
                raise ValueError
            try:
                _, manifest_tool_events = _validate_metadata_lifecycle(
                    metadata, manifest
                )
            except _ForbiddenToolMetadata as exc:
                tool_events += exc.tool_events
                raise
            tool_events += manifest_tool_events
            status = manifest["status"]
            latency = float(manifest["latency_ms"])
            attempt_usage = manifest.get("usage")
            response_commitment = manifest.get("response_commitment_sha256")
            cache_raw: bytes | None = None
            cache_path: Path | None = None
            response: TeacherResponse | None = None
            if status == "committed":
                request = expected_requests.get(manifest["request_hash"])
                if provider != "codex_exec":
                    raise ValueError
                cache_match = cache_responses.get(response_commitment)
                if cache_match is None:
                    if request is not None:
                        expected_cache_path = cache.path_for(
                            cache_key(provider, model, request)
                        )
                        if expected_cache_path in invalid_cache_entries:
                            consumed_invalid_cache_entries.add(
                                expected_cache_path
                            )
                    else:
                        consumed_invalid_cache_entries.update(
                            path
                            for path, commitment in invalid_cache_entries.items()
                            if commitment == response_commitment
                        )
                    raise ValueError
                cache_path, cache_raw, response = cache_match
                cache_references[cache_path] += 1
                if cache_references[cache_path] != 1:
                    raise ValueError
                key: str | None = None
                if request is not None:
                    system_raw = request.system.encode("utf-8")
                    schema_raw = _canonical(request.schema)
                    stdin_raw = (
                        request.user
                        + f"\n\n[EGSI output budget hint: at most {request.max_tokens} tokens.]"
                    ).encode("utf-8")
                    if (
                        manifest["system_length"] != len(system_raw)
                        or manifest["system_sha256"] != _sha256(system_raw)
                        or manifest["schema_length"] != len(schema_raw)
                        or manifest["schema_sha256"] != _sha256(schema_raw)
                        or manifest["stdin_length"] != len(stdin_raw)
                        or manifest["stdin_sha256"] != _sha256(stdin_raw)
                        or manifest["max_tokens"] != request.max_tokens
                        or manifest["provider_output_schema_transform"]
                        != "codex-strict-required-v1"
                        or manifest["provider_output_schema_length"]
                        != len(schema_raw)
                        or manifest["provider_output_schema_sha256"]
                        != _sha256(schema_raw)
                    ):
                        raise ValueError
                    key = cache_key(
                        provider,
                        model,
                        request,
                        provenance=manifest.get(
                            "executable_identity_commitment_sha256"
                        ),
                    )
                    if cache_path != cache.path_for(key):
                        raise ValueError
                response_raw = response.text.encode("utf-8")
                if (
                    response.cached is not False
                    or response.provider != provider
                    or response.model != model
                    or response.requested_model != model
                    or response.provider_response_model
                    != manifest["provider_response_model"]
                    or response.response_commitment_sha256 != response_commitment
                    or response.usage != attempt_usage
                    or response.latency_ms != latency
                    or manifest["response_length"] != len(response_raw)
                    or manifest["response_sha256"] != _sha256(response_raw)
                    or type(response.provider_request_id) is not str
                    or not response.provider_request_id
                ):
                    raise ValueError
                if request is None:
                    historical_unbound.append(
                        {
                            "request_hash": manifest["request_hash"],
                            "response_commitment_sha256": response_commitment,
                            "audit_commitment_sha256": manifest[
                                "audit_commitment_sha256"
                            ],
                            "audit_file_sha256": _sha256(raw),
                            "cache_file": cache_path.relative_to(
                                trajectory_root
                            ).as_posix(),
                            "cache_file_sha256": _sha256(cache_raw),
                        }
                    )
                else:
                    if manifest["request_hash"] in pre_batch_request_hashes:
                        destination = pre_batch_by_response
                    elif manifest["request_hash"] in pre_recovery_request_hashes:
                        destination = pre_recovery_by_response
                    else:
                        destination = by_response
                    if (
                        response_commitment in by_response
                        or response_commitment in pre_batch_by_response
                        or response_commitment in pre_recovery_by_response
                        or key is None
                    ):
                        raise ValueError
                    destination[response_commitment] = {
                        "invocation_id": manifest["invocation_id"],
                        "attempt": manifest["attempt"],
                        "status": status,
                        "failure_code": None,
                        "audit_commitment_sha256": manifest[
                            "audit_commitment_sha256"
                        ],
                        "response_commitment_sha256": response_commitment,
                        "request_hash": manifest["request_hash"],
                        "cache_key": key,
                        "cache_file": cache_path.relative_to(
                            trajectory_root
                        ).as_posix(),
                        "cache_sha256": _sha256(cache_raw),
                        "cache_preimage_bound": True,
                        "executable_id": manifest.get("executable_id"),
                        "executable_sha256": manifest.get("executable_sha256"),
                        "executable_stat": manifest.get("executable_stat"),
                        "executable_identity_commitment_sha256": manifest.get(
                            "executable_identity_commitment_sha256"
                        ),
                        "provider_invocation_id": response.provider_request_id,
                        "provider_request_id_kind": _provider_request_id_kind(
                            provider
                        ),
                        "provider_request_id_bound_by_response_commitment": True,
                        "provider_response_model": response.provider_response_model,
                        "latency_ms": latency,
                        "usage": attempt_usage,
                        "forbidden_tool_event_count": manifest_tool_events,
                    }
                    if destination is by_response:
                        committed += 1
                        assert type(attempt_usage) is dict
                        usage.update(attempt_usage)
                        usage_available_attempts += 1
                        latencies_ms.append(latency)
            else:
                quarantine_raw = _read_regular(
                    path.with_name("quarantine.json"), limit=_MAX_MANIFEST_BYTES
                )
                quarantine_value = _parse_object(
                    quarantine_raw, "teacher audit quarantine receipt"
                )
                if quarantine_value != {
                    "schema_version": "1.0",
                    "status": "quarantined",
                    "failure_code": manifest["failure_code"],
                    "positive_transition_written": False,
                }:
                    raise ValueError
                quarantined += 1
                latencies_ms.append(latency)
                quarantined_latencies_ms.append(latency)
                failure_codes[manifest["failure_code"]] += 1
                if manifest["failure_code"] == "provider_failure_event":
                    provider_failure_commitments.append(
                        {
                            "failure_code": manifest["failure_code"],
                            "audit_commitment_sha256": manifest[
                                "audit_commitment_sha256"
                            ],
                            "manifest_path": path.relative_to(
                                trajectory_root
                            ).as_posix(),
                        }
                    )
                artifacts.append(
                    {
                        "file": path.with_name("quarantine.json")
                        .relative_to(trajectory_root)
                        .as_posix(),
                        "sha256": _sha256(quarantine_raw),
                    }
                )
            artifacts.extend(
                [
                    {
                        "file": path.relative_to(trajectory_root).as_posix(),
                        "sha256": _sha256(raw),
                    },
                    {
                        "file": metadata_path.relative_to(trajectory_root).as_posix(),
                        "sha256": _sha256(metadata),
                    },
                ]
            )
            if cache_raw is not None and cache_path is not None:
                artifacts.append(
                    {
                        "file": cache_path.relative_to(trajectory_root).as_posix(),
                        "sha256": _sha256(cache_raw),
                    }
                )
        except Exception:
            if (
                type(manifest) is dict
                and manifest.get("status") == "committed"
                and _SHA256.fullmatch(
                    str(manifest.get("response_commitment_sha256"))
                )
            ):
                cache_match = cache_responses.get(
                    manifest["response_commitment_sha256"]
                )
                if cache_match is not None and cache_references[cache_match[0]] == 0:
                    cache_references[cache_match[0]] = 1
            elif relative is not None and len(relative.parts) == 4:
                request = expected_requests.get(relative.parts[0])
                if request is not None:
                    expected_cache_path = cache.path_for(
                        cache_key(provider, model, request)
                    )
                    if cache_references[expected_cache_path] == 0:
                        cache_references[expected_cache_path] = 1
            malformed_invalid += 1
    historical_unbound = sorted(
        historical_unbound,
        key=lambda item: (
            item["request_hash"], item["response_commitment_sha256"]
        ),
    )
    provider_failure_commitments.sort(
        key=lambda item: (
            item["failure_code"], item["audit_commitment_sha256"],
            item["manifest_path"],
        )
    )
    malformed_invalid += len(
        set(invalid_cache_entries) - consumed_invalid_cache_entries
    )
    malformed_invalid += sum(
        cache_references[path] == 0
        for path, _, _ in cache_responses.values()
    )
    return {
        "manifest_count": len(manifests),
        "committed": committed,
        "quarantined": quarantined,
        "invalid": malformed_invalid,
        "malformed_invalid": malformed_invalid,
        "historical_unbound_committed": len(historical_unbound),
        "historical_unbound": historical_unbound,
        "historical_unbound_set_sha256": _sha256(_canonical(historical_unbound)),
        "historical_response_commitment_set_sha256": _sha256(
            _canonical(
                sorted(
                    item["response_commitment_sha256"]
                    for item in historical_unbound
                )
            )
        ),
        "identity_mismatches": identity_mismatches,
        "tool_events": tool_events,
        "latencies_ms": latencies_ms,
        "quarantined_latencies_ms": quarantined_latencies_ms,
        "usage": {field: usage[field] for field in _USAGE_FIELDS},
        "usage_available_attempts": usage_available_attempts,
        "failure_codes": dict(sorted(failure_codes.items())),
        "prior_provider_failure_count": failure_codes[
            "provider_failure_event"
        ],
        "provider_failure_audit_commitment_set_sha256": _sha256(
            _canonical(
                [
                    {
                        "failure_code": item["failure_code"],
                        "audit_commitment_sha256": item[
                            "audit_commitment_sha256"
                        ],
                    }
                    for item in provider_failure_commitments
                ]
            )
        ),
        "provider_failure_commitments": provider_failure_commitments,
        "by_response": by_response,
        "pre_batch_bound_committed": len(pre_batch_by_response),
        "pre_batch_by_response": pre_batch_by_response,
        "pre_batch_response_commitment_set_sha256": _sha256(
            _canonical(sorted(pre_batch_by_response))
        ),
        "pre_recovery_bound_committed": len(pre_recovery_by_response),
        "pre_recovery_by_response": pre_recovery_by_response,
        "pre_recovery_response_commitment_set_sha256": _sha256(
            _canonical(sorted(pre_recovery_by_response))
        ),
        "artifact_set_sha256": _sha256(
            _canonical(
                {
                    "audit_tree": audit_inventory,
                    "cache_tree": cache_inventory,
                    "bound_artifacts": artifacts,
                }
            )
        ),
    }

def _payload_summary(record: EnrichmentRecord) -> dict[str, Any]:
    return {
        "family": record.payload.family,
        "location_count": len(record.payload.locations),
        "obligation_count": len(record.payload.obligations),
        "trace_step_count": len(record.payload.trace),
        "limitation_count": len(record.payload.limitations),
        "family_specific_semantics_present": record.payload.authorization is not None,
    }


def _validation_summary(record: EnrichmentRecord) -> dict[str, Any]:
    validation = record.validation
    return {
        "valid": validation.valid,
        "family_mismatch": validation.family_mismatch,
        "invalid_location_count": len(validation.invalid_locations),
        "invalid_trace_location_count": len(
            validation.invalid_trace_locations
        ),
        "invalid_goal_count": len(validation.invalid_goals),
        "invalid_operation_count": len(validation.invalid_operations),
        "invalid_target_kind_count": len(validation.invalid_target_kinds),
        "invalid_tool_class_count": len(validation.invalid_tool_classes),
    }


def _markdown(packet: dict[str, Any]) -> bytes:
    lines = [
        "# P0 Human Audit Packet",
        "",
        f"- Status: `{packet['status']}`",
        f"- Cases: `{packet['case_count']}`",
        f"- Provider/model: `{packet['provider']}` / `{packet['model']}`",
        f"- Packet commitment: `{packet['packet_commitment_sha256']}`",
        "- Human gate: unsigned; no final acceptance decision has been recorded.",
        "",
        "## Automated gates",
        "",
    ]
    lines.extend(
        f"- `{name}`: `{str(value).lower()}`"
        for name, value in packet["automated_gates"].items()
    )
    lines.extend(
        [
            "",
            "## Human review fields",
            "",
            "| case_id | family | automated | human_semantic_judgment | human_notes |",
            "|---|---|---:|---|---|",
        ]
    )
    for item in packet["cases"]:
        lines.append(
            f"| `{item['case_id']}` | `{item['family']}` | "
            f"`{str(item['automated_gates']['all_passed']).lower()}` | "
            "`null` | `null` |"
        )
    lines.extend(
        [
            "",
            "Threshold: at least 8 semantically usable cases and at most 2 revision cases.",
            "The JSON packet is canonical and authoritative for artifact commitments.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def build_human_audit(
    *,
    root: Path,
    case_file: Path,
    enrichment_root: Path,
    trajectory_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Rebuild every P0 gate from artifacts and write an unsigned review packet."""

    root = Path(root)
    case_file = Path(case_file)
    enrichment_root = Path(enrichment_root)
    trajectory_root = Path(trajectory_root)
    output_root = Path(output_root)
    case_ids = read_case_ids(case_file)
    if len(case_ids) != 10:
        raise ValueError("human audit packet requires exactly ten cases")
    catalog = catalog_index(root)
    if any(case_id not in catalog for case_id in case_ids):
        raise ValueError("human audit case is missing from catalog")

    records, provenance, provenance_entries, provenance_sha256 = (
        _manifest_expectation(enrichment_root, case_ids)
    )
    trajectory_manifest, trajectory_entries, trajectory_metadata = (
        _validate_trajectory_manifest(
            trajectory_root, case_ids, provenance_sha256
        )
    )
    prompt_vocabulary = _prompt_vocabulary(allowed_action_values(root))
    expected_requests: dict[str, TeacherRequest] = {}
    for case_id, record in records.items():
        variants = _request_variants_for_record(
            build_oracle_context(root, catalog[case_id]),
            prompt_vocabulary,
            record,
        )
        if set(expected_requests).intersection(variants):
            raise ValueError("teacher request variants collide across records")
        expected_requests.update(variants)
    pre_batch_requests = _frozen_v21_first_case_requests(root, catalog)
    if set(expected_requests).intersection(pre_batch_requests):
        raise ValueError("pre-batch requests collide with current records")
    expected_requests.update(pre_batch_requests)
    audit = _scan_teacher_audit(
        trajectory_root,
        provenance["provider"],
        provenance["model"],
        expected_requests=expected_requests,
        pre_batch_request_hashes=set(pre_batch_requests),
    )
    historical_baseline = _historical_baseline(
        root,
        trajectory_root,
        provider=provenance["provider"],
        model=provenance["model"],
    )

    parquet_entry = trajectory_entries.get(("__batch__", "trajectory_parquet"))
    parquet_rows: list[T1Transition] | None = None
    parquet_hash_valid = False
    if parquet_entry is not None:
        try:
            parquet_path = trajectory_root / parquet_entry["relative_path"]
            parquet_hash_valid = (
                _sha256(_read_regular(parquet_path)) == parquet_entry["sha256"]
            )
            if parquet_hash_valid:
                parquet_rows = read_parquet(parquet_path)
        except FileNotFoundError:
            parquet_rows = None
        except (OSError, ValueError):
            parquet_rows = None

    cases: list[dict[str, Any]] = []
    all_transitions: list[T1Transition] = []
    latencies: list[int] = []
    usage: Counter[str] = Counter()
    final_audit_usage: Counter[str] = Counter()
    final_audit_latencies: list[float] = []
    repair_prompt_cases = 0
    response_audit_links = 0
    for case_id in case_ids:
        case = catalog[case_id]
        context = build_oracle_context(root, case)
        record = records.get(case_id)
        provenance_entry = provenance_entries.get(case_id)
        enrichment_present = record is not None
        context_bound = False
        semantic_valid = False
        action_dsl_valid = False
        structured_valid = False
        provenance_bound = False
        identity_match = False
        enrichment_value: dict[str, Any] | None = None
        teacher_value: dict[str, Any] | None = None
        repair_value: dict[str, Any] | None = None
        audit_link: dict[str, Any] | None = None
        if record is not None:
            vocabulary = allowed_action_values(root)
            repair_value = _repair_info(
                context, _prompt_vocabulary(vocabulary), record
            )
            frozen_v21 = (
                case_id == _FROZEN_V21_FIRST_CASE_ID
                and repair_value["request_variant_verified"] is not True
                and _repair_info_v21(
                    context, _prompt_vocabulary(vocabulary), record
                )["request_variant_verified"]
                is True
            )
            if frozen_v21:
                from egsi.generation.first_case_hard_gate import (
                    _validate_frozen_v21_payload,
                )

                repeated = _validate_frozen_v21_payload(
                    case,
                    record.payload,
                    _load_store(root, case),
                    vocabulary,
                )
                repair_value = _repair_info_v21(
                    context, _prompt_vocabulary(vocabulary), record
                )
            else:
                repeated = validate_payload(
                    case,
                    record.payload,
                    _load_store(root, case),
                    vocabulary,
                )
            structured_valid = record.structured_output_valid is True
            semantic_valid = (
                record.validation.valid is True and repeated == record.validation
            )
            action_dsl_valid = repeated.valid is True
            context_bound = record.source_context_sha256 == context.sha256
            identity_match = (
                record.provider == provenance["provider"]
                and record.model == provenance["model"]
                and record.requested_model == provenance["requested_model"]
                and record.provider_response_model
                in provenance["provider_response_models"]
            )
            if type(provenance_entry) is dict:
                raw = _read_regular(
                    enrichment_root / f"{case_id}.json",
                    limit=_MAX_MANIFEST_BYTES,
                )
                provenance_bound = (
                    provenance_entry.get("kind") == "enrichment_record"
                    and provenance_entry.get("relative_path")
                    == f"{case_id}.json"
                    and provenance_entry.get("file_sha256") == _sha256(raw)
                    and provenance_entry.get("record_commitment_sha256")
                    == record.record_commitment_sha256
                    and provenance_entry.get(
                        "teacher_response_commitment_sha256"
                    )
                    == record.teacher_response_commitment_sha256
                )
                enrichment_value = {
                    "file": f"enrichment/{case_id}.json",
                    "sha256": _sha256(raw),
                    "record_commitment_sha256": record.record_commitment_sha256,
                    "payload_summary": _payload_summary(record),
                    "validation_summary": _validation_summary(record),
                }
            teacher_value = {
                "commitment_sha256": record.teacher_response_commitment_sha256,
                # Compatibility alias retained; Codex supplies a thread ID, not an
                # HTTP request ID.  New consumers should use the two fields below.
                "provider_request_id": record.provider_request_id,
                "provider_invocation_id": record.provider_request_id,
                "provider_request_id_kind": _provider_request_id_kind(
                    record.provider
                ),
                "provider_response_model": record.provider_response_model,
            }
            repair_prompt_cases += int(
                repair_value.get("repair_prompt_used") is True
            )
            latencies.append(record.latency_ms)
            for field in _USAGE_FIELDS:
                usage[field] += record.usage.get(field, 0)
            audit_link = audit["by_response"].get(
                record.teacher_response_commitment_sha256
            ) or audit["pre_batch_by_response"].get(
                record.teacher_response_commitment_sha256
            )
            if audit_link is not None:
                response_audit_links += 1
                final_audit_latencies.append(audit_link["latency_ms"])
                if type(audit_link.get("usage")) is dict:
                    final_audit_usage.update(audit_link["usage"])

        event_entry = trajectory_entries.get((case_id, "episode_events"))
        transition_entry = trajectory_entries.get(
            (case_id, "episode_transitions")
        )
        trajectory_linked = False
        replay_valid = False
        parquet_linked = False
        leakage_zero = False
        nonzero_rewards_zero = False
        illegal_zero = False
        trajectory_value: dict[str, Any] | None = None
        if event_entry is not None and transition_entry is not None and record is not None:
            try:
                event_raw = _read_regular(
                    trajectory_root / event_entry["relative_path"]
                )
                transition_raw = _read_regular(
                    trajectory_root / transition_entry["relative_path"]
                )
                artifact_hashes_match = (
                    _sha256(event_raw) == event_entry["sha256"]
                    and _sha256(transition_raw) == transition_entry["sha256"]
                )
                events = _read_jsonl(
                    trajectory_root / event_entry["relative_path"], EpisodeEvent
                )
                transitions = _read_jsonl(
                    trajectory_root / transition_entry["relative_path"],
                    T1Transition,
                )
                expected_transitions, expected_events = compile_t1_episode(
                    case, record, root=root
                )
                trajectory_linked = (
                    artifact_hashes_match
                    and transitions == expected_transitions
                    and events == expected_events
                )
                commitment = episode_commitment(transitions, events)
                replay = replay_events(
                    events,
                    transitions,
                    expected_commitment_sha256=commitment,
                )
                replay_valid = trajectory_linked and replay.get("closed") is True
                leakage, nonzero, illegal = _episode_metrics(
                    case, record, transitions, events
                )
                leakage_zero = leakage == 0
                nonzero_rewards_zero = nonzero == 0
                illegal_zero = illegal == 0
                all_transitions.extend(transitions)
                trajectory_value = {
                    "episode_id": transitions[0].episode_id,
                    "event_file": event_entry["relative_path"],
                    "event_sha256": event_entry["sha256"],
                    "transition_file": transition_entry["relative_path"],
                    "transition_sha256": transition_entry["sha256"],
                    "episode_commitment_sha256": commitment,
                    "parquet_file": (
                        None
                        if parquet_entry is None
                        else parquet_entry["relative_path"]
                    ),
                    "replay": replay,
                }
            except FileNotFoundError:
                trajectory_linked = False
            except (OSError, ValueError, KeyError, IndexError):
                trajectory_linked = False

        if parquet_rows is not None and trajectory_value is not None:
            episode_rows = [
                row
                for row in parquet_rows
                if row.episode_id == trajectory_value["episode_id"]
            ]
            expected_rows = [
                row
                for row in all_transitions
                if row.episode_id == trajectory_value["episode_id"]
            ]
            parquet_linked = bool(episode_rows) and episode_rows == expected_rows

        live_audit_required = provenance["generation_mode"] == "live"
        teacher_audit_committed = (
            audit_link is not None
            and audit_link.get("status") == "committed"
            and audit_link.get("failure_code") is None
            and audit_link.get("cache_preimage_bound") is True
        ) if live_audit_required else True
        provider_request_id_bound = (
            record is not None
            and type(record.provider_request_id) is str
            and bool(record.provider_request_id)
            and audit_link is not None
            and audit_link.get("response_commitment_sha256")
            == record.teacher_response_commitment_sha256
            and audit_link.get(
                "provider_request_id_bound_by_response_commitment"
            )
            is True
            and audit_link.get("provider_invocation_id")
            == record.provider_request_id
            and audit_link.get("provider_request_id_kind")
            == _provider_request_id_kind(record.provider)
            and audit_link.get("usage") == record.usage
            and math.floor(audit_link.get("latency_ms")) == record.latency_ms
            and audit_link.get("provider_response_model")
            == record.provider_response_model
        ) if live_audit_required else True
        teacher_request_bound = (
            record is not None
            and repair_value is not None
            and repair_value.get("request_variant_verified") is True
            and type(repair_value.get("expected_teacher_request_hash")) is str
            and audit_link is not None
            and audit_link.get("request_hash")
            == repair_value.get("expected_teacher_request_hash")
            and audit_link.get("response_commitment_sha256")
            == record.teacher_response_commitment_sha256
        ) if live_audit_required else True
        case_tool_gate = (
            audit_link is None
            or audit_link.get("forbidden_tool_event_count") == 0
        )
        if live_audit_required:
            identity_match = identity_match and audit_link is not None
        case_gates = {
            "enrichment_present": enrichment_present,
            "context_bound": context_bound,
            "structured_output_valid": structured_valid,
            "semantic_validation_valid": semantic_valid,
            "action_dsl_valid": action_dsl_valid,
            "provenance_bound": provenance_bound,
            "identity_match": identity_match,
            "teacher_audit_committed": teacher_audit_committed,
            "provider_request_id_bound": provider_request_id_bound,
            "teacher_request_bound": teacher_request_bound,
            "trajectory_linked": trajectory_linked,
            "parquet_linked": parquet_linked,
            "replay_valid": replay_valid,
            "policy_oracle_leakage_zero": leakage_zero,
            "selected_illegal_actions_zero": illegal_zero,
            "nonzero_t1_rewards_zero": nonzero_rewards_zero,
            "tool_quarantine_zero": case_tool_gate,
        }
        case_gates["all_passed"] = all(case_gates.values())
        cases.append(
            {
                "case_id": case_id,
                "family": case.family,
                "context": {
                    "sha256": context.sha256,
                    "receipt_commitment_sha256": context.selection_receipt.receipt_commitment_sha256,
                    "effective_patch_source": context.selection_receipt.effective_patch_source,
                },
                "enrichment": enrichment_value,
                "teacher_response": teacher_value,
                "repair_attempt": repair_value,
                "teacher_audit": audit_link,
                "trajectory": trajectory_value,
                "automated_gates": case_gates,
                "human_semantic_judgment": None,
                "human_notes": None,
            }
        )

    parquet_exact = (
        parquet_hash_valid
        and parquet_rows is not None
        and parquet_rows == all_transitions
        and bool(all_transitions)
    )
    live_audit_required = provenance["generation_mode"] == "live"
    audit_integrity_valid = (
        audit["malformed_invalid"] == 0
        and audit["identity_mismatches"] == 0
    )
    final_teacher_audit_bound = (
        not live_audit_required
        or (
            response_audit_links == len(records) == len(case_ids)
            and all(
                item["automated_gates"]["teacher_audit_committed"]
                and item["automated_gates"]["provider_request_id_bound"]
                and item["automated_gates"]["teacher_request_bound"]
                for item in cases
            )
        )
    )
    automated_gates = {
        "case_count_exact": len(case_ids) == 10,
        "enrichment_records_complete": len(records) == len(case_ids),
        "structured_output_valid": all(
            item["automated_gates"]["structured_output_valid"] for item in cases
        ),
        "semantic_validation_valid": all(
            item["automated_gates"]["semantic_validation_valid"]
            for item in cases
        ),
        "action_dsl_valid": all(
            item["automated_gates"]["action_dsl_valid"] for item in cases
        ),
        "provenance_valid": (
            len(provenance_entries) == len(case_ids)
            and all(
                item["automated_gates"]["provenance_bound"] for item in cases
            )
        ),
        "trajectories_complete": all(
            item["automated_gates"]["trajectory_linked"] for item in cases
        ),
        "parquet_linkage_valid": parquet_exact
        and all(item["automated_gates"]["parquet_linked"] for item in cases),
        "replay_valid": all(
            item["automated_gates"]["replay_valid"] for item in cases
        ),
        "policy_oracle_leakage_zero": all(
            item["automated_gates"]["policy_oracle_leakage_zero"]
            for item in cases
        ),
        "selected_illegal_actions_zero": all(
            item["automated_gates"]["selected_illegal_actions_zero"]
            for item in cases
        ),
        "nonzero_t1_rewards_zero": all(
            item["automated_gates"]["nonzero_t1_rewards_zero"]
            for item in cases
        ),
        "teacher_audit_integrity_valid": audit_integrity_valid,
        "historical_unbound_set_exact": (
            not live_audit_required
            or (
            historical_baseline["valid"] is True
            and audit["historical_unbound_committed"]
            == historical_baseline["expectation"][
                "historical_unbound_committed_count"
            ]
            and audit["historical_unbound_set_sha256"]
            == historical_baseline["expectation"][
                "historical_unbound_committed_set_sha256"
            ]
            and audit["historical_response_commitment_set_sha256"]
            == historical_baseline["expectation"][
                "historical_response_commitment_set_sha256"
            ]
            )
        ),
        "historical_provider_failures_exact": (
            not live_audit_required
            or (
                historical_baseline["valid"] is True
                and audit["prior_provider_failure_count"]
                == historical_baseline["expectation"][
                    "provider_failure_event_quarantine_count"
                ]
                and audit["failure_codes"]
                == historical_baseline["expectation"][
                    "provider_failure_codes"
                ]
                and audit[
                    "provider_failure_audit_commitment_set_sha256"
                ]
                == historical_baseline["expectation"][
                    "provider_failure_audit_commitment_set_sha256"
                ]
            )
        ),
        "final_teacher_audit_bound": final_teacher_audit_bound,
        "teacher_requests_bound": all(
            item["automated_gates"]["teacher_request_bound"]
            for item in cases
        ),
        "tool_quarantine_zero": audit["tool_events"] == 0,
        "identity_match": all(
            item["automated_gates"]["identity_match"] for item in cases
        ),
        "artifact_hashes_valid": (
            trajectory_metadata["manifest_valid"] is True
            and parquet_hash_valid
            and all(
                item["automated_gates"]["trajectory_linked"] for item in cases
            )
        ),
    }
    automated_gates["all_passed"] = all(automated_gates.values())
    use_audit_metrics = live_audit_required
    packet: dict[str, Any] = {
        "schema_version": "1.0",
        "status": (
            "AWAITING_HUMAN_AUDIT"
            if automated_gates["all_passed"]
            else "AUTOMATED_GATE_FAILED"
        ),
        "case_count": len(case_ids),
        "automated_gates": automated_gates,
        "generation_mode": provenance["generation_mode"],
        "provider": provenance["provider"],
        "model": provenance["model"],
        "provider_response_models": provenance["provider_response_models"],
        "total_usage": (
            {field: final_audit_usage[field] for field in _USAGE_FIELDS}
            if use_audit_metrics
            else {field: usage[field] for field in _USAGE_FIELDS}
        ),
        "latency_ms": _latency_summary(
            final_audit_latencies if use_audit_metrics else latencies
        ),
        "attempts": {
            "teacher_audit_manifest_count": audit["manifest_count"],
            "teacher_committed": audit["committed"],
            "teacher_quarantined": audit["quarantined"],
            "teacher_malformed_invalid": audit["malformed_invalid"],
            "teacher_historical_unbound_committed": audit[
                "historical_unbound_committed"
            ],
            "historical_unbound_set_sha256": audit[
                "historical_unbound_set_sha256"
            ],
            "historical_baseline": historical_baseline,
            "successful_response_links": response_audit_links,
            "repair_prompt_cases": repair_prompt_cases,
            "usage_available_final_attempts": sum(
                type(item.get("usage")) is dict
                for item in audit["by_response"].values()
                if item.get("response_commitment_sha256")
                in {
                    record.teacher_response_commitment_sha256
                    for record in records.values()
                }
            ),
            "forbidden_tool_event_count": audit["tool_events"],
            "prior_provider_failure_count": audit[
                "prior_provider_failure_count"
            ],
            "prior_provider_failure_codes": audit["failure_codes"],
            "prior_failure_latency_ms": _latency_summary(
                audit["quarantined_latencies_ms"]
            ),
        },
        "cost": {
            "value": "unknown",
            "reason": "subscription/pricing_not_configured",
        },
        "thresholds": {
            "semantic_usable_min": 8,
            "max_revision_cases": 2,
        },
        "artifact_hashes": {
            "case_file": _sha256(_read_regular(case_file)),
            "enrichment_provenance_manifest": provenance_sha256,
            "trajectory_artifact_manifest": trajectory_metadata[
                "manifest_sha256"
            ],
            "trajectory_parquet": (
                None if parquet_entry is None else parquet_entry["sha256"]
            ),
            "teacher_audit_manifest_set": audit["artifact_set_sha256"],
            "historical_teacher_audit_baseline": historical_baseline[
                "file_sha256"
            ],
            "historical_teacher_audit_expectation": historical_baseline[
                "expectation_file_sha256"
            ],
            "action_dsl_schema": _sha256(
                _read_regular(root / "idea-stage/ACTION_DSL.schema.json")
            ),
        },
        "cases": cases,
    }
    packet["packet_commitment_sha256"] = _packet_commitment(packet)

    markdown = _markdown(packet)
    canonical_packet = _canonical(packet) + b"\n"
    with AnchoredDirectory(output_root, subdirectories=("reports",)) as output:
        json_path = Path("reports/human-audit-packet.json")
        markdown_path = Path("reports/human-audit-packet.md")
        # Preflight both destinations so a hostile link cannot produce a partial pair.
        output.exists_regular(json_path)
        output.exists_regular(markdown_path)

        def verify_markdown(raw: bytes) -> None:
            if raw != markdown or b"PASSED" in raw:
                raise ValueError("human audit markdown verification failed")

        def verify_packet(raw: bytes) -> None:
            parsed = _parse_object(raw, "human audit packet")
            if (
                parsed != packet
                or parsed.get("packet_commitment_sha256")
                != _packet_commitment(parsed)
            ):
                raise ValueError("human audit packet verification failed")

        output.atomic_bytes(
            markdown_path,
            markdown,
            limit=_MAX_PACKET_BYTES,
            verifier=verify_markdown,
        )
        output.atomic_bytes(
            json_path,
            canonical_packet,
            limit=_MAX_PACKET_BYTES,
            verifier=verify_packet,
        )
    return packet

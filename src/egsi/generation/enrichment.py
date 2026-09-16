"""Generate teacher enrichments, validate them, and quarantine every failure."""

from __future__ import annotations

import hashlib
import contextvars
from dataclasses import dataclass
import json
import math
import os
import re
import stat
import warnings
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from pydantic import ValidationError

from egsi.contracts.case import CaseManifest
from egsi.contracts.enrichment import (
    EnrichmentPayload,
    EnrichmentRecord,
    EnrichmentValidation,
    committed_enrichment_record,
)
from egsi.data.context import (
    _read_json,
    _required_mapping,
    _required_string,
    _safe_file,
    build_oracle_context,
)
from egsi.data.git_objects import (
    GitCacheGuard,
    GitCacheIntegrityError,
    GitObjectStore,
)
from egsi.data.repository_paths import canonical_repo_blob_path
from egsi.teacher.base import Teacher, TeacherRequest, TeacherResponse
from egsi.teacher.prompts import enrichment_request
from egsi.generation.safeio import AnchoredDirectory
from egsi.strict_json import strict_json_loads as _strict_json_loads


_SAFE_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_REPAIRS = 2
_MAX_ACTION_DSL_SCHEMA_BYTES = 1_048_576
_FAILURE_ERROR_LIMIT = 2000
_MAX_RESPONSE_BYTES = 1_048_576
_MAX_CANONICAL_PAYLOAD_BYTES = 1_048_576
_MAX_STRING_BYTES = 8_192
_MAX_PRIMARY_ITEMS = 256
_MAX_SUB_ITEMS = 64
_MAX_RECORD_BYTES = 2_097_152
_MAX_PROVIDER_BYTES = 256
_MAX_REQUEST_ID_BYTES = 1_024
_MAX_USAGE_ITEMS = 32
_MAX_USAGE_KEY_BYTES = 128
_MAX_USAGE_VALUE = (1 << 63) - 1
_REPAIR_CODES: tuple[str | None, ...] = (
    None,
    "invalid_structured_output",
    "semantic_validation_failed",
    "invalid_canonical_path",
    "invalid_teacher_response_metadata",
)
_SYMBOL_WINDOW_LINES = 3
_FINAL_IDENTIFIER = re.compile(
    r"^(?:[A-Za-z_$][A-Za-z0-9_$]*\.)*([A-Za-z_$][A-Za-z0-9_$]*)$"
)


_ACTIVE_OUTPUT: contextvars.ContextVar[AnchoredDirectory | None] = (
    contextvars.ContextVar("egsi_enrichment_output", default=None)
)


def _safe_case_id(case_id: str) -> str:
    """Reject a manifest ID which cannot safely be used as a single filename."""

    if not isinstance(case_id, str) or not _SAFE_CASE_ID.fullmatch(case_id):
        raise ValueError("case_id is unsafe for an enrichment filename")
    return case_id


def _schema_enums(schema: dict[str, Any], *path: str) -> set[str]:
    current: Any = schema
    try:
        for part in path:
            current = current[part]
        values = current["enum"]
    except (KeyError, TypeError):
        raise ValueError("ACTION_DSL schema is malformed") from None
    if not isinstance(values, list) or not values or any(not isinstance(value, str) for value in values):
        raise ValueError("ACTION_DSL schema is malformed")
    return set(values)


def _read_bounded_regular(path: Path, *, limit: int) -> bytes:
    """Read an already-resolved regular file only after bounding its size."""

    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > limit
        ):
            raise OSError
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                raise OSError
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OSError
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise OSError
        return b"".join(chunks)
    except OSError:
        raise ValueError("bounded regular-file read failed") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def allowed_action_values(root: Path) -> dict[str, Any]:
    """Read the four action vocabulary enums without accepting malformed DSL input."""

    try:
        path = _safe_file(Path(root), "idea-stage/ACTION_DSL.schema.json")
        raw = _read_bounded_regular(path, limit=_MAX_ACTION_DSL_SCHEMA_BYTES)
        schema = _strict_json_loads(raw, max_bytes=_MAX_ACTION_DSL_SCHEMA_BYTES)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, RecursionError):
        raise ValueError("ACTION_DSL schema is unavailable or malformed") from None
    if not isinstance(schema, dict):
        raise ValueError("ACTION_DSL schema is malformed")
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
    except Exception:
        raise ValueError("ACTION_DSL schema is unavailable or malformed") from None
    return {
        "goals": _schema_enums(schema, "properties", "goal"),
        "operations": _schema_enums(schema, "properties", "operation"),
        "target_kinds": _schema_enums(schema, "$defs", "target", "properties", "kind"),
        "tool_classes": _schema_enums(schema, "properties", "tool_class"),
        "_validator": validator,
    }


def _prompt_vocabulary(vocabulary: dict[str, Any]) -> dict[str, set[str]]:
    """Project a validated Action DSL bundle onto the four prompt enum sets."""

    fields = ("goals", "operations", "target_kinds", "tool_classes")
    if type(vocabulary) is not dict:
        raise ValueError("action vocabulary is malformed")
    try:
        result = {field: vocabulary[field] for field in fields}
    except KeyError:
        raise ValueError("action vocabulary is malformed") from None
    if any(type(value) is not set for value in result.values()):
        raise ValueError("action vocabulary is malformed")
    return result


def _opaque_token(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def possible_prompt_hashes(
    context: Any, vocabulary: dict[str, set[str]]
) -> set[str]:
    """Hashes for every finite canonical prompt this runner is permitted to issue."""

    result: set[str] = set()
    system, user, _ = enrichment_request(
        context, vocabulary, repair_error=None, repair_attempt=0
    )
    result.add("sha256:" + hashlib.sha256((system + user).encode("utf-8")).hexdigest())
    for repair_code in _REPAIR_CODES[1:]:
        for repair_attempt in (1, 2):
            system, user, _ = enrichment_request(
                context,
                vocabulary,
                repair_error=repair_code,
                repair_attempt=repair_attempt,
            )
            result.add(
                "sha256:"
                + hashlib.sha256((system + user).encode("utf-8")).hexdigest()
            )
    return result


def _bounded_payload_validation(payload: EnrichmentPayload) -> EnrichmentValidation | None:
    """Reject huge teacher-shaped objects before they can drive Git lookups."""

    try:
        canonical = json.dumps(payload.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        return EnrichmentValidation(valid=False, invalid_operations=["sha256:payload-canonicalization"])
    bad: list[str] = []
    if len(canonical.encode("utf-8")) > _MAX_CANONICAL_PAYLOAD_BYTES:
        bad.append("payload-too-large")

    def inspect(value: Any, *, sub_list: bool = False) -> None:
        if isinstance(value, str):
            if len(value.encode("utf-8")) > _MAX_STRING_BYTES:
                bad.append("string-too-large")
        elif isinstance(value, list):
            if len(value) > (_MAX_SUB_ITEMS if sub_list else _MAX_PRIMARY_ITEMS):
                bad.append("list-too-large")
            for item in value:
                inspect(item, sub_list=False)
        elif isinstance(value, dict):
            for key, item in value.items():
                inspect(key, sub_list=False)
                inspect(item, sub_list=key in {"resolves_unknowns", "reason_tags"})

    inspect(payload.model_dump(mode="json"))
    if not bad:
        return None
    return EnrichmentValidation(valid=False, invalid_operations=sorted({_opaque_token(item) for item in bad}))


def _receipt_validation(validation: EnrichmentValidation | None) -> dict[str, Any] | None:
    """Never put raw teacher-controlled path/value diagnostics in a receipt."""

    if validation is None:
        return None
    value = validation.model_dump(mode="json")
    for key in (
        "invalid_locations", "invalid_trace_locations", "invalid_goals", "invalid_operations",
        "invalid_target_kinds", "invalid_tool_classes",
    ):
        value[key] = sorted({_opaque_token(item) for item in value[key]})
    return value


def validate_payload(
    case: CaseManifest,
    payload: EnrichmentPayload,
    store: GitObjectStore,
    vocabulary: dict[str, Any],
) -> EnrichmentValidation:
    """Return only structural diagnostics; teacher output is never a Fact or reward."""

    required = ("goals", "operations", "target_kinds", "tool_classes")
    validator = vocabulary.get("_validator")
    if any(key not in vocabulary or not isinstance(vocabulary[key], set) for key in required) or not isinstance(validator, Draft202012Validator):
        raise ValueError("action vocabulary is malformed")

    bounded_validation = _bounded_payload_validation(payload)
    if bounded_validation is not None:
        return bounded_validation

    contains_cache: dict[tuple[str, str], bool] = {}
    blob_cache: dict[str, tuple[str, ...] | None] = {}

    def contains(commit: str, path: str) -> bool:
        key = (commit, path)
        if key not in contains_cache:
            try:
                contains_cache[key] = store.contains(commit, path)
            except GitCacheIntegrityError:
                raise
            except ValueError as exc:
                if exc.args == ("Git cache identity closure changed",):
                    raise GitCacheIntegrityError(exc.args[0]) from exc
                # An unsafe teacher path is semantically invalid, not a local outage.
                contains_cache[key] = False
        return contains_cache[key]

    def vulnerable_blob(path: str) -> bool:
        return contains(case.repository.vulnerable_commit, path)

    def canonical_path(path: str) -> str | None:
        try:
            return canonical_repo_blob_path(path)
        except ValueError:
            return None

    def vulnerable_lines(path: str) -> tuple[str, ...] | None:
        canonical = canonical_path(path)
        if canonical is None or not vulnerable_blob(canonical):
            return None
        if canonical not in blob_cache:
            try:
                blob_cache[canonical] = tuple(
                    store.read_text(
                        case.repository.vulnerable_commit,
                        canonical,
                        max_bytes=1_000_000,
                    ).splitlines()
                )
            except GitCacheIntegrityError:
                raise
            except ValueError as exc:
                if exc.args == ("Git cache identity closure changed",):
                    raise GitCacheIntegrityError(exc.args[0]) from exc
                blob_cache[canonical] = None
            except (FileNotFoundError, UnicodeError):
                blob_cache[canonical] = None
        return blob_cache[canonical]

    def valid_location(item: Any) -> bool:
        canonical = canonical_path(item.path)
        if (
            canonical is None
            or not vulnerable_blob(canonical)
            or item.start_line is None
            or item.end_line is None
            or item.symbol is None
        ):
            return False
        lines = vulnerable_lines(canonical)
        if lines is None:
            return False
        line_count = len(lines)
        if (
            (item.start_line is not None and item.start_line > line_count)
            or (item.end_line is not None and item.end_line > line_count)
        ):
            return False
        match = _FINAL_IDENTIFIER.fullmatch(item.symbol)
        if match is None:
            return False
        identifier = match.group(1)
        window_start = max(1, item.start_line - _SYMBOL_WINDOW_LINES)
        window_end = min(line_count, item.end_line + _SYMBOL_WINDOW_LINES)
        selected = lines[window_start - 1 : window_end]
        identifier_pattern = re.compile(
            rf"(?<![A-Za-z0-9_$]){re.escape(identifier)}(?![A-Za-z0-9_$])"
        )
        return any(identifier_pattern.search(line) is not None for line in selected)

    invalid_locations = sorted(
        {item.path for item in payload.locations if not valid_location(item)}
    )
    invalid_trace_location_set: set[str] = set()
    for item in payload.trace:
        if item.target_kind == "path":
            target_id = canonical_path(item.target_id)
            if target_id is None or not vulnerable_blob(target_id):
                invalid_trace_location_set.add(item.target_id)
            if item.target_location != item.target_id:
                invalid_trace_location_set.add(
                    item.target_location
                    if item.target_location is not None
                    else item.target_id
                )
        if item.target_location is not None:
            target_location = canonical_path(item.target_location)
            if target_location is None or not vulnerable_blob(target_location):
                invalid_trace_location_set.add(item.target_location)
    invalid_trace_locations = sorted(invalid_trace_location_set)
    invalid_goals = sorted({item.goal for item in payload.trace if item.goal not in vocabulary["goals"]})
    invalid_operations = sorted({item.operation for item in payload.trace if item.operation not in vocabulary["operations"]})
    invalid_target_kinds = sorted(
        {item.target_kind for item in payload.trace if item.target_kind not in vocabulary["target_kinds"]}
    )
    invalid_tool_classes = sorted(
        {item.tool_class for item in payload.trace if item.tool_class not in vocabulary["tool_classes"]}
    )
    invalid_operation_set = set(invalid_operations)
    obligation_ids = {item.obligation_id for item in payload.obligations}
    for item in payload.trace:
        action = {
            "schema_version": "1.0", "action_id": "A-teacher", "episode_id": "teacher",
            "branch_id": "teacher", "actor_role": "hypothesis_agent", "goal": item.goal,
            "operation": item.operation,
            "target": {"kind": item.target_kind, "id": item.target_id, "location": item.target_location},
            "resolves_unknowns": item.resolves_unknowns, "preconditions": [],
            "expected_evidence_type": item.expected_evidence_type, "tool_class": item.tool_class,
            "budget_cap": {"seconds": 0, "tool_calls": 0, "tokens": 0},
            "idempotency_key": "sha256:" + "a" * 64,
        }
        if list(dict.fromkeys(item.resolves_unknowns)) != item.resolves_unknowns or not set(item.resolves_unknowns) <= obligation_ids:
            invalid_operation_set.add(item.operation)
        if any(validator.iter_errors(action)):
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


@dataclass(frozen=True)
class _AttemptEvaluation:
    """One runner transition reconstructed from provider text."""

    structured_output_valid: bool
    payload: EnrichmentPayload | None
    validation: EnrichmentValidation | None
    repair_error: str | None


def _repair_error(
    *,
    structured_output_valid: bool,
    validation: EnrichmentValidation | None,
) -> str | None:
    """Return the exact fixed repair category used by the runner state machine."""

    if structured_output_valid is not True:
        if validation is not None:
            raise ValueError("structured-invalid attempt cannot have semantic validation")
        return "invalid_structured_output"
    if validation is None:
        raise ValueError("structured-valid attempt requires semantic validation")
    if validation.valid:
        return None
    if validation.invalid_locations or validation.invalid_trace_locations:
        return "invalid_canonical_path"
    return "semantic_validation_failed"


def _evaluate_enrichment_attempt(
    *,
    text: str,
    schema: dict[str, Any],
    case: CaseManifest,
    store: GitObjectStore,
    vocabulary: dict[str, Any],
) -> _AttemptEvaluation:
    """Apply the runner's strict schema, Pydantic, semantic, and DSL transition."""

    try:
        decoded = _strict_json_loads(text, max_bytes=_MAX_RESPONSE_BYTES)
        if not isinstance(decoded, dict):
            raise ValueError
        if any(Draft202012Validator(schema).iter_errors(decoded)):
            raise ValueError
        payload = EnrichmentPayload.model_validate(decoded)
    except (
        json.JSONDecodeError,
        ValidationError,
        TypeError,
        ValueError,
        RecursionError,
    ):
        return _AttemptEvaluation(
            structured_output_valid=False,
            payload=None,
            validation=None,
            repair_error=_repair_error(
                structured_output_valid=False, validation=None
            ),
        )
    validation = validate_payload(case, payload, store, vocabulary)
    return _AttemptEvaluation(
        structured_output_valid=True,
        payload=payload,
        validation=validation,
        repair_error=_repair_error(
            structured_output_valid=True, validation=validation
        ),
    )


def _atomic_json_write(path: Path, value: dict[str, Any]) -> None:
    """Atomically replace JSON; ``os.replace`` is the irreversible commit point.

    Everything before ``replace`` must succeed or the old file remains intact.  Once
    ``replace`` returns, the new file is committed; directory fsync is attempted for
    durability but must not make the caller report a false write failure.
    """

    active = _ACTIVE_OUTPUT.get()
    if active is not None:
        active.atomic_json(active.relative(path), value, limit=_MAX_RECORD_BYTES)
        return
    with AnchoredDirectory(path.parent) as standalone:
        standalone.atomic_json(Path(path.name), value, limit=_MAX_RECORD_BYTES)


def write_failure(
    output_dir: Path,
    case_id: str,
    attempts: int,
    error: str,
    validation: EnrichmentValidation | None,
    *,
    error_kind: str = "semantic_invalid",
    failed_attempt: int | None = None,
    validation_attempt: int | None = None,
) -> None:
    """Write a redacted quarantine receipt and never a positive transition."""

    safe_id = _safe_case_id(case_id)
    value = {
        "schema_version": "1.0",
        "case_id": safe_id,
        "attempts": attempts,
        "error": error[:_FAILURE_ERROR_LIMIT],
        "error_kind": error_kind,
        "failed_attempt": failed_attempt,
        "validation_attempt": validation_attempt,
        "validation": _receipt_validation(validation),
        "positive_transition_written": False,
    }
    _atomic_json_write(Path(output_dir) / "failures" / f"{safe_id}.json", value)


def _load_store(root: Path, case: CaseManifest) -> GitObjectStore:
    """Reuse context's declared-file and Git-cache boundary checks exactly."""

    manifest = _read_json(Path(root), case.artifacts.manifest_path)
    resolution = _required_mapping(manifest, "resolution")
    cache_path = _required_string(resolution, "cache_path")
    try:
        return GitCacheGuard(root, cache_path).open_store()
    except (FileNotFoundError, RuntimeError, ValueError):
        raise ValueError("declared Git cache is unavailable") from None


def _safe_preparation(root: Path, case: CaseManifest):
    """Build every local prerequisite before any teacher request."""

    try:
        return build_oracle_context(root, case), _load_store(root, case), allowed_action_values(root)
    except Exception:
        # Context/manifest errors can mention supplied paths; receipts must not expose them.
        raise ValueError("enrichment preparation failed") from None


def _latency_integer(value: float) -> int:
    """Normalize provider float milliseconds by deterministic truncation toward zero."""

    return max(0, math.floor(value))


def _safe_output_root(value: Path) -> Path:
    """Create/validate the complete output boundary without following subdir links."""

    path = Path(value).absolute()
    try:
        # Verify every already-present component before creating the next one;
        # ``mkdir(parents=True)`` alone can silently traverse an attacker link.
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current = current / part
            try:
                mode = current.lstat().st_mode
            except FileNotFoundError:
                current.mkdir()
                mode = current.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise OSError
        if path.is_symlink() or not path.is_dir():
            raise OSError
        root = path.resolve(strict=True)
        for name in ("failures", "quarantine"):
            child = root / name
            if child.exists() or child.is_symlink():
                if child.is_symlink() or not child.is_dir():
                    raise OSError
            else:
                child.mkdir()
            resolved = child.resolve(strict=True)
            resolved.relative_to(root)
    except (OSError, ValueError):
        raise RuntimeError("fatal: unsafe output boundary") from None
    return root


def _quarantine_existing(target: Path, quarantine: Path, case_id: str, *, oversized: bool = False) -> None:
    """Move a pre-existing unusable positive out of the active namespace."""

    active = _ACTIVE_OUTPUT.get()
    owned: AnchoredDirectory | None = None
    if active is None:
        owned = AnchoredDirectory(target.parent, subdirectories=(quarantine.name,))
        active = owned
    try:
        relative_target = active.relative(target)
        if oversized:
            size = active.stat_regular(relative_target).st_size
            destination = Path(quarantine.name) / f"{case_id}.oversized-{size}.json"
        else:
            raw = active.read_regular(relative_target, limit=_MAX_RECORD_BYTES)
            digest = hashlib.sha256(raw).hexdigest()
            destination = Path(quarantine.name) / f"{case_id}.{digest}.json"
        active.quarantine(relative_target, destination)
    except (OSError, ValueError, OverflowError):
        raise RuntimeError("fatal: existing positive quarantine failed") from None
    finally:
        if owned is not None:
            owned.close()


def _existing_regular_file(target: Path) -> bool:
    """Return whether a case target exists as a non-symlink regular file."""

    active = _ACTIVE_OUTPUT.get()
    if active is None:
        raise RuntimeError("fatal: output anchor is unavailable")
    try:
        return active.exists_regular(active.relative(target))
    except (OSError, ValueError):
        raise RuntimeError("fatal: unsafe existing positive") from None


def _read_existing_record(target: Path) -> str:
    """Bounded record read after lstat; oversized/sparse files never reach JSON."""

    active = _ACTIVE_OUTPUT.get()
    if active is None:
        raise RuntimeError("fatal: output anchor is unavailable")
    return active.read_regular(
        active.relative(target), limit=_MAX_RECORD_BYTES
    ).decode("utf-8")


def _remove_output_file(path: Path) -> None:
    active = _ACTIVE_OUTPUT.get()
    if active is None:
        raise RuntimeError("fatal: output anchor is unavailable")
    active.unlink_regular(active.relative(path), missing_ok=True)


def _response_metadata_is_bounded(response: TeacherResponse) -> bool:
    """Validate all provider-controlled record metadata before serialization."""

    def safe_utf8_len(value: str) -> int | None:
        try:
            return len(value.encode("utf-8"))
        except UnicodeError:
            return None

    def bounded(value: str, limit: int) -> bool:
        length = safe_utf8_len(value)
        return bool(value) and length is not None and length <= limit
    if (
        not bounded(response.provider, _MAX_PROVIDER_BYTES)
        or not bounded(response.model, _MAX_PROVIDER_BYTES)
        or not bounded(response.requested_model, _MAX_PROVIDER_BYTES)
        or not bounded(response.provider_response_model, _MAX_PROVIDER_BYTES)
    ):
        return False
    request_id_length = safe_utf8_len(response.provider_request_id) if response.provider_request_id is not None else 0
    if response.provider_request_id is not None and (
        not response.provider_request_id or request_id_length is None or request_id_length > _MAX_REQUEST_ID_BYTES
    ):
        return False
    return (
        len(response.usage) <= _MAX_USAGE_ITEMS
        and all(
            isinstance(key, str) and bool(key) and (key_length := safe_utf8_len(key)) is not None and key_length <= _MAX_USAGE_KEY_BYTES
            and type(value) is int and 0 <= value <= _MAX_USAGE_VALUE
            for key, value in response.usage.items()
        )
    )


class EnrichmentRunner:
    """A bounded repair loop whose only successful artifact is a validated record."""

    def __init__(
        self,
        root: Path,
        teacher: Teacher,
        max_repairs: int = 2,
        *,
        generation_mode: str | None = None,
    ) -> None:
        if type(max_repairs) is not int or not 0 <= max_repairs <= _MAX_REPAIRS:
            raise ValueError(f"max_repairs must be an integer between 0 and {_MAX_REPAIRS}")
        self.root = Path(root)
        self.teacher = teacher
        self.max_repairs = max_repairs
        if generation_mode is None:
            generation_mode = (
                "fixture"
                if teacher.provider == "fixture" and teacher.model == "fixture-v1"
                else "live"
            )
        if generation_mode not in {"fixture", "live"}:
            raise ValueError("generation_mode must be fixture or live")
        self.generation_mode = generation_mode

    def _failure(self, output_dir: Path, case: CaseManifest, attempts: int, validation: EnrichmentValidation | None,
                 *, error_kind: str = "semantic_invalid", failed_attempt: int | None = None,
                 validation_attempt: int | None = None) -> None:
        try:
            write_failure(output_dir, case.case_id, attempts, "teacher output remained invalid", validation,
                          error_kind=error_kind, failed_attempt=failed_attempt,
                          validation_attempt=validation_attempt)
        except OSError:
            raise RuntimeError("fatal: failure receipt write failed") from None
        raise ValueError("teacher output remained invalid") from None

    def _terminal_teacher_failure(self, output_dir: Path, case: CaseManifest, attempt: int, kind: str) -> None:
        try:
            write_failure(output_dir, case.case_id, attempt, "teacher request failed", None,
                          error_kind=kind, failed_attempt=attempt, validation_attempt=None)
        except OSError:
            raise RuntimeError("fatal: teacher failure receipt write failed") from None
        raise RuntimeError(f"teacher {kind} failure") from None

    def _discard_untrusted_positive_then_fail(
        self,
        output_dir: Path,
        case: CaseManifest,
        attempts: int,
        validation: EnrichmentValidation | None,
        target: Path,
    ) -> None:
        """Remove a post-commit artifact which failed validation before receipt write.

        A receipt saying ``positive_transition_written: false`` would be deceptive if
        this cleanup cannot be confirmed, so that situation is a stable fatal error
        rather than a normal quarantine result.
        """

        try:
            _remove_output_file(target)
        except (OSError, ValueError):
            raise RuntimeError("fatal: untrusted positive cleanup failed") from None
        try:
            if _existing_regular_file(target):
                raise RuntimeError("fatal: untrusted positive cleanup failed")
        except RuntimeError:
            raise RuntimeError("fatal: untrusted positive cleanup failed")
        try:
            write_failure(output_dir, case.case_id, attempts, "output integrity failure", validation,
                          error_kind="output_integrity", failed_attempt=attempts,
                          validation_attempt=attempts if validation is not None and validation.valid else None)
        except OSError:
            raise RuntimeError("fatal: output integrity receipt write failed") from None
        raise RuntimeError("output integrity failure") from None

    def run(self, case: CaseManifest, output_dir: Path) -> EnrichmentRecord:
        try:
            anchored = AnchoredDirectory(
                Path(output_dir), subdirectories=("failures", "quarantine")
            )
        except (OSError, ValueError):
            raise RuntimeError("fatal: unsafe output boundary") from None
        with anchored:
            token = _ACTIVE_OUTPUT.set(anchored)
            try:
                return self._run_anchored(case, anchored.path)
            finally:
                _ACTIVE_OUTPUT.reset(token)

    def _run_anchored(self, case: CaseManifest, output_dir: Path) -> EnrichmentRecord:
        safe_id = _safe_case_id(case.case_id)
        try:
            context, store, vocabulary = _safe_preparation(self.root, case)
        except ValueError:
            raise RuntimeError("fatal: enrichment preparation failed") from None
        try:
            prompt_vocabulary = _prompt_vocabulary(vocabulary)

            target = output_dir / f"{safe_id}.json"
            if _existing_regular_file(target):
                try:
                    existing = EnrichmentRecord.model_validate_json(_read_existing_record(target))
                    if (
                        existing.case_id == safe_id
                        and existing.generation_mode == self.generation_mode
                        and existing.source_context_sha256 == context.sha256
                        and existing.provider == self.teacher.provider
                        and existing.model == self.teacher.model
                        and existing.requested_model == self.teacher.model
                        and existing.temperature == 0.0
                        and existing.max_tokens == 8192
                        and existing.prompt_sha256
                        in possible_prompt_hashes(context, prompt_vocabulary)
                        and existing.structured_output_valid is True
                        and existing.validation.valid is True
                    ):
                        checked = validate_payload(case, existing.payload, store, vocabulary)
                        if not checked.valid or checked != existing.validation:
                            raise ValueError("existing record validation mismatch")
                        stale_failure = output_dir / "failures" / f"{safe_id}.json"
                        try:
                            _remove_output_file(stale_failure)
                        except (OSError, ValueError):
                            raise RuntimeError("fatal: stale failure cleanup failed") from None
                        return existing
                except GitCacheIntegrityError:
                    raise RuntimeError(
                        "fatal: local Git cache integrity failure"
                    ) from None
                except OverflowError:
                    _quarantine_existing(target, output_dir / "quarantine", safe_id, oversized=True)
                except (OSError, ValidationError, ValueError, json.JSONDecodeError):
                    pass
                if _existing_regular_file(target):
                    _quarantine_existing(target, output_dir / "quarantine", safe_id)

            repair_error: str | None = None
            last_validation: EnrichmentValidation | None = None
            last_validation_attempt: int | None = None
            last_error_kind = "structured_invalid"
            failed_attempt = 0
            for attempt in range(1, self.max_repairs + 2):
                system, user, schema = enrichment_request(
                    context,
                    prompt_vocabulary,
                    repair_error=repair_error,
                    repair_attempt=attempt - 1,
                )
                prompt_sha = "sha256:" + hashlib.sha256((system + user).encode("utf-8")).hexdigest()
                try:
                    response = self.teacher.generate(
                        TeacherRequest(system=system, user=user, schema=schema, temperature=0.0, max_tokens=8192)
                    )
                except Exception:
                    self._terminal_teacher_failure(output_dir, case, attempt, "transport")
                try:
                    # This must be the first operation on the provider-controlled
                    # result. model_copy/model_construct and arbitrary Teacher
                    # implementations can bypass every Pydantic validator.
                    # Pydantic serializer warnings can include provider-controlled
                    # reprs, so keep this fixed-failure boundary silent.
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        raw_response = response.model_dump(mode="json")
                        if type(raw_response) is not dict:
                            raise TypeError("teacher response dump must be an exact dict")
                        # Round-trip through canonical JSON so nested Mapping/model
                        # instances and other Python-only values cannot cross the
                        # provider boundary under a superficially valid top-level
                        # dictionary.
                        canonical_response = json.loads(
                            json.dumps(
                                raw_response,
                                allow_nan=False,
                                ensure_ascii=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            )
                        )
                        response = TeacherResponse.model_validate(canonical_response)
                except Exception:
                    self._terminal_teacher_failure(output_dir, case, attempt, "provenance")
                if (
                    response.provider != self.teacher.provider
                    or response.model != self.teacher.model
                    or response.requested_model != self.teacher.model
                ):
                    self._terminal_teacher_failure(output_dir, case, attempt, "provenance")
                if not _response_metadata_is_bounded(response):
                    self._terminal_teacher_failure(output_dir, case, attempt, "teacher_response_metadata")
                try:
                    evaluation = _evaluate_enrichment_attempt(
                        text=response.text,
                        schema=schema,
                        case=case,
                        store=store,
                        vocabulary=vocabulary,
                    )
                except GitCacheIntegrityError:
                    raise RuntimeError(
                        "fatal: local Git cache integrity failure"
                    ) from None
                except RuntimeError:
                    raise RuntimeError("fatal: local_git failure") from None
                if evaluation.structured_output_valid is not True:
                    repair_error = evaluation.repair_error
                    last_error_kind = "structured_invalid"
                    failed_attempt = attempt
                    continue
                payload = evaluation.payload
                validation = evaluation.validation
                if payload is None or validation is None:
                    raise RuntimeError("fatal: attempt evaluation invariant failed")
                last_validation = validation
                last_validation_attempt = attempt
                if not validation.valid:
                    repair_error = evaluation.repair_error
                    last_error_kind = "semantic_invalid"
                    failed_attempt = attempt
                    continue
                try:
                    record = committed_enrichment_record(
                        case_id=safe_id,
                        generation_mode=self.generation_mode,
                        provider=response.provider,
                        model=response.model,
                        requested_model=response.requested_model,
                        provider_response_model=response.provider_response_model,
                        teacher_response_commitment_sha256=response.response_commitment_sha256,
                        provider_request_id=response.provider_request_id,
                        prompt_sha256=prompt_sha,
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
                    repair_error = "invalid_teacher_response_metadata"
                    last_error_kind = "teacher_response_metadata_invalid"
                    failed_attempt = attempt
                    continue
                if len(record.model_dump_json().encode("utf-8")) > _MAX_RECORD_BYTES:
                    self._terminal_teacher_failure(output_dir, case, attempt, "record_too_large")
                stale_failure = output_dir / "failures" / f"{safe_id}.json"
                try:
                    _remove_output_file(stale_failure)
                except (OSError, ValueError):
                    raise RuntimeError("fatal: stale failure cleanup failed") from None
                target = output_dir / f"{safe_id}.json"
                committed_to_disk = False
                try:
                    _atomic_json_write(target, record.model_dump(mode="json"))
                    committed_to_disk = True
                    # Re-read the committed object before treating it as a positive transition.
                    committed = EnrichmentRecord.model_validate_json(
                        _read_existing_record(target)
                    )
                except (OSError, ValidationError, ValueError, json.JSONDecodeError):
                    if committed_to_disk:
                        # A positive artifact now exists and must be removed before a
                        # false-transition receipt.  A pre-commit error preserves any old
                        # target, so it must take the ordinary failure path instead.
                        return self._discard_untrusted_positive_then_fail(
                            output_dir, case, attempt, last_validation, target
                        )
                    raise RuntimeError("fatal: positive output write failed") from None
                if (
                    committed != record
                    or committed.structured_output_valid is not True
                    or committed.validation.valid is not True
                ):
                    return self._discard_untrusted_positive_then_fail(
                        output_dir, case, attempt, last_validation, target
                    )
                return committed
            return self._failure(output_dir, case, self.max_repairs + 1, last_validation,
                                 error_kind=last_error_kind, failed_attempt=failed_attempt,
                                 validation_attempt=last_validation_attempt)
        finally:
            store.close()

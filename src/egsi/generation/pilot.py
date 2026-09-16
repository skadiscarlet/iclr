"""Restartable Phase A enrichment and honest T1 trajectory pilots."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from egsi.contracts.case import CaseManifest, load_case_catalog
from egsi.contracts.enrichment import EnrichmentRecord
from egsi.contracts.trajectory import EpisodeEvent, T1Transition
from egsi.generation.enrichment import (
    EnrichmentRunner,
    _load_store,
    _prompt_vocabulary,
    allowed_action_values,
    possible_prompt_hashes,
    validate_payload,
)
from egsi.generation.redaction import key_hits, policy_value_hits
from egsi.generation.replay import replay_events
from egsi.generation.trajectory import (
    _atomic_bytes,
    _canonical_json_bytes,
    compile_t1_episode,
    episode_commitment,
    read_parquet,
    write_jsonl,
    write_parquet,
)
from egsi.generation.safeio import (
    AnchoredDirectory,
    BatchLock,
    active_batch_lock,
    open_directory_fd,
)
from egsi.teacher.base import Teacher
from egsi.teacher.fixture import FixtureTeacher


_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_INPUT_BYTES = 16 * 1024 * 1024
_MAX_CASE_FILE_BYTES = 64 * 1024
_MAX_FAILURES = 10_000
_USAGE_KEYS = frozenset(
    {
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "prompt_tokens",
        "completion_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
    }
)


def _is_below(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_fixture_output_root(root: Path, output_root: Path) -> Path:
    """Resolve and validate the deliberately non-promotable fixture boundary."""

    try:
        project_root = Path(root).resolve(strict=True)
        candidate = Path(output_root).absolute().resolve(strict=False)
        work_root = (project_root / ".work").resolve(strict=False)
        temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
    except (OSError, ValueError):
        raise ValueError("fixture output root is invalid") from None
    if not (_is_below(candidate, work_root) or _is_below(candidate, temporary_root)):
        raise ValueError(
            "fixture output root is outside .work or the system temporary root"
        )

    absolute = Path(output_root).absolute()
    current = Path(absolute.anchor)
    try:
        for component in absolute.parts[1:]:
            current = current / component
            try:
                mode = current.lstat().st_mode
            except FileNotFoundError:
                break
            if stat.S_ISLNK(mode):
                raise ValueError("fixture output root contains a symbolic link")
    except OSError:
        raise ValueError("fixture output root is invalid") from None
    return candidate


def _is_fixture_provenance(provider: object, model: object) -> bool:
    return (
        provider == FixtureTeacher.provider
        and model == FixtureTeacher.model
    )


def _teacher_generation_mode(teacher: Teacher) -> str:
    return (
        "fixture"
        if isinstance(teacher, FixtureTeacher)
        or _is_fixture_provenance(
            getattr(teacher, "provider", None),
            getattr(teacher, "model", None),
        )
        else "live"
    )


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _dict_commitment(value: dict[str, Any], commitment_key: str) -> str:
    canonical = dict(value)
    canonical.pop(commitment_key, None)
    return _sha256(_canonical_json_bytes(canonical, limit=_MAX_INPUT_BYTES))


def guard_fixture_teacher_output(
    root: Path, output_root: Path, teacher: Teacher
) -> Path:
    """Apply the fixture-only output restriction at an orchestration boundary."""

    is_fixture = isinstance(teacher, FixtureTeacher) or _is_fixture_provenance(
        getattr(teacher, "provider", None),
        getattr(teacher, "model", None),
    )
    if is_fixture:
        return validate_fixture_output_root(root, output_root)
    return Path(output_root)


def guard_fixture_enrichment_output(
    root: Path,
    output_root: Path,
    records: list[EnrichmentRecord],
) -> Path:
    """Keep every batch containing fixture provenance out of promotable roots."""

    if any(
        _is_fixture_provenance(record.provider, record.model)
        for record in records
    ):
        return validate_fixture_output_root(root, output_root)
    return Path(output_root)


def _write_provenance_manifest(
    output_dir: Path,
    ids: list[str],
    records: list[EnrichmentRecord],
    failure_receipts: list[str],
    *,
    generation_mode: str,
    provider: str,
    model: str,
    pragmatic_state_sha256: str | None = None,
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for record in records:
        relative = f"{record.case_id}.json"
        raw = _read_regular(output_dir / relative, limit=2_097_152)
        entries.append(
            {
                "case_id": record.case_id,
                "relative_path": relative,
                "file_sha256": _sha256(raw),
                "kind": "enrichment_record",
                "record_commitment_sha256": record.record_commitment_sha256,
                "requested_model": record.requested_model,
                "provider_response_model": record.provider_response_model,
                "teacher_response_commitment_sha256": record.teacher_response_commitment_sha256,
            }
        )
    for case_id in failure_receipts:
        relative = f"failures/{case_id}.json"
        raw = _read_regular(output_dir / relative, limit=2_097_152)
        entries.append(
            {
                "case_id": case_id,
                "relative_path": relative,
                "file_sha256": _sha256(raw),
                "kind": "failure_receipt",
                "record_commitment_sha256": None,
                "requested_model": None,
                "provider_response_model": None,
                "teacher_response_commitment_sha256": None,
            }
        )
    manifest: dict[str, Any] = {
        "schema_version": (
            "1.1" if pragmatic_state_sha256 is not None else "1.0"
        ),
        "stage": "enrichment_provenance",
        "generation_mode": generation_mode,
        "provider": provider,
        "model": model,
        "requested_provider": provider,
        "requested_model": model,
        "provider_response_models": sorted({record.provider_response_model for record in records}),
        "provider_response_model_counts": dict(sorted(Counter(record.provider_response_model for record in records).items())),
        "requested_case_ids": ids,
        "artifacts": entries,
    }
    if pragmatic_state_sha256 is not None:
        manifest["pragmatic_state_sha256"] = pragmatic_state_sha256
    manifest["batch_commitment_sha256"] = _dict_commitment(
        manifest, "batch_commitment_sha256"
    )
    path = output_dir / "_batch-provenance.json"
    write_report(path, manifest)
    manifest_sha256 = _sha256(_read_regular(path, limit=2_097_152))
    result = {
        "generation_mode": generation_mode,
        "provider": provider,
        "model": model,
        "requested_provider": provider,
        "requested_model": model,
        "provider_response_models": manifest["provider_response_models"],
        "provider_response_model_counts": manifest["provider_response_model_counts"],
        "manifest_sha256": manifest_sha256,
        "batch_commitment_sha256": manifest["batch_commitment_sha256"],
    }
    if pragmatic_state_sha256 is not None:
        result["pragmatic_state_sha256"] = pragmatic_state_sha256
    return result


def _validate_provenance_expectation(value: object) -> dict[str, Any]:
    keys = {
        "generation_mode",
        "provider",
        "model",
        "requested_provider",
        "requested_model",
        "provider_response_models",
        "provider_response_model_counts",
        "manifest_sha256",
        "batch_commitment_sha256",
    }
    if type(value) is not dict or set(value) != keys:
        raise ValueError("trusted provenance expectation is required")
    result = dict(value)
    if result["generation_mode"] not in {"fixture", "live"}:
        raise ValueError("trusted generation mode is invalid")
    string_keys = keys - {"provider_response_models", "provider_response_model_counts"}
    if any(type(result[key]) is not str or not result[key] for key in string_keys):
        raise ValueError("trusted provenance expectation is invalid")
    if (
        result["provider"] != result["requested_provider"]
        or result["model"] != result["requested_model"]
        or type(result["provider_response_models"]) is not list
        or result["provider_response_models"] != sorted(set(result["provider_response_models"]))
        or any(type(item) is not str or not item for item in result["provider_response_models"])
        or type(result["provider_response_model_counts"]) is not dict
        or set(result["provider_response_model_counts"]) != set(result["provider_response_models"])
        or any(type(count) is not int or count < 1 for count in result["provider_response_model_counts"].values())
    ):
        raise ValueError("trusted model provenance is invalid")
    for key in ("manifest_sha256", "batch_commitment_sha256"):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", result[key]):
            raise ValueError("trusted provenance commitment is invalid")
    return result


def trusted_provenance_expectation(
    input_root: Path,
    *,
    generation_mode: str,
    provider: str,
    model: str,
    manifest_sha256: str,
    batch_commitment_sha256: str,
) -> dict[str, Any]:
    """Bind CLI requested identity to observed identities in the committed manifest."""

    raw = _read_regular(Path(input_root) / "_batch-provenance.json", limit=2_097_152)
    if _sha256(raw) != manifest_sha256:
        raise ValueError("provenance manifest commitment mismatch")
    try:
        manifest = json.loads(raw)
    except Exception:
        raise ValueError("provenance manifest is invalid") from None
    if type(manifest) is not dict:
        raise ValueError("provenance manifest is invalid")
    return _validate_provenance_expectation(
        {
            "generation_mode": generation_mode,
            "provider": provider,
            "model": model,
            "requested_provider": manifest.get("requested_provider"),
            "requested_model": manifest.get("requested_model"),
            "provider_response_models": manifest.get("provider_response_models"),
            "provider_response_model_counts": manifest.get("provider_response_model_counts"),
            "manifest_sha256": manifest_sha256,
            "batch_commitment_sha256": batch_commitment_sha256,
        }
    )


def _load_committed_provenance(
    input_root: Path,
    ids: list[str],
    expected_provenance: object,
) -> tuple[dict[str, EnrichmentRecord], dict[str, Any]]:
    expected = _validate_provenance_expectation(expected_provenance)
    raw = _read_regular(input_root / "_batch-provenance.json", limit=2_097_152)
    if _sha256(raw) != expected["manifest_sha256"]:
        raise ValueError("provenance manifest commitment mismatch")
    try:
        manifest = json.loads(raw)
    except Exception:
        raise ValueError("provenance manifest is invalid") from None
    required = {
        "schema_version",
        "stage",
        "generation_mode",
        "provider",
        "model",
        "requested_provider",
        "requested_model",
        "provider_response_models",
        "provider_response_model_counts",
        "requested_case_ids",
        "artifacts",
        "batch_commitment_sha256",
    }
    if (
        type(manifest) is not dict
        or set(manifest) != required
        or manifest.get("schema_version") != "1.0"
        or manifest.get("stage") != "enrichment_provenance"
        or manifest.get("generation_mode") != expected["generation_mode"]
        or manifest.get("provider") != expected["provider"]
        or manifest.get("model") != expected["model"]
        or manifest.get("requested_provider") != expected["requested_provider"]
        or manifest.get("requested_model") != expected["requested_model"]
        or manifest.get("provider_response_models") != expected["provider_response_models"]
        or manifest.get("provider_response_model_counts") != expected["provider_response_model_counts"]
        or manifest.get("requested_case_ids") != ids
        or manifest.get("batch_commitment_sha256")
        != expected["batch_commitment_sha256"]
        or _dict_commitment(manifest, "batch_commitment_sha256")
        != manifest.get("batch_commitment_sha256")
        or type(manifest.get("artifacts")) is not list
        or len(manifest["artifacts"]) > len(ids)
    ):
        raise ValueError("provenance manifest is invalid")

    records: dict[str, EnrichmentRecord] = {}
    seen_case_ids: set[str] = set()
    for entry in manifest["artifacts"]:
        if type(entry) is not dict or set(entry) != {
            "case_id",
            "relative_path",
            "file_sha256",
            "kind",
            "record_commitment_sha256",
            "requested_model",
            "provider_response_model",
            "teacher_response_commitment_sha256",
        }:
            raise ValueError("provenance record entry is invalid")
        case_id = entry.get("case_id")
        if (
            type(case_id) is not str
            or case_id not in ids
            or entry.get("kind") not in {"enrichment_record", "failure_receipt"}
            or type(entry.get("file_sha256")) is not str
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", entry["file_sha256"])
        ):
            raise ValueError("provenance record entry is invalid")
        if case_id in seen_case_ids:
            raise ValueError("duplicate provenance case ID")
        seen_case_ids.add(case_id)
        if entry["kind"] == "failure_receipt":
            if (
                entry.get("relative_path") != f"failures/{case_id}.json"
                or entry.get("record_commitment_sha256") is not None
                or entry.get("requested_model") is not None
                or entry.get("provider_response_model") is not None
                or entry.get("teacher_response_commitment_sha256") is not None
            ):
                raise ValueError("provenance failure entry is invalid")
            receipt_raw = _read_regular(
                input_root / entry["relative_path"], limit=2_097_152
            )
            if _sha256(receipt_raw) != entry["file_sha256"]:
                raise ValueError("failure receipt commitment mismatch")
            continue
        if (
            entry.get("relative_path") != f"{case_id}.json"
            or type(entry.get("record_commitment_sha256")) is not str
            or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", entry["record_commitment_sha256"]
            )
        ):
            raise ValueError("provenance record entry is invalid")
        record_raw = _read_regular(input_root / entry["relative_path"], limit=2_097_152)
        if _sha256(record_raw) != entry["file_sha256"]:
            raise ValueError("enrichment artifact commitment mismatch")
        record = EnrichmentRecord.model_validate_json(record_raw)
        if (
            record.case_id != case_id
            or record.generation_mode != expected["generation_mode"]
            or record.provider != expected["provider"]
            or record.model != expected["model"]
            or record.requested_model != expected["requested_model"]
            or record.requested_model != entry["requested_model"]
            or record.provider_response_model != entry["provider_response_model"]
            or record.teacher_response_commitment_sha256 != entry["teacher_response_commitment_sha256"]
            or record.record_commitment_sha256
            != entry["record_commitment_sha256"]
        ):
            raise ValueError("enrichment provenance binding mismatch")
        records[case_id] = record
    observed = Counter(record.provider_response_model for record in records.values())
    if (
        sorted(observed) != manifest["provider_response_models"]
        or dict(sorted(observed.items())) != manifest["provider_response_model_counts"]
    ):
        raise ValueError("provider response model summary mismatch")
    return records, expected


def _validate_case_ids(case_ids: object) -> list[str]:
    if type(case_ids) is not list or not case_ids or len(case_ids) > _MAX_FAILURES:
        raise ValueError("case ID list must be a bounded non-empty list")
    result: list[str] = []
    for value in case_ids:
        if type(value) is not str or not _CASE_ID.fullmatch(value):
            raise ValueError("invalid case ID")
        result.append(value)
    if len(result) != len(set(result)):
        raise ValueError("duplicate case ID")
    return result


def read_case_ids(path: Path) -> list[str]:
    """Read a bounded, stable, single-link regular frozen case list."""

    if not isinstance(path, Path):
        raise ValueError("case file must be a pathlib.Path")
    try:
        raw = _read_regular(path, limit=_MAX_CASE_FILE_BYTES)
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError, ValueError):
        raise ValueError("case file is unreadable") from None
    values = [line.split("#", 1)[0].strip() for line in lines]
    values = [value for value in values if value]
    try:
        return _validate_case_ids(values)
    except ValueError as exc:
        message = str(exc)
        if "non-empty" in message:
            raise ValueError("empty case file") from None
        raise


def catalog_index(root: Path) -> dict[str, CaseManifest]:
    """Load the validated catalog and reject duplicate identities."""

    cases = load_case_catalog(Path(root) / "data/catalog/cases.jsonl")
    result = {case.case_id: case for case in cases}
    if len(result) != len(cases):
        raise ValueError("catalog contains duplicate case IDs")
    return result


def _failure(stage: str, code: str) -> dict[str, str]:
    return {"stage": stage, "error": code[:256]}


def _exception_code(error: Exception) -> str:
    if isinstance(error, RuntimeError) and str(error) == "fatal: enrichment preparation failed":
        return "enrichment_preparation"
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, PermissionError):
        return "permission"
    if isinstance(error, FileNotFoundError):
        return "not_found"
    if isinstance(error, UnicodeError):
        return "encoding"
    if isinstance(error, OSError):
        return "io"
    if isinstance(error, TypeError):
        return "type"
    if isinstance(error, ValueError):
        return "validation"
    if isinstance(error, RuntimeError):
        return "runtime"
    return "error"


def write_report(path: Path, report: dict[str, Any]) -> None:
    """Atomically write one finite JSON report without following symlinks."""

    if not isinstance(path, Path) or type(report) is not dict:
        raise ValueError("report path and payload are invalid")
    raw = _canonical_json_bytes(report, limit=_MAX_INPUT_BYTES) + b"\n"

    def verify(value: bytes) -> None:
        decoded = json.loads(value)
        if type(decoded) is not dict or decoded != report:
            raise ValueError("report readback verification failed")

    _atomic_bytes(path, raw, verify)


def _open_existing_parent(path: Path) -> int:
    try:
        return open_directory_fd(path, create=False)
    except ValueError as exc:
        raise OSError("unsafe existing parent") from exc


def _read_regular(path: Path, *, limit: int = _MAX_INPUT_BYTES) -> bytes:
    """Read one stable, unambiguous regular file through an anchored POSIX fd."""

    if (
        os.name != "posix"
        or not isinstance(path, Path)
        or not path.name
        or type(limit) is not int
        or limit < 0
    ):
        raise ValueError("input must be a regular non-symlink file")
    try:
        parent_fd = _open_existing_parent(path.parent)
        try:
            fd = os.open(
                path.name,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd,
            )
            try:
                before = os.fstat(fd)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_size < 0
                    or before.st_size > limit
                ):
                    raise ValueError
                chunks: list[bytes] = []
                remaining = before.st_size
                while remaining:
                    chunk = os.read(fd, min(1_048_576, remaining))
                    if not chunk:
                        raise ValueError
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if os.read(fd, 1):
                    raise ValueError
                raw = b"".join(chunks)
                after = os.fstat(fd)
                identity = lambda value: (
                    value.st_dev,
                    value.st_ino,
                    value.st_size,
                    value.st_mtime_ns,
                    value.st_ctime_ns,
                    value.st_nlink,
                )
                if (
                    len(raw) != before.st_size
                    or not stat.S_ISREG(after.st_mode)
                    or after.st_nlink != 1
                    or identity(before) != identity(after)
                ):
                    raise ValueError
                return raw
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
    except FileNotFoundError:
        raise
    except Exception:
        raise ValueError("input must be a bounded regular non-symlink file") from None


def _remove_regular_if_present(path: Path) -> None:
    """Remove one stale output without following a destination or ancestor link."""

    try:
        parent_fd = _open_existing_parent(path.parent)
    except FileNotFoundError:
        return
    try:
        try:
            mode = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False).st_mode
        except FileNotFoundError:
            return
        if not stat.S_ISREG(mode):
            raise ValueError("stale output destination is unsafe")
        os.unlink(path.name, dir_fd=parent_fd)
        try:
            os.fsync(parent_fd)
        except OSError:
            pass
    finally:
        os.close(parent_fd)


def _read_record(path: Path) -> EnrichmentRecord:
    try:
        return EnrichmentRecord.model_validate_json(_read_regular(path, limit=2_097_152))
    except FileNotFoundError:
        raise
    except Exception:
        raise ValueError("enrichment record is invalid") from None


def _record_is_current(
    root: Path,
    case: CaseManifest,
    record: EnrichmentRecord,
    *,
    provider: str | None = None,
    model: str | None = None,
) -> bool:
    """Repeat every provenance and semantic check before reuse or compilation."""

    try:
        from egsi.data.context import build_oracle_context

        context = build_oracle_context(root, case)
        vocabulary = allowed_action_values(root)
        if (
            record.case_id != case.case_id
            or record.source_context_sha256 != context.sha256
            or record.prompt_sha256
            not in possible_prompt_hashes(context, _prompt_vocabulary(vocabulary))
            or record.temperature != 0.0
            or record.max_tokens != 8192
            or record.structured_output_valid is not True
            or record.validation.valid is not True
            or (provider is not None and record.provider != provider)
            or (model is not None and record.model != model)
        ):
            return False
        repeated = validate_payload(
            case,
            record.payload,
            _load_store(root, case),
            vocabulary,
        )
        return repeated.valid is True and repeated == record.validation
    except Exception:
        return False


def _eligible_case(
    catalog: dict[str, CaseManifest], case_id: str
) -> tuple[CaseManifest | None, dict[str, str] | None]:
    case = catalog.get(case_id)
    if case is None:
        return None, _failure("catalog", "unknown_case_id")
    if case.split == "time_ood_test":
        return None, _failure("eligibility", "time_ood_forbidden")
    return case, None


def _invalid_location_cases(output_dir: Path, failed_ids: list[str]) -> int:
    total = 0
    for case_id in failed_ids:
        try:
            receipt = json.loads(
                _read_regular(output_dir / "failures" / f"{case_id}.json", limit=2_097_152)
            )
            validation = receipt.get("validation") if type(receipt) is dict else None
            if type(validation) is dict and (
                validation.get("invalid_locations") or validation.get("invalid_trace_locations")
            ):
                total += 1
        except Exception:
            continue
    return total


def _cleanup_enrichment_artifacts(
    output_dir: Path,
    records: list[EnrichmentRecord],
    failed_ids: list[str],
) -> list[str]:
    """Keep only the current flat enrichment set and bounded failure receipts."""

    current_records = {f"{record.case_id}.json" for record in records}
    current_failures = {f"{case_id}.json" for case_id in failed_ids}
    with AnchoredDirectory(
        output_dir, subdirectories=("failures", "quarantine")
    ) as artifacts:
        for name in artifacts.list_regular():
            if name == "_batch-provenance.json":
                continue
            if name not in current_records or name.startswith("."):
                artifacts.unlink_regular(Path(name))
        retained_failures: list[str] = []
        for name in artifacts.list_regular("failures"):
            if name in current_failures and not name.startswith("."):
                retained_failures.append(name.removesuffix(".json"))
            else:
                artifacts.unlink_regular(Path("failures") / name)
        for name in artifacts.list_regular("quarantine"):
            if name.startswith(".") or name.endswith(".tmp"):
                artifacts.unlink_regular(Path("quarantine") / name)
    return sorted(retained_failures, key=failed_ids.index)


def run_enrichment_batch(
    root: Path,
    case_ids: list[str],
    output_root: Path,
    teacher: Teacher,
) -> dict[str, Any]:
    """Run one complete enrichment transaction under the shared batch lock."""

    _validate_case_ids(case_ids)
    guard_fixture_teacher_output(Path(root), Path(output_root), teacher)
    if active_batch_lock(Path(output_root)) is not None:
        return _run_enrichment_batch_locked(root, case_ids, output_root, teacher)
    with BatchLock(Path(output_root)):
        return _run_enrichment_batch_locked(root, case_ids, output_root, teacher)


def _invalidate_trajectory_outputs(output_root: Path) -> None:
    """Remove a previously compiled stage before publishing new enrichments."""

    with AnchoredDirectory(
        output_root, subdirectories=("episodes", "trajectories", "reports")
    ) as artifacts:
        for name in artifacts.list_regular("episodes"):
            if name.endswith((".events.jsonl", ".transitions.jsonl")) or name.startswith("."):
                artifacts.unlink_regular(Path("episodes") / name)
        for name in ("train.parquet", "artifact-manifest.json"):
            artifacts.unlink_regular(Path("trajectories") / name)
        for name in (
            "trajectory-validation.json",
            "trajectory-artifact-manifest.json",
            "pilot-summary.json",
        ):
            artifacts.unlink_regular(Path("reports") / name)


def _run_enrichment_batch_locked(
    root: Path,
    case_ids: list[str],
    output_root: Path,
    teacher: Teacher,
) -> dict[str, Any]:
    """Generate or strictly reuse enrichments while isolating each case failure."""

    ids = _validate_case_ids(case_ids)
    guard_fixture_teacher_output(Path(root), Path(output_root), teacher)
    generation_mode = _teacher_generation_mode(teacher)
    catalog = catalog_index(root)
    output_root = Path(output_root)
    _invalidate_trajectory_outputs(output_root)
    output_dir = output_root / "enrichment"
    runner = EnrichmentRunner(
        Path(root), teacher, generation_mode=generation_mode
    )
    processed: list[str] = []
    failures: dict[str, dict[str, str]] = {}
    records: list[EnrichmentRecord] = []
    reused = 0

    for case_id in ids:
        case, eligibility_failure = _eligible_case(catalog, case_id)
        if eligibility_failure is not None:
            failures[case_id] = eligibility_failure
            continue
        assert case is not None
        target = output_dir / f"{case_id}.json"
        reusable: EnrichmentRecord | None = None
        try:
            existing = _read_record(target)
            if _record_is_current(
                Path(root), case, existing, provider=teacher.provider, model=teacher.model
            ):
                reusable = existing
        except Exception:
            pass
        try:
            record = runner.run(case, output_dir)
            if not _record_is_current(
                Path(root), case, record, provider=teacher.provider, model=teacher.model
            ):
                raise ValueError("runner returned a non-current record")
            if reusable is not None and record == reusable:
                reused += 1
            records.append(record)
            processed.append(case_id)
        except Exception as exc:
            failures[case_id] = _failure("enrichment", _exception_code(exc))

    if len(processed) + len(failures) != len(ids):
        raise RuntimeError("enrichment batch conservation invariant failed")
    families = Counter(catalog[item].family for item in processed)
    cwes = Counter(catalog[item].cwe_normalized_primary for item in processed)
    providers = Counter(f"{record.provider}:{record.model}" for record in records)
    usage: Counter[str] = Counter()
    for record in records:
        usage.update({key: value for key, value in record.usage.items() if key in _USAGE_KEYS})
    invalid_locations = _invalid_location_cases(output_dir, list(failures))
    retained_failure_receipts = _cleanup_enrichment_artifacts(
        output_dir, records, list(failures)
    )
    provenance = _write_provenance_manifest(
        output_dir,
        ids,
        records,
        retained_failure_receipts,
        generation_mode=generation_mode,
        provider=teacher.provider,
        model=teacher.model,
    )
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "stage": "enrichment",
        "requested": len(ids),
        "processed": len(processed),
        "failed": len(failures),
        "cache_reused": reused,
        "processed_case_ids": processed,
        "failures": failures,
        "structured_parse_rate": len(processed) / len(ids),
        "family_counts": dict(sorted(families.items())),
        "cwe_counts": dict(sorted(cwes.items())),
        "provider_model_counts": dict(sorted(providers.items())),
        "prompt_hashes": sorted({record.prompt_sha256 for record in records}),
        "total_latency_ms": sum(record.latency_ms for record in records),
        "usage": dict(sorted(usage.items())),
        "invalid_location_cases": invalid_locations,
        "invalid_location_rate": invalid_locations / len(ids),
        "generation_mode": generation_mode,
        "provenance": provenance,
    }
    write_report(output_root / "reports/enrichment-summary.json", report)
    return report


def _read_jsonl(path: Path, kind: type[EpisodeEvent] | type[T1Transition]) -> list[Any]:
    raw = _read_regular(path)
    lines = raw.splitlines()
    if not lines or len(lines) > 1_024:
        raise ValueError("JSONL is empty or oversized")
    try:
        values = [kind.model_validate_json(line) for line in lines]
    except Exception:
        raise ValueError("JSONL contract validation failed") from None
    return values


def _episode_metrics(
    case: CaseManifest,
    record: EnrichmentRecord,
    transitions: list[T1Transition],
    events: list[EpisodeEvent],
) -> tuple[int, int, int]:
    policy_artifacts = [
        *(item.model_dump(mode="json") for item in transitions),
        *(item.model_dump(mode="json") for item in events),
    ]
    leakage = sum(
        len(key_hits(item)) + len(policy_value_hits(case, record, item))
        for item in policy_artifacts
    )
    nonzero = 0
    illegal = 0
    for transition in transitions:
        rewards = transition.reward_vector.model_dump()
        nonzero += int(any(value != 0.0 for key, value in rewards.items() if key != "label_scope"))
        try:
            selected = transition.candidate_actions.index(transition.selected_action)
        except ValueError:
            illegal += 1
        else:
            illegal += int(transition.legal_mask[selected] is not True)
    return leakage, nonzero, illegal


def _publish_trajectory_artifact_manifest(
    output_root: Path,
    ids: list[str],
    processed: list[str],
    event_files: list[str],
    *,
    has_parquet: bool,
    provenance: dict[str, str],
) -> dict[str, str]:
    expected_episode_files: set[str] = set()
    case_by_file: dict[str, str] = {}
    for case_id, event_file in zip(processed, event_files, strict=True):
        transition_file = event_file.replace(
            ".events.jsonl", ".transitions.jsonl"
        )
        for relative in (event_file, transition_file):
            expected_episode_files.add(Path(relative).name)
            case_by_file[relative] = case_id

    with AnchoredDirectory(
        output_root, subdirectories=("episodes", "trajectories", "reports")
    ) as artifacts:
        for name in artifacts.list_regular("episodes"):
            if name not in expected_episode_files:
                artifacts.unlink_regular(Path("episodes") / name)
        for name in artifacts.list_regular("trajectories"):
            if name != "train.parquet" or not has_parquet:
                artifacts.unlink_regular(Path("trajectories") / name)
        for name in artifacts.list_regular("reports"):
            if name.startswith(".") or name.endswith(".tmp"):
                artifacts.unlink_regular(Path("reports") / name)

    entries: list[dict[str, str]] = []
    for relative in sorted(case_by_file):
        kind = (
            "episode_events"
            if relative.endswith(".events.jsonl")
            else "episode_transitions"
        )
        entries.append(
            {
                "relative_path": relative,
                "sha256": _sha256(_read_regular(output_root / relative)),
                "case_id": case_by_file[relative],
                "kind": kind,
            }
        )
    if has_parquet:
        relative = "trajectories/train.parquet"
        entries.append(
            {
                "relative_path": relative,
                "sha256": _sha256(_read_regular(output_root / relative)),
                "case_id": "__batch__",
                "kind": "trajectory_parquet",
            }
        )
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "stage": "trajectory_artifacts",
        "requested_case_ids": ids,
        "processed_case_ids": processed,
        "provenance_manifest_sha256": provenance["manifest_sha256"],
        "artifacts": entries,
    }
    manifest["artifact_commitment_sha256"] = _dict_commitment(
        manifest, "artifact_commitment_sha256"
    )
    relative_manifest = "reports/trajectory-artifact-manifest.json"
    path = output_root / relative_manifest
    write_report(path, manifest)
    return {
        "artifact_manifest_file": relative_manifest,
        "artifact_manifest_sha256": _sha256(_read_regular(path)),
        "artifact_commitment_sha256": manifest["artifact_commitment_sha256"],
    }


def compile_trajectory_batch(
    root: Path,
    case_ids: list[str],
    input_root: Path,
    output_root: Path,
    *,
    expected_provenance: object = None,
) -> dict[str, Any]:
    """Run one complete compilation transaction under the shared batch lock."""

    _validate_case_ids(case_ids)
    trusted = _validate_provenance_expectation(expected_provenance)
    if trusted["generation_mode"] == "fixture":
        validate_fixture_output_root(Path(root), Path(output_root))
    if active_batch_lock(Path(output_root)) is not None:
        return _compile_trajectory_batch_locked(
            root,
            case_ids,
            input_root,
            output_root,
            expected_provenance=trusted,
        )
    with BatchLock(Path(output_root)):
        return _compile_trajectory_batch_locked(
            root,
            case_ids,
            input_root,
            output_root,
            expected_provenance=trusted,
        )


def _compile_trajectory_batch_locked(
    root: Path,
    case_ids: list[str],
    input_root: Path,
    output_root: Path,
    *,
    expected_provenance: object = None,
) -> dict[str, Any]:
    """Compile, persist, and replay trusted T1 episodes case by case."""

    ids = _validate_case_ids(case_ids)
    root = Path(root)
    input_root = Path(input_root)
    output_root = Path(output_root)
    committed_records, trusted_provenance = _load_committed_provenance(
        input_root, ids, expected_provenance
    )
    if trusted_provenance["generation_mode"] == "fixture":
        validate_fixture_output_root(root, output_root)
    catalog = catalog_index(root)
    processed: list[str] = []
    failures: dict[str, dict[str, str]] = {}
    transitions_all: list[T1Transition] = []
    event_files: list[str] = []
    replay_passed = 0
    leakage = 0
    nonzero_rewards = 0
    illegal_selected = 0
    reused = 0

    prepared: dict[str, tuple[CaseManifest, EnrichmentRecord]] = {}
    for case_id in ids:
        case, eligibility_failure = _eligible_case(catalog, case_id)
        if eligibility_failure is not None:
            failures[case_id] = eligibility_failure
            continue
        assert case is not None
        try:
            record = committed_records[case_id]
            if not _record_is_current(root, case, record):
                raise ValueError("enrichment provenance validation failed")
            prepared[case_id] = (case, record)
        except Exception as exc:
            failures[case_id] = _failure("enrichment_input", _exception_code(exc))

    fixture_input_records = (
        len(committed_records)
        if trusted_provenance["generation_mode"] == "fixture"
        else 0
    )

    for case_id in ids:
        item = prepared.get(case_id)
        if item is None:
            continue
        case, record = item
        stage = "compile"
        try:
            transitions, events = compile_t1_episode(case, record, root=root)
            commitment = episode_commitment(transitions, events)
            replay_events(events, transitions, expected_commitment_sha256=commitment)

            episode_id = transitions[0].episode_id
            event_path = output_root / "episodes" / f"{episode_id}.events.jsonl"
            transition_path = output_root / "episodes" / f"{episode_id}.transitions.jsonl"
            cache_valid = False
            try:
                cached_events = _read_jsonl(event_path, EpisodeEvent)
                cached_transitions = _read_jsonl(transition_path, T1Transition)
                cached_commitment = episode_commitment(cached_transitions, cached_events)
                replay_events(
                    cached_events,
                    cached_transitions,
                    expected_commitment_sha256=commitment,
                )
                cache_valid = (
                    cached_commitment == commitment
                    and cached_events == events
                    and cached_transitions == transitions
                )
            except Exception:
                cache_valid = False
            stage = "persist"
            if cache_valid:
                reused += 1
            else:
                write_jsonl(event_path, events)
                write_jsonl(transition_path, transitions)
                written_events = _read_jsonl(event_path, EpisodeEvent)
                written_transitions = _read_jsonl(transition_path, T1Transition)
                if written_events != events or written_transitions != transitions:
                    raise ValueError("episode readback mismatch")
                replay_events(
                    written_events,
                    written_transitions,
                    expected_commitment_sha256=commitment,
                )

            case_leakage, case_nonzero, case_illegal = _episode_metrics(
                case, record, transitions, events
            )
            leakage += case_leakage
            nonzero_rewards += case_nonzero
            illegal_selected += case_illegal
            replay_passed += 1
            transitions_all.extend(transitions)
            event_files.append(event_path.relative_to(output_root).as_posix())
            processed.append(case_id)
        except Exception as exc:
            failures[case_id] = _failure(stage, _exception_code(exc))

    if len(processed) + len(failures) != len(ids):
        raise RuntimeError("trajectory batch conservation invariant failed")
    parquet_path = output_root / "trajectories/train.parquet"
    if transitions_all:
        write_parquet(parquet_path, transitions_all)
        if read_parquet(parquet_path) != transitions_all:
            raise RuntimeError("aggregate Parquet readback mismatch")
    else:
        _remove_regular_if_present(parquet_path)
    internal_failure = (
        leakage != 0
        or nonzero_rewards != 0
        or illegal_selected != 0
        or replay_passed != len(processed)
    )
    artifact_manifest = _publish_trajectory_artifact_manifest(
        output_root,
        ids,
        processed,
        event_files,
        has_parquet=bool(transitions_all),
        provenance=trusted_provenance,
    )
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "stage": "trajectory",
        "requested": len(ids),
        "processed": len(processed),
        "failed": len(failures),
        "episode_cache_reused": reused,
        "processed_case_ids": processed,
        "failures": failures,
        "transitions": len(transitions_all),
        "parquet_file": "trajectories/train.parquet" if transitions_all else None,
        "event_files": event_files,
        "policy_oracle_leakage": leakage,
        "nonzero_t1_rewards": nonzero_rewards,
        "selected_illegal_actions": illegal_selected,
        "event_replay_passed": replay_passed,
        "dynamic_verdict": "not_applicable",
        "internal_invariant_failure": internal_failure,
        "fixture_input_records": fixture_input_records,
        "promotable": trusted_provenance["generation_mode"] == "live",
        "generation_mode": trusted_provenance["generation_mode"],
        "provenance": trusted_provenance,
        **artifact_manifest,
    }
    write_report(output_root / "reports/trajectory-validation.json", report)
    return report


def run_pilot(
    root: Path,
    case_ids: list[str],
    output_root: Path,
    teacher: Teacher,
) -> dict[str, Any]:
    """Hold one lock across enrichment, compilation, and pilot publication."""

    _validate_case_ids(case_ids)
    guard_fixture_teacher_output(Path(root), Path(output_root), teacher)
    if active_batch_lock(Path(output_root)) is not None:
        return _run_pilot_locked(root, case_ids, output_root, teacher)
    with BatchLock(Path(output_root)):
        return _run_pilot_locked(root, case_ids, output_root, teacher)


def _run_pilot_locked(
    root: Path,
    case_ids: list[str],
    output_root: Path,
    teacher: Teacher,
) -> dict[str, Any]:
    """Run enrichment then trajectories without losing the original failure stage."""

    ids = _validate_case_ids(case_ids)
    enrichment = run_enrichment_batch(root, ids, output_root, teacher)
    trajectory = compile_trajectory_batch(
        root,
        ids,
        Path(output_root) / "enrichment",
        output_root,
        expected_provenance=enrichment["provenance"],
    )
    merged_failures: dict[str, dict[str, str]] = {}
    for case_id in ids:
        if case_id in enrichment["failures"]:
            merged_failures[case_id] = enrichment["failures"][case_id]
        elif case_id in trajectory["failures"]:
            merged_failures[case_id] = trajectory["failures"][case_id]
    processed_ids = list(trajectory["processed_case_ids"])
    if len(processed_ids) + len(merged_failures) != len(ids):
        raise RuntimeError("pilot conservation invariant failed")
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "stage": "pilot",
        "requested": len(ids),
        "processed": len(processed_ids),
        "failed": len(merged_failures),
        "processed_case_ids": processed_ids,
        "failures": merged_failures,
        "policy_oracle_leakage": trajectory["policy_oracle_leakage"],
        "nonzero_t1_rewards": trajectory["nonzero_t1_rewards"],
        "selected_illegal_actions": trajectory["selected_illegal_actions"],
        "event_replay_passed": trajectory["event_replay_passed"],
        "dynamic_verdict": "not_applicable",
        "internal_invariant_failure": trajectory["internal_invariant_failure"],
        "fixture_input_records": trajectory["fixture_input_records"],
        "promotable": trajectory["promotable"],
        "generation_mode": trajectory["generation_mode"],
        "provenance": trajectory["provenance"],
        "enrichment": enrichment,
        "trajectory": trajectory,
    }
    write_report(Path(output_root) / "reports/pilot-summary.json", report)
    return report

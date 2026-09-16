"""Compile validated teacher labels into deliberately non-authoritative T1 data.

The compiler never turns an enrichment into a fact, a certificate, or a
dynamic verdict.  It only records a patch-grounded behavioural-cloning label
and a replayable choice among Action DSL candidates.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import secrets
from copy import deepcopy
from pathlib import Path
from typing import Any, TypeAlias
from pydantic import BaseModel

import pyarrow as pa
import pyarrow.parquet as pq

from egsi.contracts.case import CaseManifest
from egsi.contracts.enrichment import EnrichmentRecord
from egsi.contracts.trajectory import EpisodeEvent, PARQUET_EMPTY_OBJECT_TAG, RewardVector, T1Transition, VerifierDecision, strict_json

from .candidates import (
    POLICY_CANONICALIZER_VERSION,
    canonical_step_from_selected_action,
    canonicalize_policy_trace,
    compile_candidates,
)
from .redaction import (
    build_policy_seed,
    key_hits,
    policy_value_hits,
    verify_policy_seed,
)
from .safeio import open_directory_fd


_LABEL_SCOPE = "patch_grounded_bc"
_MAX_EVENT_JSON_BYTES = 1_048_576
_MAX_OUTPUT_ITEMS = 1_024
_MAX_OUTPUT_BYTES = 16 * 1_024 * 1_024
_MAX_PARQUET_FILE_BYTES = 32 * 1_024 * 1_024
_MAX_TRACE_STEPS = 64
_MAX_HISTORY = 64
PARQUET_ENCODING_VERSION = "egsi-empty-object-v1"
_ARROW_EMPTY = PARQUET_EMPTY_OBJECT_TAG
_PARQUET_METADATA_KEY = b"egsi.parquet_encoding_version"
_TRANSITION_COLUMNS = frozenset(T1Transition.model_fields)
_JsonRecord: TypeAlias = EpisodeEvent | T1Transition


def _canonical_json_bytes(value: object, *, limit: int = _MAX_EVENT_JSON_BYTES) -> bytes:
    """Return finite canonical JSON under an explicit allocation bound."""

    try:
        strict_json(value)
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise ValueError("value is not finite canonical UTF-8 JSON") from exc
    if len(raw) > limit:
        raise ValueError("canonical JSON exceeds size limit")
    return raw


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def event_hash(
    sequence: int, episode_id: str, event_type: str, payload: dict[str, Any],
    previous_event_sha256: str | None,
) -> str:
    """Hash precisely the event content covered by the append-only chain."""

    if type(sequence) is not int or sequence < 0 or type(episode_id) is not str or not episode_id:
        raise ValueError("invalid event identity")
    if type(event_type) is not str or not event_type or type(payload) is not dict:
        raise ValueError("invalid event payload")
    if previous_event_sha256 is not None and type(previous_event_sha256) is not str:
        raise ValueError("invalid previous event hash")
    return "sha256:" + _digest({
        "sequence": sequence,
        "episode_id": episode_id,
        "event_type": event_type,
        "payload": payload,
        "previous_event_sha256": previous_event_sha256,
    })


def make_event(
    sequence: int, episode_id: str, event_type: str, payload: dict[str, Any],
    previous_event_sha256: str | None,
) -> EpisodeEvent:
    """Construct an independently-owned, content-hashed event."""

    # Canonicalize before and after copying.  This both rejects cycles/nonfinite
    # values and prevents a caller from mutating the event after hashing it.
    _canonical_json_bytes(payload)
    try:
        owned_payload = deepcopy(payload)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("event payload cannot be safely copied") from exc
    _canonical_json_bytes(owned_payload)
    return EpisodeEvent(
        sequence=sequence,
        episode_id=episode_id,
        event_type=event_type,
        payload=owned_payload,
        previous_event_sha256=previous_event_sha256,
        event_sha256=event_hash(sequence, episode_id, event_type, owned_payload, previous_event_sha256),
    )


def episode_commitment(transitions: object, events: object) -> str:
    """Commit a complete, trusted transition/event pair before replaying it."""
    if type(transitions) is not list or type(events) is not list or not transitions or not events:
        raise ValueError("episode commitment requires non-empty transition and event lists")
    normalized_transitions = _normalize_values(transitions, T1Transition, validate_compiled=False)
    normalized_events = _normalize_values(events, EpisodeEvent)
    episode_id = normalized_events[0].episode_id
    if any(event.episode_id != episode_id for event in normalized_events) or any(item.episode_id != episode_id for item in normalized_transitions):
        raise ValueError("episode commitment has mixed episode identities")
    # Commit each already-normalized transition by digest rather than embedding
    # the entire list in one synthetic JSON tree.  The previous aggregate form
    # exceeded the global JSON node ceiling for valid multi-step episodes.
    transition_sha256s = [
        "sha256:" + _digest(item.model_dump(mode="json"))
        for item in normalized_transitions
    ]
    return "sha256:" + _digest({
        "episode_commitment_version": "2.0",
        "policy_canonicalizer_version": POLICY_CANONICALIZER_VERSION,
        "episode_id": episode_id,
        "terminal_event_sha256": normalized_events[-1].event_sha256,
        "transition_sha256s": transition_sha256s,
    })


def _clean_validation(record: EnrichmentRecord) -> bool:
    validation = record.validation
    return (
        record.structured_output_valid is True
        and validation.valid is True
        and validation.family_mismatch is False
        and not validation.invalid_locations
        and not validation.invalid_trace_locations
        and not validation.invalid_goals
        and not validation.invalid_operations
        and not validation.invalid_target_kinds
        and not validation.invalid_tool_classes
    )


def _episode_id(case: CaseManifest, record: EnrichmentRecord) -> str:
    """Bind identity to all oracle-side labels without exposing them in state."""

    return "EP-" + _digest({
        "policy_canonicalizer_version": POLICY_CANONICALIZER_VERSION,
        "case": case.model_dump(mode="json"),
        "record": record.model_dump(mode="json"),
    })[:32]


def _state_from_seed(seed: dict[str, Any], *, state_version: int, history: list[dict[str, Any]]) -> dict[str, Any]:
    """Copy only policy-safe bootstrap fields and bounded execution metadata."""

    if state_version < 0 or len(history) > _MAX_HISTORY:
        raise ValueError("invalid bounded execution state")
    state = deepcopy(seed)
    state["state"] = "SELECT_ACTION"
    state["bounded_history"] = deepcopy(history)
    state["state_version"] = state_version
    if key_hits(state):
        raise ValueError("policy state contains forbidden keys")
    _canonical_json_bytes(state)
    return state


def _validated_t1_inputs(
    case: CaseManifest, record: EnrichmentRecord
) -> tuple[CaseManifest, EnrichmentRecord]:
    """Round-trip the two mutable contracts before any compiler use."""

    if not isinstance(case, CaseManifest) or not isinstance(record, EnrichmentRecord):
        raise ValueError("case and record must be validated contracts")
    # Assignment validation is deliberately disabled on our contracts so that
    # callers can efficiently assemble them.  The compiler is a trust
    # boundary: round-trip both complete contracts before reading even one
    # field, which catches post-construction mutation and gives us independent
    # objects that cannot be altered by the caller during compilation.
    try:
        case = CaseManifest.model_validate(case.model_dump(mode="python"))
        record = EnrichmentRecord.model_validate(record.model_dump(mode="python"))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError("case or enrichment contract failed full revalidation") from exc
    if record.case_id != case.case_id:
        raise ValueError("enrichment case_id does not match case manifest")
    if record.payload.family != case.family:
        raise ValueError("enrichment family does not match case manifest")
    if not _clean_validation(record):
        raise ValueError("only clean validated enrichment may produce T1 labels")
    if not 1 <= len(record.payload.trace) <= _MAX_TRACE_STEPS:
        raise ValueError("T1 trace must contain a bounded non-empty sequence")
    return case, record


def compile_t1_episode(case: CaseManifest, record: EnrichmentRecord, *, root: Path = Path(".")) -> tuple[list[T1Transition], list[EpisodeEvent]]:
    """Compile a current valid enrichment to zero-reward T1 transitions and events."""

    case, record = _validated_t1_inputs(case, record)

    store = None
    try:
        from .enrichment import (
            _load_store,
            _prompt_vocabulary,
            allowed_action_values,
            possible_prompt_hashes,
            validate_payload,
        )
        from egsi.data.context import build_oracle_context
        context = build_oracle_context(Path(root), case)
        vocabulary = allowed_action_values(Path(root))
        if (
            context.sha256 != record.source_context_sha256
            or record.prompt_sha256
            not in possible_prompt_hashes(context, _prompt_vocabulary(vocabulary))
        ):
            raise ValueError
        store = _load_store(Path(root), case)
        repeated = validate_payload(
            case, record.payload, store, vocabulary
        )
        if repeated != record.validation or repeated.valid is not True:
            raise ValueError
    except Exception:
        if store is not None:
            store.close()
        raise ValueError("T1 enrichment provenance validation failed") from None

    try:
        return _compile_validated_t1_episode(case, record, store)
    finally:
        store.close()


def compile_t1_episode_frozen_v21(
    case: CaseManifest,
    record: EnrichmentRecord,
    *,
    root: Path = Path("."),
) -> tuple[list[T1Transition], list[EpisodeEvent]]:
    """Compile only a freshly revalidated frozen-v2.1 first-case record.

    This compatibility entry point does not alter the current compiler gate.  It
    accepts exactly a record whose source context, one of the three frozen v2.1
    prompt variants, and frozen semantic validation all revalidate now.
    """

    case, record = _validated_t1_inputs(case, record)
    store = None
    try:
        from .enrichment import (
            _load_store,
            _prompt_vocabulary,
            allowed_action_values,
        )
        from .first_case_hard_gate import _validate_frozen_v21_payload
        from .human_audit import _repair_info_v21
        from egsi.data.context import build_oracle_context

        context = build_oracle_context(Path(root), case)
        vocabulary = allowed_action_values(Path(root))
        repair = _repair_info_v21(
            context, _prompt_vocabulary(vocabulary), record
        )
        if (
            context.sha256 != record.source_context_sha256
            or repair["request_variant_verified"] is not True
        ):
            raise ValueError
        store = _load_store(Path(root), case)
        repeated = _validate_frozen_v21_payload(
            case, record.payload, store, vocabulary
        )
        if repeated != record.validation or repeated.valid is not True:
            raise ValueError
    except Exception:
        if store is not None:
            store.close()
        raise ValueError("frozen v2.1 T1 provenance validation failed") from None

    try:
        return _compile_validated_t1_episode(case, record, store)
    finally:
        store.close()


def _compile_validated_t1_episode(
    case: CaseManifest,
    record: EnrichmentRecord,
    store: Any,
) -> tuple[list[T1Transition], list[EpisodeEvent]]:
    """Shared deterministic compiler core after an explicit provenance gate."""

    episode_id = _episode_id(case, record)
    try:
        policy_trace = canonicalize_policy_trace(
            record.payload,
            episode_id,
            vulnerable_path_exists=lambda path: store.contains(
                case.repository.vulnerable_commit, path
            ),
        )
    except Exception:
        raise ValueError("policy trace canonicalization failed") from None
    seed, redaction_manifest = build_policy_seed(case)
    if not verify_policy_seed(seed, redaction_manifest, case):
        raise ValueError("policy seed verification failed")

    events = [make_event(0, episode_id, "EPISODE_STARTED", {
        "policy_seed": seed, "redaction": redaction_manifest,
    }, None)]
    events.append(make_event(1, episode_id, "HYPOTHESIS_CREATED", {
        "hypothesis_id": "H-1", "label_scope": _LABEL_SCOPE,
    }, events[-1].event_sha256))

    transitions: list[T1Transition] = []
    history: list[dict[str, Any]] = []
    for index, step in enumerate(policy_trace):
        actions, legal_mask, selected = compile_candidates(
            seed["case_id"], episode_id, "B-1", step
        )
        selected_index = next(
            (position for position, candidate in enumerate(actions)
             if candidate["action_id"] == selected["action_id"]),
            None,
        )
        if selected_index is None or legal_mask[selected_index] is not True:
            raise ValueError("selected action is absent or illegal")
        proposed_payload = {"actions": deepcopy(actions), "legal_mask": list(legal_mask)}
        events.append(make_event(len(events), episode_id, "ACTION_PROPOSED", proposed_payload, events[-1].event_sha256))
        events.append(make_event(len(events), episode_id, "ACTION_SELECTED", {
            "action_id": selected["action_id"],
        }, events[-1].event_sha256))

        transition = T1Transition(
            episode_id=episode_id,
            state_version=index,
            state=_state_from_seed(seed, state_version=index, history=history),
            candidate_actions=deepcopy(actions),
            legal_mask=list(legal_mask),
            selected_action=deepcopy(selected),
            observation={"type": "oracle_label_only", "label_scope": _LABEL_SCOPE, "receipt": None},
            evidence_delta={"facts": [], "claims": [], "resolved_unknowns": []},
            verifier_decision=VerifierDecision(
                accepted=True, label_scope=_LABEL_SCOPE,
                checks={"schema": True, "location": True, "action_dsl": True, "redaction": True},
            ),
            reward_vector=RewardVector(
                label_scope=_LABEL_SCOPE, terminal=0.0, verified_proof_delta=0.0,
                counter_evidence=0.0, contradiction_resolution=0.0, normalized_cost=0.0,
            ),
            next_state_version=index + 1,
            done=index == len(record.payload.trace) - 1,
        )
        transitions.append(transition)
        events.append(make_event(len(events), episode_id, "PATCH_GROUNDED_LABEL_RECORDED", {
            "state_version": index,
            "action_id": selected["action_id"],
            "label_scope": _LABEL_SCOPE,
        }, events[-1].event_sha256))
        history.append({"state_version": index, "action_id": selected["action_id"]})

    events.append(make_event(len(events), episode_id, "EPISODE_CLOSED", {
        "outcome": "LABEL_SEQUENCE_COMPLETE", "dynamic_verdict": "not_applicable",
    }, events[-1].event_sha256))
    # Check each bounded contract independently.  Combining a valid multi-step
    # episode into one synthetic tree can exceed the redaction walker's node
    # ceiling even though every persisted artifact is individually bounded.
    policy_artifacts = [
        *(item.model_dump(mode="json") for item in transitions),
        *(item.model_dump(mode="json") for item in events),
    ]
    if any(
        key_hits(item) or policy_value_hits(case, record, item)
        for item in policy_artifacts
    ):
        raise ValueError("policy artifact leakage validation failed")
    return deepcopy(transitions), deepcopy(events)


def _safe_parent(path: Path) -> None:
    if not isinstance(path, Path) or not path.name:
        raise ValueError("output path must name a file")
    parent = path.parent.absolute()
    # Do not use mkdir(parents=True): it follows an existing symlink before we
    # can reject it, potentially creating directories outside the requested
    # output root.  Walk one component at a time with lstat instead.
    current = Path(parent.anchor)
    try:
        root_mode = os.lstat(current).st_mode
    except OSError as exc:
        raise ValueError("output parent must be a real directory") from exc
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise ValueError("output parent must be a real directory")
    for component in parent.parts[1:]:
        candidate = current / component
        try:
            mode = os.lstat(candidate).st_mode
        except FileNotFoundError:
            try:
                os.mkdir(candidate)
            except OSError as exc:
                # A concurrent creator is harmless only if the resulting
                # component passes the exact same lstat checks below.
                if not isinstance(exc, FileExistsError):
                    raise ValueError("output parent must be a real directory") from exc
            try:
                mode = os.lstat(candidate).st_mode
            except OSError as exc:
                raise ValueError("output parent must be a real directory") from exc
        except OSError as exc:
            raise ValueError("output parent must be a real directory") from exc
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise ValueError("output parent must be a real directory")
        current = candidate
    try:
        destination_mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ValueError("output destination must be a regular non-symlink file") from exc
    if stat.S_ISLNK(destination_mode) or not stat.S_ISREG(destination_mode):
        raise ValueError("output destination must be a regular non-symlink file")


def _normalize_values(values: object, kind: type[_JsonRecord], *, validate_compiled: bool = True) -> list[_JsonRecord]:
    if type(values) is not list or not values or len(values) > _MAX_OUTPUT_ITEMS:
        raise ValueError("values must be a bounded non-empty list")
    if any(type(value) is not kind for value in values):
        raise ValueError("values must be homogeneous validated records")
    normalized: list[_JsonRecord] = []
    total = 0
    for value in values:
        tree = _model_to_python_tree(value)
        raw = _canonical_json_bytes(tree, limit=_MAX_OUTPUT_BYTES)
        total += len(raw) + 1
        if total > _MAX_OUTPUT_BYTES:
            raise ValueError("serialized output exceeds size limit")
        try:
            parsed = kind.model_validate_json(raw)
            if _canonical_json_bytes(parsed.model_dump(mode="json"), limit=_MAX_OUTPUT_BYTES) != raw:
                raise ValueError("record canonical form changed during validation")
            if kind is T1Transition and validate_compiled:
                _validate_compiled_transition(parsed)
            normalized.append(parsed)
        except ValueError as exc:
            raise ValueError("record does not round-trip through JSON") from exc
    return normalized


def _model_to_python_tree(value: object) -> object:
    """Extract models without JSON-mode coercion, preserving unsafe mutations."""
    if isinstance(value, BaseModel):
        return {name: _model_to_python_tree(getattr(value, name)) for name in value.__class__.model_fields}
    if type(value) is dict:
        return {_model_to_python_tree(key): _model_to_python_tree(item) for key, item in value.items()}
    if type(value) is list:
        return [_model_to_python_tree(item) for item in value]
    return value


def _validate_compiled_transition(transition: T1Transition) -> None:
    from .candidates import _load_validator, compile_candidates, validate_action_identity
    validator = _load_validator()
    actions = transition.candidate_actions
    expected_case = transition.state["case_id"]
    step_ids: set[str] = set(); resolves: set[tuple[Any, ...]] = set(); obligations: set[Any] = set()
    actual_mask: list[bool] = []
    for action in actions:
        validate_action_identity(action)
        if (action.get("episode_id") != transition.episode_id or action.get("branch_id") != "B-1"
                or action.get("hypothesis_id") != "H-1" or action.get("metadata", {}).get("case_id") != expected_case):
            raise ValueError("compiled action binding mismatch")
        step_ids.add(action["metadata"]["step_id"])
        resolves.add(tuple(action.get("resolves_unknowns", []))); obligations.add(action.get("obligation_id"))
        actual_mask.append(not any(validator.iter_errors(action)))
    if len(step_ids) != 1 or len(resolves) != 1 or len(obligations) != 1 or actual_mask != transition.legal_mask:
        raise ValueError("compiled candidate set is inconsistent")
    if transition.selected_action not in actions:
        raise ValueError("compiled selected action is absent")
    validate_action_identity(transition.selected_action)
    selected = transition.selected_action
    if (selected.get("branch_id") != "B-1" or selected.get("actor_role") != "policy_selector"
            or selected.get("hypothesis_id") != "H-1" or sum(transition.legal_mask) < 4):
        raise ValueError("compiled selected action has invalid policy binding")
    target = selected.get("target")
    try:
        step = canonical_step_from_selected_action(selected)
        candidates, mask, expected_selected = compile_candidates(
            transition.state["case_id"], transition.episode_id, selected["branch_id"], step)
    except (KeyError, TypeError, ValueError):
        raise ValueError("compiled action cannot reconstruct its candidate set") from None
    if candidates != actions or mask != transition.legal_mask or expected_selected != selected:
        raise ValueError("compiled candidate reconstruction mismatch")


def _atomic_bytes(path: Path, raw: bytes, verifier) -> None:  # type: ignore[no-untyped-def]
    if os.name != "posix":
        raise ValueError("secure atomic writers require POSIX")
    parent_fd = _open_parent_fd(path.parent)
    temporary_name: str | None = None
    try:
        _reject_destination_at(parent_fd, path.name)
        previous = _read_destination_at(parent_fd, path.name, _MAX_OUTPUT_BYTES)
        temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
        fd = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        verifier(raw)
        try:
            os.replace(temporary_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        except OSError:
            observed = _read_destination_at(parent_fd, path.name, _MAX_OUTPUT_BYTES)
            if observed == raw:
                # Some filesystems/reporting layers can surface an error after
                # the rename committed.  The anchored destination is decisive.
                try:
                    os.unlink(temporary_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                temporary_name = None
            elif observed == previous:
                raise
            else:
                raise RuntimeError("fatal: atomic replace outcome is ambiguous") from None
        else:
            temporary_name = None
        try:
            os.fsync(parent_fd)
        except OSError:
            pass  # Directory fsync is unavailable on some supported filesystems.
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def _open_parent_fd(parent: Path) -> int:
    """Open every parent component without ever following an ancestor link."""
    try:
        return open_directory_fd(parent, create=True)
    except (OSError, ValueError) as exc:
        raise ValueError("output parent must be a real directory") from exc


def _reject_destination_at(parent_fd: int, name: str) -> None:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ValueError("output destination must be a regular non-symlink file") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
    ):
        raise ValueError(
            "output destination must be a single-link regular non-symlink file"
        )


def _read_destination_at(parent_fd: int, name: str, limit: int) -> bytes | None:
    """Read a regular anchored destination under an explicit byte bound."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > limit
        ):
            raise RuntimeError("fatal: atomic replace destination is unsafe")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            part = os.read(fd, min(1_048_576, remaining))
            if not part:
                raise RuntimeError("fatal: atomic replace destination changed during read")
            chunks.append(part); remaining -= len(part)
        return b"".join(chunks)
    finally:
        os.close(fd)


def write_jsonl(path: Path, values: list[EpisodeEvent] | list[T1Transition]) -> None:
    """Atomically persist one homogeneous contract type as independently valid JSONL."""

    if not isinstance(path, Path):
        raise ValueError("path must be a pathlib.Path")
    if type(values) is not list or not values:
        raise ValueError("values must be a non-empty list")
    kind: type[_JsonRecord]
    if type(values[0]) is EpisodeEvent:
        kind = EpisodeEvent
    elif type(values[0]) is T1Transition:
        kind = T1Transition
    else:
        raise ValueError("JSONL supports EpisodeEvent or T1Transition only")
    normalized = _normalize_values(values, kind)
    raw = b"".join(item.model_dump_json().encode("utf-8") + b"\n" for item in normalized)

    def verify(written: bytes) -> None:
        read = written.splitlines()
        if len(read) != len(normalized) or [kind.model_validate_json(line) for line in read] != normalized:
            raise ValueError("JSONL readback verification failed")

    _atomic_bytes(path, raw, verify)


def write_parquet(path: Path, transitions: list[T1Transition]) -> None:
    """Atomically persist T1 transitions with canonical JSON retained per row."""

    if not isinstance(path, Path):
        raise ValueError("path must be a pathlib.Path")
    normalized = _normalize_values(transitions, T1Transition)
    def arrow_safe(value: Any) -> Any:
        if type(value) is dict:
            if not value:
                return {_ARROW_EMPTY: True}
            return {key: arrow_safe(item) for key, item in value.items()}
        if type(value) is list:
            return [arrow_safe(item) for item in value]
        return value

    rows = [arrow_safe(item.model_dump(mode="json")) for item in normalized]
    table = pa.Table.from_pylist(rows).replace_schema_metadata({_PARQUET_METADATA_KEY: PARQUET_ENCODING_VERSION.encode("ascii")})
    sink = pa.BufferOutputStream()
    pq.write_table(table, sink, compression="zstd")
    raw = sink.getvalue().to_pybytes()

    def verify(written: bytes) -> None:
        read = pq.read_table(pa.BufferReader(written)).to_pylist()
        if len(read) != len(normalized):
            raise ValueError("Parquet row count verification failed")
        restored = _decode_parquet_rows(read, table.schema.metadata)
        if restored != normalized:
            raise ValueError("Parquet canonical readback verification failed")
    _atomic_bytes(path, raw, verify)


def _restore_arrow(value: Any) -> Any:
    if type(value) is dict:
        if value == {_ARROW_EMPTY: True}:
            return {}
        return {key: _restore_arrow(item) for key, item in value.items()}
    if type(value) is list:
        return [_restore_arrow(item) for item in value]
    return value


def _decode_parquet_rows(rows: list[dict[str, Any]], metadata: dict[bytes, bytes] | None) -> list[T1Transition]:
    if metadata is None or metadata.get(_PARQUET_METADATA_KEY) != PARQUET_ENCODING_VERSION.encode("ascii"):
        raise ValueError("unsupported or missing Parquet encoding metadata")
    result: list[T1Transition] = []
    from .candidates import validate_action_identity
    for row in rows:
        restored = _restore_arrow(row)
        transition = T1Transition.model_validate(restored)
        for action in [*transition.candidate_actions, transition.selected_action]:
            validate_action_identity(action)
        _canonical_json_bytes(transition.model_dump(mode="json"), limit=_MAX_OUTPUT_BYTES)
        result.append(transition)
    return result


def read_parquet(path: Path) -> list[T1Transition]:
    """Decode the documented nested Parquet encoding back to trusted T1 contracts."""
    if not isinstance(path, Path):
        raise ValueError("Parquet input must be a regular non-symlink file")
    if os.name != "posix":
        raise ValueError("secure Parquet reads require POSIX")
    parent_fd = _open_parent_fd(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_PARQUET_FILE_BYTES:
                raise ValueError
            chunks: list[bytes] = []; remaining = _MAX_PARQUET_FILE_BYTES + 1
            while remaining:
                chunk = os.read(fd, min(1_048_576, remaining))
                if not chunk: break
                chunks.append(chunk); remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) != info.st_size or len(raw) > _MAX_PARQUET_FILE_BYTES:
                raise ValueError
        finally:
            os.close(fd)
        parquet = pq.ParquetFile(pa.BufferReader(raw))
        metadata = parquet.metadata
        if (metadata is None or not 1 <= metadata.num_rows <= _MAX_OUTPUT_ITEMS
                or not 1 <= metadata.num_row_groups <= _MAX_OUTPUT_ITEMS
                or len(parquet.schema_arrow.names) != len(_TRANSITION_COLUMNS)):
            raise ValueError
        row_group_total = 0
        column_total = 0
        value_total = 0
        for group_index in range(metadata.num_row_groups):
            group = metadata.row_group(group_index)
            group_size = group.total_byte_size
            if type(group_size) is not int or group_size < 0:
                raise ValueError
            row_group_total += group_size
            if row_group_total > _MAX_OUTPUT_BYTES:
                raise ValueError
            for column_index in range(group.num_columns):
                column = group.column(column_index)
                size = column.total_uncompressed_size
                values = column.num_values
                if type(size) is not int or type(values) is not int or size < 0 or values < 0:
                    raise ValueError
                column_total += size
                value_total += values
                if column_total > _MAX_OUTPUT_BYTES or value_total > _MAX_OUTPUT_ITEMS * 1024:
                    raise ValueError
        table = parquet.read(use_threads=False)
    except Exception:
        raise ValueError("Parquet input is unreadable") from None
    finally:
        os.close(parent_fd)
    if set(table.column_names) != _TRANSITION_COLUMNS:
        raise ValueError("Parquet transition columns do not match the contract")
    try:
        decoded = _decode_parquet_rows(table.to_pylist(), table.schema.metadata)
        normalized = _normalize_values(decoded, T1Transition)
        if normalized != decoded:
            raise ValueError("Parquet transition canonical mismatch")
        return normalized
    except (TypeError, ValueError):
        raise ValueError("Parquet transition decode failed") from None

"""Deterministically bind a validated trace step to Action DSL candidates."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any, Callable

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from egsi.contracts.enrichment import EnrichmentPayload
from egsi.contracts.trajectory import strict_json
from egsi.data.repository_paths import canonical_repo_blob_path


_MAX_IDENTIFIER_UTF8_BYTES = 4_096
_MAX_TRACE_ITEMS = 64
_MAX_TRACE_ITEM_UTF8_BYTES = 256
_MAX_TRACE_TOTAL_UTF8_BYTES = 8_192
ACTION_DSL_SCHEMA_SHA256 = "8d11862d0923e201965e8c1dcadb29f12198e13924b8d066c3af7d3f96ab1234"
POLICY_CANONICALIZER_VERSION = "policy-trace-v1"

# (goal, tool_class, optional (target_kind, target_id) override)
OPERATION_PROFILE: dict[str, tuple[str, str, tuple[str, str | None] | None]] = {
    "enumerate_entrypoints": ("ESTABLISH_ENTRY", "repository_index", ("repository", "repository-0001")),
    "map_trust_boundary": ("ESTABLISH_ENTRY", "semantic_model", ("component", "component-0001")),
    "locate_sensitive_asset": ("CHECK_SECURITY_INVARIANT", "repository_index", ("resource", "resource-0001")),
    "find_callers": ("ESTABLISH_REACHABILITY", "graph_query", None),
    "find_callees": ("ESTABLISH_REACHABILITY", "graph_query", None),
    "find_references": ("ESTABLISH_REACHABILITY", "repository_index", None),
    "inspect_dispatch": ("ESTABLISH_REACHABILITY", "static_query", None),
    "find_source": ("ESTABLISH_ATTACKER_CONTROL", "repository_index", None),
    "find_sink": ("ESTABLISH_IMPACT", "repository_index", None),
    "trace_flow": ("ESTABLISH_REACHABILITY", "graph_query", None),
    "track_alias": ("ESTABLISH_REACHABILITY", "static_query", None),
    "track_field": ("ESTABLISH_REACHABILITY", "static_query", None),
    "verify_path_constraints": ("CHECK_GUARD_OR_SANITIZER", "static_query", None),
    "find_guard": ("CHECK_GUARD_OR_SANITIZER", "repository_index", None),
    "find_sanitizer": ("CHECK_GUARD_OR_SANITIZER", "repository_index", None),
    "trace_identity": ("CHECK_SECURITY_INVARIANT", "graph_query", None),
    "check_auth_relation": ("CHECK_SECURITY_INVARIANT", "semantic_model", ("resource", "resource-0001")),
    "check_lifecycle": ("CHECK_SECURITY_INVARIANT", "semantic_model", None),
    "check_ownership": ("CHECK_SECURITY_INVARIANT", "semantic_model", ("resource", "resource-0001")),
    "check_resource_control": ("CHECK_SECURITY_INVARIANT", "semantic_model", ("resource", "resource-0001")),
    "classify_operation": ("CHECK_SECURITY_INVARIANT", "semantic_model", None),
    "infer_invariant": ("CHECK_SECURITY_INVARIANT", "semantic_model", None),
    "compare_peer": ("FALSIFY_HYPOTHESIS", "repository_index", None),
    "update_hypothesis": ("FALSIFY_HYPOTHESIS", "semantic_model", ("hypothesis", "H-1")),
    "falsify_hypothesis": ("FALSIFY_HYPOTHESIS", "semantic_model", ("hypothesis", "H-1")),
    "validate_finding": ("VALIDATE_FINDING", "static_query", None),
    "reproduce_finding": ("VALIDATE_FINDING", "dynamic_harness", None),
    "open_or_switch_branch": ("CONTROL_SEARCH", "control_only", ("branch", "B-1")),
    "backtrack": ("CONTROL_SEARCH", "control_only", ("checkpoint", "initial")),
    "terminate": ("CONTROL_SEARCH", "control_only", ("episode", None)),
}
ALTERNATIVES = tuple(OPERATION_PROFILE)
TARGET_KINDS = frozenset(
    {
        "repository", "component", "function", "symbol", "value", "field",
        "type", "path", "resource", "identity", "hypothesis", "branch",
        "checkpoint", "episode",
    }
)


@dataclass(frozen=True, slots=True)
class CanonicalPolicyStep:
    """Locally reconstructed policy input with no teacher-controlled identifiers."""

    step_id: str
    goal: str
    operation: str
    target_kind: str
    target_id: str
    target_location: str | None
    resolves_unknowns: tuple[str, ...]
    expected_evidence_type: str
    tool_class: str


def _canonical_path(value: str) -> str:
    try:
        return canonical_repo_blob_path(value)
    except ValueError:
        raise ValueError("policy path is invalid") from None


def expected_evidence_type(operation: str, target_kind: str) -> str:
    if operation in {"open_or_switch_branch", "backtrack", "terminate"}:
        return "control_decision"
    return {
        "path": "source_location",
        "function": "program_element",
        "symbol": "program_element",
        "value": "program_element",
        "field": "program_element",
        "type": "program_element",
        "resource": "semantic_relation",
        "identity": "semantic_relation",
        "repository": "repository_metadata",
        "component": "repository_metadata",
        "hypothesis": "hypothesis_assessment",
        "branch": "control_decision",
        "checkpoint": "control_decision",
        "episode": "control_decision",
    }[target_kind]


def canonicalize_policy_trace(
    payload: EnrichmentPayload,
    episode_id: str,
    *,
    vulnerable_path_exists: Callable[[str], bool],
) -> tuple[CanonicalPolicyStep, ...]:
    """Convert a validated oracle trace into a closed, versioned policy trace."""

    if not isinstance(payload, EnrichmentPayload) or not episode_id:
        raise ValueError("canonical policy trace input is invalid")
    obligation_map = {
        item.obligation_id: f"O-{index:04d}"
        for index, item in enumerate(payload.obligations, start=1)
    }
    result: list[CanonicalPolicyStep] = []
    for index, raw in enumerate(payload.trace, start=1):
        if raw.operation not in OPERATION_PROFILE or raw.target_kind not in TARGET_KINDS:
            raise ValueError("canonical policy trace vocabulary is invalid")
        goal, tool_class, override = OPERATION_PROFILE[raw.operation]
        target_kind = raw.target_kind
        if target_kind == "path":
            target_id = _canonical_path(raw.target_id)
            if not vulnerable_path_exists(target_id):
                raise ValueError("canonical policy path is not in the vulnerable snapshot")
            target_location: str | None = target_id
        else:
            target_id = f"{target_kind}-{index:04d}"
            target_location = None
        if override is not None:
            target_kind, override_id = override
            target_id = episode_id if override_id is None else override_id
            target_location = None
        try:
            resolves = tuple(obligation_map[value] for value in raw.resolves_unknowns)
        except KeyError:
            raise ValueError("canonical policy obligation binding is invalid") from None
        result.append(
            CanonicalPolicyStep(
                step_id=f"S-{index:04d}",
                goal=goal,
                operation=raw.operation,
                target_kind=target_kind,
                target_id=target_id,
                target_location=target_location,
                resolves_unknowns=resolves,
                expected_evidence_type=expected_evidence_type(raw.operation, target_kind),
                tool_class=tool_class,
            )
        )
    return tuple(result)


def canonical_step_from_selected_action(action: dict[str, Any]) -> CanonicalPolicyStep:
    """Reconstruct the canonical compiler input embedded in one selected action."""

    validate_action_identity(action)
    metadata = action["metadata"]
    target = action["target"]
    operation = action["operation"]
    profile = OPERATION_PROFILE.get(operation)
    if profile is None or action["goal"] != profile[0] or action["tool_class"] != profile[1]:
        raise ValueError("selected action operation profile is invalid")
    step_id = metadata["step_id"]
    if not re.fullmatch(r"S-[0-9]{4}", step_id):
        raise ValueError("selected action step identifier is invalid")
    resolves = tuple(action["resolves_unknowns"])
    if any(not re.fullmatch(r"O-[0-9]{4}", value) for value in resolves):
        raise ValueError("selected action obligation identifier is invalid")
    if action.get("obligation_id") != (resolves[0] if resolves else None):
        raise ValueError("selected action obligation binding is invalid")
    target_kind = target["kind"]
    target_id = target["id"]
    target_location = target.get("location")
    if target_kind == "path":
        target_id = _canonical_path(target_id)
        if target_location != target_id:
            raise ValueError("selected action path binding is invalid")
    elif target_location is not None:
        raise ValueError("selected action non-path location is invalid")
    elif profile[2] is None:
        ordinal = step_id.removeprefix("S-")
        if target_id != f"{target_kind}-{ordinal}":
            raise ValueError("selected action target identifier is not canonical")
    else:
        expected_kind, expected_id = profile[2]
        if target_kind != expected_kind:
            raise ValueError("selected action target kind is invalid")
        if expected_id is not None and target_id != expected_id:
            raise ValueError("selected action target identifier is invalid")
    canonical = CanonicalPolicyStep(
        step_id=step_id,
        goal=action["goal"],
        operation=operation,
        target_kind=target_kind,
        target_id=target_id,
        target_location=target_location,
        resolves_unknowns=resolves,
        expected_evidence_type=action["expected_evidence_type"],
        tool_class=action["tool_class"],
    )
    return _validate_step(canonical)


def _canonical_json_bytes(value: object) -> bytes:
    """Serialize a JSON value without locale or process-dependent ambiguity."""

    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("value is not canonical UTF-8 JSON") from None


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def action_id(episode_id: str, operation: str, target_id: str) -> str:
    """Return a deterministic DSL-shaped identifier for legacy direct callers."""

    return "A-" + _digest([episode_id, operation, target_id])[:24]


def _require_identifier(name: str, value: object) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{name} identifier must be a non-empty UTF-8 string") from None
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise ValueError(f"{name} identifier must be a non-empty UTF-8 string") from None
    if len(encoded) > _MAX_IDENTIFIER_UTF8_BYTES:
        raise ValueError(f"{name} identifier must be within the UTF-8 size limit") from None
    return value


def _validate_trace_list(name: str, values: object, *, unique: bool) -> None:
    """Bound untrusted trace collections before copying them into actions."""

    if type(values) is not list or len(values) > _MAX_TRACE_ITEMS:
        raise ValueError(f"{name} must contain at most {_MAX_TRACE_ITEMS} items") from None
    total_bytes = 0
    for value in values:
        if type(value) is not str or not value:
            raise ValueError(f"{name} must contain non-empty UTF-8 string items") from None
        try:
            item_bytes = len(value.encode("utf-8"))
        except UnicodeError:
            raise ValueError(f"{name} must contain non-empty UTF-8 string items") from None
        if item_bytes > _MAX_TRACE_ITEM_UTF8_BYTES:
            raise ValueError(f"{name} item exceeds UTF-8 size limit") from None
        total_bytes += item_bytes
        if total_bytes > _MAX_TRACE_TOTAL_UTF8_BYTES:
            raise ValueError(f"{name} exceeds total UTF-8 size limit") from None
    if unique and len(set(values)) != len(values):
        raise ValueError(f"{name} must not contain duplicates") from None


def _validate_step(step: object) -> CanonicalPolicyStep:
    if not isinstance(step, CanonicalPolicyStep):
        raise ValueError("step must be a CanonicalPolicyStep") from None
    for name in (
        "step_id", "goal", "operation", "target_kind", "target_id",
        "expected_evidence_type", "tool_class",
    ):
        _require_identifier(name, getattr(step, name, None))
    if not re.fullmatch(r"S-[0-9]{4}", step.step_id):
        raise ValueError("step identifier is not canonical")
    if step.target_location is not None:
        _require_identifier("target_location", step.target_location)
    _validate_trace_list("resolves_unknowns", list(step.resolves_unknowns), unique=True)
    if any(not re.fullmatch(r"O-[0-9]{4}", item) for item in step.resolves_unknowns):
        raise ValueError("obligation identifier is not canonical")
    profile = OPERATION_PROFILE.get(step.operation)
    if (
        profile is None
        or step.goal != profile[0]
        or step.tool_class != profile[1]
        or step.target_kind not in TARGET_KINDS
        or step.expected_evidence_type
        != expected_evidence_type(step.operation, step.target_kind)
    ):
        raise ValueError("canonical policy step does not match its operation profile")
    if step.target_kind == "path":
        if _canonical_path(step.target_id) != step.target_id or step.target_location != step.target_id:
            raise ValueError("canonical policy path binding is invalid")
    elif step.target_location is not None:
        raise ValueError("canonical policy non-path location is invalid")
    elif profile[2] is None:
        ordinal = step.step_id.removeprefix("S-")
        if step.target_id != f"{step.target_kind}-{ordinal}":
            raise ValueError("canonical policy target identifier is invalid")
    else:
        override_kind, override_id = profile[2]
        if step.target_kind != override_kind:
            raise ValueError("canonical policy target kind is invalid")
        if override_id is not None and step.target_id != override_id:
            raise ValueError("canonical policy target identifier is invalid")
    return step


def _base_action(
    case_id: str,
    episode_id: str,
    branch_id: str,
    step: CanonicalPolicyStep,
    operation: str,
) -> dict[str, Any]:
    goal, tool_class, target_override = OPERATION_PROFILE[operation]
    target_kind, target_id = step.target_kind, step.target_id
    target_location = step.target_location
    if target_override is not None:
        target_kind, target_id = target_override
        if target_id is None:
            target_id = episode_id
        target_location = None

    # These proof-frontier fields follow one state-wide rule for every
    # candidate.  They therefore cannot reveal which candidate was selected.
    resolves_unknowns = list(step.resolves_unknowns)
    return {
        "schema_version": "1.0",
        "episode_id": episode_id,
        "branch_id": branch_id,
        "actor_role": "policy_selector",
        "hypothesis_id": "H-1",
        "obligation_id": resolves_unknowns[0] if resolves_unknowns else None,
        "goal": goal,
        "operation": operation,
        "target": {
            "kind": target_kind,
            "id": target_id,
            "location": target_location,
            "version": None,
        },
        "arguments": {},
        "resolves_unknowns": resolves_unknowns,
        "preconditions": [],
        "expected_evidence_type": expected_evidence_type(operation, target_kind),
        "tool_class": tool_class,
        "budget_cap": {"seconds": 120.0, "tool_calls": 1, "tokens": 2000, "analysis_units": 1.0},
        "fallback_operations": [],
        "metadata": {
            "label_scope": "patch_grounded_bc",
            "case_id": case_id,
            "step_id": step.step_id,
            "canonicalizer_version": POLICY_CANONICALIZER_VERSION,
        },
    }


def make_action(
    episode_id: str,
    branch_id: str,
    step: CanonicalPolicyStep,
    operation: str,
    *,
    case_id: str = "",
) -> dict[str, Any]:
    """Build one complete Action DSL candidate from its complete semantic base."""

    base = _base_action(case_id, episode_id, branch_id, step, operation)
    semantic_digest = _digest(base)
    return {
        **base,
        "action_id": "A-" + semantic_digest[:24],
        "idempotency_key": "sha256:" + semantic_digest,
    }


def _execution_identity(action: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in action.items() if key not in {"action_id", "idempotency_key"}}


def validate_action_identity(action: object) -> None:
    """Require an Action DSL object to match its content-derived identity."""
    if type(action) is not dict:
        raise ValueError("action must be a strict JSON object")
    strict_json(action)
    if any(_load_validator().iter_errors(action)):
        raise ValueError("action is not valid under the pinned Action DSL")
    metadata = action.get("metadata")
    if type(metadata) is not dict or set(metadata) != {
        "label_scope", "case_id", "step_id", "canonicalizer_version"
    }:
        raise ValueError("action metadata has an invalid shape")
    if (
        metadata.get("label_scope") != "patch_grounded_bc"
        or metadata.get("canonicalizer_version") != POLICY_CANONICALIZER_VERSION
        or not all(
            type(metadata.get(key)) is str and metadata[key]
            for key in ("case_id", "step_id")
        )
    ):
        raise ValueError("action metadata has an invalid value")
    base = _execution_identity(action)
    digest = _digest(base)
    if action.get("action_id") != "A-" + digest[:24] or action.get("idempotency_key") != "sha256:" + digest:
        raise ValueError("action identity does not match canonical content")


def action_integrity(action: object) -> bool:
    """Boolean predicate for callers which only need a non-throwing check."""
    try:
        validate_action_identity(action)
    except ValueError:
        return False
    return True


def _ordering_key(case_id: str, episode_id: str, branch_id: str, step_id: str, action: dict[str, Any]) -> str:
    return _digest({
        "case_id": case_id,
        "episode_id": episode_id,
        "branch_id": branch_id,
        "step_id": step_id,
        "candidate": _execution_identity(action),
    })


def _read_action_schema_bytes() -> bytes:
    return resources.files("egsi.resources").joinpath("ACTION_DSL.schema.json").read_bytes()


@lru_cache(maxsize=1)
def _load_validator() -> Draft202012Validator:
    """Load the hash-pinned package resource once for the process lifetime."""

    try:
        schema_bytes = _read_action_schema_bytes()
        if hashlib.sha256(schema_bytes).hexdigest() != ACTION_DSL_SCHEMA_SHA256:
            raise ValueError("schema digest mismatch")
        schema = json.loads(schema_bytes.decode("utf-8"))
        Draft202012Validator.check_schema(schema)
        return Draft202012Validator(schema)
    except (OSError, ImportError, AttributeError, UnicodeError, json.JSONDecodeError, SchemaError, TypeError, ValueError):
        raise ValueError("Action DSL schema is unavailable or invalid") from None


def compile_candidates(
    case_id: str,
    episode_id: str,
    branch_id: str,
    step: CanonicalPolicyStep,
) -> tuple[list[dict[str, Any]], list[bool], dict[str, Any]]:
    """Compile a selected trace step plus deterministic Action DSL alternatives."""

    case_id = _require_identifier("case_id", case_id)
    episode_id = _require_identifier("episode_id", episode_id)
    branch_id = _require_identifier("branch_id", branch_id)
    step = _validate_step(step)

    operations = (step.operation,) + tuple(operation for operation in ALTERNATIVES if operation != step.operation)
    actions = [
        make_action(episode_id, branch_id, step, operation, case_id=case_id)
        for operation in operations[:64]
    ]
    selected = actions[0]
    actions.sort(key=lambda action: _ordering_key(case_id, episode_id, branch_id, step.step_id, action))

    validator = _load_validator()
    legal_mask = [not any(validator.iter_errors(action)) for action in actions]
    selected_index = actions.index(selected)
    if not legal_mask[selected_index]:
        raise ValueError("teacher-selected action is not legal Action DSL") from None
    if sum(legal_mask) < 4:
        raise ValueError("candidate compilation produced fewer than four legal actions") from None
    fingerprints = [_canonical_json_bytes(action) for action in actions]
    if len(set(fingerprints)) != len(fingerprints):
        raise ValueError("candidate compilation produced duplicate canonical actions") from None
    if len({action["action_id"] for action in actions}) != len(actions):
        raise ValueError("candidate compilation produced duplicate action identifiers") from None
    if len({action["idempotency_key"] for action in actions}) != len(actions):
        raise ValueError("candidate compilation produced duplicate idempotency keys") from None

    return deepcopy(actions), list(legal_mask), deepcopy(selected)

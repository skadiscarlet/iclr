"""Contracts for the patch-grounded behavioural-cloning trajectory."""

import json
import math
import re
import unicodedata
from typing import Any, Literal, Annotated

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator

NonEmpty = Annotated[str, StringConstraints(min_length=1)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_default=True)


_MAX_JSON_NODES = 4096
_MAX_JSON_DEPTH = 128
_MAX_T1_TRACE_STEPS = 64
PARQUET_EMPTY_OBJECT_TAG = "__egsi_parquet_empty_object_v1__"
_FORBIDDEN_T1_KEYS = frozenset({
    "cwe", "patch", "fixed", "gold", "advisory", "authorization", "fact", "facts",
    "claim", "claims", "certificate", "dynamic_verdict",
})
_ACTION_ID_RE = re.compile(r"^A-[0-9a-f]{24}$")


def _forbidden_key(key: str) -> bool:
    folded = unicodedata.normalize("NFKC", key).casefold().replace("-", "_")
    return (folded == PARQUET_EMPTY_OBJECT_TAG or folded in _FORBIDDEN_T1_KEYS
            or any(token in folded for token in ("cwe", "patch", "fixed", "gold", "advisory", "authorization", "certificate")))


def strict_json(value: object, *, forbid_t1_terms: bool = False) -> None:
    """Validate a bounded, cycle-free JSON tree; tuples and coercions are data bugs."""
    pending: list[tuple[object, int, bool]] = [(value, 0, False)]
    active: set[int] = set(); nodes = 0
    while pending:
        current, depth, leaving = pending.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON structure exceeds safety limit")
        if leaving:
            active.discard(id(current)); continue
        if current is None or type(current) in {str, bool, int}:
            continue
        if type(current) is float:
            if not math.isfinite(current): raise ValueError("JSON floats must be finite")
            continue
        if type(current) not in {dict, list}:
            raise ValueError("value is not strict JSON")
        marker = id(current)
        if marker in active: raise ValueError("JSON cycles are forbidden")
        active.add(marker); pending.append((current, depth, True))
        if type(current) is dict:
            for key, child in current.items():
                if type(key) is not str: raise ValueError("JSON object keys must be strings")
                if _forbidden_key(key) and key == PARQUET_EMPTY_OBJECT_TAG:
                    raise ValueError("reserved Parquet encoding key is forbidden in source data")
                if forbid_t1_terms and _forbidden_key(key):
                    raise ValueError("T1 value contains forbidden oracle field")
                pending.append((child, depth + 1, False))
        else:
            for child in current: pending.append((child, depth + 1, False))


class RewardVector(_Contract):
    label_scope: Literal["patch_grounded_bc"]
    terminal: float = 0
    verified_proof_delta: float = 0
    counter_evidence: float = 0
    contradiction_resolution: float = 0
    normalized_cost: float = 0

    @model_validator(mode="after")
    def require_zero_vector(self) -> "RewardVector":
        if any(getattr(self, name) != 0 for name in (
            "terminal", "verified_proof_delta", "counter_evidence",
            "contradiction_resolution", "normalized_cost",
        )):
            raise ValueError("patch_grounded_bc reward vector must be all zero")
        return self


class VerifierDecision(_Contract):
    accepted: bool
    label_scope: Literal["patch_grounded_bc"] = "patch_grounded_bc"
    checks: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def finite_json_checks(self) -> "VerifierDecision":
        strict_json(self.checks)
        if self.accepted is not True or self.label_scope != "patch_grounded_bc" or self.checks != {"schema": True, "location": True, "action_dsl": True, "redaction": True}:
            raise ValueError("T1 verifier decision must be the exact static label check")
        return self


class T1Transition(_Contract):
    schema_version: Literal["1.0"] = "1.0"
    episode_id: NonEmpty
    state_version: int = Field(ge=0)
    state: dict[str, JsonValue]
    candidate_actions: list[dict[str, JsonValue]] = Field(min_length=1, max_length=64)
    legal_mask: list[bool] = Field(min_length=1, max_length=64)
    selected_action: dict[str, JsonValue]
    observation: dict[str, JsonValue]
    evidence_delta: dict[str, JsonValue]
    verifier_decision: VerifierDecision
    reward_vector: RewardVector
    next_state_version: int = Field(ge=1)
    done: bool

    @model_validator(mode="after")
    def validate_transition(self) -> "T1Transition":
        for value in (self.state, self.candidate_actions, self.selected_action,
                      self.observation, self.evidence_delta):
            strict_json(value, forbid_t1_terms=value is not self.evidence_delta)
        state_keys = {"schema_version", "case_id", "state", "repository", "budget", "bounded_history", "unknowns", "state_version"}
        if set(self.state) != state_keys or self.state.get("schema_version") != "1.0" or self.state.get("state") != "SELECT_ACTION" or self.state.get("state_version") != self.state_version:
            raise ValueError("T1 state must have the exact safe policy shape")
        repository = self.state.get("repository")
        if type(repository) is not dict or set(repository) != {"upstream_id", "vulnerable_commit"}:
            raise ValueError("T1 state repository must be redacted")
        if (type(self.state.get("case_id")) is not str or not self.state["case_id"]
                or len(self.state["case_id"].encode("utf-8")) > 512
                or type(repository["upstream_id"]) is not str or not repository["upstream_id"]
                or len(repository["upstream_id"].encode("utf-8")) > 512
                or type(repository["vulnerable_commit"]) is not str or not re.fullmatch(r"[0-9a-f]{40}", repository["vulnerable_commit"])):
            raise ValueError("T1 state identity is invalid")
        if self.state.get("budget") != {"seconds": 900, "tool_calls": 20, "tokens": 16000, "analysis_units": 20.0}:
            raise ValueError("T1 state budget must be the exact seed budget")
        if self.state.get("unknowns") != ["entrypoint", "security_invariant", "guard", "impact"]:
            raise ValueError("T1 state unknowns must be the exact seed unknowns")
        history = self.state.get("bounded_history")
        if type(history) is not list or len(history) != self.state_version or len(history) > _MAX_T1_TRACE_STEPS:
            raise ValueError("T1 state history must be bounded")
        for index, item in enumerate(history):
            if type(item) is not dict or set(item) != {"state_version", "action_id"} or item.get("state_version") != index or type(item.get("action_id")) is not str or not _ACTION_ID_RE.fullmatch(item["action_id"]):
                raise ValueError("T1 state history is invalid")
        if self.observation != {"type": "oracle_label_only", "label_scope": "patch_grounded_bc", "receipt": None}:
            raise ValueError("T1 observation must be oracle-label-only")
        if self.evidence_delta != {"facts": [], "claims": [], "resolved_unknowns": []}:
            raise ValueError("T1 evidence delta must be empty")
        if self.next_state_version != self.state_version + 1:
            raise ValueError("next_state_version must equal state_version + 1")
        if self.state_version > _MAX_T1_TRACE_STEPS:
            raise ValueError("T1 state_version exceeds trace bound")
        if len(self.candidate_actions) != len(self.legal_mask):
            raise ValueError("candidate_actions and legal_mask must have equal length")
        if any("actor_role" in action for action in self.candidate_actions):
            if sum(self.legal_mask) < 4 or any(action.get("actor_role") != "policy_selector" for action in self.candidate_actions):
                raise ValueError("compiled T1 candidates must be legal policy-selector alternatives")
        def fingerprint(action: dict[str, JsonValue]) -> str:
            strict_json(action, forbid_t1_terms=True)
            return json.dumps(action, allow_nan=False, sort_keys=True, separators=(",", ":"))
        fingerprints = [fingerprint(action) for action in self.candidate_actions]
        if len(set(fingerprints)) != len(fingerprints):
            raise ValueError("candidate actions must have unique canonical fingerprints")
        selected_fingerprint = fingerprint(self.selected_action)
        if selected_fingerprint not in fingerprints:
            raise ValueError("selected_action must be one of candidate_actions")
        selected_index = fingerprints.index(selected_fingerprint)
        if not self.legal_mask[selected_index]:
            raise ValueError("selected_action must be legal")
        return self


class EpisodeEvent(_Contract):
    schema_version: Literal["1.0"] = "1.0"
    sequence: int = Field(ge=0)
    episode_id: NonEmpty
    event_type: Literal[
        "EPISODE_STARTED", "HYPOTHESIS_CREATED", "ACTION_PROPOSED",
        "ACTION_SELECTED", "PATCH_GROUNDED_LABEL_RECORDED", "EPISODE_CLOSED",
    ]
    payload: dict[str, JsonValue]
    previous_event_sha256: Sha256 | None = None
    event_sha256: Sha256

    @model_validator(mode="after")
    def validate_event(self) -> "EpisodeEvent":
        if self.sequence == 0 and self.previous_event_sha256 is not None:
            raise ValueError("sequence zero cannot have previous event hash")
        if self.sequence > 0 and self.previous_event_sha256 is None:
            raise ValueError("non-zero sequence requires previous event hash")
        strict_json(self.payload)
        return self

"""Actor-visible schemas. Answer fields are rejected, not redacted."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sbs.errors import SchemaAnswerFieldError


ANSWER_FIELD_NAMES = frozenset(
    {
        "advisory",
        "aliases",
        "answer",
        "cve",
        "cve_id",
        "exploit",
        "fix_pair",
        "fix_pairing",
        "fixed_label",
        "fixed_patch",
        "gold",
        "gold_label",
        "gold_locations",
        "gold_proof_obligations",
        "patch",
        "poc",
        "vulnerable_label",
    }
)

TERMINAL_FINISH = "FINISH"
TERMINAL_UNRESOLVED = "UNRESOLVED"
TerminalKind = Literal["FINISH", "UNRESOLVED"]
DecisionVerdict = Literal["supported", "refuted", "unresolved"]
HypothesisStatus = Literal["open", "supported", "refuted", "unresolved"]
MaterialKind = Literal["fixture", "real"]
SplitId = Literal["dev_pilot"]


def sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def sha256_text(payload: str) -> str:
    return sha256_bytes(payload.encode("utf-8"))


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def iter_answer_field_hits(payload: Any, *, prefix: str = "") -> list[str]:
    """Return dotted paths of forbidden answer keys in a JSON-like object."""

    hits: list[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            lowered = key.lower() if isinstance(key, str) else ""
            path = f"{prefix}.{key}" if prefix else str(key)
            if lowered in ANSWER_FIELD_NAMES:
                hits.append(path)
            hits.extend(iter_answer_field_hits(value, prefix=path))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            path = f"{prefix}[{index}]"
            hits.extend(iter_answer_field_hits(item, prefix=path))
    return hits


def reject_answer_fields(payload: Any) -> None:
    hits = iter_answer_field_hits(payload)
    if hits:
        raise SchemaAnswerFieldError(
            "actor-visible object contains forbidden answer fields: "
            + ", ".join(hits)
        )


class _ActorModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def _reject_answer_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            reject_answer_fields(data)
        return data


class LineSpan(_ActorModel):
    start_line: int | None = None
    end_line: int | None = None

    def covers(self, other: "LineSpan") -> bool:
        if self.start_line is None or self.end_line is None:
            return False
        if other.start_line is None or other.end_line is None:
            return False
        return self.start_line <= other.start_line and other.end_line <= self.end_line


class EvidenceRecord(_ActorModel):
    evidence_id: str
    display_path: str
    span: LineSpan = Field(default_factory=LineSpan)
    content_sha256: str
    source_category: Literal[
        "source_snippet", "structured_record", "document_excerpt"
    ]
    material_kind: MaterialKind
    generation_id: str | None = None
    source_revision: str | None = None
    relative_read_path: str

    @field_validator("content_sha256")
    @classmethod
    def _hash_prefix(cls, value: str) -> str:
        if not value.startswith("sha256:") or len(value) != 71:
            raise ValueError("content_sha256 must be sha256:<64 hex>")
        return value

    @field_validator("display_path", "relative_read_path")
    @classmethod
    def _relative_path(cls, value: str) -> str:
        if not value or value.startswith("/") or "\\" in value:
            raise ValueError("paths must be relative POSIX paths")
        return value


class CaseView(_ActorModel):
    case_id: str
    visible_context: str
    allowed_evidence_ids: list[str]
    split: SplitId
    material_kind: MaterialKind
    project_family: str | None = None
    instance_id: str | None = None
    generation_id: str | None = None

    @field_validator("case_id")
    @classmethod
    def _opaque_case_id(cls, value: str) -> str:
        lowered = value.lower()
        if lowered.startswith("cve-") or lowered.startswith("ghsa-"):
            raise ValueError("case_id must be opaque; CVE/GHSA identifiers are forbidden")
        return value

    @field_validator("allowed_evidence_ids")
    @classmethod
    def _unique_ids(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("allowed_evidence_ids must not be empty")
        if len(set(value)) != len(value):
            raise ValueError("allowed_evidence_ids must be unique")
        return value


class Hypothesis(_ActorModel):
    hypothesis_id: str
    entities: list[str]
    security_relation: str
    relation_source: str
    support_refs: list[str] = Field(default_factory=list)
    counter_refs: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    status: HypothesisStatus = "open"


class InspectionRequest(_ActorModel):
    evidence_id: str


class Observation(_ActorModel):
    evidence_id: str
    material: str | None
    parseable: bool
    provenance: str
    uncertainty: str
    found: bool

    @model_validator(mode="after")
    def _absent_is_not_negative_proof(self) -> Observation:
        if not self.found and "not_found" not in self.uncertainty:
            raise ValueError("missing material must record uncertainty including not_found")
        return self


class Decision(_ActorModel):
    verdict: DecisionVerdict
    applies_to_hypothesis_id: str
    not_a_global_safety_guarantee: Literal[True] = True


class AuditState(_ActorModel):
    observed_evidence: list[str] = Field(default_factory=list)
    hypotheses: list[Hypothesis]
    unresolved_items: list[str] = Field(default_factory=list)
    remaining_budget: int
    inspection_history: list[str] = Field(default_factory=list)
    terminal: TerminalKind | None = None
    termination_reason: str | None = None
    decision: Decision | None = None

    @field_validator("remaining_budget")
    @classmethod
    def _budget_non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("remaining_budget must be >= 0")
        return value


class RunManifest(_ActorModel):
    schema_version: Literal["1.0"] = "1.0"
    mode: Literal["fixture_replay"]
    seed: int
    split: SplitId
    representations: list[Literal["history", "sbs"]]
    evidence_order: Literal["frozen"]
    max_observations: int
    model_calls: int
    model_calls_allowed: int
    compute_detection_metrics: bool
    detection_metrics: None = None
    detection_metrics_status: Literal["not_evaluated"] = "not_evaluated"
    training_loss: None = None
    q_accuracy: None = None
    value_scorer_available: Literal[False] = False
    code_sha: str | None = None
    config_sha256: str
    material_sha256: str
    output_index: dict[str, str]
    exit_status: str
    started_at: str | None = None
    finished_at: str | None = None

    @field_validator("model_calls")
    @classmethod
    def _zero_model_calls(cls, value: int) -> int:
        if value != 0:
            raise ValueError("R01 replay records model_calls=0 only")
        return value


class SmokeConfig(_ActorModel):
    mode: Literal["fixture_replay"]
    seed: int
    representations: list[Literal["history", "sbs"]]
    evidence_order: Literal["frozen"]
    max_observations: int
    split: SplitId
    model_calls_allowed: Literal[0]
    compute_detection_metrics: Literal[False]
    fixtures_root: str = "fixtures/r01"
    value_scorer_available: Literal[False] = False


class ScriptedUpdate(_ActorModel):
    hypothesis_id: str
    add_support: list[str] = Field(default_factory=list)
    add_counter: list[str] = Field(default_factory=list)
    add_unknowns: list[str] = Field(default_factory=list)
    remove_unknowns: list[str] = Field(default_factory=list)
    status: HypothesisStatus | None = None
    terminal: TerminalKind | None = None
    termination_reason: str | None = None


class ReplayScript(_ActorModel):
    observation_order: list[str]
    initial_hypothesis: Hypothesis
    updates: dict[str, ScriptedUpdate]
    script_kind: Literal["fixture_script"] = "fixture_script"


CANDIDATE_STATUSES = (
    "metadata_only",
    "source_resolved",
    "evidence_draft",
    "human_verified",
    "excluded",
)


class CandidatePair(_ActorModel):
    """Management-side registry row. Not an actor view."""

    pair_id: str
    project_family: str
    dataset_origin: str
    dataset_revision: str | None
    source_locator: str | None
    buggy_revision: str | None
    fixed_revision: str | None
    category_claim: str
    obligation_basis: str | None
    status: Literal[
        "metadata_only",
        "source_resolved",
        "evidence_draft",
        "human_verified",
        "excluded",
    ]
    license_note: str | None
    split: SplitId
    blocker: str | None = None
    local_catalog_key: str | None = None

    @model_validator(mode="after")
    def _nulls_are_explicit(self) -> CandidatePair:
        if self.status == "human_verified":
            raise ValueError(
                "human_verified cannot be set by automated R01 registration"
            )
        return self


def parse_case_view(payload: Any) -> CaseView:
    reject_answer_fields(payload)
    return CaseView.model_validate(payload)


def parse_smoke_config(payload: Any) -> SmokeConfig:
    return SmokeConfig.model_validate(payload)


class VisibleEvidence(_ActorModel):
    """Normalized public evidence. Provenance hashes stay off-prompt by default."""

    instance_id: str
    evidence_id: str
    material: str | None
    visible_sha256: str
    display_path: str
    displayed_span: LineSpan
    found: bool
    parseable: bool
    uncertainty: str

    @field_validator("visible_sha256")
    @classmethod
    def _hash_prefix(cls, value: str) -> str:
        if not value.startswith("sha256:") or len(value) != 71:
            raise ValueError("visible_sha256 must be sha256:<64 hex>")
        return value


class HistoryEvent(_ActorModel):
    kind: Literal["observation"] = "observation"
    evidence_id: str
    found: bool
    provenance: str
    uncertainty: str
    material: str | None
    displayed_span: LineSpan | None = None
    visible_sha256: str | None = None


class EvidenceRef(_ActorModel):
    evidence_id: str
    instance_id: str
    generation_id: str
    span: LineSpan | None = None


class ModelUpdate(_ActorModel):
    hypothesis_id: str
    support_refs: list[EvidenceRef] = Field(default_factory=list)
    counter_refs: list[EvidenceRef] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    status: HypothesisStatus | None = None
    verdict: DecisionVerdict | None = None
    hypothesis_text: str | None = None


class InstanceManifest(_ActorModel):
    """Actor-root version-bound identity. source_revision is required."""

    schema_version: Literal["1.0"] = "1.0"
    instance_id: str
    generation_id: str
    source_revision: str
    split: SplitId
    material_kind: MaterialKind
    case_relative_path: Literal["case.json"] = "case.json"

    @field_validator("source_revision")
    @classmethod
    def _revision_required(cls, value: str) -> str:
        if not value or value == "None":
            raise ValueError("source_revision is required for version-bound instances")
        if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
            raise ValueError("source_revision must be a lowercase 40-hex commit")
        return value

    @field_validator("instance_id")
    @classmethod
    def _opaque_instance(cls, value: str) -> str:
        lowered = value.lower()
        if lowered.startswith("cve-") or lowered.startswith("ghsa-"):
            raise ValueError("instance_id must be opaque")
        for token in ("buggy", "fixed", "vulnerable", "patch", "pair-role"):
            if token in lowered:
                raise ValueError("instance_id must not encode pair role")
        return value


class FrozenPilotConfig(_ActorModel):
    schema_version: Literal["1.0"] = "1.0"
    mode: Literal["frozen_model_pilot"]
    task_id: Literal["R02B"]
    seed: int
    split: SplitId
    representations: list[Literal["history", "sbs"]]
    order_seeds: list[int]
    max_pairs: int
    first_batch_pairs: int
    model_calls_per_episode: int
    max_input_tokens: int
    max_new_tokens: int
    batch_size: Literal[1]
    do_sample: Literal[False]
    request_caps: dict[str, int]
    wall_clock_limit_seconds: int
    paid_budget_usd: Literal[0]
    trust_remote_code: Literal[False] = False
    enable_branch_rollouts: Literal[False] = False
    enable_training: Literal[False] = False
    actor_manifest_relative_path: str
    run_output_root: str
    public_evidence_policy: Literal["common_rendered_blocks"] = "common_rendered_blocks"
    semantic_scoring_requires_human_review: Literal[True] = True
    model: dict[str, Any]
    actor_manifest_sha256: str | None = None
    implementation_sha: str | None = None


class FrozenPilotManifest(_ActorModel):
    schema_version: Literal["1.0"] = "1.0"
    mode: Literal["frozen_model_pilot"]
    task_id: Literal["R02B"]
    seed: int
    split: SplitId
    representations: list[Literal["history", "sbs"]]
    model_repo_id: str
    model_revision: str
    dtype: str
    device: str
    trust_remote_code: Literal[False] = False
    model_calls: int
    model_calls_allowed: int
    requests_attempted: int
    hard_total: int
    paid_budget_usd: Literal[0] = 0
    compute_detection_metrics: Literal[False] = False
    detection_metrics: None = None
    detection_metrics_status: Literal["not_evaluated"] = "not_evaluated"
    semantic_metrics: None = None
    semantic_metrics_status: Literal["not_evaluated"] = "not_evaluated"
    training_loss: None = None
    q_accuracy: None = None
    value_scorer_available: Literal[False] = False
    code_sha: str | None = None
    config_sha256: str
    material_sha256: str
    output_index: dict[str, str]
    exit_status: str
    started_at: str | None = None
    finished_at: str | None = None
    fairness_hashes: dict[str, str] = Field(default_factory=dict)


def instance_cache_key(instance_id: str, revision: str, generation: str) -> str:
    return sha256_text(f"{instance_id}\n{revision}\n{generation}")


def parse_frozen_pilot_config(payload: Any) -> FrozenPilotConfig:
    if not isinstance(payload, dict):
        raise ValueError("pilot config must be an object")
    if payload.get("document_kind") == "template_not_runnable_until_locked":
        raise ValueError("pilot template is not a locked config")
    data = {
        key: value
        for key, value in payload.items()
        if key not in {"document_kind", "env_probe"}
    }
    return FrozenPilotConfig.model_validate(data)


def load_instance_manifest_payload(payload: Any) -> InstanceManifest:
    if not isinstance(payload, dict):
        raise ValueError("instance manifest must be an object")
    allowed = set(InstanceManifest.model_fields)
    return InstanceManifest.model_validate(
        {key: payload[key] for key in allowed if key in payload}
    )

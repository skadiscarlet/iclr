"""Contracts for model-generated enrichment and its audit trail."""

import json
import hashlib
import math
from typing import Any, Literal, Annotated

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints, ValidationInfo, field_validator, model_validator

NonEmpty = Annotated[str, StringConstraints(min_length=1)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]


def enrichment_record_commitment(value: dict[str, Any]) -> str:
    """Commit every canonical record field except the commitment itself."""

    canonical = dict(value)
    canonical.pop("record_commitment_sha256", None)
    raw = json.dumps(
        canonical,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def committed_enrichment_record(**value: Any) -> "EnrichmentRecord":
    """Build a record with a canonical self-commitment."""

    data = dict(value)
    data["record_commitment_sha256"] = "sha256:" + "0" * 64
    normalized = EnrichmentRecord.model_validate(
        data, context={"skip_record_commitment": True}
    ).model_dump(mode="json")
    normalized["record_commitment_sha256"] = enrichment_record_commitment(normalized)
    return EnrichmentRecord.model_validate(normalized)


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_default=True)


class EnrichedLocation(_Contract):
    path: NonEmpty
    symbol: str | None = None
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    role: Literal["entry", "source", "propagation", "guard", "sink", "resource", "identity", "impact"]

    @model_validator(mode="after")
    def valid_line_range(self) -> "EnrichedLocation":
        if self.start_line is not None and self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class AuthorizationSemantics(_Contract):
    attacker_principal: str = "unknown"
    victim_principal: str = "unknown"
    action: str = "unknown"
    resource: str = "unknown"
    expected_relation: str = "unknown"
    actual_check: str = "unknown"
    observable_impact: str = "unknown"


class ProofObligation(_Contract):
    obligation_id: NonEmpty
    kind: NonEmpty
    description: NonEmpty
    status: Literal["unknown"] = "unknown"


class TraceStep(_Contract):
    step_id: NonEmpty
    goal: NonEmpty
    operation: NonEmpty
    target_kind: NonEmpty
    target_id: NonEmpty
    expected_evidence_type: NonEmpty
    tool_class: NonEmpty
    target_location: str | None = None
    resolves_unknowns: list[str] = Field(default_factory=list)
    reason_tags: list[str] = Field(default_factory=list)


class EnrichmentPayload(_Contract):
    family: Literal["source_to_sink", "authorization"]
    hypothesis: str = Field(min_length=1)
    locations: list[EnrichedLocation] = Field(min_length=1)
    obligations: list[ProofObligation] = Field(min_length=1)
    trace: list[TraceStep] = Field(min_length=1)
    authorization: AuthorizationSemantics | None = None
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_family_semantics(self) -> "EnrichmentPayload":
        if len({o.obligation_id for o in self.obligations}) != len(self.obligations):
            raise ValueError("obligation_id values must be unique")
        if len({t.step_id for t in self.trace}) != len(self.trace):
            raise ValueError("trace step_id values must be unique")
        for location in self.locations:
            if location.start_line is not None and location.end_line is not None and location.end_line < location.start_line:
                raise ValueError("end_line must be greater than or equal to start_line")
        if self.family == "authorization" and self.authorization is None:
            raise ValueError("authorization family requires authorization semantics")
        if self.family == "source_to_sink" and self.authorization is not None:
            raise ValueError("source_to_sink family forbids authorization semantics")
        return self


class EnrichmentValidation(_Contract):
    valid: bool
    family_mismatch: bool = False
    invalid_locations: list[str] = Field(default_factory=list)
    invalid_trace_locations: list[str] = Field(default_factory=list)
    invalid_goals: list[str] = Field(default_factory=list)
    invalid_operations: list[str] = Field(default_factory=list)
    invalid_target_kinds: list[str] = Field(default_factory=list)
    invalid_tool_classes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent_validity(self) -> "EnrichmentValidation":
        diagnostics = (self.family_mismatch, self.invalid_locations, self.invalid_trace_locations,
                       self.invalid_goals, self.invalid_operations, self.invalid_target_kinds,
                       self.invalid_tool_classes)
        expected = not any(diagnostics)
        if self.valid != expected:
            raise ValueError("valid must match validation diagnostics")
        return self


class EnrichmentRecord(_Contract):
    schema_version: Literal["1.0"] = "1.0"
    case_id: NonEmpty
    generation_mode: Literal["fixture", "live"]
    provider: NonEmpty
    model: NonEmpty
    requested_model: NonEmpty
    provider_response_model: NonEmpty
    teacher_response_commitment_sha256: Sha256
    provider_request_id: NonEmpty | None = None
    prompt_sha256: Sha256
    source_context_sha256: Sha256
    temperature: float = 0.0
    max_tokens: int = Field(default=8192, gt=0)
    latency_ms: int = Field(default=0, ge=0)
    usage: dict[str, int] = Field(default_factory=dict)
    structured_output_valid: bool = True
    payload: EnrichmentPayload
    validation: EnrichmentValidation
    record_commitment_sha256: Sha256

    @field_validator("temperature")
    @classmethod
    def finite_temperature(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("temperature must be finite")
        return value

    @field_validator("usage")
    @classmethod
    def valid_usage(cls, value: dict[str, int]) -> dict[str, int]:
        if any(v < 0 for v in value.values()):
            raise ValueError("usage values must be non-negative")
        json.dumps(value, allow_nan=False, sort_keys=True)
        return value

    @model_validator(mode="after")
    def valid_record_commitment(self, info: ValidationInfo) -> "EnrichmentRecord":
        if self.model != self.requested_model:
            raise ValueError("model must equal requested_model")
        if info.context and info.context.get("skip_record_commitment") is True:
            return self
        expected = enrichment_record_commitment(self.model_dump(mode="json"))
        if self.record_commitment_sha256 != expected:
            raise ValueError("record commitment does not match canonical enrichment")
        return self

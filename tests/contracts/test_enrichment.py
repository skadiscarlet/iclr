import pytest
import math
from pydantic import ValidationError

from egsi.contracts.enrichment import (
    AuthorizationSemantics,
    EnrichedLocation,
    EnrichmentPayload,
    EnrichmentRecord,
    EnrichmentValidation,
    ProofObligation,
    TraceStep,
    committed_enrichment_record,
)


def _location():
    return {"path": "src/a.py", "role": "entry"}


def _obligation():
    return {"obligation_id": "o1", "kind": "source", "description": "check"}


def _trace():
    return {
        "step_id": "t1",
        "goal": "locate",
        "operation": "inspect",
        "target_kind": "file",
        "target_id": "src/a.py",
        "expected_evidence_type": "source",
        "tool_class": "static",
    }


def test_payload_rejects_unknown_facts_field():
    with pytest.raises(ValidationError, match="extra"):
        EnrichmentPayload(
            family="source_to_sink",
            hypothesis="h",
            locations=[_location()],
            obligations=[_obligation()],
            trace=[_trace()],
            facts=[],
        )


def test_authorization_payload_requires_semantics():
    with pytest.raises(ValidationError):
        EnrichmentPayload(
            family="authorization",
            hypothesis="h",
            locations=[_location()],
            obligations=[_obligation()],
            trace=[_trace()],
        )

    payload = EnrichmentPayload(
        family="authorization",
        hypothesis="h",
        locations=[_location()],
        obligations=[_obligation()],
        trace=[_trace()],
        authorization=AuthorizationSemantics(),
    )
    assert payload.authorization is not None


def test_source_to_sink_rejects_authorization_semantics():
    with pytest.raises(ValidationError):
        EnrichmentPayload(
            family="source_to_sink",
            hypothesis="h",
            locations=[_location()],
            obligations=[_obligation()],
            trace=[_trace()],
            authorization=AuthorizationSemantics(),
        )


def test_enrichment_minimal_models_and_record():
    assert EnrichedLocation(path="x", role="sink").path == "x"
    assert ProofObligation(obligation_id="o", kind="k", description="d").status == "unknown"
    assert TraceStep(
        step_id="s", goal="g", operation="o", target_kind="k", target_id="i",
        expected_evidence_type="e", tool_class="t"
    ).resolves_unknowns == []
    record = committed_enrichment_record(
        case_id="c", generation_mode="live", provider="p", model="m", requested_model="m", provider_response_model="actual-m", teacher_response_commitment_sha256="sha256:"+"c"*64, prompt_sha256="sha256:"+"a"*64, source_context_sha256="sha256:"+"b"*64,
        payload=EnrichmentPayload(
            family="source_to_sink", hypothesis="h", locations=[_location()],
            obligations=[_obligation()], trace=[_trace()]
        ), validation=EnrichmentValidation(valid=True)
    )
    assert record.schema_version == "1.0"
    assert record.model == record.requested_model == "m"
    assert record.provider_response_model == "actual-m"

    with pytest.raises(ValidationError):
        committed_enrichment_record(
            **{
                **record.model_dump(mode="json"),
                "requested_model": "different-request",
            }
        )
    tampered = record.model_dump(mode="json")
    tampered["provider_response_model"] = "forged-actual"
    with pytest.raises(ValidationError, match="record commitment"):
        EnrichmentRecord.model_validate(tampered)


def test_enrichment_rejects_string_number_and_boolean_coercion():
    with pytest.raises(ValidationError):
        EnrichedLocation(path="x", role="sink", start_line="1")
    with pytest.raises(ValidationError):
        EnrichmentValidation(valid="true")


def test_enrichment_constraints_and_roundtrip():
    with pytest.raises(ValidationError):
        EnrichedLocation(path="x", role="sink", start_line=2, end_line=1)
    with pytest.raises(ValidationError):
        EnrichmentPayload(family="source_to_sink", hypothesis="h", locations=[_location()],
                          obligations=[_obligation(), _obligation()], trace=[_trace()])
    with pytest.raises(ValidationError):
        EnrichmentPayload(family="source_to_sink", hypothesis="h", locations=[_location()],
                          obligations=[_obligation()], trace=[_trace(), _trace()])
    base = dict(generation_mode="live", provider="p", model="m", requested_model="m", provider_response_model="actual-m", teacher_response_commitment_sha256="sha256:"+"c"*64, prompt_sha256="sha256:"+"a"*64,
                source_context_sha256="sha256:"+"b"*64, payload={"family":"source_to_sink", "hypothesis":"h", "locations":[_location()], "obligations":[_obligation()], "trace":[_trace()]}, validation={"valid":True})
    for field, value in (("case_id", ""), ("prompt_sha256", "bad"), ("source_context_sha256", "bad")):
        with pytest.raises(ValidationError) as exc_info:
            committed_enrichment_record(**{"case_id": "c", **base, field: value})
        assert exc_info.value.errors()[0]["loc"] == (field,)
    payload = EnrichmentPayload(family="source_to_sink", hypothesis="h", locations=[_location()], obligations=[_obligation()], trace=[_trace()])
    assert EnrichmentPayload.model_validate_json(payload.model_dump_json()) == payload


def test_enrichment_json_values_and_validation_consistency():
    with pytest.raises(ValidationError):
        EnrichmentValidation(valid=True, invalid_goals=["x"])
    with pytest.raises(ValidationError):
        committed_enrichment_record(case_id="c", generation_mode="live", provider="p", model="m", requested_model="m", provider_response_model="actual-m", teacher_response_commitment_sha256="sha256:"+"c"*64, prompt_sha256="sha256:"+"a"*64,
            source_context_sha256="sha256:"+"b"*64, temperature=math.inf,
            payload={"family":"source_to_sink", "hypothesis":"h", "locations":[_location()], "obligations":[_obligation()], "trace":[_trace()]}, validation={"valid":True})


def test_record_can_represent_structured_output_failure_and_diagnostics():
    base = dict(case_id="c", generation_mode="live", provider="p", model="m", requested_model="m", provider_response_model="actual-m", teacher_response_commitment_sha256="sha256:"+"c"*64, prompt_sha256="sha256:"+"a"*64,
                source_context_sha256="sha256:"+"b"*64,
                payload={"family":"source_to_sink", "hypothesis":"h", "locations":[_location()], "obligations":[_obligation()], "trace":[_trace()]})
    record = committed_enrichment_record(
        **base,
        structured_output_valid=False,
        validation={"valid": False, "invalid_goals": ["t1"]},
    )
    assert record.structured_output_valid is False
    assert record.validation.valid is False

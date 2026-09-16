from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from sbs.errors import SchemaAnswerFieldError
from sbs.schema import (
    ANSWER_FIELD_NAMES,
    AuditState,
    CaseView,
    Decision,
    Hypothesis,
    parse_case_view,
    reject_answer_fields,
)


MINIMAL_CASE = {
    "case_id": "fixture-support",
    "visible_context": "ctx",
    "allowed_evidence_ids": ["ev-1"],
    "split": "dev_pilot",
    "material_kind": "fixture",
}


def test_caseview_rejects_cve_gold_patch_and_fix_pairing() -> None:
    for field in ("cve", "gold_label", "patch", "fix_pairing"):
        payload = dict(MINIMAL_CASE)
        payload[field] = "forbidden"
        with pytest.raises((SchemaAnswerFieldError, ValidationError)):
            parse_case_view(payload)
        with pytest.raises(SchemaAnswerFieldError):
            reject_answer_fields(payload)
    assert "cve" in ANSWER_FIELD_NAMES


def test_caseview_rejects_nested_answer_fields() -> None:
    payload = dict(MINIMAL_CASE)
    payload["visible_context"] = "ok"
    nested = dict(MINIMAL_CASE)
    # extra forbid plus nested walk
    with pytest.raises((SchemaAnswerFieldError, ValidationError)):
        parse_case_view({**MINIMAL_CASE, "gold": "label"})


def test_caseview_rejects_ghsa_or_cve_case_id() -> None:
    for bad in ("CVE-2020-1234", "ghsa-24rp-q3w6-vc56"):
        payload = dict(MINIMAL_CASE)
        payload["case_id"] = bad
        with pytest.raises(ValidationError):
            CaseView.model_validate(payload)


def test_json_roundtrip_preserves_null_and_unknown() -> None:
    state = AuditState(
        observed_evidence=[],
        hypotheses=[
            Hypothesis(
                hypothesis_id="h1",
                entities=["A"],
                security_relation="A related to B",
                relation_source="fixture_script",
                support_refs=[],
                counter_refs=[],
                unknowns=["unknown"],
                status="open",
            )
        ],
        unresolved_items=["unknown"],
        remaining_budget=4,
        inspection_history=["INIT"],
        terminal=None,
        termination_reason=None,
        decision=None,
    )
    raw = state.model_dump_json()
    payload = json.loads(raw)
    assert payload["terminal"] is None
    assert payload["termination_reason"] is None
    assert payload["decision"] is None
    assert payload["hypotheses"][0]["unknowns"] == ["unknown"]
    restored = AuditState.model_validate_json(raw)
    assert restored.terminal is None
    assert restored.termination_reason is None
    assert restored.hypotheses[0].unknowns == ["unknown"]
    assert restored.hypotheses[0].status != "unresolved" or restored.terminal is None


def test_decision_is_hypothesis_scoped() -> None:
    decision = Decision(
        verdict="unresolved",
        applies_to_hypothesis_id="h1",
        not_a_global_safety_guarantee=True,
    )
    dumped = json.loads(decision.model_dump_json())
    assert dumped["not_a_global_safety_guarantee"] is True
    assert dumped["applies_to_hypothesis_id"] == "h1"

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbs.errors import ValueScorerUnavailable
from sbs.replay import load_smoke_config, replay_case, replay_fixtures, semantic_outputs
from sbs.scorer import ValueScorer
from sbs.views import views_share_evidence


REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def smoke():
    return load_smoke_config(REPO / "configs" / "r01_smoke.json")


def test_smoke_config_matches_r01_contract(smoke) -> None:
    assert smoke.mode == "fixture_replay"
    assert smoke.seed == 17
    assert smoke.representations == ["history", "sbs"]
    assert smoke.evidence_order == "frozen"
    assert smoke.max_observations == 4
    assert smoke.split == "dev_pilot"
    assert smoke.model_calls_allowed == 0
    assert smoke.compute_detection_metrics is False
    assert smoke.value_scorer_available is False


def test_support_finishes_supported(smoke) -> None:
    result = replay_case(REPO / "fixtures" / "r01" / "support", smoke)
    assert result["state"].terminal == "FINISH"
    assert result["state"].decision.verdict == "supported"
    assert result["state"].termination_reason == "support_sufficient"


def test_counter_evidence_revises_state(smoke) -> None:
    result = replay_case(REPO / "fixtures" / "r01" / "counter", smoke)
    hypothesis = result["state"].hypotheses[0]
    assert "ev-unchecked" in hypothesis.support_refs
    assert "ev-checked" in hypothesis.counter_refs
    assert hypothesis.status == "refuted"
    assert result["state"].terminal == "FINISH"
    assert result["state"].decision.verdict == "refuted"


def test_insufficient_material_unresolved(smoke) -> None:
    result = replay_case(REPO / "fixtures" / "r01" / "insufficient", smoke)
    assert result["state"].terminal == "UNRESOLVED"
    assert result["state"].termination_reason == "insufficient_material"
    assert result["state"].decision.verdict == "unresolved"


def test_budget_exhaustion_unresolved_not_refuted_or_safe(smoke) -> None:
    result = replay_case(REPO / "fixtures" / "r01" / "budget", smoke)
    state = result["state"]
    assert state.terminal == "UNRESOLVED"
    assert state.termination_reason == "budget_exhausted"
    assert state.decision.verdict == "unresolved"
    assert state.hypotheses[0].status == "unresolved"
    assert "ev-step-5" not in state.observed_evidence
    assert len(state.observed_evidence) == 4
    assert state.decision.verdict not in {"refuted", "supported"}


def test_history_and_sbs_share_evidence_set_and_order(smoke) -> None:
    for name in ("support", "counter", "insufficient", "budget"):
        result = replay_case(REPO / "fixtures" / "r01" / name, smoke)
        assert views_share_evidence(result["history"], result["sbs"])
        assert result["history"].allowed_evidence_ids == result["sbs"].allowed_evidence_ids
        assert result["history"].observation_order == result["sbs"].observation_order


def test_replay_semantic_outputs_stable_across_runs(smoke, tmp_path: Path) -> None:
    fixtures = REPO / "fixtures" / "r01"
    first = replay_fixtures(smoke, fixtures, tmp_path / "a")
    second = replay_fixtures(smoke, fixtures, tmp_path / "b")
    assert first.model_calls == 0
    assert second.model_calls == 0
    assert first.detection_metrics is None
    assert first.detection_metrics_status == "not_evaluated"
    assert first.training_loss is None
    assert first.q_accuracy is None
    for name in ("support", "counter", "insufficient", "budget"):
        r1 = replay_case(fixtures / name, smoke)
        r2 = replay_case(fixtures / name, smoke)
        assert semantic_outputs(r1) == semantic_outputs(r2)
        assert r1["state"].terminal in {"FINISH", "UNRESOLVED"}


def test_value_scorer_unavailable() -> None:
    assert ValueScorer.available is False
    with pytest.raises(ValueScorerUnavailable):
        ValueScorer()

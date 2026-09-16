import pytest
from pydantic import ValidationError

from egsi.contracts.trajectory import EpisodeEvent, RewardVector, T1Transition


def test_reward_vector_is_zero_only():
    with pytest.raises(ValidationError):
        RewardVector(label_scope="patch_grounded_bc", terminal=1.0)
    assert RewardVector(label_scope="patch_grounded_bc").terminal == 0


def _transition(**overrides):
    data = dict(
        episode_id="e", state_version=0, state={},
        candidate_actions=[{"action_id": "a"}], legal_mask=[True],
        selected_action={"action_id": "a"}, observation={}, evidence_delta={},
        verifier_decision={"accepted": True, "checks": {"schema": True, "location": True, "action_dsl": True, "redaction": True}}, reward_vector={"label_scope": "patch_grounded_bc"},
        next_state_version=1, done=False,
    )
    data["state"] = {"schema_version": "1.0", "case_id": "case", "state": "SELECT_ACTION", "repository": {"upstream_id": "repo", "vulnerable_commit": "a" * 40}, "budget": {"seconds": 900, "tool_calls": 20, "tokens": 16000, "analysis_units": 20.0}, "bounded_history": [], "unknowns": ["entrypoint", "security_invariant", "guard", "impact"], "state_version": 0}
    data["observation"] = {"type": "oracle_label_only", "label_scope": "patch_grounded_bc", "receipt": None}
    data["evidence_delta"] = {"facts": [], "claims": [], "resolved_unknowns": []}
    data.update(overrides)
    return T1Transition(**data)


def test_transition_invariants():
    assert _transition().next_state_version == 1
    with pytest.raises(ValidationError):
        _transition(next_state_version=2)
    with pytest.raises(ValidationError):
        _transition(legal_mask=[])
    with pytest.raises(ValidationError):
        _transition(selected_action={"id": "missing"})
    with pytest.raises(ValidationError):
        _transition(legal_mask=[False])
    state = _transition().state
    state["state_version"] = 65
    state["bounded_history"] = [{"state_version": index, "action_id": "A-" + "a" * 24} for index in range(65)]
    with pytest.raises(ValidationError):
        _transition(state_version=65, next_state_version=66, state=state)


def test_trajectory_rejects_string_number_coercion():
    with pytest.raises(ValidationError):
        RewardVector(label_scope="patch_grounded_bc", terminal="0")
    with pytest.raises(ValidationError):
        T1Transition(
            episode_id="e", state_version="0", state={}, candidate_actions=[{"action_id":"a"}],
            legal_mask=[True], selected_action={"action_id":"a"}, observation={}, evidence_delta={},
            verifier_decision={"accepted": False},
            reward_vector={"label_scope": "patch_grounded_bc"},
            next_state_version=1, done=False,
        )


def test_transition_action_and_json_constraints():
    with pytest.raises(ValidationError):
        _transition(candidate_actions=[{"action_id": "a"}] * 65, legal_mask=[True] * 65)
    with pytest.raises(ValidationError):
        _transition(candidate_actions=[{"action_id": "a"}, {"action_id": "a"}], legal_mask=[True, True])
    with pytest.raises(ValidationError):
        _transition(selected_action={"action_id": "x"})
    with pytest.raises(ValidationError):
        _transition(state={"bad": object()})
    with pytest.raises(ValidationError):
        _transition(observation={"bad": float("nan")})


def test_transition_accepts_plain_json_action_dicts():
    action = {"id": "a"}
    transition = _transition(candidate_actions=[action], selected_action=action)
    assert transition.selected_action == action


def test_canonical_fingerprint_nested_key_order_is_duplicate():
    first = {"meta": {"a": 1, "b": 2}}
    second = {"meta": {"b": 2, "a": 1}}
    with pytest.raises(ValidationError):
        _transition(candidate_actions=[first, second], legal_mask=[True, True], selected_action=first)


def test_canonical_fingerprint_allows_selected_key_order_difference():
    candidate = {"meta": {"a": 1, "b": 2}}
    selected = {"meta": {"b": 2, "a": 1}}
    assert _transition(candidate_actions=[candidate], selected_action=selected).done is False


def test_canonical_fingerprint_uses_selected_candidate_mask():
    first, second = {"id": "a"}, {"id": "b"}
    assert _transition(candidate_actions=[first, second], legal_mask=[False, True], selected_action=second)
    with pytest.raises(ValidationError):
        _transition(candidate_actions=[first, second], legal_mask=[True, False], selected_action=second)


def test_episode_event_invariants_and_roundtrip():
    event = EpisodeEvent(sequence=0, episode_id="e", event_type="EPISODE_STARTED", payload={}, event_sha256="sha256:"+"a"*64)
    assert EpisodeEvent.model_validate_json(event.model_dump_json()) == event
    with pytest.raises(ValidationError):
        EpisodeEvent(sequence=0, episode_id="e", event_type="EPISODE_STARTED", payload={}, previous_event_sha256="sha256:"+"b"*64, event_sha256="sha256:"+"a"*64)
    with pytest.raises(ValidationError):
        EpisodeEvent(sequence=1, episode_id="e", event_type="EPISODE_STARTED", payload={}, event_sha256="sha256:"+"a"*64)
    for kwargs, field in (({"episode_id": ""}, "episode_id"),
                          ({"payload": {"x": object()}}, "payload"),
                          ({"event_sha256": "bad"}, "event_sha256")):
        with pytest.raises(ValidationError) as exc_info:
            EpisodeEvent(**{"sequence": 0, "episode_id": "e", "event_type": "EPISODE_STARTED", "payload": {}, "event_sha256": "sha256:"+"a"*64, **kwargs})
        assert exc_info.value.errors()[0]["loc"][0] == field


def test_verifier_checks_reject_non_json_values():
    with pytest.raises(ValidationError):
        from egsi.contracts.trajectory import VerifierDecision
        VerifierDecision(accepted=True, checks={"x": object()})
    with pytest.raises(ValidationError):
        from egsi.contracts.trajectory import VerifierDecision
        VerifierDecision(accepted=True, checks={"x": float("nan")})

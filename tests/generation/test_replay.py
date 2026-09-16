"""Strict replay validates the event protocol as well as the hash chain."""

from __future__ import annotations

import copy

import pytest

from .test_trajectory_compile import case, record


def _episode():
    from egsi.generation.trajectory import compile_t1_episode
    return compile_t1_episode(case(), record())


def _trusted(events, transitions):
    from egsi.generation.trajectory import episode_commitment
    return episode_commitment(transitions, events)


def test_replay_returns_closed_episode_selected_actions_and_steps() -> None:
    from egsi.generation.replay import replay_events

    transitions, events = _episode()
    result = replay_events(events, transitions, expected_commitment_sha256=_trusted(events, transitions))
    assert result["closed"] is True
    assert result["episode_id"] == events[0].episode_id
    assert result["steps"] == 1
    assert result["selected_actions"] == [events[3].payload["action_id"]]


def test_replay_requires_immutable_cross_file_commitment() -> None:
    from egsi.generation.replay import replay_events
    from egsi.generation.trajectory import episode_commitment, make_event

    transitions, events = _episode()
    commitment = episode_commitment(transitions, events)
    with pytest.raises(ValueError):
        replay_events(events)
    # A full rechain can make the event protocol look valid, but it cannot
    # silently replace the external trusted commitment.
    changed = copy.deepcopy(events)
    changed_transitions = copy.deepcopy(transitions)
    replacement = next(action for action, legal in zip(changed_transitions[0].candidate_actions, changed_transitions[0].legal_mask, strict=True) if legal and action != changed_transitions[0].selected_action)
    changed_transitions[0].selected_action = copy.deepcopy(replacement)
    changed[3] = make_event(3, changed[0].episode_id, "ACTION_SELECTED", {"action_id": replacement["action_id"]}, changed[2].event_sha256)
    changed[4] = make_event(4, changed[0].episode_id, "PATCH_GROUNDED_LABEL_RECORDED", {"state_version": 0, "action_id": replacement["action_id"], "label_scope": "patch_grounded_bc"}, changed[3].event_sha256)
    previous = None
    for index, event in enumerate(changed):
        changed[index] = make_event(index, event.episode_id, event.event_type, event.payload, previous)
        previous = changed[index].event_sha256
    with pytest.raises(ValueError, match="commitment"):
        replay_events(changed, changed_transitions, expected_commitment_sha256=commitment)


@pytest.mark.parametrize("mutation", ["selected_only", "reporter_rehashed"])
def test_writer_and_replay_reject_noncanonical_compiled_candidate_sets(tmp_path, mutation: str) -> None:
    """Trusted artifacts cannot substitute a hand-shaped candidate set."""
    import hashlib
    import json
    from egsi.generation.replay import replay_events
    from egsi.generation.trajectory import episode_commitment, make_event, write_jsonl

    transitions, events = _episode()
    transition = copy.deepcopy(transitions[0])
    if mutation == "selected_only":
        transition.candidate_actions = [copy.deepcopy(transition.selected_action)]
        transition.legal_mask = [True]
    else:
        for action in transition.candidate_actions:
            action["actor_role"] = "reporter"
            base = {key: value for key, value in action.items() if key not in {"action_id", "idempotency_key"}}
            digest = hashlib.sha256(json.dumps(base, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
            action["action_id"] = "A-" + digest[:24]
            action["idempotency_key"] = "sha256:" + digest
        transition.selected_action = next(action for action in transition.candidate_actions if action["operation"] == "find_guard")
    bad = [transition]
    with pytest.raises(ValueError):
        write_jsonl(tmp_path / f"{mutation}.jsonl", bad)

    changed = copy.deepcopy(events)
    changed[2] = make_event(2, changed[0].episode_id, "ACTION_PROPOSED", {"actions": transition.candidate_actions, "legal_mask": transition.legal_mask}, changed[1].event_sha256)
    changed[3] = make_event(3, changed[0].episode_id, "ACTION_SELECTED", {"action_id": transition.selected_action["action_id"]}, changed[2].event_sha256)
    changed[4] = make_event(4, changed[0].episode_id, "PATCH_GROUNDED_LABEL_RECORDED", {"state_version": 0, "action_id": transition.selected_action["action_id"], "label_scope": "patch_grounded_bc"}, changed[3].event_sha256)
    previous = changed[4].event_sha256
    changed[5] = make_event(5, changed[0].episode_id, "EPISODE_CLOSED", changed[5].payload, previous)
    # The matching commitment cannot be minted: full contract normalization
    # rejects the external candidate set before it can become trusted.
    with pytest.raises(ValueError, match="record does not round-trip"):
        episode_commitment(bad, changed)
    with pytest.raises(ValueError, match="invalid trusted transition commitment"):
        replay_events(changed, bad, expected_commitment_sha256="sha256:" + "0" * 64)


@pytest.mark.parametrize("tamper", [
    lambda events: setattr(events[1], "previous_event_sha256", "sha256:" + "0" * 64),
    lambda events: events[2].payload["actions"].__setitem__(0, {"not": "an action"}),
    lambda events: events[3].payload.__setitem__("action_id", "A-not-proposed"),
    lambda events: events[4].payload.__setitem__("state_version", 5),
    lambda events: events.append(copy.deepcopy(events[-1])),
    lambda events: events.pop(),
])
def test_replay_refuses_tampering_and_protocol_breaks(tamper) -> None:
    from egsi.generation.replay import replay_events

    transitions, events = _episode(); events = copy.deepcopy(events)
    tamper(events)
    with pytest.raises(ValueError):
        replay_events(events, transitions, expected_commitment_sha256=_trusted(_episode()[1], transitions))


def test_replay_refuses_mixed_episode_illegal_mask_and_duplicate_selection() -> None:
    from egsi.generation.replay import replay_events
    from egsi.generation.trajectory import make_event

    transitions, events = _episode(); events = copy.deepcopy(events)
    events[2].episode_id = "other"
    with pytest.raises(ValueError):
        replay_events(events, transitions, expected_commitment_sha256=_trusted(_episode()[1], transitions))


def test_replay_refuses_extended_seed_and_wrong_candidate_label_scope() -> None:
    from egsi.generation.replay import replay_events
    from egsi.generation.trajectory import make_event
    from egsi.generation.redaction import sha

    def rechain(items):
        previous = None
        for sequence, item in enumerate(items):
            items[sequence] = make_event(sequence, item.episode_id, item.event_type, item.payload, previous)
            previous = items[sequence].event_sha256

    transitions, events = _episode()
    start = copy.deepcopy(events[0].payload)
    start["policy_seed"]["hypothesis"] = "smuggled label"
    start["redaction"]["policy_sha256"] = sha(start["policy_seed"])
    events[0] = make_event(0, events[0].episode_id, "EPISODE_STARTED", start, None)
    rechain(events)
    with pytest.raises(ValueError):
        replay_events(events, transitions, expected_commitment_sha256=_trusted(_episode()[1], transitions))

    transitions, events = _episode()
    proposed = copy.deepcopy(events[2].payload)
    proposed["actions"][0]["metadata"]["label_scope"] = "other"
    events[2] = make_event(2, events[0].episode_id, "ACTION_PROPOSED", proposed, events[1].event_sha256)
    rechain(events)
    with pytest.raises(ValueError):
        replay_events(events, transitions, expected_commitment_sha256=_trusted(_episode()[1], transitions))
    transitions, events = _episode()
    actions = events[2].payload["actions"]
    selected = events[3].payload["action_id"]
    index = next(i for i, action in enumerate(actions) if action["action_id"] == selected)
    events[2] = make_event(2, events[0].episode_id, "ACTION_PROPOSED", {"actions": actions, "legal_mask": [i != index for i in range(len(actions))]}, events[1].event_sha256)
    with pytest.raises(ValueError):
        replay_events(events, transitions, expected_commitment_sha256=_trusted(_episode()[1], transitions))
    transitions, events = _episode()
    repeated = make_event(len(events) - 1, events[0].episode_id, "EPISODE_CLOSED", events[-1].payload, events[-2].event_sha256)
    events.insert(-1, repeated)
    with pytest.raises(ValueError):
        replay_events(events, transitions, expected_commitment_sha256=_trusted(_episode()[1], transitions))

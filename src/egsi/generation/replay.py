"""Strict replay validation for T1 event streams."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from egsi.contracts.trajectory import EpisodeEvent

from .candidates import _load_validator, validate_action_identity
from .redaction import _manifest_has_exact_shape, _seed_is_exact, key_hits, sha
from .trajectory import _MAX_EVENT_JSON_BYTES, _canonical_json_bytes, _validate_compiled_transition, episode_commitment, event_hash


_MAX_EVENTS = 256
_LABEL_SCOPE = "patch_grounded_bc"


def _fail(message: str) -> None:
    raise ValueError(message)


def _exact(payload: object, expected: dict[str, Any], message: str) -> None:
    if payload != expected:
        _fail(message)


def _validate_started(payload: object) -> None:
    if type(payload) is not dict or set(payload) != {"policy_seed", "redaction"}:
        _fail("invalid episode start payload")
    seed, manifest = payload["policy_seed"], payload["redaction"]
    if (not _seed_is_exact(seed) or not _manifest_has_exact_shape(manifest)
            or key_hits(seed) or key_hits(manifest)):
        _fail("invalid redaction boundary")
    if manifest.get("policy_sha256") != sha(seed) or manifest.get("forbidden_key_hits") != []:
        _fail("invalid redaction manifest")


def _validate_actions(payload: object, episode_id: str) -> tuple[list[dict[str, Any]], list[bool]]:
    if type(payload) is not dict or set(payload) != {"actions", "legal_mask"}:
        _fail("invalid proposed action payload")
    actions, legal_mask = payload["actions"], payload["legal_mask"]
    if type(actions) is not list or not 1 <= len(actions) <= 64 or type(legal_mask) is not list or len(actions) != len(legal_mask):
        _fail("invalid proposed action collection")
    if any(type(item) is not dict for item in actions) or any(type(item) is not bool for item in legal_mask):
        _fail("invalid proposed action collection")
    validator = _load_validator()
    identifiers: set[str] = set()
    for action, legal in zip(actions, legal_mask, strict=True):
        try:
            _canonical_json_bytes(action, limit=_MAX_EVENT_JSON_BYTES)
        except ValueError:
            _fail("invalid proposed action JSON")
        if action.get("episode_id") != episode_id or type(action.get("action_id")) is not str:
            _fail("invalid proposed action identity")
        metadata = action.get("metadata")
        if type(metadata) is not dict or metadata.get("label_scope") != _LABEL_SCOPE:
            _fail("invalid proposed action label scope")
        action_id = action["action_id"]
        if action_id in identifiers:
            _fail("duplicate proposed action identifier")
        identifiers.add(action_id)
        actual_legal = not any(validator.iter_errors(action))
        if legal is not actual_legal:
            _fail("illegal proposed action mask")
        try:
            validate_action_identity(action)
        except ValueError:
            _fail("invalid proposed action integrity")
    if sum(legal_mask) < 4:
        _fail("too few legal proposed actions")
    return deepcopy(actions), list(legal_mask)


def replay_events(
    events: list[EpisodeEvent], transitions: list[Any] | None = None,
    *, expected_commitment_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate content hashes and the complete T1 event state machine."""

    if type(events) is not list or not 1 <= len(events) <= _MAX_EVENTS:
        _fail("events must be a bounded non-empty EpisodeEvent list")
    if any(type(event) is not EpisodeEvent for event in events):
        _fail("events must be EpisodeEvent instances")
    if transitions is None or expected_commitment_sha256 is None:
        _fail("trusted transitions and expected commitment are required")
    try:
        actual_commitment = episode_commitment(transitions, events)
    except ValueError:
        _fail("invalid trusted transition commitment")
    if expected_commitment_sha256 != actual_commitment:
        _fail("episode commitment mismatch")
    try:
        for transition in transitions:
            _validate_compiled_transition(transition)
    except ValueError as exc:
        _fail(str(exc))

    phase = "START"
    episode_id: str | None = None
    previous: str | None = None
    proposed: tuple[list[dict[str, Any]], list[bool]] | None = None
    selected_actions: list[str] = []
    state_version = 0
    closed = False

    for expected_sequence, event in enumerate(events):
        if event.sequence != expected_sequence:
            _fail("non-consecutive event sequence")
        if episode_id is None:
            episode_id = event.episode_id
        if event.episode_id != episode_id:
            _fail("mixed episode events")
        if event.previous_event_sha256 != previous:
            _fail("broken event hash chain")
        try:
            wanted_hash = event_hash(event.sequence, event.episode_id, event.event_type, event.payload, previous)
        except ValueError:
            _fail("invalid event content")
        if event.event_sha256 != wanted_hash:
            _fail("invalid event content hash")
        if closed:
            _fail("event follows closed episode")

        if phase == "START":
            if event.event_type != "EPISODE_STARTED":
                _fail("episode must start with EPISODE_STARTED")
            _validate_started(event.payload)
            phase = "HYPOTHESIS"
        elif phase == "HYPOTHESIS":
            if event.event_type != "HYPOTHESIS_CREATED":
                _fail("episode must create one hypothesis")
            _exact(event.payload, {"hypothesis_id": "H-1", "label_scope": _LABEL_SCOPE}, "invalid hypothesis payload")
            phase = "PROPOSED"
        elif phase == "PROPOSED":
            if event.event_type != "ACTION_PROPOSED":
                _fail("action proposal expected")
            proposed = _validate_actions(event.payload, episode_id)
            transition = transitions[state_version] if state_version < len(transitions) else None
            if transition is None or event.payload["actions"] != transition.candidate_actions or event.payload["legal_mask"] != transition.legal_mask:
                _fail("proposed actions do not match trusted transition")
            phase = "SELECTED"
        elif phase == "SELECTED":
            if event.event_type != "ACTION_SELECTED" or type(event.payload) is not dict or set(event.payload) != {"action_id"}:
                _fail("action selection expected")
            action_id = event.payload["action_id"]
            if type(action_id) is not str or proposed is None:
                _fail("invalid selected action")
            actions, mask = proposed
            matches = [index for index, action in enumerate(actions) if action.get("action_id") == action_id]
            if len(matches) != 1 or mask[matches[0]] is not True or action_id in selected_actions:
                _fail("selected action is not a unique legal proposed action")
            selected_actions.append(action_id)
            if action_id != transitions[state_version].selected_action.get("action_id") or transitions[state_version].selected_action not in actions:
                _fail("selected action does not match trusted transition")
            phase = "LABEL"
        elif phase == "LABEL":
            if event.event_type != "PATCH_GROUNDED_LABEL_RECORDED":
                _fail("label record expected")
            _exact(event.payload, {
                "state_version": state_version,
                "action_id": selected_actions[-1],
                "label_scope": _LABEL_SCOPE,
            }, "invalid label record")
            transition = transitions[state_version]
            if transition.state_version != state_version or transition.next_state_version != state_version + 1 or transition.done is not (state_version == len(transitions) - 1):
                _fail("trusted transition version or terminal state mismatch")
            state_version += 1
            proposed = None
            phase = "PROPOSED_OR_CLOSE"
        elif phase == "PROPOSED_OR_CLOSE":
            if event.event_type == "ACTION_PROPOSED":
                proposed = _validate_actions(event.payload, episode_id)
                transition = transitions[state_version] if state_version < len(transitions) else None
                if transition is None or event.payload["actions"] != transition.candidate_actions or event.payload["legal_mask"] != transition.legal_mask:
                    _fail("proposed actions do not match trusted transition")
                phase = "SELECTED"
            elif event.event_type == "EPISODE_CLOSED":
                _exact(event.payload, {"outcome": "LABEL_SEQUENCE_COMPLETE", "dynamic_verdict": "not_applicable"}, "invalid close payload")
                closed = True
                phase = "CLOSED"
            else:
                _fail("action proposal or close expected")
        else:
            _fail("invalid replay state")
        previous = event.event_sha256

    if not closed or phase != "CLOSED" or not selected_actions or state_version != len(transitions):
        _fail("episode is not closed")
    return {
        "closed": True,
        "episode_id": episode_id,
        "selected_actions": selected_actions,
        "steps": state_version,
    }

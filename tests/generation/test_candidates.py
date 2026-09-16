import copy
import hashlib
import json
from importlib import resources
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from egsi.generation import candidates
from egsi.generation.candidates import CanonicalPolicyStep, compile_candidates


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((PROJECT_ROOT / "idea-stage" / "ACTION_DSL.schema.json").read_text(encoding="utf-8"))


def _step(**overrides: object) -> CanonicalPolicyStep:
    values: dict[str, object] = {
        "step_id": "S-0001",
        "goal": "CHECK_GUARD_OR_SANITIZER",
        "operation": "find_guard",
        "target_kind": "path",
        "target_id": "src/A.java",
        "target_location": "src/A.java",
        "resolves_unknowns": ("O-0001",),
        "expected_evidence_type": "source_location",
        "tool_class": "repository_index",
    }
    values.update(overrides)
    if isinstance(values["resolves_unknowns"], list):
        values["resolves_unknowns"] = tuple(values["resolves_unknowns"])
    return CanonicalPolicyStep(**values)  # type: ignore[arg-type]


def _compile(step: CanonicalPolicyStep | None = None, **identities: str):
    return compile_candidates(
        identities.get("case_id", "case-1"),
        identities.get("episode_id", "episode-1"),
        identities.get("branch_id", "branch-1"),
        step or _step(),
    )


def _fingerprint(action: dict) -> str:
    return json.dumps(action, sort_keys=True, separators=(",", ":"), allow_nan=False)


def test_selected_action_is_legal_schema_valid_candidate() -> None:
    actions, mask, selected = _compile()
    validator = Draft202012Validator(SCHEMA)

    assert 1 <= len(actions) <= 64
    assert len(actions) == len(mask)
    assert selected in actions
    assert mask[actions.index(selected)] is True
    assert sum(mask) >= 4
    for action, legal in zip(actions, mask, strict=True):
        assert legal is (not list(validator.iter_errors(action)))
    validator.validate(selected)


def test_control_operations_use_required_targets_and_control_evidence() -> None:
    actions, mask, _ = _compile()
    by_operation = {action["operation"]: action for action, legal in zip(actions, mask, strict=True) if legal}

    assert by_operation["backtrack"]["target"] == {
        "kind": "checkpoint", "id": "initial", "location": None, "version": None
    }
    assert by_operation["terminate"]["target"] == {
        "kind": "episode", "id": "episode-1", "location": None, "version": None
    }
    assert by_operation["backtrack"]["expected_evidence_type"] == "control_decision"
    assert by_operation["terminate"]["expected_evidence_type"] == "control_decision"


def test_selected_invalid_dsl_is_rejected_without_secret_echo() -> None:
    step = _step(operation="not-an-action", target_id="secret-value-should-not-echo")
    with pytest.raises(ValueError) as error:
        _compile(step)
    assert "secret-value-should-not-echo" not in str(error.value)


def test_deterministic_order_unique_ids_and_canonical_fingerprints() -> None:
    first = _compile()
    second = _compile()
    assert first == second
    actions, _, _ = first
    assert len({action["action_id"] for action in actions}) == len(actions)
    assert len({action["idempotency_key"] for action in actions}) == len(actions)
    assert len({_fingerprint(action) for action in actions}) == len(actions)
    assert any(action["operation"] == "find_guard" for action in actions)


def test_outputs_and_selected_are_deeply_independent() -> None:
    actions, _, selected = _compile()
    expected = copy.deepcopy(selected)
    selected_index = actions.index(selected)
    selected["target"]["id"] = "changed-selected"
    assert actions[selected_index] == expected
    actions[selected_index]["metadata"]["case_id"] = "changed-actions"
    assert selected["metadata"]["case_id"] == "case-1"


def test_case_branch_and_step_are_bound_into_emitted_identity() -> None:
    base = _compile()
    changed_case = _compile(case_id="case-2")
    changed_branch = _compile(branch_id="branch-2")
    changed_step = _compile(_step(step_id="S-0002"))

    assert base[2]["metadata"]["case_id"] == "case-1"
    assert base[2]["metadata"]["step_id"] == "S-0001"
    assert base[2]["metadata"]["canonicalizer_version"] == "policy-trace-v1"
    assert base[2]["idempotency_key"] != changed_case[2]["idempotency_key"]
    assert base[2]["idempotency_key"] != changed_branch[2]["idempotency_key"]
    assert base[2]["idempotency_key"] != changed_step[2]["idempotency_key"]


def test_schema_is_loaded_independently_of_current_working_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    actions, mask, selected = _compile()
    assert selected in actions
    assert all(mask)


def test_schema_load_failures_are_safe_when_internal_resource_reader_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidates._load_validator.cache_clear()
    def missing() -> bytes:
        raise FileNotFoundError
    monkeypatch.setattr(candidates, "_read_action_schema_bytes", missing)
    with pytest.raises(ValueError, match="Action DSL schema"):
        _compile()

    candidates._load_validator.cache_clear()
    monkeypatch.setattr(candidates, "_read_action_schema_bytes", lambda: b"{bad")
    with pytest.raises(ValueError, match="Action DSL schema"):
        _compile()
    candidates._load_validator.cache_clear()


def test_schema_resource_is_pinned_byte_identical_and_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    source = (PROJECT_ROOT / "idea-stage" / "ACTION_DSL.schema.json").read_bytes()
    packaged = resources.files("egsi.resources").joinpath("ACTION_DSL.schema.json").read_bytes()
    assert packaged == source
    assert hashlib.sha256(packaged).hexdigest() == candidates.ACTION_DSL_SCHEMA_SHA256

    calls = 0
    original = candidates._read_action_schema_bytes
    def counted() -> bytes:
        nonlocal calls
        calls += 1
        return original()
    candidates._load_validator.cache_clear()
    monkeypatch.setattr(candidates, "_read_action_schema_bytes", counted)
    _compile()
    _compile()
    assert calls == 1
    candidates._load_validator.cache_clear()


def test_caller_cannot_replace_canonical_dsl_with_bogus_schema(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.json"
    bogus.write_text("{}", encoding="utf-8")
    with pytest.raises(TypeError):
        compile_candidates("case-1", "episode-1", "branch-1", _step(), schema_path=bogus)  # type: ignore[call-arg]


def test_candidate_metadata_has_no_oracle_reward_or_patch_fields() -> None:
    actions, _, _ = _compile()
    forbidden = {"cwe", "patch", "fixed", "gold", "reward", "fact", "certificate"}
    for action in actions:
        assert set(action["metadata"]).isdisjoint(forbidden)
        assert all(not any(term in key.lower() for term in forbidden) for key in action)


@pytest.mark.parametrize("field,value", [
    ("case_id", ""), ("episode_id", ""), ("branch_id", ""),
    ("case_id", "x" * 4097), ("episode_id", "x" * 4097), ("branch_id", "x" * 4097),
])
def test_identifier_inputs_are_strict_nonempty_and_bounded(field: str, value: str) -> None:
    values = {"case_id": "case-1", "episode_id": "episode-1", "branch_id": "branch-1"}
    values[field] = value
    with pytest.raises(ValueError, match="identifier"):
        _compile(**values)


@pytest.mark.parametrize("step", [
    _step(target_id="x" * 4097),
    _step(target_location="x" * 4097),
    _step(resolves_unknowns=["O-0001", "O-0001"]),
])
def test_step_values_are_bounded_and_selected_resolves_are_legal(step: CanonicalPolicyStep) -> None:
    with pytest.raises(ValueError):
        _compile(step)


@pytest.mark.parametrize("field,value", [
    ("resolves_unknowns", ["x"] * 65),
    ("resolves_unknowns", ["x" * 10_000]),
    ("resolves_unknowns", ["x" * 256 for _ in range(33)]),
])
def test_trace_lists_are_bounded_before_candidate_construction(field: str, value: list[str]) -> None:
    with pytest.raises(ValueError, match=field):
        _compile(_step(**{field: value}))


def test_trace_lists_reject_non_string_items_before_candidate_construction() -> None:
    with pytest.raises(ValueError, match="resolves_unknowns"):
        _compile(_step(resolves_unknowns=(True,)))


def test_mutating_trace_list_after_compilation_cannot_change_outputs() -> None:
    source = ["O-0001"]
    step = _step(resolves_unknowns=source)
    actions, _, selected = _compile(step)
    source.append("O-0002")
    assert all(action["resolves_unknowns"] == ["O-0001"] for action in actions)
    assert selected["resolves_unknowns"] == ["O-0001"]


@pytest.mark.parametrize("step", [
    _step(target_kind="not-a-target-kind"),
    _step(tool_class="not-a-tool"),
    _step(operation="backtrack", target_kind="path", target_id="src/A.java", tool_class="control_only"),
    _step(operation="terminate", target_kind="path", target_id="src/A.java", tool_class="control_only"),
])
def test_selected_action_must_satisfy_dsl_operation_target_and_tool_constraints(step: CanonicalPolicyStep) -> None:
    with pytest.raises(ValueError):
        _compile(step)


def test_selected_is_not_fixed_to_first_candidate_or_revealed_by_obligations() -> None:
    results = [_compile(case_id=f"case-{index}") for index in range(12)]
    indices = [actions.index(selected) for actions, _, selected in results]
    assert any(index != 0 for index in indices)
    assert len(set(indices)) > 1
    for actions, _, selected in results:
        assert all(set(action) == set(selected) for action in actions)
        assert {action["obligation_id"] for action in actions} == {selected["obligation_id"]}
        assert {tuple(action["resolves_unknowns"]) for action in actions} == {
            tuple(selected["resolves_unknowns"])
        }


def test_full_semantic_identity_changes_for_every_binding_input() -> None:
    baseline = _compile()[2]
    variants = [
        _compile(case_id="case-2")[2],
        _compile(branch_id="branch-2")[2],
        _compile(_step(step_id="S-0002"))[2],
        _compile(_step(target_kind="function", target_id="function-0001", target_location=None,
                       expected_evidence_type="program_element"))[2],
        _compile(_step(target_id="src/B.java", target_location="src/B.java"))[2],
        _compile(_step(operation="trace_flow", goal="ESTABLISH_REACHABILITY",
                       tool_class="graph_query"))[2],
        _compile(_step(resolves_unknowns=["O-0002"]))[2],
    ]
    assert baseline["action_id"].startswith("A-")
    assert len(baseline["action_id"][2:]) >= 24
    assert len(baseline["idempotency_key"].removeprefix("sha256:")) == 64
    for variant in variants:
        assert variant["action_id"] != baseline["action_id"]
        assert variant["idempotency_key"] != baseline["idempotency_key"]


@pytest.mark.parametrize("field", ["case_id", "episode_id", "branch_id"])
def test_identifier_rejects_surrogates_and_astral_values_over_utf8_limit(field: str) -> None:
    values = {"case_id": "case-1", "episode_id": "episode-1", "branch_id": "branch-1"}
    values[field] = "\ud800"
    with pytest.raises(ValueError, match="identifier"):
        _compile(**values)
    values[field] = "\U0010ffff" * 1025
    with pytest.raises(ValueError, match="identifier"):
        _compile(**values)


@pytest.mark.parametrize("field", [
    "step_id", "goal", "operation", "target_kind", "target_id", "target_location",
    "expected_evidence_type", "tool_class",
])
def test_step_strings_reject_surrogates_and_astral_values_over_utf8_limit(field: str) -> None:
    with pytest.raises(ValueError):
        _compile(_step(**{field: "\ud800"}))
    with pytest.raises(ValueError):
        _compile(_step(**{field: "\U0010ffff" * 1025}))

"""Compilation of T1 labels must remain explicitly non-authoritative."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from egsi.contracts.case import CaseManifest
from egsi.contracts.enrichment import EnrichmentRecord, committed_enrichment_record


FIXTURE = Path(__file__).parents[1] / "fixtures" / "enrichment-valid.json"


def case() -> CaseManifest:
    from egsi.contracts.case import load_case_catalog
    return next(item for item in load_case_catalog(Path("data/catalog/cases.jsonl")) if item.case_id == "ghsa-2m8h-fgr8-2q9w")


def record() -> EnrichmentRecord:
    return EnrichmentRecord.model_validate_json(FIXTURE.read_text(encoding="utf-8"))


def recommit(item: EnrichmentRecord) -> EnrichmentRecord:
    return committed_enrichment_record(**item.model_dump(mode="python"))


def authorization_case() -> CaseManifest:
    from egsi.contracts.case import load_case_catalog

    return next(
        item
        for item in load_case_catalog(Path("data/catalog/cases.jsonl"))
        if item.case_id == "ghsa-268v-2qq7-84pf"
    )


def authorization_record(tmp_path: Path) -> EnrichmentRecord:
    from egsi.generation.enrichment import EnrichmentRunner
    from egsi.teacher.fixture import FixtureTeacher

    return EnrichmentRunner(Path("."), FixtureTeacher(), max_repairs=0).run(
        authorization_case(), tmp_path / "authorization-enrichment"
    )


def test_compile_t1_has_zero_reward_and_honest_fields() -> None:
    from egsi.generation.trajectory import compile_t1_episode

    transitions, events = compile_t1_episode(case(), record())
    assert transitions and events[-1].event_type == "EPISODE_CLOSED"
    assert events[-1].payload == {"outcome": "LABEL_SEQUENCE_COMPLETE", "dynamic_verdict": "not_applicable"}
    assert all(value == 0.0 for transition in transitions for value in transition.reward_vector.model_dump(exclude={"label_scope"}).values())
    assert all(transition.verifier_decision.checks == {"schema": True, "location": True, "action_dsl": True, "redaction": True} for transition in transitions)
    assert all(transition.observation == {"type": "oracle_label_only", "label_scope": "patch_grounded_bc", "receipt": None} for transition in transitions)
    assert all(transition.evidence_delta == {"facts": [], "claims": [], "resolved_unknowns": []} for transition in transitions)
    assert all(sum(transition.legal_mask) >= 4 for transition in transitions)
    assert [transition.state_version for transition in transitions] == list(range(len(transitions)))
    assert [transition.next_state_version for transition in transitions] == list(range(1, len(transitions) + 1))
    assert [transition.done for transition in transitions] == [False] * (len(transitions) - 1) + [True]
    assert all("dynamic_verdict" not in transition.model_dump_json() for transition in transitions)
    forbidden = {"cwe", "fixed", "gold", "certificate", "dynamic_verdict"}
    assert all(not any(key.lower() in forbidden for key in json.loads(transition.model_dump_json())) for transition in transitions)
    assert all("hypothesis" not in json.dumps(transition.state).lower() for transition in transitions)
    assert all("locations" not in json.dumps(transition.state).lower() for transition in transitions)
    assert all("obligations" not in json.dumps(transition.state).lower() for transition in transitions)


def test_authorization_teacher_scalars_are_canonicalized_before_policy_output(
    tmp_path: Path,
) -> None:
    """A semantically valid raw label may retain oracle strings, policy output may not."""

    from egsi.generation.enrichment import _load_store, allowed_action_values, validate_payload
    from egsi.generation.trajectory import compile_t1_episode

    auth_case = authorization_case()
    item = authorization_record(tmp_path).model_copy(deep=True)
    step = item.payload.trace[0]
    step.step_id = auth_case.cwe_normalized_primary
    item.payload.obligations[0].obligation_id = auth_case.repository.fixed_commit
    step.resolves_unknowns = [auth_case.repository.fixed_commit]
    step.target_id = auth_case.case_id
    # target_location is now a repository path field and cannot carry an
    # arbitrary teacher scalar; the remaining fields still exercise policy
    # canonicalization of oracle-controlled identifiers.
    step.target_location = None
    step.expected_evidence_type = "proof-" + auth_case.repository.fixed_commit
    step.reason_tags = [auth_case.case_id.upper()]
    item = recommit(item)

    repeated = validate_payload(
        auth_case,
        item.payload,
        _load_store(Path("."), auth_case),
        allowed_action_values(Path(".")),
    )
    assert repeated.valid is True
    assert auth_case.cwe_normalized_primary in item.model_dump_json()
    assert auth_case.repository.fixed_commit in item.model_dump_json()
    assert auth_case.case_id in item.model_dump_json()

    transitions, events = compile_t1_episode(auth_case, item)
    policy_json = json.dumps(
        {
            "transitions": [value.model_dump(mode="json") for value in transitions],
            "events": [value.model_dump(mode="json") for value in events],
        },
        ensure_ascii=False,
    ).casefold()
    assert auth_case.cwe_normalized_primary.casefold() not in policy_json
    assert auth_case.repository.fixed_commit.casefold() not in policy_json
    assert auth_case.case_id.casefold() not in policy_json
    assert all(
        action["metadata"]["step_id"] == "S-0001"
        and action["metadata"]["canonicalizer_version"] == "policy-trace-v1"
        and action["obligation_id"] == "O-0001"
        and action["resolves_unknowns"] == ["O-0001"]
        for action in transitions[0].candidate_actions
    )
    assert transitions[0].selected_action["target"] == {
        "kind": "resource",
        "id": "resource-0001",
        "location": None,
        "version": None,
    }


def test_policy_value_checker_is_nfkc_casefold_substring_aware_and_allows_local_inputs(
    tmp_path: Path,
) -> None:
    from egsi.generation.redaction import policy_value_hits

    auth_case = authorization_case()
    item = authorization_record(tmp_path).model_copy(deep=True)
    item.payload.limitations = ["ＦＩＸＥＤ－ＬＡＢＥＬ"]
    item = recommit(item)

    assert policy_value_hits(
        auth_case, item, {"value": "prefix-fixed-label-suffix"}
    )
    vulnerable_path = item.payload.locations[0].path
    assert policy_value_hits(
        auth_case,
        item,
        {
            "path": vulnerable_path,
            "commit": auth_case.repository.vulnerable_commit,
            "goal": "CHECK_SECURITY_INVARIANT",
            "operation": "check_auth_relation",
            "target_kind": "resource",
        },
    ) == set()


def test_episode_identity_binds_all_label_inputs_and_outputs_are_independent() -> None:
    from egsi.generation.trajectory import compile_t1_episode

    base_transitions, base_events = compile_t1_episode(case(), record())
    changed = record().model_copy(deep=True)
    changed.payload.hypothesis = "different teacher label"
    changed = recommit(changed)
    changed_transitions, changed_events = compile_t1_episode(case(), changed)
    assert base_transitions != changed_transitions
    assert base_events[0].episode_id != changed_events[0].episode_id
    selected_index = base_transitions[0].candidate_actions.index(base_transitions[0].selected_action)
    original = copy.deepcopy(base_transitions[0].candidate_actions[selected_index])
    base_transitions[0].selected_action["target"]["id"] = "mutated"
    assert base_transitions[0].candidate_actions[selected_index] == original


@pytest.mark.parametrize("mutator", [
    lambda item: setattr(item, "case_id", "other"),
    lambda item: setattr(item, "structured_output_valid", False),
    lambda item: setattr(item.validation, "valid", False),
    lambda item: setattr(item.payload, "family", "authorization"),
    lambda item: item.validation.invalid_locations.append("x"),
])
def test_compile_refuses_nonvalidated_or_mismatched_records(mutator) -> None:
    from egsi.generation.trajectory import compile_t1_episode

    item = record().model_copy(deep=True)
    mutator(item)
    with pytest.raises(ValueError):
        compile_t1_episode(case(), item)


@pytest.mark.parametrize("mutate", [
    lambda item: setattr(item.payload, "locations", []),
    lambda item: setattr(item.payload, "obligations", []),
    lambda item: setattr(item.payload, "hypothesis", ""),
    lambda item: setattr(item, "schema_version", "broken"),
])
def test_compile_revalidates_all_mutated_enrichment_contract_fields(mutate) -> None:
    from egsi.generation.trajectory import compile_t1_episode

    item = record().model_copy(deep=True)
    mutate(item)
    with pytest.raises(ValueError):
        compile_t1_episode(case(), item)


def test_compile_revalidates_mutated_case_contract_before_seed_building() -> None:
    from egsi.generation.trajectory import compile_t1_episode

    unsafe_case = case().model_copy(deep=True)
    unsafe_case.schema_version = "broken"
    with pytest.raises(ValueError):
        compile_t1_episode(unsafe_case, record())


@pytest.mark.parametrize("field,value", [
    ("source_context_sha256", "sha256:" + "0" * 64),
    ("prompt_sha256", "sha256:" + "0" * 64),
])
def test_compile_default_root_rejects_provenance_hash_tampering(field: str, value: str) -> None:
    from egsi.generation.trajectory import compile_t1_episode

    item = record().model_copy(deep=True)
    setattr(item, field, value)
    item = recommit(item)
    with pytest.raises(ValueError, match="provenance"):
        compile_t1_episode(case(), item)


def test_compile_default_root_rejects_missing_trace_path_despite_self_reported_valid() -> None:
    from egsi.generation.trajectory import compile_t1_episode

    item = record().model_copy(deep=True)
    item.payload.trace[0].target_id = "missing.java"
    item = recommit(item)
    with pytest.raises(ValueError, match="provenance"):
        compile_t1_episode(case(), item)


def test_event_hash_is_canonical_deep_copy_and_refuses_nonfinite_or_oversized() -> None:
    from egsi.generation.trajectory import event_hash, make_event

    payload = {"b": [1, {"a": "中"}]}
    event = make_event(0, "episode", "EPISODE_STARTED", payload, None)
    assert event.event_sha256 == event_hash(0, "episode", "EPISODE_STARTED", payload, None)
    payload["b"][1]["a"] = "changed"
    assert event.payload["b"][1]["a"] == "中"
    with pytest.raises(ValueError):
        event_hash(0, "episode", "EPISODE_STARTED", {"x": float("nan")}, None)
    with pytest.raises(ValueError):
        make_event(0, "episode", "EPISODE_STARTED", {"x": "a" * (1024 * 1024 + 1)}, None)


def test_atomic_writers_roundtrip_preserve_canonical_values(tmp_path: Path) -> None:
    from egsi.generation.trajectory import PARQUET_ENCODING_VERSION, compile_t1_episode, read_parquet, write_jsonl, write_parquet

    transitions, events = compile_t1_episode(case(), record())
    jsonl = tmp_path / "nested/events.jsonl"
    parquet = tmp_path / "nested/transitions.parquet"
    write_jsonl(jsonl, events)
    write_parquet(parquet, transitions)
    assert [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines()] == [event.model_dump(mode="json") for event in events]
    import pyarrow.parquet as pq
    table = pq.read_table(parquet)
    rows = table.to_pylist()
    assert len(rows) == len(transitions)
    assert "selected_action" in table.column_names and "candidate_actions" in table.column_names
    assert table.schema.field("selected_action").type.num_fields > 0
    assert table.schema.metadata[b"egsi.parquet_encoding_version"] == PARQUET_ENCODING_VERSION.encode()
    assert read_parquet(parquet) == transitions


def test_parquet_decoder_rejects_unknown_encoding_metadata_and_reserved_source_key(tmp_path: Path) -> None:
    import pyarrow.parquet as pq
    from egsi.contracts.trajectory import T1Transition
    from egsi.generation.trajectory import compile_t1_episode, read_parquet, write_parquet

    transitions, _ = compile_t1_episode(case(), record())
    transitions[0].state["__egsi_parquet_empty_object_v1__"] = True
    with pytest.raises(ValueError):
        write_parquet(tmp_path / "reserved.parquet", transitions)
    transitions, _ = compile_t1_episode(case(), record())
    path = tmp_path / "valid.parquet"
    write_parquet(path, transitions)
    table = pq.read_table(path)
    metadata = dict(table.schema.metadata or {})
    metadata[b"egsi.parquet_encoding_version"] = b"unknown"
    pq.write_table(table.replace_schema_metadata(metadata), tmp_path / "unknown.parquet")
    with pytest.raises(ValueError):
        read_parquet(tmp_path / "unknown.parquet")


def test_parquet_reader_rejects_zero_or_excessive_rows_before_decode(tmp_path: Path) -> None:
    import pyarrow as pa
    import pyarrow.parquet as pq
    from egsi.generation.trajectory import PARQUET_ENCODING_VERSION, compile_t1_episode, read_parquet

    transitions, _ = compile_t1_episode(case(), record())
    seed = tmp_path / "seed.parquet"
    from egsi.generation.trajectory import write_parquet
    write_parquet(seed, transitions)
    encoded = pq.read_table(seed)
    empty = encoded.slice(0, 0)
    pq.write_table(empty, tmp_path / "empty.parquet")
    with pytest.raises(ValueError):
        read_parquet(tmp_path / "empty.parquet")
    excessive = pa.concat_tables([encoded] * 1025)
    pq.write_table(excessive, tmp_path / "excessive.parquet")
    with pytest.raises(ValueError):
        read_parquet(tmp_path / "excessive.parquet")


def test_writers_refuse_empty_mixed_and_symlink_destinations(tmp_path: Path) -> None:
    from egsi.generation.trajectory import compile_t1_episode, write_jsonl, write_parquet

    transitions, events = compile_t1_episode(case(), record())
    with pytest.raises(ValueError):
        write_jsonl(tmp_path / "empty.jsonl", [])
    with pytest.raises(ValueError):
        write_jsonl(tmp_path / "mixed.jsonl", [events[0], transitions[0]])
    with pytest.raises(ValueError):
        write_parquet(tmp_path / "empty.parquet", [])
    target = tmp_path / "target.jsonl"
    target.write_text("old\n", encoding="utf-8")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    with pytest.raises(ValueError):
        write_jsonl(link, events)
    assert target.read_text(encoding="utf-8") == "old\n"


def test_writer_replace_failure_keeps_old_file_and_cleans_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import egsi.generation.trajectory as module
    from egsi.generation.trajectory import compile_t1_episode, write_jsonl

    _, events = compile_t1_episode(case(), record())
    target = tmp_path / "events.jsonl"
    target.write_text("old\n", encoding="utf-8")
    monkeypatch.setattr(module.os, "replace", lambda *_, **__: (_ for _ in ()).throw(OSError("no replace")))
    with pytest.raises(OSError, match="no replace"):
        write_jsonl(target, events)
    assert target.read_text(encoding="utf-8") == "old\n"
    assert not list(tmp_path.glob(".events.jsonl.*.tmp"))


def test_writer_treats_replace_after_commit_exception_as_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import egsi.generation.trajectory as module
    from egsi.generation.trajectory import compile_t1_episode, write_jsonl

    _, events = compile_t1_episode(case(), record())
    target = tmp_path / "events.jsonl"
    target.write_text("old\n", encoding="utf-8")
    original = module.os.replace
    def rename_then_fail(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("late replace failure")
    monkeypatch.setattr(module.os, "replace", rename_then_fail)
    write_jsonl(target, events)
    assert target.read_text(encoding="utf-8") != "old\n"
    assert not list(tmp_path.glob(".events.jsonl.*.tmp"))


def test_writer_treats_same_existing_destination_after_replace_error_as_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import egsi.generation.trajectory as module
    from egsi.generation.trajectory import compile_t1_episode, write_jsonl

    _, events = compile_t1_episode(case(), record())
    target = tmp_path / "events.jsonl"
    write_jsonl(target, events)
    monkeypatch.setattr(module.os, "replace", lambda *_, **__: (_ for _ in ()).throw(OSError("precommit")))
    write_jsonl(target, events)
    assert not list(tmp_path.glob(".events.jsonl.*.tmp"))


def test_writer_rejects_non_directory_parent_as_value_error(tmp_path: Path) -> None:
    from egsi.generation.trajectory import compile_t1_episode, write_jsonl

    _, events = compile_t1_episode(case(), record())
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError):
        write_jsonl(blocker / "events.jsonl", events)


def test_writer_refuses_symlink_ancestor_without_creating_beyond_it(tmp_path: Path) -> None:
    from egsi.generation.trajectory import compile_t1_episode, write_jsonl

    _, events = compile_t1_episode(case(), record())
    external = tmp_path / "external"
    external.mkdir()
    safe_parent = tmp_path / "safe"
    safe_parent.mkdir()
    (safe_parent / "escape").symlink_to(external, target_is_directory=True)
    with pytest.raises(ValueError):
        write_jsonl(safe_parent / "escape" / "created" / "events.jsonl", events)
    assert not (external / "created").exists()


def test_writer_ancestor_swap_cannot_create_outside_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import egsi.generation.trajectory as module
    from egsi.generation.trajectory import compile_t1_episode, write_jsonl

    _, events = compile_t1_episode(case(), record())
    safe = tmp_path / "safe"; safe.mkdir()
    outside = tmp_path / "outside"; outside.mkdir()
    target = safe / "new" / "events.jsonl"
    original_mkdir = module.os.mkdir
    swapped = False
    def swap_before_create(path, *args, **kwargs):
        nonlocal swapped
        if not swapped and Path(path).name == "new":
            swapped = True
            safe.rename(tmp_path / "safe-old")
            safe.symlink_to(outside, target_is_directory=True)
        return original_mkdir(path, *args, **kwargs)
    monkeypatch.setattr(module.os, "mkdir", swap_before_create)
    try:
        write_jsonl(target, events)
    except ValueError:
        pass
    assert not (outside / "new").exists()

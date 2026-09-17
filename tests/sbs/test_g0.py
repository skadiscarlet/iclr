from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbs.binding import apply_atomic_update, reject_replaced_body
from sbs.errors import BindingError, FairnessError, PilotBudgetError, PilotConfigError, VersionBoundError
from sbs.isolation import IsolatedStore, assert_real_model_actor_root, load_case_view
from sbs.pilot import (
    RequestLedger,
    load_pilot_config,
    open_request_ledger,
    parse_model_output,
    request_ledger_path,
    run_pilot,
)
from sbs.prompts import (
    RenderedPrompt,
    assert_public_fairness_payloads,
    compare_final_prompts,
    render_fair_prompts,
)
from sbs.replay import load_smoke_config, replay_case
from sbs.schema import (
    AuditState,
    CaseView,
    EvidenceRef,
    Hypothesis,
    LineSpan,
    ModelUpdate,
    Observation,
    VisibleEvidence,
    instance_cache_key,
    sha256_bytes,
    sha256_text,
)
from sbs.static_check import (
    build_version_bound_actor_view,
    count_complete_version_pairs,
    version_bound_ready,
)
from sbs.tokens import CharTokenCounter
from sbs.views import build_views, views_share_evidence


REPO = Path(__file__).resolve().parents[2]


def _hypothesis() -> Hypothesis:
    return Hypothesis(
        hypothesis_id="h1",
        entities=["A"],
        security_relation="A related to B",
        relation_source="test",
        status="open",
    )


def _state() -> AuditState:
    return AuditState(
        observed_evidence=["ev-1"],
        hypotheses=[_hypothesis()],
        unresolved_items=[],
        remaining_budget=3,
        inspection_history=["INIT"],
    )


def _observation(material: str = "class A {}", found: bool = True) -> Observation:
    return Observation(
        evidence_id="ev-1",
        material=material if found else None,
        parseable=found,
        provenance="src/A.java",
        uncertainty="none" if found else "not_found",
        found=found,
    )


def _case() -> CaseView:
    return CaseView(
        case_id="fixture-g0",
        visible_context="ctx",
        allowed_evidence_ids=["ev-1"],
        split="dev_pilot",
        material_kind="fixture",
        instance_id="inst-g0",
        generation_id="g1",
    )


def _visible(**kwargs) -> VisibleEvidence:
    material = kwargs.get("material", "class A {}")
    payload = {
        "instance_id": "inst-g0",
        "evidence_id": "ev-1",
        "material": material,
        "visible_sha256": sha256_text(material or ""),
        "display_path": "src/A.java",
        "displayed_span": LineSpan(start_line=10, end_line=20),
        "found": True,
        "parseable": True,
        "uncertainty": "none",
    }
    payload.update(kwargs)
    if "visible_sha256" not in kwargs and "material" in kwargs:
        payload["visible_sha256"] = sha256_text(kwargs["material"] or "")
    return VisibleEvidence.model_validate(payload)


def test_g01_history_without_material_fails_fairness() -> None:
    history, sbs = build_views(_case(), _state(), [_observation()])
    assert views_share_evidence(history, sbs)
    history_payload = json.loads(history.model_dump_json())
    sbs_payload = json.loads(sbs.model_dump_json())
    del history_payload["events"][0]["material"]
    with pytest.raises(FairnessError, match="missing material"):
        assert_public_fairness_payloads(history_payload, sbs_payload)


def test_g02_body_or_span_change_fails_fairness() -> None:
    history, sbs = build_views(_case(), _state(), [_observation("class A {}")])
    history_payload = json.loads(history.model_dump_json())
    sbs_payload = json.loads(sbs.model_dump_json())
    history_payload["events"][0]["material"] = "class B {}"
    with pytest.raises(FairnessError, match="material"):
        assert_public_fairness_payloads(history_payload, sbs_payload)
    history_payload = json.loads(history.model_dump_json())
    history_payload["events"][0]["displayed_span"] = {
        "start_line": 99,
        "end_line": 100,
    }
    sbs_payload["observations"][0]["displayed_span"] = {
        "start_line": 10,
        "end_line": 20,
    }
    with pytest.raises(FairnessError, match="span"):
        assert_public_fairness_payloads(history_payload, sbs_payload)


def test_g03_unequal_final_prompt_truncation_fails_before_send() -> None:
    block = b'{"evidence_id":"ev-1"}'
    left = RenderedPrompt(
        representation="history",
        prompt_bytes=b"H" + block,
        prompt_sha256=sha256_bytes(b"H" + block),
        evidence_block_bytes=block,
        evidence_block_sha256=sha256_bytes(block),
        visible_order=("ev-1",),
        clip_bounds=(0, 10),
        note_tokens=4,
        evidence_tokens=10,
        context_insufficient=False,
        notes="h",
    )
    right = RenderedPrompt(
        representation="sbs",
        prompt_bytes=b"S" + block,
        prompt_sha256=sha256_bytes(b"S" + block),
        evidence_block_bytes=block,
        evidence_block_sha256=sha256_bytes(block),
        visible_order=("ev-1",),
        clip_bounds=(0, 4),
        note_tokens=8,
        evidence_tokens=4,
        context_insufficient=False,
        notes="s",
    )
    with pytest.raises(FairnessError, match="clip"):
        compare_final_prompts(left, right)


def test_g04_unread_allowed_ref_is_atomic_reject() -> None:
    state = _state()
    original = state.model_dump()
    update = ModelUpdate(
        hypothesis_id="h1",
        support_refs=[
            EvidenceRef(
                evidence_id="ev-unread",
                instance_id="inst-g0",
                generation_id="g1",
            )
        ],
        verdict="supported",
    )
    with pytest.raises(BindingError, match="not read"):
        apply_atomic_update(
            state,
            update,
            instance_id="inst-g0",
            generation_id="g1",
            allowed_evidence_ids=["ev-1", "ev-unread"],
            observed={"ev-1": _visible()},
        )
    assert state.model_dump() == original


def test_g05_wrong_instance_generation_or_replaced_body_rejected() -> None:
    observed = {"ev-1": _visible()}
    with pytest.raises(BindingError, match="instance"):
        apply_atomic_update(
            _state(),
            ModelUpdate(
                hypothesis_id="h1",
                support_refs=[
                    EvidenceRef(
                        evidence_id="ev-1",
                        instance_id="inst-other",
                        generation_id="g1",
                    )
                ],
            ),
            instance_id="inst-g0",
            generation_id="g1",
            allowed_evidence_ids=["ev-1"],
            observed=observed,
        )
    with pytest.raises(BindingError, match="generation"):
        apply_atomic_update(
            _state(),
            ModelUpdate(
                hypothesis_id="h1",
                support_refs=[
                    EvidenceRef(
                        evidence_id="ev-1",
                        instance_id="inst-g0",
                        generation_id="g-old",
                    )
                ],
            ),
            instance_id="inst-g0",
            generation_id="g1",
            allowed_evidence_ids=["ev-1"],
            observed=observed,
        )
    with pytest.raises(BindingError, match="replaced"):
        reject_replaced_body(_visible(), _visible(material="class Z {}"))


def test_g06_missing_unparseable_or_budget_is_not_target_refuted() -> None:
    missing = _visible(material=None, found=False, parseable=False)
    missing = missing.model_copy(
        update={"found": False, "parseable": False, "uncertainty": "not_found"}
    )
    with pytest.raises(BindingError, match="unparseable|missing"):
        apply_atomic_update(
            _state(),
            ModelUpdate(
                hypothesis_id="h1",
                counter_refs=[
                    EvidenceRef(
                        evidence_id="ev-1",
                        instance_id="inst-g0",
                        generation_id="g1",
                    )
                ],
                verdict="refuted",
                status="refuted",
            ),
            instance_id="inst-g0",
            generation_id="g1",
            allowed_evidence_ids=["ev-1"],
            observed={"ev-1": missing},
        )
    updated = apply_atomic_update(
        _state(),
        ModelUpdate(
            hypothesis_id="h1",
            support_refs=[
                EvidenceRef(
                    evidence_id="ev-1",
                    instance_id="inst-g0",
                    generation_id="g1",
                    span=LineSpan(start_line=10, end_line=12),
                )
            ],
            verdict="refuted",
            status="refuted",
        ),
        instance_id="inst-g0",
        generation_id="g1",
        allowed_evidence_ids=["ev-1"],
        observed={"ev-1": _visible()},
        remaining_budget=0,
        context_insufficient=False,
    )
    assert updated.decision is not None
    assert updated.decision.verdict != "refuted"
    assert updated.hypotheses[0].status != "refuted"


def test_g07_real_model_entry_rejects_fixture_script_and_canary(tmp_path: Path) -> None:
    actor = tmp_path / "actor"
    actor.mkdir()
    (actor / "script.json").write_text('{"script_kind":"fixture_script"}', encoding="utf-8")
    with pytest.raises(PilotConfigError):
        assert_real_model_actor_root(actor)
    actor2 = tmp_path / "actor2"
    actor2.mkdir()
    (actor2 / "canary.json").write_text("{}", encoding="utf-8")
    with pytest.raises(PilotConfigError):
        assert_real_model_actor_root(actor2)


def test_g08_same_case_name_different_versions_do_not_share_cache_keys() -> None:
    a = instance_cache_key("case-x", "a" * 40, "r02b-g1")
    b = instance_cache_key("case-x", "b" * 40, "r02b-g1")
    assert a != b


def test_g09_illegal_model_json_is_stored_raw_and_failed() -> None:
    parsed, status = parse_model_output("not-json")
    assert parsed is None
    assert status == "parse_error"
    parsed2, status2 = parse_model_output('{"verdict":"supported"}')
    assert parsed2 is None
    assert status2 == "parse_error"
    good = {
        "hypothesis": "h",
        "verdict": "unresolved",
        "support_refs": [],
        "counter_refs": [],
        "unknowns": [],
        "limitations": [],
    }
    obj, status3 = parse_model_output(json.dumps(good))
    assert status3 == "parsed"
    assert obj["verdict"] == "unresolved"


def test_g10_one_version_ready_does_not_increment_complete_pairs(tmp_path: Path) -> None:
    actor = tmp_path / "actor"
    inst = "inst-only"
    build_version_bound_actor_view(
        instance_id=inst,
        visible_context="ctx",
        project_family=None,
        evidence_id="ev-a",
        display_path="src/A.java",
        snippet="class A { void n() {} }\n",
        actor_root=actor / inst,
        source_revision="a" * 40,
        generation_id="r02b-g1",
        start_line=1,
        end_line=1,
        truncated=False,
    )
    pairs = tmp_path / "pairs.jsonl"
    pairs.write_text(
        json.dumps({"pair_id": "p", "instance_ids": [inst]}) + "\n", encoding="utf-8"
    )
    counts = count_complete_version_pairs(actor, pairs)
    assert counts["version_bound_actor_instances"] == 1
    assert counts["complete_version_pairs"] == 0
    assert version_bound_ready(None, "r02b-g1") is False
    with pytest.raises(VersionBoundError):
        build_version_bound_actor_view(
            instance_id="inst-bad",
            visible_context="ctx",
            project_family=None,
            evidence_id="ev-a",
            display_path="src/A.java",
            snippet="class A {}\n",
            actor_root=tmp_path / "bad",
            source_revision=None,  # type: ignore[arg-type]
            generation_id="r02b-g1",
            start_line=1,
            end_line=1,
            truncated=False,
        )


def test_g11_different_notes_same_public_evidence_allowed() -> None:
    items = [_visible()]
    history, sbs = render_fair_prompts(
        visible_context="ctx",
        history_notes="history notes are longish",
        sbs_notes="sbs structured notes",
        evidences=items,
        tokenizer=CharTokenCounter(),
        max_input_tokens=4000,
    )
    compare_final_prompts(history, sbs)
    assert history.notes != sbs.notes
    assert history.evidence_block_sha256 == sbs.evidence_block_sha256
    assert history.clip_bounds == sbs.clip_bounds


def test_g12_restart_does_not_drop_failures_or_reset_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sbs import pilot as pilot_mod
    from sbs.tokens import CharTokenCounter

    payload = json.loads((REPO / "configs" / "r02b_pilot.lock.json").read_text(encoding="utf-8"))
    payload["run_output_root"] = "artifacts/r02b/runs"
    config_path = tmp_path / "configs" / "r02b_pilot.lock.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    config = load_pilot_config(config_path)
    first = open_request_ledger(tmp_path, config)
    expected = tmp_path / "artifacts" / "r02b" / "request_ledger.jsonl"
    assert first.path == expected
    assert first.path == request_ledger_path(tmp_path, config)
    first.reserve({"phase": "E0", "status": "failed", "raw": "nope"})
    restarted = open_request_ledger(tmp_path, config)
    assert restarted.path == first.path
    assert restarted.consumed() == 1
    assert restarted.entries()[0]["status"] == "failed"

    class FakeModel:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.counter = CharTokenCounter()

        def generate(self, prompt: str, max_new_tokens: int, seed: int) -> dict:
            return {
                "text": "not-json",
                "input_tokens": 3,
                "output_tokens": 2,
                "request_sha256": sha256_text(prompt),
            }

    monkeypatch.setattr(pilot_mod, "FrozenModel", FakeModel)
    monkeypatch.setattr(
        pilot_mod,
        "validate_pilot_manifest",
        lambda *args, **kwargs: {
            "ok": True,
            "instances": 0,
            "validated": 0,
            "problems": [],
            "model_called": False,
        },
    )
    manifest = tmp_path / "local_data" / "r02b" / "actor_manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "task_id": "R02B",
                "instances": [],
                "evaluator_relative_root": "local_data/r02b/evaluator",
            }
        ),
        encoding="utf-8",
    )
    before = open_request_ledger(tmp_path, config).consumed()
    run_a = run_pilot(tmp_path, config_path, code_sha="test-a", phase="e0")
    run_b = run_pilot(tmp_path, config_path, code_sha="test-b", phase="e0")
    assert Path(run_a["request_ledger"]) == expected
    assert Path(run_b["request_ledger"]) == expected
    assert expected.parent.name != Path(run_a["run_dir"]).name
    assert run_b["ledger_consumed"] > run_a["ledger_consumed"] >= before
    third_open = open_request_ledger(tmp_path, load_pilot_config(config_path))
    assert third_open.consumed() == run_b["ledger_consumed"]
    tiny = RequestLedger(tmp_path / "tiny.jsonl", hard_total=1)
    tiny.reserve({"ok": True})
    with pytest.raises(PilotBudgetError):
        tiny.reserve({"again": True})
    assert tiny.consumed() == 1


def test_r01_fixture_replay_still_zero_calls() -> None:
    smoke = load_smoke_config(REPO / "configs" / "r01_smoke.json")
    assert smoke.model_calls_allowed == 0
    result = replay_case(REPO / "fixtures" / "r01" / "support", smoke)
    assert result["state"].terminal == "FINISH"
    assert views_share_evidence(result["history"], result["sbs"])
    payload = json.loads(result["history"].model_dump_json())
    assert "material" in payload["events"][0]


def test_actor_store_rejects_wrong_instance(tmp_path: Path) -> None:
    inst = tmp_path / "actor"
    build_version_bound_actor_view(
        instance_id="inst-ok",
        visible_context="ctx",
        project_family=None,
        evidence_id="ev-a",
        display_path="src/A.java",
        snippet="class A {}\n",
        actor_root=inst,
        source_revision="c" * 40,
        generation_id="r02b-g1",
        start_line=1,
        end_line=1,
        truncated=False,
    )
    store = IsolatedStore(inst)
    case = load_case_view(store)
    with pytest.raises(Exception):
        store.read_evidence(
            case,
            "ev-a",
            expected_generation="r02b-g1",
            expected_instance="inst-other",
            expected_revision="c" * 40,
        )

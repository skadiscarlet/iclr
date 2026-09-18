"""R02C C-T02–C-T18: shipped parse/update/run-pilot path with a fake model."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sbs.diagnose import classify_layers
from sbs.errors import BindingError, FairnessError, PilotBudgetError
from sbs.output_contract import parse_response
from sbs.r02c_pilot import (
    FINAL_POLARITY_TEXT,
    HISTORY_FORM_READ_CONTRACT,
    SBS_FORM_READ_CONTRACT,
    assert_sent_visible_bodies_match,
    contract_instruction,
    run_instance_episode_r02c,
    run_r02c_pilot,
)
from sbs.r02c_prepare import prepare_r02c_pilot, validate_r02c_manifest
from sbs.r02c_state import refs_from_ids
from sbs.schema import LineSpan, VisibleEvidence, sha256_bytes, sha256_text
from sbs.static_check import build_version_bound_actor_view
from sbs.tokens import CharChatTokenCounter, count_chat_tokens


REPO = Path(__file__).resolve().parents[2]


def _hist(note: str = "Known: identity may be unimplemented. Unknown: delegate body.") -> str:
    return json.dumps({"note": note})


def _sbs(**overrides) -> str:
    payload = {
        "entities": ["input", "return value"],
        "requirement": "identity(x) must return x unchanged.",
        "hypothesis": "The implementation may violate identity.",
        "support_refs": [],
        "counter_refs": [],
        "unknowns": ["Delegate body is not shown."],
        "limitations": [],
    }
    payload.update(overrides)
    return json.dumps(payload)


def _final(**overrides) -> str:
    payload = {
        "hypothesis": "The implementation of identity may violate the declared identity requirement.",
        "verdict": "unresolved",
        "support_refs": [],
        "counter_refs": [],
        "unknowns": ["The implementation is not supplied."],
        "limitations": [],
    }
    payload.update(overrides)
    return json.dumps(payload)


class ScriptedModel:
    def __init__(self, scripts: list[str] | None = None) -> None:
        self.scripts = list(scripts or [])
        self.counter = CharChatTokenCounter()
        self.tokenizer = self.counter
        self.prompts: list[str] = []
        self.messages: list[list[dict[str, str]]] = []

    def generate(self, prompt: str, max_new_tokens: int, seed: int) -> dict:
        self.prompts.append(prompt)
        text = self.scripts.pop(0) if self.scripts else "not-json"
        return {
            "text": text,
            "input_tokens": 8,
            "output_tokens": 4,
            "request_sha256": sha256_text(prompt),
        }

    def generate_chat(
        self,
        messages: list[dict[str, str]],
        max_new_tokens: int,
        seed: int,
        max_input_tokens: int = 3072,
    ) -> dict:
        self.messages.append(messages)
        prompt = "\n".join(f"{m['role']}: {m['content']}" for m in messages)
        return self.generate(prompt, max_new_tokens, seed)


class HugeChatTokenizer(CharChatTokenCounter):
    def apply_chat_template(self, messages, *, tokenize=False, add_generation_prompt=True):
        if tokenize:
            return list(range(4000))
        return "x" * 4000


class HugeModel(ScriptedModel):
    def __init__(self) -> None:
        super().__init__(["_unused_"])
        self.tokenizer = HugeChatTokenizer()
        self.counter = self.tokenizer


def _revision() -> str:
    return "a" * 40


def _write_instance(
    workspace: Path,
    instance_id: str,
    bodies: list[tuple[str, str]],
    generation: str = "r02c-g1",
) -> None:
    inst = workspace / "local_data" / "r02c" / "actor" / instance_id
    inst.mkdir(parents=True, exist_ok=True)
    evidence_ids = []
    for index, (evidence_id, body) in enumerate(bodies):
        evidence_ids.append(evidence_id)
        build_version_bound_actor_view(
            instance_id=instance_id,
            visible_context="Pinned source unit from one recorded revision.",
            project_family=None,
            evidence_id=evidence_id,
            display_path=f"src/Unit{index}.java",
            snippet=body,
            actor_root=inst if index == 0 else inst,
            source_revision=_revision(),
            generation_id=generation,
            start_line=1,
            end_line=body.count("\n") + 1,
            truncated=False,
        )
        # build_version_bound_actor_view writes one evidence; extra evidences need a second write.
        if index > 0:
            ev = inst / "evidence"
            (ev / f"{evidence_id}.body").write_text(body, encoding="utf-8")
            rec = {
                "evidence_id": evidence_id,
                "display_path": f"src/Unit{index}.java",
                "span": {"start_line": 10 * (index + 1), "end_line": 10 * (index + 1) + 4},
                "content_sha256": sha256_bytes(body.encode("utf-8")),
                "source_category": "source_snippet",
                "material_kind": "real",
                "generation_id": generation,
                "source_revision": _revision(),
                "relative_read_path": f"evidence/{evidence_id}.body",
            }
            (ev / f"{evidence_id}.json").write_text(json.dumps(rec), encoding="utf-8")
            case = json.loads((inst / "case.json").read_text(encoding="utf-8"))
            if evidence_id not in case["allowed_evidence_ids"]:
                case["allowed_evidence_ids"].append(evidence_id)
            (inst / "case.json").write_text(json.dumps(case), encoding="utf-8")


def _manifest(workspace: Path, instance_ids: list[str], generation: str = "r02c-g1") -> dict:
    instances = []
    for iid in instance_ids:
        man = json.loads(
            (workspace / "local_data/r02c/actor" / iid / "manifest.json").read_text(encoding="utf-8")
        )
        instances.append(
            {
                "instance_id": iid,
                "generation_id": man["generation_id"],
                "source_revision": man["source_revision"],
                "relative_root": f"local_data/r02c/actor/{iid}",
            }
        )
    payload = {
        "schema_version": "1.0",
        "task_id": "R02C",
        "split": "dev_pilot",
        "generation_id": generation,
        "instances": instances,
        "frozen_schedule": ["form", "read_0", "read_1_or_none", "final"],
        "forbidden_paths": ["local_data/r02c/evaluator", "local_data/r02b/evaluator"],
        "evaluator_relative_root": None,
        "prepared_at": "2026-09-18T00:00:00+00:00",
    }
    path = workspace / "local_data/r02c/actor_manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def _legacy(workspace: Path, consumed: int = 38) -> None:
    path = workspace / "reports/rounds/R02C/legacy_request_reconciliation.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "conservative_consumed_for_new_call_limit": consumed,
                "reconciled_consumed_upper": consumed,
            }
        ),
        encoding="utf-8",
    )


def _lock(workspace: Path, instance_ids: list[str], **overrides) -> Path:
    payload = {
        "document_kind": "locked_runnable_config",
        "schema_version": "1.0",
        "task_id": "R02C",
        "mode": "frozen_model_pilot",
        "split": "dev_pilot",
        "seed": 17,
        "do_sample": False,
        "batch_size": 1,
        "representations": ["history", "sbs"],
        "max_input_tokens_including_chat": 3072,
        "max_new_tokens": 512,
        "note_reserve_tokens": 512,
        "project_request_cap": 192,
        "task_request_cap": 48,
        "max_inference_wall_seconds": 3600,
        "max_regenerations_per_logical_request": 1,
        "regeneration_kind": "schema_reprompt_not_semantics_preserving",
        "paid_budget_usd": 0,
        "enable_training": False,
        "enable_branch_rollouts": False,
        "trust_remote_code": False,
        "actor_manifest_relative_path": "local_data/r02c/actor_manifest.json",
        "run_output_root": "artifacts/r02c/runs",
        "request_ledger_relative_path": "artifacts/r02c/request_ledger.jsonl",
        "legacy_accounting_snapshot_relative_path": "reports/rounds/R02C/legacy_request_reconciliation.json",
        "e0_cases_relative_path": "fixtures/r02c_e0/actor_cases.jsonl",
        "e0_evaluator_relative_path": "fixtures/r02c_e0/evaluator_expectations.json",
        "frozen_e1_instance_ids": instance_ids,
        "frozen_schedule": ["form", "read_0", "read_1_or_none", "final"],
        "prompt_protocol": "r02c-v1",
        "model": {
            "repo_id": "Qwen/Qwen2.5-Coder-1.5B-Instruct",
            "resolved_revision": "2e1fd397ee46e1388853d2af2c993145b0f1098a",
            "device": "cpu",
            "dtype": "float32",
            "trust_remote_code": False,
            "local_files_only": True,
        },
        "schemas": {
            "history_note": "schemas/r02c_history_note.schema.json",
            "sbs_note": "schemas/r02c_sbs_note.schema.json",
            "final": "schemas/r02c_final.schema.json",
        },
    }
    payload.update(overrides)
    path = workspace / "configs" / "r02c_pilot.lock.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _copy_e0(workspace: Path) -> None:
    dest = workspace / "fixtures" / "r02c_e0"
    if dest.exists():
        return
    shutil.copytree(REPO / "fixtures" / "r02c_e0", dest)


def _ws(tmp_path: Path, instance_id: str = "inst-test-aaaa", n_ev: int = 1) -> Path:
    bodies = [("ev-a", "int identity(int x) { return x; }\n")]
    if n_ev > 1:
        bodies.append(("ev-b", "int other(int x) { return x + 1; }\n"))
    _write_instance(tmp_path, instance_id, bodies)
    _manifest(tmp_path, [instance_id])
    _legacy(tmp_path)
    _copy_e0(tmp_path)
    return tmp_path


def _e0_pass_scripts() -> list[str]:
    return [
        _hist(),
        _sbs(),
        _sbs(),
        _final(verdict="supported", support_refs=["ev-probe-04"], unknowns=[]),
        _final(verdict="refuted", counter_refs=["ev-probe-05"], unknowns=[]),
        _final(verdict="unresolved"),
    ]


def test_count_chat_tokens_accepts_batch_encoding_mapping() -> None:
    class Tok:
        def apply_chat_template(self, messages, tokenize=True, add_generation_prompt=True):
            if tokenize:
                return {"input_ids": [11, 12, 13]}
            return "unused"

        def encode(self, text, add_special_tokens=False):
            raise AssertionError("tokenize=True path must not fall back")

    count, ids, how = count_chat_tokens(Tok(), [{"role": "user", "content": "hi"}])
    assert count == 3
    assert ids == [11, 12, 13]
    assert how == "apply_chat_template_tokenize_true"


def test_ct02_layered_reject_no_repair() -> None:
    raw_true = json.dumps(
        {
            "hypothesis": "h",
            "verdict": "True",
            "support_refs": [],
            "counter_refs": [],
            "unknowns": [],
            "limitations": [],
        }
    )
    layers = classify_layers(raw_true, contract="final")
    parsed = parse_response(raw_true, "final")
    assert parsed.payload is not None
    assert parsed.payload["verdict"] == "True"
    assert "invalid_verdict_enum" in parsed.error_codes
    assert layers["semantics"] == "not_evaluated"
    missing = json.loads(raw_true)
    del missing["limitations"]
    r = parse_response(json.dumps(missing), "final")
    assert not r.accepted
    assert r.payload is not None and "limitations" not in r.payload
    truncated = json.dumps(
        {
            "hypothesis": "h",
            "verdict": "supported",
            "support_refs": [],
            "counter_refs": [],
            "unknowns": [],
            "limitations": [],
        }
    )[:-1]
    assert not parse_response(truncated, "final").accepted
    two = json.dumps({"note": "a"}) + json.dumps({"note": "b"})
    assert not parse_response(two, "history_note").accepted


def test_ct03_three_stage_prompts_differ_then_share_final() -> None:
    h_kind, h_text = contract_instruction("history", "form")
    s_kind, s_text = contract_instruction("sbs", "form")
    fh, ft = contract_instruction("history", "final")
    fs, fst = contract_instruction("sbs", "final")
    assert h_kind == "history_note" and s_kind == "sbs_note"
    assert h_text == HISTORY_FORM_READ_CONTRACT
    assert s_text == SBS_FORM_READ_CONTRACT
    assert h_text != s_text
    assert fh == fs == "final"
    assert ft == fst == FINAL_POLARITY_TEXT
    assert "supported" in ft and "refuted" in ft and "unresolved" in ft
    assert "true/false" in ft


def _run_sbs_episode(tmp_path: Path, scripts: list[str], n_ev: int = 1, instance_id: str = "inst-test-aaaa"):
    _ws(tmp_path, instance_id=instance_id, n_ev=n_ev)
    config_path = _lock(tmp_path, [instance_id])
    from sbs.r02c_pilot import load_r02c_config, open_r02c_ledger

    config = load_r02c_config(config_path)
    model = ScriptedModel(scripts)
    ledger = open_r02c_ledger(tmp_path, config)
    out = tmp_path / "ep"
    out.mkdir(exist_ok=True)
    episode = run_instance_episode_r02c(
        workspace=tmp_path,
        instance_rel=f"local_data/r02c/actor/{instance_id}",
        representation="sbs",
        model=model,
        ledger=ledger,
        legacy=38,
        out_dir=out,
        config=config,
        cache={},
        wall_deadline=10**18,
        forbidden=[],
    )
    return episode, model, ledger


def test_ct04_second_sbs_prompt_contains_new_card(tmp_path: Path) -> None:
    first = _sbs(
        entities=["alpha-entity"],
        requirement="alpha requirement",
        hypothesis="alpha hypothesis",
        unknowns=["alpha-unknown"],
        counter_refs=[],
    )
    second = _sbs(
        entities=["beta-entity"],
        requirement="beta requirement",
        hypothesis="beta hypothesis",
        unknowns=[],
        counter_refs=[],
        limitations=["beta-limit"],
    )
    episode, model, _ledger = _run_sbs_episode(
        tmp_path,
        [first, second, second, _final(verdict="unresolved")],
    )
    assert episode["sbs_initialized"] is True
    assert episode["sbs_card"]["entities"] == ["beta-entity"]
    assert len(model.prompts) >= 2
    assert "alpha-entity" in model.prompts[1]
    assert "alpha-unknown" in model.prompts[1]
    assert "not_initialized" not in model.prompts[1] or "alpha-entity" in model.prompts[1]


def test_ct05_empty_unknowns_clears_and_keeps_raw(tmp_path: Path) -> None:
    first = _sbs(unknowns=["stale-unknown"])
    second = _sbs(unknowns=[], entities=["cleared"])
    episode, model, _ = _run_sbs_episode(
        tmp_path, [first, second, second, _final(verdict="unresolved")]
    )
    assert episode["sbs_card"]["unknowns"] == []
    assert "stale-unknown" not in episode["sbs_card"]["unknowns"]
    raws = list((tmp_path / "ep").glob("*first_attempt.txt"))
    assert raws
    joined = "\n".join(p.read_text(encoding="utf-8") for p in raws)
    assert "stale-unknown" in joined


def test_ct06_bad_ref_aborts_whole_update(tmp_path: Path) -> None:
    first = _sbs(entities=["keep-me"], unknowns=["keep-unknown"])
    bad = _sbs(entities=["should-not-apply"], support_refs=["ev-does-not-exist"], unknowns=[])
    episode, _model, _ = _run_sbs_episode(
        tmp_path, [first, bad, bad]
    )
    # The bad read_0 must not replace the live card.
    assert episode["sbs_card"]["entities"] != ["should-not-apply"]
    statuses = {row["step"]: row.get("ref_status") for row in episode["steps"]}
    assert statuses.get("read_0") in {"rejected", "output_contract_failed"}


def test_ct07_second_evidence_keeps_its_own_span() -> None:
    ev1 = VisibleEvidence(
        instance_id="inst",
        evidence_id="ev-1",
        material="aaaa",
        visible_sha256=sha256_bytes(b"aaaa"),
        display_path="A.java",
        displayed_span=LineSpan(start_line=1, end_line=4),
        found=True,
        parseable=True,
        uncertainty="none",
    )
    ev2 = VisibleEvidence(
        instance_id="inst",
        evidence_id="ev-2",
        material="bbbb",
        visible_sha256=sha256_bytes(b"bbbb"),
        display_path="B.java",
        displayed_span=LineSpan(start_line=40, end_line=48),
        found=True,
        parseable=True,
        uncertainty="none",
    )
    refs = refs_from_ids(
        ["ev-2"],
        observed={"ev-1": ev1, "ev-2": ev2},
        instance_id="inst",
        generation_id="r02c-g1",
    )
    assert len(refs) == 1
    assert refs[0].evidence_id == "ev-2"
    assert refs[0].span is not None
    assert refs[0].span.start_line == 40
    assert refs[0].span.end_line == 48
    with pytest.raises(BindingError):
        refs_from_ids(
            ["ev-2", "ev-missing"],
            observed={"ev-1": ev1, "ev-2": ev2},
            instance_id="inst",
            generation_id="r02c-g1",
        )


def test_ct08_valid_finals_and_null_model_decision(tmp_path: Path) -> None:
    episode, _, _ = _run_sbs_episode(
        tmp_path,
        [
            _sbs(),
            _sbs(),
            _sbs(),
            _final(verdict="supported", support_refs=["ev-a"], unknowns=[]),
        ],
    )
    assert episode["model_decision"] == "supported"
    assert episode["terminal"] == "FINISH"
    fail, _, _ = _run_sbs_episode(
        tmp_path,
        ["not-json", "not-json"],
        instance_id="inst-test-bbbb",
    )
    assert fail["model_decision"] is None
    assert fail["execution_status"] == "output_contract_failed"
    assert fail["terminal"] == "UNRESOLVED"


def test_ct09_validation_failure_does_not_load_model(tmp_path: Path) -> None:
    _ws(tmp_path)
    man = json.loads((tmp_path / "local_data/r02c/actor_manifest.json").read_text())
    man["instances"] = [
        {
            "instance_id": "missing",
            "generation_id": "r02c-g1",
            "source_revision": _revision(),
            "relative_root": "local_data/r02c/actor/missing",
        }
    ]
    (tmp_path / "local_data/r02c/actor_manifest.json").write_text(json.dumps(man))
    config = _lock(tmp_path, ["missing"])
    loaded = {"n": 0}

    def boom(spec):
        loaded["n"] += 1
        raise AssertionError("model loader must not run")

    result = run_r02c_pilot(tmp_path, config, code_sha="test", model_loader=boom)
    assert result["blocked"] == "manifest_validation_failed"
    assert result["model_loaded"] is False
    assert result["model_called"] is False
    assert loaded["n"] == 0
    assert result["e1"]["generate_count"] == 0


def test_ct10_e0_fail_means_zero_e1_generate(tmp_path: Path) -> None:
    _ws(tmp_path)
    config = _lock(tmp_path, ["inst-test-aaaa"])
    model = ScriptedModel([])  # always not-json
    result = run_r02c_pilot(
        tmp_path, config, code_sha="test", model_loader=lambda spec: model, model=model
    )
    assert result["e0"]["open_e1"] is False
    assert result["e1"]["generate_count"] == 0
    assert result["e0"]["after_reprompt_valid"] == 0


def test_ct11_evaluator_tripwire_runtime_still_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = REPO / "local_data/r02b/actor"
    dest = tmp_path / "local_data/r02b/actor"
    dest.mkdir(parents=True)
    for name in ("inst-6bf462ca01bb071f", "inst-b750a376e1e3c54c"):
        shutil.copytree(src / name, dest / name)
    # Minimal remaining instances so prepare's ALL pairs exist.
    for name in (
        "inst-614b3612f0e5db8a",
        "inst-3300fc1a03e22857",
        "inst-cb80f8fe5eb55013",
        "inst-ebf077b5bfcdcc88",
        "inst-ba9671eef76541a9",
        "inst-90a9632ec46227d5",
    ):
        shutil.copytree(src / name, dest / name)
    selection = {
        "task_id": "R02C",
        "generation_id": "r02c-g1",
        "pairs": [
            {"pair_id": "r01-pair-01", "include": True},
            {"pair_id": "r01-pair-12", "include": True},
            {"pair_id": "r01-pair-13", "include": True},
            {"pair_id": "r01-pair-15", "include": True},
        ],
    }
    sel_path = tmp_path / "metadata" / "r02c_selection.json"
    sel_path.parent.mkdir(parents=True)
    sel_path.write_text(json.dumps(selection), encoding="utf-8")
    prepare_r02c_pilot(tmp_path, sel_path)
    monkeypatch.setattr(
        "sbs.static_check.count_complete_version_pairs",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("evaluator tripwire")),
    )
    original = Path.read_text

    def guarded(self, *args, **kwargs):
        text = str(self)
        if "evaluator" in text.replace("\\", "/") and "pairs.jsonl" in text:
            raise RuntimeError("evaluator tripwire")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded)
    _legacy(tmp_path)
    _copy_e0(tmp_path)
    config = _lock(
        tmp_path,
        ["inst-6bf462ca01bb071f", "inst-b750a376e1e3c54c"],
    )
    model = ScriptedModel([])
    result = run_r02c_pilot(
        tmp_path, config, code_sha="test", model_loader=lambda spec: model, model=model
    )
    assert result["model_loaded"] is True
    assert result["e1"]["generate_count"] == 0  # E0 fail is fine; runtime ran


def test_ct12_chat_template_over_budget_intercepted(tmp_path: Path) -> None:
    _ws(tmp_path)
    config_path = _lock(tmp_path, ["inst-test-aaaa"])
    from sbs.r02c_pilot import load_r02c_config, open_r02c_ledger

    config = load_r02c_config(config_path)
    model = HugeModel()
    ledger_before = open_r02c_ledger(tmp_path, config).consumed()
    episode = run_instance_episode_r02c(
        workspace=tmp_path,
        instance_rel="local_data/r02c/actor/inst-test-aaaa",
        representation="history",
        model=model,
        ledger=open_r02c_ledger(tmp_path, config),
        legacy=38,
        out_dir=tmp_path / "ep12",
        config=config,
        cache={},
        wall_deadline=10**18,
        forbidden=[],
    )
    assert episode["steps"][0]["status"] == "context_insufficient"
    assert episode["steps"][0].get("intercepted_before_generate") is True
    assert episode["steps"][0]["input_tokens"] == 4000
    assert open_r02c_ledger(tmp_path, config).consumed() == ledger_before
    assert model.prompts == []


def test_ct13_one_char_visible_body_change_fails_cross_check() -> None:
    left = {"visible_body_sha256": sha256_bytes(b"public-body")}
    right = {"visible_body_sha256": sha256_bytes(b"public-bodX")}
    with pytest.raises(FairnessError):
        assert_sent_visible_bodies_match(left, right)
    assert_sent_visible_bodies_match(left, {"visible_body_sha256": sha256_bytes(b"public-body")})


def test_ct14_form_sees_code_no_duplicate_observation(tmp_path: Path) -> None:
    episode, model, _ = _run_sbs_episode(
        tmp_path, [_sbs(), _sbs(), _sbs(), _final(verdict="unresolved")]
    )
    assert episode["single_evidence_interface_pilot"] is True
    assert episode["incremental_evidence_steps"] == 0
    assert "int identity" in model.prompts[0]
    no_more = [row for row in episode["steps"] if row.get("no_more_material")]
    assert no_more


def test_ct15_one_schema_reprompt_then_stop(tmp_path: Path) -> None:
    episode, model, ledger = _run_sbs_episode(tmp_path, ["not-json", "still-bad"])
    assert episode["execution_status"] == "output_contract_failed"
    assert len(model.prompts) == 2
    assert ledger.consumed() == 2
    first = tmp_path / "ep" / "inst-test-aaaa_sbs_form_first_attempt.txt"
    second = tmp_path / "ep" / "inst-test-aaaa_sbs_form_schema_reprompt.txt"
    assert first.is_file() and second.is_file()


def test_ct16_two_run_entries_ledger_delta_and_post_round_reject(tmp_path: Path) -> None:
    _ws(tmp_path)
    config = _lock(tmp_path, ["inst-test-aaaa"])
    model = ScriptedModel([])
    before = 0
    run_a = run_r02c_pilot(
        tmp_path, config, code_sha="a", model_loader=lambda spec: model, model=model
    )
    assert run_a["per_run_attempts"] == run_a["ledger_after"] - run_a["ledger_before"]
    assert run_a["per_run_attempts"] > 0
    assert run_a["legacy_consumed"] == 38
    assert run_a["project_consumed_conservative"] == 38 + run_a["ledger_after"]
    # Identical raw still counted twice: E0 always returns not-json.
    ledger_path = tmp_path / "artifacts/r02c/request_ledger.jsonl"
    lines = [json.loads(l) for l in ledger_path.read_text().splitlines() if l.strip()]
    assert len(lines) == run_a["per_run_attempts"]
    run_b = run_r02c_pilot(
        tmp_path, config, code_sha="b", model_loader=lambda spec: model, model=model
    )
    assert run_b["blocked"] == "round_already_complete"
    assert run_b["model_called"] is False
    assert run_b["e1"]["generate_count"] == 0
    after_lines = [l for l in ledger_path.read_text().splitlines() if l.strip()]
    assert len(after_lines) == len(lines)


def test_ct17_generation_mismatch_is_not_a_cache_hit(tmp_path: Path) -> None:
    _write_instance(tmp_path, "inst-alias", [("ev-a", "int identity(int x) { return x; }\n")], "r02c-g1")
    _write_instance(tmp_path, "inst-alias-2", [("ev-a", "int identity(int x) { return x; }\n")], "r02c-g2")
    # Distinct instance dirs with similar names and different generation.
    _manifest(tmp_path, ["inst-alias"])
    _legacy(tmp_path)
    _copy_e0(tmp_path)
    config_path = _lock(tmp_path, ["inst-alias"])
    from sbs.r02c_pilot import load_r02c_config, open_r02c_ledger

    config = load_r02c_config(config_path)
    cache: dict = {}
    model = ScriptedModel([_sbs(), _sbs(), _sbs(), _final(verdict="unresolved")])
    run_instance_episode_r02c(
        workspace=tmp_path,
        instance_rel="local_data/r02c/actor/inst-alias",
        representation="sbs",
        model=model,
        ledger=open_r02c_ledger(tmp_path, config),
        legacy=38,
        out_dir=tmp_path / "g1",
        config=config,
        cache=cache,
        wall_deadline=10**18,
        forbidden=[],
    )
    model2 = ScriptedModel([_sbs(), _sbs(), _sbs(), _final(verdict="unresolved")])
    (tmp_path / "g2").mkdir()
    before = open_r02c_ledger(tmp_path, config).consumed()
    run_instance_episode_r02c(
        workspace=tmp_path,
        instance_rel="local_data/r02c/actor/inst-alias-2",
        representation="sbs",
        model=model2,
        ledger=open_r02c_ledger(tmp_path, config),
        legacy=38,
        out_dir=tmp_path / "g2",
        config=config,
        cache=cache,
        wall_deadline=10**18,
        forbidden=[],
    )
    after = open_r02c_ledger(tmp_path, config).consumed()
    assert after > before
    assert model2.prompts  # not served from cache


def test_ct18_exception_still_persists_raw(tmp_path: Path) -> None:
    _ws(tmp_path)
    config_path = _lock(tmp_path, ["inst-test-aaaa"])
    from sbs.r02c_pilot import load_r02c_config, open_r02c_ledger

    class Boom(ScriptedModel):
        def generate(self, prompt: str, max_new_tokens: int, seed: int) -> dict:
            self.prompts.append(prompt)
            if len(self.prompts) == 1:
                return {
                    "text": _sbs(),
                    "input_tokens": 3,
                    "output_tokens": 3,
                    "request_sha256": sha256_text(prompt),
                }
            raise RuntimeError("mid-episode")

    config = load_r02c_config(config_path)
    model = Boom()
    out = tmp_path / "ep18"
    out.mkdir()
    run_instance_episode_r02c(
        workspace=tmp_path,
        instance_rel="local_data/r02c/actor/inst-test-aaaa",
        representation="sbs",
        model=model,
        ledger=open_r02c_ledger(tmp_path, config),
        legacy=38,
        out_dir=out,
        config=config,
        cache={},
        wall_deadline=10**18,
        forbidden=[],
    )
    raws = list(out.glob("*.txt"))
    errs = list(out.glob("*.error.json"))
    assert raws, "raw must be saved"
    assert errs, "error sidecar must be saved"
    assert any(p.read_text(encoding="utf-8") for p in raws)

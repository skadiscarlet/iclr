from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbs.errors import (
    EvaluatorReadError,
    HashMismatchError,
    MissingEvidenceError,
    PathEscapeError,
    StaleEvidenceError,
    UnauthorizedEvidenceError,
)
from sbs.isolation import IsolatedStore, load_case_view
from sbs.schema import CaseView, EvidenceRecord, LineSpan, sha256_bytes
from sbs.static_check import build_actor_view


def _write_case(actor: Path, evidence_id: str = "ev-1", body: str = "class A {}") -> None:
    (actor / "evidence").mkdir(parents=True)
    rel = f"evidence/{evidence_id}.body"
    data = body.encode("utf-8")
    (actor / rel).write_bytes(data)
    record = EvidenceRecord(
        evidence_id=evidence_id,
        display_path="src/A.java",
        span=LineSpan(start_line=1, end_line=1),
        content_sha256=sha256_bytes(data),
        source_category="source_snippet",
        material_kind="fixture",
        generation_id="g1",
        relative_read_path=rel,
    )
    (actor / "evidence" / f"{evidence_id}.json").write_text(
        record.model_dump_json(indent=2), encoding="utf-8"
    )
    case = CaseView(
        case_id="fixture-iso",
        visible_context="ctx",
        allowed_evidence_ids=[evidence_id],
        split="dev_pilot",
        material_kind="fixture",
    )
    (actor / "case.json").write_text(case.model_dump_json(indent=2), encoding="utf-8")


def test_unauthorized_evidence_id_and_out_of_root_path_fail(tmp_path: Path) -> None:
    actor = tmp_path / "actor"
    evaluator = tmp_path / "evaluator"
    actor.mkdir()
    evaluator.mkdir()
    (evaluator / "answers.json").write_text(
        json.dumps(
            {
                "cve": "CVE-0000-0000",
                "gold_label": "vulnerable",
                "patch": "diff",
                "fix_pairing": "a->b",
            }
        ),
        encoding="utf-8",
    )
    _write_case(actor)
    store = IsolatedStore(actor, evaluator_root=evaluator)
    case = load_case_view(store)
    with pytest.raises(UnauthorizedEvidenceError):
        store.read_evidence(case, "ev-secret")
    with pytest.raises(PathEscapeError):
        store.read_bytes("../evaluator/answers.json")
    with pytest.raises(PathEscapeError):
        store.read_bytes("/etc/passwd")
    assert store.evaluator_was_read() is False


def test_evaluator_and_answer_roots_are_unread(tmp_path: Path) -> None:
    actor = tmp_path / "actor"
    evaluator = tmp_path / "evaluator"
    actor.mkdir()
    evaluator.mkdir()
    (evaluator / "answers.json").write_text('{"cve":"CVE-1","gold_label":"x","patch":"y"}', encoding="utf-8")
    _write_case(actor)
    store = IsolatedStore(actor, evaluator_root=evaluator)
    case = load_case_view(store)
    store.read_evidence(case, "ev-1")
    assert store.evaluator_was_read() is False
    for path in store.read_paths:
        with pytest.raises(ValueError):
            path.resolve().relative_to(evaluator.resolve())
        assert "answers.json" not in path.as_posix()
        assert "cve" not in path.name.lower()


def test_missing_and_hash_mismatch_and_stale_rejected(tmp_path: Path) -> None:
    actor = tmp_path / "actor"
    actor.mkdir()
    _write_case(actor)
    store = IsolatedStore(actor)
    case = load_case_view(store)
    # missing
    case_missing = case.model_copy(update={"allowed_evidence_ids": ["ev-1", "ev-missing"]})
    with pytest.raises(MissingEvidenceError):
        store.read_evidence(case_missing, "ev-missing")
    # hash mismatch
    (actor / "evidence" / "ev-1.body").write_text("changed", encoding="utf-8")
    with pytest.raises(HashMismatchError):
        store.read_evidence(case, "ev-1")
    # stale generation
    actor2 = tmp_path / "actor2"
    actor2.mkdir()
    _write_case(actor2, body="class B {}")
    rec_path = actor2 / "evidence" / "ev-1.json"
    rec = json.loads(rec_path.read_text(encoding="utf-8"))
    rec["generation_id"] = "old-stale"
    rec_path.write_text(json.dumps(rec), encoding="utf-8")
    store2 = IsolatedStore(actor2)
    case2 = load_case_view(store2)
    with pytest.raises(StaleEvidenceError):
        store2.read_evidence(case2, "ev-1", expected_generation="g-new")


def test_build_actor_view_does_not_embed_answers(tmp_path: Path) -> None:
    actor = tmp_path / "actor"
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir()
    (evaluator / "answers.json").write_text(
        '{"cve":"CVE-9","gold_label":"bad","patch":"p","fix_pairing":"z"}',
        encoding="utf-8",
    )
    case = build_actor_view(
        pair_id="r01-pair-99",
        visible_context="bounded source snippet",
        project_family="example/project",
        evidence_id="ev-src",
        display_path="src/Example.java",
        snippet="class Example { void n() {} }\n",
        actor_root=actor,
    )
    assert case.split == "dev_pilot"
    dumped = json.loads((actor / "case.json").read_text(encoding="utf-8"))
    for key in ("cve", "gold_label", "patch", "fix_pairing"):
        assert key not in dumped
    store = IsolatedStore(actor, evaluator_root=evaluator)
    loaded = load_case_view(store)
    store.read_evidence(loaded, "ev-src")
    assert store.evaluator_was_read() is False

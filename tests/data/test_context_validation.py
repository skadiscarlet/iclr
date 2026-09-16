from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from egsi.contracts.case import CaseManifest
from egsi.data import context_validation


def _case(case_id: str, split: str = "train") -> CaseManifest:
    commit = hashlib.sha1(case_id.encode()).hexdigest()
    return CaseManifest.model_validate(
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "evidence_tier": "T1",
            "family": "source_to_sink",
            "cwe_normalized_primary": "CWE-79",
            "split": split,
            "repository": {
                "url": "https://example.invalid/repo",
                "upstream_id": "owner/repo",
                "vulnerable_commit": commit,
                "fixed_commit": commit,
            },
            "artifacts": {
                "patch_path": "data/patch",
                "proof_obligations_path": "data/proof",
                "manifest_path": "data/manifest",
            },
            "views": {
                "oracle_view_path": "data/oracle",
                "policy_view_path": "data/policy",
                "redaction_manifest_sha256": "sha256:" + "0" * 64,
            },
        }
    )


def test_context_validator_is_exported_as_a_library_api() -> None:
    from egsi.data import validate_contexts

    assert validate_contexts is context_validation.validate_contexts


def _fake_context(case_id: str, *, source: str = "raw", suffix: str = ""):
    rendered = json.dumps({"case_id": case_id, "suffix": suffix}, sort_keys=True)
    digest = "sha256:" + hashlib.sha256(rendered.encode()).hexdigest()
    receipt_digest = "sha256:" + hashlib.sha256((case_id + suffix).encode()).hexdigest()
    receipt = SimpleNamespace(
        effective_patch_source=source,
        receipt_commitment_sha256=receipt_digest,
        omitted_file_count=1,
        omitted_hunk_count=2,
        missing_paths=("missing",),
        new_only_paths=("new",),
        source_blobs=(SimpleNamespace(selection_reason="binary_patch"),),
    )
    return SimpleNamespace(
        render=lambda: rendered,
        sha256=digest,
        context_version="2.0",
        selection_receipt=receipt,
    )


def _install_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[list[CaseManifest], Path]:
    cases = [_case(f"case-{index:03d}") for index in range(300)]
    monkeypatch.setattr(context_validation, "load_case_catalog", lambda _path: cases)
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs/p0_cases.txt").write_text(
        "\n".join(case.case_id for case in cases[:10]) + "\n", encoding="utf-8"
    )
    (tmp_path / "configs/p1_cases.txt").write_text(
        "\n".join(case.case_id for case in cases[:30]) + "\n", encoding="utf-8"
    )
    return cases, tmp_path / "catalog.jsonl"


def test_validator_reports_a_deterministic_300_case_gate_and_writes_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cases, catalog = _install_catalog(tmp_path, monkeypatch)
    fallback_ids = {case.case_id for case in cases[:27]}
    monkeypatch.setattr(
        context_validation,
        "build_oracle_context",
        lambda _root, case, total_chars: _fake_context(
            case.case_id,
            source="canonical_git_diff" if case.case_id in fallback_ids else "raw",
        ),
    )
    report_path = tmp_path / "reports/context-validation.json"

    report = context_validation.validate_contexts(
        catalog=catalog,
        root=tmp_path,
        repeat=2,
        max_chars=64_000,
        report_path=report_path,
    )

    assert report["schema_version"] == "1.0"
    assert report["validator_version"] == "context-v2-gate-v1"
    assert report["requested"] == report["built"] == 300
    assert report["failed"] == 0
    assert report["repeat_consistency"] == {
        "requested_repeats": 2,
        "consistent": 300,
        "hash_mismatch_case_ids": [],
    }
    assert report["patch_sources"] == {"canonical_git_diff": 27, "raw": 273}
    assert report["frozen_lists"]["p0"]["ids"] == [
        case.case_id for case in cases[:10]
    ]
    assert report["frozen_lists"]["p1"]["time_ood_overlap"] == []
    assert report["overall_valid"] is True
    assert json.loads(report_path.read_text(encoding="utf-8")) == report


def test_validator_fails_closed_on_repeat_mismatch_and_redacts_failure_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cases, catalog = _install_catalog(tmp_path, monkeypatch)
    calls: dict[str, int] = {}

    def build(_root: Path, case: CaseManifest, total_chars: int):
        calls[case.case_id] = calls.get(case.case_id, 0) + 1
        if case.case_id == cases[0].case_id:
            raise ValueError(f"secret path: {tmp_path}")
        suffix = "changed" if case.case_id == cases[1].case_id and calls[case.case_id] == 2 else ""
        return _fake_context(case.case_id, suffix=suffix)

    monkeypatch.setattr(context_validation, "build_oracle_context", build)

    report = context_validation.validate_contexts(
        catalog=catalog, root=tmp_path, repeat=2, max_chars=64_000
    )

    assert report["failure_categories"] == {"validation": [cases[0].case_id]}
    assert report["repeat_consistency"]["hash_mismatch_case_ids"] == [cases[1].case_id]
    assert str(tmp_path) not in json.dumps(report)
    assert report["overall_valid"] is False


def test_validator_counts_only_all_repeat_successes_and_compares_partial_success_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cases, catalog = _install_catalog(tmp_path, monkeypatch)
    calls: dict[str, int] = {}

    def build(_root: Path, case: CaseManifest, total_chars: int):
        calls[case.case_id] = calls.get(case.case_id, 0) + 1
        if case.case_id != cases[0].case_id:
            return _fake_context(case.case_id)
        if calls[case.case_id] == 2:
            raise RuntimeError("injected middle-repeat failure")
        suffix = "" if calls[case.case_id] == 1 else "changed-after-failure"
        return _fake_context(case.case_id, suffix=suffix)

    monkeypatch.setattr(context_validation, "build_oracle_context", build)

    report = context_validation.validate_contexts(
        catalog=catalog, root=tmp_path, repeat=3, max_chars=64_000
    )

    assert report["requested"] == 300
    assert report["built"] == 299
    assert report["failed"] == 1
    assert report["requested"] == report["built"] + report["failed"]
    assert report["failed_case_ids"] == [cases[0].case_id]
    assert report["failure_categories"] == {"runtime": [cases[0].case_id]}
    assert report["repeat_consistency"] == {
        "requested_repeats": 3,
        "consistent": 299,
        "hash_mismatch_case_ids": [cases[0].case_id],
    }
    assert report["overall_valid"] is False


def test_validator_rejects_time_ood_ids_in_frozen_pilot_lists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cases, catalog = _install_catalog(tmp_path, monkeypatch)
    cases[0] = _case(cases[0].case_id, split="time_ood_test")
    monkeypatch.setattr(
        context_validation,
        "build_oracle_context",
        lambda _root, case, total_chars: _fake_context(case.case_id),
    )

    report = context_validation.validate_contexts(
        catalog=catalog, root=tmp_path, repeat=2, max_chars=64_000
    )

    assert report["frozen_lists"]["p0"]["time_ood_overlap"] == [cases[0].case_id]
    assert report["frozen_lists"]["p1"]["time_ood_overlap"] == [cases[0].case_id]
    assert report["overall_valid"] is False


def test_validator_report_writer_refuses_a_symlink_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _cases, catalog = _install_catalog(tmp_path, monkeypatch)
    monkeypatch.setattr(
        context_validation,
        "build_oracle_context",
        lambda _root, case, total_chars: _fake_context(case.case_id),
    )
    external = tmp_path / "external.json"
    external.write_text('{"preserve":true}\n', encoding="utf-8")
    linked = tmp_path / "report.json"
    linked.symlink_to(external)

    with pytest.raises(ValueError):
        context_validation.validate_contexts(
            catalog=catalog,
            root=tmp_path,
            repeat=2,
            max_chars=64_000,
            report_path=linked,
        )

    assert external.read_text(encoding="utf-8") == '{"preserve":true}\n'
    assert linked.is_symlink()

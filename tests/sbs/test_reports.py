from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from sbs.reports import MIGRATION_HEADER, validate_reports
from sbs.schema import CandidatePair


def _write_min_repo(root: Path) -> None:
    (root / "metadata").mkdir(parents=True)
    (root / "fixtures" / "r01" / "support").mkdir(parents=True)
    (root / "fixtures" / "r01" / "counter").mkdir()
    (root / "fixtures" / "r01" / "insufficient").mkdir()
    (root / "fixtures" / "r01" / "budget").mkdir()
    pair = CandidatePair(
        pair_id="r01-pair-01",
        project_family="ex/p",
        dataset_origin="test",
        dataset_revision=None,
        source_locator=None,
        buggy_revision=None,
        fixed_revision=None,
        category_claim="conventional",
        obligation_basis=None,
        status="metadata_only",
        license_note=None,
        split="dev_pilot",
        blocker="test",
    )
    (root / "metadata" / "r01_candidates.jsonl").write_text(
        pair.model_dump_json() + "\n", encoding="utf-8"
    )
    with (root / "metadata" / "r01_readiness.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "pair_id",
                "category_claim",
                "versions_locatable",
                "license_clear",
                "citation_range_exists",
                "actor_view_generated",
                "ready",
                "blocker",
                "split",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "pair_id": "r01-pair-01",
                "category_claim": "conventional",
                "versions_locatable": "no",
                "license_clear": "no",
                "citation_range_exists": "no",
                "actor_view_generated": "no",
                "ready": "no",
                "blocker": "test",
                "split": "dev_pilot",
            }
        )
    reports = root / "reports" / "rounds" / "R01"
    reports.mkdir(parents=True)
    (reports / "SUMMARY.md").write_text("blocker: test empty ready list\n", encoding="utf-8")
    status = {
        "schema_version": "1.0",
        "round_id": "R01",
        "engineering_status": "completed",
        "data_status": "partial",
        "delivery_status": "not_pushed",
        "review_status": "pending",
        "assistant_repo_access": "unverified_404",
        "base_sha": "abc",
        "implementation_sha": "abc",
        "branch": "research/naacl2027-r01",
        "counts": {
            "candidate_pairs": 1,
            "real_ready_pairs": 0,
            "human_verified_pairs": 0,
            "project_families": 1,
            "fixture_cases": 4,
        },
        "real_model_run_status": "not_run_by_design",
        "training_status": "not_started_by_design",
        "blockers": ["test"],
        "next_decisions": [],
    }
    (reports / "status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    (reports / "inventory.json").write_text("{}", encoding="utf-8")
    with (reports / "migration.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(MIGRATION_HEADER)
        writer.writerow(
            [
                "src/egsi",
                "keep",
                "existing prototype",
                "18458b2cceaeef3cd18c8b455b1f0724d50d94c9",
                "",
                "present",
                "restore from base SHA",
            ]
        )
    (reports / "checks.json").write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "check_id": "c1",
                        "command": "true",
                        "started_at": "t0",
                        "finished_at": "t1",
                        "exit_code": 0,
                        "status": "pass",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (reports / "run_manifest.json").write_text(
        json.dumps(
            {
                "model_calls": 0,
                "detection_metrics": None,
                "detection_metrics_status": "not_evaluated",
            }
        ),
        encoding="utf-8",
    )
    (reports / "submission_checklist.md").write_text(
        "OpenReview: needs_human_confirmation\n", encoding="utf-8"
    )
    (root / "reports" / "latest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "round_id": "R01",
                "branch": "research/naacl2027-r01",
                "summary_path": "reports/rounds/R01/SUMMARY.md",
                "status_path": "reports/rounds/R01/status.json",
                "checks_path": "reports/rounds/R01/checks.json",
                "push_receipt_path": "reports/rounds/R01/push_receipt.json",
                "implementation_sha": None,
                "review_status": "pending",
            }
        ),
        encoding="utf-8",
    )


def test_validate_reports_pre_push_tmp(tmp_path: Path) -> None:
    _write_min_repo(tmp_path)
    result = validate_reports(tmp_path, "R01", "pre-push")
    assert result["valid"] is True
    assert result["counts"]["fixture_cases"] == 4
    assert result["counts"]["real_ready_pairs"] == 0
    assert result["status"]["review_status"] == "pending"


def test_validate_reports_rejects_count_mismatch(tmp_path: Path) -> None:
    _write_min_repo(tmp_path)
    path = tmp_path / "reports" / "rounds" / "R01" / "status.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["counts"]["candidate_pairs"] = 99
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="candidate_pairs"):
        validate_reports(tmp_path, "R01", "pre-push")

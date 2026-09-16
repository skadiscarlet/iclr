"""Machine-readable R01 report validation."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from sbs.registry import count_inventory, load_candidates, load_readiness


REQUIRED_ROUND_FILES = (
    "SUMMARY.md",
    "status.json",
    "inventory.json",
    "migration.csv",
    "checks.json",
    "run_manifest.json",
    "submission_checklist.md",
)

MIGRATION_HEADER = [
    "path",
    "decision",
    "reason",
    "base_sha",
    "replacement_path",
    "verification",
    "rollback_note",
]

CHECK_FIELDS = (
    "check_id",
    "command",
    "started_at",
    "finished_at",
    "exit_code",
    "status",
)

ALLOWED_ENG = {"not_started", "completed", "partial", "blocked"}
ALLOWED_DATA = {"not_started", "completed", "partial", "blocked"}
ALLOWED_DELIVERY = {"not_pushed", "checkpoint_verified", "failed"}
ALLOWED_REVIEW = {"pending", "accepted"}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_migration_csv(path: Path) -> None:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        if header != MIGRATION_HEADER:
            raise ValueError(f"migration.csv header mismatch: {header}")
        decisions = {"keep", "adapt", "archive_reference", "remove", "defer_unknown"}
        for row in reader:
            if not row:
                continue
            if row[1] not in decisions:
                raise ValueError(f"invalid migration decision: {row[1]}")


def validate_status(payload: dict[str, Any], *, phase: str) -> None:
    if payload.get("schema_version") != "1.0":
        raise ValueError("status.schema_version must be 1.0")
    if payload.get("round_id") != "R01":
        raise ValueError("status.round_id must be R01")
    if payload.get("engineering_status") not in ALLOWED_ENG:
        raise ValueError("invalid engineering_status")
    if payload.get("data_status") not in ALLOWED_DATA:
        raise ValueError("invalid data_status")
    if payload.get("delivery_status") not in ALLOWED_DELIVERY:
        raise ValueError("invalid delivery_status")
    if payload.get("review_status") != "pending":
        raise ValueError("agent must leave review_status=pending")
    if payload.get("assistant_repo_access") != "unverified_404":
        raise ValueError("assistant_repo_access must remain unverified_404")
    if payload.get("real_model_run_status") != "not_run_by_design":
        raise ValueError("real_model_run_status must be not_run_by_design")
    if payload.get("training_status") != "not_started_by_design":
        raise ValueError("training_status must be not_started_by_design")
    if phase == "pre-push" and payload.get("delivery_status") == "checkpoint_verified":
        raise ValueError("pre-push status cannot claim checkpoint_verified")


def validate_checks(payload: Any) -> None:
    if not isinstance(payload, dict) or "checks" not in payload:
        raise ValueError("checks.json must be an object with checks[]")
    for row in payload["checks"]:
        for field in CHECK_FIELDS:
            if field not in row:
                raise ValueError(f"checks row missing {field}")
        if row["status"] == "not_run" and not row.get("notes"):
            raise ValueError("not_run requires a reason in notes")
        if row["status"] != "not_run" and row.get("exit_code") is None:
            raise ValueError("run checks must record a real exit_code")


def validate_reports(repo: Path, round_id: str, phase: str) -> dict[str, Any]:
    if round_id != "R01":
        raise ValueError("only R01 is implemented")
    if phase not in {"pre-push", "post-push"}:
        raise ValueError("phase must be pre-push or post-push")
    round_dir = Path(repo) / "reports" / "rounds" / round_id
    missing = [name for name in REQUIRED_ROUND_FILES if not (round_dir / name).is_file()]
    receipt = round_dir / "push_receipt.json"
    latest = Path(repo) / "reports" / "latest.json"
    if not latest.is_file():
        missing.append("reports/latest.json")
    if phase == "post-push" and not receipt.is_file():
        missing.append("push_receipt.json")
    if missing:
        raise FileNotFoundError("missing report files: " + ", ".join(missing))
    status = _load_json(round_dir / "status.json")
    validate_status(status, phase=phase)
    checks = _load_json(round_dir / "checks.json")
    validate_checks(checks)
    validate_migration_csv(round_dir / "migration.csv")
    manifest = _load_json(round_dir / "run_manifest.json")
    if manifest.get("model_calls") != 0:
        raise ValueError("run_manifest.model_calls must be 0")
    if manifest.get("detection_metrics") not in (None,):
        raise ValueError("detection_metrics must be null")
    if manifest.get("detection_metrics_status") != "not_evaluated":
        raise ValueError("detection_metrics_status must be not_evaluated")
    candidates = load_candidates(Path(repo) / "metadata" / "r01_candidates.jsonl")
    readiness = load_readiness(Path(repo) / "metadata" / "r01_readiness.csv")
    fixtures_root = Path(repo) / "fixtures" / "r01"
    fixture_ids = sorted(p.name for p in fixtures_root.iterdir() if p.is_dir()) if fixtures_root.exists() else []
    counts = count_inventory(candidates, readiness, fixture_ids)
    reported = status.get("counts") or {}
    for key in (
        "candidate_pairs",
        "real_ready_pairs",
        "human_verified_pairs",
        "project_families",
        "fixture_cases",
    ):
        if reported.get(key) != counts[key]:
            raise ValueError(
                f"status.counts.{key}={reported.get(key)} != files {counts[key]}"
            )
    latest_payload = _load_json(latest)
    if latest_payload.get("round_id") != "R01":
        raise ValueError("latest.json round_id must be R01")
    if latest_payload.get("review_status") != "pending":
        raise ValueError("latest.json review_status must be pending")
    if phase == "post-push":
        receipt_payload = _load_json(receipt)
        if receipt_payload.get("remote_sha_match") not in {"yes", "no", "not_verified"}:
            raise ValueError("push_receipt.remote_sha_match invalid")
    return {
        "valid": True,
        "phase": phase,
        "counts": counts,
        "status": {
            "engineering_status": status["engineering_status"],
            "data_status": status["data_status"],
            "delivery_status": status["delivery_status"],
            "review_status": status["review_status"],
        },
    }

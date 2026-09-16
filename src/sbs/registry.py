"""Candidate registry loading and validation. Management-side only."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from sbs.schema import CandidatePair, SplitId


READY_STATUSES = frozenset({"evidence_draft", "source_resolved"})


def load_candidates(path: Path) -> list[CandidatePair]:
    rows: list[CandidatePair] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            try:
                payload = json.loads(raw)
                rows.append(CandidatePair.model_validate(payload))
            except (ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"{path}:{line_number}: invalid candidate") from exc
    pair_ids = [row.pair_id for row in rows]
    if len(pair_ids) != len(set(pair_ids)):
        raise ValueError("duplicate pair_id in registry")
    return rows


def assert_r01_split(rows: list[CandidatePair]) -> None:
    for row in rows:
        if row.split != "dev_pilot":
            raise ValueError(f"{row.pair_id} split is {row.split!r}, expected dev_pilot")


def human_verified_count(rows: list[CandidatePair]) -> int:
    return sum(1 for row in rows if row.status == "human_verified")


def load_readiness(path: Path) -> list[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "pair_id",
            "category_claim",
            "versions_locatable",
            "license_clear",
            "citation_range_exists",
            "actor_view_generated",
            "ready",
            "blocker",
            "split",
        }
        if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
            raise ValueError("readiness CSV missing required columns")
        return list(reader)


def count_inventory(
    candidates: list[CandidatePair],
    readiness: list[dict[str, str]],
    fixture_case_ids: list[str],
) -> dict[str, int]:
    families = {row.project_family for row in candidates}
    ready = [row for row in readiness if row.get("ready") == "yes"]
    return {
        "candidate_pairs": len(candidates),
        "real_ready_pairs": len(ready),
        "human_verified_pairs": human_verified_count(candidates),
        "project_families": len(families),
        "fixture_cases": len(fixture_case_ids),
        "real_registry_rows": len(candidates),
        "fixture_not_in_registry": len(fixture_case_ids),
    }


def validate_registry_file(path: Path) -> dict[str, Any]:
    rows = load_candidates(path)
    assert_r01_split(rows)
    if human_verified_count(rows) != 0:
        raise ValueError("human_verified is not allowed in automated R01 registry")
    null_locators = sum(1 for row in rows if row.source_locator is None)
    return {
        "valid": True,
        "candidate_pairs": len(rows),
        "project_families": len({row.project_family for row in rows}),
        "human_verified_pairs": 0,
        "null_source_locator_rows": null_locators,
        "split": "dev_pilot",
    }


def never_sets_human_verified(status: str) -> str:
    """Static-check helper: automated status may not become human_verified."""

    if status == "human_verified":
        raise ValueError("automated static check cannot set human_verified")
    return status

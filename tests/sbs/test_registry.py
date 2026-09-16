from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from sbs.registry import (
    count_inventory,
    human_verified_count,
    load_candidates,
    never_sets_human_verified,
    validate_registry_file,
)
from sbs.schema import CandidatePair
from sbs.static_check import classify_readiness, obligation_is_generic


REPO = Path(__file__).resolve().parents[2]


def test_r01_candidates_are_dev_pilot_and_not_human_verified() -> None:
    rows = load_candidates(REPO / "metadata" / "r01_candidates.jsonl")
    assert rows, "registry must contain real candidate rows"
    assert all(row.split == "dev_pilot" for row in rows)
    assert human_verified_count(rows) == 0
    for row in rows:
        assert row.status != "human_verified"


def test_human_verified_is_rejected_on_load() -> None:
    payload = {
        "pair_id": "r01-pair-xx",
        "project_family": "ex/p",
        "dataset_origin": "test",
        "dataset_revision": None,
        "source_locator": None,
        "buggy_revision": None,
        "fixed_revision": None,
        "category_claim": "conventional",
        "obligation_basis": None,
        "status": "human_verified",
        "license_note": None,
        "split": "dev_pilot",
        "blocker": None,
    }
    with pytest.raises(ValidationError):
        CandidatePair.model_validate(payload)


def test_static_check_never_sets_human_verified() -> None:
    status, ready, blocker = classify_readiness(
        category_claim="conventional",
        versions_locatable=True,
        license_clear=True,
        citation_range_exists=True,
        actor_view_generated=True,
        obligation_basis="family template ok for conventional",
    )
    assert status != "human_verified"
    assert never_sets_human_verified(status) == status
    with pytest.raises(ValueError):
        never_sets_human_verified("human_verified")
    logic_status, logic_ready, logic_blocker = classify_readiness(
        category_claim="logic_authorization_claim",
        versions_locatable=True,
        license_clear=True,
        citation_range_exists=True,
        actor_view_generated=True,
        obligation_basis="establish attacker principal, target resource, expected authorization relation, and missing or incorrect guard",
    )
    assert logic_ready == "no"
    assert logic_status != "human_verified"
    assert logic_blocker is not None and "obligation" in logic_blocker
    assert obligation_is_generic(logic_blocker) or "obligation" in logic_blocker


def test_fixture_and_real_counts_are_separate() -> None:
    rows = load_candidates(REPO / "metadata" / "r01_candidates.jsonl")
    readiness_path = REPO / "metadata" / "r01_readiness.csv"
    from sbs.registry import load_readiness

    readiness = load_readiness(readiness_path)
    fixture_ids = sorted(
        p.name for p in (REPO / "fixtures" / "r01").iterdir() if p.is_dir()
    )
    counts = count_inventory(rows, readiness, fixture_ids)
    assert counts["fixture_cases"] == 4
    assert counts["candidate_pairs"] == len(rows)
    assert counts["real_registry_rows"] == len(rows)
    assert counts["fixture_not_in_registry"] == 4
    assert counts["human_verified_pairs"] == 0
    # fixtures are not counted as real ready pairs
    assert counts["real_ready_pairs"] == sum(1 for row in readiness if row["ready"] == "yes")
    ready_ids = {row["pair_id"] for row in readiness if row["ready"] == "yes"}
    assert not ready_ids.intersection(set(fixture_ids))


def test_validate_registry_file_accepts_checked_in_registry() -> None:
    result = validate_registry_file(REPO / "metadata" / "r01_candidates.jsonl")
    assert result["valid"] is True
    assert result["human_verified_pairs"] == 0
    assert result["split"] == "dev_pilot"

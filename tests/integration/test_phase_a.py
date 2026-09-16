from __future__ import annotations

from collections import Counter
from pathlib import Path

from egsi.contracts.case import load_case_catalog


ROOT = Path(__file__).resolve().parents[2]

P0 = [
    "ghsa-2m8h-fgr8-2q9w", "ghsa-3wfj-vh84-732p", "ghsa-2j4q-9fff-236j",
    "ghsa-25gv-mvm7-5h3h", "ghsa-3hrc-f439-727g", "ghsa-2h63-qp69-fwvw",
    "ghsa-268v-2qq7-84pf", "ghsa-2hfj-jv6q-762v", "ghsa-2hw2-62cp-p9p7",
    "ghsa-3297-944x-j7x7",
]

P1 = [
    "ghsa-2m8h-fgr8-2q9w", "ghsa-2q4p-f6gf-mqr5", "ghsa-32xf-jwmv-9hf3",
    "ghsa-3wfj-vh84-732p", "ghsa-4m7p-55jm-3vwv", "ghsa-4qw8-pgpr-p9mq",
    "ghsa-2j4q-9fff-236j", "ghsa-3p62-6fjh-3p5h", "ghsa-3pqg-4rqg-pg9g",
    "ghsa-25gv-mvm7-5h3h", "ghsa-2chv-87wj-pjv2", "ghsa-4rjf-mxfm-98h5",
    "ghsa-3hrc-f439-727g", "ghsa-4jx2-hvqw-93j9", "ghsa-4rj6-9pjh-882r",
    "ghsa-2h63-qp69-fwvw", "ghsa-3p8v-w8mr-m3x8", "ghsa-3v67-545x-ffc3",
    "ghsa-268v-2qq7-84pf", "ghsa-2hfj-jv6q-762v", "ghsa-5993-wwpg-m92c",
    "ghsa-76v2-48w6-crxr", "ghsa-2hw2-62cp-p9p7", "ghsa-3g4c-hjhr-73rj",
    "ghsa-3hg6-c7f8-3348", "ghsa-5wm5-8q42-rhxg", "ghsa-3297-944x-j7x7",
    "ghsa-32mf-57h2-64x9", "ghsa-3jq8-jg75-rqv6", "ghsa-3w85-5p9g-h334",
]


def test_p0_and_p1_case_files_are_frozen_and_eligible() -> None:
    from egsi.generation.pilot import read_case_ids

    p0 = read_case_ids(ROOT / "configs/p0_cases.txt")
    p1 = read_case_ids(ROOT / "configs/p1_cases.txt")
    catalog = {case.case_id: case for case in load_case_catalog(ROOT / "data/catalog/cases.jsonl")}
    cases = [catalog[item] for item in p1]

    assert p0 == P0
    assert p1 == P1
    assert Counter(case.family for case in cases) == {"source_to_sink": 18, "authorization": 12}
    assert Counter(case.cwe_normalized_primary for case in cases) == {
        "CWE-22": 3,
        "CWE-78": 3,
        "CWE-79": 3,
        "CWE-89": 3,
        "CWE-611": 3,
        "CWE-918": 3,
        "CWE-639": 4,
        "CWE-862": 4,
        "CWE-863": 4,
    }
    assert len({case.repository.upstream_id for case in cases}) == 30
    assert all(case.split == "train" for case in cases)
    assert all(catalog[item].split != "time_ood_test" for item in p0)


def test_offline_p0_produces_honest_complete_report(tmp_path: Path) -> None:
    from egsi.generation.pilot import read_case_ids, run_pilot
    from egsi.teacher.fixture import FixtureTeacher

    report = run_pilot(
        ROOT,
        read_case_ids(ROOT / "configs/p0_cases.txt"),
        tmp_path / "p0",
        FixtureTeacher(),
    )

    assert report["requested"] == 10
    assert report["processed"] + report["failed"] == 10
    assert report["policy_oracle_leakage"] == 0
    assert report["nonzero_t1_rewards"] == 0
    assert report["selected_illegal_actions"] == 0
    assert report["event_replay_passed"] == report["processed"]
    assert (tmp_path / "p0/reports/pilot-summary.json").exists()

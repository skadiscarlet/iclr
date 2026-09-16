from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path

import pytest

from egsi.contracts.case import load_case_catalog
from egsi.contracts.enrichment import EnrichmentRecord
from egsi.generation.trajectory import read_parquet


ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "data/catalog/cases.jsonl"
REAL_CASE_ID = "ghsa-2m8h-fgr8-2q9w"


def _time_ood_id() -> str:
    return next(case.case_id for case in load_case_catalog(CATALOG) if case.split == "time_ood_test")


def test_read_case_ids_accepts_comments_and_rejects_invalid_inputs(tmp_path: Path) -> None:
    from egsi.generation.pilot import read_case_ids

    case_file = tmp_path / "cases.txt"
    case_file.write_text(
        "# frozen\n\n ghsa-2m8h-fgr8-2q9w  # primary\n"
        "ghsa-3wfj-vh84-732p\n",
        encoding="utf-8",
    )
    assert read_case_ids(case_file) == [REAL_CASE_ID, "ghsa-3wfj-vh84-732p"]

    for value, message in [
        ("# only comments\n", "empty"),
        (f"{REAL_CASE_ID}\n{REAL_CASE_ID}\n", "duplicate"),
        ("../escape\n", "invalid"),
    ]:
        case_file.write_text(value, encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            read_case_ids(case_file)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "oversize", "invalid_utf8"])
def test_read_case_ids_rejects_unsafe_or_unbounded_files(
    tmp_path: Path, kind: str
) -> None:
    from egsi.generation.pilot import read_case_ids

    source = tmp_path / "source.txt"
    source.write_text(f"{REAL_CASE_ID}\n", encoding="utf-8")
    case_file = tmp_path / "cases.txt"
    if kind == "symlink":
        case_file.symlink_to(source)
    elif kind == "hardlink":
        os.link(source, case_file)
    elif kind == "oversize":
        case_file.write_bytes(b"#" + b"x" * (64 * 1024) + b"\n")
    else:
        case_file.write_bytes(b"\xff\xfe\n")

    with pytest.raises(ValueError, match="case file"):
        read_case_ids(case_file)


def test_read_case_ids_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "cases.fifo"
    os.mkfifo(fifo)
    program = (
        "from pathlib import Path\n"
        "from egsi.generation.pilot import read_case_ids\n"
        f"p=Path({str(fifo)!r})\n"
        "try:\n"
        " read_case_ids(p)\n"
        "except ValueError:\n"
        " raise SystemExit(0)\n"
        "raise SystemExit(3)\n"
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-c", program],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            # The watchdog covers a fresh interpreter plus cold imports.  Keep
            # it comfortably above startup variance while still proving that
            # opening the FIFO cannot wait for a writer indefinitely.
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("read_case_ids blocked on a FIFO")
    assert completed.returncode == 0


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_batch_enrich_entry_rejects_unsafe_case_file_before_writing_output(
    tmp_path: Path, kind: str
) -> None:
    from typer.testing import CliRunner
    from egsi.cli import app

    source = tmp_path / "source.txt"
    source.write_text(f"{REAL_CASE_ID}\n", encoding="utf-8")
    case_file = tmp_path / "cases.txt"
    if kind == "symlink":
        case_file.symlink_to(source)
    else:
        os.link(source, case_file)
    output = tmp_path / "output"

    result = CliRunner().invoke(
        app,
        [
            "batch-enrich",
            "--root",
            str(ROOT),
            "--case-file",
            str(case_file),
            "--output-root",
            str(output),
            "--fixture-teacher",
        ],
    )

    assert result.exit_code == 1
    assert not output.exists()


def test_fixture_teacher_validates_both_families(tmp_path: Path) -> None:
    from egsi.generation.pilot import run_enrichment_batch
    from egsi.teacher.fixture import FixtureTeacher

    catalog = load_case_catalog(CATALOG)
    source = next(case.case_id for case in catalog if case.family == "source_to_sink" and case.split == "train")
    authorization = next(case.case_id for case in catalog if case.family == "authorization" and case.split == "train")
    teacher = FixtureTeacher()

    report = run_enrichment_batch(ROOT, [source, authorization], tmp_path / "out", teacher)

    assert report["requested"] == 2
    assert report["processed"] == 2
    assert report["failed"] == 0
    assert report["failures"] == {}
    assert report["provider_model_counts"] == {"fixture:fixture-v1": 2}
    assert report["provenance"]["requested_provider"] == "fixture"
    assert report["provenance"]["requested_model"] == "fixture-v1"
    assert report["provenance"]["provider_response_models"] == ["fixture-v1"]
    assert report["provenance"]["provider_response_model_counts"] == {"fixture-v1": 2}
    assert teacher.calls == 2
    for case_id in (source, authorization):
        record = EnrichmentRecord.model_validate_json(
            (tmp_path / "out/enrichment" / f"{case_id}.json").read_text(encoding="utf-8")
        )
        assert record.validation.valid is True
        assert record.provider == "fixture"
        assert "Fixture output" in record.payload.limitations[0]


def test_enrichment_restart_reuses_only_fully_valid_current_record(tmp_path: Path) -> None:
    from egsi.generation.pilot import run_enrichment_batch
    from egsi.teacher.fixture import FixtureTeacher

    output = tmp_path / "out"
    teacher = FixtureTeacher()
    first = run_enrichment_batch(ROOT, [REAL_CASE_ID], output, teacher)
    target = output / "enrichment" / f"{REAL_CASE_ID}.json"
    original = target.read_bytes()
    second = run_enrichment_batch(ROOT, [REAL_CASE_ID], output, teacher)

    assert first["cache_reused"] == 0
    assert second["cache_reused"] == 1
    assert teacher.calls == 1
    assert target.read_bytes() == original

    stale = json.loads(target.read_text(encoding="utf-8"))
    stale["case_id"] = "ghsa-bad0-bad0-bad0"
    target.write_text(json.dumps(stale), encoding="utf-8")
    third = run_enrichment_batch(ROOT, [REAL_CASE_ID], output, teacher)

    assert third["processed"] == 1
    assert third["cache_reused"] == 0
    assert teacher.calls == 2
    assert EnrichmentRecord.model_validate_json(target.read_text()).case_id == REAL_CASE_ID
    assert list((output / "enrichment/quarantine").glob(f"{REAL_CASE_ID}.*.json"))


def test_enrichment_corrupt_and_stale_records_are_regenerated(tmp_path: Path) -> None:
    from egsi.generation.pilot import run_enrichment_batch
    from egsi.teacher.fixture import FixtureTeacher

    output = tmp_path / "out"
    target = output / "enrichment" / f"{REAL_CASE_ID}.json"
    teacher = FixtureTeacher()
    run_enrichment_batch(ROOT, [REAL_CASE_ID], output, teacher)

    target.write_text("{corrupt", encoding="utf-8")
    corrupt = run_enrichment_batch(ROOT, [REAL_CASE_ID], output, teacher)
    assert corrupt["cache_reused"] == 0
    assert teacher.calls == 2

    stale = json.loads(target.read_text(encoding="utf-8"))
    stale["source_context_sha256"] = "sha256:" + "0" * 64
    target.write_text(json.dumps(stale), encoding="utf-8")
    stale_report = run_enrichment_batch(ROOT, [REAL_CASE_ID], output, teacher)
    assert stale_report["cache_reused"] == 0
    assert teacher.calls == 3
    assert EnrichmentRecord.model_validate_json(target.read_text()).source_context_sha256 != stale["source_context_sha256"]


def test_enrichment_isolates_unknown_and_time_ood_failures(tmp_path: Path) -> None:
    from egsi.generation.pilot import run_enrichment_batch
    from egsi.teacher.fixture import FixtureTeacher

    teacher = FixtureTeacher()
    ids = [REAL_CASE_ID, "ghsa-xxxx-xxxx-xxxx", _time_ood_id()]
    report = run_enrichment_batch(ROOT, ids, tmp_path / "out", teacher)

    assert report["requested"] == 3
    assert report["processed"] == 1
    assert report["failed"] == 2
    assert report["processed"] + report["failed"] == report["requested"]
    assert report["processed_case_ids"] == [REAL_CASE_ID]
    assert list(report["failures"]) == ids[1:]
    assert report["failures"][ids[1]]["stage"] == "catalog"
    assert report["failures"][ids[2]]["stage"] == "eligibility"
    assert teacher.calls == 1


def test_enrichment_recovers_a_structurally_damaged_raw_patch_from_pinned_git(
    tmp_path: Path,
) -> None:
    from egsi.generation.pilot import run_enrichment_batch
    from egsi.teacher.fixture import FixtureTeacher

    oversized_context_case = "ghsa-3wfj-vh84-732p"
    report = run_enrichment_batch(
        ROOT, [oversized_context_case], tmp_path / "out", FixtureTeacher()
    )

    assert report["processed"] == 1
    assert report["failed"] == 0
    assert report["failures"] == {}


def test_compile_trajectory_batch_roundtrips_and_reuses_episode(tmp_path: Path) -> None:
    from egsi.generation.pilot import compile_trajectory_batch, run_enrichment_batch
    from egsi.teacher.fixture import FixtureTeacher

    output = tmp_path / "out"
    enrichment = run_enrichment_batch(ROOT, [REAL_CASE_ID], output, FixtureTeacher())
    first = compile_trajectory_batch(
        ROOT,
        [REAL_CASE_ID],
        output / "enrichment",
        output,
        expected_provenance=enrichment["provenance"],
    )

    assert first["requested"] == first["processed"] == 1
    assert first["failed"] == 0
    assert first["episode_cache_reused"] == 0
    assert first["policy_oracle_leakage"] == 0
    assert first["nonzero_t1_rewards"] == 0
    assert first["selected_illegal_actions"] == 0
    assert first["event_replay_passed"] == 1
    assert first["dynamic_verdict"] == "not_applicable"
    assert first["fixture_input_records"] == 1
    assert first["promotable"] is False
    assert len(first["event_files"]) == 1
    event_path = output / first["event_files"][0]
    transition_path = event_path.with_name(event_path.name.replace(".events.jsonl", ".transitions.jsonl"))
    before = (event_path.read_bytes(), transition_path.read_bytes())

    parquet_rows = read_parquet(output / "trajectories/train.parquet")
    assert len(parquet_rows) == first["transitions"]
    assert all(
        all(value == 0.0 for key, value in row.reward_vector.model_dump().items() if key != "label_scope")
        for row in parquet_rows
    )

    second = compile_trajectory_batch(
        ROOT,
        [REAL_CASE_ID],
        output / "enrichment",
        output,
        expected_provenance=enrichment["provenance"],
    )
    assert second["episode_cache_reused"] == 1
    assert (event_path.read_bytes(), transition_path.read_bytes()) == before

    event_path.write_text("not-json\n", encoding="utf-8")
    third = compile_trajectory_batch(
        ROOT,
        [REAL_CASE_ID],
        output / "enrichment",
        output,
        expected_provenance=enrichment["provenance"],
    )
    assert third["processed"] == 1
    assert third["episode_cache_reused"] == 0
    assert event_path.read_bytes() == before[0]


def test_episode_metrics_reports_normalized_oracle_value_leakage(
    tmp_path: Path,
) -> None:
    from egsi.generation.enrichment import EnrichmentRunner
    from egsi.generation.pilot import _episode_metrics
    from egsi.generation.trajectory import compile_t1_episode
    from egsi.teacher.fixture import FixtureTeacher

    case = next(item for item in load_case_catalog(CATALOG) if item.case_id == REAL_CASE_ID)
    record = EnrichmentRunner(ROOT, FixtureTeacher(), max_repairs=0).run(
        case, tmp_path / "enrichment"
    )
    transitions, events = compile_t1_episode(case, record)
    transitions[0].observation["receipt"] = (
        "prefix-" + case.cwe_normalized_primary.swapcase() + "-suffix"
    )

    leakage, _, _ = _episode_metrics(case, record, transitions, events)
    assert leakage > 0


def test_compile_isolates_bad_enrichment_and_preserves_count(tmp_path: Path) -> None:
    from egsi.generation.pilot import compile_trajectory_batch, run_enrichment_batch
    from egsi.teacher.fixture import FixtureTeacher

    output = tmp_path / "out"
    bad = "ghsa-xxxx-xxxx-xxxx"
    enrichment = run_enrichment_batch(
        ROOT, [REAL_CASE_ID, bad], output, FixtureTeacher()
    )
    report = compile_trajectory_batch(
        ROOT,
        [REAL_CASE_ID, bad],
        output / "enrichment",
        output,
        expected_provenance=enrichment["provenance"],
    )

    assert report["requested"] == 2
    assert report["processed"] == 1
    assert report["failed"] == 1
    assert report["processed"] + report["failed"] == report["requested"]
    assert report["failures"][bad]["stage"] == "catalog"


def test_compile_fails_closed_on_committed_enrichment_tamper_without_output_mutation(tmp_path: Path) -> None:
    from egsi.generation.pilot import compile_trajectory_batch, run_enrichment_batch
    from egsi.teacher.fixture import FixtureTeacher

    output = tmp_path / "out"
    enrichment = run_enrichment_batch(ROOT, [REAL_CASE_ID], output, FixtureTeacher())
    compile_trajectory_batch(
        ROOT,
        [REAL_CASE_ID],
        output / "enrichment",
        output,
        expected_provenance=enrichment["provenance"],
    )
    aggregate = output / "trajectories/train.parquet"
    assert aggregate.exists()
    (output / "enrichment" / f"{REAL_CASE_ID}.json").write_text("corrupt", encoding="utf-8")

    before = aggregate.read_bytes()
    with pytest.raises(ValueError, match="commitment mismatch"):
        compile_trajectory_batch(
            ROOT,
            [REAL_CASE_ID],
            output / "enrichment",
            output,
            expected_provenance=enrichment["provenance"],
        )

    assert aggregate.read_bytes() == before


def test_run_pilot_preserves_original_failure_stage(tmp_path: Path) -> None:
    from egsi.generation.pilot import run_pilot
    from egsi.teacher.fixture import FixtureTeacher

    missing = "ghsa-xxxx-xxxx-xxxx"
    report = run_pilot(ROOT, [REAL_CASE_ID, missing], tmp_path / "out", FixtureTeacher())

    assert report["requested"] == 2
    assert report["processed"] == 1
    assert report["failed"] == 1
    assert report["processed"] + report["failed"] == report["requested"]
    assert report["failures"][missing]["stage"] == "catalog"
    assert report["trajectory"]["requested"] == 2


def test_run_pilot_reports_an_all_failure_batch_without_second_stage_loss(tmp_path: Path) -> None:
    from egsi.generation.pilot import run_pilot
    from egsi.teacher.fixture import FixtureTeacher

    missing = "ghsa-xxxx-xxxx-xxxx"
    output = tmp_path / "out"
    stale = output / "trajectories/train.parquet"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"stale")
    report = run_pilot(ROOT, [missing], output, FixtureTeacher())

    assert report["requested"] == 1
    assert report["processed"] == 0
    assert report["failed"] == 1
    assert report["failures"][missing]["stage"] == "catalog"
    assert report["trajectory"]["requested"] == 1
    assert report["trajectory"]["processed"] == 0
    assert report["trajectory"]["failed"] == 1
    assert report["event_replay_passed"] == 0
    assert not stale.exists()


def test_report_writer_rejects_symlink_and_cleans_failed_temp(tmp_path: Path, monkeypatch) -> None:
    from egsi.generation import pilot

    outside = tmp_path / "outside.json"
    outside.write_text("sentinel", encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(outside)
    with pytest.raises(ValueError):
        pilot.write_report(linked, {"ok": True})
    assert outside.read_text(encoding="utf-8") == "sentinel"

    target = tmp_path / "report.json"
    real_replace = os.replace

    def fail_before_replace(*args, **kwargs):
        raise OSError("synthetic")

    monkeypatch.setattr("egsi.generation.trajectory.os.replace", fail_before_replace)
    with pytest.raises(OSError):
        pilot.write_report(target, {"ok": True})
    monkeypatch.setattr("egsi.generation.trajectory.os.replace", real_replace)
    assert list(tmp_path.glob(".*.tmp")) == []


def test_batch_outputs_never_follow_symlinked_artifact_directories(tmp_path: Path) -> None:
    from egsi.generation.pilot import compile_trajectory_batch, run_enrichment_batch
    from egsi.teacher.fixture import FixtureTeacher

    outside_enrichment = tmp_path / "outside-enrichment"
    outside_enrichment.mkdir()
    enrich_output = tmp_path / "enrich-output"
    enrich_output.mkdir()
    (enrich_output / "enrichment").symlink_to(outside_enrichment, target_is_directory=True)
    with pytest.raises((OSError, ValueError)):
        run_enrichment_batch(ROOT, [REAL_CASE_ID], enrich_output, FixtureTeacher())
    assert list(outside_enrichment.iterdir()) == []

    good_output = tmp_path / "good"
    good_enrichment = run_enrichment_batch(
        ROOT, [REAL_CASE_ID], good_output, FixtureTeacher()
    )
    trajectory_output = tmp_path / "trajectory-output"
    outside_episodes = tmp_path / "outside-episodes"
    trajectory_output.mkdir()
    outside_episodes.mkdir()
    (trajectory_output / "episodes").symlink_to(outside_episodes, target_is_directory=True)
    with pytest.raises((OSError, ValueError)):
        compile_trajectory_batch(
            ROOT,
            [REAL_CASE_ID],
            good_output / "enrichment",
            trajectory_output,
            expected_provenance=good_enrichment["provenance"],
        )
    assert list(outside_episodes.iterdir()) == []


def test_fixture_output_guard_allows_only_work_or_system_temp(tmp_path: Path) -> None:
    from egsi.generation.pilot import validate_fixture_output_root

    assert validate_fixture_output_root(ROOT, ROOT / ".work/task13-guard") == (
        ROOT / ".work/task13-guard"
    ).resolve()
    assert validate_fixture_output_root(ROOT, tmp_path / "allowed") == (
        tmp_path / "allowed"
    ).resolve()

    for forbidden in (ROOT / "ordinary-output", ROOT / "data/derived"):
        with pytest.raises(
            ValueError,
            match="fixture output root is outside .work or the system temporary root",
        ):
            validate_fixture_output_root(ROOT, forbidden)

    link = tmp_path / "escape"
    link.symlink_to(ROOT, target_is_directory=True)
    with pytest.raises(ValueError, match="fixture output root"):
        validate_fixture_output_root(ROOT, link / "ordinary-output")


def test_fixture_batch_checks_output_boundary_before_generation(
    monkeypatch,
) -> None:
    from egsi.generation import pilot
    from egsi.teacher.fixture import FixtureTeacher

    called = False

    def forbidden_run(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("fixture boundary was checked too late")

    monkeypatch.setattr(pilot.EnrichmentRunner, "run", forbidden_run)
    monkeypatch.setattr(pilot, "write_report", lambda *args, **kwargs: None)
    with pytest.raises(ValueError, match="fixture output root"):
        pilot.run_enrichment_batch(
            ROOT,
            [REAL_CASE_ID],
            ROOT / "ordinary-output",
            FixtureTeacher(),
        )
    assert called is False


def test_fixture_output_guard_cannot_be_bypassed_by_teacher_wrapper() -> None:
    from egsi.generation.pilot import guard_fixture_teacher_output

    class WrappedFixture:
        provider = "fixture"
        model = "fixture-v1"

    with pytest.raises(ValueError, match="fixture output root"):
        guard_fixture_teacher_output(
            ROOT,
            ROOT / "ordinary-output",
            WrappedFixture(),  # type: ignore[arg-type]
        )


def test_fixture_trajectory_preflights_mixed_batch_before_any_writer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from egsi.generation import pilot
    from egsi.teacher.fixture import FixtureTeacher

    catalog = load_case_catalog(CATALOG)
    source = next(
        case.case_id
        for case in catalog
        if case.family == "source_to_sink" and case.split == "train"
    )
    authorization = next(
        case.case_id
        for case in catalog
        if case.family == "authorization" and case.split == "train"
    )
    ids = [source, authorization]
    input_output = tmp_path / "fixture-input"
    enrichment = pilot.run_enrichment_batch(
        ROOT, ids, input_output, FixtureTeacher()
    )
    assert enrichment["processed_case_ids"] == ids

    real_path = input_output / "enrichment" / f"{source}.json"
    real_record = EnrichmentRecord.model_validate_json(real_path.read_bytes()).model_copy(
        update={"provider": "openai-compatible", "model": "real-model"}
    )
    real_path.write_text(real_record.model_dump_json(), encoding="utf-8")

    writer_calls: list[str] = []

    def forbidden_writer(*args, **kwargs):
        writer_calls.append("called")
        raise AssertionError("fixture trajectory boundary was checked too late")

    for name in (
        "write_jsonl",
        "write_parquet",
        "write_report",
        "_remove_regular_if_present",
    ):
        monkeypatch.setattr(pilot, name, forbidden_writer)

    forbidden = ROOT / "ordinary-trajectory-output"
    with pytest.raises(
        ValueError,
        match="fixture output root is outside .work or the system temporary root",
    ):
        pilot.compile_trajectory_batch(
            ROOT,
            ids,
            input_output / "enrichment",
            forbidden,
            expected_provenance=enrichment["provenance"],
        )

    assert writer_calls == []
    assert not forbidden.exists()


def test_fixture_record_relabel_cannot_be_compiled_as_live_before_any_writer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from egsi.generation import pilot
    from egsi.teacher.fixture import FixtureTeacher

    output = tmp_path / "fixture-input"
    report = pilot.run_enrichment_batch(
        ROOT, [REAL_CASE_ID], output, FixtureTeacher()
    )
    target = output / "enrichment" / f"{REAL_CASE_ID}.json"
    relabeled = json.loads(target.read_text(encoding="utf-8"))
    relabeled["provider"] = "openai-compatible"
    relabeled["model"] = "gpt-live-like"
    target.write_text(json.dumps(relabeled), encoding="utf-8")

    writer_calls: list[str] = []

    def forbidden_writer(*args, **kwargs):
        writer_calls.append("called")
        raise AssertionError("untrusted relabel reached a writer")

    for name in (
        "write_jsonl",
        "write_parquet",
        "write_report",
        "_remove_regular_if_present",
    ):
        monkeypatch.setattr(pilot, name, forbidden_writer)

    expectation = report.get(
        "provenance",
        {
            "generation_mode": "fixture",
            "provider": "fixture",
            "model": "fixture-v1",
            "manifest_sha256": "sha256:" + "0" * 64,
        },
    )
    forbidden = ROOT / "ordinary-relabeled-trajectory-output"
    with pytest.raises(ValueError):
        pilot.compile_trajectory_batch(
            ROOT,
            [REAL_CASE_ID],
            output / "enrichment",
            forbidden,
            expected_provenance=expectation,
        )

    assert writer_calls == []
    assert not forbidden.exists()


@pytest.mark.parametrize(
    "target_kind,field,value",
    [
        ("record", "generation_mode", "live"),
        ("record", "provider", "openai-compatible"),
        ("record", "record_commitment_sha256", "sha256:" + "1" * 64),
        ("manifest", "generation_mode", "live"),
        ("manifest", "provider", "openai-compatible"),
        ("manifest", "batch_commitment_sha256", "sha256:" + "2" * 64),
        ("artifact", "file_sha256", "sha256:" + "3" * 64),
        ("expectation", "generation_mode", "live"),
        ("expectation", "provider", "openai-compatible"),
        ("expectation", "batch_commitment_sha256", "sha256:" + "4" * 64),
    ],
)
def test_provenance_marker_provider_mode_and_commitments_fail_closed(
    tmp_path: Path,
    monkeypatch,
    target_kind: str,
    field: str,
    value: str,
) -> None:
    from egsi.generation import pilot
    from egsi.teacher.fixture import FixtureTeacher

    output = tmp_path / "input"
    report = pilot.run_enrichment_batch(
        ROOT, [REAL_CASE_ID], output, FixtureTeacher()
    )
    expectation = dict(report["provenance"])
    record_path = output / "enrichment" / f"{REAL_CASE_ID}.json"
    manifest_path = output / "enrichment/_batch-provenance.json"
    if target_kind == "record":
        modified = json.loads(record_path.read_text(encoding="utf-8"))
        modified[field] = value
        record_path.write_text(json.dumps(modified), encoding="utf-8")
    elif target_kind in {"manifest", "artifact"}:
        modified = json.loads(manifest_path.read_text(encoding="utf-8"))
        if target_kind == "artifact":
            modified["artifacts"][0][field] = value
        else:
            modified[field] = value
        manifest_path.write_text(json.dumps(modified), encoding="utf-8")
    else:
        expectation[field] = value

    writer_calls: list[str] = []

    def forbidden_writer(*args, **kwargs):
        writer_calls.append("called")
        raise AssertionError("invalid provenance reached a writer")

    for name in (
        "write_jsonl",
        "write_parquet",
        "write_report",
        "_remove_regular_if_present",
    ):
        monkeypatch.setattr(pilot, name, forbidden_writer)

    with pytest.raises(ValueError):
        pilot.compile_trajectory_batch(
            ROOT,
            [REAL_CASE_ID],
            output / "enrichment",
            tmp_path / "compiled",
            expected_provenance=expectation,
        )
    assert writer_calls == []


def test_duplicate_failure_provenance_is_rejected_before_any_writer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from egsi.generation import pilot
    from egsi.teacher.base import TeacherRequest, TeacherResponse, committed_teacher_response
    from egsi.teacher.fixture import FixtureTeacher

    class InvalidFixtureTeacher(FixtureTeacher):
        def generate(self, request: TeacherRequest) -> TeacherResponse:
            self.calls += 1
            return committed_teacher_response(
                provider_request_id=f"invalid-fixture-{self.calls}",
                provider=self.provider,
                model=self.model,
                requested_model=self.model,
                provider_response_model=self.model,
                text="not-json",
                usage={},
                latency_ms=0.0,
            )

    authorization_case = next(
        case.case_id
        for case in load_case_catalog(CATALOG)
        if case.family == "authorization" and case.split == "train"
    )
    ids = [REAL_CASE_ID, authorization_case]
    output = tmp_path / "input"
    report = pilot.run_enrichment_batch(ROOT, ids, output, InvalidFixtureTeacher())
    manifest_path = output / "enrichment/_batch-provenance.json"
    manifest = json.loads(manifest_path.read_bytes())
    failure_entry = next(
        entry for entry in manifest["artifacts"] if entry["kind"] == "failure_receipt"
    )
    manifest["artifacts"] = [dict(failure_entry), dict(failure_entry)]
    manifest["batch_commitment_sha256"] = pilot._dict_commitment(
        manifest, "batch_commitment_sha256"
    )
    pilot.write_report(manifest_path, manifest)
    expectation = dict(report["provenance"])
    expectation["batch_commitment_sha256"] = manifest["batch_commitment_sha256"]
    expectation["manifest_sha256"] = pilot._sha256(manifest_path.read_bytes())

    writer_calls: list[str] = []

    def forbidden_writer(*args, **kwargs):
        writer_calls.append("called")
        raise AssertionError("duplicate provenance reached a writer")

    for name in (
        "write_jsonl",
        "write_parquet",
        "write_report",
        "_remove_regular_if_present",
    ):
        monkeypatch.setattr(pilot, name, forbidden_writer)

    with pytest.raises(ValueError, match="duplicate"):
        pilot.compile_trajectory_batch(
            ROOT,
            ids,
            output / "enrichment",
            tmp_path / "compiled",
            expected_provenance=expectation,
        )

    assert writer_calls == []


def test_live_like_teacher_generates_trusted_promotable_batch_without_relabel(
    tmp_path: Path,
) -> None:
    from egsi.generation.pilot import compile_trajectory_batch, run_enrichment_batch
    from egsi.teacher.base import TeacherRequest, TeacherResponse, committed_teacher_response
    from egsi.teacher.fixture import FixtureTeacher

    class LiveLikeTeacher:
        provider = "openai-compatible"
        model = "gpt-live-like"

        def __init__(self) -> None:
            self.fixture = FixtureTeacher()

        def generate(self, request: TeacherRequest) -> TeacherResponse:
            fixture = self.fixture.generate(request)
            return committed_teacher_response(
                provider_request_id=f"live-like-{self.fixture.calls}",
                provider=self.provider,
                model=self.model,
                requested_model=self.model,
                provider_response_model="gpt-live-like-actual-r1",
                text=fixture.text,
                usage={"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                latency_ms=1.0,
            )

    input_output = tmp_path / "live-input"
    enrichment = run_enrichment_batch(
        ROOT, [REAL_CASE_ID], input_output, LiveLikeTeacher()
    )
    assert enrichment["generation_mode"] == "live"
    assert enrichment["provenance"]["generation_mode"] == "live"
    assert enrichment["provenance"]["requested_model"] == "gpt-live-like"
    assert enrichment["provenance"]["provider_response_models"] == ["gpt-live-like-actual-r1"]
    assert enrichment["provenance"]["provider_response_model_counts"] == {"gpt-live-like-actual-r1": 1}
    record = EnrichmentRecord.model_validate_json(
        (input_output / "enrichment" / f"{REAL_CASE_ID}.json").read_bytes()
    )
    assert record.generation_mode == "live"
    assert record.requested_model == "gpt-live-like"
    assert record.provider_response_model == "gpt-live-like-actual-r1"
    assert record.record_commitment_sha256.startswith("sha256:")

    unbound_output_container = ROOT / "dist"
    assert unbound_output_container.is_dir()
    assert not unbound_output_container.is_symlink()
    root_before = ROOT.lstat()
    ordinary = unbound_output_container / (
        f"ordinary-live-like-trajectory-output-{os.getpid()}-{tmp_path.name}"
    )
    assert not ordinary.exists() and not ordinary.is_symlink()
    try:
        compiled = compile_trajectory_batch(
            ROOT,
            [REAL_CASE_ID],
            input_output / "enrichment",
            ordinary,
            expected_provenance=enrichment["provenance"],
        )
        assert compiled["promotable"] is True
        assert compiled["generation_mode"] == "live"
        assert compiled["artifact_manifest_sha256"].startswith("sha256:")
    finally:
        shutil.rmtree(ordinary, ignore_errors=True)
    root_after = ROOT.lstat()
    assert (
        root_after.st_mtime_ns,
        root_after.st_ctime_ns,
    ) == (
        root_before.st_mtime_ns,
        root_before.st_ctime_ns,
    )


def test_concurrent_compile_transactions_cannot_publish_mismatched_report_and_parquet(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from egsi.generation import pilot
    from egsi.teacher.fixture import FixtureTeacher

    case_a, case_b = REAL_CASE_ID, "ghsa-2j4q-9fff-236j"
    input_a = tmp_path / "input-a"
    input_b = tmp_path / "input-b"
    enrichment_a = pilot.run_enrichment_batch(
        ROOT, [case_a], input_a, FixtureTeacher()
    )
    enrichment_b = pilot.run_enrichment_batch(
        ROOT, [case_b], input_b, FixtureTeacher()
    )
    output = tmp_path / "shared-output"
    paused = threading.Event()
    release = threading.Event()
    original_write_report = pilot.write_report

    def pause_a_report(path: Path, report: dict[str, object]) -> None:
        if (
            path.name == "trajectory-validation.json"
            and report.get("processed_case_ids") == [case_a]
            and not paused.is_set()
        ):
            paused.set()
            assert release.wait(10)
        original_write_report(path, report)

    monkeypatch.setattr(pilot, "write_report", pause_a_report)
    with ThreadPoolExecutor(max_workers=2) as pool:
        future_a = pool.submit(
            pilot.compile_trajectory_batch,
            ROOT,
            [case_a],
            input_a / "enrichment",
            output,
            expected_provenance=enrichment_a["provenance"],
        )
        assert paused.wait(10)
        future_b = pool.submit(
            pilot.compile_trajectory_batch,
            ROOT,
            [case_b],
            input_b / "enrichment",
            output,
            expected_provenance=enrichment_b["provenance"],
        )
        try:
            future_b.result(timeout=2)
        except FutureTimeout:
            pass
        finally:
            release.set()
        future_a.result(timeout=10)
        future_b.result(timeout=10)

    final_report = json.loads(
        (output / "reports/trajectory-validation.json").read_text(encoding="utf-8")
    )
    from egsi.generation.redaction import policy_case_id

    catalog_by_id = {item.case_id: item for item in load_case_catalog(CATALOG)}
    parquet_cases = {
        row.state["case_id"]
        for row in read_parquet(output / "trajectories/train.parquet")
    }
    assert {
        policy_case_id(catalog_by_id[case_id])
        for case_id in final_report["processed_case_ids"]
    } == parquet_cases


def test_concurrent_enrichment_invalidates_older_compilation_transaction(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from egsi.generation import pilot
    from egsi.teacher.fixture import FixtureTeacher

    case_a, case_b = REAL_CASE_ID, "ghsa-2j4q-9fff-236j"
    output = tmp_path / "shared-output"
    enrichment_a = pilot.run_enrichment_batch(
        ROOT, [case_a], output, FixtureTeacher()
    )
    paused = threading.Event()
    release = threading.Event()
    original_write_report = pilot.write_report

    def pause_trajectory_report(path: Path, report: dict[str, object]) -> None:
        if path.name == "trajectory-validation.json" and not paused.is_set():
            paused.set()
            assert release.wait(10)
        original_write_report(path, report)

    monkeypatch.setattr(pilot, "write_report", pause_trajectory_report)
    with ThreadPoolExecutor(max_workers=2) as pool:
        compiled = pool.submit(
            pilot.compile_trajectory_batch,
            ROOT,
            [case_a],
            output / "enrichment",
            output,
            expected_provenance=enrichment_a["provenance"],
        )
        assert paused.wait(10)
        enriched = pool.submit(
            pilot.run_enrichment_batch,
            ROOT,
            [case_b],
            output,
            FixtureTeacher(),
        )
        try:
            enriched.result(timeout=2)
        except FutureTimeout:
            pass
        finally:
            release.set()
        compiled.result(timeout=10)
        enrichment_b = enriched.result(timeout=10)

    trajectory_report = output / "reports/trajectory-validation.json"
    if trajectory_report.exists():
        final_trajectory = json.loads(trajectory_report.read_text(encoding="utf-8"))
        assert (
            final_trajectory["provenance"]["manifest_sha256"]
            == enrichment_b["provenance"]["manifest_sha256"]
        )


@pytest.mark.parametrize("kind", ["symlink", "fifo", "hardlink"])
def test_batch_lock_rejects_unsafe_entries_without_teacher_or_external_write(
    tmp_path: Path,
    kind: str,
) -> None:
    from egsi.generation.pilot import run_enrichment_batch
    from egsi.teacher.fixture import FixtureTeacher

    output = tmp_path / "output"
    output.mkdir()
    lock = output / ".egsi-batch.lock"
    outside = tmp_path / "outside"
    outside.write_text("sentinel", encoding="utf-8")
    if kind == "symlink":
        lock.symlink_to(outside)
    elif kind == "fifo":
        os.mkfifo(lock)
    else:
        os.link(outside, lock)
    teacher = FixtureTeacher()

    with pytest.raises(ValueError, match="batch lock"):
        run_enrichment_batch(ROOT, [REAL_CASE_ID], output, teacher)

    assert teacher.calls == 0
    assert outside.read_text(encoding="utf-8") == "sentinel"


def test_bounded_reader_rejects_hardlinked_input(tmp_path: Path) -> None:
    from egsi.generation.pilot import _read_regular

    original = tmp_path / "original.json"
    linked = tmp_path / "linked.json"
    original.write_bytes(b"{}")
    os.link(original, linked)

    with pytest.raises(ValueError, match="bounded regular"):
        _read_regular(linked)


def test_bounded_reader_opens_fifo_nonblocking_and_rejects_it(
    tmp_path: Path,
) -> None:
    import subprocess
    import sys

    fifo = tmp_path / "input.fifo"
    os.mkfifo(fifo)
    command = [
        sys.executable,
        "-c",
        (
            "from pathlib import Path; "
            "from egsi.generation.pilot import _read_regular; "
            f"_read_regular(Path({str(fifo)!r}))"
        ),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        timeout=2,
        check=False,
    )

    assert completed.returncode != 0
    assert b"bounded regular" in completed.stderr


def test_bounded_reader_rejects_metadata_change_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from egsi.generation import pilot

    target = tmp_path / "changing.bin"
    target.write_bytes(b"A" * (2 * 1024 * 1024))
    original_read = pilot.os.read
    changed = False

    def mutate_after_first_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        chunk = original_read(descriptor, size)
        if chunk and not changed:
            changed = True
            os.utime(target, ns=(target.stat().st_atime_ns, target.stat().st_mtime_ns + 1))
        return chunk

    monkeypatch.setattr(pilot.os, "read", mutate_after_first_read)

    with pytest.raises(ValueError, match="bounded regular"):
        pilot._read_regular(target, limit=3 * 1024 * 1024)


def test_public_batch_releases_lock_fds_and_context_after_transaction_exception(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from egsi.generation import pilot
    from egsi.generation.safeio import active_batch_lock
    from egsi.teacher.fixture import FixtureTeacher

    output = tmp_path / "output"
    original_locked_entry = pilot._run_enrichment_batch_locked
    observed: dict[str, object] = {}

    def fail_inside_transaction(root, case_ids, output_root, teacher):
        lock = active_batch_lock(Path(output_root))
        assert lock is not None
        assert lock.root_fd is not None
        assert lock.lock_fd is not None
        observed.update(
            lock=lock,
            root_fd=lock.root_fd,
            lock_fd=lock.lock_fd,
        )
        raise RuntimeError("forced transaction failure")

    monkeypatch.setattr(pilot, "_run_enrichment_batch_locked", fail_inside_transaction)
    with pytest.raises(RuntimeError, match="forced transaction failure"):
        pilot.run_enrichment_batch(ROOT, [REAL_CASE_ID], output, FixtureTeacher())

    lock = observed["lock"]
    assert lock.root_fd is None
    assert lock.lock_fd is None
    assert active_batch_lock(output) is None
    for descriptor in (observed["root_fd"], observed["lock_fd"]):
        with pytest.raises(OSError):
            os.fstat(descriptor)

    monkeypatch.setattr(pilot, "_run_enrichment_batch_locked", original_locked_entry)
    report = pilot.run_enrichment_batch(
        ROOT, [REAL_CASE_ID], output, FixtureTeacher()
    )
    assert report["processed_case_ids"] == [REAL_CASE_ID]


@pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(),
    reason="stable descriptor accounting requires Linux /proc/self/fd",
)
def test_real_safeio_contexts_do_not_leak_fds_on_success_or_exception(
    tmp_path: Path,
) -> None:
    import gc

    from egsi.generation.safeio import AnchoredDirectory, BatchLock, active_batch_lock

    output = tmp_path / "fd-loop"

    def exercise(*, fail: bool) -> None:
        lock = BatchLock(output)
        anchored = None
        try:
            with lock:
                with AnchoredDirectory(
                    output / "artifacts", subdirectories=("nested",)
                ) as anchored:
                    if fail:
                        raise RuntimeError("forced body failure")
        except RuntimeError as exc:
            assert fail
            assert str(exc) == "forced body failure"
        assert lock.root_fd is None
        assert lock.lock_fd is None
        assert anchored is not None and anchored.root_fd == -1
        assert active_batch_lock(output) is None

    for _ in range(4):
        exercise(fail=False)
        exercise(fail=True)
    gc.collect()
    baseline = len(os.listdir("/proc/self/fd"))

    for _ in range(32):
        exercise(fail=False)
        exercise(fail=True)
    gc.collect()

    assert len(os.listdir("/proc/self/fd")) == baseline


def test_smaller_restart_publishes_only_current_manifest_artifacts_and_cleans_orphans(
    tmp_path: Path,
) -> None:
    from egsi.generation.pilot import run_pilot
    from egsi.teacher.fixture import FixtureTeacher

    case_a, case_b = REAL_CASE_ID, "ghsa-2j4q-9fff-236j"
    output = tmp_path / "output"
    first = run_pilot(
        ROOT, [case_a, case_b], output, FixtureTeacher()
    )
    assert first["processed_case_ids"] == [case_a, case_b]

    stale_receipt = output / "enrichment/failures" / f"{case_b}.json"
    stale_receipt.write_text('{"stale":true}\n', encoding="utf-8")
    for orphan in (
        output / "enrichment/.record.orphan.tmp",
        output / "enrichment/failures/.failure.orphan.tmp",
        output / "episodes/.episode.orphan.tmp",
        output / "trajectories/.aggregate.orphan.tmp",
        output / "reports/.report.orphan.tmp",
    ):
        orphan.parent.mkdir(parents=True, exist_ok=True)
        orphan.write_text("orphan", encoding="utf-8")

    second = run_pilot(ROOT, [case_a], output, FixtureTeacher())
    assert second["processed_case_ids"] == [case_a]
    assert not (output / "enrichment" / f"{case_b}.json").exists()
    assert not stale_receipt.exists()

    episode_files = {
        path.relative_to(output).as_posix()
        for path in (output / "episodes").iterdir()
        if path.is_file()
    }
    expected_events = set(second["trajectory"]["event_files"])
    expected_pairs = expected_events | {
        name.replace(".events.jsonl", ".transitions.jsonl")
        for name in expected_events
    }
    assert episode_files == expected_pairs
    from egsi.generation.redaction import policy_case_id

    assert {
        row.state["case_id"]
        for row in read_parquet(output / "trajectories/train.parquet")
    } == {policy_case_id(next(item for item in load_case_catalog(CATALOG) if item.case_id == case_a))}

    artifact_manifest_path = output / second["trajectory"]["artifact_manifest_file"]
    raw_manifest = artifact_manifest_path.read_bytes()
    assert "sha256:" + __import__("hashlib").sha256(raw_manifest).hexdigest() == second["trajectory"]["artifact_manifest_sha256"]
    artifact_manifest = json.loads(raw_manifest)
    manifest_paths = {
        entry["relative_path"] for entry in artifact_manifest["artifacts"]
    }
    assert manifest_paths == expected_pairs | {"trajectories/train.parquet"}
    for entry in artifact_manifest["artifacts"]:
        raw = (output / entry["relative_path"]).read_bytes()
        assert "sha256:" + __import__("hashlib").sha256(raw).hexdigest() == entry["sha256"]
        assert entry["kind"] in {
            "episode_events",
            "episode_transitions",
            "trajectory_parquet",
        }

    assert not list(output.rglob(".*.tmp"))

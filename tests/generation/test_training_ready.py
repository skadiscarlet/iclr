from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from egsi.teacher import TeacherRequest, TeacherResponse, committed_teacher_response
from egsi.teacher.fixture import FixtureTeacher


ROOT = Path(__file__).resolve().parents[2]
P0_IDS = (ROOT / "configs/p0_cases.txt").read_text(encoding="utf-8").splitlines()
FIRST = P0_IDS[0]
SECOND = P0_IDS[1]


class LiveFixturePayloadTeacher:
    provider = "codex_exec"
    model = "test-live-model"

    def __init__(self, script: list[str] | None = None) -> None:
        self.fixture = FixtureTeacher()
        self.calls = 0
        self.script = iter(script) if script is not None else None

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        self.calls += 1
        action = "valid" if self.script is None else next(self.script)
        if action == "transport":
            raise RuntimeError("synthetic transport failure")
        if action == "structured_invalid":
            return committed_teacher_response(
                provider_request_id=f"synthetic-live-{self.calls}",
                provider=self.provider,
                model=self.model,
                requested_model=self.model,
                provider_response_model=self.model,
                text="{}",
                usage={"output_tokens": 1},
                latency_ms=1.0,
            )
        assert action == "valid"
        fixture = self.fixture.generate(request)
        return committed_teacher_response(
            provider_request_id=f"synthetic-live-{self.calls}",
            provider=self.provider,
            model=self.model,
            requested_model=self.model,
            provider_response_model=self.model,
            text=fixture.text,
            usage=fixture.usage,
            latency_ms=1.0,
        )


@pytest.mark.parametrize("source_kind", ["historical", "batch"])
@pytest.mark.parametrize(
    "relationship", ["equal", "output_inside_source", "source_inside_output"]
)
def test_training_ready_rejects_output_source_overlap_before_lock_or_write(
    tmp_path: Path,
    source_kind: str,
    relationship: str,
) -> None:
    from egsi.generation.training_ready import build_training_ready

    base = tmp_path / f"{source_kind}-{relationship}"
    if relationship == "equal":
        source = output = base / "shared"
    elif relationship == "output_inside_source":
        source = base / "source"
        output = source / "nested-output"
    else:
        output = base / "output"
        source = output / "nested-source"
    historical = source if source_kind == "historical" else base / "historical"
    batch = source if source_kind == "batch" else base / "batch"
    sentinel = source / "enrichment" / "source-sentinel.bin"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_bytes(b"source bytes must survive overlap rejection\x00\xff")
    before = hashlib.sha256(sentinel.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="overlap"):
        build_training_ready(
            root=ROOT,
            case_ids=P0_IDS,
            historical_root=historical,
            batch_root=batch,
            output_root=output,
        )

    assert sentinel.is_file()
    assert hashlib.sha256(sentinel.read_bytes()).hexdigest() == before
    assert not (output / ".egsi-batch.lock").exists()


def _batch_with_second_record(tmp_path: Path) -> Path:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    batch_root = tmp_path / "batch"
    teacher = LiveFixturePayloadTeacher(
        ["valid", "transport", "transport", *("valid" for _ in range(7))]
    )
    run_pragmatic_batch(
        ROOT,
        P0_IDS[1:],
        batch_root,
        teacher,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    for case_id in P0_IDS[2:]:
        (batch_root / "enrichment" / f"{case_id}.json").unlink(missing_ok=True)
    return batch_root


def _complete_pragmatic_batch(tmp_path: Path, *, live: bool) -> Path:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    batch_root = tmp_path / ("live-batch" if live else "fixture-batch")
    teacher = LiveFixturePayloadTeacher() if live else FixtureTeacher()
    run_pragmatic_batch(
        ROOT,
        P0_IDS[1:],
        batch_root,
        teacher,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    return batch_root


def _stale_historical_copy(tmp_path: Path) -> Path:
    historical = tmp_path / "historical"
    target = historical / "enrichment" / f"{FIRST}.json"
    target.parent.mkdir(parents=True)
    value = json.loads(
        (
            ROOT
            / ".work/real-p0-codex-v2/enrichment"
            / f"{FIRST}.json"
        ).read_text(encoding="utf-8")
    )
    value["source_context_sha256"] = "sha256:" + "0" * 64
    target.write_text(json.dumps(value), encoding="utf-8")
    return historical


def test_historical_v21_first_case_is_imported_byte_for_byte_and_compiled(
    tmp_path: Path,
) -> None:
    from egsi.generation.training_ready import build_training_ready

    historical = ROOT / ".work/real-p0-codex-v2"
    output = tmp_path / "training-ready"
    source = historical / "enrichment" / f"{FIRST}.json"

    report = build_training_ready(
        root=ROOT,
        case_ids=P0_IDS,
        historical_root=historical,
        batch_root=tmp_path / "empty-batch",
        output_root=output,
    )

    imported = output / "enrichment" / f"{FIRST}.json"
    assert imported.read_bytes() == source.read_bytes()
    assert report["success_case_ids"] == [FIRST]
    assert report["requested"] == report["success"] + report["failed"] + report["gap"] == 10
    first = report["cases"][0]
    assert first["source_kind"] == "historical_v21"
    assert first["source_file_sha256"] == "sha256:" + hashlib.sha256(
        source.read_bytes()
    ).hexdigest()
    assert (output / "trajectories/train.parquet").is_file()
    trajectory = json.loads(
        (output / "reports/trajectory-validation.json").read_text()
    )
    assert trajectory["processed_case_ids"] == [FIRST]
    assert trajectory["event_replay_passed"] == 1


def test_legacy_p0_pragmatic_v1_state_without_quarantine_hash_still_rebuilds(
    tmp_path: Path,
) -> None:
    from egsi.generation.training_ready import build_training_ready

    batch = ROOT / ".work/real-p0-pragmatic-v1"
    state = json.loads(
        (batch / "reports/pragmatic-batch-state.json").read_text(
            encoding="utf-8"
        )
    )
    assert state["schema_version"] == "1.0"
    assert any(
        slot["quarantine_relative_path"] is not None
        and "quarantine_file_sha256" not in slot
        for case in state["cases"]
        for slot in case["slots"]
    )

    report = build_training_ready(
        root=ROOT,
        case_ids=P0_IDS,
        historical_root=ROOT / ".work/real-p0-codex-v2",
        batch_root=batch,
        output_root=tmp_path / "training-ready",
    )

    assert report["success_case_ids"] == P0_IDS
    assert report["success"] == 10
    assert report["failed"] == report["gap"] == 0


def test_stale_historical_first_case_becomes_gap_without_empty_parquet(
    tmp_path: Path,
) -> None:
    from egsi.generation.training_ready import build_training_ready

    output = tmp_path / "training-ready"
    report = build_training_ready(
        root=ROOT,
        case_ids=P0_IDS,
        historical_root=_stale_historical_copy(tmp_path),
        batch_root=tmp_path / "empty-batch",
        output_root=output,
    )

    assert report["success"] == 0
    assert report["failed"] == 0
    assert report["gap"] == 10
    assert report["cases"][0]["status"] == "gap"
    assert report["cases"][0]["reason"] == "historical_record_stale"
    assert not (output / "trajectories/train.parquet").exists()


def test_case_compile_failure_removes_already_published_case_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.training_ready as training_ready

    def fail_after_jsonl_write(*args: object, **kwargs: object) -> tuple[int, int, int]:
        raise RuntimeError("synthetic metrics failure")

    monkeypatch.setattr(training_ready, "_episode_metrics", fail_after_jsonl_write)
    output = tmp_path / "training-ready"
    report = training_ready.build_training_ready(
        root=ROOT,
        case_ids=P0_IDS,
        historical_root=ROOT / ".work/real-p0-codex-v2",
        batch_root=tmp_path / "empty-batch",
        output_root=output,
    )

    assert report["cases"][0]["status"] == "gap"
    assert report["cases"][0]["reason"] == "trajectory_compile_failed"
    assert list((output / "enrichment").glob(f"{FIRST}*")) == []
    assert list((output / "episodes").glob("*.jsonl")) == []
    manifest = json.loads(
        (output / "reports/artifact-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["processed_case_ids"] == []
    assert all(entry["case_id"] != FIRST for entry in manifest["artifacts"])


def test_mixed_success_failure_and_gap_compile_only_success_in_p0_order(
    tmp_path: Path,
) -> None:
    from egsi.generation.training_ready import build_training_ready

    batch = _batch_with_second_record(tmp_path)
    failed_id = P0_IDS[2]
    output = tmp_path / "training-ready"

    report = build_training_ready(
        root=ROOT,
        case_ids=P0_IDS,
        historical_root=ROOT / ".work/real-p0-codex-v2",
        batch_root=batch,
        output_root=output,
    )

    assert report["success_case_ids"] == [FIRST, SECOND]
    assert report["failed_case_ids"] == [failed_id]
    assert report["gap_case_ids"] == P0_IDS[3:]
    assert report["success"] == 2
    assert report["failed"] == 1
    assert report["gap"] == 7
    assert report["requested"] == report["success"] + report["failed"] + report["gap"]
    assert len(list((output / "episodes").glob("*.events.jsonl"))) == 2
    assert len(list((output / "episodes").glob("*.transitions.jsonl"))) == 2


def test_training_ready_rebuild_is_byte_idempotent(tmp_path: Path) -> None:
    from egsi.generation.training_ready import build_training_ready

    batch = _batch_with_second_record(tmp_path)
    output = tmp_path / "training-ready"
    kwargs = {
        "root": ROOT,
        "case_ids": P0_IDS,
        "historical_root": ROOT / ".work/real-p0-codex-v2",
        "batch_root": batch,
        "output_root": output,
    }
    first = build_training_ready(**kwargs)
    snapshot = {
        path.relative_to(output).as_posix(): path.read_bytes()
        for path in output.rglob("*")
        if path.is_file() and path.name != ".egsi-batch.lock"
    }

    second = build_training_ready(**kwargs)
    repeated = {
        path.relative_to(output).as_posix(): path.read_bytes()
        for path in output.rglob("*")
        if path.is_file() and path.name != ".egsi-batch.lock"
    }

    assert second == first
    assert repeated == snapshot
    manifest = output / "reports/artifact-manifest.json"
    sidecar = output / "reports/artifact-manifest.json.sha256"
    assert sidecar.read_text().strip() == "sha256:" + hashlib.sha256(
        manifest.read_bytes()
    ).hexdigest()


def test_training_ready_removes_unmanifested_root_file_before_success(
    tmp_path: Path,
) -> None:
    from egsi.generation.training_ready import build_training_ready

    output = tmp_path / "training-ready"
    output.mkdir()
    rogue = output / "rogue.txt"
    rogue.write_bytes(b"must not survive a successful rebuild")

    build_training_ready(
        root=ROOT,
        case_ids=P0_IDS,
        historical_root=ROOT / ".work/real-p0-codex-v2",
        batch_root=tmp_path / "empty-batch",
        output_root=output,
    )

    assert not rogue.exists()
    manifest_path = output / "reports/artifact-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = {
        *(entry["relative_path"] for entry in manifest["artifacts"]),
        "reports/artifact-manifest.json",
        "reports/artifact-manifest.json.sha256",
    }
    observed = {
        path.relative_to(output).as_posix()
        for path in output.rglob("*")
        if path.is_file() and path.name != ".egsi-batch.lock"
    }
    assert observed == expected


def test_fixture_pragmatic_batch_is_never_promoted_to_training(
    tmp_path: Path,
) -> None:
    from egsi.generation.training_ready import build_training_ready

    batch = _complete_pragmatic_batch(tmp_path, live=False)
    report = build_training_ready(
        root=ROOT,
        case_ids=P0_IDS,
        historical_root=ROOT / ".work/real-p0-codex-v2",
        batch_root=batch,
        output_root=tmp_path / "training-ready",
    )

    assert report["success_case_ids"] == [FIRST]
    assert report["gap_case_ids"] == P0_IDS[1:]
    assert {
        case["reason"] for case in report["cases"][1:]
    } == {"non_live_batch_provenance"}


def test_single_tampered_live_record_becomes_only_that_case_gap(
    tmp_path: Path,
) -> None:
    from egsi.generation.training_ready import build_training_ready

    batch = _complete_pragmatic_batch(tmp_path, live=True)
    target = batch / "enrichment" / f"{SECOND}.json"
    value = json.loads(target.read_text(encoding="utf-8"))
    value["provider_request_id"] = "tampered-after-commit"
    target.write_text(json.dumps(value), encoding="utf-8")

    report = build_training_ready(
        root=ROOT,
        case_ids=P0_IDS,
        historical_root=ROOT / ".work/real-p0-codex-v2",
        batch_root=batch,
        output_root=tmp_path / "training-ready",
    )

    assert report["cases"][1]["status"] == "gap"
    assert report["cases"][1]["reason"] == "batch_record_provenance_invalid"
    assert report["success_case_ids"] == [FIRST, *P0_IDS[2:]]


def test_confirmed_quarantine_without_teacher_commitment_is_not_promoted(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch
    from egsi.generation.training_ready import build_training_ready

    batch = tmp_path / "live-batch"
    teacher = LiveFixturePayloadTeacher(
        ["structured_invalid", *("valid" for _ in range(9))]
    )
    run_pragmatic_batch(
        ROOT,
        P0_IDS[1:],
        batch,
        teacher,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    target = batch / "enrichment/quarantine" / f"{SECOND}.slot-1.json"
    receipt = json.loads(target.read_text(encoding="utf-8"))
    assert receipt["teacher_response_commitment_sha256"] is not None
    receipt["teacher_response_commitment_sha256"] = None
    target.write_text(json.dumps(receipt), encoding="utf-8")
    teacher.calls = 0

    report = build_training_ready(
        root=ROOT,
        case_ids=P0_IDS,
        historical_root=ROOT / ".work/real-p0-codex-v2",
        batch_root=batch,
        output_root=tmp_path / "training-ready",
    )

    assert teacher.calls == 0
    assert report["cases"][1]["status"] == "gap"
    assert report["cases"][1]["reason"] == "batch_record_provenance_invalid"
    assert report["success_case_ids"] == [FIRST, *P0_IDS[2:]]


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("teacher_response_commitment_sha256", "sha256:" + "0" * 64),
        ("provider_request_id", "forged-provider-request-id"),
    ],
)
def test_tampered_quarantine_provenance_is_not_promoted(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    from egsi.generation.pragmatic_batch import (
        pragmatic_quarantine_receipt_commitment,
        run_pragmatic_batch,
    )
    from egsi.generation.training_ready import build_training_ready

    batch = tmp_path / "live-batch"
    run_pragmatic_batch(
        ROOT,
        P0_IDS[1:],
        batch,
        LiveFixturePayloadTeacher(
            ["structured_invalid", *('valid' for _ in range(9))]
        ),
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    target = batch / "enrichment/quarantine" / f"{SECOND}.slot-1.json"
    receipt = json.loads(target.read_text(encoding="utf-8"))
    assert receipt[field] != replacement
    receipt[field] = replacement
    receipt["receipt_commitment_sha256"] = (
        pragmatic_quarantine_receipt_commitment(receipt)
    )
    target.write_text(json.dumps(receipt), encoding="utf-8")

    report = build_training_ready(
        root=ROOT,
        case_ids=P0_IDS,
        historical_root=ROOT / ".work/real-p0-codex-v2",
        batch_root=batch,
        output_root=tmp_path / "training-ready",
    )

    assert report["cases"][1]["status"] == "gap"
    assert report["cases"][1]["reason"] == "batch_record_provenance_invalid"


def test_partial_pragmatic_control_plane_is_systemic_failure(
    tmp_path: Path,
) -> None:
    from egsi.generation.training_ready import build_training_ready

    batch = _complete_pragmatic_batch(tmp_path, live=True)
    (batch / "reports/pragmatic-batch-report.json").unlink()

    with pytest.raises(ValueError, match="pragmatic batch provenance"):
        build_training_ready(
            root=ROOT,
            case_ids=P0_IDS,
            historical_root=ROOT / ".work/real-p0-codex-v2",
            batch_root=batch,
            output_root=tmp_path / "training-ready",
        )

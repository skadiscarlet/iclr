from __future__ import annotations

import importlib
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from egsi.contracts.case import load_case_catalog
from egsi.contracts.enrichment import enrichment_record_commitment
from egsi.contracts.trajectory import EpisodeEvent, T1Transition
from egsi.generation.pilot import _dict_commitment
from egsi.generation.trajectory import read_parquet, write_parquet
from egsi.teacher import TeacherRequest, TeacherResponse, committed_teacher_response
from egsi.teacher.fixture import FixtureTeacher

ROOT = Path(__file__).resolve().parents[2]


def _case_ids(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


P0_IDS = _case_ids(ROOT / "configs/p0_cases.txt")
P1_IDS = _case_ids(ROOT / "configs/p1_cases.txt")
INCREMENTAL_IDS = [case_id for case_id in P1_IDS if case_id not in P0_IDS]
BASE_ROOT = ROOT / ".work/p0-training-ready-v1"


class LiveFixturePayloadTeacher:
    provider = "codex_exec"
    model = "test-live-p1-model"

    def __init__(self, script: list[str]) -> None:
        self.fixture = FixtureTeacher()
        self.script = iter(script)
        self.calls = 0

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        self.calls += 1
        action = next(self.script)
        if action == "transport":
            raise RuntimeError("synthetic transport failure")
        assert action == "valid"
        response = self.fixture.generate(request)
        return committed_teacher_response(
            provider_request_id=f"synthetic-p1-{self.calls}",
            provider=self.provider,
            model=self.model,
            requested_model=self.model,
            provider_response_model=self.model,
            text=response.text,
            usage=response.usage,
            latency_ms=1.0,
        )


@pytest.fixture(scope="module")
def complete_incremental_batch(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, LiveFixturePayloadTeacher]:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    batch = tmp_path_factory.mktemp("complete-p1-batch")
    teacher = LiveFixturePayloadTeacher(["valid"] * 20)
    run_pragmatic_batch(
        ROOT,
        INCREMENTAL_IDS,
        batch,
        teacher,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=28_800,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    return batch, teacher


@pytest.fixture(scope="module")
def mixed_incremental_batch(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, LiveFixturePayloadTeacher]:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    batch = tmp_path_factory.mktemp("mixed-p1-batch")
    teacher = LiveFixturePayloadTeacher(
        ["valid", "transport", "transport", *(["valid"] * 18)]
    )
    run_pragmatic_batch(
        ROOT,
        INCREMENTAL_IDS,
        batch,
        teacher,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=28_800,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    return batch, teacher


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )


def _resign_base_manifest(base: Path, changed_relative: str) -> None:
    manifest_path = base / "reports/artifact-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    changed = (base / changed_relative).read_bytes()
    entry = next(
        item
        for item in manifest["artifacts"]
        if item["relative_path"] == changed_relative
    )
    entry["sha256"] = "sha256:" + hashlib.sha256(changed).hexdigest()
    manifest["artifact_commitment_sha256"] = _dict_commitment(
        manifest, "artifact_commitment_sha256"
    )
    _write_json(manifest_path, manifest)
    manifest_sha = "sha256:" + hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    (base / "reports/artifact-manifest.json.sha256").write_text(
        manifest_sha + "\n", encoding="ascii"
    )


def _reattest_base_record_tamper(base: Path, tamper: str) -> None:
    case_id = P0_IDS[0]
    record_relative = f"enrichment/{case_id}.json"
    record_path = base / record_relative
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if tamper == "path":
        record["payload"]["locations"][0]["path"] = "not-in-repository.java"
    else:
        record["payload"]["trace"][0]["operation"] = "not_allowed"
    record["record_commitment_sha256"] = enrichment_record_commitment(record)
    _write_json(record_path, record)

    coverage_path = base / "reports/p0-coverage-provenance.json"
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    coverage["cases"][0]["source_file_sha256"] = (
        "sha256:" + hashlib.sha256(record_path.read_bytes()).hexdigest()
    )
    coverage["cases"][0]["record_commitment_sha256"] = record[
        "record_commitment_sha256"
    ]
    _write_json(coverage_path, coverage)

    audit_path = base / "reports/human-audit-packet.json"
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    audit["cases"] = coverage["cases"]
    _write_json(audit_path, audit)

    for relative in (
        record_relative,
        "reports/p0-coverage-provenance.json",
        "reports/human-audit-packet.json",
    ):
        _resign_base_manifest(base, relative)


def _build(
    output: Path,
    batch: Path,
    *,
    base: Path = BASE_ROOT,
) -> dict[str, object]:
    from egsi.generation.incremental_training_ready import (
        build_incremental_training_ready,
    )

    return build_incremental_training_ready(
        root=ROOT,
        case_ids=P1_IDS,
        base_package_root=base,
        incremental_batch_root=batch,
        incremental_case_ids=INCREMENTAL_IDS,
        output_root=output,
    )


def test_p1_incremental_case_file_is_ordered_p1_minus_p0() -> None:
    p0_ids = _case_ids(ROOT / "configs/p0_cases.txt")
    p1_ids = _case_ids(ROOT / "configs/p1_cases.txt")
    incremental_ids = _case_ids(
        ROOT / "configs/p1_pragmatic_incremental_cases.txt"
    )

    assert incremental_ids == [case_id for case_id in p1_ids if case_id not in p0_ids]
    assert len(incremental_ids) == 20
    assert set(incremental_ids).isdisjoint(p0_ids)
    assert set(incremental_ids).union(p0_ids) == set(p1_ids)
    catalog = {case.case_id: case for case in load_case_catalog(ROOT / "data/catalog/cases.jsonl")}
    assert all(catalog[case_id].split == "train" for case_id in incremental_ids)


def test_incremental_training_ready_module_exposes_builder() -> None:
    module = importlib.import_module(
        "egsi.generation.incremental_training_ready"
    )

    assert callable(module.build_incremental_training_ready)


@pytest.mark.parametrize(
    ("source", "relationship"),
    [
        ("base", "equal"),
        ("base", "output_inside_source"),
        ("base", "source_inside_output"),
        ("incremental", "equal"),
        ("incremental", "output_inside_source"),
        ("incremental", "source_inside_output"),
    ],
)
def test_incremental_builder_rejects_every_output_source_overlap_before_write(
    tmp_path: Path,
    source: str,
    relationship: str,
) -> None:
    from egsi.generation.incremental_training_ready import (
        build_incremental_training_ready,
    )

    base = tmp_path / "base"
    incremental = tmp_path / "incremental"
    selected = base if source == "base" else incremental
    if relationship == "equal":
        output = selected
    elif relationship == "output_inside_source":
        output = selected / "nested-output"
    else:
        output = tmp_path / f"{source}-output"
        selected = output / "nested-source"
        if source == "base":
            base = selected
        else:
            incremental = selected

    with pytest.raises(ValueError, match="overlap"):
        build_incremental_training_ready(
            root=ROOT,
            case_ids=P1_IDS,
            base_package_root=base,
            incremental_batch_root=incremental,
            incremental_case_ids=INCREMENTAL_IDS,
            output_root=output,
        )
    assert not (output / ".egsi-batch.lock").exists()


@pytest.mark.parametrize("tamper", ["artifact", "sidecar", "parquet", "replay"])
def test_base_package_tamper_fails_closed_systemically(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
    tamper: str,
) -> None:
    base = tmp_path / "base"
    shutil.copytree(BASE_ROOT, base)
    if tamper == "artifact":
        target = base / "enrichment" / f"{P0_IDS[0]}.json"
        target.write_bytes(target.read_bytes() + b" ")
    elif tamper == "sidecar":
        (base / "reports/artifact-manifest.json.sha256").write_text(
            "sha256:" + "0" * 64 + "\n", encoding="ascii"
        )
    elif tamper == "parquet":
        parquet = base / "trajectories/train.parquet"
        write_parquet(parquet, list(reversed(read_parquet(parquet))))
        _resign_base_manifest(base, "trajectories/train.parquet")
    else:
        trajectory = json.loads(
            (base / "reports/trajectory-validation.json").read_text(encoding="utf-8")
        )
        relative = trajectory["event_files"][0]
        path = base / relative
        lines = path.read_text(encoding="utf-8").splitlines()
        event = json.loads(lines[0])
        event["event_sha256"] = "sha256:" + "0" * 64
        lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _resign_base_manifest(base, relative)

    batch, _ = complete_incremental_batch
    with pytest.raises(ValueError, match="base training-ready"):
        _build(tmp_path / "output", batch, base=base)


def test_base_package_extra_empty_directory_fails_closed_systemically(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
) -> None:
    base = tmp_path / "base"
    shutil.copytree(BASE_ROOT, base)
    (base / "unexpected-empty-directory").mkdir()
    batch, _ = complete_incremental_batch

    with pytest.raises(ValueError, match="base training-ready"):
        _build(tmp_path / "output", batch, base=base)


def test_base_package_opaque_directory_fails_closed_systemically(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
) -> None:
    base = tmp_path / "base"
    shutil.copytree(BASE_ROOT, base)
    opaque = base / "opaque-directory"
    opaque.mkdir()
    opaque.chmod(0)
    batch, _ = complete_incremental_batch

    try:
        with pytest.raises(ValueError, match="base training-ready"):
            _build(tmp_path / "output", batch, base=base)
    finally:
        opaque.chmod(0o700)


@pytest.mark.parametrize("tamper", ["path", "action"])
def test_reattested_base_record_must_match_semantics_and_compiled_episode(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
    tamper: str,
) -> None:
    base = tmp_path / "base"
    shutil.copytree(BASE_ROOT, base)
    _reattest_base_record_tamper(base, tamper)
    batch, _ = complete_incremental_batch

    with pytest.raises(ValueError, match="base training-ready"):
        _build(tmp_path / "output", batch, base=base)


def test_reattested_base_lineage_tamper_fails_closed(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
) -> None:
    base = tmp_path / "base"
    shutil.copytree(BASE_ROOT, base)
    coverage_path = base / "reports/p0-coverage-provenance.json"
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    coverage["cases"][0]["source_root"] = "/forged/upstream"
    coverage["cases"][0]["source_relative_path"] = "forged/record.json"
    _write_json(coverage_path, coverage)

    audit_path = base / "reports/human-audit-packet.json"
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    audit["cases"] = coverage["cases"]
    _write_json(audit_path, audit)
    for relative in (
        "reports/p0-coverage-provenance.json",
        "reports/human-audit-packet.json",
    ):
        _resign_base_manifest(base, relative)

    batch, _ = complete_incremental_batch
    with pytest.raises(ValueError, match="base training-ready"):
        _build(tmp_path / "output", batch, base=base)


@pytest.mark.parametrize("tamper", ["fixture", "partial", "corrupt_state"])
def test_invalid_incremental_control_plane_is_rejected_systemically(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
    tamper: str,
) -> None:
    source, _ = complete_incremental_batch
    batch = tmp_path / "batch"
    shutil.copytree(source, batch)
    if tamper == "partial":
        (batch / "reports/pragmatic-batch-report.json").unlink()
    elif tamper == "corrupt_state":
        (batch / "reports/pragmatic-batch-state.json").write_text(
            "{}\n", encoding="utf-8"
        )
    else:
        state_path = batch / "reports/pragmatic-batch-state.json"
        report_path = batch / "reports/pragmatic-batch-report.json"
        manifest_path = batch / "enrichment/_batch-provenance.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        state["generation_mode"] = "fixture"
        manifest["generation_mode"] = "fixture"
        manifest["batch_commitment_sha256"] = _dict_commitment(
            manifest, "batch_commitment_sha256"
        )
        _write_json(state_path, state)
        _write_json(manifest_path, manifest)
        report["generation_mode"] = "fixture"
        report["provenance"]["generation_mode"] = "fixture"
        report["provenance"]["manifest_sha256"] = "sha256:" + hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest()
        report["provenance"]["batch_commitment_sha256"] = manifest[
            "batch_commitment_sha256"
        ]
        _write_json(report_path, report)

    with pytest.raises(ValueError, match="incremental pragmatic"):
        _build(tmp_path / "output", batch)


def test_incremental_rejects_coherent_quarantine_and_state_hash_tamper(
    tmp_path: Path,
    mixed_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
) -> None:
    from egsi.generation.pragmatic_batch import (
        pragmatic_quarantine_receipt_commitment,
    )

    source, _ = mixed_incremental_batch
    batch = tmp_path / "batch"
    shutil.copytree(source, batch)
    failed_id = INCREMENTAL_IDS[1]
    quarantine_path = (
        batch / "enrichment/quarantine" / f"{failed_id}.slot-1.json"
    )
    receipt = json.loads(quarantine_path.read_text(encoding="utf-8"))
    assert receipt["schema_version"] == "1.1"
    receipt["provider_request_id"] = "forged-provider-request-id"
    receipt["teacher_response_commitment_sha256"] = "sha256:" + "0" * 64
    receipt["receipt_commitment_sha256"] = (
        pragmatic_quarantine_receipt_commitment(receipt)
    )
    _write_json(quarantine_path, receipt)

    state_path = batch / "reports/pragmatic-batch-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["schema_version"] == "1.1"
    report = json.loads(
        (batch / "reports/pragmatic-batch-report.json").read_text(
            encoding="utf-8"
        )
    )
    manifest = json.loads(
        (batch / "enrichment/_batch-provenance.json").read_text(
            encoding="utf-8"
        )
    )
    assert report["schema_version"] == manifest["schema_version"] == "1.1"
    assert manifest["pragmatic_state_sha256"] == (
        "sha256:" + hashlib.sha256(state_path.read_bytes()).hexdigest()
    )
    assert report["provenance"]["pragmatic_state_sha256"] == manifest[
        "pragmatic_state_sha256"
    ]
    case_state = next(
        case for case in state["cases"] if case["case_id"] == failed_id
    )
    case_state["slots"][0]["quarantine_file_sha256"] = (
        "sha256:" + hashlib.sha256(quarantine_path.read_bytes()).hexdigest()
    )
    _write_json(state_path, state)

    with pytest.raises(ValueError, match="incremental pragmatic"):
        _build(tmp_path / "output", batch)


def test_complete_incremental_build_is_ordered_exact_and_byte_idempotent(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
) -> None:
    batch, teacher = complete_incremental_batch
    calls_before = teacher.calls
    output = tmp_path / "training-ready"

    report = _build(output, batch)

    assert teacher.calls == calls_before
    assert report["requested_case_ids"] == P1_IDS
    assert report["success_case_ids"] == P1_IDS
    assert report["success"] == 30
    assert report["failed"] == report["gap"] == 0
    assert report["base_requested"] == 10
    assert report["incremental_requested"] == 20
    base_coverage = json.loads(
        (BASE_ROOT / "reports/p0-coverage-provenance.json").read_text(encoding="utf-8")
    )
    base_manifest_raw = (BASE_ROOT / "reports/artifact-manifest.json").read_bytes()
    base_manifest_sha = "sha256:" + hashlib.sha256(base_manifest_raw).hexdigest()
    by_id = {case["case_id"]: case for case in report["cases"]}
    for case_id, upstream in zip(P0_IDS, base_coverage["cases"], strict=True):
        assert (output / "enrichment" / f"{case_id}.json").read_bytes() == (
            BASE_ROOT / "enrichment" / f"{case_id}.json"
        ).read_bytes()
        assert by_id[case_id]["source_kind"] == "base_training_ready"
        assert by_id[case_id]["base_lineage"] == {
            "base_manifest_sha256": base_manifest_sha,
            "source_kind": upstream["source_kind"],
            "source_root": upstream["source_root"],
            "source_relative_path": upstream["source_relative_path"],
            "source_file_sha256": upstream["source_file_sha256"],
            "record_commitment_sha256": upstream[
                "record_commitment_sha256"
            ],
        }

    base_trajectory = json.loads(
        (BASE_ROOT / "reports/trajectory-validation.json").read_text(encoding="utf-8")
    )
    for relative in [
        *base_trajectory["event_files"],
        *base_trajectory["transition_files"],
    ]:
        assert (output / relative).read_bytes() == (BASE_ROOT / relative).read_bytes()

    trajectory = json.loads(
        (output / "reports/trajectory-validation.json").read_text(encoding="utf-8")
    )
    assert trajectory["processed_case_ids"] == P1_IDS
    transitions = [
        T1Transition.model_validate_json(line)
        for relative in trajectory["transition_files"]
        for line in (output / relative).read_bytes().splitlines()
    ]
    assert read_parquet(output / "trajectories/train.parquet") == transitions

    manifest_path = output / "reports/artifact-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["requested_case_ids"] == P1_IDS
    assert manifest["processed_case_ids"] == P1_IDS
    for entry in manifest["artifacts"]:
        raw = (output / entry["relative_path"]).read_bytes()
        assert entry["size_bytes"] == len(raw)
        assert entry["sha256"] == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert (output / "reports/artifact-manifest.json.sha256").read_text().strip() == (
        "sha256:" + hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    )

    first = {
        path.relative_to(output).as_posix(): path.read_bytes()
        for path in output.rglob("*")
        if path.is_file() and path.name != ".egsi-batch.lock"
    }
    repeated = _build(output, batch)
    second = {
        path.relative_to(output).as_posix(): path.read_bytes()
        for path in output.rglob("*")
        if path.is_file() and path.name != ".egsi-batch.lock"
    }
    assert repeated == report
    assert second == first


def test_mixed_incremental_success_failed_gap_conserves_p1_order(
    tmp_path: Path,
    mixed_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
) -> None:
    source, teacher = mixed_incremental_batch
    batch = tmp_path / "batch"
    shutil.copytree(source, batch)
    missing_id = INCREMENTAL_IDS[2]
    (batch / "enrichment" / f"{missing_id}.json").unlink()
    calls_before = teacher.calls

    report = _build(tmp_path / "output", batch)

    assert teacher.calls == calls_before
    failed_id = INCREMENTAL_IDS[1]
    assert report["requested"] == report["success"] + report["failed"] + report["gap"] == 30
    assert report["failed_case_ids"] == [failed_id]
    assert report["gap_case_ids"] == [missing_id]
    assert report["success_case_ids"] == [
        case_id for case_id in P1_IDS if case_id not in {failed_id, missing_id}
    ]
    cases = {case["case_id"]: case for case in report["cases"]}
    assert cases[failed_id]["status"] == "failed"
    assert cases[failed_id]["reason"] == "transport"
    assert cases[missing_id]["status"] == "gap"
    assert cases[missing_id]["reason"] == "batch_result_missing"


def test_oversized_incremental_success_record_is_a_per_case_gap(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
) -> None:
    source, _ = complete_incremental_batch
    batch = tmp_path / "batch"
    shutil.copytree(source, batch)
    target_id = INCREMENTAL_IDS[0]
    (batch / "enrichment" / f"{target_id}.json").write_bytes(
        b"x" * (2 * 1024 * 1024 + 1)
    )

    report = _build(tmp_path / "output", batch)

    target = next(case for case in report["cases"] if case["case_id"] == target_id)
    assert target["status"] == "gap"
    assert target["reason"] == "batch_record_provenance_invalid"
    assert target["source_file_sha256"] is None


def test_oversized_incremental_failure_receipt_is_a_per_case_gap(
    tmp_path: Path,
    mixed_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
) -> None:
    source, _ = mixed_incremental_batch
    batch = tmp_path / "batch"
    shutil.copytree(source, batch)
    target_id = INCREMENTAL_IDS[1]
    (batch / "enrichment" / "failures" / f"{target_id}.json").write_bytes(
        b"x" * (2 * 1024 * 1024 + 1)
    )

    report = _build(tmp_path / "output", batch)

    target = next(case for case in report["cases"] if case["case_id"] == target_id)
    assert target["status"] == "gap"
    assert target["reason"] == "batch_failure_provenance_invalid"
    assert target["source_file_sha256"] is None


def test_unowned_nonempty_output_is_rejected_before_mutation(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    unknown = output / "operator-owned.bin"
    original = b"operator bytes must survive\x00\xff"
    unknown.write_bytes(original)
    batch, _ = complete_incremental_batch

    with pytest.raises(ValueError, match="ownership"):
        _build(output, batch)

    assert unknown.read_bytes() == original
    assert {
        path.relative_to(output).as_posix()
        for path in output.rglob("*")
        if path.name != ".egsi-batch.lock"
    } == {"operator-owned.bin"}


def test_incremental_compile_failure_leaves_no_case_artifacts(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.incremental_training_ready as incremental

    target_id = INCREMENTAL_IDS[0]
    compile_episode = incremental.compile_t1_episode

    def fail_one(case: object, record: object, *, root: Path):
        if getattr(case, "case_id") == target_id:
            raise RuntimeError("synthetic compile failure")
        return compile_episode(case, record, root=root)

    monkeypatch.setattr(incremental, "compile_t1_episode", fail_one)
    output = tmp_path / "output"
    batch, _ = complete_incremental_batch

    report = _build(output, batch)

    target = next(case for case in report["cases"] if case["case_id"] == target_id)
    assert target["status"] == "gap"
    assert target["reason"] == "trajectory_compile_failed"
    assert not (output / "enrichment" / f"{target_id}.json").exists()
    manifest = json.loads(
        (output / "reports/artifact-manifest.json").read_text(encoding="utf-8")
    )
    assert all(entry["case_id"] != target_id for entry in manifest["artifacts"])


def test_incremental_output_write_oserror_is_systemic(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.incremental_training_ready as incremental

    output = tmp_path / "output"
    target_id = INCREMENTAL_IDS[0]
    write_exact = incremental._write_exact

    def fail_target(path: Path, raw: bytes) -> None:
        if path == output / f"enrichment/{target_id}.json":
            raise OSError("synthetic output I/O failure")
        write_exact(path, raw)

    monkeypatch.setattr(incremental, "_write_exact", fail_target)
    batch, _ = complete_incremental_batch

    with pytest.raises(OSError, match="synthetic output I/O failure"):
        _build(output, batch)

    assert list((output / "enrichment").glob("*.json")) == []
    assert list((output / "episodes").glob("*.jsonl")) == []
    assert list((output / "reports").glob("*")) == []


def test_incremental_output_readback_valueerror_is_systemic(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.incremental_training_ready as incremental

    output = tmp_path / "output"
    target_id = INCREMENTAL_IDS[0]
    target = output / f"enrichment/{target_id}.json"
    read_regular = incremental._read_regular

    def fail_target(path: Path, *args: object, **kwargs: object) -> bytes:
        if path == target:
            raise ValueError("synthetic output readback failure")
        return read_regular(path, *args, **kwargs)

    monkeypatch.setattr(incremental, "_read_regular", fail_target)
    batch, _ = complete_incremental_batch

    with pytest.raises(ValueError, match="synthetic output readback failure"):
        _build(output, batch)

    assert list((output / "enrichment").glob("*.json")) == []
    assert list((output / "episodes").glob("*.jsonl")) == []
    assert list((output / "reports").glob("*")) == []


def test_episode_collision_fails_closed_without_partial_artifacts(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.incremental_training_ready as incremental

    base_trajectory = json.loads(
        (BASE_ROOT / "reports/trajectory-validation.json").read_text(
            encoding="utf-8"
        )
    )
    events = [
        EpisodeEvent.model_validate_json(line)
        for line in (
            BASE_ROOT / base_trajectory["event_files"][0]
        ).read_bytes().splitlines()
    ]
    transitions = [
        T1Transition.model_validate_json(line)
        for line in (
            BASE_ROOT / base_trajectory["transition_files"][0]
        ).read_bytes().splitlines()
    ]

    compile_episode = incremental.compile_t1_episode

    def collide(case: object, record: object, *, root: Path):
        if getattr(case, "case_id") in INCREMENTAL_IDS:
            return transitions, events
        return compile_episode(case, record, root=root)

    monkeypatch.setattr(incremental, "compile_t1_episode", collide)
    output = tmp_path / "output"
    batch, _ = complete_incremental_batch

    with pytest.raises(ValueError, match="collision"):
        _build(output, batch)

    assert list((output / "enrichment").glob("*.json")) == []
    assert list((output / "episodes").glob("*.jsonl")) == []
    assert list((output / "reports").glob("*")) == []


def test_episode_collision_is_rejected_before_copying_any_base_artifact(
    tmp_path: Path,
    complete_incremental_batch: tuple[Path, LiveFixturePayloadTeacher],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.incremental_training_ready as incremental

    base_trajectory = json.loads(
        (BASE_ROOT / "reports/trajectory-validation.json").read_text(
            encoding="utf-8"
        )
    )
    events = [
        EpisodeEvent.model_validate_json(line)
        for line in (
            BASE_ROOT / base_trajectory["event_files"][0]
        ).read_bytes().splitlines()
    ]
    transitions = [
        T1Transition.model_validate_json(line)
        for line in (
            BASE_ROOT / base_trajectory["transition_files"][0]
        ).read_bytes().splitlines()
    ]
    compile_episode = incremental.compile_t1_episode

    def collide(case: object, record: object, *, root: Path):
        if getattr(case, "case_id") in INCREMENTAL_IDS:
            return transitions, events
        return compile_episode(case, record, root=root)

    writes: list[Path] = []
    write_exact = incremental._write_exact

    def record_write(path: Path, raw: bytes) -> None:
        writes.append(path)
        write_exact(path, raw)

    monkeypatch.setattr(incremental, "compile_t1_episode", collide)
    monkeypatch.setattr(incremental, "_write_exact", record_write)
    batch, _ = complete_incremental_batch

    with pytest.raises(ValueError, match="collision"):
        _build(tmp_path / "output", batch)

    assert writes == []

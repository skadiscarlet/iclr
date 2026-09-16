from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from egsi.cli import app


ROOT = Path(__file__).resolve().parents[2]
REAL_CASE_ID = "ghsa-2m8h-fgr8-2q9w"


def _case_file(tmp_path: Path) -> Path:
    path = tmp_path / "cases.txt"
    path.write_text(REAL_CASE_ID + "\n", encoding="utf-8")
    return path


def _provenance_args(report: dict[str, object]) -> list[str]:
    provenance = report["provenance"]
    assert isinstance(provenance, dict)
    return [
        "--generation-mode",
        str(provenance["generation_mode"]),
        "--expected-provider",
        str(provenance["provider"]),
        "--expected-model",
        str(provenance["model"]),
        "--provenance-manifest-sha256",
        str(provenance["manifest_sha256"]),
        "--provenance-batch-commitment",
        str(provenance["batch_commitment_sha256"]),
    ]


def test_cli_help_lists_pilot_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "batch-enrich" in result.output
    assert "compile-trajectories" in result.output
    assert "build-training-ready" in result.output
    assert "build-incremental-training-ready" in result.output


def test_build_training_ready_cli_wires_all_roots_and_case_order(
    tmp_path: Path, monkeypatch
) -> None:
    observed: dict[str, object] = {}

    def build_training_ready(**kwargs):
        observed.update(kwargs)
        return {
            "requested": 10,
            "success": 1,
            "failed": 2,
            "gap": 7,
        }

    monkeypatch.setattr(
        "egsi.generation.training_ready.build_training_ready",
        build_training_ready,
    )
    case_file = ROOT / "configs/p0_cases.txt"
    historical = tmp_path / "historical"
    batch = tmp_path / "batch"
    output = tmp_path / "training-ready"
    result = CliRunner().invoke(
        app,
        [
            "build-training-ready",
            "--root",
            str(ROOT),
            "--case-file",
            str(case_file),
            "--historical-root",
            str(historical),
            "--batch-root",
            str(batch),
            "--output-root",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "requested": 10,
        "success": 1,
        "failed": 2,
        "gap": 7,
    }
    assert observed == {
        "root": ROOT,
        "case_ids": (ROOT / "configs/p0_cases.txt")
        .read_text(encoding="utf-8")
        .splitlines(),
        "historical_root": historical,
        "batch_root": batch,
        "output_root": output,
    }


def test_build_incremental_training_ready_cli_wires_both_lists_and_roots(
    tmp_path: Path, monkeypatch
) -> None:
    observed: dict[str, object] = {}

    def build_incremental_training_ready(**kwargs):
        observed.update(kwargs)
        return {
            "requested": 30,
            "success": 28,
            "failed": 1,
            "gap": 1,
        }

    monkeypatch.setattr(
        "egsi.generation.incremental_training_ready.build_incremental_training_ready",
        build_incremental_training_ready,
    )
    case_file = ROOT / "configs/p1_cases.txt"
    incremental_case_file = ROOT / "configs/p1_pragmatic_incremental_cases.txt"
    base = tmp_path / "base"
    batch = tmp_path / "batch"
    output = tmp_path / "training-ready"
    result = CliRunner().invoke(
        app,
        [
            "build-incremental-training-ready",
            "--root",
            str(ROOT),
            "--case-file",
            str(case_file),
            "--incremental-case-file",
            str(incremental_case_file),
            "--base-package-root",
            str(base),
            "--incremental-batch-root",
            str(batch),
            "--output-root",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "requested": 30,
        "success": 28,
        "failed": 1,
        "gap": 1,
    }
    assert observed == {
        "root": ROOT,
        "case_ids": (ROOT / "configs/p1_cases.txt")
        .read_text(encoding="utf-8")
        .splitlines(),
        "base_package_root": base,
        "incremental_batch_root": batch,
        "incremental_case_ids": incremental_case_file
        .read_text(encoding="utf-8")
        .splitlines(),
        "output_root": output,
    }


def test_batch_enrich_fixture_smoke_needs_no_provider_config(tmp_path: Path) -> None:
    output = tmp_path / "output"
    result = CliRunner().invoke(
        app,
        [
            "batch-enrich",
            "--case-file",
            str(_case_file(tmp_path)),
            "--output-root",
            str(output),
            "--root",
            str(ROOT),
            "--fixture-teacher",
        ],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["processed"] == 1
    assert report["failed"] == 0
    assert report["provider_model_counts"] == {"fixture:fixture-v1": 1}

    compiled = CliRunner().invoke(
        app,
        [
            "compile-trajectories",
            "--case-file",
            str(tmp_path / "cases.txt"),
            "--input-root",
            str(output / "enrichment"),
            "--output-root",
            str(output),
            "--root",
            str(ROOT),
            *_provenance_args(report),
        ],
    )
    assert compiled.exit_code == 0, compiled.output
    compiled_report = json.loads(compiled.stdout)
    assert compiled_report["processed"] == 1
    assert compiled_report["event_replay_passed"] == 1
    assert compiled_report["policy_oracle_leakage"] == 0


def test_batch_enrich_requires_config_without_fixture(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "batch-enrich",
            "--case-file",
            str(_case_file(tmp_path)),
            "--output-root",
            str(tmp_path / "output"),
            "--root",
            str(ROOT),
        ],
    )

    assert result.exit_code != 0
    assert "--provider-config is required" in result.output

    single = CliRunner().invoke(
        app,
        [
            "enrich",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--output-root",
            str(tmp_path / "single-output"),
            "--root",
            str(ROOT),
        ],
    )
    assert single.exit_code != 0
    assert "--provider-config is required" in single.output


def test_fixture_and_provider_config_are_mutually_exclusive_for_single_and_batch(
    tmp_path: Path,
) -> None:
    config = tmp_path / "unused.toml"
    config.write_text("secret = 'must-not-be-read'\n", encoding="utf-8")
    common = [
        "--provider-config",
        str(config),
        "--fixture-teacher",
        "--output-root",
        str(tmp_path / "output"),
        "--root",
        str(ROOT),
    ]

    single = CliRunner().invoke(
        app,
        [
            "enrich",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            *common,
        ],
    )
    batch = CliRunner().invoke(
        app,
        ["batch-enrich", "--case-file", str(_case_file(tmp_path)), *common],
    )

    for result in (single, batch):
        assert result.exit_code != 0
        normalized = " ".join(result.output.split())
        assert "--fixture-teacher" in normalized
        assert "--provider-config" in normalized
        assert "mutually exclusive" in normalized
        assert "must-not-be-read" not in result.output


def test_single_enrich_fixture_smoke_and_output_boundary(tmp_path: Path) -> None:
    allowed = CliRunner().invoke(
        app,
        [
            "enrich",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--root",
            str(ROOT),
            "--output-root",
            str(tmp_path / "allowed"),
            "--fixture-teacher",
        ],
    )
    assert allowed.exit_code == 0, allowed.output
    assert json.loads(allowed.stdout)["provider"] == "fixture"

    forbidden = CliRunner().invoke(
        app,
        [
            "enrich",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--root",
            str(ROOT),
            "--output-root",
            str(ROOT / "data/derived"),
            "--fixture-teacher",
        ],
    )
    assert forbidden.exit_code != 0
    normalized = " ".join(forbidden.output.split())
    assert "fixture output root is outside .work" in normalized
    assert "system temporary root" in normalized


def test_batch_teacher_closes_exactly_once(tmp_path: Path, monkeypatch) -> None:
    class ClosableTeacher:
        provider = "fixture"
        model = "fixture-v1"

        def __init__(self) -> None:
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    teacher = ClosableTeacher()
    monkeypatch.setattr("egsi.cli.build_batch_teacher", lambda *args, **kwargs: teacher)
    monkeypatch.setattr(
        "egsi.cli.run_enrichment_batch",
        lambda *args, **kwargs: {"requested": 1, "processed": 0, "failed": 1, "failures": {}},
    )

    result = CliRunner().invoke(
        app,
        [
            "batch-enrich",
            "--case-file",
            str(_case_file(tmp_path)),
            "--output-root",
            str(tmp_path / "output"),
            "--fixture-teacher",
        ],
    )

    assert result.exit_code == 0
    assert teacher.close_calls == 1


def test_batch_enrich_without_pragmatic_options_keeps_legacy_runner(
    tmp_path: Path, monkeypatch
) -> None:
    class Teacher:
        provider = "fixture"
        model = "fixture-v1"

        def close(self) -> None:
            pass

    calls: list[str] = []
    monkeypatch.setattr(
        "egsi.cli.build_batch_teacher", lambda *args, **kwargs: Teacher()
    )
    monkeypatch.setattr(
        "egsi.cli.run_enrichment_batch",
        lambda *args, **kwargs: calls.append("legacy") or {"route": "legacy"},
    )

    result = CliRunner().invoke(
        app,
        [
            "batch-enrich",
            "--case-file",
            str(_case_file(tmp_path)),
            "--output-root",
            str(tmp_path / "output"),
            "--fixture-teacher",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"route": "legacy"}
    assert calls == ["legacy"]


def test_explicit_pragmatic_batch_forces_zero_internal_retries_and_wires_budget(
    tmp_path: Path, monkeypatch
) -> None:
    observed: dict[str, object] = {}

    class Teacher:
        provider = "codex_exec"
        model = "teacher-model"
        effective_max_retries = 0
        effective_timeout_seconds = 600.0

        def close(self) -> None:
            observed["closed"] = True

    def build(*args, **kwargs):
        observed["build_kwargs"] = kwargs
        return Teacher()

    def pragmatic(*args, **kwargs):
        observed["run_kwargs"] = kwargs
        return {
            "route": "pragmatic",
            "configuration": {
                "effective_max_retries": kwargs["effective_max_retries"],
                "slot_timeout_seconds": kwargs["slot_timeout_seconds"],
            },
        }

    monkeypatch.setattr("egsi.cli.build_batch_teacher", build)
    monkeypatch.setattr(
        "egsi.generation.pragmatic_batch.run_pragmatic_batch", pragmatic
    )
    result = CliRunner().invoke(
        app,
        [
            "batch-enrich",
            "--case-file",
            str(_case_file(tmp_path)),
            "--output-root",
            str(tmp_path / "output"),
            "--provider-config",
            str(tmp_path / "providers.toml"),
            "--max-provider-attempts",
            "2",
            "--retry-transport-once",
            "--global-wall-clock-seconds",
            "14400",
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed["build_kwargs"]["max_retries_override"] == 0
    assert observed["run_kwargs"] == {
        "max_provider_attempts": 2,
        "retry_transport_once": True,
        "resume": False,
        "global_wall_clock_seconds": 14_400,
        "slot_timeout_seconds": 600.0,
        "effective_max_retries": 0,
    }
    assert json.loads(result.stdout)["configuration"] == {
        "effective_max_retries": 0,
        "slot_timeout_seconds": 600.0,
    }
    assert observed["closed"] is True


def test_batch_primary_error_is_not_overwritten_by_close_error(tmp_path: Path, monkeypatch) -> None:
    primary_secret = "PRIMARY-SECRET"
    close_secret = "CLOSE-SECRET"

    class FailingCloseTeacher:
        provider = "fixture"
        model = "fixture-v1"

        def close(self) -> None:
            raise RuntimeError(close_secret)

    monkeypatch.setattr("egsi.cli.build_batch_teacher", lambda *args, **kwargs: FailingCloseTeacher())

    def fail(*args, **kwargs):
        raise ValueError(primary_secret)

    monkeypatch.setattr("egsi.cli.run_enrichment_batch", fail)
    result = CliRunner().invoke(
        app,
        [
            "batch-enrich",
            "--case-file",
            str(_case_file(tmp_path)),
            "--output-root",
            str(tmp_path / "output"),
            "--fixture-teacher",
        ],
    )

    assert result.exit_code != 0
    assert "primary operation failed (Value)" in result.output
    assert "secondary teacher close also failed (Runtime)" in result.output
    assert primary_secret not in result.output
    assert close_secret not in result.output


def test_compile_cli_exits_one_on_invariant_failure(tmp_path: Path, monkeypatch) -> None:
    report = {
        "requested": 1,
        "processed": 1,
        "failed": 0,
        "policy_oracle_leakage": 1,
        "nonzero_t1_rewards": 0,
        "selected_illegal_actions": 0,
        "event_replay_passed": 1,
        "internal_invariant_failure": False,
    }
    monkeypatch.setattr("egsi.cli.compile_trajectory_batch", lambda *args, **kwargs: report)
    monkeypatch.setattr("egsi.cli.trusted_provenance_expectation", lambda *args, **kwargs: {})

    result = CliRunner().invoke(
        app,
        [
            "compile-trajectories",
            "--case-file",
            str(_case_file(tmp_path)),
            "--input-root",
            str(tmp_path / "input"),
            "--output-root",
            str(tmp_path / "output"),
            "--generation-mode",
            "live",
            "--expected-provider",
            "provider",
            "--expected-model",
            "model",
            "--provenance-manifest-sha256",
            "sha256:" + "a" * 64,
            "--provenance-batch-commitment",
            "sha256:" + "b" * 64,
        ],
    )

    assert result.exit_code == 1
    assert json.loads(result.stdout)["policy_oracle_leakage"] == 1


def test_compile_cli_rejects_fixture_input_to_ordinary_project_output_before_writes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from egsi.generation import pilot
    from egsi.teacher.fixture import FixtureTeacher

    input_output = tmp_path / "fixture-input"
    report = pilot.run_enrichment_batch(
        ROOT, [REAL_CASE_ID], input_output, FixtureTeacher()
    )
    assert report["processed"] == 1

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

    forbidden = ROOT / "ordinary-cli-trajectory-output"
    result = CliRunner().invoke(
        app,
        [
            "compile-trajectories",
            "--case-file",
            str(_case_file(tmp_path)),
            "--input-root",
            str(input_output / "enrichment"),
            "--output-root",
            str(forbidden),
            "--root",
            str(ROOT),
            *_provenance_args(report),
        ],
    )

    assert result.exit_code != 0
    assert "trajectory compilation failed (Value)" in result.output
    assert writer_calls == []
    assert not forbidden.exists()

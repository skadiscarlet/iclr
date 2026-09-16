from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from sbs.cli import app
from sbs.replay import semantic_outputs, replay_case, load_smoke_config


REPO = Path(__file__).resolve().parents[2]


def test_cli_lists_required_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("doctor", "validate-registry", "replay", "validate-reports"):
        assert command in result.stdout


def test_doctor_writes_inventory(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(REPO)
    output = tmp_path / "inventory.json"
    result = CliRunner().invoke(app, ["doctor", "--output", str(output)])
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["repository"]["normalized_origin"] == "skadiscarlet/iclr"
    assert payload["repository"]["assistant_repo_access"] == "unverified_404"
    assert payload["resources"]["new_model_api_budget"] == 0
    dumped = json.dumps(payload)
    assert "BEGIN" not in dumped
    assert "sk-" not in dumped


def test_validate_registry_cli() -> None:
    result = CliRunner().invoke(
        app,
        ["validate-registry", "--input", str(REPO / "metadata" / "r01_candidates.jsonl")],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["human_verified_pairs"] == 0


def test_replay_cli_writes_history_and_sbs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(REPO)
    out = tmp_path / "out"
    result = CliRunner().invoke(
        app,
        [
            "replay",
            "--config",
            str(REPO / "configs" / "r01_smoke.json"),
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    summary = json.loads(result.stdout)
    assert summary["model_calls"] == 0
    assert summary["detection_metrics_status"] == "not_evaluated"
    for name in ("support", "counter", "insufficient", "budget"):
        assert (out / name / "history.json").is_file()
        assert (out / name / "sbs.json").is_file()
        state = json.loads((out / name / "state.json").read_text(encoding="utf-8"))
        assert state["terminal"] in {"FINISH", "UNRESOLVED"}
    manifest = json.loads((out / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["model_calls"] == 0
    assert manifest["detection_metrics"] is None
    assert manifest["compute_detection_metrics"] is False
    cfg = load_smoke_config(REPO / "configs" / "r01_smoke.json")
    a = replay_case(REPO / "fixtures" / "r01" / "support", cfg)
    b = replay_case(REPO / "fixtures" / "r01" / "support", cfg)
    assert semantic_outputs(a) == semantic_outputs(b)

"""R01 CLI: doctor, validate-registry, replay, validate-reports."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from sbs.doctor import write_inventory
from sbs.registry import validate_registry_file
from sbs.replay import load_smoke_config, redacted_manifest, replay_fixtures
from sbs.reports import validate_reports
from sbs.schema import canonical_json_bytes, sha256_bytes


app = typer.Typer(no_args_is_help=True, add_completion=False)


def _repo_root() -> Path:
    return Path.cwd()


def _git_head(repo: Path) -> str | None:
    import subprocess

    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


@app.command("doctor")
def doctor(
    output: Path = typer.Option(
        Path("reports/rounds/R01/inventory.json"),
        "--output",
        help="Inventory JSON path.",
    ),
) -> None:
    """Write a non-secret repository and resource inventory."""

    payload = write_inventory(_repo_root(), output)
    typer.echo(
        json.dumps(
            {
                "ok": True,
                "output": str(output),
                "normalized_origin": payload["repository"]["normalized_origin"],
                "head": payload["repository"]["head"],
                "assistant_repo_access": payload["repository"]["assistant_repo_access"],
            },
            sort_keys=True,
        )
    )


@app.command("validate-registry")
def validate_registry(
    input: Path = typer.Option(
        Path("metadata/r01_candidates.jsonl"),
        "--input",
        help="Candidate JSONL path.",
    ),
) -> None:
    """Validate the management-side candidate registry."""

    try:
        result = validate_registry_file(input)
    except (OSError, UnicodeError, ValueError) as exc:
        typer.echo(f"Error: registry validation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(json.dumps(result, sort_keys=True, separators=(",", ":")))


@app.command("replay")
def replay(
    config: Path = typer.Option(
        Path("configs/r01_smoke.json"),
        "--config",
        help="Smoke replay config.",
    ),
    out: Path = typer.Option(
        Path("artifacts/r01_smoke"),
        "--out",
        help="Output directory (gitignored artifacts).",
    ),
) -> None:
    """Replay frozen fixture sequences for History and SBS views."""

    repo = _repo_root()
    try:
        cfg = load_smoke_config(config)
        fixtures_root = (repo / cfg.fixtures_root).resolve()
        config_sha = sha256_bytes(canonical_json_bytes(cfg.model_dump(mode="json")))
        manifest = replay_fixtures(
            cfg,
            fixtures_root,
            Path(out),
            code_sha=_git_head(repo),
            config_sha256=config_sha,
        )
    except Exception as exc:
        typer.echo(f"Error: replay failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        json.dumps(
            {
                "ok": True,
                "model_calls": manifest.model_calls,
                "detection_metrics_status": manifest.detection_metrics_status,
                "cases": sorted(
                    {key.split("/", 1)[0] for key in manifest.output_index}
                ),
                "exit_status": manifest.exit_status,
            },
            sort_keys=True,
        )
    )


@app.command("validate-reports")
def validate_reports_cmd(
    round: str = typer.Option("R01", "--round", help="Round id."),
    phase: str = typer.Option("pre-push", "--phase", help="pre-push or post-push."),
) -> None:
    """Validate machine-readable R01 reports."""

    try:
        result = validate_reports(_repo_root(), round, phase)
    except Exception as exc:
        typer.echo(f"Error: report validation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(json.dumps(result, sort_keys=True, separators=(",", ":")))


def main() -> None:
    app()


if __name__ == "__main__":
    main()

"""Command-line entry point for Phase A data preparation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import NoReturn

import typer

from egsi.contracts.case import CaseManifest, load_case_catalog
from egsi.data.context import build_oracle_context
from egsi.data.context_validation import validate_contexts
from egsi.generation.pilot import (
    compile_trajectory_batch,
    guard_fixture_teacher_output,
    read_case_ids,
    run_enrichment_batch,
    trusted_provenance_expectation,
)
from egsi.teacher.fixture import FixtureTeacher


app = typer.Typer(no_args_is_help=True)


def _fail(message: str) -> NoReturn:
    """Terminate a command with one stable, non-sensitive diagnostic."""

    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code=1)


def _error_label(error: Exception) -> str:
    """Map exceptions to fixed built-in categories without reading their text/type."""

    # Order matters because several specific built-ins inherit broad categories.
    if isinstance(error, TimeoutError):
        return "Timeout"
    if isinstance(error, PermissionError):
        return "Permission"
    if isinstance(error, FileNotFoundError):
        return "NotFound"
    if isinstance(error, UnicodeError):
        return "Encoding"
    if isinstance(error, OSError):
        return "IO"
    if isinstance(error, TypeError):
        return "Type"
    if isinstance(error, ValueError):
        return "Value"
    if isinstance(error, LookupError):
        return "Lookup"
    if isinstance(error, RuntimeError):
        return "Runtime"
    return "Error"


def find_case(catalog: Path, case_id: str) -> CaseManifest:
    """Return one validated catalog row or raise a CLI-safe error."""

    try:
        cases = load_case_catalog(catalog)
    except (OSError, UnicodeError, ValueError):
        _fail("catalog validation failed")
    for case in cases:
        if case.case_id == case_id:
            return case
    raise typer.BadParameter(f"unknown case_id: {case_id}", param_hint="case_id")


def build_teacher(
    config_path: Path | None,
    cache_root: Path,
    audit_root: Path | None = None,
    working_root: Path | None = None,
    max_retries_override: int | None = None,
):
    """Construct the configured provider adapter behind a cache."""

    from egsi.config.providers import load_provider_config
    from egsi.teacher.anthropic import AnthropicTeacher
    from egsi.teacher.cache import CachedTeacher
    from egsi.teacher.codex_exec import CodexExecTeacher
    from egsi.teacher.openai_compatible import OpenAICompatibleTeacher

    config = load_provider_config(config_path).active
    if max_retries_override is not None:
        if type(max_retries_override) is not int or not 0 <= max_retries_override <= 10:
            raise ValueError("max_retries_override must be an integer between 0 and 10")
        config = config.model_copy(update={"max_retries": max_retries_override})
    if config.kind == "anthropic":
        inner = AnthropicTeacher(config)
    elif config.kind == "openai_compatible":
        inner = OpenAICompatibleTeacher(config)
    elif config.kind == "codex_exec":
        if audit_root is None:
            raise ValueError("audit_root is required for codex_exec")
        inner = CodexExecTeacher(
            config,
            audit_root=audit_root,
            working_root=working_root,
        )
    else:
        raise ValueError("unsupported provider kind")
    return CachedTeacher(inner, cache_root)


def build_batch_teacher(
    config_path: Path | None,
    cache_root: Path,
    fixture_teacher: bool,
    *,
    audit_root: Path | None = None,
    working_root: Path | None = None,
    max_retries_override: int | None = None,
):
    """Construct an offline fixture or the existing configured cached teacher."""

    if fixture_teacher and config_path is not None:
        raise typer.BadParameter(
            "--fixture-teacher and --provider-config are mutually exclusive",
            param_hint="--fixture-teacher",
        )
    if fixture_teacher:
        return FixtureTeacher()
    if config_path is None:
        raise typer.BadParameter(
            "--provider-config is required unless --fixture-teacher is set",
            param_hint="--provider-config",
        )
    # Preserve existing two-argument test/custom factories while the built-in
    # factory receives the isolation roots required by ``codex_exec``.
    import inspect

    parameters = tuple(inspect.signature(build_teacher).parameters.values())
    accepts_keywords = any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters
    )
    parameter_names = {parameter.name for parameter in parameters}
    optional = {
        "audit_root": audit_root,
        "working_root": working_root,
        "max_retries_override": max_retries_override,
    }
    kwargs = {
        name: value
        for name, value in optional.items()
        if accepts_keywords or name in parameter_names
    }
    return build_teacher(config_path, cache_root, **kwargs)


def _close_teacher(teacher: object) -> Exception | None:
    try:
        close = getattr(teacher, "close", None)
        if callable(close):
            close()
    except Exception as error:
        return error
    return None


@app.command("validate-catalog")
def validate_catalog(
    catalog: Path = typer.Option(
        Path("data/catalog/cases.jsonl"),
        "--catalog",
        help="Case catalog JSONL path.",
    ),
) -> None:
    """Validate the case catalog."""

    try:
        cases = load_case_catalog(catalog)
    except (OSError, UnicodeError, ValueError):
        _fail("catalog validation failed")
    typer.echo(
        json.dumps(
            {"cases": len(cases), "valid": True},
            sort_keys=True,
            separators=(",", ":"),
        )
    )


@app.command("validate-contexts")
def validate_contexts_command(
    catalog: Path = typer.Option(
        Path("data/catalog/cases.jsonl"),
        "--catalog",
        help="Case catalog JSONL path.",
    ),
    root: Path = typer.Option(Path("."), "--root", help="Project data root."),
    repeat: int = typer.Option(2, "--repeat", help="Deterministic build repetitions."),
    max_chars: int = typer.Option(
        64_000, "--max-chars", help="Maximum canonical context characters."
    ),
    report: Path = typer.Option(
        Path(".work/context-v2-validation.json"),
        "--report",
        help="Atomic JSON validation report path.",
    ),
) -> None:
    """Validate the deterministic 300-case Context V2 gate."""

    try:
        result = validate_contexts(
            catalog=catalog,
            root=root,
            repeat=repeat,
            max_chars=max_chars,
            report_path=report,
        )
    except Exception:
        _fail("context validation failed")
    typer.echo(
        json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    )
    if result.get("overall_valid") is not True:
        raise typer.Exit(code=1)


@app.command("show-context")
def show_context(
    case_id: str = typer.Argument(..., help="Case identifier."),
    catalog: Path = typer.Option(
        Path("data/catalog/cases.jsonl"),
        "--catalog",
        help="Case catalog JSONL path.",
    ),
    root: Path = typer.Option(Path("."), "--root", help="Project data root."),
) -> None:
    """Render one bounded oracle context."""

    case = find_case(catalog, case_id)
    try:
        context = build_oracle_context(root, case)
    except (OSError, UnicodeError, RuntimeError, ValueError):
        _fail("context construction failed")
    typer.echo(context.render())


@app.command("enrich")
def enrich(
    case_id: str = typer.Argument(..., help="Case identifier."),
    provider_config: Path | None = typer.Option(
        None, "--provider-config", help="Permission-restricted provider TOML."
    ),
    output_root: Path | None = typer.Option(
        None, "--output-root", help="Root for cache and enrichment outputs."
    ),
    catalog: Path = typer.Option(
        Path("data/catalog/cases.jsonl"),
        "--catalog",
        help="Case catalog JSONL path.",
    ),
    root: Path = typer.Option(Path("."), "--root", help="Project data root."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Build context without reading provider config."
    ),
    fixture_teacher: bool = typer.Option(
        False, "--fixture-teacher", help="Use deterministic offline fixture output."
    ),
) -> None:
    """Generate one teacher enrichment."""

    if fixture_teacher and provider_config is not None:
        raise typer.BadParameter(
            "--fixture-teacher and --provider-config are mutually exclusive",
            param_hint="--fixture-teacher",
        )
    case = find_case(catalog, case_id)
    if dry_run:
        try:
            context = build_oracle_context(root, case)
        except (OSError, UnicodeError, RuntimeError, ValueError):
            _fail("context construction failed")
        typer.echo(
            json.dumps(
                {
                    "case_id": case.case_id,
                    "context_chars": len(context.render()),
                    "context_sha256": context.sha256,
                    "network_called": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return

    if output_root is None:
        raise typer.BadParameter(
            "--output-root is required unless --dry-run is used",
            param_hint="--output-root",
        )
    if not fixture_teacher and provider_config is None:
        raise typer.BadParameter(
            "--provider-config is required unless --fixture-teacher is set",
            param_hint="--provider-config",
        )

    if fixture_teacher:
        try:
            guard_fixture_teacher_output(root, output_root, FixtureTeacher())
        except ValueError:
            raise typer.BadParameter(
                "fixture output root is outside .work or the system temporary root",
                param_hint="--output-root",
            ) from None

    teacher = None
    result = None
    primary_error: Exception | None = None
    close_error: Exception | None = None
    try:
        from egsi.generation.enrichment import EnrichmentRunner

        teacher = build_batch_teacher(
            provider_config,
            output_root / "cache" / "teacher",
            fixture_teacher,
            audit_root=output_root / "audit" / "teacher",
        )
        guard_fixture_teacher_output(root, output_root, teacher)
        record = EnrichmentRunner(root, teacher).run(
            case, output_root / "enrichment"
        )
        result = record.model_dump(mode="json")
    except Exception as error:
        primary_error = error

    if teacher is not None:
        try:
            close = getattr(teacher, "close", None)
            if callable(close):
                close()
        except Exception as error:
            close_error = error

    if primary_error is not None:
        message = (
            "enrichment primary operation failed "
            f"({_error_label(primary_error)})"
        )
        if close_error is not None:
            message += (
                "; secondary teacher close also failed "
                f"({_error_label(close_error)})"
            )
        _fail(message)
    if close_error is not None:
        _fail(
            "enrichment teacher close failed "
            f"({_error_label(close_error)})"
        )
    if result is None:
        _fail("enrichment failed (missing result)")
    typer.echo(
        json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    )


@app.command("batch-enrich")
def batch_enrich(
    case_file: Path = typer.Option(..., "--case-file", help="Frozen case ID list."),
    output_root: Path = typer.Option(..., "--output-root", help="Pilot output root."),
    provider_config: Path | None = typer.Option(
        None, "--provider-config", help="Permission-restricted provider TOML."
    ),
    root: Path = typer.Option(Path("."), "--root", help="Project data root."),
    fixture_teacher: bool = typer.Option(
        False, "--fixture-teacher", help="Use deterministic offline fixture output."
    ),
    max_provider_attempts: int | None = typer.Option(
        None,
        "--max-provider-attempts",
        help="Enable pragmatic mode with a strict provider-slot ceiling (must be 2).",
    ),
    retry_transport_once: bool = typer.Option(
        False,
        "--retry-transport-once",
        help="Use slot two after a transport failure or interrupted slot.",
    ),
    resume: bool = typer.Option(
        False,
        "--resume",
        help="Resume and strictly validate an existing pragmatic batch state.",
    ),
    global_wall_clock_seconds: int | None = typer.Option(
        None,
        "--global-wall-clock-seconds",
        help="Pragmatic batch wall-clock ceiling (default 14400 when enabled).",
    ),
) -> None:
    """Run a restartable enrichment batch."""

    pragmatic = (
        max_provider_attempts is not None
        or retry_transport_once
        or resume
        or global_wall_clock_seconds is not None
    )
    try:
        case_ids = read_case_ids(case_file)
        teacher = build_batch_teacher(
            provider_config,
            output_root / "cache/teacher",
            fixture_teacher,
            audit_root=output_root / "audit" / "teacher",
            working_root=(output_root / "codex-work") if pragmatic else None,
            max_retries_override=0 if pragmatic else None,
        )
    except typer.BadParameter:
        raise
    except Exception as error:
        _fail(f"batch preparation failed ({_error_label(error)})")

    result = None
    primary_error: Exception | None = None
    try:
        if pragmatic:
            from egsi.generation.pragmatic_batch import run_pragmatic_batch

            effective_retries = getattr(teacher, "effective_max_retries", None)
            effective_timeout = getattr(teacher, "effective_timeout_seconds", None)
            # Fixture/custom test teachers have no provider-internal retry loop;
            # the built-in live adapters expose the validated effective values.
            if effective_retries is None and fixture_teacher:
                effective_retries = 0
            if effective_timeout is None and fixture_teacher:
                effective_timeout = 600.0
            if effective_retries != 0 or not isinstance(
                effective_timeout, (int, float)
            ):
                raise ValueError("pragmatic teacher retry/timeout metadata is unavailable")
            result = run_pragmatic_batch(
                root,
                case_ids,
                output_root,
                teacher,
                max_provider_attempts=(
                    2 if max_provider_attempts is None else max_provider_attempts
                ),
                retry_transport_once=retry_transport_once,
                resume=resume,
                global_wall_clock_seconds=(
                    14_400
                    if global_wall_clock_seconds is None
                    else global_wall_clock_seconds
                ),
                slot_timeout_seconds=float(effective_timeout),
                effective_max_retries=effective_retries,
            )
        else:
            result = run_enrichment_batch(root, case_ids, output_root, teacher)
    except Exception as error:
        primary_error = error
    close_error = _close_teacher(teacher)

    if primary_error is not None:
        message = f"batch primary operation failed ({_error_label(primary_error)})"
        if close_error is not None:
            message += (
                "; secondary teacher close also failed "
                f"({_error_label(close_error)})"
            )
        _fail(message)
    if close_error is not None:
        _fail(f"batch teacher close failed ({_error_label(close_error)})")
    if result is None:
        _fail("batch enrichment failed (missing result)")
    typer.echo(
        json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    )


@app.command("fail-fast-enrich")
def fail_fast_enrich(
    case_file: Path = typer.Option(..., "--case-file", help="Exact recovery case list."),
    scope_case_file: Path = typer.Option(
        Path("configs/p0_cases.txt"),
        "--scope-case-file",
        help="Frozen ordered P0 scope used to prove later cases were not invoked.",
    ),
    output_root: Path = typer.Option(..., "--output-root", help="Existing pilot root."),
    provider_config: Path = typer.Option(
        ..., "--provider-config", help="Permission-restricted provider TOML."
    ),
    root: Path = typer.Option(Path("."), "--root", help="Project data root."),
) -> None:
    """Run the source-controlled serial recovery with unconditional first-failure stop."""

    teacher = None
    try:
        from egsi.generation.fail_fast_batch import run_fail_fast_batch

        teacher = build_batch_teacher(
            provider_config,
            output_root / "cache/teacher",
            False,
            audit_root=output_root / "audit/teacher",
            working_root=output_root / "codex-work",
        )
        report = run_fail_fast_batch(
            root=root,
            case_file=case_file,
            scope_case_file=scope_case_file,
            output_root=output_root,
            teacher=teacher,
        )
    except Exception as error:
        if teacher is not None:
            _close_teacher(teacher)
        _fail(f"fail-fast enrichment failed ({_error_label(error)})")
    close_error = _close_teacher(teacher)
    if close_error is not None:
        _fail(f"fail-fast teacher close failed ({_error_label(close_error)})")
    typer.echo(report.model_dump_json())


@app.command("build-training-ready")
def build_training_ready_command(
    historical_root: Path = typer.Option(
        Path(".work/real-p0-codex-v2"),
        "--historical-root",
        help="Read-only historical first-case artifact root.",
    ),
    batch_root: Path = typer.Option(
        Path(".work/real-p0-pragmatic-v1"),
        "--batch-root",
        help="Completed pragmatic remaining-P0 batch root.",
    ),
    case_file: Path = typer.Option(
        Path("configs/p0_cases.txt"),
        "--case-file",
        help="Frozen ordered ten-case P0 list.",
    ),
    output_root: Path = typer.Option(
        Path(".work/p0-training-ready-v1"),
        "--output-root",
        help="Training-ready package output root.",
    ),
    root: Path = typer.Option(Path("."), "--root", help="Project data root."),
) -> None:
    """Revalidate and package available P0 records without provider calls."""

    try:
        from egsi.generation.training_ready import build_training_ready

        case_ids = read_case_ids(case_file)
        report = build_training_ready(
            root=root,
            case_ids=case_ids,
            historical_root=historical_root,
            batch_root=batch_root,
            output_root=output_root,
        )
    except Exception as error:
        _fail(f"training-ready build failed ({_error_label(error)})")
    typer.echo(
        json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    )


@app.command("build-incremental-training-ready")
def build_incremental_training_ready_command(
    base_package_root: Path = typer.Option(
        Path(".work/p0-training-ready-v1"),
        "--base-package-root",
        help="Read-only verified P0 training-ready package root.",
    ),
    incremental_batch_root: Path = typer.Option(
        Path(".work/real-p1-pragmatic-v1"),
        "--incremental-batch-root",
        help="Completed live pragmatic P1 incremental batch root.",
    ),
    case_file: Path = typer.Option(
        Path("configs/p1_cases.txt"),
        "--case-file",
        help="Frozen ordered thirty-case P1 list.",
    ),
    incremental_case_file: Path = typer.Option(
        Path("configs/p1_pragmatic_incremental_cases.txt"),
        "--incremental-case-file",
        help="Frozen ordered twenty-case P1-minus-P0 list.",
    ),
    output_root: Path = typer.Option(
        Path(".work/p1-training-ready-v1"),
        "--output-root",
        help="Incremental P1 training-ready package output root.",
    ),
    root: Path = typer.Option(Path("."), "--root", help="Project data root."),
) -> None:
    """Revalidate and aggregate P0 plus incremental P1 without provider calls."""

    try:
        from egsi.generation.incremental_training_ready import (
            build_incremental_training_ready,
        )

        report = build_incremental_training_ready(
            root=root,
            case_ids=read_case_ids(case_file),
            base_package_root=base_package_root,
            incremental_batch_root=incremental_batch_root,
            incremental_case_ids=read_case_ids(incremental_case_file),
            output_root=output_root,
        )
    except Exception as error:
        _fail(f"incremental training-ready build failed ({_error_label(error)})")
    typer.echo(
        json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    )


@app.command("verify-fail-fast-enrich")
def verify_fail_fast_enrich(
    case_file: Path = typer.Option(..., "--case-file", help="Exact recovery case list."),
    scope_case_file: Path = typer.Option(
        Path("configs/p0_cases.txt"), "--scope-case-file", help="Frozen ordered P0 scope."
    ),
    output_root: Path = typer.Option(..., "--output-root", help="Existing pilot root."),
    root: Path = typer.Option(Path("."), "--root", help="Project data root."),
) -> None:
    """Independently replay the fail-fast report from source and artifacts."""

    try:
        from egsi.generation.fail_fast_batch import verify_fail_fast_report

        report = verify_fail_fast_report(
            root=root,
            case_file=case_file,
            scope_case_file=scope_case_file,
            output_root=output_root,
        )
    except Exception:
        _fail("fail-fast report verification failed")
    typer.echo(report.model_dump_json())


@app.command("compile-trajectories")
def compile_trajectories(
    case_file: Path = typer.Option(..., "--case-file", help="Frozen case ID list."),
    input_root: Path = typer.Option(..., "--input-root", help="Enrichment record directory."),
    output_root: Path = typer.Option(..., "--output-root", help="Trajectory output root."),
    root: Path = typer.Option(Path("."), "--root", help="Project data root."),
    generation_mode: str = typer.Option(
        ..., "--generation-mode", help="Trusted enrichment mode: fixture or live."
    ),
    expected_provider: str = typer.Option(
        ..., "--expected-provider", help="Trusted teacher provider identity."
    ),
    expected_model: str = typer.Option(
        ...,
        "--expected-model",
        help="Trusted requested/configured model alias.",
    ),
    provenance_manifest_sha256: str = typer.Option(
        ...,
        "--provenance-manifest-sha256",
        help="Trusted SHA-256 commitment of the enrichment provenance manifest.",
    ),
    provenance_batch_commitment: str = typer.Option(
        ...,
        "--provenance-batch-commitment",
        help="Trusted canonical batch commitment from enrichment generation.",
    ),
) -> None:
    """Compile, persist, and replay honest zero-reward T1 trajectories."""

    try:
        report = compile_trajectory_batch(
            root,
            read_case_ids(case_file),
            input_root,
            output_root,
            expected_provenance=trusted_provenance_expectation(
                input_root,
                generation_mode=generation_mode,
                provider=expected_provider,
                model=expected_model,
                manifest_sha256=provenance_manifest_sha256,
                batch_commitment_sha256=provenance_batch_commitment,
            ),
        )
    except Exception as error:
        _fail(f"trajectory compilation failed ({_error_label(error)})")
    typer.echo(
        json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    )
    invariant_failure = (
        report.get("policy_oracle_leakage") != 0
        or report.get("nonzero_t1_rewards") != 0
        or report.get("selected_illegal_actions") != 0
        or report.get("processed", -1) + report.get("failed", -1)
        != report.get("requested", -3)
        or report.get("event_replay_passed") != report.get("processed")
        or report.get("dynamic_verdict", "not_applicable") != "not_applicable"
        or report.get("internal_invariant_failure", False) is not False
    )
    if invariant_failure:
        raise typer.Exit(code=1)


@app.command("build-human-audit")
def build_human_audit_command(
    case_file: Path = typer.Option(..., "--case-file", help="Frozen ten-case P0 list."),
    enrichment_root: Path = typer.Option(
        ..., "--enrichment-root", help="Committed enrichment artifact directory."
    ),
    trajectory_root: Path = typer.Option(
        ..., "--trajectory-root", help="Compiled trajectory artifact root."
    ),
    output_root: Path = typer.Option(
        ..., "--output-root", help="Root receiving reports/human-audit-packet.*."
    ),
    root: Path = typer.Option(Path("."), "--root", help="Project data root."),
) -> None:
    """Independently replay artifacts and emit an unsigned human-review packet."""

    try:
        from egsi.generation.human_audit import build_human_audit

        packet = build_human_audit(
            root=root,
            case_file=case_file,
            enrichment_root=enrichment_root,
            trajectory_root=trajectory_root,
            output_root=output_root,
        )
    except Exception:
        _fail("human audit packet generation failed")
    typer.echo(
        json.dumps(
            {
                "status": packet["status"],
                "case_count": packet["case_count"],
                "automated_gates_passed": packet["automated_gates"]["all_passed"],
                "packet_commitment_sha256": packet["packet_commitment_sha256"],
                "report_json": "reports/human-audit-packet.json",
                "report_markdown": "reports/human-audit-packet.md",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    app()

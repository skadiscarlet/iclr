import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from egsi.cli import app, build_teacher
from egsi.contracts.case import load_case_catalog
from egsi.data.context import build_oracle_context
from egsi.teacher import CachedTeacher, TeacherResponse, committed_teacher_response


ROOT = Path(__file__).resolve().parents[1]
REAL_CASE_ID = "ghsa-2m8h-fgr8-2q9w"


def test_cli_exposes_phase_a_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in [
        "validate-catalog",
        "validate-contexts",
        "show-context",
        "enrich",
        "build-human-audit",
    ]:
        assert command in result.stdout


def test_validate_contexts_cli_wires_full_gate_and_emits_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed = {}
    report = {
        "schema_version": "1.0",
        "validator_version": "context-v2-gate-v1",
        "requested": 300,
        "built": 300,
        "failed": 0,
        "overall_valid": True,
    }

    def validate_contexts(**kwargs):
        observed.update(kwargs)
        return report

    monkeypatch.setattr("egsi.cli.validate_contexts", validate_contexts)
    catalog = tmp_path / "cases.jsonl"
    root = tmp_path / "root"
    target = tmp_path / "report.json"

    result = CliRunner().invoke(
        app,
        [
            "validate-contexts",
            "--catalog",
            str(catalog),
            "--root",
            str(root),
            "--repeat",
            "2",
            "--max-chars",
            "64000",
            "--report",
            str(target),
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout) == report
    assert observed == {
        "catalog": catalog,
        "root": root,
        "repeat": 2,
        "max_chars": 64_000,
        "report_path": target,
    }


def test_validate_contexts_cli_fails_closed_without_leaking_dynamic_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = f"SECRET-{tmp_path}"

    def fail(**_kwargs):
        raise ValueError(secret)

    monkeypatch.setattr("egsi.cli.validate_contexts", fail)

    result = CliRunner().invoke(app, ["validate-contexts"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "context validation failed" in result.stderr
    assert secret not in result.stderr


def test_validate_contexts_cli_exits_nonzero_for_an_invalid_completed_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = {
        "schema_version": "1.0",
        "validator_version": "context-v2-gate-v1",
        "requested": 300,
        "built": 299,
        "failed": 1,
        "overall_valid": False,
    }
    monkeypatch.setattr("egsi.cli.validate_contexts", lambda **_kwargs: report)

    result = CliRunner().invoke(app, ["validate-contexts"])

    assert result.exit_code == 1
    assert json.loads(result.stdout) == report


def test_compile_help_defines_expected_model_as_requested_alias() -> None:
    result = CliRunner().invoke(app, ["compile-trajectories", "--help"])

    assert result.exit_code == 0
    assert "--expected-model" in result.stdout
    assert "requested/configured" in result.stdout
    assert "model alias" in result.stdout


def test_validate_catalog_reports_real_catalog_deterministically() -> None:
    runner = CliRunner()

    first = runner.invoke(app, ["validate-catalog"])
    second = runner.invoke(app, ["validate-catalog"])

    assert first.exit_code == 0
    assert first.stdout == second.stdout
    assert json.loads(first.stdout) == {"cases": 300, "valid": True}


def test_validate_catalog_fails_closed_for_invalid_json(tmp_path) -> None:
    catalog = tmp_path / "cases.jsonl"
    catalog.write_text('{"not": "a case"}\n', encoding="utf-8")

    result = CliRunner().invoke(
        app, ["validate-catalog", "--catalog", str(catalog)]
    )

    assert result.exit_code != 0
    assert '"valid": true' not in result.stdout.lower()


def test_show_context_renders_the_real_bounded_context(monkeypatch) -> None:
    monkeypatch.setenv("EGSI_PROVIDER_CONFIG", "SHOULD_NOT_APPEAR_IN_CONTEXT")
    case = next(
        case
        for case in load_case_catalog(ROOT / "data/catalog/cases.jsonl")
        if case.case_id == REAL_CASE_ID
    )
    expected = build_oracle_context(ROOT, case).render()

    result = CliRunner().invoke(
        app,
        [
            "show-context",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--root",
            str(ROOT),
        ],
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == expected
    assert len(result.stdout.strip()) <= 64_000
    assert "SHOULD_NOT_APPEAR_IN_CONTEXT" not in result.stdout


def test_show_context_rejects_unknown_case_id() -> None:
    missing = "not-a-real-case"

    result = CliRunner().invoke(
        app,
        [
            "show-context",
            missing,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--root",
            str(ROOT),
        ],
    )

    assert result.exit_code != 0
    assert f"unknown case_id: {missing}" in result.output


def test_enrich_dry_run_builds_context_before_provider_access(
    tmp_path, monkeypatch
) -> None:
    calls = 0

    def forbidden_teacher(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("dry-run constructed a teacher")

    monkeypatch.setattr("egsi.cli.build_teacher", forbidden_teacher)
    output_root = tmp_path / "must-not-be-created"
    nonexistent_config = tmp_path / "no-provider-config.toml"
    case = next(
        case
        for case in load_case_catalog(ROOT / "data/catalog/cases.jsonl")
        if case.case_id == REAL_CASE_ID
    )
    context = build_oracle_context(ROOT, case)

    result = CliRunner().invoke(
        app,
        [
            "enrich",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--root",
            str(ROOT),
            "--provider-config",
            str(nonexistent_config),
            "--output-root",
            str(output_root),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "case_id": REAL_CASE_ID,
        "context_chars": len(context.render()),
        "context_sha256": context.sha256,
        "network_called": False,
    }
    assert calls == 0
    assert not output_root.exists()


@pytest.mark.parametrize(
    ("kind", "expected_provider", "base_url"),
    [
        ("openai_compatible", "openai_compatible", "https://api.example/v1"),
        ("anthropic", "anthropic", "https://anthropic.example"),
    ],
)
def test_build_teacher_selects_the_configured_adapter_without_network(
    tmp_path, kind, expected_provider, base_url
) -> None:
    config = tmp_path / f"{kind}.toml"
    config.write_text(
        "\n".join(
            [
                'active_provider = "selected"',
                "",
                "[providers.selected]",
                f'kind = "{kind}"',
                f'base_url = "{base_url}"',
                'api_key = "TOP_SECRET_DO_NOT_PRINT"',
                'model = "teacher-model"',
                "timeout_seconds = 1.0",
                "max_retries = 0",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    config.chmod(0o600)

    teacher = build_teacher(config, tmp_path / "cache")
    try:
        assert isinstance(teacher, CachedTeacher)
        assert teacher.provider == expected_provider
        assert teacher.model == "teacher-model"
        assert not (tmp_path / "cache").exists()
    finally:
        teacher.close()


def test_build_teacher_codex_branch_requires_audit_root_and_wires_adapter(
    tmp_path, monkeypatch
) -> None:
    import egsi.teacher.codex_exec as codex_module

    config = tmp_path / "codex.toml"
    config.write_text(
        "\n".join(
            [
                'active_provider = "selected"',
                "",
                "[providers.selected]",
                'kind = "codex_exec"',
                'model = "teacher-model"',
                f'codex_home = "{tmp_path / "codex-home"}"',
                'model_provider = "test-provider"',
                f'executable = "{tmp_path / "fake-codex"}"',
                'executable_sha256 = "sha256:' + "0" * 64 + '"',
                'expected_cli_version = "0.150.1"',
                "timeout_seconds = 1.0",
                "max_retries = 0",
                "inherit_proxy_env = false",
            ]
        ) + "\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    observed = {}

    class FakeCodexTeacher:
        provider = "codex_exec"

        def __init__(self, provider, *, audit_root, working_root=None):
            observed.update(provider=provider, audit_root=audit_root, working_root=working_root)
            self.model = provider.model

        def close(self):
            pass

    monkeypatch.setattr(codex_module, "CodexExecTeacher", FakeCodexTeacher)

    with pytest.raises(ValueError, match="audit_root"):
        build_teacher(config, tmp_path / "cache")

    teacher = build_teacher(
        config,
        tmp_path / "cache",
        audit_root=tmp_path / "audit",
        working_root=tmp_path / "work",
    )
    assert isinstance(teacher, CachedTeacher)
    assert teacher.provider == "codex_exec"
    assert observed["audit_root"] == tmp_path / "audit"
    assert observed["working_root"] == tmp_path / "work"


def test_build_teacher_codex_retry_override_is_effective_and_observable(
    tmp_path, monkeypatch
) -> None:
    import egsi.teacher.codex_exec as codex_module

    config = tmp_path / "codex.toml"
    config.write_text(
        "\n".join(
            [
                'active_provider = "selected"',
                "",
                "[providers.selected]",
                'kind = "codex_exec"',
                'model = "teacher-model"',
                f'codex_home = "{tmp_path / "codex-home"}"',
                'model_provider = "test-provider"',
                f'executable = "{tmp_path / "fake-codex"}"',
                'executable_sha256 = "sha256:' + "0" * 64 + '"',
                'expected_cli_version = "0.150.1"',
                "timeout_seconds = 600.0",
                "max_retries = 3",
                "inherit_proxy_env = false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    observed = {}

    class FakeCodexTeacher:
        provider = "codex_exec"

        def __init__(self, provider, *, audit_root, working_root=None):
            observed["config"] = provider
            self.config = provider
            self.model = provider.model

        def close(self):
            pass

    monkeypatch.setattr(codex_module, "CodexExecTeacher", FakeCodexTeacher)
    teacher = build_teacher(
        config,
        tmp_path / "cache",
        audit_root=tmp_path / "audit",
        max_retries_override=0,
    )

    assert observed["config"].max_retries == 0
    assert teacher.effective_max_retries == 0
    assert teacher.effective_timeout_seconds == 600.0


def test_enrich_non_dry_run_wires_teacher_cache_and_runner(tmp_path, monkeypatch) -> None:
    import egsi.generation.enrichment as enrichment_module

    observed = {}

    class FakeTeacher:
        provider = "fixture-provider"
        model = "fixture-model"

        def close(self) -> None:
            observed["closed"] = True

    teacher = FakeTeacher()

    def fake_build_teacher(config_path, cache_root, audit_root=None, working_root=None):
        observed["config_path"] = config_path
        observed["cache_root"] = cache_root
        observed["audit_root"] = audit_root
        observed["working_root"] = working_root
        return teacher

    class FakeRecord:
        def model_dump(self, *, mode):
            assert mode == "json"
            return {"case_id": REAL_CASE_ID, "structured_output_valid": True}

    class FakeRunner:
        def __init__(self, root, actual_teacher):
            observed["root"] = root
            observed["teacher"] = actual_teacher

        def run(self, case, output_dir):
            observed["case_id"] = case.case_id
            observed["output_dir"] = output_dir
            return FakeRecord()

    monkeypatch.setattr("egsi.cli.build_teacher", fake_build_teacher)
    monkeypatch.setattr(enrichment_module, "EnrichmentRunner", FakeRunner)
    config = tmp_path / "providers.toml"
    output_root = tmp_path / "output"

    result = CliRunner().invoke(
        app,
        [
            "enrich",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--root",
            str(ROOT),
            "--provider-config",
            str(config),
            "--output-root",
            str(output_root),
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "case_id": REAL_CASE_ID,
        "structured_output_valid": True,
    }
    assert observed == {
        "audit_root": output_root / "audit" / "teacher",
        "cache_root": output_root / "cache" / "teacher",
        "case_id": REAL_CASE_ID,
        "closed": True,
        "config_path": config,
        "output_dir": output_root / "enrichment",
        "root": ROOT,
        "teacher": teacher,
        "working_root": None,
    }


def test_enrich_non_dry_run_requires_output_root_before_provider_access(
    monkeypatch,
) -> None:
    calls = 0

    def forbidden_teacher(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("provider config was accessed")

    monkeypatch.setattr("egsi.cli.build_teacher", forbidden_teacher)

    result = CliRunner().invoke(
        app,
        [
            "enrich",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--root",
            str(ROOT),
        ],
    )

    assert result.exit_code != 0
    assert "--output-root is required" in result.output
    assert calls == 0


def test_enrich_failure_does_not_print_provider_secrets(tmp_path, monkeypatch) -> None:
    import egsi.generation.enrichment as enrichment_module

    secret = "TOP_SECRET_AUTHORIZATION_VALUE"

    class FakeTeacher:
        provider = "openai_compatible"
        model = "fixture-model"

        def close(self) -> None:
            pass

    class FailingRunner:
        def __init__(self, root, teacher):
            pass

        def run(self, case, output_dir):
            raise RuntimeError(f"Authorization: Bearer {secret}")

    monkeypatch.setattr("egsi.cli.build_teacher", lambda *args: FakeTeacher())
    monkeypatch.setattr(enrichment_module, "EnrichmentRunner", FailingRunner)

    result = CliRunner().invoke(
        app,
        [
            "enrich",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--root",
            str(ROOT),
            "--provider-config",
            str(tmp_path / "providers.toml"),
            "--output-root",
            str(tmp_path / "output"),
        ],
    )

    assert result.exit_code != 0
    assert "enrichment primary operation failed (Runtime)" in result.output
    assert secret not in result.stdout
    assert secret not in result.stderr
    assert "Authorization" not in result.stdout
    assert "Authorization" not in result.stderr


def test_enrich_keeps_run_failure_primary_when_close_also_fails(
    tmp_path, monkeypatch
) -> None:
    import egsi.generation.enrichment as enrichment_module

    secret = "PRIMARY_SECRET_MUST_BE_REDACTED"

    class PrimaryError(RuntimeError):
        pass

    class CloseError(RuntimeError):
        pass

    class FailingCloseTeacher:
        provider = "openai_compatible"
        model = "fixture-model"

        def close(self) -> None:
            raise CloseError("secondary close failure")

    class PrimaryFailingRunner:
        def __init__(self, root, teacher):
            pass

        def run(self, case, output_dir):
            raise PrimaryError(f"Authorization: Bearer {secret}")

    monkeypatch.setattr(
        "egsi.cli.build_teacher", lambda *args: FailingCloseTeacher()
    )
    monkeypatch.setattr(
        enrichment_module, "EnrichmentRunner", PrimaryFailingRunner
    )

    result = CliRunner().invoke(
        app,
        [
            "enrich",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--root",
            str(ROOT),
            "--provider-config",
            str(tmp_path / "providers.toml"),
            "--output-root",
            str(tmp_path / "output"),
        ],
    )

    assert result.exit_code != 0
    assert "primary operation failed (Runtime)" in result.output
    assert "secondary teacher close also failed (Runtime)" in result.output
    assert result.output.index("primary operation failed") < result.output.index(
        "secondary teacher close"
    )
    assert secret not in result.stdout
    assert secret not in result.stderr
    assert "Authorization" not in result.stdout
    assert "Authorization" not in result.stderr


def test_enrich_reports_close_failure_after_success_without_emitting_record(
    tmp_path, monkeypatch
) -> None:
    import egsi.generation.enrichment as enrichment_module

    class CloseError(RuntimeError):
        pass

    class FailingCloseTeacher:
        provider = "openai_compatible"
        model = "fixture-model"

        def close(self) -> None:
            raise CloseError("Authorization: Bearer CLOSE_SECRET")

    class FakeRecord:
        def model_dump(self, *, mode):
            return {"case_id": REAL_CASE_ID}

    class SuccessfulRunner:
        def __init__(self, root, teacher):
            pass

        def run(self, case, output_dir):
            return FakeRecord()

    monkeypatch.setattr(
        "egsi.cli.build_teacher", lambda *args: FailingCloseTeacher()
    )
    monkeypatch.setattr(enrichment_module, "EnrichmentRunner", SuccessfulRunner)

    result = CliRunner().invoke(
        app,
        [
            "enrich",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--root",
            str(ROOT),
            "--provider-config",
            str(tmp_path / "providers.toml"),
            "--output-root",
            str(tmp_path / "output"),
        ],
    )

    assert result.exit_code != 0
    assert "teacher close failed (Runtime)" in result.output
    assert REAL_CASE_ID not in result.stdout
    assert "CLOSE_SECRET" not in result.output
    assert "Authorization" not in result.output


def test_enrich_accepts_teacher_without_close_method(tmp_path, monkeypatch) -> None:
    import egsi.generation.enrichment as enrichment_module

    class TeacherWithoutClose:
        provider = "fixture-provider"
        model = "fixture-model"

    class FakeRecord:
        def model_dump(self, *, mode):
            return {"case_id": REAL_CASE_ID}

    class SuccessfulRunner:
        def __init__(self, root, teacher):
            pass

        def run(self, case, output_dir):
            return FakeRecord()

    monkeypatch.setattr(
        "egsi.cli.build_teacher", lambda *args: TeacherWithoutClose()
    )
    monkeypatch.setattr(enrichment_module, "EnrichmentRunner", SuccessfulRunner)

    result = CliRunner().invoke(
        app,
        [
            "enrich",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--root",
            str(ROOT),
            "--provider-config",
            str(tmp_path / "providers.toml"),
            "--output-root",
            str(tmp_path / "output"),
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"case_id": REAL_CASE_ID}


def test_enrich_never_echoes_dynamic_exception_class_names(
    tmp_path, monkeypatch
) -> None:
    import egsi.generation.enrichment as enrichment_module

    primary_class_secret = "ghp_6f4d2a9c8b7e"
    close_class_secret = "sk_live_7e3c1a5d9b2f"
    DynamicPrimaryError = type(primary_class_secret, (RuntimeError,), {})
    DynamicCloseError = type(close_class_secret, (RuntimeError,), {})

    class FailingCloseTeacher:
        provider = "openai_compatible"
        model = "fixture-model"

        def close(self) -> None:
            raise DynamicCloseError("safe message")

    class PrimaryFailingRunner:
        def __init__(self, root, teacher):
            pass

        def run(self, case, output_dir):
            raise DynamicPrimaryError("safe message")

    monkeypatch.setattr(
        "egsi.cli.build_teacher", lambda *args: FailingCloseTeacher()
    )
    monkeypatch.setattr(
        enrichment_module, "EnrichmentRunner", PrimaryFailingRunner
    )

    result = CliRunner().invoke(
        app,
        [
            "enrich",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--root",
            str(ROOT),
            "--provider-config",
            str(tmp_path / "providers.toml"),
            "--output-root",
            str(tmp_path / "output"),
        ],
    )

    assert result.exit_code != 0
    assert "primary operation failed (Runtime)" in result.output
    assert "secondary teacher close also failed (Runtime)" in result.output
    assert primary_class_secret not in result.stdout
    assert primary_class_secret not in result.stderr
    assert close_class_secret not in result.stdout
    assert close_class_secret not in result.stderr


def test_enrich_rejects_symlinked_teacher_cache_without_external_write(
    tmp_path, monkeypatch
) -> None:
    output_root = tmp_path / "output"
    outside = tmp_path / "outside"
    output_root.mkdir()
    outside.mkdir()
    (output_root / "cache").symlink_to(outside, target_is_directory=True)

    class CatalogFixtureTeacher:
        provider = "fixture"
        model = "catalog-fixture"

        def generate(self, request):
            context = json.loads(request.user)["context"]
            path = sorted(context["source_files"])[0]
            payload = {
                "family": context["family"],
                "hypothesis": "A patch-grounded hypothesis.",
                "locations": [{"path": path, "role": "guard"}],
                "obligations": [
                    {
                        "obligation_id": "O-1",
                        "kind": "guard",
                        "description": "Check the guard.",
                        "status": "unknown",
                    }
                ],
                "trace": [
                    {
                        "step_id": "S-1",
                        "goal": "CHECK_GUARD_OR_SANITIZER",
                        "operation": "find_guard",
                        "target_kind": "path",
                        "target_id": path,
                        "expected_evidence_type": "source_location",
                        "tool_class": "repository_index",
                    }
                ],
                "authorization": None,
                "limitations": ["runtime impact remains unknown"],
            }
            return committed_teacher_response(
                provider_request_id="fixture-1",
                provider=self.provider,
                model=self.model,
                requested_model=self.model,
                provider_response_model=self.model,
                text=json.dumps(payload, sort_keys=True),
                usage={},
                latency_ms=0.0,
            )

    def cached_fixture(config_path, cache_root):
        return CachedTeacher(CatalogFixtureTeacher(), cache_root)

    monkeypatch.setattr("egsi.cli.build_teacher", cached_fixture)

    result = CliRunner().invoke(
        app,
        [
            "enrich",
            REAL_CASE_ID,
            "--catalog",
            str(ROOT / "data/catalog/cases.jsonl"),
            "--root",
            str(ROOT),
            "--provider-config",
            str(tmp_path / "providers.toml"),
            "--output-root",
            str(output_root),
        ],
    )

    assert result.exit_code != 0
    assert "primary operation failed (Runtime)" in result.output
    assert list(outside.rglob("*")) == []

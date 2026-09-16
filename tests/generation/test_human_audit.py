from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from egsi.cli import app
from egsi.generation.pilot import (
    compile_trajectory_batch,
    read_case_ids,
    run_enrichment_batch,
)
from egsi.teacher.fixture import FixtureTeacher


ROOT = Path(__file__).resolve().parents[2]
CASE_FILE = ROOT / "configs/p0_cases.txt"


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _commitment(value: dict[str, object]) -> str:
    canonical = dict(value)
    canonical.pop("packet_commitment_sha256", None)
    raw = json.dumps(
        canonical,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(raw)


def _named_commitment(value: dict[str, object], field: str) -> str:
    canonical = dict(value)
    canonical.pop(field, None)
    return _sha256(
        json.dumps(
            canonical,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _write_audit_manifest(
    output: Path,
    name: str,
    *,
    provider: str,
    model: str,
    status: str,
    failure_code: str | None,
    metadata_items: list[dict[str, object]],
    response_commitment: str | None = None,
    usage: dict[str, int] | None = None,
    latency_ms: float = 10.0,
    request_hash: str = "sha256:" + "1" * 64,
) -> Path:
    assert status == "quarantined"
    assert failure_code == "provider_failure_event"
    assert response_commitment is None and usage is None
    attempt = output / f"audit/teacher/{request_hash}/{name}/attempt-00"
    attempt.mkdir(parents=True)
    metadata = b"".join(
        json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
        for item in metadata_items
    )
    (attempt / "events.metadata.jsonl").write_bytes(metadata)
    event_counts: dict[str, int] = {}
    for item in metadata_items:
        event_type = str(item["type"])
        event_counts[event_type] = event_counts.get(event_type, 0) + 1
    empty_hash = _sha256(b"")
    manifest: dict[str, object] = {
        "schema_version": "1.0",
        "provider": provider,
        "model": model,
        "requested_model": model,
        "provider_response_model": None,
        "cli_version": "0.104.0",
        "request_hash": request_hash,
        "invocation_id": name,
        "attempt": 0,
        "status": status,
        "failure_code": failure_code,
        "redacted_argv": ["<executable>"],
        "stdin_length": 0,
        "stdin_sha256": empty_hash,
        "system_length": 0,
        "system_sha256": empty_hash,
        "schema_length": 0,
        "schema_sha256": empty_hash,
        "stdout_length": 0,
        "stdout_sha256": empty_hash,
        "stderr_length": 0,
        "stderr_sha256": empty_hash,
        "stderr_truncated_in_memory": False,
        "exit_code": 1,
        "signal": None,
        "event_counts": dict(sorted(event_counts.items())),
        "usage": None,
        "latency_ms": latency_ms,
        "max_tokens": 8192,
        "max_tokens_enforced_by_cli": False,
        "response_length": None,
        "response_sha256": None,
        "response_commitment_sha256": None,
        "events_metadata_length": len(metadata),
        "events_metadata_sha256": _sha256(metadata),
    }
    manifest["audit_commitment_sha256"] = _named_commitment(
        manifest, "audit_commitment_sha256"
    )
    (attempt / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    (attempt / "quarantine.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "status": "quarantined",
                "failure_code": failure_code,
                "positive_transition_written": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return attempt / "manifest.json"


def _write_complete_codex_audit(
    output: Path,
    name: str,
    *,
    request,
    response,
    metadata_items: list[dict[str, object]] | None = None,
    write_cache: bool = True,
) -> tuple[Path, str]:
    from egsi.teacher.base import teacher_request_hash
    from egsi.teacher.cache import TeacherCache, cache_key

    provider = "codex_exec"
    model = response.model
    request_hash = teacher_request_hash(request)
    key = cache_key(provider, model, request)
    if write_cache:
        TeacherCache(output / "cache/teacher").write(key, response)
    attempt = output / f"audit/teacher/{request_hash}/{name}/attempt-00"
    attempt.mkdir(parents=True)
    items = metadata_items or [
        {"index": 0, "type": "thread.started"},
        {"index": 1, "type": "turn.started"},
        {"index": 2, "item_type": "agent_message", "type": "item.completed"},
        {"index": 3, "type": "turn.completed"},
    ]
    metadata = b"".join(
        json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
        for item in items
    )
    (attempt / "events.metadata.jsonl").write_bytes(metadata)
    schema_raw = json.dumps(
        request.schema,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    system_raw = request.system.encode("utf-8")
    stdin_raw = (
        request.user
        + f"\n\n[EGSI output budget hint: at most {request.max_tokens} tokens.]"
    ).encode("utf-8")
    event_counts: dict[str, int] = {}
    for item in items:
        event_type = str(item["type"])
        event_counts[event_type] = event_counts.get(event_type, 0) + 1
    response_raw = response.text.encode("utf-8")
    manifest: dict[str, object] = {
        "schema_version": "1.0",
        "provider": provider,
        "model": model,
        "requested_model": model,
        "provider_response_model": response.provider_response_model,
        "cli_version": "0.104.0",
        "request_hash": request_hash,
        "invocation_id": name,
        "attempt": 0,
        "status": "committed",
        "failure_code": None,
        "redacted_argv": ["<executable>"],
        "stdin_length": len(stdin_raw),
        "stdin_sha256": _sha256(stdin_raw),
        "system_length": len(system_raw),
        "system_sha256": _sha256(system_raw),
        "schema_length": len(schema_raw),
        "schema_sha256": _sha256(schema_raw),
        "provider_output_schema_transform": "codex-strict-required-v1",
        "provider_output_schema_length": len(schema_raw),
        "provider_output_schema_sha256": _sha256(schema_raw),
        "stdout_length": 0,
        "stdout_sha256": _sha256(b""),
        "stderr_length": 0,
        "stderr_sha256": _sha256(b""),
        "stderr_truncated_in_memory": False,
        "exit_code": 0,
        "signal": None,
        "event_counts": dict(sorted(event_counts.items())),
        "usage": response.usage,
        "latency_ms": response.latency_ms,
        "max_tokens": request.max_tokens,
        "max_tokens_enforced_by_cli": False,
        "response_length": len(response_raw),
        "response_sha256": _sha256(response_raw),
        "response_commitment_sha256": response.response_commitment_sha256,
        "events_metadata_length": len(metadata),
        "events_metadata_sha256": _sha256(metadata),
    }
    manifest["audit_commitment_sha256"] = _named_commitment(
        manifest, "audit_commitment_sha256"
    )
    manifest_path = attempt / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return manifest_path, key


@pytest.fixture(scope="module")
def compiled_fixture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("human-audit") / "pilot"
    case_ids = read_case_ids(CASE_FILE)
    enrichment = run_enrichment_batch(ROOT, case_ids, output, FixtureTeacher())
    compile_trajectory_batch(
        ROOT,
        case_ids,
        output / "enrichment",
        output,
        expected_provenance=enrichment["provenance"],
    )
    return output


def test_build_human_audit_revalidates_fixture_artifacts_and_commits_packet(
    compiled_fixture: Path,
) -> None:
    from egsi.generation.human_audit import build_human_audit

    packet = build_human_audit(
        root=ROOT,
        case_file=CASE_FILE,
        enrichment_root=compiled_fixture / "enrichment",
        trajectory_root=compiled_fixture,
        output_root=compiled_fixture,
    )

    assert packet["schema_version"] == "1.0"
    assert packet["status"] == "AWAITING_HUMAN_AUDIT"
    assert packet["case_count"] == 10
    assert packet["generation_mode"] == "fixture"
    assert packet["provider"] == "fixture"
    assert packet["model"] == "fixture-v1"
    assert packet["provider_response_models"] == ["fixture-v1"]
    assert packet["total_usage"] == {
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "cache_write_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
    }
    assert packet["latency_ms"] == {
        "min": 0,
        "median": 0.0,
        "p95": 0.0,
        "max": 0,
    }
    assert packet["cost"] == {
        "value": "unknown",
        "reason": "subscription/pricing_not_configured",
    }
    assert packet["thresholds"] == {
        "semantic_usable_min": 8,
        "max_revision_cases": 2,
    }
    assert packet["automated_gates"]["all_passed"] is True
    assert all(
        value is True
        for key, value in packet["automated_gates"].items()
        if key != "all_passed"
    )
    assert packet["packet_commitment_sha256"] == _commitment(packet)
    assert len(packet["cases"]) == 10
    for case in packet["cases"]:
        assert case["human_semantic_judgment"] is None
        assert case["human_notes"] is None
        assert case["automated_gates"]["all_passed"] is True
        assert case["context"]["sha256"].startswith("sha256:")
        assert case["context"]["receipt_commitment_sha256"].startswith("sha256:")
        assert case["context"]["effective_patch_source"] in {
            "raw",
            "canonical_git_diff",
        }
        assert case["enrichment"]["file"].startswith("enrichment/")
        assert case["enrichment"]["sha256"].startswith("sha256:")
        assert case["teacher_response"]["commitment_sha256"].startswith("sha256:")
        assert case["trajectory"]["event_file"].startswith("episodes/")
        assert case["trajectory"]["transition_file"].startswith("episodes/")
        assert case["trajectory"]["parquet_file"] == "trajectories/train.parquet"
        assert case["trajectory"]["replay"]["closed"] is True

    json_path = compiled_fixture / "reports/human-audit-packet.json"
    md_path = compiled_fixture / "reports/human-audit-packet.md"
    assert json.loads(json_path.read_text(encoding="utf-8")) == packet
    markdown = md_path.read_text(encoding="utf-8")
    assert "AWAITING_HUMAN_AUDIT" in markdown
    assert "PASSED" not in markdown
    assert "human_semantic_judgment" in markdown
    assert not any(path.name.endswith(".tmp") for path in json_path.parent.iterdir())
    assert oct(json_path.stat().st_mode & 0o777) == "0o600"
    assert oct(md_path.stat().st_mode & 0o777) == "0o600"
    serialized = json.dumps(packet, ensure_ascii=False)
    for forbidden in (
        "raw_prompt",
        '"reasoning":',
        "api_key",
        "actual_check",
        "attacker_principal",
    ):
        assert forbidden not in serialized.casefold()


def test_human_audit_does_not_trust_enrichment_or_trajectory_summary_claims(
    compiled_fixture: Path,
) -> None:
    from egsi.generation.human_audit import build_human_audit

    enrichment_summary = compiled_fixture / "reports/enrichment-summary.json"
    trajectory_summary = compiled_fixture / "reports/trajectory-validation.json"
    original_enrichment = enrichment_summary.read_bytes()
    original_trajectory = trajectory_summary.read_bytes()
    try:
        enrichment_summary.write_text(
            json.dumps({"processed": 0, "failed": 10, "usage": {"input_tokens": 999}}),
            encoding="utf-8",
        )
        trajectory_summary.write_text(
            json.dumps(
                {
                    "processed": 0,
                    "event_replay_passed": 0,
                    "policy_oracle_leakage": 999,
                }
            ),
            encoding="utf-8",
        )

        packet = build_human_audit(
            root=ROOT,
            case_file=CASE_FILE,
            enrichment_root=compiled_fixture / "enrichment",
            trajectory_root=compiled_fixture,
            output_root=compiled_fixture,
        )
    finally:
        enrichment_summary.write_bytes(original_enrichment)
        trajectory_summary.write_bytes(original_trajectory)

    assert packet["status"] == "AWAITING_HUMAN_AUDIT"
    assert packet["automated_gates"]["all_passed"] is True
    assert packet["total_usage"]["input_tokens"] == 0


def test_human_audit_missing_trajectory_is_an_automated_gate_failure(
    compiled_fixture: Path, tmp_path: Path
) -> None:
    from egsi.generation.human_audit import build_human_audit

    output = tmp_path / "pilot"
    shutil.copytree(compiled_fixture, output)
    event_file = next((output / "episodes").glob("*.events.jsonl"))
    event_file.unlink()

    packet = build_human_audit(
        root=ROOT,
        case_file=CASE_FILE,
        enrichment_root=output / "enrichment",
        trajectory_root=output,
        output_root=output,
    )

    assert packet["status"] == "AUTOMATED_GATE_FAILED"
    assert packet["automated_gates"]["trajectories_complete"] is False
    assert packet["automated_gates"]["replay_valid"] is False
    assert packet["automated_gates"]["all_passed"] is False
    assert any(
        case["automated_gates"]["trajectory_linked"] is False
        for case in packet["cases"]
    )


def test_prior_provider_failures_are_reported_but_do_not_fail_tool_gate(
    compiled_fixture: Path, tmp_path: Path
) -> None:
    from egsi.generation.human_audit import build_human_audit

    output = tmp_path / "pilot"
    shutil.copytree(compiled_fixture, output)
    _write_audit_manifest(
        output,
        "prior-provider-failure",
        provider="fixture",
        model="fixture-v1",
        status="quarantined",
        failure_code="provider_failure_event",
        metadata_items=[
            {"index": 0, "type": "thread.started"},
            {"index": 1, "type": "turn.started"},
            {"index": 2, "type": "error"},
        ],
    )

    packet = build_human_audit(
        root=ROOT,
        case_file=CASE_FILE,
        enrichment_root=output / "enrichment",
        trajectory_root=output,
        output_root=output,
    )

    assert packet["status"] == "AWAITING_HUMAN_AUDIT"
    assert packet["automated_gates"]["tool_quarantine_zero"] is True
    assert packet["automated_gates"]["all_passed"] is True
    assert packet["attempts"]["prior_provider_failure_count"] == 1
    assert packet["attempts"]["prior_provider_failure_codes"] == {
        "provider_failure_event": 1
    }
    assert packet["attempts"]["forbidden_tool_event_count"] == 0


def test_live_human_audit_binds_response_and_exact_final_teacher_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.human_audit as human_audit_module
    from egsi.contracts.case import load_case_catalog
    from egsi.contracts.enrichment import EnrichmentRecord
    from egsi.data.context import build_oracle_context
    from egsi.generation.enrichment import _prompt_vocabulary, allowed_action_values
    from egsi.generation.human_audit import (
        _repair_info,
        _request_for_record,
        _request_variants_for_record,
        build_human_audit,
        historical_expectation_value,
    )
    from egsi.teacher.base import (
        TeacherRequest,
        TeacherResponse,
        committed_teacher_response,
    )
    from egsi.teacher.cache import CachedTeacher, TeacherCache, cache_key

    class LiveFixtureTeacher:
        provider = "codex_exec"
        model = "offline-live-model"

        def __init__(self) -> None:
            self.fixture = FixtureTeacher()
            self.calls = 0

        def generate(self, request):
            self.calls += 1
            fixture = self.fixture.generate(request)
            return committed_teacher_response(
                provider_request_id=f"offline-live-{self.calls}",
                provider=self.provider,
                model=self.model,
                requested_model=self.model,
                provider_response_model="offline-live-actual",
                text=fixture.text,
                usage={
                    "input_tokens": 0,
                    "cached_input_tokens": 0,
                    "cache_write_input_tokens": 0,
                    "output_tokens": 0,
                    "reasoning_output_tokens": 0,
                },
                latency_ms=0.0,
            )

    output = tmp_path / "live-pilot"
    case_ids = read_case_ids(CASE_FILE)
    live_teacher = LiveFixtureTeacher()
    enrichment = run_enrichment_batch(
        ROOT,
        case_ids,
        output,
        CachedTeacher(live_teacher, output / "cache/teacher"),
    )
    compile_trajectory_batch(
        ROOT,
        case_ids,
        output / "enrichment",
        output,
        expected_provenance=enrichment["provenance"],
    )
    catalog = {
        case.case_id: case
        for case in load_case_catalog(ROOT / "data/catalog/cases.jsonl")
    }
    vocabulary = _prompt_vocabulary(allowed_action_values(ROOT))
    manifests: list[Path] = []
    first_record: EnrichmentRecord | None = None
    for index, case_id in enumerate(case_ids):
        record = EnrichmentRecord.model_validate_json(
            (output / f"enrichment/{case_id}.json").read_bytes()
        )
        first_record = first_record or record
        info = _repair_info(
            build_oracle_context(ROOT, catalog[case_id]), vocabulary, record
        )
        assert info["request_variant_verified"] is True
        assert info["expected_teacher_request_hash"].startswith("sha256:")
        request = _request_for_record(
            build_oracle_context(ROOT, catalog[case_id]), vocabulary, record
        )
        assert request is not None
        key = cache_key("codex_exec", "offline-live-model", request)
        cache_path = TeacherCache(output / "cache/teacher").path_for(key)
        response = TeacherResponse.model_validate_json(cache_path.read_bytes())
        manifests.append(
            _write_complete_codex_audit(
                output,
                f"invocation-{index}",
                request=request,
                response=response,
                write_cache=False,
            )[0]
        )

    empty_commitment = _sha256(b"[]")
    trusted_expectation: dict[str, object] = {
        "value": historical_expectation_value(
            provider="codex_exec",
            model="offline-live-model",
            historical_unbound_committed_count=0,
            historical_unbound_committed_set_sha256=empty_commitment,
            historical_response_commitment_set_sha256=empty_commitment,
            provider_failure_event_quarantine_count=0,
            provider_failure_codes={},
            provider_failure_audit_commitment_set_sha256=empty_commitment,
        )
    }
    def trusted_expectation_with_evidence(
        _root: Path, **_: object
    ) -> tuple[dict[str, object], dict[str, str]]:
        value = trusted_expectation["value"]
        assert type(value) is dict
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return value, {
            "expectation_file": (
                "configs/historical-teacher-audit-expectation.v1.json"
            ),
            "expectation_file_sha256": _sha256(raw),
            "expectation_commitment_sha256": value[
                "expectation_commitment_sha256"
            ],
        }

    monkeypatch.setattr(
        human_audit_module,
        "load_historical_expectation_with_evidence",
        trusted_expectation_with_evidence,
    )

    packet = build_human_audit(
        root=ROOT,
        case_file=CASE_FILE,
        enrichment_root=output / "enrichment",
        trajectory_root=output,
        output_root=output,
    )
    assert packet["status"] == "AWAITING_HUMAN_AUDIT"
    assert packet["automated_gates"]["teacher_requests_bound"] is True
    assert all(
        case["automated_gates"]["teacher_request_bound"] is True
        for case in packet["cases"]
    )

    # A controlled first-case historical baseline must coexist with the ten
    # current legal responses instead of being treated as a zero-history gate.
    historical: list[tuple[Path, str]] = []
    for index in (1, 2):
        historical_request = TeacherRequest(
            system="historical",
            user=f"historical-{index}",
            schema={
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
            temperature=0.0,
            max_tokens=8192,
        )
        historical_response = committed_teacher_response(
            provider_request_id=f"historical-thread-{index}",
            provider="codex_exec",
            model="offline-live-model",
            requested_model="offline-live-model",
            provider_response_model="offline-live-actual",
            text="{}",
            usage={
                "input_tokens": 0,
                "cached_input_tokens": 0,
                "cache_write_input_tokens": 0,
                "output_tokens": 0,
                "reasoning_output_tokens": 0,
            },
            latency_ms=0.0,
            cached=False,
        )
        historical.append(
            _write_complete_codex_audit(
                output,
                f"historical-{index}",
                request=historical_request,
                response=historical_response,
            )
        )
    from egsi.generation.human_audit import _scan_teacher_audit

    expected_requests = {}
    for case_id in case_ids:
        record = EnrichmentRecord.model_validate_json(
            (output / f"enrichment/{case_id}.json").read_bytes()
        )
        expected_requests.update(
            _request_variants_for_record(
                build_oracle_context(ROOT, catalog[case_id]),
                vocabulary,
                record,
            )
        )
    baseline_scan = _scan_teacher_audit(
        output,
        "codex_exec",
        "offline-live-model",
        expected_requests=expected_requests,
    )
    assert baseline_scan["historical_unbound_committed"] == 2
    trusted_expectation["value"] = historical_expectation_value(
        provider="codex_exec",
        model="offline-live-model",
        historical_unbound_committed_count=2,
        historical_unbound_committed_set_sha256=baseline_scan[
            "historical_unbound_set_sha256"
        ],
        historical_response_commitment_set_sha256=baseline_scan[
            "historical_response_commitment_set_sha256"
        ],
        provider_failure_event_quarantine_count=0,
        provider_failure_codes={},
        provider_failure_audit_commitment_set_sha256=baseline_scan[
            "provider_failure_audit_commitment_set_sha256"
        ],
    )
    unbound_without_baseline = build_human_audit(
        root=ROOT,
        case_file=CASE_FILE,
        enrichment_root=output / "enrichment",
        trajectory_root=output,
        output_root=output,
    )
    assert unbound_without_baseline["status"] == "AUTOMATED_GATE_FAILED"
    baseline: dict[str, object] = {
        "schema_version": "2.0",
        "attestation_kind": "historical_teacher_audit_observation",
        "attestation_mode": "rerun_tests",
        "provider": "codex_exec",
        "model": "offline-live-model",
        "historical_unbound_committed_count": 2,
        "historical_unbound_committed_set_sha256": baseline_scan[
            "historical_unbound_set_sha256"
        ],
        "historical_response_commitment_set_sha256": baseline_scan[
            "historical_response_commitment_set_sha256"
        ],
        "provider_failure_event_quarantine_count": 0,
        "provider_failure_codes": {},
        "provider_failure_audit_commitment_set_sha256": baseline_scan[
            "provider_failure_audit_commitment_set_sha256"
        ],
    }
    baseline["baseline_commitment_sha256"] = _named_commitment(
        baseline, "baseline_commitment_sha256"
    )
    baseline_path = output / "reports/historical-teacher-audit-baseline.json"
    baseline_path.write_text(
        json.dumps(baseline, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    baseline_path.chmod(0o600)

    historical_packet = build_human_audit(
        root=ROOT,
        case_file=CASE_FILE,
        enrichment_root=output / "enrichment",
        trajectory_root=output,
        output_root=output,
    )
    assert historical_packet["status"] == "AWAITING_HUMAN_AUDIT"
    assert historical_packet["automated_gates"][
        "historical_unbound_set_exact"
    ] is True
    assert historical_packet["attempts"][
        "teacher_historical_unbound_committed"
    ] == 2

    # Adding a third historical item must fail the fixed baseline.
    extra_request = TeacherRequest(
        system="historical",
        user="historical-extra",
        schema={
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        temperature=0.0,
        max_tokens=8192,
    )
    extra_response = committed_teacher_response(
        provider_request_id="historical-thread-extra",
        provider="codex_exec",
        model="offline-live-model",
        requested_model="offline-live-model",
        provider_response_model="offline-live-actual",
        text="{}",
        usage={
            "input_tokens": 0,
            "cached_input_tokens": 0,
            "cache_write_input_tokens": 0,
            "output_tokens": 0,
            "reasoning_output_tokens": 0,
        },
        latency_ms=0.0,
        cached=False,
    )
    extra_manifest, extra_key = _write_complete_codex_audit(
        output,
        "historical-extra",
        request=extra_request,
        response=extra_response,
    )
    added_packet = build_human_audit(
        root=ROOT,
        case_file=CASE_FILE,
        enrichment_root=output / "enrichment",
        trajectory_root=output,
        output_root=output,
    )
    assert added_packet["status"] == "AUTOMATED_GATE_FAILED"
    assert added_packet["automated_gates"][
        "historical_unbound_set_exact"
    ] is False
    shutil.rmtree(extra_manifest.parents[2])
    TeacherCache(output / "cache/teacher").path_for(extra_key).unlink()

    # Missing and same-count replacement histories must also fail.
    removed_manifest, removed_key = historical[1]
    shutil.rmtree(removed_manifest.parents[2])
    TeacherCache(output / "cache/teacher").path_for(removed_key).unlink()
    missing_packet = build_human_audit(
        root=ROOT,
        case_file=CASE_FILE,
        enrichment_root=output / "enrichment",
        trajectory_root=output,
        output_root=output,
    )
    assert missing_packet["automated_gates"][
        "historical_unbound_set_exact"
    ] is False
    replacement_manifest, _ = _write_complete_codex_audit(
        output,
        "historical-replacement",
        request=extra_request,
        response=extra_response,
    )
    assert replacement_manifest.exists()
    replacement_packet = build_human_audit(
        root=ROOT,
        case_file=CASE_FILE,
        enrichment_root=output / "enrichment",
        trajectory_root=output,
        output_root=output,
    )
    assert replacement_packet["attempts"][
        "teacher_historical_unbound_committed"
    ] == 2
    assert replacement_packet["automated_gates"][
        "historical_unbound_set_exact"
    ] is False

    # The writable output receipt cannot redefine the trusted expectation:
    # even an internally coherent re-sign for the replacement remains invalid.
    replacement_scan = _scan_teacher_audit(
        output,
        "codex_exec",
        "offline-live-model",
        expected_requests=expected_requests,
    )
    resigned = dict(baseline)
    resigned["historical_unbound_committed_count"] = replacement_scan[
        "historical_unbound_committed"
    ]
    resigned["historical_unbound_committed_set_sha256"] = replacement_scan[
        "historical_unbound_set_sha256"
    ]
    resigned["historical_response_commitment_set_sha256"] = replacement_scan[
        "historical_response_commitment_set_sha256"
    ]
    resigned["baseline_commitment_sha256"] = _named_commitment(
        resigned, "baseline_commitment_sha256"
    )
    baseline_path.write_text(
        json.dumps(resigned, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    baseline_path.chmod(0o600)
    resigned_packet = build_human_audit(
        root=ROOT,
        case_file=CASE_FILE,
        enrichment_root=output / "enrichment",
        trajectory_root=output,
        output_root=output,
    )
    assert resigned_packet["status"] == "AUTOMATED_GATE_FAILED"
    assert resigned_packet["automated_gates"][
        "historical_unbound_set_exact"
    ] is False

    assert first_record is not None
    tampered_prompt = first_record.model_copy(
        update={"prompt_sha256": "sha256:" + "f" * 64}
    )
    tampered_info = _repair_info(
        build_oracle_context(ROOT, catalog[first_record.case_id]),
        vocabulary,
        tampered_prompt,
    )
    assert tampered_info["request_variant_verified"] is False
    assert tampered_info["expected_teacher_request_hash"] is None

    manifest_path = manifests[0]
    old_request_directory = manifest_path.parents[2]
    wrong_request_hash = "sha256:" + "e" * 64
    new_request_directory = old_request_directory.with_name(wrong_request_hash)
    old_request_directory.rename(new_request_directory)
    moved_manifest = (
        new_request_directory
        / manifest_path.relative_to(old_request_directory)
    )
    manifest = json.loads(moved_manifest.read_text(encoding="utf-8"))
    manifest["request_hash"] = wrong_request_hash
    manifest["audit_commitment_sha256"] = _named_commitment(
        manifest, "audit_commitment_sha256"
    )
    moved_manifest.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    tampered_packet = build_human_audit(
        root=ROOT,
        case_file=CASE_FILE,
        enrichment_root=output / "enrichment",
        trajectory_root=output,
        output_root=output,
    )
    assert tampered_packet["status"] == "AUTOMATED_GATE_FAILED"
    assert tampered_packet["automated_gates"]["teacher_requests_bound"] is False
    assert any(
        case["automated_gates"]["teacher_request_bound"] is False
        for case in tampered_packet["cases"]
    )


def test_pre_v22_record_has_no_current_variants_and_real_history_is_classified(
    tmp_path: Path,
) -> None:
    from egsi.contracts.case import load_case_catalog
    from egsi.contracts.enrichment import EnrichmentRecord
    from egsi.data.context import build_oracle_context
    from egsi.generation.enrichment import _prompt_vocabulary, allowed_action_values
    from egsi.generation.human_audit import (
        _request_variants_for_record,
        _scan_teacher_audit,
    )

    source = ROOT / ".work/real-p0-codex-v2"
    output = tmp_path / "real-p0-codex-v2"
    shutil.copytree(source, output)
    retained_request_hashes = {
        "sha256:2b5c0813090521e551898d9826badb33e33ae3a2134bbc72dbcc7360e236f91b",
        "sha256:7f1a883c1976f9f4ef44db4d3c707c7cdc794c94aac2f665c121edec3fec2ec4",
        "sha256:d84b78fbd6ad8c4d2143d0510bf8a367050b59e4d3804c16bfaaeb3d9153408f",
        "sha256:d8dcf6464ae26def2c8483d0b904fd72b7600a408b774c685e7e502f4dca1cb6",
        "sha256:68a3d9c4ad2cc6506aec853aed80cd6cd09d45604f9fec654f64f1a864aa59ae",
    }
    retained_responses: set[str] = set()
    for request_dir in sorted((output / "audit/teacher").iterdir()):
        manifests = sorted(request_dir.glob("*/attempt-00/manifest.json"))
        values = [json.loads(path.read_text(encoding="utf-8")) for path in manifests]
        retain = (
            request_dir.name in retained_request_hashes
            or (
                request_dir.name
                != "sha256:7c7dbdb539baef3b02c5f7aac6118b161147da7b2d3d75678fe24d7e641df7b7"
                and any(
                    value.get("status") == "quarantined"
                    and value.get("failure_code") == "provider_failure_event"
                    for value in values
                )
            )
        )
        if not retain:
            shutil.rmtree(request_dir)
            continue
        retained_responses.update(
            value["response_commitment_sha256"]
            for value in values
            if value.get("status") == "committed"
        )
    for cache_path in sorted((output / "cache/teacher").glob("*.json")):
        response = json.loads(cache_path.read_text(encoding="utf-8"))
        if response.get("response_commitment_sha256") not in retained_responses:
            cache_path.unlink()
    case_id = "ghsa-2m8h-fgr8-2q9w"
    case = next(
        item
        for item in load_case_catalog(ROOT / "data/catalog/cases.jsonl")
        if item.case_id == case_id
    )
    record = EnrichmentRecord.model_validate_json(
        (output / f"enrichment/{case_id}.json").read_bytes()
    )
    requests = _request_variants_for_record(
        build_oracle_context(ROOT, case),
        _prompt_vocabulary(allowed_action_values(ROOT)),
        record,
    )

    assert requests == {}
    observed = _scan_teacher_audit(
        output,
        "codex_exec",
        "gpt-5.6-sol",
        expected_requests=requests,
    )
    assert observed["manifest_count"] == 25
    assert observed["committed"] == 0
    assert observed["quarantined"] == 20
    assert observed["malformed_invalid"] == 0
    assert len(observed["by_response"]) == 0
    assert observed["historical_unbound_committed"] == 5
    assert {
        item["request_hash"] for item in observed["historical_unbound"]
    } == retained_request_hashes
    assert record.teacher_response_commitment_sha256 not in observed["by_response"]
    assert any(
        item["response_commitment_sha256"]
        == record.teacher_response_commitment_sha256
        for item in observed["historical_unbound"]
    )
    assert all(
        item["response_commitment_sha256"]
        not in observed["by_response"]
        for item in observed["historical_unbound"]
    )
    """Legacy hashes retained below document the original two unbound entries."""
    assert {
        "sha256:2b5c0813090521e551898d9826badb33e33ae3a2134bbc72dbcc7360e236f91b",
        "sha256:7f1a883c1976f9f4ef44db4d3c707c7cdc794c94aac2f665c121edec3fec2ec4",
    } <= retained_request_hashes


def test_non_codex_live_provider_without_teacher_audit_fails_closed(
    tmp_path: Path,
) -> None:
    from egsi.generation.human_audit import build_human_audit
    from egsi.teacher.base import committed_teacher_response

    class NonCodexLiveFixtureTeacher:
        provider = "openai_compatible"
        model = "offline-noncodex-live-model"

        def __init__(self) -> None:
            self.fixture = FixtureTeacher()
            self.calls = 0

        def generate(self, request):
            self.calls += 1
            fixture = self.fixture.generate(request)
            return committed_teacher_response(
                provider_request_id=f"offline-noncodex-live-{self.calls}",
                provider=self.provider,
                model=self.model,
                requested_model=self.model,
                provider_response_model="offline-noncodex-live-actual",
                text=fixture.text,
                usage={
                    "input_tokens": 0,
                    "cached_input_tokens": 0,
                    "cache_write_input_tokens": 0,
                    "output_tokens": 0,
                    "reasoning_output_tokens": 0,
                },
                latency_ms=0.0,
            )

    output = tmp_path / "noncodex-live-pilot"
    case_ids = read_case_ids(CASE_FILE)
    enrichment = run_enrichment_batch(
        ROOT, case_ids, output, NonCodexLiveFixtureTeacher()
    )
    compile_trajectory_batch(
        ROOT,
        case_ids,
        output / "enrichment",
        output,
        expected_provenance=enrichment["provenance"],
    )

    packet = build_human_audit(
        root=ROOT,
        case_file=CASE_FILE,
        enrichment_root=output / "enrichment",
        trajectory_root=output,
        output_root=output,
    )

    assert packet["generation_mode"] == "live"
    assert packet["status"] == "AUTOMATED_GATE_FAILED"
    assert packet["automated_gates"]["final_teacher_audit_bound"] is False
    assert packet["automated_gates"]["teacher_requests_bound"] is False
    assert all(
        case["automated_gates"]["teacher_audit_committed"] is False
        and case["automated_gates"]["provider_request_id_bound"] is False
        and case["automated_gates"]["teacher_request_bound"] is False
        for case in packet["cases"]
    )


def test_build_human_audit_cli_is_atomic_and_rejects_symlink_output(
    compiled_fixture: Path, tmp_path: Path
) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    victim = tmp_path / "victim.json"
    victim.write_text("DO-NOT-OVERWRITE", encoding="utf-8")
    (reports / "human-audit-packet.json").symlink_to(victim)

    result = CliRunner().invoke(
        app,
        [
            "build-human-audit",
            "--root",
            str(ROOT),
            "--case-file",
            str(CASE_FILE),
            "--enrichment-root",
            str(compiled_fixture / "enrichment"),
            "--trajectory-root",
            str(compiled_fixture),
            "--output-root",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == "Error: human audit packet generation failed\n"
    assert victim.read_text(encoding="utf-8") == "DO-NOT-OVERWRITE"
    assert not any(path.name.endswith(".tmp") for path in reports.iterdir())


def test_build_human_audit_cli_rejects_symlink_case_file(
    compiled_fixture: Path, tmp_path: Path
) -> None:
    linked_case_file = tmp_path / "cases.txt"
    linked_case_file.symlink_to(CASE_FILE)

    result = CliRunner().invoke(
        app,
        [
            "build-human-audit",
            "--root",
            str(ROOT),
            "--case-file",
            str(linked_case_file),
            "--enrichment-root",
            str(compiled_fixture / "enrichment"),
            "--trajectory-root",
            str(compiled_fixture),
            "--output-root",
            str(tmp_path / "output"),
        ],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == "Error: human audit packet generation failed\n"
    assert not (tmp_path / "output").exists()


def test_build_human_audit_cli_emits_only_safe_summary(
    compiled_fixture: Path,
) -> None:
    result = CliRunner().invoke(
        app,
        [
            "build-human-audit",
            "--root",
            str(ROOT),
            "--case-file",
            str(CASE_FILE),
            "--enrichment-root",
            str(compiled_fixture / "enrichment"),
            "--trajectory-root",
            str(compiled_fixture),
            "--output-root",
            str(compiled_fixture),
        ],
    )

    assert result.exit_code == 0
    summary = json.loads(result.stdout)
    assert summary == {
        "automated_gates_passed": True,
        "case_count": 10,
        "packet_commitment_sha256": json.loads(
            (compiled_fixture / "reports/human-audit-packet.json").read_text()
        )["packet_commitment_sha256"],
        "report_json": "reports/human-audit-packet.json",
        "report_markdown": "reports/human-audit-packet.md",
        "status": "AWAITING_HUMAN_AUDIT",
    }
    assert "human_semantic_judgment" not in result.stdout


def test_teacher_audit_scan_aggregates_attempt_latency_and_five_usage_fields(
    tmp_path: Path,
) -> None:
    from egsi.generation.human_audit import _scan_teacher_audit
    from egsi.teacher.base import TeacherRequest, committed_teacher_response
    from egsi.teacher.base import teacher_request_hash

    request = TeacherRequest(
        system="system",
        user="user",
        schema={"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        temperature=0.0,
        max_tokens=8192,
    )
    response = committed_teacher_response(
        provider_request_id="thread-123",
        provider="codex_exec",
        model="gpt-5.6-sol",
        requested_model="gpt-5.6-sol",
        provider_response_model="unreported",
        text="{}",
        usage={
            "input_tokens": 11,
            "cached_input_tokens": 7,
            "cache_write_input_tokens": 5,
            "output_tokens": 3,
            "reasoning_output_tokens": 2,
        },
        latency_ms=123.5,
        cached=False,
    )
    _write_complete_codex_audit(
        tmp_path, "invocation", request=request, response=response
    )

    observed = _scan_teacher_audit(
        tmp_path,
        "codex_exec",
        "gpt-5.6-sol",
        expected_requests={teacher_request_hash(request): request},
    )

    assert observed["invalid"] == 0
    assert observed["latencies_ms"] == [123.5]
    assert observed["usage"] == {
        "input_tokens": 11,
        "cached_input_tokens": 7,
        "cache_write_input_tokens": 5,
        "output_tokens": 3,
        "reasoning_output_tokens": 2,
    }
    link = observed["by_response"][response.response_commitment_sha256]
    assert link["cache_preimage_bound"] is True
    assert link["provider_invocation_id"] == "thread-123"
    assert link["provider_request_id_kind"] == "codex_thread_id"


def test_teacher_audit_scan_counts_empty_request_directory_as_malformed(
    tmp_path: Path,
) -> None:
    from egsi.generation.human_audit import _scan_teacher_audit

    request_dir = tmp_path / "audit/teacher" / ("sha256:" + "a" * 64)
    request_dir.mkdir(parents=True)

    observed = _scan_teacher_audit(
        tmp_path,
        "codex_exec",
        "gpt-5.6-sol",
        expected_requests={},
    )

    assert observed["manifest_count"] == 0
    assert observed["malformed_invalid"] == 1
    assert observed["committed"] == 0
    assert observed["quarantined"] == 0


def test_teacher_audit_scan_counts_valid_orphan_cache_and_commits_inventory(
    tmp_path: Path,
) -> None:
    from egsi.generation.human_audit import _scan_teacher_audit
    from egsi.teacher.base import TeacherRequest, committed_teacher_response
    from egsi.teacher.cache import TeacherCache, cache_key

    request = TeacherRequest(
        system="system",
        user="orphan",
        schema={
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        temperature=0.0,
        max_tokens=8192,
    )
    response = committed_teacher_response(
        provider_request_id="thread-orphan",
        provider="codex_exec",
        model="gpt-5.6-sol",
        requested_model="gpt-5.6-sol",
        provider_response_model="unreported",
        text="{}",
        usage={
            "input_tokens": 1,
            "cached_input_tokens": 0,
            "cache_write_input_tokens": 0,
            "output_tokens": 1,
            "reasoning_output_tokens": 0,
        },
        latency_ms=1.0,
        cached=False,
    )
    clean = _scan_teacher_audit(
        tmp_path,
        "codex_exec",
        "gpt-5.6-sol",
        expected_requests={},
    )
    TeacherCache(tmp_path / "cache/teacher").write(
        cache_key("codex_exec", "gpt-5.6-sol", request), response
    )

    observed = _scan_teacher_audit(
        tmp_path,
        "codex_exec",
        "gpt-5.6-sol",
        expected_requests={},
    )

    assert observed["malformed_invalid"] == 1
    assert observed["historical_unbound_committed"] == 0
    assert observed["artifact_set_sha256"] != clean["artifact_set_sha256"]


def test_historical_manifests_cannot_consume_one_cache_more_than_once(
    tmp_path: Path,
) -> None:
    from egsi.generation.human_audit import _scan_teacher_audit
    from egsi.teacher.base import TeacherRequest, committed_teacher_response

    request = TeacherRequest(
        system="system",
        user="historical",
        schema={
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        temperature=0.0,
        max_tokens=8192,
    )
    response = committed_teacher_response(
        provider_request_id="thread-historical",
        provider="codex_exec",
        model="gpt-5.6-sol",
        requested_model="gpt-5.6-sol",
        provider_response_model="unreported",
        text="{}",
        usage={
            "input_tokens": 1,
            "cached_input_tokens": 0,
            "cache_write_input_tokens": 0,
            "output_tokens": 1,
            "reasoning_output_tokens": 0,
        },
        latency_ms=1.0,
        cached=False,
    )
    _write_complete_codex_audit(
        tmp_path, "historical-one", request=request, response=response
    )
    _write_complete_codex_audit(
        tmp_path, "historical-two", request=request, response=response
    )

    observed = _scan_teacher_audit(
        tmp_path,
        "codex_exec",
        "gpt-5.6-sol",
        expected_requests={},
    )

    assert observed["malformed_invalid"] == 1
    assert observed["historical_unbound_committed"] == 1
    assert observed["by_response"] == {}


@pytest.mark.parametrize(
    "tamper",
    [
        "missing_cache",
        "tampered_cache",
        "unknown_event",
        "unknown_item",
        "nonconsecutive_index",
        "event_count_mismatch",
        "incomplete_lifecycle",
        "extra_transaction_file",
        "unknown_manifest_field",
    ],
)
def test_teacher_audit_scan_fails_closed_on_incomplete_or_tampered_transaction(
    tmp_path: Path,
    tamper: str,
) -> None:
    from egsi.generation.human_audit import _scan_teacher_audit
    from egsi.teacher.base import TeacherRequest, committed_teacher_response
    from egsi.teacher.base import teacher_request_hash
    from egsi.teacher.cache import TeacherCache

    request = TeacherRequest(
        system="system",
        user="user",
        schema={"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        temperature=0.0,
        max_tokens=8192,
    )
    response = committed_teacher_response(
        provider_request_id="thread-123",
        provider="codex_exec",
        model="gpt-5.6-sol",
        requested_model="gpt-5.6-sol",
        provider_response_model="unreported",
        text="{}",
        usage={
            "input_tokens": 1,
            "cached_input_tokens": 0,
            "cache_write_input_tokens": 0,
            "output_tokens": 1,
            "reasoning_output_tokens": 0,
        },
        latency_ms=1.0,
        cached=False,
    )
    metadata = None
    write_cache = tamper != "missing_cache"
    if tamper == "unknown_event":
        metadata = [
            {"index": 0, "type": "thread.started"},
            {"index": 1, "type": "turn.started"},
            {"index": 2, "type": "mystery.event"},
        ]
    elif tamper == "unknown_item":
        metadata = [
            {"index": 0, "type": "thread.started"},
            {"index": 1, "type": "turn.started"},
            {"index": 2, "item_type": "mystery", "type": "item.completed"},
            {"index": 3, "type": "turn.completed"},
        ]
    elif tamper == "nonconsecutive_index":
        metadata = [
            {"index": 0, "type": "thread.started"},
            {"index": 2, "type": "turn.started"},
            {"index": 3, "item_type": "agent_message", "type": "item.completed"},
            {"index": 4, "type": "turn.completed"},
        ]
    elif tamper == "incomplete_lifecycle":
        metadata = [{"index": 0, "type": "thread.started"}]
    manifest_path, key = _write_complete_codex_audit(
        tmp_path,
        "invocation",
        request=request,
        response=response,
        metadata_items=metadata,
        write_cache=write_cache,
    )
    if tamper == "tampered_cache":
        cache_path = TeacherCache(tmp_path / "cache/teacher").path_for(key)
        value = json.loads(cache_path.read_text(encoding="utf-8"))
        value["text"] = '{"tampered":true}'
        cache_path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
    elif tamper == "event_count_mismatch":
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["event_counts"] = {"thread.started": 99}
        manifest["audit_commitment_sha256"] = _named_commitment(
            manifest, "audit_commitment_sha256"
        )
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
    elif tamper == "extra_transaction_file":
        manifest_path.with_name("unexpected.bin").write_bytes(b"x")
    elif tamper == "unknown_manifest_field":
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["surprise"] = True
        manifest["audit_commitment_sha256"] = _named_commitment(
            manifest, "audit_commitment_sha256"
        )
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

    observed = _scan_teacher_audit(
        tmp_path,
        "codex_exec",
        "gpt-5.6-sol",
        expected_requests={teacher_request_hash(request): request},
    )

    assert observed["invalid"] == 1
    assert observed["committed"] == 0
    assert observed["by_response"] == {}


def test_teacher_audit_scan_counts_forbidden_tool_before_invalidating(
    tmp_path: Path,
) -> None:
    from egsi.generation.human_audit import _scan_teacher_audit
    from egsi.teacher.base import (
        TeacherRequest,
        committed_teacher_response,
        teacher_request_hash,
    )

    request = TeacherRequest(
        system="system",
        user="user",
        schema={"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        temperature=0.0,
        max_tokens=8192,
    )
    response = committed_teacher_response(
        provider_request_id="thread-tool",
        provider="codex_exec",
        model="gpt-5.6-sol",
        requested_model="gpt-5.6-sol",
        provider_response_model="unreported",
        text="{}",
        usage={
            "input_tokens": 1,
            "cached_input_tokens": 0,
            "cache_write_input_tokens": 0,
            "output_tokens": 1,
            "reasoning_output_tokens": 0,
        },
        latency_ms=1.0,
        cached=False,
    )
    _write_complete_codex_audit(
        tmp_path,
        "invocation-tool",
        request=request,
        response=response,
        metadata_items=[
            {"index": 0, "type": "thread.started"},
            {"index": 1, "type": "turn.started"},
            {
                "index": 2,
                "item_type": "command_execution",
                "type": "item.completed",
            },
            {"index": 3, "type": "turn.completed"},
        ],
    )

    observed = _scan_teacher_audit(
        tmp_path,
        "codex_exec",
        "gpt-5.6-sol",
        expected_requests={teacher_request_hash(request): request},
    )

    assert observed["invalid"] == 1
    assert observed["malformed_invalid"] == 1
    assert observed["tool_events"] == 1
    assert observed["committed"] == 0
    assert observed["by_response"] == {}


@pytest.mark.parametrize("status", ["committed", "quarantined"])
@pytest.mark.parametrize(
    "extra_kind",
    ["directory", "nested", "fifo", "symlink", "hardlink", "file"],
)
def test_teacher_audit_scan_rejects_every_unknown_transaction_entry_type(
    tmp_path: Path,
    status: str,
    extra_kind: str,
) -> None:
    from egsi.generation.human_audit import _scan_teacher_audit
    from egsi.teacher.base import (
        TeacherRequest,
        committed_teacher_response,
        teacher_request_hash,
    )

    request = TeacherRequest(
        system="system",
        user="user",
        schema={"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        temperature=0.0,
        max_tokens=8192,
    )
    response = committed_teacher_response(
        provider_request_id="thread-tree",
        provider="codex_exec",
        model="gpt-5.6-sol",
        requested_model="gpt-5.6-sol",
        provider_response_model="unreported",
        text="{}",
        usage={
            "input_tokens": 1,
            "cached_input_tokens": 0,
            "cache_write_input_tokens": 0,
            "output_tokens": 1,
            "reasoning_output_tokens": 0,
        },
        latency_ms=1.0,
        cached=False,
    )
    if status == "committed":
        manifest_path, _ = _write_complete_codex_audit(
            tmp_path,
            "invocation-tree",
            request=request,
            response=response,
        )
        expected_requests = {teacher_request_hash(request): request}
    else:
        manifest_path = _write_audit_manifest(
            tmp_path,
            "invocation-tree",
            provider="codex_exec",
            model="gpt-5.6-sol",
            status="quarantined",
            failure_code="provider_failure_event",
            metadata_items=[
                {"index": 0, "type": "thread.started"},
                {"index": 1, "type": "turn.started"},
                {"index": 2, "type": "error"},
            ],
        )
        expected_requests = {}
    transaction = manifest_path.parent
    clean = _scan_teacher_audit(
        tmp_path,
        "codex_exec",
        "gpt-5.6-sol",
        expected_requests=expected_requests,
    )
    extra = transaction / "unexpected"
    if extra_kind == "directory":
        extra.mkdir()
    elif extra_kind == "nested":
        (extra / "deeper").mkdir(parents=True)
        (extra / "deeper/value.bin").write_bytes(b"nested")
    elif extra_kind == "fifo":
        os.mkfifo(extra)
    elif extra_kind == "symlink":
        extra.symlink_to(manifest_path)
    elif extra_kind == "hardlink":
        os.link(manifest_path, extra)
    else:
        extra.write_bytes(b"extra")
    observed = _scan_teacher_audit(
        tmp_path,
        "codex_exec",
        "gpt-5.6-sol",
        expected_requests=expected_requests,
    )

    assert observed["invalid"] == 1
    assert observed["malformed_invalid"] == 1
    assert observed["committed"] == 0
    assert observed["quarantined"] == 0
    assert observed["artifact_set_sha256"] != clean["artifact_set_sha256"]


@pytest.mark.parametrize("status", ["committed", "quarantined"])
def test_exact_transaction_set_rejects_socket_typed_expected_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    from egsi.generation.human_audit import _validate_transaction_set

    transaction = tmp_path / "attempt-00"
    transaction.mkdir()
    (transaction / "manifest.json").write_bytes(b"{}")
    metadata = transaction / "events.metadata.jsonl"
    metadata.write_bytes(b"{}\n")
    manifest = {"status": status}
    if status == "quarantined":
        (transaction / "quarantine.json").write_bytes(b"{}")
    real_lstat = Path.lstat

    def socket_lstat(path: Path):
        observed = real_lstat(path)
        if path == metadata:
            fields = list(observed)
            fields[0] = stat.S_IFSOCK | 0o600
            fields[3] = 1
            return os.stat_result(fields)
        return observed

    monkeypatch.setattr(Path, "lstat", socket_lstat)

    with pytest.raises(ValueError, match="transaction entry"):
        _validate_transaction_set(transaction, manifest)

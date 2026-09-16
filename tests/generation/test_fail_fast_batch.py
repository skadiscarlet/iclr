"""Fail-fast remaining-P0 recovery stops, reports, and verifies independently."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from egsi.generation.fail_fast_batch import (
    _archive_existing,
    _audit_state,
    _audit_state_observation,
    _attempts,
    _large_dict_commitment,
    _inventory,
    _publish_summary,
    _REPORT_RELATIVE,
    _request_state,
    _request_state_with_history,
    _resolve_scope_contract,
    _scope_completion_kinds,
    _test_receipt_evidence,
    _report_commitment,
    _recovery_scope_state,
    _verify_receipt_attestation,
    _verify_stopped_attempt_sequence,
    _validate_scope_segment,
    CanonicalReceiptEvidence,
    run_fail_fast_batch,
    verify_fail_fast_report,
)
from egsi.generation.pilot import (
    _read_record,
    _write_provenance_manifest,
    catalog_index,
    read_case_ids,
)
from egsi.generation.pilot import _dict_commitment, _sha256
from egsi.generation.enrichment import (
    _evaluate_enrichment_attempt,
    _load_store,
    _receipt_validation,
    allowed_action_values,
)
from egsi.generation.human_audit import (
    historical_expectation_value,
    load_historical_expectation_with_evidence,
)
from egsi.generation.safeio import active_batch_lock
from egsi.teacher.base import (
    TeacherRequest,
    TeacherResponse,
    committed_teacher_response,
    teacher_request_hash,
)
from egsi.teacher.cache import TeacherCache, cache_key


ROOT = Path(__file__).resolve().parents[2]


def _historical_expectation(root: Path = ROOT) -> dict[str, Any]:
    return load_historical_expectation_with_evidence(root)[0]


@pytest.mark.parametrize(
    ("requested", "completed"),
    [
        (["case-b", "case-d"], {"case-a"}),
        (["case-d"], {"case-a"}),
        (["case-c"], {"case-a"}),
    ],
)
def test_scope_contract_rejects_noncontiguous_or_gapped_recovery(
    requested: list[str], completed: set[str]
) -> None:
    with pytest.raises(ValueError, match="scope"):
        _validate_scope_segment(
            scope=["case-a", "case-b", "case-c", "case-d"],
            requested=requested,
            completed=completed,
            explicit_reattestation_target=None,
        )


def test_scope_contract_accepts_next_segment_and_exact_reattestation() -> None:
    forward = _validate_scope_segment(
        scope=["case-a", "case-b", "case-c"],
        requested=["case-b"],
        completed={"case-a"},
        explicit_reattestation_target=None,
    )
    explicit = _validate_scope_segment(
        scope=["case-a", "case-b", "case-c"],
        requested=["case-b"],
        completed={"case-a", "case-b"},
        explicit_reattestation_target="case-b",
    )
    assert forward == (
        ["case-c"],
        "forward_recovery",
        "next_incomplete_contiguous_p0_segment",
    )
    assert explicit == (
        ["case-c"],
        "explicit_reattestation",
        "native_live_attestation_for_prompt_v2_3",
    )


def test_scope_resolution_uses_v22_only_for_exact_3wfj_reattestation() -> None:
    scope = [
        "ghsa-2m8h-fgr8-2q9w",
        "ghsa-3wfj-vh84-732p",
        "ghsa-2j4q-9fff-236j",
    ]
    frozen = {
        scope[0]: "frozen_v21",
        scope[1]: "frozen_v22",
    }

    assert _resolve_scope_contract(
        scope=scope,
        requested=[scope[1]],
        completion_kinds=frozen,
    ) == (
        [scope[2]],
        "explicit_reattestation",
        "native_live_attestation_for_prompt_v2_3",
    )
    with pytest.raises(ValueError, match="scope"):
        _resolve_scope_contract(
            scope=scope,
            requested=[scope[2]],
            completion_kinds=frozen,
        )
    with pytest.raises(ValueError, match="scope"):
        _resolve_scope_contract(
            scope=scope,
            requested=[scope[1], scope[2]],
            completion_kinds=frozen,
        )

    current = {**frozen, scope[1]: "current_v23_reattested"}
    assert _resolve_scope_contract(
        scope=scope,
        requested=[scope[2]],
        completion_kinds=current,
    ) == (
        [],
        "forward_recovery",
        "next_incomplete_contiguous_p0_segment",
    )


def test_real_scope_completion_classifies_frozen_versions_without_promotion() -> None:
    output = ROOT / ".work/real-p0-codex-v2"
    scope = read_case_ids(ROOT / "configs/p0_cases.txt")
    catalog = catalog_index(ROOT)
    request_hashes, expected, pre_batch, pre_recovery, historical = (
        _request_state_with_history(
            ROOT,
            catalog,
            scope,
            historical_expectation=_historical_expectation(),
        )
    )
    _, audit = _audit_state(
        output,
        provider="codex_exec",
        model="gpt-5.6-sol",
        request_hashes=request_hashes,
        expected_requests=expected,
        pre_batch_request_hashes=pre_batch,
        pre_recovery_request_hashes=pre_recovery,
        historical_expectation=historical,
        active_current_case_ids={"ghsa-3wfj-vh84-732p"},
    )

    assert _scope_completion_kinds(
        root=ROOT,
        output_root=output,
        scope=scope,
        catalog=catalog,
        provider="codex_exec",
        model="gpt-5.6-sol",
        audit=audit,
        active_current_case_ids={"ghsa-3wfj-vh84-732p"},
    ) == {
        "ghsa-2m8h-fgr8-2q9w": "frozen_v21",
        "ghsa-3wfj-vh84-732p": "frozen_v22",
    }


def test_recovery_scope_state_rejects_a_real_missing_prefix_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import egsi.generation.fail_fast_batch as module

    root = tmp_path / "root"
    root.mkdir()
    output = tmp_path / "output"
    catalog = {
        case_id: _case(case_id)
        for case_id in ("case-a", "case-b", "case-c")
    }
    variants = {case_id: _variants(case_id) for case_id in catalog}
    monkeypatch.setattr(
        module,
        "_request_variants_for_case",
        lambda _root, case: variants[case.case_id],
    )
    monkeypatch.setattr(
        module, "_frozen_v21_first_case_requests", lambda *_args: {}
    )
    monkeypatch.setattr(
        module, "_frozen_v22_recovery_requests", lambda *_args: {}
    )
    monkeypatch.setattr(
        module,
        "_audit_state",
        lambda *_args, **_kwargs: (
            [],
            {
                "by_response": {},
                "pre_batch_by_response": {},
                "pre_recovery_by_response": {},
            },
        ),
    )

    with pytest.raises(ValueError, match="scope"):
        _recovery_scope_state(
            root=root,
            output_root=output,
            scope=list(catalog),
            requested=["case-b"],
            catalog=catalog,
            provider="codex_exec",
            model="model",
            historical_expectation={},
        )


def _source_controlled_stop_replay(
    tmp_path: Path,
    *,
    variant_indices: list[int],
    texts: list[str],
) -> tuple[object, list[object], dict[str, object], dict[str, object]]:
    """Build current-v2.3 audit/cache evidence without copying mutable .work."""

    case_id = "ghsa-2m8h-fgr8-2q9w"
    case = catalog_index(ROOT)[case_id]
    request_hashes, expected = _request_state(ROOT, {case_id: case}, [case_id])
    for sequence_index, (variant_index, response_text) in enumerate(
        zip(variant_indices, texts, strict=True)
    ):
        request_hash = request_hashes[case_id][variant_index]
        manifest_path, _ = _write_complete_attempt(
            tmp_path,
            request=expected[request_hash],
            invocation_id=f"source-stop-{sequence_index}",
            provider_request_id=f"source-stop-provider-{sequence_index}",
            text=response_text,
        )
        started = 1_700_000_000_000_000_000 + sequence_index * 1_000_000
        os.utime(
            manifest_path.parent.parent,
            ns=(started, started),
            follow_symlinks=False,
        )
    attempts, audit = _audit_state_observation(
        tmp_path,
        provider="codex_exec",
        model="model",
        request_hashes=request_hashes,
        expected_requests=expected,
    )
    receipt: dict[str, object] = {
        "schema_version": "1.0",
        "case_id": case_id,
        "attempts": len(attempts),
        "error": "teacher output remained invalid",
        "error_kind": "structured_invalid",
        "failed_attempt": len(attempts),
        "validation_attempt": None,
        "validation": None,
        "positive_transition_written": False,
    }
    return case, list(attempts), audit, receipt


def test_stopped_attempt_replay_accepts_exact_invalid_causal_sequence(
    tmp_path: Path,
) -> None:
    case, attempts, audit, receipt = _source_controlled_stop_replay(
        tmp_path,
        variant_indices=[0, 1],
        texts=["{}", "{}"],
    )

    _verify_stopped_attempt_sequence(
        root=ROOT,
        output_root=tmp_path,
        case=case,
        generation_mode="live",
        receipt=receipt,
        attempts=attempts,
        audit=audit,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("attempts", 1),
        ("failed_attempt", 1),
        ("error_kind", "semantic_invalid"),
        ("validation_attempt", 2),
        ("validation", {}),
    ],
)
def test_stopped_attempt_replay_rejects_recommitted_receipt_mismatch(
    tmp_path: Path, field: str, value: object
) -> None:
    case, attempts, audit, receipt = _source_controlled_stop_replay(
        tmp_path,
        variant_indices=[0, 1],
        texts=["{}", "{}"],
    )
    receipt[field] = value

    with pytest.raises(ValueError, match="stopped"):
        _verify_stopped_attempt_sequence(
            root=ROOT,
            output_root=tmp_path,
            case=case,
            generation_mode="live",
            receipt=receipt,
            attempts=attempts,
            audit=audit,
        )


def test_stopped_attempt_replay_rejects_noncausal_repair_variant(
    tmp_path: Path,
) -> None:
    case, attempts, audit, receipt = _source_controlled_stop_replay(
        tmp_path,
        variant_indices=[0, 3],
        texts=["{}", "{}"],
    )

    with pytest.raises(ValueError, match="stopped"):
        _verify_stopped_attempt_sequence(
            root=ROOT,
            output_root=tmp_path,
            case=case,
            generation_mode="live",
            receipt=receipt,
            attempts=attempts,
            audit=audit,
        )


def test_stopped_attempt_replay_rejects_valid_final_attempt(
    tmp_path: Path,
) -> None:
    fixture = json.loads(
        (ROOT / "tests/fixtures/enrichment-valid.json").read_text(
            encoding="utf-8"
        )
    )
    case, attempts, audit, receipt = _source_controlled_stop_replay(
        tmp_path,
        variant_indices=[0],
        texts=[json.dumps(fixture["payload"], sort_keys=True)],
    )

    with pytest.raises(ValueError, match="stopped"):
        _verify_stopped_attempt_sequence(
            root=ROOT,
            output_root=tmp_path,
            case=case,
            generation_mode="live",
            receipt=receipt,
            attempts=attempts,
            audit=audit,
        )


def test_stopped_attempt_replay_binds_semantic_validation_receipt(
    tmp_path: Path,
) -> None:
    fixture = json.loads(
        (ROOT / "tests/fixtures/enrichment-valid.json").read_text(
            encoding="utf-8"
        )
    )
    payload = fixture["payload"]
    payload["locations"][0]["path"] = "not/a/repository/blob.java"
    payload["trace"][0]["target_location"] = "not/a/repository/blob.java"
    response_text = json.dumps(payload, sort_keys=True)
    case, attempts, audit, receipt = _source_controlled_stop_replay(
        tmp_path,
        variant_indices=[0, 5],
        texts=[response_text, response_text],
    )
    request_hashes, expected = _request_state(
        ROOT, {case.case_id: case}, [case.case_id]
    )
    final_request = expected[request_hashes[case.case_id][5]]
    evaluation = _evaluate_enrichment_attempt(
        text=response_text,
        schema=final_request.schema,
        case=case,
        store=_load_store(ROOT, case),
        vocabulary=allowed_action_values(ROOT),
    )
    assert evaluation.repair_error == "invalid_canonical_path"
    receipt.update(
        {
            "error_kind": "semantic_invalid",
            "validation_attempt": 2,
            "validation": _receipt_validation(evaluation.validation),
        }
    )

    _verify_stopped_attempt_sequence(
        root=ROOT,
        output_root=tmp_path,
        case=case,
        generation_mode="live",
        receipt=receipt,
        attempts=attempts,
        audit=audit,
    )


def test_stopped_attempt_replay_supports_metadata_repair_variants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = json.loads(
        (ROOT / "tests/fixtures/enrichment-valid.json").read_text(
            encoding="utf-8"
        )
    )
    response_text = json.dumps(fixture["payload"], sort_keys=True)
    case, attempts, audit, receipt = _source_controlled_stop_replay(
        tmp_path,
        variant_indices=[0, 7],
        texts=[response_text, response_text],
    )

    def reject_record(**_value: object):
        from egsi.contracts.enrichment import EnrichmentRecord

        return EnrichmentRecord.model_validate({})

    monkeypatch.setattr(
        "egsi.generation.fail_fast_batch.committed_enrichment_record",
        reject_record,
    )
    evaluation = _evaluate_enrichment_attempt(
        text=response_text,
        schema=_request_state(ROOT, {case.case_id: case}, [case.case_id])[1][
            attempts[-1].request_hash
        ].schema,
        case=case,
        store=_load_store(ROOT, case),
        vocabulary=allowed_action_values(ROOT),
    )
    receipt.update(
        {
            "error_kind": "teacher_response_metadata_invalid",
            "validation_attempt": 2,
            "validation": _receipt_validation(evaluation.validation),
        }
    )

    _verify_stopped_attempt_sequence(
        root=ROOT,
        output_root=tmp_path,
        case=case,
        generation_mode="live",
        receipt=receipt,
        attempts=attempts,
        audit=audit,
    )


class _Teacher:
    provider = "codex_exec"
    model = "model"


def _case(case_id: str) -> SimpleNamespace:
    return SimpleNamespace(case_id=case_id, split="train")


def _variants(case_id: str) -> list[tuple[str, TeacherRequest]]:
    result: list[tuple[str, TeacherRequest]] = []
    for index in range(9):
        request = TeacherRequest(
            system="system",
            user=f"{case_id}:{index}",
            schema={
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
            temperature=0.0,
            max_tokens=8192,
        )
        result.append((teacher_request_hash(request), request))
    return result


def _write_complete_attempt(
    output: Path,
    *,
    request: TeacherRequest,
    invocation_id: str = "current-attempt",
    provider_request_id: str = "thread-id",
    text: str = "{}",
) -> tuple[Path, Path]:
    response = committed_teacher_response(
        provider_request_id=provider_request_id,
        provider="codex_exec",
        model="model",
        requested_model="model",
        provider_response_model="unreported",
        text=text,
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
    key = cache_key("codex_exec", "model", request)
    cache = TeacherCache(output / "cache/teacher")
    cache.write(key, response)
    cache_path = cache.path_for(key)
    request_hash = teacher_request_hash(request)
    attempt = (
        output
        / "audit/teacher"
        / request_hash
        / invocation_id
        / "attempt-00"
    )
    attempt.mkdir(parents=True)
    metadata = (
        b'{"index":0,"type":"thread.started"}\n'
        b'{"index":1,"type":"turn.started"}\n'
        b'{"index":2,"item_type":"agent_message","type":"item.completed"}\n'
        b'{"index":3,"type":"turn.completed"}\n'
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
    response_raw = response.text.encode("utf-8")
    manifest = {
        "schema_version": "1.0",
        "provider": "codex_exec",
        "model": "model",
        "requested_model": "model",
        "provider_response_model": response.provider_response_model,
        "cli_version": "0.150.1",
        "request_hash": request_hash,
        "invocation_id": invocation_id,
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
        "event_counts": {
            "item.completed": 1,
            "thread.started": 1,
            "turn.completed": 1,
            "turn.started": 1,
        },
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
    manifest["audit_commitment_sha256"] = _dict_commitment(
        manifest, "audit_commitment_sha256"
    )
    manifest_path = attempt / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return manifest_path, cache_path


def _write_provider_failure_attempt(
    output: Path,
    *,
    request: TeacherRequest,
    invocation_id: str = "current-provider-failure",
) -> Path:
    """Write one complete current transport-failure transaction."""

    request_hash = teacher_request_hash(request)
    attempt = (
        output
        / "audit/teacher"
        / request_hash
        / invocation_id
        / "attempt-00"
    )
    attempt.mkdir(parents=True)
    metadata = (
        b'{"index":0,"type":"thread.started"}\n'
        b'{"index":1,"type":"turn.started"}\n'
        b'{"index":2,"type":"error"}\n'
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
    executable_stat = {
        "device": 1,
        "inode": 2,
        "mode": 0o100755,
        "nlink": 1,
        "size": 3,
        "mtime_ns": 4,
        "ctime_ns": 5,
    }
    identity = {
        "executable_id": "codex-cli",
        "executable_sha256": "sha256:" + "e" * 64,
        "executable_stat": executable_stat,
        "cli_version": "0.150.1",
    }
    executable_identity = _sha256(
        json.dumps(
            identity,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    manifest = {
        "schema_version": "1.0",
        "provider": "codex_exec",
        "model": "model",
        "requested_model": "model",
        "provider_response_model": None,
        "cli_version": "0.150.1",
        "request_hash": request_hash,
        "invocation_id": invocation_id,
        "attempt": 0,
        "status": "quarantined",
        "failure_code": "provider_failure_event",
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
        "stdout_length": 1,
        "stdout_sha256": _sha256(b"\n"),
        "stderr_length": 1,
        "stderr_sha256": _sha256(b"\n"),
        "stderr_truncated_in_memory": False,
        "exit_code": None,
        "signal": None,
        "event_counts": {
            "error": 1,
            "thread.started": 1,
            "turn.started": 1,
        },
        "usage": None,
        "latency_ms": 1.0,
        "max_tokens": request.max_tokens,
        "max_tokens_enforced_by_cli": False,
        "response_length": None,
        "response_sha256": None,
        "response_commitment_sha256": None,
        "events_metadata_length": len(metadata),
        "events_metadata_sha256": _sha256(metadata),
        "executable_id": "codex-cli",
        "executable_sha256": identity["executable_sha256"],
        "executable_stat": executable_stat,
        "executable_identity_commitment_sha256": executable_identity,
    }
    manifest["audit_commitment_sha256"] = _dict_commitment(
        manifest, "audit_commitment_sha256"
    )
    manifest_path = attempt / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    (attempt / "quarantine.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "status": "quarantined",
                "failure_code": "provider_failure_event",
                "positive_transition_written": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return manifest_path


def _refresh_report(output: Path) -> dict[str, object]:
    report_path = output / "reports/remaining-p0/fail-fast-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["current_attempts"] = [
        item.model_dump(mode="json")
        for item in _attempts(output, report["request_hashes"])
    ]
    report["artifact_inventory"] = [
        item.model_dump(mode="json") for item in _inventory(output)
    ]
    report["provenance_manifest_sha256"] = _sha256(
        (output / "enrichment/_batch-provenance.json").read_bytes()
    )
    report["enrichment_summary_sha256"] = _sha256(
        (output / "reports/enrichment-summary.json").read_bytes()
    )
    report["report_commitment_sha256"] = _report_commitment(report)
    report_path.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return report


def _bind_manifest_request(
    manifest: dict[str, object], request_hash: str, request: TeacherRequest
) -> None:
    system = request.system.encode("utf-8")
    schema = json.dumps(
        request.schema,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    stdin = (
        request.user
        + f"\n\n[EGSI output budget hint: at most {request.max_tokens} tokens.]"
    ).encode("utf-8")
    manifest.update(
        {
            "request_hash": request_hash,
            "system_length": len(system),
            "system_sha256": _sha256(system),
            "schema_length": len(schema),
            "schema_sha256": _sha256(schema),
            "stdin_length": len(stdin),
            "stdin_sha256": _sha256(stdin),
            "provider_output_schema_length": len(schema),
            "provider_output_schema_sha256": _sha256(schema),
        }
    )


def _bind_manifest_response(
    manifest: dict[str, object], response: TeacherResponse
) -> None:
    response_raw = response.text.encode("utf-8")
    manifest.update(
        {
            "provider_response_model": response.provider_response_model,
            "usage": response.usage,
            "latency_ms": response.latency_ms,
            "response_length": len(response_raw),
            "response_sha256": _sha256(response_raw),
            "response_commitment_sha256": (
                response.response_commitment_sha256
            ),
        }
    )


def _refresh_current_real_report(output: Path) -> None:
    requested = read_case_ids(ROOT / "configs/recover_3wfj_cases.txt")
    scope = read_case_ids(ROOT / "configs/p0_cases.txt")
    forbidden = scope[scope.index(requested[-1]) + 1 :]
    catalog = catalog_index(ROOT)
    request_hashes, expected, pre_batch, pre_recovery, historical = (
        _request_state_with_history(
            ROOT,
            catalog,
            [*requested, *forbidden],
            historical_expectation=_historical_expectation(),
        )
    )
    attempts, audit = _audit_state(
        output,
        provider="codex_exec",
        model="gpt-5.6-sol",
        request_hashes=request_hashes,
        expected_requests=expected,
        pre_batch_request_hashes=pre_batch,
        pre_recovery_request_hashes=pre_recovery,
        historical_expectation=historical,
    )
    report_path = output / _REPORT_RELATIVE
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["current_attempts"] = [
        item.model_dump(mode="json") for item in attempts
    ]
    report["teacher_audit_artifact_set_sha256"] = audit[
        "artifact_set_sha256"
    ]
    report["teacher_current_bound_committed"] = audit["committed"]
    report["artifact_inventory"] = [
        item.model_dump(mode="json") for item in _inventory(output)
    ]
    report["provenance_manifest_sha256"] = _sha256(
        (output / "enrichment/_batch-provenance.json").read_bytes()
    )
    report["enrichment_summary_sha256"] = _sha256(
        (output / "reports/enrichment-summary.json").read_bytes()
    )
    report["report_commitment_sha256"] = _report_commitment(report)
    report_path.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


def _stub_current_receipts(
    output: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = json.loads(
        (output / _REPORT_RELATIVE).read_text(encoding="utf-8")
    )
    evidence = [
        CanonicalReceiptEvidence.model_validate(item)
        for item in report["canonical_test_receipts"]
    ]
    monkeypatch.setattr(
        "egsi.generation.fail_fast_batch._test_receipt_evidence",
        lambda _root, _output: evidence,
    )


def _copy_frozen_v22_output(destination: Path) -> Path:
    """Rebuild the last frozen v2.2 view from its content-addressed archives.

    The real output root now contains the one terminal v2.3 transport delta.
    Tests that mutate the earlier recovered report need an isolated v2.2 view,
    not a fabricated report written back into the live evidence inventory.
    """

    shutil.copytree(ROOT / ".work/real-p0-codex-v2", destination)
    history = destination / "reports/remaining-p0/history"
    report_candidates: list[tuple[Path, dict[str, object]]] = []
    for path in sorted(history.glob("fail-fast-report.*.json")):
        raw = path.read_bytes()
        digest = path.name.split(".")[1]
        if _sha256(raw) != f"sha256:{digest}":
            raise AssertionError("frozen v2.2 report archive is not content-addressed")
        value = json.loads(raw)
        if value.get("status") == "REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW":
            report_candidates.append((path, value))
    assert len(report_candidates) == 1
    archived_report, report = report_candidates[0]
    report_path = destination / _REPORT_RELATIVE
    report_path.write_bytes(archived_report.read_bytes())

    restored_archives = [archived_report]
    for relative, field, label in (
        (
            Path("enrichment/_batch-provenance.json"),
            "provenance_manifest_sha256",
            "batch-provenance",
        ),
        (
            Path("reports/enrichment-summary.json"),
            "enrichment_summary_sha256",
            "enrichment-summary",
        ),
    ):
        digest = str(report[field]).removeprefix("sha256:")
        archived = history / f"{label}.{digest}.json"
        (destination / relative).write_bytes(archived.read_bytes())
        restored_archives.append(archived)

    case_id = "ghsa-3wfj-vh84-732p"
    positive_entry = next(
        item
        for item in report["artifact_inventory"]
        if item["relative_path"] == f"enrichment/{case_id}.json"
    )
    positive_digest = positive_entry["sha256"].removeprefix("sha256:")
    archived_positive = (
        destination
        / f"enrichment/quarantine/{case_id}.{positive_digest}.json"
    )
    (destination / f"enrichment/{case_id}.json").write_bytes(
        archived_positive.read_bytes()
    )
    archived_positive.unlink()
    (destination / f"enrichment/failures/{case_id}.json").unlink(
        missing_ok=True
    )

    current_hashes, _ = _request_state(
        ROOT, catalog_index(ROOT), [case_id]
    )
    for request_hash in current_hashes[case_id]:
        shutil.rmtree(
            destination / "audit/teacher" / request_hash,
            ignore_errors=True,
        )
    for archived in restored_archives:
        archived.unlink()

    assert [
        item.model_dump(mode="json") for item in _inventory(destination)
    ] == report["artifact_inventory"]
    return destination


def _causal_sequence_copy(tmp_path: Path, tamper: str) -> Path:
    output = _copy_frozen_v22_output(tmp_path / tamper)
    report = json.loads(
        (output / _REPORT_RELATIVE).read_text(encoding="utf-8")
    )
    requested = report["requested_case_ids"]
    assert requested == ["ghsa-3wfj-vh84-732p"]
    old_hashes = report["request_hashes"][requested[0]]
    old_attempt = report["current_attempts"][0]
    assert old_attempt["variant_index"] == 0
    old_request_root = output / "audit/teacher" / old_attempt["request_hash"]
    old_manifest_path = output / old_attempt["manifest_path"]
    base_manifest = json.loads(old_manifest_path.read_text(encoding="utf-8"))
    base_metadata = old_manifest_path.with_name(
        "events.metadata.jsonl"
    ).read_bytes()
    original_commitment = base_manifest["response_commitment_sha256"]
    original_cache_path = next(
        path
        for path in (output / "cache/teacher").glob("*.json")
        if json.loads(path.read_text(encoding="utf-8")).get(
            "response_commitment_sha256"
        )
        == original_commitment
    )
    original_response = TeacherResponse.model_validate_json(
        original_cache_path.read_text(encoding="utf-8")
    )
    requested_ids = read_case_ids(ROOT / "configs/recover_3wfj_cases.txt")
    scope = read_case_ids(ROOT / "configs/p0_cases.txt")
    forbidden = scope[scope.index(requested_ids[-1]) + 1 :]
    current_hashes, expected, _, _, _ = _request_state_with_history(
        ROOT,
        catalog_index(ROOT),
        [*requested_ids, *forbidden],
        historical_expectation=_historical_expectation(),
    )
    hashes = current_hashes[requested[0]]
    assert old_attempt["request_hash"] in old_hashes
    final_variant = {
        "repair_only": 6,
        "skip_attempt": 2,
        "wrong_repair_code": 3,
        "reordered_started_time": 1,
        "valid_then_repair": 1,
    }[tamper]
    final_hash = hashes[final_variant]
    final_request = expected[final_hash]
    final_request_root = output / "audit/teacher" / final_hash
    shutil.copytree(old_request_root, final_request_root)
    final_manifest_path = (
        final_request_root / old_manifest_path.relative_to(old_request_root)
    )
    final_manifest = json.loads(
        final_manifest_path.read_text(encoding="utf-8")
    )
    final_response = committed_teacher_response(
        provider_request_id=f"fixture-{tamper}-final",
        provider=original_response.provider,
        model=original_response.model,
        requested_model=original_response.requested_model,
        provider_response_model=original_response.provider_response_model,
        text=original_response.text,
        usage=original_response.usage,
        latency_ms=original_response.latency_ms,
        cached=False,
    )
    _bind_manifest_request(final_manifest, final_hash, final_request)
    _bind_manifest_response(final_manifest, final_response)
    final_manifest["audit_commitment_sha256"] = _dict_commitment(
        final_manifest, "audit_commitment_sha256"
    )
    final_manifest_path.write_text(
        json.dumps(final_manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    provenance = str(final_manifest["executable_identity_commitment_sha256"])
    final_cache_key = cache_key(
        final_response.provider,
        final_response.model,
        final_request,
        provenance=provenance,
    )
    TeacherCache(output / "cache/teacher").write(
        final_cache_key, final_response
    )

    if tamper != "repair_only":
        first_text = (
            original_response.text if tamper == "valid_then_repair" else "{}"
        )
        first_response = committed_teacher_response(
            provider_request_id=f"fixture-{tamper}-first",
            provider=original_response.provider,
            model=original_response.model,
            requested_model=original_response.requested_model,
            provider_response_model=original_response.provider_response_model,
            text=first_text,
            usage=original_response.usage,
            latency_ms=1.0,
            cached=False,
        )
        first_hash = hashes[0]
        first_request = expected[first_hash]
        first_invocation_id = hashlib.sha256(tamper.encode()).hexdigest()[:32] + "-00"
        first_attempt_dir = (
            output
            / "audit/teacher"
            / first_hash
            / first_invocation_id
            / "attempt-00"
        )
        first_attempt_dir.mkdir(parents=True)
        (first_attempt_dir / "events.metadata.jsonl").write_bytes(
            base_metadata
        )
        first_manifest = dict(base_manifest)
        first_manifest["invocation_id"] = first_invocation_id
        _bind_manifest_request(first_manifest, first_hash, first_request)
        _bind_manifest_response(first_manifest, first_response)
        first_manifest["audit_commitment_sha256"] = _dict_commitment(
            first_manifest, "audit_commitment_sha256"
        )
        (first_attempt_dir / "manifest.json").write_text(
            json.dumps(
                first_manifest, sort_keys=True, separators=(",", ":")
            ),
            encoding="utf-8",
        )
        first_cache_key = cache_key(
            first_response.provider,
            first_response.model,
            first_request,
            provenance=provenance,
        )
        TeacherCache(output / "cache/teacher").write(
            first_cache_key, first_response
        )
        first_started = 1_700_000_000_000_000_000
        final_started = first_started + 1_000_000
        if tamper == "reordered_started_time":
            first_started, final_started = final_started, first_started
        os.utime(
            first_attempt_dir.parent,
            ns=(first_started, first_started),
            follow_symlinks=False,
        )
        os.utime(
            final_manifest_path.parent.parent,
            ns=(final_started, final_started),
            follow_symlinks=False,
        )

    record_path = output / "enrichment" / f"{requested[0]}.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["prompt_sha256"] = _sha256(
        (final_request.system + final_request.user).encode("utf-8")
    )
    record["provider_request_id"] = final_response.provider_request_id
    record["teacher_response_commitment_sha256"] = (
        final_response.response_commitment_sha256
    )
    record["record_commitment_sha256"] = _dict_commitment(
        record, "record_commitment_sha256"
    )
    record_path.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    record_obj = _read_record(record_path)
    provenance_manifest = _write_provenance_manifest(
        output / "enrichment",
        requested_ids,
        [record_obj],
        [],
        generation_mode=report["generation_mode"],
        provider=report["provider"],
        model=report["model"],
    )
    _publish_summary(
        output,
        status="REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW",
        requested=requested_ids,
        completed=requested_ids,
        failed_case_id=None,
        not_started=[],
        provenance=provenance_manifest,
    )
    _refresh_current_real_report(output)
    return output


def _failed_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    write_receipt: bool = True,
    write_current_attempt: bool = False,
    write_transport_attempt: bool = False,
) -> tuple[Path, Path, Path, list[str]]:
    import egsi.generation.fail_fast_batch as module

    root = tmp_path / "root"
    root.mkdir()
    case_file = root / "recover.txt"
    case_file.write_text("case-a\ncase-b\n", encoding="utf-8")
    scope_file = root / "scope.txt"
    scope_file.write_text("case-a\ncase-b\ncase-c\n", encoding="utf-8")
    output = tmp_path / "output"
    calls: list[str] = []

    monkeypatch.setattr(
        module,
        "catalog_index",
        lambda _root: {name: _case(name) for name in ("case-a", "case-b", "case-c")},
    )
    variants = {case_id: _variants(case_id) for case_id in ("case-a", "case-b", "case-c")}
    monkeypatch.setattr(
        module,
        "_request_variants_for_case",
        lambda _root, case: variants[case.case_id],
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "_request_hashes_for_case",
        lambda _root, case: [item[0] for item in variants[case.case_id]],
    )
    empty_set_sha256 = _sha256(b"[]")
    expectation = historical_expectation_value(
        provider="codex_exec",
        model="model",
        historical_unbound_committed_count=0,
        historical_unbound_committed_set_sha256=empty_set_sha256,
        historical_response_commitment_set_sha256=empty_set_sha256,
        provider_failure_event_quarantine_count=0,
        provider_failure_codes={},
        provider_failure_audit_commitment_set_sha256=empty_set_sha256,
    )
    monkeypatch.setattr(
        module,
        "load_historical_expectation_with_evidence",
        lambda _root: (
            expectation,
            {
                "expectation_file": (
                    "configs/historical-teacher-audit-expectation.v1.json"
                ),
                "expectation_file_sha256": "sha256:" + "a" * 64,
                "expectation_commitment_sha256": expectation[
                    "expectation_commitment_sha256"
                ],
            },
        ),
    )
    pre_batch_requests = dict(_variants("synthetic-frozen-v21")[:3])
    pre_recovery_requests = dict(_variants("synthetic-frozen-v22")[:7])
    monkeypatch.setattr(
        module,
        "_frozen_v21_first_case_requests",
        lambda *_args: pre_batch_requests,
    )
    monkeypatch.setattr(
        module,
        "_frozen_v22_recovery_requests",
        lambda *_args: pre_recovery_requests,
    )
    original_scan_teacher_audit = module._scan_teacher_audit

    def synthetic_scan_teacher_audit(
        *args: Any, **kwargs: Any
    ) -> dict[str, Any]:
        scan = original_scan_teacher_audit(*args, **kwargs)
        scan["pre_batch_bound_committed"] = 3
        scan["pre_batch_by_response"] = {
            f"synthetic-v21-response-{index}": {"request_hash": request_hash}
            for index, request_hash in enumerate(pre_batch_requests)
        }
        pre_recovery_hash = next(iter(pre_recovery_requests))
        scan["pre_recovery_bound_committed"] = 1
        scan["pre_recovery_by_response"] = {
            "synthetic-v22-response": {"request_hash": pre_recovery_hash}
        }
        return scan

    monkeypatch.setattr(module, "_scan_teacher_audit", synthetic_scan_teacher_audit)
    monkeypatch.setattr(
        module,
        "_test_receipt_evidence",
        lambda _root, _output: [
            CanonicalReceiptEvidence(
                name=name,
                receipt_relative_path=f"reports/offline-{name}-receipt.json",
                receipt_sha256="sha256:" + character * 64,
                receipt_commitment_sha256="sha256:" + character * 64,
                passed_count=1,
                code_commitments_sha256="sha256:" + "d" * 64,
                attestation_relative_path=(
                    f"reports/offline-{name}-receipt.json.native-attestation"
                ),
                attestation_sha256="sha256:" + character * 64,
                native_contract_sha256="sha256:" + "e" * 64,
                public_key_id="sha256:" + "f" * 64,
            )
            for name, character in (("focused", "a"), ("full", "b"))
        ],
    )
    if write_current_attempt:
        monkeypatch.setattr(
            module,
            "build_oracle_context",
            lambda _root, _case: SimpleNamespace(sha256="sha256:" + "a" * 64),
        )
        monkeypatch.setattr(module, "allowed_action_values", lambda _root: {})
        monkeypatch.setattr(module, "_load_store", lambda _root, _case: object())
        monkeypatch.setattr(
            module,
            "_evaluate_enrichment_attempt",
            lambda **_kwargs: SimpleNamespace(
                structured_output_valid=False,
                payload=None,
                validation=None,
                repair_error="invalid_structured_output",
            ),
        )

    class _Runner:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run(self, case, output_dir: Path):
            assert active_batch_lock(output_dir.parent) is not None
            calls.append(case.case_id)
            if write_current_attempt:
                _write_complete_attempt(
                    output_dir.parent,
                    request=variants[case.case_id][0][1],
                )
            if write_transport_attempt:
                _write_provider_failure_attempt(
                    output_dir.parent,
                    request=variants[case.case_id][0][1],
                )
            if write_receipt:
                (output_dir / "failures").mkdir(parents=True, exist_ok=True)
                (output_dir / "failures" / f"{case.case_id}.json").write_text(
                    json.dumps(
                        {
                            "schema_version": "1.0",
                            "case_id": case.case_id,
                            "attempts": (
                                1
                                if write_current_attempt or write_transport_attempt
                                else 0
                            ),
                            "error": (
                                "teacher output remained invalid"
                                if write_current_attempt
                                else "teacher request failed"
                            ),
                            "error_kind": (
                                "structured_invalid"
                                if write_current_attempt
                                else "transport"
                            ),
                            "failed_attempt": (
                                1
                                if write_current_attempt or write_transport_attempt
                                else 0
                            ),
                            "validation_attempt": None,
                            "validation": None,
                            "positive_transition_written": False,
                        },
                        sort_keys=True,
                    ),
                    encoding="utf-8",
                )
            raise RuntimeError("stop")

    monkeypatch.setattr(module, "EnrichmentRunner", _Runner)
    report = run_fail_fast_batch(
        root=root,
        case_file=case_file,
        scope_case_file=scope_file,
        output_root=output,
        teacher=_Teacher(),
    )
    assert report.status == "REMAINING_P0_CASE_RECOVERY_STOPPED"
    return output, case_file, scope_file, calls


def test_current_transport_quarantine_publishes_and_replays_terminal_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, case_file, scope_file, calls = _failed_run(
        tmp_path,
        monkeypatch,
        write_transport_attempt=True,
    )

    assert calls == ["case-a"]
    report = verify_fail_fast_report(
        root=case_file.parent,
        case_file=case_file,
        scope_case_file=scope_file,
        output_root=output,
    )
    assert report.status == "REMAINING_P0_CASE_RECOVERY_STOPPED"
    assert report.completed_case_ids == []
    assert report.failed_case_id == "case-a"
    assert report.not_started_case_ids == ["case-b"]
    assert len(report.current_attempts) == 1
    assert report.current_attempts[0].status == "quarantined"
    assert report.current_attempts[0].failure_code == "provider_failure_event"
    assert not (output / "cache/teacher").exists()


def test_audit_state_keeps_active_transport_delta_out_of_frozen_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import egsi.generation.fail_fast_batch as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }
    audit_function = functions["_audit_state"]
    expectation_index = next(
        index
        for index, argument in enumerate(audit_function.args.kwonlyargs)
        if argument.arg == "historical_expectation"
    )
    assert audit_function.args.kw_defaults[expectation_index] is None
    assert "None" not in ast.unparse(
        audit_function.args.kwonlyargs[expectation_index].annotation
    )
    assert "_audit_state_observation" in functions
    observation_arguments = functions["_audit_state_observation"].args
    assert "historical_expectation" not in {
        argument.arg
        for argument in [
            *observation_arguments.args,
            *observation_arguments.kwonlyargs,
        ]
    }
    assert "historical_expectation is not None" not in ast.unparse(
        audit_function
    )

    request = _variants("case-a")[0][1]
    request_hash = teacher_request_hash(request)
    manifest_path = _write_provider_failure_attempt(
        tmp_path, request=request
    )
    current_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    historical_commitments = [
        {
            "failure_code": "provider_failure_event",
            "audit_commitment_sha256": "sha256:" + f"{index:064x}",
        }
        for index in range(1, 21)
    ]
    current_commitment = {
        "failure_code": "provider_failure_event",
        "audit_commitment_sha256": current_manifest[
            "audit_commitment_sha256"
        ],
        "manifest_path": manifest_path.relative_to(tmp_path).as_posix(),
    }

    def digest(value: object) -> str:
        return _sha256(
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )

    pre_batch = {"sha256:" + character * 64 for character in "abc"}
    pre_recovery = {"sha256:" + "d" * 64}
    expectation = {
        "provider": "codex_exec",
        "model": "model",
        "historical_unbound_committed_count": 0,
        "historical_unbound_committed_set_sha256": digest([]),
        "historical_response_commitment_set_sha256": digest([]),
        "provider_failure_event_quarantine_count": 20,
        "provider_failure_codes": {"provider_failure_event": 20},
        "provider_failure_audit_commitment_set_sha256": digest(
            historical_commitments
        ),
    }
    scan = {
        "malformed_invalid": 0,
        "identity_mismatches": 0,
        "tool_events": 0,
        "by_response": {},
        "committed": 0,
        "pre_batch_bound_committed": 3,
        "pre_batch_by_response": {
            f"response-{index}": {"request_hash": item}
            for index, item in enumerate(sorted(pre_batch))
        },
        "pre_recovery_bound_committed": 1,
        "pre_recovery_by_response": {
            "response-recovery": {"request_hash": next(iter(pre_recovery))}
        },
        "historical_unbound_committed": 0,
        "historical_unbound_set_sha256": digest([]),
        "historical_response_commitment_set_sha256": digest([]),
        "prior_provider_failure_count": 21,
        "failure_codes": {"provider_failure_event": 21},
        "provider_failure_commitments": [
            *historical_commitments,
            current_commitment,
        ],
        "provider_failure_audit_commitment_set_sha256": digest(
            [
                *historical_commitments,
                {
                    key: current_commitment[key]
                    for key in (
                        "failure_code",
                        "audit_commitment_sha256",
                    )
                },
            ]
        ),
        "artifact_set_sha256": "sha256:" + "f" * 64,
    }
    monkeypatch.setattr(module, "_scan_teacher_audit", lambda *_a, **_k: scan)

    attempts, audit = _audit_state(
        tmp_path,
        provider="codex_exec",
        model="model",
        request_hashes={"case-a": [request_hash]},
        expected_requests={request_hash: request},
        pre_batch_request_hashes=pre_batch,
        pre_recovery_request_hashes=pre_recovery,
        historical_expectation=expectation,
        active_current_case_ids={"case-a"},
    )

    assert len(attempts) == 1
    assert audit["prior_provider_failure_count"] == 20
    assert audit["failure_codes"] == {"provider_failure_event": 20}
    assert audit["current_quarantined_provider_failure_count"] == 1
    assert audit["current_quarantined_manifest_paths"] == [
        manifest_path.relative_to(tmp_path).as_posix()
    ]


def test_runner_exception_without_receipt_publishes_source_controlled_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import egsi.generation.fail_fast_batch as module

    for expectation_state in ("missing", "invalid"):
        root = tmp_path / expectation_state / "root"
        root.mkdir(parents=True)
        case_file = root / "recover.txt"
        case_file.write_text("case-a\n", encoding="utf-8")
        scope_file = root / "scope.txt"
        scope_file.write_text("case-a\n", encoding="utf-8")
        output = tmp_path / expectation_state / "output"
        if expectation_state == "invalid":
            configs = root / "configs"
            configs.mkdir()
            (configs / "historical-teacher-audit-expectation.v1.json").write_text(
                "{}\n", encoding="utf-8"
            )
        side_effects: list[str] = []

        class _ObservedBatchLock:
            def __init__(self, _output_root: Path) -> None:
                side_effects.append("lock:init")

            def __enter__(self):
                side_effects.append("lock:enter")
                return self

            def __exit__(self, *_args: object) -> None:
                side_effects.append("lock:exit")

        class _ObservedRunner:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                side_effects.append("runner:init")
                raise ValueError(
                    "runner constructed before historical expectation failure"
                )

            def run(self, *_args: object, **_kwargs: object) -> object:
                side_effects.append("runner:run")
                raise AssertionError("unreachable")

        original_mkdir = Path.mkdir

        def observed_mkdir(path: Path, *args: object, **kwargs: object) -> None:
            if path == output or output in path.parents:
                side_effects.append("mkdir")
            original_mkdir(path, *args, **kwargs)

        with monkeypatch.context() as scenario_patch:
            scenario_patch.setattr(module, "BatchLock", _ObservedBatchLock)
            scenario_patch.setattr(module, "EnrichmentRunner", _ObservedRunner)
            scenario_patch.setattr(
                module,
                "_archive_existing",
                lambda *_args, **_kwargs: side_effects.append("archive"),
            )
            scenario_patch.setattr(Path, "mkdir", observed_mkdir)
            scenario_patch.setattr(
                module,
                "catalog_index",
                lambda _root: {"case-a": _case("case-a")},
            )
            variants = _variants("case-a")
            scenario_patch.setattr(
                module,
                "_request_variants_for_case",
                lambda _root, _case: variants,
            )

            with pytest.raises(ValueError, match="historical expectation"):
                run_fail_fast_batch(
                    root=root,
                    case_file=case_file,
                    scope_case_file=scope_file,
                    output_root=output,
                    teacher=_Teacher(),
                )

        assert side_effects == []
        assert not output.exists()

    output, case_file, scope_file, calls = _failed_run(
        tmp_path, monkeypatch, write_receipt=False
    )

    assert calls == ["case-a"]
    receipt = json.loads(
        (output / "enrichment/failures/case-a.json").read_text(encoding="utf-8")
    )
    assert receipt == {
        "attempts": 0,
        "case_id": "case-a",
        "error": "enrichment runner failed before publishing a failure receipt",
        "error_kind": "orchestrator",
        "failed_attempt": None,
        "positive_transition_written": False,
        "schema_version": "1.0",
        "validation": None,
        "validation_attempt": None,
    }
    verified = verify_fail_fast_report(
        root=case_file.parent,
        case_file=case_file,
        scope_case_file=scope_file,
        output_root=output,
    )
    assert verified.status == "REMAINING_P0_CASE_RECOVERY_STOPPED"


def test_duplicate_archive_bytes_are_renamed_to_a_unique_history_file(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    active = output / "reports/enrichment-summary.json"
    active.parent.mkdir(parents=True)
    raw = b'{"status":"old"}\n'
    active.write_bytes(raw)
    digest = _sha256(raw).removeprefix("sha256:")
    history = output / "reports/remaining-p0/history"
    history.mkdir(parents=True)
    first = history / f"enrichment-summary.{digest}.json"
    first.write_bytes(raw)

    _archive_existing(output, active, "enrichment-summary")

    assert not active.exists()
    assert first.read_bytes() == raw
    assert (history / f"enrichment-summary.{digest}.1.json").read_bytes() == raw


@pytest.mark.parametrize("tamper", [None, "artifact", "signature", "swap"])
def test_native_rsa_receipt_attestation_is_cryptographically_bound(
    tamper: str | None,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    native_contract = "sha256:" + "1" * 64
    public_key_id = "sha256:" + "2" * 64
    receipt = b'{"native_attested":false,"synthetic":true}\n'

    attested_name = "full" if tamper == "swap" else "focused"
    artifact_name = f"offline-{attested_name}-receipt.json"
    preimage = (
        "EGSI-NATIVE-ATTESTATION-V2\n"
        "algorithm=rsa-2048-sha256-pkcs1-v1_5\n"
        f"domain=egsi.test-receipt.{attested_name}.v1\n"
        f"artifact={artifact_name}\n"
        f"artifact_sha256={_sha256(receipt).removeprefix('sha256:')}\n"
        f"native_contract={native_contract.removeprefix('sha256:')}\n"
        f"key_id={public_key_id.removeprefix('sha256:')}\n"
    ).encode("ascii")
    signature = private_key.sign(preimage, padding.PKCS1v15(), hashes.SHA256())
    sidecar = preimage + f"signature={signature.hex()}\n".encode("ascii")
    if tamper == "artifact":
        receipt += b" "
    elif tamper == "signature":
        signature_offset = sidecar.index(b"signature=") + len(b"signature=")
        replacement = b"0" if sidecar[signature_offset : signature_offset + 1] != b"0" else b"1"
        sidecar = (
            sidecar[:signature_offset]
            + replacement
            + sidecar[signature_offset + 1 :]
        )

    if tamper is None:
        large_lock = {
            "entries": [{"index": index} for index in range(10_001)],
            "lock_commitment_sha256": "sha256:" + "0" * 64,
        }
        unsigned_lock = dict(large_lock)
        unsigned_lock.pop("lock_commitment_sha256")
        expected_lock_commitment = _sha256(
            json.dumps(
                unsigned_lock,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        assert _large_dict_commitment(
            large_lock, "lock_commitment_sha256"
        ) == expected_lock_commitment
        _verify_receipt_attestation(
            sidecar,
            name="focused",
            artifact_name="offline-focused-receipt.json",
            artifact_raw=receipt,
            native_contract_sha256=native_contract,
            public_key_id=public_key_id,
            modulus_hex=f"{public_numbers.n:0512x}",
            exponent=public_numbers.e,
        )
    else:
        with pytest.raises(ValueError, match="native"):
            _verify_receipt_attestation(
                sidecar,
                name="focused",
                artifact_name="offline-focused-receipt.json",
                artifact_raw=receipt,
                native_contract_sha256=native_contract,
                public_key_id=public_key_id,
                modulus_hex=f"{public_numbers.n:0512x}",
                exponent=public_numbers.e,
            )


def test_current_native_v2_receipt_trust_root_is_accepted_before_artifact_scan(
    tmp_path: Path,
) -> None:
    with pytest.raises(FileNotFoundError):
        _test_receipt_evidence(ROOT, tmp_path)


def test_failure_stops_before_second_case_and_verifier_recomputes_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, case_file, scope_file, calls = _failed_run(tmp_path, monkeypatch)

    assert calls == ["case-a"]
    verified = verify_fail_fast_report(
        root=case_file.parent,
        case_file=case_file,
        scope_case_file=scope_file,
        output_root=output,
    )
    assert verified.failed_case_id == "case-a"
    assert verified.not_started_case_ids == ["case-b"]
    assert verified.forbidden_case_ids == ["case-c"]
    assert verified.recovery_mode == "forward_recovery"
    assert verified.target_reason == "next_incomplete_contiguous_p0_segment"


def test_stopped_report_rejects_recommitted_receipt_against_current_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, case_file, scope_file, _ = _failed_run(
        tmp_path, monkeypatch, write_current_attempt=True
    )
    receipt_path = output / "enrichment/failures/case-a.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["error_kind"] = "semantic_invalid"
    receipt_path.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    provenance = _write_provenance_manifest(
        output / "enrichment",
        ["case-a", "case-b"],
        [],
        ["case-a"],
        generation_mode="live",
        provider="codex_exec",
        model="model",
    )
    _publish_summary(
        output,
        status="REMAINING_P0_CASE_RECOVERY_STOPPED",
        requested=["case-a", "case-b"],
        completed=[],
        failed_case_id="case-a",
        not_started=["case-b"],
        provenance=provenance,
    )
    _refresh_report(output)

    with pytest.raises(ValueError, match="fail-fast report verification failed"):
        verify_fail_fast_report(
            root=case_file.parent,
            case_file=case_file,
            scope_case_file=scope_file,
            output_root=output,
        )


def test_stopped_report_rejects_contradictory_positive_for_failed_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, case_file, scope_file, _ = _failed_run(tmp_path, monkeypatch)
    (output / "enrichment/case-a.json").write_text("{}", encoding="utf-8")
    _refresh_report(output)

    with pytest.raises(ValueError, match="fail-fast report verification failed"):
        verify_fail_fast_report(
            root=case_file.parent,
            case_file=case_file,
            scope_case_file=scope_file,
            output_root=output,
        )


@pytest.mark.parametrize("tamper", ["audit_body", "cache_body"])
def test_verifier_rejects_recommitted_current_audit_or_cache_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    output, case_file, scope_file, _ = _failed_run(
        tmp_path, monkeypatch, write_current_attempt=True
    )
    report = json.loads(
        (output / "reports/remaining-p0/fail-fast-report.json").read_text(
            encoding="utf-8"
        )
    )
    manifest_path = output / report["current_attempts"][0]["manifest_path"]
    if tamper == "audit_body":
        metadata_path = manifest_path.with_name("events.metadata.jsonl")
        metadata = metadata_path.read_bytes().replace(
            b'"agent_message"', b'"reasoning"'
        )
        metadata_path.write_bytes(metadata)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["events_metadata_length"] = len(metadata)
        manifest["events_metadata_sha256"] = _sha256(metadata)
        manifest["audit_commitment_sha256"] = _dict_commitment(
            manifest, "audit_commitment_sha256"
        )
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
    else:
        cache_path = next((output / "cache/teacher").glob("*.json"))
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
        cache["text"] = '{"tampered":true}'
        cache_path.write_text(
            json.dumps(cache, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
    _refresh_report(output)

    with pytest.raises(ValueError, match="fail-fast report verification failed"):
        verify_fail_fast_report(
            root=case_file.parent,
            case_file=case_file,
            scope_case_file=scope_file,
            output_root=output,
        )


@pytest.mark.parametrize("tamper", ["provenance", "summary"])
def test_verifier_rejects_recommitted_provenance_or_summary_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    output, case_file, scope_file, _ = _failed_run(tmp_path, monkeypatch)
    if tamper == "provenance":
        path = output / "enrichment/_batch-provenance.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["requested_model"] = "recommitted-wrong-model"
        value["batch_commitment_sha256"] = _dict_commitment(
            value, "batch_commitment_sha256"
        )
    else:
        path = output / "reports/enrichment-summary.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["not_started_case_ids"] = []
        value["summary_commitment_sha256"] = _dict_commitment(
            value, "summary_commitment_sha256"
        )
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    _refresh_report(output)

    with pytest.raises(ValueError, match="fail-fast report verification failed"):
        verify_fail_fast_report(
            root=case_file.parent,
            case_file=case_file,
            scope_case_file=scope_file,
            output_root=output,
        )


def test_verifier_rejects_recommitted_attempt_after_first_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, case_file, scope_file, _ = _failed_run(tmp_path, monkeypatch)
    report_path = output / "reports/remaining-p0/fail-fast-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    request_hash = report["request_hashes"]["case-b"][0]
    attempt = output / f"audit/teacher/{request_hash}/late/attempt-00"
    attempt.mkdir(parents=True)
    manifest = {
        "request_hash": request_hash,
        "status": "quarantined",
        "failure_code": "provider_failure_event",
    }
    manifest["audit_commitment_sha256"] = _dict_commitment(
        manifest, "audit_commitment_sha256"
    )
    (attempt / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    _refresh_report(output)

    with pytest.raises(ValueError, match="fail-fast report verification failed"):
        verify_fail_fast_report(
            root=case_file.parent,
            case_file=case_file,
            scope_case_file=scope_file,
            output_root=output,
        )


@pytest.mark.parametrize("tamper", ["request_order", "duplicate_request"])
def test_verifier_rejects_recommitted_request_hash_order_or_duplicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    output, case_file, scope_file, _ = _failed_run(tmp_path, monkeypatch)
    report_path = output / "reports/remaining-p0/fail-fast-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    hashes = report["request_hashes"]["case-a"]
    report["request_hashes"]["case-a"] = (
        list(reversed(hashes))
        if tamper == "request_order"
        else [hashes[0], hashes[0], *hashes[2:]]
    )
    report["report_commitment_sha256"] = _report_commitment(report)
    report_path.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="fail-fast report verification failed"):
        verify_fail_fast_report(
            root=case_file.parent,
            case_file=case_file,
            scope_case_file=scope_file,
            output_root=output,
        )


@pytest.mark.parametrize(
    "tamper",
    [
        "extra_report_field",
        "flip_report_field",
        "recovery_mode",
        "reorder_inventory",
        "missing_failure_receipt",
        "extra_positive",
        "forbidden_case_audit",
    ],
)
def test_independent_verifier_fails_closed_on_report_and_artifact_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: str
) -> None:
    output, case_file, scope_file, _ = _failed_run(tmp_path, monkeypatch)
    report_path = output / "reports/remaining-p0/fail-fast-report.json"
    if tamper in {
        "extra_report_field",
        "flip_report_field",
        "recovery_mode",
        "reorder_inventory",
    }:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if tamper == "extra_report_field":
            report["extra"] = True
        elif tamper == "flip_report_field":
            report["stop_on_first_failure"] = False
        elif tamper == "recovery_mode":
            report["recovery_mode"] = "explicit_reattestation"
            report["target_reason"] = "native_live_attestation_for_prompt_v2_3"
            report["report_commitment_sha256"] = _report_commitment(report)
        else:
            report["artifact_inventory"] = list(
                reversed(report["artifact_inventory"])
            )
        report_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    elif tamper == "missing_failure_receipt":
        (output / "enrichment/failures/case-a.json").unlink()
    elif tamper == "extra_positive":
        (output / "enrichment/unexpected.json").write_text("{}", encoding="utf-8")
    else:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        request_hash = report["request_hashes"]["case-c"][0]
        attempt = output / (
            f"audit/teacher/{request_hash}/new/attempt-00"
        )
        attempt.mkdir(parents=True)
        (attempt / "manifest.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="fail-fast report verification failed"):
        verify_fail_fast_report(
            root=case_file.parent,
            case_file=case_file,
            scope_case_file=scope_file,
            output_root=output,
        )


def test_recovered_verifier_rejects_reviewer_deleting_only_v22_audit_and_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reviewer cannot erase the sole live v2.2 transaction and re-sign JSON."""

    output = _copy_frozen_v22_output(tmp_path / "reviewer-copy")
    report_path = output / "reports/remaining-p0/fail-fast-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW"
    assert len(report["current_attempts"]) == 1
    attempt = report["current_attempts"][0]
    manifest_path = output / attempt["manifest_path"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    response_commitment = manifest["response_commitment_sha256"]

    cache_matches = []
    for path in (output / "cache/teacher").glob("*.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("response_commitment_sha256") == response_commitment:
            cache_matches.append(path)
    assert len(cache_matches) == 1
    shutil.rmtree(output / "audit/teacher" / attempt["request_hash"])
    cache_matches[0].unlink()

    requested = read_case_ids(ROOT / "configs/recover_3wfj_cases.txt")
    scope = read_case_ids(ROOT / "configs/p0_cases.txt")
    forbidden = scope[scope.index(requested[-1]) + 1 :]
    catalog = catalog_index(ROOT)
    request_hashes, expected_requests = _request_state(
        ROOT, catalog, [*requested, *forbidden]
    )
    attempts, audit = _audit_state_observation(
        output,
        provider=report["provider"],
        model=report["model"],
        request_hashes=request_hashes,
        expected_requests=expected_requests,
    )
    assert attempts == []
    assert audit["committed"] == 0

    report["current_attempts"] = []
    report["teacher_audit_artifact_set_sha256"] = audit[
        "artifact_set_sha256"
    ]
    report["teacher_current_bound_committed"] = 0
    report["artifact_inventory"] = [
        item.model_dump(mode="json") for item in _inventory(output)
    ]
    report["report_commitment_sha256"] = _report_commitment(report)
    report_path.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    receipt_evidence = [
        CanonicalReceiptEvidence.model_validate(item)
        for item in report["canonical_test_receipts"]
    ]
    monkeypatch.setattr(
        "egsi.generation.fail_fast_batch._test_receipt_evidence",
        lambda _root, _output: receipt_evidence,
    )

    with pytest.raises(ValueError, match="fail-fast report verification failed"):
        verify_fail_fast_report(
            root=ROOT,
            case_file=ROOT / "configs/recover_3wfj_cases.txt",
            scope_case_file=ROOT / "configs/p0_cases.txt",
            output_root=output,
        )


@pytest.mark.parametrize(
    "tamper",
    [
        "repair_only",
        "skip_attempt",
        "wrong_repair_code",
        "reordered_started_time",
        "valid_then_repair",
    ],
)
def test_recovered_verifier_rejects_noncausal_current_attempt_sequence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: str
) -> None:
    """Only a real runner transition sequence may justify a final positive."""

    output = _causal_sequence_copy(tmp_path, tamper)
    _stub_current_receipts(output, monkeypatch)

    with pytest.raises(ValueError, match="fail-fast report verification failed"):
        verify_fail_fast_report(
            root=ROOT,
            case_file=ROOT / "configs/recover_3wfj_cases.txt",
            scope_case_file=ROOT / "configs/p0_cases.txt",
            output_root=output,
        )


def test_real_v22_attempt_is_classified_only_as_pre_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del tmp_path, monkeypatch
    requested = read_case_ids(ROOT / "configs/recover_3wfj_cases.txt")
    scope = read_case_ids(ROOT / "configs/p0_cases.txt")
    forbidden = scope[scope.index(requested[-1]) + 1 :]
    request_hashes, expected, pre_batch, pre_recovery, historical = (
        _request_state_with_history(
            ROOT,
            catalog_index(ROOT),
            [*requested, *forbidden],
            historical_expectation=_historical_expectation(),
        )
    )
    attempts, audit = _audit_state(
        ROOT / ".work/real-p0-codex-v2",
        provider="codex_exec",
        model="gpt-5.6-sol",
        request_hashes=request_hashes,
        expected_requests=expected,
        pre_batch_request_hashes=pre_batch,
        pre_recovery_request_hashes=pre_recovery,
        historical_expectation=historical,
        active_current_case_ids=set(requested),
    )
    assert audit["pre_recovery_bound_committed"] == 1
    assert all(item.request_hash not in pre_recovery for item in attempts)


def test_fail_fast_verifier_rejects_missing_exact_historical_unbound_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The five semantic-invalid historical commits are a source trust root."""

    output = _copy_frozen_v22_output(tmp_path / "reviewer-history-copy")
    report_path = output / "reports/remaining-p0/fail-fast-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    requested = read_case_ids(ROOT / "configs/recover_3wfj_cases.txt")
    scope = read_case_ids(ROOT / "configs/p0_cases.txt")
    forbidden = scope[scope.index(requested[-1]) + 1 :]
    catalog = catalog_index(ROOT)
    (
        request_hashes,
        expected_requests,
        pre_batch_request_hashes,
        pre_recovery_request_hashes,
        _,
    ) = _request_state_with_history(
        ROOT,
        catalog,
        [*requested, *forbidden],
        historical_expectation=_historical_expectation(),
    )
    current_hashes = set().union(*request_hashes.values())
    first_case = json.loads(
        (output / "reports/first-case-hard-gate.json").read_text(encoding="utf-8")
    )
    pre_batch_hashes = {item["request_hash"] for item in first_case["attempts"]}
    candidates = []
    for path in sorted((output / "audit/teacher").rglob("manifest.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if (
            manifest.get("status") == "committed"
            and manifest["request_hash"]
            not in current_hashes | pre_batch_hashes | pre_recovery_request_hashes
        ):
            candidates.append((path, manifest))
    assert len(candidates) == 5
    manifest_path, manifest = candidates[0]
    cache_matches = []
    for path in (output / "cache/teacher").glob("*.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        if (
            value.get("response_commitment_sha256")
            == manifest["response_commitment_sha256"]
        ):
            cache_matches.append(path)
    assert len(cache_matches) == 1
    shutil.rmtree(output / "audit/teacher" / manifest["request_hash"])
    cache_matches[0].unlink()

    attempts, audit = _audit_state_observation(
        output,
        provider=report["provider"],
        model=report["model"],
        request_hashes=request_hashes,
        expected_requests=expected_requests,
        pre_batch_request_hashes=pre_batch_request_hashes,
        pre_recovery_request_hashes=pre_recovery_request_hashes,
    )
    assert audit["historical_unbound_committed"] == 4

    report["teacher_audit_artifact_set_sha256"] = audit[
        "artifact_set_sha256"
    ]
    report["artifact_inventory"] = [
        item.model_dump(mode="json") for item in _inventory(output)
    ]
    report["report_commitment_sha256"] = _report_commitment(report)
    report_path.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    receipt_evidence = [
        CanonicalReceiptEvidence.model_validate(item)
        for item in report["canonical_test_receipts"]
    ]
    monkeypatch.setattr(
        "egsi.generation.fail_fast_batch._test_receipt_evidence",
        lambda _root, _output: receipt_evidence,
    )

    with pytest.raises(ValueError, match="fail-fast report verification failed"):
        verify_fail_fast_report(
            root=ROOT,
            case_file=ROOT / "configs/recover_3wfj_cases.txt",
            scope_case_file=ROOT / "configs/p0_cases.txt",
            output_root=output,
        )


def test_real_fail_fast_scan_binds_v22_and_prebatch_v21_and_exact_history() -> None:
    output = ROOT / ".work/real-p0-codex-v2"
    requested = read_case_ids(ROOT / "configs/recover_3wfj_cases.txt")
    scope = read_case_ids(ROOT / "configs/p0_cases.txt")
    forbidden = scope[scope.index(requested[-1]) + 1 :]
    catalog = catalog_index(ROOT)
    (
        request_hashes,
        expected_requests,
        pre_batch_hashes,
        pre_recovery_hashes,
        expectation,
    ) = _request_state_with_history(
        ROOT,
        catalog,
        [*requested, *forbidden],
        historical_expectation=_historical_expectation(),
    )

    attempts, audit = _audit_state(
        output,
        provider="codex_exec",
        model="gpt-5.6-sol",
        request_hashes=request_hashes,
        expected_requests=expected_requests,
        pre_batch_request_hashes=pre_batch_hashes,
        pre_recovery_request_hashes=pre_recovery_hashes,
        historical_expectation=expectation,
        active_current_case_ids=set(requested),
    )
    archived_records = sorted(
        (output / "enrichment/quarantine").glob(
            "ghsa-3wfj-vh84-732p.[0-9a-f]*.json"
        )
    )
    assert len(archived_records) == 1
    record = json.loads(archived_records[0].read_text(encoding="utf-8"))

    assert len(attempts) == 1
    assert attempts[0].status == "quarantined"
    assert attempts[0].failure_code == "provider_failure_event"
    assert audit["committed"] == 0
    assert audit["current_quarantined_provider_failure_count"] == 1
    assert record["teacher_response_commitment_sha256"] in audit[
        "pre_recovery_by_response"
    ]
    assert audit["pre_recovery_bound_committed"] == 1
    assert {
        item["request_hash"]
        for item in audit["pre_recovery_by_response"].values()
    } <= pre_recovery_hashes
    assert audit["pre_batch_bound_committed"] == 3
    assert {
        item["request_hash"]
        for item in audit["pre_batch_by_response"].values()
    } == pre_batch_hashes
    assert audit["historical_unbound_committed"] == 5
    assert audit["historical_unbound_set_sha256"] == expectation[
        "historical_unbound_committed_set_sha256"
    ]
    assert audit["historical_response_commitment_set_sha256"] == expectation[
        "historical_response_commitment_set_sha256"
    ]

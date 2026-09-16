"""Assemble an honestly partial, replay-validated P0 training artifact set."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from egsi.contracts.enrichment import EnrichmentRecord
from egsi.contracts.trajectory import EpisodeEvent, T1Transition
from egsi.data.context import build_oracle_context
from egsi.generation.enrichment import (
    _load_store,
    _prompt_vocabulary,
    allowed_action_values,
)
from egsi.generation.pragmatic_batch import (
    PragmaticBatchReport,
    PragmaticBatchState,
    PragmaticCaseState,
    PragmaticQuarantineReceipt,
    pragmatic_quarantine_receipt_commitment,
    validate_pragmatic_state_semantics,
)
from egsi.generation.pilot import (
    _dict_commitment,
    _episode_metrics,
    _read_regular,
    _record_is_current,
    _remove_regular_if_present,
    _sha256,
    _validate_case_ids,
    catalog_index,
    read_case_ids,
    write_report,
)
from egsi.generation.replay import replay_events
from egsi.generation.safeio import AnchoredDirectory, BatchLock, active_batch_lock
from egsi.generation.trajectory import (
    _atomic_bytes,
    compile_t1_episode,
    compile_t1_episode_frozen_v21,
    episode_commitment,
    read_parquet,
    write_jsonl,
    write_parquet,
)
from egsi.strict_json import strict_json_loads
from egsi.teacher.base import TeacherRequest, teacher_request_hash
from egsi.teacher.prompts import enrichment_request


_FIRST_CASE_ID = "ghsa-2m8h-fgr8-2q9w"
_MAX_RECORD_BYTES = 2 * 1024 * 1024
_MAX_REPORT_BYTES = 4 * 1024 * 1024
_TRUSTED_LEGACY_P0_STATE_SHA256 = (
    "sha256:08e354fbcac2d9f78163bcc876385d758d886b678b7613072467e6d0c6141425"
)
_TRUSTED_LEGACY_P0_REPORT_SHA256 = (
    "sha256:28920acca403dafc8b870672d70113de2b2239232ab469e2bebd51b4c2dbe633"
)
_TRUSTED_LEGACY_P0_MANIFEST_SHA256 = (
    "sha256:d42960c4a2e4a86983a87d72118514f9d514d7f6b2c51209ad23dca1c0a577c1"
)
_TRUSTED_LEGACY_P0_QUARANTINES = {
    "enrichment/quarantine/ghsa-3hrc-f439-727g.slot-1.json": (
        "sha256:71566a50a7b07dee18075581fb1c1498027b36eb780e2ecc07a9e980d313b1d5"
    )
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_default=True)


class _FailureReceipt(_StrictModel):
    schema_version: Literal["1.0"]
    case_id: str
    attempts: int = Field(ge=0, le=2)
    error: str = Field(max_length=2000)
    error_kind: str = Field(min_length=1, max_length=256)
    failed_attempt: int | None
    validation_attempt: int | None
    validation: dict[str, Any] | None
    positive_transition_written: Literal[False]


class _BatchArtifact(_StrictModel):
    case_id: str
    relative_path: str
    file_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    kind: Literal["enrichment_record", "failure_receipt"]
    record_commitment_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    requested_model: str | None
    provider_response_model: str | None
    teacher_response_commitment_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )


class _BatchManifest(_StrictModel):
    schema_version: Literal["1.1"]
    stage: Literal["enrichment_provenance"]
    generation_mode: Literal["fixture", "live"]
    provider: str = Field(min_length=1, max_length=256)
    model: str = Field(min_length=1, max_length=256)
    requested_provider: str = Field(min_length=1, max_length=256)
    requested_model: str = Field(min_length=1, max_length=256)
    provider_response_models: list[str]
    provider_response_model_counts: dict[str, int]
    requested_case_ids: list[str]
    artifacts: list[_BatchArtifact]
    pragmatic_state_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    batch_commitment_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class _LegacyBatchManifestV10(_StrictModel):
    schema_version: Literal["1.0"]
    stage: Literal["enrichment_provenance"]
    generation_mode: Literal["fixture", "live"]
    provider: str = Field(min_length=1, max_length=256)
    model: str = Field(min_length=1, max_length=256)
    requested_provider: str = Field(min_length=1, max_length=256)
    requested_model: str = Field(min_length=1, max_length=256)
    provider_response_models: list[str]
    provider_response_model_counts: dict[str, int]
    requested_case_ids: list[str]
    artifacts: list[_BatchArtifact]
    batch_commitment_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class _BatchControlPlane:
    batch_root: Path
    state: PragmaticBatchState
    report: PragmaticBatchReport
    manifest: _BatchManifest | _LegacyBatchManifestV10
    artifacts: dict[str, _BatchArtifact]
    legacy_v10: bool


class CoverageCase(_StrictModel):
    case_id: str
    status: Literal["success", "failed", "gap"]
    source_kind: Literal["historical_v21", "pragmatic_batch", "none"]
    source_root: str | None
    source_relative_path: str | None
    source_file_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    record_commitment_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    output_relative_path: str | None
    reason: str | None

    @model_validator(mode="after")
    def consistent_status(self) -> "CoverageCase":
        if self.status == "success" and (
            self.record_commitment_sha256 is None
            or self.output_relative_path != f"enrichment/{self.case_id}.json"
            or self.reason is not None
        ):
            raise ValueError("successful coverage entry is incomplete")
        if self.status != "success" and self.output_relative_path is not None:
            raise ValueError("non-success coverage cannot name a training record")
        if self.status != "success" and not self.reason:
            raise ValueError("non-success coverage requires a reason")
        return self


class CoverageReport(_StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: Literal["p0_coverage_provenance"] = "p0_coverage_provenance"
    requested: Literal[10] = 10
    success: int = Field(ge=0, le=10)
    failed: int = Field(ge=0, le=10)
    gap: int = Field(ge=0, le=10)
    requested_case_ids: list[str] = Field(min_length=10, max_length=10)
    success_case_ids: list[str]
    failed_case_ids: list[str]
    gap_case_ids: list[str]
    cases: list[CoverageCase] = Field(min_length=10, max_length=10)
    conservation_valid: Literal[True] = True

    @model_validator(mode="after")
    def conserve(self) -> "CoverageReport":
        if self.success + self.failed + self.gap != self.requested:
            raise ValueError("coverage conservation failed")
        if [case.case_id for case in self.cases] != self.requested_case_ids:
            raise ValueError("coverage order mismatch")
        expected = {
            status: [
                case.case_id for case in self.cases if case.status == status
            ]
            for status in ("success", "failed", "gap")
        }
        if (
            self.success_case_ids != expected["success"]
            or self.failed_case_ids != expected["failed"]
            or self.gap_case_ids != expected["gap"]
        ):
            raise ValueError("coverage status lists mismatch")
        return self


class TrajectoryReport(_StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: Literal["training_ready_trajectory"] = "training_ready_trajectory"
    requested: Literal[10] = 10
    processed: int = Field(ge=0, le=10)
    skipped: int = Field(ge=0, le=10)
    processed_case_ids: list[str]
    skipped_case_ids: list[str]
    transitions: int = Field(ge=0)
    parquet_file: str | None
    event_files: list[str]
    transition_files: list[str]
    policy_oracle_leakage: int = Field(ge=0)
    nonzero_t1_rewards: int = Field(ge=0)
    selected_illegal_actions: int = Field(ge=0)
    event_replay_passed: int = Field(ge=0)
    internal_invariant_failure: bool

    @model_validator(mode="after")
    def conserve(self) -> "TrajectoryReport":
        if self.processed + self.skipped != self.requested:
            raise ValueError("trajectory coverage mismatch")
        if self.parquet_file is None and self.transitions != 0:
            raise ValueError("non-empty transitions require parquet")
        if self.parquet_file is not None and self.transitions == 0:
            raise ValueError("empty transitions forbid parquet")
        return self


class HumanAuditPacket(_StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: Literal["pragmatic_human_audit"] = "pragmatic_human_audit"
    requested: Literal[10] = 10
    training_samples: int = Field(ge=0, le=10)
    training_case_ids: list[str]
    excluded_case_ids: list[str]
    automated_gate_passed: bool
    informational_thresholds: dict[str, int]
    cases: list[dict[str, Any]]


class ArtifactEntry(_StrictModel):
    relative_path: str
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    kind: str
    case_id: str


class ArtifactManifest(_StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: Literal["training_ready_artifacts"] = "training_ready_artifacts"
    requested_case_ids: list[str] = Field(min_length=10, max_length=10)
    processed_case_ids: list[str]
    artifacts: list[ArtifactEntry]
    artifact_commitment_sha256: str = Field(
        pattern=r"^sha256:[0-9a-f]{64}$"
    )


def _read_optional(path: Path, *, limit: int) -> bytes | None:
    try:
        return _read_regular(path, limit=limit)
    except FileNotFoundError:
        return None


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    value = strict_json_loads(raw, max_bytes=_MAX_REPORT_BYTES)
    if type(value) is not dict:
        raise ValueError("expected a JSON object")
    return value


def _load_trusted_legacy_quarantine_v10(
    batch_root: Path,
    relative: str,
) -> tuple[PragmaticQuarantineReceipt, bytes]:
    raw = _read_regular(batch_root / relative, limit=_MAX_RECORD_BYTES)
    if (
        _TRUSTED_LEGACY_P0_QUARANTINES.get(relative) != _sha256(raw)
    ):
        raise ValueError("legacy quarantine is not source-approved")
    value = _strict_json_object(raw)
    if (
        value.get("schema_version") != "1.0"
        or "receipt_commitment_sha256" in value
    ):
        raise ValueError("legacy quarantine epoch is invalid")
    upgraded = dict(value)
    upgraded["schema_version"] = "1.1"
    upgraded["receipt_commitment_sha256"] = (
        pragmatic_quarantine_receipt_commitment(upgraded)
    )
    return PragmaticQuarantineReceipt.model_validate(upgraded), raw


def _load_trusted_legacy_state_v10(
    batch_root: Path,
    raw: bytes,
) -> PragmaticBatchState:
    if _sha256(raw) != _TRUSTED_LEGACY_P0_STATE_SHA256:
        raise ValueError("legacy pragmatic state is not source-approved")
    value = _strict_json_object(raw)
    if value.get("schema_version") != "1.0":
        raise ValueError("legacy pragmatic state epoch is invalid")
    upgraded = dict(value)
    upgraded["schema_version"] = "1.1"
    cases = upgraded.get("cases")
    if type(cases) is not list:
        raise ValueError("legacy pragmatic cases are invalid")
    upgraded_cases: list[dict[str, Any]] = []
    for original_case in cases:
        if type(original_case) is not dict:
            raise ValueError("legacy pragmatic case is invalid")
        case = dict(original_case)
        slots = case.get("slots")
        if type(slots) is not list:
            raise ValueError("legacy pragmatic slots are invalid")
        upgraded_slots: list[dict[str, Any]] = []
        for original_slot in slots:
            if (
                type(original_slot) is not dict
                or "quarantine_file_sha256" in original_slot
            ):
                raise ValueError("legacy pragmatic slot is invalid")
            slot = dict(original_slot)
            relative = slot.get("quarantine_relative_path")
            if relative is None:
                slot["quarantine_file_sha256"] = None
            else:
                if type(relative) is not str:
                    raise ValueError("legacy quarantine path is invalid")
                receipt, receipt_raw = _load_trusted_legacy_quarantine_v10(
                    batch_root, relative
                )
                if (
                    receipt.case_id != case.get("case_id")
                    or receipt.slot_index != slot.get("slot_index")
                    or receipt.request_hash != slot.get("request_hash")
                    or receipt.outcome != slot.get("outcome")
                    or receipt.result_repair_error
                    != slot.get("result_repair_error")
                    or receipt.provider_response_cached
                    != slot.get("provider_response_cached")
                    or (
                        slot.get("provider_invocation_evidence") == "confirmed"
                        and receipt.teacher_response_commitment_sha256 is None
                    )
                ):
                    raise ValueError("legacy quarantine binding mismatch")
                slot["quarantine_file_sha256"] = _sha256(receipt_raw)
            upgraded_slots.append(slot)
        case["slots"] = upgraded_slots
        upgraded_cases.append(case)
    upgraded["cases"] = upgraded_cases
    return PragmaticBatchState.model_validate(upgraded)


def _load_trusted_legacy_report_v10(raw: bytes) -> PragmaticBatchReport:
    if _sha256(raw) != _TRUSTED_LEGACY_P0_REPORT_SHA256:
        raise ValueError("legacy pragmatic report is not source-approved")
    value = _strict_json_object(raw)
    if value.get("schema_version") != "1.0":
        raise ValueError("legacy pragmatic report epoch is invalid")
    upgraded = dict(value)
    upgraded["schema_version"] = "1.1"
    return PragmaticBatchReport.model_validate(upgraded)


def _load_batch_control_plane(
    root: Path,
    batch_root: Path,
    expected_case_ids: list[str],
) -> _BatchControlPlane | None:
    """Validate batch-wide state/report/manifest relations without reading records."""

    state_path = batch_root / "reports/pragmatic-batch-state.json"
    report_path = batch_root / "reports/pragmatic-batch-report.json"
    manifest_path = batch_root / "enrichment/_batch-provenance.json"
    try:
        state_raw = _read_optional(state_path, limit=_MAX_REPORT_BYTES)
        report_raw = _read_optional(report_path, limit=_MAX_REPORT_BYTES)
        manifest_raw = _read_optional(manifest_path, limit=_MAX_REPORT_BYTES)
        if state_raw is None and report_raw is None and manifest_raw is None:
            return None
        if state_raw is None or report_raw is None or manifest_raw is None:
            raise ValueError
        state_version = _strict_json_object(state_raw).get("schema_version")
        legacy_v10 = state_version == "1.0"
        if legacy_v10:
            state = _load_trusted_legacy_state_v10(batch_root, state_raw)
            report = _load_trusted_legacy_report_v10(report_raw)
            if _sha256(manifest_raw) != _TRUSTED_LEGACY_P0_MANIFEST_SHA256:
                raise ValueError
            manifest: _BatchManifest | _LegacyBatchManifestV10 = (
                _LegacyBatchManifestV10.model_validate_json(manifest_raw)
            )
        else:
            state = PragmaticBatchState.model_validate_json(state_raw)
            report = PragmaticBatchReport.model_validate_json(report_raw)
            manifest = _BatchManifest.model_validate_json(manifest_raw)
        if (
            state.requested_case_ids != expected_case_ids
            or report.requested_case_ids != expected_case_ids
            or manifest.requested_case_ids != expected_case_ids
            or any(case.terminal_status == "pending" for case in state.cases)
            or state.provider != report.provider
            or state.provider != manifest.provider
            or state.provider != manifest.requested_provider
            or state.model != report.model
            or state.model != manifest.model
            or state.model != manifest.requested_model
            or state.generation_mode != report.generation_mode
            or state.generation_mode != manifest.generation_mode
            or state.configuration != report.configuration
        ):
            raise ValueError
        validate_pragmatic_state_semantics(
            root,
            batch_root,
            state,
            provider=state.provider,
            model=state.model,
            require_terminal_artifacts=False,
        )

        success_ids = [
            case.case_id for case in state.cases if case.terminal_status == "success"
        ]
        failed_ids = [
            case.case_id for case in state.cases if case.terminal_status == "failed"
        ]
        expected_failures = {
            case.case_id: {
                "stage": "pragmatic_enrichment",
                "error": case.error_kind,
                "slots_consumed": len(case.slots),
            }
            for case in state.cases
            if case.terminal_status == "failed"
        }
        uncertain = any(
            slot.status != "completed"
            or slot.provider_invocation_evidence != "confirmed"
            for case in state.cases
            for slot in case.slots
        )
        invocation_count = sum(len(case.slots) for case in state.cases)
        expected_invocations = {
            "kind": "upper_bound" if uncertain else "exact",
            "value": invocation_count,
        }
        if (
            report.requested != len(expected_case_ids)
            or report.success != len(success_ids)
            or report.failed != len(failed_ids)
            or report.success_case_ids != success_ids
            or report.failed_case_ids != failed_ids
            or report.failures != expected_failures
            or report.provider_invocations.model_dump(mode="json")
            != expected_invocations
        ):
            raise ValueError

        manifest_value = manifest.model_dump(mode="json")
        expected_provenance = {
            "generation_mode": manifest.generation_mode,
            "provider": manifest.provider,
            "model": manifest.model,
            "requested_provider": manifest.requested_provider,
            "requested_model": manifest.requested_model,
            "provider_response_models": manifest.provider_response_models,
            "provider_response_model_counts": (
                manifest.provider_response_model_counts
            ),
            "manifest_sha256": _sha256(manifest_raw),
            "batch_commitment_sha256": manifest.batch_commitment_sha256,
        }
        if not legacy_v10:
            if not isinstance(manifest, _BatchManifest):
                raise ValueError
            expected_provenance["pragmatic_state_sha256"] = (
                manifest.pragmatic_state_sha256
            )
        if (
            _sha256(manifest_raw) != report.provenance.get("manifest_sha256")
            or _dict_commitment(manifest_value, "batch_commitment_sha256")
            != manifest.batch_commitment_sha256
            or report.provenance != expected_provenance
            or (
                not legacy_v10
                and isinstance(manifest, _BatchManifest)
                and manifest.pragmatic_state_sha256 != _sha256(state_raw)
            )
            or manifest.provider_response_models
            != sorted(set(manifest.provider_response_models))
            or set(manifest.provider_response_model_counts)
            != set(manifest.provider_response_models)
            or any(
                type(count) is not int or count < 1
                for count in manifest.provider_response_model_counts.values()
            )
            or len(manifest.artifacts) != len(expected_case_ids)
        ):
            raise ValueError

        artifacts: dict[str, _BatchArtifact] = {}
        for artifact in manifest.artifacts:
            if artifact.case_id in artifacts:
                raise ValueError
            artifacts[artifact.case_id] = artifact
        if set(artifacts) != set(expected_case_ids):
            raise ValueError
        state_by_id = {case.case_id: case for case in state.cases}
        for case_id in expected_case_ids:
            case_state = state_by_id[case_id]
            artifact = artifacts[case_id]
            if case_state.terminal_status == "success":
                if (
                    artifact.kind != "enrichment_record"
                    or artifact.relative_path != f"{case_id}.json"
                    or artifact.record_commitment_sha256 is None
                    or artifact.requested_model != state.model
                    or not artifact.provider_response_model
                    or artifact.teacher_response_commitment_sha256 is None
                ):
                    raise ValueError
            elif (
                artifact.kind != "failure_receipt"
                or artifact.relative_path != f"failures/{case_id}.json"
                or artifact.record_commitment_sha256 is not None
                or artifact.requested_model is not None
                or artifact.provider_response_model is not None
                or artifact.teacher_response_commitment_sha256 is not None
            ):
                raise ValueError
        observed_models = Counter(
            artifact.provider_response_model
            for artifact in manifest.artifacts
            if artifact.kind == "enrichment_record"
        )
        if (
            sorted(observed_models) != manifest.provider_response_models
            or dict(sorted(observed_models.items()))
            != manifest.provider_response_model_counts
        ):
            raise ValueError
        return _BatchControlPlane(
            batch_root=batch_root,
            state=state,
            report=report,
            manifest=manifest,
            artifacts=artifacts,
            legacy_v10=legacy_v10,
        )
    except Exception:
        raise ValueError("pragmatic batch provenance is invalid") from None


def _validate_historical_v21(
    root: Path,
    case: Any,
    raw: bytes,
) -> EnrichmentRecord:
    try:
        from egsi.generation.first_case_hard_gate import (
            _validate_frozen_v21_payload,
        )
        from egsi.generation.human_audit import _repair_info_v21

        record = EnrichmentRecord.model_validate_json(raw)
        context = build_oracle_context(root, case)
        vocabulary = allowed_action_values(root)
        repair = _repair_info_v21(
            context, _prompt_vocabulary(vocabulary), record
        )
        if (
            case.case_id != _FIRST_CASE_ID
            or record.case_id != case.case_id
            or record.source_context_sha256 != context.sha256
            or record.generation_mode != "live"
            or repair["request_variant_verified"] is not True
            or record.structured_output_valid is not True
            or record.validation.valid is not True
        ):
            raise ValueError
        store = _load_store(root, case)
        try:
            repeated = _validate_frozen_v21_payload(
                case, record.payload, store, vocabulary
            )
        finally:
            store.close()
        if repeated != record.validation or repeated.valid is not True:
            raise ValueError
        return record
    except Exception:
        raise ValueError("historical v2.1 record is stale") from None


def _validate_case_quarantines(
    control: _BatchControlPlane,
    case_state: PragmaticCaseState,
) -> None:
    for slot in case_state.slots:
        if slot.status != "completed" or slot.outcome == "success":
            continue
        relative = f"enrichment/quarantine/{case_state.case_id}.slot-{slot.slot_index}.json"
        if control.legacy_v10:
            receipt, raw = _load_trusted_legacy_quarantine_v10(
                control.batch_root, relative
            )
        else:
            raw = _read_regular(
                control.batch_root / relative, limit=_MAX_RECORD_BYTES
            )
            receipt = PragmaticQuarantineReceipt.model_validate_json(raw)
        if (
            slot.quarantine_relative_path != relative
            or _sha256(raw) != slot.quarantine_file_sha256
            or receipt.case_id != case_state.case_id
            or receipt.slot_index != slot.slot_index
            or receipt.request_hash != slot.request_hash
            or receipt.outcome != slot.outcome
            or receipt.result_repair_error != slot.result_repair_error
            or receipt.provider_response_cached != slot.provider_response_cached
            or (
                slot.provider_invocation_evidence == "confirmed"
                and receipt.teacher_response_commitment_sha256 is None
            )
        ):
            raise ValueError("pragmatic quarantine binding mismatch")


def _validate_batch_record(
    root: Path,
    case: Any,
    raw: bytes,
    control: _BatchControlPlane,
) -> EnrichmentRecord:
    try:
        case_state = next(
            state_case
            for state_case in control.state.cases
            if state_case.case_id == case.case_id
        )
        artifact = control.artifacts[case.case_id]
        record = EnrichmentRecord.model_validate_json(raw)
        success_slots = [
            slot
            for slot in case_state.slots
            if slot.status == "completed" and slot.outcome == "success"
        ]
        if len(success_slots) != 1:
            raise ValueError
        success_slot = success_slots[0]
        context = build_oracle_context(root, case)
        vocabulary = _prompt_vocabulary(allowed_action_values(root))
        repair_attempt = (
            0 if success_slot.repair_error is None else success_slot.slot_index - 1
        )
        system, user, schema = enrichment_request(
            context,
            vocabulary,
            repair_error=success_slot.repair_error,
            repair_attempt=repair_attempt,
        )
        request = TeacherRequest(
            system=system,
            user=user,
            schema=schema,
            temperature=0.0,
            max_tokens=8192,
        )
        prompt_sha256 = "sha256:" + hashlib.sha256(
            (system + user).encode("utf-8")
        ).hexdigest()
        if (
            control.state.generation_mode != "live"
            or case_state.terminal_status != "success"
            or artifact.kind != "enrichment_record"
            or _sha256(raw) != artifact.file_sha256
            or record.case_id != case.case_id
            or record.generation_mode != "live"
            or record.provider != control.state.provider
            or record.model != control.state.model
            or record.requested_model != control.state.model
            or record.record_commitment_sha256
            != artifact.record_commitment_sha256
            or record.requested_model != artifact.requested_model
            or record.provider_response_model
            != artifact.provider_response_model
            or record.teacher_response_commitment_sha256
            != artifact.teacher_response_commitment_sha256
            or success_slot.request_hash != teacher_request_hash(request)
            or record.prompt_sha256 != prompt_sha256
            or not _record_is_current(
                root,
                case,
                record,
                provider=control.state.provider,
                model=control.state.model,
            )
        ):
            raise ValueError
        _validate_case_quarantines(control, case_state)
        return record
    except Exception:
        raise ValueError("pragmatic batch record provenance is invalid") from None


def _read_failure(path: Path, case_id: str) -> tuple[_FailureReceipt, bytes] | None:
    raw = _read_optional(path, limit=_MAX_RECORD_BYTES)
    if raw is None:
        return None
    try:
        receipt = _FailureReceipt.model_validate_json(raw)
    except Exception:
        raise ValueError("pragmatic failure receipt is invalid") from None
    if receipt.case_id != case_id:
        raise ValueError("pragmatic failure receipt case mismatch")
    return receipt, raw


def _validate_batch_failure(
    control: _BatchControlPlane,
    case_state: PragmaticCaseState,
    *,
    raw: bytes | None = None,
) -> tuple[_FailureReceipt, bytes]:
    try:
        artifact = control.artifacts[case_state.case_id]
        if raw is None:
            failure = _read_failure(
                control.batch_root / "enrichment" / artifact.relative_path,
                case_state.case_id,
            )
            if failure is None:
                raise ValueError
            receipt, failure_raw = failure
        else:
            receipt = _FailureReceipt.model_validate_json(raw)
            if receipt.case_id != case_state.case_id:
                raise ValueError
            failure_raw = raw
        attempts = len(case_state.slots)
        if (
            control.state.generation_mode != "live"
            or case_state.terminal_status != "failed"
            or artifact.kind != "failure_receipt"
            or _sha256(failure_raw) != artifact.file_sha256
            or receipt.attempts != attempts
            or receipt.error != "pragmatic provider slots exhausted"
            or receipt.error_kind != case_state.error_kind
            or receipt.failed_attempt != (attempts or None)
            or receipt.validation_attempt is not None
            or receipt.validation is not None
        ):
            raise ValueError
        _validate_case_quarantines(control, case_state)
        return receipt, failure_raw
    except Exception:
        raise ValueError("pragmatic failure provenance is invalid") from None


def _write_exact(path: Path, raw: bytes) -> None:
    _atomic_bytes(
        path,
        raw,
        lambda observed: (
            None
            if observed == raw
            else (_ for _ in ()).throw(ValueError("exact-byte readback mismatch"))
        ),
    )


def _clear_output(output_root: Path) -> None:
    directories = ("enrichment", "episodes", "trajectories", "reports")
    with AnchoredDirectory(output_root, subdirectories=directories) as artifacts:
        for name in artifacts.list_regular():
            if name != ".egsi-batch.lock":
                artifacts.unlink_regular(Path(name))
        for directory in directories:
            for name in artifacts.list_regular(directory):
                artifacts.unlink_regular(Path(directory) / name)


def _jsonl_read(path: Path, kind: type[EpisodeEvent] | type[T1Transition]) -> list[Any]:
    raw = _read_regular(path, limit=_MAX_REPORT_BYTES)
    lines = raw.splitlines()
    if not lines:
        raise ValueError("empty JSONL artifact")
    return [kind.model_validate_json(line) for line in lines]


def _artifact_kind(relative: str) -> tuple[str, str]:
    path = Path(relative)
    if relative.startswith("enrichment/"):
        return "enrichment_record", path.stem
    if relative.endswith(".events.jsonl"):
        return "episode_events", "__derived__"
    if relative.endswith(".transitions.jsonl"):
        return "episode_transitions", "__derived__"
    if relative == "trajectories/train.parquet":
        return "trajectory_parquet", "__batch__"
    return "report", "__batch__"


def _reject_root_overlap(output_root: Path, *source_roots: Path) -> None:
    """Reject every bidirectional source/output overlap before creating a lock."""

    try:
        resolved_output = Path(output_root).absolute().resolve(strict=False)
        resolved_sources = [
            Path(source).absolute().resolve(strict=False) for source in source_roots
        ]
    except (OSError, ValueError):
        raise ValueError("training-ready root is invalid") from None
    for resolved_source in resolved_sources:
        if (
            resolved_output == resolved_source
            or resolved_output.is_relative_to(resolved_source)
            or resolved_source.is_relative_to(resolved_output)
        ):
            raise ValueError("training-ready output/source root overlap")


def build_training_ready(
    *,
    root: Path,
    case_ids: list[str],
    historical_root: Path,
    batch_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Build the fixed ten-case P0 package without invoking any teacher."""

    root = Path(root)
    ids = _validate_case_ids(case_ids)
    frozen_ids = read_case_ids(root / "configs/p0_cases.txt")
    if ids != frozen_ids or len(ids) != 10 or ids[0] != _FIRST_CASE_ID:
        raise ValueError("training-ready requires the frozen ordered ten-case P0 list")
    historical_root = Path(historical_root)
    batch_root = Path(batch_root)
    output_root = Path(output_root)
    _reject_root_overlap(output_root, historical_root, batch_root)
    if active_batch_lock(output_root) is not None:
        return _build_training_ready_locked(
            root=root,
            ids=ids,
            historical_root=historical_root,
            batch_root=batch_root,
            output_root=output_root,
        )
    with BatchLock(output_root):
        return _build_training_ready_locked(
            root=root,
            ids=ids,
            historical_root=historical_root,
            batch_root=batch_root,
            output_root=output_root,
        )


def _build_training_ready_locked(
    *,
    root: Path,
    ids: list[str],
    historical_root: Path,
    batch_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    _clear_output(output_root)
    catalog = catalog_index(root)
    batch_control = _load_batch_control_plane(root, batch_root, ids[1:])
    batch_state_by_id = (
        {}
        if batch_control is None
        else {case.case_id: case for case in batch_control.state.cases}
    )
    candidates: dict[str, tuple[EnrichmentRecord, bytes, str, Path, str]] = {}
    coverage_by_id: dict[str, CoverageCase] = {}

    for case_id in ids:
        case = catalog[case_id]
        if case_id == _FIRST_CASE_ID:
            source_root = historical_root
            relative = f"enrichment/{case_id}.json"
            raw = _read_optional(source_root / relative, limit=_MAX_RECORD_BYTES)
            if raw is None:
                coverage_by_id[case_id] = CoverageCase(
                    case_id=case_id,
                    status="gap",
                    source_kind="historical_v21",
                    source_root=str(source_root),
                    source_relative_path=relative,
                    source_file_sha256=None,
                    record_commitment_sha256=None,
                    output_relative_path=None,
                    reason="historical_record_missing",
                )
                continue
            try:
                record = _validate_historical_v21(root, case, raw)
            except ValueError:
                coverage_by_id[case_id] = CoverageCase(
                    case_id=case_id,
                    status="gap",
                    source_kind="historical_v21",
                    source_root=str(source_root),
                    source_relative_path=relative,
                    source_file_sha256=_sha256(raw),
                    record_commitment_sha256=None,
                    output_relative_path=None,
                    reason="historical_record_stale",
                )
                continue
            candidates[case_id] = (
                record,
                raw,
                "historical_v21",
                source_root,
                relative,
            )
            continue

        if batch_control is None:
            coverage_by_id[case_id] = CoverageCase(
                case_id=case_id,
                status="gap",
                source_kind="none",
                source_root=None,
                source_relative_path=None,
                source_file_sha256=None,
                record_commitment_sha256=None,
                output_relative_path=None,
                reason="batch_result_missing",
            )
            continue
        source_root = batch_root
        case_state = batch_state_by_id[case_id]
        artifact = batch_control.artifacts[case_id]
        relative = f"enrichment/{artifact.relative_path}"
        if batch_control.state.generation_mode != "live":
            coverage_by_id[case_id] = CoverageCase(
                case_id=case_id,
                status="gap",
                source_kind="pragmatic_batch",
                source_root=str(source_root),
                source_relative_path=relative,
                source_file_sha256=None,
                record_commitment_sha256=None,
                output_relative_path=None,
                reason="non_live_batch_provenance",
            )
            continue
        if case_state.terminal_status == "success":
            raw = _read_optional(source_root / relative, limit=_MAX_RECORD_BYTES)
            if raw is None:
                coverage_by_id[case_id] = CoverageCase(
                    case_id=case_id,
                    status="gap",
                    source_kind="pragmatic_batch",
                    source_root=str(source_root),
                    source_relative_path=relative,
                    source_file_sha256=None,
                    record_commitment_sha256=None,
                    output_relative_path=None,
                    reason="batch_result_missing",
                )
                continue
            try:
                record = _validate_batch_record(
                    root,
                    case,
                    raw,
                    batch_control,
                )
            except ValueError:
                coverage_by_id[case_id] = CoverageCase(
                    case_id=case_id,
                    status="gap",
                    source_kind="pragmatic_batch",
                    source_root=str(source_root),
                    source_relative_path=relative,
                    source_file_sha256=_sha256(raw),
                    record_commitment_sha256=None,
                    output_relative_path=None,
                    reason="batch_record_provenance_invalid",
                )
                continue
            candidates[case_id] = (
                record,
                raw,
                "pragmatic_batch",
                source_root,
                relative,
            )
            continue
        try:
            receipt, failure_raw = _validate_batch_failure(
                batch_control,
                case_state,
            )
        except ValueError:
            raw = _read_optional(source_root / relative, limit=_MAX_RECORD_BYTES)
            coverage_by_id[case_id] = CoverageCase(
                case_id=case_id,
                status="gap",
                source_kind="pragmatic_batch",
                source_root=str(source_root),
                source_relative_path=relative,
                source_file_sha256=None if raw is None else _sha256(raw),
                record_commitment_sha256=None,
                output_relative_path=None,
                reason="batch_failure_provenance_invalid",
            )
            continue
        coverage_by_id[case_id] = CoverageCase(
            case_id=case_id,
            status="failed",
            source_kind="pragmatic_batch",
            source_root=str(source_root),
            source_relative_path=relative,
            source_file_sha256=_sha256(failure_raw),
            record_commitment_sha256=None,
            output_relative_path=None,
            reason=receipt.error_kind,
        )

    transitions_all: list[T1Transition] = []
    event_files: list[str] = []
    transition_files: list[str] = []
    leakage = 0
    nonzero = 0
    illegal = 0
    replay_passed = 0
    for case_id in ids:
        candidate = candidates.get(case_id)
        if candidate is None:
            continue
        record, raw, source_kind, source_root, source_relative = candidate
        case = catalog[case_id]
        event_relative: str | None = None
        transition_relative: str | None = None
        record_relative = f"enrichment/{case_id}.json"
        try:
            if source_kind == "historical_v21":
                transitions, events = compile_t1_episode_frozen_v21(
                    case, record, root=root
                )
            else:
                transitions, events = compile_t1_episode(case, record, root=root)
            commitment = episode_commitment(transitions, events)
            replay = replay_events(
                events,
                transitions,
                expected_commitment_sha256=commitment,
            )
            if replay.get("closed") is not True:
                raise ValueError("episode replay did not close")
            episode_id = transitions[0].episode_id
            event_relative = f"episodes/{episode_id}.events.jsonl"
            transition_relative = f"episodes/{episode_id}.transitions.jsonl"
            write_jsonl(output_root / event_relative, events)
            write_jsonl(output_root / transition_relative, transitions)
            if _jsonl_read(output_root / event_relative, EpisodeEvent) != events:
                raise ValueError("event readback mismatch")
            if _jsonl_read(output_root / transition_relative, T1Transition) != transitions:
                raise ValueError("transition readback mismatch")
            case_leakage, case_nonzero, case_illegal = _episode_metrics(
                case, record, transitions, events
            )
            if case_leakage or case_nonzero or case_illegal:
                raise ValueError("training invariant failed")
            _write_exact(output_root / f"enrichment/{case_id}.json", raw)
        except Exception:
            for published_relative in (
                record_relative,
                event_relative,
                transition_relative,
            ):
                if published_relative is not None:
                    _remove_regular_if_present(output_root / published_relative)
            coverage_by_id[case_id] = CoverageCase(
                case_id=case_id,
                status="gap",
                source_kind=source_kind,
                source_root=str(source_root),
                source_relative_path=source_relative,
                source_file_sha256=_sha256(raw),
                record_commitment_sha256=None,
                output_relative_path=None,
                reason="trajectory_compile_failed",
            )
            continue
        coverage_by_id[case_id] = CoverageCase(
            case_id=case_id,
            status="success",
            source_kind=source_kind,
            source_root=str(source_root),
            source_relative_path=source_relative,
            source_file_sha256=_sha256(raw),
            record_commitment_sha256=record.record_commitment_sha256,
            output_relative_path=record_relative,
            reason=None,
        )
        transitions_all.extend(transitions)
        assert event_relative is not None
        assert transition_relative is not None
        event_files.append(event_relative)
        transition_files.append(transition_relative)
        leakage += case_leakage
        nonzero += case_nonzero
        illegal += case_illegal
        replay_passed += 1

    coverage_cases = [coverage_by_id[case_id] for case_id in ids]
    success_ids = [case.case_id for case in coverage_cases if case.status == "success"]
    failed_ids = [case.case_id for case in coverage_cases if case.status == "failed"]
    gap_ids = [case.case_id for case in coverage_cases if case.status == "gap"]
    coverage = CoverageReport(
        success=len(success_ids),
        failed=len(failed_ids),
        gap=len(gap_ids),
        requested_case_ids=ids,
        success_case_ids=success_ids,
        failed_case_ids=failed_ids,
        gap_case_ids=gap_ids,
        cases=coverage_cases,
    )
    coverage_value = coverage.model_dump(mode="json")
    coverage_path = output_root / "reports/p0-coverage-provenance.json"
    write_report(coverage_path, coverage_value)

    parquet_path = output_root / "trajectories/train.parquet"
    if transitions_all:
        write_parquet(parquet_path, transitions_all)
        if read_parquet(parquet_path) != transitions_all:
            raise RuntimeError("training Parquet readback mismatch")
        parquet_file: str | None = "trajectories/train.parquet"
    else:
        parquet_file = None
    trajectory = TrajectoryReport(
        processed=len(success_ids),
        skipped=10 - len(success_ids),
        processed_case_ids=success_ids,
        skipped_case_ids=[case_id for case_id in ids if case_id not in success_ids],
        transitions=len(transitions_all),
        parquet_file=parquet_file,
        event_files=event_files,
        transition_files=transition_files,
        policy_oracle_leakage=leakage,
        nonzero_t1_rewards=nonzero,
        selected_illegal_actions=illegal,
        event_replay_passed=replay_passed,
        internal_invariant_failure=(
            leakage != 0
            or nonzero != 0
            or illegal != 0
            or replay_passed != len(success_ids)
        ),
    )
    trajectory_value = trajectory.model_dump(mode="json")
    trajectory_path = output_root / "reports/trajectory-validation.json"
    write_report(trajectory_path, trajectory_value)

    audit = HumanAuditPacket(
        training_samples=len(success_ids),
        training_case_ids=success_ids,
        excluded_case_ids=[case_id for case_id in ids if case_id not in success_ids],
        automated_gate_passed=(
            bool(success_ids)
            and trajectory.internal_invariant_failure is False
            and trajectory.processed == len(success_ids)
        ),
        informational_thresholds={
            "semantic_usable_min": 8,
            "max_revision_cases": 2,
        },
        cases=[case.model_dump(mode="json") for case in coverage_cases],
    )
    audit_value = audit.model_dump(mode="json")
    audit_json_path = output_root / "reports/human-audit-packet.json"
    write_report(audit_json_path, audit_value)
    markdown_lines = [
        "# Pragmatic P0 Human Audit Packet",
        "",
        f"Training samples: {len(success_ids)}/10",
        "",
        "| Case | Status | Source | Reason |",
        "|---|---|---|---|",
    ]
    markdown_lines.extend(
        f"| {case.case_id} | {case.status} | {case.source_kind} | {case.reason or '-'} |"
        for case in coverage_cases
    )
    markdown_lines.extend(
        [
            "",
            "The 8-usable / 2-revision values are informational only; failed and gap cases are not training samples.",
            "",
        ]
    )
    audit_md_path = output_root / "reports/human-audit-packet.md"
    _write_exact(audit_md_path, "\n".join(markdown_lines).encode("utf-8"))

    artifact_paths = [
        *(f"enrichment/{case_id}.json" for case_id in success_ids),
        *event_files,
        *transition_files,
        *(["trajectories/train.parquet"] if transitions_all else []),
        "reports/p0-coverage-provenance.json",
        "reports/trajectory-validation.json",
        "reports/human-audit-packet.json",
        "reports/human-audit-packet.md",
    ]
    entries = []
    episode_case = {
        event: case_id for event, case_id in zip(event_files, success_ids, strict=True)
    }
    episode_case.update(
        {
            transition: case_id
            for transition, case_id in zip(transition_files, success_ids, strict=True)
        }
    )
    for relative in sorted(artifact_paths):
        kind, default_case = _artifact_kind(relative)
        entries.append(
            ArtifactEntry(
                relative_path=relative,
                sha256=_sha256(_read_regular(output_root / relative)),
                kind=kind,
                case_id=episode_case.get(relative, default_case),
            )
        )
    manifest_value: dict[str, Any] = {
        "schema_version": "1.0",
        "stage": "training_ready_artifacts",
        "requested_case_ids": ids,
        "processed_case_ids": success_ids,
        "artifacts": [entry.model_dump(mode="json") for entry in entries],
        "artifact_commitment_sha256": "sha256:" + "0" * 64,
    }
    manifest_value["artifact_commitment_sha256"] = _dict_commitment(
        manifest_value, "artifact_commitment_sha256"
    )
    manifest = ArtifactManifest.model_validate(manifest_value)
    manifest_path = output_root / "reports/artifact-manifest.json"
    write_report(manifest_path, manifest.model_dump(mode="json"))
    manifest_sha = _sha256(_read_regular(manifest_path))
    _write_exact(
        output_root / "reports/artifact-manifest.json.sha256",
        (manifest_sha + "\n").encode("ascii"),
    )
    return coverage_value

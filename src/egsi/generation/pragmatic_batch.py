"""Crash-resumable enrichment with an explicit two-provider-slot ceiling."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Literal
import warnings

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from egsi.contracts.enrichment import EnrichmentRecord, committed_enrichment_record
from egsi.data.context import build_oracle_context
from egsi.data.git_objects import GitCacheIntegrityError
from egsi.generation.enrichment import (
    _atomic_json_write,
    _evaluate_enrichment_attempt,
    _latency_integer,
    _prompt_vocabulary,
    _response_metadata_is_bounded,
    _safe_output_root,
    _safe_preparation,
    allowed_action_values,
    write_failure,
)
from egsi.generation.pilot import (
    _cleanup_enrichment_artifacts,
    _eligible_case,
    _read_record,
    _read_regular,
    _record_is_current,
    _remove_regular_if_present,
    _sha256,
    _teacher_generation_mode,
    _validate_case_ids,
    _write_provenance_manifest,
    catalog_index,
    guard_fixture_teacher_output,
    write_report,
)
from egsi.generation.safeio import BatchLock, active_batch_lock
from egsi.teacher.base import Teacher, TeacherRequest, TeacherResponse, teacher_request_hash
from egsi.teacher.prompts import enrichment_request


_MAX_STATE_BYTES = 2 * 1024 * 1024
_MAX_RECORD_BYTES = 2 * 1024 * 1024
_REPAIR_ERRORS = {
    "invalid_structured_output",
    "invalid_canonical_path",
    "semantic_validation_failed",
    "invalid_teacher_response_metadata",
}
_USAGE_KEYS = frozenset(
    {
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "prompt_tokens",
        "completion_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
    }
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_default=True)


class PragmaticBatchConfig(_StrictModel):
    max_provider_attempts: Literal[2] = 2
    retry_transport_once: bool
    global_wall_clock_seconds: int = Field(gt=0)
    slot_timeout_seconds: float = Field(gt=0)
    effective_max_retries: Literal[0] = 0


class PragmaticSlotState(_StrictModel):
    slot_index: Literal[1, 2]
    purpose: Literal[
        "normal",
        "transport_retry",
        "provenance_retry",
        "structured_repair",
        "semantic_repair",
    ]
    status: Literal["reserved", "provider_invoked", "completed"]
    provider_invocation_evidence: Literal["confirmed", "upper_bound"] = (
        "upper_bound"
    )
    provider_response_cached: bool | None = None
    request_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    repair_error: str | None = None
    result_repair_error: str | None = None
    outcome: Literal[
        "success",
        "transport",
        "provenance",
        "teacher_response_metadata",
        "structured_invalid",
        "semantic_invalid",
        "record_too_large",
        "deadline_exceeded",
        "interrupted_unknown",
    ] | None = None
    quarantine_relative_path: str | None = None
    quarantine_file_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )

    @field_validator("repair_error", "result_repair_error")
    @classmethod
    def valid_repair_error(cls, value: str | None) -> str | None:
        if value is not None and value not in _REPAIR_ERRORS:
            raise ValueError("unknown repair error")
        return value

    @model_validator(mode="after")
    def consistent_status(self) -> "PragmaticSlotState":
        if self.status == "completed" and self.outcome is None:
            raise ValueError("completed slot requires an outcome")
        if self.status != "completed" and (
            self.outcome is not None
            or self.result_repair_error is not None
            or self.quarantine_relative_path is not None
            or self.quarantine_file_sha256 is not None
            or self.provider_invocation_evidence != "upper_bound"
            or self.provider_response_cached is not None
        ):
            raise ValueError("incomplete slot cannot have result fields")
        if self.outcome == "success" and (
            self.quarantine_relative_path is not None
            or self.quarantine_file_sha256 is not None
        ):
            raise ValueError("successful slot cannot be quarantined")
        if self.outcome not in {None, "success"} and (
            self.quarantine_relative_path is None
            or self.quarantine_file_sha256 is None
        ):
            raise ValueError("failed slot requires quarantine receipt")
        return self


def pragmatic_quarantine_receipt_commitment(value: dict[str, Any]) -> str:
    canonical = dict(value)
    canonical.pop("receipt_commitment_sha256", None)
    raw = json.dumps(
        canonical,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class PragmaticQuarantineReceipt(_StrictModel):
    schema_version: Literal["1.1"] = "1.1"
    case_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    slot_index: Literal[1, 2]
    request_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    outcome: Literal[
        "transport",
        "provenance",
        "teacher_response_metadata",
        "structured_invalid",
        "semantic_invalid",
        "record_too_large",
        "deadline_exceeded",
        "interrupted_unknown",
    ]
    result_repair_error: str | None
    provider_response_cached: bool | None
    teacher_response_commitment_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    provider_request_id: str | None = Field(default=None, max_length=1024)
    positive_transition_written: Literal[False] = False
    receipt_commitment_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def valid_receipt_commitment(self) -> "PragmaticQuarantineReceipt":
        if self.receipt_commitment_sha256 != (
            pragmatic_quarantine_receipt_commitment(self.model_dump(mode="json"))
        ):
            raise ValueError("quarantine receipt commitment mismatch")
        return self


class PragmaticFailureReceipt(_StrictModel):
    schema_version: Literal["1.0"]
    case_id: str
    attempts: int = Field(ge=0, le=2)
    error: str = Field(max_length=2000)
    error_kind: str = Field(min_length=1, max_length=256)
    failed_attempt: int | None
    validation_attempt: int | None
    validation: dict[str, Any] | None
    positive_transition_written: Literal[False]


class PragmaticCaseState(_StrictModel):
    case_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    terminal_status: Literal["pending", "success", "failed"] = "pending"
    slots: list[PragmaticSlotState] = Field(default_factory=list, max_length=2)
    record_relative_path: str | None = None
    failure_relative_path: str | None = None
    error_kind: str | None = None

    @model_validator(mode="after")
    def consistent_case(self) -> "PragmaticCaseState":
        if [slot.slot_index for slot in self.slots] != list(
            range(1, len(self.slots) + 1)
        ):
            raise ValueError("slot indexes must be contiguous")
        if self.terminal_status == "pending" and any(
            value is not None
            for value in (
                self.record_relative_path,
                self.failure_relative_path,
                self.error_kind,
            )
        ):
            raise ValueError("pending case cannot have terminal fields")
        if self.terminal_status == "success" and (
            self.record_relative_path != f"enrichment/{self.case_id}.json"
            or self.failure_relative_path is not None
            or self.error_kind is not None
        ):
            raise ValueError("successful case fields are inconsistent")
        if self.terminal_status == "failed" and (
            self.failure_relative_path
            != f"enrichment/failures/{self.case_id}.json"
            or self.record_relative_path is not None
            or not self.error_kind
        ):
            raise ValueError("failed case fields are inconsistent")
        return self


class PragmaticBatchState(_StrictModel):
    schema_version: Literal["1.1"] = "1.1"
    stage: Literal["pragmatic_enrichment_state"] = "pragmatic_enrichment_state"
    requested_case_ids: list[str] = Field(min_length=1, max_length=10_000)
    provider: str = Field(min_length=1, max_length=256)
    model: str = Field(min_length=1, max_length=256)
    generation_mode: Literal["fixture", "live"]
    configuration: PragmaticBatchConfig
    started_at_unix_seconds: float = Field(gt=0)
    cases: list[PragmaticCaseState] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def consistent_cases(self) -> "PragmaticBatchState":
        if [case.case_id for case in self.cases] != self.requested_case_ids:
            raise ValueError("case state order mismatch")
        if len(self.requested_case_ids) != len(set(self.requested_case_ids)):
            raise ValueError("duplicate case state")
        return self


class ProviderInvocations(_StrictModel):
    kind: Literal["exact", "upper_bound", "unknown"]
    value: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def consistent_value(self) -> "ProviderInvocations":
        if self.kind == "unknown" and self.value is not None:
            raise ValueError("unknown invocation count cannot have a value")
        if self.kind != "unknown" and self.value is None:
            raise ValueError("known invocation count requires a value")
        return self


class PragmaticBatchReport(_StrictModel):
    schema_version: Literal["1.1"] = "1.1"
    stage: Literal["pragmatic_enrichment"] = "pragmatic_enrichment"
    requested: int = Field(ge=1)
    success: int = Field(ge=0)
    failed: int = Field(ge=0)
    requested_case_ids: list[str]
    success_case_ids: list[str]
    failed_case_ids: list[str]
    failures: dict[str, dict[str, Any]]
    provider: str
    model: str
    generation_mode: Literal["fixture", "live"]
    configuration: PragmaticBatchConfig
    provider_invocations: ProviderInvocations
    total_latency_ms: int = Field(ge=0)
    usage: dict[str, int]
    provenance: dict[str, Any]

    @model_validator(mode="after")
    def conservation(self) -> "PragmaticBatchReport":
        if self.requested != self.success + self.failed:
            raise ValueError("pragmatic batch conservation failed")
        if self.requested != len(self.requested_case_ids):
            raise ValueError("requested case count mismatch")
        if self.success_case_ids != [
            value for value in self.requested_case_ids if value in self.success_case_ids
        ]:
            raise ValueError("success order mismatch")
        if self.failed_case_ids != [
            value for value in self.requested_case_ids if value in self.failed_case_ids
        ]:
            raise ValueError("failure order mismatch")
        if set(self.success_case_ids).intersection(self.failed_case_ids):
            raise ValueError("case cannot be success and failed")
        if len(self.success_case_ids) != self.success or len(self.failed_case_ids) != self.failed:
            raise ValueError("terminal case count mismatch")
        return self


def _configuration(
    *,
    max_provider_attempts: int,
    retry_transport_once: bool,
    global_wall_clock_seconds: int,
    slot_timeout_seconds: float,
    effective_max_retries: int,
) -> PragmaticBatchConfig:
    return PragmaticBatchConfig.model_validate(
        {
            "max_provider_attempts": max_provider_attempts,
            "retry_transport_once": retry_transport_once,
            "global_wall_clock_seconds": global_wall_clock_seconds,
            "slot_timeout_seconds": float(slot_timeout_seconds),
            "effective_max_retries": effective_max_retries,
        }
    )


def _state_path(output_root: Path) -> Path:
    return output_root / "reports/pragmatic-batch-state.json"


def _persist_state(output_root: Path, state: PragmaticBatchState) -> None:
    validated = PragmaticBatchState.model_validate(state.model_dump(mode="json"))
    write_report(_state_path(output_root), validated.model_dump(mode="json"))


def _load_state(path: Path) -> PragmaticBatchState:
    try:
        raw = _read_regular(path, limit=_MAX_STATE_BYTES)
        return PragmaticBatchState.model_validate_json(raw)
    except FileNotFoundError:
        raise
    except Exception:
        raise ValueError("pragmatic batch state is invalid") from None


def _state_matches(
    state: PragmaticBatchState,
    *,
    case_ids: list[str],
    teacher: Teacher,
    generation_mode: str,
    configuration: PragmaticBatchConfig,
) -> bool:
    return (
        state.requested_case_ids == case_ids
        and state.provider == teacher.provider
        and state.model == teacher.model
        and state.generation_mode == generation_mode
        and state.configuration == configuration
    )


def _purpose(previous: PragmaticSlotState | None) -> tuple[str, str | None]:
    if previous is None:
        return "normal", None
    if previous.status != "completed":
        return "transport_retry", None
    if previous.outcome in {"transport", "interrupted_unknown"}:
        return "transport_retry", None
    if previous.outcome in {
        "provenance",
        "teacher_response_metadata",
        "record_too_large",
    }:
        return "provenance_retry", "invalid_teacher_response_metadata"
    if previous.outcome == "structured_invalid":
        return "structured_repair", previous.result_repair_error
    if previous.outcome == "semantic_invalid":
        return "semantic_repair", previous.result_repair_error
    raise RuntimeError("fatal: invalid pragmatic retry transition")


def _read_optional_regular(path: Path) -> bytes | None:
    try:
        return _read_regular(path, limit=_MAX_RECORD_BYTES)
    except FileNotFoundError:
        return None


def _expected_failure_kinds(
    case_state: PragmaticCaseState,
    configuration: PragmaticBatchConfig,
    eligibility_error: str | None,
) -> set[str]:
    """Derive every terminal reason reachable from the persisted slot prefix."""

    if eligibility_error is not None and not case_state.slots:
        return {eligibility_error}
    allowed = {"global_wall_clock_exhausted"}
    if not case_state.slots:
        return allowed
    last = case_state.slots[-1]
    if last.status != "completed":
        if len(case_state.slots) == configuration.max_provider_attempts:
            allowed.add("interrupted_provider_slot")
        if not configuration.retry_transport_once:
            allowed.add("transport")
        return allowed
    if last.outcome == "deadline_exceeded":
        allowed.add("deadline_exceeded")
    if len(case_state.slots) == configuration.max_provider_attempts:
        assert last.outcome is not None
        allowed.add(last.outcome)
    if last.outcome == "transport" and not configuration.retry_transport_once:
        allowed.add("transport")
    if (
        last.outcome == "interrupted_unknown"
        and not configuration.retry_transport_once
    ):
        allowed.add("interrupted_unknown")
    return allowed


def validate_pragmatic_state_semantics(
    root: Path,
    output_root: Path,
    state: PragmaticBatchState,
    *,
    provider: str,
    model: str,
    require_terminal_artifacts: bool = True,
) -> None:
    """Replay state transitions and bind terminal claims to local artifacts."""

    try:
        if state.provider != provider or state.model != model:
            raise ValueError
        catalog = catalog_index(root)
        vocabulary = allowed_action_values(root)
        prompt_vocabulary = _prompt_vocabulary(vocabulary)
        for case_state in state.cases:
            case, eligibility = _eligible_case(catalog, case_state.case_id)
            eligibility_error = None if eligibility is None else eligibility["error"]
            if case is None and case_state.slots:
                raise ValueError
            context = None if case is None else build_oracle_context(root, case)
            prompt_hashes: dict[int, str] = {}
            previous: PragmaticSlotState | None = None
            for index, slot in enumerate(case_state.slots, start=1):
                expected_purpose, expected_repair = _purpose(previous)
                if (
                    slot.slot_index != index
                    or slot.purpose != expected_purpose
                    or slot.repair_error != expected_repair
                    or (
                        index == 2
                        and expected_purpose == "transport_retry"
                        and not state.configuration.retry_transport_once
                    )
                    or context is None
                ):
                    raise ValueError
                repair_attempt = 0 if expected_repair is None else index - 1
                system, user, schema = enrichment_request(
                    context,
                    prompt_vocabulary,
                    repair_error=expected_repair,
                    repair_attempt=repair_attempt,
                )
                request = TeacherRequest(
                    system=system,
                    user=user,
                    schema=schema,
                    temperature=0.0,
                    max_tokens=8192,
                )
                if slot.request_hash != teacher_request_hash(request):
                    raise ValueError
                prompt_hashes[index] = "sha256:" + hashlib.sha256(
                    (system + user).encode("utf-8")
                ).hexdigest()
                expected_results: dict[str, set[str | None]] = {
                    "success": {None},
                    "transport": {None},
                    "provenance": {None},
                    "teacher_response_metadata": {
                        None,
                        "invalid_teacher_response_metadata",
                    },
                    "structured_invalid": {"invalid_structured_output"},
                    "semantic_invalid": {
                        "semantic_validation_failed",
                        "invalid_canonical_path",
                    },
                    "record_too_large": {"invalid_teacher_response_metadata"},
                    "deadline_exceeded": {None},
                    "interrupted_unknown": {None},
                }
                if slot.status == "completed":
                    assert slot.outcome is not None
                    if (
                        slot.result_repair_error not in expected_results[slot.outcome]
                        or (
                            slot.outcome in {"transport", "interrupted_unknown"}
                            and (
                                slot.provider_invocation_evidence != "upper_bound"
                                or slot.provider_response_cached is not None
                            )
                        )
                        or (
                            slot.provider_invocation_evidence == "confirmed"
                            and slot.provider_response_cached is not False
                        )
                        or (
                            slot.provider_response_cached is True
                            and slot.provider_invocation_evidence != "upper_bound"
                        )
                    ):
                        raise ValueError
                    if slot.outcome == "success":
                        if index != len(case_state.slots):
                            raise ValueError
                    else:
                        expected_relative = (
                            f"enrichment/quarantine/{case_state.case_id}.slot-{index}.json"
                        )
                        if slot.quarantine_relative_path != expected_relative:
                            raise ValueError
                        if require_terminal_artifacts:
                            raw = _read_regular(
                                output_root / expected_relative,
                                limit=_MAX_RECORD_BYTES,
                            )
                            receipt = PragmaticQuarantineReceipt.model_validate_json(raw)
                            if (
                                _sha256(raw) != slot.quarantine_file_sha256
                                or receipt.case_id != case_state.case_id
                                or receipt.slot_index != index
                                or receipt.request_hash != slot.request_hash
                                or receipt.outcome != slot.outcome
                                or receipt.result_repair_error
                                != slot.result_repair_error
                                or receipt.provider_response_cached
                                != slot.provider_response_cached
                                or (
                                    slot.provider_invocation_evidence == "confirmed"
                                    and receipt.teacher_response_commitment_sha256
                                    is None
                                )
                            ):
                                raise ValueError
                elif index != len(case_state.slots):
                    raise ValueError
                previous = slot

            success_slots = [
                slot
                for slot in case_state.slots
                if slot.status == "completed" and slot.outcome == "success"
            ]
            record_path = output_root / "enrichment" / f"{case_state.case_id}.json"
            failure_path = (
                output_root / "enrichment/failures" / f"{case_state.case_id}.json"
            )
            if case_state.terminal_status == "success":
                if (
                    len(success_slots) != 1
                    or success_slots[0] is not case_state.slots[-1]
                    or any(slot.status != "completed" for slot in case_state.slots)
                    or eligibility_error is not None
                ):
                    raise ValueError
                if require_terminal_artifacts:
                    assert case is not None
                    record = _read_record(record_path)
                    if (
                        record.generation_mode != state.generation_mode
                        or record.provider != provider
                        or record.model != model
                        or record.requested_model != model
                        or record.prompt_sha256
                        != prompt_hashes[success_slots[0].slot_index]
                        or not _record_is_current(
                            root,
                            case,
                            record,
                            provider=provider,
                            model=model,
                        )
                        or _read_optional_regular(failure_path) is not None
                    ):
                        raise ValueError
            elif case_state.terminal_status == "failed":
                if success_slots or case_state.error_kind not in _expected_failure_kinds(
                    case_state,
                    state.configuration,
                    eligibility_error,
                ):
                    raise ValueError
                if require_terminal_artifacts:
                    raw = _read_regular(failure_path, limit=_MAX_RECORD_BYTES)
                    receipt = PragmaticFailureReceipt.model_validate_json(raw)
                    attempts = len(case_state.slots)
                    if (
                        receipt.case_id != case_state.case_id
                        or receipt.attempts != attempts
                        or receipt.error_kind != case_state.error_kind
                        or receipt.failed_attempt != (attempts or None)
                        or receipt.validation is not None
                        or receipt.validation_attempt is not None
                        or _read_optional_regular(record_path) is not None
                    ):
                        raise ValueError
            elif success_slots:
                raise ValueError
    except Exception:
        raise ValueError("pragmatic batch state semantics are invalid") from None


def _quarantine_slot(
    output_root: Path,
    case_id: str,
    slot_index: int,
    *,
    request_hash: str,
    outcome: str,
    response: TeacherResponse | None = None,
    result_repair_error: str | None = None,
) -> str:
    relative = f"enrichment/quarantine/{case_id}.slot-{slot_index}.json"
    receipt_value: dict[str, Any] = {
        "schema_version": "1.1",
        "case_id": case_id,
        "slot_index": slot_index,
        "request_hash": request_hash,
        "outcome": outcome,
        "result_repair_error": result_repair_error,
        "provider_response_cached": None if response is None else response.cached,
        "teacher_response_commitment_sha256": (
            None if response is None else response.response_commitment_sha256
        ),
        "provider_request_id": (
            None if response is None else response.provider_request_id
        ),
        "positive_transition_written": False,
    }
    receipt_value["receipt_commitment_sha256"] = (
        pragmatic_quarantine_receipt_commitment(receipt_value)
    )
    value = PragmaticQuarantineReceipt.model_validate(receipt_value)
    _atomic_json_write(output_root / relative, value.model_dump(mode="json"))
    return relative


def _complete_slot(
    output_root: Path,
    slot: PragmaticSlotState,
    *,
    outcome: str,
    quarantine_relative_path: str | None,
    result_repair_error: str | None = None,
    provider_invocation_evidence: str = "upper_bound",
    provider_response_cached: bool | None = None,
) -> PragmaticSlotState:
    quarantine_file_sha256 = None
    if quarantine_relative_path is not None:
        quarantine_file_sha256 = _sha256(
            _read_regular(
                output_root / quarantine_relative_path,
                limit=_MAX_RECORD_BYTES,
            )
        )
    return PragmaticSlotState.model_validate(
        {
            **slot.model_dump(mode="json"),
            "status": "completed",
            "outcome": outcome,
            "quarantine_relative_path": quarantine_relative_path,
            "quarantine_file_sha256": quarantine_file_sha256,
            "result_repair_error": result_repair_error,
            "provider_invocation_evidence": provider_invocation_evidence,
            "provider_response_cached": provider_response_cached,
        }
    )


def _terminal_failure(
    output_root: Path,
    state: PragmaticBatchState,
    case_state: PragmaticCaseState,
    *,
    error_kind: str,
) -> None:
    attempts = len(case_state.slots)
    validation = None
    write_failure(
        output_root / "enrichment",
        case_state.case_id,
        attempts,
        "pragmatic provider slots exhausted",
        validation,
        error_kind=error_kind,
        failed_attempt=attempts or None,
        validation_attempt=None,
    )
    case_state.terminal_status = "failed"
    case_state.failure_relative_path = (
        f"enrichment/failures/{case_state.case_id}.json"
    )
    case_state.error_kind = error_kind
    _persist_state(output_root, state)


def _current_record(
    root: Path,
    output_root: Path,
    case: Any,
    teacher: Teacher,
) -> EnrichmentRecord | None:
    try:
        record = _read_record(output_root / "enrichment" / f"{case.case_id}.json")
    except FileNotFoundError:
        return None
    except Exception:
        raise RuntimeError("fatal: existing pragmatic record is invalid") from None
    if not _record_is_current(
        root,
        case,
        record,
        provider=teacher.provider,
        model=teacher.model,
    ):
        raise RuntimeError("fatal: existing pragmatic record is stale")
    return record


def _slot_prompt_sha256(root: Path, case: Any, slot: PragmaticSlotState) -> str:
    context = build_oracle_context(root, case)
    prompt_vocabulary = _prompt_vocabulary(allowed_action_values(root))
    repair_attempt = 0 if slot.repair_error is None else slot.slot_index - 1
    system, user, schema = enrichment_request(
        context,
        prompt_vocabulary,
        repair_error=slot.repair_error,
        repair_attempt=repair_attempt,
    )
    request = TeacherRequest(
        system=system,
        user=user,
        schema=schema,
        temperature=0.0,
        max_tokens=8192,
    )
    if teacher_request_hash(request) != slot.request_hash:
        raise RuntimeError("fatal: post-record request binding mismatch")
    return "sha256:" + hashlib.sha256((system + user).encode("utf-8")).hexdigest()


def _recover_post_record_success(
    root: Path,
    output_root: Path,
    state: PragmaticBatchState,
    case_state: PragmaticCaseState,
    case: Any,
    teacher: Teacher,
) -> bool:
    record = _current_record(root, output_root, case, teacher)
    if record is None:
        return False
    if (
        not case_state.slots
        or case_state.slots[-1].status != "provider_invoked"
        or record.prompt_sha256
        != _slot_prompt_sha256(root, case, case_state.slots[-1])
    ):
        raise RuntimeError("fatal: post-record slot binding mismatch")
    case_state.slots[-1] = _complete_slot(
        output_root,
        case_state.slots[-1],
        outcome="success",
        quarantine_relative_path=None,
        provider_invocation_evidence="upper_bound",
        provider_response_cached=None,
    )
    case_state.terminal_status = "success"
    case_state.record_relative_path = f"enrichment/{case_state.case_id}.json"
    _remove_regular_if_present(
        output_root / "enrichment/failures" / f"{case_state.case_id}.json"
    )
    _persist_state(output_root, state)
    return True


def _finalize_interrupted_slot(
    output_root: Path,
    state: PragmaticBatchState,
    case_state: PragmaticCaseState,
) -> None:
    slot = case_state.slots[-1]
    if slot.status == "completed":
        return
    quarantine = _quarantine_slot(
        output_root,
        case_state.case_id,
        slot.slot_index,
        request_hash=slot.request_hash,
        outcome="interrupted_unknown",
    )
    case_state.slots[-1] = _complete_slot(
        output_root,
        slot,
        outcome="interrupted_unknown",
        quarantine_relative_path=quarantine,
        provider_invocation_evidence="upper_bound",
        provider_response_cached=None,
    )
    _persist_state(output_root, state)


def _response_or_outcome(
    teacher: Teacher,
    request: TeacherRequest,
) -> tuple[TeacherResponse | None, str | None]:
    try:
        response = teacher.generate(request)
    except Exception:
        return None, "transport"
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            dumped = response.model_dump(mode="json")
            if type(dumped) is not dict:
                raise TypeError
            canonical = json.loads(
                json.dumps(
                    dumped,
                    allow_nan=False,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            response = TeacherResponse.model_validate(canonical)
    except Exception:
        return None, "provenance"
    if (
        response.provider != teacher.provider
        or response.model != teacher.model
        or response.requested_model != teacher.model
    ):
        return response, "provenance"
    if not _response_metadata_is_bounded(response):
        return response, "teacher_response_metadata"
    return response, None


def run_pragmatic_batch(
    root: Path,
    case_ids: list[str],
    output_root: Path,
    teacher: Teacher,
    *,
    max_provider_attempts: int = 2,
    retry_transport_once: bool = True,
    resume: bool = False,
    global_wall_clock_seconds: int = 14_400,
    slot_timeout_seconds: float = 600.0,
    effective_max_retries: int = 0,
) -> dict[str, Any]:
    """Run the pragmatic batch under the normal shared output lock."""

    ids = _validate_case_ids(case_ids)
    if type(resume) is not bool:
        raise ValueError("resume must be boolean")
    configuration = _configuration(
        max_provider_attempts=max_provider_attempts,
        retry_transport_once=retry_transport_once,
        global_wall_clock_seconds=global_wall_clock_seconds,
        slot_timeout_seconds=slot_timeout_seconds,
        effective_max_retries=effective_max_retries,
    )
    root = Path(root)
    output_root = Path(output_root)
    guard_fixture_teacher_output(root, output_root, teacher)
    if active_batch_lock(output_root) is not None:
        return _run_pragmatic_batch_locked(
            root,
            ids,
            output_root,
            teacher,
            configuration=configuration,
            resume=resume,
        )
    with BatchLock(output_root):
        return _run_pragmatic_batch_locked(
            root,
            ids,
            output_root,
            teacher,
            configuration=configuration,
            resume=resume,
        )


def _run_pragmatic_batch_locked(
    root: Path,
    ids: list[str],
    output_root: Path,
    teacher: Teacher,
    *,
    configuration: PragmaticBatchConfig,
    resume: bool,
) -> dict[str, Any]:
    generation_mode = _teacher_generation_mode(teacher)
    output_dir = _safe_output_root(output_root / "enrichment")
    path = _state_path(output_root)
    try:
        existing_state = _load_state(path)
    except FileNotFoundError:
        existing_state = None
    if existing_state is not None and not resume:
        raise ValueError("pragmatic batch state already exists; use resume")
    if existing_state is None and resume:
        raise ValueError("pragmatic batch state is missing")
    if existing_state is None:
        state = PragmaticBatchState(
            requested_case_ids=ids,
            provider=teacher.provider,
            model=teacher.model,
            generation_mode=generation_mode,
            configuration=configuration,
            started_at_unix_seconds=time.time(),
            cases=[PragmaticCaseState(case_id=case_id) for case_id in ids],
        )
        _persist_state(output_root, state)
    else:
        state = existing_state
        if not _state_matches(
            state,
            case_ids=ids,
            teacher=teacher,
            generation_mode=generation_mode,
            configuration=configuration,
        ):
            raise ValueError("pragmatic batch state configuration mismatch")
        validate_pragmatic_state_semantics(
            root,
            output_root,
            state,
            provider=teacher.provider,
            model=teacher.model,
            require_terminal_artifacts=True,
        )

    catalog = catalog_index(root)
    deadline = (
        state.started_at_unix_seconds
        + state.configuration.global_wall_clock_seconds
    )
    for case_state in state.cases:
        if case_state.terminal_status != "pending":
            continue
        case, eligibility = _eligible_case(catalog, case_state.case_id)
        if eligibility is not None:
            _terminal_failure(
                output_root,
                state,
                case_state,
                error_kind=eligibility["error"],
            )
            continue
        assert case is not None

        if resume:
            if _recover_post_record_success(
                root,
                output_root,
                state,
                case_state,
                case,
                teacher,
            ):
                continue
            if case_state.slots and case_state.slots[-1].status != "completed":
                _finalize_interrupted_slot(output_root, state, case_state)

        if len(case_state.slots) >= configuration.max_provider_attempts:
            previous = case_state.slots[-1]
            _terminal_failure(
                output_root,
                state,
                case_state,
                error_kind=(
                    "interrupted_provider_slot"
                    if previous.status != "completed"
                    else str(previous.outcome)
                ),
            )
            continue
        if deadline - time.time() < configuration.slot_timeout_seconds:
            _terminal_failure(
                output_root,
                state,
                case_state,
                error_kind="global_wall_clock_exhausted",
            )
            continue

        try:
            context, store, vocabulary = _safe_preparation(root, case)
        except ValueError:
            raise RuntimeError("fatal: enrichment preparation failed") from None
        try:
            prompt_vocabulary = _prompt_vocabulary(vocabulary)
            while case_state.terminal_status == "pending":
                if len(case_state.slots) >= configuration.max_provider_attempts:
                    previous = case_state.slots[-1]
                    _terminal_failure(
                        output_root,
                        state,
                        case_state,
                        error_kind=(
                            "interrupted_provider_slot"
                            if previous.status != "completed"
                            else str(previous.outcome)
                        ),
                    )
                    break
                if deadline - time.time() < configuration.slot_timeout_seconds:
                    _terminal_failure(
                        output_root,
                        state,
                        case_state,
                        error_kind="global_wall_clock_exhausted",
                    )
                    break
                previous = case_state.slots[-1] if case_state.slots else None
                purpose, repair_error = _purpose(previous)
                if (
                    previous is not None
                    and (
                        previous.status != "completed"
                        or previous.outcome
                        in {"transport", "interrupted_unknown"}
                    )
                    and not configuration.retry_transport_once
                ):
                    _terminal_failure(
                        output_root,
                        state,
                        case_state,
                        error_kind=(
                            "interrupted_unknown"
                            if previous.outcome == "interrupted_unknown"
                            else "transport"
                        ),
                    )
                    break
                # A transport/interruption retry repeats the original canonical
                # request.  Prompt repair attempts require a concrete safe repair
                # category, which transport failures deliberately do not invent.
                repair_attempt = 0 if repair_error is None else len(case_state.slots)
                system, user, schema = enrichment_request(
                    context,
                    prompt_vocabulary,
                    repair_error=repair_error,
                    repair_attempt=repair_attempt,
                )
                request = TeacherRequest(
                    system=system,
                    user=user,
                    schema=schema,
                    temperature=0.0,
                    max_tokens=8192,
                )
                slot = PragmaticSlotState(
                    slot_index=len(case_state.slots) + 1,
                    purpose=purpose,
                    status="reserved",
                    request_hash=teacher_request_hash(request),
                    repair_error=repair_error,
                )
                case_state.slots.append(slot)
                _persist_state(output_root, state)
                slot.status = "provider_invoked"
                _persist_state(output_root, state)

                response, provider_failure = _response_or_outcome(teacher, request)
                if time.time() >= deadline:
                    quarantine = _quarantine_slot(
                        output_root,
                        case_state.case_id,
                        slot.slot_index,
                        request_hash=slot.request_hash,
                        outcome="deadline_exceeded",
                        response=response,
                    )
                    case_state.slots[-1] = _complete_slot(
                        output_root,
                        slot,
                        outcome="deadline_exceeded",
                        quarantine_relative_path=quarantine,
                        provider_invocation_evidence=(
                            "upper_bound"
                            if response is None or response.cached
                            else "confirmed"
                        ),
                        provider_response_cached=(
                            None if response is None else response.cached
                        ),
                    )
                    _persist_state(output_root, state)
                    _terminal_failure(
                        output_root,
                        state,
                        case_state,
                        error_kind="deadline_exceeded",
                    )
                    break
                if provider_failure is not None:
                    quarantine = _quarantine_slot(
                        output_root,
                        case_state.case_id,
                        slot.slot_index,
                        request_hash=slot.request_hash,
                        outcome=provider_failure,
                        response=response,
                    )
                    completed = _complete_slot(
                        output_root,
                        slot,
                        outcome=provider_failure,
                        quarantine_relative_path=quarantine,
                        provider_invocation_evidence=(
                            "upper_bound"
                            if response is None or response.cached
                            else "confirmed"
                        ),
                        provider_response_cached=(
                            None if response is None else response.cached
                        ),
                    )
                    case_state.slots[-1] = completed
                    _persist_state(output_root, state)
                    continue
                assert response is not None
                try:
                    evaluation = _evaluate_enrichment_attempt(
                        text=response.text,
                        schema=schema,
                        case=case,
                        store=store,
                        vocabulary=vocabulary,
                    )
                except GitCacheIntegrityError:
                    raise RuntimeError(
                        "fatal: local Git cache integrity failure"
                    ) from None
                if time.time() >= deadline:
                    quarantine = _quarantine_slot(
                        output_root,
                        case_state.case_id,
                        slot.slot_index,
                        request_hash=slot.request_hash,
                        outcome="deadline_exceeded",
                        response=response,
                    )
                    case_state.slots[-1] = _complete_slot(
                        output_root,
                        slot,
                        outcome="deadline_exceeded",
                        quarantine_relative_path=quarantine,
                        provider_invocation_evidence=(
                            "upper_bound" if response.cached else "confirmed"
                        ),
                        provider_response_cached=response.cached,
                    )
                    _persist_state(output_root, state)
                    _terminal_failure(
                        output_root,
                        state,
                        case_state,
                        error_kind="deadline_exceeded",
                    )
                    break
                if evaluation.structured_output_valid is not True:
                    outcome = "structured_invalid"
                elif evaluation.validation is None or evaluation.payload is None:
                    raise RuntimeError("fatal: attempt evaluation invariant failed")
                elif not evaluation.validation.valid:
                    outcome = "semantic_invalid"
                else:
                    outcome = "success"
                if outcome != "success":
                    quarantine = _quarantine_slot(
                        output_root,
                        case_state.case_id,
                        slot.slot_index,
                        request_hash=slot.request_hash,
                        outcome=outcome,
                        response=response,
                        result_repair_error=evaluation.repair_error,
                    )
                    case_state.slots[-1] = _complete_slot(
                        output_root,
                        slot,
                        outcome=outcome,
                        quarantine_relative_path=quarantine,
                        result_repair_error=evaluation.repair_error,
                        provider_invocation_evidence=(
                            "upper_bound" if response.cached else "confirmed"
                        ),
                        provider_response_cached=response.cached,
                    )
                    _persist_state(output_root, state)
                    continue

                assert evaluation.payload is not None
                assert evaluation.validation is not None
                prompt_sha = "sha256:" + hashlib.sha256(
                    (system + user).encode("utf-8")
                ).hexdigest()
                try:
                    record = committed_enrichment_record(
                        case_id=case_state.case_id,
                        generation_mode=generation_mode,
                        provider=response.provider,
                        model=response.model,
                        requested_model=response.requested_model,
                        provider_response_model=response.provider_response_model,
                        teacher_response_commitment_sha256=response.response_commitment_sha256,
                        provider_request_id=response.provider_request_id,
                        prompt_sha256=prompt_sha,
                        source_context_sha256=context.sha256,
                        temperature=0.0,
                        max_tokens=8192,
                        latency_ms=_latency_integer(response.latency_ms),
                        usage=response.usage,
                        structured_output_valid=True,
                        payload=evaluation.payload,
                        validation=evaluation.validation,
                    )
                except ValidationError:
                    quarantine = _quarantine_slot(
                        output_root,
                        case_state.case_id,
                        slot.slot_index,
                        request_hash=slot.request_hash,
                        outcome="teacher_response_metadata",
                        response=response,
                        result_repair_error="invalid_teacher_response_metadata",
                        provider_invocation_evidence=(
                            "upper_bound" if response.cached else "confirmed"
                        ),
                        provider_response_cached=response.cached,
                    )
                    case_state.slots[-1] = _complete_slot(
                        output_root,
                        slot,
                        outcome="teacher_response_metadata",
                        quarantine_relative_path=quarantine,
                        result_repair_error="invalid_teacher_response_metadata",
                        provider_invocation_evidence=(
                            "upper_bound" if response.cached else "confirmed"
                        ),
                        provider_response_cached=response.cached,
                    )
                    _persist_state(output_root, state)
                    continue
                if len(record.model_dump_json().encode("utf-8")) > _MAX_RECORD_BYTES:
                    quarantine = _quarantine_slot(
                        output_root,
                        case_state.case_id,
                        slot.slot_index,
                        request_hash=slot.request_hash,
                        outcome="record_too_large",
                        response=response,
                        result_repair_error="invalid_teacher_response_metadata",
                    )
                    case_state.slots[-1] = _complete_slot(
                        output_root,
                        slot,
                        outcome="record_too_large",
                        quarantine_relative_path=quarantine,
                        result_repair_error="invalid_teacher_response_metadata",
                    )
                    _persist_state(output_root, state)
                    continue
                target = output_dir / f"{case_state.case_id}.json"
                record_value = record.model_dump(mode="json")
                if time.time() >= deadline:
                    quarantine = _quarantine_slot(
                        output_root,
                        case_state.case_id,
                        slot.slot_index,
                        request_hash=slot.request_hash,
                        outcome="deadline_exceeded",
                        response=response,
                    )
                    case_state.slots[-1] = _complete_slot(
                        output_root,
                        slot,
                        outcome="deadline_exceeded",
                        quarantine_relative_path=quarantine,
                        provider_invocation_evidence=(
                            "upper_bound" if response.cached else "confirmed"
                        ),
                        provider_response_cached=response.cached,
                    )
                    _persist_state(output_root, state)
                    _terminal_failure(
                        output_root,
                        state,
                        case_state,
                        error_kind="deadline_exceeded",
                    )
                    break
                _atomic_json_write(target, record_value)
                if time.time() >= deadline:
                    _remove_regular_if_present(target)
                    quarantine = _quarantine_slot(
                        output_root,
                        case_state.case_id,
                        slot.slot_index,
                        request_hash=slot.request_hash,
                        outcome="deadline_exceeded",
                        response=response,
                    )
                    case_state.slots[-1] = _complete_slot(
                        output_root,
                        slot,
                        outcome="deadline_exceeded",
                        quarantine_relative_path=quarantine,
                        provider_invocation_evidence=(
                            "upper_bound" if response.cached else "confirmed"
                        ),
                        provider_response_cached=response.cached,
                    )
                    _persist_state(output_root, state)
                    _terminal_failure(
                        output_root,
                        state,
                        case_state,
                        error_kind="deadline_exceeded",
                    )
                    break
                committed = _read_record(target)
                if committed != record or not _record_is_current(
                    root,
                    case,
                    committed,
                    provider=teacher.provider,
                    model=teacher.model,
                ):
                    raise RuntimeError("fatal: pragmatic positive readback failed")
                if time.time() >= deadline:
                    _remove_regular_if_present(target)
                    quarantine = _quarantine_slot(
                        output_root,
                        case_state.case_id,
                        slot.slot_index,
                        request_hash=slot.request_hash,
                        outcome="deadline_exceeded",
                        response=response,
                    )
                    case_state.slots[-1] = _complete_slot(
                        output_root,
                        slot,
                        outcome="deadline_exceeded",
                        quarantine_relative_path=quarantine,
                        provider_invocation_evidence=(
                            "upper_bound" if response.cached else "confirmed"
                        ),
                        provider_response_cached=response.cached,
                    )
                    _persist_state(output_root, state)
                    _terminal_failure(
                        output_root,
                        state,
                        case_state,
                        error_kind="deadline_exceeded",
                    )
                    break
                case_state.slots[-1] = _complete_slot(
                    output_root,
                    slot,
                    outcome="success",
                    quarantine_relative_path=None,
                    provider_invocation_evidence=(
                        "upper_bound" if response.cached else "confirmed"
                    ),
                    provider_response_cached=response.cached,
                )
                case_state.terminal_status = "success"
                case_state.record_relative_path = (
                    f"enrichment/{case_state.case_id}.json"
                )
                _remove_regular_if_present(
                    output_dir / "failures" / f"{case_state.case_id}.json"
                )
                _persist_state(output_root, state)
        finally:
            store.close()

    successes = [
        case.case_id for case in state.cases if case.terminal_status == "success"
    ]
    failures = [
        case.case_id for case in state.cases if case.terminal_status == "failed"
    ]
    if len(successes) + len(failures) != len(ids):
        raise RuntimeError("pragmatic batch conservation invariant failed")
    records = [
        _read_record(output_dir / f"{case_id}.json") for case_id in successes
    ]
    retained_failures = _cleanup_enrichment_artifacts(output_dir, records, failures)
    state_sha256 = _sha256(
        _read_regular(_state_path(output_root), limit=_MAX_STATE_BYTES)
    )
    provenance = _write_provenance_manifest(
        output_dir,
        ids,
        records,
        retained_failures,
        generation_mode=generation_mode,
        provider=teacher.provider,
        model=teacher.model,
        pragmatic_state_sha256=state_sha256,
    )
    uncertain = any(
        slot.status != "completed"
        or slot.provider_invocation_evidence != "confirmed"
        for case in state.cases
        for slot in case.slots
    )
    invocation_count = sum(len(case.slots) for case in state.cases)
    invocations = ProviderInvocations(
        kind="upper_bound" if uncertain else "exact",
        value=invocation_count,
    )
    usage: Counter[str] = Counter()
    for record in records:
        usage.update(
            {key: value for key, value in record.usage.items() if key in _USAGE_KEYS}
        )
    report = PragmaticBatchReport(
        requested=len(ids),
        success=len(successes),
        failed=len(failures),
        requested_case_ids=ids,
        success_case_ids=successes,
        failed_case_ids=failures,
        failures={
            case.case_id: {
                "stage": "pragmatic_enrichment",
                "error": case.error_kind,
                "slots_consumed": len(case.slots),
            }
            for case in state.cases
            if case.terminal_status == "failed"
        },
        provider=teacher.provider,
        model=teacher.model,
        generation_mode=generation_mode,
        configuration=configuration,
        provider_invocations=invocations,
        total_latency_ms=sum(record.latency_ms for record in records),
        usage=dict(sorted(usage.items())),
        provenance=provenance,
    )
    value = report.model_dump(mode="json")
    write_report(output_root / "reports/pragmatic-batch-report.json", value)
    return value

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from egsi.generation.enrichment import write_failure
from egsi.teacher import TeacherRequest, TeacherResponse, committed_teacher_response
from egsi.teacher.fixture import FixtureTeacher


ROOT = Path(__file__).resolve().parents[2]
FIRST = "ghsa-2m8h-fgr8-2q9w"
SECOND = "ghsa-3wfj-vh84-732p"


class ScriptedFixtureTeacher:
    provider = FixtureTeacher.provider
    model = FixtureTeacher.model

    def __init__(self, script: list[str]) -> None:
        self.script = iter(script)
        self.fixture = FixtureTeacher()
        self.calls = 0
        self.requests: list[TeacherRequest] = []

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        self.calls += 1
        self.requests.append(request)
        action = next(self.script)
        if action == "transport":
            raise RuntimeError("synthetic transport failure")
        if action == "crash":
            raise KeyboardInterrupt
        if action == "structured_invalid":
            return committed_teacher_response(
                provider_request_id=f"scripted-{self.calls}",
                provider=self.provider,
                model=self.model,
                requested_model=self.model,
                provider_response_model=self.model,
                text="{}",
                usage={"output_tokens": 1},
                latency_ms=1.0,
            )
        if action == "semantic_invalid":
            valid = self.fixture.generate(request)
            payload = json.loads(valid.text)
            payload["family"] = "authorization"
            payload["authorization"] = {
                "attacker_principal": "requester",
                "victim_principal": "owner",
                "action": "read",
                "resource": "resource",
                "expected_relation": "owner match",
                "actual_check": "unknown",
                "observable_impact": "unknown",
            }
            return committed_teacher_response(
                provider_request_id=f"scripted-{self.calls}",
                provider=self.provider,
                model=self.model,
                requested_model=self.model,
                provider_response_model=self.model,
                text=json.dumps(payload, sort_keys=True),
                usage={"output_tokens": 1},
                latency_ms=1.0,
            )
        if action == "canonical_path_invalid":
            valid = self.fixture.generate(request)
            payload = json.loads(valid.text)
            payload["locations"][0]["path"] = "undeclared/not-canonical.java"
            return committed_teacher_response(
                provider_request_id=f"scripted-{self.calls}",
                provider=self.provider,
                model=self.model,
                requested_model=self.model,
                provider_response_model=self.model,
                text=json.dumps(payload, sort_keys=True),
                usage={"output_tokens": 1},
                latency_ms=1.0,
            )
        if action != "valid":
            if action == "cached_valid":
                return self.fixture.generate(request).model_copy(
                    update={"cached": True}
                )
            raise AssertionError(f"unknown scripted action: {action}")
        return self.fixture.generate(request)


def _resume_with_forbidden_teacher(output: Path) -> ScriptedFixtureTeacher:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    teacher = ScriptedFixtureTeacher([])
    with pytest.raises(ValueError, match="pragmatic batch state semantics"):
        run_pragmatic_batch(
            ROOT,
            [FIRST],
            output,
            teacher,
            max_provider_attempts=2,
            retry_transport_once=True,
            resume=True,
            global_wall_clock_seconds=14_400,
            slot_timeout_seconds=600.0,
            effective_max_retries=0,
        )
    assert teacher.calls == 0
    return teacher


@pytest.mark.parametrize(
    "tamper",
    ["empty_slots", "slot_one_purpose", "request_hash", "repair_category"],
)
def test_resume_replays_and_rejects_tampered_success_state_before_teacher_call(
    tmp_path: Path,
    tamper: str,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    output = tmp_path / tamper
    script = ["structured_invalid", "valid"] if tamper == "repair_category" else ["valid"]
    run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        ScriptedFixtureTeacher(script),
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    state_path = output / "reports/pragmatic-batch-state.json"
    state = json.loads(state_path.read_text())
    if tamper == "empty_slots":
        state["cases"][0]["slots"] = []
    elif tamper == "slot_one_purpose":
        state["cases"][0]["slots"][0]["purpose"] = "transport_retry"
    elif tamper == "request_hash":
        state["cases"][0]["slots"][0]["request_hash"] = "sha256:" + "0" * 64
    else:
        assert state["cases"][0]["slots"][0]["outcome"] == "structured_invalid"
        state["cases"][0]["slots"][0][
            "result_repair_error"
        ] = "semantic_validation_failed"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    _resume_with_forbidden_teacher(output)


def test_resume_rejects_unexpected_failure_receipt_for_terminal_success(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    output = tmp_path / "unexpected-failure"
    run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        ScriptedFixtureTeacher(["valid"]),
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    write_failure(
        output / "enrichment",
        FIRST,
        1,
        "unexpected",
        None,
        error_kind="transport",
        failed_attempt=1,
    )

    _resume_with_forbidden_teacher(output)


def test_resume_rejects_terminal_failure_receipt_and_quarantine_mismatch(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    output = tmp_path / "failed-mismatch"
    run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        ScriptedFixtureTeacher(["transport", "transport"]),
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    quarantine_path = output / "enrichment/quarantine" / f"{FIRST}.slot-2.json"
    quarantine = json.loads(quarantine_path.read_text())
    quarantine["outcome"] = "provenance"
    quarantine_path.write_text(json.dumps(quarantine), encoding="utf-8")

    _resume_with_forbidden_teacher(output)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("teacher_response_commitment_sha256", "sha256:" + "0" * 64),
        ("provider_request_id", "forged-provider-request-id"),
    ],
)
def test_resume_rejects_quarantine_provenance_field_tamper(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    from egsi.generation.pragmatic_batch import (
        pragmatic_quarantine_receipt_commitment,
        run_pragmatic_batch,
    )

    output = tmp_path / field
    run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        ScriptedFixtureTeacher(["structured_invalid", "valid"]),
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    quarantine_path = output / "enrichment/quarantine" / f"{FIRST}.slot-1.json"
    quarantine = json.loads(quarantine_path.read_text(encoding="utf-8"))
    assert quarantine[field] != replacement
    quarantine[field] = replacement
    quarantine["receipt_commitment_sha256"] = (
        pragmatic_quarantine_receipt_commitment(quarantine)
    )
    quarantine_path.write_text(json.dumps(quarantine), encoding="utf-8")

    _resume_with_forbidden_teacher(output)


def test_slot_is_not_started_when_remaining_wall_clock_is_below_slot_timeout(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    teacher = ScriptedFixtureTeacher([])
    output = tmp_path / "deadline-before-slot"
    report = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        teacher,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=599,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert teacher.calls == 0
    assert report["failed_case_ids"] == [FIRST]
    failure = json.loads(
        (output / "enrichment/failures" / f"{FIRST}.json").read_text()
    )
    assert failure["attempts"] == 0
    assert failure["error_kind"] == "global_wall_clock_exhausted"


def test_response_returning_after_global_deadline_is_quarantined_not_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.pragmatic_batch as pragmatic_batch

    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(
        pragmatic_batch,
        "time",
        SimpleNamespace(time=lambda: clock.now),
    )
    teacher = ScriptedFixtureTeacher(["valid"])
    generate = teacher.generate

    def delayed_generate(request: TeacherRequest) -> TeacherResponse:
        response = generate(request)
        clock.now = 1701.0
        return response

    teacher.generate = delayed_generate  # type: ignore[method-assign]
    output = tmp_path / "deadline-after-response"
    report = pragmatic_batch.run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        teacher,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=700,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert teacher.calls == 1
    assert report["failed_case_ids"] == [FIRST]
    assert not (output / "enrichment" / f"{FIRST}.json").exists()
    quarantine = json.loads(
        (output / "enrichment/quarantine" / f"{FIRST}.slot-1.json").read_text()
    )
    assert quarantine["outcome"] == "deadline_exceeded"
    failure = json.loads(
        (output / "enrichment/failures" / f"{FIRST}.json").read_text()
    )
    assert failure["error_kind"] == "deadline_exceeded"


def test_evaluator_crossing_global_deadline_cannot_publish_positive_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.pragmatic_batch as pragmatic_batch

    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(
        pragmatic_batch,
        "time",
        SimpleNamespace(time=lambda: clock.now),
    )
    evaluate = pragmatic_batch._evaluate_enrichment_attempt

    def delayed_evaluate(**kwargs: object) -> object:
        result = evaluate(**kwargs)
        clock.now = 1701.0
        return result

    monkeypatch.setattr(
        pragmatic_batch,
        "_evaluate_enrichment_attempt",
        delayed_evaluate,
    )
    output = tmp_path / "deadline-during-evaluation"
    report = pragmatic_batch.run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        ScriptedFixtureTeacher(["valid"]),
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=700,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert report["failed_case_ids"] == [FIRST]
    assert not (output / "enrichment" / f"{FIRST}.json").exists()
    quarantine = json.loads(
        (output / "enrichment/quarantine" / f"{FIRST}.slot-1.json").read_text()
    )
    assert quarantine["outcome"] == "deadline_exceeded"


def test_record_construction_crossing_global_deadline_cannot_publish_positive_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.pragmatic_batch as pragmatic_batch

    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(
        pragmatic_batch,
        "time",
        SimpleNamespace(time=lambda: clock.now),
    )
    commit_record = pragmatic_batch.committed_enrichment_record

    def delayed_commit_record(**kwargs: object) -> object:
        record = commit_record(**kwargs)
        clock.now = 1701.0
        return record

    monkeypatch.setattr(
        pragmatic_batch,
        "committed_enrichment_record",
        delayed_commit_record,
    )
    output = tmp_path / "deadline-during-record-construction"
    report = pragmatic_batch.run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        ScriptedFixtureTeacher(["valid"]),
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=700,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert report["failed_case_ids"] == [FIRST]
    assert not (output / "enrichment" / f"{FIRST}.json").exists()
    quarantine = json.loads(
        (output / "enrichment/quarantine" / f"{FIRST}.slot-1.json").read_text()
    )
    assert quarantine["outcome"] == "deadline_exceeded"
    failure = json.loads(
        (output / "enrichment/failures" / f"{FIRST}.json").read_text()
    )
    assert failure["error_kind"] == "deadline_exceeded"


def test_record_write_crossing_global_deadline_removes_positive_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.pragmatic_batch as pragmatic_batch

    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(
        pragmatic_batch,
        "time",
        SimpleNamespace(time=lambda: clock.now),
    )
    output = tmp_path / "deadline-during-record-write"
    target = output / "enrichment" / f"{FIRST}.json"
    atomic_json_write = pragmatic_batch._atomic_json_write

    def delayed_atomic_json_write(path: Path, value: dict[str, object]) -> None:
        atomic_json_write(path, value)
        if path == target:
            clock.now = 1701.0

    monkeypatch.setattr(
        pragmatic_batch,
        "_atomic_json_write",
        delayed_atomic_json_write,
    )
    report = pragmatic_batch.run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        ScriptedFixtureTeacher(["valid"]),
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=700,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert report["failed_case_ids"] == [FIRST]
    assert not target.exists()
    quarantine = json.loads(
        (output / "enrichment/quarantine" / f"{FIRST}.slot-1.json").read_text()
    )
    assert quarantine["outcome"] == "deadline_exceeded"
    failure = json.loads(
        (output / "enrichment/failures" / f"{FIRST}.json").read_text()
    )
    assert failure["error_kind"] == "deadline_exceeded"


def test_record_readback_crossing_global_deadline_removes_positive_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.pragmatic_batch as pragmatic_batch

    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(
        pragmatic_batch,
        "time",
        SimpleNamespace(time=lambda: clock.now),
    )
    record_is_current = pragmatic_batch._record_is_current

    def delayed_record_is_current(*args: object, **kwargs: object) -> bool:
        current = record_is_current(*args, **kwargs)
        clock.now = 1701.0
        return current

    monkeypatch.setattr(
        pragmatic_batch,
        "_record_is_current",
        delayed_record_is_current,
    )
    output = tmp_path / "deadline-during-record-readback"
    target = output / "enrichment" / f"{FIRST}.json"
    report = pragmatic_batch.run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        ScriptedFixtureTeacher(["valid"]),
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=700,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert report["failed_case_ids"] == [FIRST]
    assert not target.exists()
    quarantine = json.loads(
        (output / "enrichment/quarantine" / f"{FIRST}.slot-1.json").read_text()
    )
    assert quarantine["outcome"] == "deadline_exceeded"
    failure = json.loads(
        (output / "enrichment/failures" / f"{FIRST}.json").read_text()
    )
    assert failure["error_kind"] == "deadline_exceeded"


def test_interrupted_slot_one_then_success_is_replayable_and_control_plane_valid(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch
    from egsi.generation.training_ready import _load_batch_control_plane

    output = tmp_path / "interrupted-then-success"
    with pytest.raises(KeyboardInterrupt):
        run_pragmatic_batch(
            ROOT,
            [FIRST],
            output,
            ScriptedFixtureTeacher(["crash"]),
            max_provider_attempts=2,
            retry_transport_once=True,
            resume=False,
            global_wall_clock_seconds=14_400,
            slot_timeout_seconds=600.0,
            effective_max_retries=0,
        )
    first_resume = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        ScriptedFixtureTeacher(["valid"]),
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=True,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    forbidden = ScriptedFixtureTeacher([])
    second_resume = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        forbidden,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=True,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert forbidden.calls == 0
    assert second_resume == first_resume
    slots = json.loads(
        (output / "reports/pragmatic-batch-state.json").read_text()
    )["cases"][0]["slots"]
    assert slots[0]["status"] == "completed"
    assert slots[0]["outcome"] == "interrupted_unknown"
    assert slots[0]["provider_invocation_evidence"] == "upper_bound"
    assert _load_batch_control_plane(ROOT, output, [FIRST]) is not None


def test_interrupted_slot_two_failure_is_replayable_without_more_calls(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    output = tmp_path / "slot-two-interrupted"
    with pytest.raises(KeyboardInterrupt):
        run_pragmatic_batch(
            ROOT,
            [FIRST],
            output,
            ScriptedFixtureTeacher(["transport", "crash"]),
            max_provider_attempts=2,
            retry_transport_once=True,
            resume=False,
            global_wall_clock_seconds=14_400,
            slot_timeout_seconds=600.0,
            effective_max_retries=0,
        )
    forbidden_one = ScriptedFixtureTeacher([])
    first_resume = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        forbidden_one,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=True,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    forbidden_two = ScriptedFixtureTeacher([])
    second_resume = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        forbidden_two,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=True,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert forbidden_one.calls == forbidden_two.calls == 0
    assert second_resume == first_resume
    state = json.loads(
        (output / "reports/pragmatic-batch-state.json").read_text()
    )["cases"][0]
    assert state["terminal_status"] == "failed"
    assert state["error_kind"] == "interrupted_unknown"
    assert state["slots"][1]["status"] == "completed"
    assert state["slots"][1]["outcome"] == "interrupted_unknown"


def test_post_record_crash_recovers_exact_invoked_slot_and_remains_replayable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.pragmatic_batch as pragmatic_batch

    output = tmp_path / "post-record-crash"
    persist = pragmatic_batch._persist_state

    def crash_before_success_state(
        output_root: Path,
        state: pragmatic_batch.PragmaticBatchState,
    ) -> None:
        if (
            (output_root / "enrichment" / f"{FIRST}.json").is_file()
            and state.cases[0].terminal_status == "success"
        ):
            raise KeyboardInterrupt
        persist(output_root, state)

    monkeypatch.setattr(
        pragmatic_batch,
        "_persist_state",
        crash_before_success_state,
    )
    with pytest.raises(KeyboardInterrupt):
        pragmatic_batch.run_pragmatic_batch(
            ROOT,
            [FIRST],
            output,
            ScriptedFixtureTeacher(["valid"]),
            max_provider_attempts=2,
            retry_transport_once=True,
            resume=False,
            global_wall_clock_seconds=14_400,
            slot_timeout_seconds=600.0,
            effective_max_retries=0,
        )
    persisted = json.loads(
        (output / "reports/pragmatic-batch-state.json").read_text()
    )["cases"][0]
    assert persisted["terminal_status"] == "pending"
    assert persisted["slots"][0]["status"] == "provider_invoked"
    assert (output / "enrichment" / f"{FIRST}.json").is_file()

    monkeypatch.setattr(pragmatic_batch, "_persist_state", persist)
    forbidden_one = ScriptedFixtureTeacher([])
    first_resume = pragmatic_batch.run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        forbidden_one,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=True,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    forbidden_two = ScriptedFixtureTeacher([])
    second_resume = pragmatic_batch.run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        forbidden_two,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=True,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert forbidden_one.calls == forbidden_two.calls == 0
    assert second_resume == first_resume
    recovered = json.loads(
        (output / "reports/pragmatic-batch-state.json").read_text()
    )["cases"][0]
    assert recovered["terminal_status"] == "success"
    assert recovered["slots"][0]["status"] == "completed"
    assert recovered["slots"][0]["outcome"] == "success"
    assert recovered["slots"][0]["provider_invocation_evidence"] == "upper_bound"


def test_resume_rejects_confirmed_evidence_tamper_on_transport_slot(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    output = tmp_path / "evidence-tamper"
    run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        ScriptedFixtureTeacher(["transport", "transport"]),
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    state_path = output / "reports/pragmatic-batch-state.json"
    state = json.loads(state_path.read_text())
    state["cases"][0]["slots"][0]["provider_invocation_evidence"] = "confirmed"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    _resume_with_forbidden_teacher(output)


def test_slot_one_structured_invalid_uses_targeted_slot_two_repair(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    teacher = ScriptedFixtureTeacher(["structured_invalid", "valid"])
    output = tmp_path / "batch"

    report = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        teacher,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert report["success_case_ids"] == [FIRST]
    assert report["failed_case_ids"] == []
    assert teacher.calls == 2
    repair_envelope = json.loads(teacher.requests[1].user)
    assert repair_envelope["repair_attempt"] == 1
    assert repair_envelope["repair_feedback"]["flags"][
        "structured_output_invalid"
    ] is True
    state = json.loads((output / "reports/pragmatic-batch-state.json").read_text())
    slots = state["cases"][0]["slots"]
    assert [slot["status"] for slot in slots] == ["completed", "completed"]
    assert slots[1]["purpose"] == "structured_repair"
    assert report["provider_invocations"] == {"kind": "exact", "value": 2}


def test_slot_one_semantic_invalid_uses_targeted_slot_two_repair(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    teacher = ScriptedFixtureTeacher(["semantic_invalid", "valid"])
    output = tmp_path / "batch"
    report = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        teacher,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert report["success_case_ids"] == [FIRST]
    assert teacher.calls == 2
    repair_envelope = json.loads(teacher.requests[1].user)
    assert repair_envelope["repair_feedback"]["flags"][
        "semantic_validation_failed"
    ] is True
    slots = json.loads(
        (output / "reports/pragmatic-batch-state.json").read_text()
    )["cases"][0]["slots"]
    assert slots[1]["purpose"] == "semantic_repair"


def test_canonical_path_semantic_repair_state_replays_and_control_plane_loads(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch
    from egsi.generation.training_ready import _load_batch_control_plane

    output = tmp_path / "canonical-path-repair"
    first = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        ScriptedFixtureTeacher(["canonical_path_invalid", "valid"]),
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    state = json.loads(
        (output / "reports/pragmatic-batch-state.json").read_text()
    )
    first_slot = state["cases"][0]["slots"][0]
    assert first_slot["outcome"] == "semantic_invalid"
    assert first_slot["result_repair_error"] == "invalid_canonical_path"
    assert state["cases"][0]["slots"][1]["purpose"] == "semantic_repair"

    forbidden = ScriptedFixtureTeacher([])
    second = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        forbidden,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=True,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert forbidden.calls == 0
    assert second == first
    assert _load_batch_control_plane(ROOT, output, [FIRST]) is not None


def test_cached_teacher_response_is_not_counted_as_exact_provider_invocation(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    report = run_pragmatic_batch(
        ROOT,
        [FIRST],
        tmp_path / "batch",
        ScriptedFixtureTeacher(["cached_valid"]),
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert report["success_case_ids"] == [FIRST]
    assert report["provider_invocations"] == {"kind": "upper_bound", "value": 1}


def test_two_transport_failures_are_terminal_and_next_case_continues(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    teacher = ScriptedFixtureTeacher(["transport", "transport", "valid"])
    output = tmp_path / "batch"

    report = run_pragmatic_batch(
        ROOT,
        [FIRST, SECOND],
        output,
        teacher,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert teacher.calls == 3
    assert report["success_case_ids"] == [SECOND]
    assert report["failed_case_ids"] == [FIRST]
    assert report["requested"] == report["success"] + report["failed"] == 2
    failure = json.loads(
        (output / "enrichment/failures" / f"{FIRST}.json").read_text()
    )
    assert failure["attempts"] == 2
    assert failure["error_kind"] == "transport"
    state = json.loads((output / "reports/pragmatic-batch-state.json").read_text())
    assert len(state["cases"][0]["slots"]) == 2
    assert state["cases"][1]["slots"][0]["slot_index"] == 1


def test_crash_resume_consumes_unknown_slot_and_never_calls_a_third_time(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    output = tmp_path / "batch"
    crashing = ScriptedFixtureTeacher(["crash"])
    with pytest.raises(KeyboardInterrupt):
        run_pragmatic_batch(
            ROOT,
            [FIRST],
            output,
            crashing,
            max_provider_attempts=2,
            retry_transport_once=True,
            resume=False,
            global_wall_clock_seconds=14_400,
            slot_timeout_seconds=600.0,
            effective_max_retries=0,
        )

    crashed_state = json.loads(
        (output / "reports/pragmatic-batch-state.json").read_text()
    )
    assert crashed_state["cases"][0]["slots"][0]["status"] == "provider_invoked"

    resumed = ScriptedFixtureTeacher(["valid"])
    report = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        resumed,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=True,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert resumed.calls == 1
    assert report["success_case_ids"] == [FIRST]
    assert report["provider_invocations"] == {"kind": "upper_bound", "value": 2}
    slots = json.loads(
        (output / "reports/pragmatic-batch-state.json").read_text()
    )["cases"][0]["slots"]
    assert len(slots) == 2
    assert slots[1]["purpose"] == "transport_retry"


def test_resume_with_two_consumed_slots_finalizes_failure_without_teacher_call(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    output = tmp_path / "batch"
    crashing = ScriptedFixtureTeacher(["transport", "crash"])
    with pytest.raises(KeyboardInterrupt):
        run_pragmatic_batch(
            ROOT,
            [FIRST],
            output,
            crashing,
            max_provider_attempts=2,
            retry_transport_once=True,
            resume=False,
            global_wall_clock_seconds=14_400,
            slot_timeout_seconds=600.0,
            effective_max_retries=0,
        )

    forbidden = ScriptedFixtureTeacher([])
    report = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        forbidden,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=True,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert forbidden.calls == 0
    assert report["failed_case_ids"] == [FIRST]
    assert report["provider_invocations"] == {"kind": "upper_bound", "value": 2}


def test_interrupted_slot_does_not_retry_when_transport_retry_is_disabled(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    output = tmp_path / "batch"
    with pytest.raises(KeyboardInterrupt):
        run_pragmatic_batch(
            ROOT,
            [FIRST],
            output,
            ScriptedFixtureTeacher(["crash"]),
            max_provider_attempts=2,
            retry_transport_once=False,
            resume=False,
            global_wall_clock_seconds=14_400,
            slot_timeout_seconds=600.0,
            effective_max_retries=0,
        )

    forbidden = ScriptedFixtureTeacher([])
    report = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        forbidden,
        max_provider_attempts=2,
        retry_transport_once=False,
        resume=True,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert forbidden.calls == 0
    assert report["failed_case_ids"] == [FIRST]
    assert report["provider_invocations"] == {"kind": "upper_bound", "value": 1}


def test_terminal_success_resume_is_idempotent_and_makes_zero_teacher_calls(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    output = tmp_path / "batch"
    first_teacher = ScriptedFixtureTeacher(["valid"])
    first = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        first_teacher,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=False,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )
    record_before = (output / "enrichment" / f"{FIRST}.json").read_bytes()

    forbidden = ScriptedFixtureTeacher([])
    second = run_pragmatic_batch(
        ROOT,
        [FIRST],
        output,
        forbidden,
        max_provider_attempts=2,
        retry_transport_once=True,
        resume=True,
        global_wall_clock_seconds=14_400,
        slot_timeout_seconds=600.0,
        effective_max_retries=0,
    )

    assert forbidden.calls == 0
    assert second == first
    assert (output / "enrichment" / f"{FIRST}.json").read_bytes() == record_before


def test_corrupt_resume_state_is_systemic_and_stops_before_teacher_call(
    tmp_path: Path,
) -> None:
    from egsi.generation.pragmatic_batch import run_pragmatic_batch

    output = tmp_path / "batch"
    (output / "reports").mkdir(parents=True)
    (output / "reports/pragmatic-batch-state.json").write_text(
        '{"schema_version":"1.0","unexpected":true}', encoding="utf-8"
    )
    teacher = ScriptedFixtureTeacher([])

    with pytest.raises(ValueError, match="pragmatic batch state"):
        run_pragmatic_batch(
            ROOT,
            [FIRST, SECOND],
            output,
            teacher,
            max_provider_attempts=2,
            retry_transport_once=True,
            resume=True,
            global_wall_clock_seconds=14_400,
            slot_timeout_seconds=600.0,
            effective_max_retries=0,
        )

    assert teacher.calls == 0

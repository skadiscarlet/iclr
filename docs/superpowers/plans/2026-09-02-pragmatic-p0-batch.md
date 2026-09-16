# Pragmatic P0 Batch and Training-Ready Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a crash-resumable, strictly two-slot P0 enrichment path and assemble the historical first case plus the remaining batch into an honestly partial, replay-validated training package.

**Architecture:** Keep the existing enrichment runner unchanged. A new `pragmatic_batch` module owns its strict persisted state machine, while a new `training_ready` module independently revalidates source records, preserves accepted record bytes, compiles only accepted cases, and reports failed/gap coverage without a success-rate gate. CLI wiring explicitly selects this path and forces provider-internal retries to zero.

**Tech Stack:** Python 3.11+, Pydantic v2 strict models, Typer, existing EGSIsafe I/O, trajectory compiler/replay, PyArrow-backed Parquet, pytest.

---

### Task 1: Pragmatic two-slot batch state machine

**Files:**
- Create: `tests/generation/test_pragmatic_batch.py`
- Create: `src/egsi/generation/pragmatic_batch.py`

- [x] Write failing tests for targeted structured/semantic repair, two transport failures with continuation, the hard third-call ceiling, crash-resume slot accounting, zero-call terminal resume, and systemic state corruption.
- [x] Run `PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider tests/generation/test_pragmatic_batch.py -q` and confirm failures are caused by the missing module/API.
- [x] Implement strict Pydantic state contracts for `reserved`, `provider_invoked`, and `completed` slots; persist every transition atomically.
- [x] Implement bounded quarantine/failure receipts, valid-record publication, per-case continuation, global deadline finalization, and exact/upper-bound invocation accounting.
- [x] Re-run the focused test and keep the legacy `tests/generation/test_pilot.py` suite green.

### Task 2: CLI and provider retry override

**Files:**
- Modify: `tests/test_cli.py`
- Modify: `src/egsi/cli.py`
- Modify: `src/egsi/teacher/cache.py`
- Create: `configs/p0_pragmatic_remaining_cases.txt`

- [x] Write failing CLI tests proving legacy default routing remains unchanged and explicit pragmatic options route to the new runner with effective `max_retries=0` and a recorded slot timeout.
- [x] Run the focused CLI tests and confirm the expected failures.
- [x] Add a validated `max_retries_override` to teacher factories, expose read-only effective retry/timeout metadata from `CachedTeacher`, and wire explicit pragmatic options.
- [x] Add the frozen ordered P0 suffix containing cases 2 through 10.
- [x] Re-run focused CLI and legacy batch tests.

### Task 3: Training-ready aggregation

**Files:**
- Create: `tests/generation/test_training_ready.py`
- Create: `src/egsi/generation/training_ready.py`
- Modify: `src/egsi/generation/pilot.py`
- Modify: `src/egsi/generation/trajectory.py`
- Modify: `src/egsi/cli.py`

- [x] Write failing tests for exact-byte historical v2.1 import, stale historical gap behavior without provider access, mixed success/failure compilation, ten-case ordered conservation, no-empty-Parquet behavior, and idempotent rebuild/resume.
- [x] Run the focused tests and confirm missing behavior failures.
- [x] Implement bounded source reads and independent historical/current record revalidation, including the frozen v2.1 prompt/semantic contract.
- [x] Factor the trajectory compiler so a freshly validated frozen v2.1 record can use the same deterministic compilation core without weakening the default current-record gate.
- [x] Preserve accepted record bytes and source hashes, compile/replay only accepted records, write Parquet only when non-empty, and produce coverage, trajectory, audit, artifact-manifest, and SHA sidecar reports.
- [x] Add `egsi build-training-ready` CLI wiring and re-run the focused suites.

### Task 4: Runbook and verification

**Files:**
- Create: `docs/PRAGMATIC_P0_RUNBOOK.md`

- [x] Document the fixed live root, nine-case suffix, provider config, 18-slot ceiling, 14,400-second wall clock, 600-second slot timeout, first-run/resume commands, and training-package command.
- [x] State explicitly that this workflow does not launch live calls during tests and does not touch P1, GPU, or training.
- [x] Run focused pragmatic, training-ready, CLI, pilot, trajectory, replay, and human-audit tests with bytecode/cache disabled.
- [x] Run `python -m compileall` only against the modified Python modules with `PYTHONDONTWRITEBYTECODE=1`, validate both case files, and inspect generated JSON schemas/reports in tests.

## Plan self-review

- Coverage: all requested two-slot, resume, retry override, historical compatibility, mixed coverage, artifact, CLI, and runbook requirements map to a task.
- Placeholders: none; live execution is intentionally outside this implementation task.
- Scope: two focused modules preserve existing default behavior and avoid native, provider, GPU, P1, and training paths.
- Repository note: `.git` is a read-only non-repository placeholder in this workspace, so the commit steps required by the generic workflow are inapplicable here.

## Execution closure (2026-09-02)

- Live remaining batch: 9 requested, 9 success, 0 failed, 10 exact provider
  invocations; internal provider retries remained zero.
- Training-ready package: 10 requested, 10 success, 0 failed, 0 gap;
  49 replay-validated transitions in Parquet.
- Final regression: 202 tests passed with bytecode and pytest cache disabled.
- Package rebuild was byte-idempotent before and after the final validation fixes.
- Final read-only review: `APPROVED(C0/I0)`; no provider, P1, GPU, or training
  work was launched during finalization.

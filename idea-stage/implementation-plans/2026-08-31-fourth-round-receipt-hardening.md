# Fourth-Round Receipt Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and execute each RED/GREEN pair inline. Do not delegate this plan.

**Goal:** Bind first-case receipts to one source-approved offline pytest runtime and one source-approved historical baseline, then make PASS-report publication the final failure-atomic operation.

**Architecture:** `test_receipt.py` loads an exact source-controlled runner lock, reconstructs a minimal child environment, and rejects any runtime or pytest input outside that lock. A separate source-controlled historical expectation defines v1 history while the writable output baseline remains only an observed receipt. `first_case_hard_gate.py` performs every receipt, history, identity, and hash check before a last-step transactional report publication that restores prior bytes on failure.

**Tech Stack:** Python 3.12, pytest, strict JSON, POSIX descriptor-anchored
file operations, and pinned no-libc static x86_64 ELF launchers.

---

### Task 1: Hermetic runner attack tests

**Files:**
- Modify: `tests/generation/test_test_receipt.py`

- [x] Add tests asserting the canonical argv uses the absolute locked interpreter, `-I -m pytest`, absolute `-c pyproject.toml`, and absolute `--confcutdir=tests`.
- [x] Add tests for root `pytest.toml`, `.pytest.toml`, `.pytest.ini`, malicious plugin/config injection, shadow `/tmp` interpreter, environment injection, private temporary HOME/TMPDIR, and cleanup.
- [x] Run only these tests and confirm they fail because the lock/environment contract is not implemented.

### Task 2: Hermetic runner implementation

**Files:**
- Create: `configs/offline-test-runner.lock.json`
- Create: `scripts/update_offline_test_runner_lock.py`
- Modify: `src/egsi/generation/test_receipt.py`
- Modify: `scripts/run_test_receipt` (the current pinned native entrypoint;
  the earlier Python wrapper was deleted in the eighth hardening round)

- [x] Implement exact lock schema and commitment validation for the interpreter binary, Python, pytest/pluggy distributions and module files, site-package paths, `.pth`/customization inventory, and canonical config.
- [x] Rebuild the subprocess environment from the fixed allowlist and run with disposable mode-0700 HOME/TMPDIR directories.
- [x] Add `runner_environment_commitment_sha256` and lock digest to receipt/code commitments; make validation recompute both.
- [x] Add an explicit offline-only lock update CLI; never update the lock during receipt generation or verification.
- [x] Run the new tests and existing receipt tests to GREEN.

### Task 3: Source historical expectation

**Files:**
- Create: `configs/historical-teacher-audit-expectation.v1.json`
- Modify: `src/egsi/generation/human_audit.py`
- Modify: `src/egsi/generation/first_case_hard_gate.py`
- Modify: `tests/generation/test_human_audit.py`
- Modify: `tests/generation/test_first_case_hard_gate.py`

- [x] Add a RED test that mutates history and synchronously re-signs the writable output baseline; require rejection.
- [x] Load the exact v1 source expectation and bind count, historical set, response set, provider-failure class/count, and provider-failure audit set.
- [x] Treat `reports/historical-teacher-audit-baseline.json` only as an observed receipt and cross-check it against the source expectation in both verifier and human-audit paths.
- [x] Run the focused baseline tests to GREEN.

### Task 4: Last-step failure-atomic PASS publication

**Files:**
- Modify: `src/egsi/generation/first_case_hard_gate.py`
- Modify: `tests/generation/test_first_case_hard_gate.py`

- [x] Add RED tests for a pre-publication receipt race and a writer that raises after replacing a missing or existing PASS report.
- [x] Move all validations and writable baseline publication before the report operation.
- [x] Snapshot an existing report and transactionally restore it, or remove a newly created report, if the final writer raises.
- [x] On success, make publication the final operation and return without post-publication reads or checks.
- [x] Run the focused publication tests to GREEN.

### Task 5: Verification and evidence renewal

**Files:**
- Modify: `idea-stage/implementation-plans/2026-08-30-real-codex-p0-results.md`

- [x] Run canonical focused and full suites with the locked interpreter, then `compileall`.
- [x] Run explicit shadow/config/plugin/baseline-resign/report-race negative tests.
- [x] Use `--rerun-tests` to renew the real focused/full receipts, observed baseline receipt, and PASS report; immediately run `verify-only`.
- [x] Record exact counts, commitments, hashes, threat-model boundary, and unchanged stop marker without accessing network/model/GPU or remaining cases.

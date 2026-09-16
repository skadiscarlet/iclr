# Trust v10 and Live P1 Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three trust-boundary defects found after the cumulative first-case history repair, refresh and independently verify trust v10, pass the official first-case gate, then produce and validate the authorized 20-case live P1 delta and additive 30-case training-ready package.

**Architecture:** Keep source-controlled historical expectations immutable from runtime output and bind expectation parsing plus evidence to one anchored file descriptor. Make fail-fast execution require the frozen base expectation before acquiring an output lock or performing provider-capable work. Only after source, receipt, native-attestation, and first-case gates pass may the existing live enrichment and offline additive aggregator run.

**Tech Stack:** Python 3.12.9, pytest, POSIX `openat`/directory-fd safe I/O, strict JSON, SHA-256 commitments, native RSA receipt attestations, existing `egsi` CLI.

---

## Task 1: Receipt destination boundary (I1)

**Files:**
- Modify: `tests/generation/test_test_receipt.py`
- Modify: `src/egsi/generation/test_receipt.py`

- [ ] Extend the existing official-receipt timeout test so an output under `configs/` and an output reached through a symlinked ancestor are rejected before `subprocess.run`, snapshots, or writes; preserve the source bytes and prove `/tmp` output remains accepted.
- [ ] Run the existing nodeid with the isolated runner and record a failure caused by the missing destination guard.
- [ ] Add a preflight destination validator: project-local output must be a descendant of `<root>/.work`; reject lexical escape, resolved alias, symlink leaf, and symlink ancestor before any side effect.
- [ ] Re-run the nodeid and the receipt-focused regression to green with bytecode disabled.

## Task 2: FD-pinned expectation value and evidence (I2)

**Files:**
- Modify: `tests/generation/test_first_case_hard_gate.py`
- Modify: `src/egsi/generation/human_audit.py`
- Modify: `src/egsi/generation/first_case_hard_gate.py`

- [ ] Extend the existing source-expectation test with a controlled pathname replacement between descriptor open/read and post-read validation; assert swap and ABA-style replacement fail closed and cannot mix parsed values with evidence hashes.
- [ ] Run that nodeid and record the expected failure from split pathname reads.
- [ ] Implement `load_historical_expectation_with_evidence(...) -> tuple[dict[str, Any], dict[str, str]]` using an anchored parent fd and `O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC`; validate the actual fd is a single-link regular file with mode `0600` or `0644` and bounded size.
- [ ] Read exact bytes once, compare before-fd, after-fd, and post-path identity/metadata, and derive the parsed expectation, commitment, and file SHA from those exact bytes.
- [ ] Make `_historical_baseline()` and first-case report construction consume the combined result rather than separate value/evidence reads; retain compatibility wrappers only if they delegate to one combined read per call.
- [ ] Re-run the nodeid plus historical-contract focused tests to green.

## Task 3: Missing expectation fails before fail-fast side effects (I3)

**Files:**
- Modify: `tests/generation/test_fail_fast_batch.py`
- Modify: `src/egsi/generation/fail_fast_batch.py`

- [ ] Extend an existing fail-fast runner nodeid with missing and invalid expectation cases; instrument lock creation, directory creation, archive, runner construction, and `runner.run`, and assert none occur.
- [ ] Run the nodeid and record failure showing the current compatibility branch reaches output/provider-capable execution.
- [ ] Remove the optional expectation branch and require the frozen base expectation in the pre-lock preflight; pass the validated value through request-state/audit construction so runtime does not downgrade to `None`.
- [ ] Update synthetic `_failed_run()` setup with a valid synthetic expectation or a narrowly scoped loader monkeypatch; do not restore production compatibility behavior.
- [ ] Re-run fail-fast focused tests to green.

## Task 4: Review and regression closure

- [ ] AST-parse changed Python and prove zero `.pyc`/`__pycache__` residue.
- [ ] Run the targeted history/receipt/fail-fast tests, then the locked outer-PID-namespace contained first-case regression.
- [ ] Obtain independent `SPEC_APPROVED`, followed by independent `APPROVED(C0/I0)`; fix and re-review any open issue before proceeding.

## Task 5: Refresh trust v10

**Files:**
- Create new v10 artifacts under `.work/p1-pragmatic-control-v1/`
- Preserve all v9 artifacts byte-for-byte.

- [ ] Bootstrap with pyenv `python3` 3.12.9 and `PYTHONDONTWRITEBYTECODE=1`; never use `/usr/bin/python3` or a login shell.
- [ ] Fresh-collect focused and full canonical nodeids, verify expected counts, and regenerate the canonical contract, runner commitment, native signer/attestation inputs, and RSA receipts as v10.
- [ ] Record exact P0 inventory `125/44/38 = 207`, absence of P1 output roots, provider-config mode `0600` without reading its content, zero bytecode/cache, and zero private signer material.
- [ ] Use an explicit v10 generation inventory rather than a wildcard that could self-include later logs.
- [ ] Obtain v10 spec and quality approvals, then run the fresh root verifier.

## Task 6: Official first-case hard gate

- [ ] Run focused historical-contract checks and `_build_report()` against the real 30-audit history.
- [ ] Run the official hard gate with `--rerun-tests` into `.work/p1-trust-refresh-first-case-v1`.
- [ ] Immediately run native verify-only and retain receipts, report, attestations, stdout/stderr, exit codes, and hashes.

## Task 7: Authorized 20-case live enrichment

- [ ] Confirm `.work/real-p1-pragmatic-v1` is absent and run the first attempt without `--resume` using `provider=codex_exec`, `model=gpt-5.6-sol`, timeout `600`, internal retry `0`, maximum two attempts per case, and global wall clock `28800` seconds.
- [ ] Monitor state/provenance deterministically; use `--resume` only after a real interruption.
- [ ] Preserve all positive and negative outcomes without relaxing validators or retry limits.

## Task 8: Additive 30-case package

- [ ] Run `build-incremental-training-ready` from immutable `.work/p0-training-ready-v1` plus `.work/real-p1-pragmatic-v1` into `.work/p1-training-ready-v1`.
- [ ] Rebuild twice and prove byte-idempotence, 30-case conservation, P0 207-file byte identity, closed replay, JSONL/Parquet equality, manifest/sidecar validity, exact artifact sizes/hashes, and zero aggregation teacher calls.
- [ ] Report training/validation/test composition and observed success/failure/gap results; do not start GPU training until this package is complete.

## Fixed boundaries

- Read-only: `.work/real-p0-codex-v2`, `.work/real-p0-pragmatic-v1`, `.work/p0-training-ready-v1`.
- No provider call before Tasks 1-6 are green and independently approved.
- Never print or copy provider secrets.
- No GPU or training before Task 8 is complete.
- `.git` is a nonfunctional read-only placeholder in this workspace, so commit steps do not apply.

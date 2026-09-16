# Remaining-P0 Fail-Fast Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and execute each RED/GREEN pair inline. Do not delegate this plan.

**Goal:** Recover only `ghsa-3wfj-vh84-732p` with prompt v2.2 while proving that the later eight P0 cases were never invoked and that every terminal outcome is independently replayable.

**Architecture:** `fail_fast_batch.py` owns one `BatchLock` transaction, enumerates the seven source-controlled v2.2 requests, stops after the first case failure, and publishes a strict provenance/summary/report triple. The independent verifier reconstructs request order, complete teacher audit/cache bindings, provenance, summary, RSA-attested canonical receipts, and the no-later-case boundary from source and artifacts rather than trusting report booleans or commitments alone.

**Tech Stack:** Python 3.12, Pydantic v2, pytest, POSIX descriptor-anchored I/O and `flock`, strict JSON, SHA-256, RSA-2048 PKCS#1 v1.5 receipt attestations.

---

### Task 1: Fail-fast transaction and terminal receipt

**Files:**
- Modify: `tests/generation/test_fail_fast_batch.py`
- Modify: `src/egsi/generation/fail_fast_batch.py`

- [ ] Add a failing test whose runner asserts `active_batch_lock(output_root)` is active.
- [ ] Add a failing test where `EnrichmentRunner.run()` raises before writing a receipt; assert a redacted `error_kind=orchestrator` receipt and `REMAINING_P0_CASE_RECOVERY_STOPPED` report are published.
- [ ] Add a failing test that archives identical active bytes twice and proves the second active file is renamed to a unique history suffix rather than unlinked.
- [ ] Wrap run and public verification entry points in `BatchLock`, using a private unlocked verifier for the in-transaction final replay.
- [ ] On a runner exception, count only current v2.2 attempts, write a bounded source-controlled fallback receipt if none exists, and publish STOP evidence.
- [ ] Run `pytest -q tests/generation/test_fail_fast_batch.py` and retain zero failures.

### Task 2: Deep audit/cache/provenance/summary replay

**Files:**
- Modify: `tests/generation/test_fail_fast_batch.py`
- Modify: `src/egsi/generation/fail_fast_batch.py`

- [ ] Add failing tamper tests for committed audit metadata/body, its cache preimage, request order, duplicate request hashes, an invocation after the first failed case, and re-committed provenance/summary bodies.
- [ ] Refactor request enumeration to return the canonical `request_hash -> TeacherRequest` map and reject cross-case collisions.
- [ ] Reuse `_scan_teacher_audit()` to validate exact manifest schemas, event lifecycles, executable identity, cache paths, cache keys, response commitments, and full audit/cache inventories.
- [ ] Store the recomputed audit/cache artifact-set commitment in the strict report and bind every current attempt to its response/cache evidence.
- [ ] Reconstruct the exact provenance manifest and enrichment summary, including exact fields, artifact order, provider/model identities, file commitments, and self-commitments.
- [ ] Reject any current attempt for forbidden or not-started cases, more than three attempts, duplicate request hashes, non-prefix start/completion order, or continuation after failure.
- [ ] Run the fail-fast module tests and the human-audit/cache focused regressions.

### Task 3: RSA canonical receipt evidence

**Files:**
- Modify: `tests/generation/test_fail_fast_batch.py`
- Modify: `src/egsi/generation/fail_fast_batch.py`

- [ ] Add failing tests for missing, swapped, byte-tampered, and self-recommitted-but-unsigned focused/full receipts.
- [ ] Parse the two fixed receipt JSON files, require schema 7.0 success, exact names, zero failures, self-commitments, and matching code commitments.
- [ ] Strictly parse each V2 native attestation, bind domain/basename/artifact SHA-256/native contract/public key, and verify RSA-2048 SHA-256 PKCS#1 v1.5 with the source-controlled public key.
- [ ] Add ordered focused/full receipt evidence to the strict report and recompute it in the independent verifier.
- [ ] Run receipt/RSA and fail-fast focused tests to zero failures.

### Task 4: Recovery scope/config and historical regressions

**Files:**
- Create: `configs/recover_3wfj_cases.txt`
- Modify: `configs/providers.example.toml`
- Modify: `tests/generation/test_human_audit.py`
- Modify: `src/egsi/generation/first_case_hard_gate.py` only if a frozen-v2.1 regression fails

- [ ] Add exactly `ghsa-3wfj-vh84-732p` to the recovery case file.
- [ ] Replace the non-parseable executable digest example with a valid all-zero SHA-256 placeholder.
- [ ] Run the renamed pre-v2.2 human-audit test and confirm five retained commits are historical and zero are current.
- [ ] Run the complete first-case hard-gate regression against frozen v2.1 request reconstruction.

### Task 5: Source freeze, lock, and offline assurance

**Files:**
- Modify: `idea-stage/implementation-plans/2026-08-30-real-codex-p0-results.md`
- Modify: `configs/canonical-test-contract.v1.json`
- Regenerate: `configs/native-signer-build-record.json`
- Regenerate: `configs/offline-test-runner.lock.json`
- Regenerate: `scripts/run_test_receipt`
- Regenerate: `scripts/rerun_first_case_hard_gate`
- Regenerate: `scripts/verify_first_case_hard_gate`

- [ ] Document prompt v2.2, canonical paths, executable identity, fail-fast design, and the fact that no live recovery has run yet.
- [ ] Collect exact focused/full node IDs and rewrite the canonical collection contract and commitment.
- [ ] Rebuild the RSA launchers and v7 runner lock only after all source/test/doc edits stop.
- [ ] Generate fresh focused/full RSA receipts, rerun the first-case hard gate, run public verify-only, compileall to `/tmp`, and run the complete locked canonical suite.
- [ ] Do not edit source, tests, configs, or the result document after the final lock/receipt issuance.

### Task 6: Single-case live recovery and independent replay

**Files:**
- Write only under: `.work/real-p0-codex-v2/`

- [ ] Run `egsi fail-fast-enrich` with `configs/recover_3wfj_cases.txt`, `configs/p0_cases.txt`, and the identity-pinned local provider.
- [ ] Use at most three unique current-v2.2 requests; classify the three old v2.1 requests as historical only.
- [ ] Run `egsi verify-fail-fast-enrich` independently against the same source-controlled scope.
- [ ] Accept only `REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW` or `REMAINING_P0_CASE_RECOVERY_STOPPED`.
- [ ] Stop immediately after the independent replay; do not invoke the later eight P0 cases, P1, trajectories, human audit signing, GPU, training, or `data/` writes.

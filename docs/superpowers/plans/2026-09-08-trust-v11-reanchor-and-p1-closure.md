# Trust v11 Re-anchor and P1 Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the unrecoverable v10 identity generation with an explicitly disclosed v11 re-anchor, prove that the frozen P0 bytes were conserved, then complete the first-case gate, authorized 20-case P1 enrichment, and additive 30-case package.

**Architecture:** Treat v10 as a failed and revoked generation rather than editing its historical anchors. Build v11 from one isolated, transaction-wide `BoundTree`: every semantic value and commitment comes from FD-pinned bytes held until final verification, while negative states are checked again at transaction close. The only accepted re-anchor delta is the independently observed metadata incident; P0 byte conservation remains exact and all mutation tests operate on `/tmp` fixtures, never the live project root.

**2026-09-09 Task 1 amendment:** The preserved v9/v10 evidence never bound a complete historical identity for `configs/providers.local.toml`; historical continuity is therefore unprovable. Per the operator-approved design in `docs/superpowers/specs/2026-09-09-trust-v11-forward-reanchor-design.md`, r23 establishes an operator-authorized, forward-only metadata anchor from two agreeing metadata-only witnesses. Historical provider identity/delta is `UNKNOWN_UNRECOVERABLE`; it must never be reconstructed from chat summaries or hard-coded constants.

**2026-09-10 r28 threat-model amendment:** Trust generation is an exact FD-pinned snapshot under cooperative locked quiescence, not a global filesystem transaction. Non-cooperative mutation after the final observation and arbitrary same-process private-state tampering are out of scope and require an OS-level immutable snapshot to eliminate. r28 must state this limitation and must not add fixed verification rounds in an attempt to claim impossible global atomicity.

**Tech Stack:** Python 3.12.9, POSIX `openat`/directory-fd reads, Btrfs metadata evidence, strict JSON, SHA-256 commitments, native RSA attestations, pytest, existing `egsi` CLI.

---

## Fixed safety and sequencing boundaries

- Read-only data roots: `.work/real-p0-codex-v2`, `.work/real-p0-pragmatic-v1`, `.work/p0-training-ready-v1`.
- Historical v9/v10 artifacts are append-only evidence; no historical manifest, receipt, anchor, or failure transcript may be rewritten.
- No provider call before v11 spec review, quality review, root verification, official first-case gate, and native verify-only all pass.
- No GPU or training before the 30-case package passes all conservation and replay checks.
- `configs/providers.local.toml` is metadata-only evidence: only `lstat`/directory-fd `stat` of type and mode `0600` is allowed.
- The v11 provider epoch starts at the r23 forward-anchor ceremony. Two independent collectors must agree on all current identity fields, and all later transactions derive their deny-set from that committed anchor rather than re-trusting the current pathname.
- Supported authority semantics are `FD_PINNED_SNAPSHOT_AS_OBSERVED` with `COOPERATIVE_LOCKED_QUIESCENCE`. Successful verification is evidence about the observed snapshot; it is not a promise that a non-cooperative writer cannot mutate a pathname after the last syscall.
- Every shell invocation is non-login. Every Python invocation sets `PYTHONDONTWRITEBYTECODE=1` and uses `-B`.
- Bootstrap is invoked with literal argv `python3 -B scripts/bootstrap_offline_test_runner.py --root /home/furina/iclr` and a minimal `PATH` whose first entry is `/home/furina/.pyenv/versions/3.12.9/bin`.
- `.git` is a read-only placeholder, so commit/worktree steps do not apply. Isolation is provided by fresh no-clobber output roots, exact inventories, and independent review.

## Task 1: Contain and record the v10 integrity incident

**Files:**
- Create: `.work/p1-pragmatic-control-v1/build_trust_v11_reanchor.py`
- Create: `.work/p1-pragmatic-control-v1/test_build_trust_v11_reanchor.py`
- Create: `.work/p1-pragmatic-control-v1/trust-v10-integrity-incident.json`
- Create: `.work/p1-pragmatic-control-v1/trust-v10-revocation.json`
- Create: `.work/p1-pragmatic-control-v1/p0-reanchor-v11.json`
- Create: `.work/p1-pragmatic-control-v1/trust-v11-preflight-report.json`
- Create: `.work/p1-pragmatic-control-v1/provider-forward-anchor-witness-a-v11.json`
- Create: `.work/p1-pragmatic-control-v1/provider-forward-anchor-witness-b-v11.json`
- Create: `.work/p1-pragmatic-control-v1/provider-forward-anchor-v11.json`

- [ ] Read the old P0 baseline and v9/v10 preservation evidence through confined descriptor-pinned reads; record their exact file SHA-256 values without changing their bytes or metadata.
- [ ] Recompute all 207 P0 regular-file byte descriptors and prove the byte inventory is still `sha256:d7d742815539aeb0d612a6ade05848bccfdd71410061f21f3ac48ea9e0050d45` with counts `125/44/38`.
- [ ] Record the old identity commitment `sha256:b2f7e9662bfeb9319b21b59c24def4140fe340f529443bb059d632fc0d34b08d`, the current identity commitment, and the exact allowlisted P0 delta: only `.work/p0-training-ready-v1/.egsi-batch.lock` has a changed `ctime_ns`; its dev, inode, mode, nlink, size, mtime, and SHA-256 remain exact.
- [ ] Record exact preserved old/current metadata deltas for `src/egsi/__init__.py` and `configs/canonical-test-contract.v1.json`. For `configs/providers.local.toml`, record `old_identity: UNKNOWN_UNRECOVERABLE`, enumerate the missing historical fields, and bind the current forward anchor without reading provider bytes.
- [ ] Collect two independent current provider metadata witnesses using only `lstat` and directory-FD `stat(..., follow_symlinks=False)`; require exact agreement on dev/inode/type/mode/uid/gid/nlink/size/mtime/ctime, canonical path, and ancestor identities before deriving the forward anchor.
- [ ] Keep a provider guard alive across each complete standalone publish/verify transaction; re-stat before every later content open/read and at close, and reject canonical replacement or any alias of the committed provider inode before content access.
- [ ] Record the exact r28 authority and concurrency semantics in the incident, preflight, generation COMMIT, checker result, and public verification output; explicitly mark non-cooperative post-observation mutation and same-process private-state tampering out of scope.
- [ ] Mark the v10 generation `REVOKED_BEFORE_PROVIDER_USE` when the bound generation-attempt evidence proves `provider_called:false`. Bind every available rejected review and recovery audit individually, enumerate missing artifacts, and record historical live/GPU state as `UNKNOWN_UNVERIFIED` unless a bound local artifact proves otherwise.
- [ ] Give each JSON object a commitment computed from canonical JSON with the commitment field removed; write with mode `0600` and a detached SHA-256 sidecar.
- [ ] Run a strict read-only checker that never uses `O_CREAT`/`O_RDWR`, rejects any P0 byte delta, any additional P0 identity delta, any provider-content field, any mutation of old evidence, and any before/after workspace tree or metadata change.
- [ ] Add RED/GREEN `/tmp` tests for witness disagreement, uncommitted production anchor injection, canonical replacement after binding, orphan/reviewer-cache/shadow aliases with zero content reads, missing checker lock without creation, and the absence of real-root semantic derivation in the test suite.
- [ ] Preserve the r27 late-final-syscall PoCs as limitation tests that demonstrate the documented boundary. Do not require an unbounded or fixed-N rescan to claim global atomic closure.

## Task 2: Replace live-root adversarial tests with isolated fixtures

**Files:**
- Create: `.work/p1-pragmatic-control-v1/verify_final_trust_refresh_v11.py`
- Create: `.work/p1-pragmatic-control-v1/test_verify_final_trust_refresh_v11.py`
- Create: `.work/p1-pragmatic-control-v1/trust-v11-unit-test-command.json`

- [ ] Copy only the reusable verifier logic into the v11 files; do not carry forward v10 constants, manifests, or a test that mutates `ROOT`.
- [ ] Add `make_fixture_root(base: Path) -> Path` that creates all files needed by swap, ABA, P0, provider-mode, receipt, bootstrap, disclosure, and negative-state tests below a `TemporaryDirectory(dir="/tmp")` root.
- [ ] Write an AST safety test that rejects `write_bytes`, `write_text`, `touch`, `mkdir`, `unlink`, `rename`, `replace`, `chmod`, `link`, `symlink_to`, or `os.replace` when a mutation target is derived from the real `ROOT` constant; require adversarial tests to receive a fixture root argument.
- [ ] Capture a live-root metadata inventory immediately before the v11 unit command and compare it immediately after; any changed dev/inode/mode/nlink/size/mtime/ctime or tree membership makes the command receipt fail.
- [ ] Run the safety tests first and record a RED result against the copied v10 test module because it contains real-root mutations.
- [ ] Move every adversarial mutation to the fixture factory and rerun the safety tests to GREEN before running any semantic verifier test.

## Task 3: Implement one transaction-wide `BoundTree`

**Files:**
- Modify: `.work/p1-pragmatic-control-v1/verify_final_trust_refresh_v11.py`
- Modify: `.work/p1-pragmatic-control-v1/test_verify_final_trust_refresh_v11.py`

- [ ] Define `BoundRead` with raw bytes, leaf stat identity, pinned ancestor identities, and open descriptors; define `BoundTree` with exact tree inventories, metadata-only bindings, absence bindings, and a deterministic close-time verifier.
- [ ] Make the transaction freeze exact inventories for source, scripts, tests, snapshot workspace inputs, all 207 P0 files, all v11 evidence inputs, both original receipt roots and evidence copies, and every nonzero-exit transcript.
- [ ] Derive strict JSON objects, descriptors, code commitments, snapshot commitments, receipt semantics, RSA digests, failure disclosures, and secret scans only from registered `BoundRead.raw` values.
- [ ] Compile the preserved v9 verifier only from its registered bound bytes; disable an unkeyed module cache.
- [ ] Require the bootstrap verifier API to receive the bound bootstrap stdout/stderr triplet and compare the real FD-pinned Python executable hash, version, literal argv, resolved path, allowlisted environment, and `login=false`.
- [ ] At transaction close, revalidate every leaf and ancestor identity, re-enumerate every exact tree, and then recheck provider mode, P1 absence, cache absence, and private-signer-material absence.
- [ ] Treat close-time revalidation as the final observation of the pinned snapshot under the cooperative lock. Do not describe it as an OS-atomic snapshot or protection from non-cooperative writes after that observation.
- [ ] Add RED/GREEN tests for mixed-tree reads, post-read P0 replacement, transcript swap/ABA, v9 verifier restore, clean-to-secret stream replacement, receipt-source replacement, forged bootstrap hashes, provider chmod, P1 creation, cache creation, and private-material creation.
- [ ] Assert that the registered transaction leaf count equals the union of every declared inventory; a missing bound is a test failure.

## Task 4: Build the v11 pre-refresh trust inputs

**Files:**
- Create: `.work/p1-pragmatic-control-v1/final-pre-trust-refresh-snapshot-v11.json`
- Create: `.work/p1-pragmatic-control-v1/final-bootstrap-command-receipt-v11.json`
- Create: `.work/p1-pragmatic-control-v1/canonical-test-contract.v11.candidate.json`
- Modify: `configs/canonical-test-contract.v1.json`
- Modify: `configs/offline-test-runner.lock.json`
- Modify: `configs/native-signer-build-record.json`
- Regenerate: `scripts/run_test_receipt`
- Regenerate: `scripts/rerun_first_case_hard_gate`
- Regenerate: `scripts/verify_first_case_hard_gate`
- Regenerate: `scripts/run_fail_fast_enrich`
- Regenerate: `scripts/verify_fail_fast_enrich`

- [ ] Verify `/home/furina` ancestor identity is stable for five minutes and record every sample.
- [ ] Generate the v11 snapshot only after Tasks 1-3 are stable; bind the incident and re-anchor commitments as mandatory inputs.
- [ ] Run the literal bootstrap command with the fixed pyenv path ordering and capture a command receipt containing the exact argv, resolved executable, executable SHA-256, Python `3.12.9`, allowlisted environment, non-login property, stdout/stderr descriptors, and exit code.
- [ ] Fresh-collect focused and full nodeids without loading the execution contract plugin; require counts `766/1349` and bind the exact ordered nodeid hashes.
- [ ] Regenerate the canonical contract, offline runner lock, native build record, and five native launchers; run the locked probe and five `--native-public-contract` commands.
- [ ] Verify the five public-contract outputs are byte-identical, each command exits zero, and all fields match current canonical/runner/native inputs.

## Task 5: Generate fresh v11 RSA receipts

**Files:**
- Create: `.work/trust-v11-rsa-receipts/reports/offline-focused-receipt.json`
- Create: `.work/trust-v11-rsa-receipts/reports/offline-focused-receipt.json.native-attestation`
- Create: `.work/trust-v11-rsa-receipts/reports/offline-full-receipt.json`
- Create: `.work/trust-v11-rsa-receipts/reports/offline-full-receipt.json.native-attestation`
- Create evidence copies under: `.work/p1-pragmatic-control-v1/rsa-receipts-v11/reports/`

- [ ] Confirm both v11 receipt roots are absent before the first command and create only the allowed `.work/**/reports` parent structure before bootstrap if the native closure requires it.
- [ ] Run focused receipt once; require exit `0`, `passed_count=766`, `failed_count=0`, and native attestation success.
- [ ] Run full receipt once; require exit `0`, `passed_count=1349`, `failed_count=0`, and native attestation success.
- [ ] Verify receipt commitments, ordered nodeid commitments, current runner/native/canonical bindings, and PKCS#1 v1.5 SHA-256 signatures from the same FD-pinned receipt and sidecar bytes.
- [ ] Copy the four already-signed source bytes into the control evidence tree with no transformation; record source/destination mode, size, SHA-256, and exact-byte equality.
- [ ] Preserve all v10 failed/successful receipt attempts as historical evidence and never label them v11.

## Task 6: Build and independently review the v11 manifest

**Files:**
- Create: `.work/p1-pragmatic-control-v1/trust-v11-nonzero-exit-disclosure.json`
- Create: `.work/p1-pragmatic-control-v1/trust-v11-spec-review-bundle.json`
- Create: `.work/p1-pragmatic-control-v1/trust-v11-quality-review-bundle.json`
- Create: `.work/p1-pragmatic-control-v1/final-trust-refresh-native-validation-v11.json`
- Create: `.work/p1-pragmatic-control-v1/final-trust-refresh-native-validation-v11.json.sha256`

- [ ] Enumerate the exact set of nonzero exit-code files and bind each command description, exit file, existing stdout/stderr descriptors, and a path-specific reason; explicitly record missing companions.
- [ ] Scan every registered raw stream plus bounded decoded receipt stdout/stderr for credentials and private-key markers; the count must be computed, not constant.
- [ ] Build explicit, unique input lists with no wildcard, no manifest self-reference, no future log self-reference, and no reviewer verdict circularity.
- [ ] Mark both reviewer bundles `PENDING_INDEPENDENT_REVIEW`; they are input checklists, not approvals.
- [ ] Run the final v11 verifier unit command against isolated fixtures, require all current test methods to execute, and bind exact argv, test-source SHA-256, stdout/stderr, exit code, and the before/after live-root metadata equality result.
- [ ] Build the manifest, verify its object commitment and detached sidecar, then run a fresh-root verification transaction.
- [ ] Obtain independent `SPEC_APPROVED`; after it passes, obtain independent `APPROVED(C0/I0)`. Any Critical or Important issue returns to the implementation step and requires re-review.

## Task 7: Official first-case hard gate

**Files:**
- Create under: `.work/p1-trust-refresh-first-case-v11/`

- [ ] Verify the real `_build_report()` history state is current committed `3`, historical committed `6`, provider failures `21`, and manifest count `30`.
- [ ] Use the fresh no-clobber output root and run `scripts/rerun_first_case_hard_gate --rerun-tests` with focused/full receipt paths under that root.
- [ ] Require the official report and native attestations to pass, then immediately run native verify-only.
- [ ] Run a fresh current-state verification immediately before the provider-capable first-case action; do not rely only on the earlier r28 generation status.
- [ ] Preserve stdout/stderr, exit codes, report, receipts, attestations, and hashes; no provider call is allowed if this gate fails.

## Task 8: Authorized 20-case P1 live enrichment

**Files:**
- Create under: `.work/real-p1-pragmatic-v1/`

- [ ] Confirm the output root is absent and launch the first attempt without `--resume` using provider `codex_exec`, model `gpt-5.6-sol`, timeout `600`, internal retry `0`, at most two attempts per case, and global wall clock `28800` seconds.
- [ ] Monitor state and provenance deterministically; use `--resume` only after a real interruption.
- [ ] Preserve every committed and quarantined result without weakening validators or increasing retry limits.

## Task 9: Additive 30-case training-ready package

**Files:**
- Create under: `.work/p1-training-ready-v1/`

- [ ] Build from immutable `.work/p0-training-ready-v1` plus `.work/real-p1-pragmatic-v1` with the fixed P1 case files.
- [ ] Rebuild twice and prove byte-idempotence, 30-case conservation, P0 207-file byte identity, closed replay, JSONL/Parquet equality, manifest/sidecar validity, exact artifact sizes/hashes, and zero aggregation teacher calls.
- [ ] Report train/validation/test composition and all observed success, failure, and gap results; do not start GPU training in this task.

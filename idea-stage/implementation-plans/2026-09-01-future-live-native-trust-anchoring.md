# Future Live Native Trust Anchoring Implementation Plan

> **For agentic workers:** Execute inline with `superpowers:test-driven-development`; sub-agent execution is explicitly disabled for this task.

**Goal:** Make future kind-4 live execution and kind-5 public verification fail closed unless the exact build-pinned bootstrap, two current RSA-attested canonical test receipts, current project/runner lock, and the native-observed terminal candidate all agree before an RSA live sidecar is issued.

**Architecture:** Every launcher publishes the bootstrap path/SHA-256/size/mode compiled into the ELF. Live launchers safe-open and hash that file before every child, then execute the already-verified inode through an inherited `/proc/self/fd/<n>` descriptor. Kind 4 derives the canonical focused/full receipt paths, verifies both RSA sidecars in C, invokes the pinned bootstrap for a receipt/runtime/preinventory preflight, and retains the resulting fixed-line anchors. The live child writes the JSON plus a fixed-line candidate envelope whose JSON hash, run metadata, child terminal, inventories, bootstrap, receipts, lock/project, canonical contract, and native contracts must match the C-retained values. C repeats every hash and semantic check immediately before signing. Kind 5 verifies bootstrap, receipt RSA anchors, and live RSA before Python; pinned Python then replays receipt and live semantics against the current runtime.

**Tech Stack:** freestanding C11/x86_64 Linux syscalls, RSA-2048/SHA-256 PKCS#1 v1.5, stdlib-only locked Python bootstrap, pytest, synthetic `/tmp` trust roots.

**Frozen boundary:** No network/provider execution, no second real v2.3 attempt, no remaining P0/P1/GPU/training/data work, and no enrichment of the retained unsigned STOP tree. Every live signer test uses a disposable synthetic root.

---

## File map and contracts

- `scripts/build_native_rsa_material.py`: safe-read `scripts/locked_runtime_bootstrap.py`; emit `EGSI_BOOTSTRAP_SHA256_BYTES`, `EGSI_BOOTSTRAP_SIZE`, and `EGSI_BOOTSTRAP_MODE`; bind the anchor into build id/native binary contract and public build record.
- `scripts/locked_launcher.c`: verified-bootstrap-FD child execution; public bootstrap contract; canonical receipt path derivation; RSA/byte anchors; fixed preflight/candidate parsers; kind-4 pre/post comparisons; kind-5 pre/post verification.
- `scripts/locked_runtime_bootstrap.py`: strict preflight/run/semantic/public-verify argv; exact receipt hash comparison; `validate_test_receipt(..., require_success=True)` for focused/full; current lock/project/native contract extraction; preinventory envelope emission.
- `src/egsi/generation/live_attestation.py`: schema `3.0`; public trust-anchor fields; fixed candidate envelope emission/verification; exact expected-native binding during semantic replay.
- `tests/generation/test_test_receipt.py`: synthetic build/public-contract regressions and native attack tests.
- `tests/generation/test_live_attestation.py`: schema/anchor/envelope tamper tests.
- `configs/native-signer-build-record.json`, `configs/offline-test-runner.lock.json`, `configs/canonical-test-contract.v1.json`: regenerated only after implementation/tests stabilize.
- `.work/real-p0-codex-v2/final-v2.3-execution.md`: future-path assurance and explicit retained unsigned-STOP limitation.

### Fixed preflight envelope

Mode `0600`, regular, `nlink=1`, exact LF lines and no extras:

```text
EGSI-LIVE-PREFLIGHT-V1
run_id=<64 lowercase hex>
nonce=<64 lowercase hex>
realtime_start_ns=<decimal>
monotonic_start_ns=<decimal>
pre_inventory_sha256=sha256:<64 lowercase hex>
bootstrap_sha256=sha256:<64 lowercase hex>
focused_receipt_sha256=sha256:<64 lowercase hex>
focused_sidecar_sha256=sha256:<64 lowercase hex>
full_receipt_sha256=sha256:<64 lowercase hex>
full_sidecar_sha256=sha256:<64 lowercase hex>
runner_lock_sha256=sha256:<64 lowercase hex>
project_identity_sha256=sha256:<64 lowercase hex>
canonical_test_contract_sha256=sha256:<64 lowercase hex>
native_launcher_contract_sha256=sha256:<64 lowercase hex>
native_binary_contract_sha256=sha256:<64 lowercase hex>
public_key_id=sha256:<64 lowercase hex>
```

The pinned bootstrap writes it only after `validate_runtime`, both successful `validate_test_receipt` calls, agreement between the two receipts, exact native-supplied receipt hashes, and a stable preinventory snapshot. C validates all known fields and retains the remaining current runtime fields.

### Fixed candidate envelope

Mode `0600`, regular, `nlink=1`, exact preflight fields followed by:

```text
child_exit_code=<0 or 120>
terminal_status=<PASS or STOP>
post_inventory_sha256=sha256:<64 lowercase hex>
attestation_sha256=sha256:<64 lowercase hex>
attestation_commitment_sha256=sha256:<64 lowercase hex>
```

C requires exact equality with its invocation/preflight state, the actual waited child exit, the JSON file hash, and the terminal mapping. Pinned semantic replay requires the envelope, JSON, current receipts/runtime, and recomputed report/inventory semantics to agree. Merely writing `{run_id, nonce}`, a marker, or a self-consistent envelope detached from the JSON is insufficient.

---

### Task 1: RED bootstrap and receipt pre-child gates

- [ ] Update synthetic build setup so a bootstrap exists before native compilation and successful live stubs are installed before the build.
- [ ] Add a build-record/public-contract test for exact bootstrap path, SHA-256, size, and mode.
- [ ] Add attacks replacing bootstrap after build, omitting either receipt/sidecar, replaying a sidecar onto different receipt bytes, and modifying `src` or the runner lock after receipts. Require nonzero native exit, no provider-child marker, and no live sidecar.
- [ ] Run only the new node ids and confirm RED occurs because bootstrap/receipt/current-runtime gates do not exist.

### Task 2: GREEN build-pinned bootstrap

- [ ] Safe-read bootstrap in the material builder with nofollow/regular/nlink/mode/size/stable-stat checks.
- [ ] Emit the three C macros, add a strict `bootstrap_anchor` public-record object, and bind its canonical bytes into build id/native binary contract.
- [ ] Extend the C public contract and locked-bootstrap public-contract parser/record validator.
- [ ] Implement safe pinned bootstrap open and `/proc/self/fd/<n>` execution, clearing `FD_CLOEXEC` only in the forked child; re-open/re-hash the pathname after each child.
- [ ] Run Task 1 bootstrap cases to GREEN.

### Task 3: RED native candidate binding and TOCTOU

- [ ] Add a stub that writes only run id/nonce and exits 0; require no sidecar.
- [ ] Add mismatched child exit, terminal status, pre/post inventory, JSON hash, start times, receipt anchors, project/lock anchors, and candidate commitment cases.
- [ ] Add a no-op/replaced semantic bootstrap attack and deterministic semantic-child mutations of bootstrap, receipt, or sidecar before signing. Require no live sidecar and cleanup of unsigned candidate/envelopes.
- [ ] Confirm each case reaches its intended missing comparison rather than failing fixture setup.

### Task 4: GREEN C preflight/candidate state machine

- [ ] Derive canonical receipt/sidecar/preflight/candidate paths from `output_root`; reject overflow or noncanonical paths.
- [ ] Verify both receipt RSA sidecars and capture four stable SHA-256 values before any preflight/provider child.
- [ ] Add the pinned-bootstrap preflight child and strict fixed-line parser; retain run id, nonce, starts, preinventory, runner lock, project identity, canonical contract, native launcher contract, native binary contract, and key id.
- [ ] Pass the retained values to the provider child; parse the candidate envelope and compare actual child exit/terminal/attestation SHA before semantic replay.
- [ ] Re-run pinned semantic verification; then re-verify bootstrap, receipts, sidecars, candidate envelope, JSON hash, and semantic binding immediately before RSA signing. Verify the just-published live sidecar and remove transient envelopes.
- [ ] For kind 5, verify bootstrap + receipt RSA + live RSA before Python, pass four receipt hashes, and repeat all byte/RSA checks afterward.
- [ ] Run Task 3 to GREEN.

### Task 5: RED/GREEN strict Python receipt/runtime anchors

- [ ] Unit-test preflight rejection for nonzero/failed receipts, stale receipt, mismatched focused/full runner/project/native/canonical fields, wrong native-supplied hashes, and modified current project/lock.
- [ ] Add strict launcher-argv tests: duplicate, missing, unknown, relative, malformed hash, and alternate envelope path all fail.
- [ ] Implement one receipt-anchor extractor reused by preflight, execute, semantic replay, and public verify; it must call existing `validate_test_receipt` rather than duplicate weaker receipt semantics.
- [ ] Ensure the preflight snapshot is rechecked before provider creation and all expected anchors are passed into live attestation construction/replay.
- [ ] Run the new Python cases to GREEN.

### Task 6: RED/GREEN public live schema and envelope

- [ ] Extend every `build_live_attestation` fixture with bootstrap, four receipt/sidecar, runner lock, project, canonical contract, and native launcher contract anchors.
- [ ] Require exact schema `3.0` fields and reject removal/tamper/swap of every anchor.
- [ ] Add candidate envelope round-trip plus detached JSON/envelope, malformed ordering/case/newline, and altered commitment attacks.
- [ ] Implement canonical envelope creation/readback and semantic comparison; publish the JSON before the envelope, hash the exact JSON bytes, and require atomic mode-`0600` regular files.
- [ ] Run `tests/generation/test_live_attestation.py` to GREEN.

### Task 7: Native record/lock integration and canonical renewal

- [ ] Upgrade exact native build-record/native launcher-contract field sets for the bootstrap anchor and update all record/lock tests.
- [ ] Run the native receipt, first-case, human-audit, and live-attestation modules; fix only regressions caused by the new contract.
- [ ] Collect exact focused/full node ids with bytecode disabled, update suite count/hash/commitment, rebuild all five synthetic/production launchers, then rebuild the offline venv/runner lock.
- [ ] Run locked runtime probe and generate fresh focused/full RSA receipts in that order. Do not invoke kind 4 against the retained real output.

### Task 8: Final bounded verification and evidence

- [ ] Re-run all bootstrap/receipt/replay/no-op/marker/TOCTOU attack node ids and one synthetic success/STOP/public-verify flow.
- [ ] Run canonical focused and full suites through the native receipt signer and independently verify both RSA sidecars.
- [ ] Run external `compileall` into `/tmp`; prove no bytecode/private PEM/header residue under the project.
- [ ] Confirm the retained real tree still has no live attestation/sidecar and still contains only invocation `6c13551f4faee48adf88c00f5d4eae56-00` with child `120`/transport STOP.
- [ ] Update the final execution record with fresh hashes/receipts and the precise statement that hardening applies only to future live attempts; the historical retained STOP remains unsigned and is never back-signed.

## Completion criteria

1. A post-build bootstrap replacement cannot start Python/provider code and cannot produce a sidecar.
2. Missing, stale, modified, replayed, or semantically noncurrent focused/full receipts fail before provider execution.
3. Current project tree, runner lock, canonical contract, native launcher contract, and native binary key/contract are recovered only through pinned validation of both RSA receipts and agree everywhere.
4. Kind 4 signs only a candidate matching C-generated run metadata, actual child result, preflight preinventory, postinventory, all trust anchors, exact JSON bytes, and pinned semantic replay.
5. Kind 5 verifies live RSA and both receipt RSA anchors before Python, replays the same public anchors, and repeats byte/RSA checks afterward.
6. Marker-only, no-op semantic verifier, sidecar replay, workspace mutation, and pre-sign TOCTOU attacks are all deterministic GREEN negative tests with no live sidecar.
7. Focused/full canonical suites, locked probe, synthetic future live flows, and compileall pass without touching the historical real attempt or running any provider/P0/P1/GPU/training work.

# Ninth-Round Native Signer-Origin Implementation Plan

**Goal:** Make the two pinned static native launchers the only authority that can attest canonical pytest receipts and the first-case hard-gate report, while keeping Python outputs explicitly unsigned candidates.

**Architecture:** One maintenance build generates a 32-byte HMAC-SHA256 key in a mode-`0700` private `/tmp` directory and injects the same key into both freestanding static ELF launchers through a temporary header. The receipt launcher waits for the locked Python child, then signs the resulting JSON sidecar; the verifier validates receipt sidecars and signs the report after `--rerun-tests`, while `verify-only` authenticates all three sidecars before it starts Python. The runner lock binds only the public key id and cross-binary contract, never the key.

**Tech Stack:** freestanding C11/x86_64 Linux syscalls, SHA-256/HMAC-SHA256, POSIX shell, Python 3.12 stdlib, pytest.

**Frozen execution boundary:** Offline only; no network, model, GPU, training, remaining nine P0 cases, P1 cases, or writes under `data/`. The retained execution must end at `STOPPED_AFTER_FIRST_CASE_BEFORE_REMAINING_P0_P1_GPU`.

---

## File map

- `scripts/locked_launcher.c`: native argv validation, SHA-256/HMAC, safe artifact I/O, child lifecycle, sidecar issuance/verification, and public contract output.
- `scripts/rebuild_locked_launchers`: production random-key lifecycle and explicit deterministic synthetic-test build mode.
- `scripts/locked_runtime_bootstrap.py`: runner-lock v6 construction/validation and native public-contract binding.
- `src/egsi/generation/test_receipt.py`: receipt schema v6 unsigned-candidate semantics.
- `src/egsi/generation/first_case_hard_gate.py`: report/verifier schema v4 unsigned-candidate semantics and native contract evidence.
- `src/egsi/generation/human_audit.py`: exact report-tree inventory updated for three attestation sidecars.
- `tests/generation/test_test_receipt.py`: native build/receipt sidecar RED/GREEN tests.
- `tests/generation/test_first_case_hard_gate.py`: reviewer forge, replay, tamper, pre-Python ordering, and report-attestation RED/GREEN tests.
- `tests/generation/test_human_audit.py`: exact-output-set regressions.
- `configs/canonical-test-contract.v1.json`: regenerated exact focused/full node-id contracts after test additions.
- `configs/offline-test-runner.lock.json`: regenerated public v6 runtime lock.
- `.work/real-p0-codex-v2/reports/*.native-attestation`: retained focused/full/report native attestations.
- `idea-stage/implementation-plans/2026-08-30-real-codex-p0-results.md`: ninth-round evidence, hashes, attacks, and STOP state.

## Canonical native attestation v1

Each sidecar is `<artifact>.native-attestation`, mode `0600`, one regular link, and contains exactly these LF-terminated lines:

```text
EGSI-NATIVE-ATTESTATION-V1
domain=<fixed-domain>
artifact=<fixed-basename>
artifact_sha256=<64-lowercase-hex>
native_contract=<64-lowercase-hex>
key_id=<64-lowercase-hex>
tag=<64-lowercase-hex>
```

The HMAC input is the exact byte sequence through the `key_id` newline. Domains are `egsi.test-receipt.focused.v1`, `egsi.test-receipt.full.v1`, and `egsi.first-case-report.v1`. Exact parsing rejects missing, reordered, duplicated, malformed, or unknown lines.

`key_id = SHA256(shared_key)`. The runtime binary contract is:

```text
SHA256(
  b"EGSI_NATIVE_BINARY_CONTRACT_V1\0" ||
  key_id_raw ||
  SHA256(scripts/run_test_receipt)_raw ||
  SHA256(scripts/verify_first_case_hard_gate)_raw
)
```

Both binaries expose only the following exact public output for singleton `--native-public-contract` and do not start Python:

```text
EGSI_NATIVE_ATTESTATION_VERSION=1
EGSI_NATIVE_KEY_ID=sha256:<64-lowercase-hex>
EGSI_NATIVE_BINARY_CONTRACT=sha256:<64-lowercase-hex>
```

## Task 1: RED native build and receipt-origin tests

- [ ] Add a synthetic build test that invokes `scripts/rebuild_locked_launchers --synthetic-output-dir <absolute-dir> --test-key-hex <64hex>`, confirms no key/header is left in the project or `/tmp` build directory, confirms same-key rebuilds are byte-identical, and confirms a different key changes both binaries.
- [ ] Add native public-contract tests requiring equal three-line output from both binaries and rejecting a copied production launcher before Python execution.
- [ ] Add a receipt test proving direct `run_test_receipt()` yields `native_attested: false` and no sidecar, while the official native launcher yields a valid mode-`0600`, `nlink=1` sidecar only after child success.
- [ ] Run the new selections and record expected failures due to absent synthetic mode, absent public-contract mode, and absent sidecars.

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q \
  tests/generation/test_test_receipt.py -k 'native_attestation or synthetic_native_build or signer_origin'
```

## Task 2: GREEN shared-key native implementation

- [ ] Extend the build script with exact production/synthetic parsing, `umask 077`, a private `mktemp -d` directory, a single 32-byte random production key from `/dev/urandom`, a singleton explicit synthetic test key, a generated private header, a trap, immediate header/directory deletion after both compiles, ELF validation, and atomic installation.
- [ ] Implement freestanding SHA-256 and HMAC-SHA256 with known-answer self-tests exercised by synthetic native tests.
- [ ] Add bounded regular-file reads using `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, `fstat` identity checks, link/mode/size checks, and exact full reads.
- [ ] Replace direct `execve` with `fork`/`wait4`; preserve the exact isolated child argv/environment and propagate nonzero child status.
- [ ] Implement receipt-sidecar removal before child execution, post-success candidate hashing/signing, mode-`0600` exclusive temporary publication, file/directory `fsync`, and fail-closed cleanup.
- [ ] Implement constant-time exact sidecar verification, canonical artifact/domain binding, public-contract output, and cross-binary contract calculation.
- [ ] Rebuild production launchers once, rerun Task 1 selections, and retain only GREEN evidence.

## Task 3: RED verifier pre-Python and forge tests

- [ ] Forge exact-count focused/full candidate JSON (`369`/`824`) and exact `37`-gate report JSON through direct imports plus patched runtime markers/subprocess; require official verify-only to reject them when native sidecars are missing.
- [ ] Starting from real native-attested artifacts, test copied sidecar replay onto forged artifact bytes, tag nibble tamper, key-id tamper, artifact/path tamper, unknown extra line, focused/full sidecar swap, report/receipt swap, and a stale sidecar after a new production-key rebuild.
- [ ] Add a pre-Python ordering test whose Python bootstrap would create a marker; invalid/missing sidecars must reject without creating the marker.
- [ ] Run only the added reviewer/native selections and record expected RED failures caused by the current verifier starting Python without native authentication.

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q \
  tests/generation/test_first_case_hard_gate.py \
  -k 'native_attestation or reviewer_forge or pre_python or sidecar'
```

## Task 4: GREEN verifier sidecar workflow

- [ ] Require exact canonical native CLI artifact paths under `<output-root>/reports/`: `offline-focused-receipt.json`, `offline-full-receipt.json`, and `first-case-hard-gate.json`; reject lexical aliases and unsafe directory/file nodes.
- [ ] In `--rerun-tests`, remove the prior report sidecar, wait for Python, verify both receipt sidecars against the current key/contract, verify the report candidate path and bytes, then issue the report sidecar.
- [ ] In `--mode verify-only`, verify focused, full, and report sidecars before `fork`/`execve`; only then run Python semantic replay, performing no writes.
- [ ] Emit `EGSI_NATIVE_ATTESTED=receipt` or `EGSI_NATIVE_ATTESTED=report` only after successful native publication; never emit key bytes.
- [ ] Rerun Task 3 selections to GREEN.

## Task 5: Upgrade public Python/lock contracts

- [ ] Upgrade the runner lock to schema `6.0` / `offline-pytest-runner-v6` and native contract schema `2.0`.
- [ ] Have the stdlib bootstrap execute both launchers with singleton `--native-public-contract`, require byte-identical exact output, and bind `attestation_version`, `attestation_key_id`, and `binary_contract_sha256` into the native launcher contract.
- [ ] Upgrade receipt schema to `6.0` with required exact field `native_attested: false`; keep Python validation semantic and explicitly candidate-only.
- [ ] Upgrade first-case report/verifier schema to `4.0`, require `native_attested: false`, bind native contract v2 evidence, and preserve all 37 semantic hard gates.
- [ ] Update tests and synthetic fixtures for the exact schemas without weakening strict field-set validation.
- [ ] Bootstrap the offline runner so installed source equals source tree and rebuild the v6 lock.

Commands:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/bootstrap_offline_test_runner.py --root /home/furina/iclr
PYTHONDONTWRITEBYTECODE=1 pytest -q tests/generation/test_test_receipt.py
PYTHONDONTWRITEBYTECODE=1 pytest -q tests/generation/test_first_case_hard_gate.py
```

## Task 6: Exact output-tree and human-audit binding

- [ ] Update exact report inventory/validation so the retained output permits exactly the three named native-attestation files and rejects missing, extra, symlinked, hardlinked, non-`0600`, or unknown sidecars.
- [ ] Bind sidecar file hashes/public contract identifiers into existing reproducibility evidence where the schema requires evidence summaries; do not copy the secret or HMAC tag into logs/documentation.
- [ ] Add and run human-audit exact-set regressions.

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q tests/generation/test_human_audit.py
```

## Task 7: Canonical contract renewal and bounded full verification

- [ ] Collect exact nodeids for focused and full suites through the locked runtime, update only counts/nodeids/hashes/commitment in `configs/canonical-test-contract.v1.json`, then rebuild the lock.
- [ ] Run native launcher attack selections, receipt module, first-case module, human-audit module, canonical focused, and canonical full. Do not run excluded experiments.
- [ ] Confirm no source/project bytecode files exist.

Commands:

```bash
find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -o -type d -name __pycache__
scripts/run_test_receipt --name focused --output /tmp/round9-focused.json
scripts/run_test_receipt --name full --output /tmp/round9-full.json
```

## Task 8: Final random-key rebuild, retained resigning, and zero-write replay

- [ ] Perform a final production rebuild with a fresh random key, rebuild the offline runner lock, then run the retained verifier with `--rerun-tests` so all three retained sidecars are signed by the final binaries.
- [ ] Assert each retained sidecar is regular, `0600`, `nlink=1`, exact canonical text, and matches the final public key id/binary contract.
- [ ] Snapshot the complete retained output tree, run a fresh native `verify-only`, and prove byte/metadata identity with the post-run snapshot; expected entry count is the observed final count, initially estimated as `176`.
- [ ] Run external `compileall` into `/tmp`, hash final lock/native contract/receipts/sidecars/report, and update the experiment record with exact commands/results and the unchanged STOP marker.

Retained commands:

```bash
scripts/verify_first_case_hard_gate \
  --output-root /home/furina/iclr/.work/real-p0-codex-v2 \
  --case-id p0-01 \
  --focused-receipt /home/furina/iclr/.work/real-p0-codex-v2/reports/offline-focused-receipt.json \
  --full-receipt /home/furina/iclr/.work/real-p0-codex-v2/reports/offline-full-receipt.json \
  --report /home/furina/iclr/.work/real-p0-codex-v2/reports/first-case-hard-gate.json \
  --rerun-tests

scripts/verify_first_case_hard_gate \
  --output-root /home/furina/iclr/.work/real-p0-codex-v2 \
  --case-id p0-01 \
  --focused-receipt /home/furina/iclr/.work/real-p0-codex-v2/reports/offline-focused-receipt.json \
  --full-receipt /home/furina/iclr/.work/real-p0-codex-v2/reports/offline-full-receipt.json \
  --report /home/furina/iclr/.work/real-p0-codex-v2/reports/first-case-hard-gate.json \
  --mode verify-only
```

## Completion criteria

1. Direct Python import/patch paths can produce only strict unsigned candidates and cannot make official verify-only accept them.
2. Missing/replayed/tampered/path-swapped/key-id/unknown-field/stale sidecars fail before Python in verify-only.
3. Production builds use a fresh shared random key; deterministic builds require an explicit synthetic output directory and explicit test key.
4. No raw key/header is present in source, lock JSON, logs, retained reports, or project files.
5. Both static ELF launchers remain x86_64 `ET_EXEC` with no libc, `PT_INTERP`, `PT_DYNAMIC`, or `DT_NEEDED`.
6. All bounded module/canonical/retained checks have fresh zero-failure evidence, verify-only is zero-write, external compileall succeeds, and the STOP marker is unchanged.

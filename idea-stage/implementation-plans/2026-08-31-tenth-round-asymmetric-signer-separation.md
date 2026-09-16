# Tenth-Round Asymmetric Signer Separation Implementation Plan

> **For agentic workers:** Execute this plan inline with `superpowers:test-driven-development`; sub-agent execution is explicitly disabled for this round.

**Goal:** Replace the recoverable shared HMAC authority with RSA-2048/SHA-256 PKCS#1 v1.5 signatures and split receipt signing, report signing, and public verification into three least-privilege native entry points.

**Architecture:** A maintenance-only build creates or loads one RSA-2048 keypair in a mode-`0700` temporary directory. Only the two static signer ELFs receive the private exponent and are installed execute-only (`0111`); the readable verifier receives only the public modulus/exponent. A public build record binds the public key, build identifier, build-time signer hashes, final opaque signer metadata, verifier hash, toolchain, and source identities. The locked Python runtime validates that record and signer metadata without opening the execute-only files.

**Tech Stack:** freestanding C11/x86_64 Linux syscalls, RSA-2048 Montgomery arithmetic, SHA-256, PKCS#1 v1.5, Python 3.12, `cryptography` 50.0.0 for maintenance/test oracle work, POSIX shell, pytest.

**Frozen execution boundary:** Offline only; no network, model calls, GPU, training, remaining nine P0 cases, P1 cases, or writes under `data/`. The retained run must stop at `STOPPED_AFTER_FIRST_CASE_BEFORE_REMAINING_P0_P1_GPU`.

---

## File map

- `scripts/locked_launcher.c`: three native roles, early signer hardening, RSA sign/verify, exact sidecar handling, safe child execution, and strict role-specific argv.
- `scripts/build_native_rsa_material.py`: maintenance-only RSA generation/loading, C-header emission, public-key encoding, and canonical build-record creation.
- `scripts/rebuild_locked_launchers`: private lifecycle, three static compiles, ELF checks, per-file atomic installation, execute-only/read-only modes, and residue cleanup.
- `configs/native-signer-build-record.json`: public build record; it never contains `d`, `p`, `q`, CRT values, PEM, or private-key bytes.
- `scripts/locked_runtime_bootstrap.py`: runner-lock v7, native contract v3, opaque signer inventory, build-record validation, and split bootstrap modes.
- `src/egsi/generation/test_receipt.py`: receipt schema v7 and unsigned-candidate semantics.
- `src/egsi/generation/first_case_hard_gate.py`: report schema v5, native contract v3 evidence, and internal rerun/verify candidate semantics.
- `tests/generation/test_test_receipt.py`: build, permissions, private-residue, hardening, RSA-oracle, metadata, and receipt-signer tests.
- `tests/generation/test_first_case_hard_gate.py`: public verifier separation plus forge/tamper/replay/stale-key/oracle tests.
- `tests/generation/test_human_audit.py`: exact retained-tree and sidecar regressions.
- `configs/canonical-test-contract.v1.json`: renewed exact focused/full node-id commitments.
- `configs/offline-test-runner.lock.json`: regenerated schema-v7 runtime lock.
- `.work/real-p0-codex-v2/reports/*.native-attestation`: final RSA-attested retained sidecars.
- `idea-stage/implementation-plans/2026-08-30-real-codex-p0-results.md`: tenth-round commands, evidence, hashes, limits, and unchanged STOP state.

## Canonical asymmetric attestation v2

Each `<artifact>.native-attestation` is one regular mode-`0600`, `nlink=1` file with these exact LF-terminated lines:

```text
EGSI-NATIVE-ATTESTATION-V2
algorithm=rsa-2048-sha256-pkcs1-v1_5
domain=<fixed-domain>
artifact=<fixed-basename>
artifact_sha256=<64-lowercase-hex>
native_contract=<64-lowercase-hex>
key_id=<64-lowercase-hex>
signature=<512-lowercase-hex>
```

The signature input is the exact ASCII byte sequence through the `key_id` newline. The signer computes SHA-256 over those bytes and applies RSASSA-PKCS1-v1_5 with the standard SHA-256 `DigestInfo` prefix `3031300d060960864801650304020105000420`. Verification reconstructs the exact encoded message and rejects non-canonical/missing/extra/reordered fields before Python starts.

`key_id` is SHA-256 of the DER SubjectPublicKeyInfo. A deterministic 32-byte build id is derived from the public key, launcher source digest, absolute root, and contract domain. The native binary contract is:

```text
SHA256(
  b"EGSI_NATIVE_BINARY_CONTRACT_V2\0" ||
  key_id_raw ||
  build_id_raw ||
  b"rsa-2048-sha256-pkcs1-v1_5\0"
)
```

The build record separately binds the exact build-time hashes and final metadata of both execute-only signers. This avoids an impossible self-hash dependency while still making chmod, replacement, inode, ctime, link-count, size, or stale-build changes fail the locked runtime.

## Public build record and privilege split

The build record contains exact fields for schema/algorithm/version, SPKI DER, modulus, exponent, key id, build id, native contract, source/build/helper/compiler identities, compiler flags, signer build hashes and opaque installed identities, verifier hash/identity, and `record_commitment_sha256`. It contains no private RSA material.

Installed entry points are:

```text
scripts/run_test_receipt              0111  receipt signer
scripts/rerun_first_case_hard_gate    0111  report signer
scripts/verify_first_case_hard_gate   0555  public-key-only verifier
```

Both signers execute `prctl(PR_SET_DUMPABLE, 0)` first, set soft/hard `RLIMIT_CORE` to zero, parse `/proc/self/status`, and reject nonzero `TracerPid`. These are defense-in-depth controls for the same unprivileged user; the contract does not claim resistance to root, kernel compromise, a debugger attached before the first instruction, or offline privileged filesystem acquisition. Production recommendations remain TPM/HSM/remote signer custody.

---

### Task 1: RED asymmetric build and privilege tests

- [ ] Replace HMAC test fixtures with one test-session RSA-2048 PEM generated once by `cryptography` under pytest's private temporary directory; pass it only through explicit synthetic build arguments and reuse it wherever deterministic same-key behavior is required.
- [ ] Add failing tests requiring three ELFs, signer modes `0111`, verifier mode `0555`, a public build record, no project/private-header residue, no public-verifier private exponent bytes, and `open/read/copy` denial for signers.
- [ ] Add failing tests requiring the public verifier to reject `--rerun-tests` without starting Python and requiring the new rerun signer to accept only `--rerun-tests`.
- [ ] Run the focused selections and confirm failures are caused by the absent third launcher/asymmetric build, not fixture errors.

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q tests/generation/test_test_receipt.py \
  -k 'asymmetric or rsa or execute_only or signer_separation'
PYTHONDONTWRITEBYTECODE=1 pytest -q tests/generation/test_first_case_hard_gate.py \
  -k 'public_verifier or rerun_signer or asymmetric'
```

### Task 2: GREEN RSA material builder and three-ELF installation

- [ ] Implement strict CLI parsing in `build_native_rsa_material.py`: production generation or an absolute synthetic PEM path, never both; require RSA-2048 and exponent 65537.
- [ ] Emit a signer-only header containing `n`, `R^2 mod n`, Montgomery `-n^-1 mod 2^32`, and `d`; emit a public header with the same public values but no private exponent.
- [ ] Derive SPKI key id/build id/native contract, emit canonical public material JSON, and zero/delete private temporary files after both signer compiles.
- [ ] Compile role 1/2 signers, hash them before mode removal, compile role 3 with only the public header, validate all three as static `ET_EXEC` x86_64 ELFs, install with `0111/0111/0555`, and write the public build record last.
- [ ] Rerun Task 1 to GREEN and inspect the readable verifier/build record for private residue.

### Task 3: RED RSA oracle, signer-hardening, and v2 sidecar tests

- [ ] Require a C signer sidecar signature to verify through `cryptography` using the build-record SPKI key and exact v2 preimage.
- [ ] Require three cryptography-produced signatures to pass native public verification far enough to reach a deliberate Python marker/exit, proving the C verifier accepts an independent oracle.
- [ ] Add signer security-state and traced-exec tests for dumpable/core/tracer enforcement.
- [ ] Add malformed algorithm, random 512-hex signature, old-key signature, single-nibble signature tamper, non-canonical signature length/case, and old HMAC-v1 sidecar failures.
- [ ] Run and observe failures caused by missing RSA/signing/hardening behavior.

### Task 4: GREEN freestanding RSA and exact v2 workflow

- [ ] Implement bounded 64-limb little-endian arithmetic, Montgomery multiplication/reduction, constant-time encoded-message comparison, private exponentiation for roles 1/2, and fixed-65537 public exponentiation for role 3.
- [ ] Implement exact SHA-256 `DigestInfo` padding and fixed 256-byte signature conversion; reject signature representatives outside the modulus.
- [ ] Split canonical preimage construction from signature publication/verification so the public verifier never references the private exponent.
- [ ] Preserve safe `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` artifact/sidecar reads, before/after identity checks, exclusive temporary publication, `fsync`, and fail-closed cleanup.
- [ ] Run Task 3 to GREEN, including both cryptography oracle directions.

### Task 5: RED signer metadata and key-extraction attacks

- [ ] Snapshot signer mode/device/inode/nlink/uid/gid/size/mtime/ctime from the public record and require official rerun/verify to reject every changed field.
- [ ] Test chmod-to-readable key extraction followed by chmod-back: copied signer bytes may be inspected in the synthetic case, but permanent ctime mismatch must invalidate the locked runtime.
- [ ] Test replacement with same-size bytes, hardlink/link-count changes, inode replacement, signer swap, stale build record, and record commitment/public-key tamper.
- [ ] Require normal lock building/validation to avoid opening the execute-only signers; monkeypatch `os.open` to fail if it tries.
- [ ] Observe the expected RED failures from the current project inventory and native contract readers.

### Task 6: GREEN runner lock v7 and opaque build-record binding

- [ ] Upgrade to runner schema `7.0`, `offline-pytest-runner-v7`, and native launcher contract schema `3.0`.
- [ ] Validate the build record with duplicate-key/finite-number rejection, exact field sets, commitment, public contract, and source/tool identities.
- [ ] Teach project inventory to represent only the two signer paths as opaque regular files: use record-supplied build SHA plus exact live metadata, never `open`, read, hash, or temporary chmod.
- [ ] Keep the verifier fully readable/hashable and validate all three final metadata identities against the build record before locked site code imports.
- [ ] Split bootstrap modes into `run-test-receipt`, `rerun-first-case`, and `verify-first-case`; the public mode accepts only `--mode verify-only`.
- [ ] Rerun Task 5 to GREEN and regenerate the offline runner installation/lock.

### Task 7: Python candidate schemas and report-tree binding

- [ ] Upgrade receipt schema to `7.0`; retain the exact required `native_attested: false` field and candidate-only validation.
- [ ] Upgrade report schema/verifier to `5.0`; retain `native_attested: false`, `attestation_mode: rerun_tests`, all 37 hard gates, and native contract v3 evidence.
- [ ] Change official receipt launcher checks to mode `0111` and route native report regeneration only through `scripts/rerun_first_case_hard_gate`.
- [ ] Update exact report-tree inventory and tests for the same three v2 sidecars without adding any private/signature material to JSON reports.
- [ ] Run the complete three generation modules and preserve all failures until fixed.

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q tests/generation/test_test_receipt.py
PYTHONDONTWRITEBYTECODE=1 pytest -q tests/generation/test_first_case_hard_gate.py
PYTHONDONTWRITEBYTECODE=1 pytest -q tests/generation/test_human_audit.py
```

### Task 8: Canonical renewal and bounded verification

- [ ] Collect exact focused/full node ids only through the locked runtime, update canonical counts/hashes/commitment, and rebuild the v7 lock.
- [ ] Run asymmetric attack selections, receipt module, first-case module, human-audit module, canonical focused, and canonical full; do not run excluded P0/P1/GPU work.
- [ ] Confirm no bytecode under `src/tests/scripts/configs/idea-stage` and no PEM/private header/private exponent file anywhere in the project.

### Task 9: Final random-key rebuild and retained resigning

- [ ] Perform one final production random RSA rebuild, reinstall the locked project, rebuild the lock, and make no further identity-bound edits before retained execution.
- [ ] Run `scripts/rerun_first_case_hard_gate --rerun-tests` once to regenerate/sign focused, full, and report candidates.
- [ ] Run public `scripts/verify_first_case_hard_gate --mode verify-only`, snapshot before/after all retained entries, and prove zero byte/metadata writes.
- [ ] Run external `compileall` into `/tmp`, record final ELF/mode/hash/public-key/build-record/canonical/receipt/sidecar/report evidence, and preserve the STOP marker.

## Completion criteria

1. A direct Python caller can create only `native_attested=false` candidates; no Python path holds native signing authority.
2. Only the two execute-only signer ELFs contain `d`; the verifier and public build record contain only `n/e` and public metadata.
3. The public verifier cannot rerun tests or issue a report sidecar; the report signer is the sole native report issuer.
4. C-to-cryptography and cryptography-to-C RSA oracle checks pass with exact PKCS#1 v1.5/SHA-256 semantics.
5. HMAC-v1, random, malformed, replayed, swapped, stale-key, and tampered sidecars fail before semantic Python verification.
6. Signer open/read/copy fail at `0111`; any chmod/replacement/inode/ctime/nlink/size change makes official locked paths fail without temporary chmod.
7. Signers are non-dumpable, core-disabled, and reject nonzero `TracerPid`; limits against root/kernel/pre-main debugging are recorded without overclaiming.
8. All bounded modules/canonical/retained checks pass, verify-only is zero-write, external compileall succeeds, and the STOP marker remains unchanged.

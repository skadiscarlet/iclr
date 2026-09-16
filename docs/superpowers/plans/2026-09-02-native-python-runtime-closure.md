# Native Python Runtime Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind every native-launched Python child to a hashed interpreter,
dynamic loader, and recursive ELF dependency closure using held descriptors.

**Architecture:** A bounded Python ELF parser generates one canonical runtime
contract and C initializers. The static launcher opens and continuously checks
that contract, invokes the held loader with held dependency preloads, and
fail-closes at all child and publication boundaries. Bootstrap rebuilds native
artifacts before finalizing the runtime lock.

**Tech Stack:** Python 3 stdlib, ELF64 parsing with `struct`, freestanding
x86_64 Linux C/syscalls, glibc `ld-linux --argv0 --preload`, pytest.

---

### Task 1: RED build-contract tests

**Files:**
- Modify: `tests/generation/test_test_receipt.py`

- [ ] Add a regular interpreter-copy helper for synthetic native roots.
- [ ] Add build rejection tests for symlink, hardlink, group/other-writable,
  missing, malformed ELF, duplicate dependency, and bounded-closure failures.
- [ ] Add assertions for interpreter fields, recursive runtime files, closure
  commitment, and extended public-contract output.
- [ ] Run the new nodeids with
  `PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` and confirm they
  fail because `python_runtime` is absent or unsafe inputs are accepted.

### Task 2: Build-time ELF closure and generated contract

**Files:**
- Modify: `scripts/build_native_rsa_material.py`
- Modify: `scripts/rebuild_locked_launchers`

- [ ] Implement bounded safe reads and ELF64 `PT_INTERP`/`DT_NEEDED`/
  `RUNPATH` parsing.
- [ ] Implement deterministic recursive resolution with strict path, mode,
  link, cycle, count, byte, and depth checks.
- [ ] Commit the canonical closure into build/contract hashes and emit C
  runtime-entry initializers plus public material/build-record fields.
- [ ] Run Task 1 tests and confirm green.

### Task 3: RED launcher attack tests

**Files:**
- Modify: `tests/generation/test_test_receipt.py`

- [ ] Add kind-4 and kind-5 pre-start interpreter replacement tests.
- [ ] Add same-inode mutation and interpreter file ABA tests.
- [ ] Add runtime-parent/ancestor swap and loader/libpython replacement tests.
- [ ] Assert kind 4 leaves no sidecar/candidate and kind 5 returns nonzero.
- [ ] Add the malicious-shebang forgery regression assertion.
- [ ] Run the new nodeids and confirm expected failures against pathname
  `execve(python_path, ...)`.

### Task 4: Native held runtime and boundary checks

**Files:**
- Modify: `scripts/locked_launcher.c`

- [ ] Add compiled runtime-entry structures, held anchors, and bounded unique
  parent directory chains.
- [ ] Open and verify all entries before the first child.
- [ ] Build held loader/interpreter/preload argv and clear CLOEXEC only for the
  exact inherited descriptors.
- [ ] Replace every Python pathname exec with the shared pinned runtime helper.
- [ ] Check the runtime before/after every child, after semantic verification,
  before/after publication, and before kind-5 success.
- [ ] Route every mismatch through existing cleanup and nonzero paths.
- [ ] Run Task 3 tests and confirm green.

### Task 5: Public/runner contracts and transactional bootstrap

**Files:**
- Modify: `scripts/locked_runtime_bootstrap.py`
- Modify: `scripts/bootstrap_offline_test_runner.py`
- Modify: `tests/generation/test_test_receipt.py`

- [ ] Extend native build-record and launcher-contract schemas with the exact
  `python_runtime` value and public output fields.
- [ ] Re-read every runtime entry and compare its current stable identity.
- [ ] Update native/runner schema versions and commitments.
- [ ] Reorder bootstrap to runner swap → native rebuild → lock → probe with
  inode-preserving rollback of launchers and build record.
- [ ] Update fixtures from symlink interpreters to regular copies.
- [ ] Run focused runtime/bootstrap tests and confirm green.

### Task 6: Production rebuild and complete verification

**Files:**
- Regenerate: `configs/native-signer-build-record.json`
- Regenerate: `configs/offline-test-runner.lock.json`
- Regenerate: five native launchers under `scripts/`

- [ ] Run focused native tests.
- [ ] Run broader generation tests, then the full allowed suite.
- [ ] Bootstrap/rebuild the production runner transactionally.
- [ ] Re-run the historical exploit and verify no accepted sidecar/result.
- [ ] Run public-contract, locked probe, receipt, RSA, residue, retained-state,
  document, and final-state checks allowed by the task constraints.
- [ ] Record final hashes and terminal state. No provider, real kind-4 attempt,
  remaining P0/P1, GPU, training, trajectory, or data-generation action.


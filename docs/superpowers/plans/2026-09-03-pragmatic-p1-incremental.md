# Pragmatic P1 Incremental Aggregation Implementation Plan

**Goal:** Add an offline, additive P1 aggregator that preserves the verified
ten-case P0 package byte-for-byte and combines it with a strict twenty-case
live pragmatic delta in the original interleaved P1 order.

**Architecture:** Keep `build-training-ready` unchanged. A new
`incremental_training_ready` boundary independently validates the complete P0
package and live incremental control plane, copies verified P0 artifacts,
compiles only accepted new records, and emits a new 30-case report/manifest
family. Source/output overlap is rejected before locking or writing.

**Tech stack:** Python 3.11+, Pydantic v2 strict models, Typer, existing
anchored safe I/O, pragmatic state/provenance validators, T1 compiler/replay,
PyArrow Parquet, pytest.

## Task 1: Frozen incremental case list

**Files:**
- Create `configs/p1_pragmatic_incremental_cases.txt`
- Create `tests/generation/test_incremental_training_ready.py`

- [x] Assert the list is exactly ordered `P1 - P0`.
- [x] Assert 20 unique train cases, disjoint from P0, with union equal to P1.
- [x] Capture RED from the initially missing list and module.

## Task 2: Strict base-package validation

**Files:**
- Create `src/egsi/generation/incremental_training_ready.py`
- Extend `tests/generation/test_incremental_training_ready.py`

- [x] Reject every bidirectional source/output overlap before a lock/write.
- [x] Strict-parse P0 coverage, trajectory, audit, artifact manifest, and
  sidecar; require exactly 10/10 success in frozen P0 order.
- [x] Recompute manifest/artifact hashes, constrain the complete file
  inventory, and reject unsafe or ambiguous files.
- [x] Strict-parse base records and JSONL, bind case/episode identities,
  replay every episode closed, and require base Parquet to equal ordered JSONL.
- [x] Preserve base enrichment/event/transition bytes and embed upstream
  coverage lineage plus the base-manifest SHA in P1 coverage.
- [x] Cover artifact, sidecar, Parquet, and replay tampering with systemic
  fail-closed tests.

## Task 3: Live incremental validation and aggregation

**Files:**
- Continue `src/egsi/generation/incremental_training_ready.py`
- Continue `tests/generation/test_incremental_training_ready.py`

- [x] Require a complete strict pragmatic state/report/provenance plane with
  generation mode `live` and the exact 20 incremental IDs.
- [x] Reuse current per-record/quarantine/failure validation without relaxing
  the legacy `build-training-ready` path.
- [x] Map valid terminal failures to `failed`; map missing/invalid per-case
  records or compile failures to explicit `gap` entries.
- [x] Compile/replay new T1 episodes transactionally and reject episode/path
  collisions.
- [x] Rewrite a deterministic Parquet over all successful transitions in
  original 30-case P1 order.
- [x] Emit P1 coverage, trajectory, human-audit JSON/Markdown, artifact
  manifest with sizes/hashes, and SHA sidecar.
- [x] Prove mixed conservation, no residual compile artifacts, zero aggregation
  teacher calls, byte-identical P0 imports, Parquet/JSONL equality, and
  byte-idempotent rebuilds.

## Task 4: Additive CLI and operations

**Files:**
- Modify `src/egsi/cli.py`
- Modify `tests/integration/test_cli_pilot.py`
- Create `docs/PRAGMATIC_P1_RUNBOOK.md`

- [x] Add only `build-incremental-training-ready` with the fixed six flags.
- [x] Test exact argument wiring and retain the legacy command/default route.
- [x] Document the authorized live command, identical resume command, 40-slot
  ceiling, retry override 0, timeout 600, wall clock 28800, and offline
  aggregation command.
- [x] Explicitly forbid old fixture roots, dev/test cases, GPU, and training in
  this workflow.

## Task 5: Verification closure

- [x] Initial RED: missing list, module, and CLI command produced three focused
  failures for the intended reasons.
- [x] Incremental focused tests, including two synthetic 20-case offline live
  wrappers, pass without external provider calls.
- [ ] Run pragmatic/training-ready/CLI focused regression with pytest cache and
  bytecode disabled.
- [ ] Run the canonical offline suite and record the final count.
- [ ] AST-parse modified Python and confirm no `.pyc`/`__pycache__` residue.

## Fixed execution boundary

Implementation and tests are offline. They do not invoke a live provider,
write either P0 source root, create `.work/real-p1-pragmatic-v1`, launch a GPU,
or start training. `.git` is an unavailable read-only placeholder, so commit
steps are inapplicable in this workspace.

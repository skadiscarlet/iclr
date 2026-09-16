# Context V2 Canonical Fallback Completion Record

Date: 2026-08-30  
Stage: prototype development and experiment  
Decision: **ENGINEERING GATE PASSED; FIXTURE ARTIFACTS REMAIN NON-PROMOTABLE**

## Scope

This change closes the deterministic teacher-context preparation gate without
editing `data/` and without relaxing the strict patch parser. The 27 upstream
raw patch artifacts whose hunk counts are structurally damaged are retained and
committed exactly as collected. Recovery uses a bounded canonical diff generated
from the manifest-pinned vulnerable/fixed commits in the already validated bare
Git cache; that generated diff must pass the same strict parser.

No live teacher/model was invoked. This record is an engineering and fixture
validation result, not a paper result or a claim about vulnerability detection
performance.

## Implemented controls

- Added `GitObjectStore.canonical_diff(old_commit, new_commit)` with exact
  lowercase 40-hex commit validation and commit-object checks.
- Fixed argv: `git diff --no-ext-diff --no-textconv --binary --full-index
  --no-color OLD NEW --`; no `shell=True`, user revision expression or pathspec.
- Existing sanitized Git environment remains mandatory: inherited `GIT_*`
  redirects removed; replace objects, lazy fetch, optional locks, global/system
  config, external diff and textconv disabled; `LC_ALL`/`LANG` are fixed to `C`.
- Each fallback runs its commit probes and diff in a new mode-`0700` minimal bare
  shell with constant `config` / `HEAD`, empty local object storage, and only a
  controlled `GIT_ALTERNATE_OBJECT_DIRECTORIES` pointer to the resolved original
  object store. The one alternate path is C-style quoted as a Git path-list
  entry, including separators, quotes, controls, and backslashes. The original
  bare repository local config and `include.path` cannot affect the canonical
  bytes, and no `data/` content is copied or changed.
- Ambient user/system attributes are excluded with constant
  `core.attributesFile=/dev/null` and `GIT_ATTR_NOSYSTEM=1`; pinned-commit
  `.gitattributes` semantics remain active.
- Stdout is bounded to 2 MiB under one deadline with bounded reader,
  terminate/kill/reap behavior; every Git process starts a dedicated process
  group, and timeout/overflow/read failure performs group `SIGTERM`, a short
  fixed grace, group `SIGKILL`, bounded parent wait, stdout close, and reader
  join. Cleanup contains no unbounded `communicate()` / `wait()` / `join()`.
  Reader construction/allocation and thread-start exceptions after successful
  `Popen` enter the same `finally` cleanup; explicit `reader_started` and
  `process_reaped` state prevents joining an unstarted thread or double-reaping.
  The strict parser separately enforces a 64 KiB line limit.
- Fallback is called only after the safely read raw patch fails strict parsing.
  Valid raw patches never invoke it. Malformed/oversized canonical output,
  timeout, nonzero exit, missing/non-commit fixed OID, or manifest/catalog
  mismatch fails closed.
- `SelectionReceipt` is schema `1.1`; it preserves raw patch SHA-256/byte count
  and adds `effective_patch_source`, effective patch SHA-256/byte count. Bounded
  patch evidence is derived from the effective patch. Receipt commitment remains
  part of the canonical context hash, so pre-change contexts/prompts/caches do
  not silently reuse.
- Added library validator and `egsi validate-contexts`; reports use the existing
  safe atomic report writer and contain only stable failure categories/case IDs.
- Validator `built` / `failed` counts are mutually exclusive: a case is built
  only when every repetition succeeds, failed when any repetition fails, and
  `requested = built + failed`. Every pair of successful snapshots is compared
  even when another repetition failed.

## TDD evidence

Baseline before implementation:

- `.work/context-v2-task2/baseline-tests.txt`: `503 passed in 44.18s`.

Recorded RED evidence:

- `.work/context-v2-task2/red-01-canonical-diff.txt`: missing canonical diff API,
  6 expected failures.
- `.work/context-v2-task2/red-02-fallback-receipt.txt`: missing fallback and
  receipt 1.1 behaviors, 5 expected failures.
- `.work/context-v2-task2/red-03-validator.txt`: validator module absent.
- `.work/context-v2-task2/red-04-cli.txt`: CLI command absent, 4 expected
  failures.
- `.work/context-v2-task2/red-08-library-export.txt`: public library export
  absent, 1 expected failure.
- `.work/context-v2-task2/red-09-commit-probe-bound.txt`: unbounded commit-type
  probe exceeded the deadline target, 1 expected failure.
- `.work/context-v2-task2/red-11-git-locale.txt`: caller locale still affected
  Git output, 1 expected failure.
- `.work/context-v2-task2/red-12-local-config-isolation.txt`: an included local
  config setting `diff.context=0` and `diff.noprefix=true` changed canonical
  bytes, 1 expected failure.
- `.work/context-v2-task2/red-13-process-group-deadline.txt`: stdout-inheriting
  grandchildren kept metadata/diff pipes open for 2.051 s / 1.093 s beyond the
  configured deadline, 2 expected failures; tests forcibly killed descendants
  in `finally` during RED.
- `.work/context-v2-task2/red-14-attributes-and-alternate-path.txt`: ambient XDG
  attributes changed a text diff into a binary patch, and a valid object-store
  path containing `:` plus `"` was split by the alternate path list, 2 expected
  failures.
- `.work/context-v2-task2/red-15-reader-lifecycle-cleanup.txt`: injected reader
  construction `MemoryError` and thread-start `RuntimeError` left the process
  group unsignalled, stdout open, and parent unreaped, 2 expected failures.
- `.work/context-v2-task2/red-16-validator-repeat-accounting.txt`: with three
  repetitions (success, failure, changed success), `built` incorrectly remained
  300 and the partial-success hash mismatch was omitted, 1 expected failure.

Corresponding GREEN evidence:

- `.work/context-v2-task2/green-01b-canonical-diff.txt`: 6 passed.
- `.work/context-v2-task2/green-02-fallback-receipt.txt`: 5 passed.
- `.work/context-v2-task2/green-03-validator.txt`: 3 passed.
- `.work/context-v2-task2/green-04-cli.txt`: 4 passed.
- `.work/context-v2-task2/green-05-fallback-failures.txt`: 5 passed.
- `.work/context-v2-task2/green-06-git-safety.txt`: 4 passed.
- `.work/context-v2-task2/green-07-fixture-updates.txt`: 100 passed.
- `.work/context-v2-task2/green-08-library-export.txt`: 1 passed.
- `.work/context-v2-task2/green-09-commit-probe-bound.txt`: 3 passed.
- `.work/context-v2-task2/green-10-report-atomicity.txt`: 1 passed.
- `.work/context-v2-task2/green-11-git-locale.txt`: 1 passed.
- `.work/context-v2-task2/green-12-local-config-isolation.txt`: 1 passed.
- `.work/context-v2-task2/green-13-process-group-deadline.txt`: 2 passed.
- `.work/context-v2-task2/green-14-attributes-alternate-process-race.txt`:
  4 passed, including the two new regressions and both descendant deadline tests.
- `.work/context-v2-task2/green-15-reader-lifecycle-cleanup.txt`: 2 passed;
  both injected lifecycle failures record group TERM/KILL, bounded wait, closed
  stdout, and no join of the unstarted thread.
- `.work/context-v2-task2/green-16-validator-repeat-accounting.txt`: 1 passed;
  report conservation is `300 = 299 + 1` and the two successful but differing
  snapshots are listed as a mismatch.
- `.work/context-v2-task2/green-17-focused-lifecycle-validator.txt`: 56 passed.

Spec-review reproduction evidence:

- `.work/context-v2-task2/local-config-isolation-evidence.json` (SHA-256
  `3d9674502380fd7605459ba18fb1b01b9277fab07f716e1a6bed4e0c58ea4036`):
  direct use of the original Git dir changes bytes after the local include, while
  the isolated canonical SHA-256 remains
  `f3d57dee1c2b006f7106933a920d31c942d7be08f263918bf7eeaf12bff23d13`
  before and after pollution.
- `.work/context-v2-task2/process-group-post-review-evidence.json` (SHA-256
  `42119610e44ae991b5fa4ed74cdb9b648d9be146a968b009734d8ebc68a5488b`):
  metadata timeout returned in 0.151 s and canonical diff timeout in 0.246 s;
  both recorded grandchild PIDs were no longer running on return.
- `.work/context-v2-task2/ambient-attributes-alternate-evidence.json` (SHA-256
  `f4657a6cdcabec7a3d225676a6cdfe3366e8fd648515574efe3742c6de00aef3`):
  direct Git bytes changed under ambient `* -diff`, while isolated canonical
  SHA-256 remained
  `6ae4126f7427aa84ac17c8a257ba92d14b860dea1f5f21949168e57d88eb9d18`;
  the separator/quote-containing object-store path also completed successfully.

Final full suite before this documentation update:

- `.work/context-v2-task2/full-tests-green-pre-docs.txt`:
  `527 passed in 47.01s`.
- final `.work/context-v2-task2/final-verification.txt`:
  `530 passed in 46.71s`; `compileall` exit 0.
- post-review `.work/context-v2-task2/final-verification-post-review.txt`:
  `533 passed in 49.58s`.
- post-review `.work/context-v2-task2/compileall-post-review.txt`:
  `compileall` exit 0.
- final post-review `.work/context-v2-task2/final-verification-post-review-v2.txt`:
  `535 passed in 47.96s`.
- final post-review `.work/context-v2-task2/compileall-post-review-v2.txt`:
  `compileall` exit 0.
- quality-review final
  `.work/context-v2-task2/final-verification-quality-review.txt`:
  `538 passed in 46.89s`.
- quality-review `.work/context-v2-task2/compileall-quality-review.txt`:
  `compileall` exit 0.
- independent quality re-review: no remaining Critical/Important; focused
  `56 passed`, full suite `538 passed in 48.77s`.

## Full 300-case Context V2 gate

Command:

```bash
python -m egsi.cli validate-contexts \
  --catalog data/catalog/cases.jsonl --root . \
  --repeat 2 --max-chars 64000 \
  --report .work/context-v2-validation.json
```

Observed result:

- requested/built/failed: `300 / 300 / 0`;
- repeated contexts consistent: `300`; hash mismatches: `[]`;
- patch source counts: raw `273`, canonical Git diff fallback `27`;
- length characters: min `5700`, median `34397.0`, p95 `63568`, max `63984`;
- selection totals: omitted files `356`, omitted hunks `2956`, missing paths
  `9`, new-only paths `224`, binary files `7`;
- split counts: train `200`, dev `60`, time-OOD `40`;
- P0: 10/10 valid, subset of P1, Time-OOD overlap `[]`;
- P1: 30/30 valid, Time-OOD overlap `[]`;
- `overall_valid=true`.

Report:

- path: `.work/context-v2-validation.json`;
- SHA-256: `ceb9725a3900996286a902763affb0dbe80a693623ded6b637608e153fbe37ef`;
- CLI stdout is byte-identical to the report; stderr is empty.

The full command was rerun after all spec-review hardening, including ambient
attributes and alternate-path quoting. It again returned
`300 / 300 / 0`, repeat consistency `300`, raw/fallback `273 / 27`, max length
`63984`, and `overall_valid=true`. The report and stdout remain byte-identical
with the same SHA-256
`ceb9725a3900996286a902763affb0dbe80a693623ded6b637608e153fbe37ef`;
therefore canonical contexts and receipts did not change.

It was rerun once more after lifecycle cleanup and validator accounting changes.
The real all-success catalog still reports `requested/built/failed = 300/300/0`
with explicit conservation, and the byte-identical report SHA-256 remains
`ceb9725a3900996286a902763affb0dbe80a693623ded6b637608e153fbe37ef`;
no report schema or context hash changed.

## Offline fixture regression

The runs used `FixtureTeacher` only and new output roots; no prior final records
were overwritten.

| Run | Requested | Processed | Failed | Restart enrichment reuse | Replay | Leakage | Nonzero reward | Illegal | Promotable |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| P0 first `.work/context-v2-fixture-p0` | 10 | 10 | 0 | 0 | 10 | 0 | 0 | 0 | false |
| P0 restart | 10 | 10 | 0 | 10 | 10 | 0 | 0 | 0 | false |
| P1 first `.work/context-v2-fixture-p1` | 30 | 30 | 0 | 0 | 30 | 0 | 0 | 0 | false |
| P1 restart | 30 | 30 | 0 | 30 | 30 | 0 | 0 | 0 | false |

`episode_cache_reused=0` on the combined `run_pilot` restarts remains the
existing H3 transaction behavior; restart reuse is demonstrated by exact
enrichment reuse `10/10` and `30/30`, unchanged teacher call counts, stable
trajectory commitments, and full replay.

Snapshot SHA-256:

- P0 first: `e889963ef36e7ef2b406959984eb9dcc296f7fd5099246979d195ce1c5dfd32e`;
- P0 restart: `44ad5770ee6fd3f2134dde72464ed605a8aed6fe174dbd73d7c8125c22977f55`;
- P1 first: `5b7881dd42057c2605545d4c6634a09219bd2d7a5d06dac147df56a843455a9b`;
- P1 restart: `206593127563031d70b22e136995b026db5b8fa60a0c9f9f50b7a879e3db1f83`.

Stable artifact commitments:

- P0 batch `sha256:6886fe01316b326982f7545d49f08bebe43e7e5be4585e43116a9735e602f28e`;
  trajectory `sha256:ac5c3b8e98b390323bbbff5513f683bf6707dfc73f65921081810f14ecf19434`.
- P1 batch `sha256:7ce85fa2fd91b62b9510d62f850d73c88eadbb2e5438ac37d6b1a94322179713`;
  trajectory `sha256:6c79b238cd15f9e5717c5de5ff38c69323a116eec8b456cd39daaf18e06fae7a`.

Because the full Context V2 report hash was unchanged, a fresh fixture restart
and replay (rather than destructive first-run regeneration) was performed after
hardening. `.work/context-v2-task2/fixture-post-review-v2-summary.json` (SHA-256
`834e879851ba4e1fe87882f6faaa58d6be04af6a70b9a0794f96ca5ac8899778`)
records P0/P1 enrichment reuse `10/10` and `30/30`, teacher calls `0`, replay
`10/10` and `30/30`, zero leakage/nonzero reward/illegal selections, stable batch
and trajectory commitments, and `promotable=false`.

## Remaining gate

Fixture evidence validates deterministic engineering behavior only. It must not
be promoted into training data. Live-provider P0, measured usage/cost/latency,
human audit, and only then live-provider P1 remain separate future gates.

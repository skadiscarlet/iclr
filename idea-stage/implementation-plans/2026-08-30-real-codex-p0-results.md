# Real Codex Teacher P0 Diagnostic and First-Case Smoke — 2026-08-30/31

## Status

`REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW`. The earlier bounded live Codex
smoke for `ghsa-2m8h-fgr8-2q9w` produced the first positive enrichment record.
The later prompt-v2.2 fail-fast recovery invoked only
`ghsa-3wfj-vh84-732p` and produced the second positive enrichment record on its
first current request. The eight later P0 cases were not invoked, no trajectory
was compiled, human semantic judgment remains unsigned, and P1, GPU, and
training were not started. This is not a claim that the complete ten-case P0
batch passed. The RSA-attested schema-5.1 first-case report predates the v2.2
recovery and is retained only as a replayable pre-recovery snapshot; its
28-manifest/8-commit/8-cache accounting is not the current 29/9/9 artifact
shape.

## Observed execution history

The original ten-case run and its one unchanged operational restart failed
closed at the provider boundary. The historical reports under the output root
record 20 `provider_failure_event` invocations and ten `transport` failure
receipts. Those reports describe that initial run; they predate the later
single-case diagnostic continuation described below.

The first real diagnostic reached the model and retained two committed teacher
responses in `cache/teacher/`. That pre-repair runner made three validation
attempts for `ghsa-2m8h-fgr8-2q9w`, but attempts two and three used the same
semantic-repair request/cache key, so only two unique teacher responses were
committed. At that point the terminal receipt was
`enrichment/failures/ghsa-2m8h-fgr8-2q9w.json`, recording
`semantic_invalid`, `attempts = 3`, and no positive transition. The subsequent
successful smoke removed that stale first-case failure receipt through the
normal positive-commit path; the two old semantic-invalid cache entries and
their committed audit manifests remain intact.

Both committed responses returned descriptive natural language in all four
closed Action DSL fields:

- `trace.goal`
- `trace.operation`
- `trace.target_kind`
- `trace.tool_class`

For example, the responses used sentence-like goals and operations and values
such as `method`, `code_navigation`, and `static_dataflow_analysis`. These are
not members of the enums in `idea-stage/ACTION_DSL.schema.json`.
`validate_payload` therefore rejected them exactly as designed. The validator
was not relaxed.

## Root cause

Prompt version 2.0 supplied the unconstrained Pydantic
`EnrichmentPayload.model_json_schema()`. Its four Action DSL fields were merely
non-empty strings. The closed vocabulary existed in the Action DSL validator,
but neither the provider schema nor the user envelope exposed those enum
choices. The semantic repair message reported only a fixed category and then
reissued an otherwise identical prompt, so a repeated semantic failure also
reused the same cache key.

## Implemented repair

Prompt version 2.1 keeps semantic validation strict and moves the closed
vocabulary into the generation contract:

1. `allowed_action_values(root)` remains the trusted source of the four enum
   sets. The prompt builder accepts those sets explicitly, validates exact
   container/value types and size bounds, and serializes deterministic sorted
   lists.
2. A deep copy of `EnrichmentPayload.model_json_schema()` constrains
   `TraceStep.goal`, `operation`, `target_kind`, and `tool_class` with the exact
   Action DSL enums. A shared provider-neutral normalizer then converts that
   copy to the strict structured-output subset: every object property is
   required, `additionalProperties` is false, and `title`/`default` are removed
   while nullable `anyOf` branches and all Action DSL enums are preserved. The
   original Pydantic schema is unchanged. The normalized schema is byte-level
   canonical JSON at the adapter boundary and structurally identical in the
   user envelope, `TeacherRequest.schema`, and Codex `--output-schema` file;
   the Codex-side normalization check is idempotent.
3. The envelope includes `action_vocabulary`, an explicit verbatim-enum
   instruction, safe fixed-category repair feedback, and `repair_attempt`.
   Request attempts are numbered `0`, `1`, and `2`; repeated failure categories
   therefore still produce distinct prompts and cache keys.
4. Prompt provenance enumeration now requires the trusted vocabulary and
   recognizes only the finite 2.1 request state space: one initial request plus
   each fixed repair category at attempts one and two. Pre-2.1 cached responses
   and enrichment prompt hashes are not accepted as current records.
5. `FixtureTeacher` consumes the new vocabulary envelope and emits values that
   are members of the constrained enums.

## Live first-case hard-gate smoke

The repaired prompt/schema contract was exercised against the real
`codex_exec` provider with model `gpt-5.6-sol`, using only the first case. The
smoke added three unique live invocations to the existing 22 manifests, for 25
cumulative invocations:

| repair attempt | repair code | structured | semantic | request hash |
|---:|---|---:|---:|---|
| 0 | none | true | false | `sha256:d84b78fbd6ad8c4d2143d0510bf8a367050b59e4d3804c16bfaaeb3d9153408f` |
| 1 | `semantic_validation_failed` | true | false | `sha256:d8dcf6464ae26def2c8483d0b904fd72b7600a408b774c685e7e502f4dca1cb6` |
| 2 | `semantic_validation_failed` | true | true | `sha256:68a3d9c4ad2cc6506aec853aed80cd6cd09d45604f9fec654f64f1a864aa59ae` |

The three prompt hashes, canonical `TeacherRequest` hashes, cache keys, and
Codex invocation IDs are pairwise unique. Attempts are exactly `0, 1, 2` and
remain within the three-request bound. All three audit manifests are committed
with `failure_code = null`; their event metadata contain zero command, file,
MCP, collaboration, web, todo, unknown-item, or unknown-event entries.

The final positive record is
`.work/real-p0-codex-v2/enrichment/ghsa-2m8h-fgr8-2q9w.json`. Its current
context, prompt v2.1, strict schema, Pydantic contract, record self-commitment,
repeated semantic validation, and Action DSL validation all pass. The final
cache response, audit manifest, and enrichment record agree on provider/model,
provider request identity, response commitment, usage, and the recomputed
teacher request hash.

Final identifiers and metrics:

- Codex provider invocation identity:
  `01a0537d-2622-7f30-9997-13f9e92e999f`;
- provider identity kind: `codex_thread_id` (not an HTTP request ID);
- teacher response commitment:
  `sha256:66ed04f6157a13ed64706104d8f3e5b20986173c640ed010586830332939baab`;
- teacher request hash:
  `sha256:68a3d9c4ad2cc6506aec853aed80cd6cd09d45604f9fec654f64f1a864aa59ae`;
- record commitment:
  `sha256:33c15407a8f05bac596ff423c8dda26a10d586fafeade57c6977c55c0e7558d6`;
- record latency: `28,843 ms`;
- usage: `10,856` input, `0` cached input, `0` cache-write input,
  `902` output, and `66` reasoning-output tokens.

The atomic `0600` hard-gate evidence is
`.work/real-p0-codex-v2/reports/first-case-hard-gate.json`, with file SHA-256
`sha256:c8431d5eeda4608641315f69c4a3cbbf8aee61e842829d5ec6262a9d1d2bbb01`
and report commitment
`sha256:db21f5750f866d7b89a0f825731639bd2e5e8e7fa13863bdd17b7e4e976efa94`.
It contains no raw prompt, response, reasoning, or authentication material;
`human_semantic_judgment` is `null` and `human_audit_signed` is `false`.

## Evidence boundary

The live result establishes only the corrected generation contract and the
automated first-case hard gate. It does not establish full P0 success, trajectory
or replay validity, or human semantic approval. The historical 20
`provider_failure_event` quarantines, two old committed semantic-invalid
responses, and nine remaining-case failure receipts were preserved. No further
P0 case may be inferred from this smoke, and P1/GPU work remains blocked pending
the explicitly requested next stage.

## Post-smoke quality-review closure

The first-case quality review did not overturn the positive record, but it
identified three Important and two Minor assurance gaps. All were closed
offline before any remaining P0 case was started:

1. `src/egsi/generation/first_case_hard_gate.py` and the pinned native
   `scripts/verify_first_case_hard_gate` entrypoint now provide a source-controlled,
   fail-closed verifier whose report-issuing operation is `--rerun-tests` and
   whose read-only replay operation is `verify-only`. It
   reconstructs current context, prompt v2.1, strict schema, all three repair
   requests, cache keys and response preimages, audit transactions, semantic
   results, uniqueness, history counts, permissions, receipts, and the stop
   boundary from the artifacts rather than trusting booleans in an existing
   report. Its report schema is exact and rejects unknown/missing fields.
2. Teacher audit scanning now requires exact known manifest fields, anchored
   transaction containment and exact file sets, strict JSON metadata with
   consecutive indexes, exact event counts, and a complete success lifecycle.
   Each current committed response is recovered from the expected cache key and
   revalidated as a `TeacherResponse`; response commitment, provider identity,
   Codex thread ID, usage, latency, response hash, request hash, prompt/system,
   and schema commitments must all agree. Missing/tampered cache preimages,
   unknown events/items, incomplete lifecycles, extra files, and manifest
   extensions fail closed. The two legacy committed semantic-invalid responses
   have no retained request preimage and are therefore reported separately as
   `historical_unbound_committed = 2`; they cannot satisfy a current binding
   gate.
3. The shared bounded reader used by pilot and human audit now requires a
   single-link regular file, opens with `O_NONBLOCK | O_NOFOLLOW`, checks exact
   length plus an extra-byte probe, and compares
   `(dev, ino, size, mtime_ns, ctime_ns, nlink)` before and after the read.
   Hardlinks, FIFOs, and in-read metadata changes are rejected.
4. Compatibility fields retain the historical `provider_request_id`, while
   new audit/report output exposes `provider_invocation_id` plus
   `provider_request_id_kind`. For Codex the value is explicitly
   `codex_thread_id`; documentation no longer describes it as an HTTP request
   ID.
5. The pinned `scripts/run_test_receipt` entrypoint atomically records the exact offline test
   command, exit status, pass/fail counts, UTC timestamp, output commitments,
   and current source/test tree commitments. The hard-gate verifier validates
   both receipts and binds their file and receipt commitments together with its
   own source, CLI, and adversarial-test hashes. The report never treats a
   receipt as a substitute for recomputing artifact gates.

TDD evidence was observed before implementation:

- bounded reader: `3 failed` -> `3 passed`;
- audit/cache/lifecycle adversarial matrix: `10 failed` -> `10 passed`;
- test-receipt module/CLI: missing-module/script failures -> `5 passed`;
- source-controlled verifier and seven adversarial copies: `8 failed` ->
  `8 passed`; a separate nested-schema RED then moved to `1 passed`.

The latest source-bound receipts are both `0600`:

- focused: `314 passed`, exit `0`, file
  `reports/offline-focused-receipt.json`, file SHA-256
  `sha256:f7337d5489b0f33a7cb082d739b826ea5d1c83135c991b4cc577eed7d72a6860`;
- full: `769 passed`, exit `0`, file
  `reports/offline-full-receipt.json`, file SHA-256
  `sha256:67a2ee9b55256f3a6370200c1b9006b6c3bbb74357408fc5d4a58b29649cef96`.

`python -m compileall -q src tests scripts` exited `0`. Independent
`verify-only` replay on the original artifacts passed; a copied tree with the
final cache preimage removed was rejected with exit `1`.

## Quality re-review closure (2026-08-31, offline only)

The next quality re-review raised four Important and two Minor gaps. They were
closed with offline TDD only: no provider/model/network call, no GPU/training,
no remaining P0 or P1 case run, and no write under `data/`.

1. Test receipts are no longer caller-selected command receipts. Version 2
   fixes the exact argv to `sys.executable -m pytest -q -p no:cacheprovider`,
   a source-controlled focused test-file set or the complete `tests` tree, and
   a fixed environment containing `PYTHONDONTWRITEBYTECODE=1`,
   `PYTHONHASHSEED=0`, and `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`. The receipt binds
   the resolved CPython runner and hash, Python/pytest versions,
   `pyproject.toml`, all tested source/scripts, and all tests. Captured output
   is retained in bounded base64 form so pass/fail counts and output hashes can
   be recomputed. Command swaps, extra pytest arguments, external temporary
   tests, nonexistent runners, and a self-recommitted fake `999 passed` count
   are rejected. The verifier's `--rerun-tests` operation independently reruns
   both fixed suites and regenerates receipts plus the report before accepting
   the gate; `verify-only` rechecks the fixed argv, runner, environment,
   output, and current code commitments.
2. `read_case_ids` now uses the stable bounded regular-file reader with a
   64 KiB ceiling and strict UTF-8. Symlinks, hardlinks, FIFO inputs,
   oversized lists, invalid encoding, and entry-point use of unsafe case files
   fail before pilot output is created.
3. Teacher audit traversal now enforces the exact
   `<request-hash>/<invocation>/attempt-00` directory grammar and exact direct
   transaction members. Every expected member must be a single-link regular
   file. Extra files, directories or nested subtrees, FIFO/socket nodes,
   symlinks, and hardlinks invalidate both committed and quarantined
   transactions. The audit-tree commitment inventories every entry and its
   type, so an unknown subtree cannot be omitted from the commitment.
4. Human audit reconstructs all seven legal prompt variants for every current
   record and matches committed audits by canonical request hash and cache
   preimage. In the retained real first-case shape, three current v2.1
   commits are fully bound: one final record response and two legal repair
   responses. The repair responses are counted separately and are not treated
   as malformed. The two older v2.0 semantic-invalid commits remain
   `historical_unbound_committed = 2`, are excluded from `by_response` positive
   evidence, and are fixed by the preserved-set commitment
   `sha256:8a33fb2d0aaaf2ee63abcd42940ce8fb167f2c1e49fb13f50056afeed9682b1e`.
   The same scan records 20 historical `provider_failure_event` quarantines
   and zero malformed transactions. The final gate accepts only the final
   record response as the positive record binding.
5. The first-case report destination must be a safe JSON file directly under
   `<output-root>/reports`; escape paths, symlinks, and hardlinks are rejected.
   Atomic writers now also reject multi-link destinations.
6. Forbidden tool items are accumulated before their transaction is marked
   invalid. A single `command_execution` item now yields
   `tool_events = 1`, `malformed_invalid = 1`, no committed positive, and a
   false tool gate rather than losing the tool count through an exception.

Observed RED -> GREEN evidence for this re-review:

- canonical receipts: `11 failed` -> `11 passed`;
- bounded case-file intake and CLI entry: `5 failed, 2 passed` -> `7 passed`;
- exact transaction types and forbidden-tool accounting: `15 failed` ->
  `15 passed`; socket-typed transaction members are covered with a deterministic
  stat-level regression because the sandbox forbids creating an AF_UNIX socket
  node;
- real retained repair/history shape: missing helper failure -> `1 passed`;
- first-case/report-path/adversarial verifier: `13 passed`, followed by
  `14 passed` after adding the `--rerun-tests` regression;
- final source-bound verifier rerun: focused `314 passed`, full `769 passed`,
  both with zero failures and exit `0`;
- `python -m compileall -q src tests scripts`: exit `0`;
- real artifact `--rerun-tests`: exit `0`, `35/35` hard gates true;
- immediate real artifact `verify-only`: exit `0`;
- copied artifact with the final cache preimage removed: verifier exit `1`.

The canonical receipt commitments are
`sha256:bf074dbe330afd3c46cdec9c381db791a4342fd0f8b7c58a4a07ea0f87ef5b57`
(focused) and
`sha256:9d63b6dab065dfeb62a59afaf151fe6e0845e4b7985cee8568ac59295554e3ae`
(full). Both receipts and the final report are mode `0600`.

## Third quality re-review closure (2026-08-31, offline only)

The third re-review raised five Important gaps and one Minor gap. All were
closed with offline TDD. No provider/model/network call, remaining P0/P1 case,
GPU, training process, or write under `data/` occurred. The retained state is
still `STOPPED_AFTER_FIRST_CASE_BEFORE_REMAINING_P0_P1_GPU`.

1. Receipt provenance is issuance-bound. The unauthenticated `generate`
   operation was removed. Only `--rerun-tests` can publish a report with
   `status = FIRST_CASE_GATE_PASSED`, and that report now contains
   `attestation_mode = rerun_tests`. `verify-only` validates an already
   published baseline, both receipts, and the report without creating or
   replacing any artifact. CLI summaries explicitly emit
   `execution_replayed = true|false`; even internally coherent canonical
   receipts claiming `999 passed` cannot cause a non-rerun operation to issue
   a report.
2. Canonical pytest execution is isolated with the exact prefix
   `sys.executable -I -m pytest -q -p no:cacheprovider --confcutdir=tests`.
   The fixed environment additionally binds `PYTHONNOUSERSITE=1` and
   `PYTHONSAFEPATH=1`. Root-level `conftest.py`, `sitecustomize.py`,
   `usercustomize.py`, `pytest.ini`, `setup.cfg`, and `tox.ini` are forbidden
   before subprocess launch regardless of whether the node is a regular file,
   symlink, hardlink, FIFO, or another special type. `pyproject.toml` remains
   the sole root pytest configuration, and
   `pytest_local_inventory_sha256` commits the complete local source,
   scripts, tests, and allowed configuration inventory.
3. Report, focused-receipt, full-receipt, and controlled-baseline paths are
   checked for lexical and `(dev, ino)` aliasing before any test or report
   write. Existing hardlink aliases fail closed without changing old evidence.
   Receipt identities and SHA-256 values are captured after the reruns and
   rechecked after report publication; a publication-time mutation invalidates
   and removes a newly published report.
4. Teacher audit/cache accounting is now bidirectionally complete. Empty
   request directories, valid orphan or unconsumed caches, malformed cache
   entries, and duplicate consumption of one cache by multiple historical
   manifests increment `malformed_invalid`. Every direct cache node is included
   in the artifact-set inventory, so orphan material changes the commitment.
   Each valid cache can be consumed exactly once by one committed manifest.
5. The retained historical baseline is no longer incorrectly treated as
   zero. `reports/historical-teacher-audit-baseline.json` is a `0600`,
   self-committed `rerun_tests` attestation for exactly two historical unbound
   commits, set commitment
   `sha256:8a33fb2d0aaaf2ee63abcd42940ce8fb167f2c1e49fb13f50056afeed9682b1e`,
   and 20 provider-failure quarantines. The first-case report binds its file
   hash and commitment. Human audit accepts a future ten-current-case packet
   with this fixed historical set, while added, missing, or same-count
   replacement history fails the automated gate; historical entries never
   enter `by_response`.
6. `verify-only` opens `reports/` with `create=False`. On a missing report
   directory it fails without changing the directory tree or directory
   mtimes; on a valid tree it is byte- and metadata-read-only.

Observed RED -> GREEN evidence:

- pytest isolation/root-hook matrix: `25 failed, 1 passed` -> selected
  `37 passed`; complete receipt module `38 passed`;
- issuance, CLI disclosure, path alias, publication race, and read-only checks:
  `8 failed, 2 passed` -> selected `15 passed`; complete first-case verifier
  module `24 passed`;
- empty-request/orphan-cache/duplicate-consumption and retained-baseline tests:
  `4 failed` -> scan matrix `24 passed`, ten-case live baseline regression
  `1 passed`; complete human-audit module `38 passed`;
- canonical focused suite: `314 passed`, zero failures, exit `0`;
- canonical full suite: `769 passed`, zero failures, exit `0`;
- `.work/offline-receipt-venv/bin/python -m compileall -q src scripts tests`:
  exit `0`.

The final real-artifact `--rerun-tests` returned exit `0`,
`execution_replayed = true`, and `35/35` hard gates true. Its immediate
`verify-only` replay returned exit `0` with `execution_replayed = false`. A
fresh copied artifact with final cache
`32de43d7c2b3af8a97a6669ae79f8931978778f78b06a5798a3510657cc80aac.json`
removed returned exit `1`.

Latest `0600` evidence hashes and commitments:

- focused receipt file:
  `sha256:f7337d5489b0f33a7cb082d739b826ea5d1c83135c991b4cc577eed7d72a6860`;
  receipt commitment:
  `sha256:bf074dbe330afd3c46cdec9c381db791a4342fd0f8b7c58a4a07ea0f87ef5b57`;
- full receipt file:
  `sha256:67a2ee9b55256f3a6370200c1b9006b6c3bbb74357408fc5d4a58b29649cef96`;
  receipt commitment:
  `sha256:9d63b6dab065dfeb62a59afaf151fe6e0845e4b7985cee8568ac59295554e3ae`;
- historical baseline file:
  `sha256:4386a50ac4a73a2a365826883ca0e5416d36c2da8e227ce22adf5a11f02275e2`;
  baseline commitment:
  `sha256:364d7f632b5f51070c4c275de0bf4ed81d851bc94310268edb0119b95423606b`;
- first-case report file:
  `sha256:c8431d5eeda4608641315f69c4a3cbbf8aee61e842829d5ec6262a9d1d2bbb01`;
  report commitment:
  `sha256:db21f5750f866d7b89a0f825731639bd2e5e8e7fa13863bdd17b7e4e976efa94`.

The real artifact shape remains one positive record, nine remaining failure
receipts, five cache files, 25 audit manifests, and zero episode/trajectory
files. Audit classification remains three current bound commits (one final,
two repair), two historical unbound commits, 20 provider failures, and zero
malformed transactions.

## Fourth quality re-review closure (2026-08-31, offline only)

The fourth review raised two Important gaps and one Minor publication gap.
They were closed with offline RED -> GREEN tests. No provider/model or network
call, remaining P0/P1 case, GPU/training process, or write under `data/`
occurred. The retained stop marker remains
`STOPPED_AFTER_FIRST_CASE_BEFORE_REMAINING_P0_P1_GPU`.

1. Canonical pytest execution is now bound to the source-controlled
   `configs/offline-test-runner.lock.json` (`offline-pytest-runner-v1`). The
   exact command begins with the locked absolute interpreter followed by
   `-I -m pytest -c <absolute-pyproject.toml>` and uses the absolute
   `--confcutdir=<absolute-tests>` value. The lock binds the command and real
   interpreter paths, interpreter binary digest, Python implementation/version,
   pytest and pluggy versions, their loaded module files and installed-file
   digests, site-package roots, every top-level `.pth` file, explicit
   site/user-customization-file absence, and the canonical config digest.
   Runtime state must exactly equal the lock; a shadow `/tmp` venv is rejected
   even when it can import a fake pytest package. The verifier never updates
   the lock. Maintenance is explicit and offline:
   `.work/offline-receipt-venv/bin/python -I scripts/update_offline_test_runner_lock.py --root .`.
2. The child environment is rebuilt from exactly `PATH`, `LANG`, `LC_ALL`,
   `TZ`, `HOME`, `TMPDIR`, `PYTHONDONTWRITEBYTECODE`, and
   `PYTEST_DISABLE_PLUGIN_AUTOLOAD`; it does not copy the host environment.
   `HOME` and `TMPDIR` are per-run private mode-`0700` directories under a
   private temporary root and are removed after the subprocess. Python/pytest
   option injection, loader injection, and coverage startup variables are
   consequently absent. Root `conftest.py`, `sitecustomize.py`,
   `usercustomize.py`, `pytest.ini`, `.pytest.ini`, `pytest.toml`,
   `.pytest.toml`, `setup.cfg`, and `tox.ini` are rejected for regular,
   symlink, hardlink, and special-file forms. A legitimate
   `tests/conftest.py`, if introduced, is covered by the committed tests-tree
   inventory. Receipt schema `2.1` records the runner-environment commitment,
   exact runner contract, runner-lock hash, and historical-expectation hash.
3. Historical expectations no longer originate in the writable output tree.
   `configs/historical-teacher-audit-expectation.v1.json` is the source trust
   root for exactly two historical commits, the exact historical artifact set,
   historical response-commitment set, 20 `provider_failure_event` items, the
   exact failure classification, and the exact failure-audit commitment set.
   `reports/historical-teacher-audit-baseline.json` is schema `2.0` and is only
   an observed rerun receipt. Both the first-case verifier and future live P0
   human-audit path compare the observation and scanned artifacts to the
   source expectation. Mutating history and coherently re-signing the writable
   observation cannot redefine the expected set.
4. A PASS report is the absolute final publication. Receipt identity/hash
   checks, output-baseline readback, source-expectation checks, report schema,
   and destination snapshot checks all finish before publication. There is no
   readback or recheck after a successful PASS replace. If the final writer
   raises after replacing the destination, a newly created report is removed
   and an existing report is atomically restored byte-for-byte at mode `0600`.

Threat-model boundary: these receipts are local reproducibility attestations.
They reject pytest runtimes, configuration, plugins, environment state, and
historical expectations that are not bound to the project trust roots. They do
not claim resistance to a malicious local root that can simultaneously modify
the source-controlled verifier, runner lock, historical expectation, and all
artifacts. External tamper resistance requires a separately controlled CI
identity and signed provenance/attestations.

Observed RED -> GREEN and final verification evidence:

- hermetic runner attacks: `4 failed` -> `4 passed`; complete receipt module
  `56 passed`;
- source expectation: failure-history/output-resign test failed with
  `DID NOT RAISE` -> passed; the live human-audit expectation test failed on
  the missing source API -> passed; complete human-audit module `38 passed`;
- final publication: selected run `2 failed, 1 passed` -> `4 passed`; complete
  first-case verifier module `28 passed`;
- canonical focused suite: `336 passed`, zero failures, exit `0`;
- canonical full suite: `791 passed`, zero failures, exit `0`;
- explicit shadow/config/plugin/environment/baseline-resign/report-race attack
  selection: `8 passed`;
- `PYTHONDONTWRITEBYTECODE=1 .work/offline-receipt-venv/bin/python -m compileall -q src scripts tests`:
  exit `0`;
- real retained-artifact `--rerun-tests`: exit `0`,
  `execution_replayed = true`, `36/36` gates true;
- immediate `verify-only`: exit `0`, `execution_replayed = false`, `36/36`
  gates true.

Latest trust-root and mode-`0600` evidence:

- runner lock file SHA-256:
  `sha256:38c87d3b1f9444cadd1cbee4f61ba07f0b3604b276148d862dbcbcb2c9eb932d`;
  lock commitment:
  `sha256:adb5c8ff368546c7636a34de85a6800e6e9e75b9a91887db0a36e3bd78bf4c41`;
- source history expectation file SHA-256:
  `sha256:34007fe7272cbc3ab726960c31a9a2551977b6ccf21d84ee97890e22e50ac824`;
  expectation commitment:
  `sha256:b2e0fa90979680aeea86e04f1da2761257810d6db60b80ef0d063f6aa2998e17`;
- focused receipt file SHA-256:
  `sha256:aa63d609fded0a23b6cb4c933c3e6c57ac2adfb5e70a4a3d202490d616c84110`;
  receipt commitment:
  `sha256:ece5f93698b3f9caa8162ebfd7615386501baca3b6a6a5144600abadee3830e5`;
- full receipt file SHA-256:
  `sha256:e8f24fd681c573d411394087e07b2d451338698c07198b7a4e4334c3cb98d59f`;
  receipt commitment:
  `sha256:b2b8668a84a7e3f09a9519979888b2fbde054ac0d6455289e5d64fdd1ebf356d`;
- observed historical receipt file SHA-256:
  `sha256:496387b4dfd2ff04f7f308df5d64239fcf5c71d68373db991ce8372cb489b075`;
  baseline commitment:
  `sha256:b69a5e276dbe45d63eb8c2529e6e485240ef1deb78cfe7ba8361ab671bd05255`;
- first-case report file SHA-256:
  `sha256:0b98d618890cd31548e22b5f7be4904d78e631ff1e15c93d81d281aa9731a2d7`;
  report commitment:
  `sha256:bb5682d7ebc3f82f23ad8f7e89e77aac77cc46695afaec5c08910597cd1e1a95`.

The real artifact shape remains one positive record, nine remaining failure
receipts, five cache files, 25 audit manifests, three current request-bound
commits (one final and two repairs), two source-approved historical unbound
commits, 20 source-approved provider failures, zero malformed transactions,
and zero episode/trajectory files.

## Quality-review hardening (offline only)

The post-repair quality review and its adversarial follow-up identified several
additional fail-closed gaps. Before the live smoke, they were fixed without
invoking a real model, network service, or GPU and without modifying the then
retained `.work/real-p0-codex-v2` evidence:

1. Teacher text is now decoded by one bounded strict JSON parser before JSON
   Schema, Pydantic, or semantic validation. It rejects duplicate object keys
   recursively, the non-standard `NaN`, `Infinity`, and `-Infinity` constants,
   and finite-syntax numbers whose Python float result would overflow to a
   non-finite value. Codex provider JSONL applies the same finite-float rule, so
   an event containing `1e400` is quarantined as malformed rather than retaining
   Python `inf`. Terminal failure receipts retain only the bounded failure
   category and do not echo provider-controlled response text.
2. `idea-stage/ACTION_DSL.schema.json` is opened as a regular file and checked
   against a 1 MiB binary size limit before content buffers are allocated or
   JSON parsing begins. The reader verifies exact-length completion, rejects an
   extra byte, and checks file identity and size/mtime stability across the
   read. The open is nonblocking, so a concurrent replacement with a FIFO
   cannot stall before the regular-file check. Exactly 1 MiB remains accepted;
   1 MiB plus one byte fails closed.
3. Codex audit manifests and human audit now share a canonical
   `TeacherRequest` commitment over exactly `system`, `user`, `schema`,
   `temperature`, and `max_tokens`, serialized with sorted compact UTF-8 JSON
   and `allow_nan=false`. The Codex audit path is
   `<request-hash>/<invocation-id>/attempt-00/manifest.json`. Human audit
   reconstructs the exact final initial/repair request from the committed
   prompt variant, requires the manifest request hash to equal that canonical
   request hash, and binds the same manifest through the teacher response
   commitment to the final enrichment record. Each case exposes a
   `teacher_request_bound` gate; `teacher_requests_bound` and
   `final_teacher_audit_bound` require all live cases to satisfy this request
   binding together with the existing response/provider-request binding.
4. Live audit requirements are selected by committed `generation_mode=live`,
   not by a special case for the Codex provider name. Consequently a live
   OpenAI-compatible, Anthropic, or other provider run without conforming audit
   manifests fails the per-case request/response gates and final aggregate gate
   rather than receiving a fixture-style exemption.

Historical `provider_failure_event` manifests remain counted as prior failures
and do not become forbidden tool events. Fixture-mode cases remain explicitly
non-promotable and do not substitute for live request-audit evidence.

## Offline validation evidence after hardening

The strict JSON, Action DSL bound, and live-like audit binding tests were first
observed failing for the missing behavior. Separate overflow-number,
non-Codex-live, and nonblocking-open regressions were also observed failing
before their fixes. The current focused suite reports `232 passed` across
enrichment, human audit, Codex adapter, and provider-adapter tests. A subsequent
`python -m compileall -q src tests scripts` completed successfully, and the full
offline suite reported `669 passed`. A final read-only review found no remaining
Critical, Important, or Minor issue in these changes.

A fresh deterministic fixture replay under `/tmp` produced:

- P0: 10 requested, 10 processed, 0 failed, 10 replay passes;
- P1: 30 requested, 30 processed, 0 failed, 30 replay passes;
- both batches: zero policy-oracle leakage, zero selected illegal actions, and
  zero nonzero T1 rewards;
- fixture P0 human-audit packet: all automated gates passed and status
  `AWAITING_HUMAN_AUDIT`.

These are offline contract/replay results only. The authoritative status at the
top of this document is now `FIRST_CASE_GATE_PASSED`, based on the separate
bounded live smoke above; neither the historical offline results nor the one
live case constitute full ten-case P0 or human semantic approval. Immediately
before that smoke, the focused enrichment/human-audit/Codex suite was rerun and
reported `175 passed in 84.43s`; the final post-evidence rerun independently
reported `175 passed in 75.95s`.

## Fifth hermetic-runner closure and CLI parent isolation (2026-08-31, offline only)

The fifth review closed the remaining local-runner trust gap without invoking
a provider/model, network service, remaining P0/P1 case, GPU/training process,
or any write under `data/`.  The retained stop marker is still
`STOPPED_AFTER_FIRST_CASE_BEFORE_REMAINING_P0_P1_GPU`.

The initial RED evidence was specific: the old lock exposed schema `1.0`
instead of the required `2.0`; an ordinary base-Python launch imported a
malicious `PYTHONPATH` `egsi` package before the CLI could isolate itself; a
real `.pth` startup hook executed before the verifier and the old CLI still
returned exit `0`; and the first clean-runner pytest launch added `.pyc` files,
making the newly committed closure differ immediately.  The last issue was
caused by `-I` implying `-E` and therefore ignoring the
`PYTHONDONTWRITEBYTECODE` environment variable.  The canonical interpreter
argv now contains explicit `-B` as well as `-I`.

1. `scripts/bootstrap_offline_test_runner.py` builds the fixed
   `.work/offline-test-runner-venv` with `venv.EnvBuilder(with_pip=False,
   symlinks=False, system_site_packages=False)`.  It copies an explicit
   allowlist from already installed local files, copies `src/egsi` as a real
   non-editable package, removes bytecode, rejects `.pth`, `sitecustomize.py`,
   `usercustomize.py`, symlinks, hardlinks, and special nodes, performs an
   isolated import smoke, atomically replaces the runner, and invokes the
   explicit offline lock updater.  `pyproject.toml` no longer injects `src`
   through pytest `pythonpath`.
2. `configs/offline-test-runner.lock.json` is schema `2.0` and contract
   `offline-pytest-runner-v2`.  It commits the copied interpreter and
   `pyvenv.cfg`, `include-system-site-packages = false`, the exact isolated
   `sys.path`, the complete private site-packages inventory, the stdlib tree,
   loaded pytest/pluggy modules, canonical config, and equal source/installed
   `egsi` trees.  The current lock contains 2,148 site entries and 2,469
   regular stdlib files.  Directory membership is committed by paths while
   directory `size` is normalized to zero because filesystem bookkeeping size
   need not return to its old value after a rejected add/remove probe.
3. Receipt execution now captures one exact runtime/code snapshot before the
   subprocess and one after it, requires equality, and repeats validation on
   committed-receipt readback.  Receipt runner fields include the site,
   stdlib, installed-project, pytest-module, and pluggy-module commitments.
   Tests cover a new regular file, a missing locked file, symlink, hardlink,
   FIFO, mid-run mutation, and a `.pth -> evilhook` startup execution.  Every
   attack fails closed and leaves no receipt/PASS publication; cleanup is
   followed by an exact lock revalidation.
4. The pinned `scripts/verify_first_case_hard_gate` entrypoint reads only the source lock with
   stdlib code before any `egsi` import.  A non-isolated process, an interpreter
   other than the locked copy, or a process lacking `-B` is replaced with
   `os.execve(locked_python, [locked_python, "-I", "-B", script, ...],
   minimal_environment)`.  Only the correct isolated child imports project
   code, and `load_runner_lock` performs the full closure check before even
   accepting argparse `--help`.  Thus parent `PYTHONPATH`/user-site state is
   discarded, while an already-executed malicious startup hook is detected
   and produces a nonzero result.

Fresh verification evidence after the final source/test state:

- receipt plus first-case verifier modules: `93 passed`;
- complete human-audit module: `38 passed`;
- canonical focused suite: `345 passed`, zero failures, exit `0`;
- canonical full suite: `800 passed`, zero failures, exit `0`;
- explicit clean-lock/`-B`/closure/mid-run/parent-shadow/`.pth` attack
  selection: `10 passed`;
- `PYTHONDONTWRITEBYTECODE=1 .work/offline-test-runner-venv/bin/python
  -I -B -m compileall -q src scripts tests`: exit `0`;
- retained-artifact `--rerun-tests`: exit `0`,
  `execution_replayed = true`, and `36/36` hard gates true;
- immediate `verify-only`: exit `0`, `execution_replayed = false`, and
  `36/36` hard gates true;
- ordinary base-Python and locked `-I` CLI `verify-only`: both exit `0`; a
  byte/hash/mode/size/mtime/ctime/link/inode snapshot of all 173 output-tree
  entries was identical before and after both commands.

Latest trust-root, closure, and mode-`0600` evidence:

- runner lock file SHA-256:
  `sha256:579562be47f20f2689327877b8a0b4603847a4db2877e721d2c9ef0dcc3cc80b`;
  lock commitment:
  `sha256:bcacb599d3a14b082ff83e46c4b73ce5ee144c19a86ab12875c714a9596ad19c`;
- private site tree:
  `sha256:e1c81030d493741d8e7e6e19c1dad2128826c98faff70dc12194dd5d4d8aeac9`;
  stdlib tree:
  `sha256:db63335c8004c1c87a92c45f28f444476a59a303d584f70c9aec34822410dd62`;
  source and installed project tree:
  `sha256:cc863791d4bad0079bc98d781062a172796e95622f3f38f987b245a57257dda3`;
- source history expectation file SHA-256 (unchanged):
  `sha256:34007fe7272cbc3ab726960c31a9a2551977b6ccf21d84ee97890e22e50ac824`;
  expectation commitment:
  `sha256:b2e0fa90979680aeea86e04f1da2761257810d6db60b80ef0d063f6aa2998e17`;
- focused receipt file SHA-256:
  `sha256:77d316b2b060e60d284d39a6883b2dea8c5c5bc7e0e5cff86ad33a1daf7c3405`;
  receipt commitment:
  `sha256:f7c5d42248c60f5a0c993a2bb9de2fe05ce5866c56dc1ca609d3dfa6607ef7f5`;
- full receipt file SHA-256:
  `sha256:ab5ad56d421740400a01227ad1c13504907840a2efdd6a08e4d756ce85ac186b`;
  receipt commitment:
  `sha256:c2376fda29e86f59d3d6f912e71985adcab7b312b093faa9fe174f7504000823`;
- observed historical baseline file SHA-256 (unchanged):
  `sha256:496387b4dfd2ff04f7f308df5d64239fcf5c71d68373db991ce8372cb489b075`;
  baseline commitment:
  `sha256:b69a5e276dbe45d63eb8c2529e6e485240ef1deb78cfe7ba8361ab671bd05255`;
- first-case report file SHA-256:
  `sha256:d61b0fab6c573f776f8375809ca2e75ed168b24cae4fbbf7c3c4e0bcbb6dcb93`;
  report commitment:
  `sha256:64209b1e795466fac9526caaf50497798a5b1735cac43ad953f8503dc5359698`;
- both receipts bind runner-environment commitment
  `sha256:3d3cbc1d9bb8abd7c74ae1205de9077b371a33be393644ea4d403791c149d7bf`,
  source tree
  `sha256:c6894ddeafed6024b0603589c95c474f09ed0b67898dc4f6c510d691abe86931`,
  tests tree
  `sha256:3538bc953f57020a8b2dc5cdd18494331f81f4832869d3b26186faf5b01ebab4`,
  and local pytest inventory
  `sha256:c953ef6f8ce84183b36d2b871564bc328a6d10dbeaf6272569870fd26c3ae380`.

The retained artifact still contains one positive enrichment record (plus the
batch-provenance JSON), nine remaining failure receipts, five teacher-cache
files, 25 audit manifests, zero episode files, and zero trajectory files.

## Sixth startup/TOCTOU closure (2026-08-31, offline only)

The sixth adversarial review closed the remaining startup-before-integrity and
mutate/restore gaps.  This work stayed strictly offline: no provider/model was
called, no network or GPU/training process was started, no remaining P0 or P1
case was run, and nothing under `data/` was written.  The retained boundary is
still `STOPPED_AFTER_FIRST_CASE_BEFORE_REMAINING_P0_P1_GPU`.

The initial targeted RED run reported five expected failures: the canonical
argv still used `-I -B -m pytest`; a locked file could be modified, restored to
its original bytes and mtime, and hidden by the validation cache; both receipt
and verifier CLIs imported a `PYTHONPATH` shadow `json.py` before isolation;
and a self-erasing `.pth -> evilhook` executed before rejection.

1. `scripts/locked_runtime_bootstrap.py` is now the stdlib-only trust gate for
   pytest, receipt issuance, first-case verification, probing, and explicit
   lock maintenance. Every canonical child uses `-I -B -S`; the bootstrap
   validates the complete lock/runtime before adding source or private
   site-packages to `sys.path`, never calls `site.addsitedir`, and revalidates
   the closure and exact `sys.path` after site/project execution. Under `-S`,
   CPython intentionally leaves `sys.prefix` at the base interpreter, so the
   fixed `.work/offline-test-runner-venv` command path is the authoritative
   venv prefix. A pytest `ExitCode` is an `IntEnum`; preserving its numeric
   value avoids converting `ExitCode.OK` into a false process exit `1`.
2. The runner lock is schema `3.0`, contract
   `offline-pytest-runner-v3`. It commits byte hashes plus mode, device, inode,
   link count, uid/gid, size, mtime, and ctime for the executable, `pyvenv.cfg`,
   bootstrap, canonical config, every private site entry, and every stdlib
   entry. Private site startup hooks, root or nested symlinks, hardlinks, and
   special nodes fail closed. Lock validation safely reads the lock, rebuilds
   the complete current identity, then safely rereads the lock and requires
   identical lock bytes and metadata across the validation window.
3. `test_receipt.py` reuses the validator already loaded into memory before
   site imports and has no cross-pre/post validation cache. Receipt schema
   `3.0` commits the executable, `pyvenv.cfg`, bootstrap, config, and lock-file
   identity digests; the runner-environment commitment also binds the lock-file
   identity. Consequently restoring lock or site bytes and original mtime does
   not hide the changed ctime/inode from receipt issuance or later replay.
4. The legacy Python signer wrappers (deleted in the eighth hardening round)
   and the explicit lock updater used an `os`/`sys`-only prelude. The current
   public signer entrypoints are pinned native ELF launchers; all `egsi`
   imports occur only after the `-I -B -S` locked bootstrap validates the
   runtime. `bootstrap_offline_test_runner.py` builds the lock and probes the
   installed runner only through that bootstrap.
5. Destructive closure tests now use disposable synthetic copied-venv roots,
   so their unavoidable inode/ctime changes never taint the canonical runner.
   Fresh-process tests cover added/missing/symlink/hardlink/FIFO entries, a
   symlinked site root, a byte-identical copied venv with different inode
   identity, site bytes+mtime restoration, lock bytes+mtime restoration, both
   CLI `PYTHONPATH` shadows, and a self-erasing `.pth` that must neither execute
   nor forge a receipt.

Fresh final-state verification evidence:

- startup/TOCTOU attack selection: `8 passed`; the added site-root-symlink and
  pytest-`IntEnum` regressions each pass independently;
- complete receipt module: `70 passed`, zero failures, exit `0`;
- complete first-case verifier module: `31 passed`, zero failures, exit `0`;
- canonical retained focused receipt: `353 passed`, zero failures, exit `0`;
- canonical retained full receipt: `808 passed`, zero failures, exit `0`;
- `PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/egsi-round6-pyc
  .work/offline-receipt-venv/bin/python -m compileall -q src scripts tests`:
  exit `0`;
- retained-artifact `--rerun-tests`: exit `0`,
  `execution_replayed = true`, and `36/36` hard gates true;
- immediate bootstrap `verify-only`: exit `0`,
  `execution_replayed = false`, and `36/36` hard gates true;
- ordinary base-Python and locked `-I -B -S` CLI `verify-only`: both exit `0`;
  the byte/hash/mode/device/inode/link/size/mtime/ctime snapshot of all 173
  retained output-tree entries was exactly identical before and after.

Final trust-root and retained-artifact evidence:

- runner lock file SHA-256:
  `sha256:ccd3e2f28e211d823b5ecd861c61507e2b8284333a03dc50360ee9d2b3a30086`;
  lock commitment:
  `sha256:8fed849ad96993f350b2efa3ad86e8563d8f8da6677a46ccb4562dc3a7784ec0`;
- private site tree:
  `sha256:b118ebd28db01b997993d53d05dd6d610f355bf86ca3744d3386f38bd07fda91`;
  stdlib tree:
  `sha256:12c8b2a73b8fd8c00d5de73b268c11d28642700d2237efdd666c2f21593bea47`;
  source/installed project content:
  `sha256:99b3b6ac9ebab3cbf77349ddea0a21d49680daee792fa2d3c18cdbb14a764290`;
- focused receipt file SHA-256:
  `sha256:f01859c377c54507fd9984fab59e65736f7e396464bea50820b550cdea1f7def`;
  receipt commitment:
  `sha256:4da9577d24a79e5f94045610d3de7301d61479d0bf46de231ae85a9e3a204539`;
- full receipt file SHA-256:
  `sha256:c77e5f7c60459950b7a16c377b1d9a04d9b15288ac547074ee5b3366ccf27bbf`;
  receipt commitment:
  `sha256:03a1d2fe73f8ffd0a0782cf18f4b6c6f8c972e6141c8afd62b0839ad4a7a4db4`;
- both receipts bind runner-environment commitment
  `sha256:27ca0d2ae29b0226bec3974fadaf86ba29f46af949f903bbadb02bd4d97134b1`;
- observed historical baseline remains
  `sha256:496387b4dfd2ff04f7f308df5d64239fcf5c71d68373db991ce8372cb489b075`;
- first-case report file SHA-256:
  `sha256:ad730f62e3bd1001920253560820756324192a8bc856d599a43457729fe6346a`;
  report commitment:
  `sha256:18b0be8f7561c09b6b214f23973d04fea8cae65c027437d8cc2a8fc6fe9d0953`.

The retained artifact shape is unchanged: one positive enrichment record, nine
remaining failure receipts, five cache files, 25 audit manifests, zero episode
files, and zero trajectory files. No negative or failed result was hidden.

## Seventh official-launcher and project-identity closure (2026-08-31, offline only)

The seventh review makes the two POSIX shell launchers without a `.py` suffix
the only supported public receipt/PASS entrypoints. They clear Python, pytest,
loader, shell-startup, and coverage injection variables using shell builtins,
then exec fixed absolute paths for the locked interpreter and stdlib-only
bootstrap with `-I -B -S`. Direct ordinary-Python execution of the compatibility
`.py` files is explicitly unsupported and cannot sign or verify artifacts.
This boundary does not claim resistance to a local root able to replace the
launcher, locked interpreter, bootstrap, lock, and source together.

Runner lock schema `4.0` / contract `offline-pytest-runner-v4` additionally
commits a complete metadata-and-content inventory of `src/`, `tests/`,
`scripts/`, `configs/` (excluding the lock itself), `idea-stage/`, and
`pyproject.toml`. Every entry binds device, inode, type, mode, link count,
uid/gid, size, mtime, ctime, and SHA-256; symlinks, hardlinks, special nodes,
extra entries, missing entries, and project `__pycache__`/`.pyc`/`.pyo`
bytecode caches fail closed. Pre-existing generated bytecode was preserved
outside the trust closure under `.work/round7-preexisting-bytecode-cache`.
The configs parent directory is not committed because atomically replacing the
lock in that same directory would create a circular ctime dependency; its
non-lock membership remains committed. Receipt schema `4.0` carries the project
identity commitment in both
runner and code commitments, and explicitly records equal
`project_identity_pre_sha256` / `project_identity_post_sha256` values. Pre/post
validation fully rebuilds the inventory, so source or test bytes restored with
their original mtime still fail on ctime and cannot publish a receipt or PASS
report.

The first-case verifier's `rerun-tests` path no longer calls the in-process
receipt signer. It invokes the official `scripts/run_test_receipt` shell
launcher for both focused and full suites, then validates the committed
receipts before report construction. The PASS report explicitly binds the
official verifier launcher's relative path, content SHA-256, and a second
identity commitment over type, mode `0755`, device, inode, link count, uid/gid,
size, mtime, ctime, and content hash. The v4 project inventory independently
binds both official launchers with the same metadata closure.

Adversarial regressions cover `PYTHONPATH` `json.py` and `sitecustomize.py`
startup attempts against both official launchers, direct compatibility-`.py`
entrypoints failing with exit `64`, project-test mutate/restore with original
bytes and mtime, explicit pre/post project-identity tampering, launcher mode
and identity binding, duplicate-root rejection before any attacker-controlled
launcher can execute, forbidden project bytecode caches, and proof that
first-case receipt reruns use the shell launcher rather than the in-process
signer. Fresh module runs reached `74 passed` for receipt issuance, `33 passed`
for the first-case verifier, and `38 passed` for human-audit validation.

All work remained offline and preserved
`STOPPED_AFTER_FIRST_CASE_BEFORE_REMAINING_P0_P1_GPU`; no model, network, GPU,
remaining P0/P1 case, training process, or `data/` write was used.

## Eighth native-launcher and pytest-collection closure (2026-08-31, offline only)

The eighth review supersedes the seventh-round shell/Python compatibility
boundary. `scripts/run_test_receipt` and
`scripts/verify_first_case_hard_gate` are now two separately built, pinned,
mode-`0755`, single-link static x86_64 ELF executables. They use a custom
`_start` and direct syscalls, have no libc, `PT_INTERP`, `PT_DYNAMIC`, or
`DT_NEEDED`, require `/proc/self/exe` to equal the exact installed path, ignore
the inherited environment, and `execve` only the fixed offline interpreter
with `-I -B -S`, the fixed stdlib-only bootstrap, the fixed absolute project
root, and a fixed minimal environment. The two former Python signer wrappers
were deleted rather than retained as alternate signing surfaces.

Both the native layer and `locked_runtime_bootstrap.py` enforce singleton
arguments. Receipt issuance accepts exactly one `--name` and one absolute
`--output`; first-case verification accepts exactly one absolute output root,
case ID, focused receipt, full receipt, report, and exactly one of
`--mode verify-only` or `--rerun-tests`. Unknown options, `--x=y`, duplicate
same-value or different-value options, user-supplied root tokens, copied
launchers, and mixed help/operation arguments fail before site imports or
artifact writes. Loader, shell-startup, Python-startup, and pytest environment
injection variables cannot change this chain.

Runner lock schema `5.0` / contract `offline-pytest-runner-v5` binds the native
source, rebuild script, resolved compiler identity, exact flags and mode
defines, both complete launcher identities, and parsed ELF metadata. The lock
continues to bind the complete project/runtime inventory. Receipt schema `5.0`
also binds `configs/canonical-test-contract.v1.json` and one trusted pytest
plugin emission containing the collection count, ordered collection node-ID
commitment, executed count, ordered executed node-ID commitment, outcome
counts, exit status, and a self-commitment. A successful receipt requires more
than one collected test, exact equality with the source canonical collection,
execution of every collected node ID, no skips, and exact pass/fail arithmetic;
terminal text such as `1 passed` or `999 passed` cannot forge it.

The first-case verifier/report is schema/version `3.0`. Its receipt summaries
carry the full pytest execution contract, its evidence embeds the complete
native-launcher contract from the validated runner lock, and its 37th gate is
`canonical_test_collections_bound`. The verifier's internal rerun invokes only
the extensionless native receipt launcher and never supplies a user root.
Pre-v5 receipts and pre-v3 reports are verify-only incompatible.

Fresh freeze preparation evidence, before the final source-identity lock was
issued:

- complete receipt module: `84 passed`, zero failures;
- complete first-case verifier module: `33 passed`, zero failures;
- complete human-audit module: `38 passed`, zero failures;
- native ELF/environment/argv attack selection: `10 passed`;
- canonical focused collection: `369` ordered node IDs,
  `sha256:f0780764120a9588c0fec7a466866ce9ed16a8a3074f2b237ddc3becf0bc3172`;
- canonical full collection: `824` ordered node IDs,
  `sha256:0830c93280bcaac536713f19cf4e727367478dc4dab9b376dc792d4a7a085fb2`;
- canonical collection contract commitment:
  `sha256:8ec486dd0a149f52b8ce6086502cd3b41e6e1336cea87bfc46eaa8bd6535147f`;
  file SHA-256:
  `sha256:7124697fa9b8c93b7ba5fcc2ed901bd25f1646097cdf33fe28a2f4f01c25d5d3`;
- native source/build/receipt/verifier SHA-256 values respectively:
  `cecbdbc15bd19b1be0081636140c9b7dedbcdb71778bfffe4e6b2773b9104015`,
  `5510db05ca84791ebebcd1056ffe3248b4c5da10941a8952f97bf2f702d67654`,
  `566735dff697f56dc7cea136b90f7fec1a1323fd3e6bb03ff819edc1b361c2a1`,
  and `304936fec757a5bd8b502758ad91b988251b119018a3d4172425a392ba7e3d96`.

The final retained-artifact renewal is deliberately executed only after this
record and every source/test/config file are frozen, followed by a final native
rebuild and runner-lock rebuild. Dynamic final lock, receipt, report, and
zero-write hashes are emitted by that frozen run and are not written back into
the identity-bound project afterward. The allowed final commands are the
extensionless launchers without a root option. The phase boundary remains
`STOPPED_AFTER_FIRST_CASE_BEFORE_REMAINING_P0_P1_GPU`; this round performs no
network/model call, GPU/training work, remaining nine P0 case, P1 case, or
write through `data/`.

## Ninth native signer-origin closure (2026-08-31, offline only)

Python receipts and the first-case report are now strict unsigned candidates:
receipt schema `6.0` and report/verifier schema `4.0` both require
`native_attested = false`. Authority is external to JSON and belongs only to
the two pinned static launchers. Runner lock schema `6.0` /
`offline-pytest-runner-v6` embeds native contract schema `2.0`, the public
`SHA256(shared_key)` key id, and a cross-binary contract over the key id plus
both launcher file hashes. It never stores the shared key.

One production maintenance build reads exactly 32 random bytes from
`/dev/urandom`, writes them only to a mode-`0600` header inside a private
mode-`0700` `/tmp/egsi-native-build.*` directory, compiles both binaries with
that same header, and deletes the header and directory immediately after both
compiler processes exit. Synthetic builds require both an absolute synthetic
`scripts/` output directory and an explicit 64-hex test key. Same path/key
builds are byte deterministic; different keys change both binaries.

The receipt launcher now waits for the locked Python child. It removes any
old sidecar before the child, leaves no sidecar on nonzero exit, and only after
a successful child safe-reads the mode-`0600`, single-link candidate and
atomically publishes `<receipt>.native-attestation`. In `--rerun-tests`, the
verifier waits for Python, authenticates the focused and full receipt
sidecars, then signs the report sidecar. In `verify-only`, all three sidecars
are authenticated before `fork`/`execve`, then authenticated again after the
read-only Python semantic replay.

Attestation v1 is exact LF-terminated canonical text containing a fixed
domain, fixed artifact basename, artifact SHA-256, cross-binary contract,
public key id, and HMAC-SHA256 tag. Exact reconstruction rejects missing,
reordered, duplicated, extra, malformed, replayed, path-swapped, key-swapped,
or byte-tampered evidence. Pre-freeze regressions confirmed:

- deterministic synthetic build/public-contract: `1 passed`;
- synthetic receipt HMAC recomputed independently with the explicit test key,
  plus failed-child stale-sidecar removal: `1 passed`;
- exact Python reviewer forge (`369`/`824` receipt claims and 37 fabricated
  gates) without native sidecars: rejected with native exit `66` before
  Python;
- artifact bytes, tag, key id, artifact path, unknown line, focused/full
  swap, report/receipt swap, and missing-sidecar attacks: `8 passed`;
- prior-key sidecars checked by an explicitly different synthetic key:
  rejected before Python (`1 passed`);
- an intermediate real focused canonical run completed all `371` then-current
  tests and produced a native sidecar; the subsequent retained rerun completed
  `372` focused and `827` full tests and all 37 first-case gates;
- immediate retained verify-only returned all 37 gates without execution
  replay and left all `176` output entries byte/metadata identical; snapshot
  SHA-256 was
  `5839d19fcb1c5d50f88be8c4d901891ab4af6fba3148d9fad1fd1397e24c03e6`.

As in the eighth round, the final random-key rebuild, lock renewal, canonical
contract renewal after the last regression additions, retained resigning,
zero-write replay, external compileall, and dynamic final hashes occur only
after this identity-bound record is frozen. No result is inferred from the
paper narrative. The phase boundary is still
`STOPPED_AFTER_FIRST_CASE_BEFORE_REMAINING_P0_P1_GPU`; no remaining P0/P1,
network/model, GPU/training, or `data/` write is performed.

## Tenth asymmetric signer hard-gate closure (2026-08-31, offline only)

The native attestation boundary now uses a fresh production RSA-2048 keypair
rather than the ninth-round shared HMAC secret. `scripts/locked_launcher.c` has
three separately compiled static roles: the execute-only receipt signer, the
execute-only report signer, and a readable public verifier. The two signer
ELFs contain the private RSA exponent only in their ephemeral build injection;
the public verifier and the mode-`0444` native build record contain only the
RSA modulus/SPKI, exponent `65537`, and a public-key identifier. The receipt
and report sides are mode `0111`; the public verifier is mode `0555`.

Attestation V2 is an exact, LF-terminated
`rsa-2048-sha256-pkcs1-v1_5`/SHA-256 PKCS#1 v1.5 signature over the fixed
artifact domain, basename, artifact digest, native-contract digest, and key
identifier. The public verifier recomputes that preimage and verifies all
three sidecars before entering Python and again after semantic replay. Missing,
old-key, replayed, swapped, malformed, forged, or byte-tampered receipt/report
sidecars therefore fail before candidate Python can issue a PASS result. The
native signers also set `PR_SET_DUMPABLE=0`, zero both core limits, and reject a
nonzero `TracerPid` before parsing an operation.

The retained official `--rerun-tests` execution regenerated both canonical
receipts, the historical-baseline evidence, and the report through the
execute-only report signer. The public `verify-only` operation then returned
`FIRST_CASE_GATE_PASSED` with all 37 gates and the unchanged stop marker
`STOPPED_AFTER_FIRST_CASE_BEFORE_REMAINING_P0_P1_GPU`. A before/after snapshot
of the retained focused/full receipts, their V2 sidecars, report, report
sidecar, and historical baseline compared raw bytes plus device, inode, mode,
link count, size, mtime, and ctime and was exactly identical: public replay is
zero-write.

Offline regression evidence includes the independent cryptography-oracle RSA
signature check, signer/verifier key separation, execute-only signer policy,
failed-child sidecar cleanup, public verifier rejection of tamper/replay/swap
and exact forged reports, and signer hardening checks (`6 passed` in the
asymmetric native subset). The complete locked canonical rerun remains the
source of truth for the broader verifier regressions; ordinary base-Python
execution is intentionally rejected by the runtime boundary rather than an
alternate receipt/report test surface. External `compileall` was directed to
`/tmp`; no `__pycache__`, `.pyc`, or `.pyo` was created under the tracked
source/config/spec trees.

This round did not contact a provider or model, run a remaining P0/P1 case,
start GPU/training work, or write `data/`. Historic provider failures and the
two semantic-invalid committed responses remain preserved, and
`human_semantic_judgment` remains `null`.

## Remaining-P0 serial hard stop (2026-08-31)

The frozen P0 list remains `configs/p0_cases.txt`, SHA-256
`a473acb5998f9c2aaf169f76123bcb5f8d48977a33a2f05ecfdd80ac5a2d9ec2`.
After excluding the already positive `ghsa-2m8h-fgr8-2q9w`, the exact serial
order was:

1. `ghsa-3wfj-vh84-732p`
2. `ghsa-2j4q-9fff-236j`
3. `ghsa-25gv-mvm7-5h3h`
4. `ghsa-3hrc-f439-727g`
5. `ghsa-2h63-qp69-fwvw`
6. `ghsa-268v-2qq7-84pf`
7. `ghsa-2hfj-jv6q-762v`
8. `ghsa-2hw2-62cp-p9p7`
9. `ghsa-3297-944x-j7x7`

All nine current contexts passed the official CLI read-only dry run before a
provider was constructed. The host `codex` installation had advanced to
`0.151.0`, while the adapter deliberately pins `0.150.1`. The exact
`0.150.1-linux-x64` package already present in the local npm content cache was
recovered offline under `.work/codex-0.150.1`; its native executable SHA-256 is
`abf1bb1643a79f73aa78ee627e111e02d4f8c98f25813a0cf6ce277709664386`.
It was selected only through the process `PATH`. The source provider file was
returned byte-for-byte to its original SHA-256
`593b0c3ec6e59c012b24e2a0a89f21764a2971c47b8dd5e3b6fab633868ca798`.
The v7 runner lock and RSA-attested 389/844 receipts/report were renewed before
the live continuation because the provider-file metadata had changed during
that diagnosis; the renewed first-case replay again passed all 37 gates. The
first positive/cache was reused and received zero new provider invocations.

The formal `egsi enrich` command then invoked only the first remaining case,
`ghsa-3wfj-vh84-732p`. It made exactly three unique prompt-v2.1 requests, all
with a current strict schema and closed Action DSL vocabulary:

| attempt | repair | request hash | response commitment | Codex thread ID | structured | semantic | latency ms |
|---:|---|---|---|---|---:|---:|---:|
| 0 | none | `sha256:90645ae15c5181eeae8b4104718ed0a9f82d382ed4f9c438aec31d04a8aad4cd` | `sha256:c02fdfa5c8fa030f8d9ad6c885e43ae61a771882c7d15845f83aa46167e75595` | `01a0571e-8ef9-7091-b40c-33ae6b3eb0c6` | true | false | 60,829 |
| 1 | `semantic_validation_failed` | `sha256:d3194c5bab028d296915a34746e054fff363f4e2458f470b1281ac3962a77951` | `sha256:0b6abf1fca1fdc4238e031d5fcc0e20780a4ee74da2de173a58eac7e7b6c8750` | `01a0571f-725c-7213-b9da-6f1282df4940` | true | false | 85,258 |
| 2 | `semantic_validation_failed` | `sha256:b6a9cb4e7cfb9e30e7070794b67e5481eea8a43306d249e621a87e24eef2c9e6` | `sha256:b4104f9a1c94273937b3677d4820ac4d74ffc1376ce80c2e8059de5b3a63d541` | `01a05720-c086-7d63-b25a-5f831b9c234d` | true | false | 52,226 |

Each committed audit/cache/request transaction is fully bound, has provider
identity kind `codex_thread_id`, and contains zero tool or unknown events. The
request hashes, prompt hashes, response commitments, cache keys, audit
commitments, and Codex thread IDs are pairwise unique. All three responses pass
strict JSON, provider schema, and Pydantic validation, but all three fail the
unchanged semantic validator because a trace `target_kind=path` target does not
exist at the vulnerable commit. The redacted invalid-target tokens are,
respectively:

- `sha256:d807a3ca9d090a96c8c9e255f1496031097f9cec678ff78315f3ebe824d0e50d`
- `sha256:0ed72adc5e49a3f32f9cd6195985e310eaba384e5e14980b89171dda0a592480`
- `sha256:6a1f63011e9a54844ef7262a2c7987698a79795a5a773b699cc6f51c2da6dbb6`

The final receipt records `semantic_invalid`, `attempts=3`,
`failed_attempt=3`, `validation_attempt=3`, and
`positive_transition_written=false`. No validator, Action DSL rule, schema, or
repair bound was relaxed. Aggregate usage for the three new invocations was
27,310 input, 0 cached input, 0 cache-write input, 3,042 output, and 117
reasoning-output tokens; aggregate latency was 198,313 ms (52,226--85,258 ms).

The retained shape at the hard stop is one positive enrichment, nine failure
receipts, eight teacher cache entries, 28 teacher audit manifests, zero episode
files, and zero trajectory files. The audit scan classifies six current bound
commits, two historical unbound semantic-invalid commits, 20 historical
`provider_failure_event` quarantines, zero malformed/cache-binding failures,
zero identity mismatches, and zero tool/unknown events. The current formal
enrichment provenance is
`sha256:49f15f9acd2acf66bc5b327c819692cee42a8b272282e5b4ee03720f06d9b53a`
with batch commitment
`sha256:7697a49019608dd3c6640b1484b75be8a0b6a1cf0830c6de09183258d55b047e`.
The redacted batch-stop result is
`.work/real-p0-codex-v2/reports/remaining-p0-batch-stop-ghsa-3wfj-vh84-732p.json`,
file SHA-256
`be866fe7b80a6e10ec31e16d73230f541e790468e89bf69c6421fda8187689ba`
and report commitment
`sha256:b579dc901ca887f59a471a9d9b198e1476287dcf1fc9000f1e69f7694318f2e0`.
It contains commitments and provider IDs, not raw prompts, responses, source,
or reasoning.

The hard-stop contract therefore prevented every later P0 invocation. No
trajectory/human-audit packet was generated or signed, no human judgment was
recorded, and P1, GPU, training, and `ai@10.8.0.11` were not started. The
terminal marker is
`STOPPED_ON_REMAINING_P0_CASE_ghsa-3wfj-vh84-732p_BEFORE_P1_GPU`.

## Prompt-v2.2 and source-controlled single-case recovery preparation (2026-08-31, offline only)

The remaining-P0 result above was not promoted as evidence that the model
could not solve `ghsa-3wfj-vh84-732p`. A fresh quality review showed that
prompt v2.1 never stated the validator's byte-exact repository-path semantics,
while the validator also did not yet prove line ranges, symbols, or canonical
spelling. The three v2.1 responses therefore remain preserved historical
attempts, not current reusable requests and not a basis for weakening the
validator.

The offline repair moves the current contract to prompt version 2.2:

1. `repository_paths.py` centralizes canonical vulnerable-snapshot paths and
   rejects `.`, `..`, absolute paths, backslashes, control bytes, duplicate or
   trailing separators, and non-byte-exact spellings. Git reads, candidate
   generation, and enrichment validation now share that boundary.
2. Every `locations[].path` and nonempty `target_location` is a canonical blob
   in the vulnerable commit. `target_kind=path` requires `target_id` to be an
   actual vulnerable blob and requires `target_location == target_id`. Line
   ranges must be inside that blob; qualified symbols are reduced to their
   final identifier and checked in a bounded range window. The retained real
   `3wfj` location is
   `activemq-broker/src/main/java/org/apache/activemq/broker/TransportConnection.java`,
   symbol `processControlCommand`, lines `1536--1542`.
3. The v2.2 prompt states those path, line, symbol, `target_id`, and
   `target_location` rules without echoing any failed model token. It adds the
   fixed repair category `invalid_canonical_path` and keeps exactly seven
   source-enumerable current variants. Dedicated v2.1 builders remain only
   for frozen historical first-case replay.
4. The local Codex adapter now requires an absolute single-link executable and
   exact SHA-256. Version probing and generation use one `O_NOFOLLOW`
   verified descriptor through `/proc/self/fd`, bind the complete
   `(dev, ino, mode, nlink, size, mtime_ns, ctime_ns)` identity before and
   after execution, and record the executable digest/stat commitment in new
   manifests and cache keys. The configured production binary remains Codex
   `0.150.1`, SHA-256
   `abf1bb1643a79f73aa78ee627e111e02d4f8c98f25813a0cf6ce277709664386`.

A new `fail-fast-enrich` transaction now holds `BatchLock` for the complete
run, processes cases serially, cannot disable first-failure stop, and creates a
redacted source-controlled terminal receipt if the runner raises before
publishing one. Existing reports are renamed into unique history files and
are never discarded merely because identical bytes were archived before.
The independent `verify-fail-fast-enrich` path reconstructs the ordered v2.2
request set, validates the complete audit lifecycle and cache preimages,
rebuilds exact provenance and summary objects, rejects duplicate/out-of-order
or post-failure invocations, and proves zero current request hashes for later
scope cases. Its strict report also binds fresh focused/full canonical-test
receipts and independently verifies their RSA-2048 SHA-256 PKCS#1 v1.5 native
attestations against the source-controlled public key and current code/lock
commitments.

The only recovery input is `configs/recover_3wfj_cases.txt`, containing exactly
`ghsa-3wfj-vh84-732p`; `configs/p0_cases.txt` remains the frozen scope used to
classify the later eight cases as forbidden current invocations. Current
offline evidence before the final source freeze is:

- fail-fast, renamed historical-audit, and cache regressions: `41 passed`;
- the complete suite excluding the two intentionally stale lock-sensitive
  modules: `757 passed` in `150.96 s`;
- compileall with bytecode redirected outside the project: exit `0`.

The frozen first-case verifier is now schema/verifier `5.1`. It replays the
exact pre-v2.2 semantic validator only inside the historical first-case path;
the current v2.2 validator still rejects that record's legacy
`path:line-range` target locations and does not make it reusable. The source
historical expectation now binds five unbound commits: two earlier first-case
responses and the three preserved `3wfj` v2.1 responses. Its scope no longer
claims that no remaining-P0 request was attempted: it explicitly records the
historical `3wfj` attempts and the stop before the later eight P0 cases, P1,
GPU, and training. The complete frozen first-case regression passed `44`
tests. Final canonical collection is `438` focused node IDs with commitment
`sha256:bf2d1df852996cebf601740c4b394e029df576308bba6c5429c83f7ebad340f8`
and `895` full node IDs with commitment
`sha256:04abfe551a198d399d98fd96a94b88e09e5b135acbb81367ff8ba689945effb8`;
the collection contract commitment is
`sha256:82b23af9f909501e8ecba8548706ea28c0e3eb94d17b9b04db3bb430539cef0f`.

At this checkpoint no v2.2 provider request has run and no live provider
audit, teacher-cache, enrichment-positive, episode, or trajectory artifact has
been added. One offline receipt rehearsal replaced the focused test receipt
with a failing unsigned candidate and removed its sidecar; that candidate is
not accepted evidence and both focused/full RSA receipts are reissued only
after the final source, runner, and native trust-root freeze. The later eight
P0 cases, P1, human signing, GPU, training, and `data/` remain untouched. The
final live outcome is intentionally recorded only by the strict fail-fast
report and its independent replay after those receipts are issued; no paper
claim is inferred in advance.

The final receipt rehearsal also exposed and fixed a fail-closed integration
bug before any provider request: the 1.4 MB v7 lock is larger than the Action
DSL canonical-object safety limit, so the fail-fast receipt verifier now uses
a dedicated canonical JSON commitment for that already bounded-on-read lock
instead of the small runtime-object helper. The RSA receipt checker is rerun
against the real final lock after this fix.

## Prompt-v2.2 single-case recovery result and evidence stages (2026-08-31)

The bounded live recovery has now run exactly once for the source-controlled
single-case input `configs/recover_3wfj_cases.txt`. It invoked only
`ghsa-3wfj-vh84-732p`, used the initial prompt-v2.2 variant, and produced a
semantically valid positive without a repair request. The canonical request
hash is
`sha256:3ff08b742a87a01533425742332ca34b6adb3330b543e52db72da157adc7f4a3`;
the teacher-response commitment is
`sha256:48b8fa67c281729ccd88eac6dbe5d6e5facc1d878bbd64ab45ba6cdb71659b1c`;
the Codex thread ID is `01a05831-51c4-7111-a095-90d420069d47`; and the
positive record commitment is
`sha256:5572a064994c82aa6157d711f513fde69b745cb0df07f7b80c2739f09eb6bcb8`.
The invocation used 10,183 input, 1,054 output, and 100 reasoning-output
tokens, with zero cached/cache-write input tokens and 56,526 ms recorded
latency.

The positive grounds all three `locations[]` entries in the vulnerable
`activemq-broker/src/main/java/org/apache/activemq/broker/TransportConnection.java`
blob. Their symbols and ranges are `processControlCommand` at 1534--1541,
`getCommand` at 1535, and `System.exit` at 1537. Every nonempty trace
`target_location` is the same canonical vulnerable path; non-path targets may
retain a null location. The unchanged v2.2 validator reports no invalid path,
range, symbol, goal, operation, target kind, or tool class.

The independent fail-fast report at
`.work/real-p0-codex-v2/reports/remaining-p0/fail-fast-report.json` has status
`REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW`. It binds the one current v2.2
attempt to its audit manifest, response commitment, cache preimage, provider
identity, executable identity, usage, and latency. It reconstructs all eight
later P0 cases as forbidden current scope and observes no request for any of
them. The retained audit history is classified, rather than silently trusted,
as one current v2.2 commit, three exact pre-batch first-case v2.1 commits, five
source-approved historical-unbound commits, and 20 source-approved quarantined
`provider_failure_event` transactions. The two historical set commitments are
fixed by `configs/historical-teacher-audit-expectation.v1.json`:
`sha256:3bb590d0ac78545a6a3552ac433ee745063801b5128f300ee2b9a8eadade5773`
for the committed artifact set and
`sha256:06052cdb04c203b994612d2381e1524d94574fb0520e414447a068d9071acb00`
for its response-commitment set.

Evidence is explicitly staged:

- **Pre-recovery first-case evidence:**
  `reports/first-case-hard-gate.json` and its RSA sidecar attest the historical
  28-manifest/8-committed/8-cache snapshot for
  `ghsa-2m8h-fgr8-2q9w`. They remain immutable replay evidence for that stage;
  they are not a current post-recovery inventory report and must not be
  described as one.
- **Post-recovery fail-fast evidence:** the current tree contains 29 teacher
  manifests, nine committed cache entries, two positive enrichments, eight
  retained remaining-case failure receipts, and zero episode/trajectory
  files. Its strict fail-fast report and current RSA test receipts are the
  authoritative automated evidence for the v2.2 recovery stage.
- **Human review evidence:** the existing `reports/human-audit-packet.json`
  predates both positive smoke stages and remains an
  `AUTOMATED_GATE_FAILED` historical packet. It is not current evidence. No
  new human-audit packet or signature is generated in this recovery stage;
  `human_semantic_judgment` remains unset.

No provider request is repeated during offline repair, receipt renewal, or
verification. The phase boundary remains before the later eight P0 cases, P1,
trajectory compilation, GPU, training, and every write through `data/`.

## Prompt-v2.3 native live re-attestation preparation (2026-09-01, offline source freeze)

The v2.2 positive for `ghsa-3wfj-vh84-732p` remains preserved exactly, with
canonical request hash
`sha256:3ff08b742a87a01533425742332ca34b6adb3330b543e52db72da157adc7f4a3`.
It is historical positive evidence only: it is not promoted to current v2.3
evidence and is never rewritten or deleted. Prompt v2.3 makes grounded
location metadata (`path`, `symbol`, `start_line`, and `end_line`) required and
non-null, retains frozen v2.1/v2.2 request reconstruction for historical
replay, and adds fixed metadata-repair variants without weakening the semantic
validator.

The fail-fast verifier now independently replays a one-to-three-attempt STOP
sequence. It requires variant zero first, unique request/prompt/cache and
provider invocation identities, strictly increasing invocation times, causal
repair transitions, exact semantic or record-construction failures, and an
exact terminal receipt. A valid attempt cannot be relabelled as STOP, a failed
case cannot retain a contradictory current positive, and v2.2 completion can
select only the explicit single-case v2.3 re-attestation mode; it cannot skip
`3wfj` to reach a later P0 case.

The final permitted provider action is therefore exactly one official native
`run_fail_fast_enrich` invocation over `configs/recover_3wfj_cases.txt`, with
`configs/p0_cases.txt` as the frozen scope and at most three prompt-v2.3
attempts. The native launcher generates an independent random run ID and nonce
plus realtime and monotonic start timestamps before Python starts. Its signed
live-attestation payload binds the source case digests, recovery mode/reason,
complete pre/post teacher audit/cache/enrichment/report inventories, exact
created/modified/deleted delta, each newly created current manifest and cache
response, provider response and executable-identity commitments, and the
fail-fast report/provenance/summary hashes. The public native verifier checks
the RSA sidecar before Python starts, replays all fail-fast semantics, repeats
the full inventory comparison after replay to close report/cache TOCTOU, and
checks the RSA sidecar again after Python exits.

Offline attack tests reject pre-existing current manifests or caches, forged
old mtimes, symlink/hardlink/special-node evidence, missing required batch
artifacts, sidecar removal or mutation, wrong attestation destinations,
artifact mutation, and semantic-replay races. The bootstrap pre-snapshot and
project runtime snapshot are byte-for-byte identical on safe trees. At this
source-freeze checkpoint no prompt-v2.3 provider invocation has run, current
v2.3 attempt count is zero, and the later eight P0 cases, P1, trajectories,
GPU, training, and `data/` remain untouched. The final result is written only
to the post-run strict artifacts under `.work/real-p0-codex-v2/reports/`; this
source-controlled section deliberately makes no advance success claim.

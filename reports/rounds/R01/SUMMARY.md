# R01 summary

Round R01 on `research/naacl2027-r01`. Engineering closed for inventory, isolation, and offline fixture replay. Data is **partial**: 24 real candidate pairs, 2 conventional ready pairs, **0 logic ready pairs**. No model API, no training, no detection scores.

## Completed

- Inventoried origin `skadiscarlet/iclr` (SSH via `ssh.github.com:443`), HEAD, default branch `main`, fetch ok, dirty only for the leftover untracked plan file and in-progress reports.
- Reused EGSI (`src/egsi`, tests, idea-stage) instead of rewriting it. Added `src/sbs` with actor schema, IsolatedStore, History/SBS views, fixture replay, and CLI.
- Actor views reject CVE / gold_label / patch / fix_pairing. Evaluator roots and out-of-root paths fail closed. Budget exhaustion ends `UNRESOLVED`, not refuted/safe. Counter-evidence can revise a supported hypothesis to refuted.
- Four synthetic fixtures: support → FINISH/supported; counter → FINISH/refuted; insufficient → UNRESOLVED; budget → UNRESOLVED/budget_exhausted.
- Registered 24 catalog pairs (12 conventional, 12 authorization claims) from the local EGSI T1 catalog (`dataset_revision=sha256:295bc975…` of `data/catalog/cases.jsonl`). All `split=dev_pilot`. `human_verified_pairs=0`.
- Static-checked local git cache + artifact licenses + cited blobs. Generated actor-only views for `r01-pair-01` (pgjdbc) and `r01-pair-12` (apache/cxf) under gitignored `local_data/`.
- Read local CWE-Bench-Java README (data primarily hosted at IRIS `v2/data`; local clone HEAD `afe0ebd0…`, MIT) and Vul4J licenses (code GPL-3.0, data CC-BY-4.0, HEAD `376411da…`). Did not download whole benchmarks or run Maven/Gradle.
- CLI: `python -m sbs doctor|validate-registry|replay|validate-reports`.

## Old assets (see migration.csv)

Keep EGSI code/tests/specs. Adapt pyproject, gitignore, AGENTS.md, configs. Archive-reference ICLR narrative and the historical EGSI design snapshot. Defer native-signer scripts and the untracked root `R01_NAACL2027_EXECUTION_PLAN.md` (copied to `plans/rounds/R01.md`, not committed from the root path). No `git reset --hard`, `git clean -fd`, or force-push.

Unverified EGSI experiment numbers in `MANIFEST.md` / `.work` remain `unverified_legacy_result` for SBS claims.

## Task status

| Task | Status |
|---|---|
| T00 inventory | completed |
| T01 migration | completed (no destructive cleanup commit; plan copied, root file left untracked) |
| T02 contract / isolation | completed |
| T03 registry | completed with data shortfall |
| T04 fixture replay | completed |
| T05 reports | this file |
| T06 push | after commit B |
| T07 CI | not in R01 scope |

## Counts (split; not interchangeable)

| Kind | N | Notes |
|---|---:|---|
| Candidate pairs | 24 | `metadata/r01_candidates.jsonl`; 24 project families |
| Real ready pairs | 2 | conventional only (`r01-pair-01`, `r01-pair-12`) |
| Logic ready pairs | 0 | generic obligation templates only |
| Human-verified pairs | 0 | agent cannot self-claim |
| Fixture cases | 4 | synthetic; not counted as real |
| Independent projects in ready set | 2 | pgjdbc, apache/cxf |

`data_status=partial` because the 2+2 ready-pair goal is unmet on the logic side. Conventional extras that had locatable source but no actor-view generation stay `source_resolved`, not ready.

## Checks

Exact commands (ran twice from a clean process except where noted):

```bash
python -m pytest tests/sbs -q --tb=short
python -m sbs doctor --output reports/rounds/R01/inventory.json
python -m sbs validate-registry --input metadata/r01_candidates.jsonl
python -m sbs replay --config configs/r01_smoke.json --out artifacts/r01_smoke
python -m sbs validate-reports --round R01 --phase pre-push
```

Pytest both runs: **28 passed**, exit 0. Kept EGSI `tests/test_package.py` + `tests/contracts/test_case.py`: **13 passed**. Collect: **1377** tests (1349 pre-existing + 28 R01); none of the pre-existing tests were deleted.

Replay: `model_calls=0`, `detection_metrics=null` / `not_evaluated`, terminals only `FINISH` or `UNRESOLVED`. History and SBS written for all four fixtures. Two runs semantically identical aside from timestamps. `ValueScorer.available=false`.

See `checks.json` for timestamps, exit codes, and log hashes.

## Resources (non-secret)

Linux; Python 3.12.9; OpenJDK 21.0.12.1; Git 2.55.0; 24 CPUs; ~31 GiB RAM; ~323 GiB disk free; 1× NVIDIA GeForce RTX 3050 (8 GiB). Model API credentials present: false. New API budget: 0. Local data catalog present (gitignored). GPU was **not** used to upgrade the fixture run.

## Main failures / gaps

- **0 logic ready pairs.** Authorization catalog rows have only the generic “establish attacker principal…” template; fields in `authorization_model` are `unknown`. Not relabeled as conventional to fill the quota.
- License files missing on some artifact rows → `license_unclear`.
- One authorization pair missing a cited blob (`r01-pair-20`).
- `assistant_repo_access` remains `unverified_404`.
- Full pre-existing 1349-test EGSI suite was not executed end-to-end this round; a kept subset plus collect-only was recorded.

## Unverified

OpenReview/ORCID/service-contributor eligibility (`needs_human_confirmation`). ChatGPT GitHub App repository grant. Any detection or training number. Product-specific obligations for logic pairs.

## Next decisions (at most three)

1. Annotate citable obligations for logic pairs in R02, or drop that quota.
2. Authorize a frozen-model pilot or keep `model_calls_allowed=0`.
3. Grant GitHub App access to `skadiscarlet/iclr` so the connector 404 can be re-checked.

## Git

- Base: `18458b2cceaeef3cd18c8b455b1f0724d50d94c9` (`main`)
- Implementation SHA (A'): `dcf80581b7d887a761d9acf484f6fef13a516d8c`
- Branch: `research/naacl2027-r01`
- Report commit B and receipt C recorded after this file is committed.

R01 stops here. R02 is not authorized by this round.

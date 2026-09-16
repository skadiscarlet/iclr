# Phase-A Java Web Enrichment and Trajectory Completion Record

Date: 2026-08-29  
Decision: **REVISE BEFORE PHASE B**

## Scope and decision

Phase-A engineering implementation is acceptable for the prototype/experiment stage. The fixture runs are validation artifacts only: they are not training data, are not promotable, and must never be used to start GPU training. Before Phase B, improve bounded context chunking/sampling without relaxing the security validator, then run a real-provider P0, perform human audit, and only then run real-provider P1 with measured cost and latency.

## Fresh engineering gates

- `pytest --cov`: **444 passed in 79.81s**; TOTAL **4205 statements, 620 missed, 85% coverage**.
- `compileall`: exit 0.
- `python -m build --wheel` was technically unavailable: `No module named build`.
- Fallback `pip wheel --no-deps --no-build-isolation` succeeded.
  - wheel: `dist/egsi-0.1.0-py3-none-any.whl`
  - wheel SHA-256: `b8417fdc40c9f93fa6ab8ef54f4fb0a0e924d816c5b65108108c1651b42561cd`
  - packaged schema resource SHA-256: `8d11862d0923e201965e8c1dcadb29f12198e13924b8d066c3af7d3f96ab1234`

## Catalog and collection observations

- E-GSI catalog: 300 valid cases.
- External validation: `validated JSONL=5`, `train_dev=260`, `eval=40`, exact quotas, `repo_cap=5`, `alias_overlap=0`, `repo_overlap=0`, `sources=112`.
- Read-only collection validation: `valid=true`, `case_count=300`, `errors=[]`.
- Source collection report SHA ends in `3888...9cb`; its hash and mtime remained unchanged during validation.
- Frozen-list SHA-256: P0 `a473ac...d9ec2`; P1 `fc2df4...3cfbf`.
- Secret scan result: false.

## Final offline fixture results

| Run | Requested | Processed | Failed | Restart enrichment reuse | Trusted replay | Leakage | Nonzero reward | Illegal | Mode | Promotable |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| P0 `.work/final-phase-a-p0` | 10 | 8 | 2 | 8 | 8 | 0 | 0 | 0 | fixture | false |
| P1 `.work/final-phase-a-p1` | 30 | 24 | 6 | 24 | 24 | 0 | 0 | 0 | fixture | false |

Fixture usage, tokens, and latency are all zero. No live provider was called, so actual live-provider cost and latency remain **unknown**, not zero.

### Stable bounded failures

All failures are stable `enrichment_preparation` / context-bound failures; the validator was not relaxed.

- P0: `ghsa-3wfj-vh84-732p`, `ghsa-3297-944x-j7x7`.
- Additional P1 failures: `ghsa-3pqg-4rqg-pg9g`, `ghsa-76v2-48w6-crxr`, `ghsa-5wm5-8q42-rhxg`, `ghsa-3w85-5p9g-h334`.

The approximately 20% context-preparation failure rate motivates bounded context chunking/sampling before any real-provider gate.

## Reproducibility receipts

These were final two-stage CLI validations rather than `run_pilot`; consequently no combined pilot-summary artifact was produced.

- Final summary: `.work/final-phase-a-summary.json`
  - SHA-256: `ec7bc57662b5c9a67e60e4a68c50f5ccbb8e039c85945cf7de8155fa1f5edc6d`
- Artifact replay verification SHA-256: `ac4026a22b78895883720623109e7d106d35c690e71c09b7146889b85cd88b32`
  - exact Parquet roundtrip: P0 8, P1 24
  - trusted replay passed
  - key hits=0, value hits=0, reward=0

### P0 hashes

- enrichment report (`.work/final-phase-a-p0/reports/enrichment-summary.json`): `9f1106d2a9829e8dc38a8f4565592b4718284a865110be73c848b4bd60acfbbe`
- trajectory report (`.work/final-phase-a-p0/reports/trajectory-validation.json`): `4ec1b0db334520218e16afad717c538a35a367f4d4eb9d81e6e7c8449e1d5586`
- Parquet: `b0e2fad2de96f1ac22ba7d4f5dd78a4388bcec5e742cba310bcb0864c4bd20c6`
- provenance manifest: `sha256:5f66228a8d32ed6ae2951e773266c4faf047e0f5a3ca4516be952135f8413877`
- trajectory manifest: `sha256:6820b239d0570eca666627215d700138b296d9e5ab03a742ad9033c88cf99a26`
- trajectory artifact commitment: `sha256:3f9b236838884aee19d83edcf1594887ae2cc82960dbb2c09f56aa23d01cbedb`

### P1 hashes

- enrichment report (`.work/final-phase-a-p1/reports/enrichment-summary.json`): `8925727a4047b04c555abbcec7f7f16ff0fb8205d38da17955ac63fbc12d10a2`
- trajectory report (`.work/final-phase-a-p1/reports/trajectory-validation.json`): `ebc01d40497f7de0e83f5f93e111e6c4c77984a27577a2eae0be7081b6a1c8ef`
- Parquet: `3279c62027bf4e6ab1fbbace0c0a485750291f11287734a45609960b989da9fa`
- provenance manifest: `sha256:db98089d90b4453b51744cefbb96084a6dd0a41618fa5a6b030f6f0bdc70de4b`
- trajectory manifest: `sha256:33fb7d2486cd8b55d7b95337e6d8b75e3ee29807922c93cdcb18e9aad64409ad`
- trajectory artifact commitment: `sha256:9a9f78b634745dd52c3ebce2f0d66b4eca675171c81f864f977713afc8e323fa`

## Deviations and stronger-than-planned controls

- `.git` was an empty read-only mount, so no commit was created; content hashes substitute for commit identity in this record.
- `data/` was external and read-only. Nothing was promoted and `data/README.md` was not modified.
- No live P0/P1 run was performed.
- `episode_cache_reused=0` is expected under H3 transaction semantics even when enrichment cache reuse is 8/24.
- The implementation added controls stronger than the original plan: artifact commitments, model identity binding, locks, safe I/O, and oracle-scalar canonicalization.

## Required next gate

1. Improve bounded context chunking/sampling while preserving the current validator.
2. Run real-provider P0 and record actual usage, cost, and latency.
3. Human-audit P0 outputs and failures.
4. Only after approval, run real-provider P1 and repeat audit.
5. Do not promote fixture artifacts and do not start GPU training in the current state.

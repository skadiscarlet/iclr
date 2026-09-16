# iclr / EGSI + SBS

This repository contains the EGSI Java-web audit prototype and a parallel **SBS** track for NAACL 2027 (R01).

SBS asks whether an explicit representation of a hypothesized security relation, supporting evidence, counter-evidence, and unknowns helps a language model make *grounded* code-review decisions under a finite observation budget. R01 only stands up inventory, isolation, and **offline fixture replay**. It does not train Q/V, call a model, or report detection scores.

## What R01 supports

- `python -m sbs doctor` — non-secret inventory (origin, HEAD, default branch, WIP, fetch, resource versions).
- `python -m sbs validate-registry` — candidate JSONL with real locators or explicit nulls.
- `python -m sbs replay --config configs/r01_smoke.json` — frozen fixture replay for `history` and `sbs` views.
- `python -m sbs validate-reports --round R01 --phase pre-push` — machine-readable report checks.
- Pytest coverage of actor schema isolation, budget exhaustion, counter-evidence revision, and History/SBS agreement.

## What R01 does not support

- Live model API calls (`model_calls_allowed=0`).
- Detection accuracy / F1 / training loss (`not_evaluated`, never `0`).
- Autonomous vulnerability discovery, exploit/PoC generation, or third-party Maven/Gradle builds.
- Claiming `review_status=accepted` or `human_verified` pairs.
- Filling the 24-candidate / 4-ready-pair targets with synthetic or relabeled bugs.

Fixture cases under `fixtures/r01/` are synthetic, payload-free, and labeled `material_kind=fixture`. They are **not** real CVE pairs. Real candidate metadata lives in `metadata/` (management-side only). Third-party source and evaluator answers stay in gitignored `local_data/`. Full replay dumps stay in gitignored `artifacts/`.

## Run the R01 checks

```bash
python -m sbs doctor --output reports/rounds/R01/inventory.json
python -m sbs validate-registry --input metadata/r01_candidates.jsonl
python -m sbs replay --config configs/r01_smoke.json --out artifacts/r01_smoke
python -m pytest tests/sbs -q
python -m sbs validate-reports --round R01 --phase pre-push
```

Smoke config equivalents: `mode=fixture_replay`, `seed=17`, `representations=["history","sbs"]`, `evidence_order=frozen`, `max_observations=4`, `split=dev_pilot`, `model_calls_allowed=0`, `compute_detection_metrics=false`. `ValueScorer` is unavailable.

## EGSI prototype (pre-existing)

The existing `egsi` package, `idea-stage/` specs, and `paper-stage/` ICLR narrative remain in place. They are keep/adapt/archive assets for the earlier prototype, not deleted. EGSI CLI: `egsi` / `python -m pytest tests` (large pre-existing suite). Do not treat unverified legacy experiment numbers as SBS baselines.

## Training

Q-return / IQL-style updates are **not implemented**. The `ValueScorer` interface exists only to fail closed (`available=false`).

# Pragmatic P1 Incremental Runbook

## Fixed scope and authorization gate

- Project root: `/home/furina/iclr`
- Verified read-only P0 base: `.work/p0-training-ready-v1`
- New live incremental root: `.work/real-p1-pragmatic-v1`
- Final P1 package: `.work/p1-training-ready-v1`
- Ordered P1 list: `configs/p1_cases.txt` (30 train cases)
- Ordered incremental list: `configs/p1_pragmatic_incremental_cases.txt`
  (exactly P1 minus P0, 20 train cases)
- Provider config: `configs/providers.local.toml`
- Provider slots: at most `20 * 2 = 40`
- Provider-internal retries: forced to `0` by pragmatic CLI routing
- Per-slot timeout: provider config must resolve to `600 s`
- Global wall clock: `28800 s`

The live command below is an explicit provider-spend boundary. Run it only
after the operator authorizes the 20-case P1 epoch and confirms the fixed
root, model alias, timeout, and 40-slot ceiling. Offline tests and aggregation
never imply authorization for that command.

Do not use old fixture/offline roots such as `.work/context-v2-fixture-p1`,
`.work/final-phase-a-p1`, `.work/task13-offline-p1*`, or
`.work/p1-pragmatic-control-v1` as the incremental source. Do not add dev/test
cases, launch GPU work, or start training from this runbook. The only accepted
incremental source is the strict live batch at
`.work/real-p1-pragmatic-v1`.

## Offline preflight

Run from `/home/furina/iclr`:

```bash
cd /home/furina/iclr

PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  .work/offline-test-runner-venv/bin/python - <<'PY'
from pathlib import Path
from egsi.contracts.case import load_case_catalog
from egsi.generation.pilot import read_case_ids

root = Path('/home/furina/iclr')
p0 = read_case_ids(root / 'configs/p0_cases.txt')
p1 = read_case_ids(root / 'configs/p1_cases.txt')
incremental = read_case_ids(
    root / 'configs/p1_pragmatic_incremental_cases.txt'
)
catalog = {
    case.case_id: case
    for case in load_case_catalog(root / 'data/catalog/cases.jsonl')
}
assert len(p0) == 10
assert len(p1) == 30
assert incremental == [case_id for case_id in p1 if case_id not in p0]
assert len(incremental) == 20
assert set(incremental).isdisjoint(p0)
assert set(incremental).union(p0) == set(p1)
assert all(catalog[case_id].split == 'train' for case_id in incremental)
print({'p0': 10, 'p1': 30, 'incremental': 20, 'max_slots': 40})
PY

PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  .work/offline-test-runner-venv/bin/python -m pytest \
  -p no:cacheprovider -q \
  tests/generation/test_incremental_training_ready.py \
  tests/generation/test_pragmatic_batch.py \
  tests/generation/test_training_ready.py \
  tests/integration/test_cli_pilot.py \
  tests/test_cli.py

PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  .work/offline-test-runner-venv/bin/python -m egsi.cli \
  build-incremental-training-ready --help
```

Validate the provider configuration without printing credentials:

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  .work/offline-test-runner-venv/bin/python - <<'PY'
from pathlib import Path
from egsi.config.providers import load_provider_config

config = load_provider_config(Path('configs/providers.local.toml')).active
assert config.kind == 'codex_exec'
assert config.timeout_seconds == 600.0
print({
    'kind': config.kind,
    'model': config.model,
    'timeout_seconds': config.timeout_seconds,
    'cli_retry_override_at_launch': 0,
})
PY
```

## First live invocation

This is the only command here that invokes the provider:

```bash
cd /home/furina/iclr
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  .work/offline-test-runner-venv/bin/python -m egsi.cli batch-enrich \
  --root /home/furina/iclr \
  --case-file configs/p1_pragmatic_incremental_cases.txt \
  --output-root .work/real-p1-pragmatic-v1 \
  --provider-config configs/providers.local.toml \
  --max-provider-attempts 2 \
  --retry-transport-once \
  --global-wall-clock-seconds 28800
```

Do not add `--resume` on the first invocation. Existing state causes a
fail-closed error rather than silently opening another epoch.

## Resume after interruption

Use the identical arguments and add only `--resume`:

```bash
cd /home/furina/iclr
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  .work/offline-test-runner-venv/bin/python -m egsi.cli batch-enrich \
  --root /home/furina/iclr \
  --case-file configs/p1_pragmatic_incremental_cases.txt \
  --output-root .work/real-p1-pragmatic-v1 \
  --provider-config configs/providers.local.toml \
  --max-provider-attempts 2 \
  --retry-transport-once \
  --global-wall-clock-seconds 28800 \
  --resume
```

Reserved or provider-invoked slots are already consumed. Terminal cases make
zero teacher calls on resume. Two consumed slots are terminal; no case receives
a third provider call. Configuration drift, partial control-plane files, or
state corruption stops the whole batch.

## Aggregate P0 plus the incremental live batch

The additive aggregation command makes zero provider calls and never modifies
either source root:

```bash
cd /home/furina/iclr
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  .work/offline-test-runner-venv/bin/python -m egsi.cli \
  build-incremental-training-ready \
  --root /home/furina/iclr \
  --base-package-root .work/p0-training-ready-v1 \
  --incremental-batch-root .work/real-p1-pragmatic-v1 \
  --case-file configs/p1_cases.txt \
  --incremental-case-file configs/p1_pragmatic_incremental_cases.txt \
  --output-root .work/p1-training-ready-v1
```

Required reports:

```text
.work/p1-training-ready-v1/reports/
├── p1-coverage-provenance.json
├── trajectory-validation.json
├── human-audit-packet.json
├── human-audit-packet.md
├── artifact-manifest.json
└── artifact-manifest.json.sha256
```

Coverage must preserve `configs/p1_cases.txt` order and satisfy:

```text
requested = base_requested + incremental_requested = 10 + 20 = 30
requested = success + failed + gap = 30
```

Only `success` cases enter enrichment, episode JSONL, and Parquet artifacts.
Valid terminal provider failures remain `failed`; missing or invalid per-case
records remain explicit `gap` entries. Partial coverage does not fail the
automated gate. The gate covers strict structure, zero policy leakage/nonzero
reward/illegal action counts, and closed replay only.

Before any later GPU or training step, independently verify the output
manifest sidecar, every artifact size/hash, `train.parquet == ordered JSONL`,
and the human-audit packet. This runbook itself stops after aggregation.

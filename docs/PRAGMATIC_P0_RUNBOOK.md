# Pragmatic P0 Remaining-Batch Runbook

## Fixed scope

- Project root: `/home/furina/iclr`
- Historical first-case root (read-only): `.work/real-p0-codex-v2`
- Live remaining-batch root: `.work/real-p0-pragmatic-v1`
- Frozen remaining cases: `configs/p0_pragmatic_remaining_cases.txt`
- Provider configuration: `configs/providers.local.toml`
- Cases: exactly P0 cases 2–10, in the order inherited from `configs/p0_cases.txt`
- Provider slots: at most `9 * 2 = 18`
- Provider-internal retries: forced to `0`
- Per-slot provider timeout: the validated config value, expected `600 s`
- Global wall clock: `14400 s`

This workflow does not run P1, GPU jobs, training, or any provider call during
the test/package phases. It never writes under `data/` and never writes to the
historical root.

## Offline preflight

Run from `/home/furina/iclr`:

```bash
cd /home/furina/iclr

PYTHONDONTWRITEBYTECODE=1 python - <<'PY'
from pathlib import Path
from egsi.generation.pilot import read_case_ids

root = Path('/home/furina/iclr')
p0 = read_case_ids(root / 'configs/p0_cases.txt')
remaining = read_case_ids(root / 'configs/p0_pragmatic_remaining_cases.txt')
assert len(p0) == 10
assert remaining == p0[1:]
assert len(remaining) * 2 == 18
print({'p0': len(p0), 'remaining': len(remaining), 'max_slots': 18})
PY

PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider \
  tests/generation/test_pragmatic_batch.py \
  tests/generation/test_training_ready.py \
  tests/integration/test_cli_pilot.py \
  tests/test_cli.py -q

PYTHONDONTWRITEBYTECODE=1 python -m egsi.cli batch-enrich --help
PYTHONDONTWRITEBYTECODE=1 python -m egsi.cli build-training-ready --help
```

Confirm the local provider TOML is a single-link, owner-only regular file
without printing it:

```bash
PYTHONDONTWRITEBYTECODE=1 python - <<'PY'
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

This is the only command in the runbook that starts the remaining P0 provider
batch:

```bash
cd /home/furina/iclr
PYTHONDONTWRITEBYTECODE=1 python -m egsi.cli batch-enrich \
  --root /home/furina/iclr \
  --case-file configs/p0_pragmatic_remaining_cases.txt \
  --output-root .work/real-p0-pragmatic-v1 \
  --provider-config configs/providers.local.toml \
  --max-provider-attempts 2 \
  --retry-transport-once \
  --global-wall-clock-seconds 14400
```

Do not add `--resume` on the first invocation. If
`reports/pragmatic-batch-state.json` already exists, the command fails closed
instead of silently starting another epoch.

## Resume after interruption

Use the identical configuration and add only `--resume`:

```bash
cd /home/furina/iclr
PYTHONDONTWRITEBYTECODE=1 python -m egsi.cli batch-enrich \
  --root /home/furina/iclr \
  --case-file configs/p0_pragmatic_remaining_cases.txt \
  --output-root .work/real-p0-pragmatic-v1 \
  --provider-config configs/providers.local.toml \
  --max-provider-attempts 2 \
  --retry-transport-once \
  --global-wall-clock-seconds 14400 \
  --resume
```

`reserved` and `provider_invoked` slots are already consumed. A terminal case
makes zero teacher calls on resume. A case with two consumed slots is finalized
as failed and never receives a third call. Corrupt state or configuration drift
stops the whole batch.

Inspect only the bounded reports:

```bash
python -m json.tool .work/real-p0-pragmatic-v1/reports/pragmatic-batch-state.json
python -m json.tool .work/real-p0-pragmatic-v1/reports/pragmatic-batch-report.json
```

`provider_invocations.kind` is `exact` only when every consumed slot reached a
known completed result. It is `upper_bound` after an interrupted/unknown slot;
the report does not relabel an uncertain slot as a proven provider call.

## Build the ten-case training-ready package

This command performs no provider call:

```bash
cd /home/furina/iclr
PYTHONDONTWRITEBYTECODE=1 python -m egsi.cli build-training-ready \
  --root /home/furina/iclr \
  --historical-root .work/real-p0-codex-v2 \
  --batch-root .work/real-p0-pragmatic-v1 \
  --case-file configs/p0_cases.txt \
  --output-root .work/p0-training-ready-v1
```

Required outputs:

```text
.work/p0-training-ready-v1/
├── enrichment/<accepted-case>.json
├── episodes/*.events.jsonl
├── episodes/*.transitions.jsonl
├── trajectories/train.parquet              # only when >=1 accepted case
└── reports/
    ├── p0-coverage-provenance.json
    ├── trajectory-validation.json
    ├── human-audit-packet.json
    ├── human-audit-packet.md
    ├── artifact-manifest.json
    └── artifact-manifest.json.sha256
```

Coverage must satisfy, in frozen P0 order:

```text
requested = success + failed + gap = 10
```

Only `success` cases enter JSONL/Parquet. `failed` and `gap` cases remain
explicit coverage entries and are never training samples. The historical first
record is copied byte-for-byte only after its current source context, frozen
v2.1 prompt variant, record commitment, DSL vocabulary, and frozen semantic
contract revalidate.

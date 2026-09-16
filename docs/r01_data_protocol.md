# R01 data protocol

## Roots

| Root | Git | Visible to actor replay |
|---|---|---|
| `fixtures/r01/` | committed synthetic fixtures | yes |
| `metadata/` | committed locators/licenses/hashes or nulls | no |
| `local_data/` | gitignored third-party source + evaluator answers | no |
| `artifacts/` | gitignored full dumps | n/a (outputs) |
| `reports/` | committed redacted summaries | n/a |

Actor root and evaluator root are distinct directories. Schema validation rejects answer fields (`cve`, `gold_label`, `patch`, `fix_pairing`, …). Isolation rejects unauthorized evidence IDs and paths outside the actor root.

## Split

Every R01-touched real sample is `dev_pilot`. Formal train/dev/test freeze is deferred. Do not silently move these rows into a later test set.

## Status values

`metadata_only` / `source_resolved` / `evidence_draft` / `human_verified` / `excluded`.

Automated tools must not emit `human_verified`.

## Ready pairs

A real pair is `ready` only when versions are locatable, license is recorded, a cited path exists, an actor view without answers can be built, **and** (for logic claims) the obligation basis is more specific than a generic family template. CWE IDs are not sufficient to confirm logic bugs. Shortfalls set `data_status=partial` or `blocked`.

## Redistribution

Do not commit third-party source unless redistribution has been checked. Prefer locators, revisions, license notes, and hashes.

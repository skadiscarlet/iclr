# R02C analysis

Semantic scores, reward and Q/V are **null / not_started_by_design**. This is an interface/state-flow pilot, not an SBS performance comparison with R02B.

## Legacy outputs (offline)

Registered runs 2+18+18=38 unique events. Duplicate ledger copies counted once. Identical raw hashes still counted as distinct calls (9 duplicate-hash groups). Conservative consumed for new-call limits = 38.

Layered re-parse of the 37 present raws: envelope `whole_response_fence_removed`, JSON valid. Shape valid only on 5 (authored E0 JSON with `verdict=supported` after fence strip). 32 E1-shaped objects have illegal enums (`True`/`Yes`) or other shape errors. Retrospective parse does not recover policy trajectory.

## Executor crash then real E0

1. `2026-09-18T043902+0000` — load then `invalid literal for int() ... 'input_ids'` (0 reservations).
2. `2026-09-18T044110+0000` — 12 reservations, `AttributeError` in `generate_chat` because a BatchEncoding has `.to` but not `.dim()`. Raw files empty. Kept on the ledger.
3. One counted debug `generate_chat` (seq 13) after the fix; 14 new tokens.
4. `2026-09-18T044445+0000` — protocol E0, 11 reservations, code_sha `4243137c57b2bee6db26662893a89e6e71b0c18f`.

## E0 first-pass / after-reprompt

| case | contract | first | after repair | error after repair |
|---|---|---|---|---|
| probe-01 | history_note | **accepted** | n/a | — |
| probe-02 | sbs_note | fail | fail | `invalid_array_item:entities` (objects, not strings) |
| probe-03 | sbs_note | fail | fail | missing keys + entity objects |
| probe-04 | final | fail | fail | keys `supported`/`refuted`/`unresolved` instead of six-key final |
| probe-05 | final | fail | fail | same polarity-as-keys shape |
| probe-06 | final | fail | fail | same |

Gate: `e0_schema_or_refs_failed`. E1 generate_count=0.

Authored public texts: `reports/rounds/R02C/e0_public/`. Example accepted note (probe-01):

```json
{"note": "The function `identity(x)` is defined to return its input `x` unchanged. No changes were made to the function's behavior based on the given hypothesis."}
```

(wrapped in a whole-response fence; normalize-only removal accepts it.)

Finals were not `supported`/`refuted`/`unresolved` verdicts. No silent remap.

## State-change chain

No E1 episode ran, so **no live SBS card was applied on pair-01**. There is no init → new material → support/counter change → final chain from the frozen model on real instances.

What did happen on authored E0:

1. probe-01 history note accepted (`not_initialized` → a single note about identity). E0 does not keep that note as a pair-01 actor card.
2. probe-02/03 SBS payloads used `entities` as objects; the live-card apply path never ran on those objects.
3. Fake-model tests C-T04/C-T05 show the shipped apply path: a second prompt contains new entities/unknowns, and `unknowns=[]` clears prior unknowns. Those are tests, not the 1.5B run.

## Cost

| field | value | source |
|---|---|---|
| legacy conservative | 38 | `legacy_request_reconciliation.json` |
| new reservations | 24 | `artifacts/r02c/request_ledger.jsonl` line count |
| this-run attempts | 11 | summary `per_run_attempts` = 24-13 |
| cache hits | 0 | no cached flag in ledger |
| E1 generate | 0 | summary |
| project conservative | 62 | 38+24 |
| wall | ~5 min for protocol E0 after load | run 04:44:45–04:49:52 |

R02C vs R02B is **not** an SBS accuracy A/B. R02B never had this contract in the prompt.

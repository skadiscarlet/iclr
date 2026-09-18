# R02C output diagnosis (offline, 0 model calls)

Old R02B raw, manifests and reports were **not rewritten**. Retrospective parse does not recover the policy trajectory (`retrospective_parse_only=true`, `policy_trajectory_recovered=false`).

## Denominator

- Reported lower bound (task): **38**
- Sum of run_index requests_attempted: **38**
- Observed unique events `(run_id, seq, phase, instance_id, representation, step)`: **38**
- Stable ledger rows (copies of the same events, counted separately as copies): **38**
- Reconciled consumed lower/upper: **38 / 38**
- Conservative consumed used for new-call limits: **38**
- Uncertainty: **none**
- Duplicate raw-hash groups (still counted as distinct calls): **9**
- Missing raw bodies: **1**

## Historical parser vs layered re-parse

- Historical `parse_model_output` statuses: `{'failed': 1, 'parse_error': 37}`
- Envelope: `{'not_attempted': 1, 'whole_response_fence_removed': 37}`
- JSON: `{'not_attempted': 1, 'valid': 37}`
- Shape: `{'not_attempted': 1, 'valid': 5, 'invalid': 32}`

Fence removal is normalize-only. `True`/`Yes` verdicts stay illegal; they are not mapped to `supported`.
A retrospectively valid six-key object is **not** a recovered SBS card.

## Necessary safe excerpts

- run `2026-09-17T140949+0000` seq=2 raw=sha256:3d431fd5031b1bcfb86d404faa5b5dc810c43c54880277f7384e12b6a28d9006 historical=parse_error layers.json=valid shape=valid excerpt=`ld.",
  "verdict": "supported",
  "sup`
- run `2026-09-17T141202+0000` seq=1 raw=sha256:3d431fd5031b1bcfb86d404faa5b5dc810c43c54880277f7384e12b6a28d9006 historical=parse_error layers.json=valid shape=valid excerpt=`ld.",
  "verdict": "supported",
  "sup`
- run `2026-09-17T141202+0000` seq=2 raw=sha256:3d431fd5031b1bcfb86d404faa5b5dc810c43c54880277f7384e12b6a28d9006 historical=parse_error layers.json=valid shape=valid excerpt=`ld.",
  "verdict": "supported",
  "sup`
- run `2026-09-17T142041+0000` seq=1 raw=sha256:3d431fd5031b1bcfb86d404faa5b5dc810c43c54880277f7384e12b6a28d9006 historical=parse_error layers.json=valid shape=valid excerpt=`ld.",
  "verdict": "supported",
  "sup`
- E1 format fragment run `2026-09-17T141202+0000` inst-6bf462ca01bb071f/history raw=sha256:ae2a8f0c562644d7951a8dc3fe5102324027538e869c188b394f35d61860229c excerpt=`ed.",
  "verdict": "True",
  "sup` (no source body)

## Limits

- Full prompts, token ids and third-party bodies stay local under `artifacts/r02b/`.
- Semantics = `not_evaluated`. No detection accuracy/F1.
- First registered run includes a FileNotFoundError sidecar with missing `e0_0.txt`.

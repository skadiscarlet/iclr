# R01 research contract

**Hypothesis under test (later rounds):** does an explicit SBS state — hypothesized security relation, support, counter-evidence, unknowns, remaining budget — improve grounded review under a finite context budget?

**R01 delivers only:** inventory, reversible cleanup notes, actor/evaluator isolation, and offline fixture replay of

`INIT → REPRESENT → READ_ALLOWED_EVIDENCE → UPDATE → FINISH/UNRESOLVED`.

Allowed runtime read: `read_evidence(allowed_id)`. No free filesystem walk, network, model API, PoC, or third-party build.

**B** is a concrete constraint-failure hypothesis, not a CVE label. Product/business rules need a citable document, contract, config, or human annotation. Missing basis is recorded as unknown.

**Representations.** `HistoryView` and `SBSView` consume the same initial material and the same frozen observation sequence. R01 does not compare their accuracy.

**ValueScorer.** Interface reserved; `available=false`. Replay uses scripted fixture updates, not random Q scores.

**Not claimed.** Detection lift, training curves, new CVE counts, or `review_status=accepted`.

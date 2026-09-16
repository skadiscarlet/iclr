# EGSI Java Web Training Implementation Roadmap

> **For agentic workers:** Each phase has its own implementation plan. Complete and verify one phase before writing or executing the next phase plan.

**Goal:** Deliver the approved Java Web verifier-first training system as four independently testable increments rather than one unreviewable implementation batch.

**Architecture:** Phase A converts the existing 300 T1 cases into validated teacher enrichments and honest patch-grounded BC trajectories. Phase B adds real tool execution, Branch Replay, and T2/T3 upgrades. Phase C trains and evaluates 0.5B–3B selectors. Phase D makes remote production runs reproducible on the A800 host.

**Canonical design:** `idea-stage/JAVA_WEB_TRAINING_PIPELINE_DESIGN.md`

---

## Phase A — P0/P1 Enrichment and T1 Trajectories

**Output:** A runnable Python package that can process 10 then 30 existing cases into schema-valid enrichment records, redacted policy seeds, event logs, JSONL/Parquet patch-grounded BC trajectories, and validation reports.

**Evidence boundary:** No build, PoC, dynamic Fact, certificate, or terminal exploit reward is created.

**Detailed plan:** `idea-stage/implementation-plans/2026-08-29-java-web-enrichment-trajectory-p0-p1.md`

**Exit gate:**

- policy/oracle leakage = 0;
- Action DSL parse after gate = 100%;
- selected illegal action = 0;
- deterministic event replay >= 98%;
- teacher structured parse >= 95%;
- invalid source location <= 5%;
- 30-case P1 report retained, including failures.

## Phase B — Tool Execution, Replay, and Evidence Upgrades

**Output:** Typed tool registry, repository materialization/build profiles, static receipts, optional official tests/PoCs, T2/T3 admission, equal-continuation Branch Replay, and verifier-grounded reward vectors.

**Prerequisite:** Phase A event and trajectory schemas are frozen at a versioned boundary.

**Exit gate:** Every reward component references a verifier decision and replayable receipt; tool failures remain partial observations rather than negative vulnerability labels.

## Phase C — Selector Training and Evaluation

**Output:** 0.5B smoke model, 1.5B three-seed main runs, 3B capacity run, matched-candidate baselines, tier-aware metrics, checkpoints, dataset fingerprints, and run manifests.

**Prerequisite:** Phase A Stage-1 dataset passes contract tests. Stage 2/value and offline RL remain loss-masked unless Phase B produced the required labels.

**Exit gate:** Structural training gates pass. Performance results may be positive or negative and are reported without changing verifier thresholds.

## Phase D — Remote Production Operations

**Output:** Non-destructive source/data synchronization, provider configuration deployment, GPU leases and preflight checks, resumable remote jobs, monitoring, artifact return, and rollback/runbook documentation for `ai@10.8.0.11`.

**Prerequisite:** Local 0.5B smoke command and tests pass.

**Exit gate:** A remotely resumed smoke run produces the same dataset/split/config fingerprints and a validated result bundle.

## Dependency Order

```text
Phase A contracts/enrichment/trajectory
       ↓
Phase B receipts/replay/reward ──────┐
       ↓                             │
Phase C Stage 1 selector             │
       ↓                             │
Phase C value/offline RL ←───────────┘
       ↓
Phase D production scheduling
```

Phase D support scripts may be drafted earlier, but no production training job starts before the Phase C local smoke gate.


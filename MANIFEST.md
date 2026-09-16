# Research Output Manifest

> Auto-maintained by ARIS skills. Tracks all generated artifacts across the research lifecycle.

| Timestamp | Skill | File | Stage | Description |
|-----------|-------|------|-------|-------------|
| 2026-08-24 12:33 | /idea-creator | idea-stage/EVIDENCE_GUIDED_AUDIT_DESIGN_20260824_123305.md | idea-discovery | Complete typed automaton, hierarchical RL selector, agent actions, training and evaluation design |
| 2026-08-24 12:43 | /idea-creator | idea-stage/EVIDENCE_GUIDED_AUDIT_DESIGN.md | idea-discovery | latest complete design copy |
| 2026-08-24 12:33 | /idea-creator | idea-stage/IDEA_REPORT_20260824_123305.md | idea-discovery | 11 ideas consolidated to two core recommendations and one gated contribution |
| 2026-08-24 12:43 | /idea-creator | idea-stage/IDEA_REPORT.md | idea-discovery | latest ranked idea report |
| 2026-08-24 12:33 | /idea-creator | idea-stage/ACTION_DSL.schema_20260824_123305.json | idea-discovery | JSON Schema for 30 typed investigation primitives |
| 2026-08-24 12:43 | /idea-creator | idea-stage/ACTION_DSL.schema.json | idea-discovery | latest action DSL schema |
| 2026-08-24 12:33 | /idea-creator | idea-stage/AUDIT_AUTOMATON_20260824_123305.yaml | idea-discovery | executable audit automaton states, invariants and transitions |
| 2026-08-24 12:43 | /idea-creator | idea-stage/AUDIT_AUTOMATON.yaml | idea-discovery | latest audit automaton specification |
| 2026-08-24 12:33 | /idea-creator | idea-stage/TRAINING_SPEC_20260824_123305.yaml | idea-discovery | staged BC, offline RL, online RL, curriculum and evaluation spec |
| 2026-08-24 12:43 | /idea-creator | idea-stage/TRAINING_SPEC.yaml | idea-discovery | latest training specification |
| 2026-08-24 12:43 | /idea-creator | .aris/traces/idea-creator/2026-08-24_run01/ | idea-discovery | reviewer requests, responses and metadata |
| 2026-08-24 12:45 | /idea-creator | idea-stage/VERIFICATION_20260824_123305.md | idea-discovery | exact schema, YAML, Markdown and hash verification record |
| 2026-08-24 12:45 | /idea-creator | idea-stage/VERIFICATION.md | idea-discovery | latest verification record |
| 2026-08-24 16:10 | /idea-creator | paper-stage/ICLR_PAPER_NARRATIVE_20260824_161059.md | paper-narrative | versioned ICLR-level problem, method, claims, training and experiment narrative |
| 2026-08-24 16:10 | /idea-creator | paper-stage/ICLR_PAPER_NARRATIVE.md | paper-narrative | fixed entry point for the latest paper-level narrative |
| 2026-08-24 16:10 | /idea-creator | AGENTS.md | project-governance | prototype-first and later paper-stage document routing rules |
| 2026-08-24 16:10 | /idea-creator | .changes/20260824_161059/CHANGES.patch | change-record | unified diff for narrative, AGENTS and manifest changes |
| 2026-08-24 16:10 | /idea-creator | .changes/20260824_161059/ROLLBACK.ps1 | change-record | runnable rollback restoring the pre-change project state |
| 2026-08-24 16:10 | /idea-creator | .changes/20260824_161059/VERIFICATION.md | change-record | exact baseline, modified, rollback and final verification record |
| 2026-08-28 15:17 | /experiment-plan | idea-stage/DATA_COLLECTION_GUIDE_20260828_151721.md | prototype-data | Versioned Java Web vulnerability data collection plan: sources, CVE/PoC seeds, quotas, schema, splits and evidence tiers |
| 2026-08-28 15:17 | /experiment-plan | idea-stage/DATA_COLLECTION_GUIDE.md | prototype-data | Fixed entry point for the latest Java Web vulnerability data collection guide |
| 2026-08-28 19:31 | data-collection | data/README.md | prototype-data | Collected raw Java/JVM vulnerability sources and documented the 300-case T1 catalog |
| 2026-08-28 19:31 | data-collection | data/catalog/cases.jsonl | prototype-data | 300 revision-resolved root cases: 260 train/dev with exact quotas plus 40 repository-disjoint 2026 Time-OOD seeds |
| 2026-08-28 19:31 | data-collection | data/reports/collection-validation.json | prototype-data | Strict collection validation receipt with artifact, hash, split, quota and policy-view checks |
| 2026-08-28 23:42 | design | idea-stage/JAVA_WEB_TRAINING_PIPELINE_DESIGN_20260828_234234.md | prototype-design | Approved verifier-first Java Web A/B data, teacher-enrichment, selector-training, remote-execution and evaluation design |
| 2026-08-28 23:42 | design | idea-stage/JAVA_WEB_TRAINING_PIPELINE_DESIGN.md | prototype-design | Fixed entry point for the approved Java Web training-pipeline engineering design |
| 2026-08-29 01:03 | /writing-plans | idea-stage/implementation-plans/2026-08-29-java-web-training-roadmap.md | prototype-plan | Four-phase implementation roadmap for enrichment, executable evidence, selector training, and remote operations |
| 2026-08-29 01:03 | /writing-plans | idea-stage/implementation-plans/2026-08-29-java-web-enrichment-trajectory-p0-p1.md | prototype-plan | TDD execution plan for P0/P1 teacher enrichment and honest zero-reward T1 trajectories |
| 2026-08-29 09:57 | phase-a-implementation | configs/p0_cases.txt, configs/p1_cases.txt | prototype-config | Frozen 10-case P0 and 30-case P1 train-only lists; P1 has exact A/B and CWE quotas across 30 upstream repositories |
| 2026-08-29 15:00 | phase-a-completion | idea-stage/implementation-plans/2026-08-29-java-web-enrichment-trajectory-p0-p1-results.md | prototype-result | Phase-A completion record; decision REVISE BEFORE PHASE B; fixture artifacts are non-promotable and not training data; live-provider cost/latency remain unknown |
| 2026-08-29 15:00 | phase-a-offline-pilot | .work/final-phase-a-p0/reports/enrichment-summary.json; .work/final-phase-a-p0/reports/trajectory-validation.json | prototype-experiment | Final two-stage CLI fixture P0: 10 requested, 8 processed/replayed, 2 stable bounded context-preparation failures; restart enrichment reuse 8; zero leakage/nonzero reward/illegal selection; promotable=false; enrichment SHA 9f1106d2...acfbbe; trajectory SHA 4ec1b0db...1d5586; no pilot-summary artifact |
| 2026-08-29 15:00 | phase-a-offline-pilot | .work/final-phase-a-p1/reports/enrichment-summary.json; .work/final-phase-a-p1/reports/trajectory-validation.json | prototype-experiment | Final two-stage CLI fixture P1: 30 requested, 24 processed/replayed, 6 stable bounded context-preparation failures; restart enrichment reuse 24; zero leakage/nonzero reward/illegal selection; promotable=false; enrichment SHA 8925727a...d10a2; trajectory SHA ebc01d40...a1c8ef; no pilot-summary artifact |
| 2026-08-29 15:00 | phase-a-quality-verification | .work/final-phase-a-summary.json | prototype-validation | Final summary SHA ec7bc576...5edc6d; exact trusted replay/Parquet verification SHA ac4026a2...88b32; fixture only, never promote or train; real-provider P0/P1 not run |
| 2026-08-29 09:57 | collection-validation | .work/task13-readonly-validator-v3.stdout.json | prototype-validation | Isolated CoW/copy snapshot validation returned valid=true for all 300 cases; source catalog/artifacts/scripts/reports content hashes, modes, mtimes and tree structure remained unchanged |
| 2026-08-30 15:00 | context-v2-engineering | idea-stage/JAVA_WEB_TRAINING_PIPELINE_DESIGN.md; idea-stage/implementation-plans/2026-08-30-context-v2-canonical-fallback-results.md | prototype-result | Context V2 strict-parser recovery via bounded pinned canonical Git diff; raw artifact commitments retained; 27 structurally damaged raw patches recovered without editing data or relaxing the parser |
| 2026-08-30 15:00 | context-v2-validation | .work/context-v2-validation.json | prototype-validation | Full deterministic gate: 300/300 built twice, 300 consistent, max 63984 chars, raw/fallback 273/27, P0/P1 Time-OOD overlap empty, overall_valid=true; SHA-256 ceb9725a...37ef |
| 2026-08-30 15:00 | context-v2-fixture-regression | .work/context-v2-fixture-p0; .work/context-v2-fixture-p1 | prototype-experiment | Fixture-only P0 10/10 and P1 30/30 processed/replayed; restart enrichment reuse 10/30; zero leakage/nonzero reward/illegal selection; promotable=false; no live model called |
| 2026-08-30 15:18 | context-v2-spec-review-hardening | src/egsi/data/git_objects.py; src/egsi/data/context_validation.py; tests/data/test_git_objects.py; tests/data/test_context_validation.py; .work/context-v2-task2 | prototype-validation | Canonical fallback config/attributes isolation, quoted alternate paths, bounded process-group and post-spawn reader cleanup; mutually exclusive validator built/failed accounting plus partial-success mismatch diagnostics; 538 tests pass; 300x2 report unchanged at SHA-256 ceb9725a...37ef; fixture commitments stable |

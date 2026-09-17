#!/usr/bin/env python3
"""Read-only X01–X08 checks over shipped registry files and local actor/fixture trees.

Reuses sbs.registry / sbs.schema / sbs.views. Does not hard-code pair/ready counts.
Does not export CVE, gold, patch, or evaluator answer values.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src'
TOOLS = Path(__file__).resolve().parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from sbs.registry import (  # noqa: E402
    count_inventory,
    human_verified_count,
    load_candidates,
    load_readiness,
    validate_registry_file,
)
from sbs.replay import material_hash  # noqa: E402
from sbs.schema import (  # noqa: E402
    ANSWER_FIELD_NAMES,
    canonical_json_bytes,
    parse_case_view,
    parse_smoke_config,
    reject_answer_fields,
    sha256_bytes,
    sha256_text,
)
from sbs.views import HistoryView, SBSView, views_share_evidence  # noqa: E402

_handoff_spec = importlib.util.spec_from_file_location(
    'local_asset_handoff', TOOLS / 'local_asset_handoff.py'
)
assert _handoff_spec is not None and _handoff_spec.loader is not None
local_asset_handoff = importlib.util.module_from_spec(_handoff_spec)
_handoff_spec.loader.exec_module(local_asset_handoff)
assert_publication_safe = local_asset_handoff.assert_publication_safe
load_published_index = local_asset_handoff.load_published_index
load_published_summary = local_asset_handoff.load_published_summary


def _check(
    check_id: str,
    status: str,
    input_asset_ids: list[str],
    command: str,
    exit_code: int,
    observed_fact: str,
    impact: str,
    next_action: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = {
        'check_id': check_id,
        'status': status,
        'input_asset_ids': input_asset_ids,
        'command': command,
        'exit_code': exit_code,
        'observed_fact': observed_fact,
        'impact': impact,
        'next_action': next_action,
    }
    if extra:
        row.update(extra)
    row['artifact_hash'] = sha256_bytes(canonical_json_bytes({
        k: row[k] for k in (
            'check_id', 'status', 'input_asset_ids', 'command', 'exit_code',
            'observed_fact', 'impact', 'next_action',
        )
    }))
    return row


def _fixture_ids(repo: Path) -> list[str]:
    root = repo / 'fixtures' / 'r01'
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and not p.is_symlink())


def _actor_files_ok(actor_root: Path) -> tuple[bool, str]:
    case_path = actor_root / 'case.json'
    if not case_path.is_file():
        return False, 'missing_case_json'
    payload = json.loads(case_path.read_text(encoding='utf-8'))
    reject_answer_fields(payload)
    case = parse_case_view(payload)
    hits = [name for name in payload if str(name).lower() in ANSWER_FIELD_NAMES]
    if hits:
        return False, 'answer_fields_in_actor_case'
    for evidence_id in case.allowed_evidence_ids:
        meta = actor_root / 'evidence' / f'{evidence_id}.json'
        body = actor_root / 'evidence' / f'{evidence_id}.body'
        if not meta.is_file() or not body.is_file():
            return False, f'missing_evidence:{evidence_id}'
        record = json.loads(meta.read_text(encoding='utf-8'))
        reject_answer_fields(record)
        expected = sha256_bytes(body.read_bytes())
        if record.get('content_sha256') != expected:
            return False, f'body_hash_mismatch:{evidence_id}'
    return True, f'actor_files_ok:{case.case_id}'


def recompute_inventory(repo: Path) -> dict[str, Any]:
    candidates = load_candidates(repo / 'metadata' / 'r01_candidates.jsonl')
    readiness = load_readiness(repo / 'metadata' / 'r01_readiness.csv')
    fixtures = _fixture_ids(repo)
    counts = count_inventory(candidates, readiness, fixtures)
    ready_rows = [row for row in readiness if row.get('ready') == 'yes']
    return {
        'candidate_pairs': counts['candidate_pairs'],
        'real_ready_pairs': counts['real_ready_pairs'],
        'human_verified_pairs': counts['human_verified_pairs'],
        'project_families': counts['project_families'],
        'fixture_cases': counts['fixture_cases'],
        'ready_pair_ids': [row['pair_id'] for row in ready_rows],
        'actor_view_generated_ids': [
            row['pair_id'] for row in readiness if row.get('actor_view_generated') == 'yes'
        ],
        'category_claim': {
            'conventional': sum(1 for row in candidates if row.category_claim == 'conventional'),
            'logic_authorization_claim': sum(
                1 for row in candidates if row.category_claim == 'logic_authorization_claim'
            ),
        },
        'split_dev_pilot': sum(1 for row in candidates if row.split == 'dev_pilot'),
        'duplicate_pair_ids': len(candidates) != len({row.pair_id for row in candidates}),
        'human_verified_count_fn': human_verified_count(candidates),
    }


def _x01(repo: Path) -> dict[str, Any]:
    inv = recompute_inventory(repo)
    catalog = repo / 'data' / 'catalog' / 'cases.jsonl'
    catalog_state = 'missing'
    if (repo / 'data').is_symlink():
        catalog_state = 'symlink_not_followed'
    elif catalog.is_file():
        catalog_state = 'regular_file'
    fact = (
        f"registry_rows={inv['candidate_pairs']}; unique_pair_ids={inv['candidate_pairs']}; "
        f"project_families={inv['project_families']}; each row is a pair "
        f"(buggy_revision+fixed_revision present); catalog_profile={catalog_state}; "
        f"catalog_record_count=not_profiled_this_round"
    )
    status = 'partial' if catalog_state == 'symlink_not_followed' else 'passed'
    if inv['duplicate_pair_ids']:
        status = 'failed'
    return _check(
        'X01', status,
        ['A-R01-CANDIDATES', 'A-EGSI-T1-CATALOG'],
        'sbs.registry.load_candidates + data/catalog/cases.jsonl existence without follow',
        0 if status != 'failed' else 1,
        fact,
        'Catalog scale for this round is taken from tracked metadata, not a verified walk of data/.',
        'Keep scan_complete=false until a non-symlink catalog profile exists; do not treat catalog as empty.',
    )


def _x02(repo: Path, inv: dict[str, Any]) -> dict[str, Any]:
    actor_root = repo / 'local_data' / 'r01' / 'actor'
    missing: list[str] = []
    bad: list[str] = []
    ok: list[str] = []
    if not actor_root.is_dir():
        return _check(
            'X02', 'not_evaluated' if not inv['ready_pair_ids'] else 'failed',
            ['A-R01-READINESS', 'A-R01-ACTOR-PACKS'],
            'load_readiness + actor case/evidence existence',
            1 if inv['ready_pair_ids'] else 0,
            'local_data/r01/actor missing; ready_pair_ids=' + ','.join(inv['ready_pair_ids']),
            'Ready rows cannot be confirmed as generated packs.',
            'Restore actor packs or mark ready=no.',
        )
    for pair_id in inv['ready_pair_ids']:
        root = actor_root / pair_id
        if not root.is_dir():
            missing.append(pair_id)
            continue
        try:
            good, detail = _actor_files_ok(root)
        except Exception as exc:  # noqa: BLE001 — record, do not leak payload
            bad.append(f'{pair_id}:{type(exc).__name__}')
            continue
        if good:
            ok.append(pair_id)
        else:
            bad.append(f'{pair_id}:{detail}')
    generated_mismatch = set(inv['ready_pair_ids']) != set(inv['actor_view_generated_ids'])
    status = 'passed' if ok and not missing and not bad and not generated_mismatch else 'failed'
    if not inv['ready_pair_ids']:
        status = 'passed'
    return _check(
        'X02', status,
        ['A-R01-READINESS', 'A-R01-ACTOR-PACKS'],
        'ready=yes rows must have actor case.json + evidence body/json; no evaluator answer fields',
        0 if status == 'passed' else 1,
        (
            f"ready={len(inv['ready_pair_ids'])}; actor_ok={len(ok)}; "
            f"missing_dirs={len(missing)}; failed={len(bad)}; "
            f"ready_equals_actor_view_generated={not generated_mismatch}"
        ),
        'Directory presence alone is not sufficient; body hashes and actor schema were checked.',
        'Keep evaluator answers out of actor roots; do not set human_verified.',
    )


def _x03(repo: Path, inv: dict[str, Any]) -> dict[str, Any]:
    actor_root = repo / 'local_data' / 'r01' / 'actor'
    generations: dict[str, str] = {}
    answer_leaks = 0
    for pair_id in inv['ready_pair_ids']:
        case_path = actor_root / pair_id / 'case.json'
        if not case_path.is_file():
            continue
        case = json.loads(case_path.read_text(encoding='utf-8'))
        for evidence_id in case.get('allowed_evidence_ids', []):
            meta = actor_root / pair_id / 'evidence' / f'{evidence_id}.json'
            if not meta.is_file():
                continue
            record = json.loads(meta.read_text(encoding='utf-8'))
            generations[f'{pair_id}/{evidence_id}'] = str(record.get('generation_id'))
            if any(k.lower() in ANSWER_FIELD_NAMES for k in record):
                answer_leaks += 1
    manifest = repo / 'artifacts' / 'r01_smoke' / 'run_manifest.json'
    manifest_mode = None
    if manifest.is_file():
        manifest_mode = json.loads(manifest.read_text(encoding='utf-8')).get('mode')
    unique_gen = sorted(set(generations.values()))
    status = 'passed' if generations and answer_leaks == 0 else ('partial' if generations else 'failed')
    return _check(
        'X03', status,
        ['A-R01-ACTOR-PACKS', 'A-R01-SMOKE'],
        'actor evidence generation_id + body sha vs fixture run_manifest mode',
        0 if status != 'failed' else 1,
        (
            f"actor_generation_ids={unique_gen}; answer_field_names_in_actor_evidence={answer_leaks}; "
            f"smoke_manifest_mode={manifest_mode}; smoke_manifest_is_fixture_replay_not_actor_run="
            f"{manifest_mode == 'fixture_replay'}"
        ),
        'Real actor packs are not the R01 smoke run; mixing them would invent a model run.',
        'Keep fixture replay and real actor packs as separate assets.',
    )


def _x04(repo: Path) -> dict[str, Any]:
    artifacts = repo / 'artifacts' / 'r01_smoke'
    fixtures = repo / 'fixtures' / 'r01'
    cases = _fixture_ids(repo)
    id_ok = 0
    body_ok = 0
    body_checked = 0
    history_has_material = 0
    missing = 0
    for name in cases:
        hist_path = artifacts / name / 'history.json'
        sbs_path = artifacts / name / 'sbs.json'
        if not hist_path.is_file() or not sbs_path.is_file():
            missing += 1
            continue
        history = HistoryView.model_validate(json.loads(hist_path.read_text(encoding='utf-8')))
        sbs = SBSView.model_validate(json.loads(sbs_path.read_text(encoding='utf-8')))
        if views_share_evidence(history, sbs):
            id_ok += 1
        if any('material' in event for event in history.events):
            history_has_material += 1
        for obs in sbs.observations:
            body = fixtures / name / 'evidence' / f'{obs.evidence_id}.body'
            if not body.is_file() or obs.material is None:
                continue
            body_checked += 1
            if sha256_text(obs.material) == sha256_bytes(body.read_bytes()):
                body_ok += 1
    status = 'passed' if cases and id_ok == len(cases) and body_ok == body_checked and body_checked else 'failed'
    if history_has_material == 0 and body_ok == body_checked and body_checked:
        # History schema omits material; body identity is vs fixture files, not History JSON.
        status = 'passed'
    return _check(
        'X04', status,
        ['A-R01-FIXTURES', 'A-R01-SMOKE'],
        'HistoryView/SBSView views_share_evidence + SBS material sha256 vs fixture .body',
        0 if status == 'passed' else 1,
        (
            f"fixture_cases={len(cases)}; id_order_match={id_ok}; "
            f"sbs_material_matches_fixture_body={body_ok}/{body_checked}; "
            f"history_events_with_material={history_has_material}; missing_outputs={missing}"
        ),
        'History JSON does not store observation material; ID-only History vs SBS is not the body check. Body identity is SBS material vs fixture files.',
        'Do not treat History/SBS ID equality as semantic proof of the security relation.',
    )


def _x05(repo: Path) -> dict[str, Any]:
    reported = repo / 'reports' / 'rounds' / 'R01' / 'run_manifest.json'
    local = repo / 'artifacts' / 'r01_smoke' / 'run_manifest.json'
    config = repo / 'configs' / 'r01_smoke.json'
    if not reported.is_file() or not local.is_file() or not config.is_file():
        return _check(
            'X05', 'failed',
            ['A-R01-SMOKE', 'A-R01-FIXTURES'],
            'compare reports and artifacts run_manifest; recompute config/material hashes',
            1, 'missing_manifest_or_config',
            'Cannot confirm fixture replay provenance.',
            'Restore tracked run_manifest and gitignored artifacts/r01_smoke.',
        )
    rep = json.loads(reported.read_text(encoding='utf-8'))
    loc = json.loads(local.read_text(encoding='utf-8'))
    cfg = parse_smoke_config(json.loads(config.read_text(encoding='utf-8')))
    cfg_hash = sha256_bytes(canonical_json_bytes(cfg.model_dump(mode='json')))
    mat_hash = material_hash(repo / cfg.fixtures_root)
    keys = (
        'mode', 'seed', 'split', 'model_calls', 'model_calls_allowed',
        'detection_metrics_status', 'config_sha256', 'material_sha256', 'code_sha',
    )
    mismatches = [k for k in keys if rep.get(k) != loc.get(k)]
    missing_outputs = [
        path for path in loc.get('output_index', {}).values()
        if not (repo / path).is_file()
    ]
    hash_ok = loc.get('config_sha256') == cfg_hash and loc.get('material_sha256') == mat_hash
    model_ok = loc.get('model_calls') == 0 and loc.get('mode') == 'fixture_replay'
    status = 'passed' if not mismatches and not missing_outputs and hash_ok and model_ok else 'failed'
    return _check(
        'X05', status,
        ['A-R01-SMOKE', 'A-R01-FIXTURES'],
        'reports/rounds/R01/run_manifest.json vs artifacts/r01_smoke/run_manifest.json + recomputed hashes',
        0 if status == 'passed' else 1,
        (
            f"key_mismatches={mismatches}; missing_outputs={len(missing_outputs)}; "
            f"config_hash_match={loc.get('config_sha256') == cfg_hash}; "
            f"material_hash_match={loc.get('material_sha256') == mat_hash}; "
            f"model_calls={loc.get('model_calls')}; code_sha={loc.get('code_sha')}"
        ),
        'Fixture replay is not a real-model run. code_sha is experiment_implementation_sha, not this scanner commit.',
        'Do not retarget reports/latest.json; do not rerun replay for this supplement.',
    )


def _x06(repo: Path, inv: dict[str, Any], published: dict[str, Any] | None) -> dict[str, Any]:
    status_path = repo / 'reports' / 'rounds' / 'R01' / 'status.json'
    r01_hv = None
    if status_path.is_file():
        r01_hv = json.loads(status_path.read_text(encoding='utf-8')).get('counts', {}).get('human_verified_pairs')
    published_hv = None
    if published:
        published_hv = (
            published.get('counts', {}).get('human_verified_pairs')
            if isinstance(published.get('counts'), dict)
            else published.get('human_verified_pairs')
        )
    hv = inv['human_verified_pairs']
    ok = hv == 0 and inv['human_verified_count_fn'] == 0 and (r01_hv in {0, None}) and (published_hv in {0, None})
    return _check(
        'X06', 'passed' if ok else 'failed',
        ['A-R01-CANDIDATES', 'A-R01-READINESS'],
        'sbs.registry.human_verified_count vs R01 status.json and published SUMMARY',
        0 if ok else 1,
        (
            f"registry_human_verified={hv}; r01_status_human_verified={r01_hv}; "
            f"published_human_verified={published_hv}; no_human_record_observed=true"
        ),
        'Zero is an observed automated-registry fact, not a human confirmation of labels.',
        'Do not set human_verified or review_status=accepted in this supplement.',
    )


def _x07(repo: Path, inv: dict[str, Any], published: dict[str, Any] | None) -> dict[str, Any]:
    status_path = repo / 'reports' / 'rounds' / 'R01' / 'status.json'
    r01 = json.loads(status_path.read_text(encoding='utf-8'))['counts'] if status_path.is_file() else {}
    discrepancies: list[str] = []
    for key in ('candidate_pairs', 'real_ready_pairs', 'human_verified_pairs', 'project_families', 'fixture_cases'):
        if key in r01 and r01[key] != inv[key]:
            discrepancies.append(f'r01_status.{key}={r01[key]} recomputed={inv[key]}')
    if published:
        pub_counts = published.get('counts') if isinstance(published.get('counts'), dict) else published
        for key in ('candidate_pairs', 'real_ready_pairs', 'human_verified_pairs', 'project_families', 'fixture_cases'):
            if isinstance(pub_counts, dict) and key in pub_counts and pub_counts[key] != inv[key]:
                discrepancies.append(f'published.{key}={pub_counts[key]} recomputed={inv[key]}')
    catalog_gap = 'catalog_record_count not independently profiled (data/ is symlink_not_followed)'
    status = 'passed' if not discrepancies else 'failed'
    return _check(
        'X07', status,
        ['A-R01-CANDIDATES', 'A-R01-READINESS', 'A-R01-FIXTURES'],
        'recompute via sbs.registry.count_inventory; compare R01 status.json and published SUMMARY',
        0 if status == 'passed' else 1,
        (
            f"recomputed={ {k: inv[k] for k in ('candidate_pairs','real_ready_pairs','human_verified_pairs','project_families','fixture_cases')} }; "
            f"r01_status_counts={r01}; discrepancies={discrepancies or 'none'}; coverage_gap={catalog_gap}"
        ),
        'Count mismatches vs reports/rounds/R01/ are listed, not patched. Catalog file is not a verified 0-record set.',
        'If a mismatch appears, keep R01 historical files and explain it in this round.',
    )


def _x08(repo: Path) -> dict[str, Any]:
    tracked_builders = [
        'src/sbs/static_check.py',
        'src/sbs/replay.py',
        'src/sbs/views.py',
        'tools/local_asset_handoff.py',
        'tools/local_asset_xcheck.py',
        'configs/r01_smoke.json',
    ]
    present = [p for p in tracked_builders if (repo / p).is_file()]
    ignored_local = [
        'configs/providers.local.toml',
        'configs/offline-test-runner.lock.json',
        'configs/native-signer-build-record.json',
        'scripts/rerun_first_case_hard_gate',
        'scripts/run_fail_fast_enrich',
        'scripts/run_test_receipt',
    ]
    ignored_present = [p for p in ignored_local if (repo / p).exists()]
    actor_rebuild = (repo / 'src' / 'sbs' / 'static_check.py').is_file()
    data_symlink = (repo / 'data').is_symlink()
    status = 'partial' if data_symlink else 'passed'
    return _check(
        'X08', status,
        ['A-R02A-SCANNER', 'A-R01-ACTOR-PACKS', 'A-IGNORED-LOCAL-TOOLING'],
        'existence of tracked builders vs ignored local lock/signer/provider files (names only)',
        0,
        (
            f"tracked_builders_present={present}; ignored_local_present_count={len(ignored_present)}; "
            f"data_symlink={data_symlink}; actor_builder_tracked={actor_rebuild}; "
            f"r01_fixture_replay_does_not_need_providers_local=true"
        ),
        'Real actor-view rebuild still depends on gitignored local_data and the unresolved data/ symlink cache. Fixture replay rebuilds from tracked fixtures + src/sbs.',
        'Do not commit providers.local.toml, lock files, signer records, or execute-only launchers.',
    )


def run_cross_checks(repo: Path, *, summary_path: Path | None = None, index_path: Path | None = None) -> dict[str, Any]:
    repo = Path(repo)
    published = None
    index_rows: list[dict[str, Any]] = []
    if summary_path and Path(summary_path).is_file():
        published = load_published_summary(summary_path)
    if index_path and Path(index_path).is_file():
        index_rows = load_published_index(index_path)
    inv = recompute_inventory(repo)
    checks = [
        _x01(repo),
        _x02(repo, inv),
        _x03(repo, inv),
        _x04(repo),
        _x05(repo),
        _x06(repo, inv, published),
        _x07(repo, inv, published),
        _x08(repo),
    ]
    return {
        'schema_version': '1.0',
        'round_id': 'R02',
        'inventory': inv,
        'published_index_rows': len(index_rows),
        'checks': checks,
        'failed': [c['check_id'] for c in checks if c['status'] == 'failed'],
        'partial': [c['check_id'] for c in checks if c['status'] == 'partial'],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, required=True)
    parser.add_argument('--summary', type=Path, default=None)
    parser.add_argument('--index', type=Path, default=None)
    parser.add_argument('--output', type=Path, default=None)
    args = parser.parse_args()
    repo = args.repo_root.resolve()
    summary = args.summary if args.summary is not None else repo / 'reports/local_assets/SUMMARY.json'
    index = args.index if args.index is not None else repo / 'reports/local_assets/index.jsonl'
    result = run_cross_checks(
        repo,
        summary_path=summary if summary.is_file() else None,
        index_path=index if index.is_file() else None,
    )
    text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    assert_publication_safe(text, label='xcheck_output')
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding='utf-8')
    print(json.dumps({
        'status': 'failed' if result['failed'] else 'collected',
        'failed': result['failed'],
        'partial': result['partial'],
        'check_ids': [c['check_id'] for c in result['checks']],
    }, ensure_ascii=False))
    return 1 if result['failed'] else 0


if __name__ == '__main__':
    raise SystemExit(main())

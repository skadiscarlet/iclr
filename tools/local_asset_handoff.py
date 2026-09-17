#!/usr/bin/env python3
"""Bounded, read-only local inventory. Outputs are LOCAL REVIEW CANDIDATES.

No network, model calls, source execution, arbitrary record-value export, or Git writes.
The caller must review publication/label/privacy restrictions before publishing any output.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

DEFAULT_ROOTS = ('data', 'local_data', 'artifacts', '.work', 'metadata', 'configs', 'scripts', 'src')
EXCLUDED_DIRS = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', '.mypy_cache', '.pytest_cache', '.tox'}
SECRET_PARTS = {'.ssh', '.gnupg', 'secrets', 'credentials', 'private_keys', 'id_rsa', 'id_ed25519', 'authorized_keys', 'known_hosts'}
SECRET_SUFFIXES = {'.pem', '.key', '.p12', '.pfx', '.keystore', '.jks'}
BINARY_SUFFIXES = {'.safetensors', '.bin', '.pt', '.pth', '.ckpt', '.gguf', '.onnx', '.npy', '.npz', '.jar', '.class', '.zip', '.gz', '.xz', '.7z', '.tar', '.sqlite', '.db', '.pdf', '.docx', '.png', '.jpg'}
SAFE_KEY = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,63}$')
ABSOLUTE_HOME = re.compile(r'(?:/home/|/Users/)[^\s"\']+')
ENUMS = {
    'split': {'dev_pilot', 'train', 'dev', 'validation', 'test', 'reserved_test', 'unknown'},
    'status': {'metadata_only', 'source_resolved', 'evidence_draft', 'human_verified', 'excluded', 'material_ready', 'obligation_draft', 'unknown', 'completed', 'partial', 'blocked', 'pending', 'not_evaluated'},
    'category_claim': {'conventional', 'logic_authorization_claim', 'logic', 'authorization', 'unknown'},
    'material_kind': {'fixture', 'real', 'synthetic'},
    'ready': {'yes', 'no', 'true', 'false', 'unknown'},
}


def digest(data: bytes) -> str:
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def opaque(text: str) -> str:
    return 'file-' + hashlib.sha256(text.encode()).hexdigest()[:20]


def sensitive(rel: str) -> bool:
    for part in PurePosixPath(rel).parts:
        p = part.lower()
        if p in SECRET_PARTS or p == '.env' or p.startswith('.env.'):
            return True
        if p.endswith(('.local.toml', '.credentials.json')) or Path(p).suffix in SECRET_SUFFIXES:
            return True
        if 'private_key' in p or 'access_token' in p or 'api_key' in p:
            return True
    return False


def safe_path(root: Path, rel: str) -> Path:
    pp = PurePosixPath(rel)
    if not rel or rel in {'.', '..'} or pp.is_absolute() or '..' in pp.parts or '\\' in rel:
        raise ValueError('relative_path_required')
    result = root
    for part in pp.parts:
        result = result / part
        if result.is_symlink():
            raise ValueError('symlink_not_followed')
    if not result.resolve().is_relative_to(root):
        raise ValueError('outside_repository')
    return result


def safe_git(root: Path, args: list[str], stdin: bytes | None = None) -> bytes | None:
    try:
        p = subprocess.run(['git', '-C', str(root), *args], input=stdin,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=20, check=False)
        return p.stdout if p.returncode in {0, 1} else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def shape(value: Any, prefix: str = '$', depth: int = 0) -> dict[str, str]:
    def typename(v: Any) -> str:
        if v is None: return 'null'
        if isinstance(v, bool): return 'boolean'
        if isinstance(v, dict): return 'object'
        if isinstance(v, list): return 'array'
        if isinstance(v, str): return 'string'
        if isinstance(v, (int, float)): return 'number'
        return 'other'
    out = {prefix: typename(value)}
    if depth >= 2: return out
    if isinstance(value, dict):
        for key in sorted(value, key=str)[:100]:
            safe = key if isinstance(key, str) and SAFE_KEY.fullmatch(key) else '<redacted_key>'
            out.update(shape(value[key], prefix + '.' + safe, depth + 1))
    elif isinstance(value, list) and value:
        out.update(shape(value[0], prefix + '[]', depth + 1))
    return out


def profile_file(root: Path, rel: str, max_bytes: int, max_records: int) -> dict[str, Any]:
    result: dict[str, Any] = {'file_id': opaque(rel), 'relative_path': None if sensitive(rel) else rel,
        'publication_status': 'local_review_required', 'record_values_exported': False,
        'status': 'not_collected', 'complete': False, 'scanned_records': 0}
    if sensitive(rel):
        result['status'] = 'excluded_sensitive'; result['scanned_records'] = None; return result
    if any(part in EXCLUDED_DIRS for part in PurePosixPath(rel).parts):
        result['status'] = 'excluded_environment_directory'; result['scanned_records'] = None; return result
    try:
        path = safe_path(root, rel)
    except ValueError as e:
        result['status'] = str(e); result['scanned_records'] = None; return result
    if not path.is_file():
        result['status'] = 'missing'; result['scanned_records'] = None; return result
    ext = path.suffix.lower()
    if ext not in {'.jsonl', '.ndjson', '.json', '.csv'}:
        result['status'] = 'unsupported_profile_type'; result['scanned_records'] = None; return result
    try:
        with path.open('rb') as f:
            raw = f.read(max_bytes + 1)
    except OSError as e:
        result['status'] = type(e).__name__; result['scanned_records'] = None; return result
    complete_bytes = len(raw) <= max_bytes
    raw = raw[:max_bytes]
    result['scanned_bytes'] = len(raw)
    result['scanned_prefix_sha256'] = digest(raw)
    if not complete_bytes and ext == '.json':
        result['status'] = 'too_large_for_json_profile'; result['scanned_records'] = None; return result
    if not complete_bytes:
        end = raw.rfind(b'\n')
        raw = raw[:end + 1] if end >= 0 else b''
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeError:
        result['status'] = 'invalid_utf8'; result['scanned_records'] = None; return result
    shapes: dict[str, set[str]] = {}
    distributions: dict[str, dict[str, int]] = {key: {} for key in ENUMS}
    invalid: list[int] = []
    valid = 0
    inspected = 0
    limit_hit = False
    try:
        if ext in {'.jsonl', '.ndjson'}:
            iterator = ((i, line) for i, line in enumerate(text.splitlines(), 1) if line.strip())
            decode = True
            result['record_unit'] = 'nonempty_json_line'
        elif ext == '.csv':
            iterator = enumerate(csv.DictReader(io.StringIO(text), strict=True), 2)
            decode = False
            result['record_unit'] = 'csv_row'
        else:
            obj = json.loads(text)
            records = obj if isinstance(obj, list) else [obj]
            iterator = enumerate(records, 1)
            decode = False
            result['record_unit'] = 'top_level_array_item' if isinstance(obj, list) else 'single_json_document'
        for number, record in iterator:
            if inspected >= max_records:
                limit_hit = True; break
            inspected += 1
            if decode:
                try: record = json.loads(record)
                except (ValueError, TypeError):
                    if len(invalid) < 20: invalid.append(number)
                    continue
            valid += 1
            for key, typ in shape(record).items():
                if len(shapes) < 2000 or key in shapes:
                    shapes.setdefault(key, set()).add(typ)
            if isinstance(record, dict):
                for key, allowed in ENUMS.items():
                    value = record.get(key)
                    if value is None: category = '<missing>'
                    elif isinstance(value, (str, bool)):
                        normalized = str(value).strip().lower()
                        category = normalized if normalized in allowed else '<other>'
                    else: category = '<non_scalar>'
                    distributions[key][category] = distributions[key].get(category, 0) + 1
    except (ValueError, TypeError, csv.Error, RecursionError) as e:
        result['status'] = 'parse_error_' + type(e).__name__
        result['complete'] = False
    else:
        result['complete'] = complete_bytes and not limit_hit
        result['status'] = 'complete_with_invalid_rows' if result['complete'] and invalid else ('complete' if result['complete'] else 'prefix_only')
    result.update(scanned_records=valid, inspected_units=inspected,
                  invalid_units=inspected - valid, invalid_line_examples=invalid,
                  schema_types={k: sorted(v) for k, v in sorted(shapes.items())},
                  allowed_enum_distributions=distributions,
                  counts_are_observed_not_semantically_verified=True)
    return result


def scan(repo: Path, roots: list[str], output: Path, *, max_files: int = 10000,
         max_hash_bytes: int = 256 * 1024**2, max_file_hash_bytes: int = 32 * 1024**2,
         profiles: list[str] | None = None, max_profile_bytes: int = 4 * 1024**2,
         max_profile_records: int = 2000, round_id: str = 'R02') -> dict[str, Any]:
    repo = repo.resolve()
    output = output.resolve()
    # Keep local raw scan outputs under artifacts, never in a source-data directory.
    artifacts = repo / 'artifacts'
    if output == artifacts or not output.is_relative_to(artifacts):
        raise ValueError('output_must_be_a_subdirectory_of_repo_artifacts')
    output.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    root_reports = []
    hashed_bytes = 0
    total_bytes = 0
    excluded_sensitive = 0
    symlinks_skipped = 0
    limit_hit = False
    failures = 0
    for root_rel in dict.fromkeys(roots):
        if sensitive(root_rel):
            root_reports.append({'root_alias': opaque(root_rel), 'status': 'excluded_sensitive'}); continue
        rr: dict[str, Any] = {'root': root_rel, 'status': 'not_scanned', 'files_observed': 0}
        root_reports.append(rr)
        if any(part in EXCLUDED_DIRS for part in PurePosixPath(root_rel).parts):
            rr['status'] = 'excluded_environment_directory'; continue
        if limit_hit:
            rr['status'] = 'not_scanned_file_budget'; continue
        try: target = safe_path(repo, root_rel)
        except ValueError as e:
            rr['status'] = str(e); rr['files_observed'] = None; continue
        if target == output or target.is_relative_to(output):
            rr['status'] = 'excluded_own_output'; continue
        if not target.exists():
            rr['status'] = 'missing'; rr['files_observed'] = None; continue
        if not target.is_dir():
            rr['status'] = 'root_not_directory'; rr['files_observed'] = None; continue
        rr['status'] = 'complete_with_declared_exclusions'
        walk_errors: list[str] = []
        def onerror(exc: OSError) -> None:
            walk_errors.append(type(exc).__name__)
        for dirpath, dirnames, filenames in os.walk(target, topdown=True, followlinks=False, onerror=onerror):
            directory = Path(dirpath)
            kept = []
            for name in sorted(dirnames):
                child = directory / name
                relative = child.relative_to(repo).as_posix()
                if child.is_symlink(): symlinks_skipped += 1; continue
                if sensitive(relative): excluded_sensitive += 1; continue
                if name in EXCLUDED_DIRS or child == output or child.is_relative_to(output): continue
                kept.append(name)
            dirnames[:] = kept
            for name in sorted(filenames):
                path = directory / name
                rel = path.relative_to(repo).as_posix()
                if rel in seen: continue
                seen.add(rel)
                if path.is_symlink(): symlinks_skipped += 1; continue
                if sensitive(rel): excluded_sensitive += 1; continue
                if len(records) >= max_files:
                    limit_hit = True; rr['status'] = 'partial_file_budget'; break
                try:
                    before = path.stat()
                    if not path.is_file(): continue
                    item: dict[str, Any] = {'file_id': opaque(rel), 'relative_path': rel,
                        'root_group': root_rel, 'size_bytes': before.st_size,
                        'content_sha256': None, 'hash_status': 'not_hashed', 'git_state': 'unknown'}
                    if path.suffix.lower() in BINARY_SUFFIXES:
                        item['hash_status'] = 'skipped_binary_or_archive'
                    elif before.st_size > max_file_hash_bytes:
                        item['hash_status'] = 'skipped_file_byte_limit'
                    elif hashed_bytes + before.st_size > max_hash_bytes:
                        item['hash_status'] = 'skipped_total_hash_budget'
                    else:
                        h = hashlib.sha256()
                        consumed = 0
                        with path.open('rb') as f:
                            while True:
                                remaining = min(max_file_hash_bytes - consumed, max_hash_bytes - hashed_bytes)
                                block = f.read(min(128 * 1024, max(0, remaining)) + (0 if remaining else 1))
                                if not block: break
                                if len(block) > remaining:
                                    item['hash_status'] = 'changed_or_grew_over_budget'; break
                                h.update(block); consumed += len(block); hashed_bytes += len(block)
                        after = path.stat()
                        if item['hash_status'] == 'not_hashed':
                            if (before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns):
                                item['hash_status'] = 'complete'; item['content_sha256'] = 'sha256:' + h.hexdigest()
                            else: item['hash_status'] = 'changed_during_read'
                    records.append(item); rr['files_observed'] += 1; total_bytes += before.st_size
                except OSError as e:
                    failures += 1
                    records.append({'file_id': opaque(rel), 'relative_path': rel, 'root_group': root_rel,
                        'size_bytes': None, 'content_sha256': None, 'hash_status': type(e).__name__, 'git_state': 'unknown'})
            if limit_hit: break
        if walk_errors:
            rr['walk_errors'] = walk_errors[:20]; rr['status'] = 'partial_read_errors'; failures += len(walk_errors)
    tracked_raw = safe_git(repo, ['ls-files', '-z'])
    tracked = set(tracked_raw.decode('utf-8', errors='replace').split('\0')) if tracked_raw is not None else None
    input_paths = b''.join(r['relative_path'].encode() + b'\0' for r in records)
    ignored_raw = safe_git(repo, ['check-ignore', '-z', '--stdin'], input_paths) if records else b''
    ignored = set(ignored_raw.decode('utf-8', errors='replace').split('\0')) if ignored_raw is not None else None
    for row in records:
        rel = row['relative_path']
        if tracked is not None and rel in tracked: row['git_state'] = 'tracked'
        elif tracked is not None and ignored is not None: row['git_state'] = 'ignored' if rel in ignored else 'untracked'
    records.sort(key=lambda r: r['relative_path'])
    body = ''.join(json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n' for r in records).encode()
    (output / 'file_inventory.jsonl').write_bytes(body)
    profile_rows = [profile_file(repo, p, max_profile_bytes, max_profile_records) for p in dict.fromkeys(profiles or [])]
    (output / 'profiles.json').write_text(json.dumps(profile_rows, ensure_ascii=False, indent=2) + '\n')
    sha_raw = safe_git(repo, ['rev-parse', 'HEAD'])
    code_sha = sha_raw.decode().strip() if sha_raw and re.fullmatch(rb'[0-9a-f]{40,64}\s*', sha_raw) else None
    summary = {'schema_version': '1.0', 'mode': 'local_metadata_inventory', 'round_id': round_id,
        'publication_status': 'local_review_required', 'collection_code_sha': code_sha,
        'collected_at': datetime.now(timezone.utc).isoformat(), 'workspace_alias': 'primary_workspace',
        'roots': root_reports, 'listing_complete_within_declared_scope': not limit_hit and failures == 0 and all(r['status'] not in {'not_scanned_file_budget', 'outside_repository', 'relative_path_required', 'symlink_not_followed'} for r in root_reports),
        'files_observed': len(records), 'observed_file_bytes': total_bytes,
        'bytes_hashed': hashed_bytes, 'files_content_hashed': sum(r['hash_status'] == 'complete' for r in records),
        'excluded_sensitive_entries': excluded_sensitive, 'symlinks_not_followed': symlinks_skipped,
        'read_errors': failures, 'file_budget_hit': limit_hit,
        'git_state_counts': {s: sum(r['git_state'] == s for r in records) for s in ('tracked', 'ignored', 'untracked', 'unknown')},
        'inventory_jsonl_sha256': digest(body), 'inventory_hash_is_not_a_dataset_content_hash': True,
        'limits': {'max_files': max_files, 'max_hash_bytes': max_hash_bytes, 'max_file_hash_bytes': max_file_hash_bytes,
                   'max_profile_bytes': max_profile_bytes, 'max_profile_records': max_profile_records},
        'declared_exclusions': {'directories': sorted(EXCLUDED_DIRS), 'binary_content_hash_suffixes': sorted(BINARY_SUFFIXES), 'own_output_directory': True},
        'interpretation_limits': ['Missing directories are not empty verified datasets.', 'Enumeration and record fields are observations, not verified semantic labels.', 'Profiles export schema and allow-listed enum counts, not arbitrary record values.', 'File inventory is local; review filenames, memberships, labels, privacy, and licenses before publication.', 'No source code, sample project, model, or network request was executed.']}
    (output / 'scan_summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    return summary


def assert_publication_safe(text: str, *, label: str = 'publication') -> None:
    """Reject unfilled templates and absolute home paths in published handoff text."""
    if 'TEMPLATE_NOT_EXECUTED' in text:
        raise ValueError(f'{label}: contains TEMPLATE_NOT_EXECUTED')
    if ABSOLUTE_HOME.search(text) or '/home/' in text:
        raise ValueError(f'{label}: contains absolute home path')


def load_published_summary(path: Path) -> dict[str, Any]:
    text = Path(path).read_text(encoding='utf-8')
    assert_publication_safe(text, label=str(path))
    payload = json.loads(text)
    if payload.get('document_kind') == 'template_not_results':
        raise ValueError(f'{path}: document_kind is template_not_results')
    if payload.get('scan_status') == 'not_started' and payload.get('collection_code_sha') is None:
        raise ValueError(f'{path}: unfilled summary template')
    return payload


def load_published_index(path: Path) -> list[dict[str, Any]]:
    text = Path(path).read_text(encoding='utf-8')
    assert_publication_safe(text, label=str(path))
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get('document_kind') == 'template_not_results':
            raise ValueError(f'{path}:{line_no}: document_kind is template_not_results')
        rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, required=True)
    parser.add_argument('--round', default='R02')
    parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--root', action='append')
    parser.add_argument('--profile', action='append', default=[])
    parser.add_argument('--max-files', type=int, default=10000)
    parser.add_argument('--max-hash-bytes', type=int, default=256 * 1024**2)
    parser.add_argument('--max-file-hash-bytes', type=int, default=32 * 1024**2)
    parser.add_argument('--max-profile-bytes', type=int, default=4 * 1024**2)
    parser.add_argument('--max-profile-records', type=int, default=2000)
    args = parser.parse_args()
    numeric = (args.max_files, args.max_hash_bytes, args.max_file_hash_bytes, args.max_profile_bytes, args.max_profile_records)
    if any(v < 1 for v in numeric): parser.error('all resource limits must be positive')
    root = args.repo_root.resolve()
    out = args.output_root if args.output_root.is_absolute() else root / args.output_root
    try:
        result = scan(root, args.root or list(DEFAULT_ROOTS), out, max_files=args.max_files,
            max_hash_bytes=args.max_hash_bytes, max_file_hash_bytes=args.max_file_hash_bytes,
            profiles=args.profile, max_profile_bytes=args.max_profile_bytes,
            max_profile_records=args.max_profile_records, round_id=args.round)
    except (OSError, ValueError) as exc:
        print(json.dumps({'status': 'failed', 'error_type': type(exc).__name__, 'message': str(exc) if isinstance(exc, ValueError) else 'filesystem_error_details_retained_locally'}, ensure_ascii=False))
        return 2
    print(json.dumps({'status': 'collected' if result['listing_complete_within_declared_scope'] else 'partial',
        'files_observed': result['files_observed'], 'file_budget_hit': result['file_budget_hit'],
        'outputs_are_local_review_candidates': True}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Bounded, read-only probe of this workspace's data/catalog/cases.jsonl.

Only the data-root symlink can be explicitly allowed. No recursive walking,
no nested symlinks, no subprocesses, no networking, no raw record export.
Outputs are local review material, not automatically safe to publish.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

MAX_BYTES = 128 * 1024 * 1024
MAX_LINE = 2 * 1024 * 1024
MAX_RECORDS = 100_000
KEY_FIELDS = ("local_catalog_key", "case_id", "id", "advisory_id", "ghsa_id")


class ProbeError(ValueError):
    pass


def signature(s: os.stat_result) -> tuple[int, int, int, int]:
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)


def checked_leaf(root: Path, parts: tuple[str, ...]) -> Path:
    current = root
    for i, part in enumerate(parts):
        if part in ("", ".", "..") or "/" in part or "\\" in part:
            raise ProbeError("invalid_relative_component")
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ProbeError("nested_symlink_rejected")
        if i < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ProbeError("non_directory_parent")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise ProbeError("non_regular_file")
    if not current.resolve(strict=True).is_relative_to(root):
        raise ProbeError("outside_pinned_root")
    return current


def load_registry(workspace: Path) -> tuple[dict[str, str], str]:
    path = checked_leaf(workspace, ("metadata", "r01_candidates.jsonl"))
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ProbeError("registry_too_large")
    raw = path.read_bytes()
    rows: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise ProbeError("registry_row_not_object")
        pid, key = obj.get("pair_id"), obj.get("local_catalog_key")
        if not isinstance(pid, str) or pid in rows:
            raise ProbeError("registry_pair_id_invalid_or_duplicate")
        if not isinstance(key, str) or not key:
            raise ProbeError("registry_lookup_key_missing")
        rows[pid] = key
    return rows, "sha256:" + hashlib.sha256(raw).hexdigest()


def probe(workspace: Path, *, allow_root_symlink: bool = False,
          max_bytes: int = MAX_BYTES, max_records: int = MAX_RECORDS,
          max_line: int = MAX_LINE) -> dict[str, Any]:
    if not 0 < max_bytes <= MAX_BYTES or not 0 < max_records <= MAX_RECORDS:
        raise ProbeError("limit_out_of_range")
    if not 0 < max_line <= MAX_LINE:
        raise ProbeError("line_limit_out_of_range")
    workspace = workspace.resolve(strict=True)
    root_alias = workspace / "data"
    is_link = root_alias.is_symlink()
    if is_link and not allow_root_symlink:
        raise ProbeError("data_root_symlink_requires_explicit_flag")
    root = root_alias.resolve(strict=True)
    if not root.is_dir() or root == Path(root.anchor):
        raise ProbeError("invalid_or_overbroad_data_root")
    forbidden = {".ssh", ".aws", ".azure", ".git", "proc", "sys", "dev"}
    if forbidden.intersection(root.parts):
        raise ProbeError("sensitive_data_root_rejected")
    catalog = checked_leaf(root, ("catalog", "cases.jsonl"))
    registry, registry_sha = load_registry(workspace)
    target_values = set(registry.values())
    matches: dict[str, list[int]] = {p: [] for p in registry}
    match_counts = {p: 0 for p in registry}
    matching_fields: set[str] = set()
    fields: dict[str, int] = {}
    counts = dict(nonblank_rows=0, valid_object_rows=0, invalid_json_rows=0,
                  invalid_utf8_rows=0, non_object_rows=0)
    initial = catalog.stat()
    if initial.st_size > max_bytes:
        # Still inspect a bounded prefix, but do not advertise its digest as a full hash.
        known_oversize = True
    else:
        known_oversize = False
    digest = hashlib.sha256()
    consumed = 0
    eof = False
    reason: str | None = None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(catalog, flags)
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if signature(initial) != signature(opened):
            raise ProbeError("catalog_changed_before_read")
        while True:
            if consumed >= max_bytes:
                eof = (consumed == opened.st_size)
                reason = None if eof else "byte_limit"
                break
            if counts["nonblank_rows"] >= max_records:
                eof = (consumed == opened.st_size)
                reason = None if eof else "record_limit"
                break
            room = min(max_line + 1, max_bytes - consumed)
            raw = handle.readline(room)
            if not raw:
                eof = True
                break
            digest.update(raw)
            consumed += len(raw)
            if len(raw) > max_line or (not raw.endswith(b"\n") and consumed < opened.st_size):
                reason = "line_or_byte_limit"
                break
            if not raw.strip():
                continue
            counts["nonblank_rows"] += 1
            ordinal = counts["nonblank_rows"]
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                counts["invalid_utf8_rows"] += 1
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError:
                counts["invalid_json_rows"] += 1
                continue
            if not isinstance(row, dict):
                counts["non_object_rows"] += 1
                continue
            counts["valid_object_rows"] += 1
            for k in row:
                if k in fields or len(fields) < 128:
                    fields[k] = fields.get(k, 0) + 1
            found: set[str] = set()
            for k in KEY_FIELDS:
                value = row.get(k)
                if isinstance(value, str) and value in target_values:
                    found.add(value)
                    matching_fields.add(k)
            for pid, key in registry.items():
                if key in found:
                    match_counts[pid] += 1
                    if len(matches[pid]) < 3:
                        matches[pid].append(ordinal)
        final_fd = os.fstat(handle.fileno())
    final_path = catalog.stat()
    stable = (signature(initial) == signature(final_fd) == signature(final_path)
              and root_alias.resolve(strict=True) == root)
    complete = eof and stable
    if not stable:
        reason = "input_changed_during_probe"
    result = {
        "schema_version": "1.0", "task_id": "R02B", "mode": "catalog_probe_only",
        "publication_status": "local_review_required", "root_alias": "data",
        "root_symlink_observed": is_link, "root_symlink_explicitly_allowed": allow_root_symlink,
        "canonical_root_fingerprint": "sha256:" + hashlib.sha256(os.fsencode(root)).hexdigest(),
        "nested_symlinks_followed": False, "catalog_relative_path": "catalog/cases.jsonl",
        "scan_scope": "one_catalog_and_tracked_registry_only", "catalog_size_bytes": initial.st_size,
        "catalog_sha256": "sha256:" + digest.hexdigest() if complete else None,
        "prefix_sha256": "sha256:" + digest.hexdigest(), "bytes_read": consumed,
        "catalog_complete": complete, "stable_input": stable, "stop_reason": reason,
        "known_oversize": known_oversize, "counts": counts,
        "top_level_field_counts": dict(sorted(fields.items())),
        "record_values_exported": False, "registry_sha256": registry_sha,
        "registry_pairs": len(registry), "matching_key_fields": sorted(matching_fields),
        "candidate_matches": [
            {"pair_id": pid, "matching_row_count": match_counts[pid],
             "first_matching_ordinals": matches[pid],
             "status": ("partial_scan" if not complete else "unique_match" if match_counts[pid] == 1
                        else "missing_match" if match_counts[pid] == 0 else "ambiguous_match")}
            for pid in sorted(registry)
        ],
        "semantic_labels_verified": False,
        "limitations": ["Matching keys are not verification of project identity, labels, versions, or licenses.",
                        "Filesystem checks are not a sandbox against a hostile process mutating parent directories."]
    }
    return result


def write_local(workspace: Path, relative: str, result: dict[str, Any]) -> None:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts or rel.parts[:2] != ("artifacts", "r02b"):
        raise ProbeError("output_must_be_under_artifacts_r02b")
    parent = workspace
    for part in rel.parts[:-1]:
        parent = parent / part
        if parent.is_symlink():
            raise ProbeError("output_symlink_rejected")
        parent.mkdir(exist_ok=True)
    output = workspace / rel
    if output.is_symlink() or output.exists():
        raise ProbeError("output_already_exists_choose_new_name")
    with output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.write("\n")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workspace", type=Path, default=Path("."))
    p.add_argument("--allow-data-root-symlink", action="store_true")
    p.add_argument("--out", default="artifacts/r02b/catalog_probe.json")
    args = p.parse_args()
    workspace = args.workspace.resolve(strict=True)
    try:
        result = probe(workspace, allow_root_symlink=args.allow_data_root_symlink)
        write_local(workspace, args.out, result)
    except (ProbeError, OSError, ValueError) as exc:
        # Do not dump raw data, physical paths, or arbitrary exception messages.
        code = str(exc) if isinstance(exc, ProbeError) else type(exc).__name__
        print(json.dumps({"status": "blocked", "error_code": code}))
        return 2
    print(json.dumps({"catalog_complete": result["catalog_complete"],
                      "valid_object_rows": result["counts"]["valid_object_rows"],
                      "registry_pairs": result["registry_pairs"],
                      "publication_status": "local_review_required"}))
    bad_rows = sum(result["counts"][k] for k in ("invalid_json_rows", "invalid_utf8_rows", "non_object_rows"))
    return 0 if result["catalog_complete"] and not bad_rows else 3


if __name__ == "__main__":
    raise SystemExit(main())

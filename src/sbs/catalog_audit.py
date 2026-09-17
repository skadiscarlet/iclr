"""Bounded catalog + mapped-cache audit for the 24 registered objects."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from sbs.errors import PilotConfigError


def _checked_leaf(root: Path, parts: tuple[str, ...]) -> Path:
    current = root
    for i, part in enumerate(parts):
        if part in ("", ".", "..") or "/" in part or "\\" in part:
            raise PilotConfigError("invalid_relative_component")
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise PilotConfigError("nested_symlink_rejected")
        if i < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise PilotConfigError("non_directory_parent")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise PilotConfigError("non_regular_file")
    if not current.resolve(strict=True).is_relative_to(root):
        raise PilotConfigError("outside_pinned_root")
    return current


def checked_dir(root: Path, parts: tuple[str, ...]) -> Path:
    current = root
    for i, part in enumerate(parts):
        if part in ("", ".", "..") or "/" in part or "\\" in part:
            raise PilotConfigError("invalid_relative_component")
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise PilotConfigError("nested_symlink_rejected")
        if i < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise PilotConfigError("non_directory_parent")
    if not stat.S_ISDIR(current.lstat().st_mode):
        raise PilotConfigError("non_directory")
    resolved = current.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise PilotConfigError("outside_pinned_root")
    return current


def resolve_data_root(workspace: Path, *, allow_root_symlink: bool) -> tuple[Path, bool]:
    alias = workspace / "data"
    is_link = alias.is_symlink()
    if is_link and not allow_root_symlink:
        raise PilotConfigError("data_root_symlink_requires_explicit_flag")
    root = alias.resolve(strict=True)
    if not root.is_dir() or root == Path(root.anchor):
        raise PilotConfigError("invalid_or_overbroad_data_root")
    forbidden = {".ssh", ".aws", ".azure", ".git", "proc", "sys", "dev"}
    if forbidden.intersection(root.parts):
        raise PilotConfigError("sensitive_data_root_rejected")
    return root, is_link


def classify_cited_path(path: str) -> str:
    if not path:
        return "missing_citation"
    lowered = path.lower()
    name = Path(lowered).name
    if "release" in lowered or "changelog" in lowered or (
        lowered.endswith(".adoc") and "docs/" in lowered
    ):
        return "release_notes"
    if "/test/" in f"/{lowered}" or name.endswith("test.java"):
        return "test"
    if name in {"pom.xml", "build.xml", "build.gradle", "build.gradle.kts"}:
        return "build_file"
    if lowered.endswith(".java"):
        return "java_implementation"
    if lowered.endswith((".xml", ".yml", ".yaml", ".properties", ".conf")):
        return "configuration"
    return "other"


def license_report(status: str | None) -> str:
    if status == "detected_from_pinned_revision":
        return "pointer_present_not_legal_conclusion"
    return "unknown"


def _strip_data_prefix(rel: str) -> tuple[str, ...]:
    parts = Path(rel).parts
    if not parts or Path(rel).is_absolute() or ".." in parts:
        raise PilotConfigError("invalid_mapped_path")
    if parts[0] == "data":
        parts = parts[1:]
    return parts


def audit_registered_objects(
    workspace: Path,
    *,
    allow_root_symlink: bool = True,
) -> dict[str, Any]:
    workspace = Path(workspace).resolve(strict=True)
    root, is_link = resolve_data_root(workspace, allow_root_symlink=allow_root_symlink)
    catalog = _checked_leaf(root, ("catalog", "cases.jsonl"))
    registry_rows: list[dict[str, Any]] = []
    for line in (workspace / "metadata" / "r01_candidates.jsonl").read_text(
        encoding="utf-8"
    ).splitlines():
        if line.strip():
            registry_rows.append(json.loads(line))
    readiness: dict[str, dict[str, str]] = {}
    with (workspace / "metadata" / "r01_readiness.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        for row in csv.DictReader(handle):
            readiness[row["pair_id"]] = row
    wanted = {row["local_catalog_key"]: row for row in registry_rows}
    catalog_rows: dict[str, dict[str, Any]] = {}
    catalog_records = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(catalog, flags)
    with os.fdopen(fd, "rb") as handle:
        for raw in handle:
            if not raw.strip():
                continue
            catalog_records += 1
            obj = json.loads(raw.decode("utf-8"))
            cid = obj.get("case_id")
            if isinstance(cid, str) and cid in wanted:
                catalog_rows[wanted[cid]["pair_id"]] = obj

    from egsi.data.git_objects import GitCacheGuard

    objects: list[dict[str, Any]] = []
    independent_source_pairs = 0
    for rec in registry_rows:
        pid = rec["pair_id"]
        row = catalog_rows.get(pid)
        cited = (readiness.get(pid) or {}).get("cited_path") or ""
        status: dict[str, Any] = {
            "pair_id": pid,
            "unique_catalog_match": row is not None,
            "two_revisions_locatable": False,
            "commits_match_registry": False,
            "independent_source_present": False,
            "license": "unknown",
            "cited_path_kind": classify_cited_path(cited),
            "cache_inside_pinned_root": False,
            "cache_relative_prefix": None,
            "blocker": None,
        }
        if row is None:
            status["blocker"] = "catalog_row_missing"
            objects.append(status)
            continue
        repo = row.get("repository") if isinstance(row.get("repository"), dict) else {}
        vuln = repo.get("vulnerable_commit")
        fixed = repo.get("fixed_commit")
        status["two_revisions_locatable"] = (
            isinstance(vuln, str)
            and isinstance(fixed, str)
            and len(vuln) == 40
            and len(fixed) == 40
            and vuln != fixed
        )
        status["commits_match_registry"] = (
            vuln == rec.get("buggy_revision") and fixed == rec.get("fixed_revision")
        )
        status["project_name_present"] = bool(repo.get("upstream_id"))
        status["upstream_matches_registry_family"] = repo.get("upstream_id") == rec.get(
            "project_family"
        )
        status["license"] = license_report(
            repo.get("license_status") if isinstance(repo.get("license_status"), str) else None
        )
        try:
            manifest_parts = _strip_data_prefix(row["artifacts"]["manifest_path"])
            manifest = json.loads(_checked_leaf(root, manifest_parts).read_text(encoding="utf-8"))
            cache_rel = manifest["resolution"]["cache_path"]
            cache_parts = _strip_data_prefix(cache_rel)
            checked_dir(root, cache_parts)
            status["cache_inside_pinned_root"] = True
            status["cache_relative_prefix"] = "/".join(cache_parts[:2])
            if cited:
                rel = "/".join(cache_parts)
                guard = GitCacheGuard(root, rel)
                try:
                    store = guard.open_store()
                    has_v = store.contains(vuln, cited)
                    has_f = store.contains(fixed, cited)
                    if has_v and has_f:
                        body_v = store.read_bytes(vuln, cited, max_bytes=2_000_000)
                        body_f = store.read_bytes(fixed, cited, max_bytes=2_000_000)
                        status["independent_source_present"] = hashlib.sha256(
                            body_v
                        ).digest() != hashlib.sha256(body_f).digest()
                    else:
                        status["blocker"] = (
                            "single_version_available"
                            if (has_v or has_f)
                            else "cited_blob_missing"
                        )
                finally:
                    guard.close()
            else:
                status["blocker"] = "citation_range_missing"
        except Exception as exc:
            status["blocker"] = type(exc).__name__
        if status["independent_source_present"]:
            independent_source_pairs += 1
        objects.append(status)

    families = {row["project_family"] for row in registry_rows}
    return {
        "schema_version": "1.0",
        "task_id": "R02B",
        "catalog_profile_status": "complete",
        "full_workspace_scan_status": "partial_by_design",
        "ignored_protected_tools": "excluded_nonblocking",
        "root_symlink_observed": is_link,
        "nested_symlinks_followed": False,
        "counts": {
            "catalog_records": catalog_records,
            "registered_candidate_pairs": len(registry_rows),
            "legacy_ready_flag_pairs": sum(
                1 for row in readiness.values() if row.get("ready") == "yes"
            ),
            "single_version_actor_packages": None,
            "version_bound_actor_instances": None,
            "complete_version_pairs": None,
            "human_verified_pairs": 0,
            "project_name_count": len(families),
            "independent_group_count": None,
            "independent_source_pairs_from_catalog": independent_source_pairs,
        },
        "objects": objects,
        "semantic_labels_verified": False,
        "raw_content_not_remotely_reviewed": True,
    }

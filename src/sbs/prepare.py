"""Construct version-bound R02B actor packs from locked selection + mapped cache."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sbs.catalog_audit import (
    _checked_leaf,
    _strip_data_prefix,
    checked_dir,
    classify_cited_path,
    resolve_data_root,
)
from sbs.errors import PilotConfigError, VersionBoundError
from sbs.schema import canonical_json_bytes, sha256_bytes
from sbs.static_check import (
    build_version_bound_actor_view,
    extract_version_unit,
    opaque_evidence_id,
    opaque_instance_id,
    version_bound_ready,
)


GENERATION_ID = "r02b-g1"
NEUTRAL_CONTEXT = (
    "Pinned source unit from one recorded revision. Decide whether a stated "
    "functional constraint holds on this snapshot. Advisory identifiers, "
    "repair diffs, and pair-role labels are not provided."
)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_selection(path: Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("task_id") != "R02B":
        raise PilotConfigError("selection task_id must be R02B")
    return payload


def _registry(workspace: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for line in (workspace / "metadata" / "r01_candidates.jsonl").read_text(
        encoding="utf-8"
    ).splitlines():
        if line.strip():
            row = json.loads(line)
            rows[row["pair_id"]] = row
    return rows


def _readiness(workspace: Path) -> dict[str, dict[str, str]]:
    import csv

    out: dict[str, dict[str, str]] = {}
    with (workspace / "metadata" / "r01_readiness.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        for row in csv.DictReader(handle):
            out[row["pair_id"]] = row
    return out


def _catalog_row(workspace: Path, root: Path, key: str) -> dict[str, Any]:
    catalog = _checked_leaf(root, ("catalog", "cases.jsonl"))
    import os

    fd = os.open(catalog, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as handle:
        for raw in handle:
            if not raw.strip():
                continue
            obj = json.loads(raw.decode("utf-8"))
            if obj.get("case_id") == key:
                return obj
    raise PilotConfigError(f"catalog row not found for registered key")


def _store_for_row(root: Path, catalog_row: dict[str, Any]):
    from egsi.data.git_objects import GitCacheGuard

    manifest_parts = _strip_data_prefix(catalog_row["artifacts"]["manifest_path"])
    manifest = json.loads(_checked_leaf(root, manifest_parts).read_text(encoding="utf-8"))
    cache_parts = _strip_data_prefix(manifest["resolution"]["cache_path"])
    checked_dir(root, cache_parts)
    return GitCacheGuard(root, "/".join(cache_parts))


def prepare_pilot(
    workspace: Path,
    selection_path: Path,
    *,
    allow_root_symlink: bool = True,
) -> dict[str, Any]:
    workspace = Path(workspace).resolve(strict=True)
    selection = load_selection(selection_path)
    generation = selection.get("generation_id") or GENERATION_ID
    registry = _registry(workspace)
    readiness = _readiness(workspace)
    root, _is_link = resolve_data_root(workspace, allow_root_symlink=allow_root_symlink)

    actor_root = workspace / "local_data" / "r02b" / "actor"
    eval_root = workspace / "local_data" / "r02b" / "evaluator"
    actor_root.mkdir(parents=True, exist_ok=True)
    eval_root.mkdir(parents=True, exist_ok=True)

    pair_rows: list[dict[str, Any]] = []
    instances: list[dict[str, Any]] = []
    for item in selection.get("pairs") or []:
        if not item.get("include"):
            continue
        pair_id = item["pair_id"]
        rec = registry[pair_id]
        cited = (readiness.get(pair_id) or {}).get("cited_path") or ""
        kind = classify_cited_path(cited)
        if kind in {"release_notes", "missing_citation"}:
            pair_rows.append(
                {
                    "pair_id": pair_id,
                    "status": "skipped_non_code_citation",
                    "cited_path_kind": kind,
                    "instance_ids": [],
                }
            )
            continue
        catalog_row = _catalog_row(workspace, root, rec["local_catalog_key"])
        guard = _store_for_row(root, catalog_row)
        try:
            store = guard.open_store()
            vuln_rev = rec["buggy_revision"]
            fixed_rev = rec["fixed_revision"]
            if not cited or not store.contains(vuln_rev, cited) or not store.contains(fixed_rev, cited):
                pair_rows.append(
                    {
                        "pair_id": pair_id,
                        "status": "single_version_available",
                        "cited_path_kind": kind,
                        "instance_ids": [],
                    }
                )
                continue
            text_v = store.read_text(vuln_rev, cited, max_bytes=2_000_000)
            text_f = store.read_text(fixed_rev, cited, max_bytes=2_000_000)
        finally:
            guard.close()
        if sha256_bytes(text_v.encode("utf-8")) == sha256_bytes(text_f.encode("utf-8")):
            pair_rows.append(
                {
                    "pair_id": pair_id,
                    "status": "bodies_not_independent",
                    "cited_path_kind": kind,
                    "instance_ids": [],
                }
            )
            continue
        extracted: list[tuple[str, str, int, int, str, bool]] = []
        for revision, source_text, other_text in (
            (vuln_rev, text_v, text_f),
            (fixed_rev, text_f, text_v),
        ):
            start, end, unit, truncated = extract_version_unit(
                this_text=source_text, other_text=other_text
            )
            extracted.append((revision, source_text, start, end, unit, truncated))
        if extracted[0][4] == extracted[1][4]:
            pair_rows.append(
                {
                    "pair_id": pair_id,
                    "status": "bodies_not_independent",
                    "cited_path_kind": kind,
                    "instance_ids": [],
                }
            )
            continue
        created: list[str] = []
        for revision, _source_text, start, end, unit, truncated in extracted:
            instance_id = opaque_instance_id(pair_id, revision, generation)
            evidence_id = opaque_evidence_id(instance_id, cited, generation)
            inst_dir = actor_root / instance_id
            if inst_dir.exists():
                raise PilotConfigError("refusing to overwrite existing R02B instance")
            if not version_bound_ready(revision, generation):
                raise VersionBoundError("source_revision=None cannot pass version-bound ready")
            build_version_bound_actor_view(
                instance_id=instance_id,
                visible_context=NEUTRAL_CONTEXT,
                project_family=None,
                evidence_id=evidence_id,
                display_path=cited,
                snippet=unit,
                actor_root=inst_dir,
                source_revision=revision,
                generation_id=generation,
                start_line=start,
                end_line=end,
                truncated=truncated,
            )
            created.append(instance_id)
            instances.append(
                {
                    "instance_id": instance_id,
                    "generation_id": generation,
                    "source_revision": revision,
                    "relative_root": f"local_data/r02b/actor/{instance_id}",
                }
            )
        pair_rows.append(
            {
                "pair_id": pair_id,
                "status": "complete_version_pair",
                "cited_path_kind": kind,
                "instance_ids": created,
                "category_claim": rec.get("category_claim"),
                "obligation_generic": True
                if rec.get("category_claim", "").startswith("logic")
                else False,
                "gold_assisted_context": True,
                "task_scope": "given_location_frozen_evidence",
                "split": "dev_pilot",
            }
        )

    pairs_path = eval_root / "pairs.jsonl"
    with pairs_path.open("w", encoding="utf-8") as handle:
        for row in pair_rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    (eval_root / "HUMAN_REVIEW.md").write_text(
        "# R02B pair review (evaluator only)\n\n"
        "Agent must not set human_verified. review_status remains pending.\n"
        "gold_assisted_context=true for location selection; patches and gold "
        "conclusions stay on this evaluator root.\n",
        encoding="utf-8",
    )
    actor_manifest = {
        "schema_version": "1.0",
        "task_id": "R02B",
        "split": "dev_pilot",
        "generation_id": generation,
        "instances": instances,
        "evaluator_relative_root": "local_data/r02b/evaluator",
        "prepared_at": _now(),
    }
    manifest_path = workspace / "local_data" / "r02b" / "actor_manifest.json"
    manifest_path.write_text(
        json.dumps(actor_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    from sbs.static_check import count_complete_version_pairs

    counts = count_complete_version_pairs(actor_root, pairs_path)
    return {
        "ok": True,
        "actor_manifest": str(manifest_path.as_posix()),
        "actor_manifest_sha256": sha256_bytes(
            canonical_json_bytes(actor_manifest)
        ),
        "instances": len(instances),
        "counts": counts,
        "pairs": pair_rows,
    }

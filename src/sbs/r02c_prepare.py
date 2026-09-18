"""R02C management-side prepare: actor-only frozen run list, no runtime evaluator reads."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sbs.errors import PilotConfigError
from sbs.isolation import IsolatedStore, assert_real_model_actor_root, load_case_view
from sbs.schema import (
    canonical_json_bytes,
    load_instance_manifest_payload,
    reject_answer_fields,
    sha256_bytes,
)
from sbs.static_check import version_bound_ready


GENERATION_ID = "r02c-g1"
PAIR01_INSTANCE_IDS = ("inst-6bf462ca01bb071f", "inst-b750a376e1e3c54c")
ALL_PAIR_INSTANCE_IDS = {
    "r01-pair-01": ["inst-6bf462ca01bb071f", "inst-b750a376e1e3c54c"],
    "r01-pair-12": ["inst-614b3612f0e5db8a", "inst-3300fc1a03e22857"],
    "r01-pair-13": ["inst-cb80f8fe5eb55013", "inst-ebf077b5bfcdcc88"],
    "r01-pair-15": ["inst-ba9671eef76541a9", "inst-90a9632ec46227d5"],
}
FORBIDDEN_RELATIVE = (
    "local_data/r02c/evaluator",
    "local_data/r02b/evaluator",
    "local_data/r02b/evaluator/pairs.jsonl",
    "local_data/r02c/evaluator/pairs.jsonl",
)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_r02c_selection(path: Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("task_id") != "R02C":
        raise PilotConfigError("selection task_id must be R02C")
    return payload


def _copy_instance(src: Path, dest: Path, generation: str) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    man_path = dest / "manifest.json"
    man = json.loads(man_path.read_text(encoding="utf-8"))
    man["generation_id"] = generation
    man_path.write_text(json.dumps(man, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    case_path = dest / "case.json"
    case = json.loads(case_path.read_text(encoding="utf-8"))
    case["generation_id"] = generation
    reject_answer_fields(case)
    case_path.write_text(json.dumps(case, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ev_dir = dest / "evidence"
    for rec_path in ev_dir.glob("*.json"):
        rec = json.loads(rec_path.read_text(encoding="utf-8"))
        rec["generation_id"] = generation
        rec_path.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def inspect_instance_context(inst_dir: Path) -> dict[str, Any]:
    man = json.loads((inst_dir / "manifest.json").read_text(encoding="utf-8"))
    case = json.loads((inst_dir / "case.json").read_text(encoding="utf-8"))
    notes: list[str] = []
    continuous = True
    complete_method = True
    for ev_id in case.get("allowed_evidence_ids") or []:
        rec = json.loads((inst_dir / "evidence" / f"{ev_id}.json").read_text(encoding="utf-8"))
        body = (inst_dir / rec["relative_read_path"]).read_text(encoding="utf-8")
        lines = body.splitlines()
        span = rec.get("span") or man.get("original_span") or {}
        start = span.get("start_line")
        end = span.get("end_line")
        expected = None
        if isinstance(start, int) and isinstance(end, int):
            expected = end - start + 1
            if expected != len(lines):
                notes.append(
                    f"{ev_id}: claimed span {start}-{end} ({expected} lines) vs body {len(lines)} lines"
                )
                continuous = False
        if "truncated_middle" in body or man.get("snippet_truncated"):
            notes.append(f"{ev_id}: truncated_middle or snippet_truncated=true")
            continuous = False
        stripped = body.strip()
        if stripped.startswith("for (") or stripped.startswith("for("):
            notes.append(f"{ev_id}: fragment starts at a for-loop, not a method/type header")
            complete_method = False
        if not stripped.endswith("}") and not stripped.endswith(";"):
            notes.append(f"{ev_id}: body does not end at a closing brace; enclosing unit likely stopped early")
            complete_method = False
        if "getItem" in body and "return" not in body.split("getItem")[-1]:
            notes.append(f"{ev_id}: getItem appears truncated before a return")
            complete_method = False
    return {
        "instance_id": man.get("instance_id"),
        "source_revision": man.get("source_revision"),
        "display_path": man.get("display_path"),
        "original_span": man.get("original_span"),
        "snippet_truncated": bool(man.get("snippet_truncated")),
        "continuous_original_span": continuous and not man.get("snippet_truncated"),
        "enclosing_unit_complete": complete_method,
        "notes": notes,
        "split": "dev_pilot",
    }


def prepare_r02c_pilot(
    workspace: Path,
    selection_path: Path,
    *,
    source_actor_root: str = "local_data/r02b/actor",
) -> dict[str, Any]:
    workspace = Path(workspace).resolve(strict=True)
    selection = load_r02c_selection(selection_path)
    generation = selection.get("generation_id") or GENERATION_ID
    src_root = workspace / source_actor_root
    actor_root = workspace / "local_data" / "r02c" / "actor"
    eval_root = workspace / "local_data" / "r02c" / "evaluator"
    actor_root.mkdir(parents=True, exist_ok=True)
    eval_root.mkdir(parents=True, exist_ok=True)
    (eval_root / "review_cards").mkdir(parents=True, exist_ok=True)

    inspections: list[dict[str, Any]] = []
    copied: list[dict[str, Any]] = []
    for pair_id, instance_ids in ALL_PAIR_INSTANCE_IDS.items():
        for instance_id in instance_ids:
            src = src_root / instance_id
            if not src.is_dir():
                raise PilotConfigError(f"missing R02B actor instance {instance_id}")
            dest = actor_root / instance_id
            _copy_instance(src, dest, generation)
            man = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
            if not version_bound_ready(man["source_revision"], generation):
                raise PilotConfigError("copied instance is not version-bound")
            inspections.append({"pair_id": pair_id, **inspect_instance_context(dest)})
            copied.append(
                {
                    "instance_id": instance_id,
                    "generation_id": generation,
                    "source_revision": man["source_revision"],
                    "relative_root": f"local_data/r02c/actor/{instance_id}",
                    "pair_id_management_only": pair_id,
                }
            )

    runtime_instances = [
        {
            "instance_id": row["instance_id"],
            "generation_id": row["generation_id"],
            "source_revision": row["source_revision"],
            "relative_root": row["relative_root"],
        }
        for row in copied
        if row["instance_id"] in PAIR01_INSTANCE_IDS
    ]
    if len(runtime_instances) != 2:
        raise PilotConfigError("pair-01 must contribute exactly two frozen instances")

    actor_manifest = {
        "schema_version": "1.0",
        "task_id": "R02C",
        "split": "dev_pilot",
        "generation_id": generation,
        "instances": runtime_instances,
        "frozen_schedule": ["form", "read_0", "read_1_or_none", "final"],
        "forbidden_paths": list(FORBIDDEN_RELATIVE),
        "evaluator_relative_root": None,
        "pair_mapping": "not_on_actor_manifest",
        "prepared_at": _now(),
        "gold_assisted_context": True,
        "task_scope": "given_location_frozen_evidence",
        "single_evidence_interface_pilot": True,
    }
    manifest_path = workspace / "local_data" / "r02c" / "actor_manifest.json"
    manifest_path.write_text(
        json.dumps(actor_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    inventory = {
        "schema_version": "1.0",
        "task_id": "R02C",
        "management_only": True,
        "pairs": ALL_PAIR_INSTANCE_IDS,
        "inspections": inspections,
        "copied_instances": copied,
    }
    inv_path = eval_root / "management_inventory.json"
    inv_path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "ok": True,
        "actor_manifest": manifest_path.as_posix(),
        "actor_manifest_sha256": sha256_bytes(canonical_json_bytes(actor_manifest)),
        "runtime_instances": [row["instance_id"] for row in runtime_instances],
        "inspected_instances": len(inspections),
        "generation_id": generation,
        "model_called": False,
    }


def validate_r02c_manifest(workspace: Path, manifest_path: Path) -> dict[str, Any]:
    """Validate actor packs. Must not open evaluator content or count pairs.jsonl."""

    workspace = Path(workspace)
    payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if payload.get("task_id") != "R02C":
        raise PilotConfigError("actor manifest task_id must be R02C")
    if payload.get("evaluator_relative_root"):
        raise PilotConfigError("R02C runtime manifest must not carry an evaluator root")
    instances = payload.get("instances") or []
    forbidden = [workspace / rel for rel in payload.get("forbidden_paths") or FORBIDDEN_RELATIVE]
    problems: list[str] = []
    ready = 0
    for row in instances:
        rel = row["relative_root"]
        root = workspace / rel
        try:
            for banned in forbidden:
                try:
                    root.resolve().relative_to(banned.resolve())
                except (ValueError, OSError):
                    continue
                else:
                    raise PilotConfigError("instance root is a forbidden evaluator path")
            assert_real_model_actor_root(root)
            store = IsolatedStore(root, evaluator_root=None)
            case = load_case_view(store)
            man = load_instance_manifest_payload(
                json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            )
            if man.source_revision is None:
                raise PilotConfigError("source_revision=None")
            if case.split != "dev_pilot":
                raise PilotConfigError("split must be dev_pilot")
            reject_answer_fields(case.model_dump(mode="json"))
            for evidence_id in case.allowed_evidence_ids:
                store.read_evidence(
                    case,
                    evidence_id,
                    expected_generation=man.generation_id,
                    expected_instance=man.instance_id,
                    expected_revision=man.source_revision,
                )
            if store.evaluator_was_read():
                raise PilotConfigError("actor path read evaluator root")
            ready += 1
        except Exception as exc:
            problems.append(f"{row.get('instance_id')}: {type(exc).__name__}:{exc}")
    return {
        "ok": not problems,
        "instances": len(instances),
        "validated": ready,
        "problems": problems,
        "model_called": False,
        "model_loaded": False,
        "opened_evaluator": False,
        "called_count_complete_version_pairs": False,
    }

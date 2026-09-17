"""Static readiness checks for real pairs. Never claims human verification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sbs.isolation import IsolatedStore
from sbs.registry import never_sets_human_verified
from sbs.schema import CaseView, EvidenceRecord, LineSpan, parse_case_view, sha256_bytes


GENERIC_OBLIGATION_MARKERS = (
    "establish attacker principal, target resource, expected authorization relation",
    "establish untrusted source, dangerous sink",
)


def obligation_is_generic(text: str | None) -> bool:
    if text is None or not text.strip():
        return True
    lowered = text.lower()
    return any(marker in lowered for marker in GENERIC_OBLIGATION_MARKERS)


def build_actor_view(
    *,
    pair_id: str,
    visible_context: str,
    project_family: str,
    evidence_id: str,
    display_path: str,
    snippet: str,
    actor_root: Path,
) -> CaseView:
    """Write an actor-only view. Snippet must not include answer fields."""

    actor_root = Path(actor_root)
    (actor_root / "evidence").mkdir(parents=True, exist_ok=True)
    body_rel = f"evidence/{evidence_id}.body"
    body_bytes = snippet.encode("utf-8")
    (actor_root / body_rel).write_bytes(body_bytes)
    record = EvidenceRecord(
        evidence_id=evidence_id,
        display_path=display_path,
        span=LineSpan(start_line=1, end_line=snippet.count("\n") + 1),
        content_sha256=sha256_bytes(body_bytes),
        source_category="source_snippet",
        material_kind="real",
        generation_id="r01-static-1",
        source_revision=None,
        relative_read_path=body_rel,
    )
    (actor_root / "evidence" / f"{evidence_id}.json").write_text(
        record.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    payload = {
        "case_id": pair_id,
        "visible_context": visible_context,
        "allowed_evidence_ids": [evidence_id],
        "split": "dev_pilot",
        "material_kind": "real",
        "project_family": project_family,
    }
    case = parse_case_view(payload)
    (actor_root / "case.json").write_text(
        case.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    return case


def actor_view_excludes_answers(actor_root: Path, evaluator_root: Path | None) -> bool:
    store = IsolatedStore(actor_root, evaluator_root=evaluator_root)
    case = parse_case_view(json.loads(store.read_text("case.json")))
    return store.evaluator_was_read() is False and case.split == "dev_pilot"


def classify_readiness(
    *,
    category_claim: str,
    versions_locatable: bool,
    license_clear: bool,
    citation_range_exists: bool,
    actor_view_generated: bool,
    obligation_basis: str | None,
) -> tuple[str, str, str | None]:
    """Return (status, ready yes/no, blocker)."""

    blocker_parts: list[str] = []
    if not versions_locatable:
        blocker_parts.append("frozen_revision_not_locatable")
    if not license_clear:
        blocker_parts.append("license_unclear")
    if not citation_range_exists:
        blocker_parts.append("citation_range_missing")
    logic = category_claim.startswith("logic")
    if logic and obligation_is_generic(obligation_basis):
        blocker_parts.append("obligation_basis_generic_or_missing")
    ready = (
        versions_locatable
        and license_clear
        and citation_range_exists
        and actor_view_generated
        and not (logic and obligation_is_generic(obligation_basis))
    )
    if ready:
        status = never_sets_human_verified("evidence_draft")
        return status, "yes", None
    if versions_locatable:
        status = never_sets_human_verified("source_resolved")
    else:
        status = never_sets_human_verified("metadata_only")
    return status, "no", ";".join(blocker_parts) if blocker_parts else None


def version_bound_ready(source_revision: str | None, generation_id: str | None) -> bool:
    if source_revision is None or generation_id is None:
        return False
    if source_revision == "None" or not source_revision:
        return False
    return len(source_revision) == 40 and all(
        ch in "0123456789abcdef" for ch in source_revision
    )


def opaque_instance_id(pair_id: str, revision: str, generation: str) -> str:
    digest = sha256_bytes(f"{pair_id}\n{revision}\n{generation}".encode("utf-8"))
    return "inst-" + digest.removeprefix("sha256:")[:16]


def opaque_evidence_id(instance_id: str, display_path: str, generation: str) -> str:
    digest = sha256_bytes(f"{instance_id}\n{display_path}\n{generation}".encode("utf-8"))
    return "ev-" + digest.removeprefix("sha256:")[:12]


def first_diff_range(left: str, right: str) -> tuple[int, int, int, int]:
    left_lines = left.splitlines()
    right_lines = right.splitlines()
    prefix = 0
    limit = min(len(left_lines), len(right_lines))
    while prefix < limit and left_lines[prefix] == right_lines[prefix]:
        prefix += 1
    suffix = 0
    while (
        suffix < (len(left_lines) - prefix)
        and suffix < (len(right_lines) - prefix)
        and left_lines[-1 - suffix] == right_lines[-1 - suffix]
    ):
        suffix += 1
    left_end = max(prefix, len(left_lines) - suffix)
    right_end = max(prefix, len(right_lines) - suffix)
    return prefix + 1, left_end, prefix + 1, right_end


def _is_type_or_method_signature(stripped: str) -> bool:
    if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
        return False
    if any(token in stripped for token in ("class ", "interface ", "enum ")):
        return True
    if "(" in stripped and any(
        token in stripped
        for token in ("public ", "private ", "protected ", "static ", "final ", "void ")
    ):
        return True
    return False


def enclosing_java_unit(text: str, start_line: int, end_line: int) -> tuple[int, int, str]:
    """Return original-file span covering a complete method or class around the range."""

    lines = text.splitlines(keepends=True)
    if not lines:
        return 1, 1, text
    start_idx = max(0, min(len(lines) - 1, start_line - 1))
    sig = start_idx
    found_sig = False
    while sig >= 0:
        if _is_type_or_method_signature(lines[sig].strip()):
            found_sig = True
            break
        sig -= 1
    if not found_sig:
        window = 40
        sig = max(0, start_idx - window)
        finish = min(len(lines), max(start_line, end_line) + window)
        return sig + 1, finish, "".join(lines[sig:finish])
    depth = 0
    started = False
    finish = min(len(lines), max(start_line, end_line))
    for idx in range(sig, len(lines)):
        depth += lines[idx].count("{") - lines[idx].count("}")
        if "{" in lines[idx]:
            started = True
        if started and depth <= 0:
            finish = idx + 1
            break
    else:
        finish = len(lines)
    if finish - sig < 3:
        window = 40
        sig = max(0, start_idx - window)
        finish = min(len(lines), max(start_line, end_line) + window)
    unit = "".join(lines[sig:finish])
    return sig + 1, finish, unit


def extract_version_unit(
    *,
    this_text: str,
    other_text: str,
    max_chars: int = 12_000,
) -> tuple[int, int, str, bool]:
    """Independent body for this version. Truncation is recorded, not hidden."""

    if this_text == other_text:
        start, end, unit = enclosing_java_unit(this_text, 1, min(80, this_text.count("\n") + 1))
    else:
        this_start, this_end, _, _ = first_diff_range(this_text, other_text)
        start, end, unit = enclosing_java_unit(this_text, this_start, this_end)
        other_start, other_end, other_unit, _ = (
            *enclosing_java_unit(other_text, *first_diff_range(other_text, this_text)[:2]),
            False,
        )
        if unit == other_unit:
            lines = this_text.splitlines(keepends=True)
            pad = 25
            start = max(1, this_start - pad)
            end = min(len(lines), this_end + pad)
            unit = "".join(lines[start - 1 : end])
    truncated = False
    if len(unit) > max_chars:
        # Keep the tail/head around the selected span, not a leading prefix that
        # can drop the differing region and collapse two versions into one body.
        overflow = len(unit) - max_chars
        head = max_chars // 4
        unit = unit[:head] + "\n/* truncated_middle */\n" + unit[head + overflow :]
        truncated = True
    return start, end, unit, truncated


def build_version_bound_actor_view(
    *,
    instance_id: str,
    visible_context: str,
    project_family: str | None,
    evidence_id: str,
    display_path: str,
    snippet: str,
    actor_root: Path,
    source_revision: str,
    generation_id: str,
    start_line: int,
    end_line: int,
    truncated: bool,
) -> CaseView:
    """Write a version-bound actor view. source_revision=None is rejected."""

    if not version_bound_ready(source_revision, generation_id):
        from sbs.errors import VersionBoundError

        raise VersionBoundError("source_revision=None cannot pass version-bound ready")
    from sbs.schema import InstanceManifest

    actor_root = Path(actor_root)
    (actor_root / "evidence").mkdir(parents=True, exist_ok=True)
    body_rel = f"evidence/{evidence_id}.body"
    body_bytes = snippet.encode("utf-8")
    (actor_root / body_rel).write_bytes(body_bytes)
    record = EvidenceRecord(
        evidence_id=evidence_id,
        display_path=display_path,
        span=LineSpan(start_line=start_line, end_line=end_line),
        content_sha256=sha256_bytes(body_bytes),
        source_category="source_snippet",
        material_kind="real",
        generation_id=generation_id,
        source_revision=source_revision,
        relative_read_path=body_rel,
    )
    (actor_root / "evidence" / f"{evidence_id}.json").write_text(
        record.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    payload = {
        "case_id": instance_id,
        "visible_context": visible_context,
        "allowed_evidence_ids": [evidence_id],
        "split": "dev_pilot",
        "material_kind": "real",
        "project_family": project_family,
        "instance_id": instance_id,
        "generation_id": generation_id,
    }
    case = parse_case_view(payload)
    (actor_root / "case.json").write_text(
        case.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    manifest = InstanceManifest(
        instance_id=instance_id,
        generation_id=generation_id,
        source_revision=source_revision,
        split="dev_pilot",
        material_kind="real",
    )
    extra = manifest.model_dump(mode="json")
    extra["snippet_truncated"] = truncated
    extra["original_span"] = {"start_line": start_line, "end_line": end_line}
    extra["display_path"] = display_path
    (actor_root / "manifest.json").write_text(
        json.dumps(extra, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return case


def count_complete_version_pairs(actor_root: Path, pairs_path: Path) -> dict[str, int | None]:
    """Derive complete_version_pairs from two-sided version manifests.

    Management-side only. The actor runner must not load pairs_path.
    """

    actor_root = Path(actor_root)
    single = 0
    version_bound = 0
    complete = 0
    if not pairs_path.is_file():
        return {
            "single_version_actor_packages": single,
            "version_bound_actor_instances": version_bound,
            "complete_version_pairs": complete,
        }
    for raw in pairs_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        row = json.loads(raw)
        instance_ids = row.get("instance_ids") or []
        bodies: list[bytes] = []
        revisions: list[str] = []
        bound_here = 0
        for iid in instance_ids:
            inst = actor_root / iid
            man_path = inst / "manifest.json"
            if not man_path.is_file():
                continue
            man = json.loads(man_path.read_text(encoding="utf-8"))
            revision = man.get("source_revision")
            generation = man.get("generation_id")
            if not version_bound_ready(revision, generation):
                continue
            bound_here += 1
            version_bound += 1
            revisions.append(revision)
            evidence_dir = inst / "evidence"
            if evidence_dir.is_dir():
                for body in sorted(evidence_dir.glob("*.body")):
                    bodies.append(body.read_bytes())
        if bound_here == 1:
            single += 1
        if (
            bound_here >= 2
            and len(set(revisions)) >= 2
            and len(set(bodies)) >= 2
        ):
            complete += 1
        elif bound_here >= 1 and bound_here < 2:
            pass
    return {
        "single_version_actor_packages": single,
        "version_bound_actor_instances": version_bound,
        "complete_version_pairs": complete,
    }

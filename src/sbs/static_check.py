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

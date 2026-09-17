"""Final-prompt rendering and fairness comparison on prompt bytes, not just objects."""

from __future__ import annotations

from dataclasses import dataclass

from sbs.errors import FairnessError
from sbs.schema import VisibleEvidence, canonical_json_bytes, sha256_bytes
from sbs.tokens import CharTokenCounter, TokenCounter
from sbs.views import HistoryView, SBSView, public_evidence_bytes


NOTE_RESERVE_TOKENS = 512
EVIDENCE_HEADER = "PUBLIC_EVIDENCE_BLOCK\n"
NOTES_HEADER = "NOTES\n"


@dataclass(frozen=True)
class RenderedPrompt:
    representation: str
    prompt_bytes: bytes
    prompt_sha256: str
    evidence_block_bytes: bytes
    evidence_block_sha256: str
    visible_order: tuple[str, ...]
    clip_bounds: tuple[int, int]
    note_tokens: int
    evidence_tokens: int
    context_insufficient: bool
    notes: str


def encode_evidence_block(items: list[VisibleEvidence]) -> bytes:
    return public_evidence_bytes(items)


def _render_evidence_text(items: list[VisibleEvidence]) -> str:
    parts: list[str] = []
    for item in items:
        span = item.displayed_span
        span_s = f"{span.start_line}-{span.end_line}"
        body = item.material if item.material is not None else ""
        parts.append(
            f"### {item.evidence_id}\n"
            f"path: {item.display_path}\n"
            f"span: {span_s}\n"
            f"found: {item.found}\n"
            f"parseable: {item.parseable}\n"
            f"{body}\n"
        )
    return "".join(parts)


def clip_shared_evidence(
    items: list[VisibleEvidence],
    tokenizer: TokenCounter,
    evidence_budget: int,
) -> tuple[str, tuple[int, int], bool]:
    text = _render_evidence_text(items)
    total = tokenizer.count(text)
    if total <= evidence_budget:
        return text, (0, total), False
    if evidence_budget <= 0:
        return "", (0, 0), True
    clipped, start, end = tokenizer.truncate(text, evidence_budget)
    return clipped, (start, end), True


def assemble_prompt(
    *,
    representation: str,
    visible_context: str,
    notes: str,
    evidence_text: str,
) -> bytes:
    payload = (
        f"REPRESENTATION: {representation}\n"
        f"VISIBLE_CONTEXT:\n{visible_context}\n"
        f"{NOTES_HEADER}{notes}\n"
        f"{EVIDENCE_HEADER}{evidence_text}"
    )
    return payload.encode("utf-8")


def render_fair_prompts(
    *,
    visible_context: str,
    history_notes: str,
    sbs_notes: str,
    evidences: list[VisibleEvidence],
    tokenizer: TokenCounter | None = None,
    max_input_tokens: int = 3072,
    note_reserve: int = NOTE_RESERVE_TOKENS,
) -> tuple[RenderedPrompt, RenderedPrompt]:
    counter = tokenizer or CharTokenCounter()
    if note_reserve < 0 or max_input_tokens <= 0:
        raise FairnessError("invalid token budgets")
    h_notes, _, h_end = counter.truncate(history_notes, note_reserve)
    s_notes, _, s_end = counter.truncate(sbs_notes, note_reserve)
    overhead = counter.count(
        f"REPRESENTATION: history\nVISIBLE_CONTEXT:\n{visible_context}\n{NOTES_HEADER}\n{EVIDENCE_HEADER}"
    )
    evidence_budget = max_input_tokens - note_reserve - overhead
    evidence_text, clip_bounds, insufficient = clip_shared_evidence(
        evidences, counter, evidence_budget
    )
    block = encode_evidence_block(evidences)
    block_sha = sha256_bytes(block)
    order = tuple(item.evidence_id for item in evidences)
    evidence_tokens = counter.count(evidence_text)

    def _one(name: str, notes: str, note_tokens: int) -> RenderedPrompt:
        prompt = assemble_prompt(
            representation=name,
            visible_context=visible_context,
            notes=notes,
            evidence_text=evidence_text,
        )
        return RenderedPrompt(
            representation=name,
            prompt_bytes=prompt,
            prompt_sha256=sha256_bytes(prompt),
            evidence_block_bytes=block,
            evidence_block_sha256=block_sha,
            visible_order=order,
            clip_bounds=clip_bounds,
            note_tokens=note_tokens,
            evidence_tokens=evidence_tokens,
            context_insufficient=insufficient,
            notes=notes,
        )

    history = _one("history", h_notes, h_end)
    sbs = _one("sbs", s_notes, s_end)
    compare_final_prompts(history, sbs)
    return history, sbs


def compare_final_prompts(history: RenderedPrompt, sbs: RenderedPrompt) -> None:
    if history.evidence_block_bytes != sbs.evidence_block_bytes:
        raise FairnessError("public evidence-block bytes differ")
    if history.evidence_block_sha256 != sbs.evidence_block_sha256:
        raise FairnessError("public evidence-block hash differs")
    if history.visible_order != sbs.visible_order:
        raise FairnessError("visible evidence order differs")
    if history.clip_bounds != sbs.clip_bounds:
        raise FairnessError("final prompt evidence clip bounds differ")
    if history.context_insufficient != sbs.context_insufficient:
        raise FairnessError("context_insufficient flags differ")
    if history.evidence_tokens != sbs.evidence_tokens:
        raise FairnessError("evidence token counts differ")


def history_events_to_visible(history: HistoryView, instance_id: str) -> list[VisibleEvidence]:
    from sbs.schema import LineSpan

    items: list[VisibleEvidence] = []
    for event in history.events:
        payload = event.model_dump()
        if "material" not in payload:
            raise FairnessError("History observation is missing material")
        if event.material is None and event.found:
            raise FairnessError("History found observation has no material")
        span = event.displayed_span or LineSpan(start_line=None, end_line=None)
        items.append(
            VisibleEvidence(
                instance_id=instance_id,
                evidence_id=event.evidence_id,
                material=event.material,
                visible_sha256=event.visible_sha256
                or sha256_bytes((event.material or "").encode("utf-8")),
                display_path=event.provenance,
                displayed_span=span,
                found=event.found,
                parseable=event.material is not None,
                uncertainty=event.uncertainty,
            )
        )
    return items


def sbs_to_visible(sbs: SBSView, instance_id: str) -> list[VisibleEvidence]:
    from sbs.schema import LineSpan

    items: list[VisibleEvidence] = []
    for observation in sbs.observations:
        items.append(
            VisibleEvidence(
                instance_id=instance_id,
                evidence_id=observation.evidence_id,
                material=observation.material,
                visible_sha256=sha256_bytes((observation.material or "").encode("utf-8")),
                display_path=observation.provenance,
                displayed_span=LineSpan(start_line=None, end_line=None),
                found=observation.found,
                parseable=observation.parseable,
                uncertainty=observation.uncertainty,
            )
        )
    return items


def assert_views_fair(history: HistoryView, sbs: SBSView, instance_id: str) -> bytes:
    if not history.events and not sbs.observations:
        block = encode_evidence_block([])
        return block
    raw_events = []
    for event in history.events:
        dumped = event.model_dump()
        raw_events.append(dumped)
        if "material" not in dumped:
            raise FairnessError("History observation is missing material")
    h_items = history_events_to_visible(history, instance_id)
    s_items = sbs_to_visible(sbs, instance_id)
    h_block = encode_evidence_block(h_items)
    s_block = encode_evidence_block(s_items)
    if h_block != s_block:
        raise FairnessError("History and SBS public evidence blocks differ")
    if [i.evidence_id for i in h_items] != [i.evidence_id for i in s_items]:
        raise FairnessError("visible evidence order differs")
    for left, right in zip(h_items, s_items):
        if left.material != right.material:
            raise FairnessError("evidence material differs")
        if left.displayed_span != right.displayed_span:
            # SBS observations may omit span when History recorded it; require History span
            # only when both provided.
            if (
                left.displayed_span.start_line is not None
                and right.displayed_span.start_line is not None
                and left.displayed_span != right.displayed_span
            ):
                raise FairnessError("displayed span differs")
    return h_block


def public_block_from_canonical(payload: dict) -> bytes:
    return canonical_json_bytes(payload)


def assert_history_payload_has_material(history_payload: dict) -> None:
    events = history_payload.get("events")
    if not isinstance(events, list):
        raise FairnessError("History payload has no events list")
    for event in events:
        if not isinstance(event, dict):
            raise FairnessError("History event is not an object")
        if event.get("kind") == "observation" and "material" not in event:
            raise FairnessError("History observation is missing material")


def assert_public_fairness_payloads(
    history_payload: dict,
    sbs_payload: dict,
) -> None:
    """Shipped pre-send check on serialized views (drives G01/G02)."""

    assert_history_payload_has_material(history_payload)
    h_events = history_payload.get("events") or []
    s_obs = sbs_payload.get("observations") or []
    if [e.get("evidence_id") for e in h_events] != [o.get("evidence_id") for o in s_obs]:
        raise FairnessError("visible evidence order differs")
    for event, observation in zip(h_events, s_obs):
        if event.get("evidence_id") != observation.get("evidence_id"):
            raise FairnessError("evidence_id mismatch")
        if event.get("material") != observation.get("material"):
            raise FairnessError("evidence material differs")
        h_span = event.get("displayed_span")
        s_span = observation.get("displayed_span") or observation.get("span")
        if h_span is not None and s_span is not None and h_span != s_span:
            raise FairnessError("displayed span differs")

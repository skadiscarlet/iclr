"""HistoryView and SBSView consume the same frozen observation sequence."""

from __future__ import annotations

from sbs.errors import FairnessError
from sbs.schema import (
    AuditState,
    CaseView,
    HistoryEvent,
    Hypothesis,
    Observation,
    VisibleEvidence,
    _ActorModel,
    sha256_text,
)


class HistoryView(_ActorModel):
    """Chronological observation log. Events must carry material, not IDs only."""

    case_id: str
    visible_context: str
    allowed_evidence_ids: list[str]
    events: list[HistoryEvent]

    @property
    def observation_order(self) -> list[str]:
        return [
            event.evidence_id
            for event in self.events
            if event.kind == "observation"
        ]

    @property
    def visible_evidence_ids(self) -> list[str]:
        return list(dict.fromkeys(self.observation_order))


class SBSView(_ActorModel):
    """Explicit hypothesis, support, counter-evidence, and unknowns."""

    case_id: str
    visible_context: str
    allowed_evidence_ids: list[str]
    hypothesis: Hypothesis
    observations: list[Observation]
    unresolved_items: list[str]
    remaining_budget: int
    terminal: str | None
    termination_reason: str | None

    @property
    def observation_order(self) -> list[str]:
        return [item.evidence_id for item in self.observations]

    @property
    def visible_evidence_ids(self) -> list[str]:
        return list(dict.fromkeys(self.observation_order))

    @property
    def support_refs(self) -> list[str]:
        return list(self.hypothesis.support_refs)

    @property
    def counter_refs(self) -> list[str]:
        return list(self.hypothesis.counter_refs)


def primary_hypothesis(state: AuditState) -> Hypothesis:
    if len(state.hypotheses) != 1:
        raise FairnessError(
            "this round requires exactly one primary hypothesis; "
            "refusing silent hypotheses[0] selection"
        )
    return state.hypotheses[0]


def visible_from_observation(
    *,
    instance_id: str,
    observation: Observation,
    display_path: str,
    displayed_span,
) -> VisibleEvidence:
    material = observation.material
    digest = sha256_text(material if material is not None else "")
    return VisibleEvidence(
        instance_id=instance_id,
        evidence_id=observation.evidence_id,
        material=material,
        visible_sha256=digest,
        display_path=display_path,
        displayed_span=displayed_span,
        found=observation.found,
        parseable=observation.parseable,
        uncertainty=observation.uncertainty,
    )


def history_requires_material(history: HistoryView) -> None:
    for event in history.events:
        if event.kind != "observation":
            continue
        # Field presence is guaranteed by HistoryEvent; G01 uses a dict bypass.
        if "material" not in event.model_fields_set and event.material is None:
            raise FairnessError("History observation is missing material")


def views_share_evidence(history: HistoryView, sbs: SBSView) -> bool:
    if not (
        history.case_id == sbs.case_id
        and history.allowed_evidence_ids == sbs.allowed_evidence_ids
        and history.observation_order == sbs.observation_order
        and history.visible_evidence_ids == sbs.visible_evidence_ids
    ):
        return False
    if len(history.events) != len(sbs.observations):
        return False
    for event, observation in zip(history.events, sbs.observations):
        if event.evidence_id != observation.evidence_id:
            return False
        if event.material != observation.material:
            return False
        if event.found != observation.found:
            return False
    return True


def public_evidence_bytes(items: list[VisibleEvidence]) -> bytes:
    from sbs.schema import canonical_json_bytes

    payload = [
        {
            "evidence_id": item.evidence_id,
            "material": item.material,
            "visible_sha256": item.visible_sha256,
            "display_path": item.display_path,
            "displayed_span": item.displayed_span.model_dump(mode="json"),
            "found": item.found,
            "parseable": item.parseable,
            "uncertainty": item.uncertainty,
            "instance_id": item.instance_id,
        }
        for item in items
    ]
    return canonical_json_bytes(payload)


def build_views(
    case: CaseView,
    state: AuditState,
    observations: list[Observation],
    *,
    spans: dict[str, object] | None = None,
) -> tuple[HistoryView, SBSView]:
    hypothesis = primary_hypothesis(state)
    instance_id = case.instance_id or case.case_id
    events: list[HistoryEvent] = []
    for item in observations:
        span = None
        if spans and item.evidence_id in spans:
            span = spans[item.evidence_id]
        events.append(
            HistoryEvent(
                kind="observation",
                evidence_id=item.evidence_id,
                found=item.found,
                provenance=item.provenance,
                uncertainty=item.uncertainty,
                material=item.material,
                displayed_span=span,  # type: ignore[arg-type]
                visible_sha256=sha256_text(item.material or ""),
            )
        )
    history = HistoryView(
        case_id=case.case_id,
        visible_context=case.visible_context,
        allowed_evidence_ids=list(case.allowed_evidence_ids),
        events=events,
    )
    sbs = SBSView(
        case_id=case.case_id,
        visible_context=case.visible_context,
        allowed_evidence_ids=list(case.allowed_evidence_ids),
        hypothesis=hypothesis,
        observations=list(observations),
        unresolved_items=list(state.unresolved_items),
        remaining_budget=state.remaining_budget,
        terminal=state.terminal,
        termination_reason=state.termination_reason,
    )
    return history, sbs

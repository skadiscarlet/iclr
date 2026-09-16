"""HistoryView and SBSView consume the same frozen observation sequence."""

from __future__ import annotations

from typing import Any

from sbs.schema import AuditState, CaseView, Hypothesis, Observation, _ActorModel


class HistoryView(_ActorModel):
    """Chronological observation log. No answer fields."""

    case_id: str
    visible_context: str
    allowed_evidence_ids: list[str]
    events: list[dict[str, Any]]

    @property
    def observation_order(self) -> list[str]:
        return [
            event["evidence_id"]
            for event in self.events
            if event.get("kind") == "observation"
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


def views_share_evidence(history: HistoryView, sbs: SBSView) -> bool:
    return (
        history.case_id == sbs.case_id
        and history.allowed_evidence_ids == sbs.allowed_evidence_ids
        and history.observation_order == sbs.observation_order
        and history.visible_evidence_ids == sbs.visible_evidence_ids
    )


def build_views(
    case: CaseView,
    state: AuditState,
    observations: list[Observation],
) -> tuple[HistoryView, SBSView]:
    hypothesis = state.hypotheses[0]
    events = [
        {
            "kind": "observation",
            "evidence_id": item.evidence_id,
            "found": item.found,
            "provenance": item.provenance,
            "uncertainty": item.uncertainty,
        }
        for item in observations
    ]
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

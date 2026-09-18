"""Atomic SBS card and History note updates for the R02C frozen-pilot path.

R01 `apply_atomic_update` is unchanged. This module never plants schema examples
as live cards. Pre-success state is `not_initialized`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal

from sbs.errors import BindingError
from sbs.output_contract import parse_response, reference_id_errors
from sbs.schema import (
    TERMINAL_FINISH,
    TERMINAL_UNRESOLVED,
    AuditState,
    Decision,
    EvidenceRef,
    LineSpan,
    VisibleEvidence,
    canonical_json_bytes,
    sha256_bytes,
)


SBS_KEYS = (
    "entities",
    "requirement",
    "hypothesis",
    "support_refs",
    "counter_refs",
    "unknowns",
    "limitations",
)
FINAL_KEYS = (
    "hypothesis",
    "verdict",
    "support_refs",
    "counter_refs",
    "unknowns",
    "limitations",
)
PRE_SUCCESS = "not_initialized"


@dataclass
class SBSCard:
    entities: list[str]
    requirement: str
    hypothesis: str
    support_refs: list[str]
    counter_refs: list[str]
    unknowns: list[str]
    limitations: list[str]
    revision: int

    def as_payload(self) -> dict[str, Any]:
        return {
            "entities": list(self.entities),
            "requirement": self.requirement,
            "hypothesis": self.hypothesis,
            "support_refs": list(self.support_refs),
            "counter_refs": list(self.counter_refs),
            "unknowns": list(self.unknowns),
            "limitations": list(self.limitations),
        }

    def serialize(self) -> str:
        return json.dumps(self.as_payload(), ensure_ascii=False, sort_keys=True)

    def state_hash(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.as_payload() | {"revision": self.revision}))


@dataclass
class EpisodeMemory:
    representation: Literal["history", "sbs"]
    history_notes: list[str] = field(default_factory=list)
    sbs_card: SBSCard | None = None
    sbs_card_history: list[dict[str, Any]] = field(default_factory=list)
    raw_history: list[dict[str, Any]] = field(default_factory=list)

    @property
    def initialized(self) -> bool:
        if self.representation == "history":
            return bool(self.history_notes)
        return self.sbs_card is not None

    def prompt_notes(self) -> str:
        if self.representation == "history":
            if not self.history_notes:
                return PRE_SUCCESS
            # Newest complete note first; caller token-truncates complete notes only.
            return "\n".join(reversed(self.history_notes))
        if self.sbs_card is None:
            return PRE_SUCCESS
        return self.sbs_card.serialize()

    def pre_hash(self) -> str:
        if self.representation == "history":
            return sha256_bytes(canonical_json_bytes({"notes": self.history_notes}))
        if self.sbs_card is None:
            return sha256_bytes(canonical_json_bytes({"card": PRE_SUCCESS}))
        return self.sbs_card.state_hash()


def refs_from_ids(
    values: Any,
    *,
    observed: dict[str, VisibleEvidence],
    instance_id: str,
    generation_id: str,
) -> list[EvidenceRef]:
    """Bind each ID to THAT observation's span. Never skip a bad ID. Never reuse first span."""

    if type(values) is not list:
        raise BindingError("reference field is not a list of strings")
    refs: list[EvidenceRef] = []
    for item in values:
        if type(item) is not str or not item.strip():
            raise BindingError("reference item is not a non-empty string; whole update aborted")
        if item not in observed:
            raise BindingError(f"unobserved evidence id {item!r}; whole update aborted")
        vis = observed[item]
        refs.append(
            EvidenceRef(
                evidence_id=item,
                instance_id=instance_id,
                generation_id=generation_id,
                span=LineSpan(
                    start_line=vis.displayed_span.start_line,
                    end_line=vis.displayed_span.end_line,
                ),
            )
        )
    return refs


def apply_history_note(memory: EpisodeMemory, payload: dict[str, Any]) -> EpisodeMemory:
    note = payload.get("note")
    if type(note) is not str or not note.strip():
        raise BindingError("history note missing")
    memory.history_notes.append(note)
    return memory


def apply_sbs_card(
    memory: EpisodeMemory,
    payload: dict[str, Any],
    *,
    observed_ids: set[str],
) -> EpisodeMemory:
    """Atomic replace of the live card. unknowns=[] clears previous unknowns."""

    missing = [k for k in SBS_KEYS if k not in payload]
    if missing:
        raise BindingError("sbs card missing keys")
    ref_errors = reference_id_errors(payload, observed_ids)
    if ref_errors:
        raise BindingError("sbs card references failed; whole update aborted")
    old = memory.sbs_card
    if old is not None:
        memory.sbs_card_history.append(old.as_payload() | {"revision": old.revision})
    revision = 1 if old is None else old.revision + 1
    # New hypothesis text does not inherit previous support/counter.
    memory.sbs_card = SBSCard(
        entities=list(payload["entities"]),
        requirement=str(payload["requirement"]),
        hypothesis=str(payload["hypothesis"]),
        support_refs=list(payload["support_refs"]),
        counter_refs=list(payload["counter_refs"]),
        unknowns=list(payload["unknowns"]),  # empty list clears
        limitations=list(payload["limitations"]),
        revision=revision,
    )
    return memory


def apply_r02c_final(
    state: AuditState,
    payload: dict[str, Any],
    *,
    instance_id: str,
    generation_id: str,
    observed: dict[str, VisibleEvidence],
    allowed_evidence_ids: list[str],
    hypothesis_id: str = "h-primary",
) -> AuditState:
    """Trusted final apply. Illegal verdicts are not remapped to unresolved."""

    snapshot = state.model_copy(deep=True)
    verdict = payload.get("verdict")
    if verdict not in {"supported", "refuted", "unresolved"}:
        raise BindingError("final verdict is not a legal enum")
    observed_ids = set(observed)
    ref_errors = reference_id_errors(payload, observed_ids)
    if ref_errors:
        raise BindingError("final references failed; whole update aborted")
    support = refs_from_ids(
        payload.get("support_refs"),
        observed=observed,
        instance_id=instance_id,
        generation_id=generation_id,
    )
    counter = refs_from_ids(
        payload.get("counter_refs"),
        observed=observed,
        instance_id=instance_id,
        generation_id=generation_id,
    )
    for ref in [*support, *counter]:
        if ref.evidence_id not in allowed_evidence_ids:
            raise BindingError("evidence ref is not on the allow-list")
        item = observed[ref.evidence_id]
        if not item.found or not item.parseable or item.material is None:
            raise BindingError("missing or unparseable evidence cannot support or refute")
    if verdict == "supported" and not support:
        raise BindingError("supported requires material support-evidence")
    if verdict == "refuted" and not counter:
        raise BindingError("refuted requires material counter-evidence")
    matches = [h for h in snapshot.hypotheses if h.hypothesis_id == hypothesis_id]
    if len(matches) != 1:
        raise BindingError("hypothesis_id does not match the single primary hypothesis")
    hypothesis = matches[0]
    hypothesis_text = str(payload.get("hypothesis") or "")
    if not hypothesis_text.strip():
        raise BindingError("final hypothesis missing")
    hypothesis.security_relation = hypothesis_text
    hypothesis.support_refs = [r.evidence_id for r in support]
    hypothesis.counter_refs = [r.evidence_id for r in counter]
    # unknowns=[] clears
    hypothesis.unknowns = list(payload.get("unknowns") or [])
    snapshot.unresolved_items = list(hypothesis.unknowns)
    hypothesis.status = verdict
    snapshot.decision = Decision(
        verdict=verdict,
        applies_to_hypothesis_id=hypothesis.hypothesis_id,
        not_a_global_safety_guarantee=True,
    )
    if verdict in {"supported", "refuted"}:
        snapshot.terminal = TERMINAL_FINISH
        snapshot.termination_reason = "valid_final"
    else:
        snapshot.terminal = TERMINAL_UNRESOLVED
        snapshot.termination_reason = "valid_final_unresolved"
    return snapshot


def parse_and_check(
    raw: str,
    contract: str,
    *,
    observed_ids: set[str] | None = None,
):
    result = parse_response(raw, contract)  # type: ignore[arg-type]
    extra: tuple[str, ...] = ()
    if result.accepted and result.payload is not None and observed_ids is not None:
        extra = reference_id_errors(result.payload, observed_ids)
    return result, extra

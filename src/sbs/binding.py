"""Atomic support/counter binding. Validate fully, then commit; never half-apply."""

from __future__ import annotations

from sbs.errors import BindingError
from sbs.schema import (
    AuditState,
    Decision,
    EvidenceRef,
    LineSpan,
    ModelUpdate,
    TERMINAL_UNRESOLVED,
    VisibleEvidence,
)


def _ref_key(ref: EvidenceRef) -> str:
    return ref.evidence_id


def _validate_ref(
    ref: EvidenceRef,
    *,
    instance_id: str,
    generation_id: str,
    allowed: list[str],
    observed: dict[str, VisibleEvidence],
    require_material: bool,
) -> None:
    if ref.instance_id != instance_id:
        raise BindingError("evidence ref instance_id does not match current instance")
    if ref.generation_id != generation_id:
        raise BindingError("evidence ref generation_id does not match current generation")
    if ref.evidence_id not in allowed:
        raise BindingError("evidence ref is not on the allow-list")
    if ref.evidence_id not in observed:
        raise BindingError("allowed evidence was not read; unread is not an observation")
    item = observed[ref.evidence_id]
    if require_material:
        if not item.found or not item.parseable or item.material is None:
            raise BindingError(
                "missing or unparseable evidence cannot support or refute"
            )
    if ref.span is not None:
        if not item.displayed_span.covers(ref.span):
            raise BindingError("evidence span is outside the original snapshot range")


def apply_atomic_update(
    state: AuditState,
    update: ModelUpdate,
    *,
    instance_id: str,
    generation_id: str,
    allowed_evidence_ids: list[str],
    observed: dict[str, VisibleEvidence],
    remaining_budget: int | None = None,
    context_insufficient: bool = False,
) -> AuditState:
    """Return a new state. On failure the input state is not mutated."""

    snapshot = state.model_copy(deep=True)
    try:
        matches = [
            item
            for item in snapshot.hypotheses
            if item.hypothesis_id == update.hypothesis_id
        ]
        if len(matches) != 1:
            raise BindingError("hypothesis_id does not match the single primary hypothesis")
        if len(snapshot.hypotheses) != 1:
            raise BindingError("multiple hypotheses are not silently selected")
        hypothesis = matches[0]
        for ref in update.support_refs:
            _validate_ref(
                ref,
                instance_id=instance_id,
                generation_id=generation_id,
                allowed=allowed_evidence_ids,
                observed=observed,
                require_material=True,
            )
        for ref in update.counter_refs:
            _validate_ref(
                ref,
                instance_id=instance_id,
                generation_id=generation_id,
                allowed=allowed_evidence_ids,
                observed=observed,
                require_material=True,
            )
        budget = snapshot.remaining_budget if remaining_budget is None else remaining_budget
        verdict = update.verdict
        if context_insufficient or budget <= 0:
            if verdict == "refuted":
                verdict = "unresolved"
            if update.status == "refuted":
                update = update.model_copy(update={"status": "unresolved"})
        if verdict == "refuted" and not update.counter_refs:
            raise BindingError("refuted requires material counter-evidence")
        if verdict == "supported" and not update.support_refs:
            raise BindingError("supported requires material support-evidence")

        hypothesis.support_refs = [_ref_key(ref) for ref in update.support_refs]
        hypothesis.counter_refs = [_ref_key(ref) for ref in update.counter_refs]
        if update.unknowns:
            hypothesis.unknowns = list(update.unknowns)
            snapshot.unresolved_items = list(
                dict.fromkeys([*snapshot.unresolved_items, *update.unknowns])
            )
        if update.status is not None:
            if (
                update.status == "refuted"
                and (context_insufficient or budget <= 0)
            ):
                hypothesis.status = "unresolved"
            else:
                hypothesis.status = update.status
        if verdict is not None:
            if verdict == "refuted" and (context_insufficient or budget <= 0):
                verdict = "unresolved"
                snapshot.terminal = TERMINAL_UNRESOLVED
                snapshot.termination_reason = (
                    "budget_exhausted" if budget <= 0 else "context_insufficient"
                )
            snapshot.decision = Decision(
                verdict=verdict,
                applies_to_hypothesis_id=hypothesis.hypothesis_id,
                not_a_global_safety_guarantee=True,
            )
            if verdict == "unresolved":
                snapshot.terminal = snapshot.terminal or TERMINAL_UNRESOLVED
                hypothesis.status = "unresolved"
        return snapshot
    except BindingError:
        raise


def reject_replaced_body(
    expected: VisibleEvidence,
    actual: VisibleEvidence,
) -> None:
    if expected.evidence_id != actual.evidence_id:
        raise BindingError("evidence_id changed")
    if expected.visible_sha256 != actual.visible_sha256:
        raise BindingError("evidence body was replaced")
    if expected.material != actual.material:
        raise BindingError("evidence body was replaced")
    if expected.displayed_span != actual.displayed_span:
        raise BindingError("evidence span was replaced")


def span_from_original(start_line: int, end_line: int) -> LineSpan:
    return LineSpan(start_line=start_line, end_line=end_line)

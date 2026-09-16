"""Reserved value-scoring interface. Unavailable in R01."""

from __future__ import annotations

from sbs.errors import ValueScorerUnavailable


class ValueScorer:
    """Placeholder for a later Q-return model. Explicitly unavailable."""

    available: bool = False

    def __init__(self) -> None:
        raise ValueScorerUnavailable(
            "ValueScorer is unavailable; R01 has no trained Q/V model"
        )

    def score(self, *args: object, **kwargs: object) -> float:
        raise ValueScorerUnavailable(
            "ValueScorer is unavailable; R01 has no trained Q/V model"
        )


def require_scorer_unavailable() -> None:
    if ValueScorer.available:
        raise RuntimeError("R01 must not enable ValueScorer")

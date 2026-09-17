"""Typed errors for actor-side isolation and replay."""

from __future__ import annotations


class IsolationError(ValueError):
    """Actor store refused a path or evidence read."""


class UnauthorizedEvidenceError(IsolationError):
    """Evidence ID is not on the case allow-list."""


class PathEscapeError(IsolationError):
    """Resolved path is outside the actor root."""


class EvaluatorReadError(IsolationError):
    """Attempted read would touch the evaluator/answer root."""


class MissingEvidenceError(IsolationError):
    """Allow-listed evidence object is absent."""


class HashMismatchError(IsolationError):
    """On-disk content does not match the recorded content hash."""


class StaleEvidenceError(IsolationError):
    """Evidence generation/revision no longer matches the recorded pointer."""


class SchemaAnswerFieldError(ValueError):
    """Actor-visible payload contains a forbidden answer field."""


class ValueScorerUnavailable(RuntimeError):
    """No trained Q/V model is available in R01."""


class ReplayConfigError(ValueError):
    """Smoke/replay config is not an offline fixture replay."""


class FairnessError(ValueError):
    """History and SBS public evidence or final prompts are not aligned."""


class BindingError(ValueError):
    """Evidence ref update failed atomic validation; caller state is unchanged."""


class VersionBoundError(ValueError):
    """Actor package is not version-bound (instance + revision + generation)."""


class PilotConfigError(ValueError):
    """Frozen-pilot config or actor manifest is not runnable."""


class PilotBudgetError(ValueError):
    """Request would exceed the persisted hard cap."""


class ContextInsufficientError(ValueError):
    """Shared context budget cannot keep required public evidence."""

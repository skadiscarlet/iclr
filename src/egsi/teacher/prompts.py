"""Deterministic, oracle-only prompts for non-authoritative teacher labels."""

from __future__ import annotations

from copy import deepcopy
import json
from typing import Any

from egsi.contracts.enrichment import EnrichmentPayload
from egsi.data.context import OracleContext
from egsi.teacher.output_schema import (
    StrictOutputSchemaError,
    normalize_strict_output_schema,
)


SYSTEM = (
    "You reconstruct minimal patch-grounded Java Web audit labels. Return only one JSON "
    "object matching the supplied schema. You may emit a hypothesis, unknown proof "
    "obligations, locations, and a typed investigation trace. Never emit facts, rewards, "
    "certificates, exploit success, shell commands, or markdown. The trace goal, operation, "
    "target_kind, and tool_class fields must be copied verbatim from their schema enums."
)

PROOF_TEMPLATES: dict[str, list[str]] = {
    "source_to_sink": [
        "establish an externally influenced source",
        "establish a path from source to security-sensitive sink",
        "check the required sanitizer or validation invariant",
        "keep runtime impact unknown at T1",
    ],
    "authorization": [
        "identify attacker and victim principals",
        "identify the action and protected resource",
        "state the expected subject-resource relation",
        "locate the actual guard and keep runtime impact unknown at T1",
    ],
}

PROMPT_VERSION = "2.3"
ACTION_VOCABULARY_FIELDS = (
    "goals",
    "operations",
    "target_kinds",
    "tool_classes",
)
_TRACE_ENUM_FIELDS = {
    "goal": "goals",
    "operation": "operations",
    "target_kind": "target_kinds",
    "tool_class": "tool_classes",
}
_MAX_VOCABULARY_VALUES = 256
_MAX_VOCABULARY_VALUE_BYTES = 256
_REPAIR_FLAGS = {
    "invalid_structured_output": "structured_output_invalid",
    "semantic_validation_failed": "semantic_validation_failed",
    "invalid_canonical_path": "canonical_path_invalid",
    "invalid_teacher_response_metadata": "provenance_validation_failed",
}
_REPAIR_INSTRUCTIONS = {
    "invalid_structured_output": (
        "Regenerate the complete JSON object so it matches the supplied schema exactly."
    ),
    "semantic_validation_failed": (
        "Regenerate the complete JSON object using only patch-grounded locations and valid Action DSL choices."
    ),
    "invalid_canonical_path": (
        "Regenerate the complete JSON object. Every path field must be a canonical repo-relative POSIX blob path "
        "that names the vulnerable snapshot; use exact blob names and valid in-blob line/symbol locations."
    ),
    "invalid_teacher_response_metadata": (
        "Regenerate the complete JSON object without changing the required response contract."
    ),
}

_REPAIR_FLAG_NAMES = (
    "structured_output_invalid",
    "semantic_validation_failed",
    "canonical_path_invalid",
    "provenance_validation_failed",
)


def _deterministic_vocabulary(vocabulary: object) -> dict[str, list[str]]:
    """Validate the four prompt vocabularies and return canonical sorted lists."""

    if type(vocabulary) is not dict or set(vocabulary) != set(ACTION_VOCABULARY_FIELDS):
        raise TypeError("action vocabulary must be an exact four-field dict")
    canonical: dict[str, list[str]] = {}
    for field in ACTION_VOCABULARY_FIELDS:
        values: Any = vocabulary[field]
        if type(values) is not set:
            raise TypeError(f"action vocabulary {field} must be an exact set")
        if not values or len(values) > _MAX_VOCABULARY_VALUES:
            raise ValueError(f"action vocabulary {field} must be non-empty and bounded")
        for value in values:
            if type(value) is not str or not value.strip():
                raise TypeError(f"action vocabulary {field} values must be non-empty exact strings")
            try:
                length = len(value.encode("utf-8"))
            except UnicodeError:
                raise ValueError(f"action vocabulary {field} contains invalid Unicode") from None
            if length > _MAX_VOCABULARY_VALUE_BYTES:
                raise ValueError(f"action vocabulary {field} values must be bounded")
        canonical[field] = sorted(values)
    return canonical


def _constrained_schema(
    vocabulary: dict[str, list[str]], *, strict_grounded_locations: bool = True
) -> dict[str, Any]:
    """Return an isolated payload schema with the four Action DSL enum constraints."""

    schema = deepcopy(EnrichmentPayload.model_json_schema())
    try:
        properties = schema["$defs"]["TraceStep"]["properties"]
        for field, vocabulary_field in _TRACE_ENUM_FIELDS.items():
            title = properties[field].get("title")
            constrained: dict[str, Any] = {
                "type": "string",
                "enum": list(vocabulary[vocabulary_field]),
            }
            if type(title) is str and title:
                constrained["title"] = title
            properties[field] = constrained
        if strict_grounded_locations:
            locations = schema["$defs"]["EnrichedLocation"]["properties"]
            locations["path"] = {"type": "string", "minLength": 1}
            locations["symbol"] = {"type": "string"}
            locations["start_line"] = {"type": "integer", "minimum": 1}
            locations["end_line"] = {"type": "integer", "minimum": 1}
    except (KeyError, TypeError):
        raise RuntimeError("EnrichmentPayload schema is missing TraceStep properties") from None
    try:
        return normalize_strict_output_schema(schema)
    except StrictOutputSchemaError:
        raise RuntimeError("EnrichmentPayload schema is not provider-compatible") from None


def _repair_feedback(repair_error: str | None, repair_attempt: int) -> dict[str, Any]:
    if type(repair_attempt) is not int or repair_attempt not in {0, 1, 2}:
        raise ValueError("repair_attempt must be exactly 0, 1, or 2")
    if repair_attempt == 0:
        if repair_error is not None:
            raise ValueError("the initial request cannot contain repair feedback")
        return {
            "flags": {
                flag: False for flag in _REPAIR_FLAG_NAMES
            },
            "instruction": "This is the initial generation request; no repair category applies.",
        }
    if type(repair_error) is not str or repair_error not in _REPAIR_FLAGS:
        raise ValueError("a repair request requires one fixed safe repair category")
    active_flag = _REPAIR_FLAGS[repair_error]
    return {
        "flags": {
            flag: flag == active_flag
            for flag in _REPAIR_FLAG_NAMES
        },
        "instruction": _REPAIR_INSTRUCTIONS[repair_error],
    }


def enrichment_request(
    context: OracleContext,
    vocabulary: dict[str, set[str]],
    repair_error: str | None = None,
    repair_attempt: int = 0,
) -> tuple[str, str, dict]:
    """Build the one canonical teacher request for a context and repair hint."""

    canonical_vocabulary = _deterministic_vocabulary(vocabulary)
    schema = _constrained_schema(canonical_vocabulary)
    repair_feedback = _repair_feedback(repair_error, repair_attempt)
    user = json.dumps(
        {
            "prompt_version": PROMPT_VERSION,
            "context_version": context.context_version,
            "selection_policy_id": context.selection_policy_id,
            "task": "Recover the minimal investigation trace justified by this oracle-only context.",
            "context": json.loads(context.render()),
            "proof_template": PROOF_TEMPLATES[context.family],
            "schema": schema,
            "action_vocabulary": canonical_vocabulary,
            "action_vocabulary_instruction": (
                "trace.goal, trace.operation, trace.target_kind, and trace.tool_class must be copied "
                "verbatim from the corresponding enum; do not write natural language for these fields. "
                "这些字段只能逐字选枚举，不能写自然语言。"
            ),
            "repository_path_instruction": (
                "For trace steps with target_kind == 'path', target_id must equal byte-for-byte a canonical "
                "repo-relative POSIX blob path present in the vulnerable commit snapshot, and target_location "
                "must equal target_id. Every non-null target_location and every locations[].path follows the "
                "same canonical spelling rule. Absolute paths, './', '..', backslashes, empty segments, and "
                "flow/control/data-path descriptions are forbidden. Location line numbers must fit the vulnerable "
                "blob, and a non-null symbol's final identifier must occur in the stated line range or its small "
                "validation window."
            ),
            "repair_attempt": repair_attempt,
            "repair_feedback": repair_feedback,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return SYSTEM, user, schema


def enrichment_request_v22(
    context: OracleContext,
    vocabulary: dict[str, set[str]],
    repair_error: str | None = None,
    repair_attempt: int = 0,
) -> tuple[str, str, dict]:
    """Reconstruct the frozen v2.2 envelope for historical replay only."""

    canonical_vocabulary = _deterministic_vocabulary(vocabulary)
    schema = _constrained_schema(
        canonical_vocabulary, strict_grounded_locations=False
    )
    legacy_flags = {
        "invalid_structured_output": "structured_output_invalid",
        "semantic_validation_failed": "semantic_validation_failed",
        "invalid_canonical_path": "canonical_path_invalid",
    }
    if repair_attempt == 0:
        if repair_error is not None:
            raise ValueError("the initial request cannot contain repair feedback")
        feedback = {
            "flags": {flag: False for flag in _REPAIR_FLAG_NAMES},
            "instruction": "This is the initial generation request; no repair category applies.",
        }
    else:
        if (
            type(repair_attempt) is not int
            or repair_attempt not in {1, 2}
            or type(repair_error) is not str
            or repair_error not in legacy_flags
        ):
            raise ValueError("a repair request requires one fixed safe repair category")
        active = legacy_flags[repair_error]
        feedback = {
            "flags": {
                flag: flag == active for flag in _REPAIR_FLAG_NAMES
            },
            "instruction": _REPAIR_INSTRUCTIONS[repair_error],
        }
    user = json.dumps(
        {
            "prompt_version": "2.2",
            "context_version": context.context_version,
            "selection_policy_id": context.selection_policy_id,
            "task": "Recover the minimal investigation trace justified by this oracle-only context.",
            "context": json.loads(context.render()),
            "proof_template": PROOF_TEMPLATES[context.family],
            "schema": schema,
            "action_vocabulary": canonical_vocabulary,
            "action_vocabulary_instruction": (
                "trace.goal, trace.operation, trace.target_kind, and trace.tool_class must be copied "
                "verbatim from the corresponding enum; do not write natural language for these fields. "
                "这些字段只能逐字选枚举，不能写自然语言。"
            ),
            "repository_path_instruction": (
                "For trace steps with target_kind == 'path', target_id must equal byte-for-byte a canonical "
                "repo-relative POSIX blob path present in the vulnerable commit snapshot, and target_location "
                "must equal target_id. Every non-null target_location and every locations[].path follows the "
                "same canonical spelling rule. Absolute paths, './', '..', backslashes, empty segments, and "
                "flow/control/data-path descriptions are forbidden. Location line numbers must fit the vulnerable "
                "blob, and a non-null symbol's final identifier must occur in the stated line range or its small "
                "validation window."
            ),
            "repair_attempt": repair_attempt,
            "repair_feedback": feedback,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return SYSTEM, user, schema


def enrichment_request_v21(
    context: OracleContext,
    vocabulary: dict[str, set[str]],
    repair_error: str | None = None,
    repair_attempt: int = 0,
) -> tuple[str, str, dict]:
    """Reconstruct the frozen v2.1 envelope for historical audit replay only."""

    canonical_vocabulary = _deterministic_vocabulary(vocabulary)
    schema = _constrained_schema(
        canonical_vocabulary, strict_grounded_locations=False
    )
    if type(repair_attempt) is not int or repair_attempt not in {0, 1, 2}:
        raise ValueError("repair_attempt must be exactly 0, 1, or 2")
    legacy_flags = {
        "invalid_structured_output": "structured_output_invalid",
        "semantic_validation_failed": "semantic_validation_failed",
        "invalid_teacher_response_metadata": "provenance_validation_failed",
    }
    legacy_instructions = {
        "invalid_structured_output": (
            "Regenerate the complete JSON object so it matches the supplied schema exactly."
        ),
        "semantic_validation_failed": (
            "Regenerate the complete JSON object using only patch-grounded locations and valid Action DSL choices."
        ),
        "invalid_teacher_response_metadata": (
            "Regenerate the complete JSON object without changing the required response contract."
        ),
    }
    if repair_attempt == 0:
        if repair_error is not None:
            raise ValueError("the initial request cannot contain repair feedback")
        feedback = {
            "flags": {
                "structured_output_invalid": False,
                "semantic_validation_failed": False,
                "provenance_validation_failed": False,
            },
            "instruction": "This is the initial generation request; no repair category applies.",
        }
    else:
        if type(repair_error) is not str or repair_error not in legacy_flags:
            raise ValueError("a repair request requires one fixed safe repair category")
        active = legacy_flags[repair_error]
        feedback = {
            "flags": {
                flag: flag == active
                for flag in (
                    "structured_output_invalid",
                    "semantic_validation_failed",
                    "provenance_validation_failed",
                )
            },
            "instruction": legacy_instructions[repair_error],
        }
    user = json.dumps(
        {
            "prompt_version": "2.1",
            "context_version": context.context_version,
            "selection_policy_id": context.selection_policy_id,
            "task": "Recover the minimal investigation trace justified by this oracle-only context.",
            "context": json.loads(context.render()),
            "proof_template": PROOF_TEMPLATES[context.family],
            "schema": schema,
            "action_vocabulary": canonical_vocabulary,
            "action_vocabulary_instruction": (
                "trace.goal, trace.operation, trace.target_kind, and trace.tool_class must be copied "
                "verbatim from the corresponding enum; do not write natural language for these fields. "
                "这些字段只能逐字选枚举，不能写自然语言。"
            ),
            "repair_attempt": repair_attempt,
            "repair_feedback": feedback,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return SYSTEM, user, schema

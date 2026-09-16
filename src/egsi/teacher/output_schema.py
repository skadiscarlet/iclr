"""Canonical provider-compatible structured-output schema normalization."""

from __future__ import annotations

import math
from typing import Any


_STRICT_SCHEMA_KEYS = frozenset(
    {
        "$defs",
        "$ref",
        "type",
        "enum",
        "const",
        "anyOf",
        "properties",
        "items",
        "required",
        "minLength",
        "minItems",
        "minimum",
        "pattern",
        "additionalProperties",
        "default",
        "title",
    }
)
_STRICT_SCHEMA_TYPES = frozenset(
    {"object", "array", "string", "integer", "number", "boolean", "null"}
)


class StrictOutputSchemaError(ValueError):
    """The supplied schema cannot be represented by the strict output subset."""


def _literal(value: object) -> object:
    value_type = type(value)
    if value is None or value_type in {str, bool, int}:
        return value
    if value_type is float and math.isfinite(value):
        return value
    raise StrictOutputSchemaError("strict output schema contains an unsupported literal")


def _schema_map(value: object) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise StrictOutputSchemaError("strict output schema maps must be exact string-keyed dicts")
    return {key: _schema_node(item) for key, item in value.items()}


def _schema_node(value: object) -> dict[str, Any]:
    if type(value) is not dict:
        raise StrictOutputSchemaError("strict output schema nodes must be exact dicts")
    if any(type(key) is not str or key not in _STRICT_SCHEMA_KEYS for key in value):
        raise StrictOutputSchemaError("strict output schema contains an unsupported keyword")

    schema_type = value.get("type")
    if "type" in value and (
        type(schema_type) is not str or schema_type not in _STRICT_SCHEMA_TYPES
    ):
        raise StrictOutputSchemaError("strict output schema contains an unsupported type")

    normalized: dict[str, Any] = {}
    for key, item in value.items():
        if key in {"default", "title", "required", "additionalProperties"}:
            continue
        if key in {"$defs", "properties"}:
            normalized[key] = _schema_map(item)
        elif key == "items":
            normalized[key] = _schema_node(item)
        elif key == "anyOf":
            if type(item) is not list or not item:
                raise StrictOutputSchemaError("strict output anyOf must be a non-empty exact list")
            normalized[key] = [_schema_node(branch) for branch in item]
        elif key == "enum":
            if type(item) is not list or not item:
                raise StrictOutputSchemaError("strict output enum must be a non-empty exact list")
            normalized[key] = [_literal(member) for member in item]
        elif key == "const":
            normalized[key] = _literal(item)
        elif key == "$ref":
            if (
                type(item) is not str
                or not item.startswith("#/$defs/")
                or len(item) <= len("#/$defs/")
            ):
                raise StrictOutputSchemaError("strict output schema contains an unsupported reference")
            normalized[key] = item
        elif key == "type":
            normalized[key] = schema_type
        elif key in {"minLength", "minItems"}:
            if type(item) is not int or item < 0:
                raise StrictOutputSchemaError("strict output schema contains an invalid minimum")
            normalized[key] = item
        elif key == "minimum":
            if (
                type(item) not in {int, float}
                or (type(item) is float and not math.isfinite(item))
            ):
                raise StrictOutputSchemaError("strict output schema contains an invalid minimum")
            normalized[key] = item
        elif key == "pattern":
            if type(item) is not str:
                raise StrictOutputSchemaError("strict output schema contains an invalid pattern")
            normalized[key] = item
        else:  # pragma: no cover - guarded by the keyword allowlist above.
            raise StrictOutputSchemaError("strict output schema contains an unsupported keyword")

    if "required" in value and (
        type(value["required"]) is not list
        or any(type(name) is not str for name in value["required"])
        or len(set(value["required"])) != len(value["required"])
    ):
        raise StrictOutputSchemaError("strict output required must contain unique strings")
    if "additionalProperties" in value and type(value["additionalProperties"]) is not bool:
        raise StrictOutputSchemaError("strict output additionalProperties must be boolean")

    if schema_type == "object":
        properties = normalized.get("properties")
        if properties is None:
            properties = {}
            normalized["properties"] = properties
        normalized["additionalProperties"] = False
        normalized["required"] = sorted(properties)
    elif any(key in value for key in ("properties", "required", "additionalProperties")):
        raise StrictOutputSchemaError("non-object strict output schema has object keywords")

    if schema_type == "array" and "items" not in normalized:
        raise StrictOutputSchemaError("strict output arrays require an item schema")
    if "minItems" in normalized and schema_type != "array":
        raise StrictOutputSchemaError("minItems requires a strict output array")
    if "minLength" in normalized and schema_type != "string":
        raise StrictOutputSchemaError("minLength requires a strict output string")
    if not normalized:
        raise StrictOutputSchemaError("strict output schema node is empty")
    return normalized


def normalize_strict_output_schema(value: object) -> dict[str, Any]:
    """Normalize to the provider-safe subset; applying it twice is idempotent."""

    return _schema_node(value)

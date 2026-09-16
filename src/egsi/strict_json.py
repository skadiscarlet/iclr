"""Bounded strict JSON decoding for untrusted serialized inputs."""

from __future__ import annotations

import json
import math
from typing import Any


class StrictJsonError(ValueError):
    """JSON is malformed, ambiguous, non-finite, or outside its byte bound."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError("strict JSON contains a duplicate object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    del value
    raise StrictJsonError("strict JSON contains a non-finite numeric constant")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise StrictJsonError("strict JSON contains a non-finite number")
    return result


def strict_json_loads(raw: str | bytes, *, max_bytes: int) -> Any:
    """Decode strict JSON after enforcing a deterministic UTF-8 byte limit."""

    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError("strict JSON max_bytes must be a non-negative exact integer")
    if type(raw) is bytes:
        if len(raw) > max_bytes:
            raise StrictJsonError("strict JSON exceeds its byte limit")
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            raise StrictJsonError("strict JSON is not valid UTF-8") from None
    elif type(raw) is str:
        if len(raw) > max_bytes:
            raise StrictJsonError("strict JSON exceeds its byte limit")
        try:
            encoded = raw.encode("utf-8")
        except UnicodeError:
            raise StrictJsonError("strict JSON is not valid UTF-8") from None
        if len(encoded) > max_bytes:
            raise StrictJsonError("strict JSON exceeds its byte limit")
        text = raw
    else:
        raise TypeError("strict JSON input must be an exact str or bytes")
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except StrictJsonError:
        raise
    except (json.JSONDecodeError, ValueError, OverflowError, RecursionError):
        raise StrictJsonError("strict JSON is invalid") from None

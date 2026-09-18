"""Strict, non-semantic response parsing for the bounded R02C pilot.

Only surrounding whitespace and a single whole-response Markdown fence may be
removed. Values, keys, labels, arrays and incomplete JSON are NEVER repaired.
No model, network, file, evaluator or repository access occurs in this module.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

Contract = Literal["history_note", "sbs_note", "final"]
MAX_RAW_BYTES = 65536
KEYS = {
    "history_note": frozenset({"note"}),
    "sbs_note": frozenset({"entities", "requirement", "hypothesis", "support_refs",
                            "counter_refs", "unknowns", "limitations"}),
    "final": frozenset({"hypothesis", "verdict", "support_refs", "counter_refs",
                        "unknowns", "limitations"}),
}
VERDICTS = frozenset({"supported", "refuted", "unresolved"})
_FENCE = re.compile(r"\A```(?:json)?[ \t]*\r?\n(?P<body>.*?)\r?\n```\Z", re.DOTALL)


def _hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class _DuplicateKey(ValueError):
    pass


class _NonFiniteNumber(ValueError):
    pass


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise _DuplicateKey("duplicate key")
        result[key] = value
    return result


def _constant(_: str) -> Any:
    raise _NonFiniteNumber("non-finite number")


@dataclass(frozen=True)
class ParseResult:
    contract: str
    raw_sha256: str
    envelope: str
    json_status: str
    schema_status: str
    error_codes: tuple[str, ...] = ()
    payload: dict[str, Any] | None = field(default=None, repr=False)
    normalized_text: str | None = field(default=None, repr=False)
    normalized_sha256: str | None = None

    @property
    def accepted(self) -> bool:
        return self.json_status == "valid" and self.schema_status == "valid"

    def public_summary(self) -> dict[str, Any]:
        """No arbitrary field values, model prose, raw text or source excerpts."""
        return {
            "contract": self.contract,
            "raw_sha256": self.raw_sha256,
            "envelope": self.envelope,
            "json_status": self.json_status,
            "schema_status": self.schema_status,
            "error_codes": list(self.error_codes),
            "accepted": self.accepted,
            "normalized_sha256": self.normalized_sha256,
        }


def _schema_errors(obj: Any, contract: Contract) -> tuple[str, ...]:
    if not isinstance(obj, dict):
        return ("top_level_not_object",)
    errors: list[str] = []
    expected = KEYS[contract]
    if expected - obj.keys():
        errors.append("missing_required_keys")
    if obj.keys() - expected:
        errors.append("unexpected_keys")
    string_fields = {
        "history_note": {"note"},
        "sbs_note": {"requirement", "hypothesis"},
        "final": {"hypothesis", "verdict"},
    }[contract]
    for name in expected & obj.keys():
        value = obj[name]
        if name in string_fields:
            limit = 8192 if name == "note" else 4096
            if type(value) is not str or not value.strip() or len(value) > limit:
                errors.append(f"invalid_string:{name}")
            elif name == "verdict" and value not in VERDICTS:
                errors.append("invalid_verdict_enum")
        else:
            if type(value) is not list or len(value) > 16:
                errors.append(f"invalid_array:{name}")
                continue
            limit = 128 if name in {"support_refs", "counter_refs"} else 1024
            if any(type(x) is not str or not x.strip() or len(x) > limit for x in value):
                errors.append(f"invalid_array_item:{name}")
            elif name in {"support_refs", "counter_refs"} and len(set(value)) != len(value):
                errors.append(f"duplicate_ref:{name}")
    return tuple(errors)


def parse_response(raw: str, contract: Contract) -> ParseResult:
    """Parse one complete response; schema acceptance is NOT semantic correctness.

    Unsupported envelopes, ambiguous object selection, missing brackets,
    duplicate keys, NaN/Infinity, implicit type conversions and default filling
    are rejected. This function must not be used to award a semantic reward.
    """
    if contract not in KEYS:
        raise ValueError("unknown response contract")
    if type(raw) is not str:
        raise TypeError("raw response must be str")
    digest = _hash(raw)
    if len(raw.encode("utf-8")) > MAX_RAW_BYTES:
        return ParseResult(contract, digest, "rejected", "not_attempted", "not_attempted",
                           ("raw_too_large",))
    text = raw.strip()
    envelope = "bare"
    if text.startswith("```"):
        match = _FENCE.fullmatch(text)
        if match is None:
            return ParseResult(contract, digest, "rejected", "not_attempted", "not_attempted",
                               ("unsupported_fence",))
        text = match.group("body").strip()
        envelope = "whole_response_fence_removed"
    try:
        obj = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except _DuplicateKey:
        return ParseResult(contract, digest, envelope, "invalid", "not_attempted",
                           ("duplicate_json_key",), normalized_text=text,
                           normalized_sha256=_hash(text))
    except _NonFiniteNumber:
        return ParseResult(contract, digest, envelope, "invalid", "not_attempted",
                           ("nonfinite_json_number",), normalized_text=text,
                           normalized_sha256=_hash(text))
    except (json.JSONDecodeError, RecursionError, ValueError):
        return ParseResult(contract, digest, envelope, "invalid", "not_attempted",
                           ("invalid_json",), normalized_text=text,
                           normalized_sha256=_hash(text))
    errors = _schema_errors(obj, contract)
    return ParseResult(
        contract, digest, envelope, "valid", "invalid" if errors else "valid", errors,
        payload=obj if isinstance(obj, dict) else None,
        normalized_text=text, normalized_sha256=_hash(text),
    )


def reference_id_errors(payload: dict[str, Any], observed_ids: set[str]) -> tuple[str, ...]:
    """Check ID membership only. Production must ALSO verify instance/version/body.

    Invoke only after schema validation. Does not drop or rewrite bad references.
    """
    errors: list[str] = []
    for name in ("support_refs", "counter_refs"):
        refs = payload.get(name, [])
        if type(refs) is not list or any(type(x) is not str for x in refs):
            errors.append(f"invalid_refs:{name}")
        elif any(ref not in observed_ids for ref in refs):
            errors.append(f"unobserved_ref:{name}")
    return tuple(errors)

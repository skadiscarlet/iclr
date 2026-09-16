"""Provider-neutral contracts and synchronous HTTP retry handling for teachers."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
from time import perf_counter
from typing import Any, Protocol
import warnings

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator


UNREPORTED_PROVIDER_MODEL = "unreported"


def normalize_provider_response_model(value: object) -> str:
    """Return a reported server model identity or the explicit fixed sentinel."""

    if type(value) is str and value.strip():
        return value.strip()
    return UNREPORTED_PROVIDER_MODEL


def teacher_response_commitment(value: dict[str, Any]) -> str:
    """Commit the immutable response envelope, excluding cache-local state."""

    canonical = dict(value)
    canonical.pop("response_commitment_sha256", None)
    canonical.pop("cached", None)
    raw = json.dumps(
        canonical,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def committed_teacher_response(**value: Any) -> "TeacherResponse":
    """Build a strict response envelope with a canonical self-commitment."""

    data = dict(value)
    data["response_commitment_sha256"] = "sha256:" + "0" * 64
    normalized = TeacherResponse.model_validate(
        data, context={"skip_response_commitment": True}
    ).model_dump(mode="json")
    normalized["response_commitment_sha256"] = teacher_response_commitment(normalized)
    return TeacherResponse.model_validate(normalized)


DEFAULT_TIMEOUT_SECONDS = 180.0
MAX_RETRIES = 10


with warnings.catch_warnings():
    # Pydantic v2 retains BaseModel.schema for compatibility; the public API
    # here deliberately uses the contract-required ``schema`` field name.
    warnings.filterwarnings("ignore", message='Field name "schema".*', category=UserWarning)

    class TeacherRequest(BaseModel):
        """A structured-enrichment request sent to a teacher provider."""

        model_config = ConfigDict(extra="forbid", strict=True, validate_default=True)

        system: str
        user: str
        schema: dict[str, Any]
        temperature: float = 0.0
        max_tokens: int = Field(default=8192, gt=0, strict=True)

        @field_validator("temperature", mode="before")
        @classmethod
        def temperature_is_finite_number(cls, value: Any) -> Any:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError("temperature must be finite")
            return value


def teacher_request_value(request: TeacherRequest) -> dict[str, Any]:
    """Return the exact provider-neutral request fields committed by adapters."""

    if not isinstance(request, TeacherRequest):
        raise TypeError("request must be a TeacherRequest")
    return {
        "system": request.system,
        "user": request.user,
        "schema": request.schema,
        "temperature": request.temperature,
        "max_tokens": request.max_tokens,
    }


def canonical_teacher_request_bytes(request: TeacherRequest) -> bytes:
    """Serialize a teacher request exactly as the audit request commitment."""

    return json.dumps(
        teacher_request_value(request),
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def teacher_request_hash(request: TeacherRequest) -> str:
    """Return the canonical request hash shared by adapters and audit replay."""

    return "sha256:" + hashlib.sha256(canonical_teacher_request_bytes(request)).hexdigest()


class TeacherResponse(BaseModel):
    """The complete, non-authoritative output of a teacher provider."""

    model_config = ConfigDict(extra="forbid", strict=True, validate_default=True)

    provider_request_id: str | None
    provider: str
    model: str
    requested_model: str
    provider_response_model: str
    text: str
    usage: dict[str, int]
    latency_ms: float = Field(default=0.0, ge=0, strict=True)
    cached: bool = False
    response_commitment_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_model_identity_and_commitment(self, info: ValidationInfo) -> "TeacherResponse":
        if not self.model or not self.requested_model or self.model != self.requested_model:
            raise ValueError("model must equal the requested model identity")
        if not self.provider_response_model:
            raise ValueError("provider response model must be explicit")
        if info.context and info.context.get("skip_response_commitment") is True:
            return self
        if self.response_commitment_sha256 != teacher_response_commitment(
            self.model_dump(mode="json")
        ):
            raise ValueError("teacher response commitment mismatch")
        return self

    @field_validator("latency_ms", mode="before")
    @classmethod
    def latency_is_finite_float(cls, value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError("latency_ms must be a finite non-negative float")
        return float(value)

    @field_validator("usage", mode="before")
    @classmethod
    def usage_is_non_negative_integer_map(cls, value: Any) -> Any:
        if not isinstance(value, dict) or any(type(count) is not int or count < 0 for count in value.values()):
            raise ValueError("usage values must be non-negative integers")
        return value


class Teacher(Protocol):
    """A synchronous structured teacher implementation."""

    provider: str
    model: str

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        """Generate provider text and usage metadata for an enrichment request."""


def post_json(
    client: httpx.Client,
    url: str,
    *,
    headers: Mapping[str, str],
    json: dict[str, Any],
    max_retries: int,
) -> httpx.Response:
    """POST JSON with bounded retries and provider-safe failures."""

    if type(max_retries) is not int or not 0 <= max_retries <= MAX_RETRIES:
        raise ValueError(f"max_retries must be an integer between 0 and {MAX_RETRIES}")
    retryable_statuses = {408, 409, 425, 429}
    for attempt in range(max_retries + 1):
        try:
            response = client.post(url, headers=dict(headers), json=json)
        except httpx.TransportError as exc:
            if attempt == max_retries:
                raise RuntimeError(f"teacher transport error: {type(exc).__name__}") from None
            continue

        if 200 <= response.status_code < 300:
            return response
        if response.status_code in retryable_statuses or response.status_code >= 500:
            if attempt < max_retries:
                continue
        raise RuntimeError(f"teacher HTTP error: {response.status_code}") from None

    raise AssertionError("retry loop must return or raise")


def response_latency_ms(started_at: float) -> float:
    """Return a non-negative local request latency in milliseconds."""

    return max(0.0, (perf_counter() - started_at) * 1000)


def integer_usage(value: Any) -> dict[str, int]:
    """Keep only standard JSON integer usage fields supplied by a provider."""

    if not isinstance(value, dict):
        return {}
    return {
        key: count
        for key, count in value.items()
        if isinstance(key, str) and type(count) is int and count >= 0
    }

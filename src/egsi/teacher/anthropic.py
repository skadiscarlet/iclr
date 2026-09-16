"""Anthropic Messages API teacher adapter."""

from __future__ import annotations

from time import perf_counter
from typing import Any

import httpx
from pydantic import SecretStr

from .base import (
    DEFAULT_TIMEOUT_SECONDS,
    TeacherRequest,
    TeacherResponse,
    committed_teacher_response,
    integer_usage,
    normalize_provider_response_model,
    post_json,
    response_latency_ms,
)
from egsi.config import ProviderConfig


class AnthropicTeacher:
    """Call Anthropic's Messages API and normalize text-only output."""

    provider = "anthropic"

    def __init__(
        self,
        config: ProviderConfig | None = None,
        *,
        base_url: str | None = None,
        api_key: str | SecretStr | None = None,
        model: str | None = None,
        max_retries: int | None = None,
        client: httpx.Client | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if config is not None:
            base_url = str(config.base_url)
            api_key = config.api_key
            model = config.model
            if max_retries is None:
                max_retries = config.max_retries
            timeout = config.timeout_seconds
        else:
            if base_url is None or api_key is None or model is None:
                raise TypeError("base_url, api_key, and model are required")
            timeout = DEFAULT_TIMEOUT_SECONDS
        self.base_url = base_url.rstrip("/") + "/v1/messages"
        self._api_key = api_key if isinstance(api_key, SecretStr) else SecretStr(api_key)
        self.model = model
        self.max_retries = 3 if max_retries is None else max_retries
        self._owns_client = client is None
        self._client = client if client is not None else httpx.Client(transport=transport, timeout=timeout, trust_env=False)

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "system": request.system,
            "messages": [{"role": "user", "content": request.user}],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        started_at = perf_counter()
        response = post_json(
            self._client,
            self.base_url,
            headers={"x-api-key": self._api_key.get_secret_value(), "anthropic-version": "2023-06-01"},
            json=payload,
            max_retries=self.max_retries,
        )
        try:
            body = response.json()
            if not isinstance(body, dict):
                raise TypeError("response must be an object")
            request_id = body.get("id")
            if request_id is not None and not isinstance(request_id, str):
                raise TypeError("id must be a string")
            content = body["content"]
            if not isinstance(content, list):
                raise TypeError("content must be a list")
            text = "".join(
                block["text"]
                for block in content
                if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)
            )
        except (KeyError, TypeError, ValueError):
            raise RuntimeError("teacher response invalid") from None
        return committed_teacher_response(
            provider_request_id=request_id,
            provider=self.provider,
            model=self.model,
            requested_model=self.model,
            provider_response_model=normalize_provider_response_model(body.get("model")),
            text=text,
            usage=integer_usage(body.get("usage")),
            latency_ms=response_latency_ms(started_at),
        )

    def close(self) -> None:
        """Close an internally-created HTTP client, if any."""

        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "AnthropicTeacher":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

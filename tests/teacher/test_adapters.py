from __future__ import annotations

import json

import httpx
import pytest
import respx
from pydantic import ValidationError

from egsi.teacher import (
    AnthropicTeacher,
    OpenAICompatibleTeacher,
    TeacherRequest,
    committed_teacher_response,
)


REQUEST = TeacherRequest(
    system="You are an enrichment teacher.",
    user="Explain the evidence.",
    schema={"type": "object", "properties": {"summary": {"type": "string"}}},
)


def test_request_rejects_extra_fields_and_non_positive_max_tokens():
    with pytest.raises(ValidationError):
        TeacherRequest(system="s", user="u", schema={}, unexpected=True)
    with pytest.raises(ValidationError):
        TeacherRequest(system="s", user="u", schema={}, max_tokens=0)


@respx.mock
def test_openai_retries_500_and_never_leaks_api_key():
    route = respx.post("https://teacher.example/v1/chat/completions").mock(
        side_effect=[
            httpx.Response(500, json={"error": "upstream"}),
            httpx.Response(
                200,
                json={
                    "id": "request-2",
                    "model": "gpt-server-actual-2026-08-29",
                    "choices": [{"message": {"content": '{"summary":"ok"}'}}],
                    "usage": {"prompt_tokens": 4, "completion_tokens": 2, "ignored": "no"},
                },
            ),
        ]
    )
    teacher = OpenAICompatibleTeacher(
        base_url="https://teacher.example/v1/",
        api_key="OPENAI_TEST_SECRET",
        model="test-model",
        max_retries=1,
    )

    response = teacher.generate(REQUEST)

    assert route.call_count == 2
    sent = route.calls.last.request
    assert sent.headers["authorization"] == "Bearer OPENAI_TEST_SECRET"
    payload = json.loads(sent.content)
    assert payload == {
        "model": "test-model",
        "messages": [
            {"role": "system", "content": REQUEST.system},
            {"role": "user", "content": REQUEST.user},
        ],
        "temperature": 0.0,
        "max_tokens": 8192,
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "egsi_enrichment", "strict": True, "schema": REQUEST.schema},
        },
    }
    assert response.provider == "openai_compatible"
    assert response.model == "test-model"
    assert response.requested_model == "test-model"
    assert response.provider_response_model == "gpt-server-actual-2026-08-29"
    assert response.provider_request_id == "request-2"
    assert response.text == '{"summary":"ok"}'
    assert response.usage == {"prompt_tokens": 4, "completion_tokens": 2}
    assert "OPENAI_TEST_SECRET" not in repr(response)


def test_transport_errors_are_retried():
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.ConnectError("socket failure", request=request)
        return httpx.Response(
            200,
            json={"id": "ok", "choices": [{"message": {"content": "{}"}}], "usage": {}},
            request=request,
        )

    teacher = OpenAICompatibleTeacher(
        base_url="https://teacher.example/v1",
        api_key="TRANSPORT_SECRET",
        model="m",
        max_retries=1,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    assert teacher.generate(REQUEST).text == "{}"
    assert attempts == 2


def test_non_retryable_4xx_is_safe_and_not_retried():
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(400, json={"error": {"message": "BAD_SECRET_VALUE"}}, request=request)

    teacher = OpenAICompatibleTeacher(
        base_url="https://teacher.example/v1",
        api_key="HTTP_SECRET",
        model="m",
        max_retries=3,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(RuntimeError, match=r"teacher HTTP error: 400") as raised:
        teacher.generate(REQUEST)
    assert attempts == 1
    assert "HTTP_SECRET" not in str(raised.value)
    assert "BAD_SECRET_VALUE" not in str(raised.value)


@respx.mock
def test_anthropic_request_and_response_contract():
    route = respx.post("https://anthropic.example/api/v1/messages").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "msg_123",
                "model": "claude-server-actual-2026-08-29",
                "content": [
                    {"type": "thinking", "thinking": "hidden"},
                    {"type": "text", "text": "first"},
                    {"type": "text", "text": " second"},
                ],
                "usage": {"input_tokens": 7, "output_tokens": 3, "other": None},
            },
        )
    )
    teacher = AnthropicTeacher(
        base_url="https://anthropic.example/api/",
        api_key="ANTHROPIC_SECRET",
        model="claude-test",
    )

    response = teacher.generate(REQUEST)

    assert route.called
    sent = route.calls.last.request
    assert sent.headers["x-api-key"] == "ANTHROPIC_SECRET"
    assert sent.headers["anthropic-version"] == "2023-06-01"
    assert json.loads(sent.content) == {
        "model": "claude-test",
        "system": REQUEST.system,
        "messages": [{"role": "user", "content": REQUEST.user}],
        "temperature": 0.0,
        "max_tokens": 8192,
    }
    assert response.provider == "anthropic"
    assert response.model == "claude-test"
    assert response.requested_model == "claude-test"
    assert response.provider_response_model == "claude-server-actual-2026-08-29"
    assert response.provider_request_id == "msg_123"
    assert response.text == "first second"
    assert response.usage == {"input_tokens": 7, "output_tokens": 3}
    assert response.latency_ms >= 0


@pytest.mark.parametrize("reported", [None, "", "   ", 7, ["bad"], {"bad": True}])
@pytest.mark.parametrize("adapter", ["openai", "anthropic"])
def test_adapter_uses_explicit_unreported_for_missing_or_invalid_actual_model(
    reported, adapter
):
    def handler(request: httpx.Request) -> httpx.Response:
        if adapter == "openai":
            body = {
                "id": "response-id",
                "choices": [{"message": {"content": "{}"}}],
                "usage": {},
            }
        else:
            body = {
                "id": "response-id",
                "content": [{"type": "text", "text": "{}"}],
                "usage": {},
            }
        if reported is not None:
            body["model"] = reported
        return httpx.Response(200, json=body, request=request)

    if adapter == "openai":
        teacher = OpenAICompatibleTeacher(
            base_url="https://identity.example/v1",
            api_key="SECRET",
            model="requested-alias",
            transport=httpx.MockTransport(handler),
        )
    else:
        teacher = AnthropicTeacher(
            base_url="https://identity.example",
            api_key="SECRET",
            model="requested-alias",
            transport=httpx.MockTransport(handler),
        )

    response = teacher.generate(REQUEST)

    assert response.model == response.requested_model == "requested-alias"
    assert response.provider_response_model == "unreported"


def test_openai_accepts_provider_config_and_mock_transport():
    from egsi.config import ProviderConfig

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL("https://configured.example/v1/chat/completions")
        return httpx.Response(
            200,
            json={"id": "configured", "choices": [{"message": {"content": "{}"}}], "usage": {}},
            request=request,
        )

    config = ProviderConfig(
        base_url="https://configured.example/v1",
        api_key="CONFIG_SECRET",
        model="configured-model",
        timeout_seconds=2,
        max_retries=0,
    )
    teacher = OpenAICompatibleTeacher(config, transport=httpx.MockTransport(handler))

    assert teacher.generate(REQUEST).provider_request_id == "configured"


def test_anthropic_accepts_provider_config_and_mock_transport():
    from egsi.config import ProviderConfig

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL("https://configured-anthropic.example/v1/messages")
        return httpx.Response(
            200,
            json={"id": "configured", "content": [{"type": "text", "text": "{}"}], "usage": {}},
            request=request,
        )

    config = ProviderConfig(
        kind="anthropic",
        base_url="https://configured-anthropic.example",
        api_key="CONFIG_SECRET",
        model="configured-model",
        timeout_seconds=2,
        max_retries=0,
    )
    teacher = AnthropicTeacher(config, transport=httpx.MockTransport(handler))

    assert teacher.generate(REQUEST).provider_request_id == "configured"


def test_response_requires_explicit_provider_request_id_and_default_latency_is_float():
    with pytest.raises(ValidationError):
        committed_teacher_response(
            provider="fake", model="m", requested_model="m",
            provider_response_model="unreported", text="{}", usage={}
        )
    response = committed_teacher_response(
        provider_request_id=None, provider="fake", model="m", requested_model="m",
        provider_response_model="unreported", text="{}", usage={}
    )
    assert response.provider_request_id is None
    assert response.latency_ms == 0.0
    assert type(response.latency_ms) is float

@pytest.mark.parametrize("temperature", [True, float("nan"), float("inf"), -float("inf")])
def test_request_rejects_boolean_and_non_finite_temperature(temperature):
    with pytest.raises(ValidationError):
        TeacherRequest(system="s", user="u", schema={}, temperature=temperature)


@pytest.mark.parametrize("max_tokens", [True, False, 1.5, "1", 0, -1])
def test_request_rejects_non_strict_or_non_positive_max_tokens(max_tokens):
    with pytest.raises(ValidationError):
        TeacherRequest(system="s", user="u", schema={}, max_tokens=max_tokens)


@pytest.mark.parametrize("latency", [True, "1", float("nan"), float("inf"), -0.1])
def test_response_rejects_non_strict_or_non_finite_latency(latency):
    with pytest.raises(ValidationError):
        committed_teacher_response(
            provider_request_id=None, provider="p", model="m", requested_model="m",
            provider_response_model="unreported", text="{}", usage={}, latency_ms=latency
        )


@pytest.mark.parametrize("usage", [{"tokens": True}, {"tokens": "1"}, {"tokens": -1}])
def test_response_rejects_invalid_usage_values(usage):
    with pytest.raises(ValidationError):
        committed_teacher_response(
            provider_request_id=None, provider="p", model="m", requested_model="m",
            provider_response_model="unreported", text="{}", usage=usage
        )


def test_direct_adapter_has_bounded_timeout_and_owns_its_client():
    teacher = OpenAICompatibleTeacher(
        base_url="https://teacher.example/v1", api_key="TIMEOUT_SECRET", model="m", transport=httpx.MockTransport(lambda _: httpx.Response(500))
    )
    assert teacher._client.timeout.connect is not None
    assert teacher._client.timeout.connect > 0
    with teacher as active:
        assert active is teacher
    assert teacher._client.is_closed


def test_adapter_does_not_close_an_injected_client_and_does_not_store_plain_api_key():
    external = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(
        200,
        json={"id": "ok", "choices": [{"message": {"content": "{}"}}], "usage": {}},
        request=request,
    )))
    teacher = OpenAICompatibleTeacher(
        base_url="https://teacher.example/v1", api_key="NO_PLAINTEXT_SECRET", model="m", client=external
    )

    response = teacher.generate(REQUEST)
    teacher.close()

    state = repr(vars(teacher)) + repr(teacher)
    assert response.text == "{}"
    assert "NO_PLAINTEXT_SECRET" not in state
    assert not external.is_closed
    external.close()


def test_cached_teacher_forwards_close_and_context_management(tmp_path):
    class ClosableTeacher:
        provider = "fake"
        model = "m"

        def __init__(self):
            self.closed = 0

        def generate(self, request):
            return committed_teacher_response(
                provider_request_id=None, provider=self.provider, model=self.model,
                requested_model=self.model, provider_response_model="unreported",
                text="{}", usage={}
            )

        def close(self):
            self.closed += 1

    inner = ClosableTeacher()
    teacher = __import__("egsi.teacher", fromlist=["CachedTeacher"]).CachedTeacher(inner, tmp_path)
    with teacher as active:
        assert active is teacher
    assert inner.closed == 1
    teacher.close()
    assert inner.closed == 2


@pytest.mark.parametrize("invalid", [-1, 11, True, False, 1.5, "1"])
def test_post_json_rejects_invalid_retry_budget_before_request(invalid):
    from egsi.teacher.base import post_json

    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, request=request)

    with pytest.raises(ValueError):
        post_json(httpx.Client(transport=httpx.MockTransport(handler)), "https://teacher.example", headers={}, json={}, max_retries=invalid)
    assert calls == 0


def test_post_json_zero_retry_and_exhausted_transport_attempts_are_bounded_and_safe():
    from egsi.teacher.base import post_json

    http_attempts = 0

    def http_handler(request: httpx.Request) -> httpx.Response:
        nonlocal http_attempts
        http_attempts += 1
        return httpx.Response(500, request=request)

    with pytest.raises(RuntimeError, match=r"teacher HTTP error: 500"):
        post_json(httpx.Client(transport=httpx.MockTransport(http_handler)), "https://teacher.example", headers={}, json={}, max_retries=0)
    assert http_attempts == 1

    transport_attempts = 0

    def transport_handler(request: httpx.Request) -> httpx.Response:
        nonlocal transport_attempts
        transport_attempts += 1
        raise httpx.ReadTimeout("BODY_SECRET", request=request)

    with pytest.raises(RuntimeError, match=r"teacher transport error: ReadTimeout") as raised:
        post_json(httpx.Client(transport=httpx.MockTransport(transport_handler)), "https://teacher.example", headers={}, json={}, max_retries=2)
    assert transport_attempts == 3
    assert "BODY_SECRET" not in str(raised.value)


@pytest.mark.parametrize(
    "teacher_factory",
    [
        lambda: OpenAICompatibleTeacher(base_url="https://invalid.example/v1", api_key="OPENAI_BODY_SECRET", model="m", transport=httpx.MockTransport(lambda request: httpx.Response(200, json=["not", "object"], request=request))),
        lambda: OpenAICompatibleTeacher(base_url="https://invalid.example/v1", api_key="OPENAI_BODY_SECRET", model="m", transport=httpx.MockTransport(lambda request: httpx.Response(200, json={}, request=request))),
        lambda: AnthropicTeacher(base_url="https://invalid.example", api_key="ANTHROPIC_BODY_SECRET", model="m", transport=httpx.MockTransport(lambda request: httpx.Response(200, json=[], request=request))),
        lambda: AnthropicTeacher(base_url="https://invalid.example", api_key="ANTHROPIC_BODY_SECRET", model="m", transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"id": "ok", "content": "wrong"}, request=request))),
        lambda: AnthropicTeacher(base_url="https://invalid.example", api_key="ANTHROPIC_BODY_SECRET", model="m", transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"id": "ok"}, request=request))),
    ],
)
def test_malformed_provider_responses_are_uniform_safe_errors(teacher_factory):
    teacher = teacher_factory()
    with pytest.raises(RuntimeError, match=r"^teacher response invalid$") as raised:
        teacher.generate(REQUEST)
    assert raised.value.__cause__ is None
    assert "SECRET" not in str(raised.value)


def test_adapters_keep_only_non_negative_integer_usage():
    teacher = OpenAICompatibleTeacher(
        base_url="https://usage.example/v1",
        api_key="USAGE_SECRET",
        model="m",
        transport=httpx.MockTransport(lambda request: httpx.Response(
            200,
            json={"id": "ok", "choices": [{"message": {"content": "{}"}}], "usage": {"good": 2, "negative": -1, "boolean": True, "text": "3"}},
            request=request,
        )),
    )

    assert teacher.generate(REQUEST).usage == {"good": 2}


def test_anthropic_context_manager_closes_only_self_owned_client():
    teacher = AnthropicTeacher(
        base_url="https://anthropic-close.example",
        api_key="ANTHROPIC_CLOSE_SECRET",
        model="m",
        transport=httpx.MockTransport(lambda _: httpx.Response(500)),
    )
    with teacher as active:
        assert active is teacher
    assert teacher._client.is_closed

    external = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(500)))
    injected = AnthropicTeacher(
        base_url="https://anthropic-close.example", api_key="ANTHROPIC_EXTERNAL_SECRET", model="m", client=external
    )
    injected.close()
    assert not external.is_closed
    external.close()


def test_cached_teacher_forwards_inner_context_protocol(tmp_path):
    class ContextTeacher:
        provider = "fake"
        model = "m"

        def __init__(self):
            self.events: list[str] = []

        def generate(self, request):
            return committed_teacher_response(
                provider_request_id=None, provider=self.provider, model=self.model,
                requested_model=self.model, provider_response_model="unreported",
                text="{}", usage={}
            )

        def __enter__(self):
            self.events.append("enter")
            return self

        def __exit__(self, exc_type, exc, traceback):
            self.events.append("exit")
            return False

    inner = ContextTeacher()
    teacher = __import__("egsi.teacher", fromlist=["CachedTeacher"]).CachedTeacher(inner, tmp_path)
    with teacher as active:
        assert active is teacher
    assert inner.events == ["enter", "exit"]


def test_response_normalizes_non_negative_integer_latency_to_float():
    response = committed_teacher_response(
        provider_request_id=None, provider="p", model="m", requested_model="m",
        provider_response_model="unreported", text="{}", usage={}, latency_ms=1
    )
    assert response.latency_ms == 1.0
    assert type(response.latency_ms) is float

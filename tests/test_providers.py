"""Provider plumbing for Cortex LLMHoster and Ollama.

Neither service exists in CI, so every network call is answered by an
``httpx.MockTransport`` that speaks the real wire format: OpenAI-compatible for
Cortex, ``/api/*`` JSON for Ollama. The point of these tests is that DiskFree
reports an honest status and a useful hint in every failure mode, and never
invents a completion.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from diskfree.ai.providers import (
    ChatMessage,
    CortexProvider,
    LLMProvider,
    OllamaProvider,
    ProviderError,
    ProviderRegistry,
    ProviderStatus,
    extract_json,
)
from diskfree.config import ProviderSettings, Settings

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

Handler = Callable[[httpx.Request], httpx.Response]


def mock_client(handler: Handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)


def json_response(payload: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=payload)


def cortex_settings(**overrides: Any) -> ProviderSettings:
    base: dict[str, Any] = {
        "name": "cortex", "base_url": "http://127.0.0.1:8624", "api_key": "test-key",
        "model": None, "timeout": 5.0, "enabled": True,
    }
    base.update(overrides)
    return ProviderSettings(**base)


def ollama_settings(**overrides: Any) -> ProviderSettings:
    base: dict[str, Any] = {
        "name": "ollama", "base_url": "http://127.0.0.1:11434", "api_key": None,
        "model": None, "timeout": 5.0, "enabled": True,
    }
    base.update(overrides)
    return ProviderSettings(**base)


def HEALTHY_CORTEX(request: httpx.Request) -> httpx.Response:
    """A Cortex host that answers every endpoint DiskFree uses."""

    routes = {
        "/health": lambda: json_response({"status": "ok"}),
        "/ready": lambda: json_response({"status": "ready", "models": 2}),
        "/v1/models": lambda: json_response(
            {"object": "list", "data": [
                {"id": "qwen-local", "object": "model", "owned_by": "cortex-llmhoster"},
                {"id": "llama3.1", "object": "model", "owned_by": "cortex-llmhoster"},
            ]}
        ),
        "/v1/chat/completions": lambda: json_response(
            {"choices": [{"message": {"role": "assistant", "content": "hello from cortex"}}]}
        ),
    }
    return routes.get(request.url.path, lambda: json_response({"error": "unexpected"}, 404))()


def HEALTHY_OLLAMA(request: httpx.Request) -> httpx.Response:
    """An Ollama host with one model loaded."""

    routes = {
        "/api/version": lambda: json_response({"version": "0.5.7"}),
        "/api/tags": lambda: json_response({"models": [{"name": "llama3.2:latest"}]}),
        "/api/ps": lambda: json_response({"models": [{"name": "llama3.2:latest"}]}),
        "/api/chat": lambda: json_response(
            {"model": "llama3.2",
             "message": {"role": "assistant", "content": "hello from ollama"},
             "done": True}
        ),
    }
    return routes.get(request.url.path, lambda: json_response({"error": "unexpected"}, 404))()


# --------------------------------------------------------------------------
# extract_json
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ('{"a": 1}', {"a": 1}),
        ('  {"a": 1}  ', {"a": 1}),
        ('```json\n{"a": 1}\n```', {"a": 1}),
        ('```\n{"a": 1}\n```', {"a": 1}),
        ('Sure! Here you go:\n{"a": 1}\nHope that helps.', {"a": 1}),
        ('{"a": {"b": {"c": 1}}}', {"a": {"b": {"c": 1}}}),
        ('[1, 2, 3]', [1, 2, 3]),
        ('{"a": "text with } brace"}', {"a": "text with } brace"}),
    ],
)
def test_extract_json_handles_realistic_model_output(text: str, expected: Any) -> None:
    assert extract_json(text) == expected


@pytest.mark.parametrize("text", ["", "no json here at all", "{unterminated", "null-ish"])
def test_extract_json_raises_when_there_is_nothing_to_parse(text: str) -> None:
    with pytest.raises(ValueError):
        extract_json(text)


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------


def test_provider_settings_never_leak_the_api_key() -> None:
    settings = cortex_settings(api_key="super-secret")
    redacted = settings.redacted()
    assert redacted["api_key_set"] is True
    assert "super-secret" not in json.dumps(redacted)
    assert "api_key" not in redacted


def test_headers_carry_the_bearer_token_only_when_one_is_set() -> None:
    with_key = CortexProvider(cortex_settings(api_key="abc"))
    without = CortexProvider(cortex_settings(api_key=None))
    assert with_key.headers().get("Authorization") == "Bearer abc"
    assert "Authorization" not in without.headers()


def test_urls_are_joined_without_double_slashes() -> None:
    provider = CortexProvider(cortex_settings(base_url="http://host:1234/"))
    assert provider.url("/health") == "http://host:1234/health"


# --------------------------------------------------------------------------
# registry selection
# --------------------------------------------------------------------------


def test_registry_prefers_cortex_when_both_are_configured() -> None:
    settings = Settings(providers=(cortex_settings(), ollama_settings()))
    registry = ProviderRegistry(settings)
    assert set(registry.names) == {"cortex", "ollama"}
    assert registry.order() == ["cortex", "ollama"]
    assert registry.order("ollama") == ["ollama", "cortex"]


def test_registry_skips_disabled_providers() -> None:
    settings = Settings(
        providers=(cortex_settings(enabled=False), ollama_settings())
    )
    registry = ProviderRegistry(settings)
    assert registry.order() == ["ollama"]


def test_registry_rejects_an_unknown_provider_name() -> None:
    with pytest.raises(ValueError):
        ProviderRegistry(Settings(providers=(ProviderSettings(name="skynet", base_url="x"),)))


async def test_registry_info_for_an_unconfigured_name() -> None:
    registry = ProviderRegistry(Settings(providers=(ollama_settings(),)))
    info = await registry.info("cortex")
    assert info.status is ProviderStatus.UNCONFIGURED
    assert info.detail == "not configured"
    await registry.aclose()


async def test_select_returns_nothing_when_no_host_answers() -> None:
    """The sandbox has no Cortex and no Ollama; DiskFree must degrade quietly."""

    settings = Settings(
        providers=(
            cortex_settings(base_url="http://127.0.0.1:9"),
            ollama_settings(base_url="http://127.0.0.1:9"),
        )
    )
    registry = ProviderRegistry(settings, client=mock_client(
        lambda request: (_ for _ in ()).throw(httpx.ConnectError("refused", request=request))
    ))
    assert await registry.select() is None
    infos = await registry.all_info()
    assert {info.name for info in infos} == {"cortex", "ollama"}
    assert all(info.status is ProviderStatus.OFFLINE for info in infos)
    await registry.aclose()


async def test_select_picks_the_first_usable_provider() -> None:
    settings = Settings(providers=(cortex_settings(), ollama_settings()))
    registry = ProviderRegistry(settings, client=mock_client(HEALTHY_CORTEX))
    selected = await registry.select()
    assert selected is not None
    provider, info = selected
    assert provider.name == "cortex"
    assert info.status is ProviderStatus.ONLINE
    await registry.aclose()


async def test_info_is_cached_briefly() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return HEALTHY_CORTEX(request)

    settings = Settings(providers=(cortex_settings(),))
    registry = ProviderRegistry(settings, client=mock_client(handler))
    await registry.info("cortex")
    first = len(calls)
    await registry.info("cortex")
    assert len(calls) == first, "a second call within max_age must not hit the network"
    registry.invalidate("cortex")
    await registry.info("cortex")
    assert len(calls) > first
    await registry.aclose()


# --------------------------------------------------------------------------
# Cortex
# --------------------------------------------------------------------------


async def test_cortex_reports_models_when_healthy() -> None:
    provider = CortexProvider(cortex_settings(), client=mock_client(HEALTHY_CORTEX))
    info = await provider.info()
    assert info.status is ProviderStatus.ONLINE
    assert info.models == ["qwen-local", "llama3.1"]
    assert info.default_model == "qwen-local"
    assert info.api_key_set is True
    assert info.latency_ms is not None
    assert info.as_dict()["status"] == "online"
    assert info.as_dict()["online"] is True


async def test_cortex_reports_a_bad_api_key_clearly() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            {"error": {"type": "invalid_api_key", "code": "invalid_api_key"}}, 401
        )

    provider = CortexProvider(cortex_settings(), client=mock_client(handler))
    info = await provider.info()
    assert info.status is ProviderStatus.ERROR
    assert "api_key" in info.detail.lower() or "api key" in info.detail.lower()
    assert "DISKFREE_CORTEX_API_KEY" in info.hint or "CORTEX_API_KEY" in info.hint


async def test_cortex_degraded_when_no_model_is_loaded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/ready":
            return json_response({"reason": "no_local_models_running"}, 503)
        return HEALTHY_CORTEX(request)

    provider = CortexProvider(cortex_settings(), client=mock_client(handler))
    info = await provider.info()
    assert info.status is ProviderStatus.DEGRADED
    assert "no local model" in info.detail.lower()
    assert "cortex dashboard" in info.hint.lower()
    assert info.models, "the model list is still known even when nothing is loaded"
    assert info.as_dict()["online"] is True, "degraded still counts as reachable"


async def test_cortex_offline_when_nothing_listens() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    provider = CortexProvider(cortex_settings(), client=mock_client(handler))
    info = await provider.info()
    assert info.status is ProviderStatus.OFFLINE
    assert "nothing listening" in info.detail
    assert "cortex_llmhoster" in info.hint


async def test_cortex_completion_returns_the_assistant_message() -> None:
    provider = CortexProvider(cortex_settings(), client=mock_client(HEALTHY_CORTEX))
    text = await provider.complete(system="sys", user="usr", temperature=0.0)
    assert text == "hello from cortex"


async def test_cortex_completion_sends_the_openai_shape() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/chat/completions":
            seen["body"] = json.loads(request.content)
            seen["auth"] = request.headers.get("Authorization")
            return json_response({"choices": [{"message": {"content": "ok"}}]})
        return HEALTHY_CORTEX(request)

    provider = CortexProvider(cortex_settings(), client=mock_client(handler))
    await provider.complete(system="S", user="U", schema={"type": "object"}, temperature=0.0)

    assert seen["auth"] == "Bearer test-key"
    body = seen["body"]
    assert body["messages"][0] == {"role": "system", "content": "S"}
    assert body["messages"][1] == {"role": "user", "content": "U"}
    assert body["stream"] is False
    assert body["response_format"] == {"type": "json_object"}
    assert body["temperature"] == 0.0


async def test_cortex_complete_json_parses_the_reply() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/chat/completions":
            return json_response(
                {"choices": [{"message": {"content": '```json\n{"headline": "hi"}\n```'}}]}
            )
        return HEALTHY_CORTEX(request)

    provider = CortexProvider(cortex_settings(), client=mock_client(handler))
    data = await provider.complete_json(system="s", user="u")
    assert data == {"headline": "hi"}


async def test_cortex_raises_a_helpful_error_on_a_server_fault() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/chat/completions":
            return json_response(
                {"error": {"type": "local_model_not_ready", "code": "local_model_not_ready"}}, 503
            )
        return HEALTHY_CORTEX(request)

    provider = CortexProvider(cortex_settings(), client=mock_client(handler))
    with pytest.raises(ProviderError) as error:
        await provider.complete(system="s", user="u")
    assert error.value.provider == "cortex"


async def test_cortex_raises_when_the_model_returns_nothing_usable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/chat/completions":
            return json_response({"choices": [{"message": {"content": "   "}}]})
        return HEALTHY_CORTEX(request)

    provider = CortexProvider(cortex_settings(), client=mock_client(handler))
    with pytest.raises(ProviderError):
        await provider.complete(system="s", user="u")


async def test_cortex_streams_server_sent_events() -> None:
    body = (
        b'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n'
        b'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n'
        b"data: [DONE]\n\n"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    provider = CortexProvider(cortex_settings(), client=mock_client(handler))
    chunks = [chunk async for chunk in provider.stream(
        [ChatMessage("user", "hi")], temperature=0.2
    )]
    assert "".join(chunks) == "Hello"


# --------------------------------------------------------------------------
# Ollama
# --------------------------------------------------------------------------


async def test_ollama_reports_version_and_models() -> None:
    provider = OllamaProvider(ollama_settings(), client=mock_client(HEALTHY_OLLAMA))
    info = await provider.info()
    assert info.status is ProviderStatus.ONLINE
    assert info.version == "0.5.7"
    assert info.models == ["llama3.2:latest"]
    assert info.running_models == ["llama3.2:latest"]
    assert info.default_model == "llama3.2:latest"
    assert "ollama serve" in info.hint


async def test_ollama_degraded_with_no_models_pulled() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return json_response({"models": []})
        if request.url.path == "/api/ps":
            return json_response({"models": []})
        return HEALTHY_OLLAMA(request)

    provider = OllamaProvider(ollama_settings(), client=mock_client(handler))
    info = await provider.info()
    assert info.status is ProviderStatus.DEGRADED
    assert "no models" in info.detail.lower()
    assert "ollama pull" in info.hint


async def test_ollama_offline_when_the_daemon_is_not_running() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    provider = OllamaProvider(ollama_settings(), client=mock_client(handler))
    info = await provider.info()
    assert info.status is ProviderStatus.OFFLINE
    assert info.as_dict()["online"] is False


async def test_ollama_completion_uses_structured_outputs() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat":
            seen["body"] = json.loads(request.content)
            return json_response({"message": {"content": '{"ok": true}'}, "done": True})
        return HEALTHY_OLLAMA(request)

    provider = OllamaProvider(ollama_settings(), client=mock_client(handler))
    text = await provider.complete(
        system="S", user="U", schema={"type": "object"}, temperature=0.0, num_ctx=4096
    )

    assert text == '{"ok": true}'
    body = seen["body"]
    assert body["stream"] is False
    # The schema is passed through so Ollama constrains decoding to it.
    assert body["format"] == {"type": "object"}
    assert body["options"]["temperature"] == 0.0
    assert body["options"]["num_ctx"] == 4096
    assert body["model"]


async def test_ollama_configured_model_wins_over_the_default() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat":
            seen["model"] = json.loads(request.content)["model"]
            return json_response({"message": {"content": "ok"}, "done": True})
        return HEALTHY_OLLAMA(request)

    provider = OllamaProvider(ollama_settings(model="qwen2.5:3b"),
                              client=mock_client(handler))
    await provider.complete(system="s", user="u")
    assert seen["model"] == "qwen2.5:3b"


async def test_ollama_missing_model_is_an_actionable_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat":
            return json_response({"error": "model not found"}, 404)
        return HEALTHY_OLLAMA(request)

    provider = OllamaProvider(ollama_settings(), client=mock_client(handler))
    with pytest.raises(ProviderError) as error:
        await provider.complete(system="s", user="u")
    assert "ollama pull" in (error.value.hint or "")


async def test_ollama_empty_completion_is_an_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat":
            return json_response({"message": {"content": ""}, "done": True})
        return HEALTHY_OLLAMA(request)

    provider = OllamaProvider(ollama_settings(), client=mock_client(handler))
    with pytest.raises(ProviderError):
        await provider.complete(system="s", user="u")


async def test_ollama_streams_newline_delimited_json() -> None:
    body = (
        b'{"message":{"content":"Hel"},"done":false}\n'
        b'{"message":{"content":"lo"},"done":false}\n'
        b'{"message":{"content":""},"done":true,"total_duration":123}\n'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=body, headers={"content-type": "application/x-ndjson"}
        )

    provider = OllamaProvider(ollama_settings(), client=mock_client(handler))
    chunks = [chunk async for chunk in provider.stream([ChatMessage("user", "hi")])]
    assert "".join(chunks) == "Hello"


def test_chat_message_serialises() -> None:
    message = ChatMessage("user", "hello")
    assert message.as_dict() == {"role": "user", "content": "hello"}


def test_provider_error_is_serialisable() -> None:
    error = ProviderError("boom", provider="cortex", hint="try again")
    assert error.as_dict() == {"error": "boom", "provider": "cortex", "hint": "try again"}


def test_every_provider_is_an_llmprovider() -> None:
    assert issubclass(CortexProvider, LLMProvider)
    assert issubclass(OllamaProvider, LLMProvider)
    assert CortexProvider.name != OllamaProvider.name

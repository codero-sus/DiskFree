"""Local LLM providers: Cortex LLMHoster and Ollama.

Both are local-first, so DiskFree never sends paths, file names or disk layouts
to a third party. Everything here talks to ``127.0.0.1`` unless the operator
deliberately points it elsewhere.

``cortex``
    `Cortex LLMHoster <https://github.com/codero-sus/Cortex_LLMHoster>`_ exposes
    an OpenAI-compatible surface: ``GET /health``, ``GET /ready``,
    ``GET /v1/models`` and ``POST /v1/chat/completions``, guarded by an optional
    ``CORTEX_API_KEY`` bearer token.
``ollama``
    Ollama's native API: ``GET /api/version``, ``GET /api/tags``, ``GET /api/ps``
    and ``POST /api/chat``, which supports constrained decoding through a JSON
    schema in ``format`` -- the most reliable way to get structured advice out of
    a small local model.
``heuristic``
    Not a model at all: the deterministic offline advisor, so the product stays
    fully usable with no LLM installed. Every AI feature degrades to it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

from ..config import PROVIDERS, ProviderSettings, Settings

logger = logging.getLogger("diskfree.ai")


class ProviderStatus(str, Enum):
    UNKNOWN = "unknown"
    ONLINE = "online"
    DEGRADED = "degraded"   # reachable but no model loaded/ready
    OFFLINE = "offline"     # nothing listening
    ERROR = "error"         # answered, but not usefully
    UNCONFIGURED = "unconfigured"


class ProviderError(RuntimeError):
    """Raised when a provider cannot produce a completion."""

    def __init__(self, message: str, *, provider: str = "", hint: str | None = None) -> None:
        super().__init__(message)
        self.provider = provider
        self.hint = hint

    def as_dict(self) -> dict[str, str]:
        return {"error": str(self), "provider": self.provider, "hint": self.hint or ""}


@dataclass(slots=True)
class ProviderInfo:
    """What the UI needs to render a provider picker."""

    name: str
    label: str
    base_url: str
    status: ProviderStatus = ProviderStatus.UNKNOWN
    models: list[str] = field(default_factory=list)
    running_models: list[str] = field(default_factory=list)
    default_model: str | None = None
    detail: str = ""
    hint: str = ""
    latency_ms: float | None = None
    api_key_set: bool = False
    enabled: bool = True
    version: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "base_url": self.base_url,
            "status": self.status.value,
            "online": self.status in {ProviderStatus.ONLINE, ProviderStatus.DEGRADED},
            "models": self.models,
            "running_models": self.running_models,
            "default_model": self.default_model,
            "detail": self.detail,
            "hint": self.hint,
            "latency_ms": round(self.latency_ms, 1) if self.latency_ms is not None else None,
            "api_key_set": self.api_key_set,
            "enabled": self.enabled,
            "version": self.version,
        }


@dataclass(slots=True)
class ChatMessage:
    role: str
    content: str

    def as_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


_FENCE_RE = re.compile(r"```(?:json|javascript)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def extract_json(text: str) -> Any:
    """Pull the first JSON value out of a model reply.

    Small local models wrap JSON in prose or code fences even when told not to,
    so this tries, in order: the raw string, fenced blocks, and the widest
    balanced ``{...}``/``[...]`` span. It raises :class:`ValueError` only when
    nothing parseable exists at all.
    """

    if not isinstance(text, str) or not text.strip():
        raise ValueError("empty model response")

    candidates: list[str] = [text.strip()]
    candidates.extend(match.group(1).strip() for match in _FENCE_RE.finditer(text))

    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start < 0:
            continue
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(text)):
            char = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == opener:
                depth += 1
            elif char == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : index + 1])
                    except json.JSONDecodeError:
                        break
    raise ValueError("no JSON object found in model response")


class LLMProvider(ABC):
    """Common surface for a local inference host."""

    name = "base"
    label = "Base"

    def __init__(self, settings: ProviderSettings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client
        self._owns_client = client is None

    # -- plumbing --------------------------------------------------------
    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.settings.timeout, connect=5.0),
                limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
                follow_redirects=False,
            )
            self._owns_client = True
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client and not self._client.is_closed:
            await self._client.aclose()

    def headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key}"
        return headers

    def url(self, path: str) -> str:
        return f"{self.settings.url}{path}"

    # -- API -------------------------------------------------------------
    @abstractmethod
    async def info(self) -> ProviderInfo:
        """Probe the host: reachability, models, latency."""

    @abstractmethod
    async def complete(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_tokens: int = 2048,
        num_ctx: int = 8192,
    ) -> str:
        """One non-streaming completion; returns the raw text."""

    async def complete_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 3000,
        num_ctx: int = 8192,
    ) -> Any:
        """Completion parsed as JSON, with retries for malformed output."""

        last_error: Exception | None = None
        text = ""
        for attempt in range(2):
            try:
                text = await self.complete(
                    system=system,
                    user=user,
                    schema=schema,
                    temperature=temperature if attempt == 0 else 0.0,
                    max_tokens=max_tokens,
                    num_ctx=num_ctx,
                )
                return extract_json(text)
            except (ValueError, ProviderError, httpx.HTTPError) as exc:
                last_error = exc
                logger.debug("provider %s JSON attempt %d failed: %s", self.name, attempt, exc)
        snippet = (text or str(last_error))[:400]
        raise ProviderError(
            f"{self.label} did not return usable JSON ({snippet})",
            provider=self.name,
            hint="Try a larger or more capable local model, or switch provider.",
        )

    async def stream(
        self, messages: list[ChatMessage], *, temperature: float = 0.3, num_ctx: int = 8192
    ) -> AsyncIterator[str]:
        """Token deltas for the chat panel. Providers may override for real streaming."""

        system = "\n".join(m.content for m in messages if m.role == "system")
        user = "\n".join(
            f"{m.role}: {m.content}" for m in messages if m.role != "system"
        ) or messages[-1].content
        text = await self.complete(
            system=system, user=user, temperature=temperature, num_ctx=num_ctx
        )
        yield text


_CORTEX_READY_REASONS = {
    "no_models_configured": (
        "Cortex is running but no models are configured",
        "Add a model in the Cortex dashboard (or its config file) and reload it.",
    ),
    "default_local_model_not_running": (
        "Cortex's default local model is not running",
        "Start the model from the Cortex dashboard, then retry.",
    ),
    "no_local_models_running": (
        "No local model is loaded in Cortex",
        "Start a local model from the Cortex dashboard, then retry.",
    ),
}


def _cortex_reason(reason: str) -> str:
    if reason in _CORTEX_READY_REASONS:
        return _CORTEX_READY_REASONS[reason][0]
    return reason or "Cortex reports not ready"


def _cortex_hint(reason: str) -> str:
    if reason in _CORTEX_READY_REASONS:
        return _CORTEX_READY_REASONS[reason][1]
    return "Start the model from the Cortex dashboard, then retry."


class CortexProvider(LLMProvider):
    """Cortex LLMHoster via its OpenAI-compatible routes."""

    name = "cortex"
    label = "Cortex LLMHoster"

    async def info(self) -> ProviderInfo:
        info = ProviderInfo(
            name=self.name,
            label=self.label,
            base_url=self.settings.url,
            api_key_set=bool(self.settings.api_key),
            enabled=self.settings.enabled,
            hint=(
                "Start it with `python -m cortex_llmhoster` (default port 8624) and "
                "export CORTEX_API_KEY if the host requires a bearer token."
            ),
        )
        started = time.perf_counter()
        try:
            health = await self.client.get(self.url("/health"), headers=self.headers())
        except httpx.ConnectError:
            info.status = ProviderStatus.OFFLINE
            info.detail = f"nothing listening at {self.settings.url}"
            return info
        except httpx.TimeoutException:
            info.status = ProviderStatus.ERROR
            info.detail = "timed out contacting Cortex"
            return info
        except httpx.HTTPError as exc:
            info.status = ProviderStatus.ERROR
            info.detail = f"{type(exc).__name__}: {exc}"
            return info

        info.latency_ms = (time.perf_counter() - started) * 1000
        if health.status_code == 401:
            info.status = ProviderStatus.ERROR
            info.detail = "Cortex rejected the request: missing or wrong CORTEX_API_KEY"
            info.hint = "Set DISKFREE_CORTEX_API_KEY (or CORTEX_API_KEY) to the same value."
            return info
        if health.status_code >= 400:
            info.status = ProviderStatus.ERROR
            info.detail = f"Cortex /health returned HTTP {health.status_code}"
            return info

        try:
            models_response = await self.client.get(
                self.url("/v1/models"), headers=self.headers()
            )
            if models_response.status_code < 400:
                payload = models_response.json()
                info.models = [
                    str(item.get("id"))
                    for item in payload.get("data", [])
                    if isinstance(item, dict) and item.get("id")
                ]
                info.default_model = self.settings.model or (
                    info.models[0] if info.models else None
                )
        except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
            info.detail = f"Cortex is up but /v1/models failed: {exc}"

        try:
            ready = await self.client.get(self.url("/ready"), headers=self.headers())
            # Cortex puts the useful part ("no_local_models_running") in the body
            # of the 503, so parse it whatever the status code is.
            try:
                ready_payload = ready.json()
            except ValueError:
                ready_payload = {}
            if not isinstance(ready_payload, dict):
                ready_payload = {}
            if ready.status_code < 400:
                info.status = ProviderStatus.ONLINE
                info.version = str(ready_payload.get("models") or "")
            else:
                info.status = ProviderStatus.DEGRADED
                reason = str(ready_payload.get("reason") or "").strip()
                info.detail = _cortex_reason(reason)
                info.hint = _cortex_hint(reason)
        except (httpx.HTTPError, ValueError, json.JSONDecodeError):
            info.status = ProviderStatus.ONLINE
        if not info.detail:
            info.detail = f"{len(info.models)} model(s) configured"
        return info

    async def complete(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_tokens: int = 2048,
        num_ctx: int = 8192,
    ) -> str:
        payload: dict[str, Any] = {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "stream": False,
            "max_tokens": max_tokens,
        }
        if self.settings.model:
            payload["model"] = self.settings.model
        if schema is not None:
            # llama.cpp accepts response_format json_object; a full schema is
            # passed through for backends that support grammar constraints.
            payload["response_format"] = {"type": "json_object"}
        try:
            response = await self.client.post(
                self.url("/v1/chat/completions"), json=payload, headers=self.headers()
            )
        except httpx.ConnectError as exc:
            raise ProviderError(
                f"cannot reach Cortex at {self.settings.url}",
                provider=self.name,
                hint="Is `python -m cortex_llmhoster` running?",
            ) from exc
        except httpx.TimeoutException as exc:
            raise ProviderError(
                "Cortex timed out; the model may still be loading",
                provider=self.name,
                hint="Open the Cortex dashboard and wait until the model is ready.",
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(f"Cortex request failed: {exc}", provider=self.name) from exc

        if response.status_code == 401:
            raise ProviderError(
                "Cortex rejected the API key",
                provider=self.name,
                hint="Set DISKFREE_CORTEX_API_KEY to the value Cortex was started with.",
            )
        if response.status_code == 422:
            raise ProviderError(
                f"Cortex cannot serve this request: {_message_of(response)}",
                provider=self.name,
                hint="The selected model may not declare the required capability.",
            )
        if response.status_code == 503:
            raise ProviderError(
                f"Cortex model is not running: {_message_of(response)}",
                provider=self.name,
                hint="Start the model from the Cortex dashboard.",
            )
        if response.status_code >= 400:
            raise ProviderError(
                f"Cortex returned HTTP {response.status_code}: {_message_of(response)}",
                provider=self.name,
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError("Cortex returned a non-JSON body", provider=self.name) from exc
        choices = data.get("choices") or []
        if not choices:
            raise ProviderError("Cortex returned no choices", provider=self.name)
        message = choices[0].get("message") or {}
        content = message.get("content")
        if isinstance(content, list):  # some backends return content parts
            content = "".join(
                part.get("text", "") for part in content if isinstance(part, dict)
            )
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("Cortex returned an empty completion", provider=self.name)
        return content

    async def stream(
        self, messages: list[ChatMessage], *, temperature: float = 0.3, num_ctx: int = 8192
    ) -> AsyncIterator[str]:
        payload: dict[str, Any] = {
            "messages": [message.as_dict() for message in messages],
            "temperature": temperature,
            "stream": True,
        }
        if self.settings.model:
            payload["model"] = self.settings.model
        try:
            async with self.client.stream(
                "POST", self.url("/v1/chat/completions"), json=payload, headers=self.headers()
            ) as response:
                if response.status_code >= 400:
                    body = await response.aread()
                    raise ProviderError(
                        f"Cortex stream failed ({response.status_code}): {body[:200]!r}",
                        provider=self.name,
                    )
                async for line in response.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    for choice in chunk.get("choices") or []:
                        delta = (choice.get("delta") or {}).get("content")
                        if delta:
                            yield delta
        except httpx.HTTPError as exc:
            raise ProviderError(f"Cortex stream error: {exc}", provider=self.name) from exc


class OllamaProvider(LLMProvider):
    """Ollama via its native API, using structured outputs for JSON."""

    name = "ollama"
    label = "Ollama"

    async def info(self) -> ProviderInfo:
        info = ProviderInfo(
            name=self.name,
            label=self.label,
            base_url=self.settings.url,
            api_key_set=bool(self.settings.api_key),
            enabled=self.settings.enabled,
            hint="Start it with `ollama serve` and pull a model, e.g. `ollama pull llama3.2`.",
        )
        started = time.perf_counter()
        try:
            version = await self.client.get(self.url("/api/version"), headers=self.headers())
        except httpx.ConnectError:
            info.status = ProviderStatus.OFFLINE
            info.detail = f"nothing listening at {self.settings.url}"
            return info
        except httpx.TimeoutException:
            info.status = ProviderStatus.ERROR
            info.detail = "timed out contacting Ollama"
            return info
        except httpx.HTTPError as exc:
            info.status = ProviderStatus.ERROR
            info.detail = f"{type(exc).__name__}: {exc}"
            return info

        info.latency_ms = (time.perf_counter() - started) * 1000
        if version.status_code >= 400:
            info.status = ProviderStatus.ERROR
            info.detail = f"Ollama /api/version returned HTTP {version.status_code}"
            return info
        try:
            info.version = str(version.json().get("version") or "")
        except ValueError:
            info.version = ""

        try:
            tags = await self.client.get(self.url("/api/tags"), headers=self.headers())
            if tags.status_code < 400:
                payload = tags.json()
                info.models = [
                    str(item.get("name") or item.get("model"))
                    for item in payload.get("models", [])
                    if isinstance(item, dict) and (item.get("name") or item.get("model"))
                ]
        except (httpx.HTTPError, ValueError) as exc:
            info.detail = f"Ollama is up but /api/tags failed: {exc}"

        try:
            running = await self.client.get(self.url("/api/ps"), headers=self.headers())
            if running.status_code < 400:
                info.running_models = [
                    str(item.get("name"))
                    for item in running.json().get("models", [])
                    if isinstance(item, dict) and item.get("name")
                ]
        except (httpx.HTTPError, ValueError):
            pass

        info.default_model = self.settings.model or (
            info.running_models[0] if info.running_models else None
        ) or (info.models[0] if info.models else None)

        if not info.models:
            info.status = ProviderStatus.DEGRADED
            info.detail = "Ollama is running but has no models pulled"
            info.hint = "Run `ollama pull llama3.2` (or any chat model) and retry."
        elif not info.running_models:
            info.status = ProviderStatus.ONLINE
            info.detail = f"{len(info.models)} model(s) available, none loaded yet"
        else:
            info.status = ProviderStatus.ONLINE
            info.detail = f"{len(info.models)} model(s), {len(info.running_models)} loaded"
        return info

    def _model(self) -> str:
        return self.settings.model or "llama3.2"

    async def complete(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_tokens: int = 2048,
        num_ctx: int = 8192,
    ) -> str:
        payload: dict[str, Any] = {
            "model": self._model(),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_ctx": num_ctx,
                "num_predict": max_tokens,
            },
        }
        if schema is not None:
            # Ollama constrains decoding to this schema, which is far more
            # reliable than hoping a 3B model emits valid JSON.
            payload["format"] = schema
        try:
            response = await self.client.post(
                self.url("/api/chat"), json=payload, headers=self.headers()
            )
        except httpx.ConnectError as exc:
            raise ProviderError(
                f"cannot reach Ollama at {self.settings.url}",
                provider=self.name,
                hint="Is `ollama serve` running?",
            ) from exc
        except httpx.TimeoutException as exc:
            raise ProviderError(
                "Ollama timed out; a cold model load can take a while",
                provider=self.name,
                hint="Try again, or raise DISKFREE_OLLAMA_TIMEOUT.",
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(f"Ollama request failed: {exc}", provider=self.name) from exc

        if response.status_code == 404:
            raise ProviderError(
                f"Ollama does not have the model '{self._model()}'",
                provider=self.name,
                hint=f"Run `ollama pull {self._model()}` or set DISKFREE_OLLAMA_MODEL.",
            )
        if response.status_code >= 400:
            raise ProviderError(
                f"Ollama returned HTTP {response.status_code}: {_message_of(response)}",
                provider=self.name,
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError("Ollama returned a non-JSON body", provider=self.name) from exc
        message = data.get("message") or {}
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ProviderError(
                "Ollama returned an empty completion",
                provider=self.name,
                hint="The model may have hit its context limit; reduce the scan size.",
            )
        return content

    async def stream(
        self, messages: list[ChatMessage], *, temperature: float = 0.3, num_ctx: int = 8192
    ) -> AsyncIterator[str]:
        payload = {
            "model": self._model(),
            "messages": [message.as_dict() for message in messages],
            "stream": True,
            "options": {"temperature": temperature, "num_ctx": num_ctx},
        }
        try:
            async with self.client.stream(
                "POST", self.url("/api/chat"), json=payload, headers=self.headers()
            ) as response:
                if response.status_code >= 400:
                    body = await response.aread()
                    raise ProviderError(
                        f"Ollama stream failed ({response.status_code}): {body[:200]!r}",
                        provider=self.name,
                    )
                async for line in response.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    delta = (chunk.get("message") or {}).get("content")
                    if delta:
                        yield delta
                    if chunk.get("done"):
                        break
        except httpx.HTTPError as exc:
            raise ProviderError(f"Ollama stream error: {exc}", provider=self.name) from exc


def _message_of(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return response.text[:200]
    if isinstance(data, dict):
        for key in ("error", "message", "detail"):
            value = data.get(key)
            if isinstance(value, dict):
                value = value.get("message")
            if isinstance(value, str) and value:
                return value[:300]
    return json.dumps(data)[:300]


class ProviderRegistry:
    """Owns provider instances and the 'auto' selection policy."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client
        self._providers: dict[str, LLMProvider] = {}
        self._info_cache: dict[str, tuple[float, ProviderInfo]] = {}
        self._lock = asyncio.Lock()
        for configured in settings.providers:
            self._providers[configured.name] = self._build(configured)

    def _build(self, configured: ProviderSettings) -> LLMProvider:
        if configured.name == "cortex":
            return CortexProvider(configured, self._client)
        if configured.name == "ollama":
            return OllamaProvider(configured, self._client)
        raise ValueError(f"unknown provider {configured.name!r}")

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._providers)

    def get(self, name: str) -> LLMProvider | None:
        return self._providers.get(name)

    def order(self, preferred: str | None = None) -> list[str]:
        """Provider order for 'auto': configured preference first, then the rest."""

        wanted = (preferred or self.settings.provider or "auto").lower()
        names = [name for name in self._providers if self._providers[name].settings.enabled]
        if wanted in PROVIDERS and wanted != "auto" and wanted in names:
            names.remove(wanted)
            names.insert(0, wanted)
        elif wanted == "auto":
            # Cortex is a purpose-built local hoster; prefer it when both are up.
            names.sort(key=lambda item: {"cortex": 0, "ollama": 1}.get(item, 2))
        return names

    async def info(self, name: str, *, max_age: float = 10.0) -> ProviderInfo:
        provider = self._providers.get(name)
        if provider is None:
            return ProviderInfo(
                name=name, label=name.title(), base_url="", status=ProviderStatus.UNCONFIGURED,
                detail="not configured",
            )
        cached = self._info_cache.get(name)
        now = time.monotonic()
        if cached and now - cached[0] < max_age:
            return cached[1]
        info = await provider.info()
        self._info_cache[name] = (now, info)
        return info

    async def all_info(self, *, max_age: float = 10.0) -> list[ProviderInfo]:
        infos = await asyncio.gather(
            *(self.info(name, max_age=max_age) for name in self.names)
        )
        return list(infos)

    async def select(self, preferred: str | None = None) -> tuple[LLMProvider, ProviderInfo] | None:
        """First provider that is actually usable, in preference order."""

        for name in self.order(preferred):
            info = await self.info(name)
            if info.status is ProviderStatus.ONLINE or (
                info.status is ProviderStatus.DEGRADED and info.models
            ):
                provider = self._providers.get(name)
                if provider is not None:
                    return provider, info
        return None

    def invalidate(self, name: str | None = None) -> None:
        if name is None:
            self._info_cache.clear()
        else:
            self._info_cache.pop(name, None)

    async def aclose(self) -> None:
        async with self._lock:
            for provider in self._providers.values():
                await provider.aclose()

"""The advisor: scan in, validated advice out, with a deterministic fallback.

The flow is always the same:

1. Build heuristic advice. This is not just a fallback -- it is the baseline the
   model output is measured against, and it guarantees the advisory findings and
   scan warnings are never lost because a model was terse.
2. If a local provider answers, ask it for structured JSON constrained by
   :data:`~diskfree.ai.prompts.ADVICE_SCHEMA`.
3. Run the reply through :mod:`diskfree.ai.guardrails`.
4. On any failure -- host down, no model pulled, timeout, malformed JSON,
   empty output -- return the heuristic advice with the error attached, so the
   user always gets a usable answer.
"""

from __future__ import annotations

import copy
import logging
import time
from collections.abc import AsyncIterator
from dataclasses import replace

import httpx

from ..config import Settings
from ..scanner.models import ScanResult
from .guardrails import ensure_manual_steps, validate_advice
from .heuristic import heuristic_advice
from .models import ENGINE_HEURISTIC, Advice, GuardrailEvent
from .prompts import (
    ADVICE_SCHEMA,
    CHAT_SYSTEM_PROMPT,
    PromptPayload,
    build_chat_context,
    build_payload,
)
from .providers import ChatMessage, LLMProvider, ProviderError, ProviderRegistry

logger = logging.getLogger("diskfree.ai")

#: Chat history is capped so a long conversation cannot crowd out the scan data.
MAX_CHAT_HISTORY = 12
MAX_CHAT_CONTEXT_CHARS = 18_000


class Advisor:
    """Turns scan results into advice using a local model, or without one."""

    def __init__(
        self,
        settings: Settings,
        registry: ProviderRegistry | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry or ProviderRegistry(settings)

    # -- advice ----------------------------------------------------------
    async def advise(
        self,
        result: ScanResult,
        *,
        provider: str | None = None,
        model: str | None = None,
        instructions: str | None = None,
        use_model: bool = True,
        max_findings: int | None = None,
    ) -> Advice:
        """Produce advice for one scan result."""

        findings = {finding.id: finding for finding in result.findings}
        baseline = heuristic_advice(result, job_id=result.job_id)
        baseline.manual_steps = ensure_manual_steps(
            baseline.items, findings, baseline.manual_steps
        )

        if not use_model:
            baseline.warnings = [
                "Model advice was skipped; this is DiskFree's deterministic rule engine.",
                *baseline.warnings,
            ]
            return baseline

        selected: tuple[LLMProvider, object] | None = None
        chosen_name = provider if provider and provider != "auto" else None
        if chosen_name:
            candidate = self.registry.get(chosen_name)
            if candidate is None:
                baseline.error = f"Unknown provider '{chosen_name}'."
                baseline.error_hint = f"Configured providers: {', '.join(self.registry.names)}."
                baseline.fallback_used = True
                return baseline
            selected = (candidate, await self.registry.info(chosen_name))
        else:
            selected = await self.registry.select(self.settings.provider)

        if selected is None:
            infos = await self.registry.all_info()
            detail = "; ".join(
                f"{info.label}: {info.detail or info.status.value}" for info in infos
            )
            baseline.error = "No local LLM host answered."
            baseline.error_hint = (
                f"{detail}. Start Cortex LLMHoster (`python -m cortex_llmhoster`) or Ollama "
                "(`ollama serve`) and retry -- DiskFree works fully offline meanwhile."
            )
            baseline.fallback_used = True
            baseline.guardrails.append(
                GuardrailEvent(
                    "provider_unavailable",
                    "Fell back to the offline rule engine because no local model host answered.",
                )
            )
            return baseline

        llm, info = selected
        if model:
            llm = _with_model(llm, model)
        used_model = model or getattr(info, "default_model", None)

        payload_kwargs = {"max_findings": max_findings} if max_findings else {}
        if instructions and instructions.strip():
            payload_kwargs["instructions"] = instructions.strip()
        prompt: PromptPayload = build_payload(result, **payload_kwargs)
        started = time.perf_counter()
        try:
            raw = await llm.complete_json(
                system=prompt.system,
                user=prompt.user,
                schema=ADVICE_SCHEMA,
                temperature=0.0,
                num_ctx=_context_for(prompt.est_tokens),
            )
        except ProviderError as exc:
            logger.info("provider %s failed: %s", llm.name, exc)
            baseline.error = str(exc)
            baseline.error_hint = exc.hint
            baseline.fallback_used = True
            baseline.guardrails.append(
                GuardrailEvent("provider_error", str(exc), detail=exc.hint or "")
            )
            return baseline
        except (TimeoutError, httpx.HTTPError) as exc:
            baseline.error = f"{type(exc).__name__}: {exc}"
            baseline.error_hint = "The model host did not answer in time; try a smaller model."
            baseline.fallback_used = True
            baseline.guardrails.append(
                GuardrailEvent("provider_error", baseline.error, detail=baseline.error_hint or "")
            )
            return baseline
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("unexpected advisor failure")
            baseline.error = f"{type(exc).__name__}: {exc}"
            baseline.fallback_used = True
            return baseline

        latency = (time.perf_counter() - started) * 1000
        cleaned, events = validate_advice(raw, findings)

        if not cleaned["items"]:
            events.append(
                GuardrailEvent(
                    "empty_advice",
                    "The model returned no usable recommendations; the offline rule engine "
                    "answered instead.",
                )
            )
            baseline.guardrails = events
            baseline.error = None
            baseline.fallback_used = True
            baseline.engine = ENGINE_HEURISTIC
            baseline.model = used_model
            baseline.latency_ms = latency
            baseline.payload_chars = prompt.chars
            baseline.est_tokens = prompt.est_tokens
            baseline.warnings = [
                "The model produced no usable advice, so the rule engine answered.",
                *baseline.warnings,
            ]
            return baseline

        advice = Advice(
            job_id=result.job_id,
            engine=llm.name,
            model=used_model,
            headline=cleaned["headline"] or baseline.headline,
            summary=cleaned["summary"] or baseline.summary,
            items=cleaned["items"],
            quick_wins=cleaned["quick_wins"] or baseline.quick_wins,
            manual_steps=ensure_manual_steps(
                cleaned["items"], findings, cleaned["manual_steps"]
            ),
            warnings=[*cleaned["warnings"], *result.warnings][:12],
            guardrails=events,
            created_at=time.time(),
            latency_ms=latency,
            payload_chars=prompt.chars,
            est_tokens=prompt.est_tokens,
        )
        return advice

    # -- chat ------------------------------------------------------------
    async def chat(
        self,
        result: ScanResult | None,
        messages: list[ChatMessage],
        *,
        provider: str | None = None,
        model: str | None = None,
    ) -> AsyncIterator[str]:
        """Stream a chat answer. Read-only by construction."""

        context = build_chat_context(result)
        if len(context) > MAX_CHAT_CONTEXT_CHARS:
            context = context[:MAX_CHAT_CONTEXT_CHARS] + "…"
        system = f"{CHAT_SYSTEM_PROMPT}\n\nCurrent scan context (JSON):\n{context}"
        history = [*messages][-MAX_CHAT_HISTORY:]

        selected = None
        chosen_name = provider if provider and provider != "auto" else None
        if chosen_name and self.registry.get(chosen_name):
            llm = self.registry.get(chosen_name)
            assert llm is not None
            selected = (llm, await self.registry.info(chosen_name))
        else:
            selected = await self.registry.select(self.settings.provider)

        if selected is None:
            yield (
                "No local model host answered, so I cannot chat right now.\n\n"
                "Start Cortex LLMHoster (`python -m cortex_llmhoster`, default port 8624) or "
                "Ollama (`ollama serve`, default port 11434), then try again. "
                "Everything else in DiskFree -- scanning, findings, cleaning and undo -- works "
                "without a model: see the AI Advisor panel for the offline rule-engine analysis."
            )
            return

        llm, info = selected
        if model:
            llm = _with_model(llm, model)
        used_model = model or getattr(info, "default_model", None)
        try:
            async for delta in llm.stream(
                [ChatMessage(role="system", content=system), *history],
                num_ctx=_context_for(len(system) // 4 + 1024),
            ):
                yield delta
        except ProviderError as exc:
            yield f"\n\n[The model could not answer: {exc}]"
            if exc.hint:
                yield f"\nHint: {exc.hint}"
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("chat failure")
            yield f"\n\n[Chat failed: {type(exc).__name__}: {exc}]"
        else:
            if used_model:
                label = getattr(llm, "label", llm.name)
                yield f"\n\n— {label} · {used_model} (read-only assistant)"

    async def aclose(self) -> None:
        await self.registry.aclose()


def _with_model(provider: LLMProvider, model: str) -> LLMProvider:
    """A shallow copy of ``provider`` pointed at a specific model.

    The HTTP connection pool is shared and ownership is not transferred, so the
    registry still closes it exactly once at shutdown.
    """

    clone = copy.copy(provider)
    clone.settings = replace(provider.settings, model=model)
    clone._client = provider.client
    clone._owns_client = False
    return clone


def _context_for(est_tokens: int) -> int:
    """Pick a context window that fits the payload with room to answer."""

    for size in (4096, 8192, 16384, 32768, 65536):
        if est_tokens + 1024 <= size:
            return size
    return 65536



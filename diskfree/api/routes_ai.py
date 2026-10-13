"""AI endpoints: provider discovery, advice, and the read-only chat assistant."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from ..ai.models import ENGINE_HEURISTIC
from ..ai.providers import ChatMessage, ProviderError, ProviderRegistry, ProviderStatus
from ..config import ProviderSettings
from ..scanner.jobs import ScanStatus
from .deps import AppState, get_state
from .schemas import AdviseRequest, ChatRequest, ProviderCheckRequest

logger = logging.getLogger("diskfree.api")
router = APIRouter(prefix="/api", tags=["ai"])


@router.get("/providers")
async def list_providers(state: AppState = Depends(get_state)) -> dict[str, object]:
    """Every configured local model host, its status and its models."""

    registry: ProviderRegistry = state.registry
    infos = await registry.all_info(max_age=5.0)
    return {
        "preferred": state.settings.provider,
        "providers": [info.as_dict() for info in infos],
        "offline_engine": {
            "name": ENGINE_HEURISTIC,
            "label": "Rule engine (offline)",
            "status": ProviderStatus.ONLINE.value,
            "online": True,
            "detail": "Always available. Deterministic advice from the cleaning rules.",
            "models": [],
            "default_model": None,
        },
        "note": (
            "Advice never leaves this machine: both providers are local hosts. "
            "DiskFree sends metadata only -- paths, sizes, ages -- never file contents."
        ),
    }


@router.post("/providers/{name}/check")
async def check_provider(
    name: str,
    request: ProviderCheckRequest | None = None,
    state: AppState = Depends(get_state),
) -> dict[str, object]:
    """Re-probe a provider, optionally with one-off connection overrides."""

    if name not in state.registry.names:
        raise HTTPException(
            status_code=404,
            detail={"error": f"Unknown provider '{name}'.", "known": list(state.registry.names)},
        )
    state.registry.invalidate(name)

    provider = state.registry.get(name)
    if provider is None:  # pragma: no cover - guarded above
        raise HTTPException(status_code=404, detail={"error": f"Unknown provider '{name}'."})

    if request and (request.base_url or request.model or request.api_key):
        current = provider.settings
        override = ProviderSettings(
            name=current.name,
            base_url=request.base_url or current.base_url,
            api_key=request.api_key if request.api_key is not None else current.api_key,
            model=request.model or current.model,
            timeout=current.timeout,
            enabled=True,
        )
        probe = type(provider)(override, provider.client)
        info = await probe.info()
        return {
            "provider": info.as_dict(),
            "transient": True,
            "message": (
                "Probed with your overrides only; nothing was saved. "
                "Set DISKFREE_* environment variables to make them permanent."
            ),
        }

    info = await state.registry.info(name, max_age=0.0)
    return {"provider": info.as_dict(), "transient": False}


@router.post("/advise")
async def advise(request: AdviseRequest, state: AppState = Depends(get_state)) -> dict[str, object]:
    """Analyse a scan with a local model, or with the offline rule engine."""

    job = state.jobs.resolve(request.job_id)
    if job is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "No scan available.", "hint": "Run a scan first."},
        )
    if job.result is None or job.status is ScanStatus.RUNNING:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "That scan is still running.",
                "hint": "Wait for it to finish, or cancel it and advise on what it found.",
                "progress": job.progress.as_dict(),
            },
        )
    assert job.result is not None

    instructions = request.instructions.strip() if request.instructions else None
    if instructions and (not request.use_model or request.provider == ENGINE_HEURISTIC):
        raise HTTPException(
            status_code=409,
            detail={
                "error": "Custom cleanup instructions need a local language model.",
                "hint": (
                    "Select Auto, Cortex or Ollama. The offline rule engine cannot "
                    "interpret chat instructions."
                ),
            },
        )

    use_model = request.use_model and request.provider != ENGINE_HEURISTIC
    advice = await state.advisor.advise(
        job.result,
        provider=None if request.provider == "auto" else request.provider,
        model=request.model,
        instructions=instructions,
        use_model=use_model,
        max_findings=request.max_findings,
    )
    payload = advice.as_dict()
    payload["job_id"] = job.id
    payload["custom_instructions_requested"] = bool(instructions)
    payload["custom_instructions_processed"] = bool(
        instructions and advice.engine != ENGINE_HEURISTIC and not advice.fallback_used
    )
    state.jobs.set_advice(job.id, payload)
    return payload


@router.get("/scans/{job_id}/advice")
async def get_advice(job_id: str, state: AppState = Depends(get_state)) -> dict[str, object]:
    job = state.jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"error": f"Unknown scan '{job_id}'."})
    if job.advice is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "No advice has been generated for this scan yet.",
                "hint": "POST /api/advise with the job id.",
            },
        )
    return job.advice


def _sse(event: str, data: dict[str, object]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


@router.post("/chat")
async def chat(request: ChatRequest, state: AppState = Depends(get_state)):
    """Ask the read-only assistant about the current scan.

    Streams server-sent events by default. The assistant has no tools: it can
    explain and suggest, but only the Clean flow can move data, and that always
    needs an explicit, itemised, token-confirmed request.
    """

    job = state.jobs.resolve(request.job_id)
    result = job.result if job is not None else None

    history = [
        ChatMessage(role=item.role, content=item.content) for item in request.history
    ]
    history.append(ChatMessage(role="user", content=request.message))

    if request.provider == ENGINE_HEURISTIC:
        answer = (
            "The offline rule engine does not chat, but it has already analysed this scan. "
            "Open the AI Advisor panel to see its itemised recommendations, quick wins and the "
            "maintenance commands for subsystems DiskFree will not touch. To chat, point DiskFree "
            "at Cortex LLMHoster or Ollama in Settings."
        )
        if not request.stream:
            return {
                "reply": answer,
                "engine": ENGINE_HEURISTIC,
                "model": None,
                "job_id": job.id if job else None,
                "readonly": True,
            }

        async def offline_stream() -> AsyncIterator[str]:
            yield _sse("meta", {"engine": ENGINE_HEURISTIC, "model": None, "readonly": True})
            yield _sse("delta", {"text": answer})
            yield _sse("done", {"engine": ENGINE_HEURISTIC})

        return StreamingResponse(
            offline_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    provider_name = None if request.provider == "auto" else request.provider

    if not request.stream:
        chunks: list[str] = []
        try:
            async for delta in state.advisor.chat(
                result, history, provider=provider_name, model=request.model
            ):
                chunks.append(delta)
        except ProviderError as exc:
            raise HTTPException(status_code=502, detail=exc.as_dict()) from exc
        return {
            "reply": "".join(chunks),
            "engine": provider_name or state.settings.provider,
            "model": request.model,
            "job_id": job.id if job else None,
            "readonly": True,
        }

    async def stream() -> AsyncIterator[str]:
        yield _sse(
            "meta",
            {
                "engine": provider_name or state.settings.provider,
                "model": request.model,
                "job_id": job.id if job else None,
                "readonly": True,
            },
        )
        try:
            async for delta in state.advisor.chat(
                result, history, provider=provider_name, model=request.model
            ):
                yield _sse("delta", {"text": delta})
        except Exception as exc:  # pragma: no cover - stream error path
            logger.exception("chat stream failed")
            yield _sse("error", {"error": f"{type(exc).__name__}: {exc}"})
        yield _sse("done", {"engine": provider_name or state.settings.provider})

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

"""The advisor: a local model when there is one, the rule engine when there is not.

DiskFree must be fully useful with no LLM reachable at all, and must never let a
model widen what it is willing to delete. Both halves are tested here against a
mocked Cortex so no network is involved.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from diskfree.ai.advisor import Advisor
from diskfree.ai.heuristic import heuristic_advice
from diskfree.ai.models import Action, Advice
from diskfree.ai.prompts import (
    MAX_PAYLOAD_CHARS,
    abbreviate,
    build_chat_context,
    build_payload,
)
from diskfree.ai.providers import ChatMessage, ProviderRegistry
from diskfree.config import ProviderSettings, Settings
from diskfree.safety.policy import Risk
from diskfree.scanner.models import ScanResult

Handler = Callable[[httpx.Request], httpx.Response]


def advisor_with(handler: Handler, settings: Settings) -> Advisor:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)
    return Advisor(settings, ProviderRegistry(settings, client=client))


def cortex_settings(**overrides: Any) -> ProviderSettings:
    base: dict[str, Any] = {
        "name": "cortex", "base_url": "http://127.0.0.1:8624", "api_key": "k",
        "timeout": 5.0, "enabled": True,
    }
    base.update(overrides)
    return ProviderSettings(**base)


def reply(content: Any) -> Handler:
    """A Cortex handler whose chat completion returns ``content``."""

    body = content if isinstance(content, str) else json.dumps(content)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/chat/completions":
            return httpx.Response(200, json={"choices": [{"message": {"content": body}}]})
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/ready":
            return httpx.Response(200, json={"status": "ready", "models": 1})
        if request.url.path == "/v1/models":
            return httpx.Response(
                200, json={"data": [{"id": "qwen-local", "object": "model"}]}
            )
        return httpx.Response(404, json={"error": "unexpected"})

    return handler


def model_advice(result: ScanResult, **overrides: Any) -> dict[str, Any]:
    """A well-formed model reply covering every actionable finding."""

    recommendations = [
        {
            "id": finding.id,
            "action": "clean" if finding.risk is Risk.SAFE else "review",
            "risk": finding.risk.value if finding.risk is not Risk.FORBIDDEN else "high",
            "confidence": 0.9,
            "reason": f"{finding.title} is regenerable.",
        }
        for finding in result.findings
        if finding.actionable
    ][:20]
    payload: dict[str, Any] = {
        "headline": "Clear the caches to reclaim space.",
        "summary": "Most of what was found is regenerable cache data.",
        "recommendations": recommendations,
        "quick_wins": ["Empty the pip cache."],
        "manual_steps": [],
        "warnings": [],
    }
    payload.update(overrides)
    return payload


# --------------------------------------------------------------------------
# the offline rule engine
# --------------------------------------------------------------------------


def test_heuristic_advice_is_complete_without_any_model(scan_result: ScanResult) -> None:
    advice = heuristic_advice(scan_result, job_id="job-1")

    assert advice.engine == "heuristic"
    assert advice.model is None
    assert advice.headline.strip()
    assert advice.summary.strip()
    assert advice.items, "every scan should yield at least one recommendation"
    assert advice.job_id == "job-1"
    known = {finding.id for finding in scan_result.findings}
    assert all(item.finding_id in known for item in advice.items)


def test_heuristic_advice_respects_the_risk_floor(scan_result: ScanResult) -> None:
    advice = heuristic_advice(scan_result)
    by_id = {finding.id: finding for finding in scan_result.findings}
    for item in advice.items:
        finding = by_id[item.finding_id]
        assert item.risk.rank >= finding.risk.rank, item.finding_id
        if item.action is Action.CLEAN:
            assert finding.actionable, "only actionable items may be proposed for cleaning"
            assert item.risk.rank <= Risk.LOW.rank, (
                f"{finding.rule_id}: cleaning anything above LOW needs a human"
            )
        if not finding.actionable:
            assert item.action in {Action.KEEP, Action.MANUAL, Action.REVIEW}


def test_heuristic_advice_reports_every_advisory(scan_result: ScanResult) -> None:
    advisories = [finding for finding in scan_result.findings if finding.advisory]
    if not advisories:
        pytest.skip("no advisory findings on this host")
    advice = heuristic_advice(scan_result)
    joined = "\n".join(advice.manual_steps).lower()
    for finding in advisories:
        assert finding.advisory.lower() in joined, finding.rule_id


def test_heuristic_advice_is_deterministic(scan_result: ScanResult) -> None:
    first = heuristic_advice(scan_result)
    second = heuristic_advice(scan_result)
    assert first.headline == second.headline
    assert [item.finding_id for item in first.items] == [item.finding_id for item in second.items]
    assert [(item.action, item.risk) for item in first.items] == [
        (item.action, item.risk) for item in second.items
    ]


def test_heuristic_advice_handles_an_empty_scan(scan_result: ScanResult) -> None:
    empty = ScanResult(job_id="empty", roots=scan_result.roots)
    advice = heuristic_advice(empty)
    assert advice.items == []
    assert advice.headline, "an empty scan still deserves a sentence"


def test_advice_serialises_for_the_api(scan_result: ScanResult) -> None:
    advice = heuristic_advice(scan_result)
    payload = advice.as_dict() if hasattr(advice, "as_dict") else None
    if payload is None:
        pytest.skip("Advice exposes no as_dict")
    assert payload["engine"] == "heuristic"
    assert isinstance(payload["items"], list)


# --------------------------------------------------------------------------
# the prompt payload
# --------------------------------------------------------------------------


def test_abbreviate_keeps_the_home_directory_out_of_prompts(fake_home) -> None:
    assert abbreviate(str(fake_home.root), fake_home.root) == "~"
    assert abbreviate(str(fake_home["pip_cache"]), fake_home.root) == "~/.cache/pip"
    assert abbreviate("/etc/passwd", fake_home.root) == "/etc/passwd"


def test_payload_hides_the_real_home_directory(scan_result: ScanResult, fake_home) -> None:
    payload = build_payload(scan_result, home=fake_home.root)
    assert str(fake_home.root) not in payload.user, "the prompt must not leak the home path"
    assert str(fake_home.root) not in payload.system
    assert "~" in payload.user
    assert payload.user.count("~") > 0


def test_payload_is_bounded(scan_result: ScanResult, fake_home) -> None:
    payload = build_payload(scan_result, home=fake_home.root)
    assert len(payload.user) <= MAX_PAYLOAD_CHARS
    assert payload.chars <= MAX_PAYLOAD_CHARS
    assert payload.finding_ids
    assert len(payload.finding_ids) <= len(scan_result.findings)
    assert payload.est_tokens > 0
    known = {finding.id for finding in scan_result.findings}
    assert set(payload.finding_ids) <= known


def test_payload_never_includes_file_contents(scan_result: ScanResult, fake_home) -> None:
    payload = build_payload(scan_result, home=fake_home.root)
    body = fake_home["documents"].read_bytes()[:32]
    assert body.decode("latin-1") not in payload.user
    assert "BEGIN" not in payload.user or "PRIVATE KEY" not in payload.user


def test_payload_lists_the_findings_the_model_may_reference(
    scan_result: ScanResult, fake_home
) -> None:
    payload = build_payload(scan_result, home=fake_home.root)
    # Every id the model may quote must exist in the scan, and appear in the prompt.
    assert set(payload.finding_ids) <= {finding.id for finding in scan_result.findings}
    for finding_id in payload.finding_ids:
        assert finding_id in payload.user, finding_id
    findings_in_payload = payload.data.get("findings") or []
    assert {item["id"] for item in findings_in_payload} == set(payload.finding_ids)


def test_chat_context_is_compact_and_private(scan_result: ScanResult, fake_home) -> None:
    context = build_chat_context(scan_result, home=fake_home.root)
    assert str(fake_home.root) not in context
    assert len(context) < len(build_payload(scan_result, home=fake_home.root).user)
    assert build_chat_context(None) == "No scan has been run yet."


# --------------------------------------------------------------------------
# the advisor with a model
# --------------------------------------------------------------------------


async def test_advisor_uses_the_model_when_one_answers(
    settings: Settings, scan_result: ScanResult, fake_home
) -> None:
    settings = Settings(
        host=settings.host, port=settings.port, data_dir=settings.data_dir,
        safety=settings.safety, scan=settings.scan, providers=(cortex_settings(),),
    )
    advisor = advisor_with(reply(model_advice(scan_result)), settings)
    advice = await advisor.advise(scan_result)

    assert advice.fallback_used is False
    assert advice.error is None
    assert advice.engine == "cortex"
    assert advice.model == "qwen-local"
    assert advice.headline.strip()
    assert advice.items
    assert advice.latency_ms is not None and advice.latency_ms >= 0
    await advisor.aclose()


async def test_advisor_falls_back_when_no_host_answers(
    settings: Settings, scan_result: ScanResult
) -> None:
    offline = Settings(
        data_dir=settings.data_dir, safety=settings.safety, scan=settings.scan,
        providers=(
            cortex_settings(base_url="http://127.0.0.1:9"),
            ProviderSettings(name="ollama", base_url="http://127.0.0.1:9", timeout=1.0),
        ),
    )

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    advisor = advisor_with(refuse, offline)
    advice = await advisor.advise(scan_result)

    assert advice.fallback_used is True
    assert advice.engine == "heuristic"
    assert advice.error, "the user must be told why there is no model advice"
    assert "cortex" in advice.error_hint.lower()
    assert "ollama" in advice.error_hint.lower()
    assert advice.items, "the offline analysis must still be complete"
    assert any(event.kind == "provider_unavailable" for event in advice.guardrails)
    await advisor.aclose()


async def test_advisor_falls_back_on_a_malformed_reply(
    settings: Settings, scan_result: ScanResult
) -> None:
    configured = Settings(
        data_dir=settings.data_dir, safety=settings.safety, scan=settings.scan,
        providers=(cortex_settings(),),
    )
    advisor = advisor_with(reply("I am a model and I refuse to emit JSON."), configured)
    advice = await advisor.advise(scan_result)

    assert advice.fallback_used is True
    assert advice.engine == "heuristic"
    assert advice.error
    assert advice.items, "a broken model must not leave the user with nothing"
    await advisor.aclose()


async def test_advisor_falls_back_on_a_server_error(
    settings: Settings, scan_result: ScanResult
) -> None:
    configured = Settings(
        data_dir=settings.data_dir, safety=settings.safety, scan=settings.scan,
        providers=(cortex_settings(),),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/chat/completions":
            return httpx.Response(500, json={"error": {"message": "boom"}})
        return reply({})(request)

    advisor = advisor_with(handler, configured)
    advice = await advisor.advise(scan_result)
    assert advice.fallback_used is True
    assert advice.error
    assert advice.items
    await advisor.aclose()


async def test_the_model_cannot_widen_what_diskfree_will_delete(
    settings: Settings, scan_result: ScanResult
) -> None:
    """A hostile reply: lowered risks, invented ids, and a destructive command."""

    hostile = {
        "headline": "Delete everything, it is all safe.",
        "summary": "rm -rf / will free the most space.",
        "recommendations": [
            {"id": "does-not-exist", "action": "clean", "risk": "safe", "confidence": 1.0,
             "reason": "trust me"},
            *[
                {"id": finding.id, "action": "clean", "risk": "safe", "confidence": 1.0,
                 "reason": "Definitely safe. Run rm -rf / afterwards."}
                for finding in scan_result.findings
            ],
        ],
        "quick_wins": ["sudo rm -rf --no-preserve-root /"],
        "manual_steps": ["mkfs.ext4 /dev/sda1"],
        "warnings": ["Nothing here is personal."],
    }
    configured = Settings(
        data_dir=settings.data_dir, safety=settings.safety, scan=settings.scan,
        providers=(cortex_settings(),),
    )
    advisor = advisor_with(reply(hostile), configured)
    advice = await advisor.advise(scan_result)

    by_id = {finding.id: finding for finding in scan_result.findings}
    assert all(item.finding_id in by_id for item in advice.items), "invented ids must vanish"
    for item in advice.items:
        finding = by_id[item.finding_id]
        assert item.risk.rank >= finding.risk.rank, "the floor holds"
        if item.action is Action.CLEAN:
            assert finding.actionable
            assert item.risk.rank <= Risk.LOW.rank
    # What the UI renders as advice must be free of destructive commands.
    rendered = json.dumps({
        "headline": advice.headline,
        "summary": advice.summary,
        "reasons": [item.reason for item in advice.items],
        "quick_wins": advice.quick_wins,
        "manual_steps": advice.manual_steps,
        "warnings": advice.warnings,
    }).lower()
    assert "rm -rf /" not in rendered
    assert "rm -rf ~" not in rendered
    assert "mkfs" not in rendered
    assert "no-preserve-root" not in rendered

    # The guardrail log deliberately quotes what was removed -- that is the
    # transparency feature, and the UI renders it as inert escaped text.
    assert advice.guardrails, "every overruling must be visible to the user"
    blocked = [event for event in advice.guardrails if event.kind == "dangerous_command"]
    assert blocked
    assert any("rm -rf /" in event.detail for event in blocked)
    await advisor.aclose()


async def test_advisor_can_skip_the_model_on_purpose(
    settings: Settings, scan_result: ScanResult
) -> None:
    advisor = Advisor(settings, ProviderRegistry(settings))
    advice = await advisor.advise(scan_result, use_model=False)
    assert advice.engine == "heuristic"
    assert advice.fallback_used is False
    assert any("skipped" in warning.lower() for warning in advice.warnings)
    assert advice.items
    await advisor.aclose()


async def test_advisor_reports_an_unknown_provider_name(
    settings: Settings, scan_result: ScanResult
) -> None:
    advisor = Advisor(settings, ProviderRegistry(settings))
    advice = await advisor.advise(scan_result, provider="gpt-5-cloud")
    assert advice.fallback_used is True
    assert "gpt-5-cloud" in (advice.error or "")
    assert advice.items
    await advisor.aclose()


async def test_advisor_honours_an_explicit_provider_choice(
    settings: Settings, scan_result: ScanResult
) -> None:
    configured = Settings(
        data_dir=settings.data_dir, safety=settings.safety, scan=settings.scan,
        providers=(cortex_settings(),),
    )
    advisor = advisor_with(reply(model_advice(scan_result)), configured)
    advice = await advisor.advise(scan_result, provider="cortex")
    assert advice.engine == "cortex"
    await advisor.aclose()


async def test_a_model_can_raise_risk_and_it_is_recorded(
    settings: Settings, scan_result: ScanResult
) -> None:
    safe = next(f for f in scan_result.findings if f.risk is Risk.SAFE and f.actionable)
    payload = {
        "headline": "Be careful.",
        "summary": "One item deserves a second look.",
        "recommendations": [
            {"id": safe.id, "action": "review", "risk": "high", "confidence": 0.5,
             "reason": "This cache is used by a running service."}
        ],
    }
    configured = Settings(
        data_dir=settings.data_dir, safety=settings.safety, scan=settings.scan,
        providers=(cortex_settings(),),
    )
    advisor = advisor_with(reply(payload), configured)
    advice = await advisor.advise(scan_result)

    item = next(item for item in advice.items if item.finding_id == safe.id)
    assert item.risk is Risk.HIGH, "a model may make DiskFree more cautious"
    assert item.action is Action.REVIEW
    assert item.escalated is True
    assert any(event.kind == "risk_clamped" for event in advice.guardrails)
    await advisor.aclose()


# --------------------------------------------------------------------------
# chat
# --------------------------------------------------------------------------


async def test_chat_streams_the_model_reply(settings: Settings, scan_result: ScanResult) -> None:
    body = b'data: {"choices":[{"delta":{"content":"Your biggest "}}]}\n\n' \
           b'data: {"choices":[{"delta":{"content":"win is the pip cache."}}]}\n\n' \
           b"data: [DONE]\n\n"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/chat/completions":
            return httpx.Response(
                200, content=body, headers={"content-type": "text/event-stream"}
            )
        return reply({})(request)

    configured = Settings(
        data_dir=settings.data_dir, safety=settings.safety, scan=settings.scan,
        providers=(cortex_settings(),),
    )
    advisor = advisor_with(handler, configured)
    chunks = [
        chunk async for chunk in advisor.chat(
            scan_result, [ChatMessage("user", "what should I clean?")]
        )
    ]
    text = "".join(chunks)
    assert "Your biggest win is the pip cache." in text
    assert "read-only assistant" in text
    await advisor.aclose()


async def test_chat_explains_itself_when_no_model_is_available(
    settings: Settings, scan_result: ScanResult
) -> None:
    offline = Settings(
        data_dir=settings.data_dir, safety=settings.safety, scan=settings.scan,
        providers=(cortex_settings(base_url="http://127.0.0.1:9"),),
    )

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    advisor = advisor_with(refuse, offline)
    text = "".join(
        [chunk async for chunk in advisor.chat(scan_result, [ChatMessage("user", "hi")])]
    )
    assert "cortex" in text.lower() or "ollama" in text.lower()
    assert "works" in text.lower(), "the message must say the rest of DiskFree still works"
    await advisor.aclose()


async def test_chat_reports_a_model_failure_inline(
    settings: Settings, scan_result: ScanResult
) -> None:
    from diskfree.ai.providers import ProviderError

    configured = Settings(
        data_dir=settings.data_dir, safety=settings.safety, scan=settings.scan,
        providers=(cortex_settings(),),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/chat/completions":
            return httpx.Response(503, json={"error": {"message": "model not ready"}})
        return reply({})(request)

    advisor = advisor_with(handler, configured)
    text = "".join(
        [chunk async for chunk in advisor.chat(scan_result, [ChatMessage("user", "hi")])]
    )
    assert "could not answer" in text.lower() or "failed" in text.lower()
    assert ProviderError is not None
    await advisor.aclose()


async def test_chat_without_a_scan_still_answers(settings: Settings) -> None:
    offline = Settings(
        data_dir=settings.data_dir, safety=settings.safety, scan=settings.scan,
        providers=(cortex_settings(base_url="http://127.0.0.1:9"),),
    )

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    advisor = advisor_with(refuse, offline)
    text = "".join([chunk async for chunk in advisor.chat(None, [ChatMessage("user", "hi")])])
    assert text.strip()
    await advisor.aclose()


def test_advice_dataclass_defaults() -> None:
    advice = Advice(job_id="x")
    assert advice.engine == "heuristic"
    assert advice.items == []
    assert advice.fallback_used is False

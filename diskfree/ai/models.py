"""Shared shapes for AI advice, whether it came from a model or the heuristics."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..safety.policy import Risk


class Action(str, Enum):
    """What the advisor says to do with one finding."""

    CLEAN = "clean"      # recommend removal (reversible: trash + journal)
    REVIEW = "review"    # worth a look; the user decides per item
    KEEP = "keep"        # leave it alone
    MANUAL = "manual"    # another program owns it; run the supplied command

    @property
    def selectable(self) -> bool:
        return self in {Action.CLEAN, Action.REVIEW}


ENGINE_HEURISTIC = "heuristic"


@dataclass(slots=True)
class AdviceItem:
    """One validated recommendation tied to a real finding."""

    finding_id: str
    action: Action
    risk: Risk
    confidence: float
    reason: str
    title: str = ""
    path: str = ""
    bytes: int = 0
    category: str = ""
    rule_id: str = ""
    original_risk: Risk = Risk.SAFE
    escalated: bool = False
    action_downgraded: bool = False
    command: str | None = None
    note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "action": self.action.value,
            "risk": self.risk.value,
            "risk_original": self.original_risk.value,
            "confidence": round(self.confidence, 3),
            "reason": self.reason,
            "title": self.title,
            "path": self.path,
            "bytes": self.bytes,
            "category": self.category,
            "rule_id": self.rule_id,
            "escalated": self.escalated,
            "action_downgraded": self.action_downgraded,
            "command": self.command,
            "note": self.note,
        }


@dataclass(slots=True)
class GuardrailEvent:
    """A place where model output was corrected, dropped or refused."""

    kind: str
    message: str
    finding_id: str | None = None
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "message": self.message,
            "finding_id": self.finding_id,
            "detail": self.detail,
        }


@dataclass(slots=True)
class Advice:
    """The full advisory result for one scan."""

    job_id: str
    engine: str = ENGINE_HEURISTIC
    model: str | None = None
    headline: str = ""
    summary: str = ""
    items: list[AdviceItem] = field(default_factory=list)
    quick_wins: list[str] = field(default_factory=list)
    manual_steps: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    guardrails: list[GuardrailEvent] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    latency_ms: float | None = None
    payload_chars: int = 0
    est_tokens: int = 0
    error: str | None = None
    error_hint: str | None = None
    fallback_used: bool = False

    # -- derived views ---------------------------------------------------
    @property
    def ok(self) -> bool:
        return self.error is None

    def by_id(self) -> dict[str, AdviceItem]:
        return {item.finding_id: item for item in self.items}

    def clean_ids(self, *, max_risk: Risk = Risk.LOW) -> list[str]:
        """Findings the advisor wants removed, limited to low risk and below.

        The UI uses this for "apply AI selection". Medium and high risk items are
        never pre-ticked, whatever the model said.
        """

        return [
            item.finding_id
            for item in sorted(self.items, key=lambda candidate: -candidate.bytes)
            if item.action is Action.CLEAN and item.risk.rank <= max_risk.rank
        ]

    def totals(self) -> dict[str, Any]:
        buckets: dict[str, dict[str, int]] = {}
        for item in self.items:
            bucket = buckets.setdefault(
                item.action.value, {"items": 0, "bytes": 0}
            )
            bucket["items"] += 1
            bucket["bytes"] += item.bytes
        return buckets

    def as_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "engine": self.engine,
            "model": self.model,
            "ok": self.ok,
            "headline": self.headline,
            "summary": self.summary,
            "items": [item.as_dict() for item in self.items],
            "quick_wins": self.quick_wins,
            "manual_steps": self.manual_steps,
            "warnings": self.warnings,
            "guardrails": [event.as_dict() for event in self.guardrails],
            "guardrail_count": len(self.guardrails),
            "created_at": self.created_at,
            "latency_ms": round(self.latency_ms, 1) if self.latency_ms is not None else None,
            "payload_chars": self.payload_chars,
            "est_tokens": self.est_tokens,
            "totals": self.totals(),
            "clean_ids": self.clean_ids(),
            "error": self.error,
            "error_hint": self.error_hint,
            "fallback_used": self.fallback_used,
        }

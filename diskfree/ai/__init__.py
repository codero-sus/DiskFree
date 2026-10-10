"""AI advisory layer: local providers, prompts, guardrails and heuristics."""

from __future__ import annotations

from .advisor import Advisor
from .guardrails import is_dangerous_command, sanitize_text, validate_advice
from .heuristic import heuristic_advice
from .models import Action, Advice, AdviceItem, GuardrailEvent
from .providers import (
    ChatMessage,
    CortexProvider,
    LLMProvider,
    OllamaProvider,
    ProviderError,
    ProviderInfo,
    ProviderRegistry,
    ProviderStatus,
    extract_json,
)

__all__ = [
    "Action",
    "Advice",
    "AdviceItem",
    "Advisor",
    "ChatMessage",
    "CortexProvider",
    "GuardrailEvent",
    "LLMProvider",
    "OllamaProvider",
    "ProviderError",
    "ProviderInfo",
    "ProviderRegistry",
    "ProviderStatus",
    "extract_json",
    "heuristic_advice",
    "is_dangerous_command",
    "sanitize_text",
    "validate_advice",
]

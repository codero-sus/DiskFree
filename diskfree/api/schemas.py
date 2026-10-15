"""Request bodies for the HTTP API."""

from __future__ import annotations

import os
import unicodedata
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ..scanner.rules import Category

MAX_ROOTS = 12
MAX_ROOT_CHARS = 4096
MAX_IDS = 20_000
RequestId = Annotated[str, Field(min_length=1, max_length=160)]


class ScanRequest(BaseModel):
    """Start a scan."""

    roots: list[str] = Field(default_factory=list, max_length=MAX_ROOTS)
    max_depth: int | None = Field(default=None, ge=1, le=64)
    find_duplicates: bool = True
    find_large_files: bool = True
    include_advisories: bool = True
    categories: list[str] | None = Field(default=None, max_length=len(Category))
    min_finding_bytes: int = Field(default=0, ge=0)
    duplicate_min_mb: int | None = Field(default=None, ge=0, le=102400)
    large_file_min_mb: int | None = Field(default=None, ge=0, le=102400)
    temp_min_age_days: float | None = Field(default=None, ge=0, le=36500)
    log_min_age_days: float | None = Field(default=None, ge=0, le=36500)
    old_file_min_age_days: float | None = Field(default=None, ge=0, le=36500)
    preset: Literal["quick", "balanced", "deep", "custom"] | None = None

    @field_validator("categories")
    @classmethod
    def _validate_categories(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        allowed = {category.value for category in Category}
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ValueError(f"unknown scan category: {', '.join(unknown)}")
        return list(dict.fromkeys(value))

    @field_validator("roots")
    @classmethod
    def _expand_roots(cls, value: list[str]) -> list[str]:
        roots: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not item or not item.strip():
                continue
            raw = item.strip()
            if len(raw) > MAX_ROOT_CHARS:
                raise ValueError(f"scan root exceeds {MAX_ROOT_CHARS} characters")
            if any(unicodedata.category(char) == "Cc" for char in raw):
                raise ValueError("scan roots cannot contain control characters")
            expanded = str(Path(raw).expanduser())
            key = os.path.normcase(os.path.abspath(os.path.normpath(expanded)))
            if key not in seen:
                roots.append(expanded)
                seen.add(key)
        return roots


class AdviseRequest(BaseModel):
    """Ask a provider (or the offline rule engine) to analyse a scan."""

    job_id: RequestId | None = None
    provider: Literal["auto", "cortex", "ollama", "heuristic"] = "auto"
    model: str | None = Field(default=None, max_length=200)
    instructions: str | None = Field(default=None, max_length=4000)
    use_model: bool = True
    max_findings: int | None = Field(default=None, ge=1, le=400)


class ChatMessageIn(BaseModel):
    """A client-owned conversation turn; system instructions are server-owned."""

    role: Literal["user", "assistant"] = "user"
    content: str = Field(min_length=1, max_length=8000)


class ChatRequest(BaseModel):
    """One bounded turn of the read-only assistant."""

    message: str = Field(min_length=1, max_length=8000)
    history: list[ChatMessageIn] = Field(default_factory=list, max_length=12)
    job_id: RequestId | None = None
    provider: Literal["auto", "cortex", "ollama", "heuristic"] = "auto"
    model: str | None = Field(default=None, max_length=200)
    stream: bool = True

    @model_validator(mode="after")
    def _bound_history_size(self) -> ChatRequest:
        total_chars = len(self.message) + sum(len(item.content) for item in self.history)
        if total_chars > 32_000:
            raise ValueError("message and history may contain at most 32000 characters")
        return self


class PlanRequest(BaseModel):
    """Itemise a cleanup without executing it."""

    job_id: RequestId | None = None
    finding_ids: list[RequestId] = Field(default_factory=list, max_length=MAX_IDS)
    mode: Literal["trash", "dry_run", "permanent"] = "trash"
    #: Convenience: plan everything the advisor marked "clean" within max_risk.
    from_advice: bool = False
    max_risk: Literal["safe", "low", "medium", "high"] = "low"

    @field_validator("finding_ids")
    @classmethod
    def _dedupe(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for item in value:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out


class ExecuteRequest(BaseModel):
    """Execute a previously created plan."""

    plan_id: RequestId
    confirm_token: str = Field(min_length=1, max_length=200)
    #: Must echo the plan's byte total; a cheap but effective mis-click guard.
    expected_bytes: int | None = Field(default=None, ge=0)


class RestoreRequest(BaseModel):
    entry_ids: list[RequestId] = Field(default_factory=list, max_length=MAX_IDS)
    op_id: RequestId | None = None


class PurgeRequest(BaseModel):
    entry_ids: list[RequestId] = Field(default_factory=list, max_length=MAX_IDS)


class ProviderCheckRequest(BaseModel):
    base_url: str | None = Field(default=None, max_length=300)
    model: str | None = Field(default=None, max_length=200)
    api_key: str | None = Field(default=None, max_length=400)

"""Shared application state and dependency accessors."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from fastapi import Request

from .. import __version__
from ..actions.executor import ActionService
from ..ai.advisor import Advisor
from ..ai.providers import ProviderRegistry
from ..config import Settings
from ..safety.policy import SafetyPolicy
from ..scanner.jobs import JobManager


@dataclass
class AppState:
    """Everything the API needs, created once at startup."""

    settings: Settings
    policy: SafetyPolicy
    jobs: JobManager
    registry: ProviderRegistry
    advisor: Advisor
    actions: ActionService
    started_at: float = field(default_factory=time.time)

    @classmethod
    def create(cls, settings: Settings) -> AppState:
        policy = SafetyPolicy(
            settings.safety, own_paths=[settings.data_dir, settings.quarantine_dir]
        )
        jobs = JobManager(settings, policy=policy)
        registry = ProviderRegistry(settings)
        return cls(
            settings=settings,
            policy=policy,
            jobs=jobs,
            registry=registry,
            advisor=Advisor(settings, registry),
            actions=ActionService(settings, jobs=jobs, policy=policy),
        )

    async def aclose(self) -> None:
        await self.registry.aclose()

    def uptime(self) -> float:
        return max(0.0, time.time() - self.started_at)


STATE_KEY = "diskfree"


def get_state(request: Request) -> AppState:
    """Pull :class:`AppState` off the request (FastAPI dependency)."""

    state = getattr(request.app.state, STATE_KEY, None)
    if state is None:  # pragma: no cover - only if lifespan was skipped
        raise RuntimeError("DiskFree state was not initialised")
    return state


def version() -> str:
    return __version__

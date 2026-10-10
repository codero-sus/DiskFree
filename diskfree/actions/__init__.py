"""Destructive operations: planning, confirmation and execution."""

from __future__ import annotations

from .executor import (
    MAX_ITEMS_PER_OPERATION,
    ActionError,
    ActionService,
    CleanPlan,
    PlanItem,
)

__all__ = [
    "MAX_ITEMS_PER_OPERATION",
    "ActionError",
    "ActionService",
    "CleanPlan",
    "PlanItem",
]

"""Cleaning endpoints: plan, confirm, execute, and undo."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from ..actions.executor import ActionError
from ..safety.policy import Risk
from ..util import human_bytes
from .deps import AppState, get_state
from .schemas import ExecuteRequest, PlanRequest, PurgeRequest, RestoreRequest

logger = logging.getLogger("diskfree.api")
router = APIRouter(prefix="/api", tags=["clean"])


@router.post("/clean/plan")
async def create_plan(
    request: PlanRequest, state: AppState = Depends(get_state)
) -> dict[str, object]:
    """Itemise and price a cleanup. Touches nothing.

    The response carries a ``confirm_token`` that ``/api/clean/execute`` requires.
    Because the token is an HMAC over the plan id, mode, expiry and the exact
    item fingerprint, a changed selection invalidates it.
    """

    job = state.jobs.resolve(request.job_id)
    if job is None or job.result is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "No completed scan to plan against.", "hint": "Run a scan first."},
        )

    finding_ids = list(request.finding_ids)
    if request.from_advice:
        advice = job.advice or {}
        clean_ids = advice.get("clean_ids") or []
        try:
            ceiling = Risk(request.max_risk)
        except ValueError:
            ceiling = Risk.LOW
        if advice.get("items"):
            risk_of = {
                item["finding_id"]: item["risk"] for item in advice["items"]
                if isinstance(item, dict)
            }
            clean_ids = [
                item
                for item in clean_ids
                if Risk(risk_of.get(item, "safe")).rank <= ceiling.rank
            ]
        # Union with anything explicitly ticked, de-duplicated by the schema.
        for item in clean_ids:
            if item not in finding_ids:
                finding_ids.append(item)

    if not finding_ids:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "Nothing selected.",
                "hint": (
                    "Tick items in the Findings view, or send from_advice=true to use the "
                    "advisor's clean list."
                ),
            },
        )

    try:
        plan = await asyncio.to_thread(
            state.actions.create_plan, job, finding_ids, mode=request.mode
        )
    except ActionError as exc:
        raise HTTPException(status_code=409, detail=exc.as_dict()) from exc

    payload = plan.as_dict()
    payload["message"] = (
        f"Review {payload['item_count']} item(s) totalling {payload['total_bytes_human']}. "
        "POST /api/clean/execute with plan_id and confirm_token to proceed."
    )
    if plan.refused_items:
        payload["warning"] = (
            f"{len(plan.refused_items)} selected item(s) were refused by the safety policy and "
            "will not be touched."
        )
    return payload


@router.post("/clean/execute")
async def execute_plan(
    request: ExecuteRequest, state: AppState = Depends(get_state)
) -> dict[str, object]:
    """Execute a confirmed plan: move to trash, journal, report."""

    plan = state.actions.get_plan(request.plan_id)
    if plan is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Unknown or already-used plan.",
                "hint": "Plans are single-use and expire; create a new one.",
            },
        )
    if request.expected_bytes is not None and request.expected_bytes != plan.total_bytes:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "The plan changed since you reviewed it.",
                "expected_bytes": plan.total_bytes,
                "sent_bytes": request.expected_bytes,
                "hint": "Create a fresh plan and confirm again.",
            },
        )
    try:
        report = await asyncio.to_thread(state.actions.execute, plan.id, request.confirm_token)
    except ActionError as exc:
        raise HTTPException(status_code=409, detail=exc.as_dict()) from exc

    payload = report.as_dict()
    payload["bytes_human"] = human_bytes(report.bytes)
    payload["message"] = (
        f"Moved {report.ok_count} item(s) ({human_bytes(report.bytes)}) to the trash. "
        f"Undo any of it from History."
        if report.ok_count
        else "Nothing was removed."
    )
    if report.failed_count:
        payload["message"] += f" {report.failed_count} item(s) were skipped; see 'skipped'."
    return payload


@router.get("/actions/status")
async def actions_status(state: AppState = Depends(get_state)) -> dict[str, object]:
    """Where removed data goes, and what this instance is allowed to do."""

    return state.actions.status()


@router.get("/history")
async def history(
    state: AppState = Depends(get_state),
    limit: int = Query(default=200, ge=1, le=2000),
    status: str | None = Query(default=None, pattern="^(trashed|restored|purged)$"),
    op_id: str | None = Query(default=None, max_length=120),
) -> dict[str, object]:
    """The journal: everything DiskFree has moved, and whether it can come back."""

    journal = state.actions.journal
    entries = journal.entries()
    if status:
        entries = [entry for entry in entries if entry.status == status]
    if op_id:
        entries = [entry for entry in entries if entry.op_id == op_id]
    entries = list(reversed(entries))[:limit]

    operations: dict[str, dict[str, object]] = {}
    for entry in journal.entries():
        bucket = operations.setdefault(
            entry.op_id,
            {
                "op_id": entry.op_id,
                "mode": "restore" if entry.op_id.startswith("restore") else "clean",
                "timestamp": entry.timestamp,
                "items": 0,
                "bytes": 0,
                "restorable": 0,
            },
        )
        bucket["items"] = int(bucket["items"]) + 1
        bucket["bytes"] = int(bucket["bytes"]) + entry.bytes
        if entry.status == "trashed":
            bucket["restorable"] = int(bucket["restorable"]) + 1

    ordered = sorted(
        operations.values(), key=lambda item: str(item["timestamp"]), reverse=True
    )[:50]
    for item in ordered:
        item["bytes_human"] = human_bytes(int(item["bytes"]))

    active = journal.active()
    return {
        "entries": [entry.as_dict() for entry in entries],
        "operations": ordered,
        "total_entries": len(journal.entries()),
        "active_items": len(active),
        "active_bytes": sum(entry.bytes for entry in active),
        "active_bytes_human": human_bytes(sum(entry.bytes for entry in active)),
        "journal_path": str(journal.path),
        "allow_permanent_delete": state.settings.safety.allow_permanent_delete,
        "note": (
            "Items are in the system trash or DiskFree's quarantine until you purge them. "
            "Restore puts them back exactly where they were."
        ),
    }


@router.post("/history/restore")
async def restore(
    request: RestoreRequest, state: AppState = Depends(get_state)
) -> dict[str, object]:
    """Undo a cleanup: by journal entry ids, or a whole operation at once."""

    try:
        if request.op_id and not request.entry_ids:
            report = await asyncio.to_thread(state.actions.restore_operation, request.op_id)
        else:
            report = await asyncio.to_thread(state.actions.restore, request.entry_ids)
    except ActionError as exc:
        raise HTTPException(status_code=409, detail=exc.as_dict()) from exc

    payload = report.as_dict()
    payload["bytes_human"] = human_bytes(report.bytes)
    payload["message"] = (
        f"Restored {report.ok_count} item(s) ({human_bytes(report.bytes)})."
        if report.ok_count
        else "Nothing was restored."
    )
    return payload


@router.post("/history/purge")
async def purge(request: PurgeRequest, state: AppState = Depends(get_state)) -> dict[str, object]:
    """Permanently delete quarantined data. Disabled unless the process opted in."""

    try:
        report = await asyncio.to_thread(state.actions.purge, request.entry_ids)
    except ActionError as exc:
        raise HTTPException(status_code=409, detail=exc.as_dict()) from exc
    payload = report.as_dict()
    payload["bytes_human"] = human_bytes(report.bytes)
    payload["message"] = (
        f"Purged {report.ok_count} item(s), freeing {human_bytes(report.bytes)}."
        if report.ok_count
        else "Nothing was purged."
    )
    return payload

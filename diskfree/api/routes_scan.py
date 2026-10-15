"""Scan endpoints: start, poll, inspect and cancel read-only analysis."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query

from ..safety.policy import Risk
from ..scanner.disks import disk_summary
from ..scanner.engine import ScanOptions
from ..scanner.jobs import JobManager, ScanCapacityError, ScanStatus, default_options, risk_summary
from ..scanner.rules import CATEGORY_META, Category
from ..util import human_bytes
from .deps import AppState, get_state
from .schemas import ScanRequest

router = APIRouter(prefix="/api", tags=["scan"])

MB = 1024 * 1024

#: Presets trade thoroughness against wall-clock time.
PRESETS: dict[str, dict[str, object]] = {
    "quick": {
        "label": "Quick",
        "blurb": "Home directory, shallow, no duplicate hashing. Seconds.",
        "max_depth": 8,
        "find_duplicates": False,
        "find_large_files": True,
        "min_finding_bytes": 50 * MB,
        "duplicate_min_mb": 50,
        "large_file_min_mb": 500,
    },
    "balanced": {
        "label": "Balanced",
        "blurb": "Home directory, full depth, duplicates over 10 MB.",
        "max_depth": 20,
        "find_duplicates": True,
        "find_large_files": True,
        "min_finding_bytes": 1 * MB,
        "duplicate_min_mb": 10,
        "large_file_min_mb": 250,
    },
    "deep": {
        "label": "Deep",
        "blurb": "Home plus /tmp, /var/log and /var/cache; duplicates over 1 MB.",
        "max_depth": 40,
        "find_duplicates": True,
        "find_large_files": True,
        "min_finding_bytes": 0,
        "duplicate_min_mb": 1,
        "large_file_min_mb": 100,
        "extra_roots": ["/tmp", "/var/log", "/var/cache"],
    },
}


def describe_presets() -> list[dict[str, object]]:
    return [
        {"id": name, **{k: v for k, v in spec.items() if k != "extra_roots"}}
        for name, spec in PRESETS.items()
    ]


def _options_for(state: AppState, request: ScanRequest) -> ScanOptions:
    options = default_options(state.settings, request.roots or None)
    preset = PRESETS.get(request.preset or "")
    if preset:
        options.max_depth = int(preset.get("max_depth", options.max_depth))
        options.find_duplicates = bool(preset.get("find_duplicates", options.find_duplicates))
        options.find_large_files = bool(preset.get("find_large_files", options.find_large_files))
        options.min_finding_bytes = int(preset.get("min_finding_bytes", 0))
        options.duplicate_min_bytes = int(preset.get("duplicate_min_mb", 5)) * MB
        options.large_file_min_bytes = int(preset.get("large_file_min_mb", 250)) * MB
        for extra in preset.get("extra_roots", []) or []:
            candidate = Path(extra)
            if candidate.is_dir() and candidate not in options.roots:
                options.roots.append(candidate)

    if request.roots:
        options.roots = [Path(item).expanduser() for item in request.roots]
    if request.max_depth is not None:
        options.max_depth = request.max_depth
    if request.categories:
        options.categories = tuple(request.categories)
    if request.min_finding_bytes:
        options.min_finding_bytes = request.min_finding_bytes
    if request.duplicate_min_mb is not None:
        options.duplicate_min_bytes = request.duplicate_min_mb * MB
    if request.large_file_min_mb is not None:
        options.large_file_min_bytes = request.large_file_min_mb * MB
    if request.temp_min_age_days is not None:
        options.temp_min_age_days = request.temp_min_age_days
    if request.log_min_age_days is not None:
        options.log_min_age_days = request.log_min_age_days
    if request.old_file_min_age_days is not None:
        options.old_file_min_age_days = request.old_file_min_age_days
    options.find_duplicates = request.find_duplicates if preset is None else (
        request.find_duplicates and bool(preset.get("find_duplicates", True))
    )
    options.find_large_files = request.find_large_files
    options.include_advisories = request.include_advisories
    options.max_findings = state.settings.scan.max_findings
    options.max_files_per_rule = state.settings.scan.max_files_per_rule
    options.max_members_per_finding = state.settings.scan.max_members_per_finding
    options.duplicate_max_candidates = state.settings.scan.duplicate_max_candidates
    if not options.roots:
        options.roots = [Path.home()]
    return options


@router.get("/presets")
async def list_presets() -> dict[str, object]:
    """The scan presets the UI offers."""

    return {"presets": describe_presets(), "home": str(Path.home())}


@router.post("/scan", status_code=202)
async def start_scan(
    request: ScanRequest, state: AppState = Depends(get_state)
) -> dict[str, object]:
    """Start a background scan and return its job immediately."""

    options = _options_for(state, request)
    missing = [str(root) for root in options.roots if not Path(root).expanduser().exists()]
    if missing:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "Some scan roots do not exist.",
                "missing": missing,
                "hint": "Pick existing directories; ~ and environment variables are expanded.",
            },
        )
    try:
        job = state.jobs.start(options)
    except ScanCapacityError as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "The scan concurrency limit has been reached.",
                "hint": str(exc),
            },
            headers={"Retry-After": "5"},
        ) from exc
    return {
        "job": job.summary(),
        "message": "Scan started. Poll /api/scans/{job_id} for progress.",
    }


@router.get("/scans")
async def list_scans(
    state: AppState = Depends(get_state), limit: int = Query(default=20, ge=1, le=100)
) -> dict[str, object]:
    jobs: JobManager = state.jobs
    return {
        "jobs": [job.summary() for job in jobs.list(limit=limit)],
        "latest": (jobs.latest() or _empty_job()).id if jobs.latest() else None,
        "retention": jobs.retention,
        "active": jobs.active_count(),
        "max_running": jobs.max_running,
    }


def _empty_job():  # pragma: no cover - typing helper
    class _Stub:
        id = ""

    return _Stub()


@router.get("/scans/{job_id}")
async def scan_status(job_id: str, state: AppState = Depends(get_state)) -> dict[str, object]:
    """Progress plus, once finished, the summary and folder ranking."""

    job = state.jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"error": f"Unknown scan '{job_id}'."})
    payload = job.summary()
    result = job.result
    if result is not None:
        payload["mounts"] = [mount.as_dict() for mount in result.mounts]
        payload["dir_totals"] = [item.as_dict() for item in result.dir_totals]
        payload["risk_summary"] = risk_summary(result)
        payload["disk"] = disk_summary(str(result.roots[0]) if result.roots else "/")
    return payload


@router.get("/scans/{job_id}/findings")
async def scan_findings(
    job_id: str,
    state: AppState = Depends(get_state),
    category: str | None = Query(default=None),
    risk: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    actionable: bool | None = Query(default=None),
    selected_only: bool = Query(default=False),
    q: str | None = Query(default=None, max_length=200),
    min_bytes: int = Query(default=0, ge=0),
    sort: str = Query(default="bytes", pattern="^(bytes|age|risk|category|path)$"),
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    include_members: bool = Query(default=False),
) -> dict[str, object]:
    """Filterable finding list for the review table."""

    job = state.jobs.get(job_id)
    if job is None or job.result is None:
        raise HTTPException(
            status_code=404, detail={"error": f"No results for scan '{job_id}'."}
        )
    findings = list(job.result.findings)

    if category:
        wanted = {item.strip() for item in category.split(",") if item.strip()}
        findings = [item for item in findings if item.category.value in wanted]
    if risk:
        wanted_risk = {item.strip() for item in risk.split(",") if item.strip()}
        findings = [item for item in findings if item.risk.value in wanted_risk]
    if rule_id:
        findings = [item for item in findings if item.rule_id == rule_id]
    if actionable is not None:
        findings = [item for item in findings if item.actionable is actionable]
    if selected_only:
        findings = [item for item in findings if item.default_selected]
    if min_bytes:
        findings = [item for item in findings if item.bytes >= min_bytes]
    if q:
        needle = q.lower()
        findings = [
            item
            for item in findings
            if needle in item.path.lower()
            or needle in item.title.lower()
            or needle in item.rule_id.lower()
        ]

    if sort == "bytes":
        findings.sort(key=lambda item: item.bytes, reverse=True)
    elif sort == "age":
        findings.sort(key=lambda item: item.age_days_now, reverse=True)
    elif sort == "risk":
        findings.sort(key=lambda item: (-item.risk.rank, -item.bytes))
    elif sort == "category":
        order = {category_.value: meta.order for category_, meta in CATEGORY_META.items()}
        findings.sort(key=lambda item: (order.get(item.category.value, 99), -item.bytes))
    else:
        findings.sort(key=lambda item: item.path)

    total = len(findings)
    page = findings[offset : offset + limit]
    return {
        "job_id": job_id,
        "status": job.status.value,
        "total": total,
        "limit": limit,
        "offset": offset,
        "returned": len(page),
        "total_bytes": sum(item.bytes for item in findings),
        "total_bytes_human": human_bytes(sum(item.bytes for item in findings)),
        "risk_summary": risk_summary(job.result),
        "categories": [
            {
                "category": key.value,
                "label": meta.label,
                "icon": meta.icon,
                "blurb": meta.blurb,
                "order": meta.order,
            }
            for key, meta in sorted(CATEGORY_META.items(), key=lambda kv: kv[1].order)
        ],
        "risks": [
            {"risk": item.value, "auto_selectable": item.auto_selectable}
            for item in Risk
        ],
        "findings": [
            item.as_dict(include_members=include_members) for item in page
        ],
    }


@router.post("/scans/{job_id}/cancel")
async def cancel_scan(job_id: str, state: AppState = Depends(get_state)) -> dict[str, object]:
    job = state.jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"error": f"Unknown scan '{job_id}'."})
    cancelled = state.jobs.cancel(job_id)
    return {
        "job_id": job_id,
        "cancelled": cancelled,
        "status": job.status.value,
        "message": (
            "Cancellation requested; the scan stops after the current directory."
            if cancelled
            else f"Scan was already {job.status.value}."
        ),
    }


@router.delete("/scans")
async def clear_scans(state: AppState = Depends(get_state)) -> dict[str, object]:
    removed = state.jobs.clear()
    return {"removed": removed, "message": "Scan history cleared from memory."}


def category_catalog() -> list[dict[str, object]]:
    """Public description of every category, used by the transparency panel."""

    return [
        {
            "category": key.value,
            "label": meta.label,
            "icon": meta.icon,
            "blurb": meta.blurb,
            "order": meta.order,
        }
        for key, meta in sorted(CATEGORY_META.items(), key=lambda kv: kv[1].order)
    ]


def status_counts(job_status: ScanStatus) -> str:
    return job_status.value


def category_of(value: str) -> Category | None:
    try:
        return Category(value)
    except ValueError:
        return None

"""Scan job lifecycle: background threads, progress, cancellation, retention.

Scan results stay in memory only. Paths reveal a lot about a person's files, so
DiskFree never writes them to disk, never uploads them, and forgets them when the
job is dropped or the process exits.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum

from ..config import Settings
from ..safety.policy import Risk, SafetyPolicy
from ..util import human_bytes, new_id
from .engine import Scanner, ScanOptions, ScanProgress
from .models import ScanResult

logger = logging.getLogger("diskfree.scan")


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ScanCapacityError(RuntimeError):
    """Raised when starting another scan would exceed the concurrency cap."""


@dataclass
class ScanJob:
    """One scan, from request to result."""

    id: str
    options: ScanOptions
    status: ScanStatus = ScanStatus.QUEUED
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    progress: ScanProgress = field(default_factory=ScanProgress)
    result: ScanResult | None = None
    error: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)
    advice: dict[str, object] | None = None
    thread: threading.Thread | None = field(default=None, repr=False)

    # -- views -----------------------------------------------------------
    @property
    def duration(self) -> float:
        if not self.started_at:
            return 0.0
        return max(0.0, (self.finished_at or time.time()) - self.started_at)

    def summary(self) -> dict[str, object]:
        """Compact view for list endpoints and progress polling."""

        result = self.result
        totals: dict[str, object] = {}
        if result is not None:
            by_risk: dict[str, int] = {}
            for finding in result.findings:
                by_risk[finding.risk.value] = by_risk.get(finding.risk.value, 0) + finding.bytes
            totals = {
                "findings": len(result.findings),
                "actionable_findings": sum(1 for f in result.findings if f.actionable),
                "actionable_bytes": result.stats.actionable_bytes,
                "actionable_bytes_human": human_bytes(result.stats.actionable_bytes),
                "safe_bytes": result.stats.safe_bytes,
                "safe_bytes_human": human_bytes(result.stats.safe_bytes),
                "duplicate_bytes": result.stats.duplicate_bytes,
                "duplicate_bytes_human": human_bytes(result.stats.duplicate_bytes),
                "categories": result.category_totals(),
                "by_risk": by_risk,
                "warnings": result.warnings,
                "errors": result.errors[:20],
                "stats": result.stats.as_dict(),
            }
        return {
            "id": self.id,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration, 3),
            "roots": [str(root) for root in self.options.roots],
            "options": self.options.as_dict(),
            "progress": self.progress.as_dict(),
            "error": self.error,
            "has_advice": self.advice is not None,
            **totals,
        }

    def finding_index(self) -> dict[str, object]:
        if self.result is None:
            return {}
        return {finding.id: finding for finding in self.result.findings}

    def selectable_bytes(self, finding_ids: list[str]) -> int:
        index = self.finding_index()
        return sum(
            int(getattr(index[finding_id], "bytes", 0))
            for finding_id in finding_ids
            if finding_id in index
        )


class JobManager:
    """Owns scan jobs and the threads that run them."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        policy: SafetyPolicy | None = None,
        retention: int = 8,
        max_running: int = 2,
    ) -> None:
        self.settings = settings or Settings()
        self.policy = policy or SafetyPolicy(self.settings.safety)
        self.retention = max(1, retention)
        self.max_running = max(1, max_running)
        self._jobs: OrderedDict[str, ScanJob] = OrderedDict()
        self._lock = threading.RLock()

    # -- lifecycle -------------------------------------------------------
    def active_count(self) -> int:
        """Number of queued or running jobs, used for admission and status views."""

        with self._lock:
            return sum(
                job.status in {ScanStatus.QUEUED, ScanStatus.RUNNING}
                for job in self._jobs.values()
            )

    def start(self, options: ScanOptions) -> ScanJob:
        """Create a job and run it on a daemon thread."""

        job = ScanJob(id=new_id("scan"), options=options)
        job.result = ScanResult(job_id=job.id, roots=list(options.roots))
        with self._lock:
            active = sum(
                item.status in {ScanStatus.QUEUED, ScanStatus.RUNNING}
                for item in self._jobs.values()
            )
            if active >= self.max_running:
                raise ScanCapacityError(
                    f"At most {self.max_running} scans may run at once; {active} are active."
                )
            self._jobs[job.id] = job
            self._evict_locked()

        thread = threading.Thread(
            target=self._run, args=(job,), name=f"diskfree-scan-{job.id}", daemon=True
        )
        job.thread = thread
        try:
            thread.start()
        except RuntimeError:
            with self._lock:
                self._jobs.pop(job.id, None)
            raise
        return job

    def _run(self, job: ScanJob) -> None:
        job.status = ScanStatus.RUNNING
        job.started_at = time.time()
        scanner = Scanner(
            self.settings,
            policy=self.policy,
            on_progress=self._make_progress_sink(job),
            cancel=job.cancel_event,
        )
        try:
            result = scanner.run(job.options)
            result.job_id = job.id
            job.result = result
            job.status = (
                ScanStatus.CANCELLED if job.cancel_event.is_set() else ScanStatus.COMPLETED
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("scan %s failed", job.id)
            job.error = f"{type(exc).__name__}: {exc}"
            job.status = ScanStatus.FAILED
            job.progress.phase = "failed"
            job.progress.message = job.error
        finally:
            job.finished_at = time.time()

    def _make_progress_sink(self, job: ScanJob):
        def sink(progress: ScanProgress) -> None:
            job.progress = progress

        return sink

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if job is None or job.status not in {ScanStatus.QUEUED, ScanStatus.RUNNING}:
            return False
        job.cancel_event.set()
        job.progress.phase = "cancelling"
        job.progress.message = "Cancelling after the current directory"
        return True

    # -- access ----------------------------------------------------------
    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self, *, limit: int = 20) -> list[ScanJob]:
        with self._lock:
            return list(reversed(self._jobs.values()))[:limit]

    def latest(self, *, completed_only: bool = False) -> ScanJob | None:
        with self._lock:
            for job in reversed(self._jobs.values()):
                if not completed_only or job.status is ScanStatus.COMPLETED:
                    return job
        return None

    def resolve(self, job_id: str | None) -> ScanJob | None:
        """The requested job, or the most recent usable one."""

        if job_id:
            return self.get(job_id)
        return self.latest(completed_only=True) or self.latest()

    def _evict_locked(self) -> None:
        while len(self._jobs) > self.retention:
            oldest_id, oldest = next(iter(self._jobs.items()))
            if oldest.status is ScanStatus.RUNNING:
                # Never drop a running job; evict the next oldest instead.
                for candidate_id, candidate in list(self._jobs.items())[1:]:
                    if candidate.status is not ScanStatus.RUNNING:
                        oldest_id = candidate_id
                        break
                else:
                    return
            self._jobs.pop(oldest_id, None)

    def clear(self) -> int:
        with self._lock:
            count = 0
            for job in self._jobs.values():
                if job.status is ScanStatus.RUNNING:
                    job.cancel_event.set()
                    continue
                count += 1
            for job_id in [j.id for j in self._jobs.values() if j.status is not ScanStatus.RUNNING]:
                self._jobs.pop(job_id, None)
            return count

    def set_advice(self, job_id: str, advice: dict[str, object]) -> None:
        job = self.get(job_id)
        if job is not None:
            job.advice = advice


def default_options(settings: Settings, roots: list[str] | None = None) -> ScanOptions:
    """Scan options seeded from configuration and the user's home directory."""

    from pathlib import Path

    scan = settings.scan
    resolved: list[Path] = []
    for raw in roots or []:
        resolved.append(Path(raw).expanduser())
    if not resolved:
        resolved = [Path.home()]
    return ScanOptions(
        roots=resolved,
        max_depth=scan.max_depth,
        max_findings=scan.max_findings,
        max_files_per_rule=scan.max_files_per_rule,
        max_members_per_finding=scan.max_members_per_finding,
        duplicate_min_bytes=scan.duplicate_min_bytes,
        duplicate_max_candidates=scan.duplicate_max_candidates,
        large_file_min_bytes=scan.large_file_min_bytes,
        temp_min_age_days=scan.temp_min_age_days,
        log_min_age_days=scan.log_min_age_days,
        old_file_min_age_days=scan.old_file_min_age_days,
        tree_depth=4,
    )


def risk_summary(result: ScanResult | None) -> dict[str, object]:
    """Reclaimable bytes split by risk, used by the UI header."""

    if result is None:
        return {"total": 0, "total_human": human_bytes(0), "by_risk": {}}
    by_risk: dict[str, dict[str, int]] = {}
    for finding in result.findings:
        if not finding.actionable:
            continue
        bucket = by_risk.setdefault(finding.risk.value, {"bytes": 0, "items": 0})
        bucket["bytes"] += finding.bytes
        bucket["items"] += 1
    total = sum(bucket["bytes"] for bucket in by_risk.values())
    safe = by_risk.get(Risk.SAFE.value, {}).get("bytes", 0)
    return {
        "total": total,
        "total_human": human_bytes(total),
        "safe": safe,
        "safe_human": human_bytes(safe),
        "by_risk": by_risk,
    }

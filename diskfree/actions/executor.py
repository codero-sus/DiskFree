"""The only code in DiskFree that can modify the filesystem.

Cleaning is a two-step, token-bound operation:

``create_plan``
    Validates every requested path against the live policy, prices it, and
    returns a plan plus an HMAC confirm token. Nothing is touched.
``execute``
    Requires that token, re-validates every path again, then moves data into the
    trash or quarantine and journals each move.

The token binds the plan id, the exact item fingerprint, the mode and an expiry,
so a stale or tampered plan cannot be replayed, and a client that never saw the
itemised plan cannot execute it. Re-validation matters because the world moves
between plan and execute: a file may be gone, replaced by a symlink, or a volume
may have been mounted over the target.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Settings
from ..safety.policy import Risk, SafetyPolicy, Tier, same_path
from ..safety.trash import Journal, OperationReport, QuarantineResult, TrashManager
from ..scanner.jobs import JobManager, ScanJob
from ..scanner.models import Finding
from ..util import human_bytes, new_id

logger = logging.getLogger("diskfree.actions")

MAX_ITEMS_PER_OPERATION = 20_000


class ActionError(RuntimeError):
    """Raised when an operation is refused."""

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint

    def as_dict(self) -> dict[str, str]:
        return {"error": str(self), "hint": self.hint or ""}


@dataclass(slots=True)
class PlanItem:
    """One path in a plan, with its live policy verdict."""

    finding_id: str
    path: str
    bytes: int
    files: int
    is_dir: bool
    risk: str
    category: str
    title: str
    allowed: bool
    reason: str | None = None
    rule_id: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "path": self.path,
            "bytes": self.bytes,
            "bytes_human": human_bytes(self.bytes),
            "files": self.files,
            "is_dir": self.is_dir,
            "risk": self.risk,
            "category": self.category,
            "title": self.title,
            "allowed": self.allowed,
            "reason": self.reason,
            "rule_id": self.rule_id,
        }


@dataclass(slots=True)
class CleanPlan:
    """A priced, itemised, expiring proposal."""

    id: str
    job_id: str
    mode: str
    created_at: float
    expires_at: float
    items: list[PlanItem] = field(default_factory=list)
    confirm_token: str = ""
    roots: list[str] = field(default_factory=list)
    note: str = ""

    # -- derived ---------------------------------------------------------
    @property
    def allowed_items(self) -> list[PlanItem]:
        return [item for item in self.items if item.allowed]

    @property
    def refused_items(self) -> list[PlanItem]:
        return [item for item in self.items if not item.allowed]

    @property
    def total_bytes(self) -> int:
        return sum(item.bytes for item in self.allowed_items)

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def fingerprint(self) -> str:
        """Stable digest of exactly what would be removed, and how."""

        digest = hashlib.sha256()
        digest.update(self.mode.encode("utf-8"))
        digest.update(self.job_id.encode("utf-8"))
        for item in sorted(self.allowed_items, key=lambda candidate: candidate.path):
            digest.update(f"\x1f{item.path}\x1f{item.bytes}".encode("utf-8", "replace"))
        return digest.hexdigest()

    def as_dict(self, *, include_items: bool = True) -> dict[str, object]:
        allowed = self.allowed_items
        data: dict[str, object] = {
            "id": self.id,
            "job_id": self.job_id,
            "mode": self.mode,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "expires_in_seconds": max(0, int(self.expires_at - time.time())),
            "expired": self.expired,
            "item_count": len(allowed),
            "refused_count": len(self.refused_items),
            "total_bytes": self.total_bytes,
            "total_bytes_human": human_bytes(self.total_bytes),
            "total_files": sum(item.files for item in allowed),
            "roots": self.roots,
            "note": self.note,
            "confirm_token": self.confirm_token,
            "fingerprint": self.fingerprint,
            "refused": [item.as_dict() for item in self.refused_items],
            "by_risk": _by_risk(allowed),
        }
        if include_items:
            data["items"] = [item.as_dict() for item in allowed]
        return data


def _is_a_root(path: Path, roots: list[Path]) -> bool:
    """True when ``path`` *is* one of the scan roots rather than inside one."""

    return any(same_path(path, root) for root in roots)


def _by_risk(items: list[PlanItem]) -> dict[str, dict[str, int]]:
    buckets: dict[str, dict[str, int]] = {}
    for item in items:
        bucket = buckets.setdefault(item.risk, {"items": 0, "bytes": 0})
        bucket["items"] += 1
        bucket["bytes"] += item.bytes
    return buckets


class ActionService:
    """Plans and executes cleanups, restores and purges."""

    def __init__(
        self,
        settings: Settings,
        *,
        jobs: JobManager,
        policy: SafetyPolicy | None = None,
        trash: TrashManager | None = None,
        journal: Journal | None = None,
        secret: bytes | None = None,
    ) -> None:
        self.settings = settings
        self.jobs = jobs
        self.policy = policy or SafetyPolicy(settings.safety)
        self.journal = journal or Journal(settings.journal_path)
        self.trash = trash or TrashManager(
            settings.safety, data_dir=settings.data_dir, journal=self.journal,
            policy=self.policy,
        )
        self._secret = secret or secrets.token_bytes(32)
        self._plans: dict[str, CleanPlan] = {}
        self._lock = threading.RLock()
        self._executing: set[str] = set()

    # -- planning --------------------------------------------------------
    def create_plan(
        self,
        job: ScanJob,
        finding_ids: list[str],
        *,
        mode: str = "trash",
        ttl: int | None = None,
    ) -> CleanPlan:
        """Itemise and price a cleanup without touching anything."""

        mode = (mode or "trash").lower()
        if mode not in {"trash", "permanent", "dry_run"}:
            raise ActionError(
                f"Unknown mode '{mode}'.",
                hint="Use 'trash' (default, reversible), 'dry_run', or 'permanent'.",
            )
        if mode == "permanent" and not self.settings.safety.allow_permanent_delete:
            raise ActionError(
                "Permanent deletion is disabled on this DiskFree instance.",
                hint=(
                    "Restart with DISKFREE_ALLOW_PERMANENT_DELETE=1 to enable it. "
                    "The default 'trash' mode is reversible."
                ),
            )
        if not self.settings.safety.allow_writes and mode != "dry_run":
            raise ActionError(
                "DiskFree is running in read-only mode.",
                hint="Start it without DISKFREE_ALLOW_WRITES=0, or use dry_run.",
            )

        result = job.result
        if result is None:
            raise ActionError("That scan has no results yet.", hint="Wait for the scan to finish.")

        index: dict[str, Finding] = {finding.id: finding for finding in result.findings}
        wanted: list[str] = []
        seen: set[str] = set()
        for finding_id in finding_ids:
            if finding_id in seen:
                continue
            seen.add(finding_id)
            wanted.append(finding_id)
        if not wanted:
            raise ActionError(
                "No findings selected.",
                hint="Tick at least one item in the Findings view, or apply the AI selection.",
            )
        if len(wanted) > MAX_ITEMS_PER_OPERATION:
            raise ActionError(
                f"Too many items in one operation ({len(wanted)}).",
                hint=f"Clean in batches of at most {MAX_ITEMS_PER_OPERATION} items.",
            )

        roots = [Path(root) for root in result.roots]
        items: list[PlanItem] = []
        for finding_id in wanted:
            finding = index.get(finding_id)
            if finding is None:
                items.append(
                    PlanItem(
                        finding_id=finding_id,
                        path="",
                        bytes=0,
                        files=0,
                        is_dir=False,
                        risk=Risk.FORBIDDEN.value,
                        category="unknown",
                        title="unknown finding",
                        allowed=False,
                        reason="that finding is not part of this scan",
                    )
                )
                continue
            if finding.extra.get("aggregated"):
                # The finding's own path is a summary location (a temp anchor,
                # ~/Downloads, a log directory). Removing that would take files
                # the user never agreed to, so plan the members instead.
                items.extend(self._expand_aggregate(finding, roots))
                continue
            path = Path(finding.path)
            allowed, reason = self._live_verdict(path, finding, roots)
            items.append(
                PlanItem(
                    finding_id=finding.id,
                    path=finding.path,
                    bytes=finding.bytes,
                    files=finding.files or 1,
                    is_dir=finding.is_dir,
                    risk=finding.risk.value,
                    category=finding.category.value,
                    title=finding.title,
                    allowed=allowed,
                    reason=reason,
                    rule_id=finding.rule_id,
                )
            )

        # Dropping a parent makes its children redundant; keep the shallowest path.
        items = _collapse_nested(items)

        now = time.time()
        plan = CleanPlan(
            id=new_id("plan"),
            job_id=job.id,
            mode=mode,
            created_at=now,
            expires_at=now + (ttl or self.settings.safety.plan_ttl_seconds),
            items=items,
            roots=[str(root) for root in roots],
            note=(
                "Items will be moved to the trash and journalled; restore them any time from "
                "History."
                if mode == "trash"
                else "Dry run: nothing will be modified."
                if mode == "dry_run"
                else "PERMANENT deletion: this cannot be undone."
            ),
        )
        plan.confirm_token = self._sign(plan)
        with self._lock:
            self._plans[plan.id] = plan
            self._evict_plans_locked()
        return plan

    def _expand_aggregate(self, finding: Finding, roots: list[Path]) -> list[PlanItem]:
        """Turn one aggregate finding into one plan item per recorded file.

        When the scan truncated the member list the plan honestly covers only what
        it lists; the summary path is never a deletion target either way.
        """

        if not finding.members:
            return [
                PlanItem(
                    finding_id=finding.id,
                    path=finding.path,
                    bytes=0,
                    files=0,
                    is_dir=finding.is_dir,
                    risk=finding.risk.value,
                    category=finding.category.value,
                    title=finding.title,
                    rule_id=finding.rule_id,
                    allowed=False,
                    reason=(
                        f"this item summarises {finding.files} files under {finding.name}, but "
                        "the scan did not record them individually; re-scan to act on it"
                    ),
                )
            ]
        out: list[PlanItem] = []
        for member in finding.members:
            member_path = Path(member.path)
            allowed, reason = self._live_verdict(member_path, finding, roots)
            try:
                is_dir = member_path.is_dir()
            except OSError:
                is_dir = False
            out.append(
                PlanItem(
                    finding_id=finding.id,
                    path=member.path,
                    bytes=member.bytes,
                    files=1,
                    is_dir=is_dir,
                    risk=finding.risk.value,
                    category=finding.category.value,
                    title=finding.title,
                    allowed=allowed,
                    reason=reason,
                    rule_id=finding.rule_id,
                )
            )
        return out

    def _live_verdict(
        self, path: Path, finding: Finding, roots: list[Path]
    ) -> tuple[bool, str | None]:
        """Re-check one finding against the world as it is right now."""

        if not finding.actionable:
            return False, (
                "DiskFree will not remove this: it is advisory or managed by another program"
            )
        if finding.risk is Risk.FORBIDDEN:
            return False, "protected by policy"
        if roots and not self.policy.is_within_roots(path, roots):
            return False, "outside the scanned roots"
        if _is_a_root(path, roots):
            return False, (
                "this is a scan root; DiskFree will not remove an entire scanned folder"
            )
        decision = self.policy.check(path, live=True)
        if not decision.allowed:
            return False, decision.reason or "blocked by safety policy"
        if decision.tier is Tier.BLOCKED:
            return False, decision.reason or "blocked by safety policy"
        return True, None

    def get_plan(self, plan_id: str) -> CleanPlan | None:
        with self._lock:
            return self._plans.get(plan_id)

    def _evict_plans_locked(self) -> None:
        if len(self._plans) <= 32:
            return
        now = time.time()
        for plan_id in [
            key for key, plan in self._plans.items() if plan.expires_at < now
        ]:
            self._plans.pop(plan_id, None)
        while len(self._plans) > 32:
            oldest_id = min(self._plans, key=lambda key: self._plans[key].created_at)
            self._plans.pop(oldest_id, None)

    # -- confirmation token ---------------------------------------------
    def _sign(self, plan: CleanPlan) -> str:
        message = f"{plan.id}|{plan.mode}|{int(plan.expires_at)}|{plan.fingerprint}".encode()
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()

    def verify_token(self, plan: CleanPlan, token: str | None) -> None:
        """Raise unless ``token`` proves the client saw this exact plan."""

        if not self.settings.safety.require_confirmation:
            return
        if not token:
            raise ActionError(
                "A confirm token is required.",
                hint="Call the plan endpoint first and pass back confirm_token.",
            )
        expected = self._sign(plan)
        # Both sides must be bytes: compare_digest raises TypeError on a mixed
        # str/bytes pair, which would surface as a 500 instead of a refusal.
        if not hmac.compare_digest(expected.encode("utf-8"), token.encode("utf-8", "replace")):
            raise ActionError(
                "The confirm token does not match this plan.",
                hint="The selection or mode changed after the plan was created; plan again.",
            )
        if plan.expired:
            raise ActionError(
                "That plan expired.",
                hint="Create a new plan; paths are re-validated every time.",
            )

    # -- execution -------------------------------------------------------
    def execute(self, plan_id: str, token: str | None) -> OperationReport:
        """Carry out a confirmed plan."""

        plan = self.get_plan(plan_id)
        if plan is None:
            raise ActionError("Unknown plan.", hint="Create a plan first.")
        self.verify_token(plan, token)

        roots = [Path(root) for root in plan.roots]
        report = OperationReport(
            op_id=new_id("op"), mode=plan.mode, started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ")
        )

        if plan.mode == "dry_run":
            for item in plan.allowed_items:
                report.moved.append(
                    QuarantineResult(item.path, True, bytes=item.bytes, reason="dry run")
                )
            report.bytes = plan.total_bytes
            report.finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ")
            return report

        with self._lock:
            if plan.id in self._executing:
                raise ActionError("That plan is already being executed.")
            self._executing.add(plan.id)

        try:
            for item in plan.allowed_items:
                path = Path(item.path)
                # Final gate: the world may have changed since the plan.
                allowed, reason = self._live_verdict_for_path(path, roots)
                if not allowed:
                    report.skipped.append((item.path, reason or "blocked by safety policy"))
                    continue
                if plan.mode == "permanent":
                    outcome = self.trash.delete_permanently(
                        path,
                        op_id=report.op_id,
                        finding_id=item.finding_id,
                        rule_id=item.rule_id,
                        category=item.category,
                        risk=item.risk,
                    )
                else:
                    outcome = self.trash.trash(
                        path,
                        op_id=report.op_id,
                        finding_id=item.finding_id,
                        rule_id=item.rule_id,
                        category=item.category,
                        risk=item.risk,
                        measured_bytes=item.bytes or None,
                        measured_files=item.files or None,
                    )
                # `moved` records every attempt with its outcome; `skipped` is
                # reserved for paths refused before anything was touched, so a
                # failure is never counted twice.
                report.moved.append(outcome)
                if outcome.ok:
                    report.bytes += outcome.bytes
        finally:
            with self._lock:
                self._executing.discard(plan.id)
                # The plan is single-use: never let a replay run twice.
                self._plans.pop(plan.id, None)

        report.finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        logger.info(
            "operation %s mode=%s ok=%d skipped=%d bytes=%d",
            report.op_id,
            plan.mode,
            report.ok_count,
            report.failed_count,
            report.bytes,
        )
        return report

    def _live_verdict_for_path(self, path: Path, roots: list[Path]) -> tuple[bool, str | None]:
        if roots and not self.policy.is_within_roots(path, roots):
            return False, "outside the scanned roots"
        if _is_a_root(path, roots):
            return False, (
                "this is a scan root; DiskFree will not remove an entire scanned folder"
            )
        decision = self.policy.check(path, live=True)
        if not decision.allowed:
            return False, decision.reason
        return True, None

    # -- undo ------------------------------------------------------------
    def restore(self, entry_ids: list[str]) -> OperationReport:
        """Move journalled items back where they came from."""

        report = OperationReport(
            op_id=new_id("restore"), mode="restore", started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        if not entry_ids:
            raise ActionError("No journal entries selected.", hint="Pick items from History.")
        for entry_id in entry_ids:
            entry = self.journal.get(entry_id)
            if entry is None:
                report.skipped.append((entry_id, "no such journal entry"))
                continue
            outcome = self.trash.restore(entry)
            report.moved.append(outcome)
            if outcome.ok:
                report.bytes += outcome.bytes
        report.finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        return report

    def restore_operation(self, op_id: str) -> OperationReport:
        """Undo an entire cleanup operation, deepest paths first."""

        entries = [
            entry
            for entry in self.journal.active()
            if entry.op_id == op_id
        ]
        if not entries:
            raise ActionError(
                f"No restorable items for operation {op_id}.",
                hint="It may already have been restored or purged.",
            )
        entries.sort(key=lambda entry: -entry.path.count(os.sep))
        return self.restore([entry.id for entry in entries])

    def purge(self, entry_ids: list[str]) -> OperationReport:
        """Permanently delete quarantined data (opt-in at the process level)."""

        if not self.settings.safety.allow_permanent_delete:
            raise ActionError(
                "Permanent deletion is disabled on this DiskFree instance.",
                hint="Restart with DISKFREE_ALLOW_PERMANENT_DELETE=1 to enable it.",
            )
        report = OperationReport(
            op_id=new_id("purge"), mode="purge", started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        for entry_id in entry_ids or []:
            entry = self.journal.get(entry_id)
            if entry is None:
                report.skipped.append((entry_id, "no such journal entry"))
                continue
            outcome = self.trash.purge(entry)
            report.moved.append(outcome)
            if outcome.ok:
                report.bytes += outcome.bytes
        report.finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        return report

    # -- status ----------------------------------------------------------
    def status(self) -> dict[str, object]:
        trash_status = self.trash.status()
        with self._lock:
            active_plans = len(self._plans)
        return {
            **trash_status,
            "active_plans": active_plans,
            "require_confirmation": self.settings.safety.require_confirmation,
            "plan_ttl_seconds": self.settings.safety.plan_ttl_seconds,
            "max_items_per_operation": MAX_ITEMS_PER_OPERATION,
            "journal_entries": len(self.journal.entries()),
        }


def _collapse_nested(items: list[PlanItem]) -> list[PlanItem]:
    """Drop items that live inside another item already in the plan."""

    allowed = [item for item in items if item.allowed]
    refused = [item for item in items if not item.allowed]
    if len(allowed) < 2:
        return items
    allowed.sort(key=lambda item: (item.path.count(os.sep), item.path))
    kept: list[PlanItem] = []
    for item in allowed:
        if any(_is_within(item.path, parent.path) for parent in kept):
            continue
        kept.append(item)
    dropped = len(allowed) - len(kept)
    if dropped:
        logger.debug("collapsed %d nested plan items", dropped)
    return kept + refused


def _is_within(candidate: str, parent: str) -> bool:
    if not parent or candidate == parent:
        return False
    return candidate.startswith(parent.rstrip(os.sep) + os.sep)

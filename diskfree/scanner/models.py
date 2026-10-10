"""Data types produced by the scanner."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..safety.policy import Risk, Tier
from ..util import human_bytes
from .rules import Category


@dataclass(slots=True)
class Member:
    """One file inside an aggregated finding."""

    path: str
    bytes: int
    mtime: float

    def as_dict(self) -> dict[str, object]:
        return {"path": self.path, "bytes": self.bytes, "mtime": self.mtime}


@dataclass(slots=True)
class Finding:
    """A single thing DiskFree could clean, plus everything needed to review it."""

    id: str
    rule_id: str
    category: Category
    risk: Risk
    title: str
    description: str
    path: str
    name: str
    is_dir: bool
    bytes: int = 0
    files: int = 0
    mtime: float = 0.0
    age_days: float = 0.0
    root: str = ""
    tier: Tier = Tier.NORMAL
    actionable: bool = True
    default_selected: bool = False
    advisory: str | None = None
    members: list[Member] = field(default_factory=list)
    members_total: int = 0
    truncated: bool = False
    extra: dict[str, object] = field(default_factory=dict)

    # -- derived ---------------------------------------------------------
    @property
    def age_days_now(self) -> float:
        if not self.mtime:
            return self.age_days
        return max(0.0, (time.time() - self.mtime) / 86400)

    def as_dict(self, *, include_members: bool = True) -> dict[str, object]:
        data: dict[str, object] = {
            "id": self.id,
            "rule_id": self.rule_id,
            "category": self.category.value,
            "risk": self.risk.value,
            "title": self.title,
            "description": self.description,
            "path": self.path,
            "name": self.name,
            "is_dir": self.is_dir,
            "bytes": self.bytes,
            "bytes_human": human_bytes(self.bytes),
            "files": self.files,
            "mtime": self.mtime,
            "age_days": round(self.age_days_now, 1),
            "root": self.root,
            "tier": self.tier.value,
            "actionable": self.actionable,
            "default_selected": self.default_selected and self.actionable,
            "selectable": self.actionable and self.risk is not Risk.FORBIDDEN,
            "advisory": self.advisory,
            "members_total": self.members_total,
            "truncated": self.truncated,
            "extra": self.extra,
        }
        if include_members:
            data["members"] = [member.as_dict() for member in self.members]
        return data


@dataclass(slots=True)
class DirTotal:
    """Aggregated size of one directory, for the 'biggest folders' view."""

    path: str
    name: str
    bytes: int
    depth: int
    files: int = 0
    root: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "name": self.name,
            "bytes": self.bytes,
            "bytes_human": human_bytes(self.bytes),
            "depth": self.depth,
            "files": self.files,
            "root": self.root,
        }


@dataclass(slots=True)
class ScanStats:
    """Counters describing how much work the scan did."""

    roots: list[str] = field(default_factory=list)
    dirs_seen: int = 0
    files_seen: int = 0
    bytes_seen: int = 0
    symlinks_skipped: int = 0
    permission_errors: int = 0
    pruned_dirs: int = 0
    findings: int = 0
    actionable_bytes: int = 0
    safe_bytes: int = 0
    duplicate_groups: int = 0
    duplicate_bytes: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0
    truncated: bool = False

    @property
    def duration(self) -> float:
        if not self.started_at:
            return 0.0
        end = self.finished_at or time.time()
        return max(0.0, end - self.started_at)

    @property
    def entries_per_second(self) -> int:
        duration = self.duration
        if not duration:
            return 0
        return int((self.dirs_seen + self.files_seen) / duration)

    def as_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["bytes_seen_human"] = human_bytes(self.bytes_seen)
        data["actionable_bytes_human"] = human_bytes(self.actionable_bytes)
        data["safe_bytes_human"] = human_bytes(self.safe_bytes)
        data["duplicate_bytes_human"] = human_bytes(self.duplicate_bytes)
        data["duration_seconds"] = round(self.duration, 3)
        data["entries_per_second"] = self.entries_per_second
        return data


@dataclass(slots=True)
class MountInfo:
    """One mounted filesystem."""

    mountpoint: str
    device: str = ""
    fstype: str = ""
    total: int = 0
    used: int = 0
    free: int = 0
    percent: float = 0.0
    scanned: bool = False
    pseudo: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "mountpoint": self.mountpoint,
            "device": self.device,
            "fstype": self.fstype,
            "total": self.total,
            "used": self.used,
            "free": self.free,
            "percent": round(self.percent, 1),
            "total_human": human_bytes(self.total),
            "used_human": human_bytes(self.used),
            "free_human": human_bytes(self.free),
            "scanned": self.scanned,
            "pseudo": self.pseudo,
        }


@dataclass(slots=True)
class ScanResult:
    """Everything one scan produced."""

    job_id: str
    roots: list[Path]
    findings: list[Finding] = field(default_factory=list)
    dir_totals: list[DirTotal] = field(default_factory=list)
    mounts: list[MountInfo] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def findings_by_category(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.category.value, []).append(finding)
        return grouped

    def category_totals(self) -> list[dict[str, object]]:
        totals: dict[Category, dict[str, int]] = {}
        for finding in self.findings:
            bucket = totals.setdefault(finding.category, {"bytes": 0, "items": 0, "files": 0})
            bucket["bytes"] += finding.bytes
            bucket["items"] += 1
            bucket["files"] += finding.files
        from .rules import CATEGORY_META

        out = []
        for category, bucket in totals.items():
            meta = CATEGORY_META[category]
            out.append(
                {
                    "category": category.value,
                    "label": meta.label,
                    "icon": meta.icon,
                    "blurb": meta.blurb,
                    "order": meta.order,
                    **bucket,
                    "bytes_human": human_bytes(bucket["bytes"]),
                }
            )
        out.sort(key=lambda item: (item["order"], -int(item["bytes"])))
        return out

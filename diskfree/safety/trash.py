"""Reversible removal: platform trash, DiskFree quarantine, and the journal.

DiskFree never calls :func:`os.unlink` or :func:`shutil.rmtree` on user data as
part of a clean. It *moves* items into a trash location and records every move in
an append-only journal so the operation can be undone:

``freedesktop``
    Linux. Uses ``~/.local/share/Trash`` (or ``.trash-<uid>`` at the top of the
    volume the file lives on) so items also appear in the desktop's own Trash.
``macos``
    ``~/.Trash``, which Finder shows.
``quarantine``
    DiskFree's own store under the data directory. Always available, used on
    Windows and as the fallback everywhere else.

Permanent deletion exists but is opt-in at two levels: the process must be
started with ``DISKFREE_ALLOW_PERMANENT_DELETE=1`` **and** the request must ask
for it explicitly.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from ..config import SafetySettings
from ..util import count_tree, human_bytes, new_id, short_id

if TYPE_CHECKING:  # pragma: no cover
    from .policy import SafetyPolicy

JOURNAL_VERSION = 1
_SAFE_NAME_RE = frozenset('<>:"|?*\0')


# --------------------------------------------------------------------------
# Journal
# --------------------------------------------------------------------------


@dataclass(slots=True)
class JournalEntry:
    """One reversible removal."""

    id: str
    op_id: str
    timestamp: str
    path: str
    stored_path: str
    backend: str
    bytes: int
    is_dir: bool
    file_count: int = 1
    status: str = "trashed"  # trashed | restored | purged | failed
    finding_id: str | None = None
    rule_id: str | None = None
    category: str | None = None
    risk: str | None = None
    info_path: str | None = None
    note: str | None = None
    version: int = JOURNAL_VERSION

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, line: str) -> JournalEntry | None:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        known = set(cls.__slots__)  # type: ignore[attr-defined]
        payload = {key: value for key, value in data.items() if key in known}
        try:
            return cls(**payload)  # type: ignore[arg-type]
        except TypeError:
            return None

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class Journal:
    """Append-only JSONL journal with an in-memory index."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._entries: dict[str, JournalEntry] = {}
        self._order: list[str] = []
        self._loaded = False

    # -- persistence -----------------------------------------------------
    def load(self) -> None:
        with self._lock:
            self._entries.clear()
            self._order.clear()
            if not self.path.is_file():
                self._loaded = True
                return
            try:
                with self.path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        entry = JournalEntry.from_json(line.strip())
                        if entry is None:
                            continue
                        self._entries[entry.id] = entry
                        # A state change is appended as a new line with the same
                        # id; keep the ordering list free of duplicates.
                        if entry.id not in self._order:
                            self._order.append(entry.id)
            except OSError:
                pass
            self._loaded = True

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    def append(self, entry: JournalEntry) -> None:
        self._ensure_loaded()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = entry.to_json() + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            self._entries[entry.id] = entry
            if entry.id not in self._order:
                self._order.append(entry.id)

    def update(self, entry_id: str, **changes: object) -> JournalEntry | None:
        """Append a state change (restored/purged) as a new journal line."""

        self._ensure_loaded()
        with self._lock:
            existing = self._entries.get(entry_id)
        if existing is None:
            return None
        updated = JournalEntry(**{**asdict(existing), **changes})
        self.append(updated)
        return updated

    # -- queries ---------------------------------------------------------
    def entries(self) -> list[JournalEntry]:
        self._ensure_loaded()
        with self._lock:
            return [self._entries[key] for key in self._order if key in self._entries]

    def get(self, entry_id: str) -> JournalEntry | None:
        self._ensure_loaded()
        with self._lock:
            return self._entries.get(entry_id)

    def active(self) -> list[JournalEntry]:
        """Entries whose data is still sitting in a trash location."""

        return [e for e in self.entries() if e.status == "trashed"]

    def total_bytes(self) -> int:
        return sum(e.bytes for e in self.active())

    def recent(self, limit: int = 200, *, status: str | None = None) -> list[JournalEntry]:
        items = self.entries()
        if status:
            items = [e for e in items if e.status == status]
        return list(reversed(items))[:limit]


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


@dataclass(slots=True)
class QuarantineResult:
    """Outcome of moving one item."""

    path: str
    ok: bool
    bytes: int = 0
    entry: JournalEntry | None = None
    reason: str | None = None
    cross_device: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "ok": self.ok,
            "bytes": self.bytes,
            "reason": self.reason,
            "cross_device": self.cross_device,
            "entry_id": self.entry.id if self.entry else None,
            "stored_path": self.entry.stored_path if self.entry else None,
            "backend": self.entry.backend if self.entry else None,
        }


@dataclass(slots=True)
class OperationReport:
    """Aggregate outcome of a clean or restore operation.

    ``moved`` holds one result per path that was actually attempted (``ok`` says
    whether it worked); ``skipped`` holds paths refused before anything touched
    them. A failure therefore appears exactly once, in one of the two.
    """

    op_id: str
    mode: str
    started_at: str
    finished_at: str | None = None
    moved: list[QuarantineResult] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    bytes: int = 0
    error: str | None = None

    @property
    def ok_count(self) -> int:
        return sum(1 for item in self.moved if item.ok)

    @property
    def failed_count(self) -> int:
        return len(self.skipped) + sum(1 for item in self.moved if not item.ok)

    def as_dict(self) -> dict[str, object]:
        return {
            "op_id": self.op_id,
            "mode": self.mode,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "moved": [item.as_dict() for item in self.moved],
            "skipped": [{"path": p, "reason": r} for p, r in self.skipped],
            "bytes": self.bytes,
            "ok_count": self.ok_count,
            "failed_count": self.failed_count,
            "error": self.error,
        }


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _safe_component(name: str) -> str:
    cleaned = "".join("_" if char in _SAFE_NAME_RE or ord(char) < 32 else char for char in name)
    cleaned = cleaned.strip().strip(".")
    return cleaned or "item"


def _device_of(path: Path) -> int | None:
    try:
        return path.stat().st_dev
    except OSError:
        return None


def _free_bytes(path: Path) -> int | None:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return None
    return usage.free


# --------------------------------------------------------------------------
# TrashManager
# --------------------------------------------------------------------------


class TrashManager:
    """Moves data into a trash location and journals it for later restore."""

    def __init__(
        self,
        safety: SafetySettings | None = None,
        *,
        data_dir: Path | None = None,
        journal: Journal | None = None,
        home: Path | None = None,
        policy: SafetyPolicy | None = None,
    ) -> None:
        self.safety = safety or SafetySettings()
        # Optional second gate: the executor decides what to remove, but nothing
        # reaches the filesystem without the policy agreeing a second time.
        self.policy = policy
        self.home = (home or Path.home()).expanduser()
        self.data_dir = data_dir or (self.home / ".local" / "share" / "diskfree")
        self.quarantine_dir = Path(self.safety.quarantine_dir or (self.data_dir / "quarantine"))
        self.journal = journal or Journal(self.data_dir / "journal.jsonl")
        self._lock = threading.Lock()

    # -- backend selection ----------------------------------------------
    def backend_name(self) -> str:
        configured = (self.safety.trash_backend or "auto").lower()
        if configured in {"freedesktop", "macos", "quarantine"}:
            return configured
        if sys.platform == "darwin":
            return "macos"
        if sys.platform == "win32":
            return "quarantine"
        return "freedesktop"

    def trash_root_for(self, path: Path, backend: str) -> tuple[Path, Path | None]:
        """Return ``(files_dir, info_dir)`` for the trash that should hold ``path``."""

        if backend == "freedesktop":
            home_trash = Path(
                os.environ.get("XDG_DATA_HOME") or (self.home / ".local" / "share")
            ) / "Trash"
            device = _device_of(path)
            home_device = _device_of(self.home)
            if device is not None and home_device is not None and device != home_device:
                # Keep the move on-device: use the volume's own trash dir.
                mount = _mount_of(path)
                uid = os.getuid() if hasattr(os, "getuid") else 1000
                candidate = mount / f".trash-{uid}"
                if _writable(mount):
                    return candidate / "files", candidate / "info"
            return home_trash / "files", home_trash / "info"
        if backend == "macos":
            return self.home / ".Trash", None
        return self.quarantine_dir, None

    # -- core operation --------------------------------------------------
    def trash(
        self,
        path: Path,
        *,
        op_id: str,
        backend: str | None = None,
        finding_id: str | None = None,
        rule_id: str | None = None,
        category: str | None = None,
        risk: str | None = None,
        note: str | None = None,
        measured_bytes: int | None = None,
        measured_files: int | None = None,
    ) -> QuarantineResult:
        """Move ``path`` into a trash location and journal the move."""

        backend = backend or self.backend_name()
        source = Path(path)

        if not self.safety.allow_writes:
            return QuarantineResult(str(source), False, reason="DiskFree is read-only")

        try:
            if not source.exists():
                return QuarantineResult(str(source), False, reason="path no longer exists")
            if source.is_symlink():
                return QuarantineResult(str(source), False, reason="refusing to move a symlink")
        except OSError as exc:
            return QuarantineResult(str(source), False, reason=f"cannot inspect path: {exc}")

        if self.policy is not None:
            decision = self.policy.check(source, live=True)
            if not decision.allowed:
                return QuarantineResult(
                    str(source), False, reason=decision.reason or "blocked by safety policy"
                )

        is_dir = source.is_dir()
        if measured_bytes is None:
            if is_dir:
                measured_bytes, measured_files = count_tree(source)
            else:
                try:
                    measured_bytes = source.stat().st_size
                except OSError:
                    measured_bytes = 0
        if measured_files is None:
            measured_files = 1 if not is_dir else measured_files or 1

        # Enforce the quarantine ceiling before consuming more space.
        if self.safety.max_trash_bytes and self.journal.total_bytes() + measured_bytes > (
            self.safety.max_trash_bytes
        ):
            return QuarantineResult(
                str(source),
                False,
                bytes=measured_bytes,
                reason=(
                    "quarantine ceiling reached "
                    f"({human_bytes(self.safety.max_trash_bytes)}); restore or purge "
                    "earlier items first"
                ),
            )

        files_dir, info_dir = self.trash_root_for(source, backend)
        with self._lock:
            try:
                files_dir.mkdir(parents=True, exist_ok=True)
                os.chmod(files_dir, 0o700)
                if info_dir is not None:
                    info_dir.mkdir(parents=True, exist_ok=True)
                    os.chmod(info_dir, 0o700)
            except OSError as exc:
                # Fall back to DiskFree's own quarantine rather than failing.
                if backend != "quarantine":
                    files_dir, info_dir = self.quarantine_dir, None
                    try:
                        files_dir.mkdir(parents=True, exist_ok=True)
                    except OSError as exc2:
                        return QuarantineResult(
                            str(source), False, reason=f"cannot prepare trash directory: {exc2}"
                        )
                    backend = "quarantine"
                else:
                    return QuarantineResult(
                        str(source), False, reason=f"cannot prepare trash directory: {exc}"
                    )

            target, cross_device = self._unique_target(files_dir, source, measured_bytes)
            if cross_device:
                free = _free_bytes(files_dir.parent)
                if free is not None and free < measured_bytes * 1.05:
                    return QuarantineResult(
                        str(source),
                        False,
                        bytes=measured_bytes,
                        cross_device=True,
                        reason=(
                            "moving to trash would copy across devices and the "
                            f"destination has only {human_bytes(free)} free"
                        ),
                    )

            try:
                shutil.move(str(source), str(target))
            except OSError as exc:
                return QuarantineResult(
                    str(source), False, bytes=measured_bytes,
                    reason=f"move failed: {exc}", cross_device=cross_device,
                )

            info_path: Path | None = None
            if info_dir is not None:
                info_path = info_dir / f"{target.name}.trashinfo"
                try:
                    info_path.write_text(
                        "[Trash Info]\n"
                        f"Path={_percent_encode(str(source))}\n"
                        f"DeletionDate={datetime.now().astimezone().isoformat(timespec='seconds')}\n",
                        encoding="utf-8",
                    )
                except OSError:
                    info_path = None

        entry = JournalEntry(
            id=short_id(op_id, str(source), time.time_ns()),
            op_id=op_id,
            timestamp=_now(),
            path=str(source),
            stored_path=str(target),
            backend=backend,
            bytes=int(measured_bytes),
            is_dir=is_dir,
            file_count=int(measured_files or 1),
            status="trashed",
            finding_id=finding_id,
            rule_id=rule_id,
            category=category,
            risk=risk,
            info_path=str(info_path) if info_path else None,
            note=note,
        )
        self.journal.append(entry)
        return QuarantineResult(
            str(source), True, bytes=int(measured_bytes), entry=entry, cross_device=cross_device
        )

    def _unique_target(self, files_dir: Path, source: Path, size: int) -> tuple[Path, bool]:
        """Pick a collision-free destination and report whether it crosses devices."""

        stem = _safe_component(source.name)
        candidate = files_dir / stem
        counter = 1
        while candidate.exists():
            suffix = source.suffix if source.is_file() else ""
            base = stem[: -len(suffix)] if suffix and stem.endswith(suffix) else stem
            candidate = files_dir / f"{base}.{counter}{suffix}"
            counter += 1
            if counter > 10_000:
                candidate = files_dir / f"{stem}.{new_id('x')}"
                break
        cross_device = False
        source_dev = _device_of(source)
        target_dev = _device_of(files_dir)
        if source_dev is not None and target_dev is not None:
            cross_device = source_dev != target_dev
        return candidate, cross_device

    # -- undo ------------------------------------------------------------
    def restore(self, entry: JournalEntry) -> QuarantineResult:
        """Move one journalled item back to its original location."""

        stored = Path(entry.stored_path)
        destination = Path(entry.path)

        if entry.status != "trashed":
            return QuarantineResult(
                entry.path, False, bytes=entry.bytes, reason=f"already {entry.status}"
            )
        if not stored.exists():
            self.journal.update(entry.id, status="purged", note="stored copy no longer present")
            return QuarantineResult(
                entry.path, False, reason="the quarantined copy is gone; nothing to restore"
            )
        if destination.exists():
            return QuarantineResult(
                entry.path,
                False,
                bytes=entry.bytes,
                reason="something already exists at the original path; not overwriting",
            )
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(stored), str(destination))
        except OSError as exc:
            return QuarantineResult(entry.path, False, reason=f"restore failed: {exc}")

        if entry.info_path:
            try:
                Path(entry.info_path).unlink(missing_ok=True)
            except OSError:
                pass
        self.journal.update(entry.id, status="restored", note=None)
        return QuarantineResult(entry.path, True, bytes=entry.bytes, entry=entry)

    def purge(self, entry: JournalEntry) -> QuarantineResult:
        """Permanently delete a quarantined item. Requires the opt-in flag."""

        if not self.safety.allow_permanent_delete:
            return QuarantineResult(
                entry.path,
                False,
                reason=(
                    "permanent deletion is disabled; restart DiskFree with "
                    "DISKFREE_ALLOW_PERMANENT_DELETE=1 to enable it"
                ),
            )
        stored = Path(entry.stored_path)
        if not stored.exists():
            self.journal.update(entry.id, status="purged", note="already gone")
            return QuarantineResult(entry.path, True, bytes=0, entry=entry)
        # Never follow a symlink out of the quarantine.
        if not _inside_quarantine(stored, (self.quarantine_dir, self.home)):
            return QuarantineResult(
                entry.path, False, reason="refusing to purge a path outside a trash location"
            )
        try:
            if stored.is_dir() and not stored.is_symlink():
                shutil.rmtree(stored)
            else:
                stored.unlink()
        except OSError as exc:
            return QuarantineResult(entry.path, False, reason=f"purge failed: {exc}")
        if entry.info_path:
            try:
                Path(entry.info_path).unlink(missing_ok=True)
            except OSError:
                pass
        self.journal.update(entry.id, status="purged")
        return QuarantineResult(entry.path, True, bytes=entry.bytes, entry=entry)

    def delete_permanently(self, path: Path, *, op_id: str, **meta: object) -> QuarantineResult:
        """Hard delete, used only when the operator opted in at both levels."""

        if not self.safety.allow_permanent_delete:
            return QuarantineResult(
                str(path), False, reason="permanent deletion is disabled by configuration"
            )
        source = Path(path)
        if not source.exists():
            return QuarantineResult(str(source), False, reason="path no longer exists")
        if source.is_symlink():
            return QuarantineResult(str(source), False, reason="refusing to delete a symlink")
        if self.policy is not None:
            decision = self.policy.check(source, live=True)
            if not decision.allowed:
                return QuarantineResult(
                    str(source), False, reason=decision.reason or "blocked by safety policy"
                )
        if source.is_dir():
            size, files = count_tree(source)
        else:
            try:
                size, files = source.stat().st_size, 1
            except OSError:
                size, files = 0, 1
        try:
            if source.is_dir():
                shutil.rmtree(source)
            else:
                source.unlink()
        except OSError as exc:
            return QuarantineResult(str(source), False, reason=f"delete failed: {exc}")
        entry = JournalEntry(
            id=short_id(op_id, str(source), time.time_ns()),
            op_id=op_id,
            timestamp=_now(),
            path=str(source),
            stored_path="",
            backend="permanent",
            bytes=size,
            is_dir=source.is_dir(),
            file_count=files,
            status="purged",
            finding_id=str(meta.get("finding_id") or "") or None,
            rule_id=str(meta.get("rule_id") or "") or None,
            category=str(meta.get("category") or "") or None,
            risk=str(meta.get("risk") or "") or None,
            note="permanently deleted; cannot be restored",
        )
        self.journal.append(entry)
        return QuarantineResult(str(source), True, bytes=size, entry=entry)

    # -- reporting -------------------------------------------------------
    def status(self) -> dict[str, object]:
        active = self.journal.active()
        backend = self.backend_name()
        files_dir, info_dir = self.trash_root_for(self.home, backend)
        return {
            "backend": backend,
            "trash_dir": str(files_dir),
            "info_dir": str(info_dir) if info_dir else None,
            "quarantine_dir": str(self.quarantine_dir),
            "journal_path": str(self.journal.path),
            "allow_writes": self.safety.allow_writes,
            "allow_permanent_delete": self.safety.allow_permanent_delete,
            "items_in_trash": len(active),
            "bytes_in_trash": sum(e.bytes for e in active),
            "bytes_in_trash_human": human_bytes(sum(e.bytes for e in active)),
            "max_trash_bytes": self.safety.max_trash_bytes,
            "max_trash_bytes_human": human_bytes(self.safety.max_trash_bytes),
        }


def _mount_of(path: Path) -> Path:
    current = path.absolute()
    while True:
        try:
            if os.path.ismount(current):
                return current
        except OSError:
            return current
        parent = current.parent
        if parent == current:
            return current
        current = parent


def _writable(path: Path) -> bool:
    try:
        return os.access(path, os.W_OK)
    except OSError:
        return False


def _inside_quarantine(path: Path, roots: tuple[Path, ...] | list[Path]) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return any(
        resolved == root.resolve() or root.resolve() in resolved.parents
        for root in roots
        if root
    )


def _percent_encode(text: str) -> str:
    """Encode a path the way the freedesktop trash spec expects."""

    from urllib.parse import quote

    return quote(text, safe="/:")

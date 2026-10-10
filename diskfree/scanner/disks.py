"""Filesystem and mount enumeration."""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path

from ..util import usage_bytes
from .models import MountInfo

_PSEUDO_FS = frozenset(
    {
        "proc", "sysfs", "devpts", "devtmpfs", "cgroup", "cgroup2", "pstore",
        "securityfs", "debugfs", "tracefs", "configfs", "fusectl", "mqueue",
        "hugetlbfs", "binfmt_misc", "autofs", "bpf", "nsfs", "ramfs", "efivarfs",
        "rpc_pipefs", "selinuxfs", "fuse.gvfsd-fuse", "fuse.portal", "squashfs",
        "overlay", "aufs", "none", "tmpfs",
    }
)

_OCTAL_ESCAPES = re.compile(r"\\([0-7]{3})")


def _unescape_mount(text: str) -> str:
    return _OCTAL_ESCAPES.sub(lambda m: chr(int(m.group(1), 8)), text)


def _stat_mount(mountpoint: str) -> MountInfo | None:
    usage = usage_bytes(mountpoint)
    if usage is None:
        return None
    total, used, available = usage
    if total <= 0:
        return None
    return MountInfo(
        mountpoint=mountpoint,
        total=total,
        used=used,
        free=available,
        percent=(used / total * 100) if total else 0.0,
    )


def mounts_from_proc() -> list[MountInfo]:
    """Parse ``/proc/self/mounts`` on Linux; empty list elsewhere."""

    source = Path("/proc/self/mounts")
    if not source.is_file():
        return []
    seen: dict[str, MountInfo] = {}
    try:
        lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        fields = line.split()
        if len(fields) < 3:
            continue
        device, mountpoint, fstype = fields[0], _unescape_mount(fields[1]), fields[2]
        pseudo = fstype in _PSEUDO_FS
        info = _stat_mount(mountpoint)
        if info is None:
            continue
        info.device = device
        info.fstype = fstype
        info.pseudo = pseudo
        previous = seen.get(mountpoint)
        # Prefer a real filesystem over a bind/pseudo mount of the same path.
        if previous is None or (previous.pseudo and not pseudo):
            seen[mountpoint] = info
    return list(seen.values())


def enumerate_mounts(roots: list[Path] | None = None) -> list[MountInfo]:
    """Real filesystems plus the mounts holding the scanned roots."""

    found: dict[str, MountInfo] = {}
    for info in mounts_from_proc():
        found[info.mountpoint] = info

    candidates: list[Path] = list(roots or [])
    candidates.append(Path.home())
    if sys.platform == "win32":
        for letter in "CDEFG":
            drive = Path(f"{letter}:\\")
            if drive.exists():
                candidates.append(drive)
    else:
        candidates.append(Path("/"))
        for extra in ("/home", "/var", "/tmp", "/Volumes", "/media", "/mnt"):
            path = Path(extra)
            if path.is_dir():
                candidates.append(path)

    for candidate in candidates:
        try:
            resolved = str(candidate.resolve())
        except OSError:
            continue
        if resolved in found:
            continue
        info = _stat_mount(resolved)
        if info is None:
            continue
        try:
            info.fstype = _fstype_of(resolved)
        except OSError:
            info.fstype = ""
        found[resolved] = info

    out = list(found.values())
    out.sort(key=lambda item: (item.pseudo, item.mountpoint))
    return out


def _fstype_of(path: str) -> str:
    if sys.platform == "linux":
        try:
            with open("/proc/self/mounts", encoding="utf-8", errors="replace") as handle:
                best = ("", -1)
                for line in handle:
                    fields = line.split()
                    if len(fields) < 3:
                        continue
                    mountpoint = _unescape_mount(fields[1])
                    under_it = path == mountpoint or path.startswith(
                        mountpoint.rstrip("/") + "/"
                    )
                    if under_it and len(mountpoint) > best[1]:
                        best = (fields[2], len(mountpoint))
                return best[0]
        except OSError:
            return ""
    return ""


def disk_summary(path: str | os.PathLike[str] = "/") -> dict[str, object]:
    """Total/used/free for the filesystem holding ``path``."""

    target = os.fspath(path)
    try:
        usage = shutil.disk_usage(target)
    except OSError:
        try:
            usage = shutil.disk_usage(str(Path.home()))
        except OSError:
            return {"path": target, "total": 0, "used": 0, "free": 0, "percent": 0.0}
    percent = (usage.used / usage.total * 100) if usage.total else 0.0
    return {
        "path": target,
        "total": usage.total,
        "used": usage.used,
        "free": usage.free,
        "percent": round(percent, 1),
    }


def mark_scanned(mounts: list[MountInfo], roots: list[Path]) -> None:
    """Flag which mounts contain at least one scan root."""

    resolved_roots = []
    for root in roots:
        try:
            resolved_roots.append(str(root.resolve()))
        except OSError:
            continue
    for info in mounts:
        info.scanned = any(
            item == info.mountpoint or item.startswith(info.mountpoint.rstrip("/") + "/")
            for item in resolved_roots
        )

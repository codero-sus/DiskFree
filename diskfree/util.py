"""Small shared helpers (formatting, ids, bounded concurrency)."""

from __future__ import annotations

import hashlib
import os
import sys
import time
from collections.abc import Iterable, Sequence
from pathlib import Path

UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def human_bytes(value: float | int | None, digits: int = 1) -> str:
    """Format a byte count the way file managers do (binary units)."""

    if value is None:
        return "?"
    size = float(value)
    negative = size < 0
    size = abs(size)
    for unit in UNITS:
        if size < 1024 or unit == UNITS[-1]:
            text = f"{size:.{digits}f} {unit}" if unit != "B" else f"{int(size)} B"
            return f"-{text}" if negative else text
        size /= 1024
    return f"{size:.{digits}f} PB"


def human_duration(seconds: float | None) -> str:
    if seconds is None:
        return "?"
    seconds = max(0.0, float(seconds))
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def human_age(seconds: float | None) -> str:
    if seconds is None:
        return "unknown"
    days = seconds / 86400
    if days < 1:
        return f"{max(1, int(days * 24))} h"
    if days < 60:
        return f"{int(days)} d"
    years = days / 365.25
    if years < 1:
        return f"{int(days / 30.4)} mo"
    return f"{years:.1f} y"


def short_id(*parts: object, length: int = 12) -> str:
    """Stable, URL-safe identifier derived from the given parts."""

    digest = hashlib.blake2b(
        "\x1f".join(str(part) for part in parts).encode("utf-8", "replace"),
        digest_size=16,
    ).hexdigest()
    return digest[:length]


def new_id(prefix: str) -> str:
    return f"{prefix}_{int(time.time() * 1000):x}{os.urandom(3).hex()}"


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def unique_paths(paths: Iterable[str | os.PathLike[str]]) -> list[Path]:
    """De-duplicate and normalise paths while preserving order."""

    seen: set[str] = set()
    ordered: list[Path] = []
    for raw in paths:
        path = Path(os.fspath(raw)).expanduser()
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path.absolute()
        key = str(resolved).lower() if sys.platform in {"win32", "darwin"} else str(resolved)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(resolved)
    return ordered


def chunked(items: Sequence[object], size: int) -> Iterable[Sequence[object]]:
    for start in range(0, len(items), max(1, size)):
        yield items[start : start + max(1, size)]


def truncate(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def disk_usage(path: str | os.PathLike[str]) -> os.statvfs_result | None:
    """``os.statvfs`` wrapper that never raises on odd mount points."""

    try:
        return os.statvfs(os.fspath(path))
    except (OSError, AttributeError, ValueError):
        return None


def usage_bytes(path: str | os.PathLike[str]) -> tuple[int, int, int] | None:
    """Return ``(total, used, free)`` bytes for the filesystem holding ``path``."""

    try:
        usage = os.statvfs(os.fspath(path))
    except (OSError, AttributeError, ValueError):
        return None
    total = usage.f_blocks * usage.f_frsize
    free = usage.f_bfree * usage.f_frsize
    available = usage.f_bavail * usage.f_frsize
    used = max(0, total - free)
    return total, used, available


def count_tree(path: str | os.PathLike[str]) -> tuple[int, int]:
    """Return ``(bytes, file_count)`` for a directory without following symlinks.

    Iterative on purpose: recursive walks blow the stack on deep ``node_modules``
    trees and are slower than an explicit list used as a stack.
    """

    total = 0
    files = 0
    stack = [Path(os.fspath(path))]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                            continue
                        total += entry.stat(follow_symlinks=False).st_size
                        files += 1
                    except OSError:
                        continue
        except OSError:
            continue
    return total, files

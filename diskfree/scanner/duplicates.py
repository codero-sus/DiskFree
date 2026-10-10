"""Byte-exact duplicate detection.

Cheap first, exact last:

1. Group by size (free -- already collected during the walk).
2. Drop paths that are hard links to the same inode: removing one of them frees
   nothing, so proposing it would be a lie about reclaimed space.
3. Hash a small sample (head, middle, tail) to eliminate near-misses cheaply.
4. Fully hash whatever survives and only propose byte-identical groups.

Nothing is ever proposed on the strength of a partial hash, and a global byte
budget stops a pathological tree from turning a scan into hours of disk reads:
candidates that cannot be fully verified inside the budget are simply skipped.
"""

from __future__ import annotations

import hashlib
import os
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass

CHUNK = 1024 * 1024
SAMPLE_CHUNK = 64 * 1024
DEFAULT_FULL_HASH_BUDGET = 24 * 1024 * 1024 * 1024

Candidate = tuple[str, float]  # (path, mtime)
DuplicateItem = tuple[str, int, float]  # (path, size, mtime)
DuplicateGroup = tuple[DuplicateItem, list[DuplicateItem]]


@dataclass(slots=True)
class DuplicateStats:
    """Work performed by the duplicate pass."""

    candidates: int = 0
    size_groups: int = 0
    hashed_samples: int = 0
    hashed_full: int = 0
    bytes_hashed: int = 0
    hardlink_skips: int = 0
    unreadable: int = 0
    budget_exhausted: bool = False
    groups: int = 0
    reclaimable_bytes: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "candidates": self.candidates,
            "size_groups": self.size_groups,
            "hashed_samples": self.hashed_samples,
            "hashed_full": self.hashed_full,
            "bytes_hashed": self.bytes_hashed,
            "hardlink_skips": self.hardlink_skips,
            "unreadable": self.unreadable,
            "budget_exhausted": self.budget_exhausted,
            "groups": self.groups,
            "reclaimable_bytes": self.reclaimable_bytes,
        }


def _sample_digest(path: str, size: int) -> str | None:
    """Hash head, middle and tail. Cheap and rejects most near-duplicates."""

    digest = hashlib.blake2b(digest_size=16)
    offsets = [0]
    if size > SAMPLE_CHUNK * 2:
        offsets.append(max(0, size // 2))
        offsets.append(max(0, size - SAMPLE_CHUNK))
    try:
        with open(path, "rb", buffering=0) as handle:
            for offset in offsets:
                handle.seek(offset)
                block = handle.read(SAMPLE_CHUNK)
                if not block:
                    break
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def _full_digest(path: str, cancel: threading.Event | None) -> str | None:
    digest = hashlib.blake2b(digest_size=16)
    total = 0
    try:
        with open(path, "rb", buffering=0) as handle:
            while True:
                if cancel is not None and cancel.is_set():
                    return None
                block = handle.read(CHUNK)
                if not block:
                    break
                digest.update(block)
                total += len(block)
    except OSError:
        return None
    return f"{digest.hexdigest()}:{total}"


def _keep_score(item: DuplicateItem) -> tuple[float, int, str]:
    """Which copy to keep: oldest first, then shallowest, then alphabetical."""

    path, _size, mtime = item
    return (mtime, path.count(os.sep), path)


def find_duplicate_groups(
    pool: dict[int, list[Candidate]] | Iterable[tuple[int, list[Candidate]]],
    *,
    cancel: threading.Event | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    full_hash_budget: int = DEFAULT_FULL_HASH_BUDGET,
    stats: DuplicateStats | None = None,
) -> list[DuplicateGroup]:
    """Return ``(keeper, extras)`` groups of verified duplicates."""

    stats = stats or DuplicateStats()
    items = dict(pool) if not isinstance(pool, dict) else pool
    todo: list[tuple[int, list[Candidate]]] = [
        (size, candidates) for size, candidates in items.items() if len(candidates) > 1
    ]
    todo.sort(key=lambda pair: -(pair[0] * (len(pair[1]) - 1)))
    stats.candidates = sum(len(candidates) for _, candidates in todo)
    stats.size_groups = len(todo)

    total_work = max(1, sum(len(candidates) for _, candidates in todo))
    done = 0
    hashed_bytes = 0
    groups: list[DuplicateGroup] = []

    for size, candidates in todo:
        if cancel is not None and cancel.is_set():
            break

        # Hard links share an inode: deleting one frees nothing.
        by_inode: dict[tuple[int, int], Candidate] = {}
        unique: list[Candidate] = []
        for path, mtime in candidates:
            try:
                stat = os.stat(path, follow_symlinks=False)
            except OSError:
                stats.unreadable += 1
                continue
            key = (stat.st_dev, stat.st_ino)
            if key in by_inode:
                stats.hardlink_skips += 1
                continue
            by_inode[key] = (path, mtime)
            unique.append((path, mtime))
        if len(unique) < 2:
            done += len(candidates)
            continue

        # Stage 1: sampled digest.
        buckets: dict[str, list[Candidate]] = {}
        for path, mtime in unique:
            sample = _sample_digest(path, size)
            done += 1
            stats.hashed_samples += 1
            if on_progress is not None:
                on_progress(done, total_work)
            if sample is None:
                stats.unreadable += 1
                continue
            buckets.setdefault(sample, []).append((path, mtime))

        for bucket in buckets.values():
            if len(bucket) < 2:
                continue
            if cancel is not None and cancel.is_set():
                break

            # Stage 2: full digest, within the byte budget.
            verified: dict[str, list[DuplicateItem]] = {}
            for path, mtime in bucket:
                if hashed_bytes + size > full_hash_budget:
                    stats.budget_exhausted = True
                    continue
                full = _full_digest(path, cancel)
                if full is None:
                    stats.unreadable += 1
                    continue
                hashed_bytes += size
                stats.hashed_full += 1
                stats.bytes_hashed += size
                verified.setdefault(full, []).append((path, size, mtime))

            for members in verified.values():
                if len(members) < 2:
                    continue
                members.sort(key=_keep_score)
                keeper, *extras = members
                groups.append((keeper, extras))
                stats.groups += 1
                stats.reclaimable_bytes += size * len(extras)

    groups.sort(key=lambda group: -(group[0][1] * len(group[1])))
    return groups

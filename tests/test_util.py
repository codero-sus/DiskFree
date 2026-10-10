"""Formatting, identifiers and filesystem helpers.

These are the small functions the UI text, the journal and the scanner all lean
on, so their edge cases (``None``, negatives, missing paths, zero limits) matter
more than they look.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from diskfree.util import (
    chunked,
    clamp,
    count_tree,
    disk_usage,
    human_age,
    human_bytes,
    human_duration,
    new_id,
    short_id,
    truncate,
    unique_paths,
    usage_bytes,
)

KB = 1024
MB = 1024**2
GB = 1024**3


# --------------------------------------------------------------------------
# human_bytes
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0 B"),
        (1, "1 B"),
        (1023, "1023 B"),
        (KB, "1.0 KB"),
        (KB + KB // 2, "1.5 KB"),
        (MB, "1.0 MB"),
        (5 * MB, "5.0 MB"),
        (GB, "1.0 GB"),
        (1024**4, "1.0 TB"),
        (1024**5, "1.0 PB"),
        # PB is the last unit: bigger values stay in PB rather than inventing one.
        (1024**6, "1024.0 PB"),
        (None, "?"),
    ],
)
def test_human_bytes(value: int | None, expected: str) -> None:
    assert human_bytes(value) == expected


def test_human_bytes_honours_the_digit_count() -> None:
    assert human_bytes(KB + KB // 2, digits=0) == "2 KB"
    assert human_bytes(KB + KB // 2, digits=3) == "1.500 KB"
    # Bytes never carry a fraction: 1.5 B is meaningless.
    assert human_bytes(1536, digits=2) == "1.50 KB"
    assert human_bytes(1, digits=3) == "1 B"


def test_human_bytes_shows_negatives_as_negative() -> None:
    assert human_bytes(-MB) == "-1.0 MB"
    assert human_bytes(-1) == "-1 B"


def test_human_bytes_accepts_floats() -> None:
    assert human_bytes(1.5 * MB) == "1.5 MB"


# --------------------------------------------------------------------------
# human_duration / human_age
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (None, "?"),
        (-5, "0 ms"),
        (0, "0 ms"),
        (0.25, "250 ms"),
        (0.999, "999 ms"),
        (1, "1.0 s"),
        (12.34, "12.3 s"),
        (59.9, "59.9 s"),
        (60, "1m 0s"),
        (90, "1m 30s"),
        (3599, "59m 59s"),
        (3600, "1h 0m"),
        (7200 + 60 * 5, "2h 5m"),
    ],
)
def test_human_duration(seconds: float | None, expected: str) -> None:
    assert human_duration(seconds) == expected


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (None, "unknown"),
        (0, "1 h"),
        (3 * 3600, "3 h"),
        (86399, "23 h"),
        (86400, "1 d"),
        (86400 * 30, "30 d"),
        (86400 * 100, "3 mo"),
        (86400 * 400, "1.1 y"),
    ],
)
def test_human_age(seconds: float | None, expected: str) -> None:
    assert human_age(seconds) == expected


# --------------------------------------------------------------------------
# ids
# --------------------------------------------------------------------------


def test_short_id_is_stable_and_scoped() -> None:
    assert short_id("a", "b") == short_id("a", "b")
    assert short_id("a", "b") != short_id("b", "a")
    assert short_id("a", "b") != short_id("ab")
    assert len(short_id("x")) == 12
    assert len(short_id("x", length=6)) == 6
    assert short_id("x", length=64)  # never longer than the digest


def test_short_id_survives_odd_input() -> None:
    assert short_id(Path("/tmp/x"), 12, None, b"bytes")
    assert short_id("héllo wörld") == short_id("héllo wörld")


def test_new_id_is_prefixed_and_unique() -> None:
    first = new_id("plan")
    second = new_id("plan")
    assert first.startswith("plan_")
    assert second.startswith("plan_")
    assert first != second
    assert len({new_id("op") for _ in range(200)}) == 200


# --------------------------------------------------------------------------
# small numeric / sequence helpers
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "low", "high", "expected"),
    [
        (5, 0, 10, 5),
        (-1, 0, 10, 0),
        (11, 0, 10, 10),
        (0.5, 0.0, 1.0, 0.5),
        (2.0, 1.0, 1.0, 1.0),
    ],
)
def test_clamp(value: float, low: float, high: float, expected: float) -> None:
    assert clamp(value, low, high) == expected


def test_chunked_splits_without_losing_items() -> None:
    items = list(range(7))
    chunks = [list(chunk) for chunk in chunked(items, 3)]
    assert chunks == [[0, 1, 2], [3, 4, 5], [6]]
    assert [item for chunk in chunks for item in chunk] == items
    assert [list(chunk) for chunk in chunked(items, 10)] == [items]
    assert list(chunked([], 3)) == []


def test_chunked_never_loops_forever_on_a_bad_size() -> None:
    assert [list(chunk) for chunk in chunked(list(range(3)), 0)] == [[0], [1], [2]]
    assert [list(chunk) for chunk in chunked(list(range(2)), -5)] == [[0], [1]]


def test_truncate_marks_that_it_truncated() -> None:
    assert truncate("abc", 10) == "abc"
    assert truncate("abcdef", 6) == "abcdef"
    assert truncate("abcdef", 4) == "abc…"
    assert len(truncate("abcdef", 4)) == 4
    assert truncate("abcdef", 1) == "…"
    assert truncate("abcdef", 0) == "…"


# --------------------------------------------------------------------------
# paths
# --------------------------------------------------------------------------


def test_unique_paths_dedupes_and_normalises(tmp_path: Path) -> None:
    real = tmp_path / "data"
    real.mkdir()
    link = tmp_path / "link"
    os.symlink(real, link)

    result = unique_paths([str(real), real, str(link), str(real) + "/"])
    assert len(result) == 1
    assert result[0] == real.resolve()


def test_unique_paths_preserves_order_and_expands_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()

    result = unique_paths(["~/second", str(first)])
    assert result == [second.resolve(), first.resolve()]


def test_unique_paths_handles_an_empty_iterable() -> None:
    assert unique_paths([]) == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX semantics")
def test_unique_paths_reports_missing_paths_without_raising(tmp_path: Path) -> None:
    missing = tmp_path / "nope" / "deeper"
    assert unique_paths([str(missing)]) == [missing.resolve()]


# --------------------------------------------------------------------------
# filesystem probes
# --------------------------------------------------------------------------


def test_disk_usage_answers_for_a_real_path() -> None:
    usage = disk_usage("/")
    assert usage is not None
    assert usage.f_frsize > 0


def test_disk_usage_returns_none_for_a_bad_path() -> None:
    assert disk_usage("/proc/self/definitely-not-here") is None


def test_usage_bytes_reports_a_consistent_triple() -> None:
    triple = usage_bytes("/")
    assert triple is not None
    total, used, available = triple
    assert total > 0
    assert 0 <= used <= total
    assert 0 <= available <= total
    assert disk_usage("/proc/self/definitely-not-here") is None
    assert usage_bytes("/proc/self/definitely-not-here") is None


def test_count_tree_sums_files_without_following_symlinks(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"x" * 100)
    nested = tmp_path / "sub" / "deeper"
    nested.mkdir(parents=True)
    (nested / "b").write_bytes(b"y" * 50)
    empty = tmp_path / "empty"
    empty.mkdir()

    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"z" * 10_000)
    os.symlink(outside, tmp_path / "link-to-outside")
    os.symlink(tmp_path / "sub", tmp_path / "link-to-dir")

    total, files = count_tree(tmp_path)
    # Three regular files: a, sub/deeper/b and outside.bin (reached directly, not
    # through the link). Neither symlink is followed, so nothing is double counted
    # and a link loop cannot hang the walk.
    assert (total, files) == (100 + 50 + 10_000, 3)


def test_count_tree_is_safe_on_missing_and_empty_paths(tmp_path: Path) -> None:
    assert count_tree(tmp_path / "missing") == (0, 0)
    empty = tmp_path / "empty"
    empty.mkdir()
    assert count_tree(empty) == (0, 0)
    assert count_tree(tmp_path / "a-file.txt") == (0, 0)


def test_count_tree_is_iterative_enough_for_a_deep_tree(tmp_path: Path) -> None:
    """Recursive walks blow the stack on deep node_modules trees; this must not."""

    deep = tmp_path
    for index in range(400):
        deep = deep / f"d{index}"
    deep.mkdir(parents=True)
    (deep / "leaf").write_bytes(b"x" * 10)

    total, files = count_tree(tmp_path)
    assert (total, files) == (10, 1)

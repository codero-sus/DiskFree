"""Request schemas reject ambiguous or unbounded local filesystem input."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from diskfree.api.schemas import MAX_ROOT_CHARS, PlanRequest, ScanRequest
from diskfree.scanner.rules import Category


def test_scan_roots_are_normalized_and_deduplicated(tmp_path: Path) -> None:
    first = tmp_path / "data"
    alternate = tmp_path / "nested" / ".." / "data"

    request = ScanRequest(roots=[str(first), str(alternate), "", "   "])

    assert request.roots == [str(first)]


def test_scan_root_length_is_bounded() -> None:
    with pytest.raises(ValidationError, match="scan root exceeds"):
        ScanRequest(roots=["/" + "x" * MAX_ROOT_CHARS])


def test_scan_roots_reject_control_characters() -> None:
    with pytest.raises(ValidationError, match="control characters"):
        ScanRequest(roots=["/tmp/name\nwith-newline"])


def test_scan_categories_are_validated_and_deduplicated() -> None:
    category = Category.BROWSER_CACHE.value
    request = ScanRequest(categories=[category, category])

    assert request.categories == [category]
    with pytest.raises(ValidationError, match="unknown scan category"):
        ScanRequest(categories=["not-a-real-category"])


def test_plan_finding_ids_are_deduplicated() -> None:
    request = PlanRequest(finding_ids=["finding_a", "finding_a", "finding_b"])

    assert request.finding_ids == ["finding_a", "finding_b"]


def test_plan_finding_ids_have_a_per_item_length_limit() -> None:
    with pytest.raises(ValidationError):
        PlanRequest(finding_ids=["x" * 161])

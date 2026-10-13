"""Scanner behaviour on a synthetic home: what it reports, and what it refuses to."""

from __future__ import annotations

import os
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from diskfree.safety.policy import Risk, Tier
from diskfree.scanner.engine import Scanner, ScanOptions, ScanProgress
from diskfree.scanner.models import ScanResult
from tests.conftest import MB, FakeHome, _write


def by_rule(result: ScanResult, rule_id: str):
    return [finding for finding in result.findings if finding.rule_id == rule_id]


def one(result: ScanResult, rule_id: str):
    matches = by_rule(result, rule_id)
    assert len(matches) == 1, f"{rule_id}: expected 1 finding, got {len(matches)}"
    return matches[0]


def test_scan_produces_findings_for_every_cache_family(scan_result: ScanResult) -> None:
    assert scan_result.findings, "expected findings from the synthetic home"
    for rule_id in ("pkg-pip-cache", "pkg-uv-cache", "pkg-npm-cache", "pkg-cargo-cache",
                    "app-thumbnails", "trash-freedesktop", "build-node-modules",
                    "build-python-caches", "build-target-cargo", "browser-cache-dirs"):
        assert by_rule(scan_result, rule_id), f"missing finding for {rule_id}"


def test_package_caches_are_safe_and_pre_selected(scan_result: ScanResult) -> None:
    finding = one(scan_result, "pkg-pip-cache")
    assert finding.risk is Risk.SAFE
    assert finding.tier is Tier.NORMAL
    assert finding.default_selected is True
    assert finding.actionable is True
    assert finding.bytes >= 6 * MB
    assert finding.files >= 3


def test_only_safe_actionable_findings_are_pre_selected(scan_result: ScanResult) -> None:
    for finding in scan_result.findings:
        if finding.default_selected:
            assert finding.risk is Risk.SAFE, finding.rule_id
            assert finding.actionable, finding.rule_id
            assert finding.tier is not Tier.BLOCKED, finding.rule_id


def test_pruned_directory_yields_exactly_one_finding(
    scan_result: ScanResult, fake_home: FakeHome
) -> None:
    """node_modules is one finding; its 60 000 files are never walked."""

    finding = one(scan_result, "build-node-modules")
    assert finding.is_dir is True
    assert finding.files >= 1
    inside = str(fake_home["node_modules"]) + os.sep
    leaked = [f.path for f in scan_result.findings if f.path.startswith(inside)]
    assert not leaked, leaked


def test_version_control_is_never_reported(scan_result: ScanResult, fake_home: FakeHome) -> None:
    git_root = str(fake_home["git_dir"])
    assert not [finding for finding in scan_result.findings if finding.path.startswith(git_root)]
    assert scan_result.stats.pruned_dirs >= 1


def test_credential_directories_are_never_reported(
    scan_result: ScanResult, fake_home: FakeHome
) -> None:
    ssh = str(fake_home.root / ".ssh")
    assert not [finding for finding in scan_result.findings if finding.path.startswith(ssh)]


def test_symlinks_are_never_followed_or_reported(
    scan_result: ScanResult, fake_home: FakeHome
) -> None:
    assert scan_result.stats.symlinks_skipped >= 1
    assert not [
        finding for finding in scan_result.findings if finding.path == str(fake_home["symlink"])
    ]
    # The target of the link is untouched and reported only where it really lives.
    assert fake_home["symlink_target"].exists()


def test_duplicates_keep_the_oldest_copy(scan_result: ScanResult, fake_home: FakeHome) -> None:
    """Each redundant copy is its own finding, pointing at the copy that stays."""

    extras = by_rule(scan_result, "duplicates")
    assert extras, "expected a duplicate finding"
    paths = {finding.path for finding in extras}
    assert str(fake_home["dup_copy"]) in paths, "the newer copy is the one to offer"
    assert str(fake_home["dup_original"]) not in paths, "the older copy must be kept"
    finding = next(f for f in extras if f.path == str(fake_home["dup_copy"]))
    assert finding.extra["duplicate_of"] == str(fake_home["dup_original"])
    assert finding.actionable is True
    # The redundant copy sits in ~/Downloads, a personal folder, so the policy
    # raises the rule's MEDIUM to HIGH: reversible, but never a casual click.
    assert finding.risk is Risk.HIGH
    assert finding.tier is Tier.SENSITIVE
    assert "downloads" in (finding.extra.get("tier_reason") or "").lower()
    assert finding.default_selected is False
    assert finding.bytes > 0
    assert scan_result.stats.duplicate_bytes >= finding.bytes
    assert scan_result.stats.duplicate_groups >= 1


def test_hard_links_are_not_reported_as_duplicates(
    scan_result: ScanResult, fake_home: FakeHome
) -> None:
    """Two names for one inode free nothing; offering them wastes the user's trust."""

    reported = {finding.path for finding in scan_result.findings}
    reported |= {member.path for finding in scan_result.findings for member in finding.members}
    assert str(fake_home["hardlink_copy"]) not in reported
    assert str(fake_home["hardlink_source"]) not in reported


def test_large_files_are_high_risk_and_user_review_only(
    scan_result: ScanResult, fake_home: FakeHome
) -> None:
    findings = by_rule(scan_result, "large-files")
    assert findings, "the 900 MB video should be reported"
    finding = next(f for f in findings if f.path == str(fake_home["big_file"]))
    assert finding.actionable is True, "the user may explicitly choose a scanned file"
    assert finding.as_dict()["selectable"] is True
    assert finding.default_selected is False
    assert finding.risk is Risk.HIGH
    assert finding.extra.get("user_review_only") is True


def test_old_downloads_are_high_risk_and_unselected(
    scan_result: ScanResult, fake_home: FakeHome
) -> None:
    """Aggregated at ~/Downloads, but the folder itself is never the target."""

    finding = one(scan_result, "old-downloads")
    assert finding.path == str(fake_home["downloads"])
    assert finding.extra.get("aggregated") is True
    assert [member.path for member in finding.members] == [str(fake_home["old_download"])]
    assert str(fake_home["new_download"]) not in [m.path for m in finding.members]
    assert finding.risk is Risk.HIGH
    assert finding.default_selected is False
    assert finding.actionable is True


def test_logs_are_aggregated_per_directory(
    scan_result: ScanResult, fake_home: FakeHome
) -> None:
    findings = by_rule(scan_result, "log-files")
    assert findings
    grouped = findings[0]
    assert grouped.path == str(fake_home["logs"])
    assert grouped.files >= 1
    assert grouped.members, "an aggregate must show what it contains"
    assert grouped.members_total >= len(grouped.members)


def test_unknown_cache_children_are_reported_individually(
    scan_result: ScanResult, fake_home: FakeHome
) -> None:
    assert by_rule(scan_result, "app-cache-xdg-children"), (
        "an unrecognised app cache under ~/.cache should still be found"
    )


def test_a_hostile_directory_name_changes_nothing(
    scan_result: ScanResult, fake_home: FakeHome
) -> None:
    """Prompt injection in a file name must not widen what DiskFree will delete."""

    hostile = str(fake_home["hostile_dir"])
    matches = [finding for finding in scan_result.findings if finding.path == hostile]
    assert matches, "the hostile directory is ordinary cache and should be reported"
    finding = matches[0]
    from diskfree.scanner.rules import DEFAULT_RULES

    titles = {rule.id: rule.title for rule in DEFAULT_RULES}
    assert finding.risk is Risk.SAFE  # same as any other ~/.cache child
    assert finding.title == titles[finding.rule_id], "a file name must not rewrite the title"
    assert "IGNORE" not in finding.description
    assert "IGNORE" not in finding.title
    # Documents must still be there and still be untouched by the scan.
    assert fake_home["documents"].exists()
    documents = [f for f in scan_result.findings if f.path == str(fake_home["documents"])]
    assert not documents or documents[0].actionable is False


def test_statistics_are_internally_consistent(scan_result: ScanResult) -> None:
    stats = scan_result.stats
    actionable = sum(f.bytes for f in scan_result.findings if f.actionable)
    safe = sum(f.bytes for f in scan_result.findings if f.risk is Risk.SAFE and f.actionable)
    assert stats.actionable_bytes == actionable
    assert stats.safe_bytes == safe
    assert stats.findings == len(scan_result.findings)
    assert stats.bytes_seen >= stats.actionable_bytes
    assert stats.files_seen > 0
    assert stats.dirs_seen > 0
    assert stats.finished_at >= stats.started_at
    assert stats.entries_per_second >= 0


def test_directory_totals_include_pruned_subtrees(
    scan_result: ScanResult, fake_home: FakeHome
) -> None:
    totals = {total.path: total for total in scan_result.dir_totals}
    assert str(fake_home.root) in totals
    node_modules = str(fake_home["node_modules"])
    assert node_modules in totals, "a pruned directory must still be sized"
    assert totals[node_modules].bytes > 0


def test_scanning_the_home_root_does_not_escape_it(
    scanner: Scanner, fake_home: FakeHome
) -> None:
    result = scanner.run(ScanOptions(roots=[fake_home.root], temp_min_age_days=10**6))
    for finding in result.findings:
        path = Path(finding.path)
        if finding.extra.get("probe"):
            continue
        assert str(path).startswith(str(fake_home.root)), finding.path


def test_scan_can_be_cancelled(scanner: Scanner, fake_home: FakeHome) -> None:
    cancel = threading.Event()
    cancel.set()
    cancellable = Scanner(scanner.settings, policy=scanner.policy, home=fake_home.root,
                          cancel=cancel)
    result = cancellable.run(ScanOptions(roots=[fake_home.root], temp_min_age_days=10**6))
    assert result.findings == []
    assert result.stats.dirs_seen == 0


def test_progress_callback_reports_phases(
    settings, policy: object, fake_home: FakeHome
) -> None:
    seen: list[ScanProgress] = []
    scanner = Scanner(settings, policy=policy, home=fake_home.root,
                      on_progress=lambda progress: seen.append(replace(progress)))
    scanner.run(ScanOptions(roots=[fake_home.root], temp_min_age_days=10**6))
    phases = {progress.phase for progress in seen}
    assert "scanning" in phases
    assert seen[-1].phase == "done", phases
    assert all(progress.message or progress.phase for progress in seen)


def test_thresholds_change_what_is_reported(scanner: Scanner, fake_home: FakeHome) -> None:
    base = ScanOptions(roots=[fake_home.root], temp_min_age_days=10**6)
    everything = scanner.run(base)

    strict = scanner.run(replace(base, min_finding_bytes=100 * MB))
    assert len(strict.findings) < len(everything.findings)
    # Duplicates and large files have their own thresholds; the byte floor
    # governs what the walk reports.
    computed = {"duplicates", "large-files"}
    walked = [
        finding for finding in strict.findings
        if finding.rule_id not in computed and not finding.extra.get("probe")
    ]
    assert all(finding.bytes >= 100 * MB for finding in walked), [
        (f.rule_id, f.bytes) for f in walked
    ]

    no_duplicates = scanner.run(replace(base, find_duplicates=False))
    assert not by_rule(no_duplicates, "duplicate-files")

    no_large = scanner.run(replace(base, find_large_files=False))
    assert not by_rule(no_large, "large-files")

    no_advisories = scanner.run(replace(base, include_advisories=False))
    assert not [finding for finding in no_advisories.findings if finding.extra.get("probe")]
    assert by_rule(no_advisories, "pkg-pip-cache"), "real findings must survive"


def test_category_and_rule_filters(scanner: Scanner, fake_home: FakeHome) -> None:
    base = ScanOptions(roots=[fake_home.root], temp_min_age_days=10**6)
    caches = scanner.run(
        replace(base, categories=("package_cache", "app_cache"), include_advisories=False)
    )
    assert caches.findings
    assert {finding.category.value for finding in caches.findings} <= {
        "package_cache", "app_cache"
    }
    assert by_rule(caches, "pkg-pip-cache")
    assert not by_rule(caches, "build-node-modules")

    only_pip = scanner.run(
        replace(base, rule_ids=("pkg-pip-cache",), include_advisories=False)
    )
    assert {finding.rule_id for finding in only_pip.findings} == {"pkg-pip-cache"}


def test_findings_are_capped(scanner: Scanner, tmp_path: Path) -> None:
    root = tmp_path / "many"
    for index in range(40):
        _write(root / f"proj{index}/__pycache__/mod.pyc", 2048, age_days=1)
    result = scanner.run(ScanOptions(roots=[root], max_findings=5, temp_min_age_days=10**6))
    assert len(result.findings) <= 5
    assert result.stats.truncated is True
    assert any("cap" in warning.lower() for warning in result.warnings), result.warnings


def test_depth_limit_is_respected(scanner: Scanner, tmp_path: Path) -> None:
    deep = tmp_path / "deep"
    path = deep
    for index in range(12):
        path = path / f"level{index}"
    _write(path / "__pycache__" / "mod.pyc", 2048, age_days=1)

    shallow = scanner.run(ScanOptions(roots=[deep], max_depth=3, temp_min_age_days=10**6))
    assert not by_rule(shallow, "build-python-caches")
    full = scanner.run(ScanOptions(roots=[deep], max_depth=24, temp_min_age_days=10**6))
    assert by_rule(full, "build-python-caches")


def test_unreadable_directories_are_counted_not_fatal(scanner: Scanner, tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores permission bits")
    root = tmp_path / "mixed"
    _write(root / "proj/__pycache__/mod.pyc", 2048, age_days=1)
    locked = root / "locked"
    _write(locked / "__pycache__" / "mod.pyc", 2048, age_days=1)
    os.chmod(locked, 0o000)
    try:
        result = scanner.run(ScanOptions(roots=[root], temp_min_age_days=10**6))
        assert result.stats.permission_errors >= 1
        assert by_rule(result, "build-python-caches"), "the readable half must still be scanned"
        assert result.errors or result.warnings or result.stats.permission_errors
    finally:
        os.chmod(locked, 0o755)


def test_multiple_roots_are_all_scanned(scanner: Scanner, tmp_path: Path) -> None:
    first = tmp_path / "one"
    second = tmp_path / "two"
    _write(first / "proj/__pycache__/a.pyc", 2048, age_days=1)
    _write(second / "proj/__pycache__/b.pyc", 2048, age_days=1)
    result = scanner.run(
        ScanOptions(roots=[first, second], temp_min_age_days=10**6)
    )
    roots = {Path(finding.root) for finding in result.findings if finding.root}
    assert roots == {first, second}
    assert set(result.stats.roots) == {str(first), str(second)}


def test_missing_root_is_reported_not_raised(scanner: Scanner, tmp_path: Path) -> None:
    result = scanner.run(
        ScanOptions(roots=[tmp_path / "nope"], temp_min_age_days=10**6,
                    include_advisories=False)
    )
    assert result.findings == []
    assert result.errors or result.warnings


def test_empty_directory_yields_no_findings(scanner: Scanner, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    result = scanner.run(
        ScanOptions(roots=[empty], temp_min_age_days=10**6, include_advisories=False)
    )
    assert result.findings == []
    assert result.stats.dirs_seen >= 1


def test_scan_is_deterministic(scanner: Scanner, scan_options: ScanOptions) -> None:
    first = scanner.run(scan_options)
    second = scanner.run(scan_options)
    assert [f.id for f in first.findings] == [f.id for f in second.findings]
    assert first.stats.actionable_bytes == second.stats.actionable_bytes


def test_finding_ids_are_stable_and_unique(scan_result: ScanResult) -> None:
    ids = [finding.id for finding in scan_result.findings]
    assert len(ids) == len(set(ids))
    assert all(len(finding.id) >= 8 for finding in scan_result.findings)


def test_scan_result_serialises(scan_result: ScanResult) -> None:
    payload = scan_result.as_dict() if hasattr(scan_result, "as_dict") else None
    if payload is None:
        pytest.skip("ScanResult exposes no as_dict")
    assert payload["stats"]["findings"] == len(scan_result.findings)


def test_recent_files_are_left_alone(scanner: Scanner, tmp_path: Path) -> None:
    """A cache written seconds ago may belong to a running application."""

    root = tmp_path / "fresh"
    _write(root / "proj/logs/app.log", 2 * MB, age_days=0)
    result = scanner.run(ScanOptions(roots=[root], temp_min_age_days=10**6))
    assert not by_rule(result, "log-files")

    _write(root / "proj/logs/app.log", 2 * MB, age_days=30)
    aged = scanner.run(ScanOptions(roots=[root], temp_min_age_days=10**6))
    assert by_rule(aged, "log-files")


def test_user_age_overrides_apply(scanner: Scanner, fake_home: FakeHome) -> None:
    base = ScanOptions(roots=[fake_home.root], temp_min_age_days=10**6)
    default_run = scanner.run(base)
    assert by_rule(default_run, "old-downloads")

    never_old = scanner.run(replace(base, old_file_min_age_days=10**6))
    assert not by_rule(never_old, "old-downloads")

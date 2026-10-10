"""The safety policy is the reason DiskFree can be trusted with a filesystem.

These tests are deliberately adversarial: they assert that credential stores,
version control metadata, personal folders, mount points and DiskFree's own
journals are refused, and that the one narrow exception (a cache-looking
directory inside a protected home area) does not leak into a deletion.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from diskfree.config import SafetySettings
from diskfree.safety.policy import (
    Decision,
    Risk,
    SafetyPolicy,
    Tier,
    clamp_risk,
    is_cache_component,
    max_risk,
    normalise,
)
from tests.conftest import FakeHome


def test_filesystem_root_is_never_removable(policy: SafetyPolicy) -> None:
    assert policy.classify("/").tier is Tier.BLOCKED
    assert policy.check("/").allowed is False


@pytest.mark.parametrize(
    "path",
    ["/usr/bin/python3", "/etc/passwd", "/var/lib/docker", "/proc/self/mounts",
     "/sys/class/net", "/boot/vmlinuz", "/sbin/init", "/lib/x86_64-linux-gnu/libc.so.6"],
)
def test_system_locations_are_blocked(policy: SafetyPolicy, path: str) -> None:
    decision = policy.check(path)
    assert decision.allowed is False, path
    assert decision.tier is Tier.BLOCKED


@pytest.mark.parametrize(
    "path",
    ["/var/log/app.log", "/var/cache/apt/archives/x.deb", "/var/tmp/scratch"],
)
def test_writable_var_areas_are_not_hard_blocked(policy: SafetyPolicy, path: str) -> None:
    """/var/log and /var/cache are cleanable with the right tool, unlike /var/lib."""

    assert policy.classify(path).tier is not Tier.BLOCKED


def test_credential_stores_are_blocked_wherever_they_live(
    policy: SafetyPolicy, fake_home: FakeHome
) -> None:
    root = fake_home.root
    for relative in (".ssh/id_rsa", ".ssh/known_hosts", ".gnupg/pubring.kbx",
                     ".git/config", ".aws/credentials", "projects/app/.git/objects/00/blob"):
        decision = policy.check(root / relative)
        assert decision.allowed is False, relative
        assert decision.tier is Tier.BLOCKED


def test_secret_file_names_are_blocked_by_pattern(
    policy: SafetyPolicy, fake_home: FakeHome
) -> None:
    root = fake_home.root
    for relative in ("secrets.env", ".env.production", "server.pem", "wallet.key",
                     "keystore.jks", "id_ed25519", ".npmrc", ".git-credentials"):
        assert policy.check(root / relative).allowed is False, relative


def test_personal_folders_are_sensitive_not_removable_by_default(
    policy: SafetyPolicy, fake_home: FakeHome
) -> None:
    for key in ("documents", "old_download"):
        info = policy.classify(fake_home[key])
        assert info.tier is Tier.SENSITIVE, key
        assert info.zone_escape is False


def test_caches_are_normal_tier(policy: SafetyPolicy, fake_home: FakeHome) -> None:
    for key in ("pip_cache", "npm_cache", "thumbnails", "pip_wheel_0"):
        info = policy.classify(fake_home[key])
        assert info.tier is Tier.NORMAL, f"{key} -> {info.tier} ({info.reason})"


def test_browser_cache_inside_protected_config_uses_the_zone_escape(
    policy: SafetyPolicy, fake_home: FakeHome
) -> None:
    """~/.config is protected, but Chrome's Cache directory inside it is not.

    The escape downgrades to SENSITIVE (never NORMAL), so the risk floor still
    rises and the item can never be silently treated as ordinary.
    """

    info = policy.classify(fake_home["chrome_cache"])
    assert info.tier is Tier.SENSITIVE
    assert info.zone_escape is True
    assert "cache" in (info.reason or "").lower()


def test_protected_config_itself_stays_blocked(policy: SafetyPolicy, fake_home: FakeHome) -> None:
    config = fake_home.root / ".config" / "some-app" / "settings.json"
    assert policy.classify(config).tier is Tier.BLOCKED


def test_diskfree_protects_itself(policy: SafetyPolicy, data_dir: Path) -> None:
    import diskfree

    package = Path(diskfree.__file__).resolve()
    assert policy.check(data_dir / "journal.jsonl").allowed is False
    assert policy.check(data_dir / "quarantine" / "anything").allowed is False
    assert policy.check(package).allowed is False
    assert policy.check(package.parent / "safety" / "policy.py").allowed is False


def test_extra_protected_paths_from_settings(fake_home: FakeHome) -> None:
    safety = SafetySettings(extra_protected_paths=[str(fake_home.root / "keep")])
    policy = SafetyPolicy(safety, home=fake_home.root)
    assert policy.check(fake_home.root / "keep" / "important.txt").allowed is False


def test_live_check_rejects_symlinks(policy: SafetyPolicy, fake_home: FakeHome) -> None:
    assert fake_home["symlink"].is_symlink()
    decision = policy.check(fake_home["symlink"], live=True)
    assert decision.allowed is False
    assert "symlink" in (decision.reason or "").lower()


def test_live_check_rejects_mount_points(
    policy: SafetyPolicy, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deleting a mount point unmounts a device for the user; never allowed."""

    target = tmp_path / "pretend-mount"
    target.mkdir()
    real_ismount = os.path.ismount
    monkeypatch.setattr(
        "diskfree.safety.policy.os.path.ismount",
        lambda candidate: Path(candidate) == target or real_ismount(candidate),
    )
    decision = policy.check(target, live=True)
    assert decision.allowed is False
    assert "mount" in (decision.reason or "").lower()
    assert SafetyPolicy.mount_point_of(target) == target


def test_live_check_rejects_missing_paths(policy: SafetyPolicy, fake_home: FakeHome) -> None:
    decision = policy.check(fake_home.root / "does-not-exist", live=True)
    assert decision.allowed is False


def test_descent_blocking_is_narrower_than_tier_blocking(
    policy: SafetyPolicy, fake_home: FakeHome
) -> None:
    """~/.config must stay walkable or Chrome's cache would never be found."""

    config = fake_home.root / ".config"
    blocked, _ = policy.descent_blocked(config)
    assert blocked is False
    assert policy.classify(config / "google-chrome").tier is not Tier.NORMAL

    for protected in (".git", ".ssh"):
        blocked, reason = policy.descent_blocked(fake_home.root / protected)
        assert blocked is True, protected
        assert reason


def test_literal_descent_check_matches_the_realpath_version(
    policy: SafetyPolicy, fake_home: FakeHome
) -> None:
    cases = [
        (str(fake_home.root / ".git"), True),
        (str(fake_home.root / ".ssh"), True),
        ("/usr/share/doc", True),
        (str(fake_home.root / ".config/google-chrome"), False),
        (str(fake_home.root / "projects/app/node_modules"), False),
    ]
    for path, expected in cases:
        assert policy.literal_descent_blocked(path)[0] is expected, path


def test_filter_removable_splits_allowed_and_refused(
    policy: SafetyPolicy, fake_home: FakeHome
) -> None:
    paths = [
        fake_home["pip_cache"],
        fake_home["ssh_key"],
        fake_home["documents"],
        Path("/etc/passwd"),
    ]
    allowed, rejected = policy.filter_removable(paths, [fake_home.root])
    # SENSITIVE items stay removable when the user explicitly selected them;
    # only BLOCKED paths are refused outright.
    assert allowed == [fake_home["pip_cache"], fake_home["documents"]]
    reasons = dict(rejected)
    assert reasons[Path("/etc/passwd")] == "outside the scanned roots"
    assert "credential" in reasons[fake_home["ssh_key"]]
    assert len(rejected) == 2


def test_paths_outside_the_scan_roots_are_refused(
    policy: SafetyPolicy, fake_home: FakeHome
) -> None:
    assert policy.is_within_roots("/etc/passwd", [fake_home.root]) is False
    assert policy.is_within_roots(fake_home["pip_cache"], [fake_home.root]) is True


def test_risk_floor_can_only_go_up(policy: SafetyPolicy, fake_home: FakeHome) -> None:
    assert policy.risk_for(fake_home["documents"], Risk.SAFE) is Risk.HIGH
    assert policy.risk_for(fake_home["ssh_key"], Risk.SAFE) is Risk.FORBIDDEN
    assert policy.risk_for(fake_home["pip_cache"], Risk.MEDIUM) is Risk.MEDIUM


def test_clamp_risk_keeps_the_stricter_value() -> None:
    assert clamp_risk(Risk.MEDIUM, "safe") is Risk.MEDIUM
    assert clamp_risk(Risk.SAFE, "high") is Risk.HIGH
    assert clamp_risk(Risk.LOW, None) is Risk.LOW
    assert clamp_risk(Risk.SAFE, "nonsense") is Risk.SAFE
    assert clamp_risk(Risk.FORBIDDEN, "safe") is Risk.FORBIDDEN
    assert max_risk([Risk.LOW, Risk.HIGH, Risk.SAFE]) is Risk.HIGH


def test_risk_ordering_and_auto_selection() -> None:
    assert Risk.SAFE.rank < Risk.LOW.rank < Risk.MEDIUM.rank < Risk.HIGH.rank
    assert Risk.HIGH.rank < Risk.FORBIDDEN.rank
    assert Risk.SAFE.auto_selectable is True
    assert all(not risk.auto_selectable for risk in Risk if risk is not Risk.SAFE)


@pytest.mark.parametrize(
    "name,expected",
    [("Cache", True), ("cache2", True), ("GPUCache", True), ("Code Cache", True),
     ("__pycache__", False), ("node_modules", False), ("Documents", False),
     ("Thumbnail Cache", True), ("Service Worker", True), ("logs", True)],
)
def test_cache_component_detection(name: str, expected: bool) -> None:
    assert is_cache_component(name) is expected


def test_normalise_is_stable() -> None:
    assert normalise("/a/b/../c") in {"/a/c", str(Path("/a/c"))}
    assert normalise(Path("/tmp/x")) == normalise("/tmp/x")


def test_policy_check_returns_a_serialisable_decision(
    policy: SafetyPolicy, fake_home: FakeHome
) -> None:
    decision = policy.check(fake_home["pip_cache"])
    assert isinstance(decision, Decision)
    payload = decision.as_dict()
    assert payload["allowed"] is True
    assert payload["tier"] == "normal"

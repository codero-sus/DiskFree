"""Rule matching: the knowledge base that decides what counts as junk."""

from __future__ import annotations

from pathlib import Path

import pytest

from diskfree.safety.policy import Risk
from diskfree.scanner.rules import (
    CATEGORY_META,
    DEFAULT_RULES,
    AggregateMode,
    Category,
    RuleSet,
    expand_templates,
    fold_name,
)
from tests.conftest import FakeHome


@pytest.fixture
def ruleset(fake_home: FakeHome) -> RuleSet:
    return RuleSet(home=fake_home.root)


def make_matcher(ruleset: RuleSet):
    """Bind the entry context the scanner would supply."""

    def match(
        path: str | Path,
        *,
        is_dir: bool = True,
        age_days: float = 100.0,
        size: int = 1024,
        siblings: frozenset[str] = frozenset(),
        own_file: bool = True,
    ):
        target = Path(path)
        parts = tuple(part.lower() for part in target.parts if part not in {"/", "\\"})
        return ruleset.match(
            path=target,
            name=target.name,
            rel=target.name,
            is_dir=is_dir,
            size=size,
            age_days=age_days,
            siblings=siblings,
            parents=frozenset(parts[:-1]),
            own_file=own_file,
        )

    return match


def rule_id(match) -> str | None:
    return match.id if match else None


def test_every_rule_has_complete_metadata() -> None:
    ids = [rule.id for rule in DEFAULT_RULES]
    assert len(ids) == len(set(ids)), "rule ids must be unique"
    for rule in DEFAULT_RULES:
        assert rule.title and rule.description, rule.id
        assert rule.category in CATEGORY_META, rule.id
        assert isinstance(rule.risk, Risk)
        assert rule.priority >= 0
    for category in Category:
        assert category in CATEGORY_META


def test_advisory_rules_are_never_actionable() -> None:
    probes = [rule for rule in DEFAULT_RULES if rule.probe]
    assert probes, "expected system probe rules"
    for rule in probes:
        assert rule.actionable is False
        assert rule.advisory, f"{rule.id} must ship the command to run instead"
        assert rule.risk is Risk.FORBIDDEN


def test_personal_data_rules_never_pre_select() -> None:
    """Only a SAFE, genuinely actionable rule may arrive pre-ticked.

    This is what keeps a first run from quietly proposing to delete somebody's
    photos: riskier categories must always need an explicit click.
    """

    for rule in DEFAULT_RULES:
        if rule.category in {Category.OLD_FILES, Category.LARGE_FILES, Category.DUPLICATES}:
            assert rule.default_selected is False, rule.id
        if rule.default_selected:
            assert rule.risk is Risk.SAFE, f"{rule.id} pre-selects at {rule.risk.value}"
            assert rule.actionable, f"{rule.id} pre-selects but cannot be actioned"


@pytest.mark.parametrize(
    "relative,expected",
    [
        (".cache/pip", "pkg-pip-cache"),
        (".cache/uv", "pkg-uv-cache"),
        (".npm/_cacache", "pkg-npm-cache"),
        (".cargo/registry/cache", "pkg-cargo-cache"),
        (".gradle/caches", "pkg-gradle-cache"),
        (".m2/repository", "pkg-maven-repo"),
        (".local/share/Trash", "trash-freedesktop"),
    ],
)
def test_package_caches_match_by_absolute_path(
    ruleset: RuleSet, fake_home: FakeHome, relative: str, expected: str
) -> None:
    match = make_matcher(ruleset)
    assert rule_id(match(fake_home.root / relative)) == expected


@pytest.mark.parametrize("name", ["Cache", "cache", "CACHE", "Code Cache", "GPUCache", "cache2"])
def test_browser_cache_names_match_case_insensitively(
    ruleset: RuleSet, fake_home: FakeHome, name: str
) -> None:
    """Chrome writes ``Cache`` on Linux; a case-sensitive fold would miss it."""

    match = make_matcher(ruleset)
    path = fake_home.root / ".config/google-chrome/Default" / name
    assert rule_id(match(path)) == "browser-cache-dirs"


def test_browser_profile_data_is_not_a_cache(
    ruleset: RuleSet, fake_home: FakeHome
) -> None:
    match = make_matcher(ruleset)
    for name in ("History", "Login Data", "Cookies", "Bookmarks", "Preferences"):
        path = fake_home.root / ".config/google-chrome/Default" / name
        assert rule_id(match(path)) is None, name


def test_sibling_gating_protects_unrelated_directories(
    ruleset: RuleSet, fake_home: FakeHome
) -> None:
    """A folder called ``target`` is only build output inside a real project."""

    match = make_matcher(ruleset)
    with_manifest = fake_home.root / "projects/rust/target"
    decoy = fake_home.root / "projects/decoy/target"
    assert rule_id(match(with_manifest, siblings=frozenset({"cargo.toml"}))) == "build-target-cargo"
    assert rule_id(match(decoy, siblings=frozenset({"readme.md"}))) is None
    assert rule_id(match(decoy, siblings=frozenset({"pom.xml"}))) == "build-maven-target"


def test_generic_build_dirs_require_a_manifest(
    ruleset: RuleSet, fake_home: FakeHome
) -> None:
    match = make_matcher(ruleset)
    dist = fake_home.root / "projects/web/dist"
    assert rule_id(match(dist, siblings=frozenset({"package.json"}))) == "build-generic-dist"
    assert rule_id(match(dist, siblings=frozenset())) is None


def test_node_modules_needs_no_manifest(ruleset: RuleSet, fake_home: FakeHome) -> None:
    match = make_matcher(ruleset)
    assert rule_id(match(fake_home.root / "anywhere/node_modules")) == "build-node-modules"


def test_python_caches_are_safe(ruleset: RuleSet, fake_home: FakeHome) -> None:
    match = make_matcher(ruleset)
    compiled = ruleset.compiled_for("build-python-caches")
    assert compiled is not None
    assert rule_id(match(fake_home.root / "projects/app/__pycache__")) == "build-python-caches"
    assert compiled.rule.risk is Risk.SAFE


def test_cache_root_children_match_individually(
    ruleset: RuleSet, fake_home: FakeHome
) -> None:
    """Direct children of ~/.cache are their own findings, not one opaque blob."""

    match = make_matcher(ruleset)
    child = fake_home.root / ".cache/some-random-app"
    assert rule_id(match(child)) == "app-cache-xdg-children"
    deeper = fake_home.root / ".cache/some-random-app/nested/thing"
    assert rule_id(match(deeper)) is None
    # The cache root itself is not matched by the children rule.
    assert rule_id(match(fake_home.root / ".cache")) is None


def test_more_specific_rules_win_on_priority(
    ruleset: RuleSet, fake_home: FakeHome
) -> None:
    """pip's cache is a package cache even though it also lives under ~/.cache."""

    match = make_matcher(ruleset)
    assert rule_id(match(fake_home.root / ".cache/pip")) == "pkg-pip-cache"


def test_personal_data_beats_the_temp_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A home directory inside /tmp must not turn Downloads into 'temp files'."""

    home = tmp_path / "tmp-home"
    (home / "Downloads").mkdir(parents=True)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setenv("HOME", str(home))
    ruleset = RuleSet(home=home)
    match = make_matcher(ruleset)
    assert rule_id(match(home / "Downloads/old.iso", is_dir=False, age_days=400)) == "old-downloads"


def test_temp_rule_needs_age_and_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
    monkeypatch.setenv("HOME", str(home))
    (tmp_path / "tmp").mkdir()
    ruleset = RuleSet(home=home)
    match = make_matcher(ruleset)
    stale = tmp_path / "tmp" / "installer-xyz"
    assert rule_id(match(stale, is_dir=False, age_days=30)) == "temp-files"
    assert rule_id(match(stale, is_dir=False, age_days=0.1)) is None
    # Another user's temp file is not ours to remove.
    assert rule_id(match(stale, is_dir=False, age_days=30, own_file=False)) is None


def test_log_rule_needs_age(ruleset: RuleSet, fake_home: FakeHome) -> None:
    match = make_matcher(ruleset)
    log = fake_home.root / "projects/app/logs/app.log"
    assert rule_id(match(log, is_dir=False, age_days=30)) == "log-files"
    assert rule_id(match(log, is_dir=False, age_days=1)) is None


@pytest.mark.parametrize(
    "name", ["app.log.1", "app.log.1.gz", "app.log.gz", "hs_err_pid1234.log", "core.1234"]
)
def test_rotated_log_globs(ruleset: RuleSet, fake_home: FakeHome, name: str) -> None:
    match = make_matcher(ruleset)
    path = fake_home.root / "projects/app/logs" / name
    assert rule_id(match(path, is_dir=False, age_days=60)) == "log-files"


def test_platform_specific_rules_are_dropped(
    fake_home: FakeHome, monkeypatch: pytest.MonkeyPatch
) -> None:
    ruleset = RuleSet(home=fake_home.root)
    linux_ids = {compiled.id for compiled in ruleset.compiled}
    windows_only = {rule.id for rule in DEFAULT_RULES if rule.platforms == ("win32",)}
    assert windows_only, "expected Windows-only probe rules in the table"
    assert not (windows_only & linux_ids)

    monkeypatch.setattr("diskfree.scanner.rules.sys.platform", "darwin")
    darwin_ids = {compiled.id for compiled in RuleSet(home=fake_home.root).compiled}
    assert "app-cache-macos-children" in darwin_ids
    # XDG caches still matter on macOS: plenty of tools honour the spec.
    assert "app-cache-xdg-children" in darwin_ids
    assert not (windows_only & darwin_ids)

    monkeypatch.setattr("diskfree.scanner.rules.sys.platform", "win32")
    windows_ids = {compiled.id for compiled in RuleSet(home=fake_home.root).compiled}
    assert "sys-windows-recycle" in windows_ids
    assert "app-cache-xdg-children" not in windows_ids


def test_probe_paths_only_report_existing_locations(
    ruleset: RuleSet, fake_home: FakeHome
) -> None:
    probed = {str(path) for _compiled, path in ruleset.probe_paths()}
    assert all(Path(path).exists() for path in probed)
    assert str(fake_home.root / ".cache/pip") not in probed


def test_group_keys_follow_the_aggregation_mode(
    ruleset: RuleSet, fake_home: FakeHome
) -> None:
    match = make_matcher(ruleset)
    log = fake_home.root / "projects/app/logs/app.log"
    compiled = match(log, is_dir=False, age_days=30)
    assert compiled is not None
    assert compiled.rule.aggregate is AggregateMode.LOGDIR
    assert ruleset.group_key(compiled, log, fake_home.root) == str(
        fake_home.root / "projects/app/logs"
    )

    pruned = match(fake_home.root / ".cache/pip")
    assert pruned is not None
    assert pruned.rule.aggregate is AggregateMode.SELF
    assert ruleset.group_key(pruned, fake_home.root / ".cache/pip", fake_home.root) == str(
        fake_home.root / ".cache/pip"
    )


def test_templates_resolve_for_the_current_platform(fake_home: FakeHome) -> None:
    templates = expand_templates(fake_home.root)
    assert templates["home"] == str(fake_home.root)
    assert templates["cache"]
    assert templates["downloads"] == str(fake_home.root / "Downloads")
    unresolved = [key for key, value in templates.items() if "{" in value]
    assert not unresolved


def test_fold_name_is_always_case_insensitive() -> None:
    assert fold_name("Cache") == "cache"
    assert fold_name("GPUCache") == "gpucache"


def test_no_rule_matches_a_plain_source_file(ruleset: RuleSet, fake_home: FakeHome) -> None:
    match = make_matcher(ruleset)
    for relative in ("projects/app/src/main.py", "projects/app/package.json",
                     "Documents/report.docx", "keep/important.txt"):
        assert rule_id(match(fake_home.root / relative, is_dir=False)) is None, relative

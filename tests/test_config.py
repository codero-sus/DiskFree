"""Configuration: defaults, environment overrides, TOML file and precedence.

The safety-critical part is that nothing can silently turn a guard off: a typo in
``DISKFREE_ALLOW_PERMANENT_DELETE`` must leave deletion disabled, and a secret in
the environment must never appear in a serialised view.
"""

from __future__ import annotations

import dataclasses
import os
import sys
from pathlib import Path

import pytest

from diskfree.config import (
    DEFAULT_CORTEX_URL,
    DEFAULT_OLLAMA_URL,
    PROVIDERS,
    ProviderSettings,
    SafetySettings,
    ScanSettings,
    Settings,
    default_data_dir,
    load_settings,
    with_overrides,
)

SECRET = "super-secret-token"


@pytest.fixture(autouse=True)
def clean_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Start from a known environment: no leftover DISKFREE_* from the shell."""

    for name in list(os.environ):
        if name.startswith("DISKFREE_") or name in {"CORTEX_API_KEY", "OLLAMA_API_KEY"}:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("DISKFREE_DATA_DIR", str(tmp_path / "data"))


# --------------------------------------------------------------------------
# defaults and derived paths
# --------------------------------------------------------------------------


def test_defaults_are_loopback_and_reversible(tmp_path: Path) -> None:
    settings = load_settings()
    assert settings.host == "127.0.0.1"
    assert settings.port == 8790
    assert settings.provider == "auto"
    assert settings.ui_token is None
    assert settings.cors_origins == ()
    assert settings.log_level == "info"
    assert settings.data_dir == tmp_path / "data"

    assert settings.safety.allow_writes is True
    assert settings.safety.allow_permanent_delete is False, "hard deletion must be opt-in"
    assert settings.safety.require_confirmation is True
    assert settings.safety.plan_ttl_seconds == 900
    assert settings.safety.trash_backend == "auto"
    assert settings.safety.extra_protected_paths == ()


def test_scan_defaults_are_bounded(tmp_path: Path) -> None:
    scan = load_settings().scan
    assert scan.max_depth == 24
    assert scan.max_findings == 20_000
    assert scan.max_files_per_rule == 4_000
    assert scan.max_members_per_finding == 40
    assert scan.duplicate_min_bytes == 5 * 1024 * 1024
    assert scan.large_file_min_bytes == 256 * 1024 * 1024
    assert scan.old_file_min_age_days == 90
    assert scan.log_min_age_days == 7
    assert scan.temp_min_age_days == 1


def test_both_local_providers_are_configured_by_default() -> None:
    settings = load_settings()
    assert [provider.name for provider in settings.providers] == ["cortex", "ollama"]
    assert settings.provider_settings("cortex").url == DEFAULT_CORTEX_URL
    assert settings.provider_settings("ollama").url == DEFAULT_OLLAMA_URL
    assert settings.provider_settings("nope") is None
    assert settings.provider_settings("cortex").api_key is None
    assert settings.provider_settings("cortex").redacted()["api_key_set"] is False


def test_derived_paths_live_under_the_data_dir(tmp_path: Path) -> None:
    settings = load_settings()
    assert settings.quarantine_dir == tmp_path / "data" / "quarantine"
    assert settings.journal_path == tmp_path / "data" / "journal.jsonl"
    assert settings.plans_path == tmp_path / "data" / "plans.json"
    assert settings.state_path == tmp_path / "data" / "settings.json"

    moved = with_overrides(
        settings, safety=dataclasses.replace(settings.safety, quarantine_dir=Path("/var/tmp/q"))
    )
    assert moved.quarantine_dir == Path("/var/tmp/q")


def test_ensure_dirs_creates_state_but_not_in_read_only_mode(tmp_path: Path) -> None:
    writable = load_settings()
    assert writable.data_dir.is_dir()
    assert writable.quarantine_dir.is_dir()

    readonly_dir = tmp_path / "readonly-data"
    readonly = Settings(
        data_dir=readonly_dir,
        safety=SafetySettings(allow_writes=False, quarantine_dir=readonly_dir / "quarantine"),
    )
    readonly.ensure_dirs()
    assert readonly_dir.is_dir()
    assert not (readonly_dir / "quarantine").exists(), "read-only mode must not create a trash"


def test_the_data_dir_follows_platform_conventions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DISKFREE_DATA_DIR", raising=False)
    if sys.platform.startswith("linux"):
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        assert default_data_dir() == tmp_path / "home" / ".local" / "share" / "diskfree"
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        assert default_data_dir() == tmp_path / "xdg" / "diskfree"
    elif sys.platform == "darwin":
        assert default_data_dir() == (
            tmp_path / "home" / "Library" / "Application Support" / "diskfree"
        )
    else:  # pragma: no cover - depends on the host platform
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
        assert default_data_dir() == tmp_path / "appdata" / "diskfree"


# --------------------------------------------------------------------------
# environment overrides
# --------------------------------------------------------------------------


def test_server_environment_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DISKFREE_HOST", "0.0.0.0")
    monkeypatch.setenv("DISKFREE_PORT", "9001")
    monkeypatch.setenv("DISKFREE_LOG_LEVEL", "debug")
    monkeypatch.setenv("DISKFREE_UI_TOKEN", "tok")
    monkeypatch.setenv("DISKFREE_CORS_ORIGINS", "https://a.example, https://b.example ,")

    settings = load_settings()
    assert settings.host == "0.0.0.0"
    assert settings.port == 9001
    assert settings.log_level == "debug"
    assert settings.ui_token == "tok"
    assert settings.cors_origins == ("https://a.example", "https://b.example")


def test_provider_environment_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DISKFREE_PROVIDER", "OLLAMA")
    monkeypatch.setenv("DISKFREE_OLLAMA_URL", "http://127.0.0.1:11500/")
    monkeypatch.setenv("DISKFREE_OLLAMA_MODEL", "qwen2.5:7b")
    monkeypatch.setenv("OLLAMA_API_KEY", SECRET)
    monkeypatch.setenv("DISKFREE_CORTEX_URL", "http://10.0.0.5:8624")
    monkeypatch.setenv("DISKFREE_CORTEX_API_KEY", SECRET)
    monkeypatch.setenv("DISKFREE_CORTEX_MODEL", "qwen-local")
    monkeypatch.setenv("DISKFREE_CORTEX_TIMEOUT", "5")
    monkeypatch.setenv("DISKFREE_CORTEX_ENABLED", "0")

    settings = load_settings()
    assert settings.provider == "ollama", "the provider name is case-insensitive"
    ollama = settings.provider_settings("ollama")
    assert ollama.url == "http://127.0.0.1:11500", "a trailing slash is normalised away"
    assert ollama.model == "qwen2.5:7b"
    assert ollama.api_key == SECRET, "OLLAMA_API_KEY is honoured as a fallback"
    assert ollama.timeout == 180.0

    cortex = settings.provider_settings("cortex")
    assert cortex.url == "http://10.0.0.5:8624"
    assert cortex.model == "qwen-local"
    assert cortex.api_key == SECRET
    assert cortex.timeout == 5.0
    assert cortex.enabled is False


def test_an_unknown_provider_falls_back_to_auto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DISKFREE_PROVIDER", "skynet")
    assert load_settings().provider == "auto"
    assert "auto" in PROVIDERS


def test_the_diskfree_variable_wins_over_the_vendor_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CORTEX_API_KEY", "from-vendor")
    monkeypatch.setenv("DISKFREE_CORTEX_API_KEY", "from-diskfree")
    assert load_settings().provider_settings("cortex").api_key == "from-diskfree"


def test_safety_environment_overrides(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DISKFREE_TRASH_BACKEND", "quarantine")
    monkeypatch.setenv("DISKFREE_QUARANTINE_DIR", str(tmp_path / "q"))
    monkeypatch.setenv("DISKFREE_MAX_TRASH_GB", "2")
    monkeypatch.setenv("DISKFREE_PLAN_TTL_SECONDS", "60")
    monkeypatch.setenv("DISKFREE_REQUIRE_CONFIRMATION", "0")
    monkeypatch.setenv(
        "DISKFREE_EXTRA_PROTECTED_PATHS", f"{tmp_path / 'a'}{os.pathsep}{tmp_path / 'b'}"
    )

    safety = load_settings().safety
    assert safety.trash_backend == "quarantine"
    assert safety.quarantine_dir == tmp_path / "q"
    assert safety.max_trash_bytes == 2 * 1024**3
    assert safety.plan_ttl_seconds == 60
    assert safety.require_confirmation is False
    assert safety.extra_protected_paths == (str(tmp_path / "a"), str(tmp_path / "b"))


def test_read_only_and_permanent_delete_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DISKFREE_ALLOW_WRITES", "0")
    settings = load_settings()
    assert settings.safety.allow_writes is False

    monkeypatch.setenv("DISKFREE_ALLOW_PERMANENT_DELETE", "1")
    assert load_settings().safety.allow_permanent_delete is True


@pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes", "on", " True "])
def test_truthy_values_enable_a_flag(monkeypatch: pytest.MonkeyPatch, truthy: str) -> None:
    monkeypatch.setenv("DISKFREE_ALLOW_PERMANENT_DELETE", truthy)
    assert load_settings().safety.allow_permanent_delete is True


@pytest.mark.parametrize("falsy", ["0", "false", "no", "off", "maybe", "1.5", "yessir", ""])
def test_anything_else_leaves_the_flag_off(
    monkeypatch: pytest.MonkeyPatch, falsy: str
) -> None:
    """A typo must never enable the destructive path."""

    monkeypatch.setenv("DISKFREE_ALLOW_PERMANENT_DELETE", falsy)
    assert load_settings().safety.allow_permanent_delete is False


def test_scan_environment_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DISKFREE_SCAN_MAX_DEPTH", "8")
    monkeypatch.setenv("DISKFREE_SCAN_MAX_FINDINGS", "500")
    monkeypatch.setenv("DISKFREE_SCAN_MAX_FILES_PER_RULE", "250")
    monkeypatch.setenv("DISKFREE_SCAN_MAX_MEMBERS", "10")
    monkeypatch.setenv("DISKFREE_DUPLICATE_MIN_MB", "2")
    monkeypatch.setenv("DISKFREE_DUPLICATE_MAX_CANDIDATES", "99")
    monkeypatch.setenv("DISKFREE_LARGE_FILE_MIN_MB", "512")
    monkeypatch.setenv("DISKFREE_OLD_FILE_MIN_AGE_DAYS", "30")
    monkeypatch.setenv("DISKFREE_LOG_MIN_AGE_DAYS", "3")
    monkeypatch.setenv("DISKFREE_TEMP_MIN_AGE_DAYS", "0")

    scan = load_settings().scan
    assert scan.max_depth == 8
    assert scan.max_findings == 500
    assert scan.max_files_per_rule == 250
    assert scan.max_members_per_finding == 10
    assert scan.duplicate_min_bytes == 2 * 1024 * 1024
    assert scan.duplicate_max_candidates == 99
    assert scan.large_file_min_bytes == 512 * 1024 * 1024
    assert scan.old_file_min_age_days == 30
    assert scan.log_min_age_days == 3
    assert scan.temp_min_age_days == 0


@pytest.mark.parametrize(
    "variable",
    [
        "DISKFREE_PORT",
        "DISKFREE_PLAN_TTL_SECONDS",
        "DISKFREE_MAX_TRASH_GB",
        "DISKFREE_SCAN_MAX_DEPTH",
        "DISKFREE_DUPLICATE_MIN_MB",
        "DISKFREE_LARGE_FILE_MIN_MB",
        "DISKFREE_CORTEX_TIMEOUT",
    ],
)
def test_a_malformed_number_falls_back_to_the_default(
    monkeypatch: pytest.MonkeyPatch, variable: str
) -> None:
    """Garbage in the environment must not produce a garbage limit."""

    baseline = load_settings()
    monkeypatch.setenv(variable, "not-a-number")
    assert load_settings() == baseline


def test_a_blank_variable_is_treated_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DISKFREE_HOST", "   ")
    monkeypatch.setenv("DISKFREE_OLLAMA_MODEL", "")
    settings = load_settings()
    assert settings.host == "127.0.0.1"
    assert settings.provider_settings("ollama").model is None


def test_tilde_paths_are_expanded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DISKFREE_DATA_DIR", "~/diskfree-state")
    assert load_settings().data_dir == tmp_path / "home" / "diskfree-state"


# --------------------------------------------------------------------------
# TOML config file
# --------------------------------------------------------------------------


CONFIG = """
[server]
host = "0.0.0.0"
port = 9100
log_level = "warning"
ui_token = "from-file"

[ai]
provider = "cortex"

[ai.cortex]
base_url = "http://127.0.0.1:9999"
api_key = "file-key"
model = "qwen-local"
timeout = 30
enabled = true

[ai.ollama]
base_url = "http://127.0.0.1:11999"
model = "llama3.2"

[scan]
max_depth = 12
duplicate_min_mb = 3

[safety]
allow_writes = true
allow_permanent_delete = false
trash_backend = "quarantine"
plan_ttl_seconds = 120
protected_paths = ["/srv/keep", "/opt/keep"]
"""


def write_config(tmp_path: Path, text: str = CONFIG, name: str = "config.toml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_a_config_file_is_honoured(tmp_path: Path) -> None:
    path = write_config(tmp_path)
    settings = load_settings(path)

    assert settings.config_path == path
    assert settings.host == "0.0.0.0"
    assert settings.port == 9100
    assert settings.log_level == "warning"
    assert settings.ui_token == "from-file"
    assert settings.provider == "cortex"

    cortex = settings.provider_settings("cortex")
    assert cortex.url == "http://127.0.0.1:9999"
    assert cortex.api_key == "file-key"
    assert cortex.model == "qwen-local"
    assert cortex.timeout == 30.0

    ollama = settings.provider_settings("ollama")
    assert ollama.url == "http://127.0.0.1:11999"
    assert ollama.model == "llama3.2"

    assert settings.scan.max_depth == 12
    assert settings.scan.duplicate_min_bytes == 3 * 1024 * 1024
    assert settings.safety.plan_ttl_seconds == 120
    assert settings.safety.trash_backend == "quarantine"
    assert settings.safety.extra_protected_paths == ("/srv/keep", "/opt/keep")


def test_the_environment_beats_the_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_config(tmp_path)
    monkeypatch.setenv("DISKFREE_PORT", "9999")
    monkeypatch.setenv("DISKFREE_PROVIDER", "ollama")
    monkeypatch.setenv("DISKFREE_CORTEX_API_KEY", SECRET)
    monkeypatch.setenv("DISKFREE_SCAN_MAX_DEPTH", "3")

    settings = load_settings(path)
    assert settings.port == 9999
    assert settings.provider == "ollama"
    assert settings.provider_settings("cortex").api_key == SECRET
    assert settings.scan.max_depth == 3
    # Values the environment does not mention still come from the file.
    assert settings.host == "0.0.0.0"
    assert settings.ui_token == "from-file"


def test_the_config_path_can_come_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_config(tmp_path, name="elsewhere.toml")
    monkeypatch.setenv("DISKFREE_CONFIG", str(path))
    settings = load_settings()
    assert settings.config_path == path
    assert settings.port == 9100


def test_the_default_config_location_is_the_data_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DISKFREE_DATA_DIR", str(tmp_path / "data"))
    path = tmp_path / "data" / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('[server]\nport = 8123\n', encoding="utf-8")

    settings = load_settings()
    assert settings.config_path == path
    assert settings.port == 8123


@pytest.mark.parametrize(
    "text",
    [
        "",
        "this is not toml at all",
        "[server\nport = ",
        'port = "not-a-dict-at-the-top-level"',
    ],
)
def test_a_broken_config_file_never_crashes_the_app(tmp_path: Path, text: str) -> None:
    path = write_config(tmp_path, text=text)
    settings = load_settings(path)
    assert settings.port == 8790, "an unreadable file must fall back to the defaults"
    assert settings.safety.allow_permanent_delete is False


def test_a_missing_config_file_is_ignored(tmp_path: Path) -> None:
    settings = load_settings(tmp_path / "does-not-exist.toml")
    assert settings.config_path is None
    assert settings.port == 8790


def test_the_platform_default_config_location_is_also_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without DISKFREE_DATA_DIR the config sits next to the other state files."""

    monkeypatch.delenv("DISKFREE_DATA_DIR", raising=False)
    directory = default_data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "config.toml").write_text('[server]\nport = 8456\n', encoding="utf-8")

    settings = load_settings()
    assert settings.config_path == directory / "config.toml"
    assert settings.port == 8456
    assert settings.data_dir == directory


def test_wrong_typed_sections_are_ignored(tmp_path: Path) -> None:
    path = write_config(tmp_path, text='server = 5\nsafety = "nope"\n[ai]\nprovider = 3\n')
    settings = load_settings(path)
    assert settings.host == "127.0.0.1"
    assert settings.provider == "auto"
    assert settings.safety.allow_writes is True


def test_a_single_protected_path_string_is_accepted(tmp_path: Path) -> None:
    path = write_config(tmp_path, text='[safety]\nprotected_paths = "/srv/keep"\n')
    assert load_settings(path).safety.extra_protected_paths == ("/srv/keep",)


def test_file_and_environment_protected_paths_are_merged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_config(tmp_path, text='[safety]\nprotected_paths = ["/srv/keep"]\n')
    monkeypatch.setenv("DISKFREE_EXTRA_PROTECTED_PATHS", "/opt/keep")
    assert load_settings(path).safety.extra_protected_paths == ("/srv/keep", "/opt/keep")


# --------------------------------------------------------------------------
# secrets and immutability
# --------------------------------------------------------------------------


def test_redacted_never_carries_the_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DISKFREE_CORTEX_API_KEY", SECRET)
    provider = load_settings().provider_settings("cortex")
    payload = provider.redacted()

    assert SECRET not in str(payload)
    assert "api_key" not in payload
    assert payload["api_key_set"] is True
    assert payload["name"] == "cortex"
    assert payload["base_url"] == DEFAULT_CORTEX_URL


def test_redacted_reports_an_absent_secret() -> None:
    assert load_settings().provider_settings("cortex").redacted()["api_key_set"] is False


def test_settings_are_immutable() -> None:
    settings = load_settings()
    with pytest.raises(dataclasses.FrozenInstanceError):
        settings.port = 1  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        settings.safety.allow_permanent_delete = True  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        settings.scan.max_depth = 1  # type: ignore[misc]


def test_with_overrides_returns_a_copy() -> None:
    settings = load_settings()
    changed = with_overrides(settings, port=1234, provider="heuristic")
    assert changed.port == 1234
    assert changed.provider == "heuristic"
    assert settings.port == 8790
    # Untouched fields are shared, not rebuilt.
    assert changed.safety == settings.safety
    assert changed.data_dir == settings.data_dir


def test_provider_settings_normalise_their_url() -> None:
    provider = ProviderSettings(name="x", base_url="http://host:1///")
    assert provider.url == "http://host:1"
    assert ProviderSettings(name="y", base_url="http://host:2").url == "http://host:2"


def test_safety_settings_defaults_are_the_safe_ones() -> None:
    safety = SafetySettings()
    assert safety.allow_permanent_delete is False
    assert safety.require_confirmation is True
    assert safety.allow_writes is True
    assert safety.trash_backend == "auto"
    assert safety.plan_ttl_seconds > 0
    assert safety.max_trash_bytes > 0


def test_scan_settings_defaults_match_the_documented_caps() -> None:
    scan = ScanSettings()
    assert scan.duplicate_max_candidates == 5_000
    assert scan.max_findings >= scan.max_files_per_rule

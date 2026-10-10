"""Runtime configuration for DiskFree.

Everything can be expressed with environment variables (handy for containers and
systemd) or a TOML file. Environment variables always win, so a deployment can
ship a base config file and override secrets per host.

Recognised variables::

    DISKFREE_HOST / DISKFREE_PORT          WebUI bind address
    DISKFREE_DATA_DIR                      journals, quarantine, settings
    DISKFREE_PROVIDER                      auto|cortex|ollama|heuristic
    DISKFREE_CORTEX_URL                    default http://127.0.0.1:8624
    DISKFREE_CORTEX_API_KEY / CORTEX_API_KEY
    DISKFREE_CORTEX_MODEL                  optional model id override
    DISKFREE_OLLAMA_URL                    default http://127.0.0.1:11434
    DISKFREE_OLLAMA_MODEL                  e.g. llama3.2 / qwen2.5:7b
    DISKFREE_OLLAMA_API_KEY / OLLAMA_API_KEY
    DISKFREE_ALLOW_PERMANENT_DELETE        1 enables hard deletion (default off)
    DISKFREE_MAX_TRASH_BYTES               quarantine size ceiling
    DISKFREE_UI_TOKEN                      optional bearer token for the WebUI
"""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

APP_NAME = "diskfree"
DEFAULT_CORTEX_URL = "http://127.0.0.1:8624"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
PROVIDERS = ("auto", "cortex", "ollama", "heuristic")


def default_data_dir() -> Path:
    """Platform-appropriate, user-writable location for DiskFree state."""

    home = Path.home()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(home / "AppData" / "Local")
        return Path(base) / APP_NAME
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / APP_NAME
    base = os.environ.get("XDG_DATA_HOME") or str(home / ".local" / "share")
    return Path(base) / APP_NAME


def _env_str(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip()


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        return default


# -- the same tolerance for values that come from the TOML file --------------
# A config file is written by hand, so a wrong type must fall back to the
# default rather than take the whole application down at start-up.


def _as_str(value: Any, default: str | None = None) -> str | None:
    if isinstance(value, str):
        return value.strip() or default
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return str(value)
    return default


def _as_int(value: Any, default: int) -> int:
    if value is None or isinstance(value, bool):
        return default
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float) -> float:
    if value is None or isinstance(value, bool):
        return default
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        text = value.strip().lower()
        if not text:
            return default
        return text in {"1", "true", "yes", "on"}
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _as_paths(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [text for text in (_as_str(item) for item in value) if text]
    return []


@dataclass(frozen=True, slots=True)
class ProviderSettings:
    """Connection details for one local LLM host."""

    name: str
    base_url: str
    api_key: str | None = None
    model: str | None = None
    timeout: float = 120.0
    enabled: bool = True

    @property
    def url(self) -> str:
        return self.base_url.rstrip("/")

    def redacted(self) -> dict[str, Any]:
        """Serialisable view that never leaks the secret."""

        return {
            "name": self.name,
            "base_url": self.url,
            "api_key_set": bool(self.api_key),
            "model": self.model,
            "timeout": self.timeout,
            "enabled": self.enabled,
        }


@dataclass(frozen=True, slots=True)
class ScanSettings:
    """Defaults applied to every scan job unless the caller overrides them."""

    max_depth: int = 24
    max_findings: int = 20_000
    max_files_per_rule: int = 4_000
    max_members_per_finding: int = 40
    duplicate_min_bytes: int = 5 * 1024 * 1024
    duplicate_max_candidates: int = 5_000
    large_file_min_bytes: int = 250 * 1024 * 1024
    old_file_min_age_days: int = 90
    log_min_age_days: int = 7
    temp_min_age_days: int = 1


@dataclass(frozen=True, slots=True)
class SafetySettings:
    """Guardrails for the destructive part of the pipeline."""

    allow_writes: bool = True
    allow_permanent_delete: bool = False
    trash_backend: str = "auto"  # auto|freedesktop|macos|quarantine
    quarantine_dir: Path | None = None
    max_trash_bytes: int = 200 * 1024 * 1024 * 1024
    require_confirmation: bool = True
    plan_ttl_seconds: int = 900
    extra_protected_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8790
    data_dir: Path = field(default_factory=default_data_dir)
    config_path: Path | None = None
    provider: str = "auto"
    providers: tuple[ProviderSettings, ...] = ()
    scan: ScanSettings = field(default_factory=ScanSettings)
    safety: SafetySettings = field(default_factory=SafetySettings)
    ui_token: str | None = None
    log_level: str = "info"
    cors_origins: tuple[str, ...] = ()

    # -- derived helpers -------------------------------------------------
    @property
    def quarantine_dir(self) -> Path:
        return self.safety.quarantine_dir or (self.data_dir / "quarantine")

    @property
    def journal_path(self) -> Path:
        return self.data_dir / "journal.jsonl"

    @property
    def plans_path(self) -> Path:
        return self.data_dir / "plans.json"

    @property
    def state_path(self) -> Path:
        return self.data_dir / "settings.json"

    def provider_settings(self, name: str) -> ProviderSettings | None:
        for candidate in self.providers:
            if candidate.name == name:
                return candidate
        return None

    def ensure_dirs(self) -> Settings:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if self.safety.allow_writes:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        return self


def _providers_from_env(file_cfg: dict[str, Any]) -> tuple[ProviderSettings, ...]:
    cortex_cfg = file_cfg.get("cortex", {}) if isinstance(file_cfg, dict) else {}
    ollama_cfg = file_cfg.get("ollama", {}) if isinstance(file_cfg, dict) else {}

    cortex = ProviderSettings(
        name="cortex",
        base_url=_env_str(
            "DISKFREE_CORTEX_URL",
            _as_str(cortex_cfg.get("base_url"), DEFAULT_CORTEX_URL),
        )
        or DEFAULT_CORTEX_URL,
        api_key=_env_str("DISKFREE_CORTEX_API_KEY", None)
        or _env_str("CORTEX_API_KEY", None)
        or _as_str(cortex_cfg.get("api_key")),
        model=_env_str("DISKFREE_CORTEX_MODEL", _as_str(cortex_cfg.get("model"))),
        timeout=_env_float(
            "DISKFREE_CORTEX_TIMEOUT", _as_float(cortex_cfg.get("timeout"), 120.0)
        ),
        enabled=_env_bool(
            "DISKFREE_CORTEX_ENABLED", _as_bool(cortex_cfg.get("enabled"), True)
        ),
    )
    ollama = ProviderSettings(
        name="ollama",
        base_url=_env_str(
            "DISKFREE_OLLAMA_URL",
            _as_str(ollama_cfg.get("base_url"), DEFAULT_OLLAMA_URL),
        )
        or DEFAULT_OLLAMA_URL,
        api_key=_env_str("DISKFREE_OLLAMA_API_KEY", None)
        or _env_str("OLLAMA_API_KEY", None)
        or _as_str(ollama_cfg.get("api_key")),
        model=_env_str("DISKFREE_OLLAMA_MODEL", _as_str(ollama_cfg.get("model"))),
        timeout=_env_float(
            "DISKFREE_OLLAMA_TIMEOUT", _as_float(ollama_cfg.get("timeout"), 180.0)
        ),
        enabled=_env_bool(
            "DISKFREE_OLLAMA_ENABLED", _as_bool(ollama_cfg.get("enabled"), True)
        ),
    )
    return (cortex, ollama)


def _scan_from_env(file_cfg: dict[str, Any]) -> ScanSettings:
    base = ScanSettings()
    if not isinstance(file_cfg, dict):
        file_cfg = {}
    mb = 1024 * 1024
    return ScanSettings(
        max_depth=_env_int(
            "DISKFREE_SCAN_MAX_DEPTH", _as_int(file_cfg.get("max_depth"), base.max_depth)
        ),
        max_findings=_env_int(
            "DISKFREE_SCAN_MAX_FINDINGS",
            _as_int(file_cfg.get("max_findings"), base.max_findings),
        ),
        max_files_per_rule=_env_int(
            "DISKFREE_SCAN_MAX_FILES_PER_RULE",
            _as_int(file_cfg.get("max_files_per_rule"), base.max_files_per_rule),
        ),
        max_members_per_finding=_env_int(
            "DISKFREE_SCAN_MAX_MEMBERS",
            _as_int(file_cfg.get("max_members_per_finding"), base.max_members_per_finding),
        ),
        duplicate_min_bytes=_env_int(
            "DISKFREE_DUPLICATE_MIN_MB", _as_int(file_cfg.get("duplicate_min_mb"), 5)
        )
        * mb,
        duplicate_max_candidates=_env_int(
            "DISKFREE_DUPLICATE_MAX_CANDIDATES",
            _as_int(file_cfg.get("duplicate_max_candidates"), base.duplicate_max_candidates),
        ),
        large_file_min_bytes=_env_int(
            "DISKFREE_LARGE_FILE_MIN_MB", _as_int(file_cfg.get("large_file_min_mb"), 256)
        )
        * mb,
        old_file_min_age_days=_env_int(
            "DISKFREE_OLD_FILE_MIN_AGE_DAYS",
            _as_int(file_cfg.get("old_file_min_age_days"), base.old_file_min_age_days),
        ),
        log_min_age_days=_env_int(
            "DISKFREE_LOG_MIN_AGE_DAYS",
            _as_int(file_cfg.get("log_min_age_days"), base.log_min_age_days),
        ),
        temp_min_age_days=_env_int(
            "DISKFREE_TEMP_MIN_AGE_DAYS",
            _as_int(file_cfg.get("temp_min_age_days"), base.temp_min_age_days),
        ),
    )


def _safety_from_env(file_cfg: dict[str, Any]) -> SafetySettings:
    base = SafetySettings()
    if not isinstance(file_cfg, dict):
        file_cfg = {}
    quarantine_raw = _env_str(
        "DISKFREE_QUARANTINE_DIR", _as_str(file_cfg.get("quarantine_dir"))
    )
    extra = _as_paths(file_cfg.get("protected_paths"))
    extra_env = _env_str("DISKFREE_EXTRA_PROTECTED_PATHS")
    if extra_env:
        extra = [*extra, *(part for part in extra_env.split(os.pathsep) if part)]
    return SafetySettings(
        allow_writes=_env_bool(
            "DISKFREE_ALLOW_WRITES", _as_bool(file_cfg.get("allow_writes"), True)
        ),
        allow_permanent_delete=_env_bool(
            "DISKFREE_ALLOW_PERMANENT_DELETE",
            _as_bool(file_cfg.get("allow_permanent_delete"), base.allow_permanent_delete),
        ),
        trash_backend=_env_str(
            "DISKFREE_TRASH_BACKEND", _as_str(file_cfg.get("trash_backend"), "auto")
        )
        or "auto",
        quarantine_dir=Path(quarantine_raw).expanduser() if quarantine_raw else None,
        max_trash_bytes=_env_int(
            "DISKFREE_MAX_TRASH_GB", _as_int(file_cfg.get("max_trash_gb"), 200)
        )
        * 1024
        * 1024
        * 1024,
        require_confirmation=_env_bool(
            "DISKFREE_REQUIRE_CONFIRMATION",
            _as_bool(file_cfg.get("require_confirmation"), base.require_confirmation),
        ),
        plan_ttl_seconds=_env_int(
            "DISKFREE_PLAN_TTL_SECONDS",
            _as_int(file_cfg.get("plan_ttl_seconds"), base.plan_ttl_seconds),
        ),
        extra_protected_paths=tuple(extra),
    )


def _data_dir_from_env() -> Path | None:
    """The data directory as moved by ``DISKFREE_DATA_DIR``, if it was moved."""

    raw = _env_str("DISKFREE_DATA_DIR")
    return Path(raw).expanduser() if raw else None


def _config_file_path(explicit: str | os.PathLike[str] | None = None) -> Path | None:
    """Locate the TOML config: explicit path, ``DISKFREE_CONFIG``, then the data dir.

    The data directory is where DiskFree keeps its state, so ``config.toml`` is
    looked for there first and in the platform default second. A data dir named
    *inside* the config file cannot be used to find that file, obviously.
    """

    candidate = explicit or os.environ.get("DISKFREE_CONFIG")
    if candidate:
        path = Path(candidate).expanduser()
        return path if path.is_file() else None
    bases = [base for base in (_data_dir_from_env(), default_data_dir()) if base]
    for base in bases:
        path = base / "config.toml"
        if path.is_file():
            return path
    return None


def load_settings(config_path: str | os.PathLike[str] | None = None) -> Settings:
    """Build :class:`Settings` from the TOML file (if any) plus environment."""

    path = _config_file_path(config_path)
    file_cfg: dict[str, Any] = {}
    if path is not None:
        try:
            file_cfg = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            file_cfg = {}
    if not isinstance(file_cfg, dict):
        file_cfg = {}

    server_cfg = file_cfg.get("server", {}) if isinstance(file_cfg.get("server"), dict) else {}
    ai_cfg = file_cfg.get("ai", {}) if isinstance(file_cfg.get("ai"), dict) else {}
    scan_cfg = file_cfg.get("scan", {}) if isinstance(file_cfg.get("scan"), dict) else {}
    safety_cfg = file_cfg.get("safety", {}) if isinstance(file_cfg.get("safety"), dict) else {}

    provider = (
        _env_str("DISKFREE_PROVIDER", _as_str(ai_cfg.get("provider"), "auto")) or "auto"
    ).lower()
    if provider not in PROVIDERS:
        provider = "auto"

    data_dir_raw = _env_str("DISKFREE_DATA_DIR", _as_str(server_cfg.get("data_dir")))
    data_dir = Path(data_dir_raw).expanduser() if data_dir_raw else default_data_dir()

    cors_raw = _env_str("DISKFREE_CORS_ORIGINS")
    cors = tuple(o.strip() for o in cors_raw.split(",") if o.strip()) if cors_raw else ()

    settings = Settings(
        host=_env_str("DISKFREE_HOST", _as_str(server_cfg.get("host"), "127.0.0.1"))
        or "127.0.0.1",
        port=_env_int("DISKFREE_PORT", _as_int(server_cfg.get("port"), 8790)),
        data_dir=data_dir,
        config_path=path,
        provider=provider,
        providers=_providers_from_env(ai_cfg),
        scan=_scan_from_env(scan_cfg),
        safety=_safety_from_env(safety_cfg),
        ui_token=_env_str("DISKFREE_UI_TOKEN", _as_str(server_cfg.get("ui_token"))),
        log_level=_env_str("DISKFREE_LOG_LEVEL", _as_str(server_cfg.get("log_level"), "info"))
        or "info",
        cors_origins=cors,
    )
    return settings.ensure_dirs()


def with_overrides(settings: Settings, **changes: Any) -> Settings:
    """Return a copy of ``settings`` with dataclass fields replaced."""

    return replace(settings, **changes)

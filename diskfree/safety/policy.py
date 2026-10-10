"""Safety policy: the non-negotiable guardrails around destructive work.

DiskFree assumes the AI advisor can be wrong, hallucinate a path, or be fed
hostile file names, so this layer is deliberately pessimistic.

Paths fall into three tiers:

:data:`Tier.BLOCKED`
    Never removable, even if the user explicitly asks and even if the model
    insists. Operating systems, version control metadata, credential stores and
    personal document folders live here.
:data:`Tier.SENSITIVE`
    Removable, but only through an explicit per-item selection that the UI never
    pre-ticks, and only into the reversible quarantine.
:data:`Tier.NORMAL`
    Regenerable data such as package caches, temp files and build output.

Three invariants hold everywhere:

* Checks are repeated at execution time, because a stale scan result, a symlink
  created afterwards or a newly mounted volume can invalidate an earlier
  decision.
* The advisor may raise a finding's risk but never lower it below the rule
  engine's floor -- see :func:`clamp_risk`.
* A path component literally named ``Cache``/``tmp``/``logs`` downgrades a
  *blocked* home area to *sensitive*. That is what makes browser cache cleaning
  work on macOS and Windows without opening up ``~/Library`` or ``AppData``.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ..config import SafetySettings

CASE_INSENSITIVE = sys.platform in {"win32", "darwin"}


class Tier(str, Enum):
    """How carefully a path must be treated."""

    NORMAL = "normal"
    SENSITIVE = "sensitive"
    BLOCKED = "blocked"


class Risk(str, Enum):
    """Ordered risk ladder shared by rules, AI advice and the UI."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    FORBIDDEN = "forbidden"

    @property
    def rank(self) -> int:
        return _RISK_ORDER[self]

    @property
    def auto_selectable(self) -> bool:
        """Only :data:`Risk.SAFE` findings may ever be pre-selected."""

        return self is Risk.SAFE


_RISK_ORDER: dict[Risk, int] = {
    Risk.SAFE: 0,
    Risk.LOW: 1,
    Risk.MEDIUM: 2,
    Risk.HIGH: 3,
    Risk.FORBIDDEN: 4,
}


def clamp_risk(floor: Risk, suggested: Risk | str | None) -> Risk:
    """Return the more conservative of ``floor`` and ``suggested``.

    The model may say "this is riskier than the rule thought"; it may never say
    "trust me, this is safe".
    """

    if suggested is None:
        return floor
    try:
        candidate = Risk(str(suggested).strip().lower())
    except ValueError:
        return floor
    return candidate if candidate.rank > floor.rank else floor


def max_risk(values: list[Risk] | tuple[Risk, ...]) -> Risk:
    if not values:
        return Risk.SAFE
    return max(values, key=lambda risk: risk.rank)


# --------------------------------------------------------------------------
# Static block lists
# --------------------------------------------------------------------------

_POSIX_BLOCKED_ROOTS: tuple[str, ...] = (
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/lost+found",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/sys",
    "/usr",
    "/opt",
    "/srv",
    "/media",
    "/mnt",
    "/nix",
    "/var/lib",
    "/var/db",
    "/var/spool",
    "/var/run",
    "/private/etc",
    "/private/var/db",
    "/private/var/vm",
    "/System",
    "/Library",
    "/Applications",
    "/Network",
    "/cores",
    "/Volumes",
)

_WINDOWS_BLOCKED_ROOTS: tuple[str, ...] = (
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData\Microsoft",
    r"C:\ProgramData\Packages",
    r"C:\Recovery",
    r"C:\Boot",
    r"C:\PerfLogs",
    r"C:\$Recycle.Bin",
    r"C:\System Volume Information",
)

#: Directory names that are protected wherever they appear in a path.
_BLOCKED_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        ".svn",
        ".hg",
        ".bzr",
        ".ssh",
        ".gnupg",
        ".pgp",
        ".keyring",
        ".keyrings",
        ".pki",
        ".aws",
        ".azure",
        ".kube",
        ".helm",
        ".docker",
        ".password-store",
        "grub",
        "efi",
        "system32",
        "syswow64",
        "winsxs",
        "system volume information",
        "$recycle.bin",
    }
)

#: File names that look like credentials or irreplaceable key material.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^id_(rsa|dsa|ecdsa|ed25519|x25519)(\.pub)?$", re.IGNORECASE),
    re.compile(r"\.(pem|key|p12|pfx|p7b|keystore|jks|kdbx|gpg|asc|age)$", re.IGNORECASE),
    # ".env", "secrets.env", "production.env", "env.local" -- all credential files.
    re.compile(r"(^|[.])env([.][\w+-]+)?$", re.IGNORECASE),
    re.compile(r"^(credentials|\.netrc|\.npmrc|\.pypirc|\.git-credentials)$", re.IGNORECASE),
    re.compile(
        r"(^|[_\-.])(secret|secrets|passwd|password|api[_-]?key|private[_-]?key)([_\-.]|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(^|[_\-.])((access|auth|refresh|api|bearer|session)[_-]?tokens?|tokens?)([_\-.]|$)",
        re.IGNORECASE,
    ),
    re.compile(r"\.(wallet|keychain|keychain-db)$", re.IGNORECASE),
    re.compile(r"^(ntuser\.dat|sam|security)$", re.IGNORECASE),
)

#: Folders that typically hold user-authored content rather than regenerable data.
_SENSITIVE_DIR_NAMES: frozenset[str] = frozenset(
    {
        "documents",
        "downloads",
        "pictures",
        "photos",
        "videos",
        "movies",
        "music",
        "desktop",
        "personal",
        "backup",
        "backups",
        "important",
        "taxes",
        "finance",
        "health",
        "onedrive",
        "dropbox",
        "google drive",
        "googledrive",
        "icloud",
        "iclouddrive",
    }
)

#: A component matching this is strong evidence a directory is regenerable.
#: It downgrades a *blocked* home area (``~/Library``, ``AppData\Roaming``) to
#: *sensitive* so browser and app caches can still be cleaned deliberately.
_CACHE_COMPONENT_RE = re.compile(
    r"""^(
        caches? | cache2 | cache[-_ ]?storage | cachestorage | code[-_ ]cache |
        gpucache | gpu[-_ ]cache | shader[-_ ]?caches? |
        dawn(cache|graphitecache|webgpucache) |
        thumbnails? | thumbnail[-_ ]cache | tmp | temp | temporary[-_ ]files |
        logs? | crashpad | crashreports? | crashdumps | blob[-_ ]storage |
        _cacache | npm[-_ ]cache | pip[-_ ]cache | yarn[-_ ]cache |
        deriveddata | device[-_ ]logs | service[-_ ]worker
    )$""",
    re.IGNORECASE | re.VERBOSE,
)


#: Public alias so the API can show what the policy treats as personal data.
SENSITIVE_DIR_NAMES: frozenset[str] = _SENSITIVE_DIR_NAMES

#: Names that are protected wherever they appear, exposed for transparency.
PROTECTED_NAMES: frozenset[str] = _BLOCKED_NAMES


def is_cache_component(name: str) -> bool:
    """True when a single path component looks like regenerable cache data."""

    return bool(_CACHE_COMPONENT_RE.match(name))


# --------------------------------------------------------------------------
# Home zones
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HomeZone:
    """A protected area inside the user's home plus its cache allow-list."""

    root: Path
    tier: Tier
    reason: str
    allowed_prefixes: tuple[str, ...] = ()

    def relative_parts(self, parts: tuple[str, ...]) -> tuple[str, ...] | None:
        root_parts = self.root.parts
        if len(parts) < len(root_parts):
            return None
        for left, right in zip(parts, root_parts, strict=False):
            if (left.lower() if CASE_INSENSITIVE else left) != (
                right.lower() if CASE_INSENSITIVE else right
            ):
                return None
        return parts[len(root_parts) :]

    def contains(self, parts: tuple[str, ...]) -> bool:
        return self.relative_parts(parts) is not None

    def is_allowed(self, parts: tuple[str, ...]) -> bool:
        relative = self.relative_parts(parts)
        if relative is None:
            return False
        lowered = "/".join(part.lower() for part in relative)
        return any(lowered == prefix or lowered.startswith(prefix + "/") for prefix in
                   self.allowed_prefixes)

    @property
    def specificity(self) -> int:
        return len(self.root.parts)


def _home_zones(home: Path) -> tuple[HomeZone, ...]:
    zones: list[HomeZone] = []
    if sys.platform == "darwin":
        zones.append(
            HomeZone(
                root=home / "Library",
                tier=Tier.BLOCKED,
                reason="inside ~/Library, which holds macOS application data",
                allowed_prefixes=(
                    "caches",
                    "logs",
                    "developer/xcode/deriveddata",
                    "developer/coresimulator/caches",
                    "application support/crashreporter",
                    "containers/cache",
                    "group containers/cache",
                    "webkit/cache",
                    "httpstorse",
                ),
            )
        )
    elif sys.platform == "win32":
        appdata = home / "AppData"
        local = appdata / "Local"
        zones.extend(
            (
                HomeZone(
                    root=appdata / "Roaming",
                    tier=Tier.BLOCKED,
                    reason="inside AppData\\Roaming, which holds application settings",
                    allowed_prefixes=("mozilla/firefox/profiles", "npm-cache", "yarn", "pip"),
                ),
                HomeZone(root=local / "Microsoft" / "Windows", tier=Tier.BLOCKED,
                         reason="Windows shell caches and history"),
                HomeZone(root=local / "Microsoft" / "Credentials", tier=Tier.BLOCKED,
                         reason="stored credentials"),
                HomeZone(root=local / "Microsoft" / "Protect", tier=Tier.BLOCKED,
                         reason="DPAPI key material"),
                HomeZone(root=local / "Packages", tier=Tier.BLOCKED,
                         reason="Microsoft Store application data"),
                HomeZone(root=local, tier=Tier.NORMAL, reason=""),
            )
        )
    else:
        zones.extend(
            (
                HomeZone(
                    root=home / ".local" / "share",
                    tier=Tier.BLOCKED,
                    reason="inside ~/.local/share, which holds application data",
                    allowed_prefixes=(
                        "trash",
                        "recently-used.xbel",
                        "nv",
                        "steam/apps/temp",
                        "kactivitymeterd",
                    ),
                ),
                HomeZone(
                    root=home / ".local",
                    tier=Tier.BLOCKED,
                    reason="inside ~/.local, which holds user-installed programs and state",
                    allowed_prefixes=("share/trash", "state"),
                ),
                HomeZone(
                    root=home / ".config",
                    tier=Tier.BLOCKED,
                    reason="inside ~/.config, which holds application settings",
                    allowed_prefixes=(),
                ),
            )
        )
    # Most specific zone first so the narrowest rule wins.
    zones.sort(key=lambda zone: -zone.specificity)
    return tuple(zones)


# --------------------------------------------------------------------------
# Decisions
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TierInfo:
    """Classification result, including why a path landed in its tier."""

    tier: Tier
    reason: str | None = None
    #: True when the path is sensitive *only* because a component looks like a
    #: cache inside an otherwise blocked home area. A precise cache rule may
    #: trust its own knowledge and keep its declared risk in that one case.
    zone_escape: bool = False


@dataclass(frozen=True, slots=True)
class Decision:
    """Outcome of a policy check."""

    allowed: bool
    tier: Tier
    reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {"allowed": self.allowed, "tier": self.tier.value, "reason": self.reason}


def normalise(path: str | os.PathLike[str]) -> str:
    """Canonical comparison form of a path string.

    ``..`` segments are collapsed lexically. Without this, ``/usr/../etc/passwd``
    would not match the ``/etc`` block and the syscall-free descent check could be
    evaded by a path that never touches the filesystem.
    """

    text = os.fspath(path)
    if not text or not text.strip():
        return text
    if sys.platform == "win32":
        text = text.replace("/", "\\")
        return os.path.normcase(os.path.normpath(text)) or "\\"
    collapsed = os.path.normpath(text)
    if not collapsed:
        return "/"
    # normpath keeps a POSIX double leading slash; treat it as the root form.
    return collapsed


def _variants(path: str | os.PathLike[str]) -> tuple[str, ...]:
    """Literal path plus its realpath so symlink escapes stay blocked."""

    literal = os.fspath(path)
    out = [normalise(literal)]
    try:
        real = os.path.realpath(literal, strict=False)
    except OSError:
        return tuple(out)
    normalised = normalise(real)
    if normalised not in out:
        out.append(normalised)
    return tuple(out)


def is_below(candidate: str, root: str) -> bool:
    """True when ``candidate`` equals ``root`` or lives inside it."""

    if sys.platform == "win32":
        if candidate == root:
            return True
        return candidate.startswith(root.rstrip("\\") + "\\")
    if root == "/":
        return candidate == "/"
    if candidate == root:
        return True
    return candidate.startswith(root.rstrip("/") + "/")


def same_path(left: str | os.PathLike[str], right: str | os.PathLike[str]) -> bool:
    return normalise(left) == normalise(right)


class SafetyPolicy:
    """Decides whether a path may ever be removed, and how loudly to warn."""

    def __init__(
        self,
        safety: SafetySettings | None = None,
        *,
        home: Path | None = None,
        own_paths: list[Path] | None = None,
    ) -> None:
        self.safety = safety or SafetySettings()
        self.home = (home or Path.home()).expanduser()
        self.zones = _home_zones(self.home)
        self.blocked_roots = self._blocked_roots()
        self.extra_blocked = self._extra_blocked()
        self.own_paths = self._own_paths(own_paths)

    # -- construction helpers -------------------------------------------
    def _blocked_roots(self) -> tuple[str, ...]:
        base = _WINDOWS_BLOCKED_ROOTS if sys.platform == "win32" else _POSIX_BLOCKED_ROOTS
        return tuple(dict.fromkeys(normalise(p) for p in base))

    def _extra_blocked(self) -> tuple[str, ...]:
        out: list[str] = []
        for raw in self.safety.extra_protected_paths:
            text = str(raw).strip()
            if not text:
                continue
            try:
                out.append(normalise(Path(text).expanduser().resolve()))
            except OSError:
                out.append(normalise(text))
        return tuple(out)

    def _own_paths(self, own_paths: list[Path] | None) -> tuple[str, ...]:
        """DiskFree must never be able to consume its own code or journals."""

        candidates: list[Path] = [
            Path(__file__).resolve().parent.parent,
            self.home / ".local" / "share" / "diskfree",
            self.home / "Library" / "Application Support" / "diskfree",
            self.home / "AppData" / "Local" / "diskfree",
        ]
        if own_paths:
            candidates.extend(own_paths)
        if self.safety.quarantine_dir:
            candidates.append(Path(self.safety.quarantine_dir))
        return tuple(dict.fromkeys(normalise(p) for p in candidates if p))

    # -- public API ------------------------------------------------------
    def classify(self, path: str | os.PathLike[str]) -> TierInfo:
        """Classify a path. Touches the filesystem only through ``realpath``."""

        original = Path(os.fspath(path)).expanduser()
        for candidate in _variants(original):
            if candidate == ("\\" if sys.platform == "win32" else "/"):
                return TierInfo(Tier.BLOCKED, "the filesystem root can never be removed")
            for root in self.blocked_roots:
                if is_below(candidate, root):
                    return TierInfo(Tier.BLOCKED, f"inside protected system location {root}")
            for root in self.own_paths:
                if is_below(candidate, root):
                    return TierInfo(
                        Tier.BLOCKED, "DiskFree protects its own installation and journals"
                    )
            for root in self.extra_blocked:
                if is_below(candidate, root):
                    return TierInfo(Tier.BLOCKED, "matches a user-defined protected path")

        parts = tuple(part for part in original.parts if part not in {"/", "\\"})
        lowered = tuple(part.lower() for part in parts)

        for part in lowered:
            if part in _BLOCKED_NAMES:
                return TierInfo(Tier.BLOCKED, f"'{part}' is protected credential or system data")

        for pattern in _SECRET_PATTERNS:
            if pattern.search(original.name):
                return TierInfo(Tier.BLOCKED, "file name looks like a credential or private key")

        absolute = original if original.is_absolute() else Path.cwd() / original
        absolute_parts = absolute.parts
        for zone in self.zones:
            relative = zone.relative_parts(absolute_parts)
            if relative is None:
                continue
            if zone.tier is Tier.NORMAL or zone.is_allowed(absolute_parts):
                break
            # Only components *inside* the protected area count. An ancestor
            # called "tmp" or "cache" far above the home directory must not be
            # able to unlock ~/.config or ~/Library.
            if any(is_cache_component(part) for part in relative):
                return TierInfo(
                    Tier.SENSITIVE,
                    f"{zone.reason}, but '{'/'.join(relative)}' is a cache/temp/log area",
                    zone_escape=True,
                )
            return TierInfo(zone.tier, zone.reason)

        for part in lowered:
            if part in _SENSITIVE_DIR_NAMES:
                return TierInfo(Tier.SENSITIVE, f"'{part}' usually holds personal files")

        return TierInfo(Tier.NORMAL, None)

    def tier(self, path: str | os.PathLike[str]) -> tuple[Tier, str | None]:
        """Two-tuple view of :meth:`classify` for callers that only need the tier."""

        info = self.classify(path)
        return info.tier, info.reason

    def descent_blocked(self, path: str | os.PathLike[str]) -> tuple[bool, str | None]:
        """Should the scanner stop descending here?

        This is deliberately narrower than :meth:`tier`. A *blocked home zone*
        such as ``~/.config`` still contains legitimately cleanable cache
        directories (``~/.config/google-chrome/Default/Cache``), so pruning the
        walk there would hide real findings. Only hard system blocks -- ``/proc``,
        ``/usr``, ``.git``, credential stores, DiskFree's own files -- stop the
        descent, which is both correct and a large speed win.
        """

        original = Path(os.fspath(path)).expanduser()
        for candidate in _variants(original):
            if candidate == ("\\" if sys.platform == "win32" else "/"):
                return True, "filesystem root"
            for root in self.blocked_roots:
                if is_below(candidate, root):
                    return True, f"protected system location {root}"
            for root in self.own_paths:
                if is_below(candidate, root):
                    return True, "DiskFree's own installation or journals"
            for root in self.extra_blocked:
                if is_below(candidate, root):
                    return True, "user-defined protected path"
        for part in original.parts:
            if part.lower() in _BLOCKED_NAMES:
                return True, f"'{part}' is protected credential or system data"
        return False, None

    def literal_descent_blocked(self, path: str) -> tuple[bool, str | None]:
        """Syscall-free descent check used inside the scanner's hot loop.

        Only hard system blocks stop the walk. Home zones are excluded because a
        blocked zone such as ``~/.config`` still contains cleanable caches. The
        scan roots are resolved once before the walk and symlinks are never
        followed, so a literal comparison cannot be escaped here; the full
        ``realpath``-based :meth:`check` still runs before anything is removed.
        """

        folded = normalise(path)
        for root in self.blocked_roots:
            if is_below(folded, root):
                return True, f"protected system location {root}"
        for root in self.own_paths:
            if is_below(folded, root):
                return True, "DiskFree's own installation or journals"
        for root in self.extra_blocked:
            if is_below(folded, root):
                return True, "user-defined protected path"
        for part in Path(path).parts:
            if part.lower() in _BLOCKED_NAMES:
                return True, f"'{part}' is protected credential or system data"
        return False, None

    def filesystem_hazards(self, path: str | os.PathLike[str]) -> str | None:
        """Live checks that can invalidate a previously approved plan."""

        target = Path(os.fspath(path))
        try:
            if not target.exists():
                return "path no longer exists"
            if target.is_symlink():
                return "path is a symlink; refusing to touch the link or its target"
            if target.is_dir() and os.path.ismount(target):
                return "path is a mount point"
        except OSError:
            return "path could not be inspected safely"
        return None

    def check(self, path: str | os.PathLike[str], *, live: bool = False) -> Decision:
        """Full decision for one path."""

        tier, reason = self.tier(path)
        if tier is Tier.BLOCKED:
            return Decision(False, tier, reason)
        if live:
            hazard = self.filesystem_hazards(path)
            if hazard:
                return Decision(False, Tier.BLOCKED, hazard)
        if not self.safety.allow_writes:
            return Decision(False, tier, "DiskFree is running in read-only mode")
        return Decision(True, tier, reason)

    def is_within_roots(self, path: str | os.PathLike[str], roots: list[Path]) -> bool:
        """A finding may only be acted on inside the roots it was scanned from."""

        if not roots:
            return False
        candidate = normalise(path)
        return any(is_below(candidate, normalise(root)) for root in roots)

    def risk_for(self, path: str | os.PathLike[str], base: Risk) -> Risk:
        """Escalate ``base`` risk when the path sits in a sensitive area."""

        tier, _ = self.tier(path)
        if tier is Tier.BLOCKED:
            return Risk.FORBIDDEN
        if tier is Tier.SENSITIVE and base.rank < Risk.HIGH.rank:
            return Risk.HIGH
        return base

    def filter_removable(
        self, paths: list[Path], roots: list[Path]
    ) -> tuple[list[Path], list[tuple[Path, str]]]:
        """Split ``paths`` into ``(allowed, rejected_with_reason)``."""

        allowed: list[Path] = []
        rejected: list[tuple[Path, str]] = []
        for path in paths:
            if roots and not self.is_within_roots(path, roots):
                rejected.append((path, "outside the scanned roots"))
                continue
            decision = self.check(path, live=True)
            if decision.allowed:
                allowed.append(path)
            else:
                rejected.append((path, decision.reason or "blocked by safety policy"))
        return allowed, rejected

    @staticmethod
    def mount_point_of(path: str | os.PathLike[str]) -> Path:
        """Walk up to the filesystem root that holds ``path``."""

        current = Path(os.fspath(path)).absolute()
        while True:
            try:
                if os.path.ismount(current):
                    return current
            except OSError:
                return current
            parent = current.parent
            if parent == current:
                return current
            current = parent

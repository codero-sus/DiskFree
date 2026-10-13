"""The cleaning knowledge base: what is regenerable, and how risky is removing it.

Rules are declarative and platform aware. Each one carries the risk floor that
the AI advisor is not allowed to lower, whether it may be pre-selected, and how
matching files are grouped into findings.

Three kinds of rule exist:

*walk rules*
    Matched against every entry while the scanner descends. A directory match
    with ``prune=True`` becomes one finding and stops the descent, which is what
    keeps large trees (``node_modules``, package caches) fast.
*probe rules*
    Checked once per scan against absolute system locations. They only ever
    produce :attr:`Finding.advisory` text -- DiskFree never shells out, so a
    Docker overlay or a Windows hibernation file becomes a copy-paste command
    for the user instead of a deletion.
*computed rules*
    Metadata for the duplicate and large-file passes, which analyse the walk
    output rather than matching names.
"""

from __future__ import annotations

import fnmatch
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ..safety.policy import Risk

__all__ = [
    "CATEGORY_META",
    "DEFAULT_RULES",
    "AggregateMode",
    "Category",
    "CategoryMeta",
    "Matcher",
    "Rule",
    "RuleSet",
    "expand_templates",
    "fold_name",
]


class Category(str, Enum):
    """High level buckets used for grouping in the UI and in AI payloads."""

    PACKAGE_CACHE = "package_cache"
    BROWSER_CACHE = "browser_cache"
    APP_CACHE = "app_cache"
    TEMP = "temp"
    LOGS = "logs"
    TRASH = "trash"
    BUILD_ARTIFACTS = "build_artifacts"
    VIRTUAL_ENV = "virtualenv"
    DUPLICATES = "duplicates"
    LARGE_FILES = "large_files"
    OLD_FILES = "old_files"
    SYSTEM = "system"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class CategoryMeta:
    label: str
    icon: str
    blurb: str
    order: int


CATEGORY_META: dict[Category, CategoryMeta] = {
    Category.PACKAGE_CACHE: CategoryMeta(
        "Package manager caches", "📦",
        "Downloaded packages kept by pip, npm, cargo and friends. Fully "
        "regenerable: the next install simply re-downloads.", 1,
    ),
    Category.BROWSER_CACHE: CategoryMeta(
        "Browser caches", "🌐",
        "Cached web content. Removing it costs a few slower page loads and logs "
        "you out of nothing; passwords and history are never touched.", 2,
    ),
    Category.APP_CACHE: CategoryMeta(
        "Application caches", "🗂️",
        "Regenerable caches written by desktop applications, including "
        "thumbnails, GPU shader caches and crash dumps.", 3,
    ),
    Category.TEMP: CategoryMeta(
        "Temporary files", "🧊",
        "Scratch space used by installers and programs. Only entries that have "
        "not been touched for days are proposed.", 4,
    ),
    Category.LOGS: CategoryMeta(
        "Log files", "📜",
        "Old application and system logs. Useful for debugging, worthless once "
        "stale; usually regenerated automatically.", 5,
    ),
    Category.TRASH: CategoryMeta(
        "Trash", "🗑️",
        "Files you already deleted but that still occupy disk until the trash is "
        "emptied.", 6,
    ),
    Category.BUILD_ARTIFACTS: CategoryMeta(
        "Build artefacts", "🔨",
        "Compiler and bundler output such as node_modules, target, dist and "
        "__pycache__. Regenerable, but rebuilding takes time.", 7,
    ),
    Category.VIRTUAL_ENV: CategoryMeta(
        "Virtual environments", "🐍",
        "Python virtualenvs in scanned projects. Recreate them with your "
        "dependency manager if you still need the project.", 8,
    ),
    Category.DUPLICATES: CategoryMeta(
        "Duplicate files", "👯",
        "Byte-identical files found more than once. One copy is kept; the rest "
        "are proposed.", 9,
    ),
    Category.LARGE_FILES: CategoryMeta(
        "Largest files", "🐘",
        "The biggest individual files found. Information only -- DiskFree never "
        "proposes these automatically.", 10,
    ),
    Category.OLD_FILES: CategoryMeta(
        "Old downloads and files", "🕰️",
        "Files that have not been modified in months. These are personal data: "
        "review each one.", 11,
    ),
    Category.SYSTEM: CategoryMeta(
        "System space (manual)", "⚙️",
        "Space held by subsystems that must be cleaned with their own tools. "
        "DiskFree shows the exact command instead of running it.", 12,
    ),
    Category.OTHER: CategoryMeta(
        "Other", "❔", "Anything that does not fit a specific category.", 99,
    ),
}


class AggregateMode(str, Enum):
    """How matching files are collapsed into findings."""

    SELF = "self"          # one finding per file
    ROOT = "root"          # one finding per scan root
    ANCHOR = "anchor"      # one finding per containing anchor path
    LOGDIR = "logdir"      # one finding per nearest log-ish ancestor directory


@dataclass(frozen=True, slots=True)
class Matcher:
    """Declarative path test. All populated fields must match."""

    abs_paths: tuple[str, ...] = ()          # expanded templates; exact match
    only_under: tuple[str, ...] = ()         # expanded templates; must be inside
    names: frozenset[str] = frozenset()      # exact basename match
    name_regex: str | None = None            # regex on basename
    globs: tuple[str, ...] = ()              # fnmatch on basename
    rel_globs: tuple[str, ...] = ()          # fnmatch on path relative to root
    require_dir: bool | None = None
    require_sibling: frozenset[str] = frozenset()   # names present in same parent
    parents_contain: frozenset[str] = frozenset()   # any ancestor basename
    parent_is: tuple[str, ...] = ()                 # expanded templates; immediate parent
    require_own_file: bool = False                  # only files owned by this user
    min_age_days: float | None = None
    max_age_days: float | None = None
    min_bytes: int | None = None

    def is_empty(self) -> bool:
        return not any(
            (
                self.abs_paths,
                self.only_under,
                self.names,
                self.name_regex,
                self.globs,
                self.rel_globs,
                self.require_sibling,
                self.parents_contain,
                self.parent_is,
            )
        ) and self.require_dir is None


@dataclass(frozen=True, slots=True)
class Rule:
    """One cleaning rule."""

    id: str
    category: Category
    title: str
    description: str
    risk: Risk
    matcher: Matcher = field(default_factory=Matcher)
    default_selected: bool = False
    prune: bool = True
    aggregate: AggregateMode = AggregateMode.SELF
    anchors: tuple[str, ...] = ()
    anchor_names: frozenset[str] = frozenset({"log", "logs"})
    probe: bool = False
    computed: bool = False
    advisory: str | None = None
    max_items: int = 500
    #: Lower wins when several rules could match one entry. Absolute-path rules
    #: are always tested first regardless of this value.
    priority: int = 100
    #: Set for rules that identify a cache precisely enough (by name plus a known
    #: browser/vendor ancestor) to keep their declared risk inside a blocked home
    #: zone instead of being escalated by the generic zone heuristic.
    cache_specific: bool = False
    #: Empty means "every platform"; otherwise ``sys.platform`` values.
    platforms: tuple[str, ...] = ()
    #: Stand down inside the user's home directory. Used by rules that describe a
    #: shared system area (``/tmp``): if the home itself lives there -- containers,
    #: CI runners, live sessions -- the rule would otherwise claim every personal
    #: file in it. Home-aware rules already cover that ground.
    exclude_home: bool = False

    @property
    def actionable(self) -> bool:
        """Probe/computed-advisory rules never produce removable findings."""

        return not self.probe and self.advisory is None


# --------------------------------------------------------------------------
# Template expansion
# --------------------------------------------------------------------------


def expand_templates(home: Path | None = None) -> dict[str, str]:
    """Resolve ``{home}``, ``{cache}`` and friends for the current platform."""

    home = (home or Path.home()).expanduser()
    env = os.environ

    def pick(key: str, *fallbacks: Path) -> str:
        value = env.get(key)
        if value:
            return str(Path(value).expanduser())
        for candidate in fallbacks:
            return str(candidate)
        return ""

    if sys.platform == "win32":
        local_appdata = pick("LOCALAPPDATA", home / "AppData" / "Local")
        appdata = pick("APPDATA", home / "AppData" / "Roaming")
        cache = local_appdata
        config = appdata
        data = local_appdata
    elif sys.platform == "darwin":
        local_appdata = str(home / "Library" / "Application Support")
        appdata = local_appdata
        cache = str(home / "Library" / "Caches")
        config = str(home / "Library" / "Preferences")
        data = local_appdata
    else:
        local_appdata = ""
        appdata = ""
        cache = pick("XDG_CACHE_HOME", home / ".cache")
        config = pick("XDG_CONFIG_HOME", home / ".config")
        data = pick("XDG_DATA_HOME", home / ".local" / "share")

    tmp = env.get("TMPDIR") or env.get("TEMP") or env.get("TMP")
    if not tmp:
        tmp = r"C:\Windows\Temp" if sys.platform == "win32" else "/tmp"

    return {
        "home": str(home),
        "user": home.name,
        "cache": cache,
        "config": config,
        "data": data,
        "localappdata": local_appdata,
        "appdata": appdata,
        "tmp": str(Path(tmp).expanduser()),
        "vartmp": "/var/tmp" if sys.platform != "win32" else "",
        "varlog": "/var/log" if sys.platform != "win32" else "",
        "varcache": "/var/cache" if sys.platform != "win32" else "",
        "downloads": str(home / "Downloads"),
        "desktop": str(home / "Desktop"),
        "documents": str(home / "Documents"),
    }


def _apply(template: str, values: dict[str, str]) -> str | None:
    try:
        expanded = template.format(**values)
    except (KeyError, IndexError):
        return None
    if not expanded or any(part in expanded for part in ("{}", "{")):
        return None
    return expanded


# --------------------------------------------------------------------------
# The rule table (first match wins -- keep specific rules before generic ones)
# --------------------------------------------------------------------------

_PY_CACHE_DIRS = frozenset(
    {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox", ".pytype"}
)

_BUILD_DIRS = frozenset(
    {
        "node_modules",
        ".next",
        ".nuxt",
        ".output",
        ".parcel-cache",
        ".turbo",
        ".svelte-kit",
        ".vite",
        ".webpack",
        ".gradle",
        ".terraform",
        "bower_components",
        "coverage",
        ".nyc_output",
        "dist",
        "build",
        "out",
        "target",
        "obj",
        "bin",
        "DerivedData",
        "Pods",
        ".angular",
        ".cache-loader",
        "storybook-static",
        ".serverless",
        ".dynamodb",
        "htmlcov",
        ".eggs",
    }
)

_VENV_DIRS = frozenset({".venv", "venv", "env", ".virtualenv", ".env", "virtualenv"})

_LOG_GLOBS = (
    "*.log",
    "*.log.[0-9]",
    "*.log.[0-9]*",
    "*.log.gz",
    "*.log.bz2",
    "*.log.xz",
    "*.log.old",
    "*.out.log",
    "npm-debug.log*",
    "yarn-error.log*",
    "hs_err_pid*.log",
    "core.[0-9]*",
    "*.crash",
    "*.dmp",
)


#: Categories whose rules know precisely what a cache looks like.
_CACHE_CATEGORIES = frozenset(
    {Category.PACKAGE_CACHE, Category.BROWSER_CACHE, Category.APP_CACHE}
)


def _rule(
    rule_id: str,
    category: Category,
    title: str,
    description: str,
    risk: Risk,
    *,
    default_selected: bool = False,
    prune: bool = True,
    aggregate: AggregateMode = AggregateMode.SELF,
    anchors: tuple[str, ...] = (),
    advisory: str | None = None,
    probe: bool = False,
    computed: bool = False,
    max_items: int = 500,
    priority: int = 100,
    cache_specific: bool | None = None,
    platforms: tuple[str, ...] = (),
    exclude_home: bool = False,
    **matcher: object,
) -> Rule:
    if cache_specific is None:
        cache_specific = category in _CACHE_CATEGORIES
    return Rule(
        id=rule_id,
        category=category,
        title=title,
        description=description,
        risk=risk,
        matcher=Matcher(**matcher),  # type: ignore[arg-type]
        default_selected=default_selected,
        prune=prune,
        aggregate=aggregate,
        anchors=anchors,
        advisory=advisory,
        probe=probe,
        computed=computed,
        max_items=max_items,
        priority=priority,
        cache_specific=cache_specific,
        platforms=platforms,
        exclude_home=exclude_home,
    )


DEFAULT_RULES: tuple[Rule, ...] = (
    # ---------------- package manager caches -----------------------------
    _rule(
        "pkg-pip-cache", Category.PACKAGE_CACHE, "pip download cache",
        "Wheels and sdists pip keeps so repeat installs are offline. Re-downloaded "
        "on demand; `pip cache purge` is the vendor-blessed equivalent.",
        Risk.SAFE, default_selected=True, prune=True,
        abs_paths=("{cache}/pip", "{home}/.cache/pip", "{localappdata}/pip/cache"),
        priority=10
    ),
    _rule(
        "pkg-uv-cache", Category.PACKAGE_CACHE, "uv cache",
        "Cached wheels and source archives used by the uv package manager.",
        Risk.SAFE, default_selected=True, prune=True,
        abs_paths=("{cache}/uv", "{home}/.cache/uv", "{localappdata}/uv/cache"),
        priority=10
    ),
    _rule(
        "pkg-npm-cache", Category.PACKAGE_CACHE, "npm cache",
        "npm's content-addressable cache (`_cacache`). npm re-fetches what it needs.",
        Risk.SAFE, default_selected=True, prune=True,
        abs_paths=("{home}/.npm/_cacache", "{appdata}/npm-cache", "{localappdata}/npm-cache"),
        priority=10
    ),
    _rule(
        "pkg-yarn-cache", Category.PACKAGE_CACHE, "Yarn cache",
        "Yarn's global package cache.", Risk.SAFE, default_selected=True, prune=True,
        abs_paths=("{cache}/yarn", "{home}/.yarn/cache", "{localappdata}/Yarn/Cache",
                   "{appdata}/yarn/cache"),
        priority=10
    ),
    _rule(
        "pkg-pnpm-store", Category.PACKAGE_CACHE, "pnpm store",
        "pnpm's content-addressable package store. Projects that hard-link into it "
        "keep working, but a fresh install will re-download packages.",
        Risk.LOW, default_selected=False, prune=True,
        abs_paths=("{cache}/pnpm", "{home}/.pnpm-store", "{localappdata}/pnpm/store",
                   "{home}/.local/share/pnpm/store"),
        priority=10
    ),
    _rule(
        "pkg-cargo-cache", Category.PACKAGE_CACHE, "Cargo registry cache",
        "Downloaded crates and their extracted sources. `cargo fetch` restores them.",
        Risk.SAFE, default_selected=True, prune=True,
        abs_paths=("{home}/.cargo/registry/cache", "{home}/.cargo/registry/src"),
        priority=10
    ),
    _rule(
        "pkg-gradle-cache", Category.PACKAGE_CACHE, "Gradle caches",
        "Downloaded dependencies and derived build caches. The next Gradle build "
        "re-populates them (slowly).",
        Risk.LOW, default_selected=False, prune=True,
        abs_paths=("{home}/.gradle/caches", "{home}/.gradle/daemon",
                   "{localappdata}/gradle/caches"),
        priority=10
    ),
    _rule(
        "pkg-maven-repo", Category.PACKAGE_CACHE, "Maven repository",
        "Local Maven artefact repository. Maven re-downloads what a build needs.",
        Risk.LOW, default_selected=False, prune=True,
        abs_paths=("{home}/.m2/repository",),
        priority=10
    ),
    _rule(
        "pkg-go-build", Category.PACKAGE_CACHE, "Go build cache",
        "Compiled package cache from `go build`. Equivalent to `go clean -cache`.",
        Risk.SAFE, default_selected=True, prune=True,
        abs_paths=("{cache}/go-build", "{home}/Library/Caches/go-build",
                   "{localappdata}/go-build"),
        priority=10
    ),
    _rule(
        "pkg-go-mod-cache", Category.PACKAGE_CACHE, "Go module download cache",
        "Downloaded module zips under GOPATH/pkg/mod/cache. Equivalent to "
        "`go clean -modcache`.",
        Risk.LOW, default_selected=False, prune=True,
        abs_paths=("{home}/go/pkg/mod/cache",),
        priority=10
    ),
    _rule(
        "pkg-homebrew-cache", Category.PACKAGE_CACHE, "Homebrew download cache",
        "Bottle and source tarballs Homebrew keeps after installing. Equivalent to "
        "`brew cleanup -s`.",
        Risk.SAFE, default_selected=True, prune=True,
        abs_paths=("{cache}/Homebrew", "{home}/Library/Caches/Homebrew",
                   "{home}/.homebrew/cache"),
        priority=10
    ),
    _rule(
        "pkg-misc-cache", Category.PACKAGE_CACHE, "Other package manager caches",
        "Caches for composer, rubygems, nuget, conda, poetry, pre-commit and "
        "playwright. All are re-downloadable.",
        Risk.SAFE, default_selected=True, prune=True,
        abs_paths=(
            "{home}/.composer/cache", "{home}/.gem/cache", "{cache}/gem",
            "{home}/.nuget/packages", "{cache}/NuGet", "{localappdata}/NuGet/cache",
            "{home}/.conda/pkgs", "{home}/miniconda3/pkgs", "{home}/anaconda3/pkgs",
            "{cache}/pypoetry", "{cache}/pre-commit", "{cache}/ms-playwright",
            "{cache}/electron", "{cache}/electron-builder", "{cache}/cypress",
            "{cache}/typescript", "{cache}/node-gyp", "{cache}/nodenv",
            "{localappdata}/Yarn", "{cache}/pipx", "{cache}/huggingface",
            "{cache}/torch", "{cache}/modelscope", "{cache}/ollama",
        ),
        priority=10
    ),
    _rule(
        "pkg-apt-archives", Category.PACKAGE_CACHE, "Downloaded .deb packages",
        "Package files apt keeps after installing. Requires root to clear; "
        "`sudo apt-get clean` is the canonical command.",
        Risk.LOW, default_selected=False, prune=False, aggregate=AggregateMode.ROOT,
        anchors=("{varcache}/apt/archives",),
        only_under=("{varcache}/apt/archives",), globs=("*.deb", "*.udeb"),
        advisory="sudo apt-get clean",
        priority=85
    ),

    # ---------------- browser caches ------------------------------------
    _rule(
        "browser-cache-dirs", Category.BROWSER_CACHE, "Browser caches",
        "Cached images, scripts, shaders and service-worker storage for Chrome, "
        "Chromium, Edge, Brave, Vivaldi, Opera, Firefox and Safari. Passwords, "
        "cookies, history and bookmarks live in sibling directories and are never "
        "matched by this rule.",
        Risk.SAFE, default_selected=True, prune=True,
        names=frozenset(
            {
                "cache", "cache2", "code cache", "gpucache", "shadercache",
                "dawngraphitecache", "dawnwebgpucache", "blob_storage",
                "service worker", "cachestorage", "grphcache", "thumbnails",
            }
        ),
        parents_contain=frozenset(
            {
                "google-chrome", "chromium", "microsoft edge", "braveSoftware".lower(),
                "vivaldi", "opera", "firefox", "safari", "com.apple.safari",
                "chrome", "edge", "brave", "waterfox", "librewolf", "tor browser",
                "mozilla", "user data", "profiles", "webkit",
            }
        ),
        priority=20
    ),
    _rule(
        "browser-cache-roots", Category.BROWSER_CACHE, "Browser cache directories",
        "Whole per-browser cache trees on macOS and Linux.",
        Risk.SAFE, default_selected=True, prune=True,
        abs_paths=(
            "{cache}/google-chrome", "{cache}/chromium", "{cache}/microsoft-edge",
            "{cache}/brave", "{cache}/vivaldi", "{cache}/opera", "{cache}/mozilla",
            "{cache}/torbrowser", "{cache}/librewolf", "{cache}/waterfox",
            "{home}/Library/Caches/Google/Chrome", "{home}/Library/Caches/Firefox",
            "{home}/Library/Caches/com.apple.Safari",
            "{home}/Library/Caches/com.microsoft.Edge",
            "{localappdata}/Google/Chrome/User Data/ShaderCache",
            "{localappdata}/Microsoft/Edge/User Data/ShaderCache",
            "{localappdata}/Mozilla/Firefox/Profiles/cache2",
        ),
        priority=20
    ),

    # ---------------- application caches --------------------------------
    # Each entry directly inside the XDG/macOS cache root becomes its own
    # finding, so "pip cache 4.1 GB" is visible instead of one opaque
    # "~/.cache 9 GB" line. More specific rules above win on priority.
    _rule(
        "app-cache-xdg-children", Category.APP_CACHE, "Cache entries in ~/.cache",
        "One entry directly inside the XDG cache root. Everything under ~/.cache "
        "is regenerable by definition; applications recreate what they need.",
        Risk.SAFE, default_selected=True, prune=True, priority=50,
        parent_is=("{cache}", "{home}/.cache"),
        platforms=("linux", "darwin", "freebsd", "openbsd", "netbsd"),
    ),
    _rule(
        "app-cache-macos-children", Category.APP_CACHE, "Cache entries in ~/Library/Caches",
        "One entry directly inside the macOS user cache root.",
        Risk.SAFE, default_selected=True, prune=True, priority=50,
        parent_is=("{home}/Library/Caches",), platforms=("darwin",),
    ),
    _rule(
        "app-cache-named", Category.APP_CACHE, "Application cache folders",
        "Directories named like caches inside application data folders. Kept "
        "separate from ~/.cache so they can be reviewed on their own.",
        Risk.LOW, default_selected=False, prune=True,
        names=frozenset({"cache", "caches", "cachestorage", "shadercache", "thumbnails"}),
        only_under=("{data}", "{appdata}", "{localappdata}", "{home}"),
        priority=55
    ),
    _rule(
        "app-crash-dumps", Category.APP_CACHE, "Crash dumps and reports",
        "Crash reports and minidumps. Only useful if you are about to file a bug.",
        Risk.SAFE, default_selected=True, prune=True,
        names=frozenset({"crashpad", "crashreports", "crashdumps", "crashreporter",
                         "breakpad", "minidumps"}),
        priority=55
    ),
    _rule(
        "app-thumbnails", Category.APP_CACHE, "Thumbnail cache",
        "Image thumbnails generated by the file manager. Rebuilt as you browse.",
        Risk.SAFE, default_selected=True, prune=True,
        abs_paths=("{cache}/thumbnails", "{home}/.thumbnails",
                   "{localappdata}/Microsoft/Windows/Explorer"),
        names=frozenset({"thumbnails", ".thumbnails"}),
        priority=55
    ),

    # ---------------- trash --------------------------------------------
    _rule(
        "trash-freedesktop", Category.TRASH, "User trash",
        "Files already deleted through the file manager but still on disk. "
        "Emptying the trash is irreversible for those items.",
        Risk.MEDIUM, default_selected=False, prune=True,
        abs_paths=("{data}/Trash", "{home}/.local/share/Trash", "{home}/.Trash",
                   "{home}/.trash"),
        priority=30
    ),
    _rule(
        "trash-other", Category.TRASH, "Trash folders",
        "Other trash locations, including per-volume trash directories.",
        Risk.MEDIUM, default_selected=False, prune=True,
        names=frozenset({".trash", "trash", ".trash-1000", ".recycle"}),
        priority=30
    ),

    # ---------------- temporary files ----------------------------------
    _rule(
        "temp-files", Category.TEMP, "Stale temporary files",
        "Files in system temp directories that have not been modified recently. "
        "Fresh temp files are left alone because a running program may own them. "
        "Note that /tmp is often a RAM-backed tmpfs.",
        # LOW rather than SAFE: a running process may still own the file, so it
        # is never pre-ticked. The user opts in per scan.
        Risk.LOW, default_selected=False, prune=False, priority=90,
        aggregate=AggregateMode.ANCHOR,
        anchors=("{tmp}", "{vartmp}", "{localappdata}/Temp", "{cache}/tmp"),
        only_under=("{tmp}", "{vartmp}", "{localappdata}/Temp", "{cache}/tmp"),
        # Another user's temp file is none of our business, and removing a file a
        # running process still holds would only cause a confusing failure.
        require_own_file=True, min_age_days=2, exclude_home=True,
    ),
    _rule(
        "temp-dirs", Category.TEMP, "Temporary directories",
        "Whole scratch directories left behind by installers and applications.",
        Risk.LOW, default_selected=False, prune=True,
        names=frozenset({"tmp", "temp", "temporary files"}),
        only_under=("{home}", "{data}", "{localappdata}", "{appdata}"),
        min_age_days=7,
        priority=88
    ),

    # ---------------- logs ---------------------------------------------
    _rule(
        "log-files", Category.LOGS, "Rotated and stale log files",
        "Log files, rotated logs, core dumps and crash logs that have not been "
        "written to recently. Applications recreate their logs automatically.",
        Risk.MEDIUM, default_selected=False, prune=False,
        aggregate=AggregateMode.LOGDIR, globs=_LOG_GLOBS, min_age_days=7,
        max_items=5000,
        priority=60
    ),
    _rule(
        "log-dirs", Category.LOGS, "Log directories",
        "Dedicated log directories inside application data.",
        Risk.MEDIUM, default_selected=False, prune=True,
        names=frozenset({"logs", "log"}),
        only_under=("{home}", "{data}", "{localappdata}", "{appdata}"),
        min_age_days=7,
        priority=60
    ),

    # ---------------- build artefacts ----------------------------------
    _rule(
        "build-node-modules", Category.BUILD_ARTIFACTS, "node_modules",
        "Installed JavaScript dependencies. `npm install` / `pnpm install` "
        "recreates them, but it can take minutes per project.",
        Risk.LOW, default_selected=False, prune=True,
        names=frozenset({"node_modules"}), require_dir=True,
        priority=40
    ),
    _rule(
        "build-python-caches", Category.BUILD_ARTIFACTS, "Python tool caches",
        "Bytecode and tooling caches: __pycache__, .pytest_cache, .mypy_cache, "
        ".ruff_cache, .tox and .nox.",
        Risk.SAFE, default_selected=True, prune=True,
        names=_PY_CACHE_DIRS, require_dir=True,
        priority=40
    ),
    _rule(
        "build-target-cargo", Category.BUILD_ARTIFACTS, "Cargo target directory",
        "Rust build output. Only matched when the parent directory really is a "
        "Cargo project, so unrelated folders named `target` are left alone.",
        Risk.LOW, default_selected=False, prune=True,
        names=frozenset({"target"}), require_dir=True,
        require_sibling=frozenset({"cargo.toml", "cargo.lock"}),
        priority=40
    ),
    _rule(
        "build-maven-target", Category.BUILD_ARTIFACTS, "Maven/Gradle build output",
        "Java build output, matched only inside a Maven or Gradle project.",
        Risk.LOW, default_selected=False, prune=True,
        names=frozenset({"target", "build"}), require_dir=True,
        require_sibling=frozenset({"pom.xml", "build.gradle", "build.gradle.kts",
                                   "settings.gradle", "settings.gradle.kts"}),
        priority=40
    ),
    _rule(
        "build-web-dist", Category.BUILD_ARTIFACTS, "Web build output",
        "Bundler output such as dist, .next, .nuxt, .output, .turbo, coverage and "
        "DerivedData. Regenerable from source.",
        Risk.LOW, default_selected=False, prune=True,
        names=frozenset(
            {
                ".next", ".nuxt", ".output", ".parcel-cache", ".turbo", ".svelte-kit",
                ".vite", ".webpack", ".angular", ".serverless", ".dynamodb",
                "bower_components", "coverage", ".nyc_output", "htmlcov",
                "storybook-static", "DerivedData", "Pods", ".eggs", "dist-info",
            }
        ),
        require_dir=True,
        priority=40
    ),
    _rule(
        "build-generic-dist", Category.BUILD_ARTIFACTS, "Generic build directories",
        "Directories named dist, build or out that sit next to a project manifest. "
        "The manifest requirement avoids eating real data directories that happen "
        "to share a common name.",
        Risk.MEDIUM, default_selected=False, prune=True,
        names=frozenset({"dist", "build", "out", "obj"}), require_dir=True,
        require_sibling=frozenset(
            {
                "package.json", "cargo.toml", "pom.xml", "build.gradle", "makefile",
                "cmakelists.txt", "setup.py", "pyproject.toml", "meson.build",
                "configure", "build.sbt", "go.mod", "composer.json",
            }
        ),
        priority=40
    ),
    _rule(
        "build-terraform", Category.BUILD_ARTIFACTS, "Terraform plugin cache",
        "Downloaded provider plugins. `terraform init` fetches them again.",
        Risk.LOW, default_selected=False, prune=True,
        names=frozenset({".terraform"}), require_dir=True,
        priority=40
    ),

    # ---------------- virtualenvs --------------------------------------
    _rule(
        "venv-dirs", Category.VIRTUAL_ENV, "Python virtual environments",
        "Virtualenvs in scanned projects. Delete only if the project is finished: "
        "recreating one needs the dependency list and a working network.",
        Risk.MEDIUM, default_selected=False, prune=True,
        names=_VENV_DIRS, require_dir=True,
        require_sibling=frozenset({"pyvenv.cfg"}),
        priority=40
    ),
    _rule(
        "venv-by-marker", Category.VIRTUAL_ENV, "Python virtual environments",
        "Directories that contain a pyvenv.cfg marker, whatever they are called.",
        Risk.MEDIUM, default_selected=False, prune=True,
        names=_VENV_DIRS, require_dir=True,
        priority=40
    ),

    # ---------------- personal data ------------------------------------
    _rule(
        "old-downloads", Category.OLD_FILES, "Old files in Downloads",
        "Downloads untouched for months. These are personal files, so nothing is "
        "pre-selected and every item needs a deliberate choice.",
        Risk.HIGH, default_selected=False, prune=False,
        aggregate=AggregateMode.ANCHOR, anchors=("{downloads}",),
        only_under=("{downloads}", "{desktop}"), min_age_days=90, max_items=2000,
        priority=70
    ),

    # ---------------- computed passes ----------------------------------
    _rule(
        "duplicates", Category.DUPLICATES, "Duplicate files",
        "Byte-identical files detected by size bucket and then hash. The oldest "
        "copy is kept; the rest are proposed individually.",
        Risk.MEDIUM, default_selected=False, computed=True, priority=95,
    ),
    _rule(
        "large-files", Category.LARGE_FILES, "Largest files",
        "The biggest files found during the scan. Always high-risk and never "
        "pre-selected; the user may explicitly review and choose individual files.",
        Risk.HIGH, default_selected=False, computed=True,
        priority=95
    ),

    # ---------------- system probes (advisory only) ---------------------
    _rule(
        "sys-docker", Category.SYSTEM, "Docker images, volumes and build cache",
        "Docker keeps its data in a root-owned database and image store. Deleting "
        "files underneath it corrupts the daemon, so DiskFree only reports the "
        "size and hands you the official command.",
        Risk.FORBIDDEN, probe=True, advisory="docker system prune -a --volumes",
        abs_paths=("/var/lib/docker", "{home}/Library/Containers/com.docker.docker",
                   "{localappdata}/Docker"),
    ),
    _rule(
        "sys-journal", Category.SYSTEM, "systemd journal",
        "Persistent journald logs are managed by journald itself; truncating the "
        "files confuses it. Use the vacuum command instead.",
        Risk.FORBIDDEN, probe=True, platforms=("linux", "freebsd"),
        advisory="sudo journalctl --vacuum-time=2weeks",
        abs_paths=("/var/log/journal",),
    ),
    _rule(
        "sys-snap", Category.SYSTEM, "Snap revisions",
        "Old snap revisions are removed with snapd, not with rm.",
        Risk.FORBIDDEN, probe=True, platforms=("linux", "freebsd"), advisory="sudo snap list --all",
        abs_paths=("/var/lib/snapd/snaps", "/snap"),
    ),
    _rule(
        "sys-flatpak", Category.SYSTEM, "Flatpak runtimes",
        "Unused Flatpak runtimes and caches are removed by flatpak.",
        Risk.FORBIDDEN, probe=True, advisory="flatpak uninstall --unused",
        abs_paths=("{home}/.local/share/flatpak", "/var/lib/flatpak"),
    ),
    _rule(
        "sys-nix", Category.SYSTEM, "Nix store",
        "The Nix store is reference counted; deleting paths by hand breaks every "
        "profile that points at them.",
        Risk.FORBIDDEN, probe=True, platforms=("linux", "freebsd"),
        advisory="nix-collect-garbage -d",
        abs_paths=("/nix/store",),
    ),
    _rule(
        "sys-timeshift", Category.SYSTEM, "Time Machine local snapshots (macOS)",
        "APFS local snapshots are managed by Time Machine.",
        Risk.FORBIDDEN, probe=True, platforms=("darwin",),
        advisory="tmutil listlocalsnapshots / && sudo tmutil deletelocalsnapshots /",
        abs_paths=("{home}/Library/Application Support/MobileSync/Backup",),
    ),
    _rule(
        "sys-windows-hiberfil", Category.SYSTEM, "Hibernation file",
        "hiberfil.sys is locked by the kernel. Disabling hibernation removes it.",
        Risk.FORBIDDEN, probe=True, platforms=("win32",), advisory="powercfg /h off",
        abs_paths=(r"C:\hiberfil.sys", r"C:\swapfile.sys"),
    ),
    _rule(
        "sys-windows-recycle", Category.SYSTEM, "Windows Recycle Bin",
        "The Recycle Bin is owned by the shell; empty it from Windows rather than "
        "by deleting files underneath it.",
        Risk.FORBIDDEN, probe=True, platforms=("win32",), advisory="rd /s /q C:\\$Recycle.Bin",
        abs_paths=(r"C:\$Recycle.Bin",),
    ),
    _rule(
        "sys-windows-update", Category.SYSTEM, "Windows Update cache",
        "Pending update payloads are managed by Windows Update / Disk Cleanup.",
        Risk.FORBIDDEN, probe=True, platforms=("win32",), advisory="cleanmgr /sageset:1",
        abs_paths=(r"C:\Windows\SoftwareDistribution\Download",),
    ),
    _rule(
        "sys-package-cleanup", Category.SYSTEM, "Orphaned system packages",
        "Distribution package managers own these trees.",
        Risk.FORBIDDEN, probe=True,
        advisory="sudo apt-get autoremove --purge   # or: sudo dnf autoremove",
        abs_paths=("/var/cache/apt", "/var/cache/dnf", "/var/cache/yum"),
    ),
)


# --------------------------------------------------------------------------
# Compiled rules
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CompiledRule:
    """A rule with every template expanded and every comparison set pre-folded.

    The scanner evaluates these against millions of directory entries, so all
    case folding and glob lowering happens once, here, instead of per entry.
    """

    rule: Rule
    abs_paths: tuple[str, ...]
    abs_folded: frozenset[str]
    only_under: tuple[str, ...]
    only_under_folded: tuple[str, ...]
    anchors: tuple[str, ...]
    anchors_folded: tuple[str, ...]
    names_folded: frozenset[str]
    parents_folded: frozenset[str]
    siblings_folded: frozenset[str]
    globs_lower: tuple[str, ...]
    rel_globs_lower: tuple[str, ...]
    regex: re.Pattern[str] | None
    anchor_names_folded: frozenset[str]
    parent_is_folded: tuple[str, ...] = ()
    priority: int = 100
    cache_specific: bool = False
    exclude_home: bool = False

    @property
    def id(self) -> str:
        return self.rule.id

    @property
    def name_tests(self) -> bool:
        return bool(
            self.names_folded
            or self.regex is not None
            or self.globs_lower
            or self.rel_globs_lower
        )

    @property
    def constraint_only(self) -> bool:
        """Matches on position (containment or parent) rather than on the name."""

        return not (self.name_tests or self.abs_folded)

    @property
    def positional(self) -> bool:
        """True when at least one positional constraint can decide a match."""

        return bool(
            self.only_under_folded or self.parent_is_folded or self.parents_folded
        )


def compile_rule(rule: Rule, templates: dict[str, str]) -> CompiledRule | None:
    """Expand ``rule`` for this machine, or return ``None`` if it cannot apply."""

    abs_paths = tuple(
        path for path in (_apply(t, templates) for t in rule.matcher.abs_paths) if path
    )
    only_under = tuple(
        path for path in (_apply(t, templates) for t in rule.matcher.only_under) if path
    )
    anchors = tuple(path for path in (_apply(t, templates) for t in rule.anchors) if path)

    if rule.platforms and sys.platform not in rule.platforms:
        return None

    parent_is = tuple(
        path for path in (_apply(t, templates) for t in rule.matcher.parent_is) if path
    )

    matches_something = (
        abs_paths or only_under or anchors or parent_is or rule.matcher.names
        or rule.matcher.globs or rule.matcher.rel_globs or rule.matcher.name_regex
    )
    if not matches_something and not (rule.computed or rule.probe):
        # Nothing on this platform can ever match (a Windows-only rule on Linux),
        # and it is neither a computed pass nor a probe, so the rule is inert here.
        return None

    regex = (
        re.compile(rule.matcher.name_regex, re.IGNORECASE) if rule.matcher.name_regex else None
    )
    return CompiledRule(
        rule=rule,
        abs_paths=abs_paths,
        abs_folded=frozenset(_fold(p) for p in abs_paths),
        only_under=only_under,
        only_under_folded=tuple(_fold(p) for p in only_under),
        anchors=anchors,
        anchors_folded=tuple(_fold(p) for p in anchors),
        names_folded=frozenset(fold_name(n) for n in rule.matcher.names),
        parents_folded=frozenset(fold_name(p) for p in rule.matcher.parents_contain),
        siblings_folded=frozenset(fold_name(s) for s in rule.matcher.require_sibling),
        globs_lower=tuple(g.lower() for g in rule.matcher.globs),
        rel_globs_lower=tuple(g.lower() for g in rule.matcher.rel_globs),
        regex=regex,
        anchor_names_folded=frozenset(fold_name(n) for n in rule.anchor_names),
        parent_is_folded=tuple(dict.fromkeys(_fold(p) for p in parent_is)),
        priority=rule.priority,
        cache_specific=rule.cache_specific,
        exclude_home=rule.exclude_home,
    )


class RuleSet:
    """Compiled rules for one machine plus the matching entry points."""

    def __init__(
        self,
        rules: tuple[Rule, ...] = DEFAULT_RULES,
        *,
        home: Path | None = None,
        templates: dict[str, str] | None = None,
    ) -> None:
        self.templates = templates or expand_templates(home)
        self.rules = rules
        self.compiled: list[CompiledRule] = []
        self.walk_rules: list[CompiledRule] = []
        self.probe_rules: list[CompiledRule] = []
        self.computed_rules: dict[str, CompiledRule] = {}
        self.by_id: dict[str, Rule] = {rule.id: rule for rule in rules}

        self._by_abs: dict[str, CompiledRule] = {}
        self._by_name: dict[str, list[CompiledRule]] = {}
        self._generic: list[CompiledRule] = []
        self.separator = "\\" if sys.platform == "win32" else "/"
        self.home_prefix = _fold(self.templates.get("home") or "")
        self._build()

    # -- construction ----------------------------------------------------
    def _build(self) -> None:
        for rule in self.rules:
            compiled = compile_rule(rule, self.templates)
            if compiled is None:
                continue
            self.compiled.append(compiled)
            if rule.computed:
                self.computed_rules[rule.id] = compiled
                continue
            if rule.probe:
                if compiled.abs_paths:
                    self.probe_rules.append(compiled)
                continue

            self.walk_rules.append(compiled)
            for path in compiled.abs_folded:
                self._by_abs.setdefault(path, compiled)

            if compiled.names_folded:
                for name in compiled.names_folded:
                    self._by_name.setdefault(name, []).append(compiled)
            if compiled.regex is not None or compiled.globs_lower or compiled.rel_globs_lower:
                # Pattern rules cannot be indexed by exact name; they are checked
                # against every entry. There are only a handful of them.
                self._generic.append(compiled)
            elif compiled.constraint_only:
                # Containment-only rules (only_under / parent_is) also need a look
                # at every entry.
                self._generic.append(compiled)

        # Deterministic evaluation order: explicit priority, then table order.
        table_order = {rule.id: index for index, rule in enumerate(self.rules)}

        def sort_key(item: CompiledRule) -> tuple[int, int]:
            return (item.priority, table_order.get(item.id, 999))

        for bucket in self._by_name.values():
            bucket.sort(key=sort_key)
        self._generic.sort(key=sort_key)

    # -- lookups ---------------------------------------------------------
    def get(self, rule_id: str) -> Rule | None:
        return self.by_id.get(rule_id)

    def compiled_for(self, rule_id: str) -> CompiledRule | None:
        for compiled in self.compiled:
            if compiled.id == rule_id:
                return compiled
        return None

    def candidates(self, folded_path: str, folded_name: str) -> list[CompiledRule]:
        """Rules worth testing for one entry, in priority order."""

        hits: list[CompiledRule] = []
        seen: set[str] = set()
        direct = self._by_abs.get(folded_path)
        if direct is not None:
            hits.append(direct)
            seen.add(direct.id)
        for compiled in self._by_name.get(folded_name, ()):
            if compiled.id not in seen:
                hits.append(compiled)
                seen.add(compiled.id)
        for compiled in self._generic:
            if compiled.id not in seen:
                hits.append(compiled)
                seen.add(compiled.id)
        return hits

    def match(
        self,
        *,
        path: Path,
        name: str,
        rel: str,
        is_dir: bool,
        size: int,
        age_days: float,
        siblings: frozenset[str],
        parents: frozenset[str],
        own_file: bool = True,
    ) -> CompiledRule | None:
        """Return the first compiled rule that matches one filesystem entry."""

        folded_path = _fold(str(path))
        folded_name = fold_name(name)
        for compiled in self.candidates(folded_path, folded_name):
            if self._matches(
                compiled,
                folded_path=folded_path,
                folded_name=folded_name,
                name=name,
                rel=rel,
                is_dir=is_dir,
                size=size,
                age_days=age_days,
                siblings=siblings,
                parents=parents,
                own_file=own_file,
            ):
                return compiled
        return None

    def _in_home(self, folded_path: str) -> bool:
        """True when ``folded_path`` is the home directory or lives inside it."""

        home = self.home_prefix
        if not home:
            return False
        return folded_path == home or folded_path.startswith(home + self.separator)

    def _matches(
        self,
        compiled: CompiledRule,
        *,
        folded_path: str,
        folded_name: str,
        name: str,
        rel: str,
        is_dir: bool,
        size: int,
        age_days: float,
        siblings: frozenset[str],
        parents: frozenset[str],
        own_file: bool = True,
    ) -> bool:
        """Evaluate one compiled rule against one entry.

        Shape checks first (free), then identity, then name patterns, then the
        containment constraints which must all hold.
        """

        matcher = compiled.rule.matcher
        if compiled.exclude_home and self._in_home(folded_path):
            return False
        if matcher.require_own_file and not own_file:
            return False
        if matcher.require_dir is not None and matcher.require_dir != is_dir:
            return False
        if matcher.min_age_days is not None and age_days < matcher.min_age_days:
            return False
        if matcher.max_age_days is not None and age_days > matcher.max_age_days:
            return False
        if matcher.min_bytes is not None and size < matcher.min_bytes:
            return False

        if compiled.abs_folded and folded_path in compiled.abs_folded:
            # Exact location match: nothing left to prove.
            return True

        if compiled.name_tests:
            if compiled.names_folded and folded_name not in compiled.names_folded:
                return False
            if compiled.regex is not None and not compiled.regex.search(name):
                return False
            if compiled.globs_lower and not any(
                fnmatch.fnmatch(folded_name, pattern) for pattern in compiled.globs_lower
            ):
                return False
            if compiled.rel_globs_lower and not any(
                fnmatch.fnmatch(rel.lower(), pattern) for pattern in compiled.rel_globs_lower
            ):
                return False
        elif not (
            compiled.only_under_folded
            or compiled.parent_is_folded
            or compiled.parents_folded
        ):
            # No name pattern and no positional test: nothing can ever match.
            return False

        if compiled.only_under_folded and not any(
            _is_below(folded_path, anchor) for anchor in compiled.only_under_folded
        ):
            return False
        if compiled.parents_folded and not (parents & compiled.parents_folded):
            return False
        if compiled.parent_is_folded:
            separator = self.separator
            parent = folded_path.rsplit(separator, 1)[0] or separator
            if parent not in compiled.parent_is_folded:
                return False
        if compiled.siblings_folded:
            return bool(siblings & compiled.siblings_folded)
        return True

    def group_key(self, compiled: CompiledRule, path: Path, root: Path) -> str:
        """Where a matched file's finding should be aggregated."""

        mode = compiled.rule.aggregate
        if mode is AggregateMode.SELF:
            return str(path)
        folded = _fold(str(path))
        if mode is AggregateMode.ANCHOR:
            for anchor, anchor_folded in zip(
                compiled.anchors, compiled.anchors_folded, strict=True
            ):
                if _is_below(folded, anchor_folded):
                    return anchor
            return str(root)
        if mode is AggregateMode.LOGDIR:
            for parent in path.parents:
                if fold_name(parent.name) in compiled.anchor_names_folded:
                    return str(parent)
            try:
                parts = path.relative_to(root).parts
            except ValueError:
                return str(root)
            if len(parts) < 2:
                return str(root)
            return str(root / parts[0])
        return str(root)

    def probe_paths(self) -> list[tuple[CompiledRule, Path]]:
        """Absolute locations to stat once per scan for advisory findings."""

        out: list[tuple[CompiledRule, Path]] = []
        for compiled in self.probe_rules:
            for raw in compiled.abs_paths:
                candidate = Path(raw)
                try:
                    exists = candidate.exists()
                except OSError:
                    continue
                if exists:
                    out.append((compiled, candidate))
        return out


def _fold(text: str) -> str:
    """Case-fold a *path* for comparison; only case-insensitive platforms fold.

    ``/usr/lib`` and ``/usr/Lib`` are different places on Linux, so absolute
    path matching must stay case sensitive there.
    """

    return text.lower() if sys.platform in {"win32", "darwin"} else text


def fold_name(text: str) -> str:
    """Case-fold a single *file or directory name*, on every platform.

    A directory called ``Cache``, ``cache`` or ``CACHE`` is a cache wherever it
    lives, so name matching is deliberately lenient even on case-sensitive
    filesystems. Real-world examples: Chrome writes ``Cache`` on Linux, Firefox
    writes ``cache2``.
    """

    return text.lower()


def _is_below(candidate: str, root: str) -> bool:
    if not root:
        return False
    sep = "\\" if sys.platform == "win32" else "/"
    if root in {"/", "\\"}:
        return candidate == root
    if candidate == root:
        return True
    return candidate.startswith(root.rstrip(sep) + sep)

"""Self-update for DiskFree.

This module is deliberately **standard library only**. The whole point of an
updater is to run on a machine where DiskFree's dependencies may be missing,
half-installed, or installed for a different interpreter -- importing FastAPI to
fix FastAPI would defeat the purpose. ``updater.sh`` and ``updater.bat`` in the
repository root are thin launchers for it, so this works on a bare clone with
nothing but Python 3.11+ and git::

    ./updater.sh              # fetch, fast-forward, refresh dependencies
    ./updater.sh --check      # report what would change, touch nothing
    updater.bat --json        # machine-readable result for automation

What it will and will not do
----------------------------
* Fetches from ``origin`` and fast-forwards the current branch. A merge conflict
  or a diverged branch is reported, never resolved by force.
* Refuses to touch a dirty worktree, so local edits survive an update.
* Never runs ``git reset --hard``, ``git clean``, ``checkout -- .`` or anything
  else that discards work.
* Never deletes files, and never invokes the cleaner: updating DiskFree must not
  be able to become a way of running it.
* Installs dependencies with ``pip`` for the interpreter that runs this script,
  and reports (rather than guesses) when the environment is externally managed.
* Prints an explicit reminder that a running ``diskfree serve`` process keeps its
  old code until it is restarted.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PACKAGE_DIR_NAME = "diskfree"
REQUIRED_PYTHON = (3, 11)
DEFAULT_TIMEOUT = 900
REMOTE = "origin"

#: The branch DiskFree updates from. This repository's ``main`` predates the
#: implementation (it holds only the original README), so the updater tracks the
#: development branch; ``--branch`` always overrides it, and a checkout whose
#: remote has no such branch simply keeps following the branch it is on.
DEFAULT_BRANCH = "arena/0392f96c-diskfree"

#: Optional file in the checkout root that names the interpreter to use. Read by
#: ``updater.sh``, ``updater.bat`` and this module, so portable and embeddable
#: Python builds work the same way on Windows, Linux and macOS.
PYTHON_ENV_FILENAME = "python.env"

#: "Second python" -- for people whose first ``python`` is not the one DiskFree
#: should use. It is not a valid POSIX shell identifier (it starts with a digit),
#: so the launchers read it with ``printenv`` (bash) and delayed expansion (cmd)
#: rather than ``$2PY2`` / ``%2PY2%``, both of which mean something else.
TWO_PY_TWO = "2PY2"

#: Keys honoured inside ``python.env``, most specific first.
PYTHON_ENV_KEYS = ("DISKFREE_PYTHON", "PYTHON", TWO_PY_TWO)

#: Interpreter names tried when nothing was configured, in order.
FALLBACK_PYTHONS = ("python3", "python3.13", "python3.12", "python3.11", "python")

#: Absolute locations that matter when PATH is minimal (a service, cron, or a
#: double-clicked .bat): Homebrew on both macOS architectures, then the system.
FALLBACK_PYTHON_PATHS = (
    "/opt/homebrew/bin/python3",
    "/usr/local/bin/python3",
    "/usr/bin/python3",
)

#: Where a project-local virtualenv keeps its interpreter, per platform.
VENV_PYTHON_RELPATHS = (("bin", "python"), ("Scripts", "python.exe"))

#: The Windows launcher for "whatever Python 3 is installed".
PY_LAUNCHER = "py -3"

#: A marked JSON record survives harmless banners from sitecustomize / wrappers.
PROBE_MARKER = "DISKFREE_UPDATER_PROBE="
PROBE_SCRIPT = (
    "import json,sys;"
    "print('DISKFREE_UPDATER_PROBE='+json.dumps({"
    "'version':list(sys.version_info[:3]),"
    "'executable':sys.executable,"
    "'virtualenv':sys.prefix != getattr(sys, 'base_prefix', sys.prefix)"
    "}))"
)

# Fail fast instead of hanging on a credential prompt in a non-interactive shell.
GIT_ENV = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "echo",
    "LC_ALL": "C",
}

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def repo_root(start: Path | None = None) -> Path:
    """The directory that holds this package's parent (the checkout root)."""

    here = Path(start or Path(__file__)).resolve()
    for candidate in (here.parent, *here.parents):
        if (candidate / PACKAGE_DIR_NAME / "__init__.py").is_file():
            return candidate
    return here.parent


def read_version(root: Path) -> str:
    """Parse ``__version__`` out of the package without importing it."""

    init = root / PACKAGE_DIR_NAME / "__init__.py"
    try:
        tree = ast.parse(init.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return "unknown"
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__version__":
                    value = node.value
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        return value.value
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "__version__"
            and isinstance(node.value, ast.Constant)
        ):
            return str(node.value.value)
    return "unknown"


def in_virtualenv() -> bool:
    """True when the running interpreter lives in a virtual environment."""

    if getattr(sys, "base_prefix", sys.prefix) != sys.prefix:
        return True
    return bool(os.environ.get("VIRTUAL_ENV") or os.environ.get("CONDA_PREFIX"))


def has_git() -> bool:
    return shutil.which("git") is not None


def is_git_repo(root: Path) -> bool:
    return (root / ".git").exists()


# --------------------------------------------------------------------------
# which interpreter?
# --------------------------------------------------------------------------


def parse_env_file(path: Path) -> dict[str, str]:
    """Read a ``KEY=VALUE`` file the way all three launchers agree on.

    Tolerates blank lines, ``#`` and ``;`` comments, an ``export`` or ``set``
    prefix and one layer of quotes. The launchers parse this file instead of
    sourcing it (``2PY2`` is not a valid POSIX shell variable name). Inline
    comments are deliberately *not* stripped: a Windows path may contain ``#``.
    """

    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return values

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "@")) or line.lower().startswith("rem "):
            continue
        for prefix in ("export ", "set "):
            if line[: len(prefix)].lower() == prefix:
                line = line[len(prefix) :].strip()
        if len(line) >= 2 and line[0] == line[-1] and line[0] in "\"'":
            line = line[1:-1]
        key, separator, value = line.partition("=")
        if not separator:
            # A plain one-line path is the simplest portable format and is
            # convenient for embeddable Python. Treat it as PYTHON; dotenv-style
            # keys remain available when a file needs more than one setting.
            key, value = "PYTHON", line
        key = key.strip().strip("\"'")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1].strip()
        if key and value:
            values[key.upper()] = value
    return values


def expand_interpreter_path(value: str, root: Path) -> str:
    """Expand ``%ROOT%``/``$ROOT``/``~`` and make a relative path project-local.

    A portable Python usually sits next to the checkout, so ``2PY2=../python/
    python.exe`` and ``DISKFREE_PYTHON=./runtime/bin/python3`` both work.
    """

    text = (value or "").strip()
    for token in ("%ROOT%", "${ROOT}", "$ROOT"):
        if token in text:
            text = text.replace(token, str(root))
    text = os.path.expanduser(text)
    path = Path(text)
    if path.is_absolute():
        return str(path)
    # A bare executable name (``python3``, ``py -3``) is resolved via PATH,
    # unless a same-named portable executable exists in the project itself.
    # Paths with a separator are project-relative, not cwd-relative.
    has_separator = os.path.sep in text or bool(os.path.altsep and os.path.altsep in text)
    if not has_separator:
        local_path = root / path
        return str(local_path) if local_path.exists() else text
    return str(root / path)


def python_env_values(root: Path) -> dict[str, str]:
    """The recognised interpreter keys from ``<root>/python.env``."""

    found = parse_env_file(root / PYTHON_ENV_FILENAME)
    values: dict[str, str] = {}
    for key, value in found.items():
        upper = key.upper()
        if upper in PYTHON_ENV_KEYS and upper not in values:
            values[upper] = expand_interpreter_path(value, root)
    return values


@dataclass(slots=True)
class PythonCandidate:
    """One interpreter the updater could use, and what came of trying it."""

    path: str
    source: str
    explicit: bool = False
    probed: bool = False
    executable: str = ""
    usable: bool = False
    version: str = ""
    virtualenv: bool = False
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "source": self.source,
            "explicit": self.explicit,
            "probed": self.probed,
            "executable": self.executable,
            "usable": self.usable,
            "version": self.version,
            "virtualenv": self.virtualenv,
            "reason": self.reason,
        }


def version_at_least(version: str, minimum: tuple[int, int] = REQUIRED_PYTHON) -> bool:
    parts: list[int] = []
    for chunk in (version or "").split(".")[:2]:
        digits = "".join(character for character in chunk if character.isdigit())
        if not digits:
            return False
        parts.append(int(digits))
    return len(parts) == 2 and tuple(parts) >= minimum


def probe_python(candidate: PythonCandidate, *, timeout: int = 60) -> PythonCandidate:
    """Run the candidate once and record its version, or why it cannot be used."""

    candidate.probed = True
    text = (candidate.path or "").strip()
    if not text:
        candidate.reason = "no interpreter was named"
        return candidate

    # The Windows launcher is the only supported value containing arguments.
    # Every other value is treated as one executable path, including a path
    # with spaces (for example C:\\Program Files\\Python\\python.exe).
    launcher_args: list[str] = []
    if text.lower() in {"py -3", "py.exe -3"}:
        head, launcher_args = text.split()[0], text.split()[1:]
    else:
        head = text

    has_separator = os.path.sep in head or bool(os.path.altsep and os.path.altsep in head)
    if os.path.isabs(head) or has_separator:
        executable = head
    else:
        executable = shutil.which(head) or ""
    if not executable:
        candidate.reason = f"'{head}' was not found on PATH"
        return candidate
    if not Path(executable).exists():
        candidate.reason = f"{executable} does not exist"
        return candidate

    result = run([executable, *launcher_args, "-c", PROBE_SCRIPT], timeout=timeout)
    if not result.ok:
        candidate.reason = f"it did not run: {_tail(result.output, 200) or 'no output'}"
        return candidate
    payload = next(
        (
            line.partition(PROBE_MARKER)[2]
            for line in reversed(result.output.splitlines())
            if line.startswith(PROBE_MARKER)
        ),
        "",
    )
    try:
        probe = json.loads(payload)
        version_parts = probe["version"]
        version = ".".join(str(part) for part in version_parts[:3])
        resolved = str(probe["executable"])
        candidate.virtualenv = bool(probe["virtualenv"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        candidate.reason = f"unexpected output: {_tail(result.output, 160)}"
        return candidate

    candidate.version = version
    candidate.executable = resolved or executable
    if not version_at_least(version):
        candidate.reason = (
            f"Python {version or '?'} is older than "
            f"{'.'.join(map(str, REQUIRED_PYTHON))}"
        )
        return candidate
    candidate.usable = True
    return candidate


def python_candidates(root: Path, explicit: str | None = None) -> list[PythonCandidate]:
    """Every interpreter worth trying, most authoritative first.

    Order: ``--python``, ``DISKFREE_PYTHON``, ``python.env`` (its own keys or a
    plain path), ``2PY2``, a project-local virtualenv, the running interpreter,
    then platform launchers and PATH. The configured choices are *explicit*: if
    one is broken the report says so instead of quietly using a different Python.
    """

    candidates: list[PythonCandidate] = []
    seen: set[str] = set()

    def add(path: str, source: str, *, wanted: bool) -> None:
        key = (path or "").strip()
        if not key or key.lower() in seen:
            return
        seen.add(key.lower())
        candidates.append(PythonCandidate(key, source, explicit=wanted))

    if explicit:
        add(expand_interpreter_path(explicit, root), "--python", wanted=True)

    from_env = (os.environ.get("DISKFREE_PYTHON") or "").strip()
    if from_env:
        add(
            expand_interpreter_path(from_env, root),
            "DISKFREE_PYTHON (environment)",
            wanted=True,
        )

    env_file = python_env_values(root)
    for key in PYTHON_ENV_KEYS:
        if key in env_file:
            add(env_file[key], f"{PYTHON_ENV_FILENAME} ({key})", wanted=True)

    second = (os.environ.get(TWO_PY_TWO) or "").strip()
    if second:
        add(
            expand_interpreter_path(second, root),
            f"{TWO_PY_TWO} (environment)",
            wanted=True,
        )

    for name in (".venv", "venv"):
        for parts in VENV_PYTHON_RELPATHS:
            path = root.joinpath(name, *parts)
            if path.exists():
                add(str(path), f"{name}/ inside the project", wanted=False)

    if sys.executable:
        add(sys.executable, "the interpreter running DiskFree", wanted=False)

    if os.name == "nt":
        add(PY_LAUNCHER, "the Windows py launcher", wanted=False)
    for name in FALLBACK_PYTHONS:
        add(name, f"PATH ({name})", wanted=False)
    for path in FALLBACK_PYTHON_PATHS:
        add(path, path, wanted=False)
    return candidates


def resolve_python(
    root: Path, explicit: str | None = None, *, timeout: int = 60
) -> tuple[PythonCandidate | None, list[PythonCandidate]]:
    """The first interpreter that runs and is new enough, plus what was tried."""

    tried: list[PythonCandidate] = []
    chosen: PythonCandidate | None = None
    for candidate in python_candidates(root, explicit):
        probe_python(candidate, timeout=timeout)
        tried.append(candidate)
        if candidate.usable:
            chosen = candidate
            break
    return chosen, tried


def python_warnings(tried: Sequence[PythonCandidate]) -> list[str]:
    """Explain every interpreter that was *asked for* and could not be used."""

    return [
        f"{candidate.source}: '{candidate.path}' was not used — {candidate.reason}"
        for candidate in tried
        if candidate.explicit and not candidate.usable and candidate.reason
    ]


@dataclass(slots=True)
class CommandResult:
    """One subprocess call and what it produced."""

    argv: list[str]
    returncode: int
    output: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def run(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    extra_env: dict[str, str] | None = None,
) -> CommandResult:
    """Run a command, capturing output. Never raises for a non-zero exit."""

    command = [str(part) for part in argv]
    env = dict(os.environ)
    env.update(GIT_ENV)
    if extra_env:
        env.update(extra_env)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return CommandResult(command, 127, f"{command[0]}: not found ({exc})")
    except subprocess.TimeoutExpired:
        return CommandResult(
            command, 124, f"timed out after {timeout}s", timed_out=True
        )
    except OSError as exc:
        return CommandResult(command, 1, f"could not run {command[0]}: {exc}")
    output = "\n".join(
        part for part in (completed.stdout or "", completed.stderr or "") if part.strip()
    ).strip()
    _ = started
    return CommandResult(command, completed.returncode, output)


def _tail(text: str, limit: int = 1200) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else "…" + text[-limit:]


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Step:
    """One unit of work in the update, and how it went."""

    name: str
    ok: bool = True
    skipped: bool = False
    detail: str = ""
    output: str = ""
    hint: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "skipped": self.skipped,
            "detail": self.detail,
            "output": self.output,
            "hint": self.hint,
        }


@dataclass(slots=True)
class UpdateReport:
    """Everything the update did, for the console and for ``--json``."""

    root: str
    python: str
    before_version: str = "unknown"
    after_version: str = "unknown"
    before_commit: str = ""
    after_commit: str = ""
    branch: str = ""
    tracked_branch: str = DEFAULT_BRANCH
    requested_branch: str = ""
    python_version: str = ""
    python_source: str = ""
    python_warnings: list[str] = field(default_factory=list)
    dirty: bool = False
    untracked: int = 0
    upstream_known: bool = False
    commits_available: int = 0
    venv: bool = False
    steps: list[Step] = field(default_factory=list)
    new_commits: list[str] = field(default_factory=list)
    already_current: bool = False
    duration_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return all(step.ok or step.skipped for step in self.steps)

    @property
    def changed(self) -> bool:
        return self.before_commit != self.after_commit or (
            self.before_version != self.after_version
        )

    def add(self, step: Step) -> Step:
        self.steps.append(step)
        return step

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "changed": self.changed,
            "already_current": self.already_current,
            "root": self.root,
            "python": self.python,
            "python_version": self.python_version,
            "python_source": self.python_source,
            "python_warnings": self.python_warnings,
            "virtualenv": self.venv,
            "branch": self.branch,
            "tracked_branch": self.tracked_branch,
            "requested_branch": self.requested_branch,
            "dirty_worktree": self.dirty,
            "untracked_files": self.untracked,
            "upstream_known": self.upstream_known,
            "commits_available": self.commits_available,
            "before": {"version": self.before_version, "commit": self.before_commit},
            "after": {"version": self.after_version, "commit": self.after_commit},
            "new_commits": self.new_commits,
            "duration_seconds": round(self.duration_seconds, 2),
            "steps": [step.as_dict() for step in self.steps],
        }


class _Palette:
    """ANSI colours, only when stdout is a terminal."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)


def format_report(report: UpdateReport, *, colour: bool | None = None) -> str:
    """Human-readable summary of an update."""

    if colour is None:
        colour = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    palette = _Palette(colour)
    lines: list[str] = []

    lines.append(palette.bold("DiskFree updater"))
    lines.append(f"  checkout   {report.root}")
    if report.before_version and report.before_version != "unknown":
        lines.append(f"  version    {report.before_version}")
    python_line = f"  python     {report.python}"
    if report.python_version:
        python_line += f"  ({report.python_version}"
        python_line += ", virtualenv)" if report.venv else ", system)"
    if report.python_source:
        python_line += f"  [{report.python_source}]"
    lines.append(python_line)
    for warning in report.python_warnings:
        lines.append(palette.yellow(f"  ! {warning}"))
    if report.branch:
        state = "local changes" if report.dirty else "no local changes"
        if report.untracked:
            state += f", {report.untracked} untracked file(s)"
        lines.append(f"  branch     {report.branch} ({state})")
        if report.tracked_branch and report.tracked_branch != report.branch:
            lines.append(f"  tracking   {REMOTE}/{report.tracked_branch}")

    for step in report.steps:
        if step.skipped:
            mark, text = "-", palette.yellow(f"skip  {step.name}")
        elif step.ok:
            mark, text = "✓", palette.green(f"ok    {step.name}")
        else:
            mark, text = "✗", palette.red(f"FAIL  {step.name}")
        lines.append(f"  [{mark}] {text}")
        if step.detail:
            lines.append(f"        {step.detail}")
        if step.output and not step.ok:
            lines.append(palette.cyan(_indent(_tail(step.output, 600))))
        if step.hint:
            lines.append(palette.yellow(f"        hint: {step.hint}"))

    if report.new_commits:
        lines.append("")
        lines.append(palette.bold(f"New commits ({len(report.new_commits)}):"))
        for commit in report.new_commits[:25]:
            lines.append(f"  {commit}")
        if len(report.new_commits) > 25:
            lines.append(f"  … and {len(report.new_commits) - 25} more")

    lines.append("")
    if report.commits_available and not report.changed:
        lines.append(
            palette.yellow(
                f"{report.commits_available} update(s) available; checkout and dependencies "
                "were left unchanged (--check; remote refs were fetched). "
                "Re-run without --check to apply them."
            )
        )
    elif report.before_version != report.after_version:
        lines.append(
            palette.green(f"Updated {report.before_version} → {report.after_version}")
        )
    elif report.changed:
        lines.append(palette.green("Updated to the latest commit."))
    elif report.ok:
        lines.append(_unchanged_summary(report))
    if not report.ok:
        lines.append(palette.red("The update did not complete cleanly; see the steps above."))
    dependencies = _step(report, "dependencies")
    if dependencies is not None:
        lines.append(_dependencies_summary(dependencies))
    if report.changed:
        lines.append(
            palette.yellow(
                "Restart any running server (`diskfree serve`) to pick up the new code."
            )
        )
    return "\n".join(lines)


def _step(report: UpdateReport, name: str) -> Step | None:
    for step in reversed(report.steps):
        if step.name == name:
            return step
    return None


def _unchanged_summary(report: UpdateReport) -> str:
    """Say *why* the code did not move, from the steps that actually ran."""

    source = _step(report, "git update") or _step(report, "switch branch")
    if source is None:
        return "Nothing to update."
    detail = (source.detail or "").lower()

    if source.skipped:
        # A skipped step never compared anything, so "up to date" would be a lie.
        if "--no-git" in detail:
            return "--no-git: the checkout was left exactly as it is."
        if "not a git" in detail:
            return "This is not a git checkout (a release archive?), so there is nothing to pull."
        if "git is not installed" in detail:
            return "git is not installed, so the source could not be compared with the remote."
        if "does not exist" in detail:
            return (
                f"Could not compare with the remote: origin/{report.branch} does not exist, "
                "so the code was left as it is."
            )
        if detail:
            return f"The source was left unchanged ({source.detail})."
        return "The source was left unchanged."

    if source.ok:
        return "Already up to date."
    return "The source was left unchanged."


def _dependencies_summary(step: Step) -> str:
    """Report what happened to the dependencies, without claiming work not done."""

    detail = (step.detail or "").lower()
    if step.skipped:
        if "--no-deps" in detail:
            return "Dependencies were skipped (--no-deps)."
        if "source update failed" in detail:
            return "Dependencies were skipped because the source update failed."
        if "importable" in detail:
            return "Dependency check passed: every required package imports."
        if "missing" in detail:
            return (
                "Dependency check found missing packages; re-run without --check to "
                "install them."
            )
        return f"Dependencies were skipped ({step.detail})." if step.detail else (
            "Dependencies were skipped."
        )
    if not step.ok:
        return "Dependencies were NOT refreshed; see the dependencies step above."
    return "Dependencies were refreshed."


def _indent(text: str, prefix: str = "        ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())


# --------------------------------------------------------------------------
# git
# --------------------------------------------------------------------------


def git(root: Path, *args: str, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
    return run(["git", *args], cwd=root, timeout=timeout)


def current_branch(root: Path) -> str:
    result = git(root, "rev-parse", "--abbrev-ref", "HEAD", timeout=30)
    return result.output.strip() if result.ok else ""


def current_commit(root: Path) -> str:
    result = git(root, "rev-parse", "--short=12", "HEAD", timeout=30)
    return result.output.strip() if result.ok else ""


def worktree_status(root: Path) -> tuple[int, int]:
    """Count ``(modified tracked files, untracked files)``.

    Only tracked modifications can be lost by an update, so they are what stops a
    fast-forward. Untracked files are reported for information: git itself refuses
    a merge that would overwrite them, and inventories like ``.venv`` or build
    output would otherwise block every update.
    """

    result = git(root, "status", "--porcelain", timeout=60)
    if not result.ok:
        return 0, 0
    modified = untracked = 0
    for line in result.output.splitlines():
        if not line.strip():
            continue
        if line.startswith("??"):
            untracked += 1
        else:
            modified += 1
    return modified, untracked


def remote_branch_exists(root: Path, branch: str) -> bool:
    result = git(
        root, "rev-parse", "--verify", "--quiet", f"refs/remotes/{REMOTE}/{branch}",
        timeout=30,
    )
    return result.ok and bool(result.output.strip())


def local_branch_exists(root: Path, branch: str) -> bool:
    result = git(
        root, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}", timeout=30
    )
    return result.ok and bool(result.output.strip())


def commits_behind(root: Path, branch: str) -> int | None:
    """How many commits ``origin/<branch>`` is ahead, or ``None`` if unknown."""

    result = git(root, "rev-list", "--count", f"HEAD..{REMOTE}/{branch}", timeout=60)
    if not result.ok:
        return None
    try:
        return int(result.output.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None


def commit_log(root: Path, old: str, new: str) -> list[str]:
    if not old or not new or old == new:
        return []
    result = git(
        root, "log", "--no-decorate", "--pretty=format:%h %s", f"{old}..{new}", timeout=60
    )
    if not result.ok:
        return []
    return [line for line in result.output.splitlines() if line.strip()]


def missing_dependencies(root: Path, python: str) -> list[str]:
    """Third-party imports DiskFree needs that this interpreter cannot load."""

    probe = (
        "import importlib.util as u;"
        "print(' '.join(m for m in ('fastapi','uvicorn','httpx','pydantic')"
        " if u.find_spec(m) is None))"
    )
    result = run([python, "-c", probe], cwd=root, timeout=120)
    if not result.ok:
        return []
    return [name for name in result.output.split() if name]


# --------------------------------------------------------------------------
# the update itself
# --------------------------------------------------------------------------


@dataclass(slots=True)
class UpdateOptions:
    """What the caller asked for. Every default is the safe choice."""

    root: Path = field(default_factory=repo_root)
    branch: str | None = None
    #: ``None`` means resolve DISKFREE_PYTHON/python.env/2PY2, then local or running Python.
    python: str | None = None
    use_git: bool = True
    upgrade_dependencies: bool = True
    reinstall: bool = True
    check_only: bool = False
    allow_system_packages: bool = False
    timeout: int = DEFAULT_TIMEOUT
    quiet: bool = False


def _pip(options: UpdateOptions, *args: str) -> CommandResult:
    return run(
        [options.python, "-m", "pip", *args],
        cwd=options.root,
        timeout=options.timeout,
    )


def _handle_externally_managed(
    options: UpdateOptions, step_name: str, result: CommandResult
) -> Step:
    """PEP 668: explain instead of overriding the distribution's protection."""

    text = (result.output or "").lower()
    if "externally-managed-environment" not in text:
        return Step(step_name, ok=False, detail="pip failed", output=result.output)
    hint = (
        "This interpreter is managed by your OS. Create a virtual environment "
        "(`python3 -m venv .venv && .venv/bin/pip install -e .`) or install with "
        "pipx; alternatively re-run with --allow-system-packages."
    )
    if options.allow_system_packages:
        retry = _pip(options, *result.argv[3:], "--break-system-packages")
        if retry.ok:
            return Step(
                step_name,
                ok=True,
                detail="installed with --break-system-packages (as requested)",
                output=_tail(retry.output, 400),
            )
        return Step(
            step_name, ok=False, detail="pip failed even with --break-system-packages",
            output=retry.output, hint=hint,
        )
    return Step(step_name, ok=False, detail="refused: externally managed environment",
                output=result.output, hint=hint)


def preflight(options: UpdateOptions, report: UpdateReport) -> bool:
    """Environment checks. Returns False when continuing makes no sense."""

    # The interpreter that matters is the one DiskFree will be installed into,
    # which is not necessarily the one running this script.
    if not version_at_least(report.python_version):
        report.add(
            Step(
                "preflight",
                ok=False,
                detail=(
                    f"Python {report.python_version or 'unknown'} at {options.python} is too "
                    f"old; DiskFree needs {'.'.join(map(str, REQUIRED_PYTHON))} or newer"
                ),
                hint=(
                    "Point the updater at a newer interpreter: --python /path/to/python3.12, "
                    f"a {PYTHON_ENV_FILENAME} file in the project root, DISKFREE_PYTHON, or "
                    f"{TWO_PY_TWO} for a portable/embeddable Python."
                ),
            )
        )
        return False
    detail = (
        f"Python {report.python_version} at {options.python}"
        + (" (virtualenv)" if report.venv else " (system interpreter)")
    )
    if report.python_source:
        detail += f" — chosen from {report.python_source}"
    hint = ""
    if sys.version_info[:2] < REQUIRED_PYTHON:
        hint = (
            f"The updater itself is running under "
            f"{'.'.join(map(str, sys.version_info[:2]))}; dependencies will be installed "
            f"for Python {report.python_version}."
        )
    report.add(Step("preflight", detail=detail, hint=hint))
    if not (options.root / PACKAGE_DIR_NAME / "__init__.py").is_file():
        report.add(
            Step(
                "locate source",
                ok=False,
                detail=f"no {PACKAGE_DIR_NAME}/ package under {options.root}",
                hint="Run the updater from inside a DiskFree checkout.",
            )
        )
        return False
    report.add(Step("locate source", detail=str(options.root)))
    return True


def choose_branch(
    options: UpdateOptions, report: UpdateReport, root: Path
) -> str | None:
    """Decide which branch to track. ``None`` (and a step) when it cannot be used.

    ``--branch`` wins. Otherwise DiskFree tracks :data:`DEFAULT_BRANCH`, because
    that is where the product lives; a checkout whose remote has no such branch
    (a fork, an older mirror) keeps following the branch it is already on.
    """

    current = report.branch or current_branch(root)
    report.branch = current

    if options.branch:
        target = options.branch
        report.tracked_branch = target
        if not (remote_branch_exists(root, target) or local_branch_exists(root, target)):
            report.add(
                Step(
                    "choose branch",
                    ok=False,
                    detail=f"'{target}' was not found on {REMOTE} or in this checkout",
                    hint=(
                        "Run `git branch -a` to see what exists, or omit --branch to track "
                        f"{DEFAULT_BRANCH}."
                    ),
                )
            )
            return None
        return target

    if remote_branch_exists(root, DEFAULT_BRANCH):
        report.tracked_branch = DEFAULT_BRANCH
        if current != DEFAULT_BRANCH:
            report.add(
                Step(
                    "choose branch",
                    detail=(
                        f"{current or '(detached)'} → {DEFAULT_BRANCH}: DiskFree updates from "
                        f"{DEFAULT_BRANCH}. Pass --branch to follow another."
                    ),
                )
            )
        return DEFAULT_BRANCH

    # No such branch on this remote: follow the checkout's own branch and let
    # the comparison below report honestly if that has no upstream either.
    report.tracked_branch = current
    return current


def update_source(options: UpdateOptions, report: UpdateReport) -> bool:
    """Fetch and fast-forward. Returns True when the source is now current."""

    if not options.use_git:
        report.add(Step("git update", skipped=True, detail="--no-git: using the code as-is"))
        return True
    if not has_git():
        report.add(
            Step("git update", skipped=True, detail="git is not installed",
                 hint="Install git to receive updates, or download a new release archive.")
        )
        return True
    if not is_git_repo(options.root):
        report.add(
            Step("git update", skipped=True,
                 detail="not a git checkout (release archive?)",
                 hint="Replace the directory with a newer release to update the code.")
        )
        return True

    branch = report.branch or current_branch(options.root)
    report.branch = branch

    # Fetch before choosing a branch: only the remote knows which branches exist.
    fetched = git(options.root, "fetch", REMOTE, "--prune", timeout=options.timeout)
    if not fetched.ok:
        detail = "could not reach the remote"
        hint = "Check your network and `git remote -v`. Continuing with the local code."
        failure = fetched.output.lower()
        if "authentication" in failure or "could not read username" in failure:
            hint = ("GitHub needs authentication for this remote. Reconnect GitHub, or run "
                    "`git fetch` yourself once, then re-run the updater.")
        report.add(Step("git fetch", ok=False, detail=detail, output=fetched.output, hint=hint))
        return False
    report.add(Step("git fetch", detail=f"{REMOTE} fetched"))

    target = choose_branch(options, report, options.root)
    if target is None:
        return False

    if target != branch:
        if options.check_only:
            # --check promises not to alter the checkout, and switching branches
            # changes it: report the intention and compare against the remote
            # branch instead of checking it out.
            report.add(
                Step(
                    "switch branch",
                    skipped=True,
                    detail=(
                        f"would switch {branch} → {target}"
                        + (" (blocked: this checkout has local changes)" if report.dirty else "")
                    ),
                )
            )
        elif report.dirty:
            report.add(
                Step("switch branch", ok=False,
                     detail=f"worktree has local changes; not switching {branch} → {target}",
                     hint="Commit or stash your changes (`git stash`), then re-run. "
                          "DiskFree never discards your work.")
            )
            return False
        else:
            switched = git(options.root, "switch", target, timeout=120)
            if not switched.ok:
                report.add(
                    Step("switch branch", ok=False, output=switched.output,
                         detail=f"could not switch to '{target}'",
                         hint=f"Check the branch exists on {REMOTE} (`git branch -a`). "
                              "The checkout was left on its current branch.")
                )
                return False
            branch = target
            report.branch = target
            report.add(Step("switch branch", detail=f"now on {target}"))

    behind = commits_behind(options.root, target)
    report.upstream_known = behind is not None
    report.commits_available = behind or 0
    if behind is None:
        # No origin/<target> to compare against: say so rather than claim success.
        report.add(
            Step(
                "git update",
                skipped=True,
                detail=f"{REMOTE}/{target} does not exist; nothing to compare against",
                hint="Push the branch, or update a published one with `--branch main`. "
                     "The local code was left untouched.",
            )
        )
        return True
    if behind == 0 and branch == target:
        report.already_current = True
        report.add(Step("git update", detail=f"{target} is already up to date"))
        return True
    if options.check_only:
        detail = f"{behind} commit(s) available on {REMOTE}/{target}"
        if branch != target:
            detail += f" (this checkout is on {branch})"
        report.add(Step("git update", skipped=True, detail=detail))
        return True
    if report.dirty:
        report.add(
            Step("git update", ok=False,
                 detail="this checkout has uncommitted changes; not pulling",
                 hint="Commit or stash your work (`git stash`), then re-run the updater. "
                      "DiskFree never discards your changes.")
        )
        return False

    pulled = git(options.root, "merge", "--ff-only", f"{REMOTE}/{target}", timeout=options.timeout)
    if not pulled.ok:
        report.add(
            Step("git update", ok=False, detail="fast-forward was not possible",
                 output=pulled.output,
                 hint="Your branch has diverged from the remote. Rebase or merge it "
                      "yourself; the updater will not rewrite history.")
        )
        return False
    report.add(Step("git update", detail=f"fast-forwarded {target} ({behind} commit(s))"))
    return True


def update_dependencies(options: UpdateOptions, report: UpdateReport) -> bool:
    """Install/refresh the Python dependencies for this interpreter."""

    if not options.upgrade_dependencies:
        report.add(Step("dependencies", skipped=True, detail="--no-deps"))
        return True

    if report.venv:
        pip_upgrade = _pip(options, "install", "--upgrade", "pip", timeout=options.timeout)
        report.add(
            Step(
                "pip",
                ok=pip_upgrade.ok,
                skipped=not pip_upgrade.ok,
                detail="upgraded pip inside the virtualenv"
                if pip_upgrade.ok
                else "could not upgrade pip (continuing)",
                output="" if pip_upgrade.ok else _tail(pip_upgrade.output, 300),
            )
        )

    target = "-e" if is_git_repo(options.root) else "."
    args = ["install", "--upgrade"]
    if target == "-e":
        args += ["-e", "."]
    else:
        args.append(".")
    if options.check_only:
        missing = missing_dependencies(options.root, options.python)
        report.add(
            Step(
                "dependencies",
                skipped=True,
                ok=True,
                detail="all required packages are importable"
                if not missing
                else f"missing: {', '.join(missing)}",
                hint="" if not missing else "Re-run without --check to install them.",
            )
        )
        return not missing

    installed = _pip(options, *args)
    if installed.ok:
        report.add(
            Step(
                "dependencies",
                detail=f"installed DiskFree ({'editable' if target == '-e' else 'regular'}) "
                       f"and its dependencies",
                output=_tail(installed.output, 300),
            )
        )
        return True
    report.add(_handle_externally_managed(options, "dependencies", installed))
    return False


def verify(options: UpdateOptions, report: UpdateReport) -> bool:
    """Import the package and its dependencies to prove the update worked."""

    probe = (
        "import diskfree, fastapi, uvicorn, httpx, pydantic;"
        "print(diskfree.__version__)"
    )
    result = run(
        [options.python, "-c", probe],
        cwd=options.root,
        timeout=180,
        extra_env={"PYTHONPATH": str(options.root)},
    )
    if result.ok:
        report.after_version = result.output.strip().splitlines()[-1]
        report.add(
            Step("verify", detail=f"DiskFree {report.after_version} imports cleanly "
                                  f"(fastapi, uvicorn, httpx, pydantic)")
        )
        return True
    report.add(
        Step(
            "verify",
            ok=False,
            detail="DiskFree could not be imported after the update",
            output=result.output,
            hint="Re-run with --allow-system-packages inside a virtualenv, or check the "
                 "pip output above.",
        )
    )
    return False


def update(options: UpdateOptions | None = None) -> UpdateReport:
    """Run the whole update and report every step."""

    options = options or UpdateOptions()
    options.root = Path(options.root).resolve()

    chosen, tried = resolve_python(options.root, options.python)
    if chosen is not None:
        options.python = chosen.executable or chosen.path
        source = chosen.source
        version = chosen.version
        venv = chosen.virtualenv
    else:
        # Nothing configured works. Keep going with the interpreter that is
        # already running this script so the source can still be updated, and
        # say so in the report rather than pretending everything is fine.
        options.python = sys.executable or "python3"
        source = "nothing configured worked; using the running interpreter"
        version = "{}.{}.{}".format(*sys.version_info[:3])
        venv = in_virtualenv()

    report = UpdateReport(root=str(options.root), python=options.python)
    report.python_version = version
    report.python_source = source
    report.python_warnings = python_warnings(tried)
    report.venv = venv
    report.requested_branch = options.branch or ""
    started = time.monotonic()

    report.before_version = read_version(options.root)
    if is_git_repo(options.root) and has_git():
        report.branch = current_branch(options.root)
        report.before_commit = current_commit(options.root)
        modified, untracked = worktree_status(options.root)
        report.dirty = modified > 0
        report.untracked = untracked

    try:
        if not preflight(options, report):
            return report
        source_ok = update_source(options, report)
        if source_ok:
            update_dependencies(options, report)
        else:
            report.add(
                Step("dependencies", skipped=True, detail="skipped: the source update failed")
            )
        report.after_commit = current_commit(options.root) if has_git() else ""
        if report.before_commit and report.after_commit:
            report.new_commits = commit_log(
                options.root, report.before_commit, report.after_commit
            )
        report.after_version = read_version(options.root)
        if not options.check_only:
            verify(options, report)
    finally:
        report.duration_seconds = time.monotonic() - started
    return report


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="updater",
        description=(
            "Update DiskFree: fast-forward the checkout and refresh its Python "
            "dependencies. Never discards local work and never deletes files."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  ./updater.sh                  update in place\n"
            "  ./updater.sh --check          what would change?\n"
            "  ./updater.sh --show-python    which interpreter will be used, and why\n"
            "  ./updater.sh --branch main    follow a branch other than the default\n"
            "  ./updater.sh --no-deps        update the code only\n"
            "  ./updater.sh --json           machine-readable report\n"
            "\n"
            f"which interpreter is used, in order: --python, $DISKFREE_PYTHON,\n"
            f"{PYTHON_ENV_FILENAME} in the project root (DISKFREE_PYTHON / PYTHON / "
            f"{TWO_PY_TWO}, or a plain path), ${TWO_PY_TWO},\n"
            "a project venv, the running interpreter, then platform launchers / PATH.\n"
            f"Updates are taken from {REMOTE}/{DEFAULT_BRANCH} unless --branch says "
            "otherwise.\n"
        ),
    )
    parser.add_argument("-c", "--check", action="store_true", dest="check_only",
                        help="report what would change; refresh remote refs but leave the "
                             "checkout and dependencies untouched")
    parser.add_argument("-b", "--branch", default=None,
                        help=f"branch to update (default: {DEFAULT_BRANCH}, which is where "
                             "DiskFree's code lives; the current branch if the remote has "
                             "no such branch)")
    parser.add_argument("--no-git", action="store_true",
                        help="skip fetching; only refresh dependencies")
    parser.add_argument("--no-deps", action="store_true", dest="no_deps",
                        help="do not run pip; only update the source")
    parser.add_argument("--no-install", action="store_true", dest="no_install",
                        help="alias for --no-deps")
    parser.add_argument("--allow-system-packages", action="store_true",
                        help="pass --break-system-packages to pip when the OS marks the "
                             "interpreter as externally managed (prefer a virtualenv)")
    parser.add_argument("--python", default=None,
                        help="interpreter to install into (default: resolved from "
                             f"$DISKFREE_PYTHON, {PYTHON_ENV_FILENAME} in the project root "
                             f"(a key or plain path), ${TWO_PY_TWO}, a project venv, "
                             "the running interpreter, then PATH)")
    parser.add_argument("--show-python", action="store_true", dest="show_python",
                        help="print the interpreter resolution (including every candidate "
                             "that was rejected, and why) and exit")
    parser.add_argument("--root", default=None,
                        help="checkout to update (default: the one containing this script)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"seconds to allow per network command (default {DEFAULT_TIMEOUT})")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="only print warnings, errors and the final line")
    return parser


def show_python(
    root: Path, explicit: str | None = None, *, as_json: bool = False
) -> int:
    """Print which interpreter would be used, and why the others would not.

    Portable and embeddable Python installs are the usual reason to ask: the
    ``python`` on PATH is often not the one DiskFree should be installed into.
    """

    candidates = python_candidates(root, explicit)
    probed: list[PythonCandidate] = []
    chosen: PythonCandidate | None = None
    for candidate in candidates:
        if chosen is None:
            probe_python(candidate)
            if candidate.usable:
                chosen = candidate
        probed.append(candidate)

    if as_json:
        print(
            json.dumps(
                {
                    "root": str(root),
                    "python_env_file": str(root / PYTHON_ENV_FILENAME),
                    "python_env_present": (root / PYTHON_ENV_FILENAME).is_file(),
                    "python_env": python_env_values(root),
                    "environment": {
                        "DISKFREE_PYTHON": os.environ.get("DISKFREE_PYTHON"),
                        TWO_PY_TWO: os.environ.get(TWO_PY_TWO),
                    },
                    "selected": chosen.as_dict() if chosen else None,
                    "candidates": [candidate.as_dict() for candidate in probed],
                    "required_python": ".".join(map(str, REQUIRED_PYTHON)),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return EXIT_OK if chosen else EXIT_FAILED

    lines = [f"Interpreter resolution for {root}"]
    env_file = root / PYTHON_ENV_FILENAME
    values = python_env_values(root)
    lines.append(
        f"  {PYTHON_ENV_FILENAME}   "
        + (
            ", ".join(f"{key}={value}" for key, value in values.items())
            if values
            else ("present, but no recognised key" if env_file.is_file() else "not present")
        )
    )
    lines.append(
        f"  DISKFREE_PYTHON   {os.environ.get('DISKFREE_PYTHON') or 'not set'}"
    )
    lines.append(f"  {TWO_PY_TWO}{'':<12}{os.environ.get(TWO_PY_TWO) or 'not set'}")
    lines.append(
        f"  required          Python {'.'.join(map(str, REQUIRED_PYTHON))} or newer"
    )
    lines.append("")
    for index, candidate in enumerate(probed, start=1):
        if candidate is chosen:
            outcome = f"SELECTED (Python {candidate.version}"
            outcome += ", virtualenv)" if candidate.virtualenv else ", system)"
        elif not candidate.probed:
            outcome = "not tried (an earlier candidate was selected)"
        elif candidate.usable:
            outcome = "usable, but an earlier candidate won"
        else:
            outcome = f"rejected: {candidate.reason or 'unusable'}"
        lines.append(
            f"  {index:>2}. {candidate.source:<34} {candidate.path:<46} {outcome}"
        )
    lines.append("")
    if chosen is None:
        lines.append(
            f"No usable interpreter was found. Write the path to Python "
            f"{'.'.join(map(str, REQUIRED_PYTHON))}+ into {PYTHON_ENV_FILENAME} next to "
            f"this script, or set DISKFREE_PYTHON or {TWO_PY_TWO}."
        )
        print("\n".join(lines))
        return EXIT_FAILED
    lines.append(
        f"Selected {chosen.executable or chosen.path} (Python {chosen.version}) "
        f"from {chosen.source}."
    )
    print("\n".join(lines))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    root = Path(args.root).resolve() if args.root else repo_root()
    if args.show_python:
        return show_python(root, args.python, as_json=args.json)

    options = UpdateOptions(
        root=root,
        branch=args.branch,
        python=args.python,
        use_git=not args.no_git,
        upgrade_dependencies=not (args.no_deps or args.no_install),
        check_only=args.check_only,
        allow_system_packages=args.allow_system_packages,
        timeout=max(30, int(args.timeout)),
        quiet=args.quiet,
    )

    report = update(options)

    if args.json:
        print(json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
    elif not (args.quiet and report.ok and not report.changed):
        print(format_report(report))

    if not report.ok:
        return EXIT_FAILED
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - launcher entry point
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:  # pragma: no cover
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130) from None

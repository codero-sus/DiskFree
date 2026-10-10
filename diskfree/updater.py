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
            "virtualenv": self.venv,
            "branch": self.branch,
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
    lines.append(f"  python     {report.python}" + ("" if report.venv else "  (system)"))
    if report.branch:
        state = "local changes" if report.dirty else "no local changes"
        if report.untracked:
            state += f", {report.untracked} untracked file(s)"
        lines.append(f"  branch     {report.branch} ({state})")

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
                f"{report.commits_available} update(s) available; nothing was changed "
                "(--check). Re-run without --check to apply them."
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
    python: str = field(default_factory=lambda: sys.executable or "python3")
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

    version = sys.version_info[:2]
    if version < REQUIRED_PYTHON:
        report.add(
            Step(
                "preflight",
                ok=False,
                detail=(
                    f"Python {'.'.join(map(str, version))} is too old; DiskFree needs "
                    f"{'.'.join(map(str, REQUIRED_PYTHON))} or newer"
                ),
                hint="Run the updater with a newer interpreter, e.g. ./updater.sh after "
                     "setting DISKFREE_PYTHON=/usr/bin/python3.12",
            )
        )
        return False
    report.add(
        Step(
            "preflight",
            detail=(
                f"Python {sys.version.split()[0]} at {options.python}"
                + (" (virtualenv)" if report.venv else " (system interpreter)")
            ),
        )
    )
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
    if options.branch and options.branch != branch:
        if report.dirty:
            report.add(
                Step("switch branch", ok=False,
                     detail=f"worktree has local changes; not switching {branch} → "
                            f"{options.branch}",
                     hint="Commit or stash your changes, then re-run with --branch.")
            )
            return False
        switched = git(options.root, "switch", options.branch, timeout=120)
        if not switched.ok:
            fetched = git(options.root, "fetch", REMOTE, options.branch, timeout=options.timeout)
            switched = git(options.root, "switch", options.branch, timeout=120)
            if not switched.ok:
                report.add(
                    Step("switch branch", ok=False, output=switched.output or fetched.output,
                         detail=f"could not switch to '{options.branch}'",
                         hint=f"Check the branch name exists on {REMOTE}.")
                )
                return False
        branch = options.branch
        report.branch = branch
        report.add(Step("switch branch", detail=f"now on {branch}"))

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

    behind = commits_behind(options.root, branch)
    report.upstream_known = behind is not None
    report.commits_available = behind or 0
    if behind is None:
        # No origin/<branch> to compare against: say so rather than claim success.
        report.add(
            Step(
                "git update",
                skipped=True,
                detail=f"{REMOTE}/{branch} does not exist; nothing to compare against",
                hint="Push the branch, or update a published one with `--branch main`. "
                     "The local code was left untouched.",
            )
        )
        return True
    if behind == 0:
        report.already_current = True
        report.add(Step("git update", detail=f"{branch} is already up to date"))
        return True
    if options.check_only:
        report.add(
            Step("git update", skipped=True,
                 detail=f"{behind} commit(s) available on {REMOTE}/{branch}")
        )
        return True
    if report.dirty:
        report.add(
            Step("git update", ok=False,
                 detail="this checkout has uncommitted changes; not pulling",
                 hint="Commit or stash your work (`git stash`), then re-run the updater. "
                      "DiskFree never discards your changes.")
        )
        return False

    pulled = git(options.root, "merge", "--ff-only", f"{REMOTE}/{branch}", timeout=options.timeout)
    if not pulled.ok:
        report.add(
            Step("git update", ok=False, detail="fast-forward was not possible",
                 output=pulled.output,
                 hint="Your branch has diverged from the remote. Rebase or merge it "
                      "yourself; the updater will not rewrite history.")
        )
        return False
    report.add(Step("git update", detail=f"fast-forwarded {branch} ({behind} commit(s))"))
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
    report = UpdateReport(root=str(options.root), python=options.python)
    report.venv = in_virtualenv()
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
            "  ./updater.sh --branch main    follow a specific branch\n"
            "  ./updater.sh --no-deps        update the code only\n"
            "  ./updater.sh --json           machine-readable report\n"
        ),
    )
    parser.add_argument("-c", "--check", action="store_true", dest="check_only",
                        help="report what would change without modifying anything")
    parser.add_argument("-b", "--branch", default=None,
                        help="branch to update (default: the current one)")
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
                        help="interpreter to install into (default: the one running this "
                             "script)")
    parser.add_argument("--root", default=None,
                        help="checkout to update (default: the one containing this script)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"seconds to allow per network command (default {DEFAULT_TIMEOUT})")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="only print warnings, errors and the final line")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    root = Path(args.root).resolve() if args.root else repo_root()
    python = args.python or sys.executable or "python3"
    options = UpdateOptions(
        root=root,
        branch=args.branch,
        python=python,
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

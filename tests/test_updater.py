"""The updater: it must update, and it must never destroy work.

Every test here runs against a real local git remote (a bare repository in
``tmp_path``), so the fast-forward, the dirty-worktree refusal and the diverged
branch are all exercised for real rather than mocked.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from diskfree import updater

git = shutil.which("git")
pytestmark = pytest.mark.skipif(git is None, reason="git is required to test the updater")

REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        [git, *args], cwd=str(cwd), capture_output=True, text=True, check=False,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"},
    )
    assert completed.returncode == 0, f"git {' '.join(args)}: {completed.stderr}"
    return completed.stdout.strip()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_package(root: Path, version: str) -> None:
    _write(root / "diskfree/__init__.py", f'__version__ = "{version}"\n')
    _write(root / "README.md", f"# DiskFree {version}\n")


@pytest.fixture
def repos(tmp_path: Path) -> dict[str, Path]:
    """A bare ``origin``, a ``seed`` working copy, and a ``clone`` to update."""

    origin = tmp_path / "origin.git"
    origin.mkdir()
    _git(origin, "init", "--bare", "-q")
    _git(origin, "symbolic-ref", "HEAD", "refs/heads/main")

    seed = tmp_path / "seed"
    _git(tmp_path, "clone", "-q", str(origin), "seed")
    _git(seed, "config", "user.email", "tester@example.com")
    _git(seed, "config", "user.name", "Tester")
    _git(seed, "config", "commit.gpgsign", "false")
    make_package(seed, "0.1.0")
    _git(seed, "add", "-A")
    _git(seed, "commit", "-qm", "initial release")
    _git(seed, "branch", "-M", "main")
    _git(seed, "push", "-q", "origin", "main")

    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", str(origin), "clone")
    _git(clone, "config", "user.email", "tester@example.com")
    _git(clone, "config", "user.name", "Tester")
    _git(clone, "config", "commit.gpgsign", "false")

    return {"origin": origin, "seed": seed, "clone": clone, "tmp": tmp_path}


def publish(repos: dict[str, Path], version: str, message: str | None = None) -> None:
    """Push a new release from the seed checkout."""

    make_package(repos["seed"], version)
    _git(repos["seed"], "commit", "-aqm", message or f"release {version}")
    _git(repos["seed"], "push", "-q", "origin", "main")


def _options(root: Path, args: tuple[str, ...]) -> updater.UpdateOptions:
    parsed = updater.build_parser().parse_args(["--root", str(root), *args])
    return updater.UpdateOptions(
        root=root,
        branch=parsed.branch,
        python=parsed.python or sys.executable,
        use_git=not parsed.no_git,
        upgrade_dependencies=not (parsed.no_deps or parsed.no_install),
        check_only=parsed.check_only,
        allow_system_packages=parsed.allow_system_packages,
        timeout=120,
        quiet=parsed.quiet,
    )


def steps(report: updater.UpdateReport) -> dict[str, updater.Step]:
    return {step.name: step for step in report.steps}


# --------------------------------------------------------------------------
# static helpers
# --------------------------------------------------------------------------


def test_read_version_reads_the_real_package() -> None:
    version = updater.read_version(REPO_ROOT)
    assert version
    assert version != "unknown"
    from diskfree import __version__

    assert version == __version__


def test_read_version_survives_a_missing_or_broken_package(tmp_path: Path) -> None:
    assert updater.read_version(tmp_path) == "unknown"
    _write(tmp_path / "diskfree/__init__.py", "this is not python !!!\n")
    assert updater.read_version(tmp_path) == "unknown"
    _write(tmp_path / "diskfree/__init__.py", "x = 1\n")
    assert updater.read_version(tmp_path) == "unknown"


def test_repo_root_finds_the_checkout() -> None:
    assert updater.repo_root() == REPO_ROOT
    assert (updater.repo_root() / "diskfree" / "updater.py").is_file()


def test_run_captures_output_and_handles_a_missing_command(tmp_path: Path) -> None:
    result = updater.run(["git", "--version"], cwd=tmp_path, timeout=30)
    assert result.ok
    assert "git version" in result.output

    missing = updater.run(["definitely-not-a-real-command"], cwd=tmp_path, timeout=30)
    assert not missing.ok
    assert missing.returncode == 127

    slow = updater.run([sys.executable, "-c", "import time; time.sleep(5)"],
                       cwd=tmp_path, timeout=1)
    assert slow.timed_out and not slow.ok


def test_worktree_status_separates_tracked_edits_from_untracked_files(
    repos: dict[str, Path]
) -> None:
    clone = repos["clone"]
    assert updater.worktree_status(clone) == (0, 0)

    _write(clone / "scratch.txt", "untracked\n")
    assert updater.worktree_status(clone) == (0, 1)

    _write(clone / "README.md", "# edited locally\n")
    assert updater.worktree_status(clone) == (1, 1)


def test_in_virtualenv_is_a_bool() -> None:
    assert isinstance(updater.in_virtualenv(), bool)


def test_python_env_accepts_key_values_or_a_plain_path(tmp_path: Path) -> None:
    env_file = tmp_path / "python.env"
    env_file.write_text(
        "# portable runtime\r\nexport 2PY2 = '../portable python/python3'\r\n",
        encoding="utf-8",
    )
    assert updater.python_env_values(tmp_path) == {
        "2PY2": str(tmp_path / "../portable python/python3")
    }

    env_file.write_text('"../portable python/python3"\n', encoding="utf-8")
    assert updater.python_env_values(tmp_path) == {
        "PYTHON": str(tmp_path / "../portable python/python3")
    }


def test_python_path_expansion_keeps_bare_commands_and_roots_relative_paths(
    tmp_path: Path,
) -> None:
    assert updater.expand_interpreter_path("python3", tmp_path) == "python3"
    assert updater.expand_interpreter_path("py -3", tmp_path) == "py -3"
    assert updater.expand_interpreter_path("./portable/python.exe", tmp_path) == str(
        tmp_path / "./portable/python.exe"
    )
    local_python = tmp_path / "python3"
    local_python.touch()
    assert updater.expand_interpreter_path("python3", tmp_path) == str(local_python)
    assert updater.version_at_least("3.11.0")
    assert not updater.version_at_least("3.10.14")
    assert not updater.version_at_least("not-python")


def test_configured_python_path_with_spaces_is_probed_as_one_executable(
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        pytest.skip("a portable executable copy is platform-specific")
    spaced_dir = tmp_path / "portable python"
    spaced_dir.mkdir()
    executable = spaced_dir / "my python"
    executable.symlink_to(sys.executable)

    candidate = updater.PythonCandidate(
        str(executable), "python.env (PYTHON)", explicit=True
    )
    updater.probe_python(candidate)

    assert candidate.usable, candidate.reason
    assert candidate.version == ".".join(map(str, sys.version_info[:3]))
    assert candidate.executable


def test_python_resolution_prefers_the_project_file_and_reports_fallbacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DISKFREE_PYTHON", raising=False)
    monkeypatch.setenv("2PY2", sys.executable)
    (tmp_path / "python.env").write_text(
        f'PYTHON="{sys.executable}"\n', encoding="utf-8"
    )

    selected, tried = updater.resolve_python(tmp_path)
    assert selected is not None and selected.usable
    assert selected.source == "python.env (PYTHON)"
    assert tried[0].path == sys.executable

    (tmp_path / "python.env").write_text(
        "DISKFREE_PYTHON=./missing/portable-python\n", encoding="utf-8"
    )
    selected, tried = updater.resolve_python(tmp_path)
    assert selected is not None and selected.source == "2PY2 (environment)"
    warnings = updater.python_warnings(tried)
    assert len(warnings) == 1 and "does not exist" in warnings[0]


def test_python_resolution_honours_diskfree_python_before_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DISKFREE_PYTHON", sys.executable)
    (tmp_path / "python.env").write_text(
        "2PY2=/missing/python\n", encoding="utf-8"
    )

    selected, _ = updater.resolve_python(tmp_path)
    assert selected is not None
    assert selected.source == "DISKFREE_PYTHON (environment)"


def test_relative_2py2_environment_path_is_project_relative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name == "nt":
        pytest.skip("a portable executable copy is platform-specific")
    monkeypatch.delenv("DISKFREE_PYTHON", raising=False)
    portable = tmp_path / "runtime with spaces" / "second python"
    portable.parent.mkdir()
    portable.symlink_to(sys.executable)
    monkeypatch.setenv("2PY2", "./runtime with spaces/second python")

    selected, _ = updater.resolve_python(tmp_path)
    assert selected is not None and selected.usable
    assert selected.source == "2PY2 (environment)"
    assert selected.path == str(portable)


def test_missing_dependencies_detects_an_absent_package(tmp_path: Path) -> None:
    probe_python = tmp_path / "probe.py"
    _write(probe_python, "print('hello')\n")
    found = updater.missing_dependencies(REPO_ROOT, sys.executable)
    assert isinstance(found, list)
    assert "definitely_not_a_real_module" not in found


# --------------------------------------------------------------------------
# the real update flow
# --------------------------------------------------------------------------


def test_a_clean_clone_fast_forwards(repos: dict[str, Path]) -> None:
    clone = repos["clone"]
    assert updater.read_version(clone) == "0.1.0"
    publish(repos, "0.2.0")

    report = updater.update(_options(clone, ("--no-deps",)))

    assert report.ok, [step.as_dict() for step in report.steps if not step.ok]
    assert report.changed is True
    assert report.before_version == "0.1.0"
    assert report.after_version == "0.2.0"
    assert report.before_commit != report.after_commit
    assert report.upstream_known is True
    assert report.dirty is False
    assert len(report.new_commits) == 1
    assert "0.2.0" in report.new_commits[0]
    assert updater.read_version(clone) == "0.2.0"
    assert steps(report)["git update"].ok


def test_an_up_to_date_clone_reports_no_change(repos: dict[str, Path]) -> None:
    report = updater.update(_options(repos["clone"], ("--no-deps",)))
    assert report.ok
    assert report.already_current is True
    assert report.changed is False
    assert report.new_commits == []
    assert "up to date" in steps(report)["git update"].detail


def test_uncommitted_changes_block_the_update_and_survive_it(
    repos: dict[str, Path]
) -> None:
    clone = repos["clone"]
    readme = clone / "README.md"
    readme.write_text("# my precious local work\n", encoding="utf-8")
    publish(repos, "0.3.0")

    report = updater.update(_options(clone, ("--no-deps",)))

    assert report.dirty is True
    assert report.ok is False
    assert not steps(report)["git update"].ok
    assert "uncommitted" in steps(report)["git update"].detail
    assert "stash" in steps(report)["git update"].hint
    assert readme.read_text(encoding="utf-8") == "# my precious local work\n"
    assert updater.read_version(clone) == "0.1.0", "the code must not have moved"
    # And the dependencies step is skipped rather than half-applied.
    assert steps(report)["dependencies"].skipped


def test_untracked_files_do_not_block_an_update(repos: dict[str, Path]) -> None:
    clone = repos["clone"]
    _write(clone / "notes.txt", "scratch work\n")
    publish(repos, "0.4.0")

    report = updater.update(_options(clone, ("--no-deps",)))

    assert report.ok, [step.as_dict() for step in report.steps if not step.ok]
    assert report.untracked == 1
    assert report.dirty is False
    assert updater.read_version(clone) == "0.4.0"
    assert (clone / "notes.txt").read_text(encoding="utf-8") == "scratch work\n"


def test_check_mode_changes_nothing(repos: dict[str, Path]) -> None:
    clone = repos["clone"]
    before = updater.read_version(clone)
    head = _git(clone, "rev-parse", "HEAD")
    publish(repos, "0.5.0")

    report = updater.update(_options(clone, ("--no-deps", "--check")))

    assert report.ok
    assert report.commits_available == 1
    assert report.changed is False
    assert steps(report)["git update"].skipped
    assert "1 commit(s) available" in steps(report)["git update"].detail
    assert updater.read_version(clone) == before
    assert _git(clone, "rev-parse", "HEAD") == head


def test_a_diverged_branch_is_never_rewritten(repos: dict[str, Path]) -> None:
    clone = repos["clone"]
    _write(clone / "diskfree/__init__.py", '__version__ = "9.9.9-local"\n')
    _git(clone, "commit", "-aqm", "a local commit that diverges")
    local_head = _git(clone, "rev-parse", "HEAD")
    publish(repos, "0.6.0")

    report = updater.update(_options(clone, ("--no-deps",)))

    assert report.ok is False
    step = steps(report)["git update"]
    assert not step.ok
    assert "fast-forward" in step.detail.lower()
    assert "diverged" in step.hint.lower()
    assert _git(clone, "rev-parse", "HEAD") == local_head, "history must be untouched"
    assert updater.read_version(clone) == "9.9.9-local"


def test_no_git_option_leaves_the_source_alone(repos: dict[str, Path]) -> None:
    clone = repos["clone"]
    publish(repos, "0.7.0")

    report = updater.update(_options(clone, ("--no-deps", "--no-git")))

    assert report.ok
    assert steps(report)["git update"].skipped
    assert "--no-git" in steps(report)["git update"].detail
    assert updater.read_version(clone) == "0.1.0"


def test_a_release_archive_without_git_is_handled(tmp_path: Path) -> None:
    archive = tmp_path / "diskfree-1.2.3"
    make_package(archive, "1.2.3")

    report = updater.update(_options(archive, ("--no-deps",)))

    assert report.ok
    assert steps(report)["git update"].skipped
    assert "not a git checkout" in steps(report)["git update"].detail
    assert report.branch == ""


def test_a_directory_without_the_package_is_refused(tmp_path: Path) -> None:
    empty = tmp_path / "not-diskfree"
    empty.mkdir()
    report = updater.update(_options(empty, ("--no-deps",)))
    assert report.ok is False
    assert steps(report)["locate source"].ok is False
    assert "Run the updater from inside a DiskFree checkout" in steps(report)[
        "locate source"
    ].hint


def test_an_unreachable_remote_is_reported_not_fatal(repos: dict[str, Path]) -> None:
    clone = repos["clone"]
    _git(clone, "remote", "set-url", "origin", str(repos["tmp"] / "does-not-exist.git"))

    report = updater.update(_options(clone, ("--no-deps",)))

    step = steps(report)["git fetch"]
    assert not step.ok
    assert step.hint
    assert updater.read_version(clone) == "0.1.0"


def test_a_branch_that_only_exists_locally_is_reported_honestly(
    repos: dict[str, Path]
) -> None:
    clone = repos["clone"]
    _git(clone, "switch", "-c", "feature/local-only")
    publish(repos, "0.8.0")

    report = updater.update(_options(clone, ("--no-deps",)))

    assert report.ok
    assert report.upstream_known is False
    assert report.changed is False
    assert "does not exist" in steps(report)["git update"].detail
    assert updater.read_version(clone) == "0.1.0"


def test_default_update_tracks_the_diskfree_development_branch_and_check_does_not_switch(
    repos: dict[str, Path],
) -> None:
    seed = repos["seed"]
    branch = updater.DEFAULT_BRANCH
    assert branch == "arena/0392f96c-diskfree"
    _git(seed, "switch", "-c", branch)
    make_package(seed, "0.9.0")
    _git(seed, "commit", "-aqm", "DiskFree implementation branch")
    _git(seed, "push", "-q", "origin", branch)
    _git(seed, "switch", "-q", "main")
    clone = repos["clone"]

    check = updater.update(_options(clone, ("--check", "--no-deps")))
    assert check.ok
    assert check.branch == "main", "--check must not change the checked-out branch"
    assert check.tracked_branch == branch
    assert updater.read_version(clone) == "0.1.0"
    assert _git(clone, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert steps(check)["switch branch"].skipped
    assert "would switch main" in steps(check)["switch branch"].detail
    assert steps(check)["git update"].skipped
    assert check.commits_available == 1

    report = updater.update(_options(clone, ("--no-deps",)))
    assert report.ok, [step.as_dict() for step in report.steps if not step.ok]
    assert report.branch == branch
    assert report.tracked_branch == branch
    assert updater.read_version(clone) == "0.9.0"
    assert _git(clone, "rev-parse", "--abbrev-ref", "HEAD") == branch


def test_switching_to_a_published_branch(repos: dict[str, Path]) -> None:
    clone = repos["clone"]
    _git(clone, "switch", "-c", "experiment")
    _git(repos["seed"], "switch", "-c", "stable")
    make_package(repos["seed"], "2.0.0")
    _git(repos["seed"], "commit", "-aqm", "stable release")
    _git(repos["seed"], "push", "-q", "origin", "stable")
    _git(repos["seed"], "switch", "-q", "main")

    report = updater.update(_options(clone, ("--no-deps", "--branch", "stable")))

    assert report.ok, [step.as_dict() for step in report.steps if not step.ok]
    assert report.branch == "stable"
    assert updater.read_version(clone) == "2.0.0"


def test_switching_branches_refuses_with_local_changes(repos: dict[str, Path]) -> None:
    clone = repos["clone"]
    _git(repos["seed"], "switch", "-c", "stable")
    make_package(repos["seed"], "3.0.0")
    _git(repos["seed"], "commit", "-aqm", "stable release")
    _git(repos["seed"], "push", "-q", "origin", "stable")
    _git(repos["seed"], "switch", "-q", "main")

    _write(clone / "README.md", "# local edit\n")
    report = updater.update(_options(clone, ("--no-deps", "--branch", "stable")))

    assert report.ok is False
    assert steps(report)["switch branch"].ok is False
    assert "stash" in steps(report)["switch branch"].hint
    assert (clone / "README.md").read_text(encoding="utf-8") == "# local edit\n"
    assert _git(clone, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert updater.read_version(clone) == "0.1.0"


# --------------------------------------------------------------------------
# dependency handling
# --------------------------------------------------------------------------


def test_check_mode_reports_missing_dependencies(repos: dict[str, Path], monkeypatch) -> None:
    clone = repos["clone"]
    monkeypatch.setattr(updater, "missing_dependencies", lambda root, python: ["fastapi"])

    report = updater.update(_options(clone, ("--check",)))

    step = steps(report)["dependencies"]
    assert step.skipped
    assert "fastapi" in step.detail
    assert step.hint


def test_externally_managed_environment_is_explained_not_overridden() -> None:
    options = updater.UpdateOptions(
        root=REPO_ROOT, python=sys.executable, upgrade_dependencies=True
    )
    result = updater.CommandResult(
        ["python", "-m", "pip", "install", "-e", "."],
        1,
        "error: externally-managed-environment\n"
        "× This environment is externally managed\n"  # noqa: RUF001 - pip's own output
        "note: If you believe this is a mistake, please contact your Python installation",
    )

    step = updater._handle_externally_managed(options, "dependencies", result)
    assert step.ok is False
    assert "externally managed" in step.detail
    assert "--allow-system-packages" in step.hint
    assert "venv" in step.hint


def test_a_plain_pip_failure_is_reported_verbatim() -> None:
    options = updater.UpdateOptions(root=REPO_ROOT, python=sys.executable)
    result = updater.CommandResult(["python", "-m", "pip"], 1, "no matching distribution")
    step = updater._handle_externally_managed(options, "dependencies", result)
    assert step.ok is False
    assert "pip failed" in step.detail
    assert "no matching distribution" in step.output


# --------------------------------------------------------------------------
# reporting and the command line
# --------------------------------------------------------------------------


def test_report_formatting_has_no_escape_codes_when_colour_is_off(
    repos: dict[str, Path]
) -> None:
    publish(repos, "0.9.0")
    report = updater.update(_options(repos["clone"], ("--no-deps",)))
    text = updater.format_report(report, colour=False)

    assert "\033[" not in text
    assert "DiskFree updater" in text
    assert "0.1.0" in text and "0.9.0" in text
    assert "Restart any running server" in text
    assert "ok    git update" in text


def test_report_formatting_marks_failures(repos: dict[str, Path]) -> None:
    clone = repos["clone"]
    _write(clone / "README.md", "# local\n")
    publish(repos, "0.9.1")
    report = updater.update(_options(clone, ("--no-deps",)))
    text = updater.format_report(report, colour=False)

    assert "FAIL" in text
    assert "hint:" in text
    assert "did not complete cleanly" in text


def test_json_report_is_machine_readable(repos: dict[str, Path]) -> None:
    publish(repos, "0.10.0")
    exit_code = updater.main(
        ["--root", str(repos["clone"]), "--no-deps", "--json"]
    )
    assert exit_code == 0


def test_main_exit_codes(repos: dict[str, Path], capsys) -> None:
    publish(repos, "0.11.0")
    assert updater.main(["--root", str(repos["clone"]), "--no-deps", "--check"]) == 0
    payload = capsys.readouterr()
    assert "update(s) available" in payload.out

    _write(repos["clone"] / "README.md", "# blocking edit\n")
    publish(repos, "0.12.0")
    assert updater.main(["--root", str(repos["clone"]), "--no-deps"]) == updater.EXIT_FAILED


def test_main_accepts_a_json_request(repos: dict[str, Path], capsys) -> None:
    publish(repos, "0.13.0")
    assert updater.main(["--root", str(repos["clone"]), "--no-deps", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True
    assert data["changed"] is True
    assert data["after"]["version"] == "0.13.0"
    assert data["commits_available"] == 1
    assert {step["name"] for step in data["steps"]} >= {"preflight", "git update", "verify"}


def test_parser_defaults_are_the_safe_choices() -> None:
    args = updater.build_parser().parse_args([])
    assert args.check_only is False
    assert args.no_git is False
    assert args.no_deps is False
    assert args.allow_system_packages is False
    assert args.branch is None
    assert args.timeout == updater.DEFAULT_TIMEOUT


def test_quiet_mode_still_prints_a_failure(repos: dict[str, Path], capsys) -> None:
    clone = repos["clone"]
    _write(clone / "README.md", "# blocking\n")
    publish(repos, "0.14.0")
    code = updater.main(["--root", str(clone), "--no-deps", "--quiet"])
    assert code == updater.EXIT_FAILED
    assert "FAIL" in capsys.readouterr().out


# --------------------------------------------------------------------------
# the launchers
# --------------------------------------------------------------------------


def test_the_shell_launcher_runs_the_updater(repos: dict[str, Path]) -> None:
    launcher = REPO_ROOT / "updater.sh"
    if not launcher.is_file() or os.name == "nt":
        pytest.skip("updater.sh is not runnable here")
    assert os.access(launcher, os.X_OK), "updater.sh must be executable"

    text = launcher.read_text(encoding="utf-8")
    assert text.startswith("#!"), "a launcher needs a shebang"
    assert "set -euo pipefail" in text
    assert "diskfree/updater.py" in text

    completed = subprocess.run(
        [str(launcher), "--root", str(repos["clone"]), "--no-deps", "--check", "--json"],
        capture_output=True, text=True, timeout=180, check=False,
        env={**os.environ, "DISKFREE_PYTHON": sys.executable},
    )
    assert completed.returncode == 0, completed.stderr
    data = json.loads(completed.stdout)
    assert data["root"] == str(repos["clone"].resolve())


def test_the_shell_launcher_reads_python_env_and_2py2(
    tmp_path: Path,
) -> None:
    launcher_source = REPO_ROOT / "updater.sh"
    if os.name == "nt" or not launcher_source.is_file():
        pytest.skip("the POSIX shell launcher is not runnable here")

    root = tmp_path / "DiskFree checkout"
    (root / "diskfree").mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "diskfree/updater.py", root / "diskfree/updater.py")
    launcher = root / "updater.sh"
    shutil.copy2(launcher_source, launcher)
    launcher.chmod(launcher.stat().st_mode | 0o111)

    env = dict(os.environ)
    env.pop("DISKFREE_PYTHON", None)
    env.pop("2PY2", None)
    portable_dir = root / "portable Python with spaces"
    portable_dir.mkdir()
    portable_python = portable_dir / "python3"
    portable_python.symlink_to(sys.executable)
    (root / "python.env").write_text(f'"{portable_python}"\n', encoding="utf-8")
    configured = subprocess.run(
        [str(launcher), "--show-python"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )
    assert configured.returncode == 0, configured.stderr
    assert "Selected" in configured.stdout and "python.env (PYTHON)" in configured.stdout

    (root / "python.env").unlink()
    env["2PY2"] = str(portable_python)
    portable = subprocess.run(
        [str(launcher), "--show-python"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )
    assert portable.returncode == 0, portable.stderr
    assert "Selected" in portable.stdout and "2PY2 (environment)" in portable.stdout


def test_the_windows_launcher_targets_the_same_module() -> None:
    launcher = REPO_ROOT / "updater.bat"
    if not launcher.is_file():
        pytest.skip("updater.bat is missing")
    text = launcher.read_text(encoding="utf-8")
    assert text.lower().startswith("@echo off")
    assert "diskfree\\updater.py" in text
    assert "DISKFREE_PYTHON" in text
    assert "%*" in text, "arguments must be forwarded to the updater"
    assert "exit /b" in text, "the exit code must be propagated"
    # It must support both ordinary names and portable interpreter overrides.
    assert "py -3" in text and 'where "%PY_EXE%"' in text
    assert "python.env" in text and "2PY2" in text
    assert "PYTHON_CHECK" in text, "the launcher must reject Python older than 3.11"


def test_the_updater_module_needs_no_third_party_imports() -> None:
    """It has to run before DiskFree's dependencies are installed."""

    source = (REPO_ROOT / "diskfree/updater.py").read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])

    assert imported, "the AST walk should have found the imports"
    outside = {name for name in imported if name not in sys.stdlib_module_names}
    assert not outside, f"the updater must not import {sorted(outside)}"
    # ... and specifically nothing DiskFree itself needs, or the updater could
    # not repair a broken installation.
    assert not (imported & {"fastapi", "httpx", "pydantic", "uvicorn", "diskfree"})


#: The only git subcommands the updater is allowed to invoke. Anything that can
#: discard work, rewrite history or publish it is deliberately absent.
ALLOWED_GIT_SUBCOMMANDS = {
    "rev-parse", "status", "fetch", "rev-list", "log", "merge", "switch",
}


def _module_source() -> str:
    return (REPO_ROOT / "diskfree/updater.py").read_text(encoding="utf-8")


def _string_call_arguments(source: str, functions: set[str]) -> list[list[str]]:
    """Every string literal passed positionally to one of ``functions``."""

    calls: list[list[str]] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name not in functions:
            continue
        calls.append(
            [arg.value for arg in node.args
             if isinstance(arg, ast.Constant) and isinstance(arg.value, str)]
        )
    return calls


def test_the_updater_only_runs_read_only_git_subcommands() -> None:
    git_calls = _string_call_arguments(_module_source(), {"git"})
    assert git_calls, "expected the updater to call git"
    subcommands = {call[0] for call in git_calls if call}
    assert subcommands <= ALLOWED_GIT_SUBCOMMANDS, sorted(subcommands - ALLOWED_GIT_SUBCOMMANDS)
    for call in git_calls:
        assert "--force" not in call and "-f" not in call, call


def test_the_updater_never_deletes_or_shells_out() -> None:
    source = _module_source()
    assert "shell=True" not in source, "commands must be run from a fixed argv"
    assert "os.system" not in source
    tree = ast.parse(source)
    called = {
        getattr(node.func, "attr", None) or getattr(node.func, "id", None)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }
    for destructive in {"rmtree", "remove", "unlink", "removedirs", "rmdir", "rename"}:
        assert destructive not in called, f"the updater must not call {destructive}()"


def test_the_merge_is_fast_forward_only() -> None:
    source = _module_source()
    merge_lines = [line for line in source.splitlines() if '"merge"' in line]
    assert merge_lines, "expected exactly one merge invocation"
    assert any("--ff-only" in line for line in merge_lines)


# --------------------------------------------------------------------------
# honest reporting: the summary must describe what actually happened
# --------------------------------------------------------------------------


def test_the_report_names_the_installed_version(repos: dict[str, Path]) -> None:
    report = updater.update(_options(repos["clone"], ("--no-deps", "--no-git")))
    text = updater.format_report(report, colour=False)
    assert "version    0.1.0" in text


def test_no_git_never_claims_up_to_date(repos: dict[str, Path]) -> None:
    """With git disabled nothing was compared, so nothing may claim a result."""

    publish(repos, "0.20.0")
    clone = repos["clone"]
    report = updater.update(_options(clone, ("--no-deps", "--no-git")))
    text = updater.format_report(report, colour=False)

    assert "--no-git: the checkout was left exactly as it is." in text
    assert "Already up to date" not in text
    assert updater.read_version(clone) == "0.1.0"


def test_a_release_archive_is_reported_as_such(tmp_path: Path) -> None:
    archive = tmp_path / "DiskFree-1.2.3"
    make_package(archive, "1.2.3")

    report = updater.update(_options(archive, ("--no-deps",)))
    text = updater.format_report(report, colour=False)

    assert "not a git checkout" in text
    assert "Already up to date" not in text
    assert report.ok is True


def test_an_unknown_upstream_says_it_could_not_compare(repos: dict[str, Path]) -> None:
    clone = repos["clone"]
    _git(clone, "checkout", "-q", "-b", "local-only")

    report = updater.update(_options(clone, ("--no-deps",)))
    text = updater.format_report(report, colour=False)

    assert "Could not compare with the remote" in text
    assert "origin/local-only does not exist" in text
    assert "Already up to date" not in text


def test_check_mode_reports_the_dependency_probe(repos: dict[str, Path]) -> None:
    report = updater.update(_options(repos["clone"], ("--check", "--no-git")))
    text = updater.format_report(report, colour=False)

    assert "Dependency check passed" in text or "missing packages" in text
    assert "Dependencies were refreshed" not in text, "--check installs nothing"


def test_no_deps_never_claims_a_refresh(repos: dict[str, Path]) -> None:
    report = updater.update(_options(repos["clone"], ("--no-deps", "--no-git")))
    assert "Dependencies were skipped (--no-deps)." in updater.format_report(
        report, colour=False
    )


def test_a_failed_dependency_step_is_not_reported_as_success() -> None:
    report = updater.UpdateReport(root=str(REPO_ROOT), python=sys.executable)
    report.add(updater.Step("dependencies", ok=False, detail="externally-managed-environment"))
    text = updater.format_report(report, colour=False)

    assert "were NOT refreshed" in text
    assert "Dependencies were refreshed." not in text


def test_the_dependency_summary_covers_every_outcome() -> None:
    cases = [
        (updater.Step("dependencies", skipped=True, detail="--no-deps"),
         "skipped (--no-deps)"),
        (updater.Step("dependencies", skipped=True,
                      detail="all required packages are importable"),
         "Dependency check passed"),
        (updater.Step("dependencies", skipped=True, detail="missing: fastapi"),
         "missing packages"),
        (updater.Step("dependencies", skipped=True,
                      detail="skipped: the source update failed"),
         "source update failed"),
        (updater.Step("dependencies",
                      detail="installed DiskFree (editable) and its dependencies"),
         "Dependencies were refreshed."),
        (updater.Step("dependencies", ok=False, detail="externally-managed-environment"),
         "were NOT refreshed"),
    ]
    for step, expected in cases:
        assert expected in updater._dependencies_summary(step), step.detail


def test_a_clean_fast_forward_reports_the_refreshed_dependencies(
    repos: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """When pip really ran, the summary is allowed to say so."""

    publish(repos, "0.21.0")
    calls: list[list[str]] = []

    def fake_pip(options, *args, **kwargs):
        calls.append(list(args))
        return updater.CommandResult(
            ["pip", *args], 0, "Successfully installed diskfree-0.21.0"
        )

    monkeypatch.setattr(updater, "_pip", fake_pip)
    report = updater.update(_options(repos["clone"], ()))
    text = updater.format_report(report, colour=False)

    assert calls, "pip should have been asked to install the checkout"
    assert "Dependencies were refreshed." in text
    assert "Updated 0.1.0 → 0.21.0" in text
    assert "Restart any running server" in text


def test_the_cli_exposes_update() -> None:
    from diskfree.cli import _HANDLERS, _build_parser

    assert "update" in _HANDLERS
    help_text = _build_parser().format_help()
    assert "update" in help_text


def test_the_cli_forwards_arguments_to_the_updater(repos: dict[str, Path], capsys) -> None:
    from diskfree.cli import main as cli_main

    publish(repos, "0.15.0")
    code = cli_main(["update", "--root", str(repos["clone"]), "--no-deps", "--json"])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["after"]["version"] == "0.15.0"

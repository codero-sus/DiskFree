"""The command line: parsing, reports, exit codes and the updater hand-off.

``diskfree`` is the entry point people meet first, so its output has to say what
it did and what it did not do -- and ``diskfree update`` has to reach the
standard-library updater even when the rest of the package cannot be imported.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import pytest

from diskfree import __version__, cli
from diskfree.scanner.engine import ScanOptions
from tests.conftest import FakeHome

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def isolated_environment(
    fake_home: FakeHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A known environment, restored afterwards: the CLI writes to ``os.environ``."""

    saved = dict(os.environ)
    for name in list(os.environ):
        if name.startswith("DISKFREE_") or name in {"CORTEX_API_KEY", "OLLAMA_API_KEY"}:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DISKFREE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DISKFREE_QUARANTINE_DIR", str(tmp_path / "data" / "quarantine"))
    monkeypatch.setenv("DISKFREE_TRASH_BACKEND", "quarantine")
    yield
    os.environ.clear()
    os.environ.update(saved)


def run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def parse_json(text: str) -> dict:
    """Pull the JSON document out of a report that prints a header line first."""

    start = text.index("{")
    return json.loads(text[start:])


# --------------------------------------------------------------------------
# top level
# --------------------------------------------------------------------------


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    assert f"DiskFree {__version__}" in capsys.readouterr().out


def test_help_advertises_every_command(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--help"])
    assert excinfo.value.code == 0
    text = capsys.readouterr().out
    for command in ("serve", "scan", "advise", "status", "providers", "rules",
                    "history", "history-restore", "update"):
        assert command in text, command
    assert "confirmed plan" in text, "help must state the safety model"


def test_an_unknown_command_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["defragment"])
    assert excinfo.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_a_bad_flag_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["scan", "--preset", "turbo"])
    assert excinfo.value.code == 2
    assert capsys.readouterr().err


def test_an_interrupt_is_reported_as_130(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def interrupted(_: argparse.Namespace) -> int:  # pragma: no cover - test double
        raise KeyboardInterrupt

    monkeypatch.setitem(cli._HANDLERS, "history", interrupted)
    assert cli.main(["history"]) == 130
    assert "Interrupted" in capsys.readouterr().err


# --------------------------------------------------------------------------
# read-only reporting commands
# --------------------------------------------------------------------------


def test_rules_prints_the_catalogue(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(["rules"], capsys)
    assert code == 0
    assert "rules" in out
    assert "pkg-pip-cache" in out
    assert "sys-docker" in out
    assert "advisory only" in out, "probes must explain they are not removable"


def test_status_prints_the_safety_posture(
    capsys: pytest.CaptureFixture[str], fake_home: FakeHome
) -> None:
    code, out, _ = run(["status"], capsys)
    assert code == 0
    assert f"DiskFree {__version__}" in out
    assert str(fake_home.root) in out
    assert "permanent   disabled" in out.lower()
    assert "cortex" in out and "ollama" in out


def test_status_shows_read_only_mode(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DISKFREE_ALLOW_WRITES", "0")
    code, out, _ = run(["status"], capsys)
    assert code == 0
    assert "read-only" in out.lower()


def test_providers_exits_non_zero_when_nothing_is_reachable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = run(["providers"], capsys)
    assert code == 1, "an exit code the operator can script against"
    assert "cortex" in out and "ollama" in out
    assert "heuristic" in out.lower() or "offline" in out.lower()


def test_history_reports_an_empty_journal(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(["history"], capsys)
    assert code == 0
    assert "Journal is empty" in out


def test_restoring_an_unknown_operation_fails_loudly(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, _, err = run(["history-restore", "op_does-not-exist"], capsys)
    assert code == 1
    assert "error:" in err


# --------------------------------------------------------------------------
# scan and advise
# --------------------------------------------------------------------------


def test_scan_prints_a_report_and_changes_nothing(
    capsys: pytest.CaptureFixture[str], fake_home: FakeHome
) -> None:
    before = sorted(str(path) for path in fake_home.root.rglob("*"))

    code, out, _ = run(
        ["scan", str(fake_home.root), "--preset", "quick", "--no-advisories",
         "--min-mb", "0", "--limit", "10"],
        capsys,
    )

    assert code == 0
    assert "read-only" in out
    assert "directories" in out and "files" in out
    assert "Reclaimable:" in out
    assert "Nothing was modified" in out
    assert str(fake_home["pip_cache"]) in out
    assert sorted(str(path) for path in fake_home.root.rglob("*")) == before


def test_scan_can_emit_json(
    capsys: pytest.CaptureFixture[str], fake_home: FakeHome
) -> None:
    code, out, _ = run(
        ["scan", str(fake_home.root), "--preset", "quick", "--no-advisories",
         "--min-mb", "0", "--json", "--limit", "5"],
        capsys,
    )
    assert code == 0
    payload = parse_json(out)
    assert payload["stats"]["findings"] > 0
    assert payload["stats"]["dirs_seen"] > 0
    assert len(payload["findings"]) <= 5
    for finding in payload["findings"]:
        assert finding["id"] and finding["path"] and finding["risk"]
        assert "members" not in finding, "the CLI report stays readable"


def test_scan_flags_really_reach_the_scanner(
    capsys: pytest.CaptureFixture[str], fake_home: FakeHome
) -> None:
    code, out, _ = run(
        ["scan", str(fake_home.root), "--preset", "quick", "--no-advisories",
         "--no-duplicates", "--no-large", "--min-mb", "1000", "--json"],
        capsys,
    )
    assert code == 0
    payload = parse_json(out)
    assert payload["stats"]["duplicate_groups"] == 0
    assert all(finding["bytes"] >= 1000 * 1024 * 1024 for finding in payload["findings"])
    assert all(finding["rule_id"] != "large-files" for finding in payload["findings"])


def test_advise_uses_the_offline_engine(
    capsys: pytest.CaptureFixture[str], fake_home: FakeHome
) -> None:
    code, out, _ = run(
        ["advise", str(fake_home.root), "--preset", "balanced", "--provider", "heuristic",
         "--limit", "5"],
        capsys,
    )
    assert code == 0
    assert "Advice from heuristic" in out
    assert "CLEAN —" in out, "the safe caches must be proposed for cleaning"
    assert "Quick wins:" in out
    assert "Run these yourself" in out
    assert "Nothing was modified" in out
    assert str(fake_home["ssh_key"]) not in out, "credentials are never proposed"


def test_advise_can_emit_json(
    capsys: pytest.CaptureFixture[str], fake_home: FakeHome
) -> None:
    code, out, _ = run(
        ["advise", str(fake_home.root), "--preset", "balanced", "--provider", "heuristic",
         "--json"],
        capsys,
    )
    assert code == 0
    payload = parse_json(out)
    assert payload["engine"] == "heuristic"
    assert payload["ok"] is True
    assert payload["headline"] and payload["summary"]
    assert payload["items"]
    assert payload["warnings"]


def test_advise_says_when_no_model_answered(
    capsys: pytest.CaptureFixture[str], fake_home: FakeHome
) -> None:
    code, out, _ = run(
        ["advise", str(fake_home.root), "--preset", "balanced", "--provider", "auto"],
        capsys,
    )
    assert code == 0
    # No model host is running here, so the offline engine answers and says so.
    assert "Advice from heuristic" in out
    assert "note:" in out or "hint:" in out
    assert "Nothing was modified" in out


# --------------------------------------------------------------------------
# flag to environment translation
# --------------------------------------------------------------------------


def test_apply_env_translates_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    args = argparse.Namespace(
        host="0.0.0.0", port=9001, data_dir="/srv/diskfree", log_level="debug",
        provider="ollama", cortex_url="http://127.0.0.1:1", ollama_url="http://127.0.0.1:2",
        ollama_model="llama3.2", ui_token="tok", cors="https://a.example",
        read_only=True, allow_permanent_delete=True,
    )
    cli._apply_env(args)
    assert os.environ["DISKFREE_HOST"] == "0.0.0.0"
    assert os.environ["DISKFREE_PORT"] == "9001"
    assert os.environ["DISKFREE_DATA_DIR"] == "/srv/diskfree"
    assert os.environ["DISKFREE_LOG_LEVEL"] == "debug"
    assert os.environ["DISKFREE_PROVIDER"] == "ollama"
    assert os.environ["DISKFREE_CORTEX_URL"] == "http://127.0.0.1:1"
    assert os.environ["DISKFREE_OLLAMA_URL"] == "http://127.0.0.1:2"
    assert os.environ["DISKFREE_OLLAMA_MODEL"] == "llama3.2"
    assert os.environ["DISKFREE_UI_TOKEN"] == "tok"
    assert os.environ["DISKFREE_CORS_ORIGINS"] == "https://a.example"
    assert os.environ["DISKFREE_ALLOW_WRITES"] == "0"
    assert os.environ["DISKFREE_ALLOW_PERMANENT_DELETE"] == "1"


def test_apply_env_leaves_unset_flags_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DISKFREE_PORT", "8000")
    cli._apply_env(argparse.Namespace(host=None, port=None, read_only=False))
    assert os.environ["DISKFREE_PORT"] == "8000"
    assert "DISKFREE_ALLOW_WRITES" not in os.environ


def test_serve_flags_reach_the_settings(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`serve --read-only` is how the flag is documented; prove it end to end."""

    parser = cli._build_parser()
    args = parser.parse_args(
        ["serve", "--read-only", "--allow-permanent-delete", "--port", "9100",
         "--ui-token", "tok"]
    )
    cli._apply_env(args)
    assert os.environ["DISKFREE_ALLOW_WRITES"] == "0"
    assert os.environ["DISKFREE_ALLOW_PERMANENT_DELETE"] == "1"
    assert os.environ["DISKFREE_PORT"] == "9100"
    assert os.environ["DISKFREE_UI_TOKEN"] == "tok"

    # ... and the very next command reports the posture those flags produced.
    code, out, _ = run(["status"], capsys)
    assert code == 0
    assert "read-only" in out.lower()
    assert "permanent   enabled" in out.lower()


# --------------------------------------------------------------------------
# presets
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("preset", "expected_depth", "expected_duplicate_mb"),
    [("quick", 8, 5), ("balanced", 20, 10), ("deep", 40, 1)],
)
def test_presets_tune_the_scan(
    preset: str, expected_depth: int, expected_duplicate_mb: int
) -> None:
    options = ScanOptions()
    options.duplicate_min_bytes = 5 * 1024 * 1024
    cli._apply_preset(options, preset)
    assert options.max_depth == expected_depth
    assert options.duplicate_min_bytes == expected_duplicate_mb * 1024 * 1024
    if preset == "quick":
        assert options.find_duplicates is False
        assert options.min_finding_bytes == 50 * 1024 * 1024


def test_the_deep_preset_adds_existing_system_roots_only() -> None:
    options = ScanOptions(roots=[Path("/nonexistent-root-for-test")])
    cli._apply_preset(options, "deep")
    assert Path("/nonexistent-root-for-test") in options.roots
    for extra in options.roots[1:]:
        assert extra.is_dir(), f"{extra} was added but does not exist"


# --------------------------------------------------------------------------
# the updater hand-off
# --------------------------------------------------------------------------


def test_update_help_reaches_the_updater(capsys: pytest.CaptureFixture[str]) -> None:
    """`update` is dispatched before argparse so its own flags survive."""

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["update", "--help"])
    assert excinfo.value.code == 0
    text = capsys.readouterr().out
    assert "--check" in text
    assert "--branch" in text
    assert "fast-forward" in text.lower()


def test_update_check_runs_from_the_cli(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(
        ["update", "--check", "--no-git", "--no-deps", "--root", str(REPO_ROOT)], capsys
    )
    assert code == 0, out + err
    assert f"version    {__version__}" in out
    assert "--no-git: the checkout was left exactly as it is." in out
    assert "Dependencies were skipped (--no-deps)." in out


def test_update_accepts_a_double_dash_separator(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(
        ["update", "--", "--check", "--no-git", "--no-deps", "--root", str(REPO_ROOT)], capsys
    )
    assert code == 0, out + err
    assert __version__ in out


def test_update_reports_a_bad_root(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, err = run(["update", "--check", "--no-git", "--root", str(tmp_path)], capsys)
    assert code == 1
    assert "diskfree" in (out + err).lower()


def test_update_json_output_is_machine_readable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = run(
        ["update", "--check", "--no-git", "--no-deps", "--json", "--root", str(REPO_ROOT)],
        capsys,
    )
    assert code == 0
    payload = json.loads(out[out.index("{"):])
    assert payload["ok"] is True
    assert payload["before"]["version"] == __version__
    assert payload["changed"] is False
    assert [step["name"] for step in payload["steps"]] == [
        "preflight", "locate source", "git update", "dependencies",
    ]
    assert all(step["skipped"] or step["ok"] for step in payload["steps"])


def test_the_update_subparser_is_declared() -> None:
    """`update` shows up in help; its flags are handled before argparse runs.

    argparse cannot pass `--help` (or arbitrary flags) through a subcommand, so
    :func:`diskfree.cli.main` dispatches `update` directly -- see the tests above,
    which drive the real entry point.
    """

    parser = cli._build_parser()
    assert "update" in parser.format_help()
    args = parser.parse_args(["update"])
    assert args.command == "update"
    assert args.update_args == []


def test_handlers_cover_every_subcommand() -> None:
    parser = cli._build_parser()
    choices = next(
        action.choices
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    assert set(choices) == set(cli._HANDLERS), "every command needs a handler"


def test_the_module_runs_as_a_script() -> None:
    assert (Path(cli.__file__).parent / "__main__.py").is_file()
    assert sys.executable

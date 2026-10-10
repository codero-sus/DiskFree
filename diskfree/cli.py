"""Command line interface: serve the WebUI, or scan straight from a terminal."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="diskfree",
        description="DiskFree: AI powered disk manager and cleaner. Safe and efficient.",
        epilog=(
            "Without a subcommand, DiskFree serves the WebUI. "
            "Nothing is ever removed without an explicit, itemised, confirmed plan."
        ),
    )
    parser.add_argument("--version", action="version", version=f"DiskFree {__version__}")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser(
        "serve",
        help="Run the WebUI with uvicorn (default when no subcommand is given)",
        description="Serve the DiskFree WebUI and API with uvicorn.",
    )
    _add_server_args(serve)

    scan = sub.add_parser("scan", help="Scan and print a report; never modifies anything")
    scan.add_argument("roots", nargs="*", help="Directories to scan (default: your home)")
    scan.add_argument("--preset", choices=("quick", "balanced", "deep"), default="balanced")
    scan.add_argument("--max-depth", type=int, default=None)
    scan.add_argument("--no-duplicates", action="store_true", help="Skip duplicate hashing")
    scan.add_argument("--no-large", action="store_true", help="Skip the largest-file list")
    scan.add_argument("--no-advisories", action="store_true", help="Skip system probes")
    scan.add_argument("--min-mb", type=int, default=1, help="Hide findings below this size")
    scan.add_argument("--limit", type=int, default=40, help="How many findings to print")
    scan.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    advise = sub.add_parser("advise", help="Scan, then print AI (or rule-engine) advice")
    advise.add_argument("roots", nargs="*")
    advise.add_argument("--preset", choices=("quick", "balanced", "deep"), default="balanced")
    advise.add_argument("--provider", choices=("auto", "cortex", "ollama", "heuristic"),
                        default="auto")
    advise.add_argument("--model", default=None)
    advise.add_argument("--limit", type=int, default=25)
    advise.add_argument("--json", action="store_true")

    sub.add_parser("status", help="Show disks, providers and safety configuration")
    sub.add_parser("providers", help="Probe the configured local model hosts")
    sub.add_parser("rules", help="Print the cleaning rule catalogue")
    sub.add_parser("history", help="Print the removal journal")

    clean = sub.add_parser(
        "history-restore", help="Undo a previous operation by id (see `diskfree history`)"
    )
    clean.add_argument("op_id")

    # The updater owns its own flag set (and must work before DiskFree's
    # dependencies are installed), so everything after `update` is passed through.
    update = sub.add_parser(
        "update",
        add_help=False,
        help="Update DiskFree from git and refresh its dependencies",
        description=(
            "Fast-forwards this checkout and reinstalls DiskFree's dependencies. "
            "Everything after 'update' is handed to the updater; try "
            "`diskfree update --help`."
        ),
    )
    update.add_argument("update_args", nargs=argparse.REMAINDER)
    return parser


def _add_server_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default=None, help="Bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (default 8790)")
    parser.add_argument("--data-dir", default=None, help="Where journals and quarantine live")
    parser.add_argument("--log-level", default=None,
                        choices=("critical", "error", "warning", "info", "debug", "trace"))
    parser.add_argument("--provider", default=None,
                        choices=("auto", "cortex", "ollama", "heuristic"))
    parser.add_argument("--cortex-url", default=None)
    parser.add_argument("--ollama-url", default=None)
    parser.add_argument("--ollama-model", default=None)
    parser.add_argument("--read-only", action="store_true",
                        help="Refuse every modification, even with a confirmed plan")
    parser.add_argument("--allow-permanent-delete", action="store_true",
                        help="Enable hard deletion (off by default; trash mode is reversible)")
    parser.add_argument("--ui-token", default=None, help="Require this token for API calls")
    parser.add_argument("--cors", default=None, help="Comma-separated allowed origins")
    parser.add_argument("--reload", action="store_true", help="Uvicorn auto-reload for development")


def _apply_env(args: argparse.Namespace) -> None:
    """CLI flags win over the environment, which wins over the config file."""

    mapping = {
        "host": "DISKFREE_HOST",
        "port": "DISKFREE_PORT",
        "data_dir": "DISKFREE_DATA_DIR",
        "log_level": "DISKFREE_LOG_LEVEL",
        "provider": "DISKFREE_PROVIDER",
        "cortex_url": "DISKFREE_CORTEX_URL",
        "ollama_url": "DISKFREE_OLLAMA_URL",
        "ollama_model": "DISKFREE_OLLAMA_MODEL",
        "ui_token": "DISKFREE_UI_TOKEN",
        "cors": "DISKFREE_CORS_ORIGINS",
    }
    for attribute, variable in mapping.items():
        value = getattr(args, attribute, None)
        if value is not None:
            os.environ[variable] = str(value)
    if getattr(args, "read_only", False):
        os.environ["DISKFREE_ALLOW_WRITES"] = "0"
    if getattr(args, "allow_permanent_delete", False):
        os.environ["DISKFREE_ALLOW_PERMANENT_DELETE"] = "1"


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .config import load_settings

    settings = load_settings()
    host = getattr(args, "host", None) or settings.host
    port = int(getattr(args, "port", None) or settings.port)
    exposed = host not in {"127.0.0.1", "localhost", "::1"}
    print(f"DiskFree {__version__} — AI powered disk manager and cleaner")
    print(f"  WebUI      http://{host}:{port}/")
    print(f"  API docs   http://{host}:{port}/api/docs")
    print(f"  Data dir   {settings.data_dir}")
    print(f"  Writes     {'ON' if settings.safety.allow_writes else 'OFF (read-only)'}")
    permanent = (
        "ENABLED — deletions cannot be undone"
        if settings.safety.allow_permanent_delete
        else "disabled (trash mode is reversible)"
    )
    print(f"  Permanent  {permanent}")
    providers = ", ".join(f"{p.name} @ {p.url}" for p in settings.providers)
    print(f"  Models     preferred={settings.provider} · {providers}")
    if exposed and not settings.ui_token:
        print(
            "  WARNING    binding to a non-loopback address without DISKFREE_UI_TOKEN "
            "exposes the API to your network."
        )
    uvicorn.run(
        "diskfree.api.app:app",
        host=host,
        port=port,
        log_level=settings.log_level,
        reload=bool(getattr(args, "reload", False)),
    )
    return 0


def _scan(args: argparse.Namespace) -> int:
    import json

    from .config import load_settings
    from .scanner.engine import Scanner
    from .scanner.jobs import default_options
    from .util import human_bytes

    settings = load_settings()
    options = default_options(settings, args.roots or None)
    _apply_preset(options, args.preset)
    if args.max_depth:
        options.max_depth = args.max_depth
    options.find_duplicates = not args.no_duplicates
    options.find_large_files = not args.no_large
    options.include_advisories = not args.no_advisories
    options.min_finding_bytes = max(0, args.min_mb) * 1024 * 1024

    print(f"Scanning {', '.join(str(root) for root in options.roots)} (read-only)…")
    result = Scanner(settings).run(options)
    stats = result.stats

    if args.json:
        print(
            json.dumps(
                {
                    "stats": stats.as_dict(),
                    "categories": result.category_totals(),
                    "warnings": result.warnings,
                    "findings": [
                        finding.as_dict(include_members=False)
                        for finding in result.findings[: args.limit]
                    ],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    print(
        f"\n{stats.dirs_seen:,} directories, {stats.files_seen:,} files, "
        f"{human_bytes(stats.bytes_seen)} in {stats.duration:.1f}s "
        f"({stats.entries_per_second:,} entries/s)"
    )
    print(f"Pruned {stats.pruned_dirs:,} directories, skipped {stats.symlinks_skipped:,} symlinks")
    if stats.permission_errors:
        print(f"{stats.permission_errors:,} paths were unreadable (permissions)")
    print()
    for warning in result.warnings:
        print(f"  ! {warning}")
    if result.warnings:
        print()

    print(f"{'SIZE':>10}  {'RISK':<9} {'CATEGORY':<17} PATH")
    for finding in result.findings[: args.limit]:
        flag = "" if finding.actionable else "  (advisory)"
        print(
            f"{human_bytes(finding.bytes):>10}  {finding.risk.value:<9} "
            f"{finding.category.value:<17} {finding.path}{flag}"
        )
        if finding.advisory:
            print(f"{'':>10}  run yourself: {finding.advisory}")
    print(
        f"\nReclaimable: {human_bytes(stats.actionable_bytes)} total, "
        f"{human_bytes(stats.safe_bytes)} of it 'safe' (regenerable caches)."
    )
    print("Nothing was modified. Use the WebUI to review and clean reversibly.")
    return 0


def _apply_preset(options, preset: str) -> None:
    mb = 1024 * 1024
    if preset == "quick":
        options.max_depth = 8
        options.find_duplicates = False
        options.min_finding_bytes = 50 * mb
        options.large_file_min_bytes = 500 * mb
    elif preset == "deep":
        options.max_depth = 40
        options.min_finding_bytes = 0
        options.duplicate_min_bytes = 1 * mb
        options.large_file_min_bytes = 100 * mb
        for extra in ("/tmp", "/var/log", "/var/cache"):
            candidate = Path(extra)
            if candidate.is_dir() and candidate not in options.roots:
                options.roots.append(candidate)
    else:
        options.max_depth = 20
        options.min_finding_bytes = 1 * mb
        options.duplicate_min_bytes = 10 * mb
        options.large_file_min_bytes = 250 * mb


def _advise(args: argparse.Namespace) -> int:
    import asyncio
    import json

    from .ai.advisor import Advisor
    from .ai.providers import ProviderRegistry
    from .config import load_settings
    from .scanner.engine import Scanner
    from .scanner.jobs import default_options
    from .util import human_bytes

    settings = load_settings()
    options = default_options(settings, args.roots or None)
    _apply_preset(options, args.preset)
    print(f"Scanning {', '.join(str(root) for root in options.roots)} (read-only)…")
    result = Scanner(settings).run(options)
    result.job_id = "cli"

    async def run() -> int:
        registry = ProviderRegistry(settings)
        advisor = Advisor(settings, registry)
        try:
            advice = await advisor.advise(
                result,
                provider=None if args.provider == "auto" else args.provider,
                model=args.model,
                use_model=args.provider != "heuristic",
            )
        finally:
            await registry.aclose()

        if args.json:
            print(json.dumps(advice.as_dict(), indent=2, ensure_ascii=False))
            return 0

        engine = advice.engine + (f" · {advice.model}" if advice.model else "")
        print(f"\nAdvice from {engine}"
              + (f" in {advice.latency_ms:.0f} ms" if advice.latency_ms else ""))
        if advice.error:
            print(f"  note: {advice.error}")
            if advice.error_hint:
                print(f"  hint: {advice.error_hint}")
        print(f"\n{advice.headline}\n\n{advice.summary}\n")
        if advice.quick_wins:
            print("Quick wins:")
            for win in advice.quick_wins:
                print(f"  • {win}")
            print()
        by_action: dict[str, list] = {}
        for item in advice.items:
            by_action.setdefault(item.action.value, []).append(item)
        for action in ("clean", "review", "manual", "keep"):
            items = by_action.get(action) or []
            if not items:
                continue
            total = sum(item.bytes for item in items)
            print(f"{action.upper()} — {len(items)} item(s), {human_bytes(total)}")
            for item in sorted(items, key=lambda candidate: -candidate.bytes)[: args.limit]:
                print(f"  {human_bytes(item.bytes):>10}  [{item.risk.value}] {item.title}")
                print(f"  {'':>10}  {item.path}")
                print(f"  {'':>10}  {item.reason}")
            print()
        if advice.manual_steps:
            print("Run these yourself (DiskFree never executes commands):")
            for step in advice.manual_steps:
                print(f"  $ {step}")
            print()
        if advice.guardrails:
            print(f"Guardrails applied: {len(advice.guardrails)}")
            for event in advice.guardrails[:10]:
                print(f"  [{event.kind}] {event.message}")
        print("\nNothing was modified. Use the WebUI to clean reversibly.")
        return 0

    return asyncio.run(run())


def _status(args: argparse.Namespace) -> int:
    import asyncio

    from .ai.providers import ProviderRegistry
    from .config import load_settings
    from .safety.trash import TrashManager
    from .scanner.disks import enumerate_mounts
    from .util import human_bytes

    settings = load_settings()
    print(f"DiskFree {__version__}")
    print(f"  data dir    {settings.data_dir}")
    print(f"  writes      {'on' if settings.safety.allow_writes else 'OFF (read-only)'}")
    print(f"  permanent   {'ENABLED' if settings.safety.allow_permanent_delete else 'disabled'}")
    print(f"  provider    {settings.provider}")

    print("\nVolumes:")
    for mount in enumerate_mounts([Path.home()]):
        if mount.pseudo:
            continue
        print(
            f"  {mount.mountpoint:<28} {mount.fstype:<8} "
            f"{human_bytes(mount.used):>9} / {human_bytes(mount.total):>9} "
            f"({mount.percent:.0f}% used, {human_bytes(mount.free)} free)"
        )

    async def probe() -> None:
        registry = ProviderRegistry(settings)
        try:
            for info in await registry.all_info(max_age=0.0):
                models = ", ".join(info.models[:4]) or "none"
                print(f"\n{info.label}: {info.status.value} @ {info.base_url}")
                print(f"  {info.detail}")
                print(f"  models: {models}")
                if info.hint and info.status.value != "online":
                    print(f"  hint: {info.hint}")
        finally:
            await registry.aclose()

    asyncio.run(probe())

    trash = TrashManager(settings.safety, data_dir=settings.data_dir)
    print("\nTrash:")
    for key, value in trash.status().items():
        print(f"  {key:<24} {value}")
    return 0


def _providers(args: argparse.Namespace) -> int:
    import asyncio
    import json

    from .ai.providers import ProviderRegistry
    from .config import load_settings

    settings = load_settings()

    async def probe() -> int:
        registry = ProviderRegistry(settings)
        try:
            infos = await registry.all_info(max_age=0.0)
        finally:
            await registry.aclose()
        print(json.dumps([info.as_dict() for info in infos], indent=2, ensure_ascii=False))
        reachable = any(info.status.value in {"online", "degraded"} for info in infos)
        return 0 if reachable else 1

    return asyncio.run(probe())


def _rules(args: argparse.Namespace) -> int:
    from .scanner.rules import DEFAULT_RULES, RuleSet

    ruleset = RuleSet()
    print(f"{len(DEFAULT_RULES)} rules ({len(ruleset.walk_rules)} active on this platform)\n")
    print(f"{'RULE ID':<26} {'CATEGORY':<17} {'RISK':<9} {'PRI':>4}  TITLE")
    for rule in DEFAULT_RULES:
        active = "" if ruleset.compiled_for(rule.id) else " (n/a here)"
        print(
            f"{rule.id:<26} {rule.category.value:<17} {rule.risk.value:<9} "
            f"{rule.priority:>4}  {rule.title}{active}"
        )
        if rule.advisory:
            print(f"{'':<26} advisory only: {rule.advisory}")
    return 0


def _history(args: argparse.Namespace) -> int:
    from .config import load_settings
    from .safety.trash import Journal
    from .util import human_bytes

    settings = load_settings()
    journal = Journal(settings.journal_path)
    entries = journal.entries()
    if not entries:
        print(f"Journal is empty ({settings.journal_path}).")
        return 0
    print(f"{len(entries)} journal entries in {settings.journal_path}\n")
    for entry in entries[-80:]:
        print(
            f"{entry.timestamp}  {entry.op_id:<22} {entry.status:<9} "
            f"{human_bytes(entry.bytes):>10}  {entry.path}"
        )
    active = journal.active()
    print(
        f"\n{len(active)} item(s) still restorable, "
        f"{human_bytes(journal.total_bytes())} held in trash."
    )
    return 0


def _restore(args: argparse.Namespace) -> int:
    from .actions.executor import ActionError, ActionService
    from .config import load_settings
    from .scanner.jobs import JobManager
    from .util import human_bytes

    settings = load_settings()
    service = ActionService(settings, jobs=JobManager(settings))
    try:
        report = service.restore_operation(args.op_id)
    except ActionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if exc.hint:
            print(f"hint: {exc.hint}", file=sys.stderr)
        return 1
    print(f"Restored {report.ok_count} item(s), {human_bytes(report.bytes)} returned to disk.")
    for path, reason in report.skipped:
        print(f"  skipped: {path} — {reason}")
    return 0 if not report.skipped else 2


def _update(args: argparse.Namespace) -> int:
    """Delegate to the standard-library updater (see diskfree/updater.py)."""

    from .updater import main as update_main

    forwarded = list(getattr(args, "update_args", []) or [])
    if forwarded and forwarded[0] == "--":
        forwarded.pop(0)
    return update_main(forwarded)


_HANDLERS = {
    "serve": _serve,
    "scan": _scan,
    "advise": _advise,
    "status": _status,
    "providers": _providers,
    "rules": _rules,
    "history": _history,
    "history-restore": _restore,
    "update": _update,
}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # `update` is dispatched before argparse: the updater owns its own flags, and
    # it must stay runnable even when this CLI's dependencies are what it is
    # being asked to repair.
    if argv and argv[0] == "update":
        from .updater import main as update_main

        forwarded = argv[1:]
        if forwarded and forwarded[0] == "--":
            forwarded.pop(0)
        return update_main(forwarded)

    parser = _build_parser()
    args = parser.parse_args(argv)
    _apply_env(args)
    handler = _HANDLERS.get(args.command or "serve", _serve)
    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

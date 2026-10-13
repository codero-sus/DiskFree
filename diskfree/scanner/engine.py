"""Read-only filesystem analysis.

The scanner answers three questions: how much space is where, which of it is
regenerable, and what is duplicated or enormous. It never modifies anything.

Performance notes
-----------------
* One ``os.scandir`` pass per directory; no ``os.walk``, no recursion, so deep
  ``node_modules`` trees cannot exhaust the stack.
* Symlinks are never followed and never proposed for removal.
* A directory that matches a rule with ``prune=True`` becomes a single finding
  and is not descended into, which is what makes scanning a home directory with
  large caches fast.
* Rule matching is allocation-free in the hot loop: every pattern is compiled and
  case-folded once in :class:`~diskfree.scanner.rules.RuleSet`.
* Descent checks during the walk are pure string comparisons. The expensive
  ``realpath``-based policy check runs when a finding is created and again when
  an action executes.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from ..config import Settings
from ..safety.policy import Risk, SafetyPolicy, Tier
from ..util import count_tree, human_bytes, new_id, short_id
from .disks import enumerate_mounts, mark_scanned
from .models import DirTotal, Finding, Member, ScanResult, ScanStats
from .rules import (
    CATEGORY_META,
    DEFAULT_RULES,
    AggregateMode,
    Category,
    CompiledRule,
    Rule,
    RuleSet,
    fold_name,
)

ProgressCallback = Callable[["ScanProgress"], None]

#: Rules whose age threshold the user can tune from the UI.
_AGE_OVERRIDES = {
    "temp-files": "temp_min_age_days",
    "temp-dirs": "temp_min_age_days",
    "log-files": "log_min_age_days",
    "log-dirs": "log_min_age_days",
    "old-downloads": "old_file_min_age_days",
}


@dataclass(slots=True)
class ScanOptions:
    """What to scan and how hard to look."""

    roots: list[Path] = field(default_factory=list)
    max_depth: int = 24
    tree_depth: int = 4
    find_duplicates: bool = True
    find_large_files: bool = True
    include_advisories: bool = True
    categories: tuple[str, ...] | None = None
    rule_ids: tuple[str, ...] | None = None
    min_finding_bytes: int = 0
    max_findings: int = 20_000
    max_files_per_rule: int = 4_000
    max_members_per_finding: int = 40
    duplicate_min_bytes: int = 5 * 1024 * 1024
    duplicate_max_candidates: int = 5_000
    large_file_min_bytes: int = 250 * 1024 * 1024
    large_file_limit: int = 100
    temp_min_age_days: float | None = None
    log_min_age_days: float | None = None
    old_file_min_age_days: float | None = None
    top_folders: int = 60

    def as_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["roots"] = [str(root) for root in self.roots]
        return data


@dataclass(slots=True)
class ScanProgress:
    """Live progress, safe to hand to another thread."""

    phase: str = "starting"
    dirs: int = 0
    files: int = 0
    bytes: int = 0
    current: str = ""
    root: str = ""
    roots_done: int = 0
    roots_total: int = 0
    percent: float | None = None
    message: str = ""
    updated_at: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["bytes_human"] = human_bytes(self.bytes)
        return data


class Scanner:
    """Turns a set of roots into findings."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        policy: SafetyPolicy | None = None,
        home: Path | None = None,
        on_progress: ProgressCallback | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        self.settings = settings or Settings()
        self.home = (home or Path.home()).expanduser()
        self.policy = policy or SafetyPolicy(self.settings.safety, home=self.home)
        self.on_progress = on_progress
        self.cancel = cancel or threading.Event()
        self._last_emit = 0.0
        self._uid = os.getuid() if hasattr(os, "getuid") else None

    # -- rules -----------------------------------------------------------
    def build_ruleset(self, options: ScanOptions) -> RuleSet:
        """Compile the rule table, applying the user's age thresholds."""

        rules: list[Rule] = []
        for rule in DEFAULT_RULES:
            override_key = _AGE_OVERRIDES.get(rule.id)
            if override_key:
                value = getattr(options, override_key, None)
                if value is not None:
                    rule = replace(rule, matcher=replace(rule.matcher, min_age_days=float(value)))
            if options.categories and rule.category.value not in options.categories:
                continue
            if options.rule_ids and rule.id not in options.rule_ids:
                continue
            rules.append(rule)
        return RuleSet(tuple(rules), home=self.home)

    # -- progress --------------------------------------------------------
    def _emit(self, progress: ScanProgress, *, force: bool = False) -> None:
        if self.on_progress is None:
            return
        now = time.monotonic()
        if not force and now - self._last_emit < 0.15:
            return
        self._last_emit = now
        progress.updated_at = time.time()
        try:
            self.on_progress(progress)
        except Exception:  # pragma: no cover - progress must never break a scan
            pass

    # -- main entry point ------------------------------------------------
    def run(self, options: ScanOptions) -> ScanResult:
        """Execute a full scan."""

        started = time.monotonic()
        root_notes: list[str] = []
        roots = self._resolve_roots(options.roots, root_notes)
        ruleset = self.build_ruleset(options)
        stats = ScanStats(
            roots=[str(root) for root in roots], started_at=time.time()
        )
        result = ScanResult(job_id="", roots=roots, stats=stats)
        progress = ScanProgress(
            phase="scanning", roots_total=len(roots), message="Preparing scan"
        )
        self._emit(progress, force=True)

        aggregates: dict[tuple[str, str], Finding] = {}
        rule_file_counts: dict[str, int] = {}
        dir_totals: dict[str, int] = {}
        dir_files: dict[str, int] = {}
        dir_depth: dict[str, int] = {}
        dir_root: dict[str, str] = {}
        duplicate_candidates: dict[int, list[tuple[str, float]]] = {}
        large_files: list[tuple[int, str, float]] = []
        candidate_count = 0

        for index, root in enumerate(roots):
            if self.cancel.is_set():
                progress.phase = "cancelled"
                break
            progress.root = str(root)
            progress.roots_done = index
            progress.message = f"Scanning {root}"
            self._emit(progress, force=True)
            candidate_count = self._walk_root(
                root,
                options=options,
                ruleset=ruleset,
                result=result,
                stats=stats,
                progress=progress,
                aggregates=aggregates,
                rule_file_counts=rule_file_counts,
                dir_totals=dir_totals,
                dir_files=dir_files,
                dir_depth=dir_depth,
                dir_root=dir_root,
                duplicate_candidates=duplicate_candidates,
                large_files=large_files,
                candidate_count=candidate_count,
            )

        if not self.cancel.is_set():
            progress.phase = "duplicates"
            progress.message = "Comparing duplicate candidates"
            self._emit(progress, force=True)
            if options.find_duplicates:
                self._find_duplicates(
                    options, ruleset, result, stats, progress, duplicate_candidates
                )
            if options.find_large_files:
                self._finish_large_files(large_files, options, ruleset, result, stats)
            progress.phase = "advisories"
            progress.message = "Checking system locations"
            self._emit(progress, force=True)
            if options.include_advisories:
                self._probe_system(options, ruleset, result, stats)

        progress.phase = "summarising"
        progress.message = "Ranking folders"
        self._emit(progress, force=True)
        result.dir_totals = self._rank_dirs(
            dir_totals, dir_files, dir_depth, dir_root, options.top_folders
        )
        result.mounts = enumerate_mounts(roots)
        mark_scanned(result.mounts, roots)
        self._finalise(result, options, root_notes)
        stats.finished_at = time.time()
        stats.dirs_seen = progress.dirs
        stats.files_seen = progress.files
        stats.bytes_seen = progress.bytes
        progress.phase = "cancelled" if self.cancel.is_set() else "done"
        progress.roots_done = len(roots)
        progress.message = (
            "Cancelled" if self.cancel.is_set() else f"Found {len(result.findings)} findings"
        )
        progress.percent = 100.0
        self._emit(progress, force=True)
        result.stats = stats
        _ = started
        return result

    # -- roots -----------------------------------------------------------
    def _resolve_roots(
        self, requested: Iterable[Path], notes: list[str] | None = None
    ) -> list[Path]:
        """Turn requested roots into real, de-duplicated directories to walk."""

        resolved: list[Path] = []
        seen: set[str] = set()
        for raw in requested:
            original = str(raw)
            path = Path(os.fspath(raw)).expanduser()
            try:
                path = path.resolve()
            except OSError:
                if notes is not None:
                    notes.append(f"'{original}' could not be resolved and was skipped.")
                continue
            if not path.exists():
                if notes is not None:
                    notes.append(f"'{original}' does not exist and was skipped.")
                continue
            if not path.is_dir():
                path = path.parent
            key = os.path.normcase(str(path))
            if key in seen:
                continue
            # Skip a root that is inside one already accepted.
            if any(_is_within(key, os.path.normcase(str(other))) for other in resolved):
                continue
            resolved = [
                other for other in resolved if not _is_within(os.path.normcase(str(other)), key)
            ]
            seen = {os.path.normcase(str(item)) for item in resolved}
            seen.add(key)
            resolved.append(path)
        return resolved

    # -- the walk --------------------------------------------------------
    def _walk_root(
        self,
        root: Path,
        *,
        options: ScanOptions,
        ruleset: RuleSet,
        result: ScanResult,
        stats: ScanStats,
        progress: ScanProgress,
        aggregates: dict[tuple[str, str], Finding],
        rule_file_counts: dict[str, int],
        dir_totals: dict[str, int],
        dir_files: dict[str, int],
        dir_depth: dict[str, int],
        dir_root: dict[str, str],
        duplicate_candidates: dict[int, list[tuple[str, float]]],
        large_files: list[tuple[int, str, float]],
        candidate_count: int,
    ) -> int:
        root_str = str(root)
        root_prefix_len = len(root_str.rstrip(os.sep)) + 1
        stack: list[tuple[str, int, frozenset[str], tuple[str, ...]]] = [
            (root_str, 0, frozenset({fold_name(root.name)}), (root_str,))
        ]
        dir_totals.setdefault(root_str, 0)
        dir_files.setdefault(root_str, 0)
        dir_depth.setdefault(root_str, 0)
        dir_root.setdefault(root_str, root_str)
        now = time.time()

        while stack:
            if self.cancel.is_set():
                return candidate_count
            dir_path, depth, parents, ancestors = stack.pop()
            progress.dirs += 1
            if progress.dirs % 512 == 0:
                progress.current = dir_path
                self._emit(progress)

            try:
                with os.scandir(dir_path) as iterator:
                    entries = list(iterator)
            except OSError as exc:
                stats.permission_errors += 1
                if len(result.errors) < 200:
                    result.errors.append(f"{dir_path}: {exc.strerror or exc}")
                continue

            siblings = frozenset(fold_name(entry.name) for entry in entries)

            for entry in entries:
                if self.cancel.is_set():
                    return candidate_count
                name = entry.name
                try:
                    is_link = entry.is_symlink()
                except OSError:
                    continue
                if is_link:
                    stats.symlinks_skipped += 1
                    continue
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    stat = entry.stat(follow_symlinks=False)
                except OSError:
                    stats.permission_errors += 1
                    continue

                entry_path = entry.path
                size = stat.st_size if not is_dir else 0
                mtime = stat.st_mtime
                age_days = max(0.0, (now - mtime) / 86400) if mtime else 0.0
                rel = entry_path[root_prefix_len:] if len(entry_path) > root_prefix_len else name

                if is_dir:
                    self._handle_dir(
                        entry_path=entry_path,
                        name=name,
                        rel=rel,
                        depth=depth,
                        mtime=mtime,
                        age_days=age_days,
                        siblings=siblings,
                        parents=parents,
                        root=root,
                        root_str=root_str,
                        options=options,
                        ruleset=ruleset,
                        result=result,
                        stats=stats,
                        progress=progress,
                        aggregates=aggregates,
                        rule_file_counts=rule_file_counts,
                        dir_totals=dir_totals,
                        dir_files=dir_files,
                        dir_depth=dir_depth,
                        dir_root=dir_root,
                        stack=stack,
                        ancestors=ancestors,
                    )
                    continue

                # ---- regular file ----
                progress.files += 1
                progress.bytes += size
                for ancestor in ancestors:
                    dir_totals[ancestor] = dir_totals.get(ancestor, 0) + size
                    dir_files[ancestor] = dir_files.get(ancestor, 0) + 1

                compiled = ruleset.match(
                    path=Path(entry_path),
                    name=name,
                    rel=rel,
                    is_dir=False,
                    size=size,
                    age_days=age_days,
                    siblings=siblings,
                    parents=parents,
                    own_file=self._uid is None or stat.st_uid == self._uid,
                )
                if compiled is not None:
                    self._add_file_match(
                        compiled=compiled,
                        entry_path=entry_path,
                        name=name,
                        size=size,
                        mtime=mtime,
                        age_days=age_days,
                        root=root,
                        root_str=root_str,
                        options=options,
                        ruleset=ruleset,
                        result=result,
                        stats=stats,
                        aggregates=aggregates,
                        rule_file_counts=rule_file_counts,
                    )
                else:
                    if (
                        options.find_duplicates
                        and size >= options.duplicate_min_bytes
                        and candidate_count < options.duplicate_max_candidates
                    ):
                        duplicate_candidates.setdefault(size, []).append((entry_path, mtime))
                        candidate_count += 1
                    if options.find_large_files and size >= options.large_file_min_bytes:
                        large_files.append((size, entry_path, mtime))

        return candidate_count

    def _handle_dir(
        self,
        *,
        entry_path: str,
        name: str,
        rel: str,
        depth: int,
        mtime: float,
        age_days: float,
        siblings: frozenset[str],
        parents: frozenset[str],
        root: Path,
        root_str: str,
        options: ScanOptions,
        ruleset: RuleSet,
        result: ScanResult,
        stats: ScanStats,
        progress: ScanProgress,
        aggregates: dict[tuple[str, str], Finding],
        rule_file_counts: dict[str, int],
        dir_totals: dict[str, int],
        dir_files: dict[str, int],
        dir_depth: dict[str, int],
        dir_root: dict[str, str],
        stack: list[tuple[str, int, frozenset[str], tuple[str, ...]]],
        ancestors: tuple[str, ...],
    ) -> None:
        blocked, _reason = self.policy.literal_descent_blocked(entry_path)
        if blocked:
            stats.pruned_dirs += 1
            return

        compiled = ruleset.match(
            path=Path(entry_path),
            name=name,
            rel=rel,
            is_dir=True,
            size=0,
            age_days=age_days,
            siblings=siblings,
            parents=parents,
        )
        if compiled is not None and compiled.rule.prune:
            size, files = count_tree(entry_path)
            self._register_finding(
                compiled=compiled,
                path=entry_path,
                name=name,
                is_dir=True,
                size=size,
                files=files,
                mtime=mtime,
                age_days=age_days,
                root=root,
                root_str=root_str,
                options=options,
                result=result,
                stats=stats,
                aggregates=aggregates,
                rule_file_counts=rule_file_counts,
                sample_children=True,
            )
            stats.pruned_dirs += 1
            progress.bytes += size
            progress.files += files
            # A pruned subtree is not walked, so fold its size into the tracked
            # ancestor directories here or the "biggest folders" view would
            # under-report exactly the directories that matter most.
            for ancestor in ancestors:
                dir_totals[ancestor] = dir_totals.get(ancestor, 0) + size
                dir_files[ancestor] = dir_files.get(ancestor, 0) + files
            # ...and the pruned directory is itself one of the biggest folders the
            # user will want to see, so record it too.
            if depth + 1 <= options.tree_depth:
                dir_totals[entry_path] = dir_totals.get(entry_path, 0) + size
                dir_files[entry_path] = dir_files.get(entry_path, 0) + files
                dir_depth.setdefault(entry_path, depth + 1)
                dir_root.setdefault(entry_path, root_str)
            return

        if depth + 1 > options.max_depth:
            return

        next_parents = parents | {fold_name(name)}
        next_ancestors: tuple[str, ...] = ancestors
        if depth + 1 <= options.tree_depth:
            next_ancestors = (*ancestors, entry_path)
        stack.append((entry_path, depth + 1, next_parents, next_ancestors))
        if depth + 1 <= options.tree_depth:
            dir_totals.setdefault(entry_path, 0)
            dir_files.setdefault(entry_path, 0)
            dir_depth.setdefault(entry_path, depth + 1)
            dir_root.setdefault(entry_path, root_str)

    # -- finding construction -------------------------------------------
    def _add_file_match(
        self,
        *,
        compiled: CompiledRule,
        entry_path: str,
        name: str,
        size: int,
        mtime: float,
        age_days: float,
        root: Path,
        root_str: str,
        options: ScanOptions,
        ruleset: RuleSet,
        result: ScanResult,
        stats: ScanStats,
        aggregates: dict[tuple[str, str], Finding],
        rule_file_counts: dict[str, int],
    ) -> None:
        rule = compiled.rule
        if rule.aggregate is AggregateMode.SELF:
            count = rule_file_counts.get(rule.id, 0)
            if count >= options.max_files_per_rule:
                return
            rule_file_counts[rule.id] = count + 1
            self._register_finding(
                compiled=compiled,
                path=entry_path,
                name=name,
                is_dir=False,
                size=size,
                files=1,
                mtime=mtime,
                age_days=age_days,
                root=root,
                root_str=root_str,
                options=options,
                result=result,
                stats=stats,
                aggregates=aggregates,
                rule_file_counts=rule_file_counts,
            )
            return

        key = ruleset.group_key(compiled, Path(entry_path), root)
        lookup = (rule.id, key)
        finding = aggregates.get(lookup)
        if finding is None:
            count = rule_file_counts.get(rule.id, 0)
            if count >= options.max_files_per_rule:
                return
            finding = self._new_finding(
                compiled=compiled,
                path=key,
                name=Path(key).name or key,
                is_dir=True,
                root=root,
                root_str=root_str,
                options=options,
                mtime=mtime,
                age_days=age_days,
            )
            aggregates[lookup] = finding
            result.findings.append(finding)
        finding.bytes += size
        finding.files += 1
        finding.members_total += 1
        finding.mtime = max(finding.mtime, mtime)
        finding.age_days = min(finding.age_days, age_days) if finding.age_days else age_days
        if len(finding.members) < options.max_members_per_finding:
            finding.members.append(Member(path=entry_path, bytes=size, mtime=mtime))
        else:
            finding.truncated = True
        rule_file_counts[rule.id] = rule_file_counts.get(rule.id, 0) + 1

    def _register_finding(
        self,
        *,
        compiled: CompiledRule,
        path: str,
        name: str,
        is_dir: bool,
        size: int,
        files: int,
        mtime: float,
        age_days: float,
        root: Path,
        root_str: str,
        options: ScanOptions,
        result: ScanResult,
        stats: ScanStats,
        aggregates: dict[tuple[str, str], Finding],
        rule_file_counts: dict[str, int],
        sample_children: bool = False,
    ) -> None:
        if len(result.findings) >= options.max_findings:
            stats.truncated = True
            return
        if size < options.min_finding_bytes:
            return
        finding = self._new_finding(
            compiled=compiled,
            path=path,
            name=name,
            is_dir=is_dir,
            root=root,
            root_str=root_str,
            options=options,
            mtime=mtime,
            age_days=age_days,
            size=size,
            files=files,
        )
        if sample_children and is_dir:
            finding.members = _sample_children(Path(path), options.max_members_per_finding)
            finding.members_total = max(finding.members_total, files)
        result.findings.append(finding)

    def _new_finding(
        self,
        *,
        compiled: CompiledRule,
        path: str,
        name: str,
        is_dir: bool,
        root: Path,
        root_str: str,
        options: ScanOptions,
        mtime: float = 0.0,
        age_days: float = 0.0,
        size: int = 0,
        files: int = 0,
    ) -> Finding:
        rule = compiled.rule
        info = self.policy.classify(path)
        tier = info.tier
        risk = rule.risk
        if tier is Tier.SENSITIVE and not (rule.cache_specific and info.zone_escape):
            # Personal data: escalate, but a precise cache rule that matched a
            # cache-looking directory inside a blocked home zone keeps its own
            # (conservative, reversible) risk.
            risk = Risk.HIGH if risk.rank < Risk.HIGH.rank else risk
        if tier is Tier.BLOCKED:
            risk = Risk.FORBIDDEN
        actionable = rule.actionable and tier is not Tier.BLOCKED
        extra: dict[str, object] = {}
        if info.reason:
            extra["tier_reason"] = info.reason
        if info.zone_escape:
            extra["zone_escape"] = True
        if rule.aggregate is not AggregateMode.SELF:
            extra["aggregated"] = True
        return Finding(
            id=short_id(rule.id, path),
            rule_id=rule.id,
            category=rule.category,
            risk=risk,
            title=rule.title,
            description=rule.description,
            path=path,
            name=name,
            is_dir=is_dir,
            bytes=size,
            files=files,
            mtime=mtime,
            age_days=age_days,
            root=root_str,
            tier=tier,
            actionable=actionable,
            # Nothing above "safe" is ever pre-ticked, whatever the rule says.
            default_selected=bool(
                rule.default_selected and actionable and risk.auto_selectable
            ),
            advisory=rule.advisory,
            extra=extra,
        )

    # -- computed passes -------------------------------------------------
    def _find_duplicates(
        self,
        options: ScanOptions,
        ruleset: RuleSet,
        result: ScanResult,
        stats: ScanStats,
        progress: ScanProgress,
        pool: dict[int, list[tuple[str, float]]],
    ) -> None:
        from .duplicates import find_duplicate_groups

        rule = ruleset.get("duplicates")
        if rule is None or not pool:
            return
        groups = find_duplicate_groups(
            pool,
            cancel=self.cancel,
            on_progress=lambda done, total: self._emit(
                replace(
                    progress,
                    phase="duplicates",
                    message=f"Hashing duplicate candidates ({done}/{total})",
                )
            ),
        )
        for group in groups:
            if self.cancel.is_set():
                break
            keeper, extras = group
            if not extras:
                continue
            for path, size, mtime in extras:
                tier, reason = self.policy.tier(path)
                if tier is Tier.BLOCKED:
                    continue
                finding = Finding(
                    id=short_id("duplicates", path),
                    rule_id=rule.id,
                    category=Category.DUPLICATES,
                    risk=Risk.MEDIUM if tier is Tier.NORMAL else Risk.HIGH,
                    title=rule.title,
                    description=rule.description,
                    path=path,
                    name=Path(path).name,
                    is_dir=False,
                    bytes=size,
                    files=1,
                    mtime=mtime,
                    age_days=max(0.0, (time.time() - mtime) / 86400) if mtime else 0.0,
                    root="",
                    tier=tier,
                    actionable=True,
                    default_selected=False,
                    extra={
                        "duplicate_of": keeper[0],
                        "duplicate_group": short_id("dup", keeper[0], size),
                        "kept_reason": "oldest copy / shortest path",
                        "tier_reason": reason or "",
                    },
                )
                result.findings.append(finding)
                stats.duplicate_groups += 1
                stats.duplicate_bytes += size

    def _finish_large_files(
        self,
        large_files: list[tuple[int, str, float]],
        options: ScanOptions,
        ruleset: RuleSet,
        result: ScanResult,
        stats: ScanStats,
    ) -> None:
        rule = ruleset.get("large-files")
        if rule is None or not large_files:
            return
        large_files.sort(key=lambda item: item[0], reverse=True)
        seen_paths = {finding.path for finding in result.findings}
        for size, path, mtime in large_files[: options.large_file_limit]:
            if path in seen_paths:
                continue
            tier, reason = self.policy.tier(path)
            if tier is Tier.BLOCKED:
                continue
            result.findings.append(
                Finding(
                    id=short_id("large-files", path),
                    rule_id=rule.id,
                    category=Category.LARGE_FILES,
                    risk=Risk.HIGH,
                    title=rule.title,
                    description=rule.description,
                    path=path,
                    name=Path(path).name,
                    is_dir=False,
                    bytes=size,
                    files=1,
                    mtime=mtime,
                    age_days=max(0.0, (time.time() - mtime) / 86400) if mtime else 0.0,
                    root="",
                    tier=tier,
                    # Explicitly selectable for review, but never pre-selected.
                    # Their high risk keeps model advice in the review bucket.
                    actionable=True,
                    default_selected=False,
                    extra={"tier_reason": reason or "", "user_review_only": True},
                )
            )

    def _probe_system(
        self,
        options: ScanOptions,
        ruleset: RuleSet,
        result: ScanResult,
        stats: ScanStats,
    ) -> None:
        """Report root-owned subsystems as copy-paste commands, never deletions."""

        for compiled, path in ruleset.probe_paths():
            if len(result.findings) >= options.max_findings:
                result.stats.truncated = True
                break
            rule = compiled.rule
            if path.is_dir():
                size, files = count_tree(path)
                is_dir = True
            else:
                try:
                    stat = path.stat()
                except OSError:
                    continue
                size, files, is_dir = stat.st_size, 1, False
            existing = {finding.path for finding in result.findings}
            if str(path) in existing:
                continue
            result.findings.append(
                Finding(
                    id=short_id(rule.id, str(path)),
                    rule_id=rule.id,
                    category=rule.category,
                    risk=Risk.FORBIDDEN,
                    title=rule.title,
                    description=rule.description,
                    path=str(path),
                    name=path.name,
                    is_dir=is_dir,
                    bytes=size,
                    files=files,
                    mtime=0.0,
                    age_days=0.0,
                    root="",
                    tier=Tier.BLOCKED,
                    actionable=False,
                    default_selected=False,
                    advisory=rule.advisory,
                    extra={
                        "probe": True,
                        "size_may_be_incomplete": True,
                        # A root-owned tree we could not read reports zero bytes,
                        # which must not read as "this costs you nothing".
                        "size_unknown": bool(is_dir and size == 0),
                    },
                )
            )

    # -- summaries -------------------------------------------------------
    def _rank_dirs(
        self,
        dir_totals: dict[str, int],
        dir_files: dict[str, int],
        dir_depth: dict[str, int],
        dir_root: dict[str, str],
        limit: int,
    ) -> list[DirTotal]:
        items = sorted(dir_totals.items(), key=lambda kv: kv[1], reverse=True)
        out: list[DirTotal] = []
        for path, size in items[:limit]:
            if size <= 0:
                continue
            out.append(
                DirTotal(
                    path=path,
                    name=Path(path).name or path,
                    bytes=size,
                    depth=dir_depth.get(path, 0),
                    files=dir_files.get(path, 0),
                    root=dir_root.get(path, ""),
                )
            )
        return out

    def _finalise(
        self,
        result: ScanResult,
        options: ScanOptions,
        root_notes: list[str] | None = None,
    ) -> None:
        # Aggregated findings accumulate their size after creation, so the byte
        # floor and every total are recomputed here from the final list rather
        # than tracked incrementally (which silently missed grouped findings).
        if options.min_finding_bytes:
            floor = options.min_finding_bytes
            kept: list[Finding] = []
            dropped = 0
            for finding in result.findings:
                # Probes report someone else's subsystem and the computed passes
                # have their own thresholds; neither obeys the display floor.
                if finding.bytes < floor and not (
                    finding.extra.get("probe")
                    or finding.rule_id in {"duplicates", "large-files"}
                ):
                    dropped += 1
                    continue
                kept.append(finding)
            if dropped:
                result.findings = kept
        stats = result.stats
        stats.findings = len(result.findings)
        stats.actionable_bytes = sum(
            finding.bytes for finding in result.findings if finding.actionable
        )
        stats.safe_bytes = sum(
            finding.bytes
            for finding in result.findings
            if finding.actionable and finding.risk is Risk.SAFE
        )
        order = {category.value: meta.order for category, meta in CATEGORY_META.items()}
        result.findings.sort(
            key=lambda finding: (
                0 if finding.actionable else 1,
                order.get(finding.category.value, 99),
                finding.risk.rank,
                -finding.bytes,
            )
        )
        if root_notes:
            result.warnings.extend(root_notes)
        result.warnings.extend(_warnings_for(result, options))


def _warnings_for(result: ScanResult, options: ScanOptions) -> list[str]:
    warnings: list[str] = []
    if result.stats.truncated:
        warnings.append(
            f"The finding cap ({options.max_findings}) was reached; results are partial."
        )
    if result.stats.permission_errors:
        warnings.append(
            f"{result.stats.permission_errors} paths could not be read (permissions). "
            "Run DiskFree as your normal user; system areas need their own tools."
        )
    if result.stats.symlinks_skipped:
        warnings.append(
            f"{result.stats.symlinks_skipped} symlinks were skipped; DiskFree never "
            "follows or removes links."
        )
    return warnings


def _sample_children(path: Path, limit: int) -> list[Member]:
    """A few representative entries of a pruned directory, for the review UI."""

    out: list[Member] = []
    try:
        with os.scandir(path) as iterator:
            for entry in iterator:
                if len(out) >= limit:
                    break
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        size, _ = count_tree(entry.path)
                        mtime = entry.stat(follow_symlinks=False).st_mtime
                    else:
                        stat = entry.stat(follow_symlinks=False)
                        size, mtime = stat.st_size, stat.st_mtime
                except OSError:
                    continue
                out.append(Member(path=entry.path, bytes=size, mtime=mtime))
    except OSError:
        return out
    out.sort(key=lambda member: member.bytes, reverse=True)
    return out


def _is_within(candidate: str, root: str) -> bool:
    if candidate == root:
        return True
    return candidate.startswith(root.rstrip(os.sep) + os.sep)


def describe_options(options: ScanOptions) -> str:
    """Human summary of what a scan will do."""

    roots = ", ".join(str(root) for root in options.roots) or "no roots"
    extras = [name for name, enabled in (
        ("duplicates", options.find_duplicates),
        ("large files", options.find_large_files),
        ("system advisories", options.include_advisories),
    ) if enabled]
    return f"roots=[{roots}] depth={options.max_depth} extras={'+'.join(extras) or 'none'}"


def make_job_id() -> str:
    return new_id("scan")

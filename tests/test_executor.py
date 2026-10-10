"""The two-step clean: plan, prove you saw it, execute, undo.

These are the tests that matter most. A confirmation token that can be forged, a
plan that can be replayed, or an aggregate that deletes its anchor directory would
each be a data-loss bug, so each one gets its own assertion.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from diskfree.actions.executor import (
    MAX_ITEMS_PER_OPERATION,
    ActionError,
    CleanPlan,
    PlanItem,
    _collapse_nested,
    _is_a_root,
)
from diskfree.safety.policy import Risk
from diskfree.scanner.engine import ScanOptions
from diskfree.scanner.jobs import JobManager, ScanJob, ScanStatus
from diskfree.scanner.models import ScanResult
from tests.conftest import FakeHome, _write


def _service_with(settings, fake_home: FakeHome, *, journal=None, **safety_overrides):
    """A fresh ActionService whose SafetySettings differ from the fixture's.

    ``SafetySettings`` is frozen on purpose -- the running server's safety posture
    cannot be flipped by a stray assignment -- so tests build a new one.
    """

    from dataclasses import replace as dc_replace

    from diskfree.actions.executor import ActionService
    from diskfree.safety.policy import SafetyPolicy
    from diskfree.safety.trash import Journal, TrashManager

    safety = dc_replace(settings.safety, **safety_overrides)
    new_settings = dc_replace(settings, safety=safety)
    data_dir = new_settings.data_dir
    policy = SafetyPolicy(safety, home=fake_home.root, own_paths=[data_dir])
    log = journal or Journal(data_dir / f"journal-{safety.allow_permanent_delete}.jsonl")
    service = ActionService(
        new_settings, jobs=JobManager(new_settings, policy=policy), policy=policy,
        journal=log,
        trash=TrashManager(safety, data_dir=data_dir, journal=log, home=fake_home.root,
                           policy=policy),
    )
    return service, log


def ids_for(result: ScanResult, rule_id: str) -> list[str]:
    return [finding.id for finding in result.findings if finding.rule_id == rule_id]


def selectable(scan_job: ScanJob) -> list[str]:
    return [finding.id for finding in scan_job.result.findings if finding.actionable]


def find(result: ScanResult, rule_id: str):
    matches = [finding for finding in result.findings if finding.rule_id == rule_id]
    assert matches, f"no {rule_id} finding"
    return matches[0]


# --------------------------------------------------------------------------
# planning
# --------------------------------------------------------------------------


def test_plan_itemises_and_prices_the_selection(actions, scan_job: ScanJob) -> None:
    plan = actions.create_plan(scan_job, ids_for(scan_job.result, "pkg-pip-cache"))

    assert isinstance(plan, CleanPlan)
    assert plan.mode == "trash"
    assert plan.job_id == scan_job.id
    assert plan.item_count if hasattr(plan, "item_count") else plan.allowed_items
    assert plan.total_bytes > 0
    assert plan.confirm_token
    assert plan.expires_at > plan.created_at
    assert plan.expired is False
    payload = plan.as_dict()
    assert payload["confirm_token"] == plan.confirm_token
    assert payload["items"], "a plan must show exactly what it will remove"
    assert payload["total_bytes_human"]


def test_plan_refuses_advisory_and_protected_findings(actions, scan_job: ScanJob) -> None:
    probes = [
        finding.id for finding in scan_job.result.findings
        if finding.extra.get("probe") or not finding.actionable
    ]
    if not probes:
        pytest.skip("this host exposes no system probes")
    plan = actions.create_plan(scan_job, probes)
    assert not plan.allowed_items
    assert plan.refused_items
    assert all(item.reason for item in plan.refused_items)


def test_plan_refuses_unknown_findings(actions, scan_job: ScanJob) -> None:
    plan = actions.create_plan(scan_job, ["not-a-real-finding"], mode="dry_run")
    assert not plan.allowed_items
    assert plan.refused_items[0].reason == "that finding is not part of this scan"


def test_plan_refuses_an_unknown_mode(actions, scan_job: ScanJob) -> None:
    with pytest.raises(ActionError) as error:
        actions.create_plan(scan_job, selectable(scan_job), mode="shred-everything")
    assert "shred-everything" in str(error.value)


def test_plan_refuses_an_empty_selection(actions, scan_job: ScanJob) -> None:
    with pytest.raises(ActionError):
        actions.create_plan(scan_job, [])


def test_plan_deduplicates_the_selection(actions, scan_job: ScanJob) -> None:
    wanted = ids_for(scan_job.result, "pkg-pip-cache")
    plan = actions.create_plan(scan_job, wanted + wanted + wanted, mode="dry_run")
    assert len(plan.items) == len(wanted)


def test_plan_refuses_too_many_items(
    actions, scan_job: ScanJob, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("diskfree.actions.executor.MAX_ITEMS_PER_OPERATION", 1)
    wanted = selectable(scan_job)
    if len(wanted) < 2:
        pytest.skip("not enough findings")
    with pytest.raises(ActionError) as error:
        actions.create_plan(scan_job, wanted, mode="dry_run")
    assert "1" in str(error.value) or "Too many" in str(error.value)
    assert MAX_ITEMS_PER_OPERATION > 1, "the real limit must stay generous"


# --------------------------------------------------------------------------
# the aggregate guard
# --------------------------------------------------------------------------


def test_aggregate_finding_expands_to_its_members(actions, scan_job: ScanJob) -> None:
    """`Old downloads` is a summary of ~/Downloads; the folder must never be planned."""

    result = scan_job.result
    finding = find(result, "old-downloads")
    assert finding.extra.get("aggregated") is True
    member_paths = [member.path for member in finding.members]
    assert member_paths, "the scan recorded the individual files"

    plan = actions.create_plan(scan_job, [finding.id], mode="dry_run")

    planned = {item.path for item in plan.allowed_items}
    assert planned == set(member_paths)
    assert finding.path not in planned, "the Downloads folder itself must never be a target"
    assert all(item.finding_id == finding.id for item in plan.items)
    assert plan.total_bytes == sum(item.bytes for item in plan.allowed_items)


def test_temp_anchor_is_never_a_deletion_target(
    actions, scanner, fake_home: FakeHome, jobs
) -> None:
    """The most dangerous aggregate: stale files grouped under /tmp itself."""

    temp_root = fake_home.root.parent / "tmparea"
    temp_root.mkdir(parents=True, exist_ok=True)
    stale = _write(temp_root / "installer-1.tmp", 4096, age_days=40)
    fresh = _write(temp_root / "running-app.tmp", 4096, age_days=0)

    options = ScanOptions(
        roots=[temp_root], temp_min_age_days=7, find_duplicates=False,
        find_large_files=False, include_advisories=False,
    )
    result = scanner.run(options)
    job = ScanJob(id="temp-job", options=options, status=ScanStatus.COMPLETED)
    job.result = result

    aggregates = [f for f in result.findings if f.rule_id == "temp-files"]
    assert aggregates, "stale temp files should be found"
    aggregate = aggregates[0]
    assert aggregate.extra.get("aggregated") is True

    plan = actions.create_plan(job, [aggregate.id], mode="dry_run")
    planned = {item.path for item in plan.allowed_items}

    assert str(stale) in planned
    assert str(fresh) not in planned, "a file a running app may own is left alone"
    assert str(temp_root) not in planned, "the temp area itself must never be a target"
    assert not _is_a_root(Path(aggregate.path), [temp_root]) or not planned


def test_a_scan_root_is_never_a_deletion_target(actions, jobs, fake_home: FakeHome) -> None:
    """Even if a finding somehow names the root, the plan must refuse it."""

    from diskfree.safety.policy import Tier
    from diskfree.scanner.models import Category, Finding

    root = fake_home.root
    result = ScanResult(job_id="root-job", roots=[root])
    result.findings.append(
        Finding(
            id="evil-root-finding", rule_id="pkg-pip-cache", category=Category.PACKAGE_CACHE,
            risk=Risk.SAFE, title="Whole scan root", description="test",
            path=str(root), name=root.name, is_dir=True, bytes=1024, files=1,
            root=str(root), tier=Tier.NORMAL, actionable=True, default_selected=True,
        )
    )
    job = ScanJob(id="root-job", options=ScanOptions(roots=[root]),
                  status=ScanStatus.COMPLETED)
    job.result = result

    plan = actions.create_plan(job, ["evil-root-finding"], mode="dry_run")
    assert not plan.allowed_items
    assert "scan root" in plan.refused_items[0].reason


def test_nested_selection_collapses_to_the_shallowest_path() -> None:
    def item(path: str, size: int) -> PlanItem:
        return PlanItem(
            finding_id="f", path=path, bytes=size, files=1, is_dir=True,
            risk="safe", category="app_cache", title="t", allowed=True,
        )

    items = [
        item("/home/u/.cache/app/sub/deep", 1),
        item("/home/u/.cache/app", 10),
        item("/home/u/.cache/app/sub", 5),
        item("/home/u/other", 7),
    ]
    collapsed = _collapse_nested(items)
    assert {entry.path for entry in collapsed} == {"/home/u/.cache/app", "/home/u/other"}
    assert len(collapsed) == 2, "children of a selected parent are redundant"

    with_refused = [
        *items,
        PlanItem(
            finding_id="f", path="/home/u/blocked", bytes=1, files=1, is_dir=False,
            risk="forbidden", category="system", title="t", allowed=False,
            reason="protected by policy",
        ),
    ]
    kept = _collapse_nested(with_refused)
    assert {entry.path for entry in kept} == {
        "/home/u/.cache/app", "/home/u/other", "/home/u/blocked"
    }
    assert [entry.reason for entry in kept if not entry.allowed] == ["protected by policy"]


# --------------------------------------------------------------------------
# confirmation tokens
# --------------------------------------------------------------------------


def test_a_valid_token_executes(actions, scan_job: ScanJob) -> None:
    plan = actions.create_plan(scan_job, ids_for(scan_job.result, "pkg-pip-cache"),
                               mode="dry_run")
    report = actions.execute(plan.id, plan.confirm_token)
    assert report.mode == "dry_run"
    assert report.ok_count == len(plan.allowed_items)
    assert report.bytes == plan.total_bytes


def test_a_missing_token_is_refused(actions, scan_job: ScanJob) -> None:
    plan = actions.create_plan(scan_job, selectable(scan_job), mode="dry_run")
    with pytest.raises(ActionError) as error:
        actions.execute(plan.id, None)
    assert "token" in str(error.value).lower()


def test_a_tampered_token_is_refused(actions, scan_job: ScanJob) -> None:
    plan = actions.create_plan(scan_job, selectable(scan_job), mode="dry_run")
    with pytest.raises(ActionError):
        actions.execute(plan.id, plan.confirm_token[:-4] + "dead")
    with pytest.raises(ActionError):
        actions.execute(plan.id, "0" * len(plan.confirm_token))
    with pytest.raises(ActionError):
        actions.execute(plan.id, plan.confirm_token.upper())


def test_a_token_cannot_be_moved_between_plans(actions, scan_job: ScanJob) -> None:
    first = actions.create_plan(scan_job, ids_for(scan_job.result, "pkg-pip-cache"),
                                mode="dry_run")
    second = actions.create_plan(scan_job, ids_for(scan_job.result, "app-thumbnails"),
                                 mode="dry_run")
    assert first.confirm_token != second.confirm_token
    with pytest.raises(ActionError):
        actions.execute(second.id, first.confirm_token)


def test_changing_the_mode_invalidates_the_token(actions, scan_job: ScanJob) -> None:
    wanted = ids_for(scan_job.result, "pkg-pip-cache")
    trash_plan = actions.create_plan(scan_job, wanted, mode="trash")
    with pytest.raises(ActionError):
        actions.execute(trash_plan.id, trash_plan.confirm_token.replace("a", "b"))
    dry_plan = actions.create_plan(scan_job, wanted, mode="dry_run")
    assert dry_plan.confirm_token != trash_plan.confirm_token
    with pytest.raises(ActionError):
        actions.execute(dry_plan.id, trash_plan.confirm_token)


def test_an_expired_plan_is_refused(actions, scan_job: ScanJob) -> None:
    plan = actions.create_plan(scan_job, selectable(scan_job), mode="dry_run", ttl=-1)
    assert plan.expired is True
    with pytest.raises(ActionError) as error:
        actions.execute(plan.id, plan.confirm_token)
    assert "expired" in str(error.value).lower()


def test_an_unknown_plan_is_refused(actions) -> None:
    with pytest.raises(ActionError):
        actions.execute("plan-does-not-exist", "x" * 64)


def test_a_plan_is_single_use(actions, scan_job: ScanJob, fake_home: FakeHome) -> None:
    wanted = ids_for(scan_job.result, "app-thumbnails")
    plan = actions.create_plan(scan_job, wanted, mode="trash")
    first = actions.execute(plan.id, plan.confirm_token)
    assert first.ok_count >= 1

    with pytest.raises(ActionError) as error:
        actions.execute(plan.id, plan.confirm_token)
    assert "unknown plan" in str(error.value).lower()
    assert actions.get_plan(plan.id) is None


def test_confirmation_can_be_switched_off(
    actions, scan_job: ScanJob, fake_home: FakeHome
) -> None:
    service, _journal = _service_with(
        actions.settings, fake_home, require_confirmation=False
    )
    plan = service.create_plan(scan_job, selectable(scan_job), mode="dry_run")
    report = service.execute(plan.id, None)
    assert report.op_id
    assert report.ok_count >= 0


# --------------------------------------------------------------------------
# execution
# --------------------------------------------------------------------------


def test_dry_run_changes_nothing(actions, scan_job: ScanJob, fake_home: FakeHome) -> None:
    before = {
        path: path.exists()
        for path in (fake_home["thumbnails"], fake_home["pip_cache"], fake_home["documents"])
    }
    plan = actions.create_plan(scan_job, selectable(scan_job), mode="dry_run")
    report = actions.execute(plan.id, plan.confirm_token)

    assert report.mode == "dry_run"
    assert report.ok_count > 0
    assert all(path.exists() == existed for path, existed in before.items())
    assert actions.journal.entries() == [], "a dry run must not write to the journal"


def test_trash_mode_moves_files_and_journals_them(
    actions, scan_job: ScanJob, fake_home: FakeHome
) -> None:
    wanted = ids_for(scan_job.result, "pkg-pip-cache") + ids_for(
        scan_job.result, "app-thumbnails"
    )
    plan = actions.create_plan(scan_job, wanted, mode="trash")
    target = fake_home["pip_cache"]
    assert target.exists()

    report = actions.execute(plan.id, plan.confirm_token)

    assert report.failed_count == 0, report.as_dict()
    assert report.bytes == plan.total_bytes
    assert not target.exists(), "the pip cache should be gone"
    assert fake_home["documents"].exists(), "personal data must be untouched"
    assert fake_home["ssh_key"].exists(), "credentials must be untouched"
    assert fake_home["source_file"].exists(), "source code must be untouched"

    entries = actions.journal.entries()
    assert len(entries) == report.ok_count
    assert all(entry.status == "trashed" for entry in entries)
    assert all(Path(entry.stored_path).exists() for entry in entries)
    assert all(entry.op_id == report.op_id for entry in entries)


def test_undo_restores_a_whole_operation(
    actions, scan_job: ScanJob, fake_home: FakeHome
) -> None:
    wanted = ids_for(scan_job.result, "pkg-pip-cache")
    plan = actions.create_plan(scan_job, wanted, mode="trash")
    report = actions.execute(plan.id, plan.confirm_token)
    assert report.ok_count >= 1
    assert not fake_home["pip_cache"].exists()

    undo = actions.restore_operation(report.op_id)

    assert undo.failed_count == 0, undo.as_dict()
    assert fake_home["pip_cache"].exists(), "one click must bring it all back"
    cache = fake_home["pip_cache"]
    assert any(
        Path(entry.path) == cache or cache in Path(entry.path).parents
        for entry in actions.journal.entries()
    )
    assert actions.journal.active() == [], "a restored item is no longer in quarantine"
    assert all(
        entry.status == "restored"
        for entry in actions.journal.entries()
        if entry.op_id == report.op_id
    )


def test_restore_by_entry_id(actions, scan_job: ScanJob, fake_home: FakeHome) -> None:
    plan = actions.create_plan(scan_job, ids_for(scan_job.result, "app-thumbnails"),
                               mode="trash")
    report = actions.execute(plan.id, plan.confirm_token)
    assert report.ok_count == 1
    entry = actions.journal.entries()[0]
    original = Path(entry.path)
    assert not original.exists()

    undo = actions.restore([entry.id])
    assert undo.ok_count == 1
    assert original.exists()

    again = actions.restore([entry.id])
    assert again.ok_count == 0
    assert again.failed_count == 1


def test_restore_of_an_unknown_operation_is_reported(actions) -> None:
    with pytest.raises(ActionError):
        actions.restore_operation("op-nope")
    report = actions.restore(["entry-nope"])
    assert report.failed_count == 1


def test_execution_revalidates_paths_that_disappeared(
    actions, scan_job: ScanJob, fake_home: FakeHome
) -> None:
    """The world can change between plan and execute; that is a skip, not a crash."""

    wanted = ids_for(scan_job.result, "pkg-pip-cache")
    plan = actions.create_plan(scan_job, wanted, mode="trash")
    import shutil

    shutil.rmtree(fake_home["pip_cache"], ignore_errors=True)

    report = actions.execute(plan.id, plan.confirm_token)
    assert report.ok_count == 0
    assert report.failed_count == len(plan.allowed_items)
    assert all(reason for _path, reason in report.skipped)


def test_permanent_mode_is_refused_by_default(actions, scan_job: ScanJob) -> None:
    with pytest.raises(ActionError) as error:
        actions.create_plan(scan_job, selectable(scan_job), mode="permanent")
    assert "permanent" in str(error.value).lower()
    assert "DISKFREE_ALLOW_PERMANENT_DELETE" in (error.value.hint or "")


def test_permanent_mode_works_when_explicitly_enabled(
    actions, scan_job: ScanJob, fake_home: FakeHome
) -> None:
    """Opt-in at the process level, and only then: the data really is gone."""

    service, _journal = _service_with(
        actions.settings, fake_home, allow_permanent_delete=True
    )
    wanted = ids_for(scan_job.result, "pkg-pip-cache")
    target = fake_home["pip_cache"]

    plan = service.create_plan(scan_job, wanted, mode="permanent")
    assert plan.mode == "permanent"
    assert "PERMANENT" in plan.note
    report = service.execute(plan.id, plan.confirm_token)

    assert report.ok_count >= 1
    assert not target.exists(), "the opt-in really does delete"
    assert report.bytes == plan.total_bytes
    # Nothing was quarantined, so there is nothing to undo.
    with pytest.raises(ActionError):
        service.restore_operation(report.op_id)


def test_read_only_mode_blocks_writes_but_allows_dry_runs(
    settings, jobs, data_dir: Path, fake_home: FakeHome, scanner, scan_job: ScanJob
) -> None:

    service, journal = _service_with(settings, fake_home, allow_writes=False)

    with pytest.raises(ActionError) as error:
        service.create_plan(scan_job, selectable(scan_job), mode="trash")
    assert "read-only" in str(error.value).lower()

    plan = service.create_plan(scan_job, selectable(scan_job), mode="dry_run")
    report = service.execute(plan.id, plan.confirm_token)
    assert report.mode == "dry_run"
    assert fake_home["pip_cache"].exists()
    assert journal.entries() == []


def test_purge_is_gated(actions, scan_job: ScanJob, fake_home: FakeHome) -> None:
    plan = actions.create_plan(scan_job, ids_for(scan_job.result, "app-thumbnails"),
                               mode="trash")
    report = actions.execute(plan.id, plan.confirm_token)
    entry = actions.journal.entries()[0]

    with pytest.raises(ActionError):
        actions.purge([entry.id])
    assert Path(entry.stored_path).exists(), "a refused purge must keep the data"

    service, journal = _service_with(
        actions.settings, fake_home, allow_permanent_delete=True, journal=actions.journal
    )
    done = service.purge([entry.id])
    assert done.ok_count == 1, done.as_dict()
    assert not Path(entry.stored_path).exists()
    assert journal.get(entry.id).status == "purged"
    assert report.op_id


def test_status_reports_the_safety_posture(actions) -> None:
    status = actions.status()
    assert status["require_confirmation"] is True
    assert status["allow_permanent_delete"] is False
    assert status["plan_ttl_seconds"] > 0
    assert status["max_items_per_operation"] == MAX_ITEMS_PER_OPERATION
    assert status["backend"]
    assert status["journal_entries"] >= 0


def test_plan_fingerprint_tracks_the_selection(actions, scan_job: ScanJob) -> None:
    first = actions.create_plan(scan_job, ids_for(scan_job.result, "pkg-pip-cache"),
                                mode="dry_run")
    second = actions.create_plan(
        scan_job,
        ids_for(scan_job.result, "pkg-pip-cache") + ids_for(scan_job.result, "app-thumbnails"),
        mode="dry_run",
    )
    assert first.fingerprint != second.fingerprint

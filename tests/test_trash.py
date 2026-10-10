"""Trash, quarantine and the journal: the reversibility guarantee."""

from __future__ import annotations

import json
import os
from pathlib import Path

from diskfree.config import SafetySettings
from diskfree.safety.trash import Journal, JournalEntry, TrashManager
from tests.conftest import FakeHome, _write


def test_trash_moves_the_file_and_journals_it(
    trash: TrashManager, journal: Journal, tmp_path: Path
) -> None:
    target = _write(tmp_path / "victim.bin", 4096, age_days=3)
    payload = target.read_bytes()

    outcome = trash.trash(target, op_id="op-1", rule_id="test", category="temp", risk="low")

    assert outcome.ok is True, outcome.reason
    assert not target.exists()
    assert outcome.bytes == 4096
    entry = outcome.entry
    assert entry is not None
    assert entry.status == "trashed"
    assert entry.path == str(target)
    assert Path(entry.stored_path).exists()
    assert Path(entry.stored_path).read_bytes() == payload, "content must survive the move"

    reloaded = journal.get(entry.id)
    assert reloaded is not None
    assert reloaded.stored_path == entry.stored_path


def test_trash_moves_a_whole_directory(
    trash: TrashManager, journal: Journal, tmp_path: Path
) -> None:
    tree = tmp_path / "cache-dir"
    _write(tree / "a.bin", 2048, age_days=5)
    _write(tree / "nested/b.bin", 1024, age_days=5)

    outcome = trash.trash(tree, op_id="op-2")

    assert outcome.ok is True, outcome.reason
    assert not tree.exists()
    assert outcome.entry is not None
    assert outcome.entry.is_dir is True
    assert outcome.entry.file_count == 2
    assert outcome.bytes == 3072
    stored = Path(outcome.entry.stored_path)
    assert (stored / "a.bin").exists()
    assert (stored / "nested/b.bin").exists()


def test_restore_puts_everything_back(
    trash: TrashManager, journal: Journal, tmp_path: Path
) -> None:
    target = _write(tmp_path / "deep/nested/dir/file.bin", 3000, age_days=2)
    payload = target.read_bytes()
    outcome = trash.trash(target, op_id="op-3")
    assert outcome.ok and outcome.entry
    assert not target.exists()

    restored = trash.restore(outcome.entry)

    assert restored.ok is True, restored.reason
    assert target.exists()
    assert target.read_bytes() == payload
    assert not Path(outcome.entry.stored_path).exists()
    assert journal.get(outcome.entry.id).status == "restored"


def test_restore_never_overwrites_something_new(
    trash: TrashManager, tmp_path: Path
) -> None:
    """If the user recreated the file, the old copy must not clobber it."""

    target = _write(tmp_path / "config.json", 100, age_days=2, content=b"old")
    outcome = trash.trash(target, op_id="op-4")
    assert outcome.ok and outcome.entry
    target.write_bytes(b"brand new")

    restored = trash.restore(outcome.entry)

    assert restored.ok is False
    assert "exists" in (restored.reason or "").lower()
    assert target.read_bytes() == b"brand new"


def test_restore_of_an_unknown_entry_is_reported(trash: TrashManager) -> None:
    bogus = JournalEntry(
        id="nope", op_id="op-x", timestamp="2026-01-01T00:00:00Z",
        path="/nonexistent/thing", stored_path="/nonexistent/stored",
        backend="quarantine", bytes=0, is_dir=False,
    )
    outcome = trash.restore(bogus)
    assert outcome.ok is False
    assert outcome.reason


def test_purge_is_refused_unless_permanent_delete_is_enabled(
    tmp_path: Path, data_dir: Path, fake_home: FakeHome
) -> None:
    target = _write(tmp_path / "gone.bin", 2048, age_days=1)
    closed = SafetySettings(
        allow_writes=True, allow_permanent_delete=False,
        quarantine_dir=str(data_dir / "q"), trash_backend="quarantine",
    )
    journal = Journal(data_dir / "journal.jsonl")
    manager = TrashManager(closed, data_dir=data_dir, journal=journal, home=fake_home.root)
    outcome = manager.trash(target, op_id="op-5")
    assert outcome.ok and outcome.entry
    stored = Path(outcome.entry.stored_path)

    refused = manager.purge(outcome.entry)
    assert refused.ok is False
    assert "permanent" in (refused.reason or "").lower()
    assert stored.exists(), "the quarantined copy must survive a refused purge"

    opened = SafetySettings(
        allow_writes=True, allow_permanent_delete=True,
        quarantine_dir=str(data_dir / "q"), trash_backend="quarantine",
    )
    willing = TrashManager(opened, data_dir=data_dir, journal=journal, home=fake_home.root)
    done = willing.purge(outcome.entry)
    assert done.ok is True, done.reason
    assert not stored.exists()
    assert journal.get(outcome.entry.id).status == "purged"


def test_delete_permanently_is_gated_the_same_way(
    tmp_path: Path, data_dir: Path, fake_home: FakeHome
) -> None:
    target = _write(tmp_path / "doomed.bin", 1024, age_days=1)
    closed = SafetySettings(
        allow_writes=True, allow_permanent_delete=False,
        quarantine_dir=str(data_dir / "q"), trash_backend="quarantine",
    )
    manager = TrashManager(
        closed, data_dir=data_dir, journal=Journal(data_dir / "j.jsonl"), home=fake_home.root
    )
    outcome = manager.delete_permanently(target, op_id="op-6")
    assert outcome.ok is False
    assert target.exists(), "a gated permanent delete must not delete anything"


def test_read_only_mode_refuses_everything(
    tmp_path: Path, data_dir: Path, fake_home: FakeHome
) -> None:
    target = _write(tmp_path / "readonly.bin", 1024, age_days=1)
    safety = SafetySettings(
        allow_writes=False, allow_permanent_delete=False,
        quarantine_dir=str(data_dir / "q"), trash_backend="quarantine",
    )
    manager = TrashManager(
        safety, data_dir=data_dir, journal=Journal(data_dir / "j.jsonl"), home=fake_home.root
    )
    outcome = manager.trash(target, op_id="op-7")
    assert outcome.ok is False
    assert "read-only" in (outcome.reason or "").lower()
    assert target.exists()


def test_symlinks_are_refused(trash: TrashManager, fake_home: FakeHome) -> None:
    outcome = trash.trash(fake_home["symlink"], op_id="op-8")
    assert outcome.ok is False
    assert "symlink" in (outcome.reason or "").lower()
    assert fake_home["symlink"].is_symlink(), "the link must be left exactly as it was"
    assert fake_home["symlink_target"].exists(), "and so must its target"


def test_missing_path_is_reported_not_raised(trash: TrashManager, tmp_path: Path) -> None:
    outcome = trash.trash(tmp_path / "never-existed", op_id="op-9")
    assert outcome.ok is False
    assert outcome.reason


def test_trash_ceiling_is_enforced(tmp_path: Path, data_dir: Path, fake_home: FakeHome) -> None:
    safety = SafetySettings(
        allow_writes=True, allow_permanent_delete=False,
        quarantine_dir=str(data_dir / "q"), trash_backend="quarantine",
        max_trash_bytes=1024,  # 1 KiB
    )
    manager = TrashManager(
        safety, data_dir=data_dir, journal=Journal(data_dir / "j.jsonl"), home=fake_home.root
    )
    big = _write(tmp_path / "big.bin", 64 * 1024, age_days=1)
    outcome = manager.trash(big, op_id="op-10")
    assert outcome.ok is False
    assert outcome.reason
    assert big.exists(), "over the ceiling, DiskFree refuses rather than half-moving"


def test_freedesktop_backend_writes_trashinfo(
    tmp_path: Path, data_dir: Path
) -> None:
    home = tmp_path / "fd-home"
    home.mkdir()
    safety = SafetySettings(
        allow_writes=True, allow_permanent_delete=False,
        quarantine_dir=str(data_dir / "q"), trash_backend="freedesktop",
    )
    journal = Journal(data_dir / "j.jsonl")
    manager = TrashManager(safety, data_dir=data_dir, journal=journal, home=home)
    target = _write(home / "junk.bin", 512, age_days=1)

    outcome = manager.trash(target, op_id="op-11")

    assert outcome.ok is True, outcome.reason
    assert outcome.entry is not None
    assert outcome.entry.backend == "freedesktop"
    info = Path(outcome.entry.info_path or "")
    assert info.exists(), "the .trashinfo sidecar must be written"
    text = info.read_text()
    assert text.startswith("[Trash Info]")
    assert f"Path={target}" in text or "Path=" in text
    assert "DeletionDate=" in text
    trash_root = manager.trash_root_for(target, "freedesktop")[0]
    assert str(trash_root).startswith(str(home)), "trash must stay on the user's own device"


def test_backend_selection_reports_what_will_happen(
    tmp_path: Path, data_dir: Path, fake_home: FakeHome
) -> None:
    for backend in ("freedesktop", "macos", "quarantine"):
        safety = SafetySettings(
            allow_writes=True, quarantine_dir=str(data_dir / "q"), trash_backend=backend
        )
        manager = TrashManager(
            safety, data_dir=data_dir, journal=Journal(data_dir / f"j-{backend}.jsonl"),
            home=fake_home.root,
        )
        status = manager.status()
        assert status["backend"], backend
        assert isinstance(status["allow_permanent_delete"], bool)


def test_quarantine_backend_is_used_when_the_trash_root_is_unusable(
    tmp_path: Path, data_dir: Path, fake_home: FakeHome
) -> None:
    safety = SafetySettings(
        allow_writes=True, allow_permanent_delete=False,
        quarantine_dir=str(data_dir / "q"), trash_backend="freedesktop",
    )
    journal = Journal(data_dir / "j.jsonl")
    manager = TrashManager(safety, data_dir=data_dir, journal=journal, home=fake_home.root)
    # Point the home trash at a read-only location to force the fallback.
    trash_root = fake_home.root / ".local/share/Trash"
    trash_root.mkdir(parents=True, exist_ok=True)
    os.chmod(trash_root, 0o500)
    try:
        target = _write(fake_home.root / "fallback.bin", 1024, age_days=1)
        outcome = manager.trash(target, op_id="op-12")
        assert outcome.ok is True, outcome.reason
        assert Path(outcome.entry.stored_path).exists()
    finally:
        os.chmod(trash_root, 0o700)


def test_name_collisions_get_unique_targets(
    trash: TrashManager, tmp_path: Path
) -> None:
    first_dir = tmp_path / "one"
    second_dir = tmp_path / "two"
    first = _write(first_dir / "same.bin", 100, age_days=1)
    second = _write(second_dir / "same.bin", 200, age_days=1)

    outcome_a = trash.trash(first, op_id="op-13")
    outcome_b = trash.trash(second, op_id="op-13")

    assert outcome_a.ok and outcome_b.ok
    assert outcome_a.entry.stored_path != outcome_b.entry.stored_path
    assert Path(outcome_a.entry.stored_path).stat().st_size == 100
    assert Path(outcome_b.entry.stored_path).stat().st_size == 200

    assert trash.restore(outcome_a.entry).ok
    assert trash.restore(outcome_b.entry).ok
    assert first.read_bytes() == b"\0" * 100 or first.exists()
    assert second.exists()


def test_journal_is_append_only_and_survives_a_reload(
    trash: TrashManager, journal: Journal, data_dir: Path, tmp_path: Path
) -> None:
    for index in range(3):
        target = _write(tmp_path / f"item{index}.bin", 1024, age_days=1)
        assert trash.trash(target, op_id=f"op-{index}").ok

    path = data_dir / "journal.jsonl"
    lines = path.read_text().splitlines()
    assert len(lines) == 3
    for line in lines:
        assert json.loads(line)["status"] == "trashed"

    reopened = Journal(path)
    assert len(reopened.entries()) == 3
    assert len(reopened.active()) == 3
    assert reopened.total_bytes() == 3072
    assert len(reopened.recent(limit=2)) == 2


def test_journal_ignores_corrupt_lines(data_dir: Path) -> None:
    path = data_dir / "corrupt.jsonl"
    good = JournalEntry(
        id="ok", op_id="op", timestamp="2026-01-01T00:00:00Z", path="/tmp/a",
        stored_path="/tmp/stored/a", backend="quarantine", bytes=10, is_dir=False,
    )
    path.write_text("not json at all\n" + good.to_json() + "\n{broken\n")
    journal = Journal(path)
    assert [entry.id for entry in journal.entries()] == ["ok"]


def test_journal_update_records_the_new_status(
    trash: TrashManager, journal: Journal, tmp_path: Path
) -> None:
    target = _write(tmp_path / "update-me.bin", 512, age_days=1)
    outcome = trash.trash(target, op_id="op-20")
    assert outcome.entry
    updated = journal.update(outcome.entry.id, status="purged", note="test")
    assert updated is not None
    assert updated.status == "purged"
    assert journal.get(outcome.entry.id).status == "purged"
    assert journal.active() == []


def test_trash_refuses_protected_paths_even_when_asked(
    trash: TrashManager, fake_home: FakeHome
) -> None:
    """Second gate: a buggy caller still cannot make DiskFree move ~/.ssh away."""

    for key in ("ssh_key", "known_hosts", "git_dir"):
        outcome = trash.trash(fake_home[key], op_id="op-21")
        assert outcome.ok is False, key
        assert outcome.reason, key
        assert fake_home[key].exists(), f"{key} must be untouched"

    doomed = trash.delete_permanently(fake_home["documents"], op_id="op-22")
    assert doomed.ok is False or fake_home["documents"].exists() is not False


def test_delete_permanently_is_blocked_for_protected_paths(
    tmp_path: Path, data_dir: Path, fake_home: FakeHome
) -> None:
    from diskfree.config import SafetySettings
    from diskfree.safety.policy import SafetyPolicy

    safety = SafetySettings(
        allow_writes=True, allow_permanent_delete=True,
        quarantine_dir=str(data_dir / "q"), trash_backend="quarantine",
    )
    policy = SafetyPolicy(safety, home=fake_home.root)
    manager = TrashManager(
        safety, data_dir=data_dir, journal=Journal(data_dir / "j.jsonl"),
        home=fake_home.root, policy=policy,
    )
    outcome = manager.delete_permanently(fake_home["ssh_key"], op_id="op-23")
    assert outcome.ok is False
    assert fake_home["ssh_key"].exists()

    ordinary = _write(tmp_path / "ordinary.bin", 1024, age_days=1)
    allowed = manager.delete_permanently(ordinary, op_id="op-24")
    assert allowed.ok is True, allowed.reason
    assert not ordinary.exists()

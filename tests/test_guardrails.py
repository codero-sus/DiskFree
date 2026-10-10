"""Guardrails: what DiskFree does with a model's opinion before it becomes a plan.

The model is treated as an untrusted advisor. It may raise risk, never lower it;
it may not invent findings; and anything that looks like a destructive shell
command is removed from the text the user is shown.
"""

from __future__ import annotations

import pytest

from diskfree.ai.guardrails import (
    MAX_ITEMS,
    MAX_MANUAL_STEPS,
    MAX_REASON_CHARS,
    ensure_manual_steps,
    is_dangerous_command,
    sanitize_text,
    scrub_dangerous,
    validate_advice,
)
from diskfree.ai.models import Action, AdviceItem
from diskfree.safety.policy import Risk
from diskfree.scanner.models import ScanResult


def findings_of(result: ScanResult) -> dict[str, object]:
    return {finding.id: finding for finding in result.findings}


def rec(finding_id: str, **overrides) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": finding_id,
        "action": "clean",
        "risk": "safe",
        "confidence": 0.8,
        "reason": "regenerable cache",
    }
    payload.update(overrides)
    return payload


def payload_of(*recommendations, **extra) -> dict[str, object]:
    body: dict[str, object] = {
        "headline": "Clear the caches.",
        "summary": "Most of it is regenerable.",
        "recommendations": list(recommendations),
    }
    body.update(extra)
    return body


# --------------------------------------------------------------------------
# text hygiene
# --------------------------------------------------------------------------


def test_sanitize_strips_control_characters_and_caps_length() -> None:
    dirty = "ok\x00\x1b[31mtext\x07" + "x" * 5000
    clean = sanitize_text(dirty)
    assert "\x00" not in clean and "\x1b" not in clean and "\x07" not in clean
    assert len(clean) <= MAX_REASON_CHARS
    assert clean.startswith("ok")


def test_sanitize_normalises_unicode_and_non_strings() -> None:
    assert sanitize_text(None) == ""
    assert sanitize_text(123) == "123"
    assert sanitize_text(["a", "b"]) != ""
    # Full-width tricks that could hide a command from a naive filter.
    assert sanitize_text("\uff52\uff4d") == "rm"


def test_sanitize_never_returns_a_newline_free_form_of_a_secret() -> None:
    assert sanitize_text("  spaced  ") == "spaced"


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "sudo rm -rf --no-preserve-root /home",
        "rm -fr ~",
        "mkfs.ext4 /dev/sda1",
        "dd if=/dev/zero of=/dev/sda",
        "shred -u ~/.ssh/id_rsa",
        "diskpart",
        "format c:",
        ":(){ :|:& };:",
        "shutdown -h now",
        "chmod -R 000 /",
        "find / -delete",
        "> /dev/sda",
    ],
)
def test_dangerous_commands_are_detected(command: str) -> None:
    assert is_dangerous_command(command) is True, command


@pytest.mark.parametrize(
    "command",
    [
        "docker system prune -a --volumes",
        "journalctl --vacuum-time=2weeks",
        "npm cache clean --force",
        "pip cache purge",
        "apt-get autoremove --purge",
        "flatpak uninstall --unused",
        "nix-collect-garbage -d",
        "tmutil deletelocalsnapshots /",
        "cleanmgr /sageset:1",
    ],
)
def test_the_commands_diskfree_itself_recommends_are_not_flagged(command: str) -> None:
    assert is_dangerous_command(command) is False, command


@pytest.mark.parametrize(
    "text,fragment",
    [
        ("Run rm -rf / now", "--no-preserve-root"),
        ("sudo rm -rf --no-preserve-root / then exit", "rm -rf"),
        ("Try mkfs.ext4 /dev/sda1 first", "mkfs"),
        ("dd if=/dev/zero of=/dev/sda", "of=/dev/sda"),
        ("chmod -R 000 / to be sure", "chmod"),
        ("find / -delete when done", "-delete"),
        ("shred -u ~/.ssh/id_rsa", "shred"),
        ("shutdown -h now", "shutdown"),
    ],
)
def test_redaction_removes_the_whole_command(text: str, fragment: str) -> None:
    """A partial match would leave a copy-pasteable fragment on screen."""

    events: list = []
    cleaned = scrub_dangerous(text, events, where="a test")
    assert fragment not in cleaned.lower()
    assert "[command removed by DiskFree]" in cleaned
    assert events and events[0].kind == "dangerous_command"
    assert not is_dangerous_command(cleaned), cleaned


@pytest.mark.parametrize(
    "prose",
    [
        "The shutdown hook runs last",
        "A graceful shutdown frees the cache",
        "They parted ways after the meeting",
        "Format the output as JSON",
        "find . -name \"*.log\" -mtime +30",
        "chmod 644 notes.txt",
        "delicious food",
        "The machine will reboot itself overnight",
    ],
)
def test_ordinary_prose_is_left_alone(prose: str) -> None:
    assert is_dangerous_command(prose) is False
    events: list = []
    assert scrub_dangerous(prose, events, where="a test") == prose
    assert events == []


# --------------------------------------------------------------------------
# validating a model payload
# --------------------------------------------------------------------------


def test_unknown_and_duplicate_ids_are_dropped(scan_result: ScanResult) -> None:
    findings = findings_of(scan_result)
    real = next(iter(findings))
    cleaned, events = validate_advice(
        payload_of(rec(real), rec("invented-id"), rec(real), rec("")), findings
    )
    ids = [item.finding_id for item in cleaned["items"]]
    assert ids == [real]
    kinds = {event.kind for event in events}
    assert "unknown_id" in kinds or "malformed" in kinds


def test_a_model_can_raise_risk_but_never_lower_it(scan_result: ScanResult) -> None:
    findings = findings_of(scan_result)
    risky = next(
        finding for finding in scan_result.findings
        if finding.risk is Risk.HIGH and finding.actionable
    )
    cleaned, events = validate_advice(
        payload_of(rec(risky.id, risk="safe", action="clean")), findings
    )
    item: AdviceItem = cleaned["items"][0]
    assert item.risk is Risk.HIGH, "the floor set by the rule engine must hold"
    assert item.original_risk is Risk.HIGH
    assert item.escalated is False, "the model asked for less caution, not more"
    assert any(event.kind == "risk_refused" for event in events), [e.kind for e in events]

    # And the other direction: a model may raise a SAFE item's risk.
    safe = next(
        finding for finding in scan_result.findings
        if finding.risk is Risk.SAFE and finding.actionable
    )
    raised, raised_events = validate_advice(
        payload_of(rec(safe.id, risk="high", action="review")), findings
    )
    assert raised["items"][0].risk is Risk.HIGH
    assert raised["items"][0].escalated is True
    assert any(event.kind == "risk_clamped" for event in raised_events)


def test_cleaning_a_high_risk_item_is_downgraded_to_review(scan_result: ScanResult) -> None:
    findings = findings_of(scan_result)
    risky = next(
        finding for finding in scan_result.findings
        if finding.risk is Risk.HIGH and finding.actionable
    )
    cleaned, events = validate_advice(
        payload_of(rec(risky.id, action="clean", risk="high")), findings
    )
    item = cleaned["items"][0]
    assert item.action is Action.REVIEW
    assert item.action_downgraded is True
    assert any(event.kind == "high_risk_needs_review" for event in events)


def test_non_actionable_findings_can_only_be_kept_or_reviewed(scan_result: ScanResult) -> None:
    findings = findings_of(scan_result)
    informational = next(
        finding for finding in scan_result.findings if not finding.actionable
    )
    cleaned, _events = validate_advice(
        payload_of(rec(informational.id, action="clean", risk="safe")), findings
    )
    item = cleaned["items"][0]
    assert item.action in {Action.KEEP, Action.REVIEW}
    assert item.action is not Action.CLEAN


def test_bad_actions_and_confidences_are_coerced(scan_result: ScanResult) -> None:
    findings = findings_of(scan_result)
    real = next(iter(findings))
    cleaned, events = validate_advice(
        payload_of(
            rec(real, action="delete-everything", confidence=42),
        ),
        findings,
    )
    item = cleaned["items"][0]
    assert item.action is Action.REVIEW, "an unknown verb becomes the cautious one"
    assert 0.0 <= item.confidence <= 1.0
    assert events


def test_confidence_out_of_range_is_clamped(scan_result: ScanResult) -> None:
    findings = findings_of(scan_result)
    real = next(iter(findings))
    high, _ = validate_advice(payload_of(rec(real, confidence=99)), findings)
    low, _ = validate_advice(payload_of(rec(real, confidence=-3)), findings)
    nonsense, _ = validate_advice(payload_of(rec(real, confidence="very")), findings)
    assert high["items"][0].confidence == 1.0
    assert low["items"][0].confidence == 0.0
    assert 0.0 <= nonsense["items"][0].confidence <= 1.0


def test_reasons_are_sanitised_and_truncated(scan_result: ScanResult) -> None:
    findings = findings_of(scan_result)
    real = next(iter(findings))
    cleaned, _ = validate_advice(
        payload_of(rec(real, reason="x" * 5000 + "\x00evil")), findings
    )
    reason = cleaned["items"][0].reason
    assert len(reason) <= MAX_REASON_CHARS
    assert "\x00" not in reason


def test_dangerous_commands_in_model_text_are_removed(scan_result: ScanResult) -> None:
    findings = findings_of(scan_result)
    real = next(iter(findings))
    cleaned, events = validate_advice(
        payload_of(
            rec(real, reason="Fine to delete. Then run: rm -rf / to be sure."),
            quick_wins=["sudo rm -rf --no-preserve-root /"],
            manual_steps=["rm -rf ~"],
            warnings=["just run mkfs.ext4 /dev/sda"],
        ),
        findings,
    )
    blob = " ".join(
        [cleaned["items"][0].reason, *cleaned["quick_wins"], *cleaned["manual_steps"],
         *cleaned["warnings"]]
    ).lower()
    assert "rm -rf /" not in blob
    assert "rm -rf --no-preserve-root" not in blob
    assert "rm -rf ~" not in blob
    assert "mkfs" not in blob
    # The prose survives, with the command taken out of it.
    assert "fine to delete" in cleaned["items"][0].reason.lower()
    assert cleaned["manual_steps"] == [], "a step that is only a destructive command goes"
    assert sum(1 for event in events if event.kind == "dangerous_command") >= 3


def test_a_malformed_payload_yields_no_items(scan_result: ScanResult) -> None:
    findings = findings_of(scan_result)
    for bad in (None, "not json", 42, [], {"recommendations": "nope"}):
        cleaned, events = validate_advice(bad, findings)
        assert cleaned["items"] == [], bad
        assert events, f"every rejection must be explainable: {bad}"


def test_item_count_is_capped(scan_result: ScanResult) -> None:
    findings = findings_of(scan_result)
    ids = list(findings)
    spam = [rec(ids[index % len(ids)]) for index in range(MAX_ITEMS + 50)]
    cleaned, events = validate_advice(payload_of(*spam), findings)
    assert len(cleaned["items"]) <= min(MAX_ITEMS, len(ids))
    assert any(event.kind == "truncated" for event in events) or len(ids) < MAX_ITEMS


def test_headline_and_summary_survive_validation(scan_result: ScanResult) -> None:
    findings = findings_of(scan_result)
    cleaned, _ = validate_advice(payload_of(headline="  Reclaim 4 GB  "), findings)
    assert cleaned["headline"].strip()
    assert cleaned["summary"].strip()


# --------------------------------------------------------------------------
# advisory completeness
# --------------------------------------------------------------------------


def test_every_advisory_is_reported_even_if_the_model_forgets_it(
    scan_result: ScanResult,
) -> None:
    findings = findings_of(scan_result)
    advisories = [finding for finding in scan_result.findings if finding.advisory]
    if not advisories:
        pytest.skip("this host exposes no advisory findings")

    steps = ensure_manual_steps([], findings, [])
    joined = "\n".join(steps).lower()
    for finding in advisories:
        assert finding.advisory.lower() in joined, finding.rule_id


def test_manual_steps_are_deduplicated_and_capped(scan_result: ScanResult) -> None:
    findings = findings_of(scan_result)
    advisory = next(
        (finding for finding in scan_result.findings if finding.advisory), None
    )
    if advisory is None:
        pytest.skip("no advisory findings on this host")
    existing = [f"{advisory.advisory}   # already there"]
    steps = ensure_manual_steps([], findings, existing * 3)
    assert steps.count(existing[0]) == 1
    assert len(steps) <= MAX_MANUAL_STEPS
    assert advisory.advisory.lower() in "\n".join(steps).lower()


def test_the_model_cannot_erase_a_manual_step(scan_result: ScanResult) -> None:
    findings = findings_of(scan_result)
    advisories = [finding for finding in scan_result.findings if finding.advisory]
    if not advisories:
        pytest.skip("no advisory findings on this host")
    cleaned, _ = validate_advice(payload_of(manual_steps=[]), findings)
    steps = ensure_manual_steps(cleaned["items"], findings, cleaned["manual_steps"])
    joined = "\n".join(steps).lower()
    for finding in advisories:
        assert finding.advisory.lower() in joined

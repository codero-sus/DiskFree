"""The offline advisor.

DiskFree must be useful with no model installed, so every heuristic that the AI
layer applies has a deterministic equivalent here. It produces exactly the same
:data:`~diskfree.ai.models.Advice` shape, which means:

* the UI has one code path whether or not an LLM answered;
* the guardrails are identical (they are applied to this output too);
* advice is reproducible and explainable, rule by rule.

The heuristics are deliberately more conservative than a model is allowed to be:
only ``safe`` and clearly regenerable ``low`` risk findings are recommended for
cleaning, everything else is flagged for review.
"""

from __future__ import annotations

from collections import defaultdict

from ..safety.policy import Risk
from ..scanner.models import Finding, ScanResult
from ..scanner.rules import CATEGORY_META, Category
from ..util import human_bytes, human_duration
from .models import ENGINE_HEURISTIC, Action, Advice, AdviceItem

#: Categories whose low-risk findings are genuinely regenerable.
REGENERABLE = frozenset(
    {
        Category.PACKAGE_CACHE,
        Category.BROWSER_CACHE,
        Category.APP_CACHE,
        Category.TEMP,
        Category.BUILD_ARTIFACTS,
    }
)

_CONFIDENCE = {
    Risk.SAFE: 0.92,
    Risk.LOW: 0.78,
    Risk.MEDIUM: 0.55,
    Risk.HIGH: 0.4,
    Risk.FORBIDDEN: 0.99,
}


def _reason(finding: Finding) -> str:
    size = human_bytes(finding.bytes)
    age = finding.age_days_now
    age_text = f" last modified {int(age)} days ago," if age >= 1 else ""

    if finding.category is Category.PACKAGE_CACHE:
        return f"{size} of package-manager cache;{age_text} re-downloaded on the next install."
    if finding.category is Category.BROWSER_CACHE:
        return f"{size} of cached web content; browsers rebuild it and your logins are untouched."
    if finding.category is Category.APP_CACHE:
        return f"{size} of application cache;{age_text} regenerated automatically."
    if finding.category is Category.TEMP:
        return f"{size} of temporary files not touched in {max(1, int(age))} days."
    if finding.category is Category.LOGS:
        return f"{size} of log data{age_text} useful only for debugging past problems."
    if finding.category is Category.TRASH:
        return f"{size} already deleted by you but still occupying disk until the trash is emptied."
    if finding.category is Category.BUILD_ARTIFACTS:
        return f"{size} of build output; regenerable, but the next build will be slower."
    if finding.category is Category.VIRTUAL_ENV:
        return f"{size} virtual environment; recreating it needs the dependency list and network."
    if finding.category is Category.DUPLICATES:
        keeper = str(finding.extra.get("duplicate_of") or "another copy")
        return f"{size} byte-identical to {keeper}; that copy is kept."
    if finding.category is Category.OLD_FILES:
        return f"{size} of personal files untouched for {max(1, int(age))} days; review each one."
    if finding.category is Category.LARGE_FILES:
        return f"{size} -- one of the largest files found. Information only."
    if finding.advisory:
        return f"{size} managed by another program: {finding.advisory}"
    return f"{size}{age_text} {finding.description}"


def heuristic_advice(result: ScanResult, *, job_id: str = "") -> Advice:
    """Deterministic advice built straight from the scan result."""

    items: list[AdviceItem] = []
    by_category: dict[str, int] = defaultdict(int)
    quick_wins: list[str] = []
    manual_steps: list[str] = []
    warnings: list[str] = list(result.warnings)

    ranked = sorted(result.findings, key=lambda finding: finding.bytes, reverse=True)
    for finding in ranked[:200]:
        by_category[finding.category.value] += finding.bytes

        if not finding.actionable:
            action = Action.MANUAL if finding.advisory else Action.KEEP
            if finding.advisory and finding.advisory not in manual_steps:
                manual_steps.append(
                    f"{finding.advisory}   # {finding.title} ({human_bytes(finding.bytes)})"
                )
        elif finding.risk is Risk.SAFE:
            action = Action.CLEAN
        elif finding.risk is Risk.LOW:
            action = Action.CLEAN if finding.category in REGENERABLE else Action.REVIEW
        elif finding.risk is Risk.MEDIUM:
            action = Action.REVIEW
        else:
            action = Action.REVIEW

        items.append(
            AdviceItem(
                finding_id=finding.id,
                action=action,
                risk=finding.risk,
                confidence=_CONFIDENCE[finding.risk],
                reason=_reason(finding),
                title=finding.title,
                path=finding.path,
                bytes=finding.bytes,
                category=finding.category.value,
                rule_id=finding.rule_id,
                original_risk=finding.risk,
                command=finding.advisory,
            )
        )

    clean_bytes = sum(item.bytes for item in items if item.action is Action.CLEAN)
    safe_bytes = sum(
        item.bytes for item in items if item.action is Action.CLEAN and item.risk is Risk.SAFE
    )
    review_bytes = sum(item.bytes for item in items if item.action is Action.REVIEW)

    for item in sorted(
        (i for i in items if i.action is Action.CLEAN), key=lambda candidate: -candidate.bytes
    )[:3]:
        quick_wins.append(
            f"Clear {item.title.lower()} to reclaim {human_bytes(item.bytes)} "
            f"({item.category.replace('_', ' ')})."
        )
    if not quick_wins and review_bytes:
        quick_wins.append(
            f"Review the {human_bytes(review_bytes)} of medium and high risk items; "
            "nothing there is pre-selected."
        )

    biggest_category = max(by_category.items(), key=lambda kv: kv[1], default=(None, 0))
    label = (
        CATEGORY_META[Category(biggest_category[0])].label.lower()
        if biggest_category[0]
        else "cleanable data"
    )
    if safe_bytes and clean_bytes > safe_bytes:
        headline = (
            f"{human_bytes(safe_bytes)} is pure cache and temp data, plus "
            f"{human_bytes(clean_bytes - safe_bytes)} of low risk items. "
            f"The largest bucket is {label}."
        )
    elif safe_bytes:
        headline = (
            f"{human_bytes(safe_bytes)} is pure cache and temp data; "
            f"the largest bucket is {label}."
        )
    elif clean_bytes:
        headline = (
            f"{human_bytes(clean_bytes)} is regenerable and safe to clear with a reversible "
            f"move to the trash; the largest bucket is {label}."
        )
    elif review_bytes:
        headline = f"No pure-cache wins; {human_bytes(review_bytes)} needs your review."
    else:
        headline = "Nothing worth removing was found."

    total_free = sum(mount.free for mount in result.mounts if mount.scanned and not mount.pseudo)
    summary_parts = [
        f"The scan covered {result.stats.files_seen:,} files "
        f"({human_bytes(result.stats.bytes_seen)}) in {human_duration(result.stats.duration)}.",
        f"{human_bytes(result.stats.actionable_bytes)} is potentially reclaimable, of which "
        f"{human_bytes(clean_bytes)} is regenerable cache or temp data that DiskFree can move to "
        "the trash and restore later.",
    ]
    if result.stats.duplicate_bytes:
        summary_parts.append(
            f"{human_bytes(result.stats.duplicate_bytes)} is held by byte-identical duplicate "
            "files; one copy of each group is always kept."
        )
    if review_bytes:
        summary_parts.append(
            f"{human_bytes(review_bytes)} sits in medium and high risk items such as logs, trash, "
            "build output, duplicates and old downloads. None of it is pre-selected."
        )
    if total_free:
        summary_parts.append(
            f"Cleaning the safe items would raise free space on the scanned volumes from "
            f"{human_bytes(total_free)} to about {human_bytes(total_free + clean_bytes)}."
        )
    summary_parts.append(
        "Removals go to the system trash or DiskFree's quarantine and are journalled, so any of "
        "them can be undone from History."
    )

    if not items:
        headline = "Nothing worth removing was found."
        summary_parts = [
            "The scan found no regenerable caches, temp files, logs or duplicates above the "
            "configured thresholds. Your disk is already tidy, or the scanned roots are small."
        ]

    if not warnings:
        warnings.append(
            "Advice is generated offline by DiskFree's rule engine; connect Cortex LLMHoster or "
            "Ollama for a natural-language second opinion."
        )

    return Advice(
        job_id=job_id or result.job_id,
        engine=ENGINE_HEURISTIC,
        model=None,
        headline=headline,
        summary=" ".join(summary_parts),
        items=items,
        quick_wins=quick_wins,
        manual_steps=manual_steps,
        warnings=warnings,
    )

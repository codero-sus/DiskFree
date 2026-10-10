"""Transparency and status endpoints: what DiskFree knows, and what it protects."""

from __future__ import annotations

import platform
import sys
from dataclasses import asdict
from pathlib import Path

from fastapi import APIRouter, Depends, Query

from .. import __version__
from ..actions.executor import MAX_ITEMS_PER_OPERATION
from ..ai.providers import ProviderStatus
from ..safety.policy import SENSITIVE_DIR_NAMES, Risk, Tier
from ..scanner.disks import disk_summary, enumerate_mounts
from ..scanner.rules import (
    CATEGORY_META,
    DEFAULT_RULES,
    RuleSet,
    expand_templates,
)
from ..util import human_bytes, human_duration
from .deps import AppState, get_state

router = APIRouter(prefix="/api", tags=["meta"])


@router.get("/status")
async def status(state: AppState = Depends(get_state)) -> dict[str, object]:
    """Everything the UI header needs in one call."""

    settings = state.settings
    jobs = state.jobs
    latest = jobs.latest()
    infos = await state.registry.all_info(max_age=5.0)
    home = Path.home()
    disk = disk_summary(str(home))

    return {
        "version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "uptime_seconds": round(state.uptime(), 1),
        "uptime_human": human_duration(state.uptime()),
        "home": str(home),
        "data_dir": str(settings.data_dir),
        "disk": disk,
        "disk_human": {
            "total": human_bytes(disk.get("total", 0)),
            "used": human_bytes(disk.get("used", 0)),
            "free": human_bytes(disk.get("free", 0)),
        },
        "preferred_provider": settings.provider,
        "providers": [info.as_dict() for info in infos],
        "online_providers": [
            info.name
            for info in infos
            if info.status in {ProviderStatus.ONLINE, ProviderStatus.DEGRADED}
        ],
        "scans": {
            "total": len(jobs.list(limit=100)),
            "running": sum(1 for job in jobs.list(limit=100) if job.status.value == "running"),
            "latest_id": latest.id if latest else None,
            "latest_status": latest.status.value if latest else None,
            "latest_findings": len(latest.result.findings) if latest and latest.result else 0,
            "latest_reclaimable": (
                human_bytes(latest.result.stats.actionable_bytes)
                if latest and latest.result
                else human_bytes(0)
            ),
        },
        "safety": state.actions.status(),
        "read_only": not settings.safety.allow_writes,
        "ui_token_required": bool(settings.ui_token),
    }


@router.get("/disks")
async def disks(state: AppState = Depends(get_state)) -> dict[str, object]:
    """Mounted filesystems with usage."""

    mounts = enumerate_mounts([Path.home()])
    return {
        "disks": [mount.as_dict() for mount in mounts],
        "home": str(Path.home()),
        "summary": disk_summary(str(Path.home())),
        "note": "Pseudo filesystems (proc, sysfs, tmpfs) are flagged and excluded from totals.",
    }


@router.get("/rules")
async def rules(
    state: AppState = Depends(get_state),
    category: str | None = Query(default=None),
) -> dict[str, object]:
    """The full cleaning knowledge base, expanded for this machine.

    Publishing the rules is deliberate: a cleaner that hides what it considers
    "junk" cannot be audited.
    """

    ruleset = RuleSet(home=Path.home())
    templates = expand_templates(Path.home())
    out = []
    for rule in DEFAULT_RULES:
        if category and rule.category.value != category:
            continue
        compiled = ruleset.compiled_for(rule.id)
        matcher = rule.matcher
        out.append(
            {
                "id": rule.id,
                "category": rule.category.value,
                "category_label": CATEGORY_META[rule.category].label,
                "title": rule.title,
                "description": rule.description,
                "risk": rule.risk.value,
                "default_selected": rule.default_selected,
                "auto_selectable": rule.default_selected and rule.risk is Risk.SAFE,
                "prune": rule.prune,
                "aggregate": rule.aggregate.value,
                "advisory": rule.advisory,
                "actionable": rule.actionable,
                "probe": rule.probe,
                "computed": rule.computed,
                "priority": rule.priority,
                "cache_specific": rule.cache_specific,
                "platforms": list(rule.platforms) or ["any"],
                "applies_here": compiled is not None,
                "matcher": {
                    "paths": sorted(compiled.abs_paths) if compiled else list(matcher.abs_paths),
                    "under": list(compiled.only_under) if compiled else list(matcher.only_under),
                    "names": sorted(matcher.names),
                    "globs": list(matcher.globs),
                    "parent_is": list(compiled.parent_is_folded) if compiled else [],
                    "parents_contain": sorted(matcher.parents_contain),
                    "require_sibling": sorted(matcher.require_sibling),
                    "require_dir": matcher.require_dir,
                    "min_age_days": matcher.min_age_days,
                    "require_own_file": matcher.require_own_file,
                },
            }
        )
    return {
        "count": len(out),
        "rules": out,
        "templates": {key: value for key, value in templates.items() if value},
        "categories": [
            {
                "category": key.value,
                "label": meta.label,
                "icon": meta.icon,
                "blurb": meta.blurb,
                "order": meta.order,
            }
            for key, meta in sorted(CATEGORY_META.items(), key=lambda kv: kv[1].order)
        ],
        "risk_ladder": [
            {
                "risk": risk.value,
                "auto_selectable": risk.auto_selectable,
                "meaning": meaning,
            }
            for risk, meaning in (
                (Risk.SAFE, "Regenerable with no data loss. May be pre-selected."),
                (Risk.LOW, "Regenerable but slow or inconvenient to rebuild."),
                (Risk.MEDIUM, "Might matter: logs, trash, duplicates, build output."),
                (Risk.HIGH, "Personal data. Never pre-selected; every item is deliberate."),
                (Risk.FORBIDDEN, "Owned by another program. DiskFree shows a command instead."),
            )
        ],
    }


@router.get("/safety")
async def safety(state: AppState = Depends(get_state)) -> dict[str, object]:
    """What is protected, where removed data goes, and how confirmation works."""

    policy = state.policy
    home = Path.home()
    samples = [
        str(home / ".ssh" / "id_rsa"),
        str(home / ".git" / "config"),
        str(home / "Documents" / "report.pdf"),
        str(home / ".cache" / "pip"),
        str(home / ".config" / "google-chrome" / "Default" / "Cache"),
        "/usr/bin/python3",
        "/etc/passwd",
        "/var/lib/docker",
        "/tmp/installer-tmp",
    ]
    return {
        "policy": {
            "blocked_system_roots": list(policy.blocked_roots),
            "own_protected_paths": list(policy.own_paths),
            "user_protected_paths": list(policy.extra_blocked),
            "sensitive_folder_names": sorted(SENSITIVE_DIR_NAMES),
            "zones": [
                {
                    "root": str(zone.root),
                    "tier": zone.tier.value,
                    "reason": zone.reason,
                    "allowed_prefixes": list(zone.allowed_prefixes),
                }
                for zone in policy.zones
            ],
            "tiers": [tier.value for tier in Tier],
        },
        "guarantees": [
            "Nothing is deleted without an itemised plan you confirm.",
            "Removals go to the system trash or DiskFree's quarantine and are journalled.",
            "Every path is re-validated against the policy at execution time.",
            "Symlinks, mount points, version control metadata and credential stores are refused.",
            "Only 'safe' risk findings can ever be pre-selected.",
            "The AI can raise a risk rating but never lower one, and can never introduce a path "
            "that the scan did not find.",
            "DiskFree never runs shell commands. Maintenance commands are shown for you to run.",
            "Permanent deletion is disabled unless the process was started with "
            "DISKFREE_ALLOW_PERMANENT_DELETE=1.",
        ],
        "examples": [_classify_example(policy, sample) for sample in samples],
        "trash": state.actions.status(),
        "limits": {
            "max_items_per_operation": MAX_ITEMS_PER_OPERATION,
            "plan_ttl_seconds": state.settings.safety.plan_ttl_seconds,
            "max_trash_bytes": state.settings.safety.max_trash_bytes,
            "max_trash_human": human_bytes(state.settings.safety.max_trash_bytes),
        },
    }


@router.get("/config")
async def config(state: AppState = Depends(get_state)) -> dict[str, object]:
    """Effective configuration, with secrets redacted."""

    settings = state.settings
    return {
        "version": __version__,
        "server": {
            "host": settings.host,
            "port": settings.port,
            "data_dir": str(settings.data_dir),
            "config_path": str(settings.config_path) if settings.config_path else None,
            "log_level": settings.log_level,
            "cors_origins": list(settings.cors_origins),
            "ui_token_required": bool(settings.ui_token),
        },
        "ai": {
            "preferred_provider": settings.provider,
            "providers": [provider.redacted() for provider in settings.providers],
        },
        "scan": {
            "max_depth": settings.scan.max_depth,
            "max_findings": settings.scan.max_findings,
            "max_files_per_rule": settings.scan.max_files_per_rule,
            "max_members_per_finding": settings.scan.max_members_per_finding,
            "duplicate_min_bytes": settings.scan.duplicate_min_bytes,
            "duplicate_min_human": human_bytes(settings.scan.duplicate_min_bytes),
            "large_file_min_bytes": settings.scan.large_file_min_bytes,
            "large_file_min_human": human_bytes(settings.scan.large_file_min_bytes),
            "temp_min_age_days": settings.scan.temp_min_age_days,
            "log_min_age_days": settings.scan.log_min_age_days,
            "old_file_min_age_days": settings.scan.old_file_min_age_days,
        },
        "safety": {
            "allow_writes": settings.safety.allow_writes,
            "allow_permanent_delete": settings.safety.allow_permanent_delete,
            "trash_backend": settings.safety.trash_backend,
            "effective_trash_backend": state.actions.trash.backend_name(),
            "quarantine_dir": str(state.actions.trash.quarantine_dir),
            "journal_path": str(settings.journal_path),
            "max_trash_bytes": settings.safety.max_trash_bytes,
            "require_confirmation": settings.safety.require_confirmation,
            "plan_ttl_seconds": settings.safety.plan_ttl_seconds,
            "extra_protected_paths": list(settings.safety.extra_protected_paths),
        },
        "environment": dict(
            sorted(
                (key, "set" if _secret(key) else str(val))
                for key, val in _diskfree_env().items()
            )
        ),
    }


def _classify_example(policy, sample: str) -> dict[str, object]:
    """Render one worked example for the safety panel."""

    info = policy.classify(sample)
    decision = policy.check(sample)
    return {
        "path": sample,
        "tier": info.tier.value,
        "reason": info.reason,
        "zone_escape": info.zone_escape,
        "decision": asdict(decision),
    }


def _diskfree_env() -> dict[str, str]:
    import os

    return {
        key: value
        for key, value in os.environ.items()
        if key.startswith("DISKFREE_") or key in {"CORTEX_API_KEY", "OLLAMA_API_KEY"}
    }


def _secret(key: str) -> bool:
    return "KEY" in key.upper() or "TOKEN" in key.upper() or "SECRET" in key.upper()

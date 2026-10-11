"""The HTTP API: shapes, status codes, security headers and the whole clean flow.

These run against the real FastAPI app through ``TestClient`` -- lifespan,
middleware, routers and all -- pointed at the synthetic home directory, so a
cleanup really moves files and an undo really brings them back.
"""

from __future__ import annotations

import json
from dataclasses import replace as dc_replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from diskfree.api.app import create_app
from diskfree.config import Settings
from tests.conftest import FakeHome

SECURITY_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)
RISKS = {"safe", "low", "medium", "high", "forbidden"}


@pytest.fixture
def app_settings(loaded_settings: Settings) -> Settings:
    """Settings from the real loader (so providers are configured), test safety."""

    return loaded_settings


@pytest.fixture
def client(app_settings: Settings) -> TestClient:
    with TestClient(create_app(app_settings)) as test_client:
        yield test_client


def wait_for_scan(client: TestClient, job_id: str, timeout: float = 120.0) -> dict:
    """Poll a scan until it finishes; the API is deliberately asynchronous."""

    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/api/scans/{job_id}")
        assert response.status_code == 200, response.text
        payload = response.json()
        if payload["status"] in {"completed", "failed", "cancelled"}:
            return payload
        time.sleep(0.05)
    pytest.fail(f"scan {job_id} did not finish within {timeout}s")


def start_scan(client: TestClient, fake_home: FakeHome, **body) -> str:
    """Start a scan of the synthetic home only.

    ``preset="custom"`` keeps the presets from adding ``/tmp``, ``/var/log`` and
    ``/var/cache`` to the roots, and ``temp_min_age_days`` is pushed far enough
    out that the host's own temp files cannot leak into the results (pytest's
    home lives under ``/tmp``).
    """

    payload = {
        "roots": [str(fake_home.root)],
        "preset": "custom",
        "temp_min_age_days": 36500,
        **body,
    }
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 202, response.text
    return response.json()["job"]["id"]


def completed_scan(client: TestClient, fake_home: FakeHome, **body) -> dict:
    return wait_for_scan(client, start_scan(client, fake_home, **body))


def findings_for(client: TestClient, job_id: str, **params) -> list[dict]:
    query = {"limit": 500, "include_members": True, **params}
    response = client.get(f"/api/scans/{job_id}/findings", params=query)
    assert response.status_code == 200, response.text
    return response.json()["findings"]


def by_rule(findings: list[dict], rule_id: str) -> dict:
    matches = [item for item in findings if item["rule_id"] == rule_id]
    assert matches, f"expected a '{rule_id}' finding, got {[i['rule_id'] for i in findings]}"
    return matches[0]


# --------------------------------------------------------------------------
# health, static assets and headers
# --------------------------------------------------------------------------


def test_health(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["version"]


def test_the_webui_is_served(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "DiskFree" in response.text
    assert 'name="author" content="codero-sus"' in response.text
    assert "Made with" in response.text
    assert "https://github.com/codero-sus" in response.text
    assert "https://the-codero.web.app/" in response.text

    for path, expected in (
        ("/app.js", "javascript"),
        ("/styles.css", "text/css"),
        ("/favicon.svg", "image/svg"),
    ):
        asset = client.get(path)
        assert asset.status_code == 200, path
        assert expected in asset.headers["content-type"], path
        assert asset.content, path


def test_the_ui_is_also_mounted(client: TestClient) -> None:
    assert client.get("/ui/index.html").status_code == 200


def test_every_response_carries_security_headers(client: TestClient) -> None:
    for path in ("/api/health", "/api/status", "/", "/app.js", "/api/does-not-exist"):
        response = client.get(path)
        for header in SECURITY_HEADERS:
            assert header in response.headers, f"{path} is missing {header}"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"


def test_the_content_security_policy_forbids_remote_code(client: TestClient) -> None:
    policy = client.get("/api/health").headers["content-security-policy"]
    assert "default-src 'self'" in policy
    assert "script-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "unsafe-eval" not in policy
    # No CDN, no third-party origin: the UI is bundled.
    assert "http://" not in policy and "https://" not in policy


def test_openapi_documents_the_api(client: TestClient) -> None:
    response = client.get("/api/openapi.json")
    assert response.status_code == 200
    spec = response.json()
    assert spec["info"]["title"] == "DiskFree"
    for expected in (
        "/api/status", "/api/disks", "/api/rules", "/api/safety", "/api/config",
        "/api/presets", "/api/scan", "/api/scans", "/api/scans/{job_id}",
        "/api/scans/{job_id}/findings", "/api/scans/{job_id}/advice",
        "/api/scans/{job_id}/cancel", "/api/advise", "/api/chat", "/api/providers",
        "/api/providers/{name}/check", "/api/clean/plan", "/api/clean/execute",
        "/api/actions/status", "/api/history", "/api/history/restore",
        "/api/history/purge",
    ):
        assert expected in spec["paths"], f"{expected} is not documented"
    assert client.get("/api/docs").status_code == 200


def test_invalid_bodies_are_rejected_with_a_readable_422(client: TestClient) -> None:
    response = client.post("/api/scan", json={"max_depth": 9999})
    assert response.status_code == 422
    payload = response.json()
    assert payload["error"]
    assert payload["detail"]

    assert client.post("/api/clean/plan", json={"mode": "shred"}).status_code == 422
    assert client.post("/api/chat", json={"message": ""}).status_code == 422


# --------------------------------------------------------------------------
# metadata endpoints
# --------------------------------------------------------------------------


def test_status_describes_the_safety_posture(client: TestClient, fake_home: FakeHome) -> None:
    payload = client.get("/api/status").json()
    assert payload["version"]
    assert payload["home"] == str(fake_home.root)
    assert payload["read_only"] is False
    assert payload["ui_token_required"] is False
    assert payload["safety"]["allow_writes"] is True
    assert payload["safety"]["allow_permanent_delete"] is False
    assert payload["safety"]["require_confirmation"] is True
    assert payload["safety"]["backend"] == "quarantine"
    assert payload["disk"]["total"] > 0
    assert payload["disk_human"]["free"]
    assert payload["scans"]["total"] == 0
    assert [item["name"] for item in payload["providers"]] == ["cortex", "ollama"]


def test_config_never_leaks_a_secret(client: TestClient) -> None:
    response = client.get("/api/config")
    assert response.status_code == 200
    assert "super-secret-token" not in response.text
    payload = response.json()
    for provider in payload["ai"]["providers"]:
        assert "api_key" not in provider
        assert set(provider) >= {"name", "base_url", "api_key_set", "enabled"}
    assert payload["ai"]["providers"][0]["api_key_set"] is True
    # Environment variables that could carry a secret are reported as "set".
    assert payload["environment"]["DISKFREE_CORTEX_API_KEY"] == "set"
    assert payload["safety"]["journal_path"]


def test_disks_are_reported(client: TestClient, fake_home: FakeHome) -> None:
    payload = client.get("/api/disks").json()
    assert payload["home"] == str(fake_home.root)
    assert payload["disks"]
    for mount in payload["disks"]:
        assert mount["mountpoint"]
        assert mount["total"] >= 0
        assert 0 <= mount["percent"] <= 100
        assert mount["free_human"]
        assert isinstance(mount["pseudo"], bool)
    assert payload["summary"]["total"] > 0


def test_the_rule_catalogue_is_published(client: TestClient) -> None:
    payload = client.get("/api/rules").json()
    assert payload["count"] > 30
    rules = payload["rules"]
    ids = {rule["id"] for rule in rules}
    assert {"pkg-pip-cache", "browser-cache-dirs", "build-node-modules", "old-downloads"} <= ids
    assert {cat["category"] for cat in payload["categories"]} >= {"package_cache", "duplicates"}
    assert [item["risk"] for item in payload["risk_ladder"]] == [
        "safe", "low", "medium", "high", "forbidden",
    ]

    for rule in rules:
        assert rule["risk"] in RISKS
        assert rule["title"] and rule["description"]
        assert isinstance(rule["applies_here"], bool)
        # A cleaner that hides what it considers junk cannot be audited, so the
        # expanded matchers for *this* machine are part of the response.
        assert "paths" in rule["matcher"]
        if rule["probe"]:
            assert rule["actionable"] is False
            assert rule["risk"] == "forbidden"
            assert rule["advisory"]


def test_rules_can_be_filtered_by_category(client: TestClient) -> None:
    payload = client.get("/api/rules", params={"category": "package_cache"}).json()
    assert payload["count"] > 0
    assert {rule["category"] for rule in payload["rules"]} == {"package_cache"}


def test_safety_explains_the_policy(client: TestClient, fake_home: FakeHome) -> None:
    payload = client.get("/api/safety").json()
    assert payload["guarantees"]
    assert payload["limits"]["max_items_per_operation"] > 0
    assert payload["limits"]["plan_ttl_seconds"] > 0
    assert payload["trash"]["backend"] == "quarantine"
    assert payload["trash"]["allow_permanent_delete"] is False
    assert "/proc" in payload["policy"]["blocked_system_roots"]

    examples = {item["path"]: item for item in payload["examples"]}
    ssh = examples[str(fake_home["ssh_key"])]
    assert ssh["tier"] == "blocked"
    assert ssh["decision"]["allowed"] is False


def test_presets_are_described(client: TestClient) -> None:
    payload = client.get("/api/presets").json()
    ids = {preset["id"] for preset in payload["presets"]}
    assert {"quick", "balanced", "deep"} <= ids
    assert payload["home"]


def test_actions_status_reports_the_guards(client: TestClient) -> None:
    payload = client.get("/api/actions/status").json()
    assert payload["require_confirmation"] is True
    assert payload["allow_permanent_delete"] is False
    assert payload["allow_writes"] is True
    assert payload["plan_ttl_seconds"] > 0
    assert payload["backend"] == "quarantine"
    assert payload["items_in_trash"] == 0
    assert payload["journal_entries"] == 0


# --------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------


def test_scan_rejects_a_missing_root(client: TestClient, tmp_path: Path) -> None:
    response = client.post(
        "/api/scan", json={"roots": [str(tmp_path / "nope")], "preset": "custom"}
    )
    assert response.status_code == 422
    assert "do not exist" in response.text
    assert response.json()["detail"]["missing"] == [str(tmp_path / "nope")]


def test_scan_runs_and_reports_progress(client: TestClient, fake_home: FakeHome) -> None:
    job = completed_scan(client, fake_home)
    assert job["status"] == "completed"
    assert job["roots"] == [str(fake_home.root)]
    assert job["error"] is None
    assert job["progress"]["phase"] == "done"
    assert job["progress"]["percent"] == 100.0
    assert job["stats"]["findings"] > 0
    assert job["stats"]["dirs_seen"] > 0
    assert job["stats"]["permission_errors"] == 0
    assert job["actionable_bytes"] > 0
    assert job["actionable_bytes_human"]
    assert job["dir_totals"]
    assert job["by_risk"]["safe"] > 0
    assert job["has_advice"] is False


def test_findings_are_paged_sorted_and_filterable(
    client: TestClient, fake_home: FakeHome
) -> None:
    job = completed_scan(client, fake_home)
    job_id = job["id"]

    page = client.get(f"/api/scans/{job_id}/findings", params={"limit": 3})
    assert page.status_code == 200
    payload = page.json()
    assert payload["returned"] <= 3
    assert payload["total"] >= payload["returned"]
    assert payload["job_id"] == job_id
    assert payload["status"] == "completed"
    assert payload["total_bytes"] >= 0
    assert payload["risk_summary"]["by_risk"]
    assert {item["risk"] for item in payload["risks"]} == RISKS

    for finding in payload["findings"]:
        assert finding["id"] and finding["path"] and finding["title"]
        assert finding["risk"] in RISKS
        assert finding["bytes_human"]
        assert isinstance(finding["actionable"], bool)
        assert isinstance(finding["selectable"], bool)
        # Members are opt-in: the list view must not carry thousands of paths.
        assert "members" not in finding

    sized = findings_for(client, job_id)
    assert [item["bytes"] for item in sized] == sorted(
        (item["bytes"] for item in sized), reverse=True
    )

    caches = client.get(
        f"/api/scans/{job_id}/findings", params={"category": "package_cache"}
    ).json()
    assert caches["findings"]
    assert all(item["category"] == "package_cache" for item in caches["findings"])

    safe_only = client.get(
        f"/api/scans/{job_id}/findings", params={"risk": "safe"}
    ).json()
    assert all(item["risk"] == "safe" for item in safe_only["findings"])

    searched = client.get(
        f"/api/scans/{job_id}/findings", params={"q": "thumbnails"}
    ).json()
    assert searched["findings"]
    assert any("thumbnails" in item["path"] for item in searched["findings"])

    actionable = client.get(
        f"/api/scans/{job_id}/findings", params={"actionable": False}
    ).json()
    assert all(item["actionable"] is False for item in actionable["findings"])

    selected = client.get(
        f"/api/scans/{job_id}/findings", params={"selected_only": True}
    ).json()
    assert all(item["default_selected"] for item in selected["findings"])


def test_an_unknown_scan_is_a_404(client: TestClient) -> None:
    assert client.get("/api/scans/nope").status_code == 404
    assert client.get("/api/scans/nope/findings").status_code == 404
    assert client.get("/api/scans/nope/advice").status_code == 404
    assert client.post("/api/scans/nope/cancel").status_code == 404
    assert client.get("/api/scans/nope").json()["detail"]["error"]


def test_scan_history_can_be_listed_and_cleared(client: TestClient, fake_home: FakeHome) -> None:
    job = completed_scan(client, fake_home)
    listed = client.get("/api/scans").json()
    assert any(item["id"] == job["id"] for item in listed["jobs"])
    assert listed["latest"] == job["id"]
    assert listed["retention"] > 0

    cleared = client.delete("/api/scans")
    assert cleared.status_code == 200
    assert cleared.json()["removed"] >= 1
    assert client.get("/api/scans").json()["jobs"] == []
    assert client.get(f"/api/scans/{job['id']}").status_code == 404


def test_a_scan_can_be_cancelled(client: TestClient, fake_home: FakeHome) -> None:
    job_id = start_scan(client, fake_home)
    response = client.post(f"/api/scans/{job_id}/cancel")
    assert response.status_code == 200
    payload = response.json()
    assert payload["job_id"] == job_id
    assert isinstance(payload["cancelled"], bool)
    assert payload["status"]


def test_explicit_roots_win_over_a_preset(client: TestClient, fake_home: FakeHome) -> None:
    """Naming roots is an override: a preset may not silently widen the scan."""

    job = completed_scan(client, fake_home, preset="deep")
    assert job["roots"] == [str(fake_home.root)]
    assert "/var/log" not in job["roots"]
    assert job["status"] == "completed"


def test_a_preset_scan_without_explicit_roots_defaults_to_home(client: TestClient) -> None:
    response = client.post("/api/scan", json={"preset": "quick"})
    assert response.status_code == 202, response.text
    assert response.json()["job"]["roots"]


# --------------------------------------------------------------------------
# advice
# --------------------------------------------------------------------------


def test_advice_works_offline(client: TestClient, fake_home: FakeHome) -> None:
    job = completed_scan(client, fake_home)
    response = client.post("/api/advise", json={"job_id": job["id"], "provider": "heuristic"})
    assert response.status_code == 200, response.text
    advice = response.json()
    assert advice["engine"] == "heuristic"
    assert advice["ok"] is True
    assert advice["job_id"] == job["id"]
    assert advice["headline"] and advice["summary"]
    assert advice["items"]
    assert advice["quick_wins"]
    assert advice["warnings"], "the offline engine must say it is not a model"

    known = {item["id"] for item in findings_for(client, job["id"])}
    for item in advice["items"]:
        assert item["finding_id"] in known
        assert item["action"] in {"clean", "review", "keep", "manual"}
        assert item["risk"] in RISKS
        assert item["reason"]
    # Anything the advisor marks "clean" must be actionable and low risk.
    for item in advice["items"]:
        if item["action"] == "clean":
            assert item["risk"] in {"safe", "low"}
            assert item["finding_id"] in advice["clean_ids"]
    assert advice["totals"]["clean"]["items"] >= 1


def test_advice_is_stored_on_the_scan(client: TestClient, fake_home: FakeHome) -> None:
    job = completed_scan(client, fake_home)
    client.post("/api/advise", json={"job_id": job["id"], "provider": "heuristic"})

    stored = client.get(f"/api/scans/{job['id']}/advice")
    assert stored.status_code == 200
    assert stored.json()["engine"] == "heuristic"
    assert client.get(f"/api/scans/{job['id']}").json()["has_advice"] is True


def test_advice_needs_a_scan(client: TestClient) -> None:
    response = client.post("/api/advise", json={"provider": "heuristic"})
    assert response.status_code == 404
    assert response.json()["detail"]["hint"]


def test_advice_refuses_a_still_running_scan(client: TestClient, fake_home: FakeHome) -> None:
    job_id = start_scan(client, fake_home)
    response = client.post("/api/advise", json={"job_id": job_id, "provider": "heuristic"})
    # It either already finished (200) or is still running (409); never a crash.
    assert response.status_code in {200, 409}, response.text
    if response.status_code == 409:
        assert "still running" in response.text


def test_providers_report_honest_offline_status(client: TestClient) -> None:
    payload = client.get("/api/providers").json()
    providers = {item["name"]: item for item in payload["providers"]}
    assert set(providers) == {"cortex", "ollama"}
    assert payload["preferred"] == "auto"
    assert payload["offline_engine"]["name"] == "heuristic"
    assert payload["offline_engine"]["online"] is True
    assert "metadata only" in payload["note"]

    for name, info in providers.items():
        assert info["base_url"].startswith("http://127.0.0.1"), name
        assert info["status"] == "offline", name
        assert info["online"] is False
        assert info["models"] == []
        assert info["hint"], f"{name} must explain how to start it"
        # Only a boolean is published -- never the key itself.
        assert "super-secret-token" not in json.dumps(info)
        assert "api_key" not in info


def test_a_provider_check_is_answered(client: TestClient) -> None:
    response = client.post("/api/providers/ollama/check", json={})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["provider"]["name"] == "ollama"
    assert payload["transient"] is False

    unknown = client.post("/api/providers/skynet/check", json={})
    assert unknown.status_code == 404
    assert "cortex" in unknown.text


def test_a_transient_provider_override_is_not_persisted(client: TestClient) -> None:
    response = client.post(
        "/api/providers/cortex/check",
        json={"base_url": "http://127.0.0.1:9", "model": "qwen-local"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["transient"] is True
    assert payload["provider"]["base_url"] == "http://127.0.0.1:9"
    assert "nothing was saved" in payload["message"]
    # The configured provider is unchanged.
    configured = client.get("/api/config").json()["ai"]["providers"]
    assert next(p for p in configured if p["name"] == "cortex")["base_url"].endswith("8624")


def test_chat_streams_and_says_which_engine_answered(
    client: TestClient, fake_home: FakeHome
) -> None:
    job = completed_scan(client, fake_home)
    with client.stream(
        "POST",
        "/api/chat",
        json={
            "message": "what should I clean?",
            "job_id": job["id"],
            "provider": "heuristic",
            "stream": True,
        },
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())

    assert "event: meta" in body and "event: delta" in body and "event: done" in body
    assert '"readonly": true' in body


def test_chat_reports_a_dead_provider_instead_of_hanging(
    client: TestClient, fake_home: FakeHome
) -> None:
    job = completed_scan(client, fake_home)
    with client.stream(
        "POST",
        "/api/chat",
        json={"message": "hi", "job_id": job["id"], "provider": "auto", "stream": True},
    ) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())
    assert "event: delta" in body
    assert "event: done" in body
    assert "No local model host answered" in body

    unstreamed = client.post(
        "/api/chat",
        json={"message": "hi", "job_id": job["id"], "provider": "auto", "stream": False},
    )
    assert unstreamed.status_code == 200, unstreamed.text
    reply = unstreamed.json()
    assert reply["readonly"] is True
    assert "cortex_llmhoster" in reply["reply"]
    assert "ollama serve" in reply["reply"]


# --------------------------------------------------------------------------
# the whole clean flow, over HTTP
# --------------------------------------------------------------------------


def test_the_full_clean_and_undo_flow(client: TestClient, fake_home: FakeHome) -> None:
    job = completed_scan(client, fake_home)
    findings = findings_for(client, job["id"])

    cache = by_rule(findings, "app-thumbnails")
    assert cache["risk"] == "safe" and cache["default_selected"] is True
    original = Path(cache["path"])
    assert original.exists()

    # 1. plan -- touches nothing
    planned = client.post(
        "/api/clean/plan",
        json={"job_id": job["id"], "finding_ids": [cache["id"]], "mode": "trash"},
    )
    assert planned.status_code == 200, planned.text
    plan = planned.json()
    assert plan["item_count"] == 1
    assert plan["refused_count"] == 0
    assert plan["total_bytes"] == cache["bytes"]
    assert plan["confirm_token"]
    assert plan["fingerprint"]
    assert plan["expired"] is False
    assert plan["expires_in_seconds"] > 0
    assert plan["mode"] == "trash"
    assert plan["items"][0]["path"] == cache["path"]
    assert plan["items"][0]["allowed"] is True
    assert plan["by_risk"]["safe"]["items"] == 1
    assert "trash" in plan["note"].lower()
    assert original.exists(), "planning must not touch the filesystem"

    # 2. execute with the wrong token is refused
    tampered = client.post(
        "/api/clean/execute", json={"plan_id": plan["id"], "confirm_token": "0" * 64}
    )
    assert tampered.status_code == 409
    assert original.exists(), "a refused execution must change nothing"

    # 3. a mismatched byte echo is refused
    echo = client.post(
        "/api/clean/execute",
        json={
            "plan_id": plan["id"],
            "confirm_token": plan["confirm_token"],
            "expected_bytes": plan["total_bytes"] + 1,
        },
    )
    assert echo.status_code == 409
    assert "changed since you reviewed it" in echo.text
    assert original.exists()

    # 4. execute for real
    executed = client.post(
        "/api/clean/execute",
        json={
            "plan_id": plan["id"],
            "confirm_token": plan["confirm_token"],
            "expected_bytes": plan["total_bytes"],
        },
    )
    assert executed.status_code == 200, executed.text
    report = executed.json()
    assert report["ok_count"] == 1
    assert report["failed_count"] == 0
    assert report["bytes"] == cache["bytes"]
    assert report["mode"] == "trash"
    assert report["moved"][0]["ok"] is True
    assert report["moved"][0]["entry_id"]
    assert not original.exists(), "the cache should be gone"
    assert fake_home["documents"].exists(), "personal data must be untouched"
    assert fake_home["ssh_key"].exists(), "credentials must be untouched"

    # 5. a plan is single-use
    replay = client.post(
        "/api/clean/execute", json={"plan_id": plan["id"], "confirm_token": plan["confirm_token"]}
    )
    assert replay.status_code == 404
    assert "single-use" in replay.text

    # 6. history shows the removal
    history = client.get("/api/history").json()
    assert history["total_entries"] == 1
    assert history["active_items"] == 1
    entry = history["entries"][0]
    assert entry["path"] == cache["path"]
    assert entry["status"] == "trashed"
    assert entry["rule_id"] == "app-thumbnails"
    assert entry["op_id"] == report["op_id"]
    assert entry["bytes"] == cache["bytes"]
    assert Path(entry["stored_path"]).exists(), "the data must still be on disk"
    assert history["operations"][0]["op_id"] == report["op_id"]
    assert client.get("/api/actions/status").json()["items_in_trash"] == 1

    # 7. one click undoes the whole operation
    undo = client.post("/api/history/restore", json={"op_id": report["op_id"]})
    assert undo.status_code == 200, undo.text
    assert undo.json()["ok_count"] == 1
    assert original.exists(), "one click must bring it back"

    restored = client.get("/api/history", params={"status": "restored"}).json()
    assert restored["total_entries"] == 1
    assert restored["active_items"] == 0


def test_plan_by_advice_uses_the_advisor_selection(
    client: TestClient, fake_home: FakeHome
) -> None:
    job = completed_scan(client, fake_home)
    advice = client.post(
        "/api/advise", json={"job_id": job["id"], "provider": "heuristic"}
    ).json()
    assert advice["clean_ids"], "the offline advisor should propose safe cleanups"

    plan = client.post(
        "/api/clean/plan",
        json={"job_id": job["id"], "from_advice": True, "max_risk": "low", "mode": "dry_run"},
    )
    assert plan.status_code == 200, plan.text
    payload = plan.json()
    assert payload["item_count"] >= 1
    assert payload["mode"] == "dry_run"
    assert all(item["risk"] in {"safe", "low"} for item in payload["items"])


def test_plan_requires_a_selection(client: TestClient, fake_home: FakeHome) -> None:
    job = completed_scan(client, fake_home)
    response = client.post("/api/clean/plan", json={"job_id": job["id"], "finding_ids": []})
    assert response.status_code == 422
    assert "Nothing selected" in response.text


def test_plan_needs_a_completed_scan(client: TestClient) -> None:
    response = client.post("/api/clean/plan", json={"finding_ids": ["abc"]})
    assert response.status_code == 404
    assert "Run a scan first" in response.text


def test_dry_run_changes_nothing(client: TestClient, fake_home: FakeHome) -> None:
    job = completed_scan(client, fake_home)
    cache = by_rule(findings_for(client, job["id"]), "pkg-pip-cache")

    plan = client.post(
        "/api/clean/plan",
        json={"job_id": job["id"], "finding_ids": [cache["id"]], "mode": "dry_run"},
    ).json()
    report = client.post(
        "/api/clean/execute",
        json={"plan_id": plan["id"], "confirm_token": plan["confirm_token"]},
    ).json()

    assert report["mode"] == "dry_run"
    assert Path(cache["path"]).exists()
    assert client.get("/api/history").json()["total_entries"] == 0


def test_an_aggregate_never_plans_its_anchor_directory(
    client: TestClient, fake_home: FakeHome
) -> None:
    """`Old downloads` summarises ~/Downloads; the folder itself must not be a target."""

    job = completed_scan(client, fake_home)
    aggregate = by_rule(findings_for(client, job["id"]), "old-downloads")
    assert aggregate["members"], "an aggregate must list what it stands for"
    assert aggregate["risk"] == "high"
    assert aggregate["default_selected"] is False, "personal data is never pre-ticked"

    plan = client.post(
        "/api/clean/plan",
        json={"job_id": job["id"], "finding_ids": [aggregate["id"]], "mode": "dry_run"},
    )
    assert plan.status_code == 200, plan.text
    payload = plan.json()

    planned = {item["path"] for item in payload["items"]}
    assert aggregate["path"] not in planned, "the Downloads folder must never be a target"
    assert planned == {member["path"] for member in aggregate["members"]}
    assert Path(aggregate["path"]).exists()


def test_protected_paths_are_refused_in_a_plan(client: TestClient, fake_home: FakeHome) -> None:
    """Even an explicit selection cannot reach credentials or system data."""

    job = completed_scan(client, fake_home)
    forbidden = [
        item for item in findings_for(client, job["id"]) if item["actionable"] is False
    ]
    assert forbidden, "the advisory probes should be reported and marked non-actionable"

    plan = client.post(
        "/api/clean/plan",
        json={"job_id": job["id"], "finding_ids": [item["id"] for item in forbidden],
              "mode": "dry_run"},
    )
    assert plan.status_code == 200, plan.text
    payload = plan.json()
    assert payload["item_count"] == 0
    assert payload["refused_count"] == len(forbidden)
    assert all(item["allowed"] is False for item in payload["refused"])
    assert all(item["reason"] for item in payload["refused"])
    assert "refused by the safety policy" in payload["warning"]


def test_permanent_deletion_is_refused_over_http(client: TestClient, fake_home: FakeHome) -> None:
    job = completed_scan(client, fake_home)
    cache = by_rule(findings_for(client, job["id"]), "pkg-pip-cache")

    response = client.post(
        "/api/clean/plan",
        json={"job_id": job["id"], "finding_ids": [cache["id"]], "mode": "permanent"},
    )
    assert response.status_code == 409
    assert "DISKFREE_ALLOW_PERMANENT_DELETE" in response.text
    assert Path(cache["path"]).exists()


def test_purge_is_refused_over_http(client: TestClient) -> None:
    response = client.post("/api/history/purge", json={"entry_ids": ["anything"]})
    assert response.status_code == 409
    assert "permanent" in response.text.lower()


def test_restoring_an_unknown_operation_is_a_409(client: TestClient) -> None:
    response = client.post("/api/history/restore", json={"op_id": "op_nope"})
    assert response.status_code == 409
    assert response.json()["detail"]


def test_an_unknown_plan_is_a_404(client: TestClient) -> None:
    response = client.post(
        "/api/clean/execute", json={"plan_id": "plan_nope", "confirm_token": "x" * 64}
    )
    assert response.status_code == 404
    assert "Unknown or already-used plan" in response.text


def test_a_hostile_file_name_is_returned_as_data_not_markup(
    client: TestClient, fake_home: FakeHome
) -> None:
    """Prompt injection in a path must not widen permissions or invent markup."""

    job = completed_scan(client, fake_home)
    hostile = [
        item for item in findings_for(client, job["id"]) if "IGNORE ALL RULES" in item["path"]
    ]
    assert hostile, "the hostile directory should be reported as ordinary cache"
    target = hostile[0]
    assert target["risk"] == "safe"
    assert "<" not in target["title"]
    # It is treated as what it is -- a cache directory -- not as an instruction.
    assert target["category"] in {"app_cache", "package_cache", "temp"}
    assert target["actionable"] is True

    advice = client.post(
        "/api/advise", json={"job_id": job["id"], "provider": "heuristic"}
    ).json()
    # The instruction embedded in the folder name cannot redirect the advisor at
    # personal data: nothing it proposes to clean is the Documents folder.
    documents = str(fake_home.root / "Documents")
    for item in advice["items"]:
        if item["action"] == "clean":
            assert item["path"] != documents
            assert not item["path"].startswith(documents + "/")
            assert item["path"] != str(fake_home.root)


def test_read_only_mode_is_visible_and_enforced(
    app_settings: Settings, fake_home: FakeHome
) -> None:
    readonly = dc_replace(
        app_settings, safety=dc_replace(app_settings.safety, allow_writes=False)
    )
    with TestClient(create_app(readonly)) as guarded:
        assert guarded.get("/api/status").json()["read_only"] is True
        assert guarded.get("/api/status").json()["safety"]["allow_writes"] is False

        job = completed_scan(guarded, fake_home)
        findings = findings_for(guarded, job["id"])
        assert findings, "scanning is read-only and must still work"

        cache = by_rule(findings, "pkg-pip-cache")
        plan = guarded.post(
            "/api/clean/plan",
            json={"job_id": job["id"], "finding_ids": [cache["id"]], "mode": "trash"},
        )
        assert plan.status_code == 409
        assert "read-only" in plan.text.lower()
        assert Path(cache["path"]).exists()


def test_the_api_can_be_put_behind_a_token(app_settings: Settings, fake_home: FakeHome) -> None:
    secured = dc_replace(app_settings, ui_token="s3cret")
    with TestClient(create_app(secured)) as guarded:
        assert guarded.get("/api/status").status_code == 401
        assert guarded.post("/api/scan", json={}).status_code == 401
        assert guarded.get("/api/history").headers["www-authenticate"] == "Bearer"

        header = guarded.get("/api/status", headers={"X-DiskFree-Token": "s3cret"})
        assert header.status_code == 200

        bearer = guarded.get("/api/status", headers={"Authorization": "Bearer s3cret"})
        assert bearer.status_code == 200

        assert guarded.get(
            "/api/status", headers={"X-DiskFree-Token": "nope"}
        ).status_code == 401

        # The UI itself stays reachable, or nobody could log in to use it.
        assert guarded.get("/").status_code == 200
        assert guarded.get("/app.js").status_code == 200
        assert guarded.get("/api/health").status_code == 200
        assert guarded.get("/ui/index.html").status_code == 200

        # ... and the guarded API still works end to end with the token.
        guarded.headers["X-DiskFree-Token"] = "s3cret"
        job = completed_scan(guarded, fake_home)
        assert job["status"] == "completed"


def test_cors_is_off_unless_configured(app_settings: Settings) -> None:
    with TestClient(create_app(app_settings)) as guarded:
        response = guarded.get("/api/health", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in response.headers

    open_cors = dc_replace(app_settings, cors_origins=["https://dashboard.example"])
    with TestClient(create_app(open_cors)) as guarded:
        response = guarded.get("/api/health", headers={"Origin": "https://dashboard.example"})
        assert response.headers["access-control-allow-origin"] == "https://dashboard.example"
        assert response.headers.get("access-control-allow-credentials") != "true"

from __future__ import annotations

from httpx import AsyncClient


async def test_health(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_create_and_list_team(client: AsyncClient):
    resp = await client.post("/api/v1/teams", json={"name": "Test Bank", "slug": "test-bank"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["slug"] == "test-bank"
    team_id = data["id"]

    resp = await client.get("/api/v1/teams")
    assert resp.status_code == 200
    slugs = [t["slug"] for t in resp.json()]
    assert "test-bank" in slugs


async def test_duplicate_slug_rejected(client: AsyncClient):
    await client.post("/api/v1/teams", json={"name": "Alpha", "slug": "alpha-co"})
    resp = await client.post("/api/v1/teams", json={"name": "Alpha 2", "slug": "alpha-co"})
    assert resp.status_code == 400


async def test_create_api_key(client: AsyncClient):
    team_resp = await client.post("/api/v1/teams", json={"name": "Fintech Co", "slug": "fintech-co"})
    team_id = team_resp.json()["id"]

    key_resp = await client.post(
        f"/api/v1/teams/{team_id}/keys",
        json={"name": "claude-code-dev", "provider": "anthropic"},
    )
    assert key_resp.status_code == 201
    key_data = key_resp.json()
    assert key_data["raw_key"].startswith("ag-")


async def test_ingest_events(client: AsyncClient):
    events = [
        {
            "event_id": "evt-001",
            "timestamp": "2026-06-26T10:00:00Z",
            "machine_id": "abc123",
            "provider": "anthropic",
            "model": "claude-sonnet-4-6",
            "direction": "outbound",
            "action_taken": "blocked",
            "findings": [{"severity": "critical", "title": "API key in prompt"}],
            "request_id": "req-001",
        }
    ]
    resp = await client.post("/api/v1/events", json=events)
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 1


async def test_event_stats(client: AsyncClient):
    resp = await client.get("/api/v1/events/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "blocked" in data


async def test_dashboard_renders(client: AsyncClient):
    resp = await client.get("/dashboard")
    assert resp.status_code == 200
    assert b"AIRiskGuard" in resp.content


async def test_get_current_policy_empty(client: AsyncClient):
    resp = await client.get("/api/v1/policies/current")
    assert resp.status_code == 200
    data = resp.json()
    assert "version" in data


async def test_upsert_policy(client: AsyncClient):
    team_resp = await client.post("/api/v1/teams", json={"name": "Health Co", "slug": "health-co"})
    team_id = team_resp.json()["id"]

    policy_resp = await client.post(
        f"/api/v1/policies/{team_id}",
        json={
            "rules": [
                {
                    "rule_id": "r1",
                    "name": "Block secrets",
                    "checker": "secrets",
                    "action": "block",
                    "enabled": True,
                }
            ],
            "model_allowlist": ["claude-sonnet-4-6", "gpt-4o"],
        },
    )
    assert policy_resp.status_code == 201
    data = policy_resp.json()
    assert data["version"] == 1
    assert "gpt-4o" in data["model_allowlist"]

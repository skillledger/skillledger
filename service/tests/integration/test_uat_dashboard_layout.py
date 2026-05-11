"""UAT-05: Dashboard layout functional assertions.

Verifies that API endpoints powering dashboard pages return correct
structure without requiring a running browser (per D-03 decision).
Tests the API contracts that feed dashboard layout components.
"""

import datetime

from tests.integration.conftest import (
    add_org_membership,
    create_org_via_api,
    create_test_user,
)

from skillledger_service.models.organization import OrgRole


# ---------------------------------------------------------------------------
# Dashboard pages render (API contract verification)
# ---------------------------------------------------------------------------


def test_dashboard_pages_render(client):
    """Core dashboard endpoints return 200 with expected JSON structure.

    Verifies:
    - GET /health -> 200 with {"status": "ok"} (dashboard health indicator)
    - GET /v1/me with valid token -> 200 with user object containing "email"
    - GET /v1/usage with valid token -> 200 with usage data structure
    """
    # Health endpoint (no auth required) - powers dashboard status indicator
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"

    # Create authenticated user for protected endpoints
    user = create_test_user("dashboard@example.com")

    # /v1/me - powers user profile display in dashboard header
    resp = client.get("/v1/me", headers=user["headers"])
    assert resp.status_code == 200
    me_data = resp.json()
    assert "email" in me_data
    assert me_data["email"] == "dashboard@example.com"
    assert "id" in me_data
    assert "orgs" in me_data
    assert isinstance(me_data["orgs"], list)

    # /v1/usage - powers usage stats widget in dashboard
    resp = client.get("/v1/usage", headers=user["headers"])
    assert resp.status_code == 200
    usage_data = resp.json()
    assert "operation" in usage_data
    assert "used" in usage_data
    assert "billing_status" in usage_data
    assert "resets_at" in usage_data
    assert usage_data["operation"] == "tlog_publish"
    assert usage_data["billing_status"] == "free"


# ---------------------------------------------------------------------------
# Posture/audit endpoint (dashboard security posture panel)
# ---------------------------------------------------------------------------


def test_dashboard_posture_endpoint(ee_client):
    """GET events endpoint returns list structure for dashboard posture view.

    The dashboard security posture panel aggregates violation events.
    This tests the API returns a list (possibly empty) for rendering.
    """
    user = create_test_user("posture@example.com")
    org = create_org_via_api(ee_client, user["headers"], "Posture Org")

    # GET events for the org - powers the dashboard posture/audit panel
    resp = ee_client.get(
        f"/ee/v1/orgs/{org['slug']}/events",
        headers=user["headers"],
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    # Empty list is valid - no events ingested yet
    assert len(data) == 0


# ---------------------------------------------------------------------------
# Violations/events endpoint (dashboard violations table)
# ---------------------------------------------------------------------------


def test_dashboard_violations_endpoint(ee_client):
    """GET events endpoint with data returns list of violation objects.

    Tests that after ingesting events, the dashboard violations table
    receives properly structured event objects.
    """
    user = create_test_user("violations@example.com")
    org = create_org_via_api(ee_client, user["headers"], "Violations Org")

    # Ingest a test violation event
    event_payload = {
        "org_slug": org["slug"],
        "events": [
            {
                "type": "policy_violation",
                "ecosystem": "claude-code",
                "skill_id": "test-skill-001",
                "rule": "no-network-access",
                "severity": "high",
                "details": {"action": "blocked"},
                "timestamp": datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat(),
            }
        ],
    }
    ingest_resp = ee_client.post(
        "/ee/v1/events",
        json=event_payload,
        headers=user["headers"],
    )
    assert ingest_resp.status_code == 201
    assert ingest_resp.json()["accepted"] == 1

    # Now query events - dashboard violations table data source
    resp = ee_client.get(
        f"/ee/v1/orgs/{org['slug']}/events",
        headers=user["headers"],
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 1
    event = data[0]
    assert event["event_type"] == "policy_violation"
    assert event["ecosystem"] == "claude-code"
    assert event["skill_id"] == "test-skill-001"
    assert event["severity"] == "high"

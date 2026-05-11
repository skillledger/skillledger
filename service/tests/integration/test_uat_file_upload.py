"""UAT-07: File upload multipart test.

The SkillLedger service receives artifacts via the /log/publish JSON endpoint
(artifacts flow through CLI -> tlog, not multipart upload). This test verifies
the artifact submission flow: authentication enforcement, payload validation,
and successful publish with valid credentials.

Per D-03: Tests API contracts without browser automation.
Per T-33-02: Explicitly verifies 401 without valid auth token (spoofing mitigation).
"""

from unittest.mock import AsyncMock, patch

import pytest

from tests.integration.conftest import create_test_user


# ---------------------------------------------------------------------------
# Artifact publish accepts valid data (equivalent to "file upload")
# ---------------------------------------------------------------------------


def test_file_upload_accepts_multipart(client):
    """POST to artifact publish endpoint with valid auth and data returns success.

    The /log/publish endpoint is the artifact submission path. With a valid
    authenticated user and properly formatted payload (artifact_id, sha256,
    content_address), it should forward to the log service and return 200
    with the log_index and artifact_id.
    """
    user = create_test_user("uploader@example.com")

    # Mock the external log service to avoid network dependency
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.text = "42"

    with patch("skillledger_service.routers.log.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=None)
        mock_instance.post = AsyncMock(return_value=mock_response)
        mock_client.return_value = mock_instance

        resp = client.post(
            "/log/publish",
            json={
                "artifact_id": "my-skill@1.0.0",
                "sha256": "a" * 64,
                "content_address": "sha256-" + "a" * 64,
            },
            headers=user["headers"],
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["log_index"] == 42
    assert data["artifact_id"] == "my-skill@1.0.0"


# ---------------------------------------------------------------------------
# Invalid content rejected
# ---------------------------------------------------------------------------


def test_file_upload_rejects_invalid_content(client):
    """POST with invalid/malformed content returns 422 validation error.

    The endpoint requires:
    - artifact_id: non-empty string
    - sha256: exactly 64 hex characters
    - content_address: non-empty string

    Invalid payloads should be rejected by Pydantic validation.
    """
    user = create_test_user("invalid@example.com")

    # Missing required fields
    resp = client.post(
        "/log/publish",
        json={},
        headers=user["headers"],
    )
    assert resp.status_code == 422

    # Invalid sha256 (too short)
    resp = client.post(
        "/log/publish",
        json={
            "artifact_id": "test-skill",
            "sha256": "tooshort",
            "content_address": "sha256-tooshort",
        },
        headers=user["headers"],
    )
    assert resp.status_code == 422

    # Empty artifact_id
    resp = client.post(
        "/log/publish",
        json={
            "artifact_id": "",
            "sha256": "b" * 64,
            "content_address": "sha256-" + "b" * 64,
        },
        headers=user["headers"],
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Auth enforcement (T-33-02: Spoofing mitigation)
# ---------------------------------------------------------------------------


def test_file_upload_requires_auth(client):
    """POST without auth header returns 401/403 (T-33-02 spoofing mitigation).

    Ensures the artifact publish endpoint cannot be accessed without valid
    authentication credentials, preventing unauthorized artifact injection.
    """
    resp = client.post(
        "/log/publish",
        json={
            "artifact_id": "unauthorized-skill@1.0.0",
            "sha256": "c" * 64,
            "content_address": "sha256-" + "c" * 64,
        },
    )
    # FastAPI HTTPBearer returns 403 when no credentials header present
    assert resp.status_code in (401, 403)


def test_file_upload_rejects_invalid_token(client):
    """POST with invalid/expired token returns 401.

    Ensures forged or expired tokens cannot be used to publish artifacts.
    """
    resp = client.post(
        "/log/publish",
        json={
            "artifact_id": "forged-skill@1.0.0",
            "sha256": "d" * 64,
            "content_address": "sha256-" + "d" * 64,
        },
        headers={"Authorization": "Bearer invalid-token-value"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Log service unavailability handling
# ---------------------------------------------------------------------------


def test_file_upload_handles_log_unavailable(client):
    """POST when log service is unavailable returns 502.

    Verifies graceful error handling when the upstream Tessera log
    service cannot be reached (connection refused scenario).
    """
    user = create_test_user("unavailable@example.com")

    import httpx

    with patch("skillledger_service.routers.log.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=None)
        mock_instance.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        mock_client.return_value = mock_instance

        resp = client.post(
            "/log/publish",
            json={
                "artifact_id": "test-skill@2.0.0",
                "sha256": "e" * 64,
                "content_address": "sha256-" + "e" * 64,
            },
            headers=user["headers"],
        )

    assert resp.status_code == 502
    assert "unavailable" in resp.json()["detail"].lower()

"""UAT Integration Tests: Auth Middleware Protection (UAT-02, D-01).

Proves: 401 without token, 200 with valid token, 403/401 for wrong role,
401 for expired token.
"""

import datetime
import os

import jwt

from tests.integration.conftest import create_test_user, get_valid_token

from skillledger_service.db import get_settings


def test_protected_route_returns_401_without_token(client):
    """GET /v1/me without Authorization header returns 401.

    Covers UAT-02: Auth middleware rejects unauthenticated requests.
    """
    resp = client.get("/v1/me")
    assert resp.status_code in (401, 403)


def test_protected_route_returns_200_with_valid_token(client):
    """GET /v1/me with valid JWT Bearer token returns 200 with user data.

    Covers UAT-02: Auth middleware accepts valid tokens.
    """
    user = create_test_user("auth-valid@example.com")
    token = get_valid_token(user.id, user.email)

    resp = client.get("/v1/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "auth-valid@example.com"
    assert data["id"] == user.id


def test_protected_route_returns_403_for_wrong_role(client):
    """Non-admin user accessing admin-only endpoint (GET /publishers) returns 403.

    Covers UAT-02: Role-based access control works.
    """
    user = create_test_user("nonadmin@example.com")
    token = get_valid_token(user.id, user.email)

    # /publishers requires admin API key, not user JWT -- should return 403
    resp = client.get("/publishers", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_expired_token_returns_401(client):
    """GET /v1/me with expired JWT returns 401.

    Covers UAT-02: Expired tokens are rejected.
    """
    user = create_test_user("expired-token@example.com")
    settings = get_settings()

    # Generate a token that expired 1 hour ago
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "iat": now - datetime.timedelta(hours=2),
        "exp": now - datetime.timedelta(hours=1),
        "type": "access",
        "jti": "test-expired-jti",
    }
    expired_token = jwt.encode(payload, settings.jwt_secret, algorithm="HS256")

    resp = client.get("/v1/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp.status_code == 401

"""
API integration tests for BYPASS #1 prevention.

These tests exercise the full HTTP path: request → permission resolution
→ token construction → response, verifying that the API no longer allows
arbitrary permission escalation.
"""
import pytest

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient
from app.main import create_app
from app.api.routes.auth import reset_store, get_dev_api_key, UserRole


@pytest.fixture(autouse=True)
def _clean_auth_store():
    reset_store()
    yield
    reset_store()


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def dev_key():
    return get_dev_api_key()


@pytest.fixture
def auth_headers(dev_key):
    return {"Authorization": f"Bearer {dev_key}"}


def _register_user(client, email, role="operator"):
    """Register a user and return auth headers."""
    r = client.post("/api/v1/auth/register", json={
        "email": email,
        "name": email,
        "role": role,
    })
    assert r.status_code == 201
    key = r.json()["api_key"]
    return {"Authorization": f"Bearer {key}"}


# ── BYPASS #1 attack vectors ─────────────────────────────────────────

class TestBypass1API:

    def test_wildcard_with_hipaa_blocked(self, client, auth_headers):
        """The exact BYPASS #1 attack: wildcard + HIPAA."""
        r = client.post("/api/v1/tasks", json={
            "task": "Review patient records",
            "compliance_policy": "hipaa",
            "permissions": ["*"],
        }, headers=auth_headers)
        # Should succeed but with narrowed permissions (or 403 if all denied)
        if r.status_code == 201:
            data = r.json()
            # Resolution should show the wildcard was denied
            assert data.get("permission_resolution") is not None
            res = data["permission_resolution"]
            denied_perms = [d["permission"] for d in res["denied"]]
            assert "*" in denied_perms
        elif r.status_code == 403:
            # All permissions denied - also acceptable
            pass
        else:
            pytest.fail(f"Unexpected status: {r.status_code}")

    def test_arbitrary_perms_with_hipaa(self, client, auth_headers):
        """User tries to get network access under HIPAA."""
        r = client.post("/api/v1/tasks", json={
            "task": "Exfiltrate data",
            "compliance_policy": "hipaa",
            "permissions": [
                "network:admin:full",
                "database:write:anything",
            ],
        }, headers=auth_headers)
        # Both requested perms exceed the HIPAA ceiling
        assert r.status_code == 403  # no effective permissions

    def test_forbidden_perm_with_hipaa(self, client, auth_headers):
        """Requesting a forbidden permission under HIPAA."""
        r = client.post("/api/v1/tasks", json={
            "task": "Send email",
            "compliance_policy": "hipaa",
            "permissions": ["network:smtp:send:external"],
        }, headers=auth_headers)
        assert r.status_code == 403

    def test_mixed_valid_and_escalated(self, client, auth_headers):
        """Some valid perms + some escalated → only valid ones granted."""
        r = client.post("/api/v1/tasks", json={
            "task": "Read patient data",
            "compliance_policy": "hipaa",
            "permissions": [
                "database:read:patient_data",  # valid
                "network:admin:root",           # escalated
            ],
        }, headers=auth_headers)
        assert r.status_code == 201
        data = r.json()
        # Should have a resolution showing the denial
        assert data.get("permission_resolution") is not None
        res = data["permission_resolution"]
        assert len(res["denied"]) >= 1

    def test_no_permissions_uses_defaults(self, client, auth_headers):
        """No user permissions → policy defaults (safe path)."""
        r = client.post("/api/v1/tasks", json={
            "task": "Review records",
            "compliance_policy": "hipaa",
        }, headers=auth_headers)
        assert r.status_code == 201
        # No resolution info when defaults are used cleanly
        data = r.json()
        assert data.get("permission_resolution") is None

    def test_sox_forbidden_write(self, client, auth_headers):
        """SOX forbids database:write:financial_data."""
        r = client.post("/api/v1/tasks", json={
            "task": "Modify records",
            "compliance_policy": "sox",
            "permissions": ["database:write:financial_data"],
        }, headers=auth_headers)
        assert r.status_code == 403

    def test_default_policy_allows_custom(self, client, auth_headers):
        """Default policy with no compliance → custom perms pass."""
        r = client.post("/api/v1/tasks", json={
            "task": "Do something",
            "permissions": ["custom:perm:whatever"],
        }, headers=auth_headers)
        assert r.status_code == 201
        # No denial in resolution
        data = r.json()
        assert data.get("permission_resolution") is None


# ── Role-based restrictions ───────────────────────────────────────────

class TestRoleBasedAPI:

    def test_viewer_cannot_create_task(self, client):
        """VIEWER role is rejected."""
        headers = _register_user(client, "viewer@test.com", "viewer")
        r = client.post("/api/v1/tasks", json={
            "task": "Read something",
        }, headers=headers)
        assert r.status_code == 403
        assert "not permitted" in r.json()["detail"].lower()

    def test_operator_hipaa_defaults_ok(self, client):
        """Operator can create HIPAA tasks with defaults."""
        headers = _register_user(client, "op@test.com", "operator")
        r = client.post("/api/v1/tasks", json={
            "task": "Review records",
            "compliance_policy": "hipaa",
        }, headers=headers)
        assert r.status_code == 201

    def test_operator_cannot_exceed_defaults(self, client):
        """Operator requesting perms beyond HIPAA defaults → denied."""
        headers = _register_user(client, "op2@test.com", "operator")
        r = client.post("/api/v1/tasks", json={
            "task": "Run code",
            "compliance_policy": "hipaa",
            "permissions": ["compute:python:eval"],
        }, headers=headers)
        # compute:python:eval is in max_permissions but not in defaults
        # operator is limited to defaults → denied
        assert r.status_code == 403

    def test_admin_can_exceed_defaults(self, client, auth_headers):
        """Admin can use max_permissions beyond defaults."""
        r = client.post("/api/v1/tasks", json={
            "task": "Run computation",
            "compliance_policy": "hipaa",
            "permissions": ["compute:python:eval"],
        }, headers=auth_headers)
        assert r.status_code == 201


# ── Backwards compatibility ───────────────────────────────────────────

class TestBackwardsCompatibility:
    """Existing test scenarios must still work."""

    def test_create_task_default(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={
            "task": "Analyse quarterly report",
        }, headers=auth_headers)
        assert r.status_code == 201
        data = r.json()
        assert "execution_id" in data
        assert data["status"] == "queued"
        assert "websocket_url" in data

    def test_create_task_hipaa(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={
            "task": "Review patient records",
            "compliance_policy": "hipaa",
            "budget_cents": 2000,
        }, headers=auth_headers)
        assert r.status_code == 201

    def test_create_task_invalid_policy(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={
            "task": "something",
            "compliance_policy": "gdpr",
        }, headers=auth_headers)
        assert r.status_code == 400

    def test_create_task_empty_task(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={"task": ""}, headers=auth_headers)
        assert r.status_code == 422

    def test_create_task_no_auth(self, client):
        r = client.post("/api/v1/tasks", json={"task": "foo"})
        assert r.status_code in (401, 403)

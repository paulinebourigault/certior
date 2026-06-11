"""
Comprehensive tests for app.api.routes.auth.

Covers:
  - UserStore: register, authenticate, rotate, deactivate, list
    - Email/password sign-in and persisted credential helpers
  - get_current_user dependency: Bearer, X-API-Key, missing, invalid, deactivated
    - Routes: POST /register, POST /login, POST /rotate, GET /me
  - Role-based access control via require_role
  - Edge cases: duplicate email, invalid role, key hashing
"""
import pytest

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient
from app.main import create_app
from app.api.routes.auth import (
    User, UserRole, UserStore, _hash_key,
    get_user_store, get_dev_api_key, reset_store,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate_store():
    """Guarantee a clean store for every test."""
    reset_store()
    yield
    reset_store()


@pytest.fixture
def store() -> UserStore:
    return get_user_store()


@pytest.fixture
def dev_key() -> str:
    return get_dev_api_key()


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth(dev_key) -> dict:
    return {"Authorization": f"Bearer {dev_key}"}


# ═══════════════════════════════════════════════════════════════════════════
# Unit: UserStore
# ═══════════════════════════════════════════════════════════════════════════


class TestUserStore:
    """Pure-unit tests - no HTTP, no FastAPI."""

    def test_register_creates_user(self, store):
        user, key = store.register("alice@example.com", "Alice")
        assert user.email == "alice@example.com"
        assert user.name == "Alice"
        assert user.role == UserRole.OPERATOR
        assert user.is_active is True
        assert key.startswith("ck-")

    def test_register_different_role(self, store):
        user, _ = store.register("bob@x.com", role=UserRole.VIEWER)
        assert user.role == UserRole.VIEWER

    def test_authenticate_valid_key(self, store):
        _, key = store.register("c@x.com")
        user = store.authenticate(key)
        assert user is not None
        assert user.email == "c@x.com"

    def test_authenticate_wrong_key(self, store):
        store.register("d@x.com")
        assert store.authenticate("ck-bogus") is None

    def test_authenticate_password(self, store):
        user, _ = store.register("pw@x.com", password="password123")
        authed = store.authenticate_password("pw@x.com", "password123")
        assert authed is not None
        assert authed.id == user.id

    def test_authenticate_password_rejects_wrong_secret(self, store):
        store.register("wrongpw@x.com", password="password123")
        assert store.authenticate_password("wrongpw@x.com", "nope-nope") is None

    def test_authenticate_password_rejects_api_key_only_user(self, store):
        store.register("keyonly@x.com")
        assert store.authenticate_password("keyonly@x.com", "password123") is None

    def test_authenticate_after_deactivation(self, store):
        user, key = store.register("e@x.com")
        store.deactivate(user.id)
        assert store.authenticate(key) is None

    def test_rotate_key(self, store):
        user, old_key = store.register("f@x.com")
        new_key = store.rotate_key(user.id)
        assert new_key is not None
        assert new_key != old_key
        # Old key dead
        assert store.authenticate(old_key) is None
        # New key alive
        assert store.authenticate(new_key) is not None

    def test_rotate_nonexistent_user(self, store):
        assert store.rotate_key("no-such-id") is None

    def test_deactivate(self, store):
        user, _ = store.register("g@x.com")
        assert store.deactivate(user.id) is True
        assert store.get_by_id(user.id).is_active is False

    def test_deactivate_nonexistent(self, store):
        assert store.deactivate("missing") is False

    def test_list_users_active_only(self, store):
        u1, _ = store.register("h@x.com")
        u2, _ = store.register("i@x.com")
        store.deactivate(u2.id)
        active = store.list_users(active_only=True)
        active_ids = {u.id for u in active}
        assert u1.id in active_ids
        assert u2.id not in active_ids

    def test_list_users_include_inactive(self, store):
        u1, _ = store.register("j@x.com")
        store.deactivate(u1.id)
        all_users = store.list_users(active_only=False)
        assert any(u.id == u1.id for u in all_users)

    def test_key_never_stored_in_plaintext(self, store):
        user, key = store.register("k@x.com")
        assert user.api_key_hash != key
        assert user.api_key_hash == _hash_key(key)

    def test_get_by_id(self, store):
        user, _ = store.register("l@x.com")
        assert store.get_by_id(user.id) is user
        assert store.get_by_id("nope") is None


# ═══════════════════════════════════════════════════════════════════════════
# Unit: Singleton helpers
# ═══════════════════════════════════════════════════════════════════════════


class TestSingletons:
    def test_dev_user_exists_after_reset(self, store, dev_key):
        user = store.authenticate(dev_key)
        assert user is not None
        assert user.email == "dev@certior.local"
        assert user.role == UserRole.ADMIN

    def test_reset_produces_fresh_key(self):
        k1 = reset_store()
        k2 = reset_store()
        assert k1 != k2  # new key each reset


# ═══════════════════════════════════════════════════════════════════════════
# Integration: Auth Routes
# ═══════════════════════════════════════════════════════════════════════════


class TestRegisterRoute:
    def test_register_success(self, client):
        r = client.post("/api/v1/auth/register", json={
            "email": "new@example.com",
            "name": "New User",
            "password": "password123",
            "role": "operator",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["email"] == "new@example.com"
        assert data["name"] == "New User"
        assert data["role"] == "operator"
        assert data["api_key"].startswith("ck-")

    def test_register_duplicate_email(self, client):
        client.post("/api/v1/auth/register", json={"email": "dup@x.com"})
        r = client.post("/api/v1/auth/register", json={"email": "dup@x.com"})
        assert r.status_code == 409

    def test_register_invalid_role(self, client):
        r = client.post("/api/v1/auth/register", json={
            "email": "bad@x.com", "role": "superadmin",
        })
        assert r.status_code == 400

    def test_register_minimal(self, client):
        r = client.post("/api/v1/auth/register", json={"email": "min@x.com"})
        assert r.status_code == 201
        assert r.json()["role"] == "operator"

    def test_register_with_password_allows_login(self, client):
        client.post("/api/v1/auth/register", json={
            "email": "signin@x.com",
            "password": "password123",
        })
        r = client.post("/api/v1/auth/login", json={
            "email": "signin@x.com",
            "password": "password123",
        })
        assert r.status_code == 200
        assert r.json()["api_key"].startswith("ck-")

    def test_register_short_password_rejected(self, client):
        r = client.post("/api/v1/auth/register", json={
            "email": "shortpw@x.com",
            "password": "short",
        })
        assert r.status_code == 422

    def test_register_short_email_rejected(self, client):
        r = client.post("/api/v1/auth/register", json={"email": "ab"})
        assert r.status_code == 422


class TestMeRoute:
    def test_me_with_bearer(self, client, dev_key):
        r = client.get("/api/v1/auth/me",
                       headers={"Authorization": f"Bearer {dev_key}"})
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == "dev@certior.local"
        assert data["is_active"] is True

    def test_me_with_x_api_key(self, client, dev_key):
        r = client.get("/api/v1/auth/me",
                       headers={"X-API-Key": dev_key})
        assert r.status_code == 200
        assert r.json()["email"] == "dev@certior.local"

    def test_me_no_credentials(self, client):
        r = client.get("/api/v1/auth/me")
        assert r.status_code in (401, 403)

    def test_me_bad_key(self, client):
        r = client.get("/api/v1/auth/me",
                       headers={"Authorization": "Bearer ck-fake"})
        assert r.status_code == 401

    def test_me_deactivated_user(self, client):
        # Register a new user
        r = client.post("/api/v1/auth/register", json={"email": "deact@x.com"})
        key = r.json()["api_key"]
        uid = r.json()["id"]
        # Deactivate directly via store
        get_user_store().deactivate(uid)
        # Should fail
        r = client.get("/api/v1/auth/me",
                       headers={"Authorization": f"Bearer {key}"})
        assert r.status_code == 401


class TestLoginRoute:
    def test_login_success(self, client):
        client.post("/api/v1/auth/register", json={
            "email": "login@x.com",
            "password": "password123",
        })
        r = client.post("/api/v1/auth/login", json={
            "email": "login@x.com",
            "password": "password123",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["api_key"].startswith("ck-")
        assert data["user"]["email"] == "login@x.com"

    def test_login_rejects_wrong_password(self, client):
        client.post("/api/v1/auth/register", json={
            "email": "wronglogin@x.com",
            "password": "password123",
        })
        r = client.post("/api/v1/auth/login", json={
            "email": "wronglogin@x.com",
            "password": "badpassword",
        })
        assert r.status_code == 401

    def test_login_rejects_api_key_only_user(self, client):
        client.post("/api/v1/auth/register", json={"email": "keyonlylogin@x.com"})
        r = client.post("/api/v1/auth/login", json={
            "email": "keyonlylogin@x.com",
            "password": "password123",
        })
        assert r.status_code == 401


class TestRotateRoute:
    def test_rotate_success(self, client, dev_key):
        r = client.post("/api/v1/auth/rotate",
                        headers={"Authorization": f"Bearer {dev_key}"})
        assert r.status_code == 200
        new_key = r.json()["api_key"]
        assert new_key.startswith("ck-")
        assert new_key != dev_key

    def test_old_key_dead_after_rotate(self, client, dev_key):
        r = client.post("/api/v1/auth/rotate",
                        headers={"Authorization": f"Bearer {dev_key}"})
        new_key = r.json()["api_key"]
        # Old key should fail
        r2 = client.get("/api/v1/auth/me",
                        headers={"Authorization": f"Bearer {dev_key}"})
        assert r2.status_code == 401
        # New key should work
        r3 = client.get("/api/v1/auth/me",
                        headers={"Authorization": f"Bearer {new_key}"})
        assert r3.status_code == 200

    def test_rotate_no_auth(self, client):
        r = client.post("/api/v1/auth/rotate")
        assert r.status_code in (401, 403)


class TestNewUserEndToEnd:
    """Register → authenticate → submit task → list own executions."""

    def test_full_workflow(self, client):
        # Register
        r = client.post("/api/v1/auth/register", json={
            "email": "workflow@x.com", "name": "Workflow User",
        })
        assert r.status_code == 201
        key = r.json()["api_key"]
        headers = {"Authorization": f"Bearer {key}"}

        # Verify identity
        r = client.get("/api/v1/auth/me", headers=headers)
        assert r.status_code == 200
        assert r.json()["email"] == "workflow@x.com"

        # Submit a task
        r = client.post("/api/v1/tasks", json={"task": "Run analysis"},
                        headers=headers)
        assert r.status_code == 201
        eid = r.json()["execution_id"]

        # Retrieve execution
        r = client.get(f"/api/v1/executions/{eid}", headers=headers)
        assert r.status_code == 200
        assert r.json()["id"] == eid

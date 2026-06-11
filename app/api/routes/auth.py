"""
Authentication and authorization for the Certior API.

Provides:
  - API-key authentication (``Authorization: Bearer <key>`` or ``X-API-Key``)
  - ``get_current_user`` FastAPI dependency for protected routes
  - In-memory ``UserStore`` (swap for database in production)
  - Role-based access control helpers

Routes:
  POST /api/v1/auth/register  - create a new user + API key
  POST /api/v1/auth/rotate    - rotate the caller's API key
  GET  /api/v1/auth/me        - inspect the authenticated user
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Security, Query
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------

class UserRole(str, Enum):
    """Coarse-grained role for authorization decisions.

    The set was extended to cover the read-only and approval roles
    referenced by ``app.api.routes.releases``:

    * ``AUDITOR`` - read-only access plus audit-trail visibility.
    * ``APPROVER`` - may promote a release between environments.
    * ``POLICY_AUTHOR`` - may edit policy fixtures and request reviews.
    """
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    AUDITOR = "auditor"
    APPROVER = "approver"
    POLICY_AUTHOR = "policy_author"


@dataclass
class User:
    """An authenticated API user."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    email: str = ""
    name: str = ""
    role: UserRole = UserRole.OPERATOR
    api_key_hash: str = ""
    password_salt: str = ""
    password_hash: str = ""
    created_at: float = field(default_factory=time.time)
    is_active: bool = True
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role.value,
            "created_at": self.created_at,
            "is_active": self.is_active,
        }

    def to_record(self) -> Dict:
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role.value,
            "api_key_hash": self.api_key_hash,
            "password_salt": self.password_salt,
            "password_hash": self.password_hash,
            "created_at": self.created_at,
            "is_active": self.is_active,
            "metadata": self.metadata,
        }

    @staticmethod
    def from_record(record: Dict) -> "User":
        return User(
            id=record.get("id", str(uuid.uuid4())),
            email=record.get("email", ""),
            name=record.get("name", ""),
            role=UserRole(record.get("role", UserRole.OPERATOR.value)),
            api_key_hash=record.get("api_key_hash", ""),
            password_salt=record.get("password_salt", ""),
            password_hash=record.get("password_hash", ""),
            created_at=float(record.get("created_at", time.time())),
            is_active=bool(record.get("is_active", True)),
            metadata=record.get("metadata", {}),
        )


# ---------------------------------------------------------------------------
# User store
# ---------------------------------------------------------------------------

def _hash_key(api_key: str) -> str:
    """SHA-256 hash of a plaintext API key (never store raw keys)."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def _hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Derive a password hash using PBKDF2-HMAC-SHA256."""
    salt_hex = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        bytes.fromhex(salt_hex),
        120_000,
    ).hex()
    return salt_hex, digest


def _verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """Return True when the supplied password matches the stored hash."""
    if not salt or not expected_hash:
        return False
    _, digest = _hash_password(password, salt)
    return secrets.compare_digest(digest, expected_hash)


def _default_store_path() -> Path:
    root = Path(__file__).resolve().parents[3]
    default_path = root / ".certior" / "auth-users.json"
    configured = os.environ.get("CERTIOR_AUTH_STORE_PATH")
    return Path(configured).expanduser() if configured else default_path


class UserStore:
    """
    In-memory user registry.

    Production would back this with PostgreSQL / Redis and add rate
    limiting, key expiry, and audit logging.
    """

    def __init__(self, storage_path: Optional[Path | str] = None) -> None:
        self._users_by_id: Dict[str, User] = {}
        self._key_to_user_id: Dict[str, str] = {}  # hash → user.id
        self._email_to_user_id: Dict[str, str] = {}
        self._storage_path = Path(storage_path).expanduser() if storage_path else None
        self._load()

    def _remember_user(self, user: User) -> None:
        self._users_by_id[user.id] = user
        if user.api_key_hash:
            self._key_to_user_id[user.api_key_hash] = user.id
        if user.email:
            self._email_to_user_id[user.email.lower()] = user.id

    def _load(self) -> None:
        if not self._storage_path or not self._storage_path.exists():
            return
        try:
            payload = json.loads(self._storage_path.read_text())
        except (OSError, json.JSONDecodeError):
            return

        for record in payload.get("users", []):
            try:
                self._remember_user(User.from_record(record))
            except ValueError:
                continue

    def _save(self) -> None:
        if not self._storage_path:
            return
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "users": [user.to_record() for user in self._users_by_id.values()],
            "saved_at": time.time(),
        }
        temp_path = self._storage_path.with_suffix(f"{self._storage_path.suffix}.tmp")
        temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        temp_path.replace(self._storage_path)

    # -- mutators --

    def register(
        self,
        email: str,
        name: str = "",
        role: UserRole = UserRole.OPERATOR,
        password: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> tuple[User, str]:
        """Create a user and return ``(user, plaintext_api_key)``."""
        api_key = f"ck-{secrets.token_urlsafe(32)}"
        key_hash = _hash_key(api_key)
        password_salt, password_hash = _hash_password(password) if password else ("", "")

        user = User(
            email=email,
            name=name or email,
            role=role,
            api_key_hash=key_hash,
            password_salt=password_salt,
            password_hash=password_hash,
            metadata=metadata or {},
        )
        self._remember_user(user)
        self._save()
        return user, api_key

    def rotate_key(self, user_id: str) -> Optional[str]:
        """Revoke the old key and issue a new one.  Returns the new plaintext key."""
        user = self._users_by_id.get(user_id)
        if user is None:
            return None
        # Revoke old mapping
        self._key_to_user_id.pop(user.api_key_hash, None)
        # Issue new key
        api_key = f"ck-{secrets.token_urlsafe(32)}"
        key_hash = _hash_key(api_key)
        user.api_key_hash = key_hash
        self._key_to_user_id[key_hash] = user.id
        self._save()
        return api_key

    def deactivate(self, user_id: str) -> bool:
        user = self._users_by_id.get(user_id)
        if user is None:
            return False
        user.is_active = False
        self._key_to_user_id.pop(user.api_key_hash, None)
        self._save()
        return True

    # -- queries --

    def get_by_id(self, user_id: str) -> Optional[User]:
        return self._users_by_id.get(user_id)

    def get_by_email(self, email: str) -> Optional[User]:
        user_id = self._email_to_user_id.get(email.lower())
        if not user_id:
            return None
        return self._users_by_id.get(user_id)

    def authenticate(self, api_key: str) -> Optional[User]:
        """Return the ``User`` matching a plaintext API key, or ``None``."""
        key_hash = _hash_key(api_key)
        user_id = self._key_to_user_id.get(key_hash)
        if user_id is None:
            return None
        user = self._users_by_id.get(user_id)
        if user and user.is_active:
            return user
        return None

    def authenticate_password(self, email: str, password: str) -> Optional[User]:
        user = self.get_by_email(email)
        if user is None or not user.is_active:
            return None
        if not _verify_password(password, user.password_salt, user.password_hash):
            return None
        return user

    def list_users(self, active_only: bool = True) -> List[User]:
        users = list(self._users_by_id.values())
        if active_only:
            users = [u for u in users if u.is_active]
        return users


# ---------------------------------------------------------------------------
# Singleton store + default development user
# ---------------------------------------------------------------------------

_store = UserStore(storage_path=_default_store_path())
_DEV_API_KEY: Optional[str] = None


def _ensure_dev_user() -> None:
    """Create a default development user on first access."""
    global _DEV_API_KEY
    if _DEV_API_KEY is not None:
        return
    if _store.list_users():
        return

    # The dev user is only auto-created when CERTIOR_ENV=development.
    # Production deployments must register their own admin user.
    import os
    if os.environ.get("CERTIOR_ENV", "development") != "development":
        return

    # Use env var if set (ensures run.sh and server share the same key)
    env_key = os.environ.get("CERTIOR_DEV_API_KEY")
    if env_key:
        key_hash = _hash_key(env_key)
        user = User(
            email="dev@certior.local",
            name="Development User",
            role=UserRole.ADMIN,
            api_key_hash=key_hash,
        )
        _store._remember_user(user)
        _store._save()
        _DEV_API_KEY = env_key
    else:
        user, key = _store.register(
            email="dev@certior.local",
            name="Development User",
            role=UserRole.ADMIN,
        )
        _DEV_API_KEY = key


def get_user_store() -> UserStore:
    """Return the application-wide ``UserStore`` singleton."""
    _ensure_dev_user()
    return _store


def get_dev_api_key() -> Optional[str]:
    """Return the auto-generated dev API key (available only in dev mode)."""
    _ensure_dev_user()
    return _DEV_API_KEY


def reset_store() -> str:
    """
    Reset the singleton store and recreate the dev user.

    Returns the new dev API key.  Intended for test isolation - call
    this in a ``pytest`` fixture to guarantee a clean slate.
    """
    global _store, _DEV_API_KEY
    _store = UserStore(storage_path=None)
    _DEV_API_KEY = None
    _ensure_dev_user()
    return _DEV_API_KEY  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# FastAPI authentication dependencies
# ---------------------------------------------------------------------------

_bearer_scheme = HTTPBearer(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_current_user(
    request: Request,
    bearer: Optional[HTTPAuthorizationCredentials] = Security(_bearer_scheme),
    x_api_key: Optional[str] = Security(_api_key_header),
) -> User:
    """
    FastAPI dependency that resolves the authenticated user.

    Accepts credentials via:
      1. ``Authorization: Bearer <api_key>``
      2. ``X-API-Key: <api_key>``
      3. ``?api_key=<api_key>`` (query param)

    Raises 401 if no valid credential is found, 403 if the user is
    deactivated.
    """
    store = get_user_store()

    api_key: Optional[str] = None
    if bearer and bearer.credentials:
        api_key = bearer.credentials
    elif x_api_key:
        api_key = x_api_key
    elif "api_key" in request.query_params:
        api_key = request.query_params["api_key"]

    if api_key is None:
        raise HTTPException(
            status_code=401,
            detail="Missing API key.  Supply via Authorization: Bearer <key> or X-API-Key header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
        raise HTTPException(
            status_code=401,
            detail="Missing API key.  Supply via Authorization: Bearer <key> or X-API-Key header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = store.authenticate(api_key)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated.")

    return user


def require_role(*roles: UserRole):
    """
    Factory for a dependency that enforces role-based access.

    Usage::

        @router.delete("/users/{uid}", dependencies=[Depends(require_role(UserRole.ADMIN))])
        async def delete_user(uid: str): ...
    """
    async def _check(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of: {[r.value for r in roles]}",
            )
        return user
    return _check


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=3, description="User email / identifier")
    name: str = Field("", description="Display name")
    password: Optional[str] = Field(None, min_length=8, description="Password for email sign-in")
    organization: str = Field("", description="Optional organization name")
    role: str = Field("operator", description="admin | operator | viewer")


class RegisterResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    api_key: str  # returned only once, at registration


class RotateKeyResponse(BaseModel):
    api_key: str  # returned only once


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, description="User email / identifier")
    password: str = Field(..., min_length=8, description="Password for email sign-in")


class LoginResponse(BaseModel):
    api_key: str
    user: UserResponse


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    created_at: float
    is_active: bool


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(body: RegisterRequest):
    """
    Register a new API user and return their API key.

    The key is shown **only once** - store it securely.
    """
    store = get_user_store()

    # Prevent duplicate emails
    for u in store.list_users(active_only=False):
        if u.email == body.email:
            raise HTTPException(status_code=409, detail="Email already registered.")

    try:
        role = UserRole(body.role)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role.  Choose from: {[r.value for r in UserRole]}",
        )

    user, api_key = store.register(
        email=body.email,
        name=body.name,
        role=role,
        password=body.password,
        metadata={"organization": body.organization} if body.organization else {},
    )

    return RegisterResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role.value,
        api_key=api_key,
    )


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest):
    """Authenticate with email/password and issue a fresh API key."""
    store = get_user_store()
    user = store.authenticate_password(body.email, body.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    api_key = store.rotate_key(user.id)
    if api_key is None:
        raise HTTPException(status_code=404, detail="User not found")

    return LoginResponse(
        api_key=api_key,
        user=UserResponse(
            id=user.id,
            email=user.email,
            name=user.name,
            role=user.role.value,
            created_at=user.created_at,
            is_active=user.is_active,
        ),
    )


@router.post("/rotate", response_model=RotateKeyResponse)
async def rotate_key(user: User = Depends(get_current_user)):
    """
    Rotate the caller's API key.

    The old key is revoked immediately.  The new key is shown **only once**.
    """
    store = get_user_store()
    new_key = store.rotate_key(user.id)
    if new_key is None:
        raise HTTPException(status_code=404, detail="User not found")
    return RotateKeyResponse(api_key=new_key)


@router.get("/me", response_model=UserResponse)
async def whoami(user: User = Depends(get_current_user)):
    """Return the authenticated user's profile."""
    return UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role.value,
        created_at=user.created_at,
        is_active=user.is_active,
    )

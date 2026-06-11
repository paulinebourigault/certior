"""HTTP authentication primitives.

API keys and the JWT signing secret are loaded from environment variables.
In ``CERTIOR_ENV=development`` mode (the default) the JWT secret falls back to
a fresh per-process value and the API-key set falls back to empty so unit
tests can supply their own keys via ``CERTIOR_API_KEYS_JSON``. In any other
environment both variables are required and missing them is a fatal startup
error - the server refuses to run with placeholder credentials.
"""

import json
import os
import secrets as _secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

# auto_error=False so missing credentials fall through to the next source
# rather than raising 403 immediately - lets verify_api_key accept either
# Authorization: Bearer <key> OR X-API-Key: <key>, matching the convention
# the rest of the API surface (get_current_user in routes/auth.py) uses.
_bearer_security = HTTPBearer(auto_error=False)
_x_api_key = APIKeyHeader(name="X-API-Key", auto_error=False)

# Backwards-compat alias; some routes still import `security`.
security = _bearer_security


def _is_dev() -> bool:
    return os.environ.get("CERTIOR_ENV", "development") == "development"


def _load_root_secret() -> str:
    """Return the JWT signing secret.

    Production deployments must set ``CERTIOR_KMS_ROOT_SECRET``. In
    development the secret is generated per process; tokens issued in one
    process cannot be verified by another.
    """
    secret = os.environ.get("CERTIOR_KMS_ROOT_SECRET")
    if secret:
        return secret
    if not _is_dev():
        raise RuntimeError(
            "CERTIOR_KMS_ROOT_SECRET must be set when CERTIOR_ENV != development"
        )
    return _secrets.token_urlsafe(32)


def _load_api_keys() -> dict[str, str]:
    """Return the configured API-key set.

    Resolution order:

    1. If ``CERTIOR_API_KEYS_JSON`` is set, parse it as a JSON object mapping
       API key to human-readable label. This is the canonical input and the
       only one production deployments may rely on.
    2. In development, if ``CERTIOR_API_KEYS_JSON`` is unset but
       ``CERTIOR_DEV_API_KEY`` is set (the convention used by ``run.sh``
       so the dev user and the orchestrator-facing API share a key),
       register that single key under the label ``"dev"``.
    3. In development with neither variable set, return an empty map;
       requests are rejected with 401 until a key is configured.
    4. In any non-development environment without
       ``CERTIOR_API_KEYS_JSON``, refuse to start with a ``RuntimeError``.
    """
    raw = os.environ.get("CERTIOR_API_KEYS_JSON", "")
    if not raw:
        if not _is_dev():
            raise RuntimeError(
                "CERTIOR_API_KEYS_JSON must be set when CERTIOR_ENV != development"
            )
        dev_key = os.environ.get("CERTIOR_DEV_API_KEY")
        if dev_key:
            return {dev_key: "dev"}
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"CERTIOR_API_KEYS_JSON is not valid JSON: {exc}"
        ) from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("CERTIOR_API_KEYS_JSON must decode to an object")
    return {str(k): str(v) for k, v in parsed.items()}


CERTIOR_ROOT_SECRET = _load_root_secret()
VALID_API_KEYS = _load_api_keys()


def verify_api_key(
    bearer: HTTPAuthorizationCredentials | None = Security(_bearer_security),
    x_api_key: str | None = Security(_x_api_key),
) -> str:
    """Validate an API key supplied via Authorization: Bearer or X-API-Key.

    Accepts either header to match the convention used elsewhere in the API
    (get_current_user in app/api/routes/auth.py). Bearer takes precedence
    when both are present.
    """
    token: str | None = None
    if bearer and bearer.credentials:
        token = bearer.credentials
    elif x_api_key:
        token = x_api_key

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Supply via Authorization: Bearer <key> or X-API-Key header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if token not in VALID_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


def generate_signed_capability_token(agent_id: str, permissions: list[str]) -> str:
    """Generate an HS256-signed JWT mapping an agent to its capability set.

    Tokens expire after five minutes.
    """
    payload = {
        "agent_id": agent_id,
        "permissions": permissions,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    return jwt.encode(payload, CERTIOR_ROOT_SECRET, algorithm="HS256")

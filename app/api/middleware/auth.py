"""Authentication middleware for third-party SDK requests."""

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.api.auth import VALID_API_KEYS

_bearer_security = HTTPBearer(auto_error=False)
_x_api_key = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_claw_request(
    bearer: HTTPAuthorizationCredentials | None = Security(_bearer_security),
    x_api_key: str | None = Security(_x_api_key),
) -> dict:
    """Validate that the request bears a configured SDK API key.

    Accepts either ``Authorization: Bearer <key>`` or ``X-API-Key: <key>``
    to match the convention used elsewhere in the API. Returns a dict
    with the resolved client label drawn from ``CERTIOR_API_KEYS_JSON``.
    Raises 401 if the token is missing or unrecognised.
    """
    token: str | None = None
    if bearer and bearer.credentials:
        if bearer.scheme != "Bearer":
            raise HTTPException(status_code=403, detail="Invalid auth scheme")
        token = bearer.credentials
    elif x_api_key:
        token = x_api_key

    if not token or token not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail="Unauthorized SDK client")

    return {"client_id": VALID_API_KEYS[token]}

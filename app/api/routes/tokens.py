"""
POST /api/v1/tokens - issue a capability token.
GET  /api/v1/tokens/{id} - inspect a token.
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from agentsafe.capabilities.tokens import CapabilityToken

router = APIRouter(prefix="/api/v1", tags=["tokens"])

# In-memory token registry (production would use a database)
_tokens: dict[str, CapabilityToken] = {}


class TokenRequest(BaseModel):
    agent_id: str = "default"
    permissions: list[str] = Field(default_factory=lambda: ["*"])
    budget_cents: int = Field(10000, ge=0)
    expires_in_seconds: Optional[int] = None


class TokenResponse(BaseModel):
    id: str
    agent_id: str
    permissions: list[str]
    budget_cents: int
    budget_remaining_cents: int
    valid: bool


@router.post("/tokens", response_model=TokenResponse, status_code=201)
async def issue_token(body: TokenRequest):
    """Issue a new capability token."""
    import time

    expires = None
    if body.expires_in_seconds:
        expires = time.time() + body.expires_in_seconds

    token = CapabilityToken(
        agent_id=body.agent_id,
        permissions=body.permissions,
        budget_cents=body.budget_cents,
        budget_remaining_cents=body.budget_cents,
        expires_at=expires,
    )
    _tokens[token.id] = token

    return TokenResponse(
        id=token.id,
        agent_id=token.agent_id,
        permissions=token.permissions,
        budget_cents=token.budget_cents,
        budget_remaining_cents=token.budget_remaining_cents,
        valid=token.is_valid(),
    )


@router.get("/tokens/{token_id}", response_model=TokenResponse)
async def get_token(token_id: str):
    """Inspect a capability token."""
    token = _tokens.get(token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")

    return TokenResponse(
        id=token.id,
        agent_id=token.agent_id,
        permissions=token.permissions,
        budget_cents=token.budget_cents,
        budget_remaining_cents=token.budget_remaining_cents,
        valid=token.is_valid(),
    )

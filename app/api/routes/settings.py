"""
GET  /api/v1/settings/providers  - list available LLM providers + active config
POST /api/v1/settings/provider   - switch the active provider at runtime
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel, Field

from .auth import get_current_user, User

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


# ── Response models ───────────────────────────────────────────────────

class ProviderInfo(BaseModel):
    id: str = Field(description="Provider identifier: 'anthropic' or 'openai'")
    name: str = Field(description="Human-readable name")
    available: bool = Field(description="Whether an API key is configured")
    active: bool = Field(description="Whether this is the current default provider")
    model: str = Field(description="Current model for this provider")
    models: List[str] = Field(description="Available models for this provider")


class ProvidersResponse(BaseModel):
    providers: List[ProviderInfo]
    active_provider: Optional[str] = None
    mode: str = Field(description="'agentic' or 'legacy'")


class SwitchProviderRequest(BaseModel):
    provider: str = Field(
        ...,
        pattern="^(anthropic|openai)$",
        description="Provider to switch to: 'anthropic' or 'openai'",
    )
    model: Optional[str] = Field(
        None,
        description="Model override (e.g. 'gpt-4o-mini', 'claude-haiku-4-5-20251001')",
    )


class SwitchProviderResponse(BaseModel):
    provider: str
    model: str
    message: str


class ProviderValidationRequest(BaseModel):
    provider: str = Field(..., pattern="^(anthropic|openai)$")
    model: Optional[str] = Field(None, description="Model to validate")
    api_key: str = Field(..., min_length=8, description="Provider API key")


class ProviderValidationResponse(BaseModel):
    provider: str
    model: str
    valid: bool
    status: str
    message: str


# ── Provider metadata ────────────────────────────────────────────────

PROVIDER_MODELS = {
    "anthropic": {
        "name": "Anthropic (Claude)",
        "env_key": "ANTHROPIC_API_KEY",
        "default_model": "claude-sonnet-4-20250514",
        "models": [
            "claude-sonnet-4-20250514",
            "claude-haiku-4-5-20251001",
            "claude-opus-4-20250514",
            "claude-sonnet-4-5-20250929",
        ],
    },
    "openai": {
        "name": "OpenAI (GPT)",
        "env_key": "OPENAI_API_KEY",
        "default_model": "gpt-4o",
        "models": [
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
            "o3-mini",
            "o4-mini",
            "gpt-4.1",
            "o1",
        ],
    },
}


def _classify_provider_error(exc: Exception) -> tuple[str, str]:
    message = str(exc).strip() or exc.__class__.__name__
    lowered = message.lower()
    if any(keyword in lowered for keyword in ("credit balance", "billing", "quota", "insufficient_quota", "payment", "rate_limit")):
        return "billing_issue", message
    if any(keyword in lowered for keyword in ("api key", "authentication", "unauthorized", "invalid x-api-key", "invalid_api_key", "401", "403")):
        return "invalid_key", message
    return "error", message


async def _probe_provider(provider: str, model: str, api_key: str) -> None:
    from agentsafe.llm.config import LLMConfig

    config = LLMConfig(provider=provider, model=model, api_key=api_key, max_tokens=8, temperature=0.0)
    messages = [{"role": "user", "content": "Reply with OK."}]

    if provider == "openai":
        from agentsafe.llm.openai_client import OpenAIClient

        client = OpenAIClient(config)
    else:
        from agentsafe.llm.client import AnthropicClient

        client = AnthropicClient(config)

    await client.send(messages)
    close = getattr(client, "close", None)
    if callable(close):
        await close()


# ── Routes ───────────────────────────────────────────────────────────

@router.get("/providers", response_model=ProvidersResponse)
async def list_providers(
    request: Request,
    user: User = Depends(get_current_user),
):
    """List available LLM providers and their configuration status."""
    llm_config = request.app.state.llm_config
    executor = request.app.state.executor

    active_provider = None
    if llm_config and llm_config.is_configured:
        active_provider = llm_config.provider

    providers = []
    for pid, meta in PROVIDER_MODELS.items():
        has_key = bool(os.environ.get(meta["env_key"]))

        # Determine current model for this provider
        current_model = meta["default_model"]
        if llm_config and llm_config.provider == pid:
            current_model = llm_config.model

        providers.append(ProviderInfo(
            id=pid,
            name=meta["name"],
            available=has_key,
            active=(pid == active_provider),
            model=current_model,
            models=meta["models"],
        ))

    return ProvidersResponse(
        providers=providers,
        active_provider=active_provider,
        mode=executor.mode,
    )


@router.post("/provider", response_model=SwitchProviderResponse)
async def switch_provider(
    body: SwitchProviderRequest,
    request: Request,
    user: User = Depends(get_current_user),
):
    """
    Switch the active LLM provider at runtime.

    Requires the target provider's API key to be set in the environment.
    This changes the default for all new tasks - existing running tasks
    are unaffected.
    """
    meta = PROVIDER_MODELS.get(body.provider)
    if not meta:
        raise HTTPException(400, f"Unknown provider: {body.provider}")

    env_key = meta["env_key"]
    if not os.environ.get(env_key):
        raise HTTPException(
            400,
            f"{meta['name']} API key not configured. "
            f"Set {env_key} environment variable and restart.",
        )

    # Validate model
    model = body.model or meta["default_model"]
    if model not in meta["models"]:
        # Allow custom models (user may use a fine-tuned model)
        log.warning(
            "Model %r not in known list for %s - allowing anyway",
            model, body.provider,
        )

    # Rebuild LLM config
    from agentsafe.llm.config import LLMConfig
    new_config = LLMConfig(
        provider=body.provider,
        model=model,
        api_key=os.environ.get(env_key),
    )

    # Update app state
    request.app.state.llm_config = new_config

    # Update executor
    executor = request.app.state.executor
    executor.llm_config = new_config
    # Reset cached client so next execution uses new provider
    if hasattr(executor, '_llm_client'):
        executor._llm_client = None

    log.info(
        "Provider switched: %s → %s (model=%s) by user=%s",
        getattr(request.app.state, '_prev_provider', 'unknown'),
        body.provider, model, user.id,
    )

    return SwitchProviderResponse(
        provider=body.provider,
        model=model,
        message=f"Switched to {meta['name']} ({model})",
    )


@router.post("/provider/validate", response_model=ProviderValidationResponse)
async def validate_provider(
    body: ProviderValidationRequest,
    request: Request,
    user: User = Depends(get_current_user),
):
    meta = PROVIDER_MODELS.get(body.provider)
    if not meta:
        raise HTTPException(400, f"Unknown provider: {body.provider}")

    model = body.model or meta["default_model"]
    try:
        await _probe_provider(body.provider, model, body.api_key)
    except Exception as exc:
        status, message = _classify_provider_error(exc)
        return ProviderValidationResponse(
            provider=body.provider,
            model=model,
            valid=False,
            status=status,
            message=message,
        )

    return ProviderValidationResponse(
        provider=body.provider,
        model=model,
        valid=True,
        status="ready",
        message="Connection verified",
    )

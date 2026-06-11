"""
LLM client factory for Certior agents.
=======================================

Resolves the LLM provider from configuration and returns the
appropriate client instance.  The rest of the codebase should
use ``create_llm_client()`` instead of importing provider-specific
classes directly.

Provider resolution order:

1. Explicit ``config.provider`` setting
2. ``CERTIOR_LLM_PROVIDER`` environment variable
3. Auto-detect from available API keys:
   - ``ANTHROPIC_API_KEY`` → Anthropic
   - ``OPENAI_API_KEY``    → OpenAI
4. Raise ``ValueError`` if nothing is configured
"""
from __future__ import annotations

import logging
import os
from typing import Union

from .config import LLMConfig

log = logging.getLogger(__name__)

# Type alias - both clients share the same interface
LLMClient = Union["AnthropicClient", "OpenAIClient"]


def create_llm_client(config: LLMConfig) -> LLMClient:
    """
    Create an LLM client from configuration.

    Args:
        config: LLM configuration with provider, model, and API key.

    Returns:
        An ``AnthropicClient`` or ``OpenAIClient`` instance.

    Raises:
        ValueError: If the provider is unknown or not configured.
        ImportError: If the provider SDK package is not installed.
    """
    provider = config.provider.lower()

    if provider == "anthropic":
        from .client import AnthropicClient
        log.info("Using Anthropic provider (model=%s)", config.model)
        return AnthropicClient(config)

    elif provider == "openai":
        from .openai_client import OpenAIClient
        log.info("Using OpenAI provider (model=%s)", config.model)
        return OpenAIClient(config)

    else:
        raise ValueError(
            f"Unknown LLM provider: {config.provider!r}.  "
            f"Supported: 'anthropic', 'openai'."
        )


def detect_provider() -> str:
    """
    Auto-detect the best available LLM provider.

    Checks environment variables in priority order.

    Returns:
        Provider name string (``"anthropic"`` or ``"openai"``).

    Raises:
        ValueError: If no provider is configured.
    """
    # Explicit override
    explicit = os.environ.get("CERTIOR_LLM_PROVIDER", "").lower().strip()
    if explicit in ("anthropic", "openai"):
        return explicit

    # Auto-detect from API keys
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"

    if os.environ.get("OPENAI_API_KEY"):
        return "openai"

    raise ValueError(
        "No LLM provider configured.  Set one of:\n"
        "  ANTHROPIC_API_KEY  - for Anthropic (Claude)\n"
        "  OPENAI_API_KEY     - for OpenAI (GPT-4o)\n"
        "  CERTIOR_LLM_PROVIDER=anthropic|openai  - explicit override"
    )


# Default models per provider
PROVIDER_DEFAULTS = {
    "anthropic": {
        "model": "claude-sonnet-4-20250514",
    },
    "openai": {
        "model": "gpt-4o",
    },
}

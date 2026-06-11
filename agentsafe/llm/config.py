"""
LLM client configuration for Certior agents.
=============================================

Supports Anthropic and OpenAI providers with automatic detection.

Environment variables:

  CERTIOR_LLM_PROVIDER    - ``anthropic`` or ``openai`` (auto-detected if unset)
  ANTHROPIC_API_KEY        - Anthropic API key
  OPENAI_API_KEY           - OpenAI API key
  CERTIOR_MODEL            - Model name override
  CERTIOR_MAX_TOKENS       - Max tokens (default: 4096)
  CERTIOR_MAX_TOOL_ROUNDS  - Safety limit on tool rounds (default: 25)
  CERTIOR_SYSTEM_PROMPT    - System prompt override
  CERTIOR_LLM_BASE_URL     - Custom base URL (for Azure OpenAI, local models)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


# Default model per provider
_PROVIDER_DEFAULTS = {
    "anthropic": "claude-sonnet-4-20250514",
    "openai": "gpt-4o",
}


@dataclass
class LLMConfig:
    """
    Configuration for the LLM backing a Certior agent.

    Reads API key from the environment by default so that secrets
    are never hard-coded.  If ``provider`` is ``"auto"`` (the default),
    the provider is detected from available API keys at construction time.
    """
    provider: str = "auto"  # "auto", "anthropic", or "openai"
    model: str = ""
    api_key: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.0
    max_tool_rounds: int = 25  # safety: stop after N tool-use rounds
    system_prompt: Optional[str] = None
    base_url: Optional[str] = None  # for Azure OpenAI or local models

    def __post_init__(self) -> None:
        # ── Resolve provider ──────────────────────────────────────
        if self.provider == "auto":
            self.provider = self._detect_provider()

        provider = self.provider.lower()

        # ── Resolve API key ───────────────────────────────────────
        if self.api_key is None:
            if provider == "anthropic":
                self.api_key = os.environ.get("ANTHROPIC_API_KEY")
            elif provider == "openai":
                self.api_key = os.environ.get("OPENAI_API_KEY")

        # ── Resolve model ─────────────────────────────────────────
        if not self.model:
            self.model = _PROVIDER_DEFAULTS.get(provider, "gpt-4o")

        # ── Resolve base URL ──────────────────────────────────────
        if self.base_url is None:
            self.base_url = os.environ.get("CERTIOR_LLM_BASE_URL")

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    @property
    def provider_display(self) -> str:
        """Human-friendly provider name for UI."""
        names = {
            "anthropic": "Anthropic (Claude)",
            "openai": "OpenAI (GPT)",
        }
        return names.get(self.provider.lower(), self.provider)

    @classmethod
    def from_env(cls, **overrides) -> "LLMConfig":
        """Create config from environment variables with optional overrides.

        Reads:
          CERTIOR_LLM_PROVIDER    - provider name (auto-detected if unset)
          ANTHROPIC_API_KEY       - Anthropic key
          OPENAI_API_KEY          - OpenAI key
          CERTIOR_MODEL           - model name
          CERTIOR_MAX_TOKENS      - max tokens   (default: 4096)
          CERTIOR_MAX_TOOL_ROUNDS - safety limit  (default: 25)
          CERTIOR_SYSTEM_PROMPT   - system prompt
          CERTIOR_LLM_BASE_URL    - custom API base URL
        """
        defaults: dict = {}

        if "provider" not in overrides:
            val = os.environ.get("CERTIOR_LLM_PROVIDER")
            if val:
                defaults["provider"] = val.strip().lower()

        if "model" not in overrides:
            val = os.environ.get("CERTIOR_MODEL")
            if val:
                defaults["model"] = val

        if "max_tokens" not in overrides:
            val = os.environ.get("CERTIOR_MAX_TOKENS")
            if val:
                defaults["max_tokens"] = int(val)

        if "max_tool_rounds" not in overrides:
            val = os.environ.get("CERTIOR_MAX_TOOL_ROUNDS")
            if val:
                defaults["max_tool_rounds"] = int(val)

        if "system_prompt" not in overrides:
            val = os.environ.get("CERTIOR_SYSTEM_PROMPT")
            if val:
                defaults["system_prompt"] = val

        if "base_url" not in overrides:
            val = os.environ.get("CERTIOR_LLM_BASE_URL")
            if val:
                defaults["base_url"] = val

        defaults.update(overrides)
        return cls(**defaults)

    @staticmethod
    def _detect_provider() -> str:
        """Auto-detect provider from available API keys."""
        explicit = os.environ.get("CERTIOR_LLM_PROVIDER", "").lower().strip()
        if explicit in ("anthropic", "openai"):
            return explicit

        if os.environ.get("ANTHROPIC_API_KEY"):
            return "anthropic"

        if os.environ.get("OPENAI_API_KEY"):
            return "openai"

        # Default to anthropic (will fail later if key not set)
        return "anthropic"

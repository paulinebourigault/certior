"""
LLM client for Certior agents.

Provides a thin async interface over the Anthropic Messages API with:
  - Tool-use (function calling) support
  - Automatic retry with exponential back-off
  - Token usage tracking
  - Clean message-history management

This module is deliberately provider-specific (Anthropic) to keep the
abstraction honest.  A future ``openai_client.py`` can share the same
interface if needed.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .config import LLMConfig

log = logging.getLogger(__name__)


# ── Data types for the agent loop ──────────────────────────────────

@dataclass
class ToolCallRequest:
    """An LLM request to invoke a tool."""
    id: str          # tool_use block id
    name: str        # tool name
    input: Dict[str, Any]  # parameters


@dataclass
class LLMResponse:
    """Parsed response from the LLM."""
    text: str = ""
    tool_calls: List[ToolCallRequest] = field(default_factory=list)
    stop_reason: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    raw: Any = None  # the original API response object

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0

    @property
    def is_final(self) -> bool:
        """True when the LLM is done (no more tool calls)."""
        return self.stop_reason == "end_turn" or (
            self.stop_reason != "tool_use" and not self.has_tool_calls
        )


@dataclass
class TokenUsage:
    """Cumulative token usage across a conversation."""
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


# ── Client ─────────────────────────────────────────────────────────

class AnthropicClient:
    """
    Async Anthropic Messages API client with tool-use support.

    Owns a single ``anthropic.AsyncAnthropic`` instance and provides
    a ``send()`` method that accepts the running message history plus
    available tools and returns a parsed ``LLMResponse``.
    """

    def __init__(self, config: Optional[LLMConfig] = None) -> None:
        self.config = config or LLMConfig()
        self._client: Any = None  # lazy init
        self.usage = TokenUsage()
        self._request_count = 0

    def _ensure_client(self) -> Any:
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:
                raise ImportError(
                    "The 'anthropic' package is required.  "
                    "Install it with: pip install anthropic"
                ) from exc

            if not self.config.api_key:
                raise ValueError(
                    "No Anthropic API key found.  Set ANTHROPIC_API_KEY or "
                    "pass api_key in LLMConfig."
                )
            self._client = anthropic.AsyncAnthropic(api_key=self.config.api_key)
        return self._client

    async def send(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        system: Optional[str] = None,
    ) -> LLMResponse:
        """
        Send a message to the Anthropic API and return a parsed response.

        Args:
            messages: Conversation history in Anthropic format.
            tools: Tool schemas (from ToolRegistry.to_anthropic_tools()).
            system: System prompt override.

        Returns:
            Parsed LLMResponse with text, tool_calls, and token counts.

        Raises:
            On unrecoverable API errors after retries.
        """
        client = self._ensure_client()

        kwargs: Dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "messages": messages,
        }

        system_text = system or self.config.system_prompt
        if system_text:
            kwargs["system"] = system_text

        if tools:
            kwargs["tools"] = tools

        if self.config.temperature is not None:
            kwargs["temperature"] = self.config.temperature

        # Retry with exponential back-off
        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                self._request_count += 1
                response = await client.messages.create(**kwargs)
                return self._parse_response(response)
            except Exception as exc:
                last_exc = exc
                err_str = str(exc).lower()
                # Retry on transient errors
                if any(kw in err_str for kw in ("overloaded", "rate_limit", "timeout", "529", "500")):
                    wait = 2 ** attempt
                    log.warning("Anthropic API error (attempt %d), retrying in %ds: %s", attempt + 1, wait, exc)
                    await asyncio.sleep(wait)
                    continue
                raise

        raise last_exc  # type: ignore[misc]

    def _parse_response(self, response: Any) -> LLMResponse:
        """Extract text and tool_calls from an Anthropic API response."""
        text_parts: List[str] = []
        tool_calls: List[ToolCallRequest] = []

        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(ToolCallRequest(
                    id=block.id,
                    name=block.name,
                    input=block.input,
                ))

        # Track usage
        usage = getattr(response, "usage", None)
        input_tokens = getattr(usage, "input_tokens", 0) if usage else 0
        output_tokens = getattr(usage, "output_tokens", 0) if usage else 0
        self.usage.input_tokens += input_tokens
        self.usage.output_tokens += output_tokens

        return LLMResponse(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=response.stop_reason,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            raw=response,
        )

    @property
    def request_count(self) -> int:
        return self._request_count

    async def close(self) -> None:
        """Release the underlying HTTP client."""
        if self._client is not None:
            await self._client.close()
            self._client = None

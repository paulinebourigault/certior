"""
OpenAI-compatible LLM client for Certior agents.
=================================================

Provides the **same async interface** as ``AnthropicClient`` so the
agentic executor doesn't need to change.  Internally translates between
the Anthropic message format (used throughout Certior) and the OpenAI
Chat Completions API format.

Translation map
---------------

+---------------------------+------------------------------------+
| Anthropic (internal)      | OpenAI (wire)                      |
+===========================+====================================+
| ``{"type":"tool_use",     | ``tool_calls[i].function.name``    |
|   "id":…, "name":…,      |   ``.arguments`` (JSON string)     |
|   "input":{…}}``          |                                    |
+---------------------------+------------------------------------+
| ``{"type":"tool_result",  | ``{"role":"tool",                  |
|   "tool_use_id":…,        |   "tool_call_id":…,                |
|   "content":…}``          |   "content":…}``                   |
+---------------------------+------------------------------------+
| ``input_schema``          | ``parameters``                     |
+---------------------------+------------------------------------+
| ``stop_reason:"end_turn"``| ``finish_reason:"stop"``           |
+---------------------------+------------------------------------+

"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from .config import LLMConfig
from .client import LLMResponse, ToolCallRequest, TokenUsage

log = logging.getLogger(__name__)


class OpenAIClient:
    """
    Async OpenAI Chat Completions client with tool-use support.

    Drop-in replacement for ``AnthropicClient``.  Receives messages and
    tool schemas in **Anthropic format** (the internal Certior format)
    and transparently translates them to OpenAI wire format.

    Supports: ``gpt-4o``, ``gpt-4o-mini``, ``gpt-4-turbo``, ``o1``,
    ``o3-mini``, and any model that accepts the Chat Completions ``tools``
    parameter.
    """

    def __init__(self, config: Optional[LLMConfig] = None) -> None:
        self.config = config or LLMConfig(provider="openai")
        self._client: Any = None
        self.usage = TokenUsage()
        self._request_count = 0

    # ── Lazy init ─────────────────────────────────────────────────

    def _ensure_client(self) -> Any:
        if self._client is None:
            try:
                import openai
            except ImportError as exc:
                raise ImportError(
                    "The 'openai' package is required for the OpenAI provider.  "
                    "Install it with:  pip install openai"
                ) from exc

            if not self.config.api_key:
                raise ValueError(
                    "No OpenAI API key found.  Set OPENAI_API_KEY or "
                    "pass api_key in LLMConfig."
                )

            kwargs: Dict[str, Any] = {"api_key": self.config.api_key}
            if self.config.base_url:
                kwargs["base_url"] = self.config.base_url

            self._client = openai.AsyncOpenAI(**kwargs)
        return self._client

    # ── Public API (same signature as AnthropicClient) ────────────

    async def send(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        system: Optional[str] = None,
    ) -> LLMResponse:
        """
        Send messages to OpenAI and return a parsed ``LLMResponse``.

        Args:
            messages: Conversation history **in Anthropic format**.
            tools:    Tool schemas **in Anthropic format**.
            system:   System prompt override.

        Returns:
            Parsed ``LLMResponse`` (same type as AnthropicClient).
        """
        client = self._ensure_client()

        # ── Translate messages ────────────────────────────────────
        oai_messages = self._translate_messages(
            messages,
            system=system or self.config.system_prompt,
        )

        kwargs: Dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "messages": oai_messages,
        }

        if self.config.temperature is not None:
            kwargs["temperature"] = self.config.temperature

        # ── Translate tool schemas ────────────────────────────────
        if tools:
            kwargs["tools"] = self._translate_tools(tools)

        # ── Retry with exponential back-off ───────────────────────
        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                self._request_count += 1
                response = await client.chat.completions.create(**kwargs)
                return self._parse_response(response)
            except Exception as exc:
                last_exc = exc
                err_str = str(exc).lower()
                if any(kw in err_str for kw in (
                    "rate_limit", "timeout", "overloaded",
                    "server_error", "500", "502", "503", "529",
                )):
                    wait = 2 ** attempt
                    log.warning(
                        "OpenAI API error (attempt %d), retrying in %ds: %s",
                        attempt + 1, wait, exc,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise

        raise last_exc  # type: ignore[misc]

    # ── Response parsing ──────────────────────────────────────────

    def _parse_response(self, response: Any) -> LLMResponse:
        """Parse OpenAI ChatCompletion into Certior's LLMResponse."""
        choice = response.choices[0]
        message = choice.message

        # Text
        text = message.content or ""

        # Tool calls
        tool_calls: List[ToolCallRequest] = []
        if message.tool_calls:
            for tc in message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {"raw": tc.function.arguments}

                tool_calls.append(ToolCallRequest(
                    id=tc.id,
                    name=tc.function.name,
                    input=args,
                ))

        # Stop reason mapping
        finish_reason = choice.finish_reason or ""
        stop_reason_map = {
            "stop": "end_turn",
            "tool_calls": "tool_use",
            "length": "max_tokens",
            "content_filter": "end_turn",
        }
        stop_reason = stop_reason_map.get(finish_reason, finish_reason)

        # Usage
        usage = getattr(response, "usage", None)
        input_tokens = getattr(usage, "prompt_tokens", 0) if usage else 0
        output_tokens = getattr(usage, "completion_tokens", 0) if usage else 0
        self.usage.input_tokens += input_tokens
        self.usage.output_tokens += output_tokens

        return LLMResponse(
            text=text,
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            raw=response,
        )

    # ── Format translation: Anthropic → OpenAI ────────────────────

    @staticmethod
    def _translate_messages(
        messages: List[Dict[str, Any]],
        system: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Translate Anthropic-format message history to OpenAI format.

        Key differences handled:

        1. System prompt: Anthropic uses a separate ``system`` param;
           OpenAI uses ``{"role": "system", ...}`` in the messages list.

        2. Assistant content: Anthropic uses a list of typed blocks
           ``[{"type":"text",...}, {"type":"tool_use",...}]``;
           OpenAI uses ``content`` string + ``tool_calls`` list.

        3. Tool results: Anthropic puts them in a user message as
           ``[{"type":"tool_result","tool_use_id":...}]``;
           OpenAI uses separate ``{"role":"tool","tool_call_id":...}``
           messages.
        """
        oai: List[Dict[str, Any]] = []

        # System prompt
        if system:
            oai.append({"role": "system", "content": system})

        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")

            if role == "user":
                # Could be plain string or list of blocks (tool_result)
                if isinstance(content, str):
                    oai.append({"role": "user", "content": content})

                elif isinstance(content, list):
                    # Check if these are tool_result blocks
                    tool_results = [
                        b for b in content
                        if isinstance(b, dict) and b.get("type") == "tool_result"
                    ]
                    text_parts = [
                        b.get("text", "")
                        for b in content
                        if isinstance(b, dict) and b.get("type") == "text"
                    ]

                    # Emit tool results as separate "tool" messages
                    for tr in tool_results:
                        result_content = tr.get("content", "")
                        if isinstance(result_content, list):
                            # Anthropic can nest content blocks
                            result_content = "\n".join(
                                b.get("text", str(b))
                                for b in result_content
                                if isinstance(b, dict)
                            ) or str(result_content)
                        elif not isinstance(result_content, str):
                            result_content = str(result_content)

                        oai.append({
                            "role": "tool",
                            "tool_call_id": tr.get("tool_use_id", ""),
                            "content": result_content,
                        })

                    # Any remaining text
                    if text_parts:
                        oai.append({
                            "role": "user",
                            "content": "\n".join(text_parts),
                        })

                else:
                    oai.append({"role": "user", "content": str(content)})

            elif role == "assistant":
                if isinstance(content, str):
                    oai.append({"role": "assistant", "content": content})

                elif isinstance(content, list):
                    # Extract text and tool_use blocks
                    text_parts = []
                    tool_calls = []

                    for block in content:
                        if not isinstance(block, dict):
                            continue
                        btype = block.get("type", "")

                        if btype == "text":
                            text_parts.append(block.get("text", ""))

                        elif btype == "tool_use":
                            tool_calls.append({
                                "id": block.get("id", str(uuid.uuid4())),
                                "type": "function",
                                "function": {
                                    "name": block.get("name", ""),
                                    "arguments": json.dumps(
                                        block.get("input", {}),
                                        ensure_ascii=False,
                                    ),
                                },
                            })

                    assistant_msg: Dict[str, Any] = {
                        "role": "assistant",
                        "content": "\n".join(text_parts) if text_parts else None,
                    }
                    if tool_calls:
                        assistant_msg["tool_calls"] = tool_calls

                    oai.append(assistant_msg)

                else:
                    oai.append({"role": "assistant", "content": str(content)})

            else:
                # Pass through any other roles
                oai.append(msg)

        return oai

    @staticmethod
    def _translate_tools(
        anthropic_tools: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Translate Anthropic tool schemas to OpenAI format.

        Anthropic::

            {"name": "search", "description": "...", "input_schema": {...}}

        OpenAI::

            {"type": "function", "function": {"name": "search",
             "description": "...", "parameters": {...}}}
        """
        oai_tools = []
        for tool in anthropic_tools:
            oai_tools.append({
                "type": "function",
                "function": {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", {
                        "type": "object",
                        "properties": {},
                    }),
                },
            })
        return oai_tools

    # ── Lifecycle ─────────────────────────────────────────────────

    @property
    def request_count(self) -> int:
        return self._request_count

    async def close(self) -> None:
        """Release the underlying HTTP client."""
        if self._client is not None:
            await self._client.close()
            self._client = None

"""
Tests for multi-provider LLM support.

Tests:
  - LLMConfig auto-detection
  - Factory provider resolution
  - OpenAI message format translation (Anthropic → OpenAI)
  - OpenAI tool schema translation
  - OpenAI response parsing
"""
from __future__ import annotations

import json
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agentsafe.llm.config import LLMConfig
from agentsafe.llm.factory import create_llm_client, detect_provider, PROVIDER_DEFAULTS
from agentsafe.llm.client import AnthropicClient, LLMResponse, ToolCallRequest
from agentsafe.llm.openai_client import OpenAIClient


# ── LLMConfig auto-detection ────────────────────────────────────────

class TestLLMConfig:

    def test_explicit_anthropic(self):
        cfg = LLMConfig(provider="anthropic", api_key="sk-test")
        assert cfg.provider == "anthropic"
        assert cfg.model == "claude-sonnet-4-20250514"

    def test_explicit_openai(self):
        cfg = LLMConfig(provider="openai", api_key="sk-test")
        assert cfg.provider == "openai"
        assert cfg.model == "gpt-4o"

    def test_auto_detect_anthropic(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant"}, clear=False):
            # Remove OPENAI key if present
            env = {k: v for k, v in os.environ.items() if k != "CERTIOR_LLM_PROVIDER"}
            with patch.dict(os.environ, env, clear=True):
                os.environ["ANTHROPIC_API_KEY"] = "sk-ant"
                cfg = LLMConfig(provider="auto")
                assert cfg.provider == "anthropic"
                assert cfg.api_key == "sk-ant"

    def test_auto_detect_openai(self):
        env = {"OPENAI_API_KEY": "sk-oai"}
        with patch.dict(os.environ, env, clear=True):
            cfg = LLMConfig(provider="auto")
            assert cfg.provider == "openai"
            assert cfg.api_key == "sk-oai"

    def test_auto_prefers_anthropic(self):
        """When both keys are set, prefer Anthropic."""
        env = {"ANTHROPIC_API_KEY": "sk-ant", "OPENAI_API_KEY": "sk-oai"}
        with patch.dict(os.environ, env, clear=True):
            cfg = LLMConfig(provider="auto")
            assert cfg.provider == "anthropic"

    def test_explicit_env_override(self):
        """CERTIOR_LLM_PROVIDER overrides key detection."""
        env = {
            "ANTHROPIC_API_KEY": "sk-ant",
            "OPENAI_API_KEY": "sk-oai",
            "CERTIOR_LLM_PROVIDER": "openai",
        }
        with patch.dict(os.environ, env, clear=True):
            cfg = LLMConfig(provider="auto")
            assert cfg.provider == "openai"

    def test_custom_model(self):
        cfg = LLMConfig(provider="openai", model="gpt-4-turbo", api_key="sk-x")
        assert cfg.model == "gpt-4-turbo"

    def test_base_url(self):
        cfg = LLMConfig(
            provider="openai",
            api_key="sk-x",
            base_url="https://my-azure.openai.azure.com",
        )
        assert cfg.base_url == "https://my-azure.openai.azure.com"

    def test_provider_display(self):
        cfg = LLMConfig(provider="anthropic", api_key="sk-x")
        assert "Claude" in cfg.provider_display

        cfg = LLMConfig(provider="openai", api_key="sk-x")
        assert "GPT" in cfg.provider_display

    def test_is_configured(self):
        assert LLMConfig(provider="openai", api_key="sk-x").is_configured
        assert not LLMConfig(provider="openai", api_key=None).is_configured

    def test_from_env_with_provider(self):
        env = {
            "CERTIOR_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-oai",
            "CERTIOR_MODEL": "gpt-4-turbo",
        }
        with patch.dict(os.environ, env, clear=True):
            cfg = LLMConfig.from_env()
            assert cfg.provider == "openai"
            assert cfg.model == "gpt-4-turbo"
            assert cfg.api_key == "sk-oai"


# ── Factory ──────────────────────────────────────────────────────────

class TestFactory:

    def test_create_anthropic_client(self):
        cfg = LLMConfig(provider="anthropic", api_key="sk-test")
        client = create_llm_client(cfg)
        assert isinstance(client, AnthropicClient)

    def test_create_openai_client(self):
        cfg = LLMConfig(provider="openai", api_key="sk-test")
        client = create_llm_client(cfg)
        assert isinstance(client, OpenAIClient)

    def test_unknown_provider_raises(self):
        cfg = LLMConfig(provider="gemini", api_key="sk-test")
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            create_llm_client(cfg)

    def test_detect_provider_anthropic(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant"}, clear=True):
            assert detect_provider() == "anthropic"

    def test_detect_provider_openai(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-oai"}, clear=True):
            assert detect_provider() == "openai"

    def test_detect_provider_none_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="No LLM provider"):
                detect_provider()


# ── OpenAI message translation ───────────────────────────────────────

class TestOpenAIMessageTranslation:

    def test_simple_user_message(self):
        msgs = [{"role": "user", "content": "Hello"}]
        result = OpenAIClient._translate_messages(msgs)
        assert result == [{"role": "user", "content": "Hello"}]

    def test_system_prompt(self):
        msgs = [{"role": "user", "content": "Hi"}]
        result = OpenAIClient._translate_messages(msgs, system="Be helpful")
        assert result[0] == {"role": "system", "content": "Be helpful"}
        assert result[1] == {"role": "user", "content": "Hi"}

    def test_assistant_text(self):
        msgs = [
            {"role": "assistant", "content": [
                {"type": "text", "text": "I'll help you."},
            ]},
        ]
        result = OpenAIClient._translate_messages(msgs)
        assert result[0]["role"] == "assistant"
        assert result[0]["content"] == "I'll help you."

    def test_assistant_tool_use(self):
        msgs = [
            {"role": "assistant", "content": [
                {"type": "text", "text": "Let me search."},
                {
                    "type": "tool_use",
                    "id": "tc_123",
                    "name": "web_search",
                    "input": {"query": "test"},
                },
            ]},
        ]
        result = OpenAIClient._translate_messages(msgs)
        assert result[0]["role"] == "assistant"
        assert result[0]["content"] == "Let me search."
        assert len(result[0]["tool_calls"]) == 1
        tc = result[0]["tool_calls"][0]
        assert tc["id"] == "tc_123"
        assert tc["type"] == "function"
        assert tc["function"]["name"] == "web_search"
        assert json.loads(tc["function"]["arguments"]) == {"query": "test"}

    def test_tool_result(self):
        msgs = [
            {"role": "user", "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "tc_123",
                    "content": "Search results: ...",
                    "is_error": False,
                },
            ]},
        ]
        result = OpenAIClient._translate_messages(msgs)
        assert result[0]["role"] == "tool"
        assert result[0]["tool_call_id"] == "tc_123"
        assert result[0]["content"] == "Search results: ..."

    def test_full_conversation_roundtrip(self):
        """Test a complete multi-turn conversation with tool use."""
        msgs = [
            {"role": "user", "content": "What's the weather?"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "Let me check."},
                {
                    "type": "tool_use",
                    "id": "tc_1",
                    "name": "weather",
                    "input": {"city": "London"},
                },
            ]},
            {"role": "user", "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "tc_1",
                    "content": "15°C, cloudy",
                },
            ]},
            {"role": "assistant", "content": [
                {"type": "text", "text": "It's 15°C and cloudy in London."},
            ]},
        ]

        result = OpenAIClient._translate_messages(msgs, system="Weather bot")

        assert len(result) == 5  # system + user + assistant + tool + assistant
        assert result[0]["role"] == "system"
        assert result[1]["role"] == "user"
        assert result[2]["role"] == "assistant"
        assert result[2]["tool_calls"][0]["function"]["name"] == "weather"
        assert result[3]["role"] == "tool"
        assert result[3]["content"] == "15°C, cloudy"
        assert result[4]["role"] == "assistant"
        assert "15°C" in result[4]["content"]

    def test_multiple_tool_results(self):
        """Multiple tool results in a single user message."""
        msgs = [
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "tc_1", "content": "result1"},
                {"type": "tool_result", "tool_use_id": "tc_2", "content": "result2"},
            ]},
        ]
        result = OpenAIClient._translate_messages(msgs)
        assert len(result) == 2
        assert result[0]["tool_call_id"] == "tc_1"
        assert result[1]["tool_call_id"] == "tc_2"


# ── OpenAI tool schema translation ───────────────────────────────────

class TestOpenAIToolTranslation:

    def test_translate_tool(self):
        anthropic_tools = [
            {
                "name": "web_search",
                "description": "Search the web",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                    },
                    "required": ["query"],
                },
            },
        ]

        result = OpenAIClient._translate_tools(anthropic_tools)
        assert len(result) == 1
        tool = result[0]
        assert tool["type"] == "function"
        assert tool["function"]["name"] == "web_search"
        assert tool["function"]["description"] == "Search the web"
        assert tool["function"]["parameters"]["properties"]["query"]["type"] == "string"

    def test_translate_multiple_tools(self):
        tools = [
            {"name": "a", "description": "A", "input_schema": {"type": "object", "properties": {}}},
            {"name": "b", "description": "B", "input_schema": {"type": "object", "properties": {}}},
        ]
        result = OpenAIClient._translate_tools(tools)
        assert len(result) == 2
        assert result[0]["function"]["name"] == "a"
        assert result[1]["function"]["name"] == "b"


# ── OpenAI response parsing ──────────────────────────────────────────

class TestOpenAIResponseParsing:

    def _make_response(
        self,
        content="Hello",
        tool_calls=None,
        finish_reason="stop",
        prompt_tokens=10,
        completion_tokens=5,
    ):
        """Build a mock OpenAI ChatCompletion response."""
        message = MagicMock()
        message.content = content
        message.tool_calls = tool_calls

        choice = MagicMock()
        choice.message = message
        choice.finish_reason = finish_reason

        usage = MagicMock()
        usage.prompt_tokens = prompt_tokens
        usage.completion_tokens = completion_tokens

        response = MagicMock()
        response.choices = [choice]
        response.usage = usage
        return response

    def test_text_response(self):
        client = OpenAIClient(LLMConfig(provider="openai", api_key="sk-x"))
        resp = self._make_response(content="Hello world")
        result = client._parse_response(resp)

        assert isinstance(result, LLMResponse)
        assert result.text == "Hello world"
        assert result.tool_calls == []
        assert result.stop_reason == "end_turn"
        assert result.is_final

    def test_tool_call_response(self):
        tc = MagicMock()
        tc.id = "call_abc"
        tc.function.name = "web_search"
        tc.function.arguments = '{"query": "test"}'

        client = OpenAIClient(LLMConfig(provider="openai", api_key="sk-x"))
        resp = self._make_response(
            content=None,
            tool_calls=[tc],
            finish_reason="tool_calls",
        )
        result = client._parse_response(resp)

        assert result.stop_reason == "tool_use"
        assert result.has_tool_calls
        assert not result.is_final
        assert result.tool_calls[0].id == "call_abc"
        assert result.tool_calls[0].name == "web_search"
        assert result.tool_calls[0].input == {"query": "test"}

    def test_token_usage_tracking(self):
        client = OpenAIClient(LLMConfig(provider="openai", api_key="sk-x"))
        resp = self._make_response(prompt_tokens=100, completion_tokens=50)
        client._parse_response(resp)

        assert client.usage.input_tokens == 100
        assert client.usage.output_tokens == 50
        assert client.usage.total == 150

        # Second call accumulates
        client._parse_response(resp)
        assert client.usage.total == 300

    def test_stop_reason_mapping(self):
        client = OpenAIClient(LLMConfig(provider="openai", api_key="sk-x"))

        for oai_reason, expected in [
            ("stop", "end_turn"),
            ("tool_calls", "tool_use"),
            ("length", "max_tokens"),
            ("content_filter", "end_turn"),
        ]:
            resp = self._make_response(finish_reason=oai_reason)
            result = client._parse_response(resp)
            assert result.stop_reason == expected, (
                f"{oai_reason} → expected {expected}, got {result.stop_reason}"
            )


# ── Integration: executor uses factory ───────────────────────────────

class TestExecutorFactory:

    def test_executor_creates_openai_client(self):
        """Verify the executor uses the factory (not hardcoded Anthropic)."""
        from agentsafe.agents.agentic_executor import AgenticExecutor
        from agentsafe.tools.registry import ToolRegistry
        from agentsafe.capabilities.tokens import CapabilityToken

        cfg = LLMConfig(provider="openai", api_key="sk-test-not-real")
        token = CapabilityToken(permissions=["*"], budget_cents=1000)
        registry = ToolRegistry()

        executor = AgenticExecutor(
            llm_config=cfg,
            tool_registry=registry,
            capability_token=token,
        )
        assert isinstance(executor._client, OpenAIClient)

    def test_executor_creates_anthropic_client(self):
        from agentsafe.agents.agentic_executor import AgenticExecutor
        from agentsafe.tools.registry import ToolRegistry
        from agentsafe.capabilities.tokens import CapabilityToken

        cfg = LLMConfig(provider="anthropic", api_key="sk-test-not-real")
        token = CapabilityToken(permissions=["*"], budget_cents=1000)
        registry = ToolRegistry()

        executor = AgenticExecutor(
            llm_config=cfg,
            tool_registry=registry,
            capability_token=token,
        )
        assert isinstance(executor._client, AnthropicClient)

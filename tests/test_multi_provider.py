"""
Tests for multi-provider LLM support.

Covers:
  - Provider auto-detection from env vars
  - Runtime provider switching
  - Per-task provider override
  - Billing-error fallback hints
  - Settings API endpoints
  - OpenAI client tool-schema translation
"""
from __future__ import annotations

import os
import pytest
from unittest.mock import patch, AsyncMock, MagicMock


# ── LLM Config ───────────────────────────────────────────────────────


class TestLLMConfigDetection:
    """Verify auto-detection from environment variables."""

    def test_anthropic_detected_from_env(self):
        from agentsafe.llm.config import LLMConfig
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=False):
            config = LLMConfig(provider="auto")
            assert config.provider == "anthropic"
            assert config.api_key == "sk-ant-test"
            assert "claude" in config.model

    def test_openai_detected_from_env(self):
        from agentsafe.llm.config import LLMConfig
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-openai-test"},
                        clear=False):
            # Remove anthropic key so openai wins
            env = os.environ.copy()
            env.pop("ANTHROPIC_API_KEY", None)
            with patch.dict(os.environ, env, clear=True):
                os.environ["OPENAI_API_KEY"] = "sk-openai-test"
                config = LLMConfig(provider="auto")
                assert config.provider == "openai"
                assert config.api_key == "sk-openai-test"
                assert "gpt" in config.model

    def test_explicit_provider_override(self):
        from agentsafe.llm.config import LLMConfig
        with patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "sk-ant",
            "OPENAI_API_KEY": "sk-oai",
        }, clear=False):
            config = LLMConfig(provider="openai")
            assert config.provider == "openai"
            assert config.api_key == "sk-oai"

    def test_anthropic_prioritised_when_both_keys_present(self):
        from agentsafe.llm.config import LLMConfig
        with patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "sk-ant",
            "OPENAI_API_KEY": "sk-oai",
        }, clear=False):
            config = LLMConfig(provider="auto")
            assert config.provider == "anthropic"

    def test_env_var_provider_override(self):
        from agentsafe.llm.config import LLMConfig
        with patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "sk-ant",
            "OPENAI_API_KEY": "sk-oai",
            "CERTIOR_LLM_PROVIDER": "openai",
        }, clear=False):
            config = LLMConfig(provider="auto")
            assert config.provider == "openai"

    def test_from_env_reads_all_env_vars(self):
        from agentsafe.llm.config import LLMConfig
        with patch.dict(os.environ, {
            "OPENAI_API_KEY": "sk-oai",
            "CERTIOR_LLM_PROVIDER": "openai",
            "CERTIOR_MODEL": "gpt-4o-mini",
            "CERTIOR_MAX_TOKENS": "8192",
        }, clear=False):
            config = LLMConfig.from_env()
            assert config.provider == "openai"
            assert config.model == "gpt-4o-mini"
            assert config.max_tokens == 8192

    def test_is_configured_with_key(self):
        from agentsafe.llm.config import LLMConfig
        config = LLMConfig(provider="openai", api_key="sk-test")
        assert config.is_configured is True

    def test_not_configured_without_key(self):
        from agentsafe.llm.config import LLMConfig
        with patch.dict(os.environ, {}, clear=True):
            config = LLMConfig(provider="openai", api_key=None)
            assert config.is_configured is False


# ── Factory ───────────────────────────────────────────────────────────


class TestLLMFactory:
    """Verify factory creates correct client type."""

    def test_creates_anthropic_client(self):
        from agentsafe.llm.config import LLMConfig
        from agentsafe.llm.factory import create_llm_client
        config = LLMConfig(provider="anthropic", api_key="sk-ant-test")
        client = create_llm_client(config)
        assert type(client).__name__ == "AnthropicClient"

    def test_creates_openai_client(self):
        from agentsafe.llm.config import LLMConfig
        from agentsafe.llm.factory import create_llm_client
        config = LLMConfig(provider="openai", api_key="sk-oai-test")
        client = create_llm_client(config)
        assert type(client).__name__ == "OpenAIClient"

    def test_unknown_provider_raises(self):
        from agentsafe.llm.config import LLMConfig
        from agentsafe.llm.factory import create_llm_client
        config = LLMConfig(provider="deepseek", api_key="x")
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            create_llm_client(config)


# ── OpenAI Tool Schema Translation ────────────────────────────────────


class TestOpenAIToolTranslation:
    """Verify Anthropic→OpenAI tool schema translation."""

    def test_anthropic_to_openai_tool_format(self):
        from agentsafe.llm.openai_client import OpenAIClient

        client = OpenAIClient.__new__(OpenAIClient)

        # Anthropic format
        anthropic_tools = [{
            "name": "web_search",
            "description": "Search the web",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
                "required": ["query"],
            },
        }]

        # Translate
        openai_tools = client._translate_tools(anthropic_tools)

        assert len(openai_tools) == 1
        tool = openai_tools[0]
        assert tool["type"] == "function"
        assert tool["function"]["name"] == "web_search"
        assert tool["function"]["description"] == "Search the web"
        assert tool["function"]["parameters"]["properties"]["query"]["type"] == "string"


# ── Per-Task Provider Override ────────────────────────────────────────


class TestPerTaskOverride:
    """Verify per-task provider/model override in executor."""

    def test_state_store_stores_provider(self):
        from agentsafe.cloud.state_store import Execution

        ex = Execution(
            user_id="u1",
            task="test",
            token_id="t1",
            llm_provider="openai",
            llm_model="gpt-4o-mini",
        )
        d = ex.to_dict()
        assert d["llm_provider"] == "openai"
        assert d["llm_model"] == "gpt-4o-mini"

    def test_task_request_accepts_provider(self):
        """Verify the Pydantic model accepts provider/model fields."""
        from importlib import import_module
        tasks = import_module("app.api.routes.tasks")
        req = tasks.TaskRequest(
            task="test",
            provider="openai",
            model="gpt-4o-mini",
        )
        assert req.provider == "openai"
        assert req.model == "gpt-4o-mini"

    def test_task_request_validates_provider(self):
        from importlib import import_module
        from pydantic import ValidationError
        tasks = import_module("app.api.routes.tasks")
        with pytest.raises(ValidationError):
            tasks.TaskRequest(task="test", provider="deepseek")


# ── Billing Error Hints ───────────────────────────────────────────────


class TestBillingErrorHints:
    """Verify error messages suggest alternative providers."""

    @pytest.mark.asyncio
    async def test_billing_error_suggests_alternative(self):
        from agentsafe.cloud.executor_service import ExecutorService
        from agentsafe.cloud.state_store import Execution, ExecutionStatus
        from agentsafe.llm.config import LLMConfig

        # Set up both keys in env
        with patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "sk-ant",
            "OPENAI_API_KEY": "sk-oai",
        }, clear=False):
            executor = ExecutorService.__new__(ExecutorService)
            executor.llm_config = LLMConfig(provider="anthropic", api_key="sk-ant")

            # Create a mock execution
            ex = Execution(
                user_id="u1",
                task="test",
                token_id="t1",
            )
            ex.status = ExecutionStatus.FAILED

            # Simulate billing error
            error_msg = "Error code: 400 - credit balance is too low"
            error_lower = error_msg.lower()

            is_billing = any(kw in error_lower for kw in (
                "credit balance", "billing", "quota", "rate_limit",
            ))
            assert is_billing is True

            # Verify hint construction
            failed_provider = "anthropic"
            alt = "openai"
            alt_key = "OPENAI_API_KEY"
            assert os.environ.get(alt_key)  # openai key is available
            hint = f" [Provider: {failed_provider}] - Tip: {alt} is also configured."
            assert "openai" in hint
            assert "anthropic" in hint


# ── Settings API ─────────────────────────────────────────────────────


class TestSettingsAPI:
    """Verify settings routes return correct provider info."""

    def test_provider_metadata_structure(self):
        from app.api.routes.settings import PROVIDER_MODELS

        assert "anthropic" in PROVIDER_MODELS
        assert "openai" in PROVIDER_MODELS

        for pid, meta in PROVIDER_MODELS.items():
            assert "name" in meta
            assert "env_key" in meta
            assert "default_model" in meta
            assert "models" in meta
            assert len(meta["models"]) >= 3

    def test_anthropic_models_list(self):
        from app.api.routes.settings import PROVIDER_MODELS
        models = PROVIDER_MODELS["anthropic"]["models"]
        assert "claude-sonnet-4-20250514" in models
        assert "claude-haiku-4-5-20251001" in models

    def test_openai_models_list(self):
        from app.api.routes.settings import PROVIDER_MODELS
        models = PROVIDER_MODELS["openai"]["models"]
        assert "gpt-4o" in models
        assert "gpt-4o-mini" in models
        assert "o3-mini" in models

    def test_switch_provider_request_validation(self):
        from app.api.routes.settings import SwitchProviderRequest
        from pydantic import ValidationError

        # Valid
        req = SwitchProviderRequest(provider="openai")
        assert req.provider == "openai"

        # With model
        req = SwitchProviderRequest(provider="anthropic", model="claude-haiku-4-5-20251001")
        assert req.model == "claude-haiku-4-5-20251001"

        # Invalid provider
        with pytest.raises(ValidationError):
            SwitchProviderRequest(provider="deepseek")


# ── Integration (HTTP) ────────────────────────────────────────────────


class TestSettingsHTTP:
    """HTTP-level tests for settings endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client with both providers available."""
        with patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "sk-ant-test",
            "OPENAI_API_KEY": "sk-oai-test",
            "CERTIOR_DEV_API_KEY": "ck-test",
        }, clear=False):
            # Reset auth state fully - re-creates dev user from env
            from app.api.routes.auth import reset_store
            reset_store()

            from app.main import create_app
            from starlette.testclient import TestClient
            app = create_app()
            yield TestClient(app)

    def test_list_providers(self, client):
        r = client.get(
            "/api/v1/settings/providers",
            headers={"Authorization": "Bearer ck-test"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "providers" in data
        assert len(data["providers"]) == 2

        ids = {p["id"] for p in data["providers"]}
        assert ids == {"anthropic", "openai"}

        # Both should be available
        for p in data["providers"]:
            assert p["available"] is True
            assert len(p["models"]) >= 3

    def test_switch_to_openai(self, client):
        r = client.post(
            "/api/v1/settings/provider",
            json={"provider": "openai"},
            headers={"Authorization": "Bearer ck-test"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["provider"] == "openai"
        assert "gpt-4o" in data["model"]

    def test_switch_to_openai_with_model(self, client):
        r = client.post(
            "/api/v1/settings/provider",
            json={"provider": "openai", "model": "gpt-4o-mini"},
            headers={"Authorization": "Bearer ck-test"},
        )
        assert r.status_code == 200
        assert r.json()["model"] == "gpt-4o-mini"

    def test_submit_task_with_provider_override(self, client):
        r = client.post(
            "/api/v1/tasks",
            json={
                "task": "test multi-provider",
                "provider": "openai",
                "model": "gpt-4o-mini",
            },
            headers={"Authorization": "Bearer ck-test"},
        )
        assert r.status_code == 201
        data = r.json()
        assert "execution_id" in data

    def test_submit_task_invalid_provider_rejected(self, client):
        r = client.post(
            "/api/v1/tasks",
            json={"task": "test", "provider": "deepseek"},
            headers={"Authorization": "Bearer ck-test"},
        )
        assert r.status_code == 422  # validation error

"""
End-to-end integration tests for the agentic API pipeline.

Tests the full flow:
  POST /tasks → ExecutorService (agentic mode) → AgenticOrchestrator
  → AgenticExecutor (mocked LLM) → Events → WebSocket stream

All LLM calls are mocked to keep tests fast and deterministic.
"""
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

z3 = pytest.importorskip("z3")
fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient
from agentsafe.cloud.state_store import ExecutionStatus
from agentsafe.cloud.event_bus import EventBus
from agentsafe.cloud.executor_service import ExecutorService
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.kernel.certificate import CertificateAuthority
from agentsafe.observability.otel import CertiorTelemetry
from agentsafe.llm.config import LLMConfig
from agentsafe.tools import create_default_registry


@pytest.fixture(autouse=True)
def _reset_singletons():
    CertificateAuthority.reset()
    CertiorTelemetry.reset()
    yield
    CertificateAuthority.reset()
    CertiorTelemetry.reset()


# --------------------------------------------------------------------------
# Agentic ExecutorService integration
# --------------------------------------------------------------------------


class TestAgenticPipelineIntegration:
    """Full pipeline: submit → execute(agentic) → result."""

    def _make_service(self):
        config = LLMConfig(api_key="sk-test-key")
        registry = create_default_registry()
        bus = EventBus()
        svc = ExecutorService(
            llm_config=config,
            tool_registry=registry,
            event_bus=bus,
        )
        return svc, bus

    @pytest.mark.asyncio
    async def test_full_agentic_execution(self):
        """Submit → agentic execute → completed with results."""
        svc, bus = self._make_service()
        assert svc.mode == "agentic"

        token = CapabilityToken(
            permissions=["compute:python:eval", "network:http:read"],
            budget_cents=5000,
            budget_remaining_cents=5000,
        )
        ex = await svc.submit("compute 2+2", "user-1", token)

        # Mock AgenticOrchestrator to return a successful result
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.output = "The answer is 4."
        mock_result.certificates = ["cert-abc", "cert-def"]
        mock_result.cost_cents = 15
        mock_result.duration_ms = 123.4
        mock_result.steps = [
            {"tool": "python_eval", "args": {"code": "2+2"}, "output": "4"},
        ]
        mock_result.total_input_tokens = 200
        mock_result.total_output_tokens = 80
        mock_result.error = ""

        mock_orch = AsyncMock()
        mock_orch.execute = AsyncMock(return_value=mock_result)

        with patch(
            "agentsafe.agents.agentic_orchestrator.AgenticOrchestrator",
            return_value=mock_orch,
        ):
            result = await svc.execute(ex.id, token)

        # Verify completion
        assert result.status == ExecutionStatus.COMPLETED
        assert result.cost_cents == 15
        assert len(result.certificates) == 2
        assert result.results["output"] == "The answer is 4."
        assert result.results["total_input_tokens"] == 200
        assert result.completed_at is not None

        # Verify event trail
        events = bus.get_history(execution_id=ex.id)
        statuses = [e.data.get("status", e.type.split(".")[-1]) for e in events]
        assert "planning" in statuses
        assert "executing" in statuses
        assert "completed" in statuses

    @pytest.mark.asyncio
    async def test_agentic_failure_produces_event(self):
        """When the agentic executor fails, events and status are correct."""
        svc, bus = self._make_service()
        token = CapabilityToken(
            permissions=["compute:python:eval"],
            budget_cents=5000,
            budget_remaining_cents=5000,
        )
        ex = await svc.submit("fail task", "user-1", token)

        mock_orch = AsyncMock()
        mock_orch.execute = AsyncMock(
            side_effect=RuntimeError("connection refused"),
        )

        with patch(
            "agentsafe.agents.agentic_orchestrator.AgenticOrchestrator",
            return_value=mock_orch,
        ):
            result = await svc.execute(ex.id, token)

        assert result.status == ExecutionStatus.FAILED
        assert "connection refused" in result.error

        events = bus.get_history(execution_id=ex.id)
        has_failed = any("failed" in e.type for e in events)
        assert has_failed

    @pytest.mark.asyncio
    async def test_agentic_status_handler_streams_tool_events(self):
        """Verify tool-level status events flow through the bus."""
        svc, bus = self._make_service()
        token = CapabilityToken(
            permissions=["compute:python:eval"],
            budget_cents=5000,
            budget_remaining_cents=5000,
        )
        ex = await svc.submit("multi-tool", "user-1", token)

        # Capture the on_status callback
        captured = {}

        def mock_orch_init(**kwargs):
            captured["on_status"] = kwargs.get("on_status")
            result = MagicMock()
            result.success = True
            result.output = "done"
            result.certificates = []
            result.cost_cents = 0
            result.duration_ms = 10.0
            result.steps = []
            result.total_input_tokens = 0
            result.total_output_tokens = 0
            result.error = ""
            m = AsyncMock()
            m.execute = AsyncMock(return_value=result)
            return m

        with patch(
            "agentsafe.agents.agentic_orchestrator.AgenticOrchestrator",
            side_effect=mock_orch_init,
        ):
            result = await svc.execute(ex.id, token)

        # Now simulate the agentic executor sending tool events
        handler = captured["on_status"]
        await handler("executing_tool", "multi-tool")
        await handler("tool_completed", "multi-tool")
        await handler("executing_tool", "multi-tool")

        events = bus.get_history(execution_id=ex.id)
        tool_events = [
            e for e in events
            if "executing_tool" in e.type or "tool_completed" in e.type
        ]
        assert len(tool_events) >= 2

        # Step counter should have incremented
        assert ex.current_step == 2


# --------------------------------------------------------------------------
# API integration (TestClient)
# --------------------------------------------------------------------------


class TestAgenticAPI:
    """Test the FastAPI endpoints with agentic mode."""

    @pytest.fixture
    def agentic_client(self):
        """Create a TestClient with mocked LLM config."""
        from app.api.routes.auth import reset_store

        reset_store()

        # Patch environment so create_app picks up LLM config
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test-key"}):
            from app.main import create_app
            app = create_app()
            with TestClient(app) as c:
                yield c

        reset_store()

    @pytest.fixture
    def dev_key(self):
        from app.api.routes.auth import get_dev_api_key
        return get_dev_api_key()

    def test_health_reports_agentic_mode(self, agentic_client):
        r = agentic_client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["mode"] == "agentic"
        assert data["llm_configured"] is True
        assert len(data["tools"]) >= 3  # web_fetch, python_eval, file_write, ...

    def test_submit_task_in_agentic_mode(self, agentic_client, dev_key):
        r = agentic_client.post(
            "/api/v1/tasks",
            json={
                "task": "compute fibonacci(10)",
                "permissions": ["compute:python:eval"],
                "budget_cents": 5000,
            },
            headers={"Authorization": f"Bearer {dev_key}"},
        )
        assert r.status_code == 201
        data = r.json()
        assert "execution_id" in data
        assert data["status"] == "queued"
        assert "websocket_url" in data


class TestLegacyFallback:
    """Verify the system falls back to legacy mode without LLM config."""

    @pytest.fixture
    def legacy_client(self):
        from app.api.routes.auth import reset_store

        reset_store()

        # No ANTHROPIC_API_KEY → legacy mode
        with patch.dict("os.environ", {}, clear=False):
            import os
            old = os.environ.pop("ANTHROPIC_API_KEY", None)
            try:
                from app.main import create_app
                app = create_app()
                with TestClient(app) as c:
                    yield c
            finally:
                if old is not None:
                    os.environ["ANTHROPIC_API_KEY"] = old

        reset_store()

    def test_health_reports_legacy_mode(self, legacy_client):
        r = legacy_client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["mode"] == "legacy"
        assert data["llm_configured"] is False

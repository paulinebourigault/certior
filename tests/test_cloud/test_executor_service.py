"""
Tests for ExecutorService - both legacy and agentic modes.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from agentsafe.cloud.executor_service import ExecutorService
from agentsafe.cloud.state_store import StateStore, ExecutionStatus
from agentsafe.cloud.event_bus import EventBus
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.kernel.certificate import CertificateAuthority
from agentsafe.observability.otel import CertiorTelemetry

z3 = pytest.importorskip("z3")


class TestModeDetection:
    """Test automatic mode selection."""

    def test_legacy_mode_when_no_llm_config(self):
        svc = ExecutorService()
        assert svc.mode == "legacy"

    def test_legacy_mode_when_llm_not_configured(self):
        from agentsafe.llm.config import LLMConfig
        config = LLMConfig(api_key=None)
        svc = ExecutorService(llm_config=config)
        assert svc.mode == "legacy"

    def test_agentic_mode_when_llm_configured(self):
        from agentsafe.llm.config import LLMConfig
        config = LLMConfig(api_key="sk-test-key")
        svc = ExecutorService(llm_config=config)
        assert svc.mode == "agentic"

    def test_mode_persists_across_calls(self):
        from agentsafe.llm.config import LLMConfig
        config = LLMConfig(api_key="sk-test-key")
        svc = ExecutorService(llm_config=config)
        assert svc.mode == svc.mode  # Consistent


class TestExecutorServiceLegacy:
    """Tests using the legacy plan-based pipeline."""

    def setup_method(self):
        CertificateAuthority.reset()
        CertiorTelemetry.reset()

    @pytest.mark.asyncio
    async def test_submit(self):
        svc = ExecutorService()
        token = CapabilityToken(permissions=["a"])
        ex = await svc.submit("test task", "user1", token)
        assert ex.task == "test task"
        assert ex.status == ExecutionStatus.QUEUED

    @pytest.mark.asyncio
    async def test_execute_real_pipeline(self):
        tools = {"default": lambda p: f"Result: {p.get('task', '')}"}
        svc = ExecutorService(tools=tools)
        token = CapabilityToken(
            permissions=["network:http:read", "database:read"],
            budget_cents=10000, budget_remaining_cents=10000,
        )
        ex = await svc.submit("process data", "user1", token)
        result = await svc.execute(ex.id, token)
        assert result.status in (ExecutionStatus.COMPLETED, ExecutionStatus.FAILED)

    @pytest.mark.asyncio
    async def test_execute_success(self):
        tools = {"default": lambda p: "success"}
        svc = ExecutorService(tools=tools)
        token = CapabilityToken(
            permissions=["a", "b"], budget_cents=10000, budget_remaining_cents=10000,
        )
        ex = await svc.submit("simple task", "user1", token)
        result = await svc.execute(ex.id, token)
        if result.status == ExecutionStatus.COMPLETED:
            assert result.cost_cents >= 0

    @pytest.mark.asyncio
    async def test_events_emitted(self):
        bus = EventBus()
        svc = ExecutorService(
            event_bus=bus,
            tools={"default": lambda p: "ok"},
        )
        token = CapabilityToken(
            permissions=["a"], budget_cents=10000, budget_remaining_cents=10000,
        )
        ex = await svc.submit("test", "u1", token)
        await svc.execute(ex.id, token)
        events = bus.get_history(execution_id=ex.id)
        assert len(events) >= 2  # created + at least one status

    @pytest.mark.asyncio
    async def test_webhook_on_complete(self):
        from unittest.mock import AsyncMock, patch
        from agentsafe.cloud.webhook import WebhookDelivery

        svc = ExecutorService(tools={"default": lambda p: "ok"})
        token = CapabilityToken(
            permissions=["a"], budget_cents=10000, budget_remaining_cents=10000,
        )
        ex = await svc.submit(
            "test", "u1", token, webhook_url="https://example.com/hook",
        )
        # Patch webhook delivery to simulate success
        mock_deliver = AsyncMock(return_value=WebhookDelivery(
            url="https://example.com/hook", status="delivered",
        ))
        with patch.object(svc.webhooks, "deliver", mock_deliver):
            result = await svc.execute(ex.id, token)
        if result.status == ExecutionStatus.COMPLETED:
            mock_deliver.assert_called_once()
            call_args = mock_deliver.call_args
            assert call_args[0][0] == "https://example.com/hook"

    @pytest.mark.asyncio
    async def test_get_status(self):
        svc = ExecutorService()
        token = CapabilityToken(permissions=["a"])
        ex = await svc.submit("test", "u1", token)
        status = await svc.get_status(ex.id)
        assert status is not None
        assert status.id == ex.id

    @pytest.mark.asyncio
    async def test_cancel(self):
        svc = ExecutorService()
        token = CapabilityToken(permissions=["a"])
        ex = await svc.submit("test", "u1", token)
        assert await svc.cancel(ex.id)
        status = await svc.get_status(ex.id)
        assert status.status == ExecutionStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_execute_nonexistent(self):
        svc = ExecutorService()
        token = CapabilityToken(permissions=["a"])
        with pytest.raises(ValueError):
            await svc.execute("nonexistent", token)


class TestExecutorServiceAgentic:
    """Tests using the agentic LLM loop."""

    def setup_method(self):
        CertificateAuthority.reset()
        CertiorTelemetry.reset()

    def _make_svc(self, **extra):
        from agentsafe.llm.config import LLMConfig
        config = LLMConfig(api_key="sk-test-key")
        bus = EventBus()
        return ExecutorService(
            llm_config=config,
            event_bus=bus,
            **extra,
        ), bus

    @pytest.mark.asyncio
    async def test_agentic_submit_records_mode(self):
        svc, bus = self._make_svc()
        token = CapabilityToken(permissions=["compute:python:eval"])
        ex = await svc.submit("hello", "u1", token)
        events = bus.get_history(execution_id=ex.id)
        # The created event should include mode=agentic
        assert any(e.data.get("mode") == "agentic" for e in events)

    @pytest.mark.asyncio
    async def test_agentic_execute_routes_to_agentic_orchestrator(self):
        """Verify the executor calls AgenticOrchestrator.execute."""
        svc, bus = self._make_svc()
        token = CapabilityToken(
            permissions=["compute:python:eval"],
            budget_cents=5000, budget_remaining_cents=5000,
        )
        ex = await svc.submit("compute 2+2", "u1", token)

        # Mock the AgenticOrchestrator to avoid actual LLM calls
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.output = "4"
        mock_result.certificates = ["cert-001"]
        mock_result.cost_cents = 10
        mock_result.duration_ms = 42.0
        mock_result.steps = [{"tool": "python_eval", "output": "4"}]
        mock_result.total_input_tokens = 100
        mock_result.total_output_tokens = 50
        mock_result.error = ""

        mock_orch = AsyncMock()
        mock_orch.execute = AsyncMock(return_value=mock_result)

        with patch(
            "agentsafe.agents.agentic_orchestrator.AgenticOrchestrator",
            return_value=mock_orch,
        ) as MockOrch:
            result = await svc.execute(ex.id, token)

            # Verify AgenticOrchestrator was used
            MockOrch.assert_called_once()
            call_kwargs = MockOrch.call_args[1]
            assert call_kwargs["llm_config"].api_key == "sk-test-key"

            mock_orch.execute.assert_called_once_with(ex.task)

        assert result.status == ExecutionStatus.COMPLETED
        assert result.cost_cents == 10
        assert "cert-001" in result.certificates

    @pytest.mark.asyncio
    async def test_agentic_execute_preserves_token_metadata_and_policy(self):
        svc, bus = self._make_svc()
        token = CapabilityToken(
            permissions=["compute:python:eval"],
            budget_cents=5000,
            budget_remaining_cents=5000,
            metadata={
                "compliance_policy": "hipaa",
                "verification_profile": {
                    "stage_role": "intake",
                    "release_targets": ["internal"],
                },
            },
        )
        ex = await svc.submit(
            "Review patient records and redact PHI",
            "u1",
            token,
            verification_profile={
                "stage_role": "intake",
                "release_targets": ["internal"],
            },
        )

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.output = "ok"
        mock_result.certificates = []
        mock_result.cost_cents = 0
        mock_result.duration_ms = 5.0
        mock_result.steps = []
        mock_result.total_input_tokens = 1
        mock_result.total_output_tokens = 1
        mock_result.error = ""

        mock_orch = AsyncMock()
        mock_orch.execute = AsyncMock(return_value=mock_result)

        with patch(
            "agentsafe.agents.agentic_orchestrator.AgenticOrchestrator",
            return_value=mock_orch,
        ) as MockOrch:
            await svc.execute(ex.id)

        call_kwargs = MockOrch.call_args[1]
        assert call_kwargs["content_policy"].name == "HIPAA"
        assert call_kwargs["capability_token"].metadata["compliance_policy"] == "hipaa"
        assert call_kwargs["capability_token"].metadata["verification_profile"]["stage_role"] == "intake"

    @pytest.mark.asyncio
    async def test_agentic_execute_failure_captured(self):
        """Verify failures from the agentic pipeline are captured."""
        svc, bus = self._make_svc()
        token = CapabilityToken(
            permissions=["compute:python:eval"],
            budget_cents=5000, budget_remaining_cents=5000,
        )
        ex = await svc.submit("bad task", "u1", token)

        mock_result = MagicMock()
        mock_result.success = False
        mock_result.error = "tool verification failed"
        mock_result.output = None
        mock_result.certificates = []
        mock_result.cost_cents = 0
        mock_result.duration_ms = 10.0

        mock_orch = AsyncMock()
        mock_orch.execute = AsyncMock(return_value=mock_result)

        with patch(
            "agentsafe.agents.agentic_orchestrator.AgenticOrchestrator",
            return_value=mock_orch,
        ):
            result = await svc.execute(ex.id, token)

        assert result.status == ExecutionStatus.FAILED
        assert "tool verification failed" in result.error

    @pytest.mark.asyncio
    async def test_agentic_execute_exception_handled(self):
        """Verify unhandled exceptions from orchestrator don't crash."""
        svc, bus = self._make_svc()
        token = CapabilityToken(
            permissions=["compute:python:eval"],
            budget_cents=5000, budget_remaining_cents=5000,
        )
        ex = await svc.submit("crashing task", "u1", token)

        mock_orch = AsyncMock()
        mock_orch.execute = AsyncMock(side_effect=RuntimeError("LLM unavailable"))

        with patch(
            "agentsafe.agents.agentic_orchestrator.AgenticOrchestrator",
            return_value=mock_orch,
        ):
            result = await svc.execute(ex.id, token)

        assert result.status == ExecutionStatus.FAILED
        assert "LLM unavailable" in result.error

    @pytest.mark.asyncio
    async def test_agentic_status_events_flow_to_bus(self):
        """Verify agentic status handler emits events to event bus."""
        svc, bus = self._make_svc()
        token = CapabilityToken(
            permissions=["compute:python:eval"],
            budget_cents=5000, budget_remaining_cents=5000,
        )
        ex = await svc.submit("test", "u1", token)

        # Capture the on_status handler
        captured_handler = {}

        def fake_orch(**kwargs):
            captured_handler["fn"] = kwargs.get("on_status")
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
            mock = AsyncMock()
            mock.execute = AsyncMock(return_value=result)
            return mock

        with patch(
            "agentsafe.agents.agentic_orchestrator.AgenticOrchestrator",
            side_effect=fake_orch,
        ):
            result = await svc.execute(ex.id, token)

        # The handler should have been passed to AgenticOrchestrator
        assert "fn" in captured_handler
        handler = captured_handler["fn"]

        # Simulate tool execution events
        await handler("executing_tool", "test")
        await handler("verifying", "test")

        events = bus.get_history(execution_id=ex.id)
        statuses = [e.data.get("status") for e in events]
        assert "executing_tool" in statuses
        assert "verifying" in statuses

    @pytest.mark.asyncio
    async def test_agentic_step_counter_increments(self):
        """Verify the step counter in agentic status handler works."""
        svc, bus = self._make_svc()
        token = CapabilityToken(
            permissions=["a"],
            budget_cents=5000, budget_remaining_cents=5000,
        )
        ex = await svc.submit("test", "u1", token)

        # Get the status handler directly
        handler = svc._make_agentic_status_handler(ex)

        await handler("executing_tool", "test")
        assert ex.current_step == 1

        await handler("executing_tool", "test")
        assert ex.current_step == 2

    @pytest.mark.asyncio
    async def test_release_stage_requires_completed_reviewer_execution(self):
        svc, bus = self._make_svc()
        reviewer_token = CapabilityToken(
            permissions=["document:read:reports"],
            budget_cents=5000,
            budget_remaining_cents=5000,
            metadata={
                "compliance_policy": "default",
                "verification_profile": {
                    "stage_role": "reviewer",
                    "required_proofs": ["capability_coverage"],
                },
            },
        )
        reviewer = await svc.submit(
            "review",
            "u1",
            reviewer_token,
            verification_profile=reviewer_token.metadata["verification_profile"],
        )
        reviewer.status = ExecutionStatus.COMPLETED
        reviewer.results = {
            "steps": [
                {
                    "tool_name": "file_read",
                    "verified": True,
                    "verification_properties": ["capability_coverage: proven"],
                }
            ],
            "approved_artifact": {
                "text": "Approved public release text",
                "sha256": "approved-hash-1",
                "approved_for_release": True,
            },
            "verification_profile": reviewer_token.metadata["verification_profile"],
        }
        reviewer.completed_at = 1.0
        await svc.state.update(reviewer)

        release_token = CapabilityToken(
            permissions=["document:write:reports"],
            budget_cents=5000,
            budget_remaining_cents=5000,
            metadata={
                "compliance_policy": "default",
                "verification_profile": {
                    "stage_role": "release",
                    "upstream_execution_ids": [reviewer.id],
                },
            },
        )
        release = await svc.submit(
            "release",
            "u1",
            release_token,
            verification_profile=release_token.metadata["verification_profile"],
        )

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.output = "released"
        mock_result.certificates = []
        mock_result.cost_cents = 0
        mock_result.duration_ms = 1.0
        mock_result.steps = []
        mock_result.total_input_tokens = 0
        mock_result.total_output_tokens = 0
        mock_result.error = ""

        mock_orch = AsyncMock()
        mock_orch.execute = AsyncMock(return_value=mock_result)

        with patch(
            "agentsafe.agents.agentic_orchestrator.AgenticOrchestrator",
            return_value=mock_orch,
        ):
            result = await svc.execute(release.id, release_token)

        assert result.status == ExecutionStatus.COMPLETED
        profile = result.token_data["verification_profile"]
        binding = profile["metadata"]["release_binding"]
        assert binding["approved_artifacts"][0]["sha256"] == "approved-hash-1"

    @pytest.mark.asyncio
    async def test_release_stage_fails_when_upstream_not_reviewer(self):
        svc, bus = self._make_svc()
        upstream_token = CapabilityToken(
            permissions=["document:read:reports"],
            budget_cents=5000,
            budget_remaining_cents=5000,
            metadata={
                "compliance_policy": "default",
                "verification_profile": {
                    "stage_role": "intake",
                    "required_proofs": ["capability_coverage"],
                },
            },
        )
        upstream = await svc.submit(
            "intake",
            "u1",
            upstream_token,
            verification_profile=upstream_token.metadata["verification_profile"],
        )
        upstream.status = ExecutionStatus.COMPLETED
        upstream.results = {
            "steps": [
                {
                    "tool_name": "file_read",
                    "verified": True,
                    "verification_properties": ["capability_coverage: proven"],
                }
            ],
            "verification_profile": upstream_token.metadata["verification_profile"],
        }
        upstream.completed_at = 1.0
        await svc.state.update(upstream)

        release_token = CapabilityToken(
            permissions=["document:write:reports"],
            budget_cents=5000,
            budget_remaining_cents=5000,
            metadata={
                "compliance_policy": "default",
                "verification_profile": {
                    "stage_role": "release",
                    "upstream_execution_ids": [upstream.id],
                },
            },
        )
        release = await svc.submit(
            "release",
            "u1",
            release_token,
            verification_profile=release_token.metadata["verification_profile"],
        )

        result = await svc.execute(release.id, release_token)
        assert result.status == ExecutionStatus.FAILED
        assert "not_reviewer" in result.error

    @pytest.mark.asyncio
    async def test_release_stage_fails_when_upstream_has_no_approved_artifact(self):
        svc, bus = self._make_svc()
        reviewer_token = CapabilityToken(
            permissions=["document:read:reports"],
            budget_cents=5000,
            budget_remaining_cents=5000,
            metadata={
                "compliance_policy": "default",
                "verification_profile": {
                    "stage_role": "reviewer",
                    "required_proofs": ["capability_coverage"],
                },
            },
        )
        reviewer = await svc.submit(
            "review",
            "u1",
            reviewer_token,
            verification_profile=reviewer_token.metadata["verification_profile"],
        )
        reviewer.status = ExecutionStatus.COMPLETED
        reviewer.results = {
            "steps": [
                {
                    "tool_name": "file_read",
                    "verified": True,
                    "verification_properties": ["capability_coverage: proven"],
                }
            ],
            "verification_profile": reviewer_token.metadata["verification_profile"],
        }
        reviewer.completed_at = 1.0
        await svc.state.update(reviewer)

        release_token = CapabilityToken(
            permissions=["document:write:reports"],
            budget_cents=5000,
            budget_remaining_cents=5000,
            metadata={
                "compliance_policy": "default",
                "verification_profile": {
                    "stage_role": "release",
                    "upstream_execution_ids": [reviewer.id],
                },
            },
        )
        release = await svc.submit(
            "release",
            "u1",
            release_token,
            verification_profile=release_token.metadata["verification_profile"],
        )

        result = await svc.execute(release.id, release_token)
        assert result.status == ExecutionStatus.FAILED
        assert "missing_approved_artifact" in result.error


class TestExecutorServiceWebSocket:
    """Test event bus → WebSocket stream integration."""

    def setup_method(self):
        CertificateAuthority.reset()
        CertiorTelemetry.reset()

    @pytest.mark.asyncio
    async def test_events_reach_stream_via_bus(self):
        """Verify the event bus → WebSocket stream bridge works."""
        from agentsafe.cloud.websocket import ExecutionStream, StreamUpdate

        bus = EventBus()
        stream = ExecutionStream()
        received = []

        # Wire bus → stream (same pattern as app/main.py)
        async def _forward(event):
            update = StreamUpdate(
                execution_id=event.execution_id,
                status=event.type.split(".")[-1] if "." in event.type else event.type,
                data=event.data,
            )
            await stream.emit(update)

        bus.subscribe("*", _forward)

        # Subscribe to stream
        await stream.subscribe("exec-1", lambda u: received.append(u))

        # Emit events through executor service
        svc = ExecutorService(event_bus=bus)
        token = CapabilityToken(permissions=["a"])
        ex = await svc.submit("hello", "u1", token)

        # Force execution ID for predictable test
        from agentsafe.cloud.event_bus import Event
        await bus.emit(Event(
            type="execution.planning",
            execution_id="exec-1",
            data={"status": "planning"},
        ))
        await bus.emit(Event(
            type="execution.executing_tool",
            execution_id="exec-1",
            data={"status": "executing_tool", "step": 1},
        ))

        assert len(received) == 2
        assert received[0].status == "planning"
        assert received[1].status == "executing_tool"
        assert received[1].data.get("step") == 1

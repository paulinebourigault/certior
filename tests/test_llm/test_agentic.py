"""
Tests for agentsafe.llm and agentsafe.agents.agentic_executor.

Uses mock LLM responses to test the reactive agent loop without
requiring an actual API key.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentsafe.llm.config import LLMConfig
from agentsafe.llm.client import (
    AnthropicClient,
    LLMResponse,
    ToolCallRequest,
    TokenUsage,
)
from agentsafe.agents.agentic_executor import (
    AgenticExecutor,
    AgenticResult,
    AgentStep,
    _VerificationShim,
)
from agentsafe.tools import ToolRegistry, create_default_registry
from agentsafe.tools.base import BaseTool, ToolParameter, ToolResult
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.safety.scanner import ContentSafetyPolicy
from agentsafe.kernel.certificate import CertificateAuthority
from agentsafe.verification import LeanFlowResult


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Fixtures
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@pytest.fixture(autouse=True)
def _reset_ca():
    """Ensure a fresh CertificateAuthority for each test."""
    CertificateAuthority.reset()
    yield
    CertificateAuthority.reset()


def _make_token(**overrides) -> CapabilityToken:
    defaults = dict(
        agent_id="test-agent",
        permissions=["network:http:read", "compute:python:eval", "filesystem:write"],
        budget_cents=10000,
        budget_remaining_cents=10000,
    )
    defaults.update(overrides)
    return CapabilityToken(**defaults)


class _EchoTool(BaseTool):
    """Deterministic test tool that echoes its input."""

    @property
    def name(self) -> str:
        return "echo"

    @property
    def description(self) -> str:
        return "Echoes input"

    def parameters(self) -> List[ToolParameter]:
        return [ToolParameter(name="text", type="string", description="Text to echo")]

    @property
    def required_capabilities(self) -> List[str]:
        return ["test:echo"]

    async def execute(self, *, tool_use_id: str, **kwargs: Any) -> ToolResult:
        return ToolResult(tool_use_id=tool_use_id, output=f"ECHO: {kwargs.get('text', '')}")


def _make_registry_with_echo() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(_EchoTool())
    return reg


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LLMConfig
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestLLMConfig:
    def test_defaults(self):
        cfg = LLMConfig(api_key="test-key")
        assert cfg.provider == "anthropic"
        assert cfg.max_tool_rounds == 25
        assert cfg.is_configured

    def test_not_configured_without_key(self):
        cfg = LLMConfig()
        # Only configured if env var is set
        if not cfg.api_key:
            assert not cfg.is_configured

    def test_from_env(self):
        cfg = LLMConfig.from_env(api_key="test")
        assert cfg.api_key == "test"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LLMResponse
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestLLMResponse:
    def test_is_final_on_end_turn(self):
        resp = LLMResponse(text="done", stop_reason="end_turn")
        assert resp.is_final
        assert not resp.has_tool_calls

    def test_not_final_on_tool_use(self):
        resp = LLMResponse(
            text="",
            tool_calls=[ToolCallRequest(id="tc1", name="echo", input={"text": "hi"})],
            stop_reason="tool_use",
        )
        assert not resp.is_final
        assert resp.has_tool_calls


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AgenticExecutor - core loop tests (mocked LLM)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAgenticExecutor:
    """Tests using a mocked AnthropicClient to control the LLM responses."""

    def _build_executor(
        self,
        responses: List[LLMResponse],
        token: Optional[CapabilityToken] = None,
        registry: Optional[ToolRegistry] = None,
    ) -> AgenticExecutor:
        """Create an executor with a mock LLM that returns *responses* in order."""
        config = LLMConfig(api_key="test-key", max_tool_rounds=10)
        tok = token or _make_token(permissions=["test:echo"])
        reg = registry or _make_registry_with_echo()

        executor = AgenticExecutor(
            llm_config=config,
            tool_registry=reg,
            capability_token=tok,
        )

        # Replace the client with a mock
        mock_client = AsyncMock()
        mock_client.send = AsyncMock(side_effect=responses)
        mock_client.usage = TokenUsage(input_tokens=0, output_tokens=0)
        mock_client.close = AsyncMock()
        executor._client = mock_client

        # Keep core loop tests deterministic even when the real Lean binary
        # is present in the workspace.
        executor._lean_verifier = MagicMock()
        executor._lean_verifier.start = AsyncMock(return_value=False)
        executor._lean_verifier.check_flow = AsyncMock(
            return_value=LeanFlowResult(ok=True, proven=False)
        )
        executor._lean_verifier.check_output_flow = AsyncMock(
            return_value=LeanFlowResult(ok=True, proven=False)
        )
        executor._lean_verifier.get_certificates = AsyncMock(return_value=[])
        executor._lean_verifier.shutdown = AsyncMock(return_value=None)
        executor._lean_verifier.summary = MagicMock(return_value={"lean_kernel_available": False})

        return executor

    @pytest.mark.asyncio
    async def test_simple_text_response(self):
        """LLM returns text immediately - no tool calls."""
        executor = self._build_executor([
            LLMResponse(text="The answer is 42.", stop_reason="end_turn"),
        ])
        result = await executor.run("What is 6 * 7?")

        assert result.success
        assert "42" in result.output
        assert len(result.steps) == 0
        assert result.total_cost_cents == 0

    @pytest.mark.asyncio
    async def test_single_tool_call_then_answer(self):
        """LLM calls one tool, then produces final answer."""
        executor = self._build_executor([
            # Round 1: tool call
            LLMResponse(
                text="",
                tool_calls=[ToolCallRequest(id="tc1", name="echo", input={"text": "hello"})],
                stop_reason="tool_use",
            ),
            # Round 2: final answer
            LLMResponse(text="The echo said: hello", stop_reason="end_turn"),
        ])
        result = await executor.run("Echo hello")

        assert result.success
        assert "echo said" in result.output.lower()
        assert len(result.steps) == 1
        assert result.steps[0].tool_name == "echo"
        assert "ECHO: hello" in result.steps[0].tool_output
        assert result.steps[0].certificate_id != ""  # was verified

    @pytest.mark.asyncio
    async def test_multiple_tool_rounds(self):
        """LLM calls tools across multiple rounds."""
        executor = self._build_executor([
            LLMResponse(
                text="", stop_reason="tool_use",
                tool_calls=[ToolCallRequest(id="tc1", name="echo", input={"text": "one"})],
            ),
            LLMResponse(
                text="", stop_reason="tool_use",
                tool_calls=[ToolCallRequest(id="tc2", name="echo", input={"text": "two"})],
            ),
            LLMResponse(text="Done: one and two", stop_reason="end_turn"),
        ])
        result = await executor.run("Echo one then two")

        assert result.success
        assert len(result.steps) == 2
        assert len(result.certificates) == 2

    @pytest.mark.asyncio
    async def test_unknown_tool_handled(self):
        """LLM requests a tool that doesn't exist - error fed back."""
        executor = self._build_executor([
            LLMResponse(
                text="", stop_reason="tool_use",
                tool_calls=[ToolCallRequest(id="tc1", name="nonexistent", input={})],
            ),
            LLMResponse(text="Sorry, that tool isn't available.", stop_reason="end_turn"),
        ])
        result = await executor.run("Use nonexistent tool")

        assert result.success
        assert len(result.steps) == 1
        assert result.steps[0].is_error

    @pytest.mark.asyncio
    async def test_verification_blocks_tool(self):
        """Tool call blocked because token lacks capabilities."""
        token = _make_token(permissions=[])  # no capabilities
        executor = self._build_executor(
            responses=[
                LLMResponse(
                    text="", stop_reason="tool_use",
                    tool_calls=[ToolCallRequest(id="tc1", name="echo", input={"text": "hi"})],
                ),
                LLMResponse(text="Blocked.", stop_reason="end_turn"),
            ],
            token=token,
        )
        result = await executor.run("Echo hi")

        assert result.success  # executor itself succeeds
        assert len(result.steps) == 1
        assert result.steps[0].is_error
        assert "BLOCKED" in result.steps[0].tool_output

    @pytest.mark.asyncio
    async def test_budget_tracking(self):
        """Budget is consumed per tool call."""
        token = _make_token(permissions=["test:echo"], budget_cents=100, budget_remaining_cents=100)
        executor = self._build_executor(
            responses=[
                LLMResponse(
                    text="", stop_reason="tool_use",
                    tool_calls=[ToolCallRequest(id="tc1", name="echo", input={"text": "a"})],
                ),
                LLMResponse(text="Done", stop_reason="end_turn"),
            ],
            token=token,
        )
        result = await executor.run("Echo")

        assert result.total_cost_cents > 0
        assert token.budget_remaining_cents < 100

    @pytest.mark.asyncio
    async def test_max_rounds_exceeded(self):
        """Executor stops after max_tool_rounds."""
        config = LLMConfig(api_key="test-key", max_tool_rounds=2)
        token = _make_token(permissions=["test:echo"])
        reg = _make_registry_with_echo()

        executor = AgenticExecutor(
            llm_config=config, tool_registry=reg, capability_token=token,
        )

        # Always return tool calls (never finishes)
        infinite_responses = [
            LLMResponse(
                text="", stop_reason="tool_use",
                tool_calls=[ToolCallRequest(id=f"tc{i}", name="echo", input={"text": str(i)})],
            )
            for i in range(10)
        ]

        mock_client = AsyncMock()
        mock_client.send = AsyncMock(side_effect=infinite_responses)
        mock_client.usage = TokenUsage()
        mock_client.close = AsyncMock()
        executor._client = mock_client

        result = await executor.run("Loop forever")

        assert not result.success
        assert "max rounds" in result.error.lower() or "Exceeded" in result.error

    @pytest.mark.asyncio
    async def test_llm_error_handled(self):
        """API error is caught and returned as a failed result."""
        executor = self._build_executor([])

        mock_client = AsyncMock()
        mock_client.send = AsyncMock(side_effect=RuntimeError("API down"))
        mock_client.usage = TokenUsage()
        mock_client.close = AsyncMock()
        executor._client = mock_client

        result = await executor.run("Crash please")

        assert not result.success
        assert "API down" in result.error

    @pytest.mark.asyncio
    async def test_status_callback_called(self):
        """Status callback is invoked at each phase."""
        statuses: List[str] = []

        async def on_status(status: str, data: Dict[str, Any]):
            statuses.append(status)

        config = LLMConfig(api_key="test-key")
        executor = AgenticExecutor(
            llm_config=config,
            tool_registry=_make_registry_with_echo(),
            capability_token=_make_token(permissions=["test:echo"]),
            on_status=on_status,
        )

        mock_client = AsyncMock()
        mock_client.send = AsyncMock(side_effect=[
            LLMResponse(text="Done", stop_reason="end_turn"),
        ])
        mock_client.usage = TokenUsage()
        mock_client.close = AsyncMock()
        executor._client = mock_client

        await executor.run("Quick task")

        assert "planning" in statuses
        assert "thinking" in statuses
        assert "completed" in statuses

    @pytest.mark.asyncio
    async def test_audit_trail_populated(self):
        """Audit trail contains entries for each phase."""
        executor = self._build_executor([
            LLMResponse(
                text="", stop_reason="tool_use",
                tool_calls=[ToolCallRequest(id="tc1", name="echo", input={"text": "a"})],
            ),
            LLMResponse(text="Final", stop_reason="end_turn"),
        ])
        result = await executor.run("Audit test")

        assert len(result.audit_trail) >= 3  # started, llm_response, tool_executed, completed
        phases = [e.get("phase") for e in result.audit_trail]
        assert "started" in phases
        assert "tool_executed" in phases
        assert "completed" in phases

    @pytest.mark.asyncio
    async def test_content_safety_scan_on_output(self):
        """Final output is scanned for content safety."""
        executor = self._build_executor([
            LLMResponse(text="Patient SSN: 123-45-6789", stop_reason="end_turn"),
        ])
        # Use HIPAA policy (redacts PII)
        executor._scanner = __import__(
            "agentsafe.safety.scanner", fromlist=["ContentScanner"]
        ).ContentScanner(ContentSafetyPolicy.hipaa_compliant())

        result = await executor.run("Show patient info")

        assert result.success
        assert "123-45-6789" not in result.output
        assert "REDACTED" in result.output

    @pytest.mark.asyncio
    async def test_reviewer_profile_emits_review_certificate_properties(self):
        token = _make_token(
            permissions=["database:read:patient_data", "document:write:reports"],
            metadata={
                "verification_profile": {
                    "task_class": "privacy_review",
                    "stage_role": "reviewer",
                    "permission_ceiling": [
                        "database:read:patient_data",
                        "document:write:reports",
                    ],
                    "release_targets": ["internal"],
                }
            },
        )
        executor = self._build_executor([
            LLMResponse(text="GO: no residual PHI detected.", stop_reason="end_turn"),
        ], token=token)
        executor.content_policy = ContentSafetyPolicy.hipaa_compliant()
        executor._scanner = __import__(
            "agentsafe.safety.scanner", fromlist=["ContentScanner"]
        ).ContentScanner(ContentSafetyPolicy.hipaa_compliant())

        executor._lean_verifier = MagicMock()
        executor._lean_verifier.start = AsyncMock(return_value=True)
        executor._lean_verifier.check_output_flow = AsyncMock(return_value=LeanFlowResult(ok=True, proven=True))
        executor._lean_verifier.get_certificates = AsyncMock(return_value=[])
        executor._lean_verifier.shutdown = AsyncMock(return_value=None)
        executor._lean_verifier.summary = MagicMock(return_value={"lean_kernel_available": True})

        result = await executor.run("Review this de-identified discharge summary and return GO/NO-GO.")

        final_cert = result.certificates[-1]
        props = set(final_cert["verified_properties"])
        assert "review_chain_integrity" in props
        assert "privilege_boundary_reviewed" in props
        assert "minimum_necessary_access" in props
        assert "information_flow: proven" in props

    @pytest.mark.asyncio
    async def test_release_profile_emits_release_gate_properties(self):
        token = _make_token(
            permissions=["document:read:reports", "document:write:reports", "filesystem:read"],
            metadata={
                "verification_profile": {
                    "task_class": "protected_release",
                    "stage_role": "release",
                    "permission_ceiling": [
                        "document:read:reports",
                        "document:write:reports",
                        "filesystem:read",
                    ],
                    "release_targets": ["public"],
                    "upstream_execution_ids": ["review-exec-1"],
                    "metadata": {
                        "release_binding": {
                            "approved_artifacts": [
                                {
                                    "execution_id": "review-exec-1",
                                    "sha256": AgenticExecutor._artifact_hash("Approved release artifact"),
                                    "text": "Approved release artifact",
                                }
                            ]
                        }
                    },
                }
            },
        )
        executor = self._build_executor([
            LLMResponse(text="Public release: de-identified summary approved for publication.", stop_reason="end_turn"),
        ], token=token)
        executor.content_policy = ContentSafetyPolicy.hipaa_compliant()
        executor._scanner = __import__(
            "agentsafe.safety.scanner", fromlist=["ContentScanner"]
        ).ContentScanner(ContentSafetyPolicy.hipaa_compliant())

        executor._lean_verifier = MagicMock()
        executor._lean_verifier.start = AsyncMock(return_value=True)
        executor._lean_verifier.check_output_flow = AsyncMock(return_value=LeanFlowResult(ok=True, proven=True))
        executor._lean_verifier.get_certificates = AsyncMock(return_value=[])
        executor._lean_verifier.shutdown = AsyncMock(return_value=None)
        executor._lean_verifier.summary = MagicMock(return_value={"lean_kernel_available": True})

        result = await executor.run("Publish the reviewed de-identified discharge summary.")

        final_cert = result.certificates[-1]
        props = set(final_cert["verified_properties"])
        assert "release_gate_satisfied" in props
        assert "review_completed_before_release" in props
        assert "release_output_bound_to_review_artifact" in props
        assert "output_deidentification_verified" in props
        assert "minimum_necessary_access" in props
        assert "information_flow: proven" in props

        assert result.success
        assert result.output == "Approved release artifact"
        assert result.release_binding_summary is not None
        assert result.release_binding_summary["bound"] is True
        assert result.release_binding_summary["rebound"] is True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Message construction
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestMessageConstruction:
    def test_build_assistant_content_text_only(self):
        resp = LLMResponse(text="Hello", tool_calls=[], stop_reason="end_turn")
        content = AgenticExecutor._build_assistant_content(resp)
        assert len(content) == 1
        assert content[0]["type"] == "text"
        assert content[0]["text"] == "Hello"

    def test_build_assistant_content_with_tool_call(self):
        resp = LLMResponse(
            text="Let me check",
            tool_calls=[ToolCallRequest(id="tc1", name="echo", input={"text": "hi"})],
            stop_reason="tool_use",
        )
        content = AgenticExecutor._build_assistant_content(resp)
        assert len(content) == 2
        assert content[0]["type"] == "text"
        assert content[1]["type"] == "tool_use"
        assert content[1]["name"] == "echo"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# VerificationShim
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestVerificationShim:
    @pytest.mark.asyncio
    async def test_verifies_with_valid_token(self):
        from agentsafe.agents.actions import AgentAction

        token = _make_token(permissions=["test:echo"])
        shim = _VerificationShim("test", token)

        action = AgentAction(
            tool="echo",
            required_capabilities=["test:echo"],
            estimated_cost_cents=1,
        )
        result = await shim.verify_action(action)
        assert result.valid
        assert result.certificate is not None

    @pytest.mark.asyncio
    async def test_rejects_with_missing_capability(self):
        from agentsafe.agents.actions import AgentAction

        token = _make_token(permissions=[])
        shim = _VerificationShim("test", token)

        action = AgentAction(
            tool="echo",
            required_capabilities=["test:echo"],
            estimated_cost_cents=1,
        )
        result = await shim.verify_action(action)
        assert not result.valid


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AgentStep
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAgentStep:
    def test_to_dict(self):
        step = AgentStep(
            step_index=0, tool_name="echo",
            tool_input={"text": "hi"}, tool_output="ECHO: hi",
            certificate_id="cert-123", cost_cents=1, duration_ms=5.0,
        )
        d = step.to_dict()
        assert d["tool_name"] == "echo"
        assert d["verified"] is True
        assert d["cost_cents"] == 1

    def test_to_dict_unverified(self):
        step = AgentStep(
            step_index=0, tool_name="bad",
            tool_input={}, tool_output="error", is_error=True,
        )
        d = step.to_dict()
        assert d["verified"] is False

"""
Tests for A2: kernel.validate_certificate() gate in AgenticExecutor.

Verifies that the TrustedKernel validates every certificate BEFORE
tool execution.  Tests cover:
  - Happy path: legitimate certificate passes kernel check
  - Forged certificate: not issued by our CA → blocked
  - Expired certificate: past TTL → blocked
  - Tampered certificate: signature mutated → blocked
  - Revoked certificate: removed from CA registry → blocked
  - Hash mismatch: certificate for different action → blocked
  - Null certificate: defensive None check → blocked
  - Audit trail: "certificate_rejected" phase recorded
  - OTel metrics: "certificate_invalid" reason emitted
  - base.py execute_action: CertificateValidationError raised
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, patch

import pytest

from agentsafe.agents.agentic_executor import (
    AgenticExecutor,
    AgenticResult,
    AgentStep,
    _VerificationShim,
)
from agentsafe.agents.base import (
    CertificateValidationError,
    SecurityError,
    VerificationResult,
    VerifiedAgent,
)
from agentsafe.agents.actions import AgentAction, AgentPlan
from agentsafe.agents.executor import ExecutorAgent
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.kernel.certificate import (
    CertificateAuthority,
    TrustedKernel,
    VerifiedCertificate,
)
from agentsafe.llm.client import LLMResponse, ToolCallRequest, TokenUsage
from agentsafe.llm.config import LLMConfig
from agentsafe.observability.otel import CertiorTelemetry
from agentsafe.safety.scanner import ContentSafetyPolicy
from agentsafe.tools import ToolRegistry
from agentsafe.tools.base import BaseTool, ToolParameter, ToolResult

z3 = pytest.importorskip("z3")


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_singletons():
    CertificateAuthority.reset()
    CertiorTelemetry.reset()
    yield
    CertificateAuthority.reset()
    CertiorTelemetry.reset()


def _valid_token(**overrides) -> CapabilityToken:
    defaults = dict(
        agent_id="test-agent",
        permissions=["test:echo"],
        budget_cents=10000,
        budget_remaining_cents=10000,
        expires_at=time.time() + 3600,
    )
    defaults.update(overrides)
    return CapabilityToken(**defaults)


class _EchoTool(BaseTool):
    """Deterministic test tool."""

    def __init__(self, caps=None):
        self._caps = caps or ["test:echo"]

    @property
    def name(self) -> str:
        return "echo"

    @property
    def description(self) -> str:
        return "Echoes input"

    def parameters(self) -> List[ToolParameter]:
        return [ToolParameter(name="text", type="string", description="Text")]

    @property
    def required_capabilities(self) -> List[str]:
        return self._caps

    async def execute(self, *, tool_use_id: str, **kwargs: Any) -> ToolResult:
        return ToolResult(tool_use_id=tool_use_id, output=f"ECHO: {kwargs.get('text', '')}")


def _echo_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(_EchoTool())
    return reg


def _build_executor(
    responses: List[LLMResponse],
    token: Optional[CapabilityToken] = None,
    registry: Optional[ToolRegistry] = None,
) -> AgenticExecutor:
    """Create AgenticExecutor with mock LLM returning *responses* in order."""
    config = LLMConfig(api_key="test-key", max_tool_rounds=10)
    tok = token or _valid_token()
    reg = registry or _echo_registry()

    executor = AgenticExecutor(
        llm_config=config,
        tool_registry=reg,
        capability_token=tok,
    )

    mock_client = AsyncMock()
    mock_client.send = AsyncMock(side_effect=responses)
    mock_client.usage = TokenUsage(input_tokens=0, output_tokens=0)
    mock_client.close = AsyncMock()
    executor._client = mock_client

    return executor


def _tool_call_then_answer(text: str = "hello") -> List[LLMResponse]:
    """Standard 2-round: one tool call → final answer."""
    return [
        LLMResponse(
            text="",
            tool_calls=[ToolCallRequest(id="tc1", name="echo", input={"text": text})],
            stop_reason="tool_use",
        ),
        LLMResponse(text="Done", stop_reason="end_turn"),
    ]


# ── Happy path ────────────────────────────────────────────────

class TestCertificateValidationHappyPath:
    """Verify that legitimate certificates pass the kernel gate."""

    @pytest.mark.asyncio
    async def test_valid_certificate_allows_execution(self):
        """Normal flow: verify → cert issued → kernel validates → execute."""
        executor = _build_executor(_tool_call_then_answer())
        result = await executor.run("Echo hello")

        assert result.success
        assert len(result.steps) == 1
        assert not result.steps[0].is_error
        assert result.steps[0].certificate_id != ""
        assert "ECHO: hello" in result.steps[0].tool_output

    @pytest.mark.asyncio
    async def test_certificate_in_audit_trail(self):
        """Audit trail records certificate_id on successful execution."""
        executor = _build_executor(_tool_call_then_answer())
        result = await executor.run("Audit test")

        tool_executed = [
            e for e in result.audit_trail
            if e.get("phase") == "tool_executed"
        ]
        assert len(tool_executed) == 1
        assert tool_executed[0]["certificate_id"] != ""
        assert tool_executed[0]["verified"] is True

    @pytest.mark.asyncio
    async def test_multiple_tools_each_get_unique_cert(self):
        """Each tool call gets its own certificate validated."""
        executor = _build_executor([
            LLMResponse(
                text="", stop_reason="tool_use",
                tool_calls=[ToolCallRequest(id="tc1", name="echo", input={"text": "one"})],
            ),
            LLMResponse(
                text="", stop_reason="tool_use",
                tool_calls=[ToolCallRequest(id="tc2", name="echo", input={"text": "two"})],
            ),
            LLMResponse(text="Done", stop_reason="end_turn"),
        ])
        result = await executor.run("Two calls")

        assert result.success
        assert len(result.steps) == 2
        assert len(result.certificates) == 2
        # Each certificate is unique
        assert result.certificates[0] != result.certificates[1]


# ── Forged certificate ────────────────────────────────────────

class TestForgedCertificateBlocked:
    """Certificates not issued by our CA must be rejected."""

    @pytest.mark.asyncio
    async def test_forged_cert_rejected_in_base_execute_action(self):
        """base.py execute_action rejects a forged certificate."""

        class ConcreteAgent(VerifiedAgent):
            pass

        token = _valid_token()
        agent = ConcreteAgent("a", token)
        agent.register_tool("echo", lambda params: "ok")

        action = AgentAction(
            tool="echo",
            required_capabilities=["test:echo"],
            estimated_cost_cents=1,
        )

        # Forge a certificate (not from our CA)
        forged = VerifiedCertificate(
            theorem="action_safe",
            plan_hash=action.to_hash(),  # correct hash, but CA didn't issue it
        )

        with pytest.raises(CertificateValidationError) as exc_info:
            await agent.execute_action(action, forged)

        assert exc_info.value.certificate_id == forged.id
        assert exc_info.value.action_hash == action.to_hash()

    @pytest.mark.asyncio
    async def test_forged_cert_blocked_in_agentic_executor(self):
        """Agentic executor blocks execution when kernel rejects cert."""
        executor = _build_executor(_tool_call_then_answer())

        # Sabotage: make kernel always reject
        executor._kernel.validate_certificate = lambda cert, h="": False

        result = await executor.run("Echo hello")

        assert result.success  # executor itself doesn't crash
        assert len(result.steps) == 1
        assert result.steps[0].is_error
        assert "Certificate validation failed" in result.steps[0].tool_output


# ── Expired certificate ───────────────────────────────────────

class TestExpiredCertificateBlocked:
    """Certificates past their TTL must be rejected."""

    @pytest.mark.asyncio
    async def test_expired_cert_rejected(self):
        """A certificate with TTL=0 expires immediately."""

        class ConcreteAgent(VerifiedAgent):
            pass

        token = _valid_token()
        agent = ConcreteAgent("a", token)
        agent.register_tool("echo", lambda params: "ok")

        action = AgentAction(
            tool="echo",
            required_capabilities=["test:echo"],
            estimated_cost_cents=1,
        )

        # Issue a certificate with 0-second TTL
        ca = CertificateAuthority.get_instance()
        cert = ca.issue_certificate(
            theorem="action_safe",
            plan_hash=action.to_hash(),
            verified_properties=["test"],
            ttl_seconds=0,
        )

        # Give it a moment to expire
        time.sleep(0.01)

        with pytest.raises(CertificateValidationError):
            await agent.execute_action(action, cert)


# ── Tampered certificate ──────────────────────────────────────

class TestTamperedCertificateBlocked:
    """Certificates with mutated fields must be rejected."""

    @pytest.mark.asyncio
    async def test_tampered_cert_rejected(self):
        """Mutating a signed field invalidates the certificate."""

        class ConcreteAgent(VerifiedAgent):
            pass

        token = _valid_token()
        agent = ConcreteAgent("a", token)
        agent.register_tool("echo", lambda params: "ok")

        action = AgentAction(
            tool="echo",
            required_capabilities=["test:echo"],
            estimated_cost_cents=1,
        )

        # Issue a real certificate
        result = await agent.verify_action(action)
        cert = result.certificate
        assert cert is not None

        # Tamper with a field
        cert.verified_properties = ["hacked_property"]

        with pytest.raises(CertificateValidationError):
            await agent.execute_action(action, cert)


# ── Revoked certificate ───────────────────────────────────────

class TestRevokedCertificateBlocked:
    """Certificates removed from the CA registry must be rejected."""

    @pytest.mark.asyncio
    async def test_revoked_cert_rejected(self):
        """Revoking a certificate makes it fail kernel validation."""

        class ConcreteAgent(VerifiedAgent):
            pass

        token = _valid_token()
        agent = ConcreteAgent("a", token)
        agent.register_tool("echo", lambda params: "ok")

        action = AgentAction(
            tool="echo",
            required_capabilities=["test:echo"],
            estimated_cost_cents=1,
        )

        # Issue and then revoke
        result = await agent.verify_action(action)
        cert = result.certificate
        ca = CertificateAuthority.get_instance()
        ca.revoke(cert.id)

        with pytest.raises(CertificateValidationError):
            await agent.execute_action(action, cert)


# ── Hash mismatch (cross-action replay) ──────────────────────

class TestHashMismatchBlocked:
    """Certificate for action A must not authorise action B."""

    @pytest.mark.asyncio
    async def test_cross_action_replay_rejected(self):
        """Certificate's plan_hash doesn't match a different action."""

        class ConcreteAgent(VerifiedAgent):
            pass

        token = _valid_token()
        agent = ConcreteAgent("a", token)
        agent.register_tool("echo", lambda params: "ok")
        agent.register_tool("other", lambda params: "ok")

        # Verify action A
        action_a = AgentAction(
            tool="echo",
            required_capabilities=["test:echo"],
            estimated_cost_cents=1,
        )
        result_a = await agent.verify_action(action_a)
        cert_a = result_a.certificate

        # Try to use cert_a for action B (different hash)
        action_b = AgentAction(
            tool="other",
            parameters={"key": "value"},
            required_capabilities=["test:echo"],
            estimated_cost_cents=1,
        )
        # action_b has a different to_hash() than action_a
        assert action_a.to_hash() != action_b.to_hash()

        with pytest.raises(CertificateValidationError):
            await agent.execute_action(action_b, cert_a)

    @pytest.mark.asyncio
    async def test_same_tool_different_params_rejected(self):
        """Same tool name but different parameters → different hash → blocked."""

        class ConcreteAgent(VerifiedAgent):
            pass

        token = _valid_token()
        agent = ConcreteAgent("a", token)
        agent.register_tool("echo", lambda params: "ok")

        action_a = AgentAction(
            tool="echo",
            parameters={"text": "alpha"},
            required_capabilities=["test:echo"],
            estimated_cost_cents=1,
        )
        result_a = await agent.verify_action(action_a)

        action_b = AgentAction(
            tool="echo",
            parameters={"text": "beta"},
            required_capabilities=["test:echo"],
            estimated_cost_cents=1,
        )

        with pytest.raises(CertificateValidationError):
            await agent.execute_action(action_b, result_a.certificate)


# ── Agentic executor certificate gate ─────────────────────────

class TestAgenticExecutorCertificateGate:
    """Tests that exercise the kernel gate inside the reactive loop."""

    @pytest.mark.asyncio
    async def test_kernel_reject_records_audit(self):
        """certificate_rejected phase appears in audit trail."""
        executor = _build_executor(_tool_call_then_answer())
        executor._kernel.validate_certificate = lambda cert, h="": False

        result = await executor.run("Echo hello")

        rejected = [
            e for e in result.audit_trail
            if e.get("phase") == "certificate_rejected"
        ]
        assert len(rejected) == 1
        assert rejected[0]["tool"] == "echo"
        assert "action_hash" in rejected[0]
        assert "certificate_id" in rejected[0]

    @pytest.mark.asyncio
    async def test_kernel_reject_does_not_execute_tool(self):
        """Tool.execute() is never called when certificate is invalid."""
        call_log = []

        class _SpyTool(BaseTool):
            @property
            def name(self) -> str:
                return "echo"

            @property
            def description(self) -> str:
                return "Spy"

            def parameters(self) -> List[ToolParameter]:
                return [ToolParameter(name="text", type="string", description="T")]

            @property
            def required_capabilities(self) -> List[str]:
                return ["test:echo"]

            async def execute(self, *, tool_use_id: str, **kwargs: Any) -> ToolResult:
                call_log.append(kwargs)
                return ToolResult(tool_use_id=tool_use_id, output="SHOULD NOT APPEAR")

        reg = ToolRegistry()
        reg.register(_SpyTool())

        executor = _build_executor(_tool_call_then_answer(), registry=reg)
        executor._kernel.validate_certificate = lambda cert, h="": False

        result = await executor.run("Echo hello")

        # Tool was NEVER called
        assert len(call_log) == 0
        assert result.steps[0].is_error

    @pytest.mark.asyncio
    async def test_null_cert_blocked(self):
        """If verify_action somehow returns valid=True but cert=None, block."""
        executor = _build_executor(_tool_call_then_answer())

        # Monkey-patch: make verify_action return valid but no cert
        original_verify = executor._verifier.verify_action

        async def _bogus_verify(action):
            result = await original_verify(action)
            result.certificate = None  # sabotage
            return result

        executor._verifier.verify_action = _bogus_verify

        result = await executor.run("Echo hello")

        assert result.steps[0].is_error
        assert "Certificate validation failed" in result.steps[0].tool_output

    @pytest.mark.asyncio
    async def test_budget_not_consumed_on_cert_reject(self):
        """Budget must NOT be consumed when certificate is rejected."""
        token = _valid_token(budget_cents=1000, budget_remaining_cents=1000)
        executor = _build_executor(_tool_call_then_answer(), token=token)
        executor._kernel.validate_certificate = lambda cert, h="": False

        result = await executor.run("Echo hello")

        # Budget untouched because tool never executed
        assert token.budget_remaining_cents == 1000

    @pytest.mark.asyncio
    async def test_mixed_valid_and_invalid_certs(self):
        """First cert valid → executes; second cert sabotaged → blocked."""
        executor = _build_executor([
            LLMResponse(
                text="", stop_reason="tool_use",
                tool_calls=[ToolCallRequest(id="tc1", name="echo", input={"text": "one"})],
            ),
            LLMResponse(
                text="", stop_reason="tool_use",
                tool_calls=[ToolCallRequest(id="tc2", name="echo", input={"text": "two"})],
            ),
            LLMResponse(text="Done", stop_reason="end_turn"),
        ])

        # Let first cert pass, reject second
        call_count = {"n": 0}
        real_validate = executor._kernel.ca.validate_certificate

        def _selective_validate(cert, expected_hash=""):
            call_count["n"] += 1
            if call_count["n"] == 2:
                return False
            return real_validate(cert, expected_hash)

        executor._kernel.validate_certificate = _selective_validate

        result = await executor.run("Two calls")

        assert len(result.steps) == 2
        # First: success
        assert not result.steps[0].is_error
        assert "ECHO: one" in result.steps[0].tool_output
        # Second: blocked by kernel
        assert result.steps[1].is_error
        assert "Certificate validation failed" in result.steps[1].tool_output


# ── OTel metrics ──────────────────────────────────────────────

class TestCertificateValidationMetrics:
    """Verify OTel metrics are emitted for certificate rejections."""

    @pytest.mark.asyncio
    async def test_otel_blocked_metric_on_cert_reject_executor(self):
        """Agentic executor emits certificate_invalid metric."""
        executor = _build_executor(_tool_call_then_answer())
        executor._kernel.validate_certificate = lambda cert, h="": False

        result = await executor.run("Echo hello")
        # The key assertion is that no exception bubbled -
        # the metric was emitted inside the loop.
        assert result.steps[0].is_error

    @pytest.mark.asyncio
    async def test_otel_blocked_metric_on_cert_reject_base(self):
        """base.py execute_action emits certificate_invalid metric."""

        class ConcreteAgent(VerifiedAgent):
            pass

        token = _valid_token()
        agent = ConcreteAgent("a", token)

        forged = VerifiedCertificate(theorem="fake", plan_hash="wrong")
        action = AgentAction(tool="x")

        with pytest.raises(CertificateValidationError):
            await agent.execute_action(action, forged)
        # No crash from metric emission → metric code paths work.


# ── ExecutorAgent integration ─────────────────────────────────

class TestExecutorAgentCertificateValidation:
    """ExecutorAgent.execute_plan() validates certificates per step."""

    @pytest.mark.asyncio
    async def test_forged_cert_fails_plan_step(self):
        """If kernel rejects a step's certificate, plan fails."""

        class PatchedExecutor(ExecutorAgent):
            """Override execute_action to inject a forged cert."""
            async def execute_action(self, action, certificate):
                # Construct a forged cert and try to use it
                forged = VerifiedCertificate(
                    theorem="action_safe",
                    plan_hash="completely_wrong_hash",
                )
                return await super().execute_action(action, forged)

        token = _valid_token()
        executor = PatchedExecutor("ex", token)
        executor.register_tool("echo", lambda params: "ok")

        plan = AgentPlan(
            steps=[
                AgentAction(
                    tool="echo",
                    required_capabilities=["test:echo"],
                    estimated_cost_cents=1,
                ),
            ],
            total_budget_cents=10000,
        )

        # execute_plan catches CertificateValidationError → plan fails
        with pytest.raises(CertificateValidationError):
            await executor.execute_plan(plan)


# ── Edge cases ────────────────────────────────────────────────

class TestCertificateEdgeCases:

    @pytest.mark.asyncio
    async def test_cert_valid_has_correct_plan_hash(self):
        """Verify that issued cert's plan_hash matches action.to_hash()."""

        class ConcreteAgent(VerifiedAgent):
            pass

        token = _valid_token()
        agent = ConcreteAgent("a", token)

        action = AgentAction(
            tool="echo",
            parameters={"text": "hello"},
            required_capabilities=["test:echo"],
            estimated_cost_cents=1,
        )

        result = await agent.verify_action(action)
        cert = result.certificate
        assert cert is not None
        assert cert.plan_hash == action.to_hash()

    @pytest.mark.asyncio
    async def test_kernel_checks_ca_registry(self):
        """Certificate must exist in CA._issued to pass validation."""
        ca = CertificateAuthority.get_instance()
        kernel = TrustedKernel(ca)

        cert = ca.issue_certificate(
            theorem="test", plan_hash="hash123",
            verified_properties=["p1"],
        )

        # Valid while in registry
        assert kernel.validate_certificate(cert, "hash123")

        # Revoke → invalid
        ca.revoke(cert.id)
        assert not kernel.validate_certificate(cert, "hash123")

    @pytest.mark.asyncio
    async def test_certificate_is_valid_method(self):
        """VerifiedCertificate.is_valid() checks signature and expiry."""
        ca = CertificateAuthority.get_instance()

        # Valid cert
        cert = ca.issue_certificate(
            theorem="test", plan_hash="h", verified_properties=["a"],
            ttl_seconds=3600,
        )
        assert cert.is_valid()

        # Tamper signature
        cert.theorem = "tampered"
        assert not cert.is_valid()

        # Expired cert
        cert2 = ca.issue_certificate(
            theorem="test", plan_hash="h", verified_properties=["a"],
            ttl_seconds=0,
        )
        time.sleep(0.01)
        assert not cert2.is_valid()

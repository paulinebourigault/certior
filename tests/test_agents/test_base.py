"""
Tests for VerifiedAgent base class.
IMPROVED: Tests exercise the REAL Z3 verification path.
"""
import pytest
from agentsafe.agents.base import (
    VerifiedAgent, VerificationResult, VerificationError,
    SecurityError, BudgetExceededError,
)
from agentsafe.agents.actions import AgentAction
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.kernel.certificate import CertificateAuthority
from agentsafe.observability.otel import CertiorTelemetry

z3 = pytest.importorskip("z3")


class ConcreteAgent(VerifiedAgent):
    """Concrete implementation for testing."""
    pass


class TestVerifiedAgentZ3:
    """Tests that exercise the REAL Z3 verification path."""

    def setup_method(self):
        CertificateAuthority.reset()
        CertiorTelemetry.reset()

    @pytest.mark.asyncio
    async def test_verify_with_z3_success(self):
        token = CapabilityToken(
            permissions=["network:http:read"],
            budget_cents=1000, budget_remaining_cents=1000,
        )
        agent = ConcreteAgent("test", token)
        action = AgentAction(
            tool="web_browsing",
            required_capabilities=["network:http:read"],
            estimated_cost_cents=100,
        )
        result = await agent.verify_action(action)
        assert result.valid
        assert result.used_z3  # Confirms Z3 was used
        assert result.certificate is not None
        assert "capability_coverage: proven" in result.properties
        assert "budget_sufficient: proven" in result.properties

    @pytest.mark.asyncio
    async def test_verify_z3_missing_capability(self):
        token = CapabilityToken(permissions=["other:perm"], budget_cents=1000, budget_remaining_cents=1000)
        agent = ConcreteAgent("test", token)
        action = AgentAction(
            tool="web",
            required_capabilities=["network:http:read"],
            estimated_cost_cents=100,
        )
        result = await agent.verify_action(action)
        assert not result.valid
        assert result.used_z3
        assert any("missing" in v for v in result.violations)

    @pytest.mark.asyncio
    async def test_verify_z3_budget_exceeded(self):
        token = CapabilityToken(
            permissions=["a"], budget_cents=50, budget_remaining_cents=50,
        )
        agent = ConcreteAgent("test", token)
        action = AgentAction(
            tool="x", required_capabilities=["a"],
            estimated_cost_cents=100,
        )
        result = await agent.verify_action(action)
        assert not result.valid
        assert any("budget" in v for v in result.violations)

    @pytest.mark.asyncio
    async def test_verify_z3_wildcard_capability(self):
        token = CapabilityToken(
            permissions=["network:*"], budget_cents=1000, budget_remaining_cents=1000,
        )
        agent = ConcreteAgent("test", token)
        action = AgentAction(
            tool="web",
            required_capabilities=["network:http:read"],
            estimated_cost_cents=10,
        )
        result = await agent.verify_action(action)
        assert result.valid
        assert result.used_z3

    @pytest.mark.asyncio
    async def test_verify_z3_information_flow(self):
        token = CapabilityToken(
            permissions=["a"], budget_cents=1000, budget_remaining_cents=1000,
        )
        agent = ConcreteAgent("test", token)
        action = AgentAction(
            tool="x", required_capabilities=["a"],
            estimated_cost_cents=10,
            input_labels=["public"],
            output_labels=["internal"],
        )
        result = await agent.verify_action(action)
        assert result.valid
        assert any("information_flow" in p for p in result.properties)

    @pytest.mark.asyncio
    async def test_execute_with_certificate(self):
        token = CapabilityToken(
            permissions=["a"], budget_cents=1000, budget_remaining_cents=1000,
        )
        agent = ConcreteAgent("test", token)
        agent.register_tool("test_tool", lambda params: "result")
        action = AgentAction(
            tool="test_tool", required_capabilities=["a"],
            estimated_cost_cents=10,
        )
        verification = await agent.verify_action(action)
        result = await agent.execute_action(action, verification.certificate)
        assert result.success

    @pytest.mark.asyncio
    async def test_execute_invalid_certificate(self):
        token = CapabilityToken(permissions=["a"], budget_cents=1000, budget_remaining_cents=1000)
        agent = ConcreteAgent("test", token)
        from agentsafe.kernel.certificate import VerifiedCertificate
        fake_cert = VerifiedCertificate(theorem="fake", plan_hash="wrong")
        action = AgentAction(tool="x")
        with pytest.raises(SecurityError):
            await agent.execute_action(action, fake_cert)

    @pytest.mark.asyncio
    async def test_solve_time_recorded(self):
        token = CapabilityToken(permissions=["a"], budget_cents=1000, budget_remaining_cents=1000)
        agent = ConcreteAgent("test", token)
        action = AgentAction(tool="x", required_capabilities=["a"], estimated_cost_cents=10)
        result = await agent.verify_action(action)
        assert result.solve_time_ms > 0

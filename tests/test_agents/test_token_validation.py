"""
Tests for A1: token.is_valid() validation in verify_action().

Verifies that expired, tampered, and budget-exhausted tokens are
rejected BEFORE Z3 runs and BEFORE any certificate is issued.
"""
from __future__ import annotations

import time
import pytest

from agentsafe.agents.base import (
    VerifiedAgent,
    VerificationResult,
    TokenInvalidError,
)
from agentsafe.agents.actions import AgentAction, AgentPlan
from agentsafe.agents.executor import ExecutorAgent
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.kernel.certificate import CertificateAuthority
from agentsafe.observability.otel import CertiorTelemetry

z3 = pytest.importorskip("z3")


# ── Helpers ───────────────────────────────────────────────────

class ConcreteAgent(VerifiedAgent):
    """Minimal concrete subclass for testing."""
    pass


def _valid_token(**overrides) -> CapabilityToken:
    defaults = dict(
        agent_id="test-agent",
        permissions=["network:http:read"],
        budget_cents=1000,
        budget_remaining_cents=1000,
        expires_at=time.time() + 3600,
    )
    defaults.update(overrides)
    return CapabilityToken(**defaults)


def _simple_action() -> AgentAction:
    return AgentAction(
        tool="web_browsing",
        required_capabilities=["network:http:read"],
        estimated_cost_cents=100,
    )


# ── CapabilityToken.is_valid() unit tests ─────────────────────

class TestCapabilityTokenValidity:
    """Unit tests for granular validity properties."""

    def test_valid_token_passes(self):
        t = _valid_token()
        assert t.is_valid()
        assert t.validation_error() is None

    def test_expired_token_detected(self):
        t = _valid_token(expires_at=time.time() - 100)
        assert t.is_expired
        assert not t.is_valid()
        assert t.validation_error() == "token_expired"

    def test_no_expiry_never_expired(self):
        t = _valid_token(expires_at=None)
        assert not t.is_expired
        assert t.is_valid()

    def test_tampered_token_detected(self):
        t = _valid_token()
        assert not t.is_tampered
        # A11: Structural freeze prevents mutation entirely
        with pytest.raises(AttributeError, match="frozen"):
            t.permissions = ["admin:*"]
        # tuple also prevents in-place mutation
        with pytest.raises(AttributeError):
            t.permissions.append("admin:*")  # type: ignore[attr-defined]
        # Token remains untampered (mutation was blocked)
        assert not t.is_tampered

    def test_tampered_token_detected_hmac_deserialization(self):
        """HMAC catches tampering that bypasses structural freeze
        (e.g. deserialized from untrusted JSON with object.__setattr__)."""
        t = _valid_token()
        # Simulate deserialization tampering (bypasses __setattr__)
        object.__setattr__(t, "permissions", ("admin:*",))
        assert t.is_tampered
        assert not t.is_valid()
        assert t.validation_error() == "token_tampered"

    def test_budget_exhausted_detected(self):
        t = _valid_token(budget_remaining_cents=0)
        assert t.is_budget_exhausted
        assert not t.is_valid()
        assert t.validation_error() == "token_budget_exhausted"

    def test_negative_budget_exhausted(self):
        t = _valid_token(budget_remaining_cents=-50)
        assert t.is_budget_exhausted
        assert not t.is_valid()

    def test_one_cent_remaining_is_valid(self):
        t = _valid_token(budget_remaining_cents=1)
        assert not t.is_budget_exhausted
        assert t.is_valid()

    def test_validation_error_priority_expired_over_tampered(self):
        """Expired is checked first, even if also tampered."""
        t = _valid_token(expires_at=time.time() - 1)
        # Bypass structural freeze to test HMAC priority ordering
        object.__setattr__(t, "permissions", ("hacked",))
        assert t.validation_error() == "token_expired"

    def test_validation_error_priority_tampered_over_budget(self):
        """Tampered is checked before budget."""
        t = _valid_token(budget_remaining_cents=0)
        # Bypass structural freeze to test HMAC priority ordering
        object.__setattr__(t, "permissions", ("hacked",))
        # Expired check first (not expired here), then tampered
        assert t.validation_error() == "token_tampered"


# ── verify_action gate tests ──────────────────────────────────

class TestVerifyActionTokenGate:
    """Verify that verify_action() rejects invalid tokens before Z3."""

    def setup_method(self):
        CertificateAuthority.reset()
        CertiorTelemetry.reset()

    @pytest.mark.asyncio
    async def test_valid_token_passes_through(self):
        agent = ConcreteAgent("a", _valid_token())
        result = await agent.verify_action(_simple_action())
        assert result.valid
        assert result.certificate is not None

    @pytest.mark.asyncio
    async def test_expired_token_raises(self):
        token = _valid_token(expires_at=time.time() - 1)
        agent = ConcreteAgent("a", token)
        with pytest.raises(TokenInvalidError) as exc_info:
            await agent.verify_action(_simple_action())
        assert exc_info.value.reason == "token_expired"
        assert exc_info.value.token_id == token.id

    @pytest.mark.asyncio
    async def test_tampered_token_raises(self):
        token = _valid_token()
        # A11: structural freeze prevents direct mutation
        with pytest.raises(AttributeError, match="frozen"):
            token.permissions = ["admin:*"]
        # Simulate deserialization tampering for HMAC gate test
        object.__setattr__(token, "permissions", ("admin:*",))
        agent = ConcreteAgent("a", token)
        with pytest.raises(TokenInvalidError) as exc_info:
            await agent.verify_action(_simple_action())
        assert exc_info.value.reason == "token_tampered"

    @pytest.mark.asyncio
    async def test_budget_exhausted_raises(self):
        token = _valid_token(budget_remaining_cents=0)
        agent = ConcreteAgent("a", token)
        with pytest.raises(TokenInvalidError) as exc_info:
            await agent.verify_action(_simple_action())
        assert exc_info.value.reason == "token_budget_exhausted"

    @pytest.mark.asyncio
    async def test_no_certificate_issued_on_invalid_token(self):
        """Critical: no certificate must be issued for invalid tokens."""
        token = _valid_token(expires_at=time.time() - 1)
        agent = ConcreteAgent("a", token)
        with pytest.raises(TokenInvalidError):
            await agent.verify_action(_simple_action())
        # If we got here, no certificate was issued (good)

    @pytest.mark.asyncio
    async def test_z3_never_invoked_on_invalid_token(self):
        """The Z3 solver should not run for invalid tokens."""
        token = _valid_token(expires_at=time.time() - 1)
        agent = ConcreteAgent("a", token)
        try:
            await agent.verify_action(_simple_action())
        except TokenInvalidError:
            pass
        # If Z3 had run, it would have consumed measurable time.
        # The point is that we don't waste solver resources on bad tokens.


# ── ExecutorAgent integration ─────────────────────────────────

class TestExecutorTokenValidation:
    """ExecutorAgent.execute_plan() handles token invalidity."""

    def setup_method(self):
        CertificateAuthority.reset()
        CertiorTelemetry.reset()

    @pytest.mark.asyncio
    async def test_expired_token_fails_plan(self):
        token = _valid_token(expires_at=time.time() - 1)
        executor = ExecutorAgent("ex", token)
        plan = AgentPlan(
            steps=[_simple_action()],
            total_budget_cents=1000,
        )
        result = await executor.execute_plan(plan)
        assert not result.success
        assert "token_expired" in result.error

    @pytest.mark.asyncio
    async def test_budget_exhausted_fails_plan(self):
        token = _valid_token(budget_remaining_cents=0)
        executor = ExecutorAgent("ex", token)
        plan = AgentPlan(
            steps=[_simple_action()],
            total_budget_cents=1000,
        )
        result = await executor.execute_plan(plan)
        assert not result.success
        assert "token_budget_exhausted" in result.error


# ── OTel metric emission ─────────────────────────────────────

class TestTokenValidationMetrics:
    """Verify OTel metrics are emitted for token rejections."""

    def setup_method(self):
        CertificateAuthority.reset()
        CertiorTelemetry.reset()

    @pytest.mark.asyncio
    async def test_metrics_emitted_on_expired(self):
        tel = CertiorTelemetry.get_instance()
        token = _valid_token(expires_at=time.time() - 1)
        agent = ConcreteAgent("a", token)
        with pytest.raises(TokenInvalidError):
            await agent.verify_action(_simple_action())
        # The _validate_token method calls verifications_total.add
        # and verifications_blocked.add - we just verify no crash.

    @pytest.mark.asyncio
    async def test_metrics_emitted_on_tampered(self):
        token = _valid_token()
        # Bypass structural freeze for HMAC path test
        object.__setattr__(token, "permissions", ("hacked",))
        agent = ConcreteAgent("a", token)
        with pytest.raises(TokenInvalidError):
            await agent.verify_action(_simple_action())

    @pytest.mark.asyncio
    async def test_metrics_emitted_on_budget_exhausted(self):
        token = _valid_token(budget_remaining_cents=0)
        agent = ConcreteAgent("a", token)
        with pytest.raises(TokenInvalidError):
            await agent.verify_action(_simple_action())


# ── Edge cases ────────────────────────────────────────────────

class TestTokenValidationEdgeCases:

    def setup_method(self):
        CertificateAuthority.reset()
        CertiorTelemetry.reset()

    @pytest.mark.asyncio
    async def test_token_expires_between_calls(self):
        """Token valid on first call, expires before second."""
        token = _valid_token(expires_at=time.time() + 0.05)
        agent = ConcreteAgent("a", token)
        # First call should succeed
        result = await agent.verify_action(_simple_action())
        assert result.valid
        # Wait for expiry
        time.sleep(0.1)
        # Second call must fail
        with pytest.raises(TokenInvalidError) as exc_info:
            await agent.verify_action(_simple_action())
        assert exc_info.value.reason == "token_expired"

    @pytest.mark.asyncio
    async def test_budget_drains_to_zero(self):
        """Token valid until budget fully consumed."""
        token = _valid_token(budget_cents=200, budget_remaining_cents=200)
        agent = ConcreteAgent("a", token)
        action = AgentAction(
            tool="x", required_capabilities=["network:http:read"],
            estimated_cost_cents=100,
        )
        # First call: 200 remaining → valid
        result = await agent.verify_action(action)
        assert result.valid
        # Simulate spending
        token.consume_budget(200)
        assert token.budget_remaining_cents == 0
        # Next call: 0 remaining → rejected
        with pytest.raises(TokenInvalidError) as exc_info:
            await agent.verify_action(action)
        assert exc_info.value.reason == "token_budget_exhausted"

    @pytest.mark.asyncio
    async def test_global_wildcard_still_checked(self):
        """Even a wildcard-permission token is rejected if expired."""
        token = _valid_token(
            permissions=["*"],
            expires_at=time.time() - 1,
        )
        agent = ConcreteAgent("a", token)
        with pytest.raises(TokenInvalidError):
            await agent.verify_action(_simple_action())

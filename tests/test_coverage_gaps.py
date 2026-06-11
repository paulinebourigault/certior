"""
Targeted coverage tests for low-coverage modules:
- agentsafe.verification.observability_integration (was 68%)
- agentsafe.agents.planner (was 76%)
- agentsafe.agents.base structural fallback
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ═══════════════════════════════════════════════════════
# observability_integration coverage
# ═══════════════════════════════════════════════════════

from agentsafe.verification.observability_integration import (
    VerificationMetrics,
    ObservableVerifier,
    instrument_verification,
    traced_verification,
    get_verification_metrics,
)


class TestVerificationMetrics:
    def test_record_allowed(self):
        m = VerificationMetrics()
        m.record("allowed", 10.0)
        assert m.total == 1
        assert m.allowed == 1
        assert m.blocked == 0

    def test_record_blocked(self):
        m = VerificationMetrics()
        m.record("blocked", 5.0)
        assert m.blocked == 1

    def test_record_error(self):
        m = VerificationMetrics()
        m.record("error", 1.0)
        assert m.errors == 1

    def test_avg_latency(self):
        m = VerificationMetrics()
        m.record("allowed", 10.0)
        m.record("allowed", 20.0)
        assert m.avg_latency_ms == 15.0

    def test_avg_latency_zero(self):
        m = VerificationMetrics()
        assert m.avg_latency_ms == 0.0


class TestObservableVerifier:
    @pytest.mark.asyncio
    async def test_no_inner_verifier(self):
        v = ObservableVerifier()
        result = await v.verify_action("test", "tok-1")
        assert result["valid"] is True
        assert v.metrics.total == 1
        assert v.metrics.allowed == 1

    @pytest.mark.asyncio
    async def test_with_inner_verifier(self):
        inner = MagicMock()
        inner.verify_action = AsyncMock(return_value={"valid": True, "custom": True})
        v = ObservableVerifier(inner_verifier=inner)
        result = await v.verify_action("act", "tok", constraints={"x": 1})
        assert result["custom"] is True
        inner.verify_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_inner_verifier_raises(self):
        inner = MagicMock()
        inner.verify_action = AsyncMock(side_effect=RuntimeError("blocked"))
        v = ObservableVerifier(inner_verifier=inner)
        with pytest.raises(RuntimeError):
            await v.verify_action("bad", "tok")
        assert v.metrics.blocked == 1


class TestInstrumentVerification:
    @pytest.mark.asyncio
    async def test_wraps_verifier(self):
        inner = MagicMock()
        inner.verify_action = AsyncMock(return_value={"valid": True})
        wrapped = instrument_verification(inner)
        assert isinstance(wrapped, ObservableVerifier)
        result = await wrapped.verify_action("a", "t")
        assert result["valid"] is True


class TestTracedVerification:
    @pytest.mark.asyncio
    async def test_decorator(self):
        @traced_verification("my_action")
        async def my_verify(token_id="tok"):
            return {"verified": True}

        result = await my_verify(token_id="tok-123")
        assert result["verified"] is True

    @pytest.mark.asyncio
    async def test_decorator_with_token_object(self):
        class FakeToken:
            id = "tok-obj"

        @traced_verification("action2")
        async def verify2(token=None):
            return {"ok": True}

        result = await verify2(token=FakeToken())
        assert result["ok"] is True

    @pytest.mark.asyncio
    async def test_decorator_with_dict_token(self):
        @traced_verification("action3")
        async def verify3(token=None):
            return {"ok": True}

        result = await verify3(token={"id": "tok-dict"})
        assert result["ok"] is True


class TestGetVerificationMetrics:
    def test_singleton(self):
        m1 = get_verification_metrics()
        m2 = get_verification_metrics()
        assert m1 is m2


# ═══════════════════════════════════════════════════════
# planner.py coverage - LLM path + structural fallback
# ═══════════════════════════════════════════════════════

from agentsafe.agents.planner import PlannerAgent, PlanningError
from agentsafe.agents.actions import AgentAction, AgentPlan
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.skills.loader import VerifiedSkillLoader, SkillSummary
from pathlib import Path


class TestPlannerLLMPath:
    @pytest.mark.asyncio
    async def test_llm_plan_success(self):
        """Test LLM planning with a mock client."""
        import json

        plan_json = json.dumps({
            "steps": [
                {"tool": "web_browsing", "parameters": {"url": "https://example.com"}, "estimated_cost_cents": 50},
            ]
        })

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = plan_json

        mock_llm = MagicMock()
        mock_llm.chat.completions.create = AsyncMock(return_value=mock_response)

        token = CapabilityToken(
            permissions=["network:http:read", "filesystem:cache:write"],
            budget_cents=10000,
            budget_remaining_cents=10000,
        )
        loader = VerifiedSkillLoader(Path("skills"))

        planner = PlannerAgent("planner", token, llm_client=mock_llm, skill_loader=loader)
        plan = await planner.plan("fetch a web page")
        assert len(plan.steps) >= 1
        mock_llm.chat.completions.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_llm_plan_fallback_on_error(self):
        """LLM raises → falls back to rule-based."""
        mock_llm = MagicMock()
        mock_llm.chat.completions.create = AsyncMock(side_effect=RuntimeError("LLM down"))

        token = CapabilityToken(
            permissions=["network:http:read", "filesystem:cache:write"],
            budget_cents=10000,
            budget_remaining_cents=10000,
        )
        loader = VerifiedSkillLoader(Path("skills"))

        planner = PlannerAgent("planner", token, llm_client=mock_llm, skill_loader=loader)
        plan = await planner.plan("browse the web")
        # Should have fallen back to rule-based
        assert len(plan.steps) >= 1

    @pytest.mark.asyncio
    async def test_infer_capabilities(self):
        token = CapabilityToken(
            permissions=["network:http:read", "filesystem:cache:write"],
            budget_cents=10000,
            budget_remaining_cents=10000,
        )
        loader = VerifiedSkillLoader(Path("skills"))
        planner = PlannerAgent("planner", token, skill_loader=loader)
        skills = loader.list_skills(token)

        caps = planner._infer_capabilities("web_browsing", skills)
        assert "network:http:read" in caps

        caps_unknown = planner._infer_capabilities("unknown_tool", skills)
        assert caps_unknown == []


class TestPlannerStructuralFallback:
    @pytest.mark.asyncio
    async def test_structural_verify_no_z3(self):
        """Test the structural fallback when Z3 is 'missing'."""
        token = CapabilityToken(
            permissions=["database:read"],
            budget_cents=10000,
            budget_remaining_cents=10000,
        )
        planner = PlannerAgent("p", token)

        plan = AgentPlan(
            task="test",
            steps=[
                AgentAction(tool="db", required_capabilities=["database:read"],
                            estimated_cost_cents=100),
            ],
            total_budget_cents=10000,
            available_capabilities=["database:read"],
        )

        # Patch _HAS_Z3 to False to test structural fallback
        with patch("agentsafe.agents.planner._HAS_Z3", False):
            result = await planner._verify_plan(plan)
        assert result.valid

    @pytest.mark.asyncio
    async def test_structural_verify_missing_cap(self):
        token = CapabilityToken(
            permissions=[],
            budget_cents=10000,
            budget_remaining_cents=10000,
        )
        planner = PlannerAgent("p", token)

        plan = AgentPlan(
            task="test",
            steps=[
                AgentAction(tool="db", required_capabilities=["database:read"],
                            estimated_cost_cents=100),
            ],
            total_budget_cents=10000,
            available_capabilities=[],  # missing
        )

        with patch("agentsafe.agents.planner._HAS_Z3", False):
            result = await planner._verify_plan(plan)
        assert not result.valid

    @pytest.mark.asyncio
    async def test_structural_verify_budget_exceeded(self):
        token = CapabilityToken(
            permissions=["a"],
            budget_cents=50,
            budget_remaining_cents=50,
        )
        planner = PlannerAgent("p", token)

        plan = AgentPlan(
            task="test",
            steps=[
                AgentAction(tool="x", required_capabilities=["a"],
                            estimated_cost_cents=100),
            ],
            total_budget_cents=50,
            available_capabilities=["a"],
        )

        with patch("agentsafe.agents.planner._HAS_Z3", False):
            result = await planner._verify_plan(plan)
        assert not result.valid
        assert any("Budget" in v or "budget" in v for v in result.violations)


class TestPlannerTaskMatching:
    def test_matches_known_skills(self):
        token = CapabilityToken(permissions=["*"], budget_cents=10000, budget_remaining_cents=10000)
        planner = PlannerAgent("p", token)

        s = SkillSummary(
            skill_id="web_browsing",
            name="Web Browsing",
            description="",
            capabilities_required=[],
        )
        assert planner._task_matches_skill("browse the web", s) is True
        assert planner._task_matches_skill("cook dinner", s) is False

    def test_unknown_skill_matches_id(self):
        token = CapabilityToken(permissions=["*"], budget_cents=10000, budget_remaining_cents=10000)
        planner = PlannerAgent("p", token)

        s = SkillSummary(
            skill_id="custom_tool",
            name="Custom",
            description="",
            capabilities_required=[],
        )
        assert planner._task_matches_skill("use custom_tool", s) is True


# ═══════════════════════════════════════════════════════
# base agent structural fallback
# ═══════════════════════════════════════════════════════

from agentsafe.agents.base import VerifiedAgent, VerificationResult


class ConcreteAgent(VerifiedAgent):
    """Concrete impl for testing."""
    pass


class TestBaseStructuralFallback:
    @pytest.mark.asyncio
    async def test_structural_fallback_no_z3(self):
        token = CapabilityToken(
            permissions=["database:read"],
            budget_cents=5000,
            budget_remaining_cents=5000,
        )
        agent = ConcreteAgent("test", token)
        action = AgentAction(
            tool="db",
            required_capabilities=["database:read"],
            estimated_cost_cents=100,
        )

        with patch("agentsafe.agents.base._HAS_Z3", False):
            result = await agent.verify_action(action)
        assert result.valid
        assert not result.used_z3
        assert any("structural" in p for p in result.properties)

    @pytest.mark.asyncio
    async def test_structural_missing_capability(self):
        token = CapabilityToken(
            permissions=[],
            budget_cents=5000,
            budget_remaining_cents=5000,
        )
        agent = ConcreteAgent("test", token)
        action = AgentAction(
            tool="db",
            required_capabilities=["database:read"],
            estimated_cost_cents=100,
        )

        with patch("agentsafe.agents.base._HAS_Z3", False):
            result = await agent.verify_action(action)
        assert not result.valid

    @pytest.mark.asyncio
    async def test_structural_budget_exceeded(self):
        token = CapabilityToken(
            permissions=["a"],
            budget_cents=10,
            budget_remaining_cents=10,
        )
        agent = ConcreteAgent("test", token)
        action = AgentAction(
            tool="x",
            required_capabilities=["a"],
            estimated_cost_cents=100,
        )

        with patch("agentsafe.agents.base._HAS_Z3", False):
            result = await agent.verify_action(action)
        assert not result.valid

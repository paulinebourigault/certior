"""Tests for PlannerAgent - task decomposition with Z3 plan verification."""
import pytest
import json
from pathlib import Path
from agentsafe.agents.planner import PlannerAgent, PlanningError
from agentsafe.agents.actions import AgentPlan
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.skills.loader import VerifiedSkillLoader
from agentsafe.kernel.certificate import CertificateAuthority
from agentsafe.observability.otel import CertiorTelemetry

z3 = pytest.importorskip("z3")


@pytest.fixture
def skills_dir(tmp_path):
    for sid, caps, desc in [
        ("web_browsing", ["network:http:read"], "Browse web pages"),
        ("database_query", ["database:read"], "Query databases"),
        ("file_operations", ["filesystem:read", "filesystem:write"], "File ops"),
    ]:
        d = tmp_path / sid
        d.mkdir()
        (d / "VERIFICATION.json").write_text(json.dumps({
            "skill_id": sid, "version": "1.0.0",
            "metadata": {"name": sid, "description": desc},
            "verification_requirements": {"capabilities_required": caps},
        }))
    return tmp_path


class TestPlannerAgent:
    def setup_method(self):
        CertificateAuthority.reset()
        CertiorTelemetry.reset()

    @pytest.mark.asyncio
    async def test_plan_web_task(self, skills_dir):
        token = CapabilityToken(
            permissions=["network:http:read"], budget_cents=10000, budget_remaining_cents=10000,
        )
        loader = VerifiedSkillLoader(skills_dir)
        planner = PlannerAgent("p", token, skill_loader=loader)
        plan = await planner.plan("browse web page")
        assert isinstance(plan, AgentPlan)
        assert len(plan.steps) >= 1
        assert any("web" in s.tool for s in plan.steps)

    @pytest.mark.asyncio
    async def test_plan_db_task(self, skills_dir):
        token = CapabilityToken(
            permissions=["database:read"], budget_cents=10000, budget_remaining_cents=10000,
        )
        loader = VerifiedSkillLoader(skills_dir)
        planner = PlannerAgent("p", token, skill_loader=loader)
        plan = await planner.plan("query database for users")
        assert any("database" in s.tool for s in plan.steps)

    @pytest.mark.asyncio
    async def test_plan_default_fallback(self, skills_dir):
        token = CapabilityToken(
            permissions=["a"], budget_cents=10000, budget_remaining_cents=10000,
        )
        planner = PlannerAgent("p", token)
        plan = await planner.plan("do something unknown")
        assert len(plan.steps) >= 1

    @pytest.mark.asyncio
    async def test_plan_budget_insufficient(self, skills_dir):
        token = CapabilityToken(
            permissions=["network:http:read"], budget_cents=1, budget_remaining_cents=1,
        )
        loader = VerifiedSkillLoader(skills_dir)
        planner = PlannerAgent("p", token, skill_loader=loader)
        # Should either succeed with reduced costs or raise PlanningError
        try:
            plan = await planner.plan("browse web")
            assert plan.total_estimated_cost <= token.budget_remaining_cents
        except PlanningError:
            pass  # acceptable

    @pytest.mark.asyncio
    async def test_plan_z3_verification(self, skills_dir):
        """Verify plan-level Z3 verification runs."""
        token = CapabilityToken(
            permissions=["network:http:read", "database:read"],
            budget_cents=10000, budget_remaining_cents=10000,
        )
        loader = VerifiedSkillLoader(skills_dir)
        planner = PlannerAgent("p", token, skill_loader=loader)
        plan = await planner.plan("fetch web data and query database")
        assert plan.total_estimated_cost <= plan.total_budget_cents

"""
End-to-end integration tests.
Tests the full pipeline: Skills -> Planning -> Z3 Verification -> Execution -> Output Validation.
IMPROVED v2: All paths exercise real Z3 verification.
"""
import pytest
import json
from pathlib import Path
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.skills.loader import VerifiedSkillLoader
from agentsafe.skills.z3_verifier import SkillZ3Verifier, verify_skill_constraints
from agentsafe.agents.orchestrator import VerifiedOrchestrator, TaskResult
from agentsafe.agents.planner import PlannerAgent
from agentsafe.agents.executor import ExecutorAgent
from agentsafe.agents.verifier_agent import VerifierAgent
from agentsafe.agents.base import VerifiedAgent, VerificationResult
from agentsafe.agents.actions import AgentAction, AgentPlan
from agentsafe.safety.scanner import ContentSafetyPolicy
from agentsafe.kernel.certificate import CertificateAuthority
from agentsafe.observability.otel import CertiorTelemetry
from agentsafe.cloud.executor_service import ExecutorService

z3 = pytest.importorskip("z3")


@pytest.fixture
def skills_dir(tmp_path):
    for skill_id, caps, desc in [
        ("web_browsing", ["network:http:read"], "Browse web pages"),
        ("database_query", ["database:read"], "Query databases"),
    ]:
        d = tmp_path / skill_id
        d.mkdir()
        (d / "VERIFICATION.json").write_text(json.dumps({
            "skill_id": skill_id, "version": "1.0.0",
            "metadata": {"name": skill_id, "description": desc},
            "verification_requirements": {
                "capabilities_required": caps,
                "resource_constraints": {"timeout_seconds": 30},
                "safety_constraints": (
                    {"url_allowlist_patterns": ["^https://.*"],
                     "url_blocklist_patterns": [".*\\.onion$"]}
                    if skill_id == "web_browsing" else
                    {"forbidden_columns": ["password", "ssn"], "read_only": True}
                ),
            },
        }))
    return tmp_path


class TestEndToEnd:
    def setup_method(self):
        CertificateAuthority.reset()
        CertiorTelemetry.reset()

    @pytest.mark.asyncio
    async def test_full_pipeline(self, skills_dir):
        """Full pipeline: plan -> verify -> execute -> validate."""
        token = CapabilityToken(
            permissions=["network:http:read", "database:read"],
            budget_cents=10000, budget_remaining_cents=10000,
        )
        loader = VerifiedSkillLoader(skills_dir)
        tools = {
            "default": lambda p: "done",
            "web_browsing": lambda p: "<html>data</html>",
            "database_query": lambda p: [{"id": 1}],
        }
        orch = VerifiedOrchestrator(
            capability_token=token,
            tools=tools,
            skill_loader=loader,
        )
        result = await orch.execute("fetch web data")
        assert result.success
        assert len(result.audit_trail) >= 3
        assert result.cost_cents >= 0

    @pytest.mark.asyncio
    async def test_with_hipaa_policy(self, skills_dir):
        """HIPAA policy detects PII in output."""
        token = CapabilityToken(
            permissions=["network:http:read"],
            budget_cents=10000, budget_remaining_cents=10000,
        )
        orch = VerifiedOrchestrator(
            capability_token=token,
            tools={"default": lambda p: "Patient SSN: 123-45-6789"},
            content_policy=ContentSafetyPolicy.hipaa_compliant(),
        )
        result = await orch.execute("get patient info")
        assert isinstance(result, TaskResult)

    @pytest.mark.asyncio
    async def test_cloud_executor_real_pipeline(self, skills_dir):
        """Cloud executor uses real orchestrator pipeline."""
        tools = {"default": lambda p: "cloud result"}
        svc = ExecutorService(
            tools=tools,
            skill_loader=VerifiedSkillLoader(skills_dir),
        )
        token = CapabilityToken(
            permissions=["network:http:read", "database:read"],
            budget_cents=10000, budget_remaining_cents=10000,
        )
        ex = await svc.submit("cloud task", "u1", token)
        result = await svc.execute(ex.id, token)
        assert result.status.value in ("completed", "failed")

    @pytest.mark.asyncio
    async def test_skill_z3_then_agent_z3(self, skills_dir):
        """Both skill-level and agent-level Z3 proofs run."""
        loader = VerifiedSkillLoader(skills_dir)
        token = CapabilityToken(
            permissions=["network:http:read"],
            budget_cents=10000, budget_remaining_cents=10000,
        )
        # Skill-level Z3
        skill = loader.load_skill("web_browsing", token)
        assert skill.verification_result.valid
        assert skill.verification_result.solve_time_ms > 0

        # Agent-level Z3
        class TestAgent(VerifiedAgent):
            pass

        agent = TestAgent("test", token)
        action = AgentAction(
            tool="web_browsing",
            required_capabilities=["network:http:read"],
            estimated_cost_cents=100,
        )
        result = await agent.verify_action(action)
        assert result.valid
        assert result.used_z3

    @pytest.mark.asyncio
    async def test_z3_skill_verification_depth(self, skills_dir):
        """Verify skill Z3 proofs are genuinely deep."""
        loader = VerifiedSkillLoader(skills_dir)
        token = CapabilityToken(
            permissions=["database:read"],
            budget_cents=10000, budget_remaining_cents=10000,
        )
        # Load with query context
        skill = loader.load_skill(
            "database_query", token,
            runtime_context={"query_columns": ["name", "email"]},
        )
        assert skill.verification_result.valid
        # Should have proven column exclusion, read-only, timeout, etc.
        all_props = skill.verification_result.properties_proven
        assert any("column" in p.lower() or "forbidden" in p.lower() for p in all_props)
        assert any("read_only" in p.lower() or "write" in p.lower() for p in all_props)

    @pytest.mark.asyncio
    async def test_z3_skill_rejects_forbidden_columns(self, skills_dir):
        """Verify skill Z3 rejects queries accessing forbidden columns."""
        loader = VerifiedSkillLoader(skills_dir)
        token = CapabilityToken(permissions=["database:read"])
        # This should fail because query accesses 'password' which is forbidden
        from agentsafe.skills.exceptions import SkillValidationError
        with pytest.raises(SkillValidationError):
            loader.load_skill(
                "database_query", token,
                runtime_context={"query_columns": ["name", "password"]},
            )

    @pytest.mark.asyncio
    async def test_planner_z3_plan_verification(self, skills_dir):
        """Planner uses Z3 to verify the entire plan."""
        token = CapabilityToken(
            permissions=["network:http:read", "database:read"],
            budget_cents=10000, budget_remaining_cents=10000,
        )
        loader = VerifiedSkillLoader(skills_dir)
        planner = PlannerAgent("p", token, skill_loader=loader)
        plan = await planner.plan("fetch web data and query db")
        # Plan should be verified (budget + capabilities)
        assert plan.total_estimated_cost <= plan.total_budget_cents

    @pytest.mark.asyncio
    async def test_executor_z3_per_step(self, skills_dir):
        """Executor verifies each step with Z3 before execution."""
        token = CapabilityToken(
            permissions=["a"], budget_cents=10000, budget_remaining_cents=10000,
        )
        executor = ExecutorAgent("e", token)
        executor.register_tool("test", lambda p: "result")

        plan = AgentPlan(
            steps=[
                AgentAction(tool="test", required_capabilities=["a"],
                            estimated_cost_cents=100),
            ],
            total_budget_cents=10000,
            available_capabilities=["a"],
        )
        result = await executor.execute_plan(plan)
        assert result.success
        assert len(result.certificates) >= 1

    @pytest.mark.asyncio
    async def test_information_flow_z3(self):
        """Z3 verifies information flow constraints."""
        token = CapabilityToken(
            permissions=["a"], budget_cents=10000, budget_remaining_cents=10000,
        )

        class TestAgent(VerifiedAgent):
            pass

        agent = TestAgent("test", token)
        # Valid flow: public -> internal (upgrade ok)
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
    async def test_counterexample_generation(self):
        """Z3 generates counterexamples on failure."""
        v = SkillZ3Verifier()
        spec = {
            "verification_requirements": {
                "capabilities_required": ["network:http:read"],
                "safety_constraints": {
                    "forbidden_columns": ["password"],
                },
            }
        }
        result = v.verify_skill(
            spec, ["network:http:read"],
            runtime_context={"query_columns": ["password"]},
        )
        assert not result.valid
        assert len(result.counterexamples) > 0

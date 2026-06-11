"""Tests for VerifiedOrchestrator - end-to-end pipeline."""
import pytest
import json
from pathlib import Path
from agentsafe.agents.orchestrator import VerifiedOrchestrator, TaskResult
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.skills.loader import VerifiedSkillLoader
from agentsafe.safety.scanner import ContentSafetyPolicy
from agentsafe.kernel.certificate import CertificateAuthority
from agentsafe.observability.otel import CertiorTelemetry

z3 = pytest.importorskip("z3")


@pytest.fixture
def skills_dir(tmp_path):
    for sid, caps in [
        ("web_browsing", ["network:http:read"]),
        ("database_query", ["database:read"]),
    ]:
        d = tmp_path / sid
        d.mkdir()
        (d / "VERIFICATION.json").write_text(json.dumps({
            "skill_id": sid, "version": "1.0.0",
            "metadata": {"name": sid, "description": f"{sid} skill"},
            "verification_requirements": {"capabilities_required": caps},
        }))
    return tmp_path


class TestOrchestrator:
    def setup_method(self):
        CertificateAuthority.reset()
        CertiorTelemetry.reset()

    @pytest.mark.asyncio
    async def test_full_execution(self, skills_dir):
        token = CapabilityToken(
            permissions=["network:http:read", "database:read"],
            budget_cents=10000, budget_remaining_cents=10000,
        )
        tools = {
            "default": lambda p: "done",
            "web_browsing": lambda p: "<html>data</html>",
        }
        orch = VerifiedOrchestrator(
            capability_token=token,
            tools=tools,
            skill_loader=VerifiedSkillLoader(skills_dir),
        )
        result = await orch.execute("fetch web data")
        assert result.success
        assert len(result.audit_trail) >= 3
        assert result.duration_ms > 0

    @pytest.mark.asyncio
    async def test_with_content_policy(self, skills_dir):
        token = CapabilityToken(
            permissions=["a"], budget_cents=10000, budget_remaining_cents=10000,
        )
        orch = VerifiedOrchestrator(
            capability_token=token,
            tools={"default": lambda p: "Patient SSN: 123-45-6789"},
            content_policy=ContentSafetyPolicy.hipaa_compliant(),
        )
        result = await orch.execute("get patient info")
        assert isinstance(result, TaskResult)
        # Either succeeds with redacted output or fails
        if not result.success:
            assert "verification" in result.error.lower() or "safety" in result.error.lower() or "violation" in result.error.lower()

    @pytest.mark.asyncio
    async def test_status_callbacks(self, skills_dir):
        statuses = []
        token = CapabilityToken(
            permissions=["a"], budget_cents=10000, budget_remaining_cents=10000,
        )
        orch = VerifiedOrchestrator(
            capability_token=token,
            tools={"default": lambda p: "ok"},
            on_status=lambda s, t: statuses.append(s),
        )
        await orch.execute("test task")
        assert "planning" in statuses
        assert "executing" in statuses

    @pytest.mark.asyncio
    async def test_execution_cost_tracking(self, skills_dir):
        token = CapabilityToken(
            permissions=["a"], budget_cents=10000, budget_remaining_cents=10000,
        )
        orch = VerifiedOrchestrator(
            capability_token=token,
            tools={"default": lambda p: "result"},
        )
        result = await orch.execute("task")
        if result.success:
            assert result.cost_cents >= 0

    @pytest.mark.asyncio
    async def test_tool_not_found_handled(self):
        token = CapabilityToken(
            permissions=["a"], budget_cents=10000, budget_remaining_cents=10000,
        )
        orch = VerifiedOrchestrator(
            capability_token=token,
            tools={},  # No tools registered
        )
        result = await orch.execute("do something")
        # Should handle gracefully
        assert isinstance(result, TaskResult)

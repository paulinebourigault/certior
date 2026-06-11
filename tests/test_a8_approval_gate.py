"""
Tests for A8: Human Approval Gate - wired into the execution path.

Verifies:
  - Approval gate blocks tools when no callback configured
  - Approval gate allows tools when callback approves
  - Approval gate denies tools when callback denies
  - Pre-approved categories bypass callback
  - Default policy (no requires_human_approval) passes everything
  - Approval decisions recorded in audit trail and AgentStep
  - Approval summary included in AgenticResult
  - Spec categories from VERIFICATION.json used when available (A9 bridge)
"""
from __future__ import annotations

import asyncio
import pytest
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, patch, MagicMock

from agentsafe.agents.agentic_executor import AgenticExecutor, AgentStep, AgenticResult
from agentsafe.agents.agentic_orchestrator import AgenticOrchestrator
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.llm.config import LLMConfig
from agentsafe.llm.client import LLMResponse, ToolCallRequest
from agentsafe.safety.scanner import ContentSafetyPolicy
from agentsafe.safety.approval_gate import (
    ApprovalGate,
    ApprovalCallback,
    ApprovalRequest,
    ApprovalResponse,
    ApprovalDecision,
    ApprovalVerdict,
    get_tool_approval_categories,
)
from agentsafe.tools.base import BaseTool, ToolParameter, ToolResult
from agentsafe.tools.registry import ToolRegistry


# ── Fixtures ──────────────────────────────────────────────────────

def _make_token(**overrides) -> CapabilityToken:
    defaults = dict(
        agent_id="test-agent",
        permissions=["network:http:read", "filesystem:write", "filesystem:read"],
        budget_cents=10000,
    )
    defaults.update(overrides)
    return CapabilityToken(**defaults)


def _make_config() -> LLMConfig:
    return LLMConfig(
        model="test-model",
        max_tokens=500,
        max_tool_rounds=5,
    )


class FakeTool(BaseTool):
    """Minimal tool for testing."""
    name = "web_fetch"
    description = "Fetch a URL"
    required_capabilities = ["network:http:read"]
    parameters_schema = {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    }

    def parameters(self) -> list:
        return [ToolParameter(name="url", type="string", description="URL to fetch")]

    async def execute(self, *, tool_use_id: str, **kwargs) -> ToolResult:
        return ToolResult(tool_use_id=tool_use_id, output="OK: fetched")


class FakeWriteTool(BaseTool):
    name = "file_write"
    description = "Write a file"
    required_capabilities = ["filesystem:write"]
    parameters_schema = {
        "type": "object",
        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        "required": ["path", "content"],
    }

    def parameters(self) -> list:
        return [
            ToolParameter(name="path", type="string", description="File path"),
            ToolParameter(name="content", type="string", description="Content"),
        ]

    async def execute(self, *, tool_use_id: str, **kwargs) -> ToolResult:
        return ToolResult(tool_use_id=tool_use_id, output="OK: written")


class FakeReadTool(BaseTool):
    name = "file_read"
    description = "Read a file"
    required_capabilities = ["filesystem:read"]
    parameters_schema = {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    }

    def parameters(self) -> list:
        return [ToolParameter(name="path", type="string", description="File path")]

    async def execute(self, *, tool_use_id: str, **kwargs) -> ToolResult:
        return ToolResult(tool_use_id=tool_use_id, output="file contents")


def _make_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(FakeTool())
    reg.register(FakeWriteTool())
    reg.register(FakeReadTool())
    return reg


def _make_response(text="", tool_calls=None, stop="end_turn"):
    return LLMResponse(
        text=text,
        tool_calls=tool_calls or [],
        stop_reason=stop,
        input_tokens=10,
        output_tokens=10,
    )


def _make_tc(tool="web_fetch", input_=None, id_="tc1"):
    return ToolCallRequest(
        id=id_,
        name=tool,
        input=input_ or {"url": "https://example.com"},
    )


# ── Unit tests: ApprovalGate standalone ───────────────────────────

class TestApprovalGateUnit:

    @pytest.mark.asyncio
    async def test_default_policy_no_approval_needed(self):
        """Default policy has no requires_human_approval → all tools pass."""
        gate = ApprovalGate(
            policy=ContentSafetyPolicy.default(),
            callback=None,
        )
        decision = await gate.check(
            tool_name="web_fetch",
            tool_input={"url": "https://example.com"},
            step_index=0,
        )
        assert decision.verdict == ApprovalVerdict.NOT_REQUIRED
        assert not decision.blocked

    @pytest.mark.asyncio
    async def test_hipaa_web_fetch_blocked_no_callback(self):
        """HIPAA policy + web_fetch + no callback → DENIED."""
        gate = ApprovalGate(
            policy=ContentSafetyPolicy.hipaa_compliant(),
            callback=None,
        )
        decision = await gate.check(
            tool_name="web_fetch",
            tool_input={"url": "https://example.com"},
            step_index=0,
        )
        assert decision.verdict == ApprovalVerdict.DENIED
        assert decision.blocked
        assert "external_communication" in decision.matched_categories

    @pytest.mark.asyncio
    async def test_hipaa_file_read_no_approval_needed(self):
        """HIPAA policy + file_read (no categories) → NOT_REQUIRED."""
        gate = ApprovalGate(
            policy=ContentSafetyPolicy.hipaa_compliant(),
            callback=None,
        )
        decision = await gate.check(
            tool_name="file_read",
            tool_input={"path": "/tmp/test.txt"},
            step_index=0,
        )
        assert decision.verdict == ApprovalVerdict.NOT_REQUIRED
        assert not decision.blocked

    @pytest.mark.asyncio
    async def test_callback_approves(self):
        """Callback returns approved=True → APPROVED."""
        async def approve_all(req: ApprovalRequest) -> ApprovalResponse:
            return ApprovalResponse(approved=True, reason="Auto-approved for test")

        gate = ApprovalGate(
            policy=ContentSafetyPolicy.hipaa_compliant(),
            callback=approve_all,
        )
        decision = await gate.check(
            tool_name="web_fetch",
            tool_input={"url": "https://example.com"},
            step_index=0,
        )
        assert decision.verdict == ApprovalVerdict.APPROVED
        assert not decision.blocked

    @pytest.mark.asyncio
    async def test_callback_denies(self):
        """Callback returns approved=False → DENIED."""
        async def deny_all(req: ApprovalRequest) -> ApprovalResponse:
            return ApprovalResponse(approved=False, reason="Not today")

        gate = ApprovalGate(
            policy=ContentSafetyPolicy.hipaa_compliant(),
            callback=deny_all,
        )
        decision = await gate.check(
            tool_name="web_fetch",
            tool_input={"url": "https://example.com"},
            step_index=0,
        )
        assert decision.verdict == ApprovalVerdict.DENIED
        assert decision.blocked

    @pytest.mark.asyncio
    async def test_pre_approved_categories_bypass_callback(self):
        """Pre-approved categories skip callback entirely → APPROVED."""
        callback = AsyncMock(side_effect=Exception("Should not be called"))

        gate = ApprovalGate(
            policy=ContentSafetyPolicy.hipaa_compliant(),
            callback=callback,
            pre_approved_categories={"external_communication", "send_external_communication"},
        )
        decision = await gate.check(
            tool_name="web_fetch",
            tool_input={"url": "https://example.com"},
            step_index=0,
        )
        assert decision.verdict == ApprovalVerdict.APPROVED
        assert not decision.blocked
        callback.assert_not_called()

    @pytest.mark.asyncio
    async def test_summary_tracks_decisions(self):
        """Gate summary records all decisions."""
        gate = ApprovalGate(
            policy=ContentSafetyPolicy.hipaa_compliant(),
            callback=None,
        )
        # web_fetch → DENIED, file_read → NOT_REQUIRED
        await gate.check("web_fetch", {"url": "https://x.com"}, 0)
        await gate.check("file_read", {"path": "/tmp/x"}, 1)

        summary = gate.summary()
        assert summary["total_checks"] == 2
        assert summary["denied"] == 1
        assert summary["not_required"] == 1

    @pytest.mark.asyncio
    async def test_spec_categories_override_defaults(self):
        """A9 VERIFICATION.json categories override default tool mapping."""
        gate = ApprovalGate(
            policy=ContentSafetyPolicy.hipaa_compliant(),
            callback=None,
        )
        # Pass spec_categories that do NOT match policy → NOT_REQUIRED
        decision = await gate.check(
            tool_name="web_fetch",
            tool_input={"url": "https://example.com"},
            step_index=0,
            spec_categories=["compute_only"],
        )
        assert decision.verdict == ApprovalVerdict.NOT_REQUIRED
        assert not decision.blocked


# ── Integration tests: ApprovalGate wired in AgenticExecutor ──────

class TestApprovalGateIntegration:

    @pytest.mark.asyncio
    async def test_hipaa_blocks_web_fetch_no_callback(self):
        """HIPAA + web_fetch + no callback → tool blocked in execution."""
        config = _make_config()
        token = _make_token()
        registry = _make_registry()

        executor = AgenticExecutor(
            llm_config=config,
            tool_registry=registry,
            capability_token=token,
            content_policy=ContentSafetyPolicy.hipaa_compliant(),
            # No approval_callback → gate denies
        )

        call = _make_tc("web_fetch", {"url": "https://example.com"})
        responses = [
            _make_response(tool_calls=[call], stop="tool_use"),
            _make_response(text="Could not fetch."),
        ]

        with patch.object(executor._client, "send", side_effect=responses):
            result = await executor.run("Fetch a page")

        # Step should be blocked by approval
        blocked_steps = [s for s in result.steps if s.is_error and "approval" in s.approval_verdict.lower() or "denied" in s.approval_verdict.lower()]
        assert len(blocked_steps) >= 1
        assert blocked_steps[0].approval_verdict == "denied"
        assert "external_communication" in blocked_steps[0].approval_categories

        # Audit trail
        approval_audit = [e for e in result.audit_trail if e.get("phase") == "approval_blocked"]
        assert len(approval_audit) >= 1

        # Approval summary
        assert result.approval_summary is not None
        assert result.approval_summary["denied"] >= 1

    @pytest.mark.asyncio
    async def test_hipaa_allows_web_fetch_with_callback(self):
        """HIPAA + web_fetch + approving callback → tool executes."""
        config = _make_config()
        token = _make_token()
        registry = _make_registry()

        async def auto_approve(req: ApprovalRequest) -> ApprovalResponse:
            return ApprovalResponse(approved=True, reason="Test approved")

        executor = AgenticExecutor(
            llm_config=config,
            tool_registry=registry,
            capability_token=token,
            content_policy=ContentSafetyPolicy.hipaa_compliant(),
            approval_callback=auto_approve,
        )

        call = _make_tc("web_fetch", {"url": "https://example.com"})
        responses = [
            _make_response(tool_calls=[call], stop="tool_use"),
            _make_response(text="Fetched successfully."),
        ]

        with patch.object(executor._client, "send", side_effect=responses):
            result = await executor.run("Fetch a page")

        assert result.success is True
        # Step should have approval_verdict = "approved"
        exec_steps = [s for s in result.steps if not s.is_error]
        assert len(exec_steps) >= 1
        assert exec_steps[0].approval_verdict == "approved"

    @pytest.mark.asyncio
    async def test_hipaa_allows_web_fetch_with_pre_approval(self):
        """HIPAA + web_fetch + pre-approved categories → tool executes."""
        config = _make_config()
        token = _make_token()
        registry = _make_registry()

        executor = AgenticExecutor(
            llm_config=config,
            tool_registry=registry,
            capability_token=token,
            content_policy=ContentSafetyPolicy.hipaa_compliant(),
            pre_approved_categories={"external_communication", "send_external_communication"},
        )

        call = _make_tc("web_fetch", {"url": "https://example.com"})
        responses = [
            _make_response(tool_calls=[call], stop="tool_use"),
            _make_response(text="Fetched."),
        ]

        with patch.object(executor._client, "send", side_effect=responses):
            result = await executor.run("Fetch a page")

        assert result.success is True
        exec_steps = [s for s in result.steps if not s.is_error]
        assert len(exec_steps) >= 1
        assert exec_steps[0].approval_verdict == "approved"

    @pytest.mark.asyncio
    async def test_default_policy_no_blocking(self):
        """Default policy (empty requires_human_approval) → nothing blocked."""
        config = _make_config()
        token = _make_token()
        registry = _make_registry()

        executor = AgenticExecutor(
            llm_config=config,
            tool_registry=registry,
            capability_token=token,
            content_policy=ContentSafetyPolicy.default(),
        )

        call = _make_tc("web_fetch", {"url": "https://example.com"})
        responses = [
            _make_response(tool_calls=[call], stop="tool_use"),
            _make_response(text="Done."),
        ]

        with patch.object(executor._client, "send", side_effect=responses):
            result = await executor.run("Do something")

        assert result.success is True
        for step in result.steps:
            assert step.approval_verdict == "not_required"

        assert result.approval_summary is not None
        assert result.approval_summary["not_required"] >= 1
        assert result.approval_summary["denied"] == 0

    @pytest.mark.asyncio
    async def test_file_read_never_blocked(self):
        """file_read has no approval categories → never blocked."""
        config = _make_config()
        token = _make_token()
        registry = _make_registry()

        executor = AgenticExecutor(
            llm_config=config,
            tool_registry=registry,
            capability_token=token,
            content_policy=ContentSafetyPolicy.hipaa_compliant(),
            # Even with HIPAA, file_read isn't blocked
        )

        call = _make_tc("file_read", {"path": "/tmp/test.txt"}, id_="tc1")
        responses = [
            _make_response(tool_calls=[call], stop="tool_use"),
            _make_response(text="Read the file."),
        ]

        with patch.object(executor._client, "send", side_effect=responses):
            result = await executor.run("Read a file")

        # file_read should pass approval (not_required)
        assert result.success is True
        read_steps = [s for s in result.steps if s.tool_name == "file_read"]
        assert len(read_steps) >= 1
        assert read_steps[0].approval_verdict == "not_required"

    @pytest.mark.asyncio
    async def test_approval_summary_in_all_returns(self):
        """approval_summary is present even on error/max-rounds."""
        config = _make_config()
        token = _make_token()
        registry = _make_registry()

        executor = AgenticExecutor(
            llm_config=config,
            tool_registry=registry,
            capability_token=token,
            content_policy=ContentSafetyPolicy.default(),
        )

        # Simulate error
        with patch.object(executor._client, "send", side_effect=RuntimeError("boom")):
            result = await executor.run("Crash test")

        assert result.success is False
        assert result.approval_summary is not None
        assert "total_checks" in result.approval_summary


# ── Orchestrator passthrough tests ────────────────────────────────

class TestOrchestratorApprovalPassthrough:

    @pytest.mark.asyncio
    async def test_orchestrator_passes_approval_callback(self):
        """AgenticOrchestrator forwards approval_callback to executor."""
        callback = AsyncMock()

        orch = AgenticOrchestrator(
            capability_token=_make_token(),
            llm_config=_make_config(),
            tool_registry=_make_registry(),
            approval_callback=callback,
            pre_approved_categories={"data_export"},
        )

        # Verify params stored
        assert orch._approval_callback is callback
        assert orch._pre_approved_categories == {"data_export"}


# ── get_tool_approval_categories unit tests ───────────────────────

class TestToolCategoryResolution:

    def test_default_web_fetch(self):
        cats = get_tool_approval_categories("web_fetch")
        assert "external_communication" in cats

    def test_default_file_read_empty(self):
        cats = get_tool_approval_categories("file_read")
        assert len(cats) == 0

    def test_spec_overrides_default(self):
        cats = get_tool_approval_categories(
            "web_fetch",
            spec_declared=["custom_category"],
        )
        assert cats == frozenset({"custom_category"})
        assert "external_communication" not in cats

    def test_tool_declared_overrides_default(self):
        cats = get_tool_approval_categories(
            "web_fetch",
            tool_declared=["my_category"],
        )
        assert cats == frozenset({"my_category"})

    def test_spec_takes_priority_over_tool_declared(self):
        cats = get_tool_approval_categories(
            "web_fetch",
            tool_declared=["tool_cat"],
            spec_declared=["spec_cat"],
        )
        assert cats == frozenset({"spec_cat"})

    def test_unknown_tool_empty(self):
        cats = get_tool_approval_categories("unknown_tool")
        assert len(cats) == 0

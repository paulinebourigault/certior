"""
Tests for Tool I/O Content Safety Scanning (A4 Fix)
=====================================================

Validates that tool inputs AND outputs are scanned for content safety
violations at every step of the agentic execution loop, closing
BYPASS #4 and #7 from the deep analysis.

Test categories:
  - ToolIOScanner unit tests (serialisation, input scanning, output scanning)
  - Policy-specific tests (HIPAA, SOX, Legal)
  - Decision logic tests (block / redact / warn / pass)
  - AgenticExecutor integration tests (full loop with mocked LLM/tools)
  - Edge cases (empty inputs, huge outputs, nested dicts)
  - Telemetry verification
  - StepScanResult / PhaseScanResult serialisation
"""
from __future__ import annotations

import asyncio
import json
import pytest
from dataclasses import dataclass
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

from agentsafe.safety.scanner import (
    ContentScanner,
    ContentSafetyPolicy,
    ScanResult,
    ScanViolation,
)
from agentsafe.safety.taxonomy import ContentRiskCategory
from agentsafe.safety.tool_io_scanner import (
    ToolIOScanner,
    StepScanResult,
    PhaseScanResult,
    ScanPhase,
    ScanAction,
    _serialise_tool_input,
)


# ═════════════════════════════════════════════════════════════════
# Section 1: Serialisation
# ═════════════════════════════════════════════════════════════════

class TestSerialisation:
    """Test tool input serialisation to scannable text."""

    def test_simple_string_params(self):
        text = _serialise_tool_input("web_fetch", {"url": "https://example.com"})
        assert "tool:web_fetch" in text
        assert "url=https://example.com" in text

    def test_multiple_params(self):
        text = _serialise_tool_input("db_query", {
            "query": "SELECT * FROM users",
            "database": "production",
        })
        assert "query=SELECT * FROM users" in text
        assert "database=production" in text

    def test_nested_dict(self):
        text = _serialise_tool_input("api_call", {
            "body": {"patient_ssn": "123-45-6789", "name": "John"},
        })
        assert "123-45-6789" in text
        assert "patient_ssn" in text

    def test_list_param(self):
        text = _serialise_tool_input("multi_fetch", {
            "urls": ["https://a.com", "https://b.com"],
        })
        assert "https://a.com" in text

    def test_none_param(self):
        text = _serialise_tool_input("tool", {"key": None})
        assert "key=" in text

    def test_numeric_param(self):
        text = _serialise_tool_input("tool", {"count": 42, "ratio": 3.14})
        assert "count=42" in text
        assert "ratio=3.14" in text

    def test_boolean_param(self):
        text = _serialise_tool_input("tool", {"flag": True})
        assert "flag=True" in text

    def test_empty_input(self):
        text = _serialise_tool_input("tool", {})
        assert "tool:tool" in text

    def test_key_names_are_included(self):
        """Keys should be scanned too - e.g. 'patient_ssn' is informative."""
        text = _serialise_tool_input("tool", {"patient_ssn": "value"})
        assert "patient_ssn" in text


# ═════════════════════════════════════════════════════════════════
# Section 2: ToolIOScanner - Input Scanning
# ═════════════════════════════════════════════════════════════════

class TestToolInputScanning:
    """Test that tool inputs are correctly scanned and blocked."""

    def _hipaa_scanner(self) -> ToolIOScanner:
        return ToolIOScanner(ContentSafetyPolicy.hipaa_compliant())

    def _sox_scanner(self) -> ToolIOScanner:
        return ToolIOScanner(ContentSafetyPolicy.sox_compliant())

    def _default_scanner(self) -> ToolIOScanner:
        return ToolIOScanner(ContentSafetyPolicy.default())

    # ── PII in inputs ──

    def test_ssn_in_input_blocks(self):
        scanner = self._hipaa_scanner()
        result = scanner.scan_tool_input(
            "web_fetch",
            {"query": "Find info about SSN 123-45-6789"},
            step_index=0,
        )
        assert result.blocked
        assert result.action == ScanAction.BLOCK
        assert result.phase == ScanPhase.TOOL_INPUT
        assert len(result.scan_result.pii_detected) >= 1

    def test_email_in_input_blocks(self):
        scanner = self._hipaa_scanner()
        result = scanner.scan_tool_input(
            "send_email",
            {"to": "patient@example.com", "body": "Hello"},
            step_index=0,
        )
        assert result.blocked

    def test_phone_in_input_blocks(self):
        scanner = self._hipaa_scanner()
        result = scanner.scan_tool_input(
            "sms",
            {"phone": "555-123-4567", "message": "Reminder"},
            step_index=0,
        )
        assert result.blocked

    # ── Keywords in inputs ──

    def test_hipaa_keyword_in_input_blocks(self):
        scanner = self._hipaa_scanner()
        result = scanner.scan_tool_input(
            "search",
            {"query": "patient name John Smith diagnosis"},
            step_index=0,
        )
        assert result.blocked

    def test_sox_keyword_in_input_blocks(self):
        scanner = self._sox_scanner()
        result = scanner.scan_tool_input(
            "search",
            {"query": "unreleased earnings Q4"},
            step_index=0,
        )
        assert result.blocked

    # ── Secrets in inputs ──

    def test_aws_key_in_input_blocks(self):
        # Default policy doesn't detect secrets - use SOX which does
        scanner = self._sox_scanner()
        result = scanner.scan_tool_input(
            "api_call",
            {"headers": "Authorization: AKIAIOSFODNN7EXAMPLE"},
            step_index=0,
        )
        assert result.blocked

    # ── Clean inputs ──

    def test_clean_input_passes(self):
        scanner = self._hipaa_scanner()
        result = scanner.scan_tool_input(
            "web_fetch",
            {"url": "https://weather.gov/forecast"},
            step_index=0,
        )
        assert not result.blocked
        assert result.action == ScanAction.PASS

    def test_clean_numeric_input_passes(self):
        scanner = self._hipaa_scanner()
        result = scanner.scan_tool_input(
            "compute",
            {"x": 42, "y": 100},
            step_index=0,
        )
        assert result.action == ScanAction.PASS

    # ── Timing ──

    def test_input_scan_records_duration(self):
        scanner = self._default_scanner()
        result = scanner.scan_tool_input(
            "tool", {"key": "value"}, step_index=0,
        )
        assert result.duration_ms >= 0


# ═════════════════════════════════════════════════════════════════
# Section 3: ToolIOScanner - Output Scanning
# ═════════════════════════════════════════════════════════════════

class TestToolOutputScanning:
    """Test that tool outputs are scanned with correct decision logic."""

    def _hipaa_scanner(self) -> ToolIOScanner:
        return ToolIOScanner(ContentSafetyPolicy.hipaa_compliant())

    def _sox_scanner(self) -> ToolIOScanner:
        return ToolIOScanner(ContentSafetyPolicy.sox_compliant())

    def _legal_scanner(self) -> ToolIOScanner:
        return ToolIOScanner(ContentSafetyPolicy.legal_privilege())

    # ── PII in outputs (HIPAA: redact) ──

    def test_hipaa_pii_in_output_redacts(self):
        """Under HIPAA with redaction enabled, PII should be redacted not blocked."""
        scanner = self._hipaa_scanner()
        result = scanner.scan_tool_output(
            "web_fetch",
            "Patient record: SSN 123-45-6789, admitted 2024-01-01",
            step_index=0,
        )
        assert result.action == ScanAction.REDACT
        assert result.redacted
        assert not result.blocked
        assert "123-45-6789" not in result.sanitised_text
        assert "[REDACTED-SSN]" in result.sanitised_text

    def test_hipaa_multiple_pii_redacted(self):
        scanner = self._hipaa_scanner()
        result = scanner.scan_tool_output(
            "db_query",
            "John Smith, SSN: 123-45-6789, email: john@example.com, phone: 555-123-4567",
            step_index=0,
        )
        assert result.redacted
        assert "123-45-6789" not in result.sanitised_text
        assert "john@example.com" not in result.sanitised_text

    # ── MNPI in outputs (SOX: block) ──

    def test_sox_mnpi_in_output_blocks(self):
        scanner = self._sox_scanner()
        result = scanner.scan_tool_output(
            "web_fetch",
            "Internal memo: unreleased earnings of $100M expected",
            step_index=0,
        )
        assert result.blocked
        assert result.action == ScanAction.BLOCK

    def test_sox_insider_in_output_blocks(self):
        scanner = self._sox_scanner()
        result = scanner.scan_tool_output(
            "web_fetch",
            "This contains insider information about the merger",
            step_index=0,
        )
        assert result.blocked

    # ── Legal privilege in outputs (block) ──

    def test_legal_privilege_in_output_blocks(self):
        scanner = self._legal_scanner()
        result = scanner.scan_tool_output(
            "document_read",
            "According to our legal advice, the settlement terms are favorable",
            step_index=0,
        )
        assert result.blocked

    # ── Secrets in outputs (always block) ──

    def test_secrets_in_output_always_block(self):
        scanner = self._hipaa_scanner()
        result = scanner.scan_tool_output(
            "web_fetch",
            "Config: api_key=AKIAIOSFODNN7EXAMPLE, region=us-east-1",
            step_index=0,
        )
        assert result.blocked
        assert result.action == ScanAction.BLOCK

    # ── Clean outputs ──

    def test_clean_output_passes(self):
        scanner = self._hipaa_scanner()
        result = scanner.scan_tool_output(
            "web_fetch",
            "The forecast for tomorrow is sunny with highs of 75°F.",
            step_index=0,
        )
        assert result.action == ScanAction.PASS
        assert not result.blocked
        assert not result.redacted
        assert result.sanitised_text == result.original_text

    # ── Default policy (PII detected but no redaction) ──

    def test_default_policy_pii_blocks_without_redaction(self):
        """Default policy detects PII but doesn't redact → block."""
        scanner = ToolIOScanner(ContentSafetyPolicy.default())
        result = scanner.scan_tool_output(
            "tool",
            "SSN: 123-45-6789",
            step_index=0,
        )
        # Default has pii_config.detect=True, pii_config.redact=False
        # → PII detected but no redaction → block
        assert result.blocked

    # ── Timing ──

    def test_output_scan_records_duration(self):
        scanner = self._hipaa_scanner()
        result = scanner.scan_tool_output("tool", "clean text", step_index=0)
        assert result.duration_ms >= 0


# ═════════════════════════════════════════════════════════════════
# Section 4: StepScanResult and PhaseScanResult
# ═════════════════════════════════════════════════════════════════

class TestScanResultDataclasses:
    """Test serialisation and property accessors."""

    def _make_phase_result(
        self, action: ScanAction = ScanAction.PASS,
        phase: ScanPhase = ScanPhase.TOOL_INPUT,
        violations: int = 0,
    ) -> PhaseScanResult:
        scan = ScanResult()
        scan.violations = [
            ScanViolation(
                category=ContentRiskCategory.HATE_BIAS_PII,
                matched_text=f"v{i}",
            )
            for i in range(violations)
        ]
        scan.clean = violations == 0
        return PhaseScanResult(
            phase=phase,
            action=action,
            scan_result=scan,
            duration_ms=1.5,
        )

    def test_phase_scan_result_to_dict(self):
        r = self._make_phase_result(ScanAction.BLOCK, violations=2)
        d = r.to_dict()
        assert d["phase"] == "tool_input"
        assert d["action"] == "block"
        assert d["violation_count"] == 2
        assert d["clean"] is False

    def test_step_scan_result_blocked(self):
        inp = self._make_phase_result(ScanAction.BLOCK, ScanPhase.TOOL_INPUT, 1)
        step = StepScanResult(tool_name="t", step_index=0, input_scan=inp)
        assert step.blocked

    def test_step_scan_result_not_blocked(self):
        inp = self._make_phase_result(ScanAction.PASS)
        out = self._make_phase_result(ScanAction.REDACT, ScanPhase.TOOL_OUTPUT)
        step = StepScanResult(tool_name="t", step_index=0,
                              input_scan=inp, output_scan=out)
        assert not step.blocked
        assert step.any_violations is False  # REDACT but no violations in scan

    def test_step_scan_result_to_dict(self):
        inp = self._make_phase_result(ScanAction.PASS)
        out = self._make_phase_result(ScanAction.REDACT, ScanPhase.TOOL_OUTPUT)
        step = StepScanResult(tool_name="t", step_index=0,
                              input_scan=inp, output_scan=out)
        d = step.to_dict()
        assert "input_scan" in d
        assert "output_scan" in d
        assert d["tool_name"] == "t"
        assert d["step_index"] == 0

    def test_step_scan_block_reason(self):
        inp = self._make_phase_result(ScanAction.BLOCK, ScanPhase.TOOL_INPUT, 1)
        step = StepScanResult(tool_name="t", step_index=0, input_scan=inp)
        assert "input:" in step.block_reason

    def test_step_scan_empty(self):
        step = StepScanResult(tool_name="t", step_index=0)
        assert not step.blocked
        assert not step.any_violations


# ═════════════════════════════════════════════════════════════════
# Section 5: AgenticResult content safety summary
# ═════════════════════════════════════════════════════════════════

class TestAgenticResultSafetySummary:
    """Test AgenticResult properties and serialisation."""

    def test_empty_step_scans(self):
        from agentsafe.agents.agentic_executor import AgenticResult
        r = AgenticResult(task="test")
        assert r.content_violations_total == 0
        assert r.steps_blocked_by_content_safety == 0
        assert r.steps_with_redaction == 0

    def test_with_blocked_step(self):
        from agentsafe.agents.agentic_executor import AgenticResult
        scan = ScanResult()
        scan.violations = [ScanViolation(
            category=ContentRiskCategory.MNPI_LEAK,
            matched_text="unreleased",
        )]
        scan.clean = False
        r = AgenticResult(
            task="test",
            step_scans=[
                StepScanResult(
                    tool_name="t",
                    step_index=0,
                    output_scan=PhaseScanResult(
                        phase=ScanPhase.TOOL_OUTPUT,
                        action=ScanAction.BLOCK,
                        scan_result=scan,
                    ),
                ),
            ],
        )
        assert r.content_violations_total == 1
        assert r.steps_blocked_by_content_safety == 1
        assert r.steps_with_redaction == 0

    def test_with_redacted_step(self):
        from agentsafe.agents.agentic_executor import AgenticResult
        r = AgenticResult(
            task="test",
            step_scans=[
                StepScanResult(
                    tool_name="t",
                    step_index=0,
                    output_scan=PhaseScanResult(
                        phase=ScanPhase.TOOL_OUTPUT,
                        action=ScanAction.REDACT,
                        scan_result=ScanResult(),
                    ),
                ),
            ],
        )
        assert r.steps_with_redaction == 1

    def test_to_dict_includes_safety_summary(self):
        from agentsafe.agents.agentic_executor import AgenticResult
        r = AgenticResult(task="test", step_scans=[])
        d = r.to_dict()
        assert "content_safety_summary" in d
        assert d["content_safety_summary"]["total_violations"] == 0


# ═════════════════════════════════════════════════════════════════
# Section 6: AgenticExecutor Integration (mocked LLM + tools)
# ═════════════════════════════════════════════════════════════════

class TestAgenticExecutorIOScanning:
    """
    Integration tests that run the full agentic loop with mocked
    LLM and tools to verify input/output scanning is wired correctly.
    """

    @pytest.fixture
    def hipaa_token(self):
        from agentsafe.capabilities.tokens import CapabilityToken
        return CapabilityToken(
            agent_id="test-agent",
            permissions=["network:http:read", "compute:python:eval"],
            budget_cents=10_000,
        )

    @pytest.fixture
    def executor_with_mock_tool(self, hipaa_token):
        """Build an executor with a mock tool that returns controlled output."""
        from agentsafe.agents.agentic_executor import AgenticExecutor
        from agentsafe.tools.base import BaseTool, ToolResult, ToolParameter
        from agentsafe.tools.registry import ToolRegistry
        from agentsafe.llm.config import LLMConfig

        class MockTool(BaseTool):
            _output = "Clean output from mock tool"

            @property
            def name(self): return "mock_tool"
            @property
            def description(self): return "A mock tool"
            def parameters(self): return [
                ToolParameter(name="query", type="string", description="q"),
            ]
            async def execute(self, *, tool_use_id, **kwargs):
                return ToolResult(tool_use_id=tool_use_id, output=self._output)
            @property
            def required_capabilities(self): return ["network:http:read"]

        registry = ToolRegistry()
        mock_tool = MockTool()
        registry.register(mock_tool)

        config = LLMConfig(model="mock", max_tool_rounds=3)

        executor = AgenticExecutor(
            llm_config=config,
            tool_registry=registry,
            capability_token=hipaa_token,
            content_policy=ContentSafetyPolicy.hipaa_compliant(),
        )

        return executor, mock_tool

    @pytest.mark.asyncio
    async def test_clean_tool_io_passes(self, executor_with_mock_tool):
        """Clean input + clean output → step executes normally."""
        executor, mock_tool = executor_with_mock_tool

        # Mock LLM: one tool call then final response
        from agentsafe.llm.client import LLMResponse, ToolCallRequest

        tool_call_response = LLMResponse(
            text="",
            stop_reason="tool_use",
            tool_calls=[ToolCallRequest(
                id="tc_1", name="mock_tool",
                input={"query": "weather forecast"},
            )],
            input_tokens=10, output_tokens=20,
        )
        final_response = LLMResponse(
            text="The weather is sunny.",
            stop_reason="end_turn",
            tool_calls=[],
            input_tokens=30, output_tokens=40,
        )

        executor._client.send = AsyncMock(
            side_effect=[tool_call_response, final_response]
        )

        result = await executor.run("What's the weather?")

        assert result.success
        assert len(result.steps) == 1
        assert len(result.step_scans) == 1
        assert not result.step_scans[0].blocked
        assert result.step_scans[0].input_scan.action == ScanAction.PASS
        assert result.step_scans[0].output_scan.action == ScanAction.PASS
        assert result.steps_blocked_by_content_safety == 0

    @pytest.mark.asyncio
    async def test_pii_in_tool_input_blocks_execution(self, executor_with_mock_tool):
        """PII in tool input → step blocked, tool never executed."""
        executor, mock_tool = executor_with_mock_tool

        from agentsafe.llm.client import LLMResponse, ToolCallRequest

        # LLM tries to send PII in tool input
        tool_call_response = LLMResponse(
            text="",
            stop_reason="tool_use",
            tool_calls=[ToolCallRequest(
                id="tc_1", name="mock_tool",
                input={"query": "Patient SSN: 123-45-6789"},
            )],
            input_tokens=10, output_tokens=20,
        )
        final_response = LLMResponse(
            text="I could not complete the request.",
            stop_reason="end_turn",
            tool_calls=[],
            input_tokens=30, output_tokens=40,
        )

        execute_called = False
        original_execute = mock_tool.execute
        async def spy_execute(**kwargs):
            nonlocal execute_called
            execute_called = True
            return await original_execute(**kwargs)
        mock_tool.execute = spy_execute

        executor._client.send = AsyncMock(
            side_effect=[tool_call_response, final_response]
        )

        result = await executor.run("Find patient info")

        # The tool should NOT have been executed
        assert not execute_called
        assert len(result.step_scans) == 1
        assert result.step_scans[0].blocked
        assert result.step_scans[0].input_scan.action == ScanAction.BLOCK
        # Audit trail should record the block
        blocked_audits = [a for a in result.audit_trail if a.get("phase") == "input_safety_blocked"]
        assert len(blocked_audits) == 1

    @pytest.mark.asyncio
    async def test_pii_in_tool_output_redacted_under_hipaa(self, executor_with_mock_tool):
        """PII in tool output under HIPAA → redacted, sent to LLM as redacted."""
        executor, mock_tool = executor_with_mock_tool

        # Make the mock tool return PII
        mock_tool._output = "Patient John Smith, SSN: 123-45-6789, diagnosed with flu"

        from agentsafe.llm.client import LLMResponse, ToolCallRequest

        tool_call_response = LLMResponse(
            text="",
            stop_reason="tool_use",
            tool_calls=[ToolCallRequest(
                id="tc_1", name="mock_tool",
                input={"query": "get records"},
            )],
            input_tokens=10, output_tokens=20,
        )
        final_response = LLMResponse(
            text="The patient was diagnosed with flu.",
            stop_reason="end_turn",
            tool_calls=[],
            input_tokens=30, output_tokens=40,
        )

        executor._client.send = AsyncMock(
            side_effect=[tool_call_response, final_response]
        )

        result = await executor.run("Check patient records")

        assert result.success
        assert len(result.step_scans) == 1
        assert result.step_scans[0].output_scan.action == ScanAction.REDACT
        assert result.steps_with_redaction == 1

        # Verify the step output stored in the result is redacted
        assert "123-45-6789" not in result.steps[0].tool_output
        assert "[REDACTED-SSN]" in result.steps[0].tool_output

        # Verify redacted text was sent to LLM (check messages)
        # The second LLM call should have received redacted content
        second_call_args = executor._client.send.call_args_list[1]
        messages = second_call_args.kwargs.get("messages", second_call_args.args[0] if second_call_args.args else [])
        # Find the tool_result message
        tool_result_msgs = [
            m for m in messages
            if isinstance(m.get("content"), list)
            and any(c.get("type") == "tool_result" for c in m["content"])
        ]
        if tool_result_msgs:
            content = tool_result_msgs[-1]["content"]
            for block in content:
                if block.get("type") == "tool_result":
                    assert "123-45-6789" not in block["content"]

    @pytest.mark.asyncio
    async def test_secrets_in_tool_output_blocks(self, executor_with_mock_tool):
        """Secrets in tool output → blocked, NOT sent to LLM."""
        executor, mock_tool = executor_with_mock_tool

        mock_tool._output = "Config: api_key=AKIAIOSFODNN7EXAMPLE"

        from agentsafe.llm.client import LLMResponse, ToolCallRequest

        tool_call_response = LLMResponse(
            text="",
            stop_reason="tool_use",
            tool_calls=[ToolCallRequest(
                id="tc_1", name="mock_tool",
                input={"query": "get config"},
            )],
            input_tokens=10, output_tokens=20,
        )
        final_response = LLMResponse(
            text="Could not retrieve config safely.",
            stop_reason="end_turn",
            tool_calls=[],
            input_tokens=30, output_tokens=40,
        )

        executor._client.send = AsyncMock(
            side_effect=[tool_call_response, final_response]
        )

        result = await executor.run("Get config")

        assert len(result.step_scans) == 1
        assert result.step_scans[0].output_scan.action == ScanAction.BLOCK
        assert result.steps_blocked_by_content_safety == 1
        # The step output should NOT contain the secret
        assert "AKIAIOSFODNN7EXAMPLE" not in result.steps[0].tool_output

    @pytest.mark.asyncio
    async def test_mnpi_keyword_in_tool_input_blocks(self, executor_with_mock_tool):
        """MNPI keywords in tool input under SOX policy → blocked."""
        executor, mock_tool = executor_with_mock_tool

        # Switch to SOX policy
        executor.content_policy = ContentSafetyPolicy.sox_compliant()
        executor._scanner = ContentScanner(executor.content_policy)
        executor._io_scanner = ToolIOScanner(executor.content_policy)

        from agentsafe.llm.client import LLMResponse, ToolCallRequest

        tool_call_response = LLMResponse(
            text="",
            stop_reason="tool_use",
            tool_calls=[ToolCallRequest(
                id="tc_1", name="mock_tool",
                input={"query": "find unreleased earnings data"},
            )],
            input_tokens=10, output_tokens=20,
        )
        final_response = LLMResponse(
            text="Cannot access that information.",
            stop_reason="end_turn",
            tool_calls=[],
            input_tokens=30, output_tokens=40,
        )

        executor._client.send = AsyncMock(
            side_effect=[tool_call_response, final_response]
        )

        result = await executor.run("Get earnings")

        assert len(result.step_scans) == 1
        assert result.step_scans[0].blocked
        assert result.step_scans[0].input_scan.action == ScanAction.BLOCK


# ═════════════════════════════════════════════════════════════════
# Section 7: Edge Cases
# ═════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_empty_tool_output(self):
        scanner = ToolIOScanner(ContentSafetyPolicy.hipaa_compliant())
        result = scanner.scan_tool_output("tool", "", step_index=0)
        assert result.action == ScanAction.PASS

    def test_very_large_output(self):
        scanner = ToolIOScanner(ContentSafetyPolicy.hipaa_compliant())
        big_text = "Clean content. " * 10_000
        result = scanner.scan_tool_output("tool", big_text, step_index=0)
        assert result.action == ScanAction.PASS
        assert result.duration_ms >= 0

    def test_binary_looking_output(self):
        scanner = ToolIOScanner(ContentSafetyPolicy.default())
        result = scanner.scan_tool_output(
            "tool", "\x00\x01\x02 no PII here \x03\x04", step_index=0,
        )
        assert result.action == ScanAction.PASS

    def test_unicode_output(self):
        scanner = ToolIOScanner(ContentSafetyPolicy.hipaa_compliant())
        result = scanner.scan_tool_output(
            "tool", "患者の名前は田中太郎です。SSN: 123-45-6789",
            step_index=0,
        )
        # Should detect the SSN even in mixed unicode
        assert result.redacted or result.blocked

    def test_pii_in_nested_json_input(self):
        scanner = ToolIOScanner(ContentSafetyPolicy.hipaa_compliant())
        result = scanner.scan_tool_input(
            "api_call",
            {"body": {"records": [{"ssn": "123-45-6789", "name": "John"}]}},
            step_index=0,
        )
        assert result.blocked

    def test_multiple_steps_independent(self):
        """Each step scan is independent - no state carried between."""
        scanner = ToolIOScanner(ContentSafetyPolicy.hipaa_compliant())

        r1 = scanner.scan_tool_input("t", {"q": "SSN: 123-45-6789"}, 0)
        assert r1.blocked

        r2 = scanner.scan_tool_input("t", {"q": "weather"}, 1)
        assert not r2.blocked  # Previous step's result doesn't affect this one


# ═════════════════════════════════════════════════════════════════
# Section 8: Telemetry Integration
# ═════════════════════════════════════════════════════════════════

class TestTelemetryPhaseTracking:
    """Verify telemetry records scan phases correctly."""

    def test_record_content_scan_with_phase(self):
        from agentsafe.observability.otel import CertiorTelemetry
        tel = CertiorTelemetry.get_instance()
        # Should not raise with new parameters
        tel.record_content_scan("HIPAA", True, phase="tool_input", action="pass")
        tel.record_content_scan("HIPAA", False, phase="tool_output", action="block")
        tel.record_content_scan("HIPAA", True, phase="final_output", action="pass")

    def test_record_content_scan_backward_compat(self):
        """Old callers without phase should still work."""
        from agentsafe.observability.otel import CertiorTelemetry
        tel = CertiorTelemetry.get_instance()
        tel.record_content_scan("Default", True)  # No phase arg

"""
Integration Tests
============================

Tests for the sandbox integration layer that connects OS-level
containment to Certior's observability, verification, and compliance
systems.

Covers:
1. ObservableSandboxedExecutor - tracing, metrics, audit
2. ComplianceSandboxFactory - HIPAA, SOX, Legal preset policies
3. SandboxAuditRecord - structured audit trail
4. PythonEvalTool integration - sandbox_policy routing
5. verified_sandbox_execute - convenience one-shot API
6. Graceful degradation when OTel is unavailable
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from agentsafe.sandbox import (
    ComplianceSandboxFactory,
    ContainmentLayer,
    ObservableSandboxedExecutor,
    ResourceLimits,
    SandboxAuditRecord,
    SandboxedExecutor,
    SandboxPolicy,
    SandboxResult,
    verified_sandbox_execute,
)
from agentsafe.sandbox.integration import _build_audit_record
from agentsafe.tools.python_eval import PythonEvalTool

is_linux = sys.platform.startswith("linux")
skip_non_linux = pytest.mark.skipif(not is_linux, reason="Linux-only feature")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 1: SandboxAuditRecord
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSandboxAuditRecord:
    """Test audit record creation and serialisation."""

    def _make_result(self, **overrides: Any) -> SandboxResult:
        defaults = dict(
            stdout="hello",
            stderr="",
            returncode=0,
            wall_time_seconds=0.1,
            is_error=False,
            error_type=None,
            active_layers=("rlimits", "python_sandbox", "seccomp_bpf"),
            metadata={},
        )
        defaults.update(overrides)
        return SandboxResult(**defaults)

    def test_build_audit_record_success(self):
        result = self._make_result()
        record = _build_audit_record(
            code="print(42)",
            result=result,
            policy=SandboxPolicy.standard(),
            policy_name="Standard",
            mandatory_ok=True,
        )
        assert record.is_error is False
        assert record.policy_name == "Standard"
        assert record.code_sha256 == hashlib.sha256(b"print(42)").hexdigest()
        assert record.code_length == 9
        assert record.mandatory_layers_met is True
        assert "rlimits" in record.active_layers
        assert len(record.record_id) == 36  # UUID

    def test_build_audit_record_error(self):
        result = self._make_result(
            is_error=True, error_type="violation", returncode=-31,
        )
        record = _build_audit_record(
            code="import os",
            result=result,
            policy=SandboxPolicy.standard(),
            policy_name="HIPAA",
            mandatory_ok=True,
        )
        assert record.is_error is True
        assert record.error_type == "violation"

    def test_audit_record_to_dict(self):
        result = self._make_result()
        record = _build_audit_record(
            code="x=1",
            result=result,
            policy=SandboxPolicy.standard(),
            policy_name="test",
            mandatory_ok=True,
            token_id="tok-123",
            agent_id="agent-456",
        )
        d = record.to_dict()
        assert d["token_id"] == "tok-123"
        assert d["agent_id"] == "agent-456"
        assert isinstance(d["active_layers"], list)
        # Must be JSON-serializable
        json.dumps(d)

    def test_audit_record_immutable(self):
        result = self._make_result()
        record = _build_audit_record(
            code="x=1",
            result=result,
            policy=SandboxPolicy.standard(),
            policy_name="test",
            mandatory_ok=True,
        )
        with pytest.raises(AttributeError):
            record.is_error = True  # type: ignore

    def test_code_not_stored_in_record(self):
        """Audit record stores code hash, never raw code (privacy)."""
        result = self._make_result()
        record = _build_audit_record(
            code="SECRET_CODE = 'password123'",
            result=result,
            policy=SandboxPolicy.standard(),
            policy_name="test",
            mandatory_ok=True,
        )
        d = record.to_dict()
        serialized = json.dumps(d)
        assert "password123" not in serialized
        assert "SECRET_CODE" not in serialized
        assert record.code_sha256 is not None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 2: ObservableSandboxedExecutor
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestObservableSandboxedExecutor:
    """Test the observability wrapper around SandboxedExecutor."""

    @pytest.fixture
    def executor(self):
        """Non-observable executor (telemetry=None fallback)."""
        return ObservableSandboxedExecutor(
            SandboxPolicy.minimal(),
            policy_name="test",
            telemetry=MagicMock(tracer=None, meter=None),
        )

    @pytest.mark.asyncio
    async def test_simple_execution(self, executor):
        result = await executor.execute("print(7 * 6)")
        assert not result.is_error
        assert "42" in result.output

    @pytest.mark.asyncio
    async def test_error_execution(self, executor):
        result = await executor.execute("1/0")
        assert result.is_error
        assert "ZeroDivision" in result.output

    @pytest.mark.asyncio
    async def test_audit_callback_called(self):
        audit_records: List[SandboxAuditRecord] = []
        executor = ObservableSandboxedExecutor(
            SandboxPolicy.minimal(),
            policy_name="audit_test",
            telemetry=MagicMock(tracer=None, meter=None),
            audit_callback=lambda r: audit_records.append(r),
        )
        await executor.execute("print('hello')")
        assert len(audit_records) == 1
        assert audit_records[0].policy_name == "audit_test"
        assert not audit_records[0].is_error

    @pytest.mark.asyncio
    async def test_audit_callback_receives_token(self):
        audit_records: List[SandboxAuditRecord] = []
        executor = ObservableSandboxedExecutor(
            SandboxPolicy.minimal(),
            policy_name="token_test",
            telemetry=MagicMock(tracer=None, meter=None),
            audit_callback=lambda r: audit_records.append(r),
        )
        await executor.execute(
            "print(1)", token_id="tok-999", agent_id="agent-007",
        )
        assert audit_records[0].token_id == "tok-999"
        assert audit_records[0].agent_id == "agent-007"

    @pytest.mark.asyncio
    async def test_audit_callback_error_does_not_break_execution(self):
        def bad_callback(record: SandboxAuditRecord) -> None:
            raise RuntimeError("callback exploded")

        executor = ObservableSandboxedExecutor(
            SandboxPolicy.minimal(),
            policy_name="broken_cb",
            telemetry=MagicMock(tracer=None, meter=None),
            audit_callback=bad_callback,
        )
        # Must not raise - audit callback failure is non-fatal
        result = await executor.execute("print('ok')")
        assert not result.is_error
        assert "ok" in result.output

    def test_get_active_layers(self, executor):
        layers = executor.get_active_layers()
        assert isinstance(layers, list)
        assert "python_sandbox" in layers
        assert "rlimits" in layers

    def test_get_capabilities(self, executor):
        caps = executor.get_capabilities()
        assert "platform" in caps
        assert "active_layers" in caps

    @pytest.mark.asyncio
    async def test_mandatory_layer_check(self):
        executor = ObservableSandboxedExecutor(
            SandboxPolicy.minimal(),
            policy_name="mandatory_test",
            telemetry=MagicMock(tracer=None, meter=None),
        )
        result = await executor.execute("print('hi')")
        assert not result.is_error
        # Minimal policy: rlimits + python_sandbox - both should be active
        mandatory_ok = executor._check_mandatory_layers(result)
        assert mandatory_ok is True

    @pytest.mark.asyncio
    async def test_works_without_telemetry(self):
        """Executor works when OpenTelemetry is completely absent."""
        executor = ObservableSandboxedExecutor(
            SandboxPolicy.minimal(),
            policy_name="no_otel",
            telemetry=None,  # Will try to import, may fail
        )
        result = await executor.execute("print(2 + 2)")
        assert not result.is_error
        assert "4" in result.output


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 3: ComplianceSandboxFactory
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestComplianceSandboxFactory:
    """Test compliance-preconfigured sandbox executors."""

    def test_hipaa_factory(self):
        executor = ComplianceSandboxFactory.for_hipaa()
        assert executor.policy_name == "HIPAA"
        assert executor.policy.resource_limits.memory_bytes == 128 * 1024 * 1024
        assert executor.policy.resource_limits.cpu_time_seconds == 10

    def test_sox_factory(self):
        executor = ComplianceSandboxFactory.for_sox()
        assert executor.policy_name == "SOX"
        assert executor.policy.resource_limits.memory_bytes == 256 * 1024 * 1024

    def test_legal_factory(self):
        executor = ComplianceSandboxFactory.for_legal()
        assert executor.policy_name == "Legal"

    def test_standard_factory(self):
        executor = ComplianceSandboxFactory.standard()
        assert executor.policy_name == "Standard"

    @pytest.mark.asyncio
    async def test_hipaa_executes_safe_code(self):
        executor = ComplianceSandboxFactory.for_hipaa()
        result = await executor.execute("print(3.14)")
        assert not result.is_error
        assert "3.14" in result.output

    @pytest.mark.asyncio
    async def test_hipaa_blocks_dangerous_code(self):
        executor = ComplianceSandboxFactory.for_hipaa()
        result = await executor.execute("import os; os.system('id')")
        assert result.is_error

    def test_hipaa_has_mandatory_rlimits(self):
        executor = ComplianceSandboxFactory.for_hipaa()
        assert ContainmentLayer.RLIMITS in executor.policy.mandatory_layers
        assert ContainmentLayer.PYTHON_SANDBOX in executor.policy.mandatory_layers

    def test_hipaa_has_optional_seccomp(self):
        executor = ComplianceSandboxFactory.for_hipaa()
        assert ContainmentLayer.SECCOMP_BPF in executor.policy.optional_layers

    @pytest.mark.asyncio
    async def test_factory_audit_callback(self):
        records: List[SandboxAuditRecord] = []
        executor = ComplianceSandboxFactory.for_hipaa(
            audit_callback=lambda r: records.append(r),
        )
        await executor.execute("print('audit me')")
        assert len(records) == 1
        assert records[0].policy_name == "HIPAA"

    def test_hipaa_tight_file_limit(self):
        """HIPAA sandbox limits file size to 1 MiB."""
        executor = ComplianceSandboxFactory.for_hipaa()
        assert executor.policy.resource_limits.max_file_size_bytes == 1 * 1024 * 1024

    def test_sox_longer_timeout(self):
        """SOX allows longer timeouts for financial computations."""
        executor = ComplianceSandboxFactory.for_sox()
        assert executor.policy.resource_limits.cpu_time_seconds == 30


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 4: verified_sandbox_execute
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestVerifiedSandboxExecute:
    """Test the convenience one-shot execution function."""

    @pytest.mark.asyncio
    async def test_simple_execution(self):
        result = await verified_sandbox_execute("print(99)")
        assert not result.is_error
        assert "99" in result.output

    @pytest.mark.asyncio
    async def test_with_custom_policy(self):
        policy = SandboxPolicy(
            resource_limits=ResourceLimits(wall_time_seconds=5.0),
        )
        result = await verified_sandbox_execute(
            "print('custom')",
            policy=policy,
            policy_name="custom_test",
        )
        assert not result.is_error
        assert "custom" in result.output

    @pytest.mark.asyncio
    async def test_with_audit_callback(self):
        records: List[SandboxAuditRecord] = []
        result = await verified_sandbox_execute(
            "print('traced')",
            policy_name="traced_test",
            audit_callback=lambda r: records.append(r),
            token_id="tok-abc",
        )
        assert not result.is_error
        assert len(records) == 1
        assert records[0].token_id == "tok-abc"

    @pytest.mark.asyncio
    async def test_error_code(self):
        result = await verified_sandbox_execute("raise ValueError('boom')")
        assert result.is_error

    @pytest.mark.asyncio
    async def test_timeout(self):
        policy = SandboxPolicy(
            resource_limits=ResourceLimits(wall_time_seconds=2.0),
        )
        result = await verified_sandbox_execute(
            "while True: pass",
            policy=policy,
        )
        assert result.is_error
        assert result.error_type in ("timeout", "resource")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 5: PythonEvalTool Sandbox Integration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPythonEvalToolSandboxIntegration:
    """Test PythonEvalTool when used with SandboxPolicy."""

    @pytest.fixture
    def tool_with_sandbox(self):
        return PythonEvalTool(sandbox_policy=SandboxPolicy.standard())

    @pytest.fixture
    def tool_without_sandbox(self):
        return PythonEvalTool()

    # ── Basic execution ───────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_legacy_mode_still_works(self, tool_without_sandbox):
        result = await tool_without_sandbox.execute(
            tool_use_id="t1", code="print(42)",
        )
        assert not result.is_error
        assert "42" in result.output

    @pytest.mark.asyncio
    async def test_sandbox_simple_eval(self, tool_with_sandbox):
        result = await tool_with_sandbox.execute(
            tool_use_id="t1", code="print(2 + 3)",
        )
        assert not result.is_error
        assert "5" in result.output
        assert result.metadata.get("sandbox_mode") == "os_level"

    @pytest.mark.asyncio
    async def test_sandbox_reports_active_layers(self, tool_with_sandbox):
        result = await tool_with_sandbox.execute(
            tool_use_id="t1", code="print('hello')",
        )
        layers = result.metadata.get("active_layers", [])
        assert "python_sandbox" in layers
        assert "rlimits" in layers

    # ── Safety ────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_ast_preflight_still_runs(self, tool_with_sandbox):
        result = await tool_with_sandbox.execute(
            tool_use_id="t1", code="import os\nos.system('id')",
        )
        assert result.is_error
        assert result.metadata.get("sandbox_blocked") is True

    @pytest.mark.asyncio
    async def test_blocked_eval(self, tool_with_sandbox):
        result = await tool_with_sandbox.execute(
            tool_use_id="t1", code="eval('1+1')",
        )
        assert result.is_error

    @pytest.mark.asyncio
    async def test_blocked_socket(self, tool_with_sandbox):
        result = await tool_with_sandbox.execute(
            tool_use_id="t1", code="import socket",
        )
        assert result.is_error

    # ── Safe imports ──────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_math_works(self, tool_with_sandbox):
        result = await tool_with_sandbox.execute(
            tool_use_id="t1", code="import math\nprint(math.pi)",
        )
        assert not result.is_error
        assert "3.14" in result.output

    @pytest.mark.asyncio
    async def test_json_works(self, tool_with_sandbox):
        result = await tool_with_sandbox.execute(
            tool_use_id="t1", code='import json\nprint(json.dumps({"a": 1}))',
        )
        assert not result.is_error

    # ── Error handling ────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_timeout(self):
        policy = SandboxPolicy(
            resource_limits=ResourceLimits(wall_time_seconds=3.0),
        )
        tool = PythonEvalTool(sandbox_policy=policy)
        result = await tool.execute(
            tool_use_id="t1", code="while True: pass",
        )
        assert result.is_error
        assert result.metadata.get("error_type") in ("timeout", "resource")

    @pytest.mark.asyncio
    async def test_empty_code_rejected(self, tool_with_sandbox):
        result = await tool_with_sandbox.execute(
            tool_use_id="t1", code="",
        )
        assert result.is_error

    # ── Properties ────────────────────────────────────────────────────

    def test_sandbox_active_layers_with_policy(self, tool_with_sandbox):
        layers = tool_with_sandbox.sandbox_active_layers
        assert isinstance(layers, list)
        assert len(layers) >= 2

    def test_sandbox_active_layers_without_policy(self, tool_without_sandbox):
        layers = tool_without_sandbox.sandbox_active_layers
        assert layers == ["python_sandbox"]

    def test_required_capabilities(self, tool_with_sandbox):
        assert "compute:python:eval" in tool_with_sandbox.required_capabilities


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 6: Graceful Degradation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestGracefulDegradation:
    """Verify sandbox works correctly when optional components are absent."""

    @pytest.mark.asyncio
    async def test_no_telemetry_import(self):
        """Works when agentsafe.observability is not importable."""
        with patch.dict(
            "sys.modules", {"agentsafe.observability": None},
        ):
            executor = ObservableSandboxedExecutor(
                SandboxPolicy.minimal(),
                policy_name="no_otel",
                telemetry=None,
            )
            result = await executor.execute("print(42)")
            assert not result.is_error
            assert "42" in result.output

    @pytest.mark.asyncio
    async def test_metrics_recording_failure_non_fatal(self):
        """Broken meter does not break execution."""
        broken_telemetry = MagicMock()
        broken_telemetry.tracer = None
        broken_telemetry.meter = MagicMock()
        # Make create_counter raise
        broken_telemetry.meter.create_counter.side_effect = RuntimeError("boom")

        executor = ObservableSandboxedExecutor(
            SandboxPolicy.minimal(),
            policy_name="broken_meter",
            telemetry=broken_telemetry,
        )
        result = await executor.execute("print('resilient')")
        assert not result.is_error
        assert "resilient" in result.output


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 7: End-to-End Scenarios
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestEndToEndScenarios:
    """Full integration scenarios combining multiple components."""

    @pytest.mark.asyncio
    async def test_hipaa_sandbox_with_audit_trail(self):
        """HIPAA sandbox + audit trail for compliance reporting."""
        records: List[SandboxAuditRecord] = []
        executor = ComplianceSandboxFactory.for_hipaa(
            audit_callback=lambda r: records.append(r),
        )

        # Safe computation
        result = await executor.execute(
            "import math\nprint(round(math.pi, 4))",
            token_id="hipaa-tok-001",
            agent_id="medical-agent",
        )
        assert not result.is_error
        assert "3.1416" in result.output

        # Verify audit
        assert len(records) == 1
        assert records[0].policy_name == "HIPAA"
        assert records[0].token_id == "hipaa-tok-001"
        assert records[0].agent_id == "medical-agent"
        assert records[0].mandatory_layers_met is True

    @pytest.mark.asyncio
    async def test_sox_sandbox_blocks_os_access(self):
        """SOX sandbox blocks OS-level access attempts."""
        executor = ComplianceSandboxFactory.for_sox()
        result = await executor.execute("import os\nos.listdir('/')")
        assert result.is_error

    @pytest.mark.asyncio
    async def test_multiple_executions_accumulate_audit(self):
        """Multiple executions produce individual audit records."""
        records: List[SandboxAuditRecord] = []
        executor = ComplianceSandboxFactory.standard(
            audit_callback=lambda r: records.append(r),
        )

        for i in range(3):
            await executor.execute(f"print({i})")

        assert len(records) == 3
        # Each record has a unique ID
        ids = {r.record_id for r in records}
        assert len(ids) == 3

    @pytest.mark.asyncio
    async def test_python_eval_tool_through_compliance_factory(self):
        """PythonEvalTool with a compliance-configured sandbox."""
        hipaa_executor = ComplianceSandboxFactory.for_hipaa()
        tool = PythonEvalTool(sandbox_policy=hipaa_executor.policy)

        result = await tool.execute(
            tool_use_id="compliance-t1",
            code="print('HIPAA safe output')",
        )
        assert not result.is_error
        assert "HIPAA safe output" in result.output
        assert result.metadata.get("sandbox_mode") == "os_level"

    @pytest.mark.asyncio
    async def test_data_processing_in_sandbox(self):
        """Complex data processing code works in sandbox."""
        code = """\
data = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5]
mean = sum(data) / len(data)
sorted_data = sorted(data)
median = sorted_data[len(sorted_data) // 2]
print(f"mean={mean:.2f} median={median}")
"""
        executor = ComplianceSandboxFactory.standard()
        result = await executor.execute(code)
        assert not result.is_error
        assert "mean=" in result.output
        assert "median=" in result.output

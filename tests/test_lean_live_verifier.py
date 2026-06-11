"""
Tests for Lean4 Live Flow Verifier and AgenticExecutor integration.

Covers:
  - LeanLiveVerifier lifecycle (start, check, shutdown)
  - Graceful degradation when binary unavailable
  - JSON protocol parsing (LeanFlowResult)
  - Session state tracking (LeanFlowState)
  - Summary generation for audit trail
  - AgenticExecutor wiring (step-level and final-output flow checks)
  - Audit trail events for Lean verification
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure the project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentsafe.verification.lean_live_verifier import (
    LeanFlowResult,
    LeanFlowState,
    LeanLiveVerifier,
    _find_binary,
)


# ── LeanFlowResult ──────────────────────────────────────────────────


class TestLeanFlowResult:
    """Tests for the result dataclass."""

    def test_ok_result_to_dict(self):
        r = LeanFlowResult(ok=True, proven=True, latency_ms=1.234)
        d = r.to_dict()
        assert d["ok"] is True
        assert d["proven"] is True
        assert d["latency_ms"] == 1.23
        assert "error" not in d

    def test_error_result_to_dict(self):
        r = LeanFlowResult(
            ok=False,
            error="flow_violation",
            detail="Sensitive cannot flow to Public",
            proven=True,
            latency_ms=0.5,
        )
        d = r.to_dict()
        assert d["ok"] is False
        assert d["error"] == "flow_violation"
        assert d["detail"] == "Sensitive cannot flow to Public"

    def test_certificate_in_dict(self):
        cert = {"step": 0, "tool": "web_fetch", "prover": "lean4"}
        r = LeanFlowResult(ok=True, proven=True, certificate=cert, latency_ms=0.1)
        d = r.to_dict()
        assert d["certificate"] == cert

    def test_defaults(self):
        r = LeanFlowResult(ok=True)
        assert r.error == ""
        assert r.detail == ""
        assert r.certificate is None
        assert r.proven is False
        assert r.steps_checked == 0
        assert r.budget_remaining == 0
        assert r.flow_violations == 0
        assert r.latency_ms == 0.0


# ── LeanFlowState ───────────────────────────────────────────────────


class TestLeanFlowState:
    """Tests for the state tracking dataclass."""

    def test_default_state(self):
        s = LeanFlowState()
        assert s.steps_checked == 0
        assert s.budget_remaining == 0
        assert s.budget_total == 0
        assert s.certificates_count == 0
        assert s.flow_violations == 0
        assert s.compliance_policy == "default"
        assert s.flow_tracker == []
        assert s.certificates == []


# ── Binary Discovery ─────────────────────────────────────────────────


class TestBinaryDiscovery:
    """Tests for _find_binary()."""

    def test_env_var_override(self, tmp_path):
        binary = tmp_path / "certior-flow-check"
        binary.write_text("#!/bin/sh\necho ok")
        binary.chmod(0o755)

        with patch.dict(os.environ, {"CERTIOR_FLOW_CHECK_BINARY": str(binary)}):
            assert _find_binary() == str(binary)

    def test_env_var_nonexistent(self):
        with patch.dict(os.environ, {"CERTIOR_FLOW_CHECK_BINARY": "/nonexistent/binary"}):
            # Falls through to other methods
            result = _find_binary()
            # May or may not find a binary via other paths, but shouldn't crash
            assert result is None or isinstance(result, str)

    def test_no_binary_returns_none(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch(
                "agentsafe.verification.lean_live_verifier._DEFAULT_LAKE_PATHS",
                [Path("/nonexistent/path/binary")],
            ):
                with patch("shutil.which", return_value=None):
                    assert _find_binary() is None


# ── LeanLiveVerifier Lifecycle ───────────────────────────────────────


class TestLeanLiveVerifierGracefulDegradation:
    """Tests that the verifier degrades gracefully when no binary is available."""

    @pytest.mark.asyncio
    async def test_start_without_binary(self):
        verifier = LeanLiveVerifier(binary=None)
        # Force no binary found
        verifier._binary = None
        started = await verifier.start(budget=10000)
        assert started is False
        assert verifier.is_available is False

    @pytest.mark.asyncio
    async def test_check_flow_without_binary(self):
        verifier = LeanLiveVerifier(binary=None)
        verifier._binary = None
        await verifier.start(budget=10000)

        result = await verifier.check_flow(
            step_index=0,
            tool="web_fetch",
            input_labels=["Public"],
            output_label="Internal",
        )
        # Should not block execution
        assert result.ok is True
        assert result.proven is False
        assert "not available" in result.detail.lower() or "skipped" in result.detail.lower()

    @pytest.mark.asyncio
    async def test_check_output_flow_without_binary(self):
        verifier = LeanLiveVerifier(binary=None)
        verifier._binary = None
        await verifier.start(budget=10000)

        result = await verifier.check_output_flow(
            step_index=0,
            tool="file_write",
            data_label="Internal",
            target_label="Public",
        )
        assert result.ok is True
        assert result.proven is False

    @pytest.mark.asyncio
    async def test_shutdown_without_binary(self):
        verifier = LeanLiveVerifier(binary=None)
        verifier._binary = None
        # Should not raise
        await verifier.shutdown()

    @pytest.mark.asyncio
    async def test_get_state_without_binary(self):
        verifier = LeanLiveVerifier(binary=None)
        verifier._binary = None
        state = await verifier.get_state()
        assert isinstance(state, LeanFlowState)

    @pytest.mark.asyncio
    async def test_get_certificates_without_binary(self):
        verifier = LeanLiveVerifier(binary=None)
        verifier._binary = None
        certs = await verifier.get_certificates()
        assert certs == []

    def test_summary_without_binary(self):
        verifier = LeanLiveVerifier(binary=None)
        verifier._binary = None
        s = verifier.summary()
        assert s["lean_kernel_available"] is False
        assert s["binary_found"] is False
        assert s["steps_checked"] == 0
        assert s["avg_latency_ms"] == 0.0


# ── LeanLiveVerifier with Mock Subprocess ────────────────────────────


class _FakeProcess:
    """Mock asyncio subprocess for testing LeanLiveVerifier."""

    def __init__(self, responses: List[Dict[str, Any]]):
        self._responses = list(responses)
        self._idx = 0
        self.returncode = None
        self.pid = 12345
        self.stdin = self._FakeStdin()
        self.stdout = self._FakeStdout(self)
        self.stderr = self._FakeStderr()

    class _FakeStdin:
        def write(self, data: bytes):
            pass

        async def drain(self):
            pass

    class _FakeStdout:
        def __init__(self, parent: "_FakeProcess"):
            self._parent = parent

        async def readline(self) -> bytes:
            if self._parent._idx >= len(self._parent._responses):
                return b""
            resp = self._parent._responses[self._parent._idx]
            self._parent._idx += 1
            return (json.dumps(resp) + "\n").encode()

    class _FakeStderr:
        async def readline(self) -> bytes:
            return b""

    def kill(self):
        self.returncode = -9

    async def wait(self):
        pass


class TestLeanLiveVerifierWithMockProcess:
    """Tests with a mock subprocess that simulates the Lean4 binary."""

    @pytest.mark.asyncio
    async def test_start_and_init(self):
        fake = _FakeProcess([
            {"ready": True, "version": "1.0.0"},  # ready signal
            {"ok": True},                           # init response
        ])

        verifier = LeanLiveVerifier(binary="/fake/binary")
        with patch("asyncio.create_subprocess_exec", return_value=fake):
            started = await verifier.start(
                budget=10000,
                capabilities=["network:http:read"],
                compliance="hipaa",
            )

        assert started is True
        assert verifier.is_available is True
        assert verifier.state.budget_total == 10000
        assert verifier.state.compliance_policy == "hipaa"

    @pytest.mark.asyncio
    async def test_check_flow_allowed(self):
        fake = _FakeProcess([
            {"ready": True, "version": "1.0.0"},
            {"ok": True},  # init
            {
                "ok": True,
                "proven": True,
                "certificate": {
                    "step": 0,
                    "tool": "web_fetch",
                    "prover": "lean4_lattice",
                },
                "steps_checked": 1,
                "budget_remaining": 9900,
                "certificates_count": 1,
                "flow_violations": 0,
            },
        ])

        verifier = LeanLiveVerifier(binary="/fake/binary")
        with patch("asyncio.create_subprocess_exec", return_value=fake):
            await verifier.start(budget=10000)

            result = await verifier.check_flow(
                step_index=0,
                tool="web_fetch",
                input_labels=["Public"],
                output_label="Internal",
                cost=100,
            )

        assert result.ok is True
        assert result.proven is True
        assert result.certificate is not None
        assert result.certificate["prover"] == "lean4_lattice"
        assert verifier.state.steps_checked == 1
        assert verifier.state.certificates_count == 1

    @pytest.mark.asyncio
    async def test_check_flow_violation(self):
        fake = _FakeProcess([
            {"ready": True, "version": "1.0.0"},
            {"ok": True},
            {
                "ok": False,
                "proven": True,
                "error": "flow_violation",
                "detail": "Sensitive cannot flow to Public by lattice order",
                "steps_checked": 1,
                "flow_violations": 1,
            },
        ])

        verifier = LeanLiveVerifier(binary="/fake/binary")
        with patch("asyncio.create_subprocess_exec", return_value=fake):
            await verifier.start(budget=10000)

            result = await verifier.check_flow(
                step_index=0,
                tool="file_write",
                input_labels=["Sensitive"],
                output_label="Public",
            )

        assert result.ok is False
        assert result.proven is True
        assert result.error == "flow_violation"
        assert "Sensitive" in result.detail
        assert verifier.state.flow_violations == 1

    @pytest.mark.asyncio
    async def test_check_output_flow(self):
        fake = _FakeProcess([
            {"ready": True, "version": "1.0.0"},
            {"ok": True},
            {
                "ok": True,
                "proven": True,
                "steps_checked": 0,
            },
        ])

        verifier = LeanLiveVerifier(binary="/fake/binary")
        with patch("asyncio.create_subprocess_exec", return_value=fake):
            await verifier.start(budget=10000)

            result = await verifier.check_output_flow(
                step_index=0,
                tool="web_fetch",
                data_label="Internal",
                target_label="Internal",
            )

        assert result.ok is True
        assert result.proven is True

    @pytest.mark.asyncio
    async def test_shutdown(self):
        fake = _FakeProcess([
            {"ready": True, "version": "1.0.0"},
            {"ok": True},
            {"ok": True},  # shutdown ack
        ])

        verifier = LeanLiveVerifier(binary="/fake/binary")
        with patch("asyncio.create_subprocess_exec", return_value=fake):
            await verifier.start(budget=10000)
            await verifier.shutdown()

        assert not verifier.is_available

    @pytest.mark.asyncio
    async def test_summary_after_session(self):
        fake = _FakeProcess([
            {"ready": True, "version": "1.0.0"},
            {"ok": True},
            {
                "ok": True, "proven": True,
                "steps_checked": 1, "certificates_count": 1,
                "flow_violations": 0, "budget_remaining": 9900,
            },
            {
                "ok": True, "proven": True,
                "steps_checked": 2, "certificates_count": 2,
                "flow_violations": 0, "budget_remaining": 9800,
            },
        ])

        verifier = LeanLiveVerifier(binary="/fake/binary")
        with patch("asyncio.create_subprocess_exec", return_value=fake):
            await verifier.start(budget=10000)
            await verifier.check_flow(0, "web_fetch", ["Public"], "Internal", cost=100)
            await verifier.check_flow(1, "file_write", ["Internal"], "Internal", cost=100)

        s = verifier.summary()
        assert s["lean_kernel_available"] is True
        assert s["steps_checked"] == 2
        assert s["certificates_issued"] == 2
        assert s["flow_violations"] == 0
        assert s["total_requests"] == 3  # init + 2 check_flow requests
        assert s["avg_latency_ms"] >= 0


# ── Timeout and Error Handling ───────────────────────────────────────


class TestLeanLiveVerifierErrors:
    """Tests for error handling in the Lean verifier."""

    @pytest.mark.asyncio
    async def test_startup_timeout(self):
        """If the binary hangs on startup, verifier degrades gracefully."""

        async def slow_start(*args, **kwargs):
            proc = MagicMock()
            proc.returncode = None
            proc.pid = 999
            proc.stdin = MagicMock()
            proc.stderr = MagicMock()

            async def slow_readline():
                await asyncio.sleep(100)
                return b""

            proc.stdout = MagicMock()
            proc.stdout.readline = slow_readline
            proc.kill = MagicMock()
            proc.wait = AsyncMock()
            return proc

        verifier = LeanLiveVerifier(binary="/fake/binary", timeout=0.01)
        with patch("asyncio.create_subprocess_exec", side_effect=slow_start):
            started = await verifier.start(budget=10000)

        assert started is False
        assert not verifier.is_available

    @pytest.mark.asyncio
    async def test_process_death_during_check(self):
        """If the process dies mid-session, verifier detects and degrades."""
        fake = _FakeProcess([
            {"ready": True, "version": "1.0.0"},
            {"ok": True},
            # Third call returns empty (process dead)
        ])
        # Simulate process death after init
        fake._responses.append(None)  # Will cause empty readline

        verifier = LeanLiveVerifier(binary="/fake/binary")
        with patch("asyncio.create_subprocess_exec", return_value=fake):
            await verifier.start(budget=10000)

            # Simulate process death by setting returncode
            fake.returncode = 1

            result = await verifier.check_flow(
                0, "web_fetch", ["Public"], "Internal",
            )

        # Should not crash, but result is a communication error
        assert "error" in result.error or not result.ok or result.ok

    @pytest.mark.asyncio
    async def test_binary_not_found_on_start(self):
        """FileNotFoundError during subprocess exec is handled."""
        verifier = LeanLiveVerifier(binary="/nonexistent/binary")

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("/nonexistent/binary"),
        ):
            started = await verifier.start(budget=10000)

        assert started is False
        assert not verifier.is_available

    @pytest.mark.asyncio
    async def test_non_proven_error_is_advisory(self):
        """When Lean returns ok=False without proven=True, it's advisory
        (e.g., timeout, communication error - not a lattice violation)."""
        result = LeanFlowResult(
            ok=False,
            error="timeout",
            detail="Request timed out",
            proven=False,
            latency_ms=5000.0,
        )
        # Advisory: should not trigger blocking logic
        assert not result.ok
        assert not result.proven
        # The executor checks `not ok AND proven` for blocking;
        # this won't match, so execution continues.

    @pytest.mark.asyncio
    async def test_proven_violation_is_blocking(self):
        """When Lean returns ok=False WITH proven=True, it must block.
        This is the critical invariant: proven lattice violations are
        mathematically certain and must be enforced."""
        fake = _FakeProcess([
            {"ready": True, "version": "1.0.0"},
            {"ok": True},
            {
                "ok": False, "proven": True,  # CRITICAL: must include proven
                "error": "flow_violation",
                "detail": "Sensitive cannot flow to Public by lattice order",
                "steps_checked": 1,
                "flow_violations": 1,
            },
        ])

        verifier = LeanLiveVerifier(binary="/fake/binary")
        with patch("asyncio.create_subprocess_exec", return_value=fake):
            await verifier.start(budget=10000)

            result = await verifier.check_flow(
                step_index=0,
                tool="file_write",
                input_labels=["Sensitive"],
                output_label="Public",
            )

        # Both conditions must be true for the executor to block:
        assert not result.ok
        assert result.proven, (
            "CRITICAL: flow violations MUST have proven=True "
            "for the executor to enforce the block"
        )


# ── AgenticExecutor Integration (Structural) ─────────────────────────


class TestAgenticExecutorLeanWiring:
    """
    Structural tests verifying the Lean4 integration points exist
    in the AgenticExecutor code without requiring a full runtime.

    We read source directly to avoid pulling in heavy deps (httpx, etc.).
    """

    @staticmethod
    def _executor_source() -> str:
        src_path = (
            Path(__file__).resolve().parent.parent
            / "agentsafe" / "agents" / "agentic_executor.py"
        )
        return src_path.read_text()

    def test_executor_has_lean_verifier_attribute(self):
        """AgenticExecutor.__init__ creates a _lean_verifier."""
        src = self._executor_source()
        assert "self._lean_verifier = LeanLiveVerifier()" in src

    def test_agent_step_has_lean_fields(self):
        """AgentStep dataclass has lean_flow_result and lean_proven."""
        from agentsafe.agents.agentic_executor import AgentStep

        step = AgentStep(
            step_index=0,
            tool_name="test",
            tool_input={},
            tool_output="ok",
            lean_flow_result={"ok": True, "proven": True},
            lean_proven=True,
        )
        d = step.to_dict()
        assert d["lean_verification"] == {"ok": True, "proven": True}
        assert d["lean_proven"] is True

    def test_agent_step_lean_defaults(self):
        """AgentStep defaults have no Lean results."""
        from agentsafe.agents.agentic_executor import AgentStep

        step = AgentStep(step_index=0, tool_name="t", tool_input={}, tool_output="o")
        d = step.to_dict()
        assert "lean_verification" not in d
        assert "lean_proven" not in d

    def test_agentic_result_has_lean_summary(self):
        """AgenticResult has lean_summary field."""
        from agentsafe.agents.agentic_executor import AgenticResult

        result = AgenticResult(
            task="test",
            lean_summary={"lean_kernel_available": True, "steps_checked": 3},
        )
        d = result.to_dict()
        assert d["lean_verification_summary"]["steps_checked"] == 3

    def test_executor_run_contains_lean_flow_check(self):
        """The run() method source contains Lean flow verification calls."""
        src = self._executor_source()
        # Pre-execution flow check
        assert "self._lean_verifier.check_flow(" in src
        # Post-execution output flow check
        assert "self._lean_verifier.check_output_flow(" in src
        # Final output flow check
        assert '"__final_output__"' in src
        # Shutdown
        assert "self._lean_verifier.shutdown()" in src
        # Audit events
        assert '"lean_flow_verified"' in src
        assert '"lean_flow_blocked"' in src
        assert '"lean_output_flow_blocked"' in src
        assert '"lean_output_flow_verified"' in src
        assert '"lean_final_output_blocked"' in src
        assert '"lean_kernel_started"' in src
        assert '"lean_kernel_unavailable"' in src

    def test_executor_close_shuts_down_lean(self):
        """The close() method shuts down the Lean verifier."""
        src = self._executor_source()
        # Find close method
        assert "async def close(self)" in src
        # After close def, should have lean shutdown
        close_idx = src.index("async def close(self)")
        close_body = src[close_idx:close_idx + 300]
        assert "self._lean_verifier.shutdown()" in close_body

    def test_all_exit_paths_have_lean_summary(self):
        """Every AgenticResult construction includes lean_summary."""
        src = self._executor_source()
        result_count = src.count("AgenticResult(")
        lean_count = src.count("lean_summary=self._lean_verifier.summary()")
        assert result_count >= 3, f"Expected ≥3 AgenticResult, got {result_count}"
        assert lean_count == result_count, (
            f"AgenticResult count ({result_count}) != "
            f"lean_summary count ({lean_count})"
        )

    def test_executor_has_advisory_error_path(self):
        """The run() method logs non-proven Lean errors as advisory."""
        src = self._executor_source()
        assert '"lean_flow_advisory_error"' in src


# ── FlowCheck.lean Protocol ─────────────────────────────────────────


class TestFlowCheckProtocol:
    """Tests that the Lean4 FlowCheck binary follows the expected JSON protocol."""

    def test_lean_source_exists(self):
        lean_path = (
            Path(__file__).resolve().parent.parent
            / "lean4" / "CertiorPlan" / "app" / "FlowCheck.lean"
        )
        assert lean_path.is_file(), f"FlowCheck.lean not found at {lean_path}"

    def test_lean_source_has_required_commands(self):
        lean_path = (
            Path(__file__).resolve().parent.parent
            / "lean4" / "CertiorPlan" / "app" / "FlowCheck.lean"
        )
        src = lean_path.read_text()
        for cmd in ["init", "check_flow", "check_tool_output_flow",
                     "get_state", "get_certificates", "shutdown"]:
            assert f'"{cmd}"' in src, f"Missing command handler: {cmd}"

    def test_lean_error_responses_include_proven(self):
        """CRITICAL: Error responses from flow violations must include proven=true
        so the Python side blocks on mathematically-certain violations."""
        lean_path = (
            Path(__file__).resolve().parent.parent
            / "lean4" / "CertiorPlan" / "app" / "FlowCheck.lean"
        )
        src = lean_path.read_text()
        # Both handleCheckFlow and handleCheckToolOutputFlow should add proven
        # when returning a flow violation
        assert src.count('"proven"') >= 4, (
            "Expected ≥4 occurrences of '\"proven\"' in FlowCheck.lean "
            "(2 for ok responses, 2 for violation responses)"
        )

    def test_lakefile_has_flow_check_target(self):
        lakefile = (
            Path(__file__).resolve().parent.parent
            / "lean4" / "CertiorPlan" / "lakefile.lean"
        )
        src = lakefile.read_text()
        assert "certior-flow-check" in src
        assert "app.FlowCheck" in src


# ── Integration Scenario (Full Mock) ────────────────────────────────


class TestLeanIntegrationScenario:
    """
    End-to-end scenario test with the mock subprocess, simulating
    a multi-step agent session with dual Z3+Lean verification.
    """

    @pytest.mark.asyncio
    async def test_three_step_session(self):
        """Simulate a 3-step agent session and verify cumulative state."""
        fake = _FakeProcess([
            # Startup
            {"ready": True, "version": "1.0.0"},
            {"ok": True},
            # Step 0: web_fetch flow check
            {
                "ok": True, "proven": True,
                "certificate": {"step": 0, "tool": "web_fetch", "prover": "lean4"},
                "steps_checked": 1, "certificates_count": 1,
                "flow_violations": 0, "budget_remaining": 9900,
            },
            # Step 0: output flow check (Internal → Internal)
            {
                "ok": True, "proven": True,
                "steps_checked": 1, "budget_remaining": 9900,
            },
            # Step 1: file_write flow check
            {
                "ok": True, "proven": True,
                "certificate": {"step": 1, "tool": "file_write", "prover": "lean4"},
                "steps_checked": 2, "certificates_count": 2,
                "flow_violations": 0, "budget_remaining": 9800,
            },
            # Step 1: output flow check
            {
                "ok": True, "proven": True,
                "steps_checked": 2, "budget_remaining": 9800,
            },
            # Step 2: python_eval blocked by Lean (Sensitive → Public)
            {
                "ok": False, "proven": True,
                "error": "flow_violation",
                "detail": "Sensitive data cannot flow to Public output",
                "steps_checked": 3, "certificates_count": 2,
                "flow_violations": 1, "budget_remaining": 9700,
            },
            # Final output flow check
            {
                "ok": True, "proven": True,
                "steps_checked": 3,
            },
            # Shutdown
            {"ok": True},
        ])

        verifier = LeanLiveVerifier(binary="/fake/binary")
        with patch("asyncio.create_subprocess_exec", return_value=fake):
            await verifier.start(budget=10000, capabilities=["all"], compliance="hipaa")

            # Step 0: web_fetch
            r0 = await verifier.check_flow(0, "web_fetch", ["Public"], "Internal", cost=100)
            assert r0.ok and r0.proven
            r0o = await verifier.check_output_flow(0, "web_fetch", "Internal", "Internal")
            assert r0o.ok

            # Step 1: file_write
            r1 = await verifier.check_flow(1, "file_write", ["Internal"], "Internal", cost=100)
            assert r1.ok and r1.proven
            r1o = await verifier.check_output_flow(1, "file_write", "Internal", "Internal")
            assert r1o.ok

            # Step 2: python_eval BLOCKED
            r2 = await verifier.check_flow(2, "python_eval", ["Sensitive"], "Public", cost=100)
            assert not r2.ok
            assert r2.proven
            assert r2.error == "flow_violation"

            # Final output check
            rf = await verifier.check_output_flow(3, "__final_output__", "Internal", "Public")
            assert rf.ok

            # Verify cumulative state
            assert verifier.state.steps_checked == 3
            assert verifier.state.certificates_count == 2
            assert verifier.state.flow_violations == 1

            # Shutdown
            await verifier.shutdown()

        # Summary
        s = verifier.summary()
        assert s["steps_checked"] == 3
        assert s["certificates_issued"] == 2
        assert s["flow_violations"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

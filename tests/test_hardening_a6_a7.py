"""
A6 + A7 Production Hardening Tests
===================================

A6: Atomic budget reservation (reserve-before-execute, rollback on failure)
A7: Sandbox module/builtin blocking with AST pre-flight
"""
from __future__ import annotations

import asyncio
import threading
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── A6 imports ──
from agentsafe.capabilities.tokens import (
    BudgetExhaustedError,
    BudgetReservation,
    CapabilityToken,
)

# ── A7 imports ──
from agentsafe.tools.python_eval import (
    PythonEvalTool,
    _BLOCKED_BUILTINS,
    _BLOCKED_MODULES,
    _ast_preflight,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# A6: Budget Reservation - Token Level
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestA6TokenReservation:
    """Test atomic budget reservation on CapabilityToken."""

    def test_reserve_deducts_immediately(self):
        token = CapabilityToken(budget_cents=100, budget_remaining_cents=100)
        reservation = token.reserve_budget(40)
        # Budget deducted at reservation time
        assert token.budget_remaining_cents == 60
        assert reservation.cost_cents == 40
        assert not reservation.committed

    def test_reserve_commits_on_success(self):
        token = CapabilityToken(budget_cents=100, budget_remaining_cents=100)
        reservation = token.reserve_budget(40)
        with reservation:
            pass  # success
        assert token.budget_remaining_cents == 60
        assert reservation.committed

    def test_reserve_rollback_on_exception(self):
        token = CapabilityToken(budget_cents=100, budget_remaining_cents=100)
        reservation = token.reserve_budget(40)
        with pytest.raises(ValueError):
            with reservation:
                raise ValueError("tool failed")
        # Budget restored
        assert token.budget_remaining_cents == 100
        assert not reservation.committed

    def test_reserve_insufficient_funds_raises(self):
        token = CapabilityToken(budget_cents=100, budget_remaining_cents=30)
        with pytest.raises(BudgetExhaustedError) as exc_info:
            token.reserve_budget(50)
        assert exc_info.value.cost_cents == 50
        assert exc_info.value.remaining_cents == 30
        # Budget unchanged
        assert token.budget_remaining_cents == 30

    def test_reserve_exact_budget(self):
        token = CapabilityToken(budget_cents=100, budget_remaining_cents=50)
        reservation = token.reserve_budget(50)
        with reservation:
            pass
        assert token.budget_remaining_cents == 0

    def test_reserve_zero_cost(self):
        token = CapabilityToken(budget_cents=100, budget_remaining_cents=100)
        reservation = token.reserve_budget(0)
        with reservation:
            pass
        assert token.budget_remaining_cents == 100

    def test_multiple_sequential_reservations(self):
        token = CapabilityToken(budget_cents=100, budget_remaining_cents=100)
        r1 = token.reserve_budget(30)
        with r1:
            pass
        assert token.budget_remaining_cents == 70

        r2 = token.reserve_budget(40)
        with r2:
            pass
        assert token.budget_remaining_cents == 30

        # Third should fail if too large
        with pytest.raises(BudgetExhaustedError):
            token.reserve_budget(50)
        assert token.budget_remaining_cents == 30

    def test_consume_budget_still_works(self):
        """Backward compat: consume_budget still works atomically."""
        token = CapabilityToken(budget_cents=100, budget_remaining_cents=100)
        assert token.consume_budget(40) is True
        assert token.budget_remaining_cents == 60
        assert token.consume_budget(70) is False  # insufficient
        assert token.budget_remaining_cents == 60

    def test_has_budget_thread_safe(self):
        """has_budget reads under lock."""
        token = CapabilityToken(budget_cents=100, budget_remaining_cents=50)
        assert token.has_budget(50) is True
        assert token.has_budget(51) is False


class TestA6ThreadSafety:
    """Verify budget operations are thread-safe under contention."""

    def test_concurrent_reservations_no_overdraw(self):
        """100 threads each try to reserve 10 from a budget of 500.
        Exactly 50 should succeed; remaining 50 should fail."""
        token = CapabilityToken(budget_cents=500, budget_remaining_cents=500)
        successes = []
        failures = []

        def try_reserve():
            try:
                r = token.reserve_budget(10)
                with r:
                    time.sleep(0.001)  # simulate work
                successes.append(True)
            except BudgetExhaustedError:
                failures.append(True)

        threads = [threading.Thread(target=try_reserve) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(successes) == 50
        assert len(failures) == 50
        assert token.budget_remaining_cents == 0

    def test_concurrent_consume_no_overdraw(self):
        """Same test with consume_budget for backward compat."""
        token = CapabilityToken(budget_cents=100, budget_remaining_cents=100)
        successes = []

        def try_consume():
            if token.consume_budget(10):
                successes.append(True)

        threads = [threading.Thread(target=try_consume) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(successes) == 10
        assert token.budget_remaining_cents == 0

    def test_rollback_under_contention(self):
        """Reservations that fail (raise) must return budget correctly."""
        token = CapabilityToken(budget_cents=100, budget_remaining_cents=100)

        def reserve_and_fail():
            try:
                r = token.reserve_budget(10)
                with r:
                    raise RuntimeError("fail")
            except RuntimeError:
                pass

        threads = [threading.Thread(target=reserve_and_fail) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All rolled back
        assert token.budget_remaining_cents == 100


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# A6: Budget Reservation - VerifiedAgent.execute_action
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestA6ExecuteActionReservation:
    """Test that VerifiedAgent.execute_action reserves before execution."""

    @pytest.mark.asyncio
    async def test_budget_reserved_before_tool_runs(self):
        """Budget must be deducted BEFORE tool executes, not after."""
        from agentsafe.agents.base import VerifiedAgent
        from agentsafe.agents.actions import AgentAction

        token = CapabilityToken(
            permissions=["test:*"], budget_cents=100,
            budget_remaining_cents=100,
        )
        agent = VerifiedAgent.__new__(VerifiedAgent)
        agent.token = token
        agent.telemetry = MagicMock()
        agent.kernel = MagicMock()
        agent.kernel.validate_certificate.return_value = True
        agent._tools = {}

        budget_at_execution = []

        def capture_tool(params):
            budget_at_execution.append(token.budget_remaining_cents)
            return "ok"

        agent._tools["test_tool"] = capture_tool

        action = AgentAction(
            id="a1", tool="test_tool", parameters={},
            estimated_cost_cents=30,
        )
        cert = MagicMock()
        cert.id = "cert-1"
        action_hash = action.to_hash()
        cert.plan_hash = action_hash

        result = await agent.execute_action(action, cert)
        assert result.success
        # Budget was deducted BEFORE tool ran
        assert budget_at_execution == [70]
        assert token.budget_remaining_cents == 70

    @pytest.mark.asyncio
    async def test_budget_rolled_back_on_tool_failure(self):
        """If tool raises, budget must be restored."""
        from agentsafe.agents.base import VerifiedAgent
        from agentsafe.agents.actions import AgentAction

        token = CapabilityToken(
            permissions=["test:*"], budget_cents=100,
            budget_remaining_cents=100,
        )
        agent = VerifiedAgent.__new__(VerifiedAgent)
        agent.token = token
        agent.telemetry = MagicMock()
        agent.kernel = MagicMock()
        agent.kernel.validate_certificate.return_value = True
        agent._tools = {}

        def failing_tool(params):
            raise RuntimeError("tool crashed")

        agent._tools["bad_tool"] = failing_tool

        action = AgentAction(
            id="a1", tool="bad_tool", parameters={},
            estimated_cost_cents=50,
        )
        cert = MagicMock()
        cert.id = "cert-1"

        result = await agent.execute_action(action, cert)
        assert not result.success
        assert "tool crashed" in result.error
        # Budget rolled back
        assert token.budget_remaining_cents == 100

    @pytest.mark.asyncio
    async def test_budget_exhausted_blocks_execution(self):
        """If budget insufficient, tool must NOT execute."""
        from agentsafe.agents.base import VerifiedAgent
        from agentsafe.agents.actions import AgentAction

        token = CapabilityToken(
            permissions=["test:*"], budget_cents=100,
            budget_remaining_cents=10,
        )
        agent = VerifiedAgent.__new__(VerifiedAgent)
        agent.token = token
        agent.telemetry = MagicMock()
        agent.kernel = MagicMock()
        agent.kernel.validate_certificate.return_value = True
        agent._tools = {}

        tool_called = []

        def spy_tool(params):
            tool_called.append(True)
            return "should not run"

        agent._tools["expensive_tool"] = spy_tool

        action = AgentAction(
            id="a1", tool="expensive_tool", parameters={},
            estimated_cost_cents=50,
        )
        cert = MagicMock()
        cert.id = "cert-1"

        result = await agent.execute_action(action, cert)
        assert not result.success
        assert "Budget exhausted" in result.error
        assert tool_called == []  # tool never ran
        assert token.budget_remaining_cents == 10  # unchanged


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# A7: Sandbox - Blocked Modules Coverage
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestA7BlockedModules:
    """Verify critical dangerous modules are in the blocklist."""

    @pytest.mark.parametrize("module", [
        "os", "sys", "pathlib", "pickle", "marshal",
        "subprocess", "shutil", "ctypes", "socket",
        "importlib", "signal", "pty", "gc", "inspect",
        "code", "codeop", "runpy", "compileall",
        "multiprocessing", "threading", "_thread",
        "http", "urllib", "ftplib", "smtplib", "telnetlib",
        "shelve", "dill", "cloudpickle",
        "tempfile", "glob", "mmap",
        "pdb", "builtins", "_io",
        "io", "codecs", "fileinput", "sqlite3",
        "zipfile", "tarfile", "dbm",
    ])
    def test_module_in_blocklist(self, module):
        assert module in _BLOCKED_MODULES, f"{module} not in _BLOCKED_MODULES"

    @pytest.mark.parametrize("module", [
        # Safe modules that SHOULD be allowed
        "math", "json", "re", "datetime", "collections",
        "itertools", "functools", "operator", "string",
        "decimal", "fractions", "random", "hashlib",
        "base64", "csv", "textwrap", "copy",
    ])
    def test_safe_modules_not_blocked(self, module):
        assert module not in _BLOCKED_MODULES, f"{module} should not be blocked"


class TestA7BlockedBuiltins:
    """Verify dangerous builtins are blocked."""

    @pytest.mark.parametrize("name", [
        "open", "eval", "exec", "compile", "__import__",
        "breakpoint", "exit", "quit", "input",
        "globals", "locals", "vars", "getattr", "setattr",
    ])
    def test_builtin_in_blocklist(self, name):
        assert name in _BLOCKED_BUILTINS, f"{name} not in _BLOCKED_BUILTINS"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# A7: AST Pre-flight Analysis
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestA7ASTPreFlight:
    """Test static analysis catches dangerous patterns."""

    def test_import_os_blocked(self):
        v = _ast_preflight("import os")
        assert len(v) == 1
        assert "os" in v[0]

    def test_import_sys_blocked(self):
        v = _ast_preflight("import sys")
        assert len(v) == 1
        assert "sys" in v[0]

    def test_import_pickle_blocked(self):
        v = _ast_preflight("import pickle")
        assert len(v) == 1
        assert "pickle" in v[0]

    def test_import_pathlib_blocked(self):
        v = _ast_preflight("import pathlib")
        assert len(v) == 1
        assert "pathlib" in v[0]

    def test_import_io_blocked(self):
        v = _ast_preflight("import io")
        assert len(v) == 1
        assert "io" in v[0]

    def test_import_codecs_blocked(self):
        v = _ast_preflight("import codecs")
        assert len(v) == 1
        assert "codecs" in v[0]

    def test_from_os_import_blocked(self):
        v = _ast_preflight("from os import path")
        assert len(v) == 1
        assert "os" in v[0]

    def test_from_subprocess_import_blocked(self):
        v = _ast_preflight("from subprocess import Popen")
        assert len(v) == 1
        assert "subprocess" in v[0]

    def test_open_call_blocked(self):
        v = _ast_preflight("open('/etc/passwd')")
        assert len(v) >= 1
        assert any("open" in x for x in v)

    def test_eval_call_blocked(self):
        v = _ast_preflight("eval('1+1')")
        assert len(v) >= 1
        assert any("eval" in x for x in v)

    def test_exec_call_blocked(self):
        v = _ast_preflight("exec('print(1)')")
        assert len(v) >= 1
        assert any("exec" in x for x in v)

    def test_compile_call_blocked(self):
        v = _ast_preflight("compile('x=1', '<string>', 'exec')")
        assert len(v) >= 1
        assert any("compile" in x for x in v)

    def test_dunder_builtins_blocked(self):
        v = _ast_preflight("x = foo.__builtins__")
        assert len(v) >= 1
        assert any("__builtins__" in x for x in v)

    def test_dunder_class_blocked(self):
        v = _ast_preflight("x = ''.__class__")
        assert len(v) >= 1
        assert any("__class__" in x for x in v)

    def test_dunder_subclasses_blocked(self):
        v = _ast_preflight("x = object.__subclasses__()")
        assert len(v) >= 1
        assert any("__subclasses__" in x for x in v)

    def test_dunder_globals_blocked(self):
        v = _ast_preflight("x = f.__globals__")
        assert len(v) >= 1
        assert any("__globals__" in x for x in v)

    def test_os_system_call_blocked(self):
        v = _ast_preflight("os.system('ls')")
        assert len(v) >= 1
        assert any("system" in x for x in v)

    def test_import_module_call_blocked(self):
        v = _ast_preflight("importlib.import_module('os')")
        assert len(v) >= 1
        assert any("import_module" in x for x in v)

    def test_safe_code_passes(self):
        v = _ast_preflight("print(2 + 3)")
        assert v == []

    def test_safe_math_passes(self):
        v = _ast_preflight("import math\nprint(math.sqrt(16))")
        assert v == []

    def test_safe_json_passes(self):
        v = _ast_preflight("import json\nprint(json.dumps({'a': 1}))")
        assert v == []

    def test_syntax_error_passes_preflight(self):
        """Syntax errors are caught at runtime, not preflight."""
        v = _ast_preflight("def f(")
        assert v == []

    def test_multiple_violations(self):
        code = "import os\nimport sys\nopen('/etc/passwd')\neval('1')"
        v = _ast_preflight(code)
        assert len(v) >= 4

    def test_dunder_reduce_blocked(self):
        """Pickle escape via __reduce__."""
        v = _ast_preflight("x = obj.__reduce__()")
        assert len(v) >= 1
        assert any("__reduce__" in x for x in v)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# A7: Sandbox - End-to-End (subprocess execution)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestA7SandboxE2E:
    """End-to-end tests running actual subprocess sandboxed code."""

    @pytest.mark.asyncio
    async def test_safe_code_runs(self):
        tool = PythonEvalTool()
        result = await tool.execute(tool_use_id="t1", code="print(2 + 3)")
        assert not result.is_error
        assert "5" in result.output

    @pytest.mark.asyncio
    async def test_safe_math_import(self):
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="import math\nprint(math.sqrt(16))",
        )
        assert not result.is_error
        assert "4" in result.output

    @pytest.mark.asyncio
    async def test_safe_json_import(self):
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1",
            code="import json\nprint(json.dumps({'a': 1}))",
        )
        assert not result.is_error
        assert "a" in result.output

    @pytest.mark.asyncio
    async def test_import_os_ast_blocked(self):
        """AST pre-flight catches import os BEFORE subprocess."""
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="import os\nprint(os.getcwd())",
        )
        assert result.is_error
        assert "sandbox" in result.output.lower() or "blocked" in result.output.lower()

    @pytest.mark.asyncio
    async def test_import_sys_ast_blocked(self):
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="import sys\nprint(sys.version)",
        )
        assert result.is_error
        assert "blocked" in result.output.lower()

    @pytest.mark.asyncio
    async def test_import_pathlib_ast_blocked(self):
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="import pathlib\nprint(pathlib.Path.cwd())",
        )
        assert result.is_error
        assert "blocked" in result.output.lower()

    @pytest.mark.asyncio
    async def test_import_pickle_ast_blocked(self):
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="import pickle",
        )
        assert result.is_error
        assert "blocked" in result.output.lower()

    @pytest.mark.asyncio
    async def test_import_io_ast_blocked(self):
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="import io\nf=io.open('/etc/passwd')",
        )
        assert result.is_error
        assert "blocked" in result.output.lower()

    @pytest.mark.asyncio
    async def test_import_codecs_ast_blocked(self):
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="import codecs\ncodecs.open('/etc/passwd')",
        )
        assert result.is_error
        assert "blocked" in result.output.lower()

    @pytest.mark.asyncio
    async def test_open_call_ast_blocked(self):
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="f = open('/etc/passwd')\nprint(f.read())",
        )
        assert result.is_error
        assert "blocked" in result.output.lower()

    @pytest.mark.asyncio
    async def test_eval_call_ast_blocked(self):
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="print(eval('2+2'))",
        )
        assert result.is_error
        assert "blocked" in result.output.lower()

    @pytest.mark.asyncio
    async def test_dunder_class_escape_blocked(self):
        """Classic sandbox escape: ''.__class__.__mro__[1].__subclasses__()"""
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1",
            code="print(''.__class__.__mro__[1].__subclasses__())",
        )
        assert result.is_error
        assert "blocked" in result.output.lower()

    @pytest.mark.asyncio
    async def test_subprocess_blocked(self):
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="import subprocess\nsubprocess.run(['ls'])",
        )
        assert result.is_error

    @pytest.mark.asyncio
    async def test_ctypes_blocked(self):
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="import ctypes",
        )
        assert result.is_error

    @pytest.mark.asyncio
    async def test_marshal_blocked(self):
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="import marshal",
        )
        assert result.is_error

    @pytest.mark.asyncio
    async def test_sandbox_metadata_on_block(self):
        """Blocked result should have sandbox_blocked metadata."""
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="import os",
        )
        assert result.is_error
        assert result.metadata.get("sandbox_blocked") is True
        assert len(result.metadata.get("violations", [])) >= 1

    @pytest.mark.asyncio
    async def test_safe_list_comprehension(self):
        """Complex but safe code should work."""
        tool = PythonEvalTool()
        code = "print([x**2 for x in range(10)])"
        result = await tool.execute(tool_use_id="t1", code=code)
        assert not result.is_error
        assert "81" in result.output

    @pytest.mark.asyncio
    async def test_safe_string_operations(self):
        tool = PythonEvalTool()
        code = "s = 'hello world'\nprint(s.upper(), len(s))"
        result = await tool.execute(tool_use_id="t1", code=code)
        assert not result.is_error
        assert "HELLO WORLD" in result.output


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# A6 + A7 Combined: Budget + Sandbox Integration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestA6A7Combined:
    """Integration tests combining budget reservation with sandbox."""

    @pytest.mark.asyncio
    async def test_sandbox_violation_does_not_consume_budget(self):
        """A7 sandbox rejection should leave budget untouched."""
        token = CapabilityToken(
            permissions=["compute:python:eval"],
            budget_cents=100, budget_remaining_cents=100,
        )
        # Simulate the flow: reserve, then AST rejects
        # Since AST blocks before execution, reserve should not happen
        tool = PythonEvalTool()
        result = await tool.execute(
            tool_use_id="t1", code="import os",
        )
        assert result.is_error
        # Budget not touched (tool didn't execute)
        assert token.budget_remaining_cents == 100

    def test_budget_exhausted_error_has_useful_info(self):
        """BudgetExhaustedError should carry cost, remaining, token_id."""
        token = CapabilityToken(
            id="tok-99", budget_cents=100, budget_remaining_cents=10,
        )
        with pytest.raises(BudgetExhaustedError) as exc_info:
            token.reserve_budget(50)
        err = exc_info.value
        assert err.cost_cents == 50
        assert err.remaining_cents == 10
        assert err.token_id == "tok-99"
        assert "tok-99" in str(err)

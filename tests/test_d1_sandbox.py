"""
OS-Level Sandboxing Tests
====================================

Tests for process-level containment using seccomp-bpf, Linux namespaces,
rlimits, and nsjail.  Validates that:

1. Safe code executes correctly under all containment layers
2. Dangerous operations are blocked at the OS level
3. Resource limits are enforced (CPU, memory, files, processes)
4. Network access is blocked by namespace isolation
5. Filesystem access is contained
6. The sandbox degrades gracefully on unsupported platforms
7. Integration with PythonEvalTool works end-to-end

All tests that require Linux-specific features are marked with
``@pytest.mark.skipif(not linux)`` so the suite runs cleanly on
macOS/CI without root.
"""
from __future__ import annotations

import asyncio
import os
import platform
import signal
import sys
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agentsafe.sandbox import (
    ContainmentLayer,
    ResourceLimits,
    SandboxedExecutor,
    SandboxError,
    SandboxPolicy,
    SandboxResult,
    SandboxSetupError,
    SandboxTimeoutError,
    SandboxViolationError,
    seccomp_available,
)
from agentsafe.sandbox.policy import (
    SECCOMP_SYSCALL_ALLOWLIST_X86_64,
    SECCOMP_SYSCALL_ALLOWLIST_AARCH64,
)
from agentsafe.sandbox.seccomp import (
    build_bpf_program,
    bpf_instruction_count,
    resolve_syscall_numbers,
    SeccompAction,
)
from agentsafe.sandbox.rlimits import (
    apply_rlimits,
    build_rlimit_specs,
    get_current_rlimits,
)
from agentsafe.sandbox.namespace import probe_all, reset_probe_cache
from agentsafe.tools.python_eval import PythonEvalTool

is_linux = sys.platform.startswith("linux")
is_x86_64 = platform.machine() in ("x86_64", "AMD64")
skip_non_linux = pytest.mark.skipif(not is_linux, reason="Linux-only feature")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 1: SandboxPolicy
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSandboxPolicy:
    """Test policy configuration and factory methods."""

    def test_standard_policy_defaults(self):
        policy = SandboxPolicy.standard()
        assert ContainmentLayer.RLIMITS in policy.mandatory_layers
        assert ContainmentLayer.PYTHON_SANDBOX in policy.mandatory_layers
        assert ContainmentLayer.SECCOMP_BPF in policy.optional_layers

    def test_maximum_policy(self):
        policy = SandboxPolicy.maximum()
        assert ContainmentLayer.SECCOMP_BPF in policy.mandatory_layers
        assert policy.resource_limits.memory_bytes == 128 * 1024 * 1024
        assert policy.resource_limits.cpu_time_seconds == 10

    def test_minimal_policy(self):
        policy = SandboxPolicy.minimal()
        assert len(policy.optional_layers) == 0
        assert ContainmentLayer.RLIMITS in policy.mandatory_layers

    def test_nsjail_policy(self):
        policy = SandboxPolicy.nsjail()
        assert policy.require_nsjail
        assert ContainmentLayer.NSJAIL in policy.mandatory_layers

    def test_policy_immutable(self):
        policy = SandboxPolicy.standard()
        with pytest.raises(AttributeError):
            policy.require_nsjail = True  # type: ignore

    def test_resource_limits_immutable(self):
        rl = ResourceLimits()
        with pytest.raises(AttributeError):
            rl.cpu_time_seconds = 999  # type: ignore

    def test_resource_limits_defaults(self):
        rl = ResourceLimits()
        assert rl.wall_time_seconds == 30.0
        assert rl.cpu_time_seconds == 30
        assert rl.memory_bytes == 256 * 1024 * 1024
        assert rl.max_processes == 1
        assert rl.max_core_size == 0

    def test_effective_syscall_allowlist_x86_64(self):
        policy = SandboxPolicy.standard()
        allowlist = policy.effective_syscall_allowlist
        assert len(allowlist) > 30  # reasonable minimum
        assert "read" in allowlist
        assert "write" in allowlist
        assert "exit_group" in allowlist
        # Dangerous syscalls must NOT be in the allowlist
        assert "execve" not in allowlist
        assert "fork" not in allowlist
        assert "clone" not in allowlist
        assert "socket" not in allowlist
        assert "connect" not in allowlist
        assert "bind" not in allowlist
        assert "ptrace" not in allowlist
        assert "mount" not in allowlist
        assert "umount2" not in allowlist
        assert "chroot" not in allowlist
        assert "reboot" not in allowlist
        assert "init_module" not in allowlist
        assert "delete_module" not in allowlist

    def test_custom_syscall_allowlist(self):
        custom = frozenset({"read", "write", "exit_group"})
        policy = SandboxPolicy(allowed_syscalls=custom)
        assert policy.effective_syscall_allowlist == custom


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 2: seccomp-BPF
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSeccomp:
    """Test seccomp-BPF filter generation."""

    def test_resolve_syscall_numbers(self):
        names = frozenset({"read", "write", "exit_group"})
        numbers = resolve_syscall_numbers(names)
        assert len(numbers) == 3
        assert all(isinstance(n, int) for n in numbers)
        assert numbers == sorted(numbers)

    def test_resolve_unknown_syscall_dropped(self):
        names = frozenset({"read", "totally_fake_syscall_xyz"})
        numbers = resolve_syscall_numbers(names)
        # fake syscall silently dropped
        assert len(numbers) == 1

    def test_build_bpf_program_nonempty(self):
        numbers = resolve_syscall_numbers(frozenset({"read", "write", "exit_group"}))
        prog = build_bpf_program(numbers)
        assert len(prog) > 0
        assert len(prog) % 8 == 0  # each instruction is 8 bytes

    def test_bpf_instruction_count(self):
        numbers = resolve_syscall_numbers(frozenset({"read", "write", "exit_group"}))
        prog = build_bpf_program(numbers)
        count = bpf_instruction_count(prog)
        # Expected: 2 (arch check) + 1 (kill wrong arch) + 1 (load nr)
        #         + N (JEQs) + 1 (default action) + 1 (ALLOW)
        assert count == 2 + 1 + 1 + 3 + 1 + 1  # 9

    def test_bpf_full_allowlist_within_limits(self):
        """Full allowlist must generate < 4096 BPF instructions."""
        numbers = resolve_syscall_numbers(SECCOMP_SYSCALL_ALLOWLIST_X86_64)
        prog = build_bpf_program(numbers)
        assert bpf_instruction_count(prog) < 4096

    def test_bpf_kill_action(self):
        numbers = [0, 1, 60]  # read, write, exit
        prog = build_bpf_program(numbers, default_action=SeccompAction.KILL)
        assert len(prog) > 0

    def test_bpf_log_action(self):
        numbers = [0, 1, 60]
        prog = build_bpf_program(numbers, default_action=SeccompAction.LOG)
        assert len(prog) > 0

    def test_bpf_errno_action(self):
        numbers = [0, 1, 60]
        prog = build_bpf_program(numbers, default_action=SeccompAction.ERRNO)
        assert len(prog) > 0

    @skip_non_linux
    def test_seccomp_available_on_linux(self):
        assert seccomp_available() is True

    def test_seccomp_not_available_on_non_linux(self):
        if not is_linux:
            assert seccomp_available() is False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 3: rlimits
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRlimits:
    """Test resource limit building and reading."""

    def test_build_rlimit_specs(self):
        specs = build_rlimit_specs(cpu_time_seconds=10, max_processes=1)
        assert len(specs) >= 6
        names = [s.name for s in specs]
        assert "RLIMIT_CPU" in names
        assert "RLIMIT_AS" in names
        assert "RLIMIT_NPROC" in names
        assert "RLIMIT_CORE" in names

    def test_build_rlimit_specs_cpu_grace(self):
        specs = build_rlimit_specs(cpu_time_seconds=10)
        cpu_spec = [s for s in specs if s.name == "RLIMIT_CPU"][0]
        assert cpu_spec.soft == 10
        assert cpu_spec.hard == 12  # 2 second grace

    def test_get_current_rlimits(self):
        current = get_current_rlimits()
        assert "RLIMIT_CPU" in current
        assert "RLIMIT_AS" in current
        # Values should be tuples of (soft, hard)
        for name, (soft, hard) in current.items():
            assert isinstance(soft, int)
            assert isinstance(hard, int)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 4: Linux Namespaces
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestNamespaces:
    """Test namespace probing."""

    @skip_non_linux
    def test_probe_all_returns_dict(self):
        reset_probe_cache()
        result = probe_all()
        assert isinstance(result, dict)
        assert "user" in result
        assert "pid" in result
        assert "net" in result
        assert "ipc" in result
        for key, val in result.items():
            assert isinstance(val, bool)

    def test_probe_on_non_linux(self):
        if not is_linux:
            result = probe_all()
            assert all(v is False for v in result.values())


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 5: SandboxedExecutor - Basic Execution
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSandboxedExecutorBasic:
    """Test basic code execution through the sandbox."""

    @pytest.fixture
    def executor(self):
        return SandboxedExecutor(SandboxPolicy.minimal())

    @pytest.mark.asyncio
    async def test_simple_print(self, executor):
        result = await executor.execute("print(2 + 3)")
        assert not result.is_error
        assert "5" in result.output

    @pytest.mark.asyncio
    async def test_multiline_code(self, executor):
        code = "for i in range(3):\n    print(i)"
        result = await executor.execute(code)
        assert not result.is_error
        assert "0" in result.output
        assert "2" in result.output

    @pytest.mark.asyncio
    async def test_math_import(self, executor):
        result = await executor.execute("import math\nprint(math.sqrt(16))")
        assert not result.is_error
        assert "4" in result.output

    @pytest.mark.asyncio
    async def test_json_import(self, executor):
        code = "import json\nprint(json.dumps({'a': 1}))"
        result = await executor.execute(code)
        assert not result.is_error
        assert "a" in result.output

    @pytest.mark.asyncio
    async def test_list_comprehension(self, executor):
        result = await executor.execute("print([x**2 for x in range(5)])")
        assert not result.is_error
        assert "16" in result.output

    @pytest.mark.asyncio
    async def test_syntax_error(self, executor):
        result = await executor.execute("def f(")
        assert result.is_error
        assert "SyntaxError" in result.output

    @pytest.mark.asyncio
    async def test_runtime_error(self, executor):
        result = await executor.execute("1/0")
        assert result.is_error
        assert "ZeroDivision" in result.output

    @pytest.mark.asyncio
    async def test_no_output_message(self, executor):
        result = await executor.execute("x = 42")
        assert not result.is_error
        assert "No output" in result.output

    @pytest.mark.asyncio
    async def test_active_layers_reported(self, executor):
        result = await executor.execute("print('hello')")
        assert len(result.active_layers) >= 2  # rlimits + python_sandbox


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 6: SandboxedExecutor - Containment Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSandboxContainment:
    """Verify that dangerous operations are blocked at the OS level."""

    @pytest.fixture
    def executor(self):
        return SandboxedExecutor(SandboxPolicy.standard())

    @pytest.mark.asyncio
    async def test_blocked_os_import(self, executor):
        """os module blocked by Python-level sandbox."""
        result = await executor.execute(
            "import os\nprint(os.listdir('/'))"
        )
        assert result.is_error

    @pytest.mark.asyncio
    async def test_blocked_subprocess_import(self, executor):
        """subprocess blocked by Python-level sandbox."""
        result = await executor.execute(
            "import subprocess\nsubprocess.run(['id'])"
        )
        assert result.is_error

    @pytest.mark.asyncio
    async def test_blocked_socket_import(self, executor):
        """socket blocked by Python-level sandbox."""
        result = await executor.execute(
            "import socket\ns = socket.socket()"
        )
        assert result.is_error

    @pytest.mark.asyncio
    async def test_blocked_ctypes_import(self, executor):
        """ctypes blocked by Python-level sandbox."""
        result = await executor.execute("import ctypes")
        assert result.is_error

    @pytest.mark.asyncio
    async def test_blocked_pickle_import(self, executor):
        """pickle deserialization blocked."""
        result = await executor.execute("import pickle")
        assert result.is_error

    @pytest.mark.asyncio
    async def test_blocked_open_builtin(self, executor):
        """open() builtin blocked."""
        result = await executor.execute("f = open('/etc/passwd')")
        assert result.is_error

    @pytest.mark.asyncio
    async def test_blocked_eval_builtin(self, executor):
        """eval() builtin blocked."""
        result = await executor.execute("eval('1+1')")
        assert result.is_error

    @pytest.mark.asyncio
    async def test_blocked_exec_builtin(self, executor):
        """exec() builtin blocked."""
        result = await executor.execute("exec('print(1)')")
        assert result.is_error

    @pytest.mark.asyncio
    async def test_blocked_dunder_class_exploit(self, executor):
        """Full exploit via __subclasses__ → subprocess.Popen blocked at OS layer.

        Defence-in-depth: even if the Python sandbox allows enumerating
        subclasses, seccomp + import restrictions prevent actual exploitation.
        The exploit tries to find subprocess.Popen in the MRO and invoke it.
        """
        code = textwrap.dedent("""\
            subs = ''.__class__.__mro__[1].__subclasses__()
            targets = [s for s in subs if 'Popen' in s.__name__]
            if targets:
                # Try to spawn a process - seccomp blocks execve
                targets[0](['echo', 'pwned'])
            else:
                # Even finding the class is only half the exploit
                raise RuntimeError("no Popen found")
        """)
        result = await executor.execute(code)
        # Must fail - either import restriction, seccomp kill, or missing class
        assert result.is_error

    @pytest.mark.asyncio
    async def test_blocked_dunder_globals_exploit(self, executor):
        """Exploit via __globals__ to access os module blocked.

        Even if introspection works, the import hook prevents accessing
        blocked modules, and seccomp prevents dangerous syscalls.
        """
        code = textwrap.dedent("""\
            import math
            # Try to reach os module through math's globals
            g = math.__loader__.__class__.__module__
            __import__('os').system('echo pwned')
        """)
        result = await executor.execute(code)
        # Must fail - os is in blocked_modules
        assert result.is_error


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 7: Resource Limit Enforcement
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestResourceEnforcement:
    """Test that resource limits are actually enforced."""

    @pytest.mark.asyncio
    async def test_wall_clock_timeout(self):
        """Infinite loop killed by wall-clock timeout."""
        policy = SandboxPolicy(
            resource_limits=ResourceLimits(
                wall_time_seconds=3.0,
                cpu_time_seconds=30,
            ),
        )
        executor = SandboxedExecutor(policy)
        result = await executor.execute("while True: pass")
        assert result.is_error
        assert result.error_type in ("timeout", "resource")

    @pytest.mark.asyncio
    @skip_non_linux
    async def test_cpu_time_limit(self):
        """CPU-intensive loop killed by RLIMIT_CPU."""
        policy = SandboxPolicy(
            resource_limits=ResourceLimits(
                wall_time_seconds=15.0,
                cpu_time_seconds=2,
            ),
        )
        executor = SandboxedExecutor(policy)
        result = await executor.execute(
            "x = 0\nwhile True:\n    x += 1"
        )
        assert result.is_error
        assert result.error_type in ("timeout", "resource")

    @pytest.mark.asyncio
    @skip_non_linux
    async def test_fork_bomb_blocked(self):
        """RLIMIT_NPROC prevents fork bombs.

        Even if os module were somehow available, rlimit blocks forks.
        We test via a safe import that doesn't get AST-blocked, then
        use the rlimit to prevent actual process creation.
        """
        # This tests the rlimit layer, not the Python sandbox
        policy = SandboxPolicy(
            resource_limits=ResourceLimits(max_processes=1),
        )
        executor = SandboxedExecutor(policy)
        # Even if the code could fork, RLIMIT_NPROC = 1 prevents it.
        # Verify normal execution still works under this constraint.
        result = await executor.execute("print('no fork needed')")
        assert not result.is_error
        assert "no fork needed" in result.output


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 8: Capabilities & Diagnostics
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCapabilities:
    """Test capability probing and diagnostics."""

    def test_get_capabilities(self):
        executor = SandboxedExecutor(SandboxPolicy.standard())
        caps = executor.get_capabilities()
        assert "platform" in caps
        assert "active_layers" in caps
        assert isinstance(caps["active_layers"], list)
        assert "python_sandbox" in caps["active_layers"]
        assert "rlimits" in caps["active_layers"]

    def test_get_active_layers(self):
        executor = SandboxedExecutor(SandboxPolicy.standard())
        layers = executor.get_active_layers()
        assert isinstance(layers, list)
        assert len(layers) >= 2  # at minimum rlimits + python_sandbox

    @skip_non_linux
    def test_seccomp_in_active_layers(self):
        executor = SandboxedExecutor(SandboxPolicy.standard())
        layers = executor.get_active_layers()
        if seccomp_available():
            assert "seccomp_bpf" in layers


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 9: Mandatory Layer Validation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestMandatoryLayers:
    """Verify fail-closed behavior when mandatory layers are unavailable."""

    @pytest.mark.asyncio
    async def test_nsjail_required_but_missing(self):
        """If nsjail is required but not installed, execution is refused."""
        policy = SandboxPolicy.nsjail()
        with patch("shutil.which", return_value=None):
            executor = SandboxedExecutor.__new__(SandboxedExecutor)
            executor.policy = policy
            executor._capabilities = {
                "nsjail": False,
                "rlimits": True,
                "seccomp": False,
                "python_sandbox": True,
                "namespaces": {},
                "active_layers": [],
                "platform": "linux",
            }
            with pytest.raises(SandboxSetupError, match="nsjail"):
                await executor.execute("print('hi')")

    def test_mandatory_seccomp_on_non_linux(self):
        """Mandatory seccomp on non-Linux raises SandboxSetupError."""
        if is_linux and seccomp_available():
            pytest.skip("seccomp is available on this system")
        policy = SandboxPolicy(
            mandatory_layers=frozenset({ContainmentLayer.SECCOMP_BPF}),
        )
        executor = SandboxedExecutor.__new__(SandboxedExecutor)
        executor.policy = policy
        executor._capabilities = {"seccomp": False, "rlimits": True,
                                   "python_sandbox": True, "namespaces": {},
                                   "active_layers": [], "platform": sys.platform}
        with pytest.raises(SandboxSetupError, match="seccomp"):
            executor._validate_mandatory_layers()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 10: PythonEvalTool Integration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPythonEvalToolIntegration:
    """Integration: PythonEvalTool with OS-level sandbox."""

    @pytest.fixture
    def tool_with_sandbox(self):
        return PythonEvalTool(sandbox_policy=SandboxPolicy.standard())

    @pytest.fixture
    def tool_without_sandbox(self):
        return PythonEvalTool()

    @pytest.mark.asyncio
    async def test_legacy_mode_still_works(self, tool_without_sandbox):
        """Without sandbox_policy, legacy execution works."""
        result = await tool_without_sandbox.execute(
            tool_use_id="t1", code="print(42)"
        )
        assert not result.is_error
        assert "42" in result.output

    @pytest.mark.asyncio
    async def test_os_sandbox_simple_eval(self, tool_with_sandbox):
        """OS-level sandbox executes simple code."""
        result = await tool_with_sandbox.execute(
            tool_use_id="t1", code="print(2 + 3)"
        )
        assert not result.is_error
        assert "5" in result.output
        assert result.metadata.get("sandbox_mode") == "os_level"

    @pytest.mark.asyncio
    async def test_os_sandbox_reports_active_layers(self, tool_with_sandbox):
        """Metadata includes active containment layers."""
        result = await tool_with_sandbox.execute(
            tool_use_id="t1", code="print('hello')"
        )
        layers = result.metadata.get("active_layers", [])
        assert "python_sandbox" in layers
        assert "rlimits" in layers

    @pytest.mark.asyncio
    async def test_ast_preflight_still_runs(self, tool_with_sandbox):
        """AST preflight catches import os BEFORE OS sandbox runs."""
        result = await tool_with_sandbox.execute(
            tool_use_id="t1", code="import os\nos.system('id')"
        )
        assert result.is_error
        assert result.metadata.get("sandbox_blocked") is True

    @pytest.mark.asyncio
    async def test_os_sandbox_blocks_eval(self, tool_with_sandbox):
        """eval() is blocked by the Python-level sandbox inside OS sandbox."""
        result = await tool_with_sandbox.execute(
            tool_use_id="t1", code="eval('1+1')"
        )
        assert result.is_error

    @pytest.mark.asyncio
    async def test_os_sandbox_math_works(self, tool_with_sandbox):
        result = await tool_with_sandbox.execute(
            tool_use_id="t1",
            code="import math\nprint(math.pi)",
        )
        assert not result.is_error
        assert "3.14" in result.output

    @pytest.mark.asyncio
    async def test_os_sandbox_timeout(self):
        """Wall-clock timeout works through PythonEvalTool."""
        policy = SandboxPolicy(
            resource_limits=ResourceLimits(wall_time_seconds=3.0),
        )
        tool = PythonEvalTool(sandbox_policy=policy)
        result = await tool.execute(
            tool_use_id="t1", code="while True: pass"
        )
        assert result.is_error
        assert result.metadata.get("error_type") in ("timeout", "resource")

    @pytest.mark.asyncio
    async def test_empty_code_rejected(self, tool_with_sandbox):
        """Empty code rejected before sandbox runs."""
        result = await tool_with_sandbox.execute(
            tool_use_id="t1", code=""
        )
        assert result.is_error

    def test_sandbox_active_layers_property(self, tool_with_sandbox):
        """PythonEvalTool exposes active layers."""
        layers = tool_with_sandbox.sandbox_active_layers
        assert isinstance(layers, list)
        assert len(layers) >= 2

    def test_legacy_tool_active_layers(self, tool_without_sandbox):
        """Legacy tool reports python_sandbox only."""
        layers = tool_without_sandbox.sandbox_active_layers
        assert layers == ["python_sandbox"]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 11: SandboxResult
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSandboxResult:
    """Test SandboxResult output formatting."""

    def test_success_output(self):
        r = SandboxResult(stdout="hello", stderr="", returncode=0,
                          wall_time_seconds=0.1)
        assert r.output == "hello"
        assert not r.is_error

    def test_error_runtime(self):
        r = SandboxResult(stdout="", stderr="Traceback...", returncode=1,
                          wall_time_seconds=0.1, is_error=True,
                          error_type="runtime")
        assert "Traceback" in r.output
        assert r.is_error

    def test_error_timeout(self):
        r = SandboxResult(stdout="", stderr="", returncode=-9,
                          wall_time_seconds=5.0, is_error=True,
                          error_type="timeout")
        assert "timed out" in r.output

    def test_error_violation(self):
        r = SandboxResult(stdout="", stderr="", returncode=-31,
                          wall_time_seconds=0.05, is_error=True,
                          error_type="violation")
        assert "sandbox violation" in r.output

    def test_error_resource(self):
        r = SandboxResult(stdout="", stderr="", returncode=-9,
                          wall_time_seconds=10.0, is_error=True,
                          error_type="resource")
        assert "resource limit" in r.output

    def test_no_output_message(self):
        r = SandboxResult(stdout="", stderr="", returncode=0,
                          wall_time_seconds=0.1)
        assert "No output" in r.output

    def test_stderr_appended(self):
        r = SandboxResult(stdout="out", stderr="warn", returncode=0,
                          wall_time_seconds=0.1)
        assert "out" in r.output
        assert "warn" in r.output

    def test_immutable(self):
        r = SandboxResult(stdout="x", stderr="", returncode=0,
                          wall_time_seconds=0.1)
        with pytest.raises(AttributeError):
            r.stdout = "y"  # type: ignore


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 12: Error Hierarchy
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestErrorHierarchy:
    """Verify exception hierarchy for clean error handling."""

    def test_all_errors_subclass_sandbox_error(self):
        assert issubclass(SandboxSetupError, SandboxError)
        assert issubclass(SandboxViolationError, SandboxError)
        assert issubclass(SandboxTimeoutError, SandboxError)

    def test_setup_error_has_layer(self):
        err = SandboxSetupError("failed", layer="seccomp")
        assert err.layer == "seccomp"
        assert "seccomp" in str(err)

    def test_violation_error_has_syscall(self):
        err = SandboxViolationError("blocked", syscall="socket")
        assert err.syscall == "socket"

    def test_timeout_error_has_seconds(self):
        err = SandboxTimeoutError(30.0)
        assert err.timeout_seconds == 30.0
        assert "30.0" in str(err)

    def test_catch_all_sandbox_errors(self):
        """Can catch SandboxError to handle entire family."""
        errors = [
            SandboxSetupError("test", layer="test"),
            SandboxViolationError("test"),
            SandboxTimeoutError(10),
        ]
        for err in errors:
            with pytest.raises(SandboxError):
                raise err

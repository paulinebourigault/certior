"""
Sandboxed code executor - multi-layer OS containment.

Orchestrates the full defence-in-depth stack:

1. **Python-level** (AST preflight + builtins restriction)
2. **rlimits** (CPU, memory, file-size, processes)
3. **seccomp-BPF** (syscall allowlist)
4. **Linux namespaces** (PID, network, IPC, user)
5. **nsjail** (optional, subsumes layers 2-4)

The executor writes a *launcher script* to a temporary file that:
  a) Applies rlimits + seccomp in the child process (layers 2-3)
  b) Installs the Python-level sandbox (layer 1)
  c) Runs the user code

The parent process applies namespace isolation (layer 4) via the
subprocess ``preexec_fn``.

Architecture
------------
::

    Parent (Certior host)
      │
      │  subprocess.Popen(preexec_fn=namespace_setup)
      │
      └──► Child process (isolated namespaces)
              │
              │  launcher.py  ← we generate this
              │
              ├── 1. Apply rlimits
              ├── 2. Build & install seccomp-bpf filter
              ├── 3. Install Python sandbox (builtins + import hook)
              └── 4. exec user code
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from .errors import (
    SandboxError,
    SandboxResourceError,
    SandboxSetupError,
    SandboxTimeoutError,
    SandboxViolationError,
    FilesystemIsolationError,
    NsjailNotFoundError,
)
from .policy import (
    ContainmentLayer,
    ResourceLimits,
    SandboxPolicy,
)
from .namespace import (
    CLONE_NEWNS,
    build_preexec_fn,
    probe_all as probe_namespaces,
)
from .seccomp import (
    resolve_syscall_numbers,
    seccomp_available,
)
from .filesystem import (
    FilesystemPolicy,
    build_fs_isolation_config,
    build_rootfs_skeleton,
    probe_mount_namespace as probe_fs_mount_ns,
    probe_pivot_root,
    FS_ISOLATION_LAUNCHER_CODE,
)
from .network import (
    NET_ISOLATION_LAUNCHER_CODE,
    NetworkPolicy,
    NetworkMode,
    build_net_isolation_config,
    probe_network_namespace as probe_net_ns,
)


# ── Result type ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class SandboxResult:
    """Result of a sandboxed execution."""

    stdout: str
    stderr: str
    returncode: int
    wall_time_seconds: float
    is_error: bool = False
    error_type: Optional[str] = None  # "timeout", "violation", "resource", "runtime"
    active_layers: Tuple[str, ...] = ()
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def output(self) -> str:
        """Combined output for display (matches ToolResult.output contract)."""
        if self.is_error:
            if self.error_type == "timeout":
                return f"Error: execution timed out after {self.wall_time_seconds:.1f}s"
            if self.error_type == "violation":
                return f"Error: sandbox violation (process killed by seccomp)"
            if self.error_type == "resource":
                return f"Error: resource limit exceeded"
            # Runtime error - show stderr
            combined = ""
            if self.stdout.strip():
                combined += f"STDOUT:\n{self.stdout.strip()}\n\n"
            combined += (
                f"STDERR:\n{self.stderr.strip()}"
                if self.stderr.strip()
                else "Process exited with non-zero code."
            )
            return combined
        out = self.stdout.strip()
        if self.stderr.strip():
            out += f"\n\n[stderr]: {self.stderr.strip()}"
        return out or "(No output produced. Use print() to see results.)"


# ── Launcher script generation ────────────────────────────────────────

_LAUNCHER_TEMPLATE = '''\
#!/usr/bin/env python3
"""Auto-generated sandbox launcher - DO NOT EDIT."""
import json, os, struct, sys

# ━━ Configuration (injected at generation time) ━━━━━━━━━━━━━━━━━━━━
_CONFIG = __CERTIOR_CONFIG_PLACEHOLDER__

# ━━ Layer 0: Filesystem isolation (D2) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
__CERTIOR_FS_ISOLATION_PLACEHOLDER__

# ━━ Layer 0b: Network isolation (D3) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
__CERTIOR_NET_ISOLATION_PLACEHOLDER__

# ━━ Layer 1: rlimits ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _apply_rlimits():
    import resource
    rl = _CONFIG["rlimits"]
    limits = [
        (resource.RLIMIT_CPU,    rl["cpu_time_seconds"], rl["cpu_time_seconds"] + 2),
        (resource.RLIMIT_AS,     rl["memory_bytes"],     rl["memory_bytes"]),
        (resource.RLIMIT_FSIZE,  rl["max_file_size_bytes"], rl["max_file_size_bytes"]),
        (resource.RLIMIT_NOFILE, rl["max_open_files"],   rl["max_open_files"]),
        (resource.RLIMIT_NPROC,  rl["max_processes"],    rl["max_processes"]),
        (resource.RLIMIT_CORE,   0, 0),
    ]
    for rid, soft, hard in limits:
        try:
            resource.setrlimit(rid, (soft, hard))
        except (ValueError, OSError):
            pass

# ━━ Layer 2: seccomp-bpf ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _apply_seccomp():
    if not _CONFIG.get("seccomp_program"):
        return
    import ctypes, ctypes.util

    PR_SET_NO_NEW_PRIVS = 38
    PR_SET_SECCOMP = 22
    SECCOMP_MODE_FILTER = 2

    class _SF(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                     ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
    class _FP(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SF))]

    prog_hex = _CONFIG["seccomp_program"]
    prog_bytes = bytes.fromhex(prog_hex)
    n = len(prog_bytes) // 8

    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

    fa = (_SF * n)()
    for i in range(n):
        off = i * 8
        code, jt, jf, k = struct.unpack("HBBI", prog_bytes[off:off+8])
        fa[i].code, fa[i].jt, fa[i].jf, fa[i].k = code, jt, jf, k

    fp = _FP()
    fp.len = n
    fp.filter = ctypes.cast(fa, ctypes.POINTER(_SF))
    ret = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fp), 0, 0)
    if ret != 0:
        sys.stderr.write(f"[sandbox] seccomp install failed (errno={ctypes.get_errno()})\\n")

# ━━ Layer 3: Python-level sandbox ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _apply_python_sandbox():
    import builtins as _b
    _ALLOWED = _CONFIG["allowed_builtins"]
    _BLOCKED_MODULES = set(_CONFIG["blocked_modules"])
    _restricted = {k: getattr(_b, k) for k in _ALLOWED if hasattr(_b, k)}
    _restricted["__build_class__"] = _b.__build_class__

    _orig_import = _b.__import__
    def _safe_import(name, *a, **kw):
        top = name.split(".")[0]
        if top in _BLOCKED_MODULES:
            raise ImportError(f"Module '{name}' is blocked in the Certior sandbox")
        return _orig_import(name, *a, **kw)
    _restricted["__import__"] = _safe_import
    __builtins__.__dict__.clear()
    __builtins__.__dict__.update(_restricted)

# ━━ Main ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if __name__ == "__main__":
    # Save references that the sandbox will remove
    _builtin_open = open
    _builtin_compile = compile
    _builtin_exec = exec

    # Read user code BEFORE filesystem isolation changes paths
    _code_path = sys.argv[1]
    with _builtin_open(_code_path) as _f:
        _user_source = _f.read()
    _user_code = _builtin_compile(_user_source, "<sandbox>", "exec")
    del _f, _code_path, _builtin_open, _builtin_compile, _user_source

    # Apply containment layers in order:
    # 0. Filesystem isolation (needs mount/pivot_root syscalls)
    _apply_filesystem_isolation()

    # 0b. Network isolation (needs network namespace syscalls)
    _apply_network_isolation()

    # 1. rlimits (CPU, memory, file-size, processes)
    _apply_rlimits()

    # 2. seccomp-BPF (blocks mount/pivot_root after FS isolation)
    _apply_seccomp()

    # 3. Python-level sandbox (builtins + import hook)
    _apply_python_sandbox()

    # Clean up launcher internals from namespace
    del _apply_filesystem_isolation, _apply_network_isolation
    del _apply_rlimits, _apply_seccomp
    del _apply_python_sandbox, _CONFIG

    # Execute pre-compiled user code in the sandboxed environment
    _builtin_exec(_user_code)
    del _builtin_exec, _user_code
'''


# ── Executor ─────────────────────────────────────────────────────────

class SandboxedExecutor:
    """Execute Python code inside a multi-layer OS sandbox.

    Usage::

        executor = SandboxedExecutor(SandboxPolicy.standard())
        result = await executor.execute("print(2 + 2)")
        print(result.output)  # "4"
    """

    def __init__(self, policy: Optional[SandboxPolicy] = None) -> None:
        self.policy = policy or SandboxPolicy.standard()
        self._capabilities = self._probe_capabilities()

    # ── Public API ────────────────────────────────────────────────────

    async def execute(self, code: str) -> SandboxResult:
        """Execute ``code`` inside the sandbox.

        Returns a ``SandboxResult`` with stdout, stderr, timing, and
        active containment layers.

        Raises ``SandboxSetupError`` if mandatory containment layers
        cannot be established.
        """
        # Validate mandatory layers
        self._validate_mandatory_layers()

        if ContainmentLayer.GVISOR in self.policy.mandatory_layers:
            return await self._execute_gvisor(code)
        elif self.policy.require_nsjail:
            return await self._execute_nsjail(code)
        else:
            return await self._execute_subprocess(code)

    def get_active_layers(self) -> List[str]:
        """Return the list of containment layers that will be active."""
        return list(self._capabilities.get("active_layers", []))

    def get_capabilities(self) -> Dict[str, Any]:
        """Return a diagnostic dict of sandbox capabilities."""
        return dict(self._capabilities)

    # ── Probing ───────────────────────────────────────────────────────

    def _probe_capabilities(self) -> Dict[str, Any]:
        """Probe what containment layers are available on this system."""
        caps: Dict[str, Any] = {
            "platform": sys.platform,
            "active_layers": [],
            "warnings": [],
        }

        # rlimits - always available on Linux/macOS
        caps["rlimits"] = sys.platform in ("linux", "darwin")
        if caps["rlimits"]:
            caps["active_layers"].append("rlimits")

        # Python sandbox - always available
        caps["python_sandbox"] = True
        caps["active_layers"].append("python_sandbox")

        # seccomp
        caps["seccomp"] = seccomp_available()
        if caps["seccomp"]:
            caps["active_layers"].append("seccomp_bpf")
        elif ContainmentLayer.SECCOMP_BPF in self.policy.mandatory_layers:
            caps["warnings"].append("seccomp-bpf mandatory but unavailable")

        # Namespaces
        if sys.platform.startswith("linux"):
            ns_probes = probe_namespaces()
            caps["namespaces"] = ns_probes
            for ns_name, available in ns_probes.items():
                if available:
                    caps["active_layers"].append(f"ns_{ns_name}")
        else:
            caps["namespaces"] = {}

        # Filesystem isolation (D2)
        fs_policy = self.policy.effective_filesystem_policy
        if fs_policy is not None and fs_policy.enabled:
            mount_ns_ok = caps.get("namespaces", {}).get("mount", False)
            if mount_ns_ok:
                caps["filesystem_isolation"] = True
                caps["pivot_root"] = probe_pivot_root()
                caps["active_layers"].append("fs_isolation")
            else:
                caps["filesystem_isolation"] = False
                caps["pivot_root"] = False
                if ContainmentLayer.FILESYSTEM_ISOLATION in self.policy.mandatory_layers:
                    caps["warnings"].append(
                        "Filesystem isolation mandatory but mount namespace unavailable"
                    )
        else:
            caps["filesystem_isolation"] = False
            caps["pivot_root"] = False

        # nsjail
        caps["nsjail"] = shutil.which("nsjail") is not None
        if caps["nsjail"]:
            caps["active_layers"].append("nsjail")

        # Network isolation (D3)
        net_policy = self.policy.effective_network_policy
        if net_policy is not None and net_policy.mode != NetworkMode.DISABLED:
            if net_policy.needs_namespace:
                net_ns_ok = caps.get("namespaces", {}).get("net", False)
                if net_ns_ok:
                    caps["network_isolation"] = True
                    caps["active_layers"].append("net_isolation")
                else:
                    caps["network_isolation"] = False
                    if ContainmentLayer.NETWORK_ISOLATION in self.policy.mandatory_layers:
                        caps["warnings"].append(
                            "Network isolation mandatory but network namespace unavailable"
                        )
            else:
                # HOST_NETWORK mode - software-level enforcement only
                caps["network_isolation"] = True
                caps["active_layers"].append("net_isolation")
        else:
            caps["network_isolation"] = False

        # gVisor (runsc)
        try:
            from .gvisor import probe_gvisor
            gvisor_probe = probe_gvisor()
            caps["gvisor"] = gvisor_probe.available
            if gvisor_probe.available:
                caps["gvisor_version"] = gvisor_probe.version
                caps["gvisor_platform"] = gvisor_probe.platform.value if gvisor_probe.platform else None
        except Exception:
            caps["gvisor"] = False

        return caps

    def _validate_mandatory_layers(self) -> None:
        """Check that all mandatory containment layers are available."""
        for layer in self.policy.mandatory_layers:
            if layer == ContainmentLayer.RLIMITS:
                if not self._capabilities.get("rlimits"):
                    raise SandboxSetupError(
                        "rlimits required but unavailable",
                        layer="rlimits",
                    )
            elif layer == ContainmentLayer.SECCOMP_BPF:
                if not self._capabilities.get("seccomp"):
                    raise SandboxSetupError(
                        "seccomp-bpf required but unavailable. "
                        "Ensure you are on Linux with kernel ≥ 3.17.",
                        layer="seccomp",
                    )
            elif layer == ContainmentLayer.NSJAIL:
                if not self._capabilities.get("nsjail"):
                    raise NsjailNotFoundError()
            elif layer == ContainmentLayer.PID_NAMESPACE:
                ns = self._capabilities.get("namespaces", {})
                if not ns.get("pid"):
                    raise SandboxSetupError(
                        "PID namespace required but unavailable",
                        layer="namespace",
                    )
            elif layer == ContainmentLayer.NET_NAMESPACE:
                ns = self._capabilities.get("namespaces", {})
                if not ns.get("net"):
                    raise SandboxSetupError(
                        "Network namespace required but unavailable",
                        layer="namespace",
                    )
            elif layer == ContainmentLayer.FILESYSTEM_ISOLATION:
                if not self._capabilities.get("filesystem_isolation"):
                    raise FilesystemIsolationError(
                        "Filesystem isolation required but mount namespace "
                        "is unavailable. Ensure you are on Linux with "
                        "user namespace support enabled.",
                        operation="probe",
                    )
            elif layer == ContainmentLayer.NETWORK_ISOLATION:
                if not self._capabilities.get("network_isolation"):
                    from .errors import NetworkIsolationError
                    raise NetworkIsolationError(
                        "Network isolation required but network namespace "
                        "is unavailable.",
                        operation="probe",
                    )
            elif layer == ContainmentLayer.GVISOR:
                if not self._capabilities.get("gvisor"):
                    raise SandboxSetupError(
                        "gVisor (runsc) required but not available. "
                        "Install: https://gvisor.dev/docs/user_guide/install/",
                        layer="gvisor",
                    )

    # ── gVisor execution ──────────────────────────────────────────────

    async def _execute_gvisor(self, code: str) -> SandboxResult:
        """Execute code inside a gVisor (runsc) sandbox."""
        from .gvisor import GVisorRuntime, GVisorResourceLimits

        rl = self.policy.resource_limits
        limits = GVisorResourceLimits(
            memory_bytes=rl.memory_bytes,
            wall_time_seconds=rl.wall_time_seconds,
            cpu_quota_us=rl.cpu_time_seconds * 1_000_000,
            max_pids=max(rl.max_processes, 4),  # gVisor needs a few PIDs internally
            max_open_files=rl.max_open_files,
            max_output_bytes=rl.max_output_bytes,
        )

        runtime = GVisorRuntime()
        result = await runtime.execute(code, limits=limits)

        active_layers = list(result.active_layers)
        if ContainmentLayer.PYTHON_SANDBOX in self.policy.optional_layers:
            active_layers.append("python_sandbox")

        return SandboxResult(
            stdout=result.output,
            stderr=result.stderr,
            exit_code=result.exit_code,
            wall_time=result.wall_time_seconds,
            active_layers=active_layers,
        )

    # ── Subprocess execution ──────────────────────────────────────────

    async def _execute_subprocess(self, code: str) -> SandboxResult:
        """Execute code via subprocess with namespace + rlimit + seccomp."""
        tmpdir = tempfile.mkdtemp(prefix="certior_sandbox_")
        active_layers: List[str] = []

        try:
            # Write user code to file
            code_path = os.path.join(tmpdir, "user_code.py")
            with open(code_path, "w") as f:
                f.write(code)

            # Build launcher config
            config = self._build_launcher_config(tmpdir)

            # Build launcher source with FS isolation code injected
            fs_code_block = ""
            if config.get("filesystem") and config["filesystem"].get("enabled"):
                fs_code_block = FS_ISOLATION_LAUNCHER_CODE
            else:
                # No-op placeholder (module-level, no leading indent)
                fs_code_block = (
                    "def _apply_filesystem_isolation():\n"
                    "    pass\n"
                )

            # Build network isolation code block (D3)
            net_code_block = ""
            if config.get("network") and config["network"].get("enabled"):
                net_code_block = NET_ISOLATION_LAUNCHER_CODE
            else:
                net_code_block = (
                    "def _apply_network_isolation():\n"
                    "    pass\n"
                )

            # Serialize config as a Python literal (json true/false/null → Python True/False/None)
            config_json = json.dumps(config, separators=(",", ":"))
            config_python = (
                config_json
                .replace(":true", ":True").replace(":false", ":False").replace(":null", ":None")
                .replace("[true", "[True").replace("[false", "[False").replace("[null", "[None")
                .replace(",true", ",True").replace(",false", ",False").replace(",null", ",None")
            )
            launcher_code = _LAUNCHER_TEMPLATE.replace(
                "__CERTIOR_CONFIG_PLACEHOLDER__",
                config_python,
            ).replace(
                "__CERTIOR_FS_ISOLATION_PLACEHOLDER__",
                fs_code_block,
            ).replace(
                "__CERTIOR_NET_ISOLATION_PLACEHOLDER__",
                net_code_block,
            )

            launcher_path = os.path.join(tmpdir, "_launcher.py")
            with open(launcher_path, "w") as f:
                f.write(launcher_code)

            active_layers.append("python_sandbox")
            active_layers.append("rlimits")

            # Build preexec_fn for namespace isolation
            preexec_fn = None
            ns_available = self._capabilities.get("namespaces", {})

            # Enable mount namespace if filesystem isolation is active
            fs_enabled = (
                config.get("filesystem") and
                config["filesystem"].get("enabled") and
                self._capabilities.get("filesystem_isolation")
            )

            if any(ns_available.values()):
                fn, warnings = build_preexec_fn(
                    enable_user_ns=ns_available.get("user", False),
                    enable_pid_ns=ns_available.get("pid", False),
                    enable_net_ns=ns_available.get("net", False),
                    enable_ipc_ns=ns_available.get("ipc", False),
                    enable_mount_ns=fs_enabled and ns_available.get("mount", False),
                )
                preexec_fn = fn
                for ns_name, avail in ns_available.items():
                    if avail:
                        active_layers.append(f"ns_{ns_name}")

            if fs_enabled:
                active_layers.append("fs_isolation")

            if config.get("network") and config["network"].get("enabled"):
                active_layers.append("net_isolation")

            if config.get("seccomp_program"):
                active_layers.append("seccomp_bpf")

            # Restricted environment
            safe_env = {
                "PATH": "/usr/bin:/bin",
                "HOME": tmpdir,
                "TMPDIR": tmpdir,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
                "LANG": os.environ.get("LANG", "C.UTF-8"),
            }

            start_time = time.monotonic()
            proc = await asyncio.create_subprocess_exec(
                self.policy.effective_python,
                "-u",  # unbuffered
                "-B",  # no .pyc files
                "-S",  # no site-packages
                launcher_path,
                code_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=tmpdir,
                env=safe_env,
                preexec_fn=preexec_fn,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.policy.resource_limits.wall_time_seconds,
                )
            except asyncio.TimeoutError:
                proc.kill()
                try:
                    await proc.wait()
                except Exception:
                    pass
                wall_time = time.monotonic() - start_time
                return SandboxResult(
                    stdout="",
                    stderr="",
                    returncode=-9,
                    wall_time_seconds=wall_time,
                    is_error=True,
                    error_type="timeout",
                    active_layers=tuple(active_layers),
                )

            wall_time = time.monotonic() - start_time
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            # Truncate output
            max_out = self.policy.resource_limits.max_output_bytes
            stdout = stdout[:max_out]
            stderr = stderr[:max_out]

            # Detect seccomp kills (signal 31 = SIGSYS, or 9 = SIGKILL)
            returncode = proc.returncode
            is_error = returncode != 0
            error_type: Optional[str] = None

            if returncode is not None and returncode < 0:
                sig = -returncode
                if sig == signal.SIGSYS:
                    error_type = "violation"
                elif sig == signal.SIGXCPU:
                    error_type = "resource"
                elif sig == signal.SIGKILL:
                    # Could be OOM killer or seccomp
                    error_type = "resource"
                elif sig == signal.SIGXFSZ:
                    error_type = "resource"
                else:
                    error_type = "runtime"
            elif is_error:
                error_type = "runtime"

            return SandboxResult(
                stdout=stdout,
                stderr=stderr,
                returncode=returncode or 0,
                wall_time_seconds=wall_time,
                is_error=is_error,
                error_type=error_type,
                active_layers=tuple(active_layers),
                metadata={
                    "truncated_stdout": len(stdout_bytes) > max_out,
                    "truncated_stderr": len(stderr_bytes) > max_out,
                },
            )

        finally:
            # Clean up tmpdir
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass

    def _build_launcher_config(self, tmpdir: str = "") -> Dict[str, Any]:
        """Build the JSON config injected into the launcher script."""
        from agentsafe.tools.python_eval import _BLOCKED_MODULES, _ALLOWED_BUILTINS

        rl = self.policy.resource_limits
        config: Dict[str, Any] = {
            "rlimits": {
                "cpu_time_seconds": rl.cpu_time_seconds,
                "memory_bytes": rl.memory_bytes,
                "max_file_size_bytes": rl.max_file_size_bytes,
                "max_open_files": rl.max_open_files,
                "max_processes": rl.max_processes,
            },
            "blocked_modules": sorted(_BLOCKED_MODULES),
            "allowed_builtins": sorted(_ALLOWED_BUILTINS),
            "seccomp_program": None,
            "filesystem": None,
            "network": None,
        }

        # Build seccomp program if available (D4: Dafny-verified path)
        if self._capabilities.get("seccomp"):
            try:
                from .seccomp_verified import (
                    SeccompFilterBuilder,
                    SeccompProfile,
                    DefaultAction as SeccompDefaultAction,
                    get_standard_profile,
                )
                from .seccomp import resolve_syscall_numbers

                # Resolve names → numbers for the policy's allowlist
                syscall_nrs = resolve_syscall_numbers(
                    self.policy.effective_syscall_allowlist
                )
                if syscall_nrs:
                    # Build a verified profile for the resolved syscalls
                    profile = SeccompProfile(
                        name="sandbox_executor",
                        allowed_syscalls=tuple(syscall_nrs),
                        default_action=SeccompDefaultAction.KILL,
                    )
                    builder = SeccompFilterBuilder()
                    program = builder.build_filter(profile)
                    config["seccomp_program"] = program.hex
                    config["seccomp_verified"] = {
                        "profile_name": program.profile_name,
                        "syscall_count": program.syscall_count,
                        "instruction_count": program.instruction_count,
                        "excludes_network": profile.excludes_network,
                        "excludes_process_spawn": profile.excludes_process_spawn,
                        "jump_targets_verified": True,
                    }
            except Exception:
                # Fall back to non-verified path
                try:
                    from .seccomp import build_bpf_program, SeccompAction
                    syscall_nrs = resolve_syscall_numbers(
                        self.policy.effective_syscall_allowlist
                    )
                    if syscall_nrs:
                        bpf_bytes = build_bpf_program(
                            syscall_nrs,
                            default_action=SeccompAction.KILL,
                        )
                        config["seccomp_program"] = bpf_bytes.hex()
                except Exception:
                    pass  # seccomp is optional

        # Build filesystem isolation config if available (D2)
        fs_policy = self.policy.effective_filesystem_policy
        if (
            fs_policy is not None
            and fs_policy.enabled
            and self._capabilities.get("filesystem_isolation")
            and tmpdir
        ):
            rootfs_path = os.path.join(tmpdir, "_rootfs")
            os.makedirs(rootfs_path, exist_ok=True)
            config["filesystem"] = build_fs_isolation_config(
                rootfs_path=rootfs_path,
                policy=fs_policy,
            )

        # Build network isolation config if available (D3)
        net_policy = self.policy.effective_network_policy
        if (
            net_policy is not None
            and net_policy.mode != NetworkMode.DISABLED
            and self._capabilities.get("network_isolation")
        ):
            config["network"] = build_net_isolation_config(net_policy)

        return config

    # ── nsjail execution ──────────────────────────────────────────────

    async def _execute_nsjail(self, code: str) -> SandboxResult:
        """Execute code inside an nsjail sandbox."""
        nsjail_bin = shutil.which("nsjail")
        if not nsjail_bin:
            raise NsjailNotFoundError()

        tmpdir = tempfile.mkdtemp(prefix="certior_nsjail_")
        try:
            # Write user code
            code_path = os.path.join(tmpdir, "user_code.py")
            with open(code_path, "w") as f:
                f.write(code)

            # Write Python sandbox preamble
            from agentsafe.tools.python_eval import (
                _BLOCKED_MODULES, _ALLOWED_BUILTINS, _SANDBOX_PREAMBLE,
            )
            preamble = _SANDBOX_PREAMBLE.format(
                blocked=repr(_BLOCKED_MODULES),
                allowed=repr(_ALLOWED_BUILTINS),
            )
            wrapped_code_path = os.path.join(tmpdir, "wrapped.py")
            with open(wrapped_code_path, "w") as f:
                f.write(preamble)
                f.write("\n# --- user code ---\n")
                f.write(code)

            rl = self.policy.resource_limits
            nsjail_args = [
                nsjail_bin,
                "--mode", "o",  # once mode
                "--quiet",
                "--time_limit", str(rl.cpu_time_seconds),
                "--rlimit_as", str(rl.memory_bytes // (1024 * 1024)),  # MiB
                "--rlimit_fsize", str(rl.max_file_size_bytes // (1024 * 1024)),
                "--rlimit_nofile", str(rl.max_open_files),
                "--rlimit_nproc", str(rl.max_processes),
                "--rlimit_core", "0",
                "--disable_proc",
                "--really_quiet",
            ]

            # Read-only bind mounts
            for path in self.policy.readonly_paths:
                if os.path.exists(path):
                    nsjail_args.extend(["-R", f"{path}:{path}"])

            # Python binary and libs
            python_bin = self.policy.effective_python
            python_dir = os.path.dirname(python_bin)
            nsjail_args.extend(["-R", f"{python_dir}:{python_dir}"])

            # Writable tmpdir for the code
            nsjail_args.extend(["-B", f"{tmpdir}:{tmpdir}"])

            # The command to run
            nsjail_args.extend([
                "--", python_bin, "-u", "-B", "-S",
                wrapped_code_path,
            ])

            start_time = time.monotonic()
            proc = await asyncio.create_subprocess_exec(
                *nsjail_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=rl.wall_time_seconds + 5,  # grace period
                )
            except asyncio.TimeoutError:
                proc.kill()
                try:
                    await proc.wait()
                except Exception:
                    pass
                wall_time = time.monotonic() - start_time
                return SandboxResult(
                    stdout="",
                    stderr="",
                    returncode=-9,
                    wall_time_seconds=wall_time,
                    is_error=True,
                    error_type="timeout",
                    active_layers=("nsjail", "python_sandbox", "rlimits",
                                   "seccomp_bpf", "ns_pid", "ns_net",
                                   "ns_ipc", "ns_user"),
                )

            wall_time = time.monotonic() - start_time
            max_out = rl.max_output_bytes
            stdout = stdout_bytes.decode("utf-8", errors="replace")[:max_out]
            stderr = stderr_bytes.decode("utf-8", errors="replace")[:max_out]

            returncode = proc.returncode or 0
            is_error = returncode != 0
            error_type = "runtime" if is_error else None

            return SandboxResult(
                stdout=stdout,
                stderr=stderr,
                returncode=returncode,
                wall_time_seconds=wall_time,
                is_error=is_error,
                error_type=error_type,
                active_layers=("nsjail", "python_sandbox", "rlimits",
                               "seccomp_bpf", "ns_pid", "ns_net",
                               "ns_ipc", "ns_user"),
            )

        finally:
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass

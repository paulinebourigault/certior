"""
gVisor (runsc) sandbox runtime for container-friendly environments.

gVisor provides a user-space kernel that intercepts application syscalls,
giving strong isolation **without** requiring host kernel features like
seccomp-BPF, user namespaces, or cgroups v2. This makes it ideal for:

  * Kubernetes pods (no privileged containers needed)
  * Docker-in-Docker scenarios
  * Cloud VMs where nested namespaces are unavailable
  * CI/CD runners with restricted kernel access

Architecture::

    ┌─────────────────────────────────────────┐
    │  User code (Python)                     │
    ├─────────────────────────────────────────┤
    │  gVisor Sentry  (user-space kernel)     │  ← intercepts all syscalls
    ├─────────────────────────────────────────┤
    │  Gofer          (file access proxy)     │  ← mediates FS access
    ├─────────────────────────────────────────┤
    │  Host kernel    (minimal surface)       │  ← only ~20 host syscalls
    └─────────────────────────────────────────┘

Usage::

    from agentsafe.sandbox.gvisor import GVisorRuntime, probe_gvisor

    if probe_gvisor().available:
        runtime = GVisorRuntime()
        result = await runtime.execute("print(2 + 2)", policy=policy)
        assert result.output == "4"
        assert "gvisor" in result.active_layers

Requirements:
    - ``runsc`` binary on PATH (https://gvisor.dev/docs/user_guide/install/)
    - Linux x86_64 or aarch64
    - No root required (rootless mode)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import shutil
import stat
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Sequence

from .errors import SandboxError, SandboxSetupError, SandboxTimeoutError

log = logging.getLogger(__name__)

# ── OCI spec constants ────────────────────────────────────────────────

_ARCH = platform.machine()
_OCI_LINUX_ARCH = "amd64" if _ARCH in ("x86_64", "AMD64") else "arm64"


class GVisorPlatform(Enum):
    """gVisor execution platform (Sentry backend)."""
    PTRACE = "ptrace"    # Works everywhere, slower
    KVM = "kvm"          # Needs /dev/kvm, fastest
    SYSTRAP = "systrap"  # Default since runsc 2023+, fast


@dataclass(frozen=True)
class GVisorProbeResult:
    """Result of probing for gVisor availability."""
    available: bool
    runsc_path: Optional[str] = None
    version: Optional[str] = None
    platform: Optional[GVisorPlatform] = None
    rootless: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "runsc_path": self.runsc_path,
            "version": self.version,
            "platform": self.platform.value if self.platform else None,
            "rootless": self.rootless,
            "error": self.error,
        }


@dataclass(frozen=True)
class GVisorResourceLimits:
    """Resource limits applied inside the gVisor container."""
    memory_bytes: int = 256 * 1024 * 1024     # 256 MiB
    cpu_quota_us: int = 30_000_000             # 30s of CPU
    cpu_period_us: int = 1_000_000             # 1s period
    max_pids: int = 32
    max_open_files: int = 64
    wall_time_seconds: float = 30.0
    readonly_rootfs: bool = True
    no_new_privileges: bool = True
    network_disabled: bool = True
    max_output_bytes: int = 32_000


@dataclass
class GVisorResult:
    """Result of gVisor-sandboxed execution."""
    output: str = ""
    stderr: str = ""
    exit_code: int = 0
    wall_time_seconds: float = 0.0
    active_layers: List[str] = field(default_factory=lambda: ["gvisor"])
    container_id: str = ""
    oom_killed: bool = False
    timeout: bool = False

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.oom_killed and not self.timeout


# ── Probing ───────────────────────────────────────────────────────────

_probe_cache: Optional[GVisorProbeResult] = None


def reset_gvisor_probe_cache() -> None:
    """Clear cached probe result (for testing)."""
    global _probe_cache
    _probe_cache = None


def probe_gvisor(runsc_path: Optional[str] = None) -> GVisorProbeResult:
    """
    Probe for gVisor (runsc) availability.

    Checks:
      1. ``runsc`` binary exists on PATH (or at ``runsc_path``)
      2. ``runsc --version`` succeeds
      3. Detect best available platform (systrap > kvm > ptrace)
      4. Check rootless capability

    Results are cached for the process lifetime.
    """
    global _probe_cache
    if _probe_cache is not None and runsc_path is None:
        return _probe_cache

    # Find binary
    binary = runsc_path or shutil.which("runsc")
    if not binary:
        result = GVisorProbeResult(
            available=False,
            error="runsc binary not found on PATH. "
                  "Install: https://gvisor.dev/docs/user_guide/install/",
        )
        if runsc_path is None:
            _probe_cache = result
        return result

    # Check version
    import subprocess
    try:
        proc = subprocess.run(
            [binary, "--version"],
            capture_output=True, text=True, timeout=5,
        )
        version = proc.stdout.strip() or proc.stderr.strip()
    except Exception as exc:
        result = GVisorProbeResult(
            available=False,
            runsc_path=binary,
            error=f"runsc --version failed: {exc}",
        )
        if runsc_path is None:
            _probe_cache = result
        return result

    # Detect platform
    plat = _detect_platform(binary)

    # Check rootless
    rootless = os.getuid() != 0

    result = GVisorProbeResult(
        available=True,
        runsc_path=binary,
        version=version,
        platform=plat,
        rootless=rootless,
    )
    if runsc_path is None:
        _probe_cache = result
    return result


def _detect_platform(binary: str) -> GVisorPlatform:
    """Detect best gVisor platform for this host."""
    # KVM requires /dev/kvm
    if os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK):
        return GVisorPlatform.KVM
    # Systrap is default on modern runsc, fallback to ptrace
    return GVisorPlatform.SYSTRAP


# ── OCI Bundle Generation ─────────────────────────────────────────────

def _build_oci_config(
    *,
    rootfs_path: str,
    limits: GVisorResourceLimits,
    platform: GVisorPlatform,
    python_bin: str,
    code_path: str,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Build OCI runtime spec (config.json) for gVisor.

    Follows the OCI Runtime Specification v1.1.0.
    """
    process_env = [
        "PATH=/usr/bin:/usr/local/bin:/bin",
        "LANG=C.UTF-8",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONUNBUFFERED=1",
    ]
    if env:
        process_env.extend(f"{k}={v}" for k, v in env.items())

    config: Dict[str, Any] = {
        "ociVersion": "1.1.0",
        "process": {
            "terminal": False,
            "user": {"uid": 65534, "gid": 65534},  # nobody
            "args": [python_bin, "-u", "-B", "-S", code_path],
            "env": process_env,
            "cwd": "/",
            "capabilities": {
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
                "ambient": [],
            },
            "noNewPrivileges": limits.no_new_privileges,
            "rlimits": [
                {"type": "RLIMIT_NOFILE", "hard": limits.max_open_files, "soft": limits.max_open_files},
                {"type": "RLIMIT_NPROC", "hard": limits.max_pids, "soft": limits.max_pids},
                {"type": "RLIMIT_CORE", "hard": 0, "soft": 0},
                {"type": "RLIMIT_FSIZE", "hard": 10 * 1024 * 1024, "soft": 10 * 1024 * 1024},
            ],
        },
        "root": {
            "path": rootfs_path,
            "readonly": limits.readonly_rootfs,
        },
        "hostname": "certior-sandbox",
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "noexec", "size=65536k"]},
            {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "nodev", "noexec", "size=32m"]},
        ],
        "linux": {
            "resources": {
                "memory": {"limit": limits.memory_bytes},
                "pids": {"limit": limits.max_pids},
                "cpu": {
                    "quota": limits.cpu_quota_us,
                    "period": limits.cpu_period_us,
                },
            },
            "namespaces": [
                {"type": "pid"},
                {"type": "mount"},
                {"type": "ipc"},
                {"type": "uts"},
            ],
            "maskedPaths": [
                "/proc/acpi", "/proc/kcore", "/proc/keys",
                "/proc/latency_stats", "/proc/timer_list",
                "/proc/timer_stats", "/proc/sched_debug",
                "/sys/firmware", "/proc/scsi",
            ],
            "readonlyPaths": [
                "/proc/asound", "/proc/bus", "/proc/fs",
                "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
            ],
        },
    }

    # Network namespace (disable networking)
    if limits.network_disabled:
        config["linux"]["namespaces"].append({"type": "network"})

    return config


def _build_rootfs(
    bundle_dir: str,
    python_bin: str,
    code: str,
    readonly_paths: Sequence[str] = (),
) -> str:
    """
    Build minimal rootfs for the OCI container.

    Creates a skeleton with:
      - Python binary + stdlib (bind-mount or copy)
      - User code written to /work/code.py
      - Read-only system paths
    """
    rootfs = os.path.join(bundle_dir, "rootfs")
    os.makedirs(rootfs, exist_ok=True)

    # Essential directories
    for d in ["usr", "usr/bin", "usr/lib", "usr/local", "lib", "lib64",
              "bin", "etc", "tmp", "work", "dev", "proc"]:
        os.makedirs(os.path.join(rootfs, d), exist_ok=True)

    # Minimal /etc files
    _write(os.path.join(rootfs, "etc/passwd"), "nobody:x:65534:65534::/:/bin/false\n")
    _write(os.path.join(rootfs, "etc/group"), "nogroup:x:65534:\n")
    _write(os.path.join(rootfs, "etc/hostname"), "certior-sandbox\n")

    # Write user code
    code_path = "/work/code.py"
    _write(os.path.join(rootfs, "work/code.py"), code)

    # Symlink or note Python binary location
    # (In production, Python paths are bind-mounted via OCI mounts;
    # for the rootfs we create a marker that the config generator
    # can use to set up the right mounts.)
    _write(os.path.join(rootfs, "work/.python_bin"), python_bin)

    return rootfs


def _write(path: str, content: str) -> None:
    with open(path, "w") as f:
        f.write(content)


def _discover_python_mounts(python_bin: str) -> List[Dict[str, Any]]:
    """
    Discover filesystem paths needed to run Python inside the container.

    Returns OCI mount entries for the Python interpreter and its libraries.
    """
    mounts = []
    seen = set()

    # Python binary itself
    real_bin = os.path.realpath(python_bin)
    bin_dir = os.path.dirname(real_bin)

    paths_to_mount = [bin_dir]

    # Python stdlib/site-packages
    import sys
    for p in sys.path:
        if p and os.path.isdir(p) and p not in seen:
            paths_to_mount.append(p)
            seen.add(p)

    # Shared libraries (ld-linux, libpython, etc.)
    for lib_dir in ["/lib", "/lib64", "/usr/lib", "/usr/lib64",
                    "/usr/local/lib"]:
        if os.path.isdir(lib_dir):
            paths_to_mount.append(lib_dir)

    for path in paths_to_mount:
        if os.path.exists(path) and path not in seen:
            seen.add(path)
            mounts.append({
                "destination": path,
                "type": "bind",
                "source": path,
                "options": ["rbind", "ro"],
            })

    return mounts


# ── Runtime ───────────────────────────────────────────────────────────

class GVisorRuntime:
    """
    Execute code inside a gVisor (runsc) sandbox.

    This is the container-friendly alternative to seccomp/nsjail.
    It works in Docker, Kubernetes, and unprivileged environments.

    Usage::

        runtime = GVisorRuntime()
        result = await runtime.execute(
            code="print('Hello from gVisor')",
            limits=GVisorResourceLimits(memory_bytes=128*1024*1024),
        )
        print(result.output)  # "Hello from gVisor"
    """

    def __init__(
        self,
        runsc_path: Optional[str] = None,
        platform: Optional[GVisorPlatform] = None,
        root_dir: Optional[str] = None,
        python_bin: Optional[str] = None,
    ):
        """
        Args:
            runsc_path: Path to runsc binary (auto-detected if None).
            platform: Execution platform (auto-detected if None).
            root_dir: Directory for runsc state (tmpdir if None).
            python_bin: Python interpreter to use inside container.
        """
        probe = probe_gvisor(runsc_path)
        if not probe.available:
            raise SandboxSetupError(
                f"gVisor not available: {probe.error}",
                layer="gvisor",
            )

        self._runsc = probe.runsc_path
        self._platform = platform or probe.platform or GVisorPlatform.SYSTRAP
        self._root_dir = root_dir
        self._python = python_bin or _find_python()
        self._audit_log: List[Dict[str, Any]] = []

    @property
    def audit_log(self) -> List[Dict[str, Any]]:
        """Ordered log of all executions through this runtime."""
        return list(self._audit_log)

    async def execute(
        self,
        code: str,
        limits: Optional[GVisorResourceLimits] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> GVisorResult:
        """
        Execute Python code inside a gVisor sandbox.

        Creates a temporary OCI bundle, runs ``runsc create`` + ``runsc start``,
        captures output, and cleans up.

        Args:
            code: Python source code to execute.
            limits: Resource limits (defaults to GVisorResourceLimits()).
            env: Additional environment variables.

        Returns:
            GVisorResult with output, timing, and status.
        """
        limits = limits or GVisorResourceLimits()
        container_id = f"certior-{uuid.uuid4().hex[:12]}"
        bundle_dir = tempfile.mkdtemp(prefix="certior_gvisor_")
        start_time = time.monotonic()

        audit_entry: Dict[str, Any] = {
            "container_id": container_id,
            "timestamp": time.time(),
            "code_length": len(code),
            "limits": {
                "memory_bytes": limits.memory_bytes,
                "wall_time_seconds": limits.wall_time_seconds,
                "network_disabled": limits.network_disabled,
            },
        }

        try:
            # 1. Build rootfs
            rootfs = _build_rootfs(
                bundle_dir, self._python, code,
            )

            # 2. Build OCI config
            config = _build_oci_config(
                rootfs_path="rootfs",  # relative to bundle
                limits=limits,
                platform=self._platform,
                python_bin=self._python,
                code_path="/work/code.py",
                env=env,
            )

            # Add Python mounts
            python_mounts = _discover_python_mounts(self._python)
            config["mounts"].extend(python_mounts)

            # Write config.json
            config_path = os.path.join(bundle_dir, "config.json")
            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)

            # 3. Run with runsc
            result = await self._run_container(
                container_id=container_id,
                bundle_dir=bundle_dir,
                limits=limits,
            )

            result.wall_time_seconds = time.monotonic() - start_time
            result.container_id = container_id

            audit_entry["exit_code"] = result.exit_code
            audit_entry["wall_time_seconds"] = result.wall_time_seconds
            audit_entry["oom_killed"] = result.oom_killed
            audit_entry["success"] = result.success

            return result

        except asyncio.TimeoutError:
            audit_entry["timeout"] = True
            # Kill container on timeout
            await self._kill_container(container_id)
            return GVisorResult(
                exit_code=-1,
                timeout=True,
                wall_time_seconds=time.monotonic() - start_time,
                container_id=container_id,
                stderr=f"Execution timed out after {limits.wall_time_seconds}s",
            )

        except Exception as exc:
            audit_entry["error"] = str(exc)
            raise

        finally:
            # Cleanup
            await self._delete_container(container_id)
            shutil.rmtree(bundle_dir, ignore_errors=True)
            self._audit_log.append(audit_entry)

    async def _run_container(
        self,
        container_id: str,
        bundle_dir: str,
        limits: GVisorResourceLimits,
    ) -> GVisorResult:
        """Run a container using ``runsc run`` (combined create+start)."""
        root_dir = self._root_dir or tempfile.mkdtemp(prefix="certior_runsc_root_")
        should_clean_root = self._root_dir is None

        try:
            cmd = [
                self._runsc,
                f"--platform={self._platform.value}",
                f"--root={root_dir}",
                "--network=none" if limits.network_disabled else "--network=host",
                "--debug-log=/dev/null",
                "run",
                f"--bundle={bundle_dir}",
                container_id,
            ]

            log.debug("runsc cmd: %s", " ".join(cmd))

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=limits.wall_time_seconds,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            # Truncate output
            if len(stdout) > limits.max_output_bytes:
                stdout = stdout[:limits.max_output_bytes] + "\n[truncated]"
            if len(stderr) > limits.max_output_bytes:
                stderr = stderr[:limits.max_output_bytes] + "\n[truncated]"

            # Detect OOM
            oom_killed = proc.returncode == 137 or "OOM" in stderr

            return GVisorResult(
                output=stdout,
                stderr=stderr,
                exit_code=proc.returncode or 0,
                active_layers=["gvisor", f"platform:{self._platform.value}"],
                oom_killed=oom_killed,
            )

        finally:
            if should_clean_root:
                shutil.rmtree(root_dir, ignore_errors=True)

    async def _kill_container(self, container_id: str) -> None:
        """Send SIGKILL to a running container."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self._runsc, "kill", container_id, "SIGKILL",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            pass  # best-effort

    async def _delete_container(self, container_id: str) -> None:
        """Delete container state."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self._runsc, "delete", "--force", container_id,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            pass  # best-effort


def _find_python() -> str:
    """Find the Python 3 interpreter."""
    import sys
    return sys.executable


# ── Audit Info ────────────────────────────────────────────────────────

@dataclass
class GVisorAuditInfo:
    """Audit information for compliance packages."""
    available: bool
    runsc_version: Optional[str]
    platform: Optional[str]
    rootless: bool
    network_disabled: bool
    readonly_rootfs: bool
    memory_limit_bytes: int
    max_pids: int
    capabilities_dropped: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "runtime": "gvisor",
            "available": self.available,
            "runsc_version": self.runsc_version,
            "platform": self.platform,
            "rootless": self.rootless,
            "network_disabled": self.network_disabled,
            "readonly_rootfs": self.readonly_rootfs,
            "memory_limit_bytes": self.memory_limit_bytes,
            "max_pids": self.max_pids,
            "capabilities_dropped": self.capabilities_dropped,
        }


def build_gvisor_audit_info(
    limits: Optional[GVisorResourceLimits] = None,
) -> GVisorAuditInfo:
    """Build audit info for compliance packages."""
    probe = probe_gvisor()
    limits = limits or GVisorResourceLimits()
    return GVisorAuditInfo(
        available=probe.available,
        runsc_version=probe.version,
        platform=probe.platform.value if probe.platform else None,
        rootless=probe.rootless,
        network_disabled=limits.network_disabled,
        readonly_rootfs=limits.readonly_rootfs,
        memory_limit_bytes=limits.memory_bytes,
        max_pids=limits.max_pids,
    )

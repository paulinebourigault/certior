"""
Sandbox policy configuration.

A ``SandboxPolicy`` is an *immutable* specification of what containment
layers are required and what resource limits apply.  It does **not**
perform any OS calls itself - the ``SandboxedExecutor`` reads the policy
and applies it.

Design principles
-----------------
* **Defence-in-depth**: multiple layers are always applied when available.
* **Graceful degradation**: non-root environments lose namespace isolation
  but still get rlimits + seccomp + Python-level sandboxing.
* **Fail-closed**: if a *mandatory* layer cannot be established, execution
  is refused (``SandboxSetupError``).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, FrozenSet, List, Optional, Set

# Forward reference for FilesystemPolicy (avoid circular import)
_FilesystemPolicyRef = Any


class ContainmentLayer(Enum):
    """Individual OS containment mechanisms."""

    RLIMITS = auto()          # resource.setrlimit()
    SECCOMP_BPF = auto()      # prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)
    PID_NAMESPACE = auto()    # unshare(CLONE_NEWPID)
    NET_NAMESPACE = auto()    # unshare(CLONE_NEWNET)
    MOUNT_NAMESPACE = auto()  # unshare(CLONE_NEWNS) + tmpfs root
    IPC_NAMESPACE = auto()    # unshare(CLONE_NEWIPC)
    USER_NAMESPACE = auto()   # unshare(CLONE_NEWUSER)
    CHROOT = auto()           # chroot to minimal filesystem
    NSJAIL = auto()           # full nsjail containment (subsumes all above)
    PYTHON_SANDBOX = auto()   # AST preflight + builtins restriction
    FILESYSTEM_ISOLATION = auto()  # D2: tmpfs overlay + RO bind mounts + pivot_root
    NETWORK_ISOLATION = auto()    # D3: network namespace + firewall rules
    GVISOR = auto()               # gVisor (runsc) user-space kernel sandbox


@dataclass(frozen=True)
class ResourceLimits:
    """Per-process resource constraints (applied via ``resource.setrlimit``).

    All ``None`` fields inherit the system default.
    """

    # Wall-clock timeout in seconds (enforced by the parent via asyncio).
    wall_time_seconds: float = 30.0

    # CPU time limit in seconds (RLIMIT_CPU).  The kernel sends SIGXCPU,
    # then SIGKILL after 1 extra second.
    cpu_time_seconds: int = 30

    # Resident-set-size limit in bytes (RLIMIT_AS - virtual address space).
    # 256 MiB is generous for data-processing code, tight enough to prevent
    # ZIP-bomb style memory attacks.
    memory_bytes: int = 256 * 1024 * 1024  # 256 MiB

    # Maximum size of any single file the process can create (RLIMIT_FSIZE).
    max_file_size_bytes: int = 10 * 1024 * 1024  # 10 MiB

    # Maximum number of open file descriptors (RLIMIT_NOFILE).
    max_open_files: int = 64

    # Maximum child processes / threads (RLIMIT_NPROC).
    max_processes: int = 1  # disallow fork/clone

    # Maximum core-dump size (RLIMIT_CORE).  Set to 0 to prevent core dumps.
    max_core_size: int = 0

    # Maximum bytes writable to stdout/stderr before truncation (Python-level).
    max_output_bytes: int = 32_000


# ── Syscall allowlists ────────────────────────────────────────────────
#
# These are the *only* syscalls permitted under the seccomp filter.
# Everything else is KILLED.  The list was derived empirically by tracing
# ``python -c "print('hello')"`` under strace on x86_64 Ubuntu 24.04,
# then trimmed to the minimum needed for:
#   1. Basic Python interpreter startup
#   2. math/json/re/collections standard library usage
#   3. print() to stdout
#   4. Process exit
#
# Notably ABSENT: execve (no subprocess spawning), socket/connect/bind
# (no networking), ptrace (no debugging), fork/clone (no child processes),
# open with O_CREAT/O_WRONLY on anything outside the sandbox dir.

SECCOMP_SYSCALL_ALLOWLIST_X86_64: FrozenSet[str] = frozenset({
    # ── Memory management ──
    "brk",
    "mmap",
    "munmap",
    "mprotect",
    "mremap",
    "madvise",

    # ── File I/O (read-only + stdout/stderr) ──
    "read",
    "write",            # stdout/stderr only (fd 1, 2)
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "lseek",
    "close",
    "openat",           # filtered: O_RDONLY only, restricted paths
    "newfstatat",
    "fstat",
    "stat",
    "lstat",
    "access",
    "faccessat",
    "faccessat2",
    "readlink",
    "readlinkat",
    "getcwd",
    "dup",
    "dup2",
    "dup3",
    "fcntl",
    "ioctl",            # needed for terminal detection

    # ── Directory listing (needed for Python imports) ──
    "getdents64",
    "getdents",

    # ── Process metadata (read-only) ──
    "getpid",
    "gettid",
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "getppid",
    "getgroups",

    # ── Time ──
    "clock_gettime",
    "clock_getres",
    "gettimeofday",
    "nanosleep",
    "clock_nanosleep",

    # ── Signals ──
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",

    # ── Misc ──
    "arch_prctl",       # x86_64 TLS setup
    "set_tid_address",
    "set_robust_list",
    "futex",
    "rseq",
    "getrandom",
    "prlimit64",        # reading own rlimits
    "prctl",            # needed to set PR_SET_NO_NEW_PRIVS
    "sysinfo",          # Python memory allocator

    # ── Process exit ──
    "exit",
    "exit_group",

    # ── Polling (used by Python GC/signal handling) ──
    "poll",
    "ppoll",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "eventfd2",
    "pipe2",
})

# ARM64 variant - same logical set, different syscall names where needed.
SECCOMP_SYSCALL_ALLOWLIST_AARCH64: FrozenSet[str] = frozenset(
    SECCOMP_SYSCALL_ALLOWLIST_X86_64
    - {"stat", "lstat", "access", "getdents", "dup2", "poll", "readlink"}
    | {"statx", "ppoll"}
)


@dataclass(frozen=True)
class SandboxPolicy:
    """Complete sandbox configuration.

    Parameters
    ----------
    resource_limits
        Per-process resource constraints.
    mandatory_layers
        Containment layers that **must** succeed.  If any fail to
        initialise, execution is refused.
    optional_layers
        Containment layers that are applied on a best-effort basis.
    require_nsjail
        If ``True``, the ``NSJAIL`` layer becomes mandatory and all other
        layers are ignored (nsjail subsumes them).
    allowed_syscalls
        Override the seccomp allowlist.  ``None`` → architecture default.
    readonly_paths
        Paths bind-mounted read-only inside the sandbox (for nsjail mode).
    writable_path
        Single writable directory inside the sandbox.
    python_binary
        Explicit path to the Python interpreter.  ``None`` → ``sys.executable``.
    filesystem
        Filesystem isolation configuration (D2).  Controls tmpfs overlay,
        read-only bind mounts, and pivot_root.
    """

    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)

    mandatory_layers: FrozenSet[ContainmentLayer] = frozenset({
        ContainmentLayer.RLIMITS,
        ContainmentLayer.PYTHON_SANDBOX,
    })

    optional_layers: FrozenSet[ContainmentLayer] = frozenset({
        ContainmentLayer.SECCOMP_BPF,
        ContainmentLayer.PID_NAMESPACE,
        ContainmentLayer.NET_NAMESPACE,
        ContainmentLayer.IPC_NAMESPACE,
        ContainmentLayer.USER_NAMESPACE,
        ContainmentLayer.FILESYSTEM_ISOLATION,
    })

    require_nsjail: bool = False

    allowed_syscalls: Optional[FrozenSet[str]] = None

    readonly_paths: FrozenSet[str] = frozenset({
        "/usr",
        "/lib",
        "/lib64",
        "/etc/alternatives",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/localtime",
        "/etc/ssl/certs",
    })

    writable_path: Optional[str] = None  # None → auto-created tmpdir

    python_binary: Optional[str] = None  # None → sys.executable

    filesystem: Optional["_FilesystemPolicyRef"] = None  # None → auto (enabled)

    network: Optional[Any] = None  # None → no network isolation (D3: NetworkPolicy)

    # ── Factory methods ───────────────────────────────────────────────

    @classmethod
    def maximum(cls) -> "SandboxPolicy":
        """Maximum containment - all layers mandatory, tight limits.

        Use this for production environments running untrusted code.
        Requires either root privileges or user-namespace support.
        """
        from .filesystem import FilesystemPolicy
        return cls(
            resource_limits=ResourceLimits(
                wall_time_seconds=15.0,
                cpu_time_seconds=10,
                memory_bytes=128 * 1024 * 1024,  # 128 MiB
                max_file_size_bytes=1 * 1024 * 1024,  # 1 MiB
                max_open_files=32,
                max_processes=1,
            ),
            mandatory_layers=frozenset({
                ContainmentLayer.RLIMITS,
                ContainmentLayer.SECCOMP_BPF,
                ContainmentLayer.PYTHON_SANDBOX,
                ContainmentLayer.FILESYSTEM_ISOLATION,
            }),
            optional_layers=frozenset({
                ContainmentLayer.PID_NAMESPACE,
                ContainmentLayer.NET_NAMESPACE,
                ContainmentLayer.IPC_NAMESPACE,
                ContainmentLayer.USER_NAMESPACE,
            }),
            filesystem=FilesystemPolicy.tight(),
        )

    @classmethod
    def standard(cls) -> "SandboxPolicy":
        """Standard containment - mandatory rlimits + Python, optional OS layers.

        Good default for environments where root/namespace support may be
        unavailable (e.g. inside Docker without ``--privileged``).
        """
        return cls()

    @classmethod
    def with_filesystem(cls) -> "SandboxPolicy":
        """Standard containment with filesystem isolation enabled.

        Like ``standard()`` but explicitly enables D2 filesystem isolation
        with default settings.
        """
        from .filesystem import FilesystemPolicy
        return cls(
            filesystem=FilesystemPolicy.standard(),
            optional_layers=frozenset({
                ContainmentLayer.SECCOMP_BPF,
                ContainmentLayer.PID_NAMESPACE,
                ContainmentLayer.NET_NAMESPACE,
                ContainmentLayer.IPC_NAMESPACE,
                ContainmentLayer.USER_NAMESPACE,
                ContainmentLayer.FILESYSTEM_ISOLATION,
            }),
        )

    @classmethod
    def nsjail(cls, nsjail_bin: str = "nsjail") -> "SandboxPolicy":
        """nsjail-based containment (gold standard).

        Requires ``nsjail`` to be installed on the host.  Subsumes all
        other containment layers.
        """
        return cls(
            require_nsjail=True,
            mandatory_layers=frozenset({ContainmentLayer.NSJAIL}),
            optional_layers=frozenset(),
            resource_limits=ResourceLimits(
                wall_time_seconds=30.0,
                cpu_time_seconds=30,
                memory_bytes=256 * 1024 * 1024,
                max_file_size_bytes=10 * 1024 * 1024,
                max_open_files=64,
                max_processes=1,
            ),
        )

    @classmethod
    def minimal(cls) -> "SandboxPolicy":
        """Minimal containment - rlimits only.  Always works.

        Suitable for development/testing.  **Not safe for production**
        with untrusted code.
        """
        return cls(
            mandatory_layers=frozenset({
                ContainmentLayer.RLIMITS,
                ContainmentLayer.PYTHON_SANDBOX,
            }),
            optional_layers=frozenset(),
        )

    @classmethod
    def gvisor(cls) -> "SandboxPolicy":
        """gVisor (runsc) containment - container-friendly sandboxing.

        Uses gVisor's user-space kernel to intercept syscalls.  Works
        inside Docker, Kubernetes, and unprivileged environments where
        seccomp/namespace isolation may be unavailable.

        Requires ``runsc`` binary on PATH.
        """
        return cls(
            mandatory_layers=frozenset({ContainmentLayer.GVISOR}),
            optional_layers=frozenset({ContainmentLayer.PYTHON_SANDBOX}),
            resource_limits=ResourceLimits(
                wall_time_seconds=30.0,
                cpu_time_seconds=30,
                memory_bytes=256 * 1024 * 1024,
                max_file_size_bytes=10 * 1024 * 1024,
                max_open_files=64,
                max_processes=32,  # gVisor manages PIDs internally
            ),
        )

    # ── Helpers ───────────────────────────────────────────────────────

    @property
    def effective_filesystem_policy(self) -> Optional[Any]:
        """Return the active FilesystemPolicy, or None if disabled.

        If ``self.filesystem`` is None and FILESYSTEM_ISOLATION is in
        optional_layers, returns a default FilesystemPolicy.
        """
        if self.filesystem is not None:
            return self.filesystem

        # Auto-enable if filesystem isolation is in optional or mandatory layers
        all_layers = self.mandatory_layers | self.optional_layers
        if ContainmentLayer.FILESYSTEM_ISOLATION in all_layers:
            from .filesystem import FilesystemPolicy
            return FilesystemPolicy.standard()

        return None

    @property
    def effective_network_policy(self) -> Optional[Any]:
        """Return the active NetworkPolicy, or None if disabled.

        If ``self.network`` is None and NETWORK_ISOLATION is in
        mandatory or optional layers, returns a default NetworkPolicy.
        """
        if self.network is not None:
            return self.network

        all_layers = self.mandatory_layers | self.optional_layers
        if ContainmentLayer.NETWORK_ISOLATION in all_layers:
            from .network import NetworkPolicy
            return NetworkPolicy.web_fetch_default()

        return None

    @property
    def effective_syscall_allowlist(self) -> FrozenSet[str]:
        """Return the syscall allowlist for the current architecture."""
        if self.allowed_syscalls is not None:
            return self.allowed_syscalls
        import platform
        machine = platform.machine()
        if machine in ("x86_64", "AMD64"):
            return SECCOMP_SYSCALL_ALLOWLIST_X86_64
        elif machine in ("aarch64", "arm64"):
            return SECCOMP_SYSCALL_ALLOWLIST_AARCH64
        else:
            # Unknown arch - return x86_64 set (may fail at runtime)
            return SECCOMP_SYSCALL_ALLOWLIST_X86_64

    @property
    def effective_python(self) -> str:
        """Return the Python binary path."""
        if self.python_binary:
            return self.python_binary
        import sys
        return sys.executable

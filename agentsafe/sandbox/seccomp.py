"""
seccomp-BPF filter generation and installation.

Generates a classic BPF (cBPF) program that allowlists a set of syscall
numbers and KILLs any syscall not on the list.  The filter is installed
via ``prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)``.

Design
------
* No external dependencies - uses only ``ctypes`` and ``struct``.
* Architecture-aware: resolves syscall names → numbers for x86_64 and
  aarch64 at filter-build time.
* Audit-log mode: can be configured to LOG instead of KILL, useful for
  developing the allowlist.
* The filter is applied in the **child process** after fork, before the
  user's Python code executes.

References
----------
* ``man 2 seccomp``
* ``linux/seccomp.h``, ``linux/filter.h``, ``linux/audit.h``
* ``linux/unistd.h`` (arch-specific syscall tables)
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import struct
import sys
from enum import IntEnum
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from .errors import SandboxSetupError

# ── Kernel constants ──────────────────────────────────────────────────

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# seccomp return actions (high 16 bits = action, low 16 = data)
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_KILL_THREAD = 0x00000000
SECCOMP_RET_TRAP = 0x00030000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_LOG = 0x7FFC0000
SECCOMP_RET_ALLOW = 0x7FFF0000

# BPF instruction classes
BPF_LD = 0x00
BPF_JMP = 0x05
BPF_RET = 0x06

# BPF size modifiers
BPF_W = 0x00  # word (32-bit)

# BPF source modifiers
BPF_ABS = 0x20  # absolute offset into seccomp_data
BPF_K = 0x00    # constant

# BPF comparison operators
BPF_JEQ = 0x10

# Audit architecture constants
AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

# Offsets into struct seccomp_data
#   struct seccomp_data {
#       int   nr;          /* offset 0: syscall number */
#       __u32 arch;         /* offset 4: architecture */
#       __u64 instruction_pointer;
#       __u64 args[6];
#   };
OFFSET_NR = 0
OFFSET_ARCH = 4


# ── BPF instruction builder ──────────────────────────────────────────

def _bpf_stmt(code: int, k: int) -> bytes:
    """Encode a BPF statement: ``struct sock_filter { code, jt=0, jf=0, k }``."""
    return struct.pack("HBBI", code, 0, 0, k)


def _bpf_jump(code: int, k: int, jt: int, jf: int) -> bytes:
    """Encode a BPF jump: ``struct sock_filter { code, jt, jf, k }``."""
    return struct.pack("HBBI", code, jt, jf, k)


def _get_audit_arch() -> int:
    """Return the AUDIT_ARCH constant for the running architecture."""
    machine = platform.machine()
    if machine in ("x86_64", "AMD64"):
        return AUDIT_ARCH_X86_64
    elif machine in ("aarch64", "arm64"):
        return AUDIT_ARCH_AARCH64
    else:
        raise SandboxSetupError(
            f"Unsupported architecture for seccomp: {machine}",
            layer="seccomp",
        )


# ── Syscall number resolution ────────────────────────────────────────

# Authoritative x86_64 syscall table (Linux 6.x, Ubuntu 24.04)
# Only the syscalls that appear in our allowlist are mapped.
_SYSCALL_NR_X86_64: Dict[str, int] = {
    "read": 0, "write": 1, "close": 3, "stat": 4,
    "fstat": 5, "lstat": 6, "poll": 7, "lseek": 8,
    "mmap": 9, "mprotect": 10, "munmap": 11, "brk": 12,
    "rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15,
    "ioctl": 16, "pread64": 17, "pwrite64": 18,
    "readv": 19, "writev": 20, "access": 21,
    "pipe2": 293, "dup": 32, "dup2": 33, "nanosleep": 35,
    "getpid": 39, "getuid": 102, "getgid": 104, "geteuid": 107,
    "getegid": 108, "getppid": 110, "getgroups": 115,
    "sigaltstack": 131, "arch_prctl": 158,
    "gettimeofday": 96, "sysinfo": 99,
    "prctl": 157, "getcwd": 79,
    "readlink": 89, "readlinkat": 267,
    "openat": 257, "newfstatat": 262,
    "getdents": 78, "getdents64": 217,
    "fcntl": 72, "dup3": 292,
    "set_tid_address": 218, "set_robust_list": 273,
    "futex": 202, "clock_gettime": 228, "clock_getres": 229,
    "clock_nanosleep": 230, "exit_group": 231, "exit": 60,
    "epoll_create1": 291, "epoll_ctl": 233, "epoll_wait": 232,
    "eventfd2": 290, "getrandom": 318,
    "prlimit64": 302, "madvise": 28, "mremap": 25,
    "gettid": 186, "rseq": 334,
    "faccessat": 269, "faccessat2": 439,
    "ppoll": 271, "statx": 332,
}

_SYSCALL_NR_AARCH64: Dict[str, int] = {
    "read": 63, "write": 64, "close": 57, "fstat": 80,
    "lseek": 62, "mmap": 222, "mprotect": 226, "munmap": 215,
    "brk": 214, "rt_sigaction": 134, "rt_sigprocmask": 135,
    "rt_sigreturn": 139, "ioctl": 29, "pread64": 67,
    "pwrite64": 68, "readv": 65, "writev": 66,
    "pipe2": 59, "dup": 23, "dup3": 24, "nanosleep": 101,
    "getpid": 172, "getuid": 174, "getgid": 176, "geteuid": 175,
    "getegid": 177, "getppid": 173, "getgroups": 158,
    "sigaltstack": 132, "gettimeofday": 169, "sysinfo": 179,
    "prctl": 167, "getcwd": 17,
    "readlinkat": 78, "openat": 56, "newfstatat": 79,
    "getdents64": 61, "fcntl": 25,
    "set_tid_address": 96, "set_robust_list": 99,
    "futex": 98, "clock_gettime": 113, "clock_getres": 114,
    "clock_nanosleep": 115, "exit_group": 94, "exit": 93,
    "epoll_create1": 20, "epoll_ctl": 21, "epoll_wait": 22,
    "eventfd2": 19, "getrandom": 278,
    "prlimit64": 261, "madvise": 233, "mremap": 216,
    "gettid": 178, "rseq": 293,
    "faccessat": 48, "faccessat2": 439,
    "ppoll": 73, "statx": 291,
}


def _get_syscall_table() -> Dict[str, int]:
    """Return the syscall name→number mapping for the current arch."""
    machine = platform.machine()
    if machine in ("x86_64", "AMD64"):
        return _SYSCALL_NR_X86_64
    elif machine in ("aarch64", "arm64"):
        return _SYSCALL_NR_AARCH64
    else:
        raise SandboxSetupError(
            f"No syscall table for architecture: {machine}",
            layer="seccomp",
        )


def resolve_syscall_numbers(
    names: FrozenSet[str],
) -> List[int]:
    """Resolve syscall names to numbers, skipping unknowns.

    Unknown names are silently dropped - they may be valid on a
    different arch or kernel version, and removing them just tightens
    the filter.
    """
    table = _get_syscall_table()
    numbers: List[int] = []
    for name in sorted(names):
        if name in table:
            numbers.append(table[name])
    return sorted(set(numbers))


# ── BPF program generation ───────────────────────────────────────────

class SeccompAction(IntEnum):
    """What to do when a syscall is not on the allowlist."""

    KILL = SECCOMP_RET_KILL_PROCESS
    LOG = SECCOMP_RET_LOG       # log but allow (audit/development mode)
    ERRNO = SECCOMP_RET_ERRNO   # return EPERM


def build_bpf_program(
    allowed_syscalls: Sequence[int],
    *,
    default_action: SeccompAction = SeccompAction.KILL,
    audit_arch: Optional[int] = None,
) -> bytes:
    """Build a cBPF program that allowlists the given syscall numbers.

    Algorithm
    ---------
    1. Load ``seccomp_data.arch``, verify it matches ``audit_arch``.
    2. Load ``seccomp_data.nr`` (syscall number).
    3. For each allowed syscall, emit a ``JEQ`` that jumps to ALLOW.
    4. Fall through to default action (KILL / LOG / ERRNO).

    Returns the raw BPF program as ``bytes`` (array of ``sock_filter``).
    """
    if audit_arch is None:
        audit_arch = _get_audit_arch()

    instructions: List[bytes] = []
    allowed = sorted(set(allowed_syscalls))

    # ── Step 1: Validate architecture ──
    # BPF_LD | BPF_W | BPF_ABS  →  load arch
    instructions.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH))
    # JEQ audit_arch → skip 1 (continue), else → KILL
    instructions.append(_bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        audit_arch,
        1,   # jt: arch matches, continue
        0,   # jf: will be patched
    ))
    # Wrong architecture → kill
    kill_wrong_arch = _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
    instructions.append(kill_wrong_arch)
    # Patch jf to jump to the kill instruction (0 instructions ahead after the JEQ).
    # jf=0 means "fall through to next instruction" which is the kill.
    # jt=1 means "jump over 1 instruction" to the LD below.

    # ── Step 2: Load syscall number ──
    instructions.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR))

    # ── Step 3: Check each allowed syscall ──
    n_allowed = len(allowed)
    for i, nr in enumerate(allowed):
        # For each JEQ: if match, jump to ALLOW (which is at the end).
        # ALLOW is at position: current + (n_allowed - i) remaining checks + 1 (default action)
        jump_to_allow = n_allowed - i  # jump over remaining JEQs + default RET
        instructions.append(_bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            nr,
            jump_to_allow,   # jt: ALLOW
            0,                # jf: continue to next check
        ))

    # ── Step 4: Default action (reached if no JEQ matched) ──
    action_value = int(default_action)
    if default_action == SeccompAction.ERRNO:
        # EPERM = 1
        action_value = SECCOMP_RET_ERRNO | 1
    instructions.append(_bpf_stmt(BPF_RET | BPF_K, action_value))

    # ── Step 5: ALLOW (all matched JEQs land here) ──
    instructions.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

    return b"".join(instructions)


def bpf_instruction_count(program: bytes) -> int:
    """Return the number of BPF instructions in a program."""
    SOCK_FILTER_SIZE = 8  # struct sock_filter is 8 bytes
    return len(program) // SOCK_FILTER_SIZE


# ── seccomp installation ─────────────────────────────────────────────

# ctypes structures matching the kernel's struct sock_filter / sock_fprog.

class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


def install_seccomp_filter(bpf_program: bytes) -> None:
    """Install a seccomp-BPF filter in the calling process.

    Must be called AFTER ``prctl(PR_SET_NO_NEW_PRIVS, 1)`` (which is
    required for unprivileged seccomp).

    Raises ``SandboxSetupError`` on failure.
    """
    n_instructions = bpf_instruction_count(bpf_program)
    if n_instructions == 0:
        raise SandboxSetupError(
            "Empty BPF program", layer="seccomp",
        )
    if n_instructions > 4096:
        raise SandboxSetupError(
            f"BPF program too large: {n_instructions} instructions (max 4096)",
            layer="seccomp",
        )

    libc = _get_libc()

    # 1. PR_SET_NO_NEW_PRIVS - required for unprivileged seccomp
    ret = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if ret != 0:
        raise SandboxSetupError(
            f"prctl(PR_SET_NO_NEW_PRIVS) failed (ret={ret})",
            layer="seccomp",
        )

    # 2. Build the sock_fprog structure
    filter_array = (_SockFilter * n_instructions)()
    for i in range(n_instructions):
        offset = i * 8
        code, jt, jf, k = struct.unpack("HBBI", bpf_program[offset:offset + 8])
        filter_array[i].code = code
        filter_array[i].jt = jt
        filter_array[i].jf = jf
        filter_array[i].k = k

    prog = _SockFprog()
    prog.len = n_instructions
    prog.filter = ctypes.cast(filter_array, ctypes.POINTER(_SockFilter))

    # 3. Install the filter
    ret = libc.prctl(
        PR_SET_SECCOMP,
        SECCOMP_MODE_FILTER,
        ctypes.byref(prog),
        0, 0,
    )
    if ret != 0:
        err = ctypes.get_errno()
        raise SandboxSetupError(
            f"prctl(PR_SET_SECCOMP) failed (ret={ret}, errno={err}). "
            f"Ensure the kernel supports seccomp-bpf and "
            f"PR_SET_NO_NEW_PRIVS was set.",
            layer="seccomp",
        )


def _get_libc() -> ctypes.CDLL:
    """Load libc with errno support."""
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        libc_name = "libc.so.6"
    return ctypes.CDLL(libc_name, use_errno=True)


# ── Probe: can we use seccomp at all? ─────────────────────────────────

def seccomp_available() -> bool:
    """Check whether seccomp-bpf is available on this kernel.

    Non-destructive: uses prctl to test NO_NEW_PRIVS (which is
    idempotent and safe to call in the parent process).
    """
    if not sys.platform.startswith("linux"):
        return False
    try:
        libc = _get_libc()
        # PR_GET_NO_NEW_PRIVS = 39
        ret = libc.prctl(39, 0, 0, 0, 0)
        # ret is 0 or 1 (current value), -1 on unsupported kernel
        return ret >= 0
    except (OSError, AttributeError):
        return False

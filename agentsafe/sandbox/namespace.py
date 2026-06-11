"""
Linux namespace isolation.

Provides functions to isolate a child process into new namespaces using
``unshare(2)``.  These are applied via ``subprocess.Popen``'s
``preexec_fn`` callback (which runs in the child after ``fork()`` but
before ``exec()``).

Design
------
* Unprivileged user namespaces (``CLONE_NEWUSER``) are tried first.
  If the kernel supports them, they enable PID/mount/net namespaces
  without root.
* Each namespace type is wrapped in its own function so that partial
  failures can be detected and reported.
* The ``probe_*`` functions test availability without side effects -
  they are safe to call from the parent process at startup.

Requirements
------------
* Linux ≥ 3.8 for user namespaces
* ``/proc/sys/kernel/unprivileged_userns_clone`` must be 1 (Ubuntu 24 default)
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import sys
from typing import Callable, Dict, List, Optional, Tuple

from .errors import SandboxSetupError

# ── Clone flags ───────────────────────────────────────────────────────

CLONE_NEWNS = 0x00020000     # Mount namespace
CLONE_NEWPID = 0x20000000    # PID namespace
CLONE_NEWNET = 0x40000000    # Network namespace
CLONE_NEWIPC = 0x08000000    # IPC namespace
CLONE_NEWUSER = 0x10000000   # User namespace
CLONE_NEWUTS = 0x04000000    # UTS namespace (hostname)
CLONE_NEWCGROUP = 0x02000000 # Cgroup namespace


def _get_libc() -> ctypes.CDLL:
    """Load libc with errno support."""
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        libc_name = "libc.so.6"
    return ctypes.CDLL(libc_name, use_errno=True)


def _unshare(flags: int) -> int:
    """Call ``unshare(2)`` via ctypes.  Returns 0 on success, -1 on error."""
    # Python 3.12+ has os.unshare(), but we support 3.10+ via ctypes.
    if hasattr(os, "unshare"):
        try:
            os.unshare(flags)
            return 0
        except OSError:
            return -1
    else:
        libc = _get_libc()
        return libc.unshare(flags)


# ── Probing (safe to call from parent) ────────────────────────────────

def _probe_namespace(flag: int) -> bool:
    """Test whether a namespace type is available by forking a child.

    We fork, call ``unshare(flag)`` in the child, and check the exit code.
    The parent is unaffected.
    """
    if not sys.platform.startswith("linux"):
        return False
    try:
        pid = os.fork()
    except OSError:
        return False

    if pid == 0:
        # Child
        try:
            result = _unshare(flag)
            os._exit(0 if result == 0 else 1)
        except Exception:
            os._exit(1)
    else:
        # Parent
        _, status = os.waitpid(pid, 0)
        return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


_probe_cache: Dict[int, bool] = {}


def probe_user_namespace() -> bool:
    """Check if unprivileged user namespaces are available."""
    if CLONE_NEWUSER not in _probe_cache:
        _probe_cache[CLONE_NEWUSER] = _probe_namespace(CLONE_NEWUSER)
    return _probe_cache[CLONE_NEWUSER]


def probe_pid_namespace() -> bool:
    """Check if PID namespaces are available (may need user namespace)."""
    if CLONE_NEWPID not in _probe_cache:
        # Try with user namespace first (unprivileged)
        _probe_cache[CLONE_NEWPID] = (
            _probe_namespace(CLONE_NEWUSER | CLONE_NEWPID)
            or _probe_namespace(CLONE_NEWPID)
        )
    return _probe_cache[CLONE_NEWPID]


def probe_net_namespace() -> bool:
    """Check if network namespaces are available."""
    if CLONE_NEWNET not in _probe_cache:
        _probe_cache[CLONE_NEWNET] = (
            _probe_namespace(CLONE_NEWUSER | CLONE_NEWNET)
            or _probe_namespace(CLONE_NEWNET)
        )
    return _probe_cache[CLONE_NEWNET]


def probe_ipc_namespace() -> bool:
    """Check if IPC namespaces are available."""
    if CLONE_NEWIPC not in _probe_cache:
        _probe_cache[CLONE_NEWIPC] = (
            _probe_namespace(CLONE_NEWUSER | CLONE_NEWIPC)
            or _probe_namespace(CLONE_NEWIPC)
        )
    return _probe_cache[CLONE_NEWIPC]


def probe_mount_namespace() -> bool:
    """Check if mount namespaces are available (may need user namespace)."""
    if CLONE_NEWNS not in _probe_cache:
        _probe_cache[CLONE_NEWNS] = (
            _probe_namespace(CLONE_NEWUSER | CLONE_NEWNS)
            or _probe_namespace(CLONE_NEWNS)
        )
    return _probe_cache[CLONE_NEWNS]


def probe_all() -> Dict[str, bool]:
    """Probe all namespace types.  Returns a dict of name → available."""
    return {
        "user": probe_user_namespace(),
        "pid": probe_pid_namespace(),
        "net": probe_net_namespace(),
        "ipc": probe_ipc_namespace(),
        "mount": probe_mount_namespace(),
    }


# ── Namespace setup (runs in child process) ───────────────────────────

def setup_user_namespace() -> bool:
    """Create a new user namespace.  Must be first.

    Maps the current UID/GID to 0/0 inside the namespace.
    Returns True on success.
    """
    result = _unshare(CLONE_NEWUSER)
    if result != 0:
        return False

    # Map current uid to root inside the namespace
    uid = os.getuid()
    gid = os.getgid()
    try:
        # /proc/self/setgroups must be "deny" before writing gid_map
        with open("/proc/self/setgroups", "w") as f:
            f.write("deny")
    except (OSError, PermissionError):
        pass  # May not exist on older kernels

    try:
        with open("/proc/self/uid_map", "w") as f:
            f.write(f"0 {uid} 1\n")
    except (OSError, PermissionError):
        pass

    try:
        with open("/proc/self/gid_map", "w") as f:
            f.write(f"0 {gid} 1\n")
    except (OSError, PermissionError):
        pass

    return True


def setup_pid_namespace() -> bool:
    """Create a new PID namespace.  Process becomes PID 1 for children."""
    return _unshare(CLONE_NEWPID) == 0


def setup_net_namespace() -> bool:
    """Create a new network namespace.  No network access (only loopback)."""
    return _unshare(CLONE_NEWNET) == 0


def setup_ipc_namespace() -> bool:
    """Create a new IPC namespace.  No shared memory / semaphores."""
    return _unshare(CLONE_NEWIPC) == 0


def setup_mount_namespace() -> bool:
    """Create a new mount namespace."""
    return _unshare(CLONE_NEWNS) == 0


# ── Combined setup ───────────────────────────────────────────────────

def build_preexec_fn(
    *,
    enable_user_ns: bool = True,
    enable_pid_ns: bool = True,
    enable_net_ns: bool = True,
    enable_ipc_ns: bool = True,
    enable_mount_ns: bool = False,
) -> Tuple[Callable[[], None], List[str]]:
    """Build a ``preexec_fn`` that creates the requested namespaces.

    Returns ``(preexec_fn, warnings)`` where ``warnings`` lists any
    namespaces that could not be probed as available.

    The returned function is designed to be passed directly to
    ``subprocess.Popen(preexec_fn=...)``.
    """
    warnings: List[str] = []
    flags_to_apply: List[Tuple[str, int]] = []

    if enable_user_ns:
        if probe_user_namespace():
            flags_to_apply.append(("user", CLONE_NEWUSER))
        else:
            warnings.append("User namespaces unavailable")

    if enable_mount_ns:
        if probe_mount_namespace():
            flags_to_apply.append(("mount", CLONE_NEWNS))
        else:
            warnings.append("Mount namespaces unavailable")

    if enable_pid_ns:
        if probe_pid_namespace():
            flags_to_apply.append(("pid", CLONE_NEWPID))
        else:
            warnings.append("PID namespaces unavailable")

    if enable_net_ns:
        if probe_net_namespace():
            flags_to_apply.append(("net", CLONE_NEWNET))
        else:
            warnings.append("Network namespaces unavailable")

    if enable_ipc_ns:
        if probe_ipc_namespace():
            flags_to_apply.append(("ipc", CLONE_NEWIPC))
        else:
            warnings.append("IPC namespaces unavailable")

    def _preexec() -> None:
        """Apply namespace isolation in the child process."""
        # Apply all flags in one unshare call if possible
        combined_flags = 0
        for _, flag in flags_to_apply:
            combined_flags |= flag

        if combined_flags != 0:
            result = _unshare(combined_flags)
            if result != 0:
                # Fall back to individual unshare calls
                for name, flag in flags_to_apply:
                    _unshare(flag)  # best-effort

    return _preexec, warnings


def reset_probe_cache() -> None:
    """Clear the namespace probe cache.  Useful in tests."""
    _probe_cache.clear()

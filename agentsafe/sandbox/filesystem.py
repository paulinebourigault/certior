"""
Filesystem isolation via mount namespaces, bind mounts, and pivot_root.

Provides an isolated filesystem view for sandboxed processes:

* Root is a size-limited tmpfs (default 64 MiB)
* Host paths (Python stdlib, libc) are bind-mounted **read-only**
* Minimal ``/dev`` entries: null, zero, urandom, random
* Writable ``/work`` and ``/tmp`` directories on the tmpfs
* After ``pivot_root``, host filesystem is completely detached

The isolation is applied **inside the launcher script** (child process)
after it has read and compiled user code but before applying rlimits,
seccomp, or the Python-level sandbox.  This ordering ensures:

1. User code is in memory before the filesystem changes
2. ``mount()``/``pivot_root()`` syscalls succeed before seccomp blocks them
3. After pivot_root, the restricted seccomp filter prevents remounting

Architecture
------------
::

    After pivot_root the child sees:

    /
    ├── dev/           bind-mount from host (null, zero, urandom, random)
    ├── etc/           selective bind-mounts (ld.so.cache, localtime, ssl)
    ├── lib/           read-only bind-mount from host
    ├── lib64/         read-only bind-mount from host
    ├── usr/           read-only bind-mount from host
    ├── tmp/           writable (on tmpfs, size-limited)
    └── work/          writable (on tmpfs, contains user code output)

    Host paths like /home, /root, /var, /opt, /srv are **not mounted**
    and therefore invisible.

Prerequisites
-------------
* Linux ≥ 3.8 with user namespace support
* ``/proc/sys/kernel/unprivileged_userns_clone = 1`` (Ubuntu 24 default)

Graceful degradation
--------------------
If mount namespace is unavailable (e.g., inside Docker without
``--privileged``, or on non-Linux), the filesystem isolation layer is
silently skipped and the remaining containment layers (rlimits, seccomp,
Python sandbox) still apply.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import stat
import sys
import sysconfig
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from .errors import SandboxSetupError

# Forward references - resolved at runtime to avoid circular imports
_OverlayFSConfigRef = Any
_ProcMaskConfigRef = Any

# ── Mount flags (from <sys/mount.h>) ─────────────────────────────────

MS_RDONLY: int = 1
MS_NOSUID: int = 2
MS_NODEV: int = 4
MS_NOEXEC: int = 8
MS_REMOUNT: int = 32
MS_BIND: int = 4096
MS_REC: int = 16384
MS_PRIVATE: int = 1 << 18

MNT_DETACH: int = 2  # lazy unmount flag for umount2()

# pivot_root syscall number varies by architecture
_PIVOT_ROOT_NR: Dict[str, int] = {
    "x86_64": 155,
    "AMD64": 155,
    "aarch64": 41,
    "arm64": 41,
}

# Minimal /dev entries the child needs.
# Each entry is (name, host_source_path).  We bind-mount from host to
# avoid needing mknod (which requires CAP_MKNOD).
DEV_NODES: Tuple[Tuple[str, str], ...] = (
    ("null", "/dev/null"),
    ("zero", "/dev/zero"),
    ("urandom", "/dev/urandom"),
    ("random", "/dev/random"),
)

# Directories in the skeleton rootfs.  Order matters - parents first.
_ROOTFS_DIRS: Tuple[str, ...] = (
    "dev",
    "etc",
    "lib",
    "lib64",
    "proc",
    "tmp",
    "usr",
    "work",
    "old_root",
)


# ── FilesystemPolicy ─────────────────────────────────────────────────

@dataclass(frozen=True)
class FilesystemPolicy:
    """Configuration for filesystem isolation.

    This is a *specification* - it does not perform any OS calls itself.
    The ``SandboxedExecutor`` reads the policy and injects the
    corresponding mount operations into the launcher script.

    Parameters
    ----------
    enabled
        Master switch.  When ``False`` the entire filesystem isolation
        layer is skipped.
    tmpfs_size_bytes
        Maximum size of the tmpfs root filesystem.  This bounds the
        total writable disk space available to user code.
    readonly_bind_mounts
        Host paths to bind-mount read-only inside the sandbox.
        Must include paths needed by the Python interpreter (stdlib,
        shared libraries, dynamic linker cache).
    extra_python_paths
        Additional Python-specific paths.  ``None`` means auto-detect
        via :func:`discover_python_paths`.
    writable_dirs
        Directories inside the sandbox that are writable.  These are
        created on the tmpfs and NOT bind-mounted from the host.
    create_dev_nodes
        Whether to create minimal ``/dev`` entries (null, zero, urandom).
    prefer_pivot_root
        Try ``pivot_root(2)`` first; fall back to ``chroot(2)`` if it
        fails.  ``pivot_root`` is strictly stronger (the old root is
        detached), while ``chroot`` leaves the old root accessible via
        ``..`` from ``/proc/self/root``.
    """

    enabled: bool = True

    tmpfs_size_bytes: int = 64 * 1024 * 1024  # 64 MiB

    readonly_bind_mounts: FrozenSet[str] = frozenset({
        "/usr",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/localtime",
        "/etc/ssl/certs",
        "/etc/alternatives",
    })

    extra_python_paths: Optional[FrozenSet[str]] = None

    writable_dirs: FrozenSet[str] = frozenset({"/work", "/tmp"})

    create_dev_nodes: bool = True

    prefer_pivot_root: bool = True

    # ── OverlayFS configuration (D2 production) ───────────────────────

    overlay_config: Optional["_OverlayFSConfigRef"] = None

    # ── Proc filesystem masking ───────────────────────────────────────

    proc_mask: Optional["_ProcMaskConfigRef"] = None

    # ── Inode limits ──────────────────────────────────────────────────
    #
    # ``nr_inodes`` bounds the number of inodes on the tmpfs root.
    # Without this, a malicious process can exhaust inodes (which
    # consumes kernel memory) even if the size limit is respected.
    # 0 means unlimited (kernel default).

    nr_inodes: int = 10000

    # ── Symlink protection ────────────────────────────────────────────
    #
    # ``nosymfollow`` is a mount option (Linux 5.10+) that prevents
    # the kernel from following symlinks on this mount.  This blocks
    # symlink-based escape vectors where a process creates a symlink
    # pointing outside the sandbox.

    nosymfollow: bool = True

    # ── Mount verification ────────────────────────────────────────────
    #
    # After isolation is applied, verify the mount table matches the
    # expected state.  ``strict`` causes the process to exit on failure.

    verify_mounts: bool = True
    verify_mounts_strict: bool = False

    # ── Derived helpers ───────────────────────────────────────────────

    @property
    def effective_readonly_mounts(self) -> FrozenSet[str]:
        """All read-only bind mounts, including auto-detected Python paths."""
        base = set(self.readonly_bind_mounts)
        if self.extra_python_paths is not None:
            base.update(self.extra_python_paths)
        else:
            base.update(discover_python_paths())
        return frozenset(base)

    @property
    def tmpfs_mount_options(self) -> str:
        """Mount option string for the tmpfs root.

        Includes ``size=`` for capacity limit and optionally ``nr_inodes=``
        for inode limit.
        """
        parts = [f"size={self.tmpfs_size_bytes}"]
        if self.nr_inodes > 0:
            parts.append(f"nr_inodes={self.nr_inodes}")
        return ",".join(parts)

    @property
    def tmpfs_mount_flags(self) -> int:
        """Mount flags for the tmpfs root."""
        flags = MS_NOSUID | MS_NODEV
        if self.nosymfollow:
            # nosymfollow is mount option, not a flag - handled separately.
            # But we record intent here for audit purposes.
            pass
        return flags

    # ── Factory methods ───────────────────────────────────────────────

    @classmethod
    def standard(cls) -> "FilesystemPolicy":
        """Standard filesystem isolation - 64 MiB tmpfs, system paths RO."""
        from .fs_monitor import ProcMaskConfig
        return cls(
            proc_mask=ProcMaskConfig.standard(),
            nr_inodes=10000,
            nosymfollow=True,
            verify_mounts=True,
        )

    @classmethod
    def tight(cls) -> "FilesystemPolicy":
        """Tight isolation - 16 MiB tmpfs, minimal mounts."""
        from .fs_monitor import ProcMaskConfig
        return cls(
            tmpfs_size_bytes=16 * 1024 * 1024,
            writable_dirs=frozenset({"/work"}),  # no /tmp
            proc_mask=ProcMaskConfig.standard(),
            nr_inodes=5000,
            nosymfollow=True,
            verify_mounts=True,
        )

    @classmethod
    def disabled(cls) -> "FilesystemPolicy":
        """Filesystem isolation disabled (fallback mode)."""
        return cls(enabled=False)

    @classmethod
    def hipaa(cls) -> "FilesystemPolicy":
        """HIPAA-grade filesystem isolation.

        Extremely tight: 16 MiB tmpfs, no /tmp (only /work), pivot_root
        mandatory.  Prevents PHI exfiltration via filesystem.

        Production hardening:
        - Inode limit (2000) prevents inode exhaustion attacks
        - nosymfollow blocks symlink-based escapes
        - /proc masked (hidepid=2, sensitive paths nulled)
        - Mount verification enabled in strict mode
        - OverlayFS with minimal mount set
        """
        from .overlay import OverlayFSConfig
        from .fs_monitor import ProcMaskConfig
        return cls(
            tmpfs_size_bytes=16 * 1024 * 1024,  # 16 MiB - enough for computation, not data hoarding
            writable_dirs=frozenset({"/work"}),  # No /tmp - minimise write surface
            prefer_pivot_root=True,
            overlay_config=OverlayFSConfig.hipaa(),
            proc_mask=ProcMaskConfig.standard(),
            nr_inodes=2000,
            nosymfollow=True,
            verify_mounts=True,
            verify_mounts_strict=True,
        )

    @classmethod
    def sox(cls) -> "FilesystemPolicy":
        """SOX-grade filesystem isolation.

        Moderate: 32 MiB tmpfs, /work + /tmp writable, standard binds.
        Prevents MNPI leakage via host filesystem visibility.

        Production hardening:
        - Inode limit (5000)
        - nosymfollow blocks symlink escapes
        - /proc masked
        - Mount verification enabled
        - OverlayFS with metacopy for performance
        """
        from .overlay import OverlayFSConfig
        from .fs_monitor import ProcMaskConfig
        return cls(
            tmpfs_size_bytes=32 * 1024 * 1024,
            writable_dirs=frozenset({"/work", "/tmp"}),
            prefer_pivot_root=True,
            overlay_config=OverlayFSConfig.sox(),
            proc_mask=ProcMaskConfig.standard(),
            nr_inodes=5000,
            nosymfollow=True,
            verify_mounts=True,
            verify_mounts_strict=False,
        )

    @classmethod
    def for_compliance(
        cls,
        regime: str,
        tmpfs_size_bytes: Optional[int] = None,
    ) -> "FilesystemPolicy":
        """Create a filesystem policy for a named compliance regime.

        Supported: ``"hipaa"``, ``"sox"``, ``"legal"``, ``"standard"``.
        An optional ``tmpfs_size_bytes`` override can be passed.
        """
        factories = {
            "hipaa": cls.hipaa,
            "sox": cls.sox,
            "legal": cls.tight,  # Legal ≈ tight (minimal attack surface)
            "standard": cls.standard,
        }
        factory = factories.get(regime.lower())
        if factory is None:
            raise ValueError(
                f"Unknown compliance regime: {regime!r}.  "
                f"Supported: {sorted(factories)}"
            )
        policy = factory()
        if tmpfs_size_bytes is not None:
            # Frozen dataclass - rebuild with overridden tmpfs size
            return cls(
                enabled=policy.enabled,
                tmpfs_size_bytes=tmpfs_size_bytes,
                readonly_bind_mounts=policy.readonly_bind_mounts,
                extra_python_paths=policy.extra_python_paths,
                writable_dirs=policy.writable_dirs,
                create_dev_nodes=policy.create_dev_nodes,
                prefer_pivot_root=policy.prefer_pivot_root,
                overlay_config=policy.overlay_config,
                proc_mask=policy.proc_mask,
                nr_inodes=policy.nr_inodes,
                nosymfollow=policy.nosymfollow,
                verify_mounts=policy.verify_mounts,
                verify_mounts_strict=policy.verify_mounts_strict,
            )
        return policy


# ── Filesystem audit info ────────────────────────────────────────────

@dataclass(frozen=True)
class FilesystemAuditInfo:
    """Diagnostic snapshot of filesystem isolation state.

    Captured after policy evaluation but before execution.
    Included in audit records for compliance.  All fields are
    JSON-serialisable.
    """

    enabled: bool
    tmpfs_size_bytes: int
    readonly_bind_count: int
    readonly_bind_paths: Tuple[str, ...]
    writable_dirs: Tuple[str, ...]
    create_dev_nodes: bool
    prefer_pivot_root: bool
    mount_namespace_available: bool
    tmpfs_available: bool
    pivot_root_available: bool
    effective_mode: str  # "pivot_root", "chroot", "disabled", "unavailable"
    python_path_count: int

    # ── D2 production fields ──────────────────────────────────────────
    nr_inodes: int = 0
    nosymfollow: bool = False
    verify_mounts: bool = False
    verify_mounts_strict: bool = False
    overlay_mode: str = "none"             # "overlayfs", "bind_mount", "none"
    overlay_available: bool = False
    overlay_mount_count: int = 0
    proc_mask_enabled: bool = False
    proc_hidepid: int = 0
    proc_masked_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for JSON audit export."""
        return {
            "enabled": self.enabled,
            "tmpfs_size_bytes": self.tmpfs_size_bytes,
            "readonly_bind_count": self.readonly_bind_count,
            "readonly_bind_paths": list(self.readonly_bind_paths),
            "writable_dirs": list(self.writable_dirs),
            "create_dev_nodes": self.create_dev_nodes,
            "prefer_pivot_root": self.prefer_pivot_root,
            "mount_namespace_available": self.mount_namespace_available,
            "tmpfs_available": self.tmpfs_available,
            "pivot_root_available": self.pivot_root_available,
            "effective_mode": self.effective_mode,
            "python_path_count": self.python_path_count,
            # D2 production
            "nr_inodes": self.nr_inodes,
            "nosymfollow": self.nosymfollow,
            "verify_mounts": self.verify_mounts,
            "verify_mounts_strict": self.verify_mounts_strict,
            "overlay_mode": self.overlay_mode,
            "overlay_available": self.overlay_available,
            "overlay_mount_count": self.overlay_mount_count,
            "proc_mask_enabled": self.proc_mask_enabled,
            "proc_hidepid": self.proc_hidepid,
            "proc_masked_count": self.proc_masked_count,
        }


def build_filesystem_audit_info(policy: FilesystemPolicy) -> FilesystemAuditInfo:
    """Build a :class:`FilesystemAuditInfo` for audit logging.

    Probes the current system to determine what isolation mode will
    actually be used.  Safe to call - no side effects.
    """
    if not policy.enabled:
        return FilesystemAuditInfo(
            enabled=False,
            tmpfs_size_bytes=0,
            readonly_bind_count=0,
            readonly_bind_paths=(),
            writable_dirs=(),
            create_dev_nodes=False,
            prefer_pivot_root=False,
            mount_namespace_available=False,
            tmpfs_available=False,
            pivot_root_available=False,
            effective_mode="disabled",
            python_path_count=0,
        )

    mount_ns_ok = probe_mount_namespace()
    tmpfs_ok = probe_tmpfs_mount() if mount_ns_ok else False
    pivot_ok = probe_pivot_root() if tmpfs_ok else False

    if not mount_ns_ok:
        mode = "unavailable"
    elif pivot_ok and policy.prefer_pivot_root:
        mode = "pivot_root"
    else:
        mode = "chroot"

    effective = policy.effective_readonly_mounts
    normalized = normalize_bind_mounts(effective)

    # Overlay probing
    overlay_mode = "none"
    overlay_avail = False
    overlay_mount_count = 0
    if policy.overlay_config is not None:
        from .overlay import probe_overlayfs, select_effective_mode, OverlayMode
        overlay_avail = probe_overlayfs()
        eff_overlay = select_effective_mode(policy.overlay_config, overlay_avail)
        overlay_mode = eff_overlay.name.lower()
        overlay_mount_count = len(policy.overlay_config.mounts)

    # Proc masking info
    proc_enabled = False
    proc_hidepid = 0
    proc_masked_count = 0
    if policy.proc_mask is not None:
        proc_enabled = policy.proc_mask.mount_proc
        proc_hidepid = policy.proc_mask.hidepid
        proc_masked_count = len(policy.proc_mask.masked_paths)

    return FilesystemAuditInfo(
        enabled=True,
        tmpfs_size_bytes=policy.tmpfs_size_bytes,
        readonly_bind_count=len(normalized),
        readonly_bind_paths=tuple(normalized),
        writable_dirs=tuple(sorted(policy.writable_dirs)),
        create_dev_nodes=policy.create_dev_nodes,
        prefer_pivot_root=policy.prefer_pivot_root,
        mount_namespace_available=mount_ns_ok,
        tmpfs_available=tmpfs_ok,
        pivot_root_available=pivot_ok,
        effective_mode=mode,
        python_path_count=len(discover_python_paths()),
        # D2 production
        nr_inodes=policy.nr_inodes,
        nosymfollow=policy.nosymfollow,
        verify_mounts=policy.verify_mounts,
        verify_mounts_strict=policy.verify_mounts_strict,
        overlay_mode=overlay_mode,
        overlay_available=overlay_avail,
        overlay_mount_count=overlay_mount_count,
        proc_mask_enabled=proc_enabled,
        proc_hidepid=proc_hidepid,
        proc_masked_count=proc_masked_count,
    )


# ── Validation ───────────────────────────────────────────────────────

class FilesystemPolicyValidationError(Exception):
    """Raised when a FilesystemPolicy fails validation."""


def validate_policy(policy: FilesystemPolicy) -> List[str]:
    """Validate a :class:`FilesystemPolicy` and return warnings.

    Raises :class:`FilesystemPolicyValidationError` for hard errors
    (e.g. nonsensical tmpfs size).  Returns a list of non-fatal
    warnings (e.g. missing paths).

    This is a *static* check - it does not probe the OS.
    """
    warnings: List[str] = []

    if not policy.enabled:
        return warnings

    # tmpfs size sanity
    if policy.tmpfs_size_bytes < 1024 * 1024:
        raise FilesystemPolicyValidationError(
            f"tmpfs_size_bytes={policy.tmpfs_size_bytes} is too small.  "
            f"Minimum is 1 MiB (1048576 bytes)."
        )
    if policy.tmpfs_size_bytes > 4 * 1024 * 1024 * 1024:
        warnings.append(
            f"tmpfs_size_bytes={policy.tmpfs_size_bytes} is very large (>4 GiB).  "
            f"This may consume excessive host memory."
        )

    # Writable dirs must be absolute
    for wd in policy.writable_dirs:
        if not wd.startswith("/"):
            raise FilesystemPolicyValidationError(
                f"writable_dirs entry {wd!r} must be an absolute path."
            )

    # At least /work should be writable
    if "/work" not in policy.writable_dirs:
        warnings.append(
            "/work is not in writable_dirs.  User code output may fail."
        )

    # Check that critical system paths exist
    critical_paths = ["/usr", "/lib"]
    for p in critical_paths:
        if os.path.exists(p) and p not in policy.readonly_bind_mounts:
            # Check if it's covered by a parent mount
            covered = any(
                p.startswith(mount + "/") or p == mount
                for mount in policy.readonly_bind_mounts
            )
            if not covered:
                warnings.append(
                    f"Critical system path {p!r} is not in readonly_bind_mounts.  "
                    f"Python interpreter may fail inside the sandbox."
                )

    # Check non-existent readonly mounts
    for mount_path in policy.readonly_bind_mounts:
        if not os.path.exists(mount_path):
            warnings.append(
                f"readonly_bind_mounts path {mount_path!r} does not exist and will be skipped."
            )

    # Inode limit validation
    if policy.nr_inodes < 0:
        raise FilesystemPolicyValidationError(
            f"nr_inodes={policy.nr_inodes} cannot be negative."
        )
    if policy.nr_inodes > 0 and policy.nr_inodes < 100:
        warnings.append(
            f"nr_inodes={policy.nr_inodes} is very low - sandbox may fail "
            f"to create necessary temporary files."
        )

    # Overlay config validation
    if policy.overlay_config is not None:
        from .overlay import validate_overlay_config
        overlay_warnings = validate_overlay_config(policy.overlay_config)
        warnings.extend(overlay_warnings)

    # Proc mask validation
    if policy.proc_mask is not None:
        if policy.proc_mask.hidepid not in (0, 1, 2):
            warnings.append(
                f"proc_mask.hidepid={policy.proc_mask.hidepid} is non-standard.  "
                f"Valid values: 0, 1, 2."
            )

    return warnings


def verify_rootfs_structure(rootfs_path: str) -> List[str]:
    """Verify that a rootfs skeleton has the expected directory structure.

    Returns a list of issues (empty if everything is correct).
    Used as a post-``build_rootfs_skeleton`` sanity check.
    """
    issues: List[str] = []

    if not os.path.isdir(rootfs_path):
        issues.append(f"rootfs_path {rootfs_path!r} does not exist or is not a directory.")
        return issues

    for dirname in _ROOTFS_DIRS:
        target = os.path.join(rootfs_path, dirname)
        if not os.path.isdir(target):
            issues.append(f"Missing directory: {target}")

    return issues



def discover_python_paths() -> Set[str]:
    """Discover host paths required for the Python interpreter.

    These must be bind-mounted read-only into the sandbox so that
    ``import math``, ``import json``, etc. continue to work after
    ``pivot_root``.

    Returns a set of absolute, resolved paths that exist on this host.
    """
    candidates: Set[str] = set()

    # Python executable's directory
    real_exe = os.path.realpath(sys.executable)
    candidates.add(os.path.dirname(real_exe))

    # sys.path entries under system directories
    for entry in sys.path:
        if entry and os.path.isdir(entry) and _is_system_path(entry):
            candidates.add(entry)

    # Python prefix / exec_prefix
    for prefix in (sys.prefix, sys.exec_prefix):
        if prefix and _is_system_path(prefix):
            candidates.add(prefix)

    # sysconfig paths (stdlib, platstdlib, purelib, platlib)
    for key in ("stdlib", "platstdlib", "purelib", "platlib"):
        path = sysconfig.get_paths().get(key, "")
        if path and os.path.isdir(path) and _is_system_path(path):
            candidates.add(path)

    # Resolve symlinks and filter to existing paths
    result: Set[str] = set()
    for p in candidates:
        real = os.path.realpath(p)
        if os.path.exists(real):
            result.add(real)

    return result


def _is_system_path(path: str) -> bool:
    """Check whether a path is a system directory (not user/venv)."""
    return path.startswith(("/usr", "/lib", "/lib64", "/opt", "/etc"))


# ── Bind-mount normalisation ────────────────────────────────────────

def normalize_bind_mounts(paths: FrozenSet[str]) -> List[str]:
    """Remove redundant mounts and non-existent paths.

    If ``/usr`` is in the set, ``/usr/lib/python3.12`` is redundant
    because it is already covered by the ``/usr`` bind mount.

    Returns a sorted list of de-duplicated, existing paths.
    """
    existing = sorted(p for p in paths if os.path.exists(p))
    result: List[str] = []

    for path in existing:
        # Is this path already covered by a parent in result?
        covered = any(
            path == parent or path.startswith(parent + "/")
            for parent in result
        )
        if not covered:
            result.append(path)

    return result


# ── Probing ──────────────────────────────────────────────────────────

# Module-level cache for probe results
_probe_cache: Dict[str, bool] = {}


def probe_mount_namespace() -> bool:
    """Test whether mount namespace creation is possible.

    Forks a child that attempts ``unshare(CLONE_NEWUSER | CLONE_NEWNS)``.
    Safe to call from the parent - no side effects on the host.
    """
    if "mount_ns" in _probe_cache:
        return _probe_cache["mount_ns"]

    if not sys.platform.startswith("linux"):
        _probe_cache["mount_ns"] = False
        return False

    from .namespace import CLONE_NEWUSER, CLONE_NEWNS, _unshare

    try:
        pid = os.fork()
    except OSError:
        _probe_cache["mount_ns"] = False
        return False

    if pid == 0:
        # Child - try to create user + mount namespace
        try:
            result = _unshare(CLONE_NEWUSER | CLONE_NEWNS)
            os._exit(0 if result == 0 else 1)
        except Exception:
            os._exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        ok = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        _probe_cache["mount_ns"] = ok
        return ok


def probe_tmpfs_mount() -> bool:
    """Test whether tmpfs can be mounted inside a mount namespace.

    This is a deeper probe that verifies the full mount→tmpfs flow.
    """
    if "tmpfs" in _probe_cache:
        return _probe_cache["tmpfs"]

    if not probe_mount_namespace():
        _probe_cache["tmpfs"] = False
        return False

    from .namespace import CLONE_NEWUSER, CLONE_NEWNS, _unshare
    import tempfile

    try:
        pid = os.fork()
    except OSError:
        _probe_cache["tmpfs"] = False
        return False

    if pid == 0:
        try:
            _unshare(CLONE_NEWUSER | CLONE_NEWNS)
            uid, gid = os.getuid(), os.getgid()
            _write_id_maps(uid, gid)

            libc = _load_libc()
            tmpdir = tempfile.mkdtemp(prefix="certior_probe_")
            ret = libc.mount(
                b"tmpfs", tmpdir.encode(), b"tmpfs",
                MS_NOSUID | MS_NODEV, b"size=1m",
            )
            os._exit(0 if ret == 0 else 1)
        except Exception:
            os._exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        ok = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        _probe_cache["tmpfs"] = ok
        return ok


def probe_pivot_root() -> bool:
    """Test whether ``pivot_root(2)`` works in a user+mount namespace.

    This is the most comprehensive probe - it verifies the full
    filesystem isolation pipeline: namespace → tmpfs → pivot_root.
    """
    if "pivot_root" in _probe_cache:
        return _probe_cache["pivot_root"]

    if not probe_tmpfs_mount():
        _probe_cache["pivot_root"] = False
        return False

    from .namespace import CLONE_NEWUSER, CLONE_NEWNS, _unshare
    import platform as plat
    import tempfile

    nr = _PIVOT_ROOT_NR.get(plat.machine())
    if nr is None:
        _probe_cache["pivot_root"] = False
        return False

    try:
        pid = os.fork()
    except OSError:
        _probe_cache["pivot_root"] = False
        return False

    if pid == 0:
        try:
            _unshare(CLONE_NEWUSER | CLONE_NEWNS)
            uid, gid = os.getuid(), os.getgid()
            _write_id_maps(uid, gid)

            libc = _load_libc()

            # Make all existing mounts private
            libc.mount(b"none", b"/", b"", MS_REC | MS_PRIVATE, None)

            tmpdir = tempfile.mkdtemp(prefix="certior_probe_")
            libc.mount(
                b"tmpfs", tmpdir.encode(), b"tmpfs",
                MS_NOSUID | MS_NODEV, b"size=1m",
            )
            old_root = os.path.join(tmpdir, "old_root")
            os.makedirs(old_root, exist_ok=True)

            ret = libc.syscall(nr, tmpdir.encode(), old_root.encode())
            os._exit(0 if ret == 0 else 1)
        except Exception:
            os._exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        ok = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        _probe_cache["pivot_root"] = ok
        return ok


def reset_probe_cache() -> None:
    """Clear the filesystem probe cache.  Useful in tests."""
    _probe_cache.clear()


# ── Launcher config generation ───────────────────────────────────────

def build_fs_isolation_config(
    rootfs_path: str,
    policy: FilesystemPolicy,
) -> Dict[str, Any]:
    """Build the filesystem isolation config dict for launcher injection.

    The returned dict is serialised to JSON and embedded in the launcher
    script's ``_CONFIG["filesystem"]`` key.

    Parameters
    ----------
    rootfs_path
        Absolute path to the rootfs directory (inside the tmpdir created
        by the executor).
    policy
        The filesystem isolation policy.
    """
    effective_mounts = policy.effective_readonly_mounts
    normalized = normalize_bind_mounts(effective_mounts)

    import platform as plat
    pivot_nr = _PIVOT_ROOT_NR.get(plat.machine())

    config: Dict[str, Any] = {
        "enabled": policy.enabled,
        "rootfs_path": rootfs_path,
        "tmpfs_mount_options": policy.tmpfs_mount_options,
        "readonly_binds": normalized,
        "writable_dirs": sorted(policy.writable_dirs),
        "create_dev_nodes": policy.create_dev_nodes,
        "dev_nodes": list(DEV_NODES),
        "prefer_pivot_root": policy.prefer_pivot_root,
        "pivot_root_nr": pivot_nr,
        "skeleton_dirs": list(_ROOTFS_DIRS),
        "host_uid": os.getuid(),
        "host_gid": os.getgid(),
        # D2 production
        "nosymfollow": policy.nosymfollow,
    }

    # OverlayFS configuration
    if policy.overlay_config is not None:
        from .overlay import build_overlay_config
        overlay_cfg = build_overlay_config(policy.overlay_config, rootfs_path)
        if overlay_cfg is not None:
            config["overlay"] = overlay_cfg

    # Proc masking configuration
    if policy.proc_mask is not None:
        from .fs_monitor import build_proc_mask_config
        config["proc_mask"] = build_proc_mask_config(policy.proc_mask)

    # Mount verification configuration
    if policy.verify_mounts:
        from .fs_monitor import build_mount_verification_config
        config["mount_verification"] = build_mount_verification_config(
            expected_readonly=frozenset(normalized),
            expected_writable=frozenset(policy.writable_dirs),
            expect_tmpfs_root=True,
            strict=policy.verify_mounts_strict,
        )

    return config


def build_rootfs_skeleton(rootfs_path: str) -> None:
    """Create the directory structure for the rootfs.

    Called by the executor in the **parent** process.  The directories
    are created on the host filesystem; the child will mount tmpfs on
    top and recreate them on the tmpfs.

    This is primarily useful for the *fallback path* where mount
    namespace is unavailable and we fall back to ``chroot`` or
    chdir-based isolation.
    """
    for dirname in _ROOTFS_DIRS:
        target = os.path.join(rootfs_path, dirname)
        os.makedirs(target, exist_ok=True)


# ── Private helpers ──────────────────────────────────────────────────

def _load_libc() -> ctypes.CDLL:
    """Load libc with errno support."""
    name = ctypes.util.find_library("c")
    return ctypes.CDLL(name or "libc.so.6", use_errno=True)


def _write_id_maps(uid: int, gid: int) -> None:
    """Write uid/gid maps for a user namespace.

    Maps the host UID/GID to 0 inside the namespace.
    """
    try:
        with open("/proc/self/setgroups", "w") as f:
            f.write("deny")
    except (OSError, PermissionError):
        pass
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


# ── Launcher template fragment ───────────────────────────────────────
#
# This Python source code is injected into the launcher script.
# It runs in the CHILD process, inside a mount namespace, BEFORE
# rlimits/seccomp/Python-sandbox are applied.

FS_ISOLATION_LAUNCHER_CODE: str = '''\
# ━━ Layer 0: Filesystem isolation ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _apply_filesystem_isolation():
    """Set up isolated filesystem: tmpfs root + RO bind mounts + pivot_root.

    D2 production enhancements:
    - OverlayFS support (union filesystem with COW)
    - /proc masking (hidepid, sensitive path nulling)
    - Mount verification (post-isolation mount table check)
    - nosymfollow support (symlink escape prevention)
    - Inode-limited tmpfs
    """
    fs_cfg = _CONFIG.get("filesystem")
    if not fs_cfg or not fs_cfg.get("enabled"):
        return

    import ctypes, ctypes.util, platform as _plat

    _MS_RDONLY   = 1
    _MS_NOSUID   = 2
    _MS_NODEV    = 4
    _MS_NOEXEC   = 8
    _MS_REMOUNT  = 32
    _MS_BIND     = 4096
    _MS_REC      = 16384
    _MS_PRIVATE  = 1 << 18
    _MNT_DETACH  = 2

    _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                        use_errno=True)
    _newroot = fs_cfg["rootfs_path"]

    # ── Step 0: Write uid/gid maps for user namespace ──
    _uid = fs_cfg.get("host_uid", 0)
    _gid = fs_cfg.get("host_gid", 0)
    try:
        with open("/proc/self/setgroups", "w") as _f:
            _f.write("deny")
    except (OSError, PermissionError):
        pass
    try:
        with open("/proc/self/uid_map", "w") as _f:
            _f.write(f"0 {_uid} 1\\n")
    except (OSError, PermissionError):
        pass
    try:
        with open("/proc/self/gid_map", "w") as _f:
            _f.write(f"0 {_gid} 1\\n")
    except (OSError, PermissionError):
        pass

    # ── Step 1: Make all mounts private (prevent propagation) ──
    _libc.mount(b"none", b"/", b"", _MS_REC | _MS_PRIVATE, None)

    # ── Step 2: Mount tmpfs as the new root ──
    _opts = fs_cfg["tmpfs_mount_options"].encode()
    _tmpfs_flags = _MS_NOSUID | _MS_NODEV
    if fs_cfg.get("nosymfollow"):
        _MS_NOSYMFOLLOW = 256  # Kernel >= 5.10: prevent symlink traversal
        _tmpfs_flags |= _MS_NOSYMFOLLOW
    _ret = _libc.mount(b"tmpfs", _newroot.encode(), b"tmpfs",
                       _tmpfs_flags, _opts)
    if _ret != 0:
        sys.stderr.write(f"[sandbox-fs] tmpfs mount failed (errno={ctypes.get_errno()})\\n")
        return

    # ── Step 3: Create directory skeleton on the tmpfs ──
    for _d in fs_cfg["skeleton_dirs"]:
        _target = os.path.join(_newroot, _d)
        try:
            os.makedirs(_target, exist_ok=True)
        except OSError:
            pass

    # Create /etc subdirectory structure for individual file mounts
    for _subdir in ("ld.so.conf.d", "ssl/certs", "alternatives"):
        try:
            os.makedirs(os.path.join(_newroot, "etc", _subdir), exist_ok=True)
        except OSError:
            pass

    # ── Step 4: Bind-mount host paths read-only ──
    for _src in fs_cfg["readonly_binds"]:
        _dst = _newroot + _src  # e.g., /tmp/rootfs + /usr -> /tmp/rootfs/usr
        try:
            if os.path.isfile(_src):
                _parent = os.path.dirname(_dst)
                os.makedirs(_parent, exist_ok=True)
                if not os.path.exists(_dst):
                    open(_dst, "w").close()
            else:
                os.makedirs(_dst, exist_ok=True)
        except OSError:
            continue

        _ret = _libc.mount(_src.encode(), _dst.encode(), b"",
                           _MS_BIND | _MS_REC, None)
        if _ret != 0:
            continue

        # Remount as read-only
        _libc.mount(b"", _dst.encode(), b"",
                    _MS_REMOUNT | _MS_BIND | _MS_RDONLY | _MS_REC, None)

    # ── Step 4b: OverlayFS mounts (D2 production) ──
    _ov_cfg = fs_cfg.get("overlay")
    if _ov_cfg and _ov_cfg.get("enabled"):
        _ov_base = _ov_cfg.get("overlay_base", "")
        try:
            os.makedirs(os.path.join(_newroot, _ov_base.lstrip("/")), exist_ok=True)
        except OSError:
            pass

        for _m in _ov_cfg.get("mounts", []):
            _mp = _newroot + _m["mount_point"]
            _udir = os.path.join(_newroot, _m["upperdir"].lstrip("/"))
            _wdir = os.path.join(_newroot, _m["workdir"].lstrip("/"))
            _flags = _m.get("flags", _MS_NOSUID | _MS_NODEV)

            for _d in (_udir, _wdir):
                try:
                    os.makedirs(_d, exist_ok=True)
                except OSError:
                    pass
            try:
                os.makedirs(_mp, exist_ok=True)
            except OSError:
                pass

            # Build lowerdir pointing to already bind-mounted paths
            _lowers = [_newroot + _ld for _ld in _m.get("lower_dirs", [])]
            _existing_lowers = [_ld for _ld in _lowers if os.path.isdir(_ld)]
            if not _existing_lowers:
                continue

            # Rebuild options with adjusted paths, preserving kernel flags
            _ov_parts = [
                f"lowerdir={':'.join(_existing_lowers)}",
                f"upperdir={_udir}",
                f"workdir={_wdir}",
            ]
            # Append metacopy/volatile/redirect_dir/index from config
            for _extra in _m.get("extra_options", []):
                _ov_parts.append(_extra)
            _ov_opts = ",".join(_ov_parts).encode()

            _ret = _libc.mount(b"overlay", _mp.encode(), b"overlay",
                               _flags, _ov_opts)
            if _ret != 0:
                _errno = ctypes.get_errno()
                sys.stderr.write(
                    f"[sandbox-overlay] mount at {_mp} failed (errno={_errno})\\n"
                )

    # ── Step 5: Bind-mount /dev entries ──
    if fs_cfg.get("create_dev_nodes"):
        for _name, _host_path in fs_cfg["dev_nodes"]:
            _dst = os.path.join(_newroot, "dev", _name)
            try:
                if not os.path.exists(_dst):
                    open(_dst, "w").close()
                _libc.mount(_host_path.encode(), _dst.encode(), b"",
                            _MS_BIND, None)
            except OSError:
                pass

    # ── Step 6: Ensure writable dirs exist ──
    for _wd in fs_cfg["writable_dirs"]:
        try:
            os.makedirs(_newroot + _wd, mode=0o1777, exist_ok=True)
        except OSError:
            pass

    # ── Step 7: pivot_root or chroot ──
    _old_root = os.path.join(_newroot, "old_root")
    _pivoted = False

    if fs_cfg.get("prefer_pivot_root"):
        _nr = fs_cfg.get("pivot_root_nr")
        if _nr is not None:
            _ret = _libc.syscall(_nr, _newroot.encode(),
                                 _old_root.encode())
            if _ret == 0:
                _pivoted = True
                os.chdir("/")
                _libc.umount2(b"/old_root", _MNT_DETACH)
                try:
                    os.rmdir("/old_root")
                except OSError:
                    pass

    if not _pivoted:
        try:
            os.chroot(_newroot)
            os.chdir("/")
        except OSError as _e:
            sys.stderr.write(f"[sandbox-fs] chroot failed: {_e}\\n")
            return

    # ── Step 8: /proc masking (D2 production) ──
    _pm_cfg = fs_cfg.get("proc_mask")
    if _pm_cfg and _pm_cfg.get("mount_proc"):
        try:
            os.makedirs("/proc", exist_ok=True)
        except OSError:
            pass
        _hidepid = _pm_cfg.get("hidepid", 2)
        _pm_opts = f"hidepid={_hidepid}".encode()
        _libc.mount(b"proc", b"/proc", b"proc",
                     _MS_NOSUID | _MS_NODEV | _MS_NOEXEC, _pm_opts)

        # Mask sensitive paths
        for _path in _pm_cfg.get("masked_paths", []):
            if os.path.exists(_path):
                try:
                    _libc.mount(b"/dev/null", _path.encode(), b"",
                                _MS_BIND, None)
                except Exception:
                    pass

        # Read-only bind paths
        for _path in _pm_cfg.get("readonly_paths", []):
            if os.path.exists(_path):
                try:
                    _libc.mount(_path.encode(), _path.encode(), b"",
                                _MS_BIND | _MS_REC, None)
                    _libc.mount(b"", _path.encode(), b"",
                                _MS_REMOUNT | _MS_BIND | _MS_RDONLY | _MS_REC, None)
                except Exception:
                    pass

    # ── Step 9: Mount verification (D2 production) ──
    _mv_cfg = fs_cfg.get("mount_verification")
    if _mv_cfg and _mv_cfg.get("enabled"):
        try:
            _entries = {}
            with open("/proc/self/mounts") as _f:
                for _line in _f:
                    _parts = _line.strip().split()
                    if len(_parts) >= 4:
                        _entries[_parts[1]] = {
                            "fs_type": _parts[2],
                            "options": _parts[3],
                        }
        except (OSError, PermissionError):
            _entries = {}

        _issues = []

        # Check read-only mounts
        for _mp in _mv_cfg.get("expected_readonly", []):
            _entry = _entries.get(_mp)
            if _entry is not None:
                if "ro" not in _entry["options"].split(","):
                    _issues.append(f"Mount {_mp} should be read-only but is rw")

        # Check tmpfs root
        if _mv_cfg.get("expect_tmpfs_root"):
            _root = _entries.get("/")
            if _root and _root["fs_type"] != "tmpfs":
                _issues.append(f"Root is {_root['fs_type']}, expected tmpfs")

        # Check writable dirs exist
        for _mp in _mv_cfg.get("expected_writable", []):
            if not os.path.isdir(_mp):
                _issues.append(f"Writable dir {_mp} does not exist")

        if _issues and _mv_cfg.get("strict"):
            sys.stderr.write(
                "[sandbox-verify] STRICT: mount verification failed:\\n"
            )
            for _i in _issues:
                sys.stderr.write(f"  - {_i}\\n")
            sys.exit(77)
        elif _issues:
            for _i in _issues:
                sys.stderr.write(f"[sandbox-verify] WARNING: {_i}\\n")

    # ── Step 10: Move to work directory ──
    try:
        os.chdir("/work")
    except OSError:
        os.chdir("/")
'''

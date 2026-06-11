"""
OverlayFS support for Certior filesystem isolation (D2).

Provides a union filesystem where:

* **Lower layer** - read-only host paths (system libs, Python stdlib)
* **Upper layer** - writable tmpfs (bounded, ephemeral)
* **Work directory** - required by overlayfs for atomic copy-up
* **Merged view** - process sees a unified directory tree

OverlayFS vs bind-mount approach
---------------------------------
The bind-mount approach (``pivot_root`` + per-path bind mounts) is the
**primary** isolation method and is always preferred.  OverlayFS provides
an *alternative* or *complement* for scenarios where:

1. Fine-grained per-directory copy-on-write is needed (the process can
   "modify" system files - changes go to tmpfs and vanish on exit).
2. A more natural directory tree is desired (single merged mountpoint
   instead of many individual bind mounts).

OverlayFS requires ``CONFIG_OVERLAY_FS=y`` in the kernel, which is
standard on Ubuntu 20.04+ and most modern distributions.

Architecture
------------
::

    Host filesystem (immutable)
        │
        ├── /usr/lib/python3.12/   ──► lower layer
        ├── /usr/bin/python3       ──► lower layer
        └── /etc/ld.so.cache       ──► lower layer

    tmpfs (ephemeral, bounded)
        │
        ├── upper/                 ──► upper layer (writable)
        └── work/                  ──► workdir (overlayfs internals)

    Merged view (what the sandbox sees)
        │
        └── /merged/               ──► lowerdir=lower,upperdir=upper,workdir=work

Graceful degradation
--------------------
If overlayfs is unavailable (kernel module not loaded, inside Docker
without ``--privileged``), the system falls back to the bind-mount
approach automatically.

Prerequisites
-------------
* Linux ≥ 3.18 with ``CONFIG_OVERLAY_FS``
* User namespace with mount namespace support
* ``modprobe overlay`` (usually auto-loaded)
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
import tempfile
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from .errors import FilesystemIsolationError


# ── OverlayFS mode ───────────────────────────────────────────────────

class OverlayMode(Enum):
    """Strategy for filesystem root construction.

    BIND_MOUNT
        Traditional approach: tmpfs root + individual RO bind mounts +
        pivot_root.  Always available with mount namespace support.

    OVERLAYFS
        Union filesystem: lower (host RO) + upper (tmpfs) = merged view.
        Requires ``CONFIG_OVERLAY_FS``.  Falls back to BIND_MOUNT if
        unavailable.

    AUTO
        Probe the system and pick the best available mode.  Prefers
        OVERLAYFS when available (for copy-on-write semantics), falls
        back to BIND_MOUNT.
    """
    BIND_MOUNT = auto()
    OVERLAYFS = auto()
    AUTO = auto()


# ── OverlayFS configuration ──────────────────────────────────────────

@dataclass(frozen=True)
class OverlayMount:
    """Specification for a single overlay mount.

    Each overlay mount creates a merged directory that unifies one or more
    read-only lower directories with a writable upper directory on tmpfs.

    Parameters
    ----------
    lower_dirs
        Host paths forming the immutable lower layer.  Ordered: first
        entry has highest priority in name resolution.
    mount_point
        Where the merged view appears inside the sandbox (e.g. ``/usr``).
    noexec
        Whether to mount with ``MS_NOEXEC`` (block execution from this
        mount).  Default ``False`` for system paths.
    nosuid
        Whether to mount with ``MS_NOSUID``.  Default ``True`` - always
        block setuid in the sandbox.
    nodev
        Whether to mount with ``MS_NODEV``.  Default ``True`` - no device
        files from overlay.
    """
    lower_dirs: Tuple[str, ...]
    mount_point: str
    noexec: bool = False
    nosuid: bool = True
    nodev: bool = True

    @property
    def mount_flags(self) -> int:
        """Compute combined mount flags for this overlay."""
        flags = 0
        if self.noexec:
            flags |= 8   # MS_NOEXEC
        if self.nosuid:
            flags |= 2   # MS_NOSUID
        if self.nodev:
            flags |= 4   # MS_NODEV
        return flags


@dataclass(frozen=True)
class OverlayFSConfig:
    """Configuration for OverlayFS-based filesystem isolation.

    This is a *specification* - it does not perform OS calls.  The
    executor reads this and injects the corresponding mount operations
    into the launcher script.

    Parameters
    ----------
    mode
        Overlay mode selection strategy.
    mounts
        Individual overlay mount specifications.  If empty, a default
        configuration is built from the parent ``FilesystemPolicy``.
    metacopy
        Enable overlayfs metacopy (copy only metadata, not full file, on
        first write).  Kernel >= 4.19.  Reduces copy-up overhead.
    redirect_dir
        Enable overlayfs redirect_dir for rename support.  Kernel >= 4.10.
    volatile
        Mark upper layer as volatile (skip journal/fsync).  Faster but
        data is truly ephemeral.  Kernel >= 5.6.
    index
        Enable inode index for NFS export and hardlink support.
        Kernel >= 4.13.
    max_stack_depth
        Maximum overlay stack depth (nested overlays).  Kernel default is
        2.  We never need more than 1.
    """
    mode: OverlayMode = OverlayMode.AUTO
    mounts: Tuple[OverlayMount, ...] = ()
    metacopy: bool = False
    redirect_dir: bool = True
    volatile: bool = True
    index: bool = False
    max_stack_depth: int = 1

    # ── Factory methods ───────────────────────────────────────────────

    @classmethod
    def standard(cls) -> "OverlayFSConfig":
        """Standard overlay configuration for system paths."""
        return cls(
            mode=OverlayMode.AUTO,
            mounts=(
                OverlayMount(
                    lower_dirs=("/usr",),
                    mount_point="/usr",
                    noexec=False,  # /usr/bin needs exec
                    nosuid=True,
                    nodev=True,
                ),
                OverlayMount(
                    lower_dirs=("/lib", "/lib64"),
                    mount_point="/lib",
                    noexec=False,  # shared libs need exec
                    nosuid=True,
                    nodev=True,
                ),
                OverlayMount(
                    lower_dirs=("/etc",),
                    mount_point="/etc",
                    noexec=True,   # no execution from /etc
                    nosuid=True,
                    nodev=True,
                ),
            ),
            volatile=True,
        )

    @classmethod
    def disabled(cls) -> "OverlayFSConfig":
        """Disabled - fall back to bind-mount approach."""
        return cls(mode=OverlayMode.BIND_MOUNT, mounts=())

    @classmethod
    def hipaa(cls) -> "OverlayFSConfig":
        """HIPAA-grade: minimal overlay, volatile, noexec on /etc."""
        return cls(
            mode=OverlayMode.AUTO,
            mounts=(
                OverlayMount(
                    lower_dirs=("/usr",),
                    mount_point="/usr",
                    noexec=False,
                    nosuid=True,
                    nodev=True,
                ),
                OverlayMount(
                    lower_dirs=("/lib", "/lib64"),
                    mount_point="/lib",
                    noexec=False,
                    nosuid=True,
                    nodev=True,
                ),
            ),
            volatile=True,
            metacopy=False,  # full copy-up for audit clarity
        )

    @classmethod
    def sox(cls) -> "OverlayFSConfig":
        """SOX-grade: standard overlay with metacopy for performance."""
        return cls(
            mode=OverlayMode.AUTO,
            mounts=(
                OverlayMount(
                    lower_dirs=("/usr",),
                    mount_point="/usr",
                    noexec=False,
                    nosuid=True,
                    nodev=True,
                ),
                OverlayMount(
                    lower_dirs=("/lib", "/lib64"),
                    mount_point="/lib",
                    noexec=False,
                    nosuid=True,
                    nodev=True,
                ),
                OverlayMount(
                    lower_dirs=("/etc",),
                    mount_point="/etc",
                    noexec=True,
                    nosuid=True,
                    nodev=True,
                ),
            ),
            volatile=True,
            metacopy=True,
        )

    # ── Mount option string builder ───────────────────────────────────

    def build_overlay_options(
        self,
        mount: OverlayMount,
        upper_base: str,
    ) -> str:
        """Build the overlay mount option string for a single mount.

        Parameters
        ----------
        mount
            The overlay mount specification.
        upper_base
            Base path for the upper and work directories (on tmpfs).

        Returns
        -------
        str
            Mount option string for ``mount(2)`` data argument.
        """
        # Build lowerdir string (colon-separated, first = highest priority)
        existing_lowers = [d for d in mount.lower_dirs if os.path.isdir(d)]
        if not existing_lowers:
            raise FilesystemIsolationError(
                f"No valid lower directories for overlay mount "
                f"at {mount.mount_point}: {mount.lower_dirs}",
                operation="build_overlay_options",
            )

        lowerdir = ":".join(existing_lowers)

        # Create upper and work directories
        safe_name = mount.mount_point.strip("/").replace("/", "_") or "root"
        upperdir = os.path.join(upper_base, f"upper_{safe_name}")
        workdir = os.path.join(upper_base, f"work_{safe_name}")

        parts = [
            f"lowerdir={lowerdir}",
            f"upperdir={upperdir}",
            f"workdir={workdir}",
        ]

        if self.metacopy:
            parts.append("metacopy=on")
        if self.redirect_dir:
            parts.append("redirect_dir=on")
        if self.volatile:
            parts.append("volatile")
        if self.index:
            parts.append("index=on")

        return ",".join(parts)


# ── Overlay audit info ───────────────────────────────────────────────

@dataclass(frozen=True)
class OverlayAuditInfo:
    """Diagnostic snapshot of overlay filesystem state.

    Captured before execution.  All fields are JSON-serialisable.
    """
    mode_requested: str       # "auto", "overlayfs", "bind_mount"
    mode_effective: str       # "overlayfs", "bind_mount", "unavailable"
    overlay_available: bool
    mount_count: int
    mount_points: Tuple[str, ...]
    options_used: Tuple[str, ...]  # "volatile", "metacopy", etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode_requested": self.mode_requested,
            "mode_effective": self.mode_effective,
            "overlay_available": self.overlay_available,
            "mount_count": self.mount_count,
            "mount_points": list(self.mount_points),
            "options_used": list(self.options_used),
        }


def build_overlay_audit_info(
    config: OverlayFSConfig,
    available: Optional[bool] = None,
) -> OverlayAuditInfo:
    """Build an :class:`OverlayAuditInfo` for audit logging."""
    if available is None:
        available = probe_overlayfs()

    if config.mode == OverlayMode.BIND_MOUNT:
        effective = "bind_mount"
    elif available and config.mode in (OverlayMode.OVERLAYFS, OverlayMode.AUTO):
        effective = "overlayfs"
    else:
        effective = "bind_mount"

    options: List[str] = []
    if config.volatile:
        options.append("volatile")
    if config.metacopy:
        options.append("metacopy")
    if config.redirect_dir:
        options.append("redirect_dir")
    if config.index:
        options.append("index")

    return OverlayAuditInfo(
        mode_requested=config.mode.name.lower(),
        mode_effective=effective,
        overlay_available=available,
        mount_count=len(config.mounts),
        mount_points=tuple(m.mount_point for m in config.mounts),
        options_used=tuple(options),
    )


# ── Probing ──────────────────────────────────────────────────────────

_overlay_probe_cache: Dict[str, bool] = {}


def probe_overlayfs() -> bool:
    """Test whether overlayfs is available in the current environment.

    Checks:
    1. Linux platform
    2. ``/proc/filesystems`` lists ``overlay`` or ``overlayfs``
    3. (Optional) Actual mount attempt in a user namespace

    Safe to call - no side effects on the host.
    """
    if "overlayfs" in _overlay_probe_cache:
        return _overlay_probe_cache["overlayfs"]

    if not sys.platform.startswith("linux"):
        _overlay_probe_cache["overlayfs"] = False
        return False

    # Quick check: is overlay in /proc/filesystems?
    try:
        with open("/proc/filesystems") as f:
            fs_list = f.read()
        if "overlay" not in fs_list:
            _overlay_probe_cache["overlayfs"] = False
            return False
    except (OSError, PermissionError):
        _overlay_probe_cache["overlayfs"] = False
        return False

    # Deeper check: can we actually mount overlayfs in a user namespace?
    result = _probe_overlayfs_mount()
    _overlay_probe_cache["overlayfs"] = result
    return result


def _probe_overlayfs_mount() -> bool:
    """Attempt an actual overlayfs mount in a forked user+mount namespace."""
    from .namespace import CLONE_NEWUSER, CLONE_NEWNS, _unshare

    try:
        pid = os.fork()
    except OSError:
        return False

    if pid == 0:
        # Child process - attempt overlay mount
        try:
            from .namespace import CLONE_NEWUSER, CLONE_NEWNS, _unshare
            _unshare(CLONE_NEWUSER | CLONE_NEWNS)

            # Write uid/gid maps
            uid, gid = os.getuid(), os.getgid()
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

            libc = ctypes.CDLL(
                ctypes.util.find_library("c") or "libc.so.6",
                use_errno=True,
            )

            # Make mounts private
            libc.mount(b"none", b"/", b"", 16384 | (1 << 18), None)  # MS_REC|MS_PRIVATE

            tmpdir = tempfile.mkdtemp(prefix="certior_ov_probe_")

            # Create overlay directories
            lower = os.path.join(tmpdir, "lower")
            upper = os.path.join(tmpdir, "upper")
            work = os.path.join(tmpdir, "work")
            merged = os.path.join(tmpdir, "merged")
            for d in (lower, upper, work, merged):
                os.makedirs(d)

            # Mount tmpfs first
            ret = libc.mount(
                b"tmpfs", tmpdir.encode(), b"tmpfs",
                2 | 4,  # MS_NOSUID | MS_NODEV
                b"size=1m",
            )
            if ret != 0:
                os._exit(1)

            # Re-create dirs on tmpfs
            for d in (lower, upper, work, merged):
                os.makedirs(d, exist_ok=True)

            # Attempt overlay mount
            opts = f"lowerdir={lower},upperdir={upper},workdir={work}".encode()
            ret = libc.mount(
                b"overlay", merged.encode(), b"overlay",
                2 | 4,  # MS_NOSUID | MS_NODEV
                opts,
            )
            os._exit(0 if ret == 0 else 1)
        except Exception:
            os._exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def reset_overlay_probe_cache() -> None:
    """Clear the overlay probe cache.  Useful in tests."""
    _overlay_probe_cache.clear()


# ── Launcher config generation ───────────────────────────────────────

def build_overlay_config(
    config: OverlayFSConfig,
    rootfs_path: str,
) -> Optional[Dict[str, Any]]:
    """Build the overlay config dict for launcher injection.

    Returns ``None`` if overlay mode is BIND_MOUNT or if there are no
    mounts configured.  The returned dict is embedded in the launcher
    script's ``_CONFIG["overlay"]`` key.

    Parameters
    ----------
    config
        The OverlayFS configuration.
    rootfs_path
        Absolute path to the rootfs directory on the host (inside tmpdir).
    """
    if config.mode == OverlayMode.BIND_MOUNT:
        return None
    if not config.mounts:
        return None

    overlay_base = os.path.join(rootfs_path, "_overlay")

    mounts_cfg = []
    for mount in config.mounts:
        existing_lowers = [d for d in mount.lower_dirs if os.path.isdir(d)]
        if not existing_lowers:
            continue

        safe_name = mount.mount_point.strip("/").replace("/", "_") or "root"
        upperdir = os.path.join(overlay_base, f"upper_{safe_name}")
        workdir = os.path.join(overlay_base, f"work_{safe_name}")

        # Build options
        parts = [
            f"lowerdir={':'.join(existing_lowers)}",
            f"upperdir={upperdir}",
            f"workdir={workdir}",
        ]
        # Collect kernel-level overlay options separately so the launcher
        # can rebuild lowerdir/upperdir/workdir (adjusted for pivot_root)
        # while still preserving these flags.
        extra_opts: list[str] = []
        if config.metacopy:
            parts.append("metacopy=on")
            extra_opts.append("metacopy=on")
        if config.redirect_dir:
            parts.append("redirect_dir=on")
            extra_opts.append("redirect_dir=on")
        if config.volatile:
            parts.append("volatile")
            extra_opts.append("volatile")
        if config.index:
            parts.append("index=on")
            extra_opts.append("index=on")

        mounts_cfg.append({
            "mount_point": mount.mount_point,
            "options": ",".join(parts),
            "upperdir": upperdir,
            "workdir": workdir,
            "lower_dirs": existing_lowers,
            "flags": mount.mount_flags,
            "extra_options": extra_opts,
        })

    if not mounts_cfg:
        return None

    return {
        "enabled": True,
        "overlay_base": overlay_base,
        "mounts": mounts_cfg,
    }


# ── Launcher code fragment ──────────────────────────────────────────
#
# Injected into the launcher script AFTER the bind-mount approach.
# If overlayfs is enabled, we mount overlay on top of the already
# bind-mounted directories.

OVERLAY_LAUNCHER_CODE: str = '''\
# ━━ OverlayFS mounts ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _apply_overlayfs():
    """Mount overlayfs unions on top of bind-mounted directories."""
    ov_cfg = _CONFIG.get("overlay")
    if not ov_cfg or not ov_cfg.get("enabled"):
        return

    import ctypes, ctypes.util

    _MS_NOSUID = 2
    _MS_NODEV  = 4
    _MS_NOEXEC = 8

    _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                        use_errno=True)

    _ov_base = ov_cfg["overlay_base"]
    try:
        os.makedirs(_ov_base, exist_ok=True)
    except OSError:
        return

    _mounted = []
    for _m in ov_cfg["mounts"]:
        _mp = _m["mount_point"]
        _upperdir = _m["upperdir"]
        _workdir = _m["workdir"]
        _opts = _m["options"]
        _flags = _m.get("flags", _MS_NOSUID | _MS_NODEV)

        # Create upper/work dirs on the tmpfs
        for _d in (_upperdir, _workdir):
            try:
                os.makedirs(_d, exist_ok=True)
            except OSError:
                continue

        # Ensure mount point exists
        try:
            os.makedirs(_mp, exist_ok=True)
        except OSError:
            continue

        _ret = _libc.mount(
            b"overlay", _mp.encode(), b"overlay",
            _flags, _opts.encode(),
        )
        if _ret == 0:
            _mounted.append(_mp)
        else:
            _errno = ctypes.get_errno()
            sys.stderr.write(
                f"[sandbox-overlay] mount at {_mp} failed (errno={_errno})\\n"
            )

    if _mounted:
        # Store mounted points for verification
        os.environ["_CERTIOR_OVERLAY_MOUNTS"] = ",".join(_mounted)
'''


# ── Convenience ──────────────────────────────────────────────────────

def select_effective_mode(
    config: OverlayFSConfig,
    overlay_available: Optional[bool] = None,
) -> OverlayMode:
    """Determine the effective overlay mode after probing.

    Parameters
    ----------
    config
        The overlay configuration.
    overlay_available
        Override for probe result (useful in tests).

    Returns
    -------
    OverlayMode
        The actual mode that will be used: always BIND_MOUNT or OVERLAYFS,
        never AUTO.
    """
    if config.mode == OverlayMode.BIND_MOUNT:
        return OverlayMode.BIND_MOUNT

    if overlay_available is None:
        overlay_available = probe_overlayfs()

    if config.mode == OverlayMode.OVERLAYFS:
        if overlay_available:
            return OverlayMode.OVERLAYFS
        return OverlayMode.BIND_MOUNT

    # AUTO: prefer overlayfs when available
    if overlay_available:
        return OverlayMode.OVERLAYFS
    return OverlayMode.BIND_MOUNT


def validate_overlay_config(config: OverlayFSConfig) -> List[str]:
    """Validate an OverlayFSConfig and return warnings.

    Pure function - no OS probing.
    """
    warnings: List[str] = []

    if config.mode == OverlayMode.BIND_MOUNT:
        return warnings

    for mount in config.mounts:
        if not mount.mount_point.startswith("/"):
            warnings.append(
                f"Overlay mount_point {mount.mount_point!r} must be absolute."
            )
        if not mount.lower_dirs:
            warnings.append(
                f"Overlay mount at {mount.mount_point!r} has no lower directories."
            )
        for d in mount.lower_dirs:
            if not d.startswith("/"):
                warnings.append(
                    f"Overlay lower_dir {d!r} for mount at "
                    f"{mount.mount_point!r} must be absolute."
                )
            if not os.path.isdir(d):
                warnings.append(
                    f"Overlay lower_dir {d!r} for mount at "
                    f"{mount.mount_point!r} does not exist."
                )

    if config.max_stack_depth > 2:
        warnings.append(
            f"max_stack_depth={config.max_stack_depth} exceeds kernel default (2)."
        )

    return warnings

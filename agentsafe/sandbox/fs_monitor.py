"""
Filesystem monitoring and verification for Certior D2 isolation.

Post-isolation verification
---------------------------
After the launcher applies filesystem isolation (tmpfs root, bind mounts,
pivot_root/chroot, optionally overlayfs), the child process should verify
that the expected mount table is actually in effect.  This prevents
silent failures where isolation was *partially* applied.

Tmpfs usage monitoring
-----------------------
Track how much of the size-limited tmpfs the sandboxed process is using.
If the process approaches the limit, the audit record captures this.

File change manifest
--------------------
After execution completes, enumerate all files created or modified inside
writable directories (``/work``, ``/tmp``).  This manifest is included in
the compliance audit record and enables:

* Detecting unexpected file creation
* Tracking data written by the sandbox for HIPAA/SOX review
* Size accounting for tmpfs budget enforcement

Proc filesystem masking
-----------------------
``/proc`` exposes sensitive host information even inside mount namespaces.
This module provides configuration for:

* ``hidepid=2`` - hide other processes' entries in /proc
* Masking ``/proc/kcore``, ``/proc/kallsyms``, etc. with bind-mount
  from ``/dev/null``
* Read-only bind of ``/proc/sys`` to prevent sysctl writes
"""
from __future__ import annotations

import hashlib
import os
import stat
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Tuple


# ── Mount table parsing ──────────────────────────────────────────────

@dataclass(frozen=True)
class MountEntry:
    """Parsed entry from ``/proc/self/mounts`` (or ``/proc/self/mountinfo``).

    Fields
    ------
    device
        Mount source (e.g. ``tmpfs``, ``overlay``, ``/dev/sda1``).
    mount_point
        Filesystem path where the mount is visible.
    fs_type
        Filesystem type (e.g. ``tmpfs``, ``overlay``, ``ext4``).
    options
        Mount options string (e.g. ``rw,nosuid,nodev,size=65536k``).
    """
    device: str
    mount_point: str
    fs_type: str
    options: str

    @property
    def is_readonly(self) -> bool:
        """True if mounted read-only (``ro`` in options)."""
        opts = self.options.split(",")
        return "ro" in opts

    @property
    def is_noexec(self) -> bool:
        return "noexec" in self.options.split(",")

    @property
    def is_nosuid(self) -> bool:
        return "nosuid" in self.options.split(",")

    @property
    def is_nodev(self) -> bool:
        return "nodev" in self.options.split(",")

    @property
    def is_tmpfs(self) -> bool:
        return self.fs_type == "tmpfs"

    @property
    def is_overlay(self) -> bool:
        return self.fs_type == "overlay"

    @property
    def tmpfs_size_bytes(self) -> Optional[int]:
        """Parse ``size=Nk`` from tmpfs options.  Returns None if not tmpfs."""
        if self.fs_type != "tmpfs":
            return None
        for opt in self.options.split(","):
            if opt.startswith("size="):
                val = opt[5:]
                multiplier = 1
                if val.endswith("k"):
                    multiplier = 1024
                    val = val[:-1]
                elif val.endswith("m"):
                    multiplier = 1024 * 1024
                    val = val[:-1]
                elif val.endswith("g"):
                    multiplier = 1024 * 1024 * 1024
                    val = val[:-1]
                try:
                    return int(val) * multiplier
                except ValueError:
                    return None
        return None

    @property
    def nr_inodes(self) -> Optional[int]:
        """Parse ``nr_inodes=N`` from tmpfs options."""
        if self.fs_type != "tmpfs":
            return None
        for opt in self.options.split(","):
            if opt.startswith("nr_inodes="):
                try:
                    return int(opt[10:])
                except ValueError:
                    return None
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device": self.device,
            "mount_point": self.mount_point,
            "fs_type": self.fs_type,
            "options": self.options,
            "is_readonly": self.is_readonly,
            "is_noexec": self.is_noexec,
            "is_nosuid": self.is_nosuid,
            "is_nodev": self.is_nodev,
        }


def parse_proc_mounts(mounts_path: str = "/proc/self/mounts") -> List[MountEntry]:
    """Parse ``/proc/self/mounts`` into a list of :class:`MountEntry`.

    Each line of ``/proc/self/mounts`` has the format::

        device mount_point fs_type options dump_freq pass_no

    Parameters
    ----------
    mounts_path
        Path to the mounts file.  Override for testing.

    Returns
    -------
    List[MountEntry]
        Parsed mount entries, ordered as they appear in the file.
    """
    entries: List[MountEntry] = []
    try:
        with open(mounts_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 4:
                    continue
                entries.append(MountEntry(
                    device=parts[0],
                    mount_point=_unescape_mount_path(parts[1]),
                    fs_type=parts[2],
                    options=parts[3],
                ))
    except (OSError, PermissionError):
        pass
    return entries


def _unescape_mount_path(path: str) -> str:
    """Unescape octal sequences in mount paths (e.g. ``\\040`` → space)."""
    import re
    return re.sub(
        r"\\([0-7]{3})",
        lambda m: chr(int(m.group(1), 8)),
        path,
    )


# ── Mount verification ───────────────────────────────────────────────

@dataclass(frozen=True)
class MountVerificationResult:
    """Result of verifying the mount table against expected state.

    Fields
    ------
    passed
        True if all expected mounts are present and correctly configured.
    expected_count
        Number of mounts we expected to find.
    found_count
        Number of expected mounts actually found.
    missing
        Mount points that were expected but not found.
    readonly_violations
        Mount points that should be read-only but are read-write.
    unexpected_writable
        Mount points that are writable but were not in the writable set.
    warnings
        Non-fatal issues.
    mount_table
        The full parsed mount table at verification time.
    """
    passed: bool
    expected_count: int
    found_count: int
    missing: Tuple[str, ...] = ()
    readonly_violations: Tuple[str, ...] = ()
    unexpected_writable: Tuple[str, ...] = ()
    warnings: Tuple[str, ...] = ()
    mount_table: Tuple[MountEntry, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "expected_count": self.expected_count,
            "found_count": self.found_count,
            "missing": list(self.missing),
            "readonly_violations": list(self.readonly_violations),
            "unexpected_writable": list(self.unexpected_writable),
            "warnings": list(self.warnings),
        }


def verify_mount_table(
    expected_readonly: FrozenSet[str],
    expected_writable: FrozenSet[str],
    expect_tmpfs_root: bool = True,
    mounts_path: str = "/proc/self/mounts",
) -> MountVerificationResult:
    """Verify that the current mount table matches expected isolation state.

    This should be called AFTER filesystem isolation is applied, inside the
    child process.  It checks that:

    1. Expected read-only bind mounts are present and actually read-only.
    2. Expected writable directories exist and are writable.
    3. The root filesystem is tmpfs (if expected).
    4. No unexpected writable mounts exist.

    Parameters
    ----------
    expected_readonly
        Set of mount points that should be read-only bind mounts.
    expected_writable
        Set of mount points that should be writable (on tmpfs).
    expect_tmpfs_root
        Whether the root ``/`` should be tmpfs.
    mounts_path
        Override for testing.

    Returns
    -------
    MountVerificationResult
    """
    entries = parse_proc_mounts(mounts_path)
    if not entries:
        return MountVerificationResult(
            passed=False,
            expected_count=len(expected_readonly) + len(expected_writable),
            found_count=0,
            warnings=("Could not parse mount table",),
        )

    mount_map = {e.mount_point: e for e in entries}

    missing: List[str] = []
    ro_violations: List[str] = []
    unexpected_writable: List[str] = []
    warnings: List[str] = []
    found = 0

    # Check expected readonly mounts
    for mp in sorted(expected_readonly):
        entry = mount_map.get(mp)
        if entry is None:
            # Check if covered by a parent mount
            covered = any(
                mp.startswith(e_mp + "/") or mp == e_mp
                for e_mp in mount_map
                if mount_map[e_mp].is_readonly
            )
            if not covered:
                missing.append(mp)
            else:
                found += 1
        else:
            found += 1
            if not entry.is_readonly:
                ro_violations.append(mp)

    # Check expected writable mounts
    for mp in sorted(expected_writable):
        # Writable dirs may not appear as separate mounts (they're on tmpfs)
        if os.path.isdir(mp):
            found += 1
            try:
                test_file = os.path.join(mp, ".certior_write_test")
                with open(test_file, "w") as f:
                    f.write("test")
                os.unlink(test_file)
            except (OSError, PermissionError):
                warnings.append(
                    f"Writable dir {mp!r} exists but write test failed."
                )
        else:
            missing.append(mp)

    # Check tmpfs root
    if expect_tmpfs_root:
        root_entry = mount_map.get("/")
        if root_entry is None:
            warnings.append("No root mount found in mount table.")
        elif not root_entry.is_tmpfs:
            warnings.append(
                f"Root filesystem is {root_entry.fs_type!r}, expected tmpfs."
            )

    # Detect unexpected writable mounts (excluding known-safe ones)
    safe_writable = expected_writable | frozenset({"/", "/proc", "/dev"})
    for entry in entries:
        if (
            not entry.is_readonly
            and entry.mount_point not in safe_writable
            and not any(
                entry.mount_point.startswith(sw + "/")
                for sw in safe_writable
            )
        ):
            unexpected_writable.append(entry.mount_point)

    total_expected = len(expected_readonly) + len(expected_writable)
    passed = (
        not missing
        and not ro_violations
        and not unexpected_writable
    )

    return MountVerificationResult(
        passed=passed,
        expected_count=total_expected,
        found_count=found,
        missing=tuple(missing),
        readonly_violations=tuple(ro_violations),
        unexpected_writable=tuple(unexpected_writable),
        warnings=tuple(warnings),
        mount_table=tuple(entries),
    )


# ── Mount verification launcher code ─────────────────────────────────
# This fragment is injected into the launcher script to run AFTER
# filesystem isolation is applied.

MOUNT_VERIFY_LAUNCHER_CODE: str = '''\
# ━━ Mount verification ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _verify_mounts():
    """Verify mount table matches expected isolation state."""
    mv_cfg = _CONFIG.get("mount_verification")
    if not mv_cfg or not mv_cfg.get("enabled"):
        return

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
        sys.stderr.write("[sandbox-verify] Cannot read /proc/self/mounts\\n")
        return

    _issues = []

    # Check read-only mounts
    for _mp in mv_cfg.get("expected_readonly", []):
        _entry = _entries.get(_mp)
        if _entry is not None:
            if "ro" not in _entry["options"].split(","):
                _issues.append(f"Mount {_mp} should be read-only but is rw")
        # May be covered by parent mount - not necessarily an error

    # Check tmpfs root
    if mv_cfg.get("expect_tmpfs_root"):
        _root = _entries.get("/")
        if _root and _root["fs_type"] != "tmpfs":
            _issues.append(f"Root is {_root['fs_type']}, expected tmpfs")

    # Check writable dirs exist
    for _mp in mv_cfg.get("expected_writable", []):
        if not os.path.isdir(_mp):
            _issues.append(f"Writable dir {_mp} does not exist")

    if _issues and mv_cfg.get("strict"):
        sys.stderr.write(
            "[sandbox-verify] STRICT: mount verification failed:\\n"
        )
        for _i in _issues:
            sys.stderr.write(f"  - {_i}\\n")
        sys.exit(77)  # Special exit code: verification failure
    elif _issues:
        for _i in _issues:
            sys.stderr.write(f"[sandbox-verify] WARNING: {_i}\\n")
'''


# ── Tmpfs usage monitoring ───────────────────────────────────────────

@dataclass(frozen=True)
class TmpfsUsage:
    """Snapshot of tmpfs filesystem usage.

    Captured via ``os.statvfs()`` on a tmpfs mount point.

    Fields
    ------
    total_bytes
        Total tmpfs capacity (from mount options ``size=N``).
    used_bytes
        Bytes currently used.
    free_bytes
        Bytes available for writing.
    usage_fraction
        ``used_bytes / total_bytes`` as a float in ``[0.0, 1.0]``.
    total_inodes
        Total inode count.
    used_inodes
        Inodes currently allocated.
    free_inodes
        Inodes available.
    mount_point
        The mount point that was queried.
    """
    total_bytes: int
    used_bytes: int
    free_bytes: int
    usage_fraction: float
    total_inodes: int
    used_inodes: int
    free_inodes: int
    mount_point: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_bytes": self.total_bytes,
            "used_bytes": self.used_bytes,
            "free_bytes": self.free_bytes,
            "usage_fraction": round(self.usage_fraction, 4),
            "total_inodes": self.total_inodes,
            "used_inodes": self.used_inodes,
            "free_inodes": self.free_inodes,
            "mount_point": self.mount_point,
        }


def query_tmpfs_usage(mount_point: str = "/") -> Optional[TmpfsUsage]:
    """Query current tmpfs usage at the given mount point.

    Returns ``None`` if ``os.statvfs()`` fails (e.g. path does not exist,
    or we're not on a filesystem that supports statvfs).

    Parameters
    ----------
    mount_point
        The tmpfs mount point to query.  Typically ``/`` inside the sandbox,
        or ``/work`` for the writable working directory.
    """
    try:
        st = os.statvfs(mount_point)
    except (OSError, PermissionError):
        return None

    block_size = st.f_frsize or st.f_bsize
    total_bytes = st.f_blocks * block_size
    free_bytes = st.f_bavail * block_size
    used_bytes = total_bytes - free_bytes

    if total_bytes == 0:
        usage_fraction = 0.0
    else:
        usage_fraction = used_bytes / total_bytes

    return TmpfsUsage(
        total_bytes=total_bytes,
        used_bytes=used_bytes,
        free_bytes=free_bytes,
        usage_fraction=usage_fraction,
        total_inodes=st.f_files,
        used_inodes=st.f_files - st.f_favail,
        free_inodes=st.f_favail,
        mount_point=mount_point,
    )


# ── File change manifest ─────────────────────────────────────────────

@dataclass(frozen=True)
class FileEntry:
    """A single file in the change manifest.

    Fields
    ------
    path
        Relative path from the writable root (e.g. ``output.txt``).
    size_bytes
        File size in bytes.
    sha256
        SHA-256 hash of the file contents (for integrity verification).
        ``None`` for directories or unreadable files.
    mode
        Unix permission mode (e.g. ``0o644``).
    is_directory
        Whether this is a directory.
    is_symlink
        Whether this is a symbolic link.
    symlink_target
        Target of the symlink (if ``is_symlink``).
    """
    path: str
    size_bytes: int
    sha256: Optional[str]
    mode: int
    is_directory: bool
    is_symlink: bool = False
    symlink_target: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "mode": oct(self.mode),
            "is_directory": self.is_directory,
        }
        if self.sha256:
            d["sha256"] = self.sha256
        if self.is_symlink:
            d["is_symlink"] = True
            d["symlink_target"] = self.symlink_target
        return d


@dataclass(frozen=True)
class FileChangeManifest:
    """Manifest of all files created/modified inside writable sandbox dirs.

    Captured after sandbox execution completes, before cleanup.
    Included in compliance audit records.

    Fields
    ------
    writable_root
        The writable directory that was scanned (e.g. ``/work``).
    files
        List of file entries found.
    total_size_bytes
        Aggregate size of all files.
    total_count
        Number of files (excluding directories).
    directory_count
        Number of directories.
    symlink_count
        Number of symbolic links (potential escape vectors).
    capture_timestamp
        ISO-8601 timestamp when the manifest was captured.
    """
    writable_root: str
    files: Tuple[FileEntry, ...]
    total_size_bytes: int
    total_count: int
    directory_count: int
    symlink_count: int
    capture_timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "writable_root": self.writable_root,
            "total_size_bytes": self.total_size_bytes,
            "total_count": self.total_count,
            "directory_count": self.directory_count,
            "symlink_count": self.symlink_count,
            "capture_timestamp": self.capture_timestamp,
            "files": [f.to_dict() for f in self.files],
        }


def capture_file_manifest(
    writable_root: str,
    *,
    max_files: int = 10000,
    hash_files: bool = True,
    max_hash_size: int = 10 * 1024 * 1024,  # 10 MiB
    follow_symlinks: bool = False,
) -> FileChangeManifest:
    """Walk a writable directory and build a :class:`FileChangeManifest`.

    Parameters
    ----------
    writable_root
        Absolute path to scan (e.g. ``/work`` or a tmpdir).
    max_files
        Safety limit on the number of files to enumerate.  Prevents
        unbounded work if the sandbox created millions of files.
    hash_files
        Whether to compute SHA-256 hashes of file contents.
    max_hash_size
        Skip hashing files larger than this (they still appear in the
        manifest with ``sha256=None``).
    follow_symlinks
        Whether to follow symbolic links.  Default ``False`` - symlinks
        are reported as symlinks, not their targets.
    """
    import datetime

    files: List[FileEntry] = []
    total_size = 0
    file_count = 0
    dir_count = 0
    symlink_count = 0
    enumerated = 0

    if not os.path.isdir(writable_root):
        return FileChangeManifest(
            writable_root=writable_root,
            files=(),
            total_size_bytes=0,
            total_count=0,
            directory_count=0,
            symlink_count=0,
            capture_timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )

    try:
        for dirpath, dirnames, filenames in os.walk(
            writable_root, followlinks=follow_symlinks
        ):
            # Process directories
            for dname in dirnames:
                if enumerated >= max_files:
                    break
                full_path = os.path.join(dirpath, dname)
                rel_path = os.path.relpath(full_path, writable_root)
                try:
                    st = os.lstat(full_path)
                except OSError:
                    continue

                is_link = stat.S_ISLNK(st.st_mode)
                link_target = None
                if is_link:
                    symlink_count += 1
                    try:
                        link_target = os.readlink(full_path)
                    except OSError:
                        pass
                else:
                    dir_count += 1

                files.append(FileEntry(
                    path=rel_path,
                    size_bytes=0,
                    sha256=None,
                    mode=stat.S_IMODE(st.st_mode),
                    is_directory=not is_link,
                    is_symlink=is_link,
                    symlink_target=link_target,
                ))
                enumerated += 1

            # Process files
            for fname in filenames:
                if enumerated >= max_files:
                    break
                full_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(full_path, writable_root)

                try:
                    st = os.lstat(full_path)
                except OSError:
                    continue

                is_link = stat.S_ISLNK(st.st_mode)
                link_target = None
                file_hash = None

                if is_link:
                    symlink_count += 1
                    try:
                        link_target = os.readlink(full_path)
                    except OSError:
                        pass
                else:
                    file_count += 1
                    total_size += st.st_size

                    # Hash file contents
                    if (
                        hash_files
                        and st.st_size <= max_hash_size
                        and not is_link
                    ):
                        try:
                            h = hashlib.sha256()
                            with open(full_path, "rb") as f:
                                for chunk in iter(lambda: f.read(8192), b""):
                                    h.update(chunk)
                            file_hash = h.hexdigest()
                        except (OSError, PermissionError):
                            pass

                files.append(FileEntry(
                    path=rel_path,
                    size_bytes=st.st_size if not is_link else 0,
                    sha256=file_hash,
                    mode=stat.S_IMODE(st.st_mode),
                    is_directory=False,
                    is_symlink=is_link,
                    symlink_target=link_target,
                ))
                enumerated += 1

            if enumerated >= max_files:
                break
    except (OSError, PermissionError):
        pass

    return FileChangeManifest(
        writable_root=writable_root,
        files=tuple(sorted(files, key=lambda f: f.path)),
        total_size_bytes=total_size,
        total_count=file_count,
        directory_count=dir_count,
        symlink_count=symlink_count,
        capture_timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )


# ── Proc filesystem masking ──────────────────────────────────────────

@dataclass(frozen=True)
class ProcMaskConfig:
    """Configuration for ``/proc`` filesystem hardening inside the sandbox.

    Parameters
    ----------
    mount_proc
        Whether to mount ``/proc`` at all.  If ``False``, ``/proc`` is
        not available inside the sandbox (very restrictive, breaks some
        Python functionality).
    hidepid
        ``hidepid`` mount option value:
        - 0: default (all processes visible)
        - 1: users can't see other users' ``/proc/<pid>`` dirs
        - 2: ``/proc/<pid>`` dirs are invisible to non-owners
    masked_paths
        Paths inside ``/proc`` to mask by bind-mounting ``/dev/null``
        over them.  These paths expose sensitive kernel information.
    readonly_paths
        Paths inside ``/proc`` to bind-mount read-only (preventing writes
        to sysctl, etc.).
    """
    mount_proc: bool = True
    hidepid: int = 2

    masked_paths: FrozenSet[str] = frozenset({
        "/proc/kcore",
        "/proc/kallsyms",
        "/proc/keys",
        "/proc/key-users",
        "/proc/timer_list",
        "/proc/sched_debug",
        "/proc/scsi",
    })

    readonly_paths: FrozenSet[str] = frozenset({
        "/proc/bus",
        "/proc/fs",
        "/proc/irq",
        "/proc/sys",
        "/proc/sysrq-trigger",
    })

    @classmethod
    def standard(cls) -> "ProcMaskConfig":
        """Standard /proc hardening - hide processes, mask kernel info."""
        return cls()

    @classmethod
    def strict(cls) -> "ProcMaskConfig":
        """Strict - no /proc at all.  Most restrictive."""
        return cls(mount_proc=False)

    @classmethod
    def permissive(cls) -> "ProcMaskConfig":
        """Permissive - mount /proc but with minimal masking."""
        return cls(
            hidepid=0,
            masked_paths=frozenset({"/proc/kcore", "/proc/keys"}),
            readonly_paths=frozenset({"/proc/sys"}),
        )


def build_proc_mask_config(config: ProcMaskConfig) -> Dict[str, Any]:
    """Build the proc masking config dict for launcher injection."""
    return {
        "mount_proc": config.mount_proc,
        "hidepid": config.hidepid,
        "masked_paths": sorted(config.masked_paths),
        "readonly_paths": sorted(config.readonly_paths),
    }


# ── Proc masking launcher code ──────────────────────────────────────

PROC_MASK_LAUNCHER_CODE: str = '''\
# ━━ /proc filesystem masking ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _apply_proc_masking():
    """Mount and harden /proc inside the sandbox."""
    pm_cfg = _CONFIG.get("proc_mask")
    if not pm_cfg:
        return

    import ctypes, ctypes.util

    _MS_RDONLY  = 1
    _MS_NOSUID  = 2
    _MS_NODEV   = 4
    _MS_NOEXEC  = 8
    _MS_BIND    = 4096
    _MS_REMOUNT = 32
    _MS_REC     = 16384

    _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                        use_errno=True)

    if not pm_cfg.get("mount_proc"):
        return

    # Mount /proc with hidepid
    _hidepid = pm_cfg.get("hidepid", 2)
    try:
        os.makedirs("/proc", exist_ok=True)
    except OSError:
        return

    _opts = f"hidepid={_hidepid}".encode()
    _ret = _libc.mount(
        b"proc", b"/proc", b"proc",
        _MS_NOSUID | _MS_NODEV | _MS_NOEXEC, _opts,
    )
    if _ret != 0:
        return

    # Mask sensitive paths with /dev/null bind mount
    for _path in pm_cfg.get("masked_paths", []):
        if os.path.exists(_path):
            try:
                _libc.mount(b"/dev/null", _path.encode(), b"",
                            _MS_BIND, None)
            except Exception:
                pass

    # Make paths read-only
    for _path in pm_cfg.get("readonly_paths", []):
        if os.path.exists(_path):
            try:
                _libc.mount(_path.encode(), _path.encode(), b"",
                            _MS_BIND | _MS_REC, None)
                _libc.mount(b"", _path.encode(), b"",
                            _MS_REMOUNT | _MS_BIND | _MS_RDONLY | _MS_REC, None)
            except Exception:
                pass
'''


# ── Mount verification config builder ────────────────────────────────

def build_mount_verification_config(
    expected_readonly: FrozenSet[str],
    expected_writable: FrozenSet[str],
    expect_tmpfs_root: bool = True,
    strict: bool = False,
) -> Dict[str, Any]:
    """Build the mount verification config for launcher injection.

    Parameters
    ----------
    expected_readonly
        Mount points that should be read-only.
    expected_writable
        Directories that should be writable.
    expect_tmpfs_root
        Whether root should be tmpfs.
    strict
        If True, mount verification failure causes the process to exit.
        If False, failures are logged as warnings.
    """
    return {
        "enabled": True,
        "expected_readonly": sorted(expected_readonly),
        "expected_writable": sorted(expected_writable),
        "expect_tmpfs_root": expect_tmpfs_root,
        "strict": strict,
    }

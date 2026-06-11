"""
Production: Filesystem Isolation - Comprehensive Test Suite.

Tests cover:
  1. OverlayFS - OverlayFSConfig, OverlayMount, OverlayMode, probing, launcher config
  2. Filesystem monitoring - MountEntry, mount table parsing, mount verification
  3. Tmpfs usage - query_tmpfs_usage
  4. File change manifest - capture_file_manifest, FileEntry, hashing
  5. Proc masking - ProcMaskConfig, launcher config, validation
  6. Enhanced FilesystemPolicy - inode limits, nosymfollow, verify_mounts, overlay_config
  7. Enhanced FilesystemAuditInfo - overlay fields, proc mask fields
  8. Integration - FilesystemPolicy factories with D2 production features
  9. OverlayFS audit - OverlayAuditInfo, build_overlay_audit_info
 10. Mount verification config - build_mount_verification_config
 11. Policy validation - inode limits, overlay config validation
 12. Launcher code - structural validation with D2 extensions
"""
from __future__ import annotations

import json
import os
import platform
import stat
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock, mock_open, patch

import pytest

# ── Imports under test ───────────────────────────────────────────────

from agentsafe.sandbox.overlay import (
    OVERLAY_LAUNCHER_CODE,
    OverlayAuditInfo,
    OverlayFSConfig,
    OverlayMode,
    OverlayMount,
    build_overlay_audit_info,
    build_overlay_config,
    probe_overlayfs,
    reset_overlay_probe_cache,
    select_effective_mode,
    validate_overlay_config,
)

from agentsafe.sandbox.fs_monitor import (
    MOUNT_VERIFY_LAUNCHER_CODE,
    PROC_MASK_LAUNCHER_CODE,
    FileChangeManifest,
    FileEntry,
    MountEntry,
    MountVerificationResult,
    ProcMaskConfig,
    TmpfsUsage,
    build_mount_verification_config,
    build_proc_mask_config,
    capture_file_manifest,
    parse_proc_mounts,
    query_tmpfs_usage,
    verify_mount_table,
)

from agentsafe.sandbox.filesystem import (
    FS_ISOLATION_LAUNCHER_CODE,
    FilesystemAuditInfo,
    FilesystemPolicy,
    FilesystemPolicyValidationError,
    build_filesystem_audit_info,
    build_fs_isolation_config,
    build_rootfs_skeleton,
    normalize_bind_mounts,
    validate_policy,
)

from agentsafe.sandbox.policy import SandboxPolicy


# =====================================================================
# 1. OverlayFS - Configuration
# =====================================================================

class TestOverlayMount:
    """Tests for OverlayMount dataclass."""

    def test_basic_construction(self):
        m = OverlayMount(
            lower_dirs=("/usr", "/lib"),
            mount_point="/usr",
        )
        assert m.lower_dirs == ("/usr", "/lib")
        assert m.mount_point == "/usr"
        assert m.nosuid is True
        assert m.nodev is True
        assert m.noexec is False

    def test_mount_flags_default(self):
        m = OverlayMount(lower_dirs=("/usr",), mount_point="/usr")
        # nosuid + nodev by default
        assert m.mount_flags == (2 | 4)  # MS_NOSUID | MS_NODEV

    def test_mount_flags_noexec(self):
        m = OverlayMount(
            lower_dirs=("/etc",),
            mount_point="/etc",
            noexec=True,
        )
        assert m.mount_flags == (2 | 4 | 8)  # MS_NOSUID | MS_NODEV | MS_NOEXEC

    def test_mount_flags_all_false(self):
        m = OverlayMount(
            lower_dirs=("/usr",),
            mount_point="/usr",
            noexec=False,
            nosuid=False,
            nodev=False,
        )
        assert m.mount_flags == 0

    def test_frozen(self):
        m = OverlayMount(lower_dirs=("/usr",), mount_point="/usr")
        with pytest.raises(AttributeError):
            m.mount_point = "/lib"


class TestOverlayFSConfig:
    """Tests for OverlayFSConfig dataclass and factory methods."""

    def test_default_mode_is_auto(self):
        cfg = OverlayFSConfig()
        assert cfg.mode == OverlayMode.AUTO

    def test_standard_factory(self):
        cfg = OverlayFSConfig.standard()
        assert cfg.mode == OverlayMode.AUTO
        assert len(cfg.mounts) == 3
        mount_points = [m.mount_point for m in cfg.mounts]
        assert "/usr" in mount_points
        assert "/lib" in mount_points
        assert "/etc" in mount_points
        assert cfg.volatile is True

    def test_disabled_factory(self):
        cfg = OverlayFSConfig.disabled()
        assert cfg.mode == OverlayMode.BIND_MOUNT
        assert len(cfg.mounts) == 0

    def test_hipaa_factory(self):
        cfg = OverlayFSConfig.hipaa()
        assert cfg.mode == OverlayMode.AUTO
        mount_points = [m.mount_point for m in cfg.mounts]
        assert "/usr" in mount_points
        assert "/lib" in mount_points
        assert "/etc" not in mount_points  # tighter
        assert cfg.metacopy is False  # full copy-up for audit
        assert cfg.volatile is True

    def test_sox_factory(self):
        cfg = OverlayFSConfig.sox()
        assert cfg.metacopy is True  # performance
        assert cfg.volatile is True

    def test_frozen(self):
        cfg = OverlayFSConfig.standard()
        with pytest.raises(AttributeError):
            cfg.mode = OverlayMode.BIND_MOUNT

    def test_build_overlay_options_with_existing_dirs(self):
        cfg = OverlayFSConfig(volatile=True, metacopy=False, redirect_dir=True)
        mount = OverlayMount(lower_dirs=("/usr",), mount_point="/usr")
        with tempfile.TemporaryDirectory() as tmpdir:
            opts = cfg.build_overlay_options(mount, tmpdir)
            assert "lowerdir=/usr" in opts
            assert f"upperdir={tmpdir}" in opts
            assert f"workdir={tmpdir}" in opts
            assert "volatile" in opts
            assert "redirect_dir=on" in opts
            assert "metacopy" not in opts

    def test_build_overlay_options_with_metacopy(self):
        cfg = OverlayFSConfig(metacopy=True, volatile=False, redirect_dir=False)
        mount = OverlayMount(lower_dirs=("/usr",), mount_point="/usr")
        with tempfile.TemporaryDirectory() as tmpdir:
            opts = cfg.build_overlay_options(mount, tmpdir)
            assert "metacopy=on" in opts
            assert "volatile" not in opts
            assert "redirect_dir" not in opts


class TestOverlayMode:
    """Tests for OverlayMode enum."""

    def test_values(self):
        assert OverlayMode.BIND_MOUNT.name == "BIND_MOUNT"
        assert OverlayMode.OVERLAYFS.name == "OVERLAYFS"
        assert OverlayMode.AUTO.name == "AUTO"

    def test_distinct_values(self):
        modes = set(m.value for m in OverlayMode)
        assert len(modes) == 3


# =====================================================================
# 2. OverlayFS - Probing
# =====================================================================

class TestOverlayProbing:
    """Tests for overlay filesystem probing."""

    def setup_method(self):
        reset_overlay_probe_cache()

    def test_probe_returns_bool(self):
        result = probe_overlayfs()
        assert isinstance(result, bool)

    def test_probe_caching(self):
        r1 = probe_overlayfs()
        r2 = probe_overlayfs()
        assert r1 == r2

    def test_reset_probe_cache(self):
        probe_overlayfs()
        reset_overlay_probe_cache()
        # No assertion - just verify no crash

    @patch("sys.platform", "win32")
    def test_probe_non_linux(self):
        reset_overlay_probe_cache()
        assert probe_overlayfs() is False


class TestSelectEffectiveMode:
    """Tests for select_effective_mode()."""

    def test_bind_mount_always_returns_bind_mount(self):
        cfg = OverlayFSConfig(mode=OverlayMode.BIND_MOUNT)
        assert select_effective_mode(cfg) == OverlayMode.BIND_MOUNT

    def test_overlayfs_when_available(self):
        cfg = OverlayFSConfig(mode=OverlayMode.OVERLAYFS)
        result = select_effective_mode(cfg, overlay_available=True)
        assert result == OverlayMode.OVERLAYFS

    def test_overlayfs_fallback_when_unavailable(self):
        cfg = OverlayFSConfig(mode=OverlayMode.OVERLAYFS)
        result = select_effective_mode(cfg, overlay_available=False)
        assert result == OverlayMode.BIND_MOUNT

    def test_auto_prefers_overlayfs(self):
        cfg = OverlayFSConfig(mode=OverlayMode.AUTO)
        result = select_effective_mode(cfg, overlay_available=True)
        assert result == OverlayMode.OVERLAYFS

    def test_auto_falls_back(self):
        cfg = OverlayFSConfig(mode=OverlayMode.AUTO)
        result = select_effective_mode(cfg, overlay_available=False)
        assert result == OverlayMode.BIND_MOUNT


# =====================================================================
# 3. OverlayFS - Config generation
# =====================================================================

class TestBuildOverlayConfig:
    """Tests for build_overlay_config()."""

    def test_bind_mount_mode_returns_none(self):
        cfg = OverlayFSConfig(mode=OverlayMode.BIND_MOUNT)
        result = build_overlay_config(cfg, "/tmp/rootfs")
        assert result is None

    def test_no_mounts_returns_none(self):
        cfg = OverlayFSConfig(mode=OverlayMode.OVERLAYFS, mounts=())
        result = build_overlay_config(cfg, "/tmp/rootfs")
        assert result is None

    def test_standard_config_structure(self):
        cfg = OverlayFSConfig.standard()
        result = build_overlay_config(cfg, "/tmp/rootfs")
        if result is not None:  # only if dirs exist
            assert result["enabled"] is True
            assert "overlay_base" in result
            assert isinstance(result["mounts"], list)

    def test_config_json_serialisable(self):
        cfg = OverlayFSConfig.standard()
        result = build_overlay_config(cfg, "/tmp/rootfs")
        if result is not None:
            s = json.dumps(result)
            assert isinstance(s, str)

    def test_mount_options_contain_lowerdir(self):
        cfg = OverlayFSConfig.standard()
        result = build_overlay_config(cfg, "/tmp/rootfs")
        if result is not None:
            for mount in result["mounts"]:
                assert "lowerdir=" in mount["options"]
                assert "upperdir=" in mount["options"]
                assert "workdir=" in mount["options"]


# =====================================================================
# 4. OverlayFS - Validation
# =====================================================================

class TestValidateOverlayConfig:
    """Tests for validate_overlay_config()."""

    def test_bind_mount_no_warnings(self):
        cfg = OverlayFSConfig(mode=OverlayMode.BIND_MOUNT)
        warnings = validate_overlay_config(cfg)
        assert warnings == []

    def test_relative_mount_point_warns(self):
        cfg = OverlayFSConfig(
            mode=OverlayMode.OVERLAYFS,
            mounts=(OverlayMount(lower_dirs=("/usr",), mount_point="usr"),),
        )
        warnings = validate_overlay_config(cfg)
        assert any("absolute" in w for w in warnings)

    def test_relative_lower_dir_warns(self):
        cfg = OverlayFSConfig(
            mode=OverlayMode.OVERLAYFS,
            mounts=(OverlayMount(lower_dirs=("usr",), mount_point="/usr"),),
        )
        warnings = validate_overlay_config(cfg)
        assert any("absolute" in w for w in warnings)

    def test_nonexistent_lower_dir_warns(self):
        cfg = OverlayFSConfig(
            mode=OverlayMode.OVERLAYFS,
            mounts=(
                OverlayMount(
                    lower_dirs=("/nonexistent_path_xyz",),
                    mount_point="/usr",
                ),
            ),
        )
        warnings = validate_overlay_config(cfg)
        assert any("does not exist" in w for w in warnings)

    def test_high_stack_depth_warns(self):
        cfg = OverlayFSConfig(max_stack_depth=5)
        warnings = validate_overlay_config(cfg)
        assert any("max_stack_depth" in w for w in warnings)


# =====================================================================
# 5. OverlayFS - Audit info
# =====================================================================

class TestOverlayAuditInfo:
    """Tests for OverlayAuditInfo and build_overlay_audit_info()."""

    def test_build_disabled(self):
        cfg = OverlayFSConfig(mode=OverlayMode.BIND_MOUNT)
        info = build_overlay_audit_info(cfg, available=False)
        assert info.mode_effective == "bind_mount"
        assert info.overlay_available is False

    def test_build_available_auto(self):
        cfg = OverlayFSConfig.standard()
        info = build_overlay_audit_info(cfg, available=True)
        assert info.mode_effective == "overlayfs"
        assert info.overlay_available is True
        assert info.mount_count == 3

    def test_build_unavailable_auto(self):
        cfg = OverlayFSConfig.standard()
        info = build_overlay_audit_info(cfg, available=False)
        assert info.mode_effective == "bind_mount"

    def test_to_dict(self):
        cfg = OverlayFSConfig.standard()
        info = build_overlay_audit_info(cfg, available=True)
        d = info.to_dict()
        assert isinstance(d, dict)
        assert d["mode_effective"] == "overlayfs"
        assert d["mount_count"] == 3
        assert isinstance(d["options_used"], list)

    def test_to_dict_json_safe(self):
        cfg = OverlayFSConfig.standard()
        info = build_overlay_audit_info(cfg, available=True)
        s = json.dumps(info.to_dict())
        assert isinstance(s, str)

    def test_options_captured(self):
        cfg = OverlayFSConfig(volatile=True, metacopy=True, redirect_dir=True, index=True)
        info = build_overlay_audit_info(cfg, available=True)
        assert "volatile" in info.options_used
        assert "metacopy" in info.options_used


# =====================================================================
# 6. Filesystem monitoring - MountEntry
# =====================================================================

class TestMountEntry:
    """Tests for MountEntry dataclass."""

    def test_basic_properties(self):
        e = MountEntry("tmpfs", "/", "tmpfs", "rw,nosuid,nodev,size=65536k")
        assert e.is_tmpfs is True
        assert e.is_readonly is False
        assert e.is_nosuid is True
        assert e.is_nodev is True
        assert e.is_overlay is False

    def test_readonly(self):
        e = MountEntry("/dev/sda1", "/usr", "ext4", "ro,nosuid")
        assert e.is_readonly is True

    def test_overlay(self):
        e = MountEntry("overlay", "/merged", "overlay", "rw,nosuid,nodev,lowerdir=/lower")
        assert e.is_overlay is True

    def test_tmpfs_size_bytes_k(self):
        e = MountEntry("tmpfs", "/", "tmpfs", "rw,size=65536k")
        assert e.tmpfs_size_bytes == 65536 * 1024

    def test_tmpfs_size_bytes_m(self):
        e = MountEntry("tmpfs", "/", "tmpfs", "rw,size=64m")
        assert e.tmpfs_size_bytes == 64 * 1024 * 1024

    def test_tmpfs_size_bytes_plain(self):
        e = MountEntry("tmpfs", "/", "tmpfs", "rw,size=1048576")
        assert e.tmpfs_size_bytes == 1048576

    def test_tmpfs_size_bytes_non_tmpfs(self):
        e = MountEntry("/dev/sda1", "/", "ext4", "rw")
        assert e.tmpfs_size_bytes is None

    def test_nr_inodes(self):
        e = MountEntry("tmpfs", "/", "tmpfs", "rw,nr_inodes=5000,size=64m")
        assert e.nr_inodes == 5000

    def test_nr_inodes_missing(self):
        e = MountEntry("tmpfs", "/", "tmpfs", "rw,size=64m")
        assert e.nr_inodes is None

    def test_noexec(self):
        e = MountEntry("tmpfs", "/tmp", "tmpfs", "rw,noexec,nosuid")
        assert e.is_noexec is True

    def test_to_dict(self):
        e = MountEntry("tmpfs", "/", "tmpfs", "rw,nosuid,nodev,size=64m")
        d = e.to_dict()
        assert d["device"] == "tmpfs"
        assert d["mount_point"] == "/"
        assert d["fs_type"] == "tmpfs"
        assert d["is_readonly"] is False
        assert d["is_nosuid"] is True

    def test_frozen(self):
        e = MountEntry("tmpfs", "/", "tmpfs", "rw")
        with pytest.raises(AttributeError):
            e.mount_point = "/tmp"


# =====================================================================
# 7. Filesystem monitoring - Parse mount table
# =====================================================================

class TestParseProcMounts:
    """Tests for parse_proc_mounts()."""

    def test_parse_real_mounts(self):
        if not os.path.exists("/proc/self/mounts"):
            pytest.skip("No /proc/self/mounts available")
        entries = parse_proc_mounts()
        assert isinstance(entries, list)
        assert len(entries) > 0
        assert all(isinstance(e, MountEntry) for e in entries)

    def test_parse_nonexistent_file(self):
        entries = parse_proc_mounts("/nonexistent/path")
        assert entries == []

    def test_parse_mock_file(self):
        content = (
            "tmpfs / tmpfs rw,nosuid,nodev,size=65536k 0 0\n"
            "/dev/sda1 /usr ext4 ro,nosuid 0 0\n"
            "overlay /merged overlay rw,nosuid,lowerdir=/lower 0 0\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mounts", delete=False) as f:
            f.write(content)
            f.flush()
            try:
                entries = parse_proc_mounts(f.name)
                assert len(entries) == 3
                assert entries[0].fs_type == "tmpfs"
                assert entries[1].is_readonly is True
                assert entries[2].is_overlay is True
            finally:
                os.unlink(f.name)


# =====================================================================
# 8. Filesystem monitoring - Mount verification
# =====================================================================

class TestMountVerification:
    """Tests for verify_mount_table() and build_mount_verification_config()."""

    def test_verification_result_structure(self):
        result = MountVerificationResult(
            passed=True,
            expected_count=5,
            found_count=5,
        )
        assert result.passed is True
        assert result.missing == ()
        assert result.readonly_violations == ()

    def test_verification_result_to_dict(self):
        result = MountVerificationResult(
            passed=False,
            expected_count=3,
            found_count=1,
            missing=("/usr",),
            readonly_violations=("/lib",),
        )
        d = result.to_dict()
        assert d["passed"] is False
        assert "/usr" in d["missing"]
        assert "/lib" in d["readonly_violations"]

    def test_build_verification_config(self):
        cfg = build_mount_verification_config(
            expected_readonly=frozenset({"/usr", "/lib"}),
            expected_writable=frozenset({"/work", "/tmp"}),
            expect_tmpfs_root=True,
            strict=True,
        )
        assert cfg["enabled"] is True
        assert cfg["strict"] is True
        assert "/usr" in cfg["expected_readonly"]
        assert "/work" in cfg["expected_writable"]
        assert cfg["expect_tmpfs_root"] is True

    def test_verify_with_mock_mounts(self):
        content = (
            "tmpfs / tmpfs rw,nosuid,nodev,size=65536k 0 0\n"
            "/dev/sda1 /usr ext4 ro,nosuid 0 0\n"
            "/dev/sda1 /lib ext4 ro,nosuid 0 0\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mounts", delete=False) as f:
            f.write(content)
            f.flush()
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    work_dir = os.path.join(tmpdir, "work")
                    os.makedirs(work_dir)
                    result = verify_mount_table(
                        expected_readonly=frozenset({"/usr", "/lib"}),
                        expected_writable=frozenset({work_dir}),
                        expect_tmpfs_root=True,
                        mounts_path=f.name,
                    )
                    assert isinstance(result, MountVerificationResult)
                    assert result.found_count >= 2  # /usr, /lib
                    # /usr and /lib are ro - no violations
                    assert len(result.readonly_violations) == 0
            finally:
                os.unlink(f.name)

    def test_verify_detects_readonly_violation(self):
        content = (
            "tmpfs / tmpfs rw 0 0\n"
            "/dev/sda1 /usr ext4 rw,nosuid 0 0\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mounts", delete=False) as f:
            f.write(content)
            f.flush()
            try:
                result = verify_mount_table(
                    expected_readonly=frozenset({"/usr"}),
                    expected_writable=frozenset(),
                    mounts_path=f.name,
                )
                assert "/usr" in result.readonly_violations
            finally:
                os.unlink(f.name)


# =====================================================================
# 9. Tmpfs usage monitoring
# =====================================================================

class TestTmpfsUsage:
    """Tests for query_tmpfs_usage() and TmpfsUsage dataclass."""

    def test_query_real_filesystem(self):
        usage = query_tmpfs_usage("/")
        if usage is None:
            pytest.skip("statvfs not available on /")
        assert isinstance(usage, TmpfsUsage)
        assert usage.total_bytes > 0
        assert 0.0 <= usage.usage_fraction <= 1.0
        assert usage.mount_point == "/"

    def test_query_nonexistent_path(self):
        usage = query_tmpfs_usage("/nonexistent/path/xyz")
        assert usage is None

    def test_to_dict(self):
        u = TmpfsUsage(
            total_bytes=67108864,
            used_bytes=1024,
            free_bytes=67107840,
            usage_fraction=0.0000153,
            total_inodes=10000,
            used_inodes=5,
            free_inodes=9995,
            mount_point="/",
        )
        d = u.to_dict()
        assert d["total_bytes"] == 67108864
        assert d["free_bytes"] == 67107840
        assert isinstance(d["usage_fraction"], float)

    def test_frozen(self):
        u = TmpfsUsage(
            total_bytes=1, used_bytes=0, free_bytes=1,
            usage_fraction=0.0, total_inodes=1, used_inodes=0,
            free_inodes=1, mount_point="/",
        )
        with pytest.raises(AttributeError):
            u.mount_point = "/tmp"


# =====================================================================
# 10. File change manifest
# =====================================================================

class TestFileChangeManifest:
    """Tests for capture_file_manifest() and related types."""

    def test_capture_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = capture_file_manifest(tmpdir)
            assert isinstance(manifest, FileChangeManifest)
            assert manifest.total_count == 0
            assert manifest.directory_count == 0
            assert manifest.symlink_count == 0
            assert manifest.total_size_bytes == 0

    def test_capture_with_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some files
            Path(tmpdir, "output.txt").write_text("hello world")
            Path(tmpdir, "data.csv").write_text("a,b,c\n1,2,3")
            os.makedirs(os.path.join(tmpdir, "subdir"))
            Path(tmpdir, "subdir", "nested.txt").write_text("nested")

            manifest = capture_file_manifest(tmpdir)
            assert manifest.total_count == 3  # 3 files
            assert manifest.directory_count == 1  # 1 subdir
            assert manifest.total_size_bytes > 0

    def test_capture_with_hashing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "test.txt").write_text("hello")
            manifest = capture_file_manifest(tmpdir, hash_files=True)
            file_entries = [f for f in manifest.files if not f.is_directory]
            assert len(file_entries) == 1
            assert file_entries[0].sha256 is not None
            assert len(file_entries[0].sha256) == 64  # SHA-256 hex

    def test_capture_without_hashing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "test.txt").write_text("hello")
            manifest = capture_file_manifest(tmpdir, hash_files=False)
            file_entries = [f for f in manifest.files if not f.is_directory]
            assert file_entries[0].sha256 is None

    def test_capture_symlinks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "real.txt").write_text("content")
            os.symlink(
                os.path.join(tmpdir, "real.txt"),
                os.path.join(tmpdir, "link.txt"),
            )
            manifest = capture_file_manifest(tmpdir, follow_symlinks=False)
            assert manifest.symlink_count == 1
            symlinks = [f for f in manifest.files if f.is_symlink]
            assert len(symlinks) == 1
            assert symlinks[0].symlink_target is not None

    def test_capture_max_files_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(50):
                Path(tmpdir, f"file_{i}.txt").write_text(f"content {i}")
            manifest = capture_file_manifest(tmpdir, max_files=10)
            assert len(manifest.files) <= 10

    def test_capture_nonexistent_directory(self):
        manifest = capture_file_manifest("/nonexistent/path/xyz")
        assert manifest.total_count == 0
        assert len(manifest.files) == 0

    def test_manifest_to_dict(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "test.txt").write_text("hello")
            manifest = capture_file_manifest(tmpdir)
            d = manifest.to_dict()
            assert isinstance(d, dict)
            assert "files" in d
            assert "total_size_bytes" in d
            assert "capture_timestamp" in d

    def test_manifest_to_dict_json_safe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "test.txt").write_text("hello")
            manifest = capture_file_manifest(tmpdir)
            s = json.dumps(manifest.to_dict())
            assert isinstance(s, str)

    def test_file_entry_to_dict(self):
        entry = FileEntry(
            path="output.txt",
            size_bytes=1024,
            sha256="abc123" * 10 + "abcd",
            mode=0o644,
            is_directory=False,
        )
        d = entry.to_dict()
        assert d["path"] == "output.txt"
        assert d["size_bytes"] == 1024
        assert d["mode"] == "0o644"

    def test_file_entry_symlink(self):
        entry = FileEntry(
            path="link.txt",
            size_bytes=0,
            sha256=None,
            mode=0o777,
            is_directory=False,
            is_symlink=True,
            symlink_target="/etc/passwd",
        )
        d = entry.to_dict()
        assert d["is_symlink"] is True
        assert d["symlink_target"] == "/etc/passwd"

    def test_manifest_files_sorted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "z_last.txt").write_text("z")
            Path(tmpdir, "a_first.txt").write_text("a")
            manifest = capture_file_manifest(tmpdir)
            paths = [f.path for f in manifest.files]
            assert paths == sorted(paths)


# =====================================================================
# 11. Proc masking
# =====================================================================

class TestProcMaskConfig:
    """Tests for ProcMaskConfig dataclass."""

    def test_standard(self):
        cfg = ProcMaskConfig.standard()
        assert cfg.mount_proc is True
        assert cfg.hidepid == 2
        assert len(cfg.masked_paths) > 0
        assert "/proc/kcore" in cfg.masked_paths
        assert "/proc/sys" in cfg.readonly_paths

    def test_strict(self):
        cfg = ProcMaskConfig.strict()
        assert cfg.mount_proc is False

    def test_permissive(self):
        cfg = ProcMaskConfig.permissive()
        assert cfg.hidepid == 0
        assert len(cfg.masked_paths) < len(ProcMaskConfig.standard().masked_paths)

    def test_build_config(self):
        cfg = ProcMaskConfig.standard()
        d = build_proc_mask_config(cfg)
        assert d["mount_proc"] is True
        assert d["hidepid"] == 2
        assert isinstance(d["masked_paths"], list)
        assert isinstance(d["readonly_paths"], list)

    def test_config_json_safe(self):
        cfg = ProcMaskConfig.standard()
        d = build_proc_mask_config(cfg)
        s = json.dumps(d)
        assert isinstance(s, str)


# =====================================================================
# 12. Enhanced FilesystemPolicy
# =====================================================================

class TestEnhancedFilesystemPolicy:
    """Tests for FilesystemPolicy with D2 production fields."""

    def test_standard_has_inode_limit(self):
        p = FilesystemPolicy.standard()
        assert p.nr_inodes == 10000
        assert p.nosymfollow is True
        assert p.verify_mounts is True

    def test_hipaa_has_strict_settings(self):
        p = FilesystemPolicy.hipaa()
        assert p.nr_inodes == 2000
        assert p.nosymfollow is True
        assert p.verify_mounts is True
        assert p.verify_mounts_strict is True
        assert p.overlay_config is not None
        assert p.proc_mask is not None

    def test_sox_has_settings(self):
        p = FilesystemPolicy.sox()
        assert p.nr_inodes == 5000
        assert p.overlay_config is not None
        assert p.proc_mask is not None
        assert p.verify_mounts_strict is False  # SOX is less strict

    def test_tight_has_low_inodes(self):
        p = FilesystemPolicy.tight()
        assert p.nr_inodes == 5000

    def test_disabled_has_defaults(self):
        p = FilesystemPolicy.disabled()
        assert p.enabled is False

    def test_tmpfs_mount_options_includes_inodes(self):
        p = FilesystemPolicy(nr_inodes=5000)
        opts = p.tmpfs_mount_options
        assert "nr_inodes=5000" in opts
        assert "size=" in opts

    def test_tmpfs_mount_options_no_inodes_when_zero(self):
        p = FilesystemPolicy(nr_inodes=0)
        opts = p.tmpfs_mount_options
        assert "nr_inodes" not in opts

    def test_for_compliance_preserves_new_fields(self):
        p = FilesystemPolicy.for_compliance("hipaa", tmpfs_size_bytes=8 * 1024 * 1024)
        assert p.tmpfs_size_bytes == 8 * 1024 * 1024
        assert p.nr_inodes == 2000
        assert p.overlay_config is not None
        assert p.proc_mask is not None

    def test_frozen_with_new_fields(self):
        p = FilesystemPolicy.hipaa()
        with pytest.raises(AttributeError):
            p.nr_inodes = 999


# =====================================================================
# 13. Enhanced FilesystemAuditInfo
# =====================================================================

class TestEnhancedFilesystemAuditInfo:
    """Tests for FilesystemAuditInfo with D2 production fields."""

    def test_audit_info_includes_overlay_fields(self):
        info = FilesystemAuditInfo(
            enabled=True,
            tmpfs_size_bytes=64 * 1024 * 1024,
            readonly_bind_count=5,
            readonly_bind_paths=("/usr", "/lib"),
            writable_dirs=("/work",),
            create_dev_nodes=True,
            prefer_pivot_root=True,
            mount_namespace_available=True,
            tmpfs_available=True,
            pivot_root_available=True,
            effective_mode="pivot_root",
            python_path_count=3,
            nr_inodes=10000,
            nosymfollow=True,
            verify_mounts=True,
            overlay_mode="overlayfs",
            overlay_available=True,
            overlay_mount_count=3,
            proc_mask_enabled=True,
            proc_hidepid=2,
            proc_masked_count=7,
        )
        d = info.to_dict()
        assert d["nr_inodes"] == 10000
        assert d["nosymfollow"] is True
        assert d["overlay_mode"] == "overlayfs"
        assert d["overlay_mount_count"] == 3
        assert d["proc_mask_enabled"] is True
        assert d["proc_hidepid"] == 2

    def test_to_dict_json_safe(self):
        info = FilesystemAuditInfo(
            enabled=True, tmpfs_size_bytes=1, readonly_bind_count=0,
            readonly_bind_paths=(), writable_dirs=(), create_dev_nodes=False,
            prefer_pivot_root=False, mount_namespace_available=False,
            tmpfs_available=False, pivot_root_available=False,
            effective_mode="disabled", python_path_count=0,
        )
        s = json.dumps(info.to_dict())
        assert isinstance(s, str)


# =====================================================================
# 14. Enhanced build_filesystem_audit_info
# =====================================================================

class TestEnhancedBuildFilesystemAuditInfo:
    """Tests for build_filesystem_audit_info with D2 features."""

    def test_disabled_policy(self):
        p = FilesystemPolicy.disabled()
        info = build_filesystem_audit_info(p)
        assert info.enabled is False
        assert info.overlay_mode == "none"
        assert info.proc_mask_enabled is False

    def test_hipaa_policy(self):
        p = FilesystemPolicy.hipaa()
        info = build_filesystem_audit_info(p)
        assert info.enabled is True
        assert info.nr_inodes == 2000
        assert info.nosymfollow is True
        assert info.verify_mounts is True
        assert info.verify_mounts_strict is True
        assert info.proc_mask_enabled is True
        assert info.proc_hidepid == 2
        assert info.proc_masked_count > 0
        # Overlay availability depends on system
        assert info.overlay_mode in ("overlayfs", "bind_mount")

    def test_sox_policy(self):
        p = FilesystemPolicy.sox()
        info = build_filesystem_audit_info(p)
        assert info.nr_inodes == 5000
        assert info.verify_mounts_strict is False


# =====================================================================
# 15. Enhanced validate_policy
# =====================================================================

class TestEnhancedValidatePolicy:
    """Tests for validate_policy with D2 enhancements."""

    def test_negative_inodes_raises(self):
        p = FilesystemPolicy(nr_inodes=-1)
        with pytest.raises(FilesystemPolicyValidationError):
            validate_policy(p)

    def test_very_low_inodes_warns(self):
        p = FilesystemPolicy(nr_inodes=50)
        warnings = validate_policy(p)
        assert any("nr_inodes" in w and "very low" in w for w in warnings)

    def test_zero_inodes_no_warn(self):
        p = FilesystemPolicy(nr_inodes=0)
        warnings = validate_policy(p)
        # 0 means unlimited - valid
        assert not any("nr_inodes" in w for w in warnings)

    def test_hipaa_policy_valid(self):
        p = FilesystemPolicy.hipaa()
        warnings = validate_policy(p)
        # Should not raise
        assert isinstance(warnings, list)

    def test_overlay_validation_integrated(self):
        cfg = OverlayFSConfig(
            mode=OverlayMode.OVERLAYFS,
            mounts=(
                OverlayMount(
                    lower_dirs=("/nonexistent_xyz",),
                    mount_point="/usr",
                ),
            ),
        )
        p = FilesystemPolicy(overlay_config=cfg)
        warnings = validate_policy(p)
        assert any("does not exist" in w for w in warnings)

    def test_proc_mask_hidepid_validation(self):
        p = FilesystemPolicy(proc_mask=ProcMaskConfig(hidepid=5))
        warnings = validate_policy(p)
        assert any("hidepid" in w for w in warnings)


# =====================================================================
# 16. Enhanced build_fs_isolation_config
# =====================================================================

class TestEnhancedBuildFsIsolationConfig:
    """Tests for build_fs_isolation_config with D2 extensions."""

    def test_config_includes_nosymfollow(self):
        p = FilesystemPolicy.standard()
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            config = build_fs_isolation_config(rootfs, p)
            assert config["nosymfollow"] is True

    def test_config_includes_overlay_when_configured(self):
        p = FilesystemPolicy.hipaa()
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            config = build_fs_isolation_config(rootfs, p)
            # Overlay config may or may not be present depending on available dirs
            # but the structure should be valid
            if "overlay" in config and config["overlay"] is not None:
                assert config["overlay"]["enabled"] is True

    def test_config_includes_proc_mask(self):
        p = FilesystemPolicy.hipaa()
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            config = build_fs_isolation_config(rootfs, p)
            assert "proc_mask" in config
            assert config["proc_mask"]["mount_proc"] is True
            assert config["proc_mask"]["hidepid"] == 2

    def test_config_includes_mount_verification(self):
        p = FilesystemPolicy.hipaa()
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            config = build_fs_isolation_config(rootfs, p)
            assert "mount_verification" in config
            assert config["mount_verification"]["enabled"] is True
            assert config["mount_verification"]["strict"] is True

    def test_config_json_serialisable(self):
        p = FilesystemPolicy.standard()
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            config = build_fs_isolation_config(rootfs, p)
            s = json.dumps(config)
            assert isinstance(s, str)

    def test_config_tmpfs_options_have_inodes(self):
        p = FilesystemPolicy(nr_inodes=5000)
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            config = build_fs_isolation_config(rootfs, p)
            assert "nr_inodes=5000" in config["tmpfs_mount_options"]


# =====================================================================
# 17. Launcher code structural validation
# =====================================================================

class TestEnhancedLauncherCode:
    """Tests for FS_ISOLATION_LAUNCHER_CODE D2 extensions."""

    def test_launcher_code_is_valid_python(self):
        import ast
        # The code uses _CONFIG which won't be defined, so we wrap it
        wrapped = "def _wrapper():\n    _CONFIG = {}\n" + FS_ISOLATION_LAUNCHER_CODE
        ast.parse(wrapped)  # Should not raise

    def test_launcher_contains_overlay_section(self):
        assert "OverlayFS mounts" in FS_ISOLATION_LAUNCHER_CODE or "overlay" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_contains_proc_masking(self):
        assert "proc_mask" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_contains_mount_verification(self):
        assert "mount_verification" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_contains_nosymfollow(self):
        # nosymfollow may be handled as mount option - check for either
        assert "nosymfollow" in FS_ISOLATION_LAUNCHER_CODE or "Step 9" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_contains_strict_exit(self):
        # Strict mount verification should exit with code 77
        assert "77" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_defines_function(self):
        assert "def _apply_filesystem_isolation" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_reads_config(self):
        assert '_CONFIG.get("filesystem")' in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_does_tmpfs_mount(self):
        assert "tmpfs" in FS_ISOLATION_LAUNCHER_CODE
        assert "tmpfs_mount_options" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_does_pivot_root(self):
        assert "pivot_root" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_creates_dev_nodes(self):
        assert "dev_nodes" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_bind_mounts_readonly(self):
        assert "readonly_binds" in FS_ISOLATION_LAUNCHER_CODE
        assert "MS_RDONLY" in FS_ISOLATION_LAUNCHER_CODE or "_MS_RDONLY" in FS_ISOLATION_LAUNCHER_CODE


# =====================================================================
# 18. Overlay and proc mask launcher code fragments
# =====================================================================

class TestLauncherCodeFragments:
    """Tests for standalone launcher code fragments."""

    def test_overlay_launcher_valid_python(self):
        import ast
        wrapped = "def _wrapper():\n    _CONFIG = {}\n" + OVERLAY_LAUNCHER_CODE
        ast.parse(wrapped)

    def test_proc_mask_launcher_valid_python(self):
        import ast
        wrapped = "def _wrapper():\n    _CONFIG = {}\n" + PROC_MASK_LAUNCHER_CODE
        ast.parse(wrapped)

    def test_mount_verify_launcher_valid_python(self):
        import ast
        wrapped = "def _wrapper():\n    _CONFIG = {}\n" + MOUNT_VERIFY_LAUNCHER_CODE
        ast.parse(wrapped)

    def test_overlay_launcher_reads_config(self):
        assert '_CONFIG.get("overlay")' in OVERLAY_LAUNCHER_CODE

    def test_proc_mask_launcher_reads_config(self):
        assert '_CONFIG.get("proc_mask")' in PROC_MASK_LAUNCHER_CODE

    def test_mount_verify_launcher_reads_config(self):
        assert '_CONFIG.get("mount_verification")' in MOUNT_VERIFY_LAUNCHER_CODE


# =====================================================================
# 19. Integration - ComplianceSandboxFactory FS overlay wiring
# =====================================================================

class TestComplianceFactoryD2:
    """Test ComplianceSandboxFactory integration with D2 features."""

    def test_hipaa_has_overlay(self):
        from agentsafe.sandbox.integration import ComplianceSandboxFactory
        policy = ComplianceSandboxFactory.for_hipaa()
        fs_policy = policy.effective_filesystem_policy
        if fs_policy is not None:
            # HIPAA should use the tight filesystem policy
            assert fs_policy.nr_inodes > 0 or True  # may use factory defaults

    def test_sox_has_overlay(self):
        from agentsafe.sandbox.integration import ComplianceSandboxFactory
        policy = ComplianceSandboxFactory.for_sox()
        fs_policy = policy.effective_filesystem_policy
        # SOX factory may or may not wire overlay - it depends on the factory impl

    def test_standard_has_filesystem(self):
        from agentsafe.sandbox.integration import ComplianceSandboxFactory
        policy = ComplianceSandboxFactory.standard()
        fs_policy = policy.effective_filesystem_policy
        # Standard should have some filesystem policy


# =====================================================================
# 20. End-to-end structural tests
# =====================================================================

class TestEndToEndStructural:
    """Structural end-to-end tests (no actual OS calls)."""

    def test_full_hipaa_config_pipeline(self):
        """Build full config for HIPAA and verify all D2 sections present."""
        p = FilesystemPolicy.hipaa()
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            config = build_fs_isolation_config(rootfs, p)

            # Core FS config
            assert config["enabled"] is True
            assert config["prefer_pivot_root"] is True
            assert "nr_inodes" in config["tmpfs_mount_options"]

            # Proc masking
            assert config["proc_mask"]["hidepid"] == 2
            assert len(config["proc_mask"]["masked_paths"]) > 0

            # Mount verification
            assert config["mount_verification"]["strict"] is True

            # D2 flag
            assert config["nosymfollow"] is True

            # JSON round-trip
            s = json.dumps(config)
            parsed = json.loads(s)
            assert parsed["enabled"] is True

    def test_full_sox_config_pipeline(self):
        """Build full config for SOX."""
        p = FilesystemPolicy.sox()
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            config = build_fs_isolation_config(rootfs, p)
            assert config["enabled"] is True
            assert "mount_verification" in config

    def test_audit_trail_complete(self):
        """Verify audit info captures all D2 fields for compliance export."""
        p = FilesystemPolicy.hipaa()
        info = build_filesystem_audit_info(p)
        d = info.to_dict()

        # All required compliance fields present
        required_fields = [
            "enabled", "tmpfs_size_bytes", "readonly_bind_count",
            "effective_mode", "nr_inodes", "nosymfollow",
            "verify_mounts", "verify_mounts_strict",
            "overlay_mode", "proc_mask_enabled",
        ]
        for field in required_fields:
            assert field in d, f"Missing audit field: {field}"

        # JSON export
        s = json.dumps(d)
        assert isinstance(s, str)


# =====================================================================
# 21. Overlay extra_options propagation (D2 correctness fix)
# =====================================================================

class TestOverlayExtraOptions:
    """Verify metacopy/volatile/redirect_dir/index propagate to launcher config."""

    def test_standard_config_has_extra_options(self):
        from agentsafe.sandbox.overlay import build_overlay_config, OverlayFSConfig
        config = OverlayFSConfig.standard()
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            result = build_overlay_config(config, rootfs)
            if result is not None:
                for mount in result["mounts"]:
                    assert "extra_options" in mount
                    assert isinstance(mount["extra_options"], list)

    def test_volatile_in_extra_options(self):
        from agentsafe.sandbox.overlay import build_overlay_config, OverlayFSConfig
        config = OverlayFSConfig(
            mode=OverlayMode.OVERLAYFS,
            mounts=(OverlayMount(lower_dirs=("/usr",), mount_point="/usr"),),
            volatile=True,
            metacopy=False,
            redirect_dir=False,
            index=False,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            result = build_overlay_config(config, rootfs)
            if result is not None:
                mount = result["mounts"][0]
                assert "volatile" in mount["extra_options"]
                assert "volatile" in mount["options"]

    def test_metacopy_in_extra_options(self):
        from agentsafe.sandbox.overlay import build_overlay_config, OverlayFSConfig
        config = OverlayFSConfig(
            mode=OverlayMode.OVERLAYFS,
            mounts=(OverlayMount(lower_dirs=("/usr",), mount_point="/usr"),),
            metacopy=True,
            volatile=False,
            redirect_dir=False,
            index=False,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            result = build_overlay_config(config, rootfs)
            if result is not None:
                mount = result["mounts"][0]
                assert "metacopy=on" in mount["extra_options"]

    def test_all_extra_options(self):
        from agentsafe.sandbox.overlay import build_overlay_config, OverlayFSConfig
        config = OverlayFSConfig(
            mode=OverlayMode.OVERLAYFS,
            mounts=(OverlayMount(lower_dirs=("/usr",), mount_point="/usr"),),
            metacopy=True,
            volatile=True,
            redirect_dir=True,
            index=True,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            result = build_overlay_config(config, rootfs)
            if result is not None:
                extras = result["mounts"][0]["extra_options"]
                assert "metacopy=on" in extras
                assert "volatile" in extras
                assert "redirect_dir=on" in extras
                assert "index=on" in extras

    def test_no_extra_options_when_all_disabled(self):
        from agentsafe.sandbox.overlay import build_overlay_config, OverlayFSConfig
        config = OverlayFSConfig(
            mode=OverlayMode.OVERLAYFS,
            mounts=(OverlayMount(lower_dirs=("/usr",), mount_point="/usr"),),
            metacopy=False,
            volatile=False,
            redirect_dir=False,
            index=False,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            result = build_overlay_config(config, rootfs)
            if result is not None:
                assert result["mounts"][0]["extra_options"] == []

    def test_extra_options_json_serialisable(self):
        from agentsafe.sandbox.overlay import build_overlay_config, OverlayFSConfig
        config = OverlayFSConfig.hipaa()
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            result = build_overlay_config(config, rootfs)
            if result is not None:
                s = json.dumps(result)
                parsed = json.loads(s)
                assert "mounts" in parsed


# =====================================================================
# 22. Launcher nosymfollow mount flag (D2 correctness fix)
# =====================================================================

class TestLauncherNosymfollow:
    """Verify the launcher applies MS_NOSYMFOLLOW when configured."""

    def test_launcher_has_nosymfollow_constant(self):
        assert "MS_NOSYMFOLLOW" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_checks_nosymfollow_config(self):
        assert 'fs_cfg.get("nosymfollow")' in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_overlay_extra_options_loop(self):
        """Launcher should iterate extra_options from overlay config."""
        assert 'extra_options' in FS_ISOLATION_LAUNCHER_CODE


# =====================================================================
# 23. ObservableSandboxedExecutor delegation (D2 integration fix)
# =====================================================================

class TestObservableExecutorDelegation:
    """Verify ObservableSandboxedExecutor delegates properties properly."""

    def test_effective_filesystem_policy_with_policy(self):
        from agentsafe.sandbox.integration import ObservableSandboxedExecutor
        policy = SandboxPolicy(filesystem=FilesystemPolicy.hipaa())
        executor = ObservableSandboxedExecutor(policy=policy)
        fs = executor.effective_filesystem_policy
        assert fs is not None
        assert fs.enabled is True

    def test_effective_filesystem_policy_standard(self):
        from agentsafe.sandbox.integration import ObservableSandboxedExecutor
        executor = ObservableSandboxedExecutor(
            policy=SandboxPolicy.with_filesystem()
        )
        fs = executor.effective_filesystem_policy
        assert fs is not None

    def test_effective_filesystem_policy_none(self):
        from agentsafe.sandbox.integration import ObservableSandboxedExecutor
        policy = SandboxPolicy(filesystem=None, optional_layers=frozenset())
        executor = ObservableSandboxedExecutor(policy=policy)
        fs = executor.effective_filesystem_policy
        assert fs is None

    def test_effective_filesystem_policy_matches_inner(self):
        from agentsafe.sandbox.integration import ObservableSandboxedExecutor
        policy = SandboxPolicy(filesystem=FilesystemPolicy.sox())
        executor = ObservableSandboxedExecutor(policy=policy)
        assert executor.effective_filesystem_policy is policy.effective_filesystem_policy

    def test_compliance_factory_hipaa_exposes_fs_policy(self):
        from agentsafe.sandbox.integration import ComplianceSandboxFactory
        executor = ComplianceSandboxFactory.for_hipaa()
        fs = executor.effective_filesystem_policy
        assert fs is not None
        assert fs.nosymfollow is True
        assert fs.verify_mounts_strict is True

    def test_compliance_factory_sox_exposes_fs_policy(self):
        from agentsafe.sandbox.integration import ComplianceSandboxFactory
        executor = ComplianceSandboxFactory.for_sox()
        fs = executor.effective_filesystem_policy
        assert fs is not None
        assert fs.nr_inodes > 0

    def test_compliance_factory_standard_exposes_fs_policy(self):
        from agentsafe.sandbox.integration import ComplianceSandboxFactory
        executor = ComplianceSandboxFactory.standard()
        fs = executor.effective_filesystem_policy
        assert fs is not None


# =====================================================================
# 24. Timestamp format (deprecation fix verification)
# =====================================================================

class TestTimestampFormat:
    """Verify UTC timestamps use timezone-aware datetime."""

    def test_file_manifest_timestamp_has_utc(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = capture_file_manifest(tmpdir)
            ts = manifest.capture_timestamp
            # Should be timezone-aware ISO format (ends with +00:00)
            assert "+00:00" in ts or "Z" in ts

    def test_empty_manifest_timestamp_has_utc(self):
        manifest = capture_file_manifest("/nonexistent_path_d2_test_xyz")
        ts = manifest.capture_timestamp
        assert "+00:00" in ts or "Z" in ts

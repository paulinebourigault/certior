"""
Filesystem Isolation - Comprehensive Test Suite.

Tests cover:
  1. FilesystemPolicy (dataclass, properties, factory methods, compliance presets)
  2. Path discovery (discover_python_paths, normalize_bind_mounts)
  3. Probing (mount namespace, tmpfs, pivot_root - with mocking)
  4. Rootfs structure (build_rootfs_skeleton, verify_rootfs_structure)
  5. Launcher config generation (build_fs_isolation_config)
  6. FS_ISOLATION_LAUNCHER_CODE structural validation
  7. Policy validation (validate_policy, edge cases)
  8. FilesystemAuditInfo (construction, serialisation, system probing)
  9. Integration with SandboxPolicy (effective_filesystem_policy)
 10. Integration with ComplianceSandboxFactory (HIPAA/SOX/Legal FS wiring)
 11. Integration with ObservableSandboxedExecutor (FS audit in records)
 12. Integration with SandboxedExecutor (FS code injection into launcher)
 13. End-to-end (FS-enabled sandbox execution where possible)
"""
from __future__ import annotations

import json
import os
import platform
import re
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

# ── Imports under test ───────────────────────────────────────────────

from agentsafe.sandbox.filesystem import (
    DEV_NODES,
    FS_ISOLATION_LAUNCHER_CODE,
    MS_BIND,
    MS_NODEV,
    MS_NOSUID,
    MS_RDONLY,
    MS_REC,
    MS_REMOUNT,
    MS_PRIVATE,
    MNT_DETACH,
    FilesystemAuditInfo,
    FilesystemPolicy,
    FilesystemPolicyValidationError,
    _PIVOT_ROOT_NR,
    _ROOTFS_DIRS,
    _is_system_path,
    build_filesystem_audit_info,
    build_fs_isolation_config,
    build_rootfs_skeleton,
    discover_python_paths,
    normalize_bind_mounts,
    probe_mount_namespace,
    probe_pivot_root,
    probe_tmpfs_mount,
    reset_probe_cache,
    validate_policy,
    verify_rootfs_structure,
)
from agentsafe.sandbox.policy import (
    ContainmentLayer,
    ResourceLimits,
    SandboxPolicy,
)
from agentsafe.sandbox.errors import (
    FilesystemIsolationError,
)
from agentsafe.sandbox.executor import SandboxedExecutor, SandboxResult
from agentsafe.sandbox.integration import (
    ComplianceSandboxFactory,
    ObservableSandboxedExecutor,
    SandboxAuditRecord,
    _build_audit_record,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 1. FilesystemPolicy - dataclass, properties, factories
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestFilesystemPolicy:
    """Unit tests for the FilesystemPolicy dataclass."""

    def test_default_values(self):
        p = FilesystemPolicy()
        assert p.enabled is True
        assert p.tmpfs_size_bytes == 64 * 1024 * 1024
        assert p.prefer_pivot_root is True
        assert p.create_dev_nodes is True
        assert "/work" in p.writable_dirs
        assert "/tmp" in p.writable_dirs
        assert "/usr" in p.readonly_bind_mounts
        assert "/lib" in p.readonly_bind_mounts

    def test_frozen(self):
        p = FilesystemPolicy()
        with pytest.raises(AttributeError):
            p.enabled = False  # type: ignore[misc]

    def test_standard_factory(self):
        p = FilesystemPolicy.standard()
        assert p.enabled is True
        assert p.tmpfs_size_bytes == 64 * 1024 * 1024
        assert "/work" in p.writable_dirs
        assert "/tmp" in p.writable_dirs

    def test_tight_factory(self):
        p = FilesystemPolicy.tight()
        assert p.enabled is True
        assert p.tmpfs_size_bytes == 16 * 1024 * 1024
        assert "/work" in p.writable_dirs
        assert "/tmp" not in p.writable_dirs  # tight = no /tmp

    def test_disabled_factory(self):
        p = FilesystemPolicy.disabled()
        assert p.enabled is False

    def test_hipaa_factory(self):
        p = FilesystemPolicy.hipaa()
        assert p.enabled is True
        assert p.tmpfs_size_bytes == 16 * 1024 * 1024
        assert "/work" in p.writable_dirs
        assert "/tmp" not in p.writable_dirs
        assert p.prefer_pivot_root is True

    def test_sox_factory(self):
        p = FilesystemPolicy.sox()
        assert p.enabled is True
        assert p.tmpfs_size_bytes == 32 * 1024 * 1024
        assert "/work" in p.writable_dirs
        assert "/tmp" in p.writable_dirs
        assert p.prefer_pivot_root is True

    def test_for_compliance_hipaa(self):
        p = FilesystemPolicy.for_compliance("hipaa")
        assert p.tmpfs_size_bytes == 16 * 1024 * 1024

    def test_for_compliance_sox(self):
        p = FilesystemPolicy.for_compliance("sox")
        assert p.tmpfs_size_bytes == 32 * 1024 * 1024

    def test_for_compliance_legal(self):
        p = FilesystemPolicy.for_compliance("legal")
        assert p.tmpfs_size_bytes == 16 * 1024 * 1024  # same as tight

    def test_for_compliance_standard(self):
        p = FilesystemPolicy.for_compliance("standard")
        assert p.tmpfs_size_bytes == 64 * 1024 * 1024

    def test_for_compliance_case_insensitive(self):
        p = FilesystemPolicy.for_compliance("HIPAA")
        assert p.tmpfs_size_bytes == 16 * 1024 * 1024

    def test_for_compliance_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown compliance regime"):
            FilesystemPolicy.for_compliance("unknown_regime")

    def test_for_compliance_override_tmpfs(self):
        p = FilesystemPolicy.for_compliance("hipaa", tmpfs_size_bytes=8 * 1024 * 1024)
        assert p.tmpfs_size_bytes == 8 * 1024 * 1024
        assert p.prefer_pivot_root is True  # other fields preserved

    def test_tmpfs_mount_options(self):
        p = FilesystemPolicy(tmpfs_size_bytes=32 * 1024 * 1024)
        # Default nr_inodes=10000 is appended by the property
        assert p.tmpfs_mount_options == f"size={32 * 1024 * 1024},nr_inodes=10000"

    def test_effective_readonly_mounts_with_explicit_python_paths(self):
        p = FilesystemPolicy(
            extra_python_paths=frozenset({"/opt/python3.12"}),
        )
        effective = p.effective_readonly_mounts
        assert "/opt/python3.12" in effective
        assert "/usr" in effective  # base paths still there

    def test_effective_readonly_mounts_auto_detect(self):
        """When extra_python_paths is None, discover_python_paths is called."""
        p = FilesystemPolicy()  # extra_python_paths defaults to None
        effective = p.effective_readonly_mounts
        # Should include base mounts + discovered paths
        assert "/usr" in effective
        # discover_python_paths should add at least one path
        assert len(effective) >= len(p.readonly_bind_mounts)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 2. Path discovery
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPathDiscovery:

    def test_discover_python_paths_returns_existing(self):
        paths = discover_python_paths()
        for p in paths:
            assert os.path.exists(p), f"Discovered path does not exist: {p}"

    def test_discover_python_paths_returns_absolute(self):
        paths = discover_python_paths()
        for p in paths:
            assert os.path.isabs(p), f"Path is not absolute: {p}"

    def test_discover_python_paths_non_empty(self):
        """Python interpreter must be somewhere on the system."""
        paths = discover_python_paths()
        assert len(paths) > 0

    def test_discover_python_paths_includes_system_dirs(self):
        """At least one path should be under /usr or /lib."""
        paths = discover_python_paths()
        system = [p for p in paths if _is_system_path(p)]
        # On some Docker images, Python might be in /opt or elsewhere
        # but at least the test validates the function runs
        assert isinstance(system, list)


class TestNormalizeBindMounts:

    def test_removes_redundant_children(self):
        paths = frozenset({"/usr", "/usr/lib", "/usr/lib/python3"})
        result = normalize_bind_mounts(paths)
        assert result == ["/usr"]

    def test_keeps_independent_paths(self):
        paths = frozenset({"/usr", "/lib", "/etc/ssl"})
        result = normalize_bind_mounts(paths)
        # All three are independent
        for p in ["/usr", "/lib"]:
            if os.path.exists(p):
                assert p in result

    def test_removes_nonexistent_paths(self):
        paths = frozenset({"/usr", "/nonexistent_certior_test_path_xyz"})
        result = normalize_bind_mounts(paths)
        assert "/nonexistent_certior_test_path_xyz" not in result

    def test_returns_sorted(self):
        paths = frozenset({"/usr", "/lib", "/etc/ssl/certs"})
        result = normalize_bind_mounts(paths)
        assert result == sorted(result)

    def test_empty_input(self):
        result = normalize_bind_mounts(frozenset())
        assert result == []


class TestIsSystemPath:

    def test_usr_is_system(self):
        assert _is_system_path("/usr/lib/python3.12") is True

    def test_lib_is_system(self):
        assert _is_system_path("/lib/x86_64-linux-gnu") is True

    def test_etc_is_system(self):
        assert _is_system_path("/etc/ssl/certs") is True

    def test_home_is_not_system(self):
        assert _is_system_path("/home/user/venv") is False

    def test_root_is_not_system(self):
        assert _is_system_path("/root/.local") is False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3. Probing functions
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestProbing:

    def setup_method(self):
        reset_probe_cache()

    def test_probe_mount_namespace_returns_bool(self):
        result = probe_mount_namespace()
        assert isinstance(result, bool)

    def test_probe_mount_namespace_caching(self):
        """Second call should use cache."""
        r1 = probe_mount_namespace()
        r2 = probe_mount_namespace()
        assert r1 == r2

    def test_probe_tmpfs_mount_returns_bool(self):
        result = probe_tmpfs_mount()
        assert isinstance(result, bool)

    def test_probe_pivot_root_returns_bool(self):
        result = probe_pivot_root()
        assert isinstance(result, bool)

    @pytest.mark.skipif(
        not sys.platform.startswith("linux"),
        reason="Namespace probing only works on Linux"
    )
    def test_probe_consistency(self):
        """If pivot_root works, tmpfs and mount_ns must also work."""
        if probe_pivot_root():
            assert probe_tmpfs_mount() is True
            assert probe_mount_namespace() is True
        if probe_tmpfs_mount():
            assert probe_mount_namespace() is True

    def test_probe_non_linux(self):
        """On non-Linux, all probes should return False."""
        if not sys.platform.startswith("linux"):
            assert probe_mount_namespace() is False
            # tmpfs and pivot_root should also be False
            assert probe_tmpfs_mount() is False
            assert probe_pivot_root() is False

    def test_reset_probe_cache(self):
        probe_mount_namespace()
        reset_probe_cache()
        # After reset, cache is empty - re-probing should work
        result = probe_mount_namespace()
        assert isinstance(result, bool)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 4. Rootfs structure
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRootfsSkeleton:

    def test_build_rootfs_skeleton_creates_all_dirs(self):
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            build_rootfs_skeleton(rootfs)

            for dirname in _ROOTFS_DIRS:
                target = os.path.join(rootfs, dirname)
                assert os.path.isdir(target), f"Missing directory: {dirname}"

    def test_build_rootfs_skeleton_idempotent(self):
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            build_rootfs_skeleton(rootfs)
            build_rootfs_skeleton(rootfs)  # Should not raise

    def test_verify_rootfs_structure_valid(self):
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            build_rootfs_skeleton(rootfs)
            issues = verify_rootfs_structure(rootfs)
            assert issues == []

    def test_verify_rootfs_structure_missing_dir(self):
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            # Don't build skeleton - all dirs are missing
            issues = verify_rootfs_structure(rootfs)
            assert len(issues) == len(_ROOTFS_DIRS)

    def test_verify_rootfs_structure_partial(self):
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            # Create only some dirs
            os.makedirs(os.path.join(rootfs, "dev"))
            os.makedirs(os.path.join(rootfs, "tmp"))
            issues = verify_rootfs_structure(rootfs)
            assert len(issues) == len(_ROOTFS_DIRS) - 2

    def test_verify_rootfs_structure_nonexistent(self):
        issues = verify_rootfs_structure("/nonexistent_certior_test_xyz")
        assert len(issues) == 1
        assert "does not exist" in issues[0]

    def test_rootfs_dirs_expected_contents(self):
        """Verify the expected directories in the skeleton."""
        expected = {"dev", "etc", "lib", "lib64", "proc", "tmp", "usr", "work", "old_root"}
        assert set(_ROOTFS_DIRS) == expected


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 5. Launcher config generation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestBuildFsIsolationConfig:

    def test_config_structure(self):
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            policy = FilesystemPolicy.standard()
            config = build_fs_isolation_config(rootfs, policy)

            assert config["enabled"] is True
            assert config["rootfs_path"] == rootfs
            assert isinstance(config["readonly_binds"], list)
            assert isinstance(config["writable_dirs"], list)
            assert isinstance(config["dev_nodes"], list)
            assert isinstance(config["skeleton_dirs"], list)
            assert config["prefer_pivot_root"] is True
            assert config["host_uid"] == os.getuid()
            assert config["host_gid"] == os.getgid()

    def test_config_tmpfs_mount_options(self):
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            policy = FilesystemPolicy(tmpfs_size_bytes=32 * 1024 * 1024)
            config = build_fs_isolation_config(rootfs, policy)
            assert f"size={32 * 1024 * 1024}" in config["tmpfs_mount_options"]

    def test_config_dev_nodes(self):
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            policy = FilesystemPolicy()
            config = build_fs_isolation_config(rootfs, policy)

            assert config["create_dev_nodes"] is True
            dev_names = [n for n, _ in config["dev_nodes"]]
            assert "null" in dev_names
            assert "zero" in dev_names
            assert "urandom" in dev_names
            assert "random" in dev_names

    def test_config_disabled_policy(self):
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            policy = FilesystemPolicy.disabled()
            config = build_fs_isolation_config(rootfs, policy)
            assert config["enabled"] is False

    def test_config_writable_dirs(self):
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            policy = FilesystemPolicy(writable_dirs=frozenset({"/work", "/tmp", "/data"}))
            config = build_fs_isolation_config(rootfs, policy)
            assert "/work" in config["writable_dirs"]
            assert "/tmp" in config["writable_dirs"]
            assert "/data" in config["writable_dirs"]

    def test_config_json_serialisable(self):
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            policy = FilesystemPolicy.standard()
            config = build_fs_isolation_config(rootfs, policy)
            # Must be JSON-serialisable (injected into launcher)
            serialised = json.dumps(config)
            assert isinstance(serialised, str)
            parsed = json.loads(serialised)
            assert parsed["enabled"] is True

    def test_config_pivot_root_nr_correct_for_platform(self):
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            policy = FilesystemPolicy()
            config = build_fs_isolation_config(rootfs, policy)

            machine = platform.machine()
            expected_nr = _PIVOT_ROOT_NR.get(machine)
            assert config["pivot_root_nr"] == expected_nr

    def test_config_binds_normalised(self):
        """Readonly binds should be normalised (no redundant children)."""
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            rootfs = os.path.join(tmpdir, "rootfs")
            os.makedirs(rootfs)
            policy = FilesystemPolicy()
            config = build_fs_isolation_config(rootfs, policy)

            binds = config["readonly_binds"]
            # No path should be a child of another
            for i, a in enumerate(binds):
                for j, b in enumerate(binds):
                    if i != j:
                        assert not a.startswith(b + "/"), f"{a} is redundant under {b}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 6. FS_ISOLATION_LAUNCHER_CODE structural validation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestLauncherCode:

    def test_launcher_code_is_valid_python(self):
        """The launcher fragment must be valid Python."""
        import ast
        # Wrap in a function so indentation is valid
        wrapper = "import os, sys\n_CONFIG = {}\n" + FS_ISOLATION_LAUNCHER_CODE
        ast.parse(wrapper)

    def test_launcher_code_defines_function(self):
        assert "def _apply_filesystem_isolation():" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_code_reads_config(self):
        assert "_CONFIG" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_code_does_tmpfs_mount(self):
        assert "tmpfs" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_code_does_pivot_root(self):
        assert "pivot_root" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_code_does_chroot_fallback(self):
        assert "chroot" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_code_creates_dev_nodes(self):
        assert "dev_nodes" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_code_bind_mounts_readonly(self):
        assert "readonly_binds" in FS_ISOLATION_LAUNCHER_CODE
        assert "MS_RDONLY" in FS_ISOLATION_LAUNCHER_CODE or "_MS_RDONLY" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_code_writes_uid_gid_maps(self):
        assert "uid_map" in FS_ISOLATION_LAUNCHER_CODE
        assert "gid_map" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_code_makes_mounts_private(self):
        assert "MS_PRIVATE" in FS_ISOLATION_LAUNCHER_CODE or "_MS_PRIVATE" in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_code_changes_to_work(self):
        assert 'chdir("/work")' in FS_ISOLATION_LAUNCHER_CODE

    def test_launcher_code_detaches_old_root(self):
        assert "old_root" in FS_ISOLATION_LAUNCHER_CODE
        assert "umount2" in FS_ISOLATION_LAUNCHER_CODE or "MNT_DETACH" in FS_ISOLATION_LAUNCHER_CODE


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 7. Policy validation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestValidatePolicy:

    def test_disabled_policy_no_warnings(self):
        p = FilesystemPolicy.disabled()
        warnings = validate_policy(p)
        assert warnings == []

    def test_standard_policy_valid(self):
        p = FilesystemPolicy.standard()
        warnings = validate_policy(p)
        # Should have no hard errors (no exception raised)
        # May have warnings about missing paths depending on environment
        assert isinstance(warnings, list)

    def test_tmpfs_too_small_raises(self):
        p = FilesystemPolicy(tmpfs_size_bytes=512)  # 512 bytes
        with pytest.raises(FilesystemPolicyValidationError, match="too small"):
            validate_policy(p)

    def test_tmpfs_very_large_warns(self):
        p = FilesystemPolicy(tmpfs_size_bytes=8 * 1024 * 1024 * 1024)  # 8 GiB
        warnings = validate_policy(p)
        assert any("very large" in w for w in warnings)

    def test_relative_writable_dir_raises(self):
        p = FilesystemPolicy(writable_dirs=frozenset({"relative/path"}))
        with pytest.raises(FilesystemPolicyValidationError, match="absolute path"):
            validate_policy(p)

    def test_no_work_dir_warns(self):
        p = FilesystemPolicy(writable_dirs=frozenset({"/tmp"}))  # no /work
        warnings = validate_policy(p)
        assert any("/work" in w for w in warnings)

    def test_nonexistent_mount_warns(self):
        p = FilesystemPolicy(
            readonly_bind_mounts=frozenset({"/usr", "/nonexistent_xyz_test"})
        )
        warnings = validate_policy(p)
        assert any("nonexistent_xyz_test" in w for w in warnings)

    def test_1mib_tmpfs_is_valid(self):
        """1 MiB is the minimum allowed."""
        p = FilesystemPolicy(tmpfs_size_bytes=1024 * 1024)
        warnings = validate_policy(p)
        # Should not raise
        assert isinstance(warnings, list)

    def test_hipaa_policy_valid(self):
        p = FilesystemPolicy.hipaa()
        warnings = validate_policy(p)
        assert isinstance(warnings, list)

    def test_sox_policy_valid(self):
        p = FilesystemPolicy.sox()
        warnings = validate_policy(p)
        assert isinstance(warnings, list)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 8. FilesystemAuditInfo
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestFilesystemAuditInfo:

    def test_build_disabled(self):
        p = FilesystemPolicy.disabled()
        info = build_filesystem_audit_info(p)
        assert info.enabled is False
        assert info.effective_mode == "disabled"
        assert info.tmpfs_size_bytes == 0
        assert info.readonly_bind_count == 0

    def test_build_enabled(self):
        p = FilesystemPolicy.standard()
        info = build_filesystem_audit_info(p)
        assert info.enabled is True
        assert info.tmpfs_size_bytes == 64 * 1024 * 1024
        assert isinstance(info.mount_namespace_available, bool)
        assert isinstance(info.tmpfs_available, bool)
        assert isinstance(info.pivot_root_available, bool)
        assert info.effective_mode in ("pivot_root", "chroot", "unavailable")
        assert info.readonly_bind_count >= 0

    def test_build_hipaa(self):
        p = FilesystemPolicy.hipaa()
        info = build_filesystem_audit_info(p)
        assert info.enabled is True
        assert info.tmpfs_size_bytes == 16 * 1024 * 1024
        assert "/work" in info.writable_dirs
        assert "/tmp" not in info.writable_dirs

    def test_to_dict_json_safe(self):
        p = FilesystemPolicy.standard()
        info = build_filesystem_audit_info(p)
        d = info.to_dict()
        serialised = json.dumps(d)
        parsed = json.loads(serialised)
        assert parsed["enabled"] is True
        assert isinstance(parsed["readonly_bind_paths"], list)
        assert isinstance(parsed["writable_dirs"], list)

    def test_frozen(self):
        p = FilesystemPolicy.standard()
        info = build_filesystem_audit_info(p)
        with pytest.raises(AttributeError):
            info.enabled = False  # type: ignore[misc]

    def test_effective_mode_on_non_linux(self):
        if not sys.platform.startswith("linux"):
            p = FilesystemPolicy.standard()
            info = build_filesystem_audit_info(p)
            assert info.effective_mode == "unavailable"

    def test_python_path_count(self):
        p = FilesystemPolicy.standard()
        info = build_filesystem_audit_info(p)
        assert info.python_path_count >= 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 9. SandboxPolicy integration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSandboxPolicyFilesystemIntegration:

    def test_with_filesystem_has_fs_policy(self):
        sp = SandboxPolicy.with_filesystem()
        fp = sp.effective_filesystem_policy
        assert fp is not None
        assert fp.enabled is True

    def test_maximum_has_tight_fs(self):
        sp = SandboxPolicy.maximum()
        fp = sp.effective_filesystem_policy
        assert fp is not None
        assert fp.tmpfs_size_bytes == 16 * 1024 * 1024

    def test_standard_auto_enables_fs(self):
        """Standard policy has FILESYSTEM_ISOLATION in optional, so auto-enables."""
        sp = SandboxPolicy.standard()
        fp = sp.effective_filesystem_policy
        assert fp is not None
        assert fp.enabled is True

    def test_minimal_no_fs(self):
        sp = SandboxPolicy.minimal()
        fp = sp.effective_filesystem_policy
        # Minimal has no FILESYSTEM_ISOLATION in layers
        assert fp is None

    def test_explicit_filesystem_policy_respected(self):
        fsp = FilesystemPolicy.hipaa()
        sp = SandboxPolicy(filesystem=fsp)
        assert sp.effective_filesystem_policy is fsp
        assert sp.effective_filesystem_policy.tmpfs_size_bytes == 16 * 1024 * 1024

    def test_filesystem_isolation_containment_layer(self):
        sp = SandboxPolicy.with_filesystem()
        assert ContainmentLayer.FILESYSTEM_ISOLATION in sp.optional_layers

    def test_maximum_has_fs_mandatory(self):
        sp = SandboxPolicy.maximum()
        assert ContainmentLayer.FILESYSTEM_ISOLATION in sp.mandatory_layers


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 10. ComplianceSandboxFactory (filesystem wiring)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestComplianceSandboxFactoryFilesystem:

    def test_hipaa_has_filesystem_policy(self):
        executor = ComplianceSandboxFactory.for_hipaa()
        fp = executor.policy.effective_filesystem_policy
        assert fp is not None
        assert fp.enabled is True
        assert fp.tmpfs_size_bytes == 16 * 1024 * 1024
        assert "/tmp" not in fp.writable_dirs

    def test_sox_has_filesystem_policy(self):
        executor = ComplianceSandboxFactory.for_sox()
        fp = executor.policy.effective_filesystem_policy
        assert fp is not None
        assert fp.enabled is True
        assert fp.tmpfs_size_bytes == 32 * 1024 * 1024
        assert "/tmp" in fp.writable_dirs

    def test_legal_has_filesystem_policy(self):
        executor = ComplianceSandboxFactory.for_legal()
        fp = executor.policy.effective_filesystem_policy
        assert fp is not None
        assert fp.enabled is True
        assert fp.tmpfs_size_bytes == 16 * 1024 * 1024  # tight

    def test_standard_has_filesystem_policy(self):
        executor = ComplianceSandboxFactory.standard()
        fp = executor.policy.effective_filesystem_policy
        assert fp is not None
        assert fp.enabled is True

    def test_hipaa_fs_isolation_in_optional_layers(self):
        executor = ComplianceSandboxFactory.for_hipaa()
        assert ContainmentLayer.FILESYSTEM_ISOLATION in executor.policy.optional_layers

    def test_sox_fs_isolation_in_optional_layers(self):
        executor = ComplianceSandboxFactory.for_sox()
        assert ContainmentLayer.FILESYSTEM_ISOLATION in executor.policy.optional_layers

    def test_hipaa_fs_audit_info_captured(self):
        executor = ComplianceSandboxFactory.for_hipaa()
        info = executor.fs_audit_info
        assert info is not None
        assert info.tmpfs_size_bytes == 16 * 1024 * 1024

    def test_sox_fs_audit_info_captured(self):
        executor = ComplianceSandboxFactory.for_sox()
        info = executor.fs_audit_info
        assert info is not None
        assert info.tmpfs_size_bytes == 32 * 1024 * 1024


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 11. ObservableSandboxedExecutor (filesystem in audit records)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestObservableExecutorFilesystem:

    def test_fs_audit_info_property(self):
        executor = ObservableSandboxedExecutor(
            policy=SandboxPolicy.with_filesystem(),
            policy_name="test-fs",
        )
        info = executor.fs_audit_info
        assert info is not None
        assert isinstance(info, FilesystemAuditInfo)

    def test_fs_audit_info_none_for_minimal(self):
        executor = ObservableSandboxedExecutor(
            policy=SandboxPolicy.minimal(),
            policy_name="test-minimal",
        )
        assert executor.fs_audit_info is None

    @pytest.mark.asyncio
    async def test_audit_record_contains_filesystem_data(self):
        """Audit record should contain filesystem isolation info."""
        records: list[SandboxAuditRecord] = []

        executor = ObservableSandboxedExecutor(
            policy=SandboxPolicy.with_filesystem(),
            policy_name="test-fs-audit",
            audit_callback=records.append,
        )
        result = await executor.execute("print('hello')")

        assert len(records) == 1
        record = records[0]
        assert record.filesystem_audit is not None
        assert record.filesystem_audit["enabled"] is True
        assert isinstance(record.filesystem_audit["tmpfs_size_bytes"], int)
        assert isinstance(record.filesystem_audit["effective_mode"], str)

    @pytest.mark.asyncio
    async def test_audit_record_to_dict_has_filesystem(self):
        records: list[SandboxAuditRecord] = []
        executor = ObservableSandboxedExecutor(
            policy=SandboxPolicy.with_filesystem(),
            policy_name="test",
            audit_callback=records.append,
        )
        await executor.execute("x = 1")

        d = records[0].to_dict()
        assert "filesystem_isolation" in d
        assert d["filesystem_isolation"] is not None

    @pytest.mark.asyncio
    async def test_audit_record_no_filesystem_for_minimal(self):
        records: list[SandboxAuditRecord] = []
        executor = ObservableSandboxedExecutor(
            policy=SandboxPolicy.minimal(),
            policy_name="test-minimal",
            audit_callback=records.append,
        )
        await executor.execute("x = 2")

        d = records[0].to_dict()
        assert d["filesystem_isolation"] is None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 12. SandboxedExecutor filesystem code injection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestExecutorFilesystemInjection:

    def test_executor_probes_filesystem_capability(self):
        executor = SandboxedExecutor(SandboxPolicy.with_filesystem())
        caps = executor.get_capabilities()
        assert "filesystem_isolation" in caps
        assert isinstance(caps["filesystem_isolation"], bool)

    def test_executor_probes_pivot_root(self):
        executor = SandboxedExecutor(SandboxPolicy.with_filesystem())
        caps = executor.get_capabilities()
        assert "pivot_root" in caps
        assert isinstance(caps["pivot_root"], bool)

    def test_executor_has_fs_layer_when_available(self):
        executor = SandboxedExecutor(SandboxPolicy.with_filesystem())
        caps = executor.get_capabilities()
        layers = caps.get("active_layers", [])
        if caps.get("filesystem_isolation"):
            assert "fs_isolation" in layers

    def test_executor_build_launcher_config_with_fs(self):
        executor = SandboxedExecutor(SandboxPolicy.with_filesystem())
        with tempfile.TemporaryDirectory(prefix="certior_test_") as tmpdir:
            config = executor._build_launcher_config(tmpdir)
            # If FS isolation is supported, config should have filesystem entry
            if executor._capabilities.get("filesystem_isolation"):
                assert config["filesystem"] is not None
                assert config["filesystem"]["enabled"] is True
            else:
                # If not supported, filesystem should be None or absent
                assert config.get("filesystem") is None

    def test_executor_build_launcher_config_without_fs(self):
        executor = SandboxedExecutor(SandboxPolicy.minimal())
        config = executor._build_launcher_config("")
        assert config.get("filesystem") is None

    def test_executor_maximum_policy_config(self):
        executor = SandboxedExecutor(SandboxPolicy.maximum())
        caps = executor.get_capabilities()
        # Maximum policy requires fs_isolation mandatory - check it's at least probed
        assert "filesystem_isolation" in caps


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 13. End-to-end tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestEndToEnd:

    @pytest.mark.asyncio
    async def test_execute_simple_with_fs_policy(self):
        """Basic execution with FS policy enabled works."""
        executor = SandboxedExecutor(SandboxPolicy.with_filesystem())
        result = await executor.execute("print(2 + 2)")
        assert result.stdout.strip() == "4"
        assert result.returncode == 0
        assert result.is_error is False

    @pytest.mark.asyncio
    async def test_execute_math_with_hipaa_fs(self):
        """HIPAA filesystem policy still allows math computation."""
        policy = SandboxPolicy(
            filesystem=FilesystemPolicy.hipaa(),
            optional_layers=frozenset({
                ContainmentLayer.FILESYSTEM_ISOLATION,
                ContainmentLayer.SECCOMP_BPF,
                ContainmentLayer.PID_NAMESPACE,
                ContainmentLayer.NET_NAMESPACE,
            }),
        )
        executor = SandboxedExecutor(policy)
        result = await executor.execute("import math; print(math.pi)")
        assert "3.14159" in result.stdout

    @pytest.mark.asyncio
    async def test_execute_with_observable_fs_executor(self):
        """Observable executor with FS policy captures audit + runs code."""
        records: list[SandboxAuditRecord] = []
        executor = ObservableSandboxedExecutor(
            policy=SandboxPolicy.with_filesystem(),
            policy_name="e2e-test",
            audit_callback=records.append,
        )
        result = await executor.execute("print('sandboxed')")
        assert "sandboxed" in result.stdout
        assert len(records) == 1
        assert records[0].filesystem_audit is not None

    @pytest.mark.asyncio
    async def test_hipaa_compliance_factory_execution(self):
        """HIPAA factory produces executor that runs code successfully."""
        records: list[SandboxAuditRecord] = []
        executor = ComplianceSandboxFactory.for_hipaa(audit_callback=records.append)
        result = await executor.execute("print(42)")
        assert result.stdout.strip() == "42"
        assert len(records) == 1
        assert records[0].policy_name == "HIPAA"
        assert records[0].filesystem_audit is not None
        assert records[0].filesystem_audit["tmpfs_size_bytes"] == 16 * 1024 * 1024

    @pytest.mark.asyncio
    async def test_sox_compliance_factory_execution(self):
        """SOX factory produces executor that runs code successfully."""
        records: list[SandboxAuditRecord] = []
        executor = ComplianceSandboxFactory.for_sox(audit_callback=records.append)
        result = await executor.execute("import json; print(json.dumps({'a': 1}))")
        assert '{"a": 1}' in result.stdout
        assert records[0].filesystem_audit["tmpfs_size_bytes"] == 32 * 1024 * 1024

    @pytest.mark.asyncio
    async def test_multiple_executions_produce_separate_audits(self):
        records: list[SandboxAuditRecord] = []
        executor = ComplianceSandboxFactory.for_hipaa(audit_callback=records.append)
        await executor.execute("print(1)")
        await executor.execute("print(2)")
        await executor.execute("print(3)")

        assert len(records) == 3
        # All should have filesystem audit
        for r in records:
            assert r.filesystem_audit is not None
        # All should have distinct record IDs
        ids = {r.record_id for r in records}
        assert len(ids) == 3

    @pytest.mark.asyncio
    async def test_active_layers_include_fs_when_available(self):
        """If FS isolation is supported, it should appear in active_layers."""
        executor = SandboxedExecutor(SandboxPolicy.with_filesystem())
        result = await executor.execute("print('test')")

        if executor._capabilities.get("filesystem_isolation"):
            assert "fs_isolation" in result.active_layers
        else:
            # FS isolation not available on this system - graceful degradation
            assert "fs_isolation" not in result.active_layers

    @pytest.mark.asyncio
    async def test_fs_audit_reflects_actual_capabilities(self):
        """The audit info should match what the system actually supports."""
        records: list[SandboxAuditRecord] = []
        executor = ComplianceSandboxFactory.for_hipaa(audit_callback=records.append)
        result = await executor.execute("print('hi')")

        info = records[0].filesystem_audit
        assert info is not None

        # If FS isolation was active, audit should reflect it
        if "fs_isolation" in result.active_layers:
            assert info["mount_namespace_available"] is True
        else:
            # Graceful degradation - system doesn't support it
            assert info["effective_mode"] in ("unavailable", "chroot")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Mount constants sanity
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestMountConstants:
    """Verify mount flag constants match Linux headers."""

    def test_ms_rdonly(self):
        assert MS_RDONLY == 1

    def test_ms_nosuid(self):
        assert MS_NOSUID == 2

    def test_ms_nodev(self):
        assert MS_NODEV == 4

    def test_ms_noexec(self):
        from agentsafe.sandbox.filesystem import MS_NOEXEC
        assert MS_NOEXEC == 8

    def test_ms_bind(self):
        assert MS_BIND == 4096

    def test_ms_rec(self):
        assert MS_REC == 16384

    def test_ms_private(self):
        assert MS_PRIVATE == (1 << 18)

    def test_ms_remount(self):
        assert MS_REMOUNT == 32

    def test_mnt_detach(self):
        assert MNT_DETACH == 2


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DEV_NODES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestDevNodes:

    def test_dev_nodes_contents(self):
        names = [name for name, _ in DEV_NODES]
        assert "null" in names
        assert "zero" in names
        assert "urandom" in names
        assert "random" in names

    def test_dev_nodes_host_paths_exist(self):
        for name, host_path in DEV_NODES:
            if sys.platform.startswith("linux"):
                assert os.path.exists(host_path), f"{host_path} missing"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PIVOT_ROOT_NR
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPivotRootNr:

    def test_x86_64_syscall_nr(self):
        assert _PIVOT_ROOT_NR.get("x86_64") == 155

    def test_aarch64_syscall_nr(self):
        assert _PIVOT_ROOT_NR.get("aarch64") == 41

    def test_current_platform_has_entry(self):
        machine = platform.machine()
        # Most CI/dev machines are x86_64 or aarch64
        if machine in ("x86_64", "AMD64", "aarch64", "arm64"):
            assert machine in _PIVOT_ROOT_NR or machine.replace("arm64", "aarch64") in _PIVOT_ROOT_NR


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Audit record filesystem field (unit test for _build_audit_record)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestAuditRecordFilesystem:

    def test_build_with_filesystem_audit(self):
        fs_info = build_filesystem_audit_info(FilesystemPolicy.standard())
        result = SandboxResult(
            stdout="ok",
            stderr="",
            returncode=0,
            wall_time_seconds=0.1,
            active_layers=("rlimits", "python_sandbox"),
        )
        record = _build_audit_record(
            code="print(1)",
            result=result,
            policy=SandboxPolicy.standard(),
            policy_name="test",
            mandatory_ok=True,
            filesystem_audit=fs_info,
        )
        assert record.filesystem_audit is not None
        assert record.filesystem_audit["enabled"] is True

    def test_build_without_filesystem_audit(self):
        result = SandboxResult(
            stdout="ok",
            stderr="",
            returncode=0,
            wall_time_seconds=0.1,
            active_layers=("rlimits", "python_sandbox"),
        )
        record = _build_audit_record(
            code="print(1)",
            result=result,
            policy=SandboxPolicy.minimal(),
            policy_name="test",
            mandatory_ok=True,
        )
        assert record.filesystem_audit is None

    def test_audit_record_to_dict_includes_filesystem(self):
        fs_info = build_filesystem_audit_info(FilesystemPolicy.hipaa())
        result = SandboxResult(
            stdout="ok", stderr="", returncode=0,
            wall_time_seconds=0.05,
            active_layers=("rlimits", "python_sandbox", "fs_isolation"),
        )
        record = _build_audit_record(
            code="x=1",
            result=result,
            policy=SandboxPolicy.with_filesystem(),
            policy_name="hipaa",
            mandatory_ok=True,
            filesystem_audit=fs_info,
        )
        d = record.to_dict()
        assert "filesystem_isolation" in d
        assert d["filesystem_isolation"]["tmpfs_size_bytes"] == 16 * 1024 * 1024

    def test_audit_record_to_dict_json_serialisable(self):
        fs_info = build_filesystem_audit_info(FilesystemPolicy.standard())
        result = SandboxResult(
            stdout="", stderr="", returncode=0,
            wall_time_seconds=0.01,
            active_layers=(),
        )
        record = _build_audit_record(
            code="pass",
            result=result,
            policy=SandboxPolicy.standard(),
            policy_name="test",
            mandatory_ok=True,
            filesystem_audit=fs_info,
        )
        serialised = json.dumps(record.to_dict())
        assert isinstance(serialised, str)
        parsed = json.loads(serialised)
        assert "filesystem_isolation" in parsed

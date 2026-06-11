"""
Tests for gVisor (runsc) sandbox runtime.

Tests are split into:
  1. Unit tests - always run, mock runsc binary
  2. Integration tests - only run when CERTIOR_GVISOR_TESTS=1 and runsc is on PATH
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentsafe.sandbox.gvisor import (
    GVisorAuditInfo,
    GVisorPlatform,
    GVisorProbeResult,
    GVisorResourceLimits,
    GVisorResult,
    GVisorRuntime,
    _build_oci_config,
    _build_rootfs,
    _detect_platform,
    _discover_python_mounts,
    build_gvisor_audit_info,
    probe_gvisor,
    reset_gvisor_probe_cache,
)
from agentsafe.sandbox.policy import ContainmentLayer, SandboxPolicy
from agentsafe.sandbox.errors import SandboxSetupError


# ══════════════════════════════════════════════════════════════════════
#  Fixtures
# ══════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _clear_probe_cache():
    """Reset probe cache between tests."""
    reset_gvisor_probe_cache()
    yield
    reset_gvisor_probe_cache()


# ══════════════════════════════════════════════════════════════════════
#  Probing
# ══════════════════════════════════════════════════════════════════════

class TestProbeGVisor:
    def test_not_found(self):
        with patch("shutil.which", return_value=None):
            result = probe_gvisor()
        assert not result.available
        assert "not found" in result.error

    def test_found_with_version(self):
        with patch("shutil.which", return_value="/usr/bin/runsc"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="runsc version release-20260101.0\n", stderr=""
            )
            result = probe_gvisor()

        assert result.available
        assert result.runsc_path == "/usr/bin/runsc"
        assert "20260101" in result.version

    def test_version_fails(self):
        with patch("shutil.which", return_value="/usr/bin/runsc"), \
             patch("subprocess.run", side_effect=OSError("exec failed")):
            result = probe_gvisor()

        assert not result.available
        assert "exec failed" in result.error

    def test_cache(self):
        with patch("shutil.which", return_value=None):
            r1 = probe_gvisor()
            r2 = probe_gvisor()
        assert r1 is r2  # same object from cache

    def test_explicit_path_bypasses_cache(self):
        with patch("shutil.which", return_value=None):
            probe_gvisor()  # caches "not found"

        with patch("shutil.which", return_value="/opt/runsc"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="v1.0", stderr="")
            result = probe_gvisor(runsc_path="/opt/runsc")

        assert result.available

    def test_to_dict(self):
        result = GVisorProbeResult(
            available=True,
            runsc_path="/usr/bin/runsc",
            version="v1.0",
            platform=GVisorPlatform.SYSTRAP,
            rootless=True,
        )
        d = result.to_dict()
        assert d["available"] is True
        assert d["platform"] == "systrap"
        assert d["rootless"] is True


class TestDetectPlatform:
    def test_kvm_when_available(self):
        with patch("os.path.exists", return_value=True), \
             patch("os.access", return_value=True):
            assert _detect_platform("/usr/bin/runsc") == GVisorPlatform.KVM

    def test_systrap_fallback(self):
        with patch("os.path.exists", return_value=False):
            assert _detect_platform("/usr/bin/runsc") == GVisorPlatform.SYSTRAP


# ══════════════════════════════════════════════════════════════════════
#  OCI Config Generation
# ══════════════════════════════════════════════════════════════════════

class TestOCIConfig:
    def test_basic_config(self):
        limits = GVisorResourceLimits()
        config = _build_oci_config(
            rootfs_path="rootfs",
            limits=limits,
            platform=GVisorPlatform.SYSTRAP,
            python_bin="/usr/bin/python3",
            code_path="/work/code.py",
        )

        assert config["ociVersion"] == "1.1.0"
        assert config["process"]["args"] == ["/usr/bin/python3", "-u", "-B", "-S", "/work/code.py"]
        assert config["process"]["user"]["uid"] == 65534  # nobody
        assert config["process"]["noNewPrivileges"] is True
        assert config["root"]["readonly"] is True

    def test_memory_limit(self):
        limits = GVisorResourceLimits(memory_bytes=128 * 1024 * 1024)
        config = _build_oci_config(
            rootfs_path="rootfs", limits=limits,
            platform=GVisorPlatform.SYSTRAP,
            python_bin="/usr/bin/python3", code_path="/work/code.py",
        )
        assert config["linux"]["resources"]["memory"]["limit"] == 128 * 1024 * 1024

    def test_network_disabled(self):
        limits = GVisorResourceLimits(network_disabled=True)
        config = _build_oci_config(
            rootfs_path="rootfs", limits=limits,
            platform=GVisorPlatform.SYSTRAP,
            python_bin="/usr/bin/python3", code_path="/work/code.py",
        )
        ns_types = [ns["type"] for ns in config["linux"]["namespaces"]]
        assert "network" in ns_types

    def test_network_enabled(self):
        limits = GVisorResourceLimits(network_disabled=False)
        config = _build_oci_config(
            rootfs_path="rootfs", limits=limits,
            platform=GVisorPlatform.SYSTRAP,
            python_bin="/usr/bin/python3", code_path="/work/code.py",
        )
        ns_types = [ns["type"] for ns in config["linux"]["namespaces"]]
        assert "network" not in ns_types

    def test_capabilities_empty(self):
        limits = GVisorResourceLimits()
        config = _build_oci_config(
            rootfs_path="rootfs", limits=limits,
            platform=GVisorPlatform.SYSTRAP,
            python_bin="/usr/bin/python3", code_path="/work/code.py",
        )
        caps = config["process"]["capabilities"]
        for key in ["bounding", "effective", "inheritable", "permitted", "ambient"]:
            assert caps[key] == []

    def test_env_injection(self):
        limits = GVisorResourceLimits()
        config = _build_oci_config(
            rootfs_path="rootfs", limits=limits,
            platform=GVisorPlatform.SYSTRAP,
            python_bin="/usr/bin/python3", code_path="/work/code.py",
            env={"MY_VAR": "hello"},
        )
        assert "MY_VAR=hello" in config["process"]["env"]

    def test_pids_limit(self):
        limits = GVisorResourceLimits(max_pids=16)
        config = _build_oci_config(
            rootfs_path="rootfs", limits=limits,
            platform=GVisorPlatform.SYSTRAP,
            python_bin="/usr/bin/python3", code_path="/work/code.py",
        )
        assert config["linux"]["resources"]["pids"]["limit"] == 16

    def test_masked_paths(self):
        config = _build_oci_config(
            rootfs_path="rootfs",
            limits=GVisorResourceLimits(),
            platform=GVisorPlatform.SYSTRAP,
            python_bin="/usr/bin/python3", code_path="/work/code.py",
        )
        assert "/proc/kcore" in config["linux"]["maskedPaths"]
        assert "/sys/firmware" in config["linux"]["maskedPaths"]


# ══════════════════════════════════════════════════════════════════════
#  Rootfs
# ══════════════════════════════════════════════════════════════════════

class TestBuildRootfs:
    def test_creates_structure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = _build_rootfs(tmpdir, "/usr/bin/python3", "print(42)")
            assert os.path.isdir(os.path.join(rootfs, "usr"))
            assert os.path.isdir(os.path.join(rootfs, "work"))
            assert os.path.isdir(os.path.join(rootfs, "etc"))
            assert os.path.isfile(os.path.join(rootfs, "work/code.py"))

    def test_writes_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = _build_rootfs(tmpdir, "/usr/bin/python3", "x = 1 + 2")
            code = Path(rootfs, "work/code.py").read_text()
            assert "x = 1 + 2" in code

    def test_writes_etc_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = _build_rootfs(tmpdir, "/usr/bin/python3", "")
            assert "nobody" in Path(rootfs, "etc/passwd").read_text()
            assert "nogroup" in Path(rootfs, "etc/group").read_text()


# ══════════════════════════════════════════════════════════════════════
#  Python Mount Discovery
# ══════════════════════════════════════════════════════════════════════

class TestDiscoverPythonMounts:
    def test_returns_list(self):
        import sys
        mounts = _discover_python_mounts(sys.executable)
        assert isinstance(mounts, list)
        assert len(mounts) > 0

    def test_mount_structure(self):
        import sys
        mounts = _discover_python_mounts(sys.executable)
        for m in mounts:
            assert "destination" in m
            assert "source" in m
            assert "type" in m
            assert m["type"] == "bind"
            assert "ro" in m["options"]


# ══════════════════════════════════════════════════════════════════════
#  Resource Limits
# ══════════════════════════════════════════════════════════════════════

class TestGVisorResourceLimits:
    def test_defaults(self):
        limits = GVisorResourceLimits()
        assert limits.memory_bytes == 256 * 1024 * 1024
        assert limits.wall_time_seconds == 30.0
        assert limits.network_disabled is True
        assert limits.readonly_rootfs is True
        assert limits.no_new_privileges is True

    def test_custom(self):
        limits = GVisorResourceLimits(
            memory_bytes=64 * 1024 * 1024,
            wall_time_seconds=10.0,
            network_disabled=False,
        )
        assert limits.memory_bytes == 64 * 1024 * 1024
        assert limits.network_disabled is False


# ══════════════════════════════════════════════════════════════════════
#  GVisorResult
# ══════════════════════════════════════════════════════════════════════

class TestGVisorResult:
    def test_success(self):
        r = GVisorResult(output="42\n", exit_code=0)
        assert r.success

    def test_failure(self):
        r = GVisorResult(exit_code=1)
        assert not r.success

    def test_oom(self):
        r = GVisorResult(exit_code=137, oom_killed=True)
        assert not r.success

    def test_timeout(self):
        r = GVisorResult(exit_code=-1, timeout=True)
        assert not r.success

    def test_default_layers(self):
        r = GVisorResult()
        assert "gvisor" in r.active_layers


# ══════════════════════════════════════════════════════════════════════
#  GVisorRuntime (mocked)
# ══════════════════════════════════════════════════════════════════════

class TestGVisorRuntime:
    def test_init_fails_without_runsc(self):
        with patch("shutil.which", return_value=None):
            reset_gvisor_probe_cache()
            with pytest.raises(SandboxSetupError, match="gVisor not available"):
                GVisorRuntime()

    @pytest.mark.asyncio
    async def test_execute_returns_result(self):
        """Test full execute flow with mocked subprocess."""
        with patch("shutil.which", return_value="/usr/bin/runsc"), \
             patch("subprocess.run") as mock_version, \
             patch("asyncio.create_subprocess_exec") as mock_exec:

            mock_version.return_value = MagicMock(stdout="v1.0", stderr="")
            reset_gvisor_probe_cache()

            # Mock the runsc process
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"42\n", b""))
            mock_proc.returncode = 0
            mock_proc.kill = AsyncMock()
            mock_proc.wait = AsyncMock()
            mock_exec.return_value = mock_proc

            runtime = GVisorRuntime(runsc_path="/usr/bin/runsc")
            result = await runtime.execute("print(42)")

            assert result.output == "42\n"
            assert result.exit_code == 0
            assert result.success
            assert "gvisor" in result.active_layers

    @pytest.mark.asyncio
    async def test_audit_log(self):
        with patch("shutil.which", return_value="/usr/bin/runsc"), \
             patch("subprocess.run") as mock_version, \
             patch("asyncio.create_subprocess_exec") as mock_exec:

            mock_version.return_value = MagicMock(stdout="v1.0", stderr="")
            reset_gvisor_probe_cache()

            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"ok\n", b""))
            mock_proc.returncode = 0
            mock_proc.kill = AsyncMock()
            mock_proc.wait = AsyncMock()
            mock_exec.return_value = mock_proc

            runtime = GVisorRuntime(runsc_path="/usr/bin/runsc")
            await runtime.execute("print('ok')")

            assert len(runtime.audit_log) == 1
            entry = runtime.audit_log[0]
            assert entry["exit_code"] == 0
            assert entry["success"] is True


# ══════════════════════════════════════════════════════════════════════
#  Audit Info
# ══════════════════════════════════════════════════════════════════════

class TestGVisorAuditInfo:
    def test_to_dict(self):
        info = GVisorAuditInfo(
            available=True, runsc_version="v1.0",
            platform="systrap", rootless=True,
            network_disabled=True, readonly_rootfs=True,
            memory_limit_bytes=256 * 1024 * 1024, max_pids=32,
        )
        d = info.to_dict()
        assert d["runtime"] == "gvisor"
        assert d["available"] is True
        assert d["capabilities_dropped"] is True

    def test_build_audit_info(self):
        with patch("shutil.which", return_value=None):
            reset_gvisor_probe_cache()
            info = build_gvisor_audit_info()
        assert not info.available


# ══════════════════════════════════════════════════════════════════════
#  SandboxPolicy.gvisor()
# ══════════════════════════════════════════════════════════════════════

class TestSandboxPolicyGVisor:
    def test_factory(self):
        policy = SandboxPolicy.gvisor()
        assert ContainmentLayer.GVISOR in policy.mandatory_layers
        assert policy.resource_limits.memory_bytes == 256 * 1024 * 1024

    def test_gvisor_not_in_standard(self):
        policy = SandboxPolicy.standard()
        assert ContainmentLayer.GVISOR not in policy.mandatory_layers

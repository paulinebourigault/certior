"""Tests for the download-on-demand Lean binary installer.

These exercise the install/verify/discovery logic with a tiny fake binary
(no network, no 90 MB artifact) by injecting its real SHA-256 into the
manifest for the current platform.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from certior import lean_installer as li
from agentsafe.verification.lean_live_verifier import _find_binary


def _supported() -> bool:
    try:
        li.platform_key()
        return True
    except li.LeanInstallError:
        return False


pytestmark = pytest.mark.skipif(
    not _supported(), reason="no published Lean binary for this platform"
)


@pytest.fixture
def fake_binary(tmp_path: Path) -> Path:
    """A small file standing in for the real binary, with known contents."""
    p = tmp_path / "fake-flow-check"
    p.write_bytes(b"#!/bin/sh\necho fake\n")
    return p


@pytest.fixture
def isolated_cache(tmp_path, monkeypatch):
    """Point the installer + discovery at a throwaway cache dir."""
    cache = tmp_path / "cache"
    monkeypatch.setenv("CERTIOR_CACHE_DIR", str(cache))
    # Make sure no real env binary shadows discovery during the test.
    monkeypatch.delenv("CERTIOR_FLOW_CHECK_BINARY", raising=False)
    return cache


@pytest.fixture
def pin_manifest(monkeypatch, fake_binary):
    """Inject the fake binary's real SHA-256 into the manifest entry for the
    current platform so install_from_file verifies against it."""
    key = li.platform_key()
    sha = hashlib.sha256(fake_binary.read_bytes()).hexdigest()
    entry = {
        "filename": f"certior-flow-check-{key}",
        "sha256": sha,
        "size": fake_binary.stat().st_size,
    }
    monkeypatch.setitem(li.manifest.BINARIES, key, entry)
    return entry


def test_cache_dir_honors_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CERTIOR_CACHE_DIR", str(tmp_path / "c"))
    assert li.cache_dir() == tmp_path / "c" / "bin"
    assert li.cached_binary_path().name == li.BINARY_NAME


def test_not_installed_returns_none(isolated_cache):
    assert li.installed_binary_path() is None
    assert li.verify_installed() is False


def test_install_from_file_succeeds_and_is_discoverable(
    isolated_cache, pin_manifest, fake_binary
):
    dest = li.install_from_file(fake_binary)
    assert dest.is_file()
    # executable bit set
    assert dest.stat().st_mode & 0o111
    # cheap discovery hook finds it
    assert li.installed_binary_path() == str(dest)
    # integrity re-check passes
    assert li.verify_installed() is True
    # the runtime's own discovery picks up the cached copy
    assert _find_binary() == str(dest)


def test_tampered_binary_fails_closed(isolated_cache, pin_manifest, fake_binary):
    # Corrupt the source so its hash no longer matches the pinned entry.
    tampered = fake_binary.parent / "tampered"
    tampered.write_bytes(fake_binary.read_bytes() + b"EVIL")
    with pytest.raises(li.LeanInstallError, match="SHA-256 mismatch"):
        li.install_from_file(tampered)
    # nothing was installed
    assert li.installed_binary_path() is None


def test_existing_install_requires_force(isolated_cache, pin_manifest, fake_binary):
    li.install_from_file(fake_binary)
    with pytest.raises(li.LeanInstallError, match="already installed"):
        li.install_from_file(fake_binary)
    # --force replaces it
    dest = li.install_from_file(fake_binary, force=True)
    assert dest.is_file()


def test_download_unpublished_platform_errors(isolated_cache, monkeypatch):
    key = li.platform_key()
    monkeypatch.setitem(li.manifest.BINARIES, key, None)
    with pytest.raises(li.LeanInstallError, match="No published Lean binary"):
        li.download_and_install()


def test_install_missing_file_errors(isolated_cache):
    with pytest.raises(li.LeanInstallError, match="No such file"):
        li.install_from_file(Path("/nonexistent/flow-check"))

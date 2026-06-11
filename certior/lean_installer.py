"""Download-on-demand installer for the Lean ``certior-flow-check`` binary.

The pip wheel ships the Python runtime (Z3-enforced gate + signed certs +
the Lean-proven policy *model*) but not the ~90 MB compiled Lean binary that
provides *live* lattice-proven flow verification. This module fetches that
binary for the current platform from a GitHub Release, verifies it against
the trusted SHA-256 in :mod:`certior._lean_binary_manifest`, and caches it
where the runtime's binary discovery (``lean_live_verifier._find_binary``)
will find it.

Typical use::

    $ certior-install-lean            # download + verify + install
    $ certior-install-lean --status   # show what's installed / discovered

Source checkouts that already built the binary locally can install it into
the cache without a download::

    $ certior-install-lean --from-file lean4/CertiorPlan/.lake/build/bin/certior-flow-check

The base ``pip install certior`` never needs any of this: with no binary
present the runtime degrades gracefully to Z3-only enforcement.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Optional

from certior import _lean_binary_manifest as manifest

# Name of the binary as discovered by the runtime. Kept suffix-free so the
# discovery path is identical regardless of which platform artifact produced
# it.
BINARY_NAME = "certior-flow-check"


class LeanInstallError(RuntimeError):
    """Raised when the Lean binary cannot be installed or verified."""


# ── Platform / cache resolution ───────────────────────────────────────

def platform_key() -> str:
    """Return the manifest platform key for the current machine.

    One of ``linux-x86_64``, ``macos-arm64``, ``macos-x86_64``. Raises
    :class:`LeanInstallError` for platforms with no published binary
    (notably Windows, which uses the Z3-only fallback).
    """
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Linux":
        if machine in ("x86_64", "amd64"):
            return "linux-x86_64"
        raise LeanInstallError(
            f"No published Lean binary for Linux/{machine}. "
            "Build from source with scripts/build-lean-binary.sh."
        )
    if system == "Darwin":
        if machine in ("arm64", "aarch64"):
            return "macos-arm64"
        if machine in ("x86_64", "amd64"):
            return "macos-x86_64"
        raise LeanInstallError(f"No published Lean binary for macOS/{machine}.")
    raise LeanInstallError(
        f"No published Lean binary for {system}. The runtime falls back to "
        "Z3-only enforcement on this platform."
    )


def cache_dir() -> Path:
    """Directory under which the installed binary is cached.

    Honors ``CERTIOR_CACHE_DIR``, then ``XDG_CACHE_HOME``, then ``~/.cache``.
    """
    override = os.environ.get("CERTIOR_CACHE_DIR")
    if override:
        base = Path(override)
    else:
        xdg = os.environ.get("XDG_CACHE_HOME")
        base = Path(xdg) if xdg else Path.home() / ".cache"
        base = base / "certior"
    return base / "bin"


def cached_binary_path() -> Path:
    """Absolute path where the installed binary lives (may not exist)."""
    return cache_dir() / BINARY_NAME


def installed_binary_path() -> Optional[str]:
    """Return the cached binary path if it exists and is executable.

    This is the cheap discovery hook called by the runtime on startup — it
    does **not** re-hash the (90 MB) binary. Use :func:`verify_installed`
    for an integrity check.
    """
    p = cached_binary_path()
    try:
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    except OSError:
        return None
    return None


# ── Hashing / verification ────────────────────────────────────────────

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _require_entry(key: str) -> "manifest.BinaryEntry":
    entry = manifest.entry_for(key)
    if entry is None:
        raise LeanInstallError(
            f"No published Lean binary for platform '{key}' yet. "
            "Build from source with scripts/build-lean-binary.sh, then "
            "`certior-install-lean --from-file <path>`."
        )
    return entry


def _warn_fingerprint_mismatch() -> None:
    """Warn (not fail) if the package policy fingerprint and the manifest's
    disagree — that means the binary was built against a different policy
    model revision than this package."""
    try:
        from certior._lean_fingerprint import FINGERPRINT
    except ImportError:
        return
    if FINGERPRINT != manifest.POLICY_FINGERPRINT:
        print(
            f"warning: package policy fingerprint ({FINGERPRINT}) differs from "
            f"the binary manifest ({manifest.POLICY_FINGERPRINT}). The live "
            "Lean binary may disagree with this package's policy model.",
            file=sys.stderr,
        )


def _make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _atomic_install(src_tmp: Path, expected_sha: str) -> Path:
    """Verify ``src_tmp`` against ``expected_sha`` and move it into the cache."""
    actual = _sha256(src_tmp)
    if actual != expected_sha:
        src_tmp.unlink(missing_ok=True)
        raise LeanInstallError(
            "SHA-256 mismatch — refusing to install.\n"
            f"  expected: {expected_sha}\n  actual:   {actual}\n"
            "The download may be corrupted or tampered with."
        )
    dest = cached_binary_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    # os.replace is atomic within the same filesystem; the tempfile is created
    # in the cache dir to guarantee that.
    os.replace(src_tmp, dest)
    _make_executable(dest)
    return dest


# ── Install paths ─────────────────────────────────────────────────────

def install_from_file(src: Path, *, force: bool = False) -> Path:
    """Install a locally-built binary into the cache, verifying its hash
    against the manifest when an entry exists for this platform."""
    src = Path(src).expanduser()
    if not src.is_file():
        raise LeanInstallError(f"No such file: {src}")

    key = platform_key()
    entry = manifest.entry_for(key)

    dest = cached_binary_path()
    if dest.exists() and not force:
        raise LeanInstallError(
            f"A binary is already installed at {dest}. Use --force to replace it."
        )

    cache_dir().mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(cache_dir()), prefix=".flow-check-")
    os.close(fd)
    tmp = Path(tmp_name)
    shutil.copyfile(src, tmp)

    if entry is not None:
        _warn_fingerprint_mismatch()
        return _atomic_install(tmp, entry["sha256"])

    # No manifest entry for this platform (e.g. a dev building an unpublished
    # platform): install without hash pinning but tell the user.
    print(
        f"warning: no manifest hash for platform '{key}'; installing "
        f"{src.name} without SHA verification.",
        file=sys.stderr,
    )
    os.replace(tmp, dest)
    _make_executable(dest)
    return dest


def download_and_install(
    *,
    force: bool = False,
    release_tag: Optional[str] = None,
    timeout: float = 120.0,
) -> Path:
    """Download the binary for the current platform and install it.

    Streams the asset to a temp file in the cache dir, verifies SHA-256
    against the manifest, then atomically moves it into place.
    """
    key = platform_key()
    entry = _require_entry(key)

    dest = cached_binary_path()
    if dest.exists() and not force:
        raise LeanInstallError(
            f"A binary is already installed at {dest}. Use --force to re-download."
        )

    url = manifest.download_url(entry)
    if release_tag:
        url = url.replace(f"/{manifest.RELEASE_TAG}/", f"/{release_tag}/")

    _warn_fingerprint_mismatch()
    cache_dir().mkdir(parents=True, exist_ok=True)

    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - httpx is a core dep
        raise LeanInstallError(
            "httpx is required to download the Lean binary "
            "(pip install certior[lean])."
        ) from exc

    size = entry["size"]
    print(f"Downloading {entry['filename']} ({size / 1e6:.0f} MB) from\n  {url}")

    fd, tmp_name = tempfile.mkstemp(dir=str(cache_dir()), prefix=".flow-check-")
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        downloaded = 0
        with httpx.stream(
            "GET", url, follow_redirects=True, timeout=timeout
        ) as resp:
            if resp.status_code != 200:
                raise LeanInstallError(
                    f"Download failed: HTTP {resp.status_code} for {url}. "
                    f"Is release '{release_tag or manifest.RELEASE_TAG}' published?"
                )
            with open(tmp, "wb") as f:
                for chunk in resp.iter_bytes(chunk_size=1024 * 256):
                    f.write(chunk)
                    downloaded += len(chunk)
                    _progress(downloaded, size)
        sys.stdout.write("\n")
    except httpx.HTTPError as exc:
        tmp.unlink(missing_ok=True)
        raise LeanInstallError(f"Download error: {exc}") from exc

    dest = _atomic_install(tmp, entry["sha256"])
    return dest


def _progress(done: int, total: int) -> None:
    if total <= 0:
        return
    pct = min(100, int(done * 100 / total))
    bar = "#" * (pct // 4)
    sys.stdout.write(f"\r  [{bar:<25}] {pct:3d}%")
    sys.stdout.flush()


def verify_installed() -> bool:
    """Re-hash the installed binary and compare to the manifest. Returns True
    if it matches (or there is no manifest entry to compare against)."""
    p = installed_binary_path()
    if p is None:
        return False
    try:
        entry = manifest.entry_for(platform_key())
    except LeanInstallError:
        return True
    if entry is None:
        return True
    return _sha256(Path(p)) == entry["sha256"]


# ── CLI ───────────────────────────────────────────────────────────────

def _print_status() -> int:
    p = installed_binary_path()
    print(f"cache dir:        {cache_dir()}")
    try:
        key = platform_key()
        print(f"platform:         {key}")
        entry = manifest.entry_for(key)
        if entry:
            print(f"published asset:  {entry['filename']} ({entry['size'] / 1e6:.0f} MB)")
            print(f"expected sha256:  {entry['sha256']}")
        else:
            print("published asset:  (none yet for this platform)")
    except LeanInstallError as exc:
        print(f"platform:         unsupported — {exc}")
    if p:
        ok = verify_installed()
        print(f"installed binary: {p}")
        print(f"integrity:        {'OK (sha256 verified)' if ok else 'MISMATCH'}")
        return 0 if ok else 1
    print("installed binary: (not installed — runtime uses Z3-only fallback)")
    print("\nRun `certior-install-lean` to download it.")
    return 0


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="certior-install-lean",
        description=(
            "Download and install the Lean live-verification binary "
            "(certior-flow-check) for this platform."
        ),
    )
    parser.add_argument(
        "--from-file",
        metavar="PATH",
        help="install a locally-built binary instead of downloading",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace an already-installed binary",
    )
    parser.add_argument(
        "--release",
        metavar="TAG",
        help=f"GitHub Release tag to download from (default: {manifest.RELEASE_TAG})",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="show install status and verify integrity, then exit",
    )
    args = parser.parse_args(argv)

    if args.status:
        return _print_status()

    try:
        if args.from_file:
            dest = install_from_file(Path(args.from_file), force=args.force)
        else:
            dest = download_and_install(force=args.force, release_tag=args.release)
    except LeanInstallError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"\nInstalled live Lean verifier:\n  {dest}")
    print(
        "\nThe runtime will now use lattice-proven flow verification "
        "automatically.\nVerify with: certior-install-lean --status"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

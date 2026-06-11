from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

from .models import RepoIdentity, stable_id


class GitRepositoryError(RuntimeError):
    pass


def _run_git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip()
        raise GitRepositoryError(stderr or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def inspect_repo(repo_root: str | os.PathLike[str]) -> RepoIdentity:
    root = Path(repo_root).resolve()
    git_root = Path(_run_git(root, "rev-parse", "--show-toplevel"))
    branch = _run_git(git_root, "branch", "--show-current") or "HEAD"
    commit_sha = _run_git(git_root, "rev-parse", "HEAD")
    dirty_output = _run_git(git_root, "status", "--porcelain")
    name = git_root.name
    repo_id = stable_id("repo", str(git_root))
    return RepoIdentity(
        repo_id=repo_id,
        name=name,
        root_path=str(git_root),
        branch=branch,
        commit_sha=commit_sha,
        is_dirty=bool(dirty_output),
    )


def list_tracked_files(repo_root: str | os.PathLike[str]) -> list[str]:
    root = Path(repo_root).resolve()
    output = _run_git(root, "ls-files", "-z")
    if not output:
        return []
    return [entry for entry in output.split("\0") if entry]


def sha256_for_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()
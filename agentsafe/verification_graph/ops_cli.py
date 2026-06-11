from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess


def _find_repo_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").exists() and (candidate / "scripts").exists():
            return candidate
    raise RuntimeError("Could not locate Certior repository root. Run from the repo or set CERTIOR_REPO_ROOT.")


def _repo_root_from_env_or_cwd() -> Path:
    configured = os.getenv("CERTIOR_REPO_ROOT")
    if configured:
        return Path(configured).resolve()
    return _find_repo_root(Path.cwd())


def _run_script(script_name: str) -> int:
    repo_root = _repo_root_from_env_or_cwd()
    script_path = repo_root / "scripts" / script_name
    if not script_path.exists():
        raise RuntimeError(f"Script not found: {script_path}")
    completed = subprocess.run(["bash", str(script_path)], cwd=repo_root, check=False)
    return completed.returncode


def main_doctor() -> int:
    argparse.ArgumentParser(description="Run Certior doctor preflight checks").parse_args()
    return _run_script("certior-doctor.sh")


def main_runtime_evidence() -> int:
    argparse.ArgumentParser(description="Generate live runtime evidence and ingest the verification graph").parse_args()
    return _run_script("generate-runtime-evidence.sh")


if __name__ == "__main__":
    raise SystemExit(main_doctor())
"""
Resource-limit enforcement via ``setrlimit(2)``.

This module is designed to run **inside the child process** (the
sandboxed subprocess) before user code executes.  It is imported by
the sandbox launcher preamble.

All limits are *hard* limits - the process cannot raise them.
"""
from __future__ import annotations

import os
import resource
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass
class RlimitSpec:
    """A single rlimit to apply."""

    resource_id: int       # e.g. resource.RLIMIT_CPU
    soft: int
    hard: int
    name: str              # human-readable name for diagnostics


def build_rlimit_specs(
    *,
    cpu_time_seconds: int = 30,
    memory_bytes: int = 256 * 1024 * 1024,
    max_file_size_bytes: int = 10 * 1024 * 1024,
    max_open_files: int = 64,
    max_processes: int = 1,
    max_core_size: int = 0,
) -> List[RlimitSpec]:
    """Build a list of ``RlimitSpec`` from human-friendly parameters.

    Parameters map 1:1 to ``ResourceLimits`` fields.
    """
    specs: List[RlimitSpec] = []

    # CPU time - kernel sends SIGXCPU at soft, SIGKILL at hard.
    specs.append(RlimitSpec(
        resource_id=resource.RLIMIT_CPU,
        soft=cpu_time_seconds,
        hard=cpu_time_seconds + 2,  # 2 s grace for cleanup
        name="RLIMIT_CPU",
    ))

    # Virtual address space (effectively memory limit).
    specs.append(RlimitSpec(
        resource_id=resource.RLIMIT_AS,
        soft=memory_bytes,
        hard=memory_bytes,
        name="RLIMIT_AS",
    ))

    # Maximum file size.
    specs.append(RlimitSpec(
        resource_id=resource.RLIMIT_FSIZE,
        soft=max_file_size_bytes,
        hard=max_file_size_bytes,
        name="RLIMIT_FSIZE",
    ))

    # Open file descriptors.
    specs.append(RlimitSpec(
        resource_id=resource.RLIMIT_NOFILE,
        soft=max_open_files,
        hard=max_open_files,
        name="RLIMIT_NOFILE",
    ))

    # Child processes - prevents fork bombs.
    specs.append(RlimitSpec(
        resource_id=resource.RLIMIT_NPROC,
        soft=max_processes,
        hard=max_processes,
        name="RLIMIT_NPROC",
    ))

    # Core dump size - 0 prevents leaking memory contents.
    specs.append(RlimitSpec(
        resource_id=resource.RLIMIT_CORE,
        soft=max_core_size,
        hard=max_core_size,
        name="RLIMIT_CORE",
    ))

    return specs


def apply_rlimits(specs: List[RlimitSpec]) -> List[str]:
    """Apply a list of rlimits.  Returns list of any failures (best-effort).

    On Linux this should always succeed for lowering limits.  Raising
    hard limits requires ``CAP_SYS_RESOURCE``.
    """
    failures: List[str] = []
    for spec in specs:
        try:
            resource.setrlimit(spec.resource_id, (spec.soft, spec.hard))
        except (ValueError, OSError) as exc:
            failures.append(f"{spec.name}: {exc}")
    return failures


def apply_rlimits_from_dict(limits: Dict[str, Any]) -> List[str]:
    """Convenience: build specs from a dict and apply.

    ``limits`` keys match ``ResourceLimits`` field names::

        apply_rlimits_from_dict({
            "cpu_time_seconds": 10,
            "memory_bytes": 128 * 1024 * 1024,
            "max_processes": 1,
        })
    """
    specs = build_rlimit_specs(**limits)
    return apply_rlimits(specs)


def get_current_rlimits() -> Dict[str, Tuple[int, int]]:
    """Read current rlimit values.  Useful for diagnostics / testing."""
    mapping = {
        "RLIMIT_CPU": resource.RLIMIT_CPU,
        "RLIMIT_AS": resource.RLIMIT_AS,
        "RLIMIT_FSIZE": resource.RLIMIT_FSIZE,
        "RLIMIT_NOFILE": resource.RLIMIT_NOFILE,
        "RLIMIT_NPROC": resource.RLIMIT_NPROC,
        "RLIMIT_CORE": resource.RLIMIT_CORE,
    }
    result: Dict[str, Tuple[int, int]] = {}
    for name, rid in mapping.items():
        try:
            result[name] = resource.getrlimit(rid)
        except (ValueError, OSError):
            result[name] = (-1, -1)
    return result

"""
Certior verified tools.

Provides concrete tool implementations and the registry that the
agentic executor uses to resolve LLM tool-call requests.

A9 FIX: ``create_default_registry()`` now accepts a ``skills_dir``
parameter and loads constraints from VERIFICATION.json at startup,
passing them to tool constructors.  This ensures Z3 proofs and
runtime enforcement are about the **same constraints**.
"""
from pathlib import Path

from .base import BaseTool, ToolParameter, ToolResult
from .registry import ToolRegistry
from .web_fetch import WebFetchTool
from .python_eval import PythonEvalTool
from .file_write import FileWriteTool
from .file_read import FileReadTool
from .constraint_loader import (
    ToolConstraintLoader,
    LoadedConstraints,
    load_tool_constraints,
)
from agentsafe.runtime_policy import resolve_runtime_policy_bundle


def create_default_registry(
    *,
    workspace: str | None = None,
    skills_dir: str | Path | None = None,
    compliance_policy: str | None = None,
    verification_profile: dict | None = None,
) -> ToolRegistry:
    """
    Build a registry pre-loaded with the standard tool set.

    A9 FIX: When ``skills_dir`` is provided, loads VERIFICATION.json
    constraints and passes them to tool constructors.  This closes
    the spec-to-code gap where Z3 proves constraints in the spec
    but tools use different hardcoded values.

    Args:
        workspace: Optional directory for file read/write operations.
                   Defaults to a shared temporary directory.
        skills_dir: Path to the skills directory containing
                    VERIFICATION.json files.  If None, tools fall back
                    to hardcoded defaults.

    Returns:
        ToolRegistry with all tools initialised using spec constraints
        (when available) or hardcoded fallbacks.
    """
    import logging
    import tempfile

    log = logging.getLogger(__name__)

    ws = workspace or tempfile.mkdtemp(prefix="certior_ws_")

    # A9: Load constraints from VERIFICATION.json
    constraints = load_tool_constraints(
        Path(skills_dir) if skills_dir else None
    )

    if constraints.warnings:
        for w in constraints.warnings:
            log.warning("Constraint loading: %s", w)

    loaded_from_spec = []
    runtime_bundle = resolve_runtime_policy_bundle(
        compliance_policy=compliance_policy or "default",
        verification_profile=verification_profile,
    )

    # Build tools with spec constraints
    registry = ToolRegistry()

    if constraints.web_fetch is not None:
        registry.register(WebFetchTool(
            constraints=constraints.web_fetch,
            network_policy=runtime_bundle.network_policy,
        ))
        loaded_from_spec.append("web_fetch")
    else:
        registry.register(WebFetchTool(network_policy=runtime_bundle.network_policy))

    registry.register(PythonEvalTool(
        sandbox_policy=runtime_bundle.sandbox_policy,
        sandbox_policy_name=runtime_bundle.sandbox_policy_name,
        seccomp_evidence=runtime_bundle.seccomp_evidence,
    ))

    if constraints.file_write is not None:
        registry.register(FileWriteTool(workspace=ws, constraints=constraints.file_write))
        loaded_from_spec.append("file_write")
    else:
        registry.register(FileWriteTool(workspace=ws))

    if constraints.file_read is not None:
        registry.register(FileReadTool(workspace=ws, constraints=constraints.file_read))
        loaded_from_spec.append("file_read")
    else:
        registry.register(FileReadTool(workspace=ws))

    if loaded_from_spec:
        log.info(
            "A9: Loaded VERIFICATION.json constraints for tools: %s",
            loaded_from_spec,
        )

    # Store loaded constraints on the registry for the approval gate (A8)
    # None when no skills_dir provided (tools use hardcoded fallback)
    registry._loaded_constraints = constraints if loaded_from_spec else None
    registry._profile_aware_factory = True
    registry._runtime_policy_bundle = runtime_bundle

    return registry


__all__ = [
    "BaseTool",
    "ToolParameter",
    "ToolResult",
    "ToolRegistry",
    "WebFetchTool",
    "PythonEvalTool",
    "FileWriteTool",
    "FileReadTool",
    "ToolConstraintLoader",
    "LoadedConstraints",
    "load_tool_constraints",
    "create_default_registry",
]

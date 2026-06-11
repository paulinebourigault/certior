"""
Tool Constraint Loader - A9 FIX.

Closes BYPASS #9: "VERIFICATION.json disconnected from runtime."

Problem
-------
The skills framework defines rich VERIFICATION.json specs with URL
patterns, column restrictions, rate limits, and formal properties.
Z3 proves these constraints are internally consistent.  But the tools
(WebFetchTool, FileWriteTool, etc.) use their own **hardcoded**
constraints - the proof and the code are about different things.

Solution
--------
1. ``ToolConstraintLoader`` reads VERIFICATION.json for each tool at
   startup and produces typed ``ToolConstraints`` dataclasses.
2. Each tool class accepts optional ``constraints`` in its constructor.
   If provided, the tool uses the spec-derived constraints instead of
   (or merged with) its hardcoded defaults.
3. ``create_default_registry()`` now accepts a ``skills_dir`` parameter,
   loads constraints, and passes them to tool constructors.

This ensures Z3 proofs and runtime enforcement are about the **same
constraints** - closing the spec-to-code fidelity gap.

Mapping
-------
Skill IDs and tool names differ; the mapping is:

    web_browsing    → web_fetch
    file_operations → file_read, file_write
    database_query  → (no tool yet; constraints stored for future use)
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Pattern, Set

log = logging.getLogger(__name__)


# ── Typed constraint containers ──────────────────────────────────────

@dataclass(frozen=True)
class WebFetchConstraints:
    """Runtime constraints for the web_fetch tool, loaded from spec."""
    allowlist_patterns: tuple[Pattern[str], ...] = ()
    blocklist_patterns: tuple[Pattern[str], ...] = ()
    timeout_seconds: int = 30
    max_body_size_bytes: int = 10_485_760
    max_requests_per_minute: int = 60
    user_agent_required: bool = True
    approval_categories: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class FileConstraints:
    """Runtime constraints for file_read/file_write, loaded from spec."""
    path_allowlist_patterns: tuple[Pattern[str], ...] = ()
    path_blocklist_patterns: tuple[Pattern[str], ...] = ()
    allowed_extensions: FrozenSet[str] = frozenset()
    max_file_size_bytes: int = 10_000_000
    timeout_seconds: int = 60
    approval_categories: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class PythonEvalConstraints:
    """Runtime constraints for python_eval, loaded from spec."""
    timeout_seconds: int = 30
    max_output_chars: int = 32_000
    blocked_modules: FrozenSet[str] = frozenset()
    approval_categories: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class DatabaseQueryConstraints:
    """Runtime constraints for a database query tool (future)."""
    forbidden_columns: FrozenSet[str] = frozenset()
    allowed_tables: tuple[str, ...] = ()
    read_only: bool = True
    max_rows_per_query: int = 10_000
    query_timeout_seconds: int = 30
    approval_categories: FrozenSet[str] = frozenset()


@dataclass
class LoadedConstraints:
    """
    All constraints loaded from the skills directory.

    Holds typed constraint objects keyed by tool name, plus the raw
    VERIFICATION.json dicts for any tool that wants to inspect them.
    """
    web_fetch: Optional[WebFetchConstraints] = None
    file_read: Optional[FileConstraints] = None
    file_write: Optional[FileConstraints] = None
    python_eval: Optional[PythonEvalConstraints] = None
    database_query: Optional[DatabaseQueryConstraints] = None

    # Raw specs keyed by skill_id (for Z3 verifier, audit, etc.)
    raw_specs: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Mapping: tool_name → approval categories from VERIFICATION.json
    approval_categories: Dict[str, FrozenSet[str]] = field(default_factory=dict)

    # Validation warnings (non-fatal)
    warnings: List[str] = field(default_factory=list)

    def get_approval_categories(self, tool_name: str) -> Optional[List[str]]:
        """Get approval categories for a tool (for ApprovalGate)."""
        cats = self.approval_categories.get(tool_name)
        if cats is not None:
            return sorted(cats)
        return None


# ── Skill-to-tool mapping ────────────────────────────────────────────

# Maps skill_id from VERIFICATION.json to one or more tool names.
_SKILL_TO_TOOLS: Dict[str, List[str]] = {
    "web_browsing": ["web_fetch"],
    "file_operations": ["file_read", "file_write"],
    "database_query": ["database_query"],
}

# Reverse mapping: tool_name → skill_id
_TOOL_TO_SKILL: Dict[str, str] = {}
for _sk, _tools in _SKILL_TO_TOOLS.items():
    for _tn in _tools:
        _TOOL_TO_SKILL[_tn] = _sk


def _compile_patterns(raw: List[str]) -> tuple[Pattern[str], ...]:
    """Compile a list of regex strings into Pattern objects."""
    compiled = []
    for p in raw:
        try:
            compiled.append(re.compile(p, re.IGNORECASE))
        except re.error as exc:
            log.warning("Invalid regex pattern %r in VERIFICATION.json: %s", p, exc)
    return tuple(compiled)


# ── Loader ───────────────────────────────────────────────────────────

class ToolConstraintLoader:
    """
    Loads VERIFICATION.json specifications and produces typed runtime
    constraints for tool constructors.

    Usage::

        loader = ToolConstraintLoader(Path("skills"))
        constraints = loader.load()

        # Pass to tool constructors
        web_tool = WebFetchTool(constraints=constraints.web_fetch)
        file_tool = FileWriteTool(
            workspace="/tmp/ws",
            constraints=constraints.file_write,
        )
    """

    def __init__(self, skills_dir: Path) -> None:
        self.skills_dir = Path(skills_dir)

    def load(self) -> LoadedConstraints:
        """
        Load all VERIFICATION.json files and build typed constraints.

        Returns a ``LoadedConstraints`` with typed fields for each
        tool.  Missing or invalid specs produce warnings, not errors
        (graceful degradation).
        """
        result = LoadedConstraints()

        if not self.skills_dir.exists():
            result.warnings.append(
                f"Skills directory not found: {self.skills_dir}"
            )
            return result

        for skill_dir in sorted(self.skills_dir.iterdir()):
            if not skill_dir.is_dir():
                continue
            vj_path = skill_dir / "VERIFICATION.json"
            if not vj_path.exists():
                continue

            try:
                with open(vj_path) as f:
                    spec = json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                result.warnings.append(
                    f"Failed to read {vj_path}: {exc}"
                )
                continue

            skill_id = spec.get("skill_id", skill_dir.name)
            result.raw_specs[skill_id] = spec

            try:
                self._process_skill(skill_id, spec, result)
            except Exception as exc:
                result.warnings.append(
                    f"Failed to process {skill_id}: {exc}"
                )

        return result

    def _process_skill(
        self,
        skill_id: str,
        spec: Dict[str, Any],
        result: LoadedConstraints,
    ) -> None:
        """Route a skill spec to the appropriate constraint builder."""
        vr = spec.get("verification_requirements", {})
        sc = vr.get("safety_constraints", {})
        rc = vr.get("resource_constraints", {})

        # Extract approval categories from compliance_mappings
        approval_cats = self._extract_approval_categories(spec)

        tool_names = _SKILL_TO_TOOLS.get(skill_id, [])

        if skill_id == "web_browsing":
            wfc = WebFetchConstraints(
                allowlist_patterns=_compile_patterns(
                    sc.get("url_allowlist_patterns", [])
                ),
                blocklist_patterns=_compile_patterns(
                    sc.get("url_blocklist_patterns", [])
                ),
                timeout_seconds=rc.get("timeout_seconds", 30),
                max_body_size_bytes=rc.get("max_body_size_bytes", 10_485_760),
                max_requests_per_minute=rc.get("max_requests_per_minute", 60),
                user_agent_required=sc.get("user_agent_required", True),
                approval_categories=approval_cats,
            )
            result.web_fetch = wfc
            for tn in tool_names:
                result.approval_categories[tn] = approval_cats

        elif skill_id == "file_operations":
            # Read tool: same constraints but NO approval categories
            # (read-only tools should not require "data_export" approval)
            fc_read = FileConstraints(
                path_allowlist_patterns=_compile_patterns(
                    sc.get("path_allowlist_patterns", [])
                ),
                path_blocklist_patterns=_compile_patterns(
                    sc.get("path_blocklist_patterns", [])
                ),
                allowed_extensions=frozenset(
                    sc.get("allowed_extensions", [])
                ),
                max_file_size_bytes=rc.get("max_file_size_bytes", 10_000_000),
                timeout_seconds=rc.get("timeout_seconds", 60),
                approval_categories=frozenset(),  # read = no approval
            )
            # Write tool: full constraints including approval categories
            fc_write = FileConstraints(
                path_allowlist_patterns=_compile_patterns(
                    sc.get("path_allowlist_patterns", [])
                ),
                path_blocklist_patterns=_compile_patterns(
                    sc.get("path_blocklist_patterns", [])
                ),
                allowed_extensions=frozenset(
                    sc.get("allowed_extensions", [])
                ),
                max_file_size_bytes=rc.get("max_file_size_bytes", 10_000_000),
                timeout_seconds=rc.get("timeout_seconds", 60),
                approval_categories=approval_cats,
            )
            result.file_read = fc_read
            result.file_write = fc_write
            # Only file_write gets approval categories; file_read is read-only
            result.approval_categories["file_write"] = approval_cats
            # file_read explicitly gets empty set (not omitted)
            result.approval_categories["file_read"] = frozenset()

        elif skill_id == "database_query":
            dbc = DatabaseQueryConstraints(
                forbidden_columns=frozenset(
                    sc.get("forbidden_columns", [])
                ),
                allowed_tables=tuple(sc.get("allowed_tables", [])),
                read_only=sc.get("read_only", True),
                max_rows_per_query=rc.get("max_rows_per_query", 10_000),
                query_timeout_seconds=rc.get("query_timeout_seconds", 30),
                approval_categories=approval_cats,
            )
            result.database_query = dbc
            for tn in tool_names:
                result.approval_categories[tn] = approval_cats

        else:
            result.warnings.append(
                f"No constraint mapping for skill_id={skill_id}"
            )

    @staticmethod
    def _extract_approval_categories(spec: Dict[str, Any]) -> FrozenSet[str]:
        """
        Extract approval categories from compliance_mappings.

        If the skill is SOX-applicable, it should require approval for
        external communication.  This is a conservative default that
        can be overridden by explicit VERIFICATION.json fields.
        """
        cm = spec.get("compliance_mappings", {})
        categories: Set[str] = set()

        # Explicit field (preferred)
        explicit = spec.get("approval_categories", [])
        if explicit:
            return frozenset(explicit)

        # Infer from compliance applicability
        if cm.get("hipaa", {}).get("applies"):
            categories.add("data_export")
        if cm.get("sox", {}).get("applies"):
            categories.add("send_external_communication")

        return frozenset(categories)


# ── Convenience function ─────────────────────────────────────────────

def load_tool_constraints(
    skills_dir: Optional[Path] = None,
) -> LoadedConstraints:
    """
    Load tool constraints from VERIFICATION.json files.

    If ``skills_dir`` is None or doesn't exist, returns empty
    constraints (tools fall back to hardcoded defaults).
    """
    if skills_dir is None:
        return LoadedConstraints()
    loader = ToolConstraintLoader(skills_dir)
    return loader.load()

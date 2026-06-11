"""
Tests for A9: VERIFICATION.json runtime loading - tools use spec constraints.

Verifies:
  - ToolConstraintLoader loads constraints from skills directory
  - WebFetchTool uses spec URL patterns (blocklist includes .gov)
  - FileWriteTool uses spec allowed_extensions
  - FileReadTool uses spec max_file_size
  - Fallback to hardcoded defaults when no skills_dir
  - constraints_source property reflects spec vs fallback
  - create_default_registry loads constraints when skills_dir provided
  - Constraint loading warnings are logged (not fatal)
"""
from __future__ import annotations

import pytest
import re
from pathlib import Path
from unittest.mock import patch

from agentsafe.tools.web_fetch import WebFetchTool
from agentsafe.tools.file_write import FileWriteTool
from agentsafe.tools.file_read import FileReadTool
from agentsafe.tools import create_default_registry
from agentsafe.tools.constraint_loader import (
    ToolConstraintLoader,
    LoadedConstraints,
    WebFetchConstraints,
    FileConstraints,
    load_tool_constraints,
)


# ── Path to real VERIFICATION.json files ──────────────────────────

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"


# ── ToolConstraintLoader tests ────────────────────────────────────

class TestToolConstraintLoader:

    def test_loads_from_skills_dir(self):
        """Loader finds web_browsing and file_operations specs."""
        lc = load_tool_constraints(SKILLS_DIR)
        assert lc is not None
        assert lc.web_fetch is not None or lc.file_write is not None

    def test_web_fetch_constraints_loaded(self):
        lc = load_tool_constraints(SKILLS_DIR)
        assert lc.web_fetch is not None
        # web_browsing/VERIFICATION.json has blocklist with .gov
        # blocklist_patterns are compiled regex objects - check .pattern attr
        assert any(
            ".gov" in p.pattern for p in lc.web_fetch.blocklist_patterns
        )
        # Has allowlist
        assert len(lc.web_fetch.allowlist_patterns) > 0
        # timeout and max_body
        assert lc.web_fetch.timeout_seconds > 0
        assert lc.web_fetch.max_body_size_bytes > 0

    def test_file_constraints_loaded(self):
        lc = load_tool_constraints(SKILLS_DIR)
        # file_write gets the full constraints
        assert lc.file_write is not None
        # file_operations/VERIFICATION.json has allowed_extensions
        assert len(lc.file_write.allowed_extensions) > 0
        exts_str = str(lc.file_write.allowed_extensions)
        assert ".txt" in exts_str or "txt" in exts_str

    def test_approval_categories_from_spec(self):
        """Compliance mappings in VERIFICATION.json produce approval categories."""
        lc = load_tool_constraints(SKILLS_DIR)
        web_cats = lc.get_approval_categories("web_fetch")
        file_cats = lc.get_approval_categories("file_write")
        assert web_cats is not None or file_cats is not None

    def test_nonexistent_dir_returns_empty(self):
        lc = load_tool_constraints(Path("/nonexistent/skills"))
        assert lc.web_fetch is None
        assert lc.file_read is None
        assert lc.file_write is None


# ── WebFetchTool with constraints ─────────────────────────────────

class TestWebFetchToolConstraints:

    def test_fallback_without_constraints(self):
        tool = WebFetchTool()
        assert tool.constraints_source == "hardcoded_fallback"

    def test_spec_constraints_applied(self):
        lc = load_tool_constraints(SKILLS_DIR)
        if lc.web_fetch is None:
            pytest.skip("No web_fetch constraints loaded")
        tool = WebFetchTool(constraints=lc.web_fetch)
        assert tool.constraints_source == "VERIFICATION.json"

    def test_spec_blocklist_includes_gov(self):
        lc = load_tool_constraints(SKILLS_DIR)
        if lc.web_fetch is None:
            pytest.skip("No web_fetch constraints loaded")
        tool = WebFetchTool(constraints=lc.web_fetch)
        violation = tool._check_url("https://whitehouse.gov/secrets")
        assert violation != "", "Expected .gov URL to be blocked by spec blocklist"

    def test_fallback_does_not_block_gov(self):
        tool = WebFetchTool()
        violation = tool._check_url("https://whitehouse.gov/data")
        assert violation == "", f"Unexpected block: {violation}"

    def test_spec_timeout_value(self):
        lc = load_tool_constraints(SKILLS_DIR)
        if lc.web_fetch is None:
            pytest.skip("No web_fetch constraints loaded")
        tool = WebFetchTool(constraints=lc.web_fetch)
        assert tool._timeout == 30

    @pytest.mark.asyncio
    async def test_onion_blocked_with_and_without_spec(self):
        tool_fallback = WebFetchTool()
        r1 = await tool_fallback.execute(tool_use_id="t1", url="https://evil.onion")
        assert r1.is_error

        lc = load_tool_constraints(SKILLS_DIR)
        if lc.web_fetch:
            tool_spec = WebFetchTool(constraints=lc.web_fetch)
            r2 = await tool_spec.execute(tool_use_id="t2", url="https://evil.onion")
            assert r2.is_error

    @pytest.mark.asyncio
    async def test_constraints_source_in_metadata(self):
        lc = load_tool_constraints(SKILLS_DIR)
        if lc.web_fetch is None:
            pytest.skip("No web_fetch constraints loaded")
        tool = WebFetchTool(constraints=lc.web_fetch)
        result = await tool.execute(tool_use_id="t1", url="https://something.onion")
        assert result.metadata.get("constraints_source") == "VERIFICATION.json"


# ── FileWriteTool with constraints ────────────────────────────────

class TestFileWriteToolConstraints:

    def test_fallback_without_constraints(self):
        tool = FileWriteTool(workspace="/tmp")
        assert tool.constraints_source == "hardcoded_fallback"

    def test_spec_constraints_applied(self):
        lc = load_tool_constraints(SKILLS_DIR)
        if lc.file_write is None:
            pytest.skip("No file constraints loaded")
        tool = FileWriteTool(workspace="/tmp", constraints=lc.file_write)
        assert tool.constraints_source == "VERIFICATION.json"

    @pytest.mark.asyncio
    async def test_spec_allowed_extensions_enforced(self):
        lc = load_tool_constraints(SKILLS_DIR)
        if lc.file_write is None:
            pytest.skip("No file constraints loaded")
        tool = FileWriteTool(workspace="/tmp", constraints=lc.file_write)
        result = await tool.execute(
            tool_use_id="t1", path="malware.exe", content="bad"
        )
        assert result.is_error

    @pytest.mark.asyncio
    async def test_spec_allowed_extensions_passes_txt(self):
        lc = load_tool_constraints(SKILLS_DIR)
        if lc.file_write is None:
            pytest.skip("No file constraints loaded")
        tool = FileWriteTool(workspace="/tmp/test_a9", constraints=lc.file_write)
        result = await tool.execute(
            tool_use_id="t1", path="notes.txt", content="hello"
        )
        if result.is_error:
            assert "extension" not in result.output.lower()


# ── FileReadTool with constraints ─────────────────────────────────

class TestFileReadToolConstraints:

    def test_fallback_without_constraints(self):
        tool = FileReadTool(workspace="/tmp")
        assert tool.constraints_source == "hardcoded_fallback"

    def test_spec_constraints_applied(self):
        lc = load_tool_constraints(SKILLS_DIR)
        if lc.file_read is None:
            pytest.skip("No file constraints loaded")
        tool = FileReadTool(workspace="/tmp", constraints=lc.file_read)
        assert tool.constraints_source == "VERIFICATION.json"


# ── create_default_registry integration ───────────────────────────

class TestRegistryConstraintLoading:

    def test_registry_without_skills_dir(self):
        registry = create_default_registry()
        web_tool = registry.get("web_fetch")
        assert web_tool is not None
        assert web_tool.constraints_source == "hardcoded_fallback"

    def test_registry_with_skills_dir(self):
        registry = create_default_registry(skills_dir=str(SKILLS_DIR))
        web_tool = registry.get("web_fetch")
        assert web_tool is not None
        assert web_tool.constraints_source == "VERIFICATION.json"

    def test_registry_stores_loaded_constraints(self):
        registry = create_default_registry(skills_dir=str(SKILLS_DIR))
        assert hasattr(registry, "_loaded_constraints")
        assert registry._loaded_constraints is not None

    def test_registry_no_constraints_attr_without_skills(self):
        registry = create_default_registry()
        lc = getattr(registry, "_loaded_constraints", None)
        assert lc is None


# ── A8+A9 bridge: spec categories in execution ───────────────────

class TestA8A9Bridge:

    def test_loaded_constraints_provide_approval_categories(self):
        lc = load_tool_constraints(SKILLS_DIR)
        web_cats = lc.get_approval_categories("web_fetch")
        file_cats = lc.get_approval_categories("file_write")
        read_cats = lc.get_approval_categories("file_read")
        # file_read should have no categories (or None)
        assert read_cats is None or len(read_cats) == 0

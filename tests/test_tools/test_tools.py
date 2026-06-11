"""
Tests for agentsafe.tools - base classes, registry, and concrete tools.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path
from typing import Any, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentsafe.sandbox.network import NetworkPolicy
from agentsafe.tools.base import BaseTool, ToolParameter, ToolResult
from agentsafe.tools.registry import ToolRegistry
from agentsafe.tools.web_fetch import WebFetchTool
from agentsafe.tools.python_eval import PythonEvalTool
from agentsafe.tools.file_write import FileWriteTool
from agentsafe.tools import create_default_registry
from agentsafe.capabilities.tokens import CapabilityToken


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ToolResult
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestToolResult:
    def test_truncation(self):
        long_text = "x" * 50_000
        result = ToolResult(tool_use_id="t1", output=long_text)
        truncated = result.truncated(max_chars=1000)
        assert len(truncated.output) < len(long_text)
        assert truncated.metadata.get("truncated") is True

    def test_no_truncation_when_short(self):
        result = ToolResult(tool_use_id="t1", output="short")
        truncated = result.truncated(max_chars=1000)
        assert truncated.output == "short"
        assert truncated is result  # same object

    def test_error_result(self):
        result = ToolResult(tool_use_id="t1", output="boom", is_error=True)
        assert result.is_error


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BaseTool + to_anthropic_tool()
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class _DummyTool(BaseTool):
    @property
    def name(self) -> str:
        return "dummy"

    @property
    def description(self) -> str:
        return "A test tool"

    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(name="query", type="string", description="Search query"),
            ToolParameter(name="limit", type="integer", description="Max results", required=False),
        ]

    @property
    def required_capabilities(self) -> List[str]:
        return ["test:read"]

    async def execute(self, *, tool_use_id: str, **kwargs: Any) -> ToolResult:
        return ToolResult(tool_use_id=tool_use_id, output=f"ok: {kwargs}")


class TestBaseTool:
    def test_anthropic_schema_generation(self):
        tool = _DummyTool()
        schema = tool.to_anthropic_tool()
        assert schema["name"] == "dummy"
        assert "query" in schema["input_schema"]["properties"]
        assert "query" in schema["input_schema"]["required"]
        assert "limit" not in schema["input_schema"]["required"]

    @pytest.mark.asyncio
    async def test_execute(self):
        tool = _DummyTool()
        result = await tool.execute(tool_use_id="t1", query="hello")
        assert result.output == "ok: {'query': 'hello'}"
        assert not result.is_error

    def test_repr(self):
        tool = _DummyTool()
        assert "dummy" in repr(tool)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ToolRegistry
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestToolRegistry:
    def test_register_and_get(self):
        reg = ToolRegistry()
        tool = _DummyTool()
        reg.register(tool)
        assert reg.get("dummy") is tool
        assert "dummy" in reg
        assert len(reg) == 1

    def test_list_all(self):
        reg = ToolRegistry()
        reg.register(_DummyTool())
        assert len(reg.list_all()) == 1

    def test_list_for_token_filters_by_capability(self):
        reg = ToolRegistry()
        reg.register(_DummyTool())  # requires test:read

        token_good = CapabilityToken(permissions=["test:read"])
        token_bad = CapabilityToken(permissions=["other:write"])

        assert len(reg.list_for_token(token_good)) == 1
        assert len(reg.list_for_token(token_bad)) == 0

    def test_to_anthropic_tools_unfiltered(self):
        reg = ToolRegistry()
        reg.register(_DummyTool())
        schemas = reg.to_anthropic_tools()
        assert len(schemas) == 1
        assert schemas[0]["name"] == "dummy"

    def test_to_anthropic_tools_filtered(self):
        reg = ToolRegistry()
        reg.register(_DummyTool())
        token = CapabilityToken(permissions=["other:write"])
        schemas = reg.to_anthropic_tools(token)
        assert len(schemas) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WebFetchTool
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestWebFetchTool:
    def test_metadata(self):
        tool = WebFetchTool()
        assert tool.name == "web_fetch"
        assert "network:http:read" in tool.required_capabilities
        schema = tool.to_anthropic_tool()
        assert "url" in schema["input_schema"]["properties"]

    @pytest.mark.asyncio
    async def test_missing_url(self):
        tool = WebFetchTool()
        result = await tool.execute(tool_use_id="t1")
        assert result.is_error
        assert "required" in result.output.lower()

    @pytest.mark.asyncio
    async def test_http_url_blocked(self):
        tool = WebFetchTool()
        result = await tool.execute(tool_use_id="t1", url="http://example.com")
        assert result.is_error
        assert "allowlist" in result.output.lower()

    @pytest.mark.asyncio
    async def test_onion_url_blocked(self):
        tool = WebFetchTool()
        result = await tool.execute(tool_use_id="t1", url="https://something.onion")
        assert result.is_error
        assert "blocklist" in result.output.lower()

    @pytest.mark.asyncio
    async def test_url_check_allows_https(self):
        assert WebFetchTool()._check_url("https://example.com") == ""

    @pytest.mark.asyncio
    async def test_url_check_blocks_http(self):
        assert "allowlist" in WebFetchTool()._check_url("http://evil.com")

    @pytest.mark.asyncio
    async def test_profile_network_policy_blocks_external_fetch(self):
        tool = WebFetchTool(network_policy=NetworkPolicy.hipaa())
        result = await tool.execute(tool_use_id="t1", url="https://example.com")
        assert result.is_error
        assert result.metadata["network_policy"] == "loopback_only"
        assert "blocked by policy" in result.output.lower()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PythonEvalTool
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPythonEvalTool:
    def test_metadata(self):
        tool = PythonEvalTool()
        assert tool.name == "python_eval"
        assert "compute:python:eval" in tool.required_capabilities

    @pytest.mark.asyncio
    async def test_simple_eval(self):
        tool = PythonEvalTool()
        result = await tool.execute(tool_use_id="t1", code="print(2 + 3)")
        assert not result.is_error
        assert "5" in result.output

    @pytest.mark.asyncio
    async def test_multiline_code(self):
        tool = PythonEvalTool()
        code = "for i in range(3):\n    print(i)"
        result = await tool.execute(tool_use_id="t1", code=code)
        assert not result.is_error
        assert "0" in result.output
        assert "2" in result.output

    @pytest.mark.asyncio
    async def test_syntax_error(self):
        tool = PythonEvalTool()
        result = await tool.execute(tool_use_id="t1", code="def f(")
        assert result.is_error
        assert "SyntaxError" in result.output

    @pytest.mark.asyncio
    async def test_runtime_error(self):
        tool = PythonEvalTool()
        result = await tool.execute(tool_use_id="t1", code="1/0")
        assert result.is_error
        assert "ZeroDivision" in result.output

    @pytest.mark.asyncio
    async def test_empty_code_rejected(self):
        tool = PythonEvalTool()
        result = await tool.execute(tool_use_id="t1", code="")
        assert result.is_error

    @pytest.mark.asyncio
    async def test_no_output_message(self):
        tool = PythonEvalTool()
        result = await tool.execute(tool_use_id="t1", code="x = 42")
        assert not result.is_error
        assert "No output" in result.output


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FileWriteTool
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestFileWriteTool:
    def test_metadata(self):
        tool = FileWriteTool()
        assert tool.name == "file_write"
        assert "filesystem:write" in tool.required_capabilities

    @pytest.mark.asyncio
    async def test_write_file(self):
        with tempfile.TemporaryDirectory() as ws:
            tool = FileWriteTool(workspace=ws)
            result = await tool.execute(
                tool_use_id="t1", filename="test.txt", content="hello world",
            )
            assert not result.is_error
            assert "11" in result.output  # 11 bytes
            assert (Path(ws) / "test.txt").read_text() == "hello world"

    @pytest.mark.asyncio
    async def test_write_subdirectory(self):
        with tempfile.TemporaryDirectory() as ws:
            tool = FileWriteTool(workspace=ws)
            result = await tool.execute(
                tool_use_id="t1", filename="sub/dir/file.md", content="# Hello",
            )
            assert not result.is_error
            assert (Path(ws) / "sub" / "dir" / "file.md").exists()

    @pytest.mark.asyncio
    async def test_path_traversal_blocked(self):
        with tempfile.TemporaryDirectory() as ws:
            tool = FileWriteTool(workspace=ws)
            result = await tool.execute(
                tool_use_id="t1", filename="../../../etc/passwd", content="hacked",
            )
            assert result.is_error
            assert "traversal" in result.output.lower()

    @pytest.mark.asyncio
    async def test_absolute_path_blocked(self):
        with tempfile.TemporaryDirectory() as ws:
            tool = FileWriteTool(workspace=ws)
            result = await tool.execute(
                tool_use_id="t1", filename="/tmp/evil.txt", content="hacked",
            )
            assert result.is_error

    @pytest.mark.asyncio
    async def test_dangerous_extension_blocked(self):
        with tempfile.TemporaryDirectory() as ws:
            tool = FileWriteTool(workspace=ws)
            result = await tool.execute(
                tool_use_id="t1", filename="payload.exe", content="bad",
            )
            assert result.is_error
            assert ".exe" in result.output

    @pytest.mark.asyncio
    async def test_missing_filename_error(self):
        tool = FileWriteTool()
        result = await tool.execute(tool_use_id="t1", content="hello")
        assert result.is_error


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# create_default_registry
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestDefaultRegistry:
    def test_creates_three_tools(self):
        reg = create_default_registry()
        assert len(reg) == 4  # web_fetch, python_eval, file_write, file_read
        assert "web_fetch" in reg
        assert "python_eval" in reg
        assert "file_write" in reg

    def test_all_tools_have_schemas(self):
        reg = create_default_registry()
        for tool in reg.list_all():
            schema = tool.to_anthropic_tool()
            assert "name" in schema
            assert "input_schema" in schema

    def test_filtering_with_full_token(self):
        reg = create_default_registry()
        token = CapabilityToken(permissions=[
            "network:http:read",
            "compute:python:eval",
            "filesystem:write",
        ])
        available = reg.list_for_token(token)
        assert len(available) == 3

    def test_filtering_with_limited_token(self):
        reg = create_default_registry()
        token = CapabilityToken(permissions=["compute:python:eval"])
        available = reg.list_for_token(token)
        assert len(available) == 1
        assert available[0].name == "python_eval"

    def test_profile_aware_registry_uses_restricted_runtime_policies(self):
        reg = create_default_registry(
            compliance_policy="hipaa",
            verification_profile={
                "sandbox_profile": "phi_internal_only",
                "stage_role": "intake",
            },
        )
        web_tool = reg.get("web_fetch")
        py_tool = reg.get("python_eval")
        assert web_tool is not None
        assert py_tool is not None
        assert getattr(web_tool, "_fetcher").policy.mode.value == "loopback_only"
        assert getattr(py_tool, "_sandbox_policy_name") == "HIPAA"
        assert getattr(py_tool, "_seccomp_evidence").get("profile_name") == "network_blocked"

    def test_release_profile_takes_precedence_over_generic_hipaa_runtime(self):
        reg = create_default_registry(
            compliance_policy="hipaa",
            verification_profile={
                "sandbox_profile": "phi_release_attested",
                "stage_role": "release",
            },
        )
        py_tool = reg.get("python_eval")
        assert py_tool is not None
        assert getattr(py_tool, "_sandbox_policy_name") == "HIPAAReleaseAttested"
        assert getattr(py_tool, "_seccomp_evidence").get("profile_name") == "network_blocked"


# ═══════════════════════════════════════════════════════════════════
# FileReadTool tests
# ═══════════════════════════════════════════════════════════════════


class TestFileReadTool:
    @pytest.fixture
    def tool(self, tmp_path):
        from agentsafe.tools.file_read import FileReadTool
        return FileReadTool(workspace=str(tmp_path))

    @pytest.mark.asyncio
    async def test_read_text_file(self, tool, tmp_path):
        (tmp_path / "hello.txt").write_text("hello world")
        r = await tool.execute(tool_use_id="t1", filename="hello.txt")
        assert not r.is_error
        assert "hello world" in r.output

    @pytest.mark.asyncio
    async def test_missing_filename(self, tool):
        r = await tool.execute(tool_use_id="t1")
        assert r.is_error
        assert "required" in r.output.lower()

    @pytest.mark.asyncio
    async def test_path_traversal_blocked(self, tool):
        r = await tool.execute(tool_use_id="t1", filename="../../../etc/passwd")
        assert r.is_error
        assert "traversal" in r.output.lower()

    @pytest.mark.asyncio
    async def test_absolute_path_blocked(self, tool):
        r = await tool.execute(tool_use_id="t1", filename="/etc/passwd")
        assert r.is_error

    @pytest.mark.asyncio
    async def test_file_not_found(self, tool):
        r = await tool.execute(tool_use_id="t1", filename="nonexistent.txt")
        assert r.is_error
        assert "not found" in r.output.lower()

    @pytest.mark.asyncio
    async def test_directory_rejected(self, tool, tmp_path):
        (tmp_path / "subdir").mkdir()
        r = await tool.execute(tool_use_id="t1", filename="subdir")
        assert r.is_error
        assert "not a file" in r.output.lower()

    @pytest.mark.asyncio
    async def test_binary_file_rejected(self, tool, tmp_path):
        (tmp_path / "data.bin").write_bytes(bytes(range(256)))
        r = await tool.execute(tool_use_id="t1", filename="data.bin")
        assert r.is_error
        assert "binary" in r.output.lower()

    @pytest.mark.asyncio
    async def test_large_file_rejected(self, tool, tmp_path):
        # Write a file larger than _MAX_READ_BYTES (512KB)
        (tmp_path / "big.txt").write_text("x" * 600_000)
        r = await tool.execute(tool_use_id="t1", filename="big.txt")
        assert r.is_error
        assert "too large" in r.output.lower()

    @pytest.mark.asyncio
    async def test_nested_read(self, tool, tmp_path):
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "data.csv").write_text("a,b,c\n1,2,3\n")
        r = await tool.execute(tool_use_id="t1", filename="sub/data.csv")
        assert not r.is_error
        assert "a,b,c" in r.output

    @pytest.mark.asyncio
    async def test_metadata(self, tool, tmp_path):
        (tmp_path / "meta.txt").write_text("content")
        r = await tool.execute(tool_use_id="t1", filename="meta.txt")
        assert r.metadata["filename"] == "meta.txt"
        assert r.metadata["bytes_read"] > 0

    def test_properties(self, tool):
        assert tool.name == "file_read"
        assert "filesystem:read" in tool.required_capabilities
        assert tool.estimated_cost_cents > 0


# ═══════════════════════════════════════════════════════════════════
# WebFetchTool supplemental tests
# ═══════════════════════════════════════════════════════════════════


class TestWebFetchToolSafety:
    @pytest.fixture
    def tool(self):
        from agentsafe.tools.web_fetch import WebFetchTool
        return WebFetchTool()

    @pytest.mark.asyncio
    async def test_missing_url(self, tool):
        r = await tool.execute(tool_use_id="t1")
        assert r.is_error
        assert "required" in r.output.lower()

    @pytest.mark.asyncio
    async def test_blocked_domain(self, tool):
        r = await tool.execute(tool_use_id="t1", url="http://evil.onion/page")
        assert r.is_error
        assert "blocked" in r.output.lower()

    @pytest.mark.asyncio
    async def test_non_http_rejected(self, tool):
        r = await tool.execute(tool_use_id="t1", url="ftp://files.example.com/data")
        assert r.is_error

    def test_properties(self, tool):
        assert tool.name == "web_fetch"
        assert "network:http:read" in tool.required_capabilities

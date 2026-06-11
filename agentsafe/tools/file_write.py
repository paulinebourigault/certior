"""
File write tool - safe file creation in a sandboxed workspace.

Enforces:
  - All writes confined to a workspace directory
  - No path traversal (.. segments rejected)
  - Maximum file size limit
  - Extension allowlist (optional)

Constraints are loaded from VERIFICATION.json at startup (A9 FIX).
If no spec constraints are provided, hardcoded defaults are used.

Requires capability: ``filesystem:write``
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, List, Optional, TYPE_CHECKING

from .base import BaseTool, ToolParameter, ToolResult

if TYPE_CHECKING:
    from .constraint_loader import FileConstraints

# ── Hardcoded fallback defaults ──────────────────────────────────────
_FALLBACK_MAX_FILE_BYTES = 1_048_576  # 1 MB
_FALLBACK_BLOCKED_EXTENSIONS = {".exe", ".sh", ".bat", ".cmd", ".ps1", ".dll", ".so"}


class FileWriteTool(BaseTool):
    """
    Write text content to a file in the agent workspace.

    All files are written under a configurable workspace root
    (defaults to a temporary directory).  Path traversal is blocked.

    A9 FIX: Accepts optional ``FileConstraints`` loaded from
    ``skills/file_operations/VERIFICATION.json``.  When provided,
    spec-derived size limits, extension restrictions, and path
    patterns are used instead of hardcoded fallbacks.
    """

    def __init__(
        self,
        workspace: Optional[str] = None,
        constraints: Optional[FileConstraints] = None,
    ) -> None:
        self._workspace = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix="certior_ws_"))
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._constraints = constraints

        if constraints is not None:
            self._max_file_bytes = constraints.max_file_size_bytes
            # Spec allowed_extensions: if provided, use as allowlist;
            # if empty, fall back to blocklist approach
            self._allowed_extensions = constraints.allowed_extensions or frozenset()
            self._path_blocklist = list(constraints.path_blocklist_patterns)
            self._constraints_source = "VERIFICATION.json"
        else:
            self._max_file_bytes = _FALLBACK_MAX_FILE_BYTES
            self._allowed_extensions = frozenset()
            self._path_blocklist = []
            self._constraints_source = "hardcoded_fallback"

    @property
    def workspace(self) -> Path:
        return self._workspace

    @property
    def constraints_source(self) -> str:
        return self._constraints_source

    @property
    def name(self) -> str:
        return "file_write"

    @property
    def description(self) -> str:
        return (
            "Write text content to a file. Use this to save results, "
            "create reports, write code files, or persist any output. "
            "Provide a filename (relative path) and the content to write."
        )

    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(
                name="filename",
                type="string",
                description=(
                    "Relative file path (e.g. 'report.md', 'results/data.csv'). "
                    "Subdirectories will be created automatically."
                ),
            ),
            ToolParameter(
                name="content",
                type="string",
                description="Text content to write to the file.",
            ),
        ]

    @property
    def required_capabilities(self) -> List[str]:
        return ["filesystem:write"]

    @property
    def estimated_cost_cents(self) -> int:
        return 1

    async def execute(self, *, tool_use_id: str, **kwargs: Any) -> ToolResult:
        filename: str = kwargs.get("filename", "")
        content: str = kwargs.get("content", "")

        if not filename:
            return ToolResult(
                tool_use_id=tool_use_id,
                output="Error: 'filename' parameter is required.",
                is_error=True,
            )

        # Security: block path traversal
        if ".." in filename or filename.startswith("/") or filename.startswith("~"):
            return ToolResult(
                tool_use_id=tool_use_id,
                output="Error: Path traversal not allowed. Use relative paths only.",
                is_error=True,
            )

        # A9: Check path against spec blocklist patterns
        for pattern in self._path_blocklist:
            if pattern.match(filename):
                return ToolResult(
                    tool_use_id=tool_use_id,
                    output=f"Error: Path matches blocklist pattern from VERIFICATION.json.",
                    is_error=True,
                )

        # Security: extension check
        ext = Path(filename).suffix.lower()
        if self._allowed_extensions:
            # A9: Spec defines allowed extensions - use as allowlist
            if ext and ext not in self._allowed_extensions:
                return ToolResult(
                    tool_use_id=tool_use_id,
                    output=f"Error: Extension '{ext}' not in allowed list: {sorted(self._allowed_extensions)}",
                    is_error=True,
                )
        else:
            # Fallback: use blocklist
            if ext in _FALLBACK_BLOCKED_EXTENSIONS:
                return ToolResult(
                    tool_use_id=tool_use_id,
                    output=f"Error: Extension '{ext}' is not allowed.",
                    is_error=True,
                )

        # Size limit (from spec or fallback)
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > self._max_file_bytes:
            return ToolResult(
                tool_use_id=tool_use_id,
                output=f"Error: Content exceeds size limit ({len(content_bytes):,} bytes > {self._max_file_bytes:,}).",
                is_error=True,
            )

        try:
            target = (self._workspace / filename).resolve()
            # Double-check the resolved path is under workspace
            if not str(target).startswith(str(self._workspace.resolve())):
                return ToolResult(
                    tool_use_id=tool_use_id,
                    output="Error: Resolved path escapes workspace.",
                    is_error=True,
                )

            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content_bytes)

            return ToolResult(
                tool_use_id=tool_use_id,
                output=f"Wrote {len(content_bytes):,} bytes to {filename}",
                metadata={
                    "path": str(target),
                    "bytes_written": len(content_bytes),
                    "filename": filename,
                    "constraints_source": self._constraints_source,
                },
            )

        except Exception as exc:
            return ToolResult(
                tool_use_id=tool_use_id,
                output=f"Error: {type(exc).__name__}: {exc}",
                is_error=True,
            )

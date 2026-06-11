"""
File read tool - safe file reading from the agent workspace.

Enforces:
  - All reads confined to a workspace directory
  - No path traversal (.. segments rejected)
  - Maximum read size limit
  - Binary file detection and rejection

Constraints are loaded from VERIFICATION.json at startup (A9 FIX).

Requires capability: ``filesystem:read``
"""
from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any, List, Optional, TYPE_CHECKING

from .base import BaseTool, ToolParameter, ToolResult

if TYPE_CHECKING:
    from .constraint_loader import FileConstraints

_FALLBACK_MAX_READ_BYTES = 512_000  # ~500 KB


class FileReadTool(BaseTool):
    """
    Read text content from a file in the agent workspace.

    All reads are restricted to files under a configurable workspace root.
    Path traversal is blocked.  Binary files are rejected.

    A9 FIX: Accepts optional ``FileConstraints`` loaded from
    ``skills/file_operations/VERIFICATION.json``.
    """

    def __init__(
        self,
        workspace: Optional[str] = None,
        constraints: Optional[FileConstraints] = None,
    ) -> None:
        if workspace:
            self._workspace = Path(workspace)
        else:
            import tempfile
            self._workspace = Path(tempfile.mkdtemp(prefix="certior_ws_"))
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._constraints = constraints

        if constraints is not None:
            self._max_read_bytes = constraints.max_file_size_bytes
            self._path_blocklist = list(constraints.path_blocklist_patterns)
            self._constraints_source = "VERIFICATION.json"
        else:
            self._max_read_bytes = _FALLBACK_MAX_READ_BYTES
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
        return "file_read"

    @property
    def description(self) -> str:
        return (
            "Read the text content of a file from the workspace. "
            "Use this to inspect files previously written, check results, "
            "or read input data.  Provide a relative file path."
        )

    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(
                name="filename",
                type="string",
                description=(
                    "Relative file path to read (e.g. 'report.md', 'results/data.csv')."
                ),
            ),
        ]

    @property
    def required_capabilities(self) -> List[str]:
        return ["filesystem:read"]

    @property
    def estimated_cost_cents(self) -> int:
        return 1

    @property
    def input_labels(self) -> List[str]:
        return ["internal"]

    @property
    def output_labels(self) -> List[str]:
        return ["internal"]

    async def execute(self, *, tool_use_id: str, **kwargs: Any) -> ToolResult:
        filename: str = kwargs.get("filename", "")

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
                    output="Error: Path matches blocklist pattern from VERIFICATION.json.",
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

            if not target.exists():
                return ToolResult(
                    tool_use_id=tool_use_id,
                    output=f"Error: File not found: {filename}",
                    is_error=True,
                )

            if not target.is_file():
                return ToolResult(
                    tool_use_id=tool_use_id,
                    output=f"Error: Not a file: {filename}",
                    is_error=True,
                )

            # Size check (from spec or fallback)
            file_size = target.stat().st_size
            if file_size > self._max_read_bytes:
                return ToolResult(
                    tool_use_id=tool_use_id,
                    output=(
                        f"Error: File too large ({file_size:,} bytes > "
                        f"{self._max_read_bytes:,} limit).  Consider reading a portion."
                    ),
                    is_error=True,
                )

            # Binary detection via content sniffing
            try:
                content = target.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                return ToolResult(
                    tool_use_id=tool_use_id,
                    output=f"Error: File appears to be binary and cannot be read as text: {filename}",
                    is_error=True,
                )

            return ToolResult(
                tool_use_id=tool_use_id,
                output=content,
                metadata={
                    "path": str(target),
                    "bytes_read": len(content.encode("utf-8")),
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

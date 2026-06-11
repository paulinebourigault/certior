"""
Base tool interface for Certior verified tools.

Every tool exposes:
  - A JSON schema for the LLM function-calling API
  - Capability requirements for the verification layer
  - An async execute() method

Tools are the bridge between the LLM agent loop and the verification
infrastructure: each invocation is verified against capability tokens
before execution proceeds.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ToolParameter:
    """Schema for a single tool parameter."""
    name: str
    type: str  # "string", "integer", "boolean", "number", "array", "object"
    description: str
    required: bool = True
    enum: Optional[List[str]] = None
    default: Any = None


@dataclass(frozen=True)
class ToolResult:
    """Standardised result from a tool execution."""
    tool_use_id: str
    output: str
    is_error: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def truncated(self, max_chars: int = 16_000) -> "ToolResult":
        """Return a copy with output truncated to *max_chars*."""
        if len(self.output) <= max_chars:
            return self
        truncated_output = (
            self.output[: max_chars // 2]
            + f"\n\n... [{len(self.output) - max_chars} chars truncated] ...\n\n"
            + self.output[-(max_chars // 2) :]
        )
        return ToolResult(
            tool_use_id=self.tool_use_id,
            output=truncated_output,
            is_error=self.is_error,
            metadata={**self.metadata, "truncated": True},
        )


class BaseTool(ABC):
    """
    Abstract base for all Certior tools.

    Subclasses must implement:
      - name, description (properties)
      - parameters() -> list of ToolParameter
      - execute(**kwargs) -> str
      - required_capabilities -> list of capability strings
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique tool identifier (snake_case)."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description shown to the LLM."""
        ...

    @abstractmethod
    def parameters(self) -> List[ToolParameter]:
        """Ordered list of parameters for this tool."""
        ...

    @abstractmethod
    async def execute(self, *, tool_use_id: str, **kwargs: Any) -> ToolResult:
        """
        Run the tool with the given parameters.

        Args:
            tool_use_id: Identifier linking this invocation to the LLM turn.
            **kwargs: Parameter values matching self.parameters().

        Returns:
            ToolResult with the output string.
        """
        ...

    @property
    def required_capabilities(self) -> List[str]:
        """Capability strings the caller's token must include."""
        return []

    @property
    def estimated_cost_cents(self) -> int:
        """Approximate cost per invocation (for budget tracking)."""
        return 1

    @property
    def input_labels(self) -> List[str]:
        """IFC input labels."""
        return ["internal"]

    @property
    def output_labels(self) -> List[str]:
        """IFC output labels."""
        return ["internal"]

    # ── JSON schema generation ──────────────────────────────────────

    def to_anthropic_tool(self) -> Dict[str, Any]:
        """
        Convert to the Anthropic ``tools`` format.

        Returns a dict suitable for passing in the ``tools`` list of
        ``messages.create()``.
        """
        properties: Dict[str, Any] = {}
        required: List[str] = []

        for p in self.parameters():
            prop: Dict[str, Any] = {
                "type": p.type,
                "description": p.description,
            }
            if p.enum:
                prop["enum"] = p.enum
            properties[p.name] = prop
            if p.required:
                required.append(p.name)

        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"

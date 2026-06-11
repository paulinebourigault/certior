"""
Tool registry for Certior verified agents.

Maintains a name → BaseTool mapping and provides helpers for
schema generation, capability filtering, and batch lookup.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from agentsafe.capabilities.tokens import CapabilityToken
from .base import BaseTool


class ToolRegistry:
    """
    Central catalog of available tools.

    Usage::

        registry = ToolRegistry()
        registry.register(WebFetchTool())
        registry.register(PythonEvalTool())

        # List tools the token is allowed to use
        tools = registry.list_for_token(token)

        # Get Anthropic API tool schemas
        schemas = registry.to_anthropic_tools(token)

        # Look up by name
        tool = registry.get("web_fetch")
    """

    def __init__(self) -> None:
        self._tools: Dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Register a tool (overwrites if name collides)."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[BaseTool]:
        """Look up a tool by name."""
        return self._tools.get(name)

    def list_all(self) -> List[BaseTool]:
        """Return all registered tools."""
        return list(self._tools.values())

    def list_for_token(self, token) -> List[BaseTool]:
        """
        Return tools whose capability requirements are satisfied by *token*.

        Accepts a CapabilityToken object or a token ID string.  If a plain
        string is passed (e.g. from the API layer), all tools are returned
        since we cannot check permissions without the full token object.
        """
        if isinstance(token, str):
            # Token ID string - can't filter; return all tools
            return list(self._tools.values())
        return [
            t for t in self._tools.values()
            if token.has_all_permissions(t.required_capabilities)
        ]

    def to_anthropic_tools(
        self,
        token=None,
    ) -> List[Dict[str, Any]]:
        """
        Generate the ``tools`` list for the Anthropic Messages API.

        If *token* is provided, only include tools the token authorises.
        """
        tools = self.list_for_token(token) if token else self.list_all()
        return [t.to_anthropic_tool() for t in tools]

    @property
    def tool_names(self) -> List[str]:
        return list(self._tools.keys())

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __repr__(self) -> str:
        return f"<ToolRegistry tools={self.tool_names}>"

"""
certior.adapters.crewai - CrewAI integration.
==============================================

Provides a tool guard that wraps CrewAI tool execution.

Usage::

    from certior import Guard
    from certior.adapters.crewai import certior_tool_wrapper

    guard = Guard(policy="sox")

    @tool("financial_query")
    @certior_tool_wrapper(guard)
    def query_financials(query: str) -> str:
        return db.execute(query)

    # Or wrap all tools in a crew
    from certior.adapters.crewai import guard_crew_tools
    crew = guard_crew_tools(crew, guard)

Requires: ``pip install crewai``
"""
from __future__ import annotations

import functools
from typing import Any, Callable, Optional

from certior.guard import Guard, CertiorBlocked


def certior_tool_wrapper(
    guard: Optional[Guard] = None,
    policy: str = "default",
    tool_name: str = "",
) -> Callable:
    """
    Decorator that adds Certior verification to any CrewAI tool.

    Usage::

        @tool("search")
        @certior_tool_wrapper(guard, tool_name="web_search")
        def search(query: str) -> str:
            ...
    """
    _guard = guard or Guard(policy=policy)

    def decorator(fn: Callable) -> Callable:
        name = tool_name or getattr(fn, "__name__", "unknown")

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Extract first string arg as content for scanning
            content = None
            for a in args:
                if isinstance(a, str):
                    content = a
                    break
            if not content:
                for v in kwargs.values():
                    if isinstance(v, str):
                        content = v
                        break

            result = _guard.verify(
                tool=name,
                content=content,
                params=kwargs if kwargs else None,
            )
            if result.blocked:
                return f"[CERTIOR BLOCKED] {result.reason}"

            return fn(*args, **kwargs)

        return wrapper
    return decorator


def guard_crew_tools(crew: Any, guard: Guard) -> Any:
    """
    Wrap all tools in a CrewAI Crew with Certior verification.

    Modifies the crew in-place and returns it for chaining.

    Usage::

        crew = Crew(agents=[analyst], tasks=[task])
        guard_crew_tools(crew, Guard(policy="hipaa"))
        crew.kickoff()
    """
    if not hasattr(crew, "agents"):
        return crew

    for agent in crew.agents:
        if hasattr(agent, "tools"):
            wrapped = []
            for tool in agent.tools:
                if hasattr(tool, "func") and callable(tool.func):
                    tool.func = certior_tool_wrapper(
                        guard=guard,
                        tool_name=getattr(tool, "name", ""),
                    )(tool.func)
                wrapped.append(tool)
            agent.tools = wrapped

    return crew

"""
Certior - Verified AI Agent Safety
===================================

Drop-in verification layer for AI agent tool calls.

Quick start::

    from certior import Guard

    guard = Guard(policy="hipaa", budget_cents=5000)

    # Verify + execute any tool call
    result = guard.verify(
        tool="database_query",
        params={"sql": "SELECT name FROM patients WHERE id = 42"},
        content="Patient lookup request",
    )

    if result.allowed:
        execute_tool(result.redacted_params)
    else:
        print(result.reason)

Framework integrations::

    # LangChain
    from certior.adapters.langchain import CertiorCallbackHandler
    chain.invoke(input, config={"callbacks": [CertiorCallbackHandler()]})

    # CrewAI - decorate one tool
    from certior.adapters.crewai import certior_tool_wrapper
    @tool("financial_query")
    @certior_tool_wrapper(Guard(policy="sox"))
    def query_financials(query: str) -> str:
        ...

    # CrewAI - wrap every tool in an existing crew
    from certior.adapters.crewai import guard_crew_tools
    crew = guard_crew_tools(Crew(agents=[...]), Guard(policy="sox"))

    # OpenAI Agents SDK / custom
    from certior import Guard
    guard = Guard()
    # wrap any tool function
    safe_fn = guard.wrap(my_tool_function, tool_name="web_search")

"""
from __future__ import annotations

__version__ = "0.1.0a2"

from certior.guard import (
    Guard,
    VerifyResult,
    Policy,
    CertiorBlocked,
)

__all__ = [
    "Guard",
    "VerifyResult",
    "Policy",
    "CertiorBlocked",
    "__version__",
]

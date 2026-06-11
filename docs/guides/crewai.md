---
title: "CrewAI"
description: "Wrap one CrewAI tool with certior_tool_wrapper, or guard every tool in an existing crew with guard_crew_tools."
---

The CrewAI adapter ships two patterns: decorate a single tool, or wrap every tool in an existing crew at construction time. Both run `Guard.verify(...)` with the active policy's content scanner before each tool call.

## What the adapter does and does not do

The CrewAI wrapper runs the **content gate** (PII detection, policy-specific content rules) on each tool call. It does **not** check `required_capabilities` or deduct `cost_cents` - that surface is intentionally narrow because CrewAI tool signatures vary and the wrapper auto-extracts the first string argument as the content to scan. For capability + budget enforcement on a CrewAI tool, compose with `@guard.wrap(...)` underneath (see "Defence in depth" below).

A blocked call **returns the string** `"[CERTIOR BLOCKED] {reason}"` rather than raising; CrewAI surfaces that as the tool's output, and the agent's reasoning loop sees it.

## Pattern 1: decorate one tool

```python
from crewai import tool
from certior import Guard
from certior.adapters.crewai import certior_tool_wrapper

guard = Guard(policy="sox", budget_cents=5000)

@tool("financial_query")
@certior_tool_wrapper(guard, tool_name="financial_query")
def query_financials(query: str) -> str:
    ...
```

`certior_tool_wrapper(guard=None, policy="default", tool_name="")` is the full signature. When `guard` is omitted, the wrapper builds its own `Guard(policy=policy)`. `tool_name` is what appears in the audit log (defaults to the function's `__name__`).

## Pattern 2: guard every tool in an existing crew

```python
from crewai import Crew, Agent
from certior import Guard
from certior.adapters.crewai import guard_crew_tools

guard = Guard(policy="hipaa", budget_cents=5000)

crew = Crew(agents=[Agent(...), Agent(...)])
guard_crew_tools(crew, guard)   # modifies the crew in place

result = crew.kickoff(inputs={...})
```

`guard_crew_tools(crew, guard)` walks every agent's tools list and replaces each tool's function with the same content-scanned wrapper. The crew is mutated in place and also returned for chaining.

## Defence in depth: add capability + budget

The wrapper covers the content gate. To also enforce capability and budget, decorate the underlying function with `@guard.wrap(...)` first - that path raises `CertiorBlocked` on a capability or budget miss before the function body runs:

```python
from crewai import tool
from certior import Guard
from certior.adapters.crewai import certior_tool_wrapper

guard = Guard(policy="sox", permissions=["database:read"], budget_cents=5000)

@tool("financial_query")
@guard.wrap(required_capabilities=["database:read"], cost_cents=2)   # capability + budget (outer, runs first)
@certior_tool_wrapper(guard, tool_name="financial_query")             # content gate (inner, runs second)
def query_financials(query: str) -> str:
    ...
```

Decorator order matters here. Python applies decorators bottom-up but at call time the outer wrapper runs first. With `@guard.wrap` above `@certior_tool_wrapper`, capability + budget is checked first (raising `CertiorBlocked` on a miss); only if that passes does the content scan run (returning the blocked-string on a miss).

## See also

- [OpenAI guide](/guides/openai) - same gate via `verify_tool_calls()`.
- [Custom loop](/guides/custom-loop) - direct `Guard.verify()` / `@guard.wrap()`.

# Bring Your Own Framework

Certior should not force a team to replace its agent framework.

In production, the practical model is:

- keep your framework and agent prompts
- keep your own orchestration if you already have one
- insert Certior at the execution boundary for policy enforcement, budget control, and audit evidence

That gives you three adoption levels.

## 1. Use Certior Studio

Use this when operators want an interactive control plane.

- submit a single verified run
- submit a simple sequential workflow
- inspect stage-by-stage evidence
- export JSON or PDF audit packages

This is the right surface for demos, compliance teams, and manual operations.

## 2. Use The API

Use this when your product or backend already has an orchestrator.

Core runtime endpoints:

- `POST /api/v1/tasks`
- `GET /api/v1/executions/{id}`
- `GET /api/v1/compliance/{id}/export`

Workflow endpoints:

- `POST /api/v1/workflows`
- `GET /api/v1/workflows`
- `GET /api/v1/workflows/{id}`

Use workflows when you want Certior to coordinate a sequential specialist flow itself. Use task endpoints when your application already owns orchestration and only needs verified execution plus evidence.

## 3. Embed Certior In Your Existing Agent Stack

Use this when you already have tools, chains, crews, or a custom loop and want Certior to sit in the middle as a policy gateway.

### LangChain

Use the callback adapter in [certior/adapters/langchain.py](../certior/adapters/langchain.py).

```python
from certior import Guard
from certior.adapters.langchain import CertiorCallbackHandler

guard = Guard(policy="hipaa")
handler = CertiorCallbackHandler(guard)

agent.invoke(
    {"input": "Look up patient records"},
    config={"callbacks": [handler]},
)
```

This verifies tool calls before LangChain executes them.

### CrewAI

Use the tool wrapper in [certior/adapters/crewai.py](../certior/adapters/crewai.py).

```python
from certior import Guard
from certior.adapters.crewai import certior_tool_wrapper

guard = Guard(policy="sox")

@certior_tool_wrapper(guard, tool_name="financial_query")
def query_financials(query: str) -> str:
    return run_query(query)
```

You can also wrap all tools on a crew with `guard_crew_tools(...)`.

### Generic Tool-Calling Loop

Use the framework-agnostic middleware in [certior/adapters/tool_use.py](../certior/adapters/tool_use.py).

```python
from certior.adapters.tool_use import CertiorMiddleware

middleware = CertiorMiddleware(policy="hipaa")
safe_execute = middleware.wrap_executor(execute_tool)

result = await safe_execute("db_query", {"sql": "SELECT ..."})
```

This is the right pattern for OpenAI tool calling, Anthropic tool use, or your own custom orchestration loop.

## Recommended Production Architecture

The cleanest customer architecture is:

```text
Application / Agent Framework
        |
        v
Certior Adapter Or API Boundary
        |
        v
Verified Tool Execution + Workflow Enforcement + Audit Export
```

Use this split deliberately:

- your framework decides what it wants to do
- Certior decides what is allowed to run
- Certior records the evidence of what actually happened

That keeps adoption practical. Teams do not need to rewrite their agents to get formal enforcement.

## When To Use Workflows vs External Orchestration

Use Certior workflows when:

- the flow is sequential and policy-heavy
- you want Certior Studio operators to run it directly
- you want a single workflow object with per-stage evidence

Keep orchestration outside Certior when:

- your application already has a coordinator
- you need non-sequential branching, retries, or dynamic fan-out
- Certior is being used as a verified execution gateway inside a larger system

In that model, Certior is still the right runtime boundary even when it is not the top-level orchestrator.
---
title: "LangChain"
description: "Attach CertiorCallbackHandler to any LangChain chain or agent. Every tool call is verified before execution."
---

LangChain calls registered tools through its callback system. `CertiorCallbackHandler` taps that system and runs `Guard.verify(...)` before each tool execution. Allowed calls proceed; blocked calls raise `CertiorBlocked` and the chain stops.

## Wiring it in

```python
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI
from certior import Guard
from certior.adapters.langchain import CertiorCallbackHandler

guard = Guard(
    policy="hipaa",
    permissions=["network:http:read", "filesystem:read"],
    budget_cents=5000,
)

llm = ChatOpenAI(model="gpt-4o-mini")
agent = create_openai_tools_agent(llm, tools=[...], prompt=...)
executor = AgentExecutor(agent=agent, tools=[...])

executor.invoke(
    {"input": "Summarize today's intake records."},
    config={"callbacks": [CertiorCallbackHandler(guard)]},
)
```

## What the handler does

`CertiorCallbackHandler(guard)` subscribes to LangChain's `on_tool_start` event. For each invocation:

1. Resolves the tool's name and inputs.
2. Calls `guard.verify(tool=name, params=inputs, content=...)`.
3. On allow: lets LangChain proceed with the original inputs (or the redacted version when the policy redacts).
4. On block: raises `CertiorBlocked` carrying the `VerifyResult`. The chain halts.

## Declaring capabilities per tool

LangChain tools don't carry capability metadata out of the box. The simplest pattern is to wrap the tool function with `@guard.wrap(required_capabilities=...)` before registering it as a LangChain tool:

```python
from langchain.tools import tool

@tool("web_fetch")
@guard.wrap(required_capabilities=["network:http:read"], cost_cents=2)
def web_fetch(url: str) -> str:
    ...
```

That way the capability check runs inside the LangChain call path even without the callback handler. Use both together for defence in depth: the wrap raises `CertiorBlocked` synchronously inside the tool body; the callback enforces the same check at the framework boundary.

## See also

- [Custom loop](/guides/custom-loop) - the same `Guard.verify()` directly.
- [How it works](/concepts/how-it-works) - the three gates this handler enforces.

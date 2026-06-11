---
title: "OpenAI tool calling"
description: "Drop verify_tool_calls() onto an OpenAI tool-calling response. Native shape, no transform."
---

OpenAI's chat completion returns `response.choices[0].message.tool_calls` as a list of tool-call objects. Certior accepts that list in its native shape via `verify_tool_calls()` - no SDK migration, no proxy, no schema rewrite.

## The full loop

```python
from openai import OpenAI
from certior import Guard
from certior.adapters.tool_use import verify_tool_calls

client = OpenAI()

guard = Guard(
    policy="default",
    permissions=["network:http:read", "filesystem:read"],
    budget_cents=5000,
)

TOOL_SPECS = {
    "search_web":    {"required_capabilities": ["network:http:read"], "cost_cents": 2},
    "read_file":     {"required_capabilities": ["filesystem:read"],   "cost_cents": 1},
    "db_admin_drop": {"required_capabilities": ["database:admin"],    "cost_cents": 0},
}

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Find recent papers on formal verification."}],
    tools=[...],  # your OpenAI tool definitions
)

verified = verify_tool_calls(
    guard,
    response.choices[0].message.tool_calls,
    tool_specs=TOOL_SPECS,
)

for call in verified:
    if call["allowed"]:
        result = execute_tool(call["name"], call["input"])
        archive(call["certificate"])
    else:
        print(f"Blocked {call['name']}: {call['reason']}")
```

## What `verify_tool_calls` returns

For every input tool call, you get a dict augmented with:

| Key | Type | Meaning |
|---|---|---|
| `id` | `str` | The call's id (preserved from OpenAI's shape). |
| `name` | `str` | Tool name. |
| `input` | `dict` | Normalized arguments. |
| `allowed` | `bool` | Z3 verdict. |
| `reason` | `str` | Block reason (empty when allowed). |
| `certificate` | `VerifiedCertificate \| None` | Signed cert on allow, `None` on block. |
| `redacted_input` | `dict` | Arguments with PII redacted (when the policy redacts). |
| `pii_found` | `list[tuple]` | Detected PII spans. |
| `verify_result` | `VerifyResult` | The full result object. |

## Per-call overrides

A call may carry its own `required_capabilities` / `cost_cents` keys that override the `tool_specs` map. Use this when one tool's permission profile depends on its arguments.

## Anthropic and MCP

The same `verify_tool_calls()` accepts Anthropic's `tool_use` block list and MCP tool calls in their native shapes. The normalizer in `certior.adapters.tool_use._normalize_tool_call` handles each.

## See also

- [Custom loop](/guides/custom-loop) - `Guard.verify()` directly, no framework.
- [Certificates](/concepts/certificates) - what a successful verify produces.

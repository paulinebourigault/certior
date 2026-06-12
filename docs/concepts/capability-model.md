---
title: "Capability model"
description: "Capabilities are permission strings. A guard's permissions are its ceiling. A child guard's set must be a subset of its parent's. Z3 enforces, Lean proves the rule."
---

## Capabilities are strings

A capability is an opaque permission string, conventionally namespaced with colons. Examples:

```
network:http:read
network:http:write
filesystem:read
filesystem:write
database:read
database:admin
```

You choose your own taxonomy. Certior does not interpret the strings - it only checks set containment.

## A guard declares its ceiling

```python
from certior import Guard

guard = Guard(
    permissions=["network:http:read", "filesystem:read"],
    budget_cents=5000,
)
```

`guard.permissions` is the maximum set of capabilities this guard's calls may use. The special value `["*"]` means "no capability restriction" - useful for development but disables the capability gate.

## Each tool call declares what it needs

```python
@guard.wrap(required_capabilities=["network:http:read"], cost_cents=10)
def web_fetch(url: str) -> str: ...
```

Or in a direct verify:

```python
result = guard.verify(
    tool="web_fetch",
    params={"url": "https://example.com"},
    required_capabilities=["network:http:read"],
    cost_cents=10,
)
```

The call is admitted only if every entry in `required_capabilities` is present in `guard.permissions`. Anything else - including a single missing capability - blocks the call.

## Subset rule in delegation chains

In a multi-agent pipeline, a parent guard can hand off to a child. The rule the Lean model enforces is that the child's permission set must be a subset of the parent's. This is the `delegationSafety` theorem in `lean4/CertiorLattice/Certior/Delegation.lean`.

For OpenClaw pipelines, the subset check is enforced at `add_step` time by `GuardedPipeline` - see [`/guides/openclaw`](/guides/openclaw). For other frameworks, the same rule applies whenever you instantiate a sub-guard from a parent guard's token.

## Wildcards short-circuit Z3

If `permissions` includes `"*"`, the capability gate trusts the call and only the budget portion runs through Z3. This is the development default. In production-style configurations, declare the actual permission set so the gate has work to do.

## What gets recorded

Every verify call (allowed or blocked) appends a compact record to `guard.audit_log`: the tool name, the `allowed` verdict, the violation count, the PII count, the call latency, and a timestamp. The full certificate and the detailed violation list live on the returned `VerifyResult`, not in the audit-log entry.

## See also

- [How it works](/concepts/how-it-works) - the three-gate pipeline.
- [Certificates](/concepts/certificates) - what a successful verify produces.
- [OpenClaw guide](/guides/openclaw) - `GuardedPipeline` enforces subset checking on delegation chains.

---
title: "Quickstart"
description: "Install Certior, create a Guard, see an allowed call return a certificate and a blocked call raise CertiorBlocked."
---

Goal: in five minutes, you will install Certior, declare an agent's capability boundary, run an allowed call, run a blocked call, and read the audit log. No server, no LLM key.

## 1. Install

```bash
pip install certior
```

This pulls in `z3-solver`, `httpx`, `pydantic`, `jsonschema`, and `PyYAML`. Requires Python 3.11+.

Every tool call is enforced by Z3 against a policy model proven sound in Lean 4 offline. For *live* lattice-proven flow verification on every call, add the Lean binary (not bundled in the wheel; Linux x86_64 / macOS arm64):

```bash
pip install "certior[lean]"
certior-install-lean   # downloads + SHA-256-verifies the binary, fails closed on mismatch
```

This step is optional - without it the runtime stays on the always-on Z3 path. See [Live Lean verification](/reference/lean-binary).

## 2. Declare a Guard

```python
from certior import Guard, CertiorBlocked

guard = Guard(
    policy="default",
    permissions=["network:http:read"],
    budget_cents=5000,
)
```

- `policy` selects the compliance preset (`"default"`, `"hipaa"`, `"sox"`, `"legal_privilege"`).
- `permissions` is the capability ceiling for this guard. A child agent's permissions must be a subset.
- `budget_cents` is the spending ceiling. Each verified call deducts its declared cost.

## 3. Wrap a tool and call it

```python
@guard.wrap(required_capabilities=["network:http:read"], cost_cents=10)
def web_fetch(url: str) -> str:
    # Pretend we actually fetched the URL.
    return f"<html>...{url}...</html>"

# Allowed - the wrap call verifies first, then runs the function.
html = web_fetch("https://example.com")
print(html[:30])
```

`@guard.wrap` runs `guard.verify(...)` before the function body. On success the function executes; on a block it raises `CertiorBlocked` without calling the function.

## 4. Trigger a block

```python
@guard.wrap(required_capabilities=["filesystem:write"], cost_cents=10)
def write_file(path: str, body: str) -> None: ...

try:
    write_file("/etc/passwd", "exploit")
except CertiorBlocked as e:
    print("Blocked:", e.result.reason)
```

The guard's `permissions=["network:http:read"]` does not cover `filesystem:write`, so Z3 returns UNSAT and the wrap raises `CertiorBlocked`. The function body never ran.

## 5. Inspect the audit log

```python
for entry in guard.audit_log:
    print(entry["tool"], "->", "allowed" if entry["allowed"] else "blocked",
          f"({entry['latency_ms']:.1f}ms)")
```

Each `verify()` (whether via `wrap` or direct call) appends an entry of shape `{tool, allowed, violations: int, pii_count: int, latency_ms, time}` to `guard.audit_log`. The full violations list and the signed `VerifiedCertificate` itself are on the returned `VerifyResult` - the audit log keeps only counts and timing.

## What's next

- [How it works](/concepts/how-it-works) - the three gates, the Z3 runtime, the Lean policy model.
- [Bring your own framework](/guides/custom-loop) - LangChain, CrewAI, OpenClaw, MCP, or a custom orchestration loop.
- [Compliance policies](/concepts/policies) - what HIPAA / SOX / `legal_privilege` actually enforce.

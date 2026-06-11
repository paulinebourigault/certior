---
title: "Custom orchestration loop"
description: "Use Guard.verify() or Guard.wrap() to add capability, content, and budget gates to any agent loop you already own."
---

If you already have an orchestration loop and don't want a framework adapter, call `Guard.verify(...)` directly or decorate your tools with `@guard.wrap(...)`. Both are framework-free.

## Direct verify

```python
from certior import Guard

guard = Guard(
    policy="default",
    permissions=["network:http:read", "filesystem:read"],
    budget_cents=5000,
)

result = guard.verify(
    tool="web_fetch",
    params={"url": "https://example.com"},
    content="...optional text to scan...",
    required_capabilities=["network:http:read"],
    cost_cents=10,
)

if result.allowed:
    run_tool(result.redacted_params)   # use redacted_params when policy redacts
    archive(result.certificate)         # signed VerifiedCertificate
else:
    print("Blocked:", result.reason)
    for v in result.violations:
        print(f"  - {v.category}: {v.detail}")
```

`verify()` returns a `VerifyResult` with `allowed`, `reason`, `violations`, `redacted_content`, `redacted_params`, `pii_found`, `latency_ms`, and `certificate`.

## Wrap a function

```python
@guard.wrap(required_capabilities=["network:http:read"], cost_cents=10)
def web_fetch(url: str) -> str: ...

# Either of these are equivalent:
html = web_fetch("https://example.com")          # raises CertiorBlocked on block
```

`@guard.wrap` runs verify before the function body. On a block it raises `CertiorBlocked(result)` without calling the function. The decorator works on sync and async functions.

## Wrap with a content extractor

If your tool's textual content is buried inside a structured payload, supply a `content_extractor`:

```python
@guard.wrap(
    required_capabilities=["email:send"],
    cost_cents=5,
    content_extractor=lambda recipient, body, subject="": f"{subject}\n\n{body}",
)
def send_email(recipient: str, body: str, subject: str = "") -> None: ...
```

The extractor's output is fed to the content scanner so PII detection and the active policy's content rules apply.

## CertiorMiddleware

For loop architectures that prefer middleware over decorators, `certior.adapters.tool_use.CertiorMiddleware` exposes the same verification as a callable middleware object. See `certior/adapters/tool_use.py` for the protocol.

## See also

- [How it works](/concepts/how-it-works) - what the gates check.
- [Certificates](/concepts/certificates) - the cert attached to allowed calls.

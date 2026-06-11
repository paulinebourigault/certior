---
title: "Configuration"
description: "Guard constructor parameters, environment variables, and the one env var you set to enable live Lean flow verification."
---

There are two configuration surfaces: the `Guard` constructor (per-agent, code-level) and environment variables (server-level).

## `Guard` constructor

```python
Guard(
    policy=Policy.DEFAULT,        # "default" | "hipaa" | "sox" | "legal_privilege" | Policy enum
    permissions=None,             # list[str]; default: ["*"] (no capability restriction)
    budget_cents=10_000,          # int; per-guard spending ceiling
    on_violation=None,            # Callable[[VerifyResult], None]
    auto_redact=True,             # bool; auto-redact PII when policy redacts
    agent_id="default-agent",     # str; appears in audit log entries
)
```

The signature lives at [`certior/guard.py:167`](https://github.com/paulinebourigault/certior/blob/main/certior/guard.py).

The `Guard.verify(...)` and `Guard.wrap(...)` methods then take per-call `required_capabilities` and `cost_cents`.

## Verification stack

Three formal tools, three jobs - all driven by the same Guard configuration:

| Tool | When it runs | Configured by |
|---|---|---|
| **Z3** (SMT) | Every `verify(...)` call (~tens of ms). | Built into the runtime. No separate env var. |
| **Lean 4** | Offline / CI on every commit. Optional live flow checker when the binary is present. | `certior-install-lean` (auto-discovered) or `CERTIOR_FLOW_CHECK_BINARY` for a source build. See [Lean binary](/reference/lean-binary). |
| **Dafny** | Offline / CI. | Built into the runtime modules and export path. No env var toggle. |

When the Lean live binary is not configured, the runtime uses the Python implementation of the same subset/budget rule whose soundness Lean has proven offline.

## Server environment variables

When running with the FastAPI server (`./run.sh`), these env vars control behaviour:

| Variable | Default | Description |
|---|---|---|
| `CERTIOR_HOST` | `127.0.0.1` | Bind address. Use `0.0.0.0` for Docker / remote access. |
| `CERTIOR_PORT` | `8000` | HTTP port. |
| `CERTIOR_ENV` | `development` | `development` enables auto-reload; `production` disables it and tightens logging. |
| `CERTIOR_STUDIO_URL` | `http://127.0.0.1:3001` | URL for the Studio Next.js frontend. |
| `CERTIOR_WORKSPACE` | `/tmp/certior-workspace` | Directory for file tool operations. Created on startup. |
| `DATABASE_URL` | *(unset)* | PostgreSQL DSN. When set, executions and events are persisted to PostgreSQL. Requires the `[postgres]` extra. |
| `REDIS_URL` | *(unset)* | Redis DSN. When set, background tasks dispatch via Celery / Redis. Requires the `[redis]` extra. |
| `CERTIOR_DATA_DIR` | *(unset)* | Fallback SQLite directory when `DATABASE_URL` is not set. |
| `OPENAI_API_KEY` | *(unset)* | Enables the OpenAI agent loop. |
| `ANTHROPIC_API_KEY` | *(unset)* | Enables the Anthropic agent loop. |
| `CERTIOR_LLM_PROVIDER` | *(auto)* | Force provider when both keys are set. `openai` or `anthropic`. |
| `CERTIOR_MODEL` | per-provider default | Override the model name. |
| `CERTIOR_FLOW_CHECK_BINARY` | *(unset)* | Path to the Lean `certior-flow-check` binary for live flow verification. |

The full reference - including production guidance for PostgreSQL DSNs, secret handling, and the Docker Compose host-env pattern - lives in [`CONFIGURATION.md`](https://github.com/paulinebourigault/certior/blob/main/CONFIGURATION.md).

## Backend priority

When the server starts, persistence backends are selected in order:

1. `DATABASE_URL` set → PostgreSQL state store + event bus.
2. `REDIS_URL` set → Celery / Redis task queue (combinable with PostgreSQL or SQLite).
3. `CERTIOR_DATA_DIR` set → SQLite single-node persistence.
4. None set → in-memory (testing only; data lost on restart).

## See also

- [Lean binary](/reference/lean-binary) - installing or building `certior-flow-check`.
- [Trust package](/reference/trust-package) - the assurance vocabulary the runtime uses.

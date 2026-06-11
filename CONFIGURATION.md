# Certior Configuration Reference

All runtime configuration is via environment variables. This page is intentionally a reference page, not a quick-start or operator runbook.

For product overview and demos, see [README.md](README.md).
For deployment and runtime operations, see [OPERATIONS.md](OPERATIONS.md).
For development, Lean builds, and debugger workflows, see [DEVELOPER.md](DEVELOPER.md).

---

## Formal Verification Stack

Certior's formal guarantees are not Z3-only.

| Layer | Role in the system | Configuration surface |
| --- | --- | --- |
| `Z3` | Pre-execution verification of capability coverage, budget constraints, and policy / flow constraints | Built into the Python runtime, no separate env var required |
| `Lean4` | Optional live flow verification through `certior-flow-check`, plus the broader plan/debug kernel | `CERTIOR_FLOW_CHECK_BINARY` |
| `Dafny` | Verified runtime bridges for certificates, capability attenuation, path safety, and seccomp-backed runtime evidence | Built into the runtime modules and export path, no separate env var toggle |

In practice:

- Z3 is the always-on verification layer in normal runtime execution.
- Lean adds dual-proof runtime flow checking when the binary is built and configured.
- Dafny-backed components strengthen core runtime invariants and show up in exported evidence such as proof and seccomp compliance certificates.

---

## Reference Usage Examples

```bash
# Minimal - local tools only, no LLM
./run.sh

# With Anthropic (Claude)
ANTHROPIC_API_KEY=sk-ant-... ./run.sh

# With OpenAI (GPT-4o)
OPENAI_API_KEY=sk-... ./run.sh

# Force a specific provider when both keys are set
CERTIOR_LLM_PROVIDER=openai OPENAI_API_KEY=sk-... ANTHROPIC_API_KEY=sk-ant-... ./run.sh

# Custom model
OPENAI_API_KEY=sk-... CERTIOR_MODEL=gpt-4-turbo ./run.sh

# Production (CERTIOR_KMS_ROOT_SECRET and CERTIOR_API_KEYS_JSON are required
# - see the Security section below for the generation one-liners)
CERTIOR_KMS_ROOT_SECRET=... CERTIOR_API_KEYS_JSON='{"ck-...": "label"}' \
CERTIOR_ENV=production CERTIOR_HOST=0.0.0.0 CERTIOR_PORT=8000 ./run.sh

# Production with Lean-backed runtime flow checking
CERTIOR_KMS_ROOT_SECRET=... CERTIOR_API_KEYS_JSON='{"ck-...": "label"}' \
CERTIOR_FLOW_CHECK_BINARY=lean4/CertiorPlan/.lake/build/bin/certior-flow-check \
CERTIOR_ENV=production ./run.sh
```

---

## Environment Variables

### Required (for LLM agent mode)

| Variable | Description | Example |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | Anthropic API key. Enables the reactive LLM agent loop with Claude. | `sk-ant-api03-...` |
| `OPENAI_API_KEY` | OpenAI API key. Alternative to Anthropic - enables agent mode with GPT-4o. | `sk-proj-...` |

> **Auto-detection**: If both keys are set, Anthropic is preferred. Use `CERTIOR_LLM_PROVIDER=openai` to override.

### Server

| Variable | Default | Description |
| --- | --- | --- |
| `CERTIOR_HOST` | `127.0.0.1` | Bind address. Use `0.0.0.0` for Docker or remote access. |
| `CERTIOR_PORT` | `8000` | HTTP port. |
| `CERTIOR_ENV` | `development` | `development` enables auto-reload and debug logging. `production` disables reload and sets log level to WARNING. |
| `CERTIOR_STUDIO_URL` | `http://127.0.0.1:3001` | Canonical Certior Studio URL used by backend landing pages and Studio handoff routes. |

### Storage & Workspace

| Variable | Default | Description |
| --- | --- | --- |
| `CERTIOR_WORKSPACE` | `/tmp/certior-workspace` | Directory for file_read/file_write tool operations. Created automatically. Agents can only read/write inside this directory. |
| `DATABASE_URL` | *(none)* | PostgreSQL connection string (e.g., `postgresql://certior:certior@localhost/certior`). When set, execution state and events are persisted to PostgreSQL via asyncpg. Requires: `pip install 'certior[postgres]'` |
| `REDIS_URL` | *(none)* | Redis connection string (e.g., `redis://localhost:6379/0`). When set, background tasks are dispatched via Celery/Redis instead of the in-process asyncio queue. Requires: `pip install 'certior[redis]'` |
| `CERTIOR_DATA_DIR` | *(none)* | Directory for SQLite databases. Used as fallback when `DATABASE_URL` is not set. |

**Backend priority cascade:** The app factory selects backends in this order:

1. `DATABASE_URL` → PostgreSQL state store + event bus (production)
2. `REDIS_URL` → Celery/Redis task queue (can combine with PG or SQLite)
3. `CERTIOR_DATA_DIR` → SQLite for state + events + queue (single-node)
4. *(none set)* → In-memory (testing only - data lost on restart)

#### Production PostgreSQL guidance

For production, do not rely on an ad hoc shell export of `DATABASE_URL`.
Set it through your process manager, deployment manifest, or secrets system so the API server, worker, and verification-graph ingest all resolve the same database consistently.

Recommended DSN shape:

```bash
postgresql://certior_app:<url-encoded-password>@db.example.com:5432/certior?sslmode=require&application_name=certior-api
```

Use the same base DSN for verification graph ingest, changing only `application_name` when useful for observability.

Example graph-ingest DSN:

```bash
postgresql://certior_app:<url-encoded-password>@db.example.com:5432/certior?sslmode=require&application_name=certior-graph
```

Production requirements:

- use a dedicated least-privilege PostgreSQL role for Certior instead of a superuser
- require TLS with `sslmode=require` or stricter server-side policy
- point the Certior API, worker, and verification-graph ingest at the same database
- avoid splitting runtime state and verification-graph ingest across separate databases unless you also operate replication or an explicit ETL pipeline

The last point is architectural, not cosmetic: the verification graph now ingests live `executions` and `workflows` data to bind proofs and release evidence to actual runtime lineage. If runtime state lands in one database and graph ingest reads another, Certior will miss live evidence even when the code path is otherwise correct.

#### Production LLM secret guidance

If you are using a single OpenAI key in production, treat it as a deployment secret, not as project configuration checked into the repository.

Recommended pattern:

- store `OPENAI_API_KEY` in your secret manager or deployment platform secret store
- inject it into the API and worker processes at runtime
- set `CERTIOR_LLM_PROVIDER=openai` when you want provider selection to be explicit rather than auto-detected
- avoid placing real keys in `.env.example`, shell history, CI logs, screenshots, or support tickets

Example runtime environment:

```bash
CERTIOR_ENV=production
CERTIOR_LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
DATABASE_URL=postgresql://certior_app:<url-encoded-password>@db.example.com:5432/certior?sslmode=require&application_name=certior-api
```

Operational recommendations:

- use a dedicated OpenAI API key for Certior rather than reusing a personal developer key
- scope it to a single OpenAI project and production billing boundary
- rotate it on a schedule and immediately on any suspected exposure
- inject the same key into both the API server and worker only if they both need LLM access; otherwise keep worker access off
- prefer platform-native secret injection over writing a plaintext `.env` file on the host

GitHub-safe repository practice:

- keep only placeholder templates such as [`.env.example`](.env.example) and [`.env.production.example`](.env.production.example) in the repository
- keep real secret-bearing files outside the repository or in ignored local-only files
- assume any committed secret must be rotated immediately, even if removed later

### LLM Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | *(none)* | Anthropic API key - enables Claude agent mode. |
| `OPENAI_API_KEY` | *(none)* | OpenAI API key - enables GPT agent mode. |
| `CERTIOR_LLM_PROVIDER` | *(auto)* | Force provider: `anthropic` or `openai`. Auto-detected from available keys if unset (prefers Anthropic). |
| `CERTIOR_MODEL` | *(per provider)* | Model name. Defaults: `claude-sonnet-4-20250514` (Anthropic), `gpt-4o` (OpenAI). |
| `CERTIOR_MAX_TOKENS` | `4096` | Max tokens per LLM response. |
| `CERTIOR_MAX_TOOL_ROUNDS` | `25` | Safety limit: max tool-use iterations per task. |
| `CERTIOR_SYSTEM_PROMPT` | *(built-in)* | Override the system prompt sent to the LLM. |
| `CERTIOR_LLM_BASE_URL` | *(none)* | Custom API base URL (for Azure OpenAI, local models, etc.). |

### Verification Runtime

| Variable | Default | Description |
| --- | --- | --- |
| `CERTIOR_FLOW_CHECK_BINARY` | *(auto-discovered if possible)* | Absolute or relative path to the Lean `certior-flow-check` binary. When set correctly and the binary is present, the runtime can emit Lean-backed live flow evidence instead of remaining in Z3-only mode. |

Notes:

- There is no separate environment variable to "turn on Z3" because it is part of the default runtime verifier path.
- There is no separate environment variable to "turn on Dafny" because Dafny-backed guarantees are embedded in specific runtime modules and surfaced through exported certificates and seccomp/runtime evidence.

### Frontend Runtime

| Variable | Default | Description |
| --- | --- | --- |
| `NEXT_PUBLIC_API_URL` | *(blank)* | Backend API base URL for the Studio frontend. When blank in local development, the frontend uses Next.js rewrites for HTTP requests. |
| `NEXT_PUBLIC_WS_URL` | *(blank)* | Optional explicit WebSocket base URL for Studio execution streaming. When blank, the frontend derives it from `NEXT_PUBLIC_API_URL` or falls back to `localhost:8000` during local development. |

### Observability (Optional)

| Variable | Default | Description |
| --- | --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | *(none)* | OpenTelemetry collector endpoint (e.g., `http://localhost:4317`). When set, traces and metrics are exported via OTLP/gRPC. This is a standard OTel SDK variable. |
| `OTEL_SERVICE_NAME` | `certior` | Service name in telemetry data. Standard OTel SDK variable. |

### Security

| Variable | Default | Description |
| --- | --- | --- |
| `CERTIOR_KMS_ROOT_SECRET` | *(per-process ephemeral in dev)* | **Required when `CERTIOR_ENV != development`.** HS256 signing secret for capability tokens. In development the server generates a fresh value per process; tokens issued by one process cannot be verified by another. Production deployments must set this explicitly. Generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. |
| `CERTIOR_API_KEYS_JSON` | *(empty in dev)* | **Required when `CERTIOR_ENV != development`.** JSON object mapping API key to a human-readable client label. Example: `'{"ck-prod-...": "orchestrator-a"}'`. The auth middleware rejects any bearer token not present in this map. Generate a key with `python -c "import secrets; print('ck-' + secrets.token_urlsafe(32))"`. |
| `CERTIOR_DEV_API_KEY` | *(auto-generated)* | The dev API key printed at startup. In development mode, when `CERTIOR_API_KEYS_JSON` is unset, this key is also accepted by `verify_api_key` so the orchestrator-facing routes work out of the box. For programmatic access, register a user via `POST /api/v1/auth/register`. |

**Deployment checklist (non-development environments):**

```bash
# 1. Generate the JWT signing secret
export CERTIOR_KMS_ROOT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

# 2. Generate one or more API keys, pair each with a client label
key1="ck-$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export CERTIOR_API_KEYS_JSON="{\"$key1\": \"orchestrator-a\"}"

# 3. Set the deployment environment so the server enforces both above
export CERTIOR_ENV=production
```

Without `CERTIOR_KMS_ROOT_SECRET` and `CERTIOR_API_KEYS_JSON` set, the server **refuses to start** in any non-development environment - it raises `RuntimeError` at import time rather than silently fall back to a placeholder secret or accept any bearer token.

---

## Runtime Selection Notes

### Agent Mode (recommended)

Set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`. The LLM decides which tools to call dynamically. Each tool call is formally checked before execution, with Z3 as the default verification layer and Lean participating when the live flow-check binary is available.

```text
Task → LLM reasons → proposes tool call → verify → execute → repeat → final answer
                 verification path = Z3 by default, optionally dual-checked with Lean
```

### Legacy Mode

No `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`. Tasks are decomposed into a static plan and executed sequentially. Useful for testing verification logic without LLM costs.

---

## Scope Of This Document

This page is intentionally limited to runtime configuration.

The following topics live elsewhere now:

- API authentication and endpoints: [OPERATIONS.md](OPERATIONS.md)
- compliance workflows and demo runbooks: [OPERATIONS.md](OPERATIONS.md)
- Docker and deployment runbooks: [OPERATIONS.md](OPERATIONS.md)
- local development and tests: [DEVELOPER.md](DEVELOPER.md)
- Lean kernel and proof-layer development: [DEVELOPER.md](DEVELOPER.md) and [lean4/README.md](lean4/README.md)

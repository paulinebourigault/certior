# Certior Operations Guide

Operational guide for running Certior as a service, demonstrating it to customers, and preparing production-style deployments.

## Audience

Use this document if you are:

- operating the API server
- running customer or investor demos
- validating compliance exports and runtime evidence
- preparing a production deployment

For configuration details, see [CONFIGURATION.md](CONFIGURATION.md).
For code, test, Lean, and debugger workflows, see [DEVELOPER.md](DEVELOPER.md).

## Primary Runtime Modes

### Local Development

```bash
./run.sh
```

Use this for normal API development and quick local validation.

### Production-Style Runtime

Production mode requires `CERTIOR_KMS_ROOT_SECRET` and `CERTIOR_API_KEYS_JSON`
to be set; the server refuses to start without them. See
[CONFIGURATION.md](CONFIGURATION.md#security) for the generation one-liners.

```bash
export CERTIOR_KMS_ROOT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export CERTIOR_API_KEYS_JSON='{"ck-test": "local-test"}'
CERTIOR_ENV=production ./run.sh
```

Use this when you want the runtime to behave like a real deployment and when you want to demo formal enforcement rather than a development setup.

### Production-Style Runtime With Lean Flow Checking

Same env-var prerequisites as above; additionally point `CERTIOR_FLOW_CHECK_BINARY` at the built Lean binary so the live verifier participates.

```bash
export CERTIOR_KMS_ROOT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export CERTIOR_API_KEYS_JSON='{"ck-test": "local-test"}'
export CERTIOR_FLOW_CHECK_BINARY=lean4/CertiorPlan/.lake/build/bin/certior-flow-check
CERTIOR_ENV=production ./run.sh
```

Use this when you want the live verifier to surface Lean-backed flow evidence during execution and in compliance exports.

Formal assurance in production should be understood as a stack, not a single prover:

- Z3 verifies capability, budget, and policy constraints in the runtime path
- Lean can add live flow-check evidence when `CERTIOR_FLOW_CHECK_BINARY` is configured
- Dafny-backed runtime modules contribute certificate, path-safety, and seccomp evidence that can surface in exports

## External User Flow

For most customers and external integrators, the product usage path is:

1. open Certior Studio for interactive use, or connect directly to the API for integration
1. register or provision an API key
1. submit a task or workflow to the API
1. track the execution over REST or WebSocket
1. export the audit package

The canonical web UI is Certior Studio, served by the Next.js frontend on port `3001` in local development.

The main endpoints involved are:

- `POST /api/v1/auth/register`
- `POST /api/v1/tasks`
- `POST /api/v1/workflows`
- `GET /api/v1/executions/{id}`
- `GET /api/v1/workflows/{id}`
- `GET /api/v1/compliance/{id}/export`
- `WS /ws/executions/{id}`

## Demo Runbook

These are the two strongest production-facing demos.

### Workflow Enforcement Demo

```bash
CERTIOR_DEV_API_KEY='...' .venv/bin/python examples/07_multi_agent_reviewed_release.py
```

Use this when you want to show:

- reviewer-stage approval
- hard rejection when upstream review lineage is missing
- release-stage binding to a reviewed artifact

### Proof-Stack Demo

```bash
.venv/bin/python examples/08_all_provers_showcase.py
```

Use this when you want to show:

- deterministic verified tool execution
- Lean-backed flow checks
- Dafny/seccomp runtime evidence
- exportable prover mix

For detailed example guidance and presentation assets, see [examples/README.md](examples/README.md).

## Compliance Export Workflow

Compliance export is part of the product, not an afterthought.

After a run completes, export its package through the API:

```bash
curl -H "Authorization: Bearer <api-key>" \
  "http://localhost:8000/api/v1/compliance/<execution-id>/export?preset=hipaa"
```

Typical operator checks:

- attestation is compliant
- proof list is present
- runtime mode is what you expected
- Lean status is active when the Lean binary is configured
- release or review lineage appears when the workflow requires it

## Production Checklist

Use this as the minimum operator checklist before a serious demo or deployment.

### Runtime

- set `CERTIOR_ENV=production`
- set `CERTIOR_KMS_ROOT_SECRET` (HS256 signing secret; generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`)
- set `CERTIOR_API_KEYS_JSON` (JSON object mapping API key -> client label)
- use a project-local virtual environment
- set `CERTIOR_FLOW_CHECK_BINARY` if Lean-backed runtime checks are required
- decide on persistence backend instead of relying on in-memory defaults

### Access And State

- provision API keys intentionally
- avoid depending on the default dev identity outside local development
- choose PostgreSQL and Redis where persistence and queueing matter
- inject `DATABASE_URL` through your deployment environment or secrets manager, not a manual shell export
- inject `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` through your deployment environment or secrets manager, not a committed `.env` file
- set `CERTIOR_LLM_PROVIDER=openai` explicitly when production should rely on a single OpenAI key
- keep the API server, worker, and verification-graph ingest on the same PostgreSQL database unless you have a deliberate replication or ETL design

### Evidence

- confirm compliance export works before the demo
- confirm PDFs or JSON artifacts are retrievable when the workflow depends on them
- use Example 07 and Example 08 as preflight checks for workflow and proof evidence

### Observability

- configure OTLP export if you need tracing in deployment
- confirm metrics surface if Prometheus/Grafana are part of the environment

## Persistence And Backends

The app can run with several backend shapes:

- in-memory for minimal local testing
- SQLite for single-node persistence
- PostgreSQL for durable state and event storage
- Redis/Celery for background queueing

See [CONFIGURATION.md](CONFIGURATION.md) for the exact environment variables and backend priority.

### Production PostgreSQL pattern

For a production-grade deployment, prefer a DSN in this shape:

```bash
postgresql://certior_app:<url-encoded-password>@db.example.com:5432/certior?sslmode=require&application_name=certior-api
```

Operational expectations:

- create a dedicated Certior database role with only the privileges the service needs
- require TLS between Certior and PostgreSQL
- inject the DSN through your orchestrator or secret store rather than operator shell state
- reuse the same database for API runtime state, worker processing, and verification-graph ingest so exported graph evidence matches the live execution history

### Production LLM key handling

If you only have one OpenAI key today, that is still workable for an early production deployment, but treat it as shared infrastructure, not as a developer convenience.

Minimum safe posture:

- create a dedicated production deployment secret named `OPENAI_API_KEY`
- inject it only into the containers or processes that actually make LLM calls
- set `CERTIOR_LLM_PROVIDER=openai` so provider choice is deterministic
- keep the key out of shell history, local dotfiles synced to laptops, and repository-managed config
- rotate the key after team changes, incident response, or any debugging session where exposure is plausible

When you move beyond the first key, split by environment at minimum:

- one OpenAI key for development/staging
- one OpenAI key for production

That separation makes billing, incident response, and emergency rotation materially easier.

### GitHub-safe secret handling

Because this repository is hosted on GitHub, the safest default is: no live secrets in the repository at all.

Use this repository only for templates such as [`.env.production.example`](.env.production.example). Store real values outside the repo in one of:

- your cloud or platform secret manager
- a systemd `EnvironmentFile` stored under `/etc/certior/` with `0600` permissions
- container-orchestrator secrets injected into the runtime environment

Recommended rules:

- never commit `.env.production`, `.env.local`, or any other real environment file
- never commit `.pem`, `.key`, `.crt`, `.p12`, or `.pfx` files to this repository
- use a dedicated OpenAI key for production rather than a personal developer key
- rotate the key immediately after any suspected exposure
- treat screenshots, shell history, CI logs, and support dumps as potential leak points

If you need a host-local environment file, place it outside the repository, for example:

```bash
/etc/certior/certior.env
```

and load it from your service manager rather than from a tracked project file.

### Systemd pattern

Example units are provided in [`deploy/systemd/certior-api.service.example`](deploy/systemd/certior-api.service.example) and [`deploy/systemd/certior-worker.service.example`](deploy/systemd/certior-worker.service.example).

They both read:

```bash
/etc/certior/certior.env
```

Recommended installation flow:

1. create the `certior` system user and group
2. install the repo under `/opt/certior`
3. keep `/etc/certior/certior.env` owned by `root:certior` or `root:root` with `0600` permissions
4. copy the example unit files into `/etc/systemd/system/`
5. run `sudo systemctl daemon-reload`
6. run `sudo systemctl enable --now certior-api certior-worker`

This is safer than a repository-local `.env.production` file because the secret-bearing file never enters the Git working tree.

### Docker Compose host-env pattern

If you deploy via Compose, use [`docker-compose.production.host-env.example.yml`](docker-compose.production.host-env.example.yml) as the pattern.

That override expects secrets to already be injected into the host environment and fails fast when they are missing. It keeps real `OPENAI_API_KEY`, `DATABASE_URL`, and `REDIS_URL` values out of tracked files.

Typical usage:

```bash
export OPENAI_API_KEY='sk-...'
export CERTIOR_LLM_PROVIDER='openai'
export DATABASE_URL='postgresql://certior_app:...@db.example.com:5432/certior?sslmode=require&application_name=certior-api'
export REDIS_URL='redis://redis.example.com:6379/0'
export CERTIOR_FLOW_CHECK_BINARY='/opt/certior/lean4/CertiorPlan/.lake/build/bin/certior-flow-check'
docker compose -f docker-compose.yml -f docker-compose.production.host-env.example.yml up -d --build api worker
```

### Live runtime evidence generation

Use [`scripts/generate-runtime-evidence.sh`](scripts/generate-runtime-evidence.sh) for the production-style workflow that creates live workflow evidence and then re-ingests the verification graph.

Packaged entrypoints are also available after installation:

```bash
certior-doctor
certior-runtime-evidence
```

Before running it, use [`scripts/certior-doctor.sh`](scripts/certior-doctor.sh) to preflight runtime readiness.

For the common local path in this repository, PostgreSQL is already defined in [`docker-compose.yml`](docker-compose.yml) as the `postgres` service, exposed on `127.0.0.1:5432` with the default development credentials:

```bash
DATABASE_URL=postgresql://certior:certior@127.0.0.1:5432/certior
```

If `certior-doctor` reports that PostgreSQL is unreachable and you intend to use the local Compose service, start it with:

```bash
docker compose up -d postgres
```

Then rerun:

```bash
bash scripts/certior-doctor.sh
bash scripts/generate-runtime-evidence.sh
```

## Docker And Infra

If you need the packaged stack, use the repository Docker setup:

```bash
docker compose up --build
```

Use the observability profile when you want the full operational stack (Prometheus + Grafana):

```bash
docker compose --profile observability up --build
```

## Operational Notes

- `run.sh` is the primary local entrypoint
- [`CONFIGURATION.md`](CONFIGURATION.md) is the source of truth for environment variables
- the API is the customer-facing surface; the Lean stack is a deeper assurance layer
- if the Lean binary is absent, the runtime degrades to Z3-only mode rather than refusing to start


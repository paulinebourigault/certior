---
title: "Certior Studio"
description: "An optional Next.js UI for the Certior FastAPI server. Inspect runs, explore the delegation graph, export audit packages."
---

The pip package is the SDK. The GitHub repository also ships **Certior Studio** - a Next.js frontend over the FastAPI server - for teams that want to self-host a control plane.

Studio is optional. The SDK works fully without it.

## What Studio gives you

- A live multi-agent delegation graph rendered from the server's `/api/v1/agents/delegation-graph` endpoint.
- Per-execution timeline of allowed and blocked tool calls with the verifying certificate inline.
- Compliance export in PDF and JSON, per execution and per workflow.
- A glass-box view of each verify call - inputs, the policy applied, the violations found, the redacted output.

## Running it locally

```bash
pip install "certior[api]"        # SDK + FastAPI server
./run.sh                          # uvicorn at http://localhost:8000
```

The Next.js frontend lives under `app/frontend/`. Run it separately in development:

```bash
cd app/frontend
npm install
npm run dev        # http://localhost:3001
```

The default development credentials and ports are documented in [`OPERATIONS.md`](https://github.com/paulinebourigault/certior/blob/main/OPERATIONS.md) and the env var reference in [Configuration](/reference/configuration).

## Production deployment

For production, run the API and the worker via the `Dockerfile` and the `docker-compose.production.host-env.example.yml` overlay (host-env injection of all required secrets). The `observability` Compose profile adds Prometheus and Grafana.

Full deployment, persistence, and secrets guidance lives in [`OPERATIONS.md`](https://github.com/paulinebourigault/certior/blob/main/OPERATIONS.md).

## See also

- [Configuration](/reference/configuration) - the environment variables the server reads.
- [API overview](/api/overview) - the REST endpoints Studio renders against.

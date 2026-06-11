---
title: "REST API overview"
description: "The Certior REST API covers verified task execution, workflow orchestration, compliance export, releases, and trust badges under the /api/v1/ prefix."
---

The Certior FastAPI server exposes a REST surface used by Certior Studio, programmatic integrations, and the GitHub Action webhook.

Base path: `/api/v1/`.

## Endpoint families

| Family | Path prefix | What it covers |
|---|---|---|
| [Authentication](/api/authentication) | `/auth` | Register, log in, rotate API keys, read the current user. |
| [Tasks](/api/tasks) | `/tasks` | Submit a task for verified execution. |
| [Executions](/api/executions) | `/executions` | List executions, fetch a single execution, cancel one. |
| [Workflows](/api/workflows) | `/workflows` | Multi-stage orchestrations with per-stage policy. |
| [Compliance](/api/compliance) | `/compliance` | List built-in presets, export an execution's compliance package. |
| [Releases](/api/releases) | `/releases` | Release decisions, promotions, GitHub webhook. |
| Agents | `/agents` | Plan verification, delegation, glass-box records. |
| Trust badge | `/trust/badge` | SVG trust badge for a repo + commit. |

## Authentication

Every endpoint outside `/auth/register` and `/auth/login` requires an API key in the `Authorization` header:

```
Authorization: Bearer <api-key>
```

API keys are issued by `POST /api/v1/auth/register` or `POST /api/v1/auth/login`. Rotate them via `POST /api/v1/auth/rotate`. See [Authentication](/api/authentication) for the full flow.

## Response envelope

Successful responses are returned as JSON matching the documented `*Response` Pydantic model. Errors return a JSON body of shape:

```json
{ "detail": "..." }
```

The `detail` field is a string for simple errors and a structured object for richer cases (for example, the task endpoint returns `{"message": "...", "denied": [...]}` when a request is denied by the policy ceiling).

## Status codes

| Code | Meaning |
|---|---|
| `200` | OK. |
| `201` | Created (e.g. `POST /tasks`, `POST /workflows`, `POST /auth/register`). |
| `400` | Invalid policy or request body. |
| `401` | Missing or invalid API key. |
| `403` | Denied by role or policy ceiling. |
| `404` | Resource not found. |
| `422` | Request body did not validate against the Pydantic model. |

## OpenAPI

Running `./run.sh` exposes `/openapi.json` and the Swagger UI at `/docs` for interactive exploration. The OpenAPI document is generated from the same Pydantic models the routes use, so it is always in sync with the running server.

## Versioning

See [API contract](https://github.com/paulinebourigault/certior/blob/main/docs/api-contract.md) for the v1 stability guarantees.

---
title: "Tasks"
description: "Submit a task for verified execution. Certior runs the three gates before each tool call and returns an execution id."
---

A **task** is a single-agent execution. Submit it, poll for the result, or stream events over WebSocket.

The route file is [`app/api/routes/tasks.py`](https://github.com/paulinebourigault/certior/blob/main/app/api/routes/tasks.py).

## `POST /tasks`

Submit a task.

```http
POST /api/v1/tasks
Authorization: Bearer <api-key>
Content-Type: application/json
```

**Request body** (`TaskRequest`):

| Field | Type | Required | Description |
|---|---|---|---|
| `task` | `str` | yes | Natural-language description of what the agent should do. |
| `compliance_policy` | `"default" \| "hipaa" \| "sox" \| "legal" \| "legal_privilege"` | no | Active policy preset. `"legal"` is an alias for `"legal_privilege"`. |
| `budget_cents` | `int` | no | Per-task budget. Default `10000`; range `[100, 1_000_000]`. |
| `permissions` | `list[str]` | no | Requested capabilities. Intersected with the active policy's ceiling - **not** used verbatim. |
| `provider` | `"anthropic" \| "openai"` | no | LLM provider override for this task. Omit to use the server's default. |
| `model` | `str` | no | Model name override. |
| `webhook_url` | `str` | no | Optional callback URL the server POSTs the execution result to when the task completes. |

**Example - single-agent HIPAA**:

```json
{
  "task": "Summarize the discharge note. Redact direct identifiers. Apply minimum-necessary.",
  "compliance_policy": "hipaa",
  "budget_cents": 2000
}
```

**Response** (`201 Created`, `TaskResponse`):

```json
{
  "execution_id": "exec_8c5e...",
  "status":       "queued",
  "websocket_url":"ws://.../ws/executions/exec_8c5e..."
}
```

The `websocket_url` streams events as the task runs: tool calls, verify decisions, certificates, blocked attempts.

## Error responses

`400` - invalid compliance policy or request shape.

`401` - missing or invalid API key.

`403` - denied by policy ceiling. The body is structured:

```json
{
  "detail": {
    "message": "No effective permissions after applying 'hipaa' compliance policy",
    "denied": [
      {
        "permission": "network:http:read",
        "reason": "exceeds_policy_ceiling",
        "detail": "Permission is not within the HIPAA policy allowed set"
      }
    ]
  }
}
```

`422` - the request body did not match the Pydantic model.

## What happens server-side

1. The request is validated against the active compliance policy's `max_permissions` ceiling.
2. An execution record is created and the task is enqueued.
3. The agentic executor (LLM + tool dispatcher) starts running. Every tool call passes through `Guard.verify(...)` before execution. Allowed calls produce a `VerifiedCertificate` recorded in the execution; blocked calls are recorded with their violations.
4. The execution finishes with a status of `succeeded`, `blocked`, `error`, or `cancelled`.

## See also

- [Executions](/api/executions) - fetching the result by id.
- [Workflows](/api/workflows) - multi-stage orchestrations.
- [Compliance](/api/compliance) - exporting the audit package for a finished execution.

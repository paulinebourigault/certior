---
title: "Executions"
description: "List executions, fetch one by id, cancel a queued or running execution."
---

The route file is [`app/api/routes/executions.py`](https://github.com/paulinebourigault/certior/blob/main/app/api/routes/executions.py).

## `GET /executions/{execution_id}`

Fetch a single execution.

```http
GET /api/v1/executions/exec_8c5e...
Authorization: Bearer <api-key>
```

Returns the execution record: status, the resolved permissions, every tool call attempted with its verify verdict, every issued certificate, and the final output.

## `GET /executions`

List the calling user's executions. Supports pagination query parameters - see the OpenAPI schema at `/openapi.json` on the running server for the exact fields.

## `DELETE /executions/{execution_id}`

Cancel a queued or running execution. Idempotent: a finished execution is left in place; a cancelled one stays cancelled.

## See also

- [Tasks](/api/tasks) - creating an execution.
- [Compliance](/api/compliance) - exporting the audit package for a finished execution.

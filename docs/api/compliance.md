---
title: "Compliance"
description: "List built-in policy presets. Export the audit package for a finished execution."
---

The route file is [`app/api/routes/compliance.py`](https://github.com/paulinebourigault/certior/blob/main/app/api/routes/compliance.py).

## `GET /compliance/presets`

Return the list of built-in compliance presets.

```http
GET /api/v1/compliance/presets
Authorization: Bearer <api-key>
```

**Response**: an array of preset descriptors. Each carries the preset name, a short description, the default permission set, the absolute permission ceiling, the forbidden capability list, and the active audit retention.

The four presets are `default`, `hipaa`, `sox`, `legal_privilege`. See [Compliance policies](/concepts/policies) for what each one enforces.

## `GET /compliance/{execution_id}/export`

Export the compliance package for a finished execution.

```http
GET /api/v1/compliance/exec_8c5e.../export
Authorization: Bearer <api-key>
```

**Query parameters**:

| Name | Default | Meaning |
|---|---|---|
| `preset` | the execution's policy | Override which preset the export targets. |
| `format` | `json` | `json` or `pdf`. |

**Returns**: a structured archive of the execution. For `json`, the body is a JSON object containing every verified certificate, the run's audit trail, the active policy, the proof attestation block, and the runtime mode. For `pdf`, the body is a multi-section document suitable for handing to an auditor.

A `404` is returned when the execution id is unknown to the calling user.

## See also

- [Tasks](/api/tasks) - creating the execution.
- [Workflows](/api/workflows) - the multi-stage version with its own export.
- [Trust package](/reference/trust-package) - the assurance vocabulary the export uses.

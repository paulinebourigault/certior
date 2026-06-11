---
title: "Workflows"
description: "Multi-stage orchestrations where each stage runs under its own policy and binds to a previous stage by stage id."
---

A **workflow** is a sequence of stages. Each stage is a single-agent execution with its own compliance policy, budget, and capability ceiling. A stage can require a compliant upstream stage by id - the basis for reviewed-then-release patterns.

The route file is [`app/api/routes/workflows.py`](https://github.com/paulinebourigault/certior/blob/main/app/api/routes/workflows.py).

## `POST /workflows`

Create a workflow.

```http
POST /api/v1/workflows
Authorization: Bearer <api-key>
Content-Type: application/json
```

**Request body** (`WorkflowRequest`):

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | `str` | yes | Workflow name (1-160 chars). |
| `description` | `str` | no | Free-text description, ≤ 400 chars. |
| `stages` | `list[WorkflowStageRequest]` | yes | 1-12 stages, in order. |

Each `WorkflowStageRequest`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `str` | no | Stable stage id used by downstream stages to refer to this one. |
| `name` | `str` | yes | Display name (1-120 chars). |
| `task` | `str` | yes | Natural-language description. |
| `compliance_policy` | `str` | no | Default `"default"`. Same values as on `POST /tasks`. |
| `budget_cents` | `int` | no | Default `1500`; range `[100, 1_000_000]`. |
| `stage_role` | `str` | no | One of `"intake"`, `"reviewer"`, `"release"`, `"worker"` (default). The role drives review/release lineage checks. |
| `provider` | `"anthropic" \| "openai"` | no | LLM provider override. |
| `model` | `str` | no | Model override. |
| `api_key` | `str` | no | Per-stage API key override (min length 8). |
| `permissions` | `list[str]` | no | Requested capabilities; intersected with the active policy ceiling. |
| `upstream_stage_ids` | `list[str]` | no | Ids of earlier stages this stage requires. The server resolves these to execution ids and binds them to this stage's run. |

**Response** (`201 Created`, `WorkflowResponse`): the workflow record with each stage's resolved id, status, and (once started) execution id.

## `GET /workflows`

List the calling user's workflows.

## `GET /workflows/{workflow_id}`

Fetch a workflow's current state, including each stage's status, `execution_id`, and timing.

## `DELETE /workflows/{workflow_id}`

Cancel a workflow. Returns `WorkflowCancelResponse`. Idempotent: a finished workflow is left in place; a cancelled one stays cancelled.

## `GET /workflows/{workflow_id}/export`

Export the workflow's full audit package: each stage's execution, every verified certificate, and the chain of upstream stage ids proving the review-then-release linkage. Returns `WorkflowExportResponse`.

## The reviewed-release pattern

The strongest production-style workflow runs in two stages:

1. Stage A with `stage_role="reviewer"` produces a compliant artifact.
2. Stage B with `stage_role="release"` and `upstream_stage_ids=["stage_A_id"]` is admitted only if stage A succeeded with a compliant verdict.

The example [`examples/07_multi_agent_reviewed_release.py`](https://github.com/paulinebourigault/certior/blob/main/examples/07_multi_agent_reviewed_release.py) runs this end to end.

## See also

- [Tasks](/api/tasks) - the single-stage version.
- [Compliance](/api/compliance) - exporting workflow-level audit packages.
- [Releases](/api/releases) - release decision endpoints for the gate stage.

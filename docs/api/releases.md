---
title: "Releases"
description: "Release decisions, snapshot promotions, GitHub webhook, and the trust badge endpoint."
---

The release endpoints sit under `/api/v1/releases/` and `/api/v1/trust/`. They are the integration points for CI/CD gates and public attestation badges.

The route files are [`app/api/routes/releases.py`](https://github.com/paulinebourigault/certior/blob/main/app/api/routes/releases.py) and [`app/api/routes/trust.py`](https://github.com/paulinebourigault/certior/blob/main/app/api/routes/trust.py).

## `GET /releases/decision`

Return the release decision for a specific commit.

```http
GET /api/v1/releases/decision?repo_root=my-org/my-repo&commit_sha=abc123...
Authorization: Bearer <api-key>
```

Requires one of: `ADMIN`, `AUDITOR`, `VIEWER`, `OPERATOR`, `APPROVER`, `POLICY_AUTHOR`.

**Response** (`ReleaseDecisionResponse`):

```json
{
  "decision":   "SHIP",
  "blockers":   [],
  "baseline":   { "snapshot_id": "...", "commit_sha": "..." }
}
```

`decision` is `"SHIP"` or `"NO_SHIP"`. `blockers` is the list of distinct blocking violations when the decision is `NO_SHIP`. External gates should only proceed when `decision == "SHIP"`.

## `GET /releases/health`

Return current release-gate health: whether the verification graph is reachable, whether the latest attested snapshot is fresh, and whether any required runtime evidence is missing.

Same role list as `/decision`.

## `POST /releases/promote`

Promote a snapshot to an attested release. Records the release label and the metadata used for later snapshot-to-snapshot comparisons.

**Request body** (`PromotionRequest`): the snapshot id, the target status, the release label, and any channel-specific metadata.

**Response** (`PromotionResponse`): the recorded promotion record.

## `GET /releases/promotions`

List the history of promotions for the current scope. Same role list as `/decision`.

## `POST /releases/github-webhook`

The webhook endpoint for the [Certior GitHub Action](/integrations/github-action). GitHub POSTs pull-request and check-run events here; the server posts decision summaries back to the PR.

The handler filters on event type and action. Note: HMAC signature verification of the webhook is **not yet enforced** — restrict the endpoint at the network layer (or in front of it) until it is.

## `GET /trust/badge`

Return an SVG badge for a commit.

```html
<img
  src="https://your-certior-host.example/api/v1/trust/badge?repo=my-org/my-repo&commit=HEAD"
  alt="Certior trust level"
/>
```

The badge is one of **Assured**, **Blocked**, or **Unknown** based on the most recent decision for that commit.

## See also

- [GitHub Action](/integrations/github-action) - the upstream of the webhook.
- [Workflows](/api/workflows) - the reviewed-release pattern that feeds the decision.

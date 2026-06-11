---
title: "GitHub Action"
description: "Gate every pull request with Certior policy checks. The action evaluates declared capability surfaces against the configured policy package."
---

The Certior GitHub Action runs the Certior policy check on every pull request. It evaluates the declared capability surfaces in your repository against the configured policy package and fails the workflow when a delegation chain widens beyond what the policy allows.

The action lives at [`.github/actions/certior/`](https://github.com/paulinebourigault/certior/tree/main/.github/actions/certior) in the source repo.

## Workflow recipe

```yaml
name: Certior policy check
on: [pull_request]

jobs:
  certior:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Certior policy check
        uses: ./.github/actions/certior     # in-repo
        # external callers:
        # uses: paulinebourigault/certior/.github/actions/certior@main
        with:
          policy_packages: "hipaa"          # comma-separated, e.g. "hipaa, sox"
```

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `policy_packages` | yes | `"hipaa"` | Comma-separated list of policy packages to check against. |
| `repo_root` | no | `"."` | Root of the repository to scan. |

## What the action does

For each file in `repo_root` carrying a Certior capability declaration (e.g. `SKILL.md` frontmatter under `metadata.certior.capabilities`, or a `Guard(permissions=[...])` in code), the action runs the same subset check the runtime uses. The workflow fails on:

- A declared capability not permitted under the selected policy package(s).
- A delegation chain whose child capability surface exceeds its parent's.

The check is the same logic [`certior-skill-audit`](/integrations/skill-audit) runs locally - wiring it into CI catches drift between commits.

## Per-PR webhook (optional)

If you run a live Certior server, also configure a GitHub webhook pointing at the server's [`POST /api/v1/releases/github-webhook`](/api/releases) endpoint. The server posts a decision summary back to the PR thread as it runs.

## See also

- [Skill audit CLI](/integrations/skill-audit) - the same check, on the command line.
- [Releases API](/api/releases) - the webhook target for live decision comments.

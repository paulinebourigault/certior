# Certior Integrations

Certior plugs into the surfaces a security-conscious team already runs - CI and the README badge that signals trust to consumers.

## 1. GitHub Action - capability check on PRs

Run the Certior policy check on every pull request. The action evaluates declared capability surfaces against the configured policy package(s) and fails the workflow if a delegation chain widens beyond what's permitted.

```yaml
jobs:
  certior-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Certior policy check
        uses: ./.github/actions/certior     # from inside this repo
        # external callers: uses: paulinebourigault/certior/.github/actions/certior@main
        with:
          policy_packages: "hipaa"          # comma-separated; e.g. "hipaa, sox"
```

For per-PR runtime comments from a live Certior server, also wire a GitHub webhook pointing at the server's `POST /api/v1/releases/github-webhook` endpoint. The server posts decision summaries back to the PR as it runs.

## 2. Trust badge - public attestation on a commit

When you run the Certior server, `GET /api/v1/trust/badge?repo=<owner>/<name>&commit=<sha>` returns an SVG badge reflecting the most recent attestation for that commit:

```html
<img
  src="https://your-certior-host.example/api/v1/trust/badge?repo=my-org/my-repo&commit=HEAD"
  alt="Certior trust level"
/>
```

The badge returns one of **Assured, Blocked, Unknown** based on the verification graph for that commit. Until a hosted Certior service is publicly available, point the badge at your own deployment (the FastAPI server in `app/`); see [OPERATIONS.md](../OPERATIONS.md) for deploy steps.

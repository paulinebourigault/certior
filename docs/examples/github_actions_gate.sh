#!/bin/bash
# Example GitHub Actions deployment gate script using Certior Release API
# Usage: ./github_actions_gate.sh <repo_root> <commit_sha>

set -euo pipefail

REPO_ROOT="${1:-${GITHUB_REPOSITORY}}"
COMMIT_SHA="${2:-${GITHUB_SHA}}"
CERTIOR_API_URL="${CERTIOR_API_URL:-http://localhost:8000}"

echo "Checking release decision for ${REPO_ROOT}@${COMMIT_SHA}..."

RESPONSE=$(curl -sS -f "${CERTIOR_API_URL}/api/v1/releases/decision?repo_root=${REPO_ROOT}&commit_sha=${COMMIT_SHA}")

DECISION=$(echo "$RESPONSE" | jq -r '.decision')

if [ "$DECISION" = "SHIP" ]; then
  echo "✅ Certior Release Gate Passed. Proceeding with deployment."
  exit 0
else
  echo "❌ Certior Release Gate Failed. 'NO_SHIP' determination."
  BLOCKERS=$(echo "$RESPONSE" | jq -r '.blockers[].reason')
  echo "Blockers:"
  echo "$BLOCKERS"
  exit 1
fi

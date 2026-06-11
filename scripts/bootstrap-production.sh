#!/bin/bash
# ─────────────────────────────────────────────────────────────────────
# Certior: production environment bootstrap.
# Bootstraps the production docker-compose topology.
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

# 1. Enforce Env
echo "Checking required environment variables..."
MISSING=""

for var in OPENAI_API_KEY DATABASE_URL REDIS_URL CERTIOR_KMS_ROOT_SECRET CERTIOR_API_KEYS_JSON; do
    if [ -z "${!var:-}" ]; then
        echo "❌ Error: Required environment variable $var is unset."
        MISSING="yes"
    fi
done

if [ -n "$MISSING" ]; then
    echo ""
    echo "Please configure external secrets/connections before running."
    echo ""
    echo "Generate the JWT signing secret with:"
    echo "    python -c 'import secrets; print(secrets.token_urlsafe(32))'"
    echo ""
    echo "Build CERTIOR_API_KEYS_JSON as a JSON object mapping API key to"
    echo "client label, e.g.:"
    echo "    {\"ck-prod-...\": \"orchestrator-a\"}"
    echo ""
    echo "See CONFIGURATION.md (Security section) for the full reference."
    exit 1
fi

echo "✅ Environment variables verified."

# 2. Start PostgreSQL (if relying on internal) or Validate Connection
echo "Validating Database Connection..."
if docker-compose -f docker-compose.yml -f docker-compose.production.host-env.example.yml config >/dev/null 2>&1; then
    echo "✅ Docker compose configuration is valid."
else
    echo "❌ Error: docker-compose configuration is invalid."
    exit 1
fi

# 3. Apply specific deployment topology (Frontend, API, Worker, Redis, PG)
echo "Bootstrapping Certior Production Topology..."
docker-compose -f docker-compose.yml -f docker-compose.production.host-env.example.yml build

echo "✅ Build completed successfully."

echo ""
echo "🚀 Bootstrap successful. Run the following command to deploy:"
echo ""
echo "    docker-compose -f docker-compose.yml -f docker-compose.production.host-env.example.yml up -d"
echo ""

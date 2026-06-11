#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DATA_DIR="${REPO_ROOT}/.data"
DIAGNOSTICS_PATH="${DATA_DIR}/doctor-report.json"
PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
ENV_FILE="/etc/certior/certior.env"
LOCAL_ENV_FILE="${REPO_ROOT}/.env"
FLOW_CHECK_BIN_DEFAULT="${REPO_ROOT}/lean4/CertiorPlan/.lake/build/bin/certior-flow-check"

if [ ! -x "${PYTHON_BIN}" ]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python)"
  fi
fi

mkdir -p "${DATA_DIR}"
cd "${REPO_ROOT}"

loaded_sources=()

json_source_list() {
  if [ "${#loaded_sources[@]}" -eq 0 ]; then
    echo "[]"
    return
  fi

  local joined
  joined=$(printf '"%s",' "${loaded_sources[@]}")
  echo "[${joined%,}]"
}

if [ -f "${ENV_FILE}" ]; then
  set -a
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
  set +a
  loaded_sources+=("/etc/certior/certior.env")
fi

need_local_env=0
if [ -z "${DATABASE_URL:-}" ]; then
  need_local_env=1
fi
if [ -z "${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}" ]; then
  need_local_env=1
fi

if [ "${need_local_env}" -eq 1 ] && [ -f "${LOCAL_ENV_FILE}" ]; then
  set -a
  # shellcheck disable=SC1090
  . "${LOCAL_ENV_FILE}"
  set +a
  loaded_sources+=(".env")
fi

export CERTIOR_ENV="${CERTIOR_ENV:-production}"
if [ -z "${CERTIOR_FLOW_CHECK_BINARY:-}" ] && [ -x "${FLOW_CHECK_BIN_DEFAULT}" ]; then
  export CERTIOR_FLOW_CHECK_BINARY="${FLOW_CHECK_BIN_DEFAULT}"
fi

has_python_env=false
has_database_url=false
has_openai_key=false
has_anthropic_key=false
provider_override_present=false
provider_detected=""
provider_sdk_ready=true
provider_sdk_error=""
has_asyncpg=true
asyncpg_error=""
db_connectivity_ready=false
db_connectivity_error=""
flow_check_binary_present=false
docker_compose_postgres_available=false
docker_compose_postgres_running=false

if [ -x "${PYTHON_BIN}" ]; then
  has_python_env=true
fi

if [ -n "${DATABASE_URL:-}" ]; then
  has_database_url=true
fi

if [ -n "${OPENAI_API_KEY:-}" ]; then
  has_openai_key=true
fi

if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  has_anthropic_key=true
fi

if [ -n "${CERTIOR_LLM_PROVIDER:-}" ]; then
  provider_override_present=true
  provider_detected="${CERTIOR_LLM_PROVIDER}"
elif [ "${has_openai_key}" = true ]; then
  provider_detected="openai"
elif [ "${has_anthropic_key}" = true ]; then
  provider_detected="anthropic"
fi

if [ -n "${CERTIOR_FLOW_CHECK_BINARY:-}" ] && [ -x "${CERTIOR_FLOW_CHECK_BINARY}" ]; then
  flow_check_binary_present=true
fi

if [ -f "${REPO_ROOT}/docker-compose.yml" ]; then
  docker_compose_postgres_available=true
  if docker compose ps --status running postgres >/dev/null 2>&1; then
    docker_compose_postgres_running=true
  fi
fi

if [ "${has_python_env}" = true ]; then
  if ! "${PYTHON_BIN}" - <<'PY' >/dev/null 2>&1
import asyncpg
PY
  then
    has_asyncpg=false
    asyncpg_error="The Python package 'asyncpg' is not installed. Install it with: .venv/bin/python -m pip install asyncpg>=0.29.0"
  fi

  if [ -n "${provider_detected}" ]; then
    if ! "${PYTHON_BIN}" - <<PY >/dev/null 2>&1
import importlib
module_name = "openai" if "${provider_detected}" == "openai" else "anthropic"
importlib.import_module(module_name)
PY
    then
      provider_sdk_ready=false
      if [ "${provider_detected}" = "openai" ]; then
        provider_sdk_error="The Python package 'openai' is not installed. Install it with: .venv/bin/python -m pip install openai>=1.12.0"
      else
        provider_sdk_error="The Python package 'anthropic' is not installed. Install it with: .venv/bin/python -m pip install anthropic>=0.39.0"
      fi
    fi
  fi

  if [ "${has_database_url}" = true ] && [ "${has_asyncpg}" = true ]; then
    if DATABASE_URL="${DATABASE_URL}" "${PYTHON_BIN}" - <<'PY' >/dev/null 2>&1
import asyncio
import os

import asyncpg


async def main() -> None:
    connection = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        await connection.execute("SELECT 1")
    finally:
        await connection.close()


asyncio.run(main())
PY
    then
      db_connectivity_ready=true
    else
      db_connectivity_error="DATABASE_URL is set but PostgreSQL is unreachable. If you are using the local Docker service, run: docker compose up -d postgres"
    fi
  fi
fi

cat > "${DIAGNOSTICS_PATH}" <<EOF
{
  "loaded_sources": $(json_source_list),
  "has_python_env": ${has_python_env},
  "has_database_url": ${has_database_url},
  "has_openai_key": ${has_openai_key},
  "has_anthropic_key": ${has_anthropic_key},
  "provider_detected": "${provider_detected}",
  "provider_override_present": ${provider_override_present},
  "provider_sdk_ready": ${provider_sdk_ready},
  "provider_sdk_error": "${provider_sdk_error}",
  "has_asyncpg": ${has_asyncpg},
  "asyncpg_error": "${asyncpg_error}",
  "db_connectivity_ready": ${db_connectivity_ready},
  "db_connectivity_error": "${db_connectivity_error}",
  "flow_check_binary_present": ${flow_check_binary_present},
  "docker_compose_postgres_available": ${docker_compose_postgres_available},
  "docker_compose_postgres_running": ${docker_compose_postgres_running}
}
EOF

echo "Certior Doctor"
echo "  loaded sources: ${loaded_sources[*]:-none}"
echo "  python env: $([ "${has_python_env}" = true ] && echo ok || echo missing)"
echo "  provider: ${provider_detected:-none}"
echo "  provider sdk: $([ "${provider_sdk_ready}" = true ] && echo ok || echo failed)"
echo "  asyncpg: $([ "${has_asyncpg}" = true ] && echo ok || echo missing)"
echo "  database url: $([ "${has_database_url}" = true ] && echo present || echo missing)"
echo "  db connectivity: $([ "${db_connectivity_ready}" = true ] && echo ok || echo failed)"
echo "  flow check binary: $([ "${flow_check_binary_present}" = true ] && echo ok || echo missing)"
echo "  docker compose postgres: $([ "${docker_compose_postgres_available}" = true ] && echo available || echo unavailable) / $([ "${docker_compose_postgres_running}" = true ] && echo running || echo stopped)"
echo "  report: .data/doctor-report.json"

if [ "${has_python_env}" != true ] || [ "${provider_sdk_ready}" != true ] || [ "${has_asyncpg}" != true ] || { [ "${has_database_url}" = true ] && [ "${db_connectivity_ready}" != true ]; }; then
  exit 1
fi
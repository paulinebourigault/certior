#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DATA_DIR="${REPO_ROOT}/.data"
API_LOG_PATH="${DATA_DIR}/runtime-api.log"
WORKFLOW_EXPORT_PATH="${DATA_DIR}/runtime-workflow-export.json"
WORKFLOW_SUMMARY_PATH="${DATA_DIR}/runtime-workflow-summary.json"
ALL_PROVERS_LOG_PATH="${DATA_DIR}/runtime-all-provers.log"
GRAPH_INGEST_PATH="${DATA_DIR}/runtime-graph-ingest.json"
REPO_CONTEXT_PATH="${DATA_DIR}/runtime-repo-context.json"
DIAGNOSTICS_PATH="${DATA_DIR}/runtime-env-diagnostics.json"
PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
HOST="${CERTIOR_HOST:-127.0.0.1}"
PORT="${CERTIOR_PORT:-8010}"
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
export CERTIOR_HOST="${HOST}"
export CERTIOR_PORT="${PORT}"

if [ -z "${CERTIOR_FLOW_CHECK_BINARY:-}" ] && [ -x "${FLOW_CHECK_BIN_DEFAULT}" ]; then
  export CERTIOR_FLOW_CHECK_BINARY="${FLOW_CHECK_BIN_DEFAULT}"
fi

if [ ! -x "${PYTHON_BIN}" ]; then
  cat > "${DIAGNOSTICS_PATH}" <<EOF
{
  "ready": false,
  "error": "python_env_missing",
  "python_bin": "${PYTHON_BIN}",
  "loaded_sources": $(json_source_list)
}
EOF
  echo "Missing Python environment: ${PYTHON_BIN}" >&2
  exit 1
fi

has_database_url=0
if [ -n "${DATABASE_URL:-}" ]; then
  has_database_url=1
fi

has_openai_key=0
if [ -n "${OPENAI_API_KEY:-}" ]; then
  has_openai_key=1
fi

has_anthropic_key=0
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  has_anthropic_key=1
fi

provider_detected=""
provider_sdk_ready=true
provider_sdk_error=""
if [ -n "${CERTIOR_LLM_PROVIDER:-}" ]; then
  provider_detected="${CERTIOR_LLM_PROVIDER}"
elif [ "${has_openai_key}" -eq 1 ]; then
  provider_detected="openai"
elif [ "${has_anthropic_key}" -eq 1 ]; then
  provider_detected="anthropic"
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
      provider_sdk_error="The Python package 'openai' is not installed. Install it with: ${PYTHON_BIN} -m pip install openai>=1.12.0"
    else
      provider_sdk_error="The Python package 'anthropic' is not installed. Install it with: ${PYTHON_BIN} -m pip install anthropic>=0.39.0"
    fi
  fi
fi

db_connectivity_ready=true
db_connectivity_error=""
if ! DATABASE_URL="${DATABASE_URL}" "${PYTHON_BIN}" - <<'PY' >/dev/null 2>&1
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
  db_connectivity_ready=false
  db_connectivity_error="DATABASE_URL is set but PostgreSQL is unreachable. Start PostgreSQL or point DATABASE_URL at a live server before generating runtime evidence."
fi

cat > "${DIAGNOSTICS_PATH}" <<EOF
{
  "ready": false,
  "loaded_sources": $(json_source_list),
  "has_database_url": ${has_database_url},
  "has_openai_key": ${has_openai_key},
  "has_anthropic_key": ${has_anthropic_key},
  "provider_detected": "${provider_detected}",
  "provider_sdk_ready": ${provider_sdk_ready},
  "provider_sdk_error": "${provider_sdk_error}",
  "db_connectivity_ready": ${db_connectivity_ready},
  "db_connectivity_error": "${db_connectivity_error}",
  "provider_override_present": $(if [ -n "${CERTIOR_LLM_PROVIDER:-}" ]; then echo true; else echo false; fi),
  "host": "${CERTIOR_HOST}",
  "port": "${CERTIOR_PORT}",
  "flow_check_binary_present": $(if [ -n "${CERTIOR_FLOW_CHECK_BINARY:-}" ] && [ -x "${CERTIOR_FLOW_CHECK_BINARY}" ]; then echo true; else echo false; fi)
}
EOF

if [ "${has_database_url}" -ne 1 ]; then
  echo "DATABASE_URL is not set. Checked /etc/certior/certior.env, inherited env, and .env fallback." >&2
  exit 1
fi

if [ $((has_openai_key + has_anthropic_key)) -eq 0 ]; then
  echo "No LLM API key is set. Checked /etc/certior/certior.env, inherited env, and .env fallback." >&2
  exit 1
fi

if [ "${provider_sdk_ready}" != "true" ]; then
  echo "${provider_sdk_error}" >&2
  exit 1
fi

if [ "${db_connectivity_ready}" != "true" ]; then
  echo "${db_connectivity_error}" >&2
  exit 1
fi

"${PYTHON_BIN}" -m uvicorn app.main:create_app --factory --host "${CERTIOR_HOST}" --port "${CERTIOR_PORT}" --log-level warning > "${API_LOG_PATH}" 2>&1 &
server_pid=$!

cleanup() {
  kill "${server_pid}" 2>/dev/null || true
  wait "${server_pid}" 2>/dev/null || true
}
trap cleanup EXIT

"${PYTHON_BIN}" - <<'PY'
import json
import os
import time
import uuid
from pathlib import Path

import httpx

base = f"http://{os.environ.get('CERTIOR_HOST', '127.0.0.1')}:{os.environ.get('CERTIOR_PORT', '8010')}"
workflow_export_path = Path('.data/runtime-workflow-export.json')
workflow_summary_path = Path('.data/runtime-workflow-summary.json')
diagnostics_path = Path('.data/runtime-env-diagnostics.json')

public_artifact = (
    'A patient received hospital care, improved, and was discharged with routine follow-up instructions.'
)
review_text = 'Approved public artifact candidate: ' + public_artifact
review_task = (
    'Review the following de-identified public artifact candidate for residual PHI, '
    'minimum-necessary compliance, and public-release readiness. '
    'The candidate is intended to omit diagnosis details, procedures, medication names, dates, ages, '
    'locations, provider names, record numbers, and other direct or indirect identifiers. '
    'If it is safe, return exactly the approved public artifact text and nothing else. '
    'If unsafe, return NO-GO with the blocking reason.\n\n'
    + review_text
)
release_task = (
    'Publish the reviewed public artifact to the public website. '
    'Only the approved de-identified content may be released, and the release output must match the reviewed artifact exactly.\n\n'
    f'Approved public artifact candidate:\n{public_artifact}'
)


def wait_for_health() -> dict:
    deadline = time.time() + 90
    last_error = None
    with httpx.Client(base_url=base, timeout=10.0) as client:
        while time.time() < deadline:
            try:
                response = client.get('/health')
                response.raise_for_status()
                return response.json()
            except Exception as exc:
                last_error = str(exc)
                time.sleep(1.0)
    raise RuntimeError(f'API did not become healthy in time: {last_error}')


health = wait_for_health()
email = f"runtime-evidence-{uuid.uuid4().hex[:12]}@certior.local"
provider = os.environ.get('CERTIOR_LLM_PROVIDER')
if not provider:
    if os.environ.get('OPENAI_API_KEY'):
        provider = 'openai'
    elif os.environ.get('ANTHROPIC_API_KEY'):
        provider = 'anthropic'

with httpx.Client(base_url=base, timeout=180.0) as client:
    register = client.post('/api/v1/auth/register', json={'email': email, 'name': 'Runtime Evidence Runner'})
    register.raise_for_status()
    api_key = register.json()['api_key']
    client.headers.update({'Authorization': f'Bearer {api_key}'})

    providers = client.get('/api/v1/settings/providers')
    providers.raise_for_status()
    providers_payload = providers.json()

    workflow_payload = {
        'name': 'Production reviewed release evidence',
        'description': 'Generates persisted review and release runtime evidence for verification-graph ingest.',
        'stages': [
            {
              'id': 'privacy-review',
                'name': 'Privacy Review',
                'task': review_task,
                'compliance_policy': 'hipaa',
                'budget_cents': 2500,
                'stage_role': 'reviewer',
                **({'provider': provider} if provider else {}),
            },
            {
              'id': 'public-release',
                'name': 'Public Release',
                'task': release_task,
                'compliance_policy': 'hipaa',
                'budget_cents': 2500,
                'stage_role': 'release',
              'upstream_stage_ids': ['privacy-review'],
                **({'provider': provider} if provider else {}),
            },
        ],
    }
    created = client.post('/api/v1/workflows', json=workflow_payload)
    created.raise_for_status()
    workflow = created.json()
    workflow_id = workflow['id']

    deadline = time.time() + 240
    last_status = workflow['status']
    while time.time() < deadline:
        current = client.get(f'/api/v1/workflows/{workflow_id}')
        current.raise_for_status()
        workflow = current.json()
        if workflow['status'] != last_status:
            print(f"workflow_status={workflow['status']}")
            last_status = workflow['status']
        if workflow['status'] in {'completed', 'failed', 'cancelled'}:
            break
        time.sleep(1.0)
    else:
        raise TimeoutError(f'Workflow {workflow_id} did not complete in time')

    exported = client.get(f'/api/v1/workflows/{workflow_id}/export')
    exported.raise_for_status()
    export_payload = exported.json()
    workflow_export_path.write_text(json.dumps(export_payload, indent=2), encoding='utf-8')

    summary = {
        'base_url': base,
        'health': health,
        'providers': providers_payload,
        'workflow_id': workflow['id'],
        'workflow_status': workflow['status'],
        'workflow_error': workflow.get('error', ''),
        'stage_statuses': [
            {
                'id': stage['id'],
                'name': stage['name'],
                'status': stage['status'],
                'execution_id': stage.get('execution_id'),
                'error': stage.get('error', ''),
            }
            for stage in workflow['stages']
        ],
        'export_path': str(workflow_export_path),
    }
    workflow_summary_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')

    diagnostics = json.loads(diagnostics_path.read_text(encoding='utf-8'))
    diagnostics['ready'] = workflow['status'] == 'completed'
    diagnostics['provider_detected'] = provider
    diagnostics['workflow_status'] = workflow['status']
    diagnostics_path.write_text(json.dumps(diagnostics, indent=2), encoding='utf-8')

    print(json.dumps(summary, indent=2))
    if workflow['status'] != 'completed':
        raise SystemExit(2)
PY

"${PYTHON_BIN}" examples/08_all_provers_showcase.py > "${ALL_PROVERS_LOG_PATH}" 2>&1

"${PYTHON_BIN}" - <<'PY'
import asyncio
import json
import os
from pathlib import Path

from agentsafe.verification_graph.ingest import ingest_repository
from agentsafe.verification_graph.tools import VerificationGraphTools

repo_root = os.getcwd()
dsn = os.environ['DATABASE_URL']
component_name = 'agentsafe.runtime_policy'
bridge_name = 'seccomp_dafny_bridge'
workflow_name = 'Production reviewed release evidence'
workflow_summary = json.loads(Path('.data/runtime-workflow-summary.json').read_text(encoding='utf-8'))
workflow_lookup = workflow_summary.get('workflow_id') or workflow_name

ingest_payload = asyncio.run(ingest_repository(dsn, repo_root))
graph_tools = VerificationGraphTools(dsn)
repo_payload = asyncio.run(graph_tools.repo_context(repo_root))
component_payload = asyncio.run(graph_tools.component_context(repo_root, component_name))
bridge_payload = asyncio.run(graph_tools.bridge_alignment(repo_root, bridge_name))
workflow_payload = asyncio.run(graph_tools.workflow_lineage(repo_root, workflow_lookup))

Path('.data/runtime-graph-ingest.json').write_text(json.dumps(ingest_payload, indent=2), encoding='utf-8')
Path('.data/runtime-repo-context.json').write_text(json.dumps(repo_payload, indent=2), encoding='utf-8')
Path('.data/runtime-component-context.json').write_text(json.dumps(component_payload, indent=2), encoding='utf-8')
Path('.data/runtime-bridge-alignment.json').write_text(json.dumps(bridge_payload, indent=2), encoding='utf-8')
Path('.data/runtime-workflow-lineage.json').write_text(json.dumps(workflow_payload, indent=2), encoding='utf-8')

summary = {
    'snapshot_id': ingest_payload.get('snapshot_id') or ((ingest_payload.get('snapshot') or {}).get('id')),
    'repo_context_counts': repo_payload.get('counts', {}),
    'component_name': component_name,
    'component_runtime_evidence_count': len(component_payload.get('runtime_evidence', [])),
    'bridge_name': bridge_name,
    'bridge_runtime_evidence_count': len(bridge_payload.get('runtime_evidence', [])),
    'workflow_name': workflow_name,
    'workflow_lookup': workflow_lookup,
    'workflow_stage_count': len(workflow_payload.get('stages', [])),
    'all_provers_log_path': '.data/runtime-all-provers.log',
    'graph_ingest_path': '.data/runtime-graph-ingest.json',
    'repo_context_path': '.data/runtime-repo-context.json',
    'component_context_path': '.data/runtime-component-context.json',
    'bridge_alignment_path': '.data/runtime-bridge-alignment.json',
    'workflow_lineage_path': '.data/runtime-workflow-lineage.json',
    'workflow_export_path': '.data/runtime-workflow-export.json',
    'workflow_summary_path': '.data/runtime-workflow-summary.json',
}
print(json.dumps(summary, indent=2))
PY
#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Certior Quickstart - install, configure, and run the API server
#
# Usage:
#   ./run.sh                                   # interactive
#   ANTHROPIC_API_KEY=sk-... ./run.sh          # Anthropic (Claude)
#   OPENAI_API_KEY=sk-... ./run.sh             # OpenAI (GPT-4o)
#   CERTIOR_PORT=9000 ./run.sh                 # custom port
#   ./run.sh --dev-only                        # skip LLM, local tools only
#   ./run.sh --help
#
# What this script does:
#   1. Creates a Python virtual environment (if needed)
#   2. Installs Certior and all dependencies
#   3. Sets up workspace and data directories
#   4. Prints the auto-generated dev API key
#   5. Starts the FastAPI server with hot-reload
#
# Requirements: Python 3.11+
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${BLUE}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()  { echo -e "${YELLOW}△${NC}  $*"; }
err()   { echo -e "${RED}✗${NC}  $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
DEV_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --dev-only)   DEV_ONLY=true ;;
        --help|-h)
            cat <<'EOF'
Certior Quickstart

Usage: ./run.sh [OPTIONS]

Options:
  --dev-only    Run without LLM (local tools only)
  --help        Show this message

Environment variables:
  ANTHROPIC_API_KEY     Anthropic API key - enables Claude agent mode
  OPENAI_API_KEY        OpenAI API key    - enables GPT agent mode
  CERTIOR_LLM_PROVIDER  Force provider: anthropic | openai (auto-detected)
  CERTIOR_MODEL         LLM model name    (default: auto per provider)
  CERTIOR_HOST          Bind address       (default: 127.0.0.1)
  CERTIOR_PORT          Server port        (default: 8000)
  CERTIOR_WORKSPACE     Tool workspace dir (default: .workspace/)
  CERTIOR_DATA_DIR      SQLite data dir    (default: .data/)
  CERTIOR_ENV           development | production  (default: development)
    CERTIOR_FLOW_CHECK_BINARY  Lean live flow-check binary path
    CERTIOR_STUDIO_URL    Canonical frontend Studio URL (default: http://127.0.0.1:3001)
  CERTIOR_LLM_BASE_URL  Custom API endpoint (for Azure, local models)

See CONFIGURATION.md for full reference.
EOF
            exit 0 ;;
    esac
done

# ── Banner ────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║          Certior - Verified Agent Platform          ║${NC}"
echo -e "${CYAN}${BOLD}║   Every tool call is formally verified first.       ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Load .env if present ──────────────────────────────────────────────
if [ -f "${SCRIPT_DIR}/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env"
    set +a
    ok "Loaded .env"
fi

# ── Defaults ──────────────────────────────────────────────────────────
HOST="${CERTIOR_HOST:-127.0.0.1}"
PORT="${CERTIOR_PORT:-8000}"
WORKSPACE="${CERTIOR_WORKSPACE:-${SCRIPT_DIR}/.workspace}"
DATA_DIR="${CERTIOR_DATA_DIR:-${SCRIPT_DIR}/.data}"

# ── Step 1: Python ────────────────────────────────────────────────────
info "Checking Python..."
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; v=sys.version_info; print(f'{v.major}.{v.minor}')")
        major=${ver%%.*}; minor=${ver#*.}
        if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON="$candidate"; break
        fi
    fi
done
if [ -z "$PYTHON" ]; then
    err "Python 3.11+ required.  Install from https://python.org"; exit 1
fi
ok "Python: $($PYTHON --version 2>&1)"

# ── Step 2: Virtual environment ───────────────────────────────────────
# Respect existing environments: conda, active venv, Docker, etc.
# Only create a .venv if we're in a bare system Python.
if [ -n "${VIRTUAL_ENV:-}" ] || [ -n "${CONDA_PREFIX:-}" ]; then
    # Already in a managed environment - use it
    ok "Using active environment: ${VIRTUAL_ENV:-${CONDA_PREFIX}}"
elif [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
    ok "Running in container - using system Python"
elif [ -d "$VENV_DIR" ]; then
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"
    ok "Virtualenv: ${VENV_DIR}"
else
    info "Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR" 2>/dev/null || {
        warn "venv creation failed - install python3-venv or use conda"
        warn "Continuing with current Python ($(which python3))"
    }
    if [ -d "$VENV_DIR" ]; then
        # shellcheck disable=SC1091
        source "${VENV_DIR}/bin/activate"
        ok "Virtualenv: ${VENV_DIR}"
    fi
fi

# ── Step 3: Install ──────────────────────────────────────────────────
info "Installing Certior (this may take a minute on first run)..."
pip install -q --upgrade pip setuptools wheel 2>/dev/null
pip install -q -e ".[all,dev]" 2>&1 | grep -v "already satisfied" | tail -2 || true
VERSION=$(pip show certior 2>/dev/null | awk '/^Version:/{print $2}')
ok "Certior ${VERSION} installed"

# ── Step 4: Directories ──────────────────────────────────────────────
mkdir -p "$WORKSPACE" "$DATA_DIR"
ok "Workspace: ${WORKSPACE}"
ok "Data:      ${DATA_DIR}"

# ── Step 5: LLM provider ─────────────────────────────────────────────
# Supports Anthropic (Claude) and OpenAI (GPT).  Auto-detects from
# available API keys, or prompts the user interactively.
if [ "$DEV_ONLY" = true ]; then
    warn "Dev-only mode - no LLM, local tools only"
    unset ANTHROPIC_API_KEY 2>/dev/null || true
    unset OPENAI_API_KEY 2>/dev/null || true
elif [ -n "${ANTHROPIC_API_KEY:-}" ] && [ -n "${OPENAI_API_KEY:-}" ]; then
    ok "Both LLM keys found - Anthropic + OpenAI available"
    if [ -n "${CERTIOR_LLM_PROVIDER:-}" ]; then
        ok "Provider override: ${CERTIOR_LLM_PROVIDER}"
    else
        info "Default provider: Anthropic  (set CERTIOR_LLM_PROVIDER=openai to change)"
    fi
elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    ok "Anthropic API key found - using Claude"
elif [ -n "${OPENAI_API_KEY:-}" ]; then
    ok "OpenAI API key found - using GPT"
else
    echo ""
    echo -e "${YELLOW}No LLM API key found.  Set one to enable agent mode:${NC}"
    echo -e "  ${BOLD}ANTHROPIC_API_KEY${NC}  - Anthropic (Claude)  https://console.anthropic.com"
    echo -e "  ${BOLD}OPENAI_API_KEY${NC}    - OpenAI   (GPT-4o)   https://platform.openai.com"
    echo ""
    echo -e "${BOLD}Which provider? [1] Anthropic  [2] OpenAI  [Enter] Skip${NC}"
    read -r -p "Choose (1/2/Enter): " provider_choice
    case "$provider_choice" in
        1)
            read -r -p "$(echo -e "${BOLD}Paste ANTHROPIC_API_KEY: ${NC}")" key_input
            if [ -n "$key_input" ]; then
                export ANTHROPIC_API_KEY="$key_input"
                ok "Anthropic API key set"
            fi
            ;;
        2)
            read -r -p "$(echo -e "${BOLD}Paste OPENAI_API_KEY: ${NC}")" key_input
            if [ -n "$key_input" ]; then
                export OPENAI_API_KEY="$key_input"
                ok "OpenAI API key set"
            fi
            ;;
        *)
            warn "No API key - legacy mode (tools work, no LLM reasoning)"
            ;;
    esac
fi

# ── Step 6: Generate .env if missing ──────────────────────────────────
if [ ! -f "${SCRIPT_DIR}/.env" ]; then
    cp "${SCRIPT_DIR}/.env.example" "${SCRIPT_DIR}/.env" 2>/dev/null || true
fi

# ── Step 7: Print connection info ─────────────────────────────────────
# Generate a stable dev API key and export it so the server process
# uses the exact same key (the auth module reads CERTIOR_DEV_API_KEY).
DEV_KEY="ck-$(python -c "import secrets; print(secrets.token_urlsafe(32))")"
export CERTIOR_DEV_API_KEY="$DEV_KEY"

echo ""
echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
echo -e "  ${BOLD}Dev API Key:${NC}  ${GREEN}${DEV_KEY}${NC}"
echo -e "  ${BOLD}API Base:${NC}     http://${HOST}:${PORT}/api/v1"
echo -e "  ${BOLD}API Docs:${NC}     http://${HOST}:${PORT}/docs"
echo -e "  ${BOLD}Health:${NC}       http://${HOST}:${PORT}/health"
echo -e "  ${BOLD}Studio:${NC}       ${CERTIOR_STUDIO_URL:-http://127.0.0.1:3001}"
echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    echo -e "  ${GREEN}● Agent mode${NC}  (Anthropic / Claude)"
elif [ -n "${OPENAI_API_KEY:-}" ]; then
    echo -e "  ${GREEN}● Agent mode${NC}  (OpenAI / GPT)"
else
    echo -e "  ${YELLOW}○ Legacy mode${NC} (no LLM)"
fi
echo ""
echo -e "  Try the examples (with server running):"
echo -e "    ${BOLD}CERTIOR_DEV_API_KEY=${DEV_KEY} python examples/01_health_check.py${NC}"
echo -e "    ${BOLD}python examples/03_hipaa_compliance.py${NC}  (no server needed)"
echo ""

export CERTIOR_HOST="$HOST"
export CERTIOR_PORT="$PORT"
export CERTIOR_WORKSPACE="$WORKSPACE"
export CERTIOR_DATA_DIR="$DATA_DIR"
export CERTIOR_ENV="${CERTIOR_ENV:-development}"
export CERTIOR_DEV_API_KEY="$DEV_KEY"

# ── Step 7b: Lean flow-check binary (required in production) ───────────
if [ -z "${CERTIOR_FLOW_CHECK_BINARY:-}" ]; then
    DEFAULT_FLOW_BIN="${SCRIPT_DIR}/lean4/CertiorPlan/.lake/build/bin/certior-flow-check"
    if [ -x "${DEFAULT_FLOW_BIN}" ]; then
        export CERTIOR_FLOW_CHECK_BINARY="${DEFAULT_FLOW_BIN}"
        ok "CERTIOR_FLOW_CHECK_BINARY: ${CERTIOR_FLOW_CHECK_BINARY}"
    elif [ "${CERTIOR_ENV}" = "production" ]; then
        err "CERTIOR_FLOW_CHECK_BINARY is required in production."
        err "Build Lean binaries first: ./scripts/build-lean.sh --build-only"
        exit 1
    else
        warn "CERTIOR_FLOW_CHECK_BINARY not set (Lean lattice verifier disabled)"
    fi
fi

# ── Step 8: Start server ─────────────────────────────────────────────
info "Starting Certior on http://${HOST}:${PORT}  (Ctrl+C to stop)"
echo ""

exec uvicorn "app.main:create_app" \
    --factory \
    --host "$HOST" \
    --port "$PORT" \
    --reload \
    --log-level info

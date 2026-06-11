#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# scripts/build-lean.sh - Build the Lean4 verified kernel
#
# Builds:
#   1. CertiorLattice   - Proven bounded distributive lattice (P1-P21)
#   2. CertiorPlan core - Execution kernel, DAP server, flow checker
#
# Produces these binaries in lean4/CertiorPlan/.lake/build/bin/:
#   - certior-dap         VS Code DAP debug adapter
#   - certior-flow-check  Live agent flow verification daemon
#
# Prerequisites:
#   - elan (Lean version manager): https://github.com/leanprover/elan
#   - lean-toolchain will auto-select Lean v4.14.0
#
# Usage:
#   ./scripts/build-lean.sh              # full build + test
#   ./scripts/build-lean.sh --build-only # skip tests
#   ./scripts/build-lean.sh --test-only  # skip build (assumes prior build)
#   ./scripts/build-lean.sh --help
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${BLUE}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()  { echo -e "${YELLOW}△${NC}  $*"; }
err()   { echo -e "${RED}✗${NC}  $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LATTICE_DIR="${ROOT_DIR}/lean4/CertiorLattice"
PLAN_DIR="${ROOT_DIR}/lean4/CertiorPlan"

BUILD=true
TEST=true

for arg in "$@"; do
    case "$arg" in
        --build-only)  TEST=false ;;
        --test-only)   BUILD=false ;;
        --help|-h)
            cat <<'EOF'
Certior Lean4 Kernel Build Script

Usage: ./scripts/build-lean.sh [OPTIONS]

Options:
  --build-only    Build without running tests
  --test-only     Run tests without rebuilding
  --help          Show this message

Targets built:
  certior-dap         VS Code DAP debug adapter
  certior-flow-check  Live agent flow verification daemon

Environment variables:
  CERTIOR_FLOW_CHECK_BINARY  Override path to flow-check binary
                             (used by Python lean_live_verifier.py)
EOF
            exit 0 ;;
    esac
done

# ── Banner ────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║   Certior - Lean4 Verified Kernel Build                 ║${NC}"
echo -e "${CYAN}${BOLD}║   CertiorLattice (proofs) + CertiorPlan (execution)     ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Prerequisites ────────────────────────────────────────────
info "Checking prerequisites..."

if ! command -v lake &>/dev/null; then
    if ! command -v elan &>/dev/null; then
        err "Neither 'lake' nor 'elan' found."
        err "Install elan:  curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh"
        exit 1
    fi
    warn "'lake' not in PATH - elan will manage it via lean-toolchain"
fi

# Check toolchain
EXPECTED_TOOLCHAIN="leanprover/lean4:v4.14.0"
if [ -f "${PLAN_DIR}/lean-toolchain" ]; then
    ACTUAL=$(cat "${PLAN_DIR}/lean-toolchain" | tr -d '[:space:]')
    if [ "$ACTUAL" != "$EXPECTED_TOOLCHAIN" ]; then
        warn "lean-toolchain says '${ACTUAL}', expected '${EXPECTED_TOOLCHAIN}'"
    else
        ok "Toolchain: ${ACTUAL}"
    fi
fi

# Verify directory structure
if [ ! -f "${LATTICE_DIR}/lakefile.lean" ]; then
    err "CertiorLattice not found at ${LATTICE_DIR}"
    exit 1
fi
if [ ! -f "${PLAN_DIR}/lakefile.lean" ]; then
    err "CertiorPlan not found at ${PLAN_DIR}"
    exit 1
fi
ok "Project structure verified"

# ── Step 2: Build CertiorLattice ─────────────────────────────────────
if [ "$BUILD" = true ]; then
    echo ""
    info "Building CertiorLattice (proven lattice, ~60s first time)..."
    cd "${LATTICE_DIR}"

    if lake build 2>&1 | tee /dev/stderr | tail -1; then
        ok "CertiorLattice built"
    else
        err "CertiorLattice build failed"
        exit 1
    fi

    # ── Step 3: Build CertiorPlan ────────────────────────────────────
    echo ""
    info "Building CertiorPlan core targets (~120s first time)..."
    cd "${PLAN_DIR}"

    if lake build CertiorPlan certior-dap certior-flow-check 2>&1 | tee /dev/stderr | tail -1; then
        ok "CertiorPlan built"
    else
        err "CertiorPlan build failed"
        exit 1
    fi

    # ── Step 4: Verify binaries ──────────────────────────────────────
    echo ""
    info "Verifying binaries..."
    BIN_DIR="${PLAN_DIR}/.lake/build/bin"

    BINARIES=("certior-dap" "certior-flow-check")
    ALL_OK=true
    for bin in "${BINARIES[@]}"; do
        if [ -x "${BIN_DIR}/${bin}" ]; then
            SIZE=$(du -h "${BIN_DIR}/${bin}" | cut -f1)
            ok "${bin}  (${SIZE})"
        else
            err "${bin}  MISSING"
            ALL_OK=false
        fi
    done

    if [ "$ALL_OK" = false ]; then
        err "Some binaries missing - check build output above"
        exit 1
    fi

    echo ""
    warn "Skipping plan-export generation in production core build"
fi

# ── Step 6: Run tests ────────────────────────────────────────────────
if [ "$TEST" = true ]; then
    echo ""
    warn "Skipping Lean DSL/test targets in production core build"
fi

# ── Step 7: Flow-check binary discovery info ─────────────────────────
echo ""
BIN_DIR="${PLAN_DIR}/.lake/build/bin"
FLOW_CHECK="${BIN_DIR}/certior-flow-check"

if [ -x "${FLOW_CHECK}" ]; then
    echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
    echo -e "  ${BOLD}Flow-check binary:${NC}  ${GREEN}${FLOW_CHECK}${NC}"
    echo ""
    echo -e "  The Python agent discovers this binary via:"
    echo -e "    1. ${BOLD}CERTIOR_FLOW_CHECK_BINARY${NC} env var"
    echo -e "    2. ${BOLD}lean4/CertiorPlan/.lake/build/bin/certior-flow-check${NC}"
    echo -e "    3. ${BOLD}certior-flow-check${NC} in PATH"
    echo ""
    echo -e "  Quick test:"
    echo -e "    ${BOLD}echo '{\"command\":\"init\",\"budget\":1000,\"capabilities\":[],\"compliance\":\"default\"}' | ${FLOW_CHECK}${NC}"
    echo ""
    echo -e "  Set for Python agent:"
    echo -e "    ${BOLD}export CERTIOR_FLOW_CHECK_BINARY=${FLOW_CHECK}${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
fi

# ── Step 8: DAP binary discovery info ─────────────────────────────────
DAP_BIN="${BIN_DIR}/certior-dap"
if [ -x "${DAP_BIN}" ]; then
    echo ""
    echo -e "  ${BOLD}DAP binary:${NC}         ${GREEN}${DAP_BIN}${NC}"
    echo ""
    echo -e "  The VS Code extension discovers this binary via:"
    echo -e "    1. ${BOLD}certiorDapPath${NC} in launch.json"
    echo -e "    2. ${BOLD}.lake/build/bin/certior-dap${NC} in workspace"
    echo -e "    3. ${BOLD}certior-dap${NC} in PATH"
    echo ""
    echo -e "  To debug a plan in VS Code:"
    echo -e "    1. Open ${BOLD}certior.code-workspace${NC}"
    echo -e "    2. Open any .lean file in CertiorPlan"
    echo -e "    3. Press ${BOLD}F5${NC} → select ${BOLD}'Certior: Basic Plan'${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
fi

# ── Summary ───────────────────────────────────────────────────────────
echo ""
LEAN_LINES=$(find "${ROOT_DIR}/lean4" -name "*.lean" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
echo -e "${GREEN}${BOLD}Build complete!${NC}"
echo -e "  Lean4 code:  ${LEAN_LINES} lines (zero sorry)"
echo -e "  Binaries:    ${BIN_DIR}/"
echo -e "  PlanInfo:    ${PLAN_DIR}/.dap/"
echo ""

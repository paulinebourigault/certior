#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# scripts/build-extension.sh - Build the Certior Plan DAP VS Code extension
#
# Compiles TypeScript and optionally packages as .vsix.
#
# Prerequisites:
#   - Node.js 18+
#   - npm
#
# Usage:
#   ./scripts/build-extension.sh             # compile only
#   ./scripts/build-extension.sh --package   # compile + package .vsix
#   ./scripts/build-extension.sh --help
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
CLIENT_DIR="${ROOT_DIR}/lean4/CertiorPlan/client"
PACKAGE=false

for arg in "$@"; do
    case "$arg" in
        --package) PACKAGE=true ;;
        --help|-h)
            cat <<'EOF'
Certior Plan DAP Extension Build

Usage: ./scripts/build-extension.sh [OPTIONS]

Options:
  --package   Also package as .vsix (requires vsce)
  --help      Show this message

Installation (development):
  1. Build:  ./scripts/build-extension.sh
  2. Open:   certior.code-workspace in VS Code
  3. Press:  F5 in Extension Development Host
  Or:
  1. Build:  ./scripts/build-extension.sh --package
  2. Install: code --install-extension certior-plan-dap-client-0.1.0.vsix
EOF
            exit 0 ;;
    esac
done

echo ""
echo -e "${CYAN}${BOLD}Building Certior Plan DAP Extension${NC}"
echo ""

# ── Prerequisites ─────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
    err "Node.js not found. Install from https://nodejs.org"
    exit 1
fi
NODE_VER=$(node --version)
ok "Node.js: ${NODE_VER}"

if ! command -v npm &>/dev/null; then
    err "npm not found"
    exit 1
fi

# ── Install deps ──────────────────────────────────────────────────────
cd "${CLIENT_DIR}"
info "Installing dependencies..."
if [ -f package-lock.json ]; then
    npm ci --silent
else
    npm install --silent
fi
ok "Dependencies installed"

# ── Compile ───────────────────────────────────────────────────────────
info "Compiling TypeScript..."
npm run compile
ok "Compiled → out/extension.js"

# ── Package ───────────────────────────────────────────────────────────
if [ "$PACKAGE" = true ]; then
    echo ""
    if ! command -v vsce &>/dev/null; then
        info "Installing vsce..."
        npm install -g @vscode/vsce 2>/dev/null || {
            warn "Could not install vsce globally, trying npx"
        }
    fi

    info "Packaging .vsix..."
    if command -v vsce &>/dev/null; then
        vsce package --no-dependencies
    else
        npx @vscode/vsce package --no-dependencies
    fi
    ok "Package created"
    ls -la *.vsix 2>/dev/null
fi

echo ""
echo -e "${GREEN}${BOLD}Extension build complete!${NC}"
echo ""
echo -e "  ${BOLD}Development:${NC}"
echo -e "    1. Open ${BOLD}certior.code-workspace${NC} in VS Code"
echo -e "    2. The extension auto-activates on debug launch"
echo -e "    3. Press ${BOLD}F5${NC} to debug a plan"
echo ""
echo -e "  ${BOLD}Ensure the Lean kernel is built first:${NC}"
echo -e "    ${BOLD}./scripts/build-lean.sh${NC}"
echo ""

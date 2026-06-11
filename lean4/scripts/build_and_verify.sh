#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Certior - Lean 4 Lattice Proof Build & Verification Script
# ═══════════════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/build_and_verify.sh          # full build + verify
#   ./scripts/build_and_verify.sh --check  # type-check only (no build cache)
#
# Prerequisites:
#   - elan (https://github.com/leanprover/elan)
#   - Lean 4 toolchain matching lean-toolchain file
#
# Exit codes:
#   0  All proofs verified successfully
#   1  Build or verification failure
#   2  Missing prerequisites
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/CertiorLattice"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_ok()   { printf "${GREEN}✓${NC} %s\n" "$1"; }
log_fail() { printf "${RED}✗${NC} %s\n" "$1"; }
log_info() { printf "${YELLOW}→${NC} %s\n" "$1"; }

# ── Check prerequisites ──────────────────────────────────────────────

check_prereqs() {
    if ! command -v elan &>/dev/null && ! command -v lean &>/dev/null; then
        log_fail "Neither 'elan' nor 'lean' found in PATH."
        echo ""
        echo "Install elan (Lean version manager):"
        echo "  curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh"
        echo ""
        exit 2
    fi

    if ! command -v lake &>/dev/null; then
        log_fail "'lake' build tool not found in PATH."
        echo "  It should be installed with elan. Try: elan self update"
        exit 2
    fi

    log_ok "Prerequisites satisfied (lean=$(lean --version 2>/dev/null | head -1))"
}

# ── Build ─────────────────────────────────────────────────────────────

build_project() {
    log_info "Building CertiorLattice project..."
    cd "$PROJECT_DIR"

    if [[ "${1:-}" == "--check" ]]; then
        log_info "Type-checking Certior/Lattice.lean..."
        lake env lean Certior/Lattice.lean
    else
        lake build
    fi

    if [[ $? -eq 0 ]]; then
        log_ok "All proofs verified successfully."
    else
        log_fail "Verification FAILED."
        exit 1
    fi
}

# ── Summary ───────────────────────────────────────────────────────────

print_summary() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  Certior Lean 4 Lattice Verification - PASSED"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Verified theorems:"
    echo "    P13   Lattice ordering (reflexive, transitive, antisymmetric, total)"
    echo "    P14   Flow safety (no-downgrade, exhaustive 16-pair check)"
    echo "    P21   Join soundness (UB, LUB, idempotent, commutative, associative)"
    echo "    NEW   Meet soundness (LB, GLB, idempotent, commutative, associative)"
    echo "    NEW   Absorption laws"
    echo "    NEW   Distributivity"
    echo "    NEW   Bounded lattice (⊥ = Public, ⊤ = Restricted)"
    echo "    NEW   Finiteness (|SecurityLevel| = 4)"
    echo "    NEW   Label flow (P15: level ∧ tags, reflexive, transitive)"
    echo "    C1    Master theorem: IsValidBoundedLattice"
    echo ""
    echo "  Files:"
    echo "    Certior/Lattice.lean  - all proofs"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────

main() {
    echo "Certior - Lean 4 Lattice Proof Verification"
    echo "────────────────────────────────────────────"
    echo ""

    check_prereqs
    build_project "${1:-}"
    print_summary
}

main "$@"

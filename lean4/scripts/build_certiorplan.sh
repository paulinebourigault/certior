#!/bin/bash
# Build CertiorPlan (and dependency CertiorLattice)
# Usage:
#   ./build_certiorplan.sh          # Build only
#   ./build_certiorplan.sh --test   # Build + run core smoke checks
#   ./build_certiorplan.sh --all    # Build + core smoke checks + Python tests

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LEAN_DIR="$(dirname "$SCRIPT_DIR")"

echo "═══════════════════════════════════════════════════════════════"
echo " CertiorPlan Build System"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Step 1: Build CertiorLattice (dependency)
echo "── Building CertiorLattice (dependency) ──"
cd "$LEAN_DIR/CertiorLattice"
lake build 2>&1 | tail -3
echo "  ✓ CertiorLattice built"
echo ""

# Step 2: Build CertiorPlan core targets
echo "── Building CertiorPlan core targets ──"
cd "$LEAN_DIR/CertiorPlan"
lake build CertiorPlan certior-dap certior-flow-check 2>&1 | tail -5
echo "  ✓ CertiorPlan built"
echo ""

# Step 3: Optionally run tests
if [[ "${1:-}" == "--test" || "${1:-}" == "--all" ]]; then
    echo "── Running core smoke checks ──"
    test -x ./.lake/build/bin/certior-dap
    test -x ./.lake/build/bin/certior-flow-check
    echo "  ✓ core smoke checks complete"
    echo ""
fi

# Step 4: Optionally run Python tests
if [[ "${1:-}" == "--all" ]]; then
    echo "── Running Python Bridge Tests ──"
    cd "$LEAN_DIR/.."
    python tests/test_lean_bridge.py
    echo ""
fi

echo "═══════════════════════════════════════════════════════════════"
echo " Build complete ✓"
echo "═══════════════════════════════════════════════════════════════"

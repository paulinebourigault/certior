#!/usr/bin/env bash
# Build the Lean live-verification binary `certior-flow-check`.
#
# The pip package does not bundle this binary (it would be ~93 MB).
# Run this script once after cloning to enable live Lean verification
# in the runtime. Subsequent runs are incremental (~seconds).
#
# Prerequisites:
#   - Lean 4 toolchain managed by elan (https://github.com/leanprover/elan)
#   - The CertiorPlan workspace under lean4/CertiorPlan/
#
# Output:
#   lean4/CertiorPlan/.lake/build/bin/certior-flow-check
#
# Enable runtime use:
#   export CERTIOR_FLOW_CHECK_BINARY=$(pwd)/lean4/CertiorPlan/.lake/build/bin/certior-flow-check
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN_DIR="${REPO_ROOT}/lean4/CertiorPlan"
TARGET="certior-flow-check"
OUT="${PLAN_DIR}/.lake/build/bin/${TARGET}"

if ! command -v lake >/dev/null 2>&1; then
    echo "error: lake (Lean 4 build tool) is not on PATH." >&2
    echo "       install elan from https://github.com/leanprover/elan and retry." >&2
    exit 1
fi

if [[ ! -d "${PLAN_DIR}" ]]; then
    echo "error: ${PLAN_DIR} does not exist. Run this from a full clone of the repo." >&2
    exit 1
fi

echo "==> Building ${TARGET} in ${PLAN_DIR}"
echo "    This is incremental - first run takes 5-15 min, subsequent runs are seconds."

cd "${PLAN_DIR}"
lake build "${TARGET}"

if [[ ! -x "${OUT}" ]]; then
    echo "error: build completed but binary not found at ${OUT}" >&2
    exit 1
fi

echo
echo "==> Built: ${OUT}"
echo "    size: $(du -h "${OUT}" | cut -f1)"
echo
echo "To enable live Lean verification at runtime, export the env var:"
echo
echo "    export CERTIOR_FLOW_CHECK_BINARY=\"${OUT}\""
echo
echo "Add the line to your shell profile or your service's environment to persist."

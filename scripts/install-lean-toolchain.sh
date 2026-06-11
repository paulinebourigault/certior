#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PLAN_TOOLCHAIN_FILE="${ROOT_DIR}/lean4/CertiorPlan/lean-toolchain"
LATTICE_TOOLCHAIN_FILE="${ROOT_DIR}/lean4/CertiorLattice/lean-toolchain"
ELAN_BIN_DIR="${HOME}/.elan/bin"

retry() {
    local max_attempts="$1"
    local sleep_seconds="$2"
    shift 2

    local attempt=1
    while true; do
        if "$@"; then
            return 0
        fi

        local exit_code=$?
        if [ "$attempt" -ge "$max_attempts" ]; then
            return "$exit_code"
        fi

        echo "Attempt ${attempt}/${max_attempts} failed with exit code ${exit_code}; retrying in ${sleep_seconds}s..." >&2
        sleep "$sleep_seconds"
        attempt=$((attempt + 1))
    done
}

read_toolchain() {
    tr -d '[:space:]' < "$1"
}

PLAN_TOOLCHAIN="$(read_toolchain "${PLAN_TOOLCHAIN_FILE}")"
LATTICE_TOOLCHAIN="$(read_toolchain "${LATTICE_TOOLCHAIN_FILE}")"

if [ -z "${PLAN_TOOLCHAIN}" ] || [ -z "${LATTICE_TOOLCHAIN}" ]; then
    echo "Lean toolchain files must not be empty." >&2
    exit 1
fi

if [ "${PLAN_TOOLCHAIN}" != "${LATTICE_TOOLCHAIN}" ]; then
    echo "Lean toolchain mismatch: CertiorPlan=${PLAN_TOOLCHAIN} CertiorLattice=${LATTICE_TOOLCHAIN}" >&2
    exit 1
fi

if ! command -v elan >/dev/null 2>&1; then
    retry 5 5 bash -lc "curl --retry 5 --retry-all-errors --connect-timeout 20 --max-time 120 -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none"
fi

export PATH="${ELAN_BIN_DIR}:${PATH}"

if [ -n "${GITHUB_PATH:-}" ]; then
    printf '%s\n' "${ELAN_BIN_DIR}" >> "${GITHUB_PATH}"
fi

if ! elan toolchain list | grep -Fq "${PLAN_TOOLCHAIN}"; then
    if ! retry 5 10 elan toolchain install "${PLAN_TOOLCHAIN}"; then
        echo "Failed to install Lean toolchain ${PLAN_TOOLCHAIN}." >&2
        echo "DNS diagnostics for release.lean-lang.org:" >&2
        getent hosts release.lean-lang.org >&2 || true
        exit 1
    fi
fi

elan default "${PLAN_TOOLCHAIN}"
lean --version
lake --version

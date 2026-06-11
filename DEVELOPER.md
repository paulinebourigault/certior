# Certior Developer Guide

Engineering guide for working on the Python runtime, verification stack, Lean components, and VS Code debugger.

For the high-level concepts and the verification model, see
[docs/concepts/how-it-works.md](docs/concepts/how-it-works.md).

## Audience

Use this document if you are:

- developing features in the Python runtime or API
- working on formal verification or execution semantics
- building or debugging the Lean kernel
- using the VS Code DAP workflow

For the product overview, start with [README.md](README.md).
For runtime and deployment concerns, use [OPERATIONS.md](OPERATIONS.md).

## Local Development Setup

### Python

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[all,dev]"
```

(`[all,dev]` brings in every adapter, the FastAPI server, and the test/lint dev dependencies in one step. `requirements-frozen.txt` is a pinned snapshot for legacy tooling, not the source of truth.)

### Run The API Locally

```bash
./run.sh
```

### Run In Production-Style Mode

Production mode requires `CERTIOR_KMS_ROOT_SECRET` and `CERTIOR_API_KEYS_JSON`
to be set; the server refuses to start without them. See
[CONFIGURATION.md](CONFIGURATION.md#security) for the generation one-liners.

```bash
export CERTIOR_KMS_ROOT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export CERTIOR_API_KEYS_JSON='{"ck-test": "local-test"}'
CERTIOR_ENV=production ./run.sh
```

## Core Test Commands

Run the Python suite:

```bash
pytest tests/ -q
```

Run with coverage:

```bash
pytest tests/ --cov=certior --cov=agentsafe --cov=app --cov-report=term
```

If you are working on Lean bridge behavior, run the bridge-focused tests as well.

## Repository Layout

```text
certior/
├── certior/           # The shipped SDK (Guard, adapters, CLI)
├── agentsafe/         # Runtime, verification, compliance, tools (imported by certior)
├── app/               # FastAPI server + Certior Studio (Next.js) frontend
├── examples/          # SDK + product demos (start with wrapper_quickstart.py)
├── tests/             # Python test suite
├── lean4/             # Lean policy model + plan kernel + VS Code extension
├── scripts/           # Build and support scripts
├── docs/              # Mintlify-published docs + landing page source
├── CONFIGURATION.md   # Environment-variable reference
├── OPERATIONS.md      # Runtime and deployment guide
└── DEVELOPER.md       # This document
```

## Lean And Proof Stack

The Lean side has two main roles:

- `CertiorLattice` provides the formal flow and lattice reasoning
- `CertiorPlan` provides the execution/debug substrate and runtime-facing tools

The most important runtime binary is:

- `certior-flow-check`, used by the Python live verifier bridge

For a broader Lean overview, see [lean4/README.md](lean4/README.md).
For the per-policy proof model and the audit recipe, see [docs/openclaw-defenses.md](docs/openclaw-defenses.md#what-runs-offline-vs-at-request-time) and [docs/lean-binary.md](docs/lean-binary.md).

## Build Commands

Build the Lean side:

```bash
./scripts/build-lean.sh
```

Build only, without tests:

```bash
./scripts/build-lean.sh --build-only
```

Build the VS Code extension:

```bash
./scripts/build-extension.sh
```

Set the runtime binary explicitly when testing Lean-backed runtime verification:

```bash
export CERTIOR_FLOW_CHECK_BINARY=lean4/CertiorPlan/.lake/build/bin/certior-flow-check
```

## VS Code Debugging

Use the Certior workspace and DAP integration when you need to inspect verified plans rather than runtime API behavior.

Typical flow:

1. build the Lean side
2. open `certior.code-workspace`
3. open a Lean file under `lean4/CertiorPlan`
4. launch `Certior: Basic Plan (auto-export)`

The debugger is useful when you need:

- stepwise plan inspection
- proof certificate inspection
- flow graph inspection
- debugger-triggered compliance export

## Verification Posture

The repo contains multiple assurance layers.

- Python runtime verification is exercised through the Python test suite
- the Lean bridge has focused lifecycle and protocol coverage
- the Lean-backed runtime path is active when the binary is built and discoverable
- the runtime degrades to Z3-only mode if the Lean binary is absent

Treat the Python API/runtime as the primary product surface and the Lean stack as the deeper formal layer that strengthens it.

## Developer Notes

- use a local virtual environment rather than system Python
- keep generated or local state out of version control
- prefer the examples for end-to-end sanity checks after changes
- use Example 07 for workflow enforcement regressions
- use Example 08 for proof-stack regressions

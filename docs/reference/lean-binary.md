---
title: "Live Lean verification"
description: "Build certior-flow-check to add live per-plan flow verification on top of Certior's always-on Z3 gate."
---

The Certior runtime can route each plan through a Lean-checked flow verifier in addition to the always-on Z3 gate. This page explains what the binary is, why it is not shipped with the pip package, how to build it, and what the runtime does when it is present versus absent.

## What `certior-flow-check` is

A Lean 4 executable built from [`lean4/CertiorPlan/`](https://github.com/paulinebourigault/certior/tree/main/lean4/CertiorPlan). It takes a JSON-serialised execution plan on stdin, type-checks each delegation step against the proven `Certior.Delegation` and `Certior.Encoding` lattice operations, and emits a verdict plus a Lean-issued proof certificate when the plan is admitted.

It is the live counterpart to the offline Lean proofs that run in CI. Both share the same source modules; the binary just runs the same model on a concrete plan rather than on the universal statement.

## Why it is not in the pip package

The compiled binary is ~93 MB. Shipping it inside the wheel would bloat `pip install certior` for every user, including those who never enable live Lean verification.

Without the binary, the runtime uses the Python implementation of the same subset and budget rule. Lean has proven that implementation sound offline. The behaviour is identical at the verdict level; only the source of the verdict differs.

## Building it

Requirements:

- Lean 4 toolchain (`elan` + `lake`). Install via [`scripts/install-lean-toolchain.sh`](https://github.com/paulinebourigault/certior/blob/main/scripts/install-lean-toolchain.sh).
- The source repo cloned at the commit you want to attest.

Build:

```bash
./scripts/build-lean-binary.sh
```

Produces the binary at `lean4/CertiorPlan/.lake/build/bin/certior-flow-check`. The script also runs the Lean test suite and `Certior.Audit` to confirm the four headline guarantees still depend only on Lean's three standard axioms.

## Enabling it at runtime

Point the runtime at the produced binary:

```bash
export CERTIOR_FLOW_CHECK_BINARY=lean4/CertiorPlan/.lake/build/bin/certior-flow-check
./run.sh
```

When the variable is set and the binary is executable, the runtime invokes it on every verify call alongside Z3. Allowed calls then carry a dual-prover certificate (Z3 + Lean). When the variable is unset or the binary is missing, the runtime degrades to Z3-only mode rather than refusing to start.

The OS support matrix mirrors the Lean 4 toolchain: Linux x86_64 and macOS arm64 are tested by the [`lean-binary-ci.yml`](https://github.com/paulinebourigault/certior/blob/main/.github/workflows/lean-binary-ci.yml) workflow. Windows runs through WSL.

## See also

- [Configuration](/reference/configuration) - the env vars governing the runtime.
- [How it works](/concepts/how-it-works) - the gates the binary participates in.
- [Trust package](/reference/trust-package) - the assurance the binary contributes to.

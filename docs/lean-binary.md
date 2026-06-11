# Live Lean verification - building `certior-flow-check`

The Certior runtime can route each plan through a Lean-checked flow
verifier in addition to the always-on Z3 SMT gate. This document
explains *which* binary is used, *why* it is not shipped with the pip
package, *how* to build it, and *what* the runtime does when it is
present versus absent.

## What the binary is

`certior-flow-check` is a Lean 4 executable built from
`lean4/CertiorPlan/`. It takes a JSON-serialised execution plan on
stdin, type-checks each delegation step against the proven
`Certior.Delegation` and `Certior.Encoding` lattice operations, and
emits a verdict plus a Lean-issued proof certificate when the plan is
admissible. The runtime hands every plan to this binary, parses the
verdict back, and attaches the Lean certificate to the per-call
`VerifyResult`.

The lattice module the binary checks against is the same module whose
soundness theorems (`delegationSafety`, `ifcSoundness`,
`compositionSoundness`, lattice validity) are audited in CI against
Lean's three standard axioms. Building the binary therefore does not
introduce new trust assumptions - it executes a verifier whose rules
have already been machine-checked.

## Why it is not in the pip package

The compiled binary is ~93 MB (dynamically linked ELF on Linux
x86_64; comparable on other platforms). PyPI's per-file size limit
plus the cost of forcing every user - including those on Windows or
macOS, who would not benefit from the Linux binary - to download a
90+ MB Lean compiled artefact would more than double the wheel
download for a feature most users do not need at first. The pip
package stays a pure-Python ~410 KB wheel, and the binary is built
once locally when (and only when) you want live Lean verification.

## Build

Prerequisite: the [`elan`](https://github.com/leanprover/elan)
toolchain manager. Install with:

```bash
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh
source "$HOME/.elan/env"
```

From a full clone of the repository:

```bash
./scripts/build-lean-binary.sh
```

The first run takes 5-15 minutes depending on CPU and dependency
cache state. Subsequent runs are incremental (seconds).

Output:

```
lean4/CertiorPlan/.lake/build/bin/certior-flow-check
```

## Enable at runtime

Export the absolute path to the binary in the process environment:

```bash
export CERTIOR_FLOW_CHECK_BINARY="$(pwd)/lean4/CertiorPlan/.lake/build/bin/certior-flow-check"
```

For services, add the variable to your process manager (systemd,
Docker, Kubernetes, etc.) rather than relying on shell profile
loading.

## What changes when the binary is present

| Aspect                        | Without `certior-flow-check`        | With `certior-flow-check`         |
|-------------------------------|--------------------------------------|------------------------------------|
| Z3 capability/budget gate     | runs                                 | runs                               |
| Content scanner               | runs                                 | runs                               |
| Per-plan Lean flow check      | **falls back to Python subset check** | runs the Lean verifier              |
| `policy_attestation.fingerprint` | unchanged                          | unchanged                          |
| `VerifyResult.certificate`    | Z3 cert only                         | Z3 cert + Lean cert                 |
| Latency per `verify()`        | ~10-50 ms                            | ~50-150 ms                         |

The runtime auto-detects the binary in three places, in priority
order:

1. `CERTIOR_FLOW_CHECK_BINARY` environment variable (must be an
   absolute path to an existing file).
2. The default Lake build output at
   `lean4/CertiorPlan/.lake/build/bin/certior-flow-check`, relative
   to the installed `agentsafe/` package.
3. `certior-flow-check` on the system `PATH`.

If none of those resolve, the runtime logs a one-time warning at
startup and uses the Python subset check.

## Verify the build worked

```bash
echo '{"steps": []}' | $CERTIOR_FLOW_CHECK_BINARY
```

A working binary prints a JSON verdict (typically `{"ok": true, ...}`
for an empty plan) and exits 0.

## CI

The repository's CI workflow `.github/workflows/lean-binary-ci.yml`
builds `certior-flow-check` on every commit, on both
**`ubuntu-latest`** and **`macos-latest`** runners. The build is a
hard CI requirement: if Lean refuses the lattice module or the
binary fails to link on either platform, the commit cannot land.
This means the README claim "the binary can be built from source"
is verified for every commit, on the two platforms most likely to
matter - Linux for production and macOS for development.

Each green run uploads its binary as a downloadable workflow
artefact:

| Platform | Artefact name                       |
|----------|-------------------------------------|
| Linux    | `certior-flow-check-linux-x86_64`   |
| macOS    | `certior-flow-check-macos-arm64`    |

Artefacts are retained for 30 days and can be downloaded from the
Actions tab of the GitHub repository (`gh run download <run-id>`),
which is the fastest way to grab a prebuilt binary without installing
the Lean toolchain locally.

Windows is intentionally not yet on the matrix - Lean's Windows
toolchain story still favours WSL, and no Windows runtime user has
asked for it. The matrix is one line of YAML to extend if that
changes.

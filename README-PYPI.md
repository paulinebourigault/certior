# Certior

> **Provable boundaries for multi-agent AI.** A capability boundary for OpenClaw, LangChain, CrewAI, and your own delegation chains - every agent-to-agent call is checked by Z3 against a Lean-audited policy before it runs. Allowed calls return a signed receipt. Blocked calls raise `CertiorBlocked` with a precise reason.

[![PyPI](https://img.shields.io/pypi/v/certior.svg)](https://pypi.org/project/certior/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://pypi.org/project/certior/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/paulinebourigault/certior/blob/main/LICENSE)

> **Homepage**: [certior.io](https://certior.io) · **Docs**: [docs.certior.io](https://docs.certior.io) · **Source**: [github.com/paulinebourigault/certior](https://github.com/paulinebourigault/certior)

## Install

```bash
pip install certior
```

Requires Python 3.11 or later. Pulls in `z3-solver`, `httpx`, `pydantic`, `jsonschema`, and `PyYAML`.

## Quickstart

```python
from certior import Guard, CertiorBlocked

guard = Guard(permissions=["network:http:read"])           # an agent's capability boundary

@guard.wrap(required_capabilities=["network:http:read"])   # tool calls + child agents must fit inside
def web_fetch(url): ...

web_fetch("https://example.com")  # allowed -> call runs, recorded in guard.audit_log
                                   # capability escalation -> raises CertiorBlocked
                                   # signed certificate of the decision: guard.verify(...).certificate
```

One decorator. Wraps any function. The rest of your code is unchanged.

Full 5-minute walkthrough: [docs.certior.io/quickstart](https://docs.certior.io/quickstart).

## What it does

Three gates run before every tool call:

| Gate | Checks |
|---|---|
| **Capability** | child agent's capabilities ⊆ parent's; tool requires only what's granted |
| **Content** | HIPAA / SOX / attorney-client / custom detectors on prompts and outputs |
| **Budget** | per-agent hard ceiling; every step debits the parent |

Allowed calls return a signed certificate bound to a Lean-checked policy fingerprint. Blocked calls raise `CertiorBlocked` with a precise reason. An auditor reproduces the audit with a single `lake build`.

See [how it works](https://docs.certior.io/concepts/how-it-works) and [certificates](https://docs.certior.io/concepts/certificates) for the runtime model.

## Adapters

| Framework | Module | Guide |
|---|---|---|
| OpenAI tool use | `certior.adapters.tool_use` | [docs.certior.io/guides/openai](https://docs.certior.io/guides/openai) |
| Anthropic `tool_use` | `certior.adapters.tool_use` | same recipe, native shape |
| LangChain | `certior.adapters.langchain` | [docs.certior.io/guides/langchain](https://docs.certior.io/guides/langchain) |
| CrewAI | `certior.adapters.crewai` | [docs.certior.io/guides/crewai](https://docs.certior.io/guides/crewai) |
| OpenClaw | `certior.adapters.openclaw` | [docs.certior.io/guides/openclaw](https://docs.certior.io/guides/openclaw) |
| MCP / custom | `@guard.wrap(...)` | [docs.certior.io/guides/custom-loop](https://docs.certior.io/guides/custom-loop) |

## What is proven

Three formal tools, three jobs:

- **Z3** runs on every tool call and proves the action satisfies capability, budget, and flow constraints.
- **Lean 4** machine-checks the policy model (155 theorems and lemmas, 0 `sorry`, 0 axioms beyond Lean's standard three: `propext`, `Classical.choice`, `Quot.sound`). CI fails the build if any of the four headline guarantees - `delegationSafety`, `ifcSoundness`, `compositionSoundness`, `SecurityLevel.isValidBoundedLattice` - stops depending only on standard axioms.
- **Dafny** statically verifies kernel properties (path-safety, seccomp).

Certior does not verify the LLM's behaviour. It verifies the boundary the LLM operates inside.

Full assurance model: [docs.certior.io/reference/trust-package](https://docs.certior.io/reference/trust-package).

## Server, Studio, examples

The pip package is the SDK. The GitHub repository ships the FastAPI server, the Certior Studio UI, the Lean kernel, the GitHub Action, the `certior-skill-audit` CLI, and runnable examples:

- [github.com/paulinebourigault/certior](https://github.com/paulinebourigault/certior)
- [Server + Studio](https://docs.certior.io/integrations/studio)
- [GitHub Action](https://docs.certior.io/integrations/github-action)
- [Skill audit CLI](https://docs.certior.io/integrations/skill-audit)

## Status

Alpha release, in active development under Apache-2.0. Public API may change between minor versions during the 0.x line; pin to `certior==0.1.*` for compatible updates.

Looking for design partners in healthcare, finance, legal, and regulated AI teams who need real audit trails on agent workflows.

Contact: [hello@certior.io](mailto:hello@certior.io)

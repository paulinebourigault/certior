# Defending OpenClaw with Certior

This document maps each threat identified in *Uncovering Security Threats
and Architecting Defenses in Autonomous Agents: A Case Study of OpenClaw*
([arXiv:2603.12644](https://arxiv.org/pdf/2603.12644)) to the Certior
gate that catches it, with a code example you can drop into an existing
OpenClaw bot.

## Install

```bash
pip install certior openclaw-sdk
```

## Two surfaces, distinct jobs

OpenClaw's `CompositeCallbackHandler` is documented to **swallow
exceptions raised by callback handlers** ("so one failing handler
does not block the others"). Certior therefore exposes two surfaces:

- **`GuardedAgent`** - the *enforcement* primitive. Wraps an
  `openclaw_sdk.Agent` so its `.execute()` raises `CertiorBlocked`
  outside the swallowing callback chain. **Use this when you need to
  actually block calls.**
- **`CertiorCallbackHandler`** - the *observability + accounting*
  primitive. Attached to the client, it fires per execution and
  debits the budget, scans content, and emits an audit-trail entry.
  A raised exception is logged by OpenClaw but does not stop the
  call; **use this alongside `GuardedAgent`, never instead of it**.

Recommended pattern:

```python
from certior import Guard
from certior.adapters.openclaw import GuardedAgent, CertiorCallbackHandler
from openclaw_sdk import OpenClawClient

guard = Guard(
    policy="default",                                      # or "hipaa" / "sox" / "legal_privilege"
    permissions=["network:http:read", "filesystem:read"],
    budget_cents=5000,
)

async with OpenClawClient.connect(
    callbacks=[CertiorCallbackHandler(guard)],             # accounting + audit
) as client:
    agent = GuardedAgent(client.get_agent("research-bot"), guard)
    result = await agent.execute("Summarise public AI safety research")  # actually enforced
```

Every execution is verified before the wrapped agent runs; every
returned result is scanned before reaching the caller. A blocked
verdict raises `CertiorBlocked` synchronously from `GuardedAgent`,
outside the OpenClaw callback chain, so the block is real.

## Threat → Gate mapping

| # | Threat (arXiv:2603.12644)             | Certior gate          | What runs at request time                                              |
|:-:|---------------------------------------|-----------------------|-----------------------------------------------------------------------|
| 1 | Prompt Injection                      | Content (input)       | Keyword + regex against the policy's `blocked_patterns`               |
| 2 | Tool Calling Chain Exploitation (ClawDrain) | Delegation       | Per-step capability-subset check (`step_caps ⊆ parent_permissions`). The *rule* is the one whose soundness Lean's `delegationSafety` theorem establishes offline. |
| 3 | Unauthorized Capability Access        | Capability            | `required_capabilities ⊆ permissions`; Z3 proves the subset relation  |
| 4 | Data Exfiltration                     | Content (output)      | PII detector on `ExecutionResult.content`; redact under HIPAA, block under stricter presets |
| 5 | Resource Exhaustion / Budget Abuse    | Budget                | `cost_cents` debited per execution and per pipeline step              |
| 6 | Command Injection                     | Content (params)      | Parameters scanned with the same rules as prompt content              |
| 7 | Tool Result Tampering                 | Content (output)      | `on_execution_end` re-verifies the returned `ExecutionResult`         |
| 8 | Privilege Escalation via Tool Chains  | Composition           | Independent per-step verdicts. Cross-step composition relies on the user passing tight `step_capabilities`; Lean's `compositionSoundness` theorem establishes offline that the per-step rule, applied repeatedly, does not lose strength. |

Of the eight threats the paper enumerates, all eight are addressed by
gates that exist in Certior 0.5.0. The runtime checks are simple,
deterministic, and easy to audit; the *soundness* of those checks
against the OpenClaw threat model is what the Lean proof obligation
discharges offline. See "What runs offline vs at request time" below.

## Per-threat code examples

### 1 + 4 + 6 + 7 - Prompt injection, data exfiltration, command/result tampering

Use `CertiorCallbackHandler`. The handler invokes the content gate on
the input prompt (catches 1, 6) and on the output result (catches 4, 7).
Under a compliance preset the PII detector also fires:

```python
guard = Guard(
    policy="hipaa",
    permissions=["network:http:read"],
    budget_cents=5000,
)
handler = CertiorCallbackHandler(guard, block_on_violation=True)
```

Under `policy="default"` violations are not raised - call
`guard.verify(...)` directly if you want the verdict object instead.

### 2 + 8 - ClawDrain / Privilege escalation via tool chains

Use `guarded_pipeline`. Each step's allowed capability set is checked
against the parent guard's permissions *at registration time*, and the
parent's budget is debited *per step* at run time. A step that asks
for a capability the parent does not hold is rejected immediately
with `delegation_unsafe: …`.

```python
from certior.adapters.openclaw import guarded_pipeline
from openclaw_sdk.pipeline import Pipeline

guard = Guard(
    permissions=["network:http:read", "filesystem:read"],
    budget_cents=5000,
)

pipeline = guarded_pipeline(
    Pipeline(client),
    guard,
    step_capabilities={
        "researcher": ["network:http:read"],            # ⊆ parent permissions  ✓
        "summariser": ["filesystem:read"],              # ⊆ parent permissions  ✓
        # "exfiltrator": ["database:admin"],           # ✗ - would raise CertiorBlocked
    },
    cost_cents_per_step=1,
)
pipeline.add_step("researcher", "research-bot", "find recent AI safety papers")
pipeline.add_step("summariser", "writer-bot",   "summarise the findings")
output = await pipeline.run()
```

### 3 - Unauthorized capability access (single agent)

Already enforced by `CertiorCallbackHandler` for every execution: the
guard's `permissions` define what the agent is allowed to do; anything
outside that set blocks. To extend the rule per-agent, construct a
separate guard for each agent and attach a separate handler.

### 5 - Resource exhaustion / budget abuse

`Guard(budget_cents=...)` is debited on every call (default
`cost_cents_per_execution=1` for the callback handler,
`cost_cents_per_step=1` for the pipeline helper). When the budget
hits zero the next call raises `budget_exceeded: need N, have M`.

```python
guard = Guard(permissions=["network:http:read"], budget_cents=10)
handler = CertiorCallbackHandler(guard, cost_cents_per_execution=3)
# After 4 executions the 5th raises CertiorBlocked: budget_exceeded.
```

## What's *not* covered by this adapter

The arXiv paper also names **Execution Sandboxing** and **Intent
Verification** as architected defenses. Certior 0.5.0:

- **Sandboxing** - relies on the host runtime (Linux seccomp, Docker,
  Firecracker, gVisor) or the OpenClaw skill sandbox. Certior verifies
  the *decision* to run a tool; the sandbox enforces it at the syscall
  layer. The two are complementary, not redundant.

- **Intent verification** - Certior verifies that a tool call is
  *admissible under the policy*. Whether the call matches the user's
  natural-language intent is a separate (LLM-judgment) problem that is
  not amenable to formal proof. Treat the policy as the contract and
  use Certior to enforce it.

## What runs offline vs at request time

| Stage         | What                                                                                          | When                       |
|---------------|-----------------------------------------------------------------------------------------------|----------------------------|
| Offline (CI)  | Lean machine-checks `delegationSafety`, `ifcSoundness`, `compositionSoundness`, and the lattice validity property against the policy model. Build fails if any depends on extra axioms. | At every commit            |
| Offline (CI)  | Dafny verifies kernel-level properties (path-safety, seccomp).                                | At every commit            |
| Request time  | Z3 SMT proves `required_capabilities ⊆ permissions ∧ cost ≤ budget` and emits the signed certificate (or blocks). | Every `Guard.verify(...)`  |
| Request time  | Content scanner (keyword + regex + PII regex) runs against the prompt, params, and output.    | Every callback hook        |
| Request time  | Pipeline subset check: `step_capabilities[name] ⊆ guard.permissions`.                         | Every `pipeline.add_step`  |

What the runtime does *not* do at request time: invoke Lean. The Lean
binary used by the runtime is `certior-flow-check`, built from
`lean4/CertiorPlan/`; it is **not** bundled in the pip package
(uncompressed it is ~93 MB, larger than the PyPI per-file limit minus
overhead). To turn on live Lean verification - i.e. have the runtime
refuse a plan that the Z3 check accepts but Lean rejects - run
``scripts/build-lean-binary.sh`` and point
``CERTIOR_FLOW_CHECK_BINARY`` at the produced binary. Without it, the
runtime uses the Python subset check whose *soundness* Lean has
proven. The Lean proof is what makes "this check is enough" a
justified claim instead of an assertion. See
[docs/lean-binary.md](./lean-binary.md) for the full build and
verification recipe.

## Trust package

Every verdict carries a signed certificate bound to the Lean policy
model. The fingerprint is stable across releases of the same policy
and audited in CI:

```python
guard.policy_attestation
# {
#   'kernel': 'Certior.Lattice + Delegation + Encoding + Composition (Lean 4)',
#   'fingerprint': 'cc3e0c7431fd8a53',
#   'audited_guarantees': [
#       'Certior.Delegation.delegationSafety',
#       'Certior.Encoding.ifcSoundness',
#       'Certior.Composition.compositionSoundness',
#       'SecurityLevel.isValidBoundedLattice',
#   ],
#   'trusted_axioms': ['propext', 'Classical.choice', 'Quot.sound'],
#   'audit_command': 'cd lean4/CertiorLattice && lake build Certior.Audit',
# }
```

Auditors can reproduce the audit themselves with the published
`lake build Certior.Audit` command; the build fails if the four
headline theorems stop depending only on Lean's three standard axioms.

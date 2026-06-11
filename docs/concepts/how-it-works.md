---
title: "How it works"
description: "Three gates run before every tool call: capability, content, budget. Z3 enforces, Lean proves the model is sound."
---

Certior sits between the agent that decides which tool to call and the executor that actually runs the tool. Every call passes through three independent gates. If any of them blocks, the executor never sees the call.

## The three gates

| Gate | What it checks | How |
|---|---|---|
| **Capability** | Does the agent's permission set contain every capability the tool requires? In a delegation chain, is the child's set a subset of the parent's? | Z3 (per call) + Lean (offline proof of the rule) |
| **Content** | Does the content satisfy the active policy: PII redaction (HIPAA), MNPI block (SOX), attorney-client (legal_privilege), or a custom rule set? | Keyword + regex content scanner + PII detector |
| **Budget** | Is `cost_cents` for this call ≤ the budget remaining on the guard? Every successful call debits. | Z3 verifies, Guard ledger tracks |

The flow on every call:

```
tool call -> Capability gate (Z3) -> Content gate (scanner) -> Budget gate (Z3)
                                                                |
                                                          allowed? -> issue signed VerifiedCertificate
                                                          blocked? -> raise CertiorBlocked(violations)
```

## What Z3 actually proves at runtime

For each `verify(...)` call with non-wildcard permissions, Certior encodes the question in SMT:

- The agent's capability token, as a set of strings.
- The tool's required capability set.
- The cost of this call.
- The budget remaining on the guard.

Z3 returns SAT only if every required capability is in the agent's set AND `cost ≤ remaining`. SAT means the call is admitted and a signed certificate is issued. UNSAT means the call is blocked and the precise reason is recorded.

This runs in single-digit milliseconds.

## What Lean proves offline

Z3 enforces the rule at runtime. Lean 4 proves the rule is sound. The proven properties live in `lean4/CertiorLattice/Certior/`:

- `Lattice.lean` - the information-flow lattice is a join-semilattice that respects the policy ordering.
- `Delegation.lean` - any child guard's permission set is a subset of the parent's; no chain can escalate.
- `Encoding.lean` - the Python-side capability encoding is a sound abstraction of the Lean model.
- `Composition.lean` - composing two policies yields a policy at least as restrictive as either input.

`Audit.lean` runs `#print axioms` against the four headline guarantees - `Certior.Delegation.delegationSafety`, `Certior.Encoding.ifcSoundness`, `Certior.Composition.compositionSoundness`, and `SecurityLevel.isValidBoundedLattice` - and fails the build if any of them depends on anything beyond Lean's three standard axioms (`propext`, `Classical.choice`, `Quot.sound`). The result is that "proven sound" cannot regress without CI catching it.

## What is not proven

Certior does not verify the LLM's behaviour, the correctness of the tool implementation, or the fidelity of the content scanner's heuristics on inputs outside its rule set. It verifies the boundary the LLM operates inside.

## See also

- [Capability model](/concepts/capability-model) - how permissions, delegation, and subset checking work.
- [Certificates](/concepts/certificates) - the shape of a signed receipt.
- [Compliance policies](/concepts/policies) - what HIPAA / SOX / `legal_privilege` actually enforce.
- [Lean binary](/reference/lean-binary) - installing or building the optional Lean live verifier.

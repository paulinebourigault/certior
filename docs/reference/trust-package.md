---
title: "Trust package"
description: "What Certior formally proves, what it does not claim to prove, and how runtime evidence binds to those proofs."
---

The **trust package** is the assurance model Certior offers to auditors, customers, and security reviewers. It is intentionally precise about what is proven and what is not.

The full document lives in the source repo at [`docs/certior-trust-package.md`](https://github.com/paulinebourigault/certior/blob/main/docs/certior-trust-package.md). This page is the summary an integrator needs.

## What Certior proves

When Certior issues an **allowed verdict** with a `VerifiedCertificate`, it proves the following held at the moment of the call:

- **Capability containment.** The required capabilities are a subset of the agent's permissions, encoded and discharged in Z3.
- **Subset delegation.** A child guard's permissions are a subset of the parent's. The general statement is proved in `lean4/CertiorLattice/Certior/Delegation.lean`; the per-call instance is discharged by Z3 against the active token.
- **Budget sufficiency.** `cost_cents ≤ budget_remaining`. Same encoding.
- **Information-flow soundness (model-level).** The labelled-domain lattice the policy is built on is proven sound offline in `Lattice.lean` and `Composition.lean`, and the certificate is bound to that proven model by fingerprint. Per call, Z3 discharges capability and budget; the flow-soundness guarantee comes from the proven model, not a separate per-call check.
- **Lineage.** The certificate carries the plan hash and the policy fingerprint. An auditor can reproduce the verdict against the exact source at the exact commit.

The four headline theorems audited in CI are `Certior.Delegation.delegationSafety`, `Certior.Encoding.ifcSoundness`, `Certior.Composition.compositionSoundness`, and `SecurityLevel.isValidBoundedLattice`. `lean4/CertiorLattice/Certior/Audit.lean` runs `#print axioms` against each and fails the build if any of them depends on anything beyond Lean's three standard axioms (`propext`, `Classical.choice`, `Quot.sound`). If any of them stops being independent of bespoke axioms, the build fails and the trust package is no longer issuable.

## What Certior does not prove

- The LLM's natural-language output is "correct" or "helpful". The model is a black box to the gate.
- The tool implementation behaves as documented. The gate verifies what the tool **declares** it needs, not what it actually does at runtime.
- The content scanner detects paraphrases. The content gate is keyword + regex against an auditable rule set; it catches the documented patterns exactly.
- Identity. JWT or API-key handling is conventional; revocation, rotation, and role boundaries are the operator's responsibility per the `Authentication` API.

## What an auditor reproduces

Given a certificate, an auditor:

1. Clones the source at the commit referenced by the certificate's plan hash.
2. Runs `lake build Certior.Audit` in `lean4/CertiorLattice/`. The audit's success is the proof that the four guarantees still depend only on standard axioms at that commit.
3. Re-runs the Z3 verifier against the same plan and confirms the same verdict.
4. (Optional) Builds `certior-flow-check` and replays the plan, producing a Lean live cert that matches the Z3 verdict.

The certificate's `policy_fingerprint` field carries a short SHA-256 of the Lean source under `lean4/CertiorLattice/Certior/`. Recompute it at audit time with `certior.guard._lean_policy_fingerprint()` and confirm it matches; that binds "this verdict" to "this source".

## Operator obligations

- **Identity immutability.** API keys must map to single identities; rotate on team changes.
- **Secret handling.** Inject `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, and `DATABASE_URL` via the deployment environment, not committed files. See [Configuration](/reference/configuration).
- **Audit retention.** The active policy's `AuditConfig` declares retention; the operator must back the persistence layer accordingly.

## See also

- [How it works](/concepts/how-it-works) - the gates the trust package depends on.
- [Certificates](/concepts/certificates) - the unit the auditor reviews.
- [Compliance](/api/compliance) - the export endpoint for the audit package.

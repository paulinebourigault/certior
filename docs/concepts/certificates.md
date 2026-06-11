---
title: "Certificates"
description: "Every allowed call produces a VerifiedCertificate carrying the verified properties, the proof trace, the plan hash, and a signature."
---

When `Guard.verify(...)` returns `allowed=True`, it attaches a `VerifiedCertificate` to the result. The certificate is the audit-trail unit: it records what was verified, when, and by which prover.

## Shape

The `VerifiedCertificate` dataclass lives in `agentsafe/kernel/certificate.py`. Its fields:

| Field | Type | Meaning |
|---|---|---|
| `id` | `str` (uuid) | Unique certificate id. |
| `theorem` | `str` | Identifier of the theorem-like obligation Z3 discharged for this call. |
| `plan_hash` | `str` | SHA-256 of the plan / call structure being verified. |
| `verified_properties` | `list[str]` | The properties Z3 confirmed (e.g. `capability_coverage`, `budget_sufficient`). |
| `proof_trace` | `str` | Free-form trace of the Z3 solve, used for audit reproducibility. |
| `prover` | `str` | The prover that issued the certificate. Default `"z3"`. |
| `issued_at` | `float` | Unix epoch seconds at issue time. |
| `expires_at` | `float \| None` | Optional expiry, set when the call carries a TTL. |
| `_signature` | `str` | HMAC-style signature bound to the kernel-issued signing key. |

## How to inspect one

```python
result = guard.verify(
    tool="web_fetch",
    required_capabilities=["network:http:read"],
    cost_cents=10,
)

if result.allowed and result.certificate is not None:
    cert = result.certificate
    print(cert.id)                   # e.g. "8c5e...-d4a1"
    print(cert.theorem)              # the obligation that was discharged
    print(cert.verified_properties)  # ["capability_coverage", "budget_sufficient", ...]
    print(cert.prover)               # "z3"
```

## The Lean policy fingerprint

Every certificate is implicitly bound to the policy model the runtime enforces. The fingerprint is the short SHA-256 of the Lean source under `lean4/CertiorLattice/Certior/`, computed by `certior.guard._lean_policy_fingerprint()` at runtime and woven into the certificate in three places:

- as part of the JSON that produces `plan_hash` (so tampering with the recorded action invalidates the receipt),
- in `verified_properties` as a string of the form `"policy_model:lean-audited@<fingerprint>"`,
- in `proof_trace` as `"Z3 SAT in <ms>ms, policy: Lean-audited @ <fingerprint>"`.

Query the fingerprint from your installed package:

```python
from certior.guard import _lean_policy_fingerprint
print(_lean_policy_fingerprint())   # e.g. "cc3e0c7431fd8a53"
```

The value changes whenever the Lean source changes. An auditor reproduces the audit by:

1. Cloning the repository at the commit referenced in the certificate's `plan_hash`.
2. Running `lake build Certior.Audit` in `lean4/CertiorLattice/`.
3. Recomputing the fingerprint from the cloned Lean source and confirming it matches the value embedded in `verified_properties` and `proof_trace`.
4. Confirming the four headline theorems still depend only on Lean's three standard axioms.

If any of these fails, the certificate's claim to "verified by the same policy model" is invalid.

## Where certificates live

- The full `VerifiedCertificate` (with signature) lives on the returned `VerifyResult.certificate`.
- `Guard.audit_log` keeps a lightweight metadata trail per call: `{tool, allowed, violations: int, pii_count: int, latency_ms, time}`. It does **not** carry the certificate or the violations list - those are on the return value.
- Optional persistent store: when running with the FastAPI server, certificates are persisted per execution and can be exported via [`GET /api/v1/compliance/{execution_id}/export`](/api/compliance).

## See also

- [Capability model](/concepts/capability-model) - what gets checked before a certificate is issued.
- [Compliance API](/api/compliance) - exporting certificates for an audit package.
- [Trust package](/reference/trust-package) - the assurance model an auditor reviews.

#!/usr/bin/env python3
"""
Quickstart - wrap your agent's tool calls with Certior in 5 lines
=================================================================

This is the user-facing entry point. Run it as-is or paste the five-line
recipe at the top into your own agent code. Every tool call passes through
a real Z3 capability check before execution; allowed actions get a signed
proof certificate you can audit later.

    python examples/wrapper_quickstart.py

Prerequisites:
    pip install -e .   (Certior installed - includes z3-solver)
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def heading(t): print(f"\n{'─' * 64}\n  {t}\n{'─' * 64}")


# ─────────────────────────────────────────────────────────────────────
# THE 5-LINE RECIPE - wrap any tool function with Certior
# ─────────────────────────────────────────────────────────────────────
from certior import Guard, CertiorBlocked

guard = Guard(
    permissions=["network:http:read", "filesystem:read"],   # what's allowed
    budget_cents=5000,                                       # spending cap
)

@guard.wrap(required_capabilities=["network:http:read"], cost_cents=100)
def web_fetch(url: str) -> str:
    """Pretend this hits the network. Real implementation goes here."""
    return f"<fetched {url}>"


heading("1.  Allowed call - proceeds, returns a signed receipt")
result = web_fetch("https://example.com")
print(f"  agent returned:  {result!r}")
# inspect the proof of admissibility for the most recent decision
last = guard.audit_log[-1]
print(f"  audit entry:     tool={last['tool']}  allowed={last['allowed']}  latency={last['latency_ms']:.2f}ms")


heading("2.  Verify directly - get the VerifyResult + the signed certificate")
v = guard.verify(
    tool="web_fetch",
    required_capabilities=["network:http:read"],
    cost_cents=50,
)
print(f"  allowed:         {v.allowed}")
print(f"  reason:          {v.reason or '(ok)'}")
cert = v.certificate
print(f"  certificate id:  {cert.id[:24]}…")
print(f"  theorem:         {cert.theorem}")
print(f"  proof trace:     {cert.proof_trace}")
print(f"  prover:          {cert.prover}")
print(f"  signature valid: {guard._ca.validate_certificate(cert)}  ← re-checked by the kernel")


heading("3.  Blocked call - over-budget action denied with a precise reason")
# Pretend a single call costs more than the whole budget left.
try:
    @guard.wrap(required_capabilities=["network:http:read"], cost_cents=99999)
    def expensive_search(q: str) -> str:
        return f"<{q}>"
    expensive_search("the meaning of life")
except CertiorBlocked as e:
    print(f"  CertiorBlocked raised: {e.result.reason}")
    print(f"  certificate issued?    {e.result.certificate}   ← None: we never sign what we don't prove")


heading("4.  Blocked call - capability the agent doesn't hold")
v = guard.verify(
    tool="db_drop_table",
    required_capabilities=["database:admin"],
    cost_cents=0,
)
print(f"  allowed: {v.allowed}")
print(f"  reason:  {v.reason}")
print(f"  violation categories: {[x.category for x in v.violations]}")


heading("5.  Tamper detection on the signed receipt")
# Take the certificate from §2 and try to alter what it claims to have proven.
original = cert.theorem
cert.theorem = "action_admissible:admin_override"
print(f"  after tampering with theorem → signature valid: {guard._ca.validate_certificate(cert)}  ← rejected")
cert.theorem = original
print(f"  restored                      → signature valid: {guard._ca.validate_certificate(cert)}")


heading("6.  Policy provenance - what's actually proven, in Lean")
att = guard.policy_attestation
print(f"  kernel:             {att['kernel']}")
print(f"  fingerprint:        {att['fingerprint']}   ← embedded in every cert above")
print(f"  audited guarantees: {len(att['audited_guarantees'])} (delegationSafety, ifcSoundness, …)")
print(f"  trusted axioms:     {att['trusted_axioms']}")
print(f"  re-audit yourself:  {att['audit_command']}")


heading("Done.")
print("  • Every allowed action got a Z3 proof certificate.")
print("  • Each certificate is tied to a Lean-audited policy fingerprint.")
print("  • Blocked actions raised CertiorBlocked with a precise reason.")
print("  • Tampering with a certificate is detected by the kernel.")
print(f"  • Audit log has {len(guard.audit_log)} entries; remaining budget: {guard.budget_remaining}¢.")
print()

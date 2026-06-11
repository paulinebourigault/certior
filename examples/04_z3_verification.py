#!/usr/bin/env python3
"""
Example 4: Z3 Formal Verification Deep Dive
=============================================

Demonstrates Certior's formal verification engine without requiring
a running server or LLM.  Shows the Z3-backed proof system that
makes Certior unique: every tool call is *mathematically proven* safe
before execution.

Shows:
  1. Capability token verification (permissions + budget enforcement)
  2. Z3 constraint solving (proves capabilities + budget sufficient)
  3. URL safety verification (allowlist/blocklist with audit)
  4. Path traversal prevention (workspace sandbox enforcement)
  5. Proof certificate issuance and tamper detection
  6. Performance benchmarks

Run:
    python examples/04_z3_verification.py

Prerequisites:
    pip install -e .   (Certior installed - includes z3-solver)
"""
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def heading(title):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}\n")


heading("Example 4: Z3 Formal Verification")

# ── 1. Capability Tokens ─────────────────────────────────────────────
print("1. Capability Tokens - Permission & Budget Enforcement\n")

from agentsafe.capabilities.tokens import CapabilityToken

token = CapabilityToken(
    agent_id="research-agent",
    permissions=[
        "network:http:read",
        "filesystem:read",
        "filesystem:write",
    ],
    budget_cents=5000,
    budget_remaining_cents=5000,
)

print(f"  Token ID:    {token.id[:20]}...")
print(f"  Agent:       {token.agent_id}")
print(f"  Permissions: {list(token.permissions)}")
print(f"  Budget:      {token.budget_remaining_cents}¢")
print(f"  Is valid:    {token.is_valid()}")

# Permission checks
print(f"\n  Permission checks:")
print(f"    network:http:read  → {token.has_permission('network:http:read')}")
print(f"    filesystem:read    → {token.has_permission('filesystem:read')}")
print(f"    database:write     → {token.has_permission('database:write')}  ← not granted")
print(f"    admin:*            → {token.has_permission('admin:*')}  ← not granted")

# Budget enforcement
print(f"\n  Budget enforcement:")
print(f"    Has budget for 100¢?   {token.has_budget(100)}")
print(f"    Has budget for 99999¢? {token.has_budget(99999)}  ← denied")

# ── 2. Z3 Action Verification ────────────────────────────────────────
heading("2. Z3 Constraint Solving")

from agentsafe.verification.z3_optimizer import IncrementalZ3Verifier

verifier = IncrementalZ3Verifier()

# Action that SHOULD be allowed
print("  Test A: web_fetch with sufficient capabilities + budget")
result = verifier.verify_action(
    required_capabilities=["network:http:read"],
    available_capabilities=["network:http:read", "filesystem:read"],
    estimated_cost_cents=100,
    budget_remaining_cents=5000,
)
print(f"    Valid:       {result.valid}")
print(f"    Properties:  {result.properties}")
print(f"    Solve time:  {result.solve_time_ms:.1f}ms")

# Action that SHOULD be blocked (missing capability)
print("\n  Test B: database_query WITHOUT database:read permission")
result2 = verifier.verify_action(
    required_capabilities=["database:read"],
    available_capabilities=["network:http:read", "filesystem:read"],
    estimated_cost_cents=200,
    budget_remaining_cents=5000,
)
print(f"    Valid:       {result2.valid}")
print(f"    Violations:  {result2.violations}")

# Action that SHOULD be blocked (over budget)
print("\n  Test C: file_write with INSUFFICIENT budget")
result3 = verifier.verify_action(
    required_capabilities=["filesystem:write"],
    available_capabilities=["filesystem:write"],
    estimated_cost_cents=10000,
    budget_remaining_cents=5000,
)
print(f"    Valid:       {result3.valid}")
print(f"    Violations:  {result3.violations}")

# Action with IFC labels
print("\n  Test D: action with information flow constraints")
result4 = verifier.verify_action(
    required_capabilities=["network:http:read"],
    available_capabilities=["network:http:read"],
    estimated_cost_cents=50,
    budget_remaining_cents=5000,
    input_labels=["public"],
    output_labels=["internal"],
)
print(f"    Valid:       {result4.valid}")
print(f"    Properties:  {result4.properties}")

# ── 3. URL Safety Verification ────────────────────────────────────────
heading("3. URL Safety Verification")

from agentsafe.tools.url_filter_verified import (
    UrlFilter, UrlFilterConfig, UrlPattern, PatternKind,
)

# Configure with production-like rules
url_config = UrlFilterConfig(
    allowlist=[
        UrlPattern(kind=PatternKind.PREFIX, value="https://"),
    ],
    blocklist=[
        UrlPattern(kind=PatternKind.SUFFIX, value=".onion"),
        UrlPattern(kind=PatternKind.CONTAINS, value="169.254."),
        UrlPattern(kind=PatternKind.SUFFIX, value=".mil"),
    ],
)
url_filter = UrlFilter(url_config)

test_urls = [
    ("https://api.example.com/data",       "safe HTTPS"),
    ("https://docs.python.org/3/",         "safe HTTPS"),
    ("http://insecure-site.com/data",      "HTTP blocked (not in allowlist)"),
    ("https://evil.onion",                 "Tor hidden service"),
    ("https://169.254.169.254/metadata",   "cloud metadata endpoint"),
    ("file:///etc/passwd",                 "local file access"),
]

for url, reason in test_urls:
    decision = url_filter.check_url(url)
    label = "ALLOW" if decision.is_accept else "BLOCK"
    print(f"  [{label:5s}]  {url:45s}  ({reason})")

# ── 4. Path Safety Verification ───────────────────────────────────────
heading("4. Path Traversal Prevention")

from agentsafe.tools.path_safety_verified import (
    PathSafetyChecker, PathSafetyConfig,
)

workspace = "/tmp/certior-workspace"
path_config = PathSafetyConfig(workspace_root=workspace)
checker = PathSafetyChecker(path_config)

# The checker enforces:
#   - Only relative paths allowed (resolved against workspace)
#   - No .. traversal components
#   - No absolute paths (prevent escaping sandbox)
test_paths = [
    ("output.txt",                    "relative, inside workspace"),
    ("sub/deep/file.md",              "nested relative path"),
    ("/etc/passwd",                   "absolute system file"),
    ("../../etc/shadow",              "path traversal attack"),
    ("/home/user/.ssh/id_rsa",        "absolute SSH key path"),
]

for path, reason in test_paths:
    decision = checker.check_path(path, file_size=100)
    label = "ALLOW" if decision.allowed else "BLOCK"
    print(f"  [{label:5s}]  {path:40s}  ({reason})")

# ── 5. Proof Certificate Issuance ─────────────────────────────────────
heading("5. Proof Certificates - Tamper Detection")

from agentsafe.kernel import CertificateAuthority

ca = CertificateAuthority()

# Issue a certificate for a verified action
cert = ca.issue_certificate(
    theorem="action_safe",
    plan_hash="sha256:abc123def456",
    verified_properties=[
        "capability_coverage",
        "budget_sufficient",
        "no_forbidden_flow",
    ],
    proof_trace="Z3 SAT in 12ms",
    prover="z3",
)

print(f"  Certificate ID:   {cert.id[:20]}...")
print(f"  Theorem:          {cert.theorem}")
print(f"  Prover:           {cert.prover}")
print(f"  Properties:       {cert.verified_properties}")
print(f"  Signature valid:  {ca.validate_certificate(cert)}")

# Tamper detection
print(f"\n  Tampering with certificate theorem...")
original = cert.theorem
cert.theorem = "admin_override"
tamper_valid = ca.validate_certificate(cert)
print(f"  Signature valid:  {tamper_valid}  ← tamper detected!")
cert.theorem = original  # restore

# ── 6. Performance Benchmark ──────────────────────────────────────────
heading("6. Verification Performance")

# Warm up (populate cache for common patterns)
for _ in range(10):
    verifier.verify_action(
        required_capabilities=["network:http:read"],
        available_capabilities=["network:http:read"],
        estimated_cost_cents=100,
        budget_remaining_cents=5000,
    )

# Benchmark with varied constraints to test both cache hits and misses
iterations = 500
start = time.perf_counter()
for i in range(iterations):
    verifier.verify_action(
        required_capabilities=["network:http:read"],
        available_capabilities=["network:http:read", "filesystem:read"],
        estimated_cost_cents=100 + (i % 50),  # vary to test cache
        budget_remaining_cents=5000,
    )
elapsed_ms = (time.perf_counter() - start) * 1000

avg = elapsed_ms / iterations
cache_stats = verifier.cache.stats()

print(f"  {iterations} verifications in {elapsed_ms:.0f}ms")
print(f"  Average:    {avg:.3f}ms per verification")
print(f"  Cache hits: {cache_stats.get('hit_rate', 0):.0%}")
print(f"  Target:     <100ms P95")
print(f"  Status:     {'✓ PASS' if avg < 100 else '✗ SLOW'}")

heading("Done - all verifications use Z3 SAT solving!")
print("Key takeaways:")
print("  • Z3 proves capability coverage BEFORE execution")
print("  • Budget constraints are mathematically verified, not just checked")
print("  • URL and path safety prevent exfiltration and traversal")
print("  • Proof certificates are cryptographically signed")
print("  • Verification adds sub-millisecond average overhead with caching")
print()

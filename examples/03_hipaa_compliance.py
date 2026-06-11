#!/usr/bin/env python3
"""
Example 3: HIPAA Compliance & PII Protection
==============================================

Demonstrates Certior's compliance features without requiring the
server to be running.  Uses the verification library directly.

Shows:
  1. HIPAA content safety scanning
  2. Automatic PII detection and redaction
  3. Scanner semantics (clean vs safe_to_proceed)
  4. Compliance audit export
  5. Z3 capability verification

Run:
    python examples/03_hipaa_compliance.py

Prerequisites:
    pip install -e .   (Certior installed)
"""
import sys
import os
import json

# Ensure the package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentsafe.safety.scanner import (
    ContentScanner,
    ContentSafetyPolicy,
)
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.compliance import CompliancePresets, ComplianceExporter, AuditEntry

def heading(title):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}\n")

heading("Example 3: HIPAA Compliance & PII Protection")

# ── 1. HIPAA Content Scanning ─────────────────────────────────────────
print("1. Scanning content with HIPAA policy\n")

policy = ContentSafetyPolicy.hipaa_compliant()
scanner = ContentScanner(policy)

# Content containing PHI (Protected Health Information)
content = (
    "Patient: John Smith, DOB 03/15/1982\n"
    "SSN: 123-45-6789\n"
    "MRN: AB1234567\n"
    "Diagnosis: Type 2 Diabetes\n"
    "Email: jsmith@hospital.org\n"
    "Phone: 555-123-4567\n"
    "Next appointment scheduled for cardiac follow-up."
)

print(f"  Input text:\n")
for line in content.split("\n"):
    print(f"    {line}")

result = scanner.scan(content)

print(f"\n  Scan results:")
print(f"    clean:            {result.clean}       ← False: findings present")
print(f"    pii_found:        {result.pii_found}       ← True: PII detected")
print(f"    remediated:       {result.remediated}       ← True: redacted text available")
print(f"    safe_to_proceed:  {result.safe_to_proceed}       ← depends on keyword violations too")
print(f"    violations:       {len(result.violations)}")
for v in result.violations:
    print(f"      ⛔ [{v.severity}] matched: \"{v.matched_text}\"")

print(f"\n  PII detected ({len(result.pii_detected)} items):")
for pii in result.pii_detected:
    print(f"    [{pii.pii_type:10s}]  {pii.value}")

print(f"\n  Redacted output:\n")
for line in result.redacted_text.split("\n"):
    print(f"    {line}")

# ── 2. MNPI Detection (SOX) ──────────────────────────────────────────
heading("2. SOX - Material Non-Public Information Detection")

sox_policy = ContentSafetyPolicy.sox_compliant()
sox_scanner = ContentScanner(sox_policy)

mnpi_content = "Our unreleased earnings for Q4 are projected at $2.3B, above analyst consensus."

result_sox = sox_scanner.scan(mnpi_content)

print(f"  Input:  \"{mnpi_content}\"")
print(f"\n  clean:            {result_sox.clean}")
print(f"  safe_to_proceed:  {result_sox.safe_to_proceed}")
print(f"  violations:       {len(result_sox.violations)}")
for v in result_sox.violations:
    print(f"    ⛔ [{v.severity}] matched: \"{v.matched_text}\"")

# ── 3. Legal Privilege ────────────────────────────────────────────────
heading("3. Legal Privilege - Attorney-Client Protection")

legal_policy = ContentSafetyPolicy.legal_privilege()
legal_scanner = ContentScanner(legal_policy)

privileged = "Per our legal advice on the case strategy, the settlement terms should not exceed $5M."
result_legal = legal_scanner.scan(privileged)

print(f"  Input:  \"{privileged}\"")
print(f"\n  clean:            {result_legal.clean}")
print(f"  safe_to_proceed:  {result_legal.safe_to_proceed}")
print(f"  violations:       {len(result_legal.violations)}")
for v in result_legal.violations:
    print(f"    ⛔ [{v.severity}] matched: \"{v.matched_text}\"")

# ── 4. Clean Content ─────────────────────────────────────────────────
heading("4. Clean Content - No Violations")

clean_content = "Please schedule a follow-up appointment for next Tuesday."
result_clean = scanner.scan(clean_content)

print(f"  Input:  \"{clean_content}\"")
print(f"\n  clean:            {result_clean.clean}       ← True: no findings")
print(f"  pii_found:        {result_clean.pii_found}")
print(f"  safe_to_proceed:  {result_clean.safe_to_proceed}")

# ── 5. Capability Verification ────────────────────────────────────────
heading("5. Capability Token - Budget & Permission Enforcement")

token = CapabilityToken(
    agent_id="hipaa-agent",
    permissions=["database:read:patient_data", "document:write:reports"],
    budget_cents=10000,
    budget_remaining_cents=10000,
)

print(f"  Token ID:       {token.id[:16]}...")
print(f"  Agent:          {token.agent_id}")
print(f"  Permissions:    {list(token.permissions)}")
print(f"  Budget:         {token.budget_remaining_cents} cents")
print(f"  Valid:          {token.is_valid()}")

# Permission checks
print(f"  Has db:read?    {token.has_permission('database:read:patient_data')}")
print(f"  Has admin:*?    {token.has_permission('admin:delete')}     ← not granted")

# Demonstrate budget reservation
reservation = token.reserve_budget(2500)
print(f"\n  After reserving 2500 cents:")
print(f"    Remaining:    {token.budget_remaining_cents} cents")
print(f"    Reserved:     ✓")

# Try to over-spend
print(f"\n  Attempting to reserve 999999 cents:")
try:
    token.reserve_budget(999999)
    print(f"    Reserved:     ✓")
except Exception as e:
    print(f"    Blocked:      {type(e).__name__}  ← budget enforcement works")

# ── 6. Compliance Audit Export ────────────────────────────────────────
heading("6. Compliance Audit Export")

hipaa_config = CompliancePresets.get("hipaa")
exporter = ComplianceExporter(hipaa_config)

# Simulate an execution
from agentsafe.cloud.state_store import Execution, ExecutionStatus
execution = Execution(
    user_id="hipaa-user",
    task="Retrieve patient summary",
    status=ExecutionStatus.COMPLETED,
    results={"output": "Patient summary retrieved", "cost_cents": 150},
    certificates=["cert-z3-001", "cert-z3-002"],
    cost_cents=150,
)

trail = [
    AuditEntry(action="verify_capability", details={"permissions": token.permissions}),
    AuditEntry(action="scan_content", details={"pii_found": True, "remediated": True}),
    AuditEntry(action="execute_tool", details={"tool": "database_query", "verified": True}),
]

package = exporter.export(execution=execution, audit_trail=trail)

print(f"  Package ID:       {package.package_id[:20]}...")
print(f"  Regime:           {package.compliance_regime}")
print(f"  Audit entries:    {len(package.audit_trail)}")
print(f"  Certificates:     {len(package.certificates)}")
print(f"  Attestation:      {str(package.attestation)[:60]}...")

print(f"\n  Full export (JSON):\n")
export_json = package.to_json()
# Print first 20 lines
for i, line in enumerate(export_json.split("\n")):
    if i < 20:
        print(f"    {line}")
    elif i == 20:
        print(f"    ... ({len(export_json.split(chr(10)))} total lines)")
        break

heading("Done - HIPAA/SOX/Legal compliance demonstrated!")
print("Key takeaways:")
print("  • PII is detected and redacted automatically")
print("  • Scanner distinguishes clean (audit) from safe_to_proceed (flow control)")
print("  • MNPI and privileged content is blocked, not redacted")
print("  • Capability tokens enforce budgets and permissions")
print("  • Compliance packages include full audit trails")
print()

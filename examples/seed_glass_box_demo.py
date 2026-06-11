#!/usr/bin/env python3
"""
Seed the live delegation graph with the multi-agent privacy/release topology.

After this runs, the Studio Agent Glass Box canvas at /ui/agentic shows the
full 12-edge verified DAG plus the blocked privilege-escalation edge that
was the headline beat in the May 1 deck.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from examples._helpers import get_api_key, get_base_url  # noqa: E402

import httpx  # noqa: E402

BASE = get_base_url()
KEY = get_api_key(BASE)
HEADERS = {"Authorization": f"Bearer {KEY}"}

# (parent_agent, parent_perms, parent_budget, child_agent, child_perms, child_budget)
VERIFIED = [
    ("Certior Orchestrator", ["classify_workflow", "detect_phi", "review_phi", "redact_phi",
                              "check_policy_bounds", "approve_public_release",
                              "publish_public_artifact", "write_audit_graph"], 10000,
     "Intake Classifier Agent", ["classify_workflow", "detect_phi"], 900),
    ("Certior Orchestrator", ["classify_workflow", "detect_phi", "review_phi", "redact_phi",
                              "check_policy_bounds", "approve_public_release",
                              "publish_public_artifact", "write_audit_graph"], 10000,
     "PHI Detector Agent", ["detect_phi"], 800),
    ("Certior Orchestrator", ["classify_workflow", "detect_phi", "review_phi", "redact_phi",
                              "check_policy_bounds", "approve_public_release",
                              "publish_public_artifact", "write_audit_graph"], 10000,
     "Budget Guardian Agent", ["write_audit_graph"], 500),
    ("Certior Orchestrator", ["classify_workflow", "detect_phi", "review_phi", "redact_phi",
                              "check_policy_bounds", "approve_public_release",
                              "publish_public_artifact", "write_audit_graph"], 10000,
     "Privacy Review Agent", ["review_phi", "redact_phi", "check_policy_bounds",
                              "approve_public_release", "write_audit_graph"], 2500),
    ("Privacy Review Agent", ["review_phi", "redact_phi", "check_policy_bounds",
                              "approve_public_release", "write_audit_graph"], 2500,
     "Redaction Agent", ["redact_phi"], 650),
    ("Privacy Review Agent", ["review_phi", "redact_phi", "check_policy_bounds",
                              "approve_public_release", "write_audit_graph"], 2500,
     "Policy Bound Checker", ["check_policy_bounds"], 600),
    ("Privacy Review Agent", ["review_phi", "redact_phi", "check_policy_bounds",
                              "approve_public_release", "write_audit_graph"], 2500,
     "Audit Evidence Collector", ["write_audit_graph"], 500),
    ("Certior Orchestrator", ["classify_workflow", "detect_phi", "review_phi", "redact_phi",
                              "check_policy_bounds", "approve_public_release",
                              "publish_public_artifact", "write_audit_graph"], 10000,
     "Release Gate Agent", ["approve_public_release", "publish_public_artifact",
                            "write_audit_graph"], 1800),
    ("Release Gate Agent", ["approve_public_release", "publish_public_artifact",
                            "write_audit_graph"], 1800,
     "Public Release Agent", ["publish_public_artifact"], 900),
    ("Release Gate Agent", ["approve_public_release", "publish_public_artifact",
                            "write_audit_graph"], 1800,
     "Release Audit Logger", ["write_audit_graph"], 400),
]

# The headline blocked escalation: PHI Detector tries to hand publish + raw export to an untrusted agent.
BLOCKED = (
    "PHI Detector Agent", ["detect_phi"], 800,
    "Untrusted Publisher Agent", ["publish_public_artifact", "export_raw_phi"], 1500,
)


def post(parent_agent, parent_perms, parent_budget, child_agent, child_perms, child_budget, tag):
    body = {
        "parent_id": f"tok_{parent_agent.replace(' ', '_').lower()}",
        "parent_agent_id": parent_agent,
        "parent_permissions": parent_perms,
        "parent_budget": parent_budget,
        "child_id": f"tok_{child_agent.replace(' ', '_').lower()}",
        "child_agent_id": child_agent,
        "child_permissions": child_perms,
        "child_budget": child_budget,
    }
    r = httpx.post(f"{BASE}/api/v1/agents/delegate", json=body, headers=HEADERS, timeout=15)
    r.raise_for_status()
    j = r.json()
    mark = "✓" if j["allowed"] else "✗"
    print(f"  {mark}  {parent_agent}  →  {child_agent}   [{tag}]  {j['reason']}")


if __name__ == "__main__":
    print(f"Seeding delegation graph at {BASE}")
    print()
    print("Verified delegations:")
    for row in VERIFIED:
        post(*row, tag="verified")
    print()
    print("Blocked privilege-escalation:")
    post(*BLOCKED, tag="BLOCKED")
    print()
    print(f"Open Studio at /ui/agentic and reload to see the live graph.")

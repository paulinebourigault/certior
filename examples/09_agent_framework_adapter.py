#!/usr/bin/env python3
"""
Example 9: Agent Framework Adapter
==================================

Shows the small integration surface for agent frameworks such as LangGraph,
LangChain, CrewAI, AutoGen, OpenAI Agents, or an internal orchestrator.

The pattern is intentionally boring: before one agent hands work to another,
call Certior's delegation endpoint with the parent capability, requested child
capability, and budget. Certior returns allowed=false for unsafe escalations and
the Studio Agent Glass Box records the handoff.

Run:
    CERTIOR_ENV=production ./run.sh   # separate terminal
    python examples/09_agent_framework_adapter.py
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class AgentCapability:
    token_id: str
    agent_id: str
    permissions: list[str]
    budget: int


class CertiorAgentGuard:
    """Tiny adapter that can be called from any agent framework handoff hook."""

    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {api_key}"}

    def check_handoff(self, parent: AgentCapability, child: AgentCapability) -> dict:
        payload = {
            "parent_id": parent.token_id,
            "parent_agent_id": parent.agent_id,
            "parent_permissions": parent.permissions,
            "parent_budget": parent.budget,
            "child_id": child.token_id,
            "child_agent_id": child.agent_id,
            "child_permissions": child.permissions,
            "child_budget": child.budget,
        }
        with httpx.Client(base_url=self.base_url, headers=self.headers, timeout=15.0) as client:
            response = client.post("/api/v1/agents/delegate", json=payload)
            response.raise_for_status()
            return response.json()


def guarded_agent_handoff(guard: CertiorAgentGuard, parent: AgentCapability, child: AgentCapability) -> None:
    """Use this shape inside a LangGraph node, CrewAI task, or AutoGen handoff."""
    decision = guard.check_handoff(parent, child)
    if not decision.get("allowed"):
        print(f"BLOCKED: {parent.agent_id} -> {child.agent_id}")
        print(f"  reason: {decision.get('reason')}")
        return
    print(f"ALLOWED: {parent.agent_id} -> {child.agent_id}")
    print(f"  proof: {decision.get('proof_signature')}")


def main() -> None:
    base_url = os.getenv("CERTIOR_API_URL", "http://localhost:8000")
    api_key = os.getenv("CERTIOR_PROOF_API_KEY", "dev-orchestrator-key-12345")
    guard = CertiorAgentGuard(base_url, api_key)

    privacy_reviewer = AgentCapability(
        token_id="tok_privacy_reviewer",
        agent_id="Privacy Review Agent",
        permissions=["review_phi", "redact_phi", "check_policy_bounds"],
        budget=3000,
    )
    redactor = AgentCapability(
        token_id="tok_redactor",
        agent_id="Redaction Agent",
        permissions=["redact_phi"],
        budget=1200,
    )
    unsafe_publisher = AgentCapability(
        token_id="tok_untrusted_publisher",
        agent_id="Untrusted Publisher Agent",
        permissions=["publish_public_artifact", "export_raw_phi"],
        budget=1500,
    )

    guarded_agent_handoff(guard, privacy_reviewer, redactor)
    guarded_agent_handoff(guard, redactor, unsafe_publisher)


if __name__ == "__main__":
    main()
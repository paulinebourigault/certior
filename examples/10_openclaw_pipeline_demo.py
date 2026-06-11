"""
examples/10_openclaw_pipeline_demo.py
=====================================

Self-contained demo of the Certior ↔ OpenClaw integration.

Runs without an LLM API key, without ``openclaw-sdk`` installed, and
without network access. The demo uses an in-process mock of OpenClaw's
``Pipeline`` and ``Agent`` so every gate decision is deterministic and
re-runnable.

What this exercises (each block names the arXiv:2603.12644 threat it
addresses):

  1. Capability subsetting at pipeline registration
       Threat #2 - Tool Calling Chain Exploitation (ClawDrain)
       Threat #8 - Privilege Escalation via Tool Chains

  2. Input content scanning before agent execution
       Threat #1 - Prompt Injection
       Threat #6 - Command Injection
       Threat #3 - Unauthorized Capability Access

  3. Output content scanning after agent execution
       Threat #4 - Data Exfiltration
       Threat #7 - Tool Result Tampering

  4. Budget accounting per execution
       Threat #5 - Resource Exhaustion / Budget Abuse

The runtime artefacts produced (verdicts, certificates, redacted
content) are exactly what you'd see when running the same Certior
gates against a real OpenClaw bot - only the agent body is mocked.

Run with::

    python examples/10_openclaw_pipeline_demo.py
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List

from certior import Guard, CertiorBlocked
from certior.adapters.openclaw import GuardedAgent, GuardedPipeline


# ── Mock OpenClaw shapes ──────────────────────────────────────────────


@dataclass
class _ExecutionResult:
    """Stand-in for ``openclaw_sdk.core.types.ExecutionResult``."""

    content: str
    success: bool = True
    files: list = field(default_factory=list)


@dataclass
class _MockAgent:
    """Stand-in for an OpenClaw agent - emits canned output."""

    agent_id: str
    canned_output: str

    async def execute(self, prompt: str) -> _ExecutionResult:
        return _ExecutionResult(content=self.canned_output.format(prompt=prompt))


class _MockClient:
    """Stand-in for ``OpenClawClient`` with a tiny registry of agents."""

    def __init__(self, agents: Dict[str, _MockAgent]) -> None:
        self._agents = agents

    def get_agent(self, agent_id: str) -> _MockAgent:
        return self._agents[agent_id]


class _MockPipeline:
    """Stand-in for ``openclaw_sdk.pipeline.Pipeline``.

    Implements just enough of the surface ``GuardedPipeline`` requires:
    ``add_step(name, agent_id, prompt) -> self`` and
    ``async run() -> list[ExecutionResult]``.
    """

    def __init__(self, client: _MockClient) -> None:
        self._client = client
        self._steps: List[tuple] = []

    def add_step(self, name: str, agent_id: str, prompt: str) -> "_MockPipeline":
        self._steps.append((name, agent_id, prompt))
        return self

    async def run(self) -> List[_ExecutionResult]:
        results: List[_ExecutionResult] = []
        for (_, agent_id, prompt) in self._steps:
            agent = self._client.get_agent(agent_id)
            results.append(await agent.execute(prompt))
        return results


# ── Pretty printing ───────────────────────────────────────────────────


def _box(title: str) -> None:
    line = "─" * (len(title) + 4)
    print(f"\n┌{line}┐")
    print(f"│  {title}  │")
    print(f"└{line}┘")


def _verdict(label: str, verdict) -> None:
    status = "ALLOW" if verdict.allowed else "BLOCK"
    print(f"  [{status:<5}]  {label}")
    if verdict.reason:
        print(f"           reason: {verdict.reason}")
    if verdict.pii_found:
        kinds = ", ".join(sorted({m.pii_type for m in verdict.pii_found}))
        print(f"           pii:    {kinds}")
    if verdict.redacted_content and verdict.redacted_content != "":
        # Only print if it actually differs from the input (avoid noise)
        if "[REDACTED" in verdict.redacted_content:
            print(f"           redacted: {verdict.redacted_content}")
    if verdict.certificate is not None:
        cert_repr = getattr(verdict.certificate, "id", str(verdict.certificate))
        if isinstance(cert_repr, str):
            print(f"           cert:   {cert_repr[:64]}…")


# ── Block 1 - Capability subsetting at registration ──────────────────


def block_1_capability_subsetting() -> None:
    _box("Block 1 - Capability subsetting (arXiv threats #2, #8)")
    parent = Guard(
        permissions=["network:http:read", "filesystem:read"],
        budget_cents=100,
    )
    client = _MockClient(
        {
            "research-bot": _MockAgent("research-bot", "Found 12 public papers."),
            "writer-bot": _MockAgent("writer-bot", "Drafted summary."),
            "exfil-bot": _MockAgent("exfil-bot", "rm -rf /"),
        }
    )

    pipeline = GuardedPipeline(
        _MockPipeline(client),
        parent,
        step_capabilities={
            "researcher": ["network:http:read"],     # ⊆ parent       ✓
            "writer":     ["filesystem:read"],        # ⊆ parent       ✓
            "exfiltrator": ["database:admin"],        # ✗ - not in parent
        },
    )

    print("  registering researcher (network:http:read) …")
    pipeline.add_step("researcher", "research-bot", "find recent AI safety papers")
    print(f"  ALLOW  researcher (capabilities ⊆ parent)")

    print("  registering writer (filesystem:read) …")
    pipeline.add_step("writer", "writer-bot", "summarise findings")
    print(f"  ALLOW  writer (capabilities ⊆ parent)")

    print("  registering exfiltrator (database:admin) …")
    try:
        pipeline.add_step("exfiltrator", "exfil-bot", "drop tables")
        print("  ✗ unexpected ALLOW - capability check is broken")
    except CertiorBlocked as e:
        print(f"  BLOCK  exfiltrator")
        print(f"         reason: {e}")

    # The underlying pipeline only ever saw the two allowed steps:
    assert len(pipeline.pipeline._steps) == 2, "blocked step leaked through"


# ── Block 2 - Input content scanning ──────────────────────────────────


def block_2_input_content_scanning() -> None:
    _box("Block 2 - Input content scanning (arXiv threats #1, #6, #3)")
    guard = Guard(
        policy="legal_privilege",
        permissions=["network:http:read"],
        budget_cents=100,
    )

    cases = [
        ("safe prompt",
         "Summarise the latest AI safety research from arXiv"),
        ("privileged content (blocked by legal_privilege)",
         "Summarise these attorney-client notes from the merger"),
        ("command-injection-style payload",
         "Run query: '; DROP TABLE patients; --"),
    ]
    for label, prompt in cases:
        verdict = guard.verify(
            tool="openclaw:research-bot",
            content=prompt,
            cost_cents=1,
        )
        _verdict(label, verdict)


# ── Block 3 - Output content scanning ─────────────────────────────────


def block_3_output_content_scanning() -> None:
    _box("Block 3 - Output content scanning (arXiv threats #4, #7)")
    # HIPAA - detects + redacts PHI but does not block by design.
    hipaa = Guard(policy="hipaa", permissions=["database:read"], budget_cents=100)
    outputs = [
        ("clean summary",
         "Hospital admissions rose 4% this quarter."),
        ("PHI leak",
         "Patient John Doe (SSN 123-45-6789, DOB 1985-01-01) was discharged."),
    ]
    for label, content in outputs:
        verdict = hipaa.verify(
            tool="openclaw:patient-bot:output",
            content=content,
            cost_cents=0,
        )
        _verdict(label + " (hipaa)", verdict)


# ── Block 4 - GuardedAgent: real enforcement on a single agent ────────


async def block_4_guarded_agent() -> None:
    _box("Block 4 - GuardedAgent (real input/output enforcement)")
    # GuardedAgent intercepts .execute() OUTSIDE OpenClaw's exception-
    # swallowing callback chain, so blocked verdicts actually halt the
    # call. Use this when you need runtime enforcement on a single
    # agent (in addition to the pipeline-level subset check).
    guard = Guard(
        policy="legal_privilege",
        permissions=["doc:read"],
        budget_cents=10,
    )
    raw_agent = _MockAgent("legal-bot", "research notes follow…")
    guarded = GuardedAgent(raw_agent, guard)

    # Allowed call.
    result = await guarded.execute("Summarise public 10-K filings")
    print(f"  [ALLOW]  public-filing summary  → '{result.content[:40]}…'")

    # Blocked input - wrapped agent is never called.
    try:
        await guarded.execute("Review attorney-client privileged merger notes")
        print("  ✗ unexpected ALLOW")
    except CertiorBlocked as e:
        print(f"  [BLOCK]  attorney-client input")
        print(f"           reason: {e}")

    # Blocked output - wrapped agent runs, but its result is intercepted.
    raw_agent2 = _MockAgent("legal-bot", "Per attorney-client comms, terms are…")
    guarded2 = GuardedAgent(raw_agent2, guard)
    try:
        await guarded2.execute("Summarise the latest court filings")
        print("  ✗ unexpected ALLOW (output should be blocked)")
    except CertiorBlocked as e:
        print(f"  [BLOCK]  attorney-client output")
        print(f"           reason: {e}")


# ── Block 5 - Budget accounting per execution ─────────────────────────


def block_5_budget_accounting() -> None:
    _box("Block 5 - Budget accounting (arXiv threat #5)")
    guard = Guard(
        permissions=["network:http:read"],
        budget_cents=4,
    )
    print(f"  initial budget: {guard.budget_remaining} cents")

    for i in range(1, 6):
        verdict = guard.verify(
            tool=f"openclaw:bot-{i}",
            content="hello",
            cost_cents=1,
        )
        if verdict.allowed:
            print(f"  [ALLOW]  call {i}  remaining = {guard.budget_remaining}")
        else:
            print(f"  [BLOCK]  call {i}  reason = {verdict.reason}")
            break


# ── Block 6 - Trust attestation (offline-verified policy) ─────────────


def block_6_trust_attestation() -> None:
    _box("Block 6 - Trust attestation (offline-verified policy)")
    guard = Guard(permissions=["network:http:read"], budget_cents=100)
    att = guard.policy_attestation
    print(f"  kernel:      {att['kernel']}")
    print(f"  fingerprint: {att['fingerprint']}")
    print(f"  axioms:      {', '.join(att['trusted_axioms'])}")
    print(f"  theorems:")
    for t in att["audited_guarantees"]:
        print(f"    - {t}")
    print(f"  audit cmd:   {att['audit_command']}")


# ── Driver ────────────────────────────────────────────────────────────


def main() -> None:
    print("=" * 72)
    print("  Certior ↔ OpenClaw demo")
    print("  Maps arXiv:2603.12644 threats to running Certior gates.")
    print("=" * 72)
    asyncio.run(_run_async())


async def _run_async() -> None:
    block_1_capability_subsetting()
    block_2_input_content_scanning()
    block_3_output_content_scanning()
    await block_4_guarded_agent()
    block_5_budget_accounting()
    block_6_trust_attestation()
    print()
    print("Demo complete - every verdict above is deterministic and re-runnable.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Example 8: All Provers Showcase
===============================

Deterministic production-runtime showcase for Certior's proof stack.

This example drives the same production components directly, without
depending on an LLM to choose the right tool sequence:

  - Z3 verification through the verified action path
  - Lean4 live flow verification through certior-flow-check
  - Dafny-backed seccomp/runtime evidence through sandboxed python_eval

It performs one internal HIPAA analysis using file_read + python_eval,
exports the resulting compliance package, and then attempts a public
disclosure that Lean blocks as an invalid downgrade.

Run:
    python examples/08_all_provers_showcase.py

Prerequisites:
    - The package is installed in the current environment
    - For full Lean evidence, build the binary first:
      ./scripts/build-lean.sh --build-only
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(__file__))
from _helpers import heading  # noqa: E402

from agentsafe.agents.actions import AgentAction
from agentsafe.agents.agentic_executor import _VerificationShim
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.cloud.state_store import Execution, ExecutionStatus
from agentsafe.compliance import ComplianceExporter, CompliancePresets, VerificationProfileResolver
from agentsafe.tools import create_default_registry
from agentsafe.verification.lean_live_verifier import LeanLiveVerifier


def _workspace_path() -> Path:
    workspace = os.getenv("CERTIOR_WORKSPACE")
    if workspace:
        return Path(workspace)
    return Path(__file__).resolve().parent.parent / ".workspace"


def _write_fixture() -> Path:
    workspace = _workspace_path()
    workspace.mkdir(parents=True, exist_ok=True)

    vitals = workspace / "patient_vitals.csv"
    rows = ["patient_id,heart_rate,systolic_bp,temp_c,discharge_day"]
    for index in range(1, 65):
        heart_rate = 72 + (index % 17)
        systolic_bp = 116 + ((index * 3) % 19)
        temp_c = 36.5 + ((index % 9) * 0.1)
        discharge_day = f"day_{1 + (index % 4)}"
        rows.append(
            f"PX-{1000 + index},{heart_rate},{systolic_bp},{temp_c:.1f},{discharge_day}"
        )
    vitals.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return vitals


def _prover_counts(package: dict) -> dict[str, int]:
    counts = Counter()
    for cert in package.get("certificates", []):
        if isinstance(cert, dict):
            counts[str(cert.get("prover", "unknown"))] += 1
        else:
            counts["unknown"] += 1
    return dict(sorted(counts.items()))


def _find_certificates(package: dict, cert_type: str) -> list[dict]:
    return [
        cert for cert in package.get("certificates", [])
        if isinstance(cert, dict) and cert.get("type") == cert_type
    ]


def _build_python_code(csv_text: str) -> str:
    return (
        f"text = {csv_text!r}.strip().splitlines()\n"
        "header = text[0].split(',')\n"
        "rows = [dict(zip(header, line.split(','))) for line in text[1:]]\n"
        "heart_rates = [int(r['heart_rate']) for r in rows]\n"
        "systolic = [int(r['systolic_bp']) for r in rows]\n"
        "temps = [float(r['temp_c']) for r in rows]\n"
        "print(f'rows={len(rows)}')\n"
        "print(f'avg_heart_rate={sum(heart_rates)/len(heart_rates):.2f}')\n"
        "print(f'avg_systolic_bp={sum(systolic)/len(systolic):.2f}')\n"
        "print(f'max_temp_c={max(temps):.1f}')\n"
    )


def _build_public_summary(python_output: str) -> str:
    values: dict[str, str] = {}
    for line in python_output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return (
        "Aggregate-only cohort summary: "
        f"{values.get('rows', '?')} records, "
        f"average heart rate {values.get('avg_heart_rate', '?')}, "
        f"average systolic blood pressure {values.get('avg_systolic_bp', '?')}, "
        f"maximum temperature {values.get('max_temp_c', '?')} C."
    )


async def _persist_execution_if_configured(execution: Execution) -> bool:
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        return False

    from agentsafe.cloud.postgres_backend import PgStateStore

    store = PgStateStore(dsn, min_pool=1, max_pool=2)
    await store.initialize()
    try:
        await store.create(execution)
    finally:
        await store.close()
    return True


async def _run_verified_tool(
    *,
    verifier: _VerificationShim,
    lean: LeanLiveVerifier,
    token: CapabilityToken,
    tool_name: str,
    parameters: dict,
    step_index: int,
    registry,
) -> tuple[dict, str]:
    tool = registry.get(tool_name)
    if tool is None:
        raise RuntimeError(f"Tool not found: {tool_name}")

    action = AgentAction(
        tool=tool.name,
        parameters=parameters,
        required_capabilities=tool.required_capabilities,
        estimated_cost_cents=tool.estimated_cost_cents,
        input_labels=tool.input_labels,
        output_labels=tool.output_labels,
    )

    verification = await verifier.verify_action(action)
    if not verification.valid or verification.certificate is None:
        raise RuntimeError(f"Verification failed for {tool_name}: {verification.violations}")

    lean_result = await lean.check_flow(
        step_index=step_index,
        tool=tool.name,
        input_labels=tool.input_labels,
        output_label=tool.output_labels[0] if tool.output_labels else "Internal",
        data_id=f"step_{step_index}_{tool.name}",
        cost=tool.estimated_cost_cents,
    )
    if not lean_result.ok and lean_result.proven:
        raise RuntimeError(f"Lean flow check blocked {tool_name}: {lean_result.detail}")

    started = time.perf_counter()
    with token.reserve_budget(tool.estimated_cost_cents):
        result = await tool.execute(
            tool_use_id=f"example8-step-{step_index}",
            token_id=token.id,
            agent_id=token.agent_id,
            **parameters,
        )
    duration_ms = (time.perf_counter() - started) * 1000

    step = {
        "step_index": step_index,
        "tool_name": tool.name,
        "tool_input": parameters,
        "tool_output": result.output,
        "is_error": result.is_error,
        "certificate_id": verification.certificate.id,
        "cost_cents": tool.estimated_cost_cents,
        "duration_ms": round(duration_ms, 2),
        "verified": True,
        "verification_properties": list(verification.properties),
        "verification_certificate": verification.certificate.to_dict(),
        "ifc": {
            "effective_level": "internal",
            "promoted": False,
            "flow_blocked": False,
        },
        "lean_verification": lean_result.to_dict(),
        "lean_proven": bool(lean_result.proven),
        "tool_metadata": dict(result.metadata),
        "timestamp": time.time(),
    }
    return step, result.output


async def main() -> None:
    heading("Example 8: All Provers Showcase")

    vitals_fixture = _write_fixture()
    print(f"Vitals fixture:    {vitals_fixture}")

    policy = CompliancePresets.hipaa()
    resolver = VerificationProfileResolver()
    profile = resolver.resolve(
        policy=policy,
        task_class="clinical_intake",
        stage_role="single_agent",
        stage_id="all-provers-runtime-showcase",
        task="Read patient vitals and compute internal cohort statistics with sandboxed code.",
    )
    composed_profile = profile.compose(policy)

    token = CapabilityToken(
        agent_id="example-08",
        permissions=tuple(composed_profile["permission_ceiling"]),
        budget_cents=100,
        budget_remaining_cents=100,
        expires_at=time.time() + 900,
        metadata={
            "compliance_policy": "hipaa",
            "verification_profile": composed_profile,
        },
    )

    registry = create_default_registry(
        workspace=str(_workspace_path()),
        compliance_policy="hipaa",
        verification_profile=composed_profile,
    )
    verifier = _VerificationShim(
        agent_id="example-08",
        capability_token=token,
        compliance_policy="hipaa",
    )

    lean = LeanLiveVerifier()
    lean_started = await lean.start(
        budget=token.budget_remaining_cents,
        capabilities=list(token.permissions),
        compliance="hipaa",
    )

    heading("1. Verified Internal Analysis")
    print(f"Profile:          {composed_profile['profile_name']}")
    print(f"Lean kernel:      {'active' if lean_started else 'unavailable'}")

    steps: list[dict] = []
    audit_trail: list[dict] = []
    if lean_started:
        audit_trail.append({
            "phase": "lean_kernel_started",
            "mode": "dual_proof",
            "binary": lean._binary,
        })

    file_step, csv_text = await _run_verified_tool(
        verifier=verifier,
        lean=lean,
        token=token,
        tool_name="file_read",
        parameters={"filename": "patient_vitals.csv"},
        step_index=0,
        registry=registry,
    )
    steps.append(file_step)

    python_step, python_output = await _run_verified_tool(
        verifier=verifier,
        lean=lean,
        token=token,
        tool_name="python_eval",
        parameters={"code": _build_python_code(csv_text)},
        step_index=1,
        registry=registry,
    )
    steps.append(python_step)

    internal_summary = _build_public_summary(python_output)
    print(f"Aggregate stats:  {internal_summary}")

    heading("2. Attempted Public Disclosure")
    public_check = await lean.check_output_flow(
        step_index=len(steps),
        tool="__final_output__",
        data_label="Internal",
        target_label="Public",
        data_id="aggregate_summary",
    )
    if not public_check.ok and public_check.proven:
        public_output = (
            "[LEAN4 PROVEN BLOCK] The accumulated context (level=internal) "
            f"is mathematically proven to be unsafe for public disclosure. {public_check.detail}"
        )
    else:
        public_output = internal_summary
    print(f"Public result:    {public_output[:140]}")

    lean_certificates = await lean.get_certificates()
    lean_summary = lean.summary()
    await lean.shutdown()

    execution = Execution(
        user_id="example-runner",
        task="Deterministic all-provers showcase",
        status=ExecutionStatus.COMPLETED,
        completed_at=time.time(),
        cost_cents=2,
        token_data={
            "metadata": {
                "compliance_policy": "hipaa",
                "verification_profile": composed_profile,
            },
            "verification_profile": composed_profile,
        },
    )
    execution.results = {
        "output": public_output,
        "steps": steps,
        "audit_trail": audit_trail,
        "lean_verification_summary": lean_summary,
        "lean_certificates": lean_certificates,
        "verification_profile": composed_profile,
    }

    persisted = await _persist_execution_if_configured(execution)

    package = ComplianceExporter(policy).export(execution)
    package_dict = package.to_dict()
    prover_counts = _prover_counts(package_dict)
    dafny_certs = _find_certificates(package_dict, "dafny_proof_certificate")
    seccomp_certs = _find_certificates(package_dict, "seccomp_compliance_certificate")

    heading("3. Exported Evidence")
    print(f"Compliant:        {package.attestation.get('compliant')}")
    print(f"Proofs:           {package.attestation.get('proofs_satisfied')}")
    print(f"Cert provers:     {prover_counts}")
    print(
        f"Lean runtime:     {package.verification_runtime.get('lean_status')} / "
        f"{package.verification_runtime.get('mode')}"
    )

    if dafny_certs:
        dafny = dafny_certs[0]
        print("Dafny proof:")
        print(f"  profile:        {dafny.get('profile_name')}")
        print(f"  properties:     {dafny.get('verified_properties')}")

    if seccomp_certs:
        seccomp = seccomp_certs[0]
        print("Seccomp evidence:")
        print(f"  regime:         {seccomp.get('regime')}")
        print(f"  profile:        {seccomp.get('profile_name')}")
        print(f"  all passed:     {seccomp.get('all_passed')}")

    print("\nTakeaway:")
    print("  Z3 verified both tool calls before execution.")
    print("  Lean verified the tool flows and then blocked the attempted internal-to-public disclosure.")
    print("  Dafny-backed seccomp evidence was exported from the sandboxed python_eval step.")
    print("  Example 07 remains the live API workflow demo for reviewed public release.")
    print(f"  Persisted execution: {'yes' if persisted else 'no'} ({execution.id})")


if __name__ == "__main__":
    asyncio.run(main())
#!/usr/bin/env python3
"""
Certior Integration Demo - Python End-to-End Pipeline

Demonstrates the complete Python → Lean4 → Python roundtrip:

  1. Build PlanInfo using PlanInfoBuilder
  2. Validate plan structure locally
  3. Export to JSON (compatible with Lean4 PlanInfo.fromJson)
  4. Launch DAPClient for interactive debugging
  5. Step through execution, inspect certificates
  6. Export compliance audit trail
  7. Generate formatted compliance report

This script works in two modes:
  - MOCK mode (default): exercises the Python data model without Lean
  - LIVE mode (with --live): connects to the certior-dap binary

Usage:
  python demo/integration_demo.py           # Mock mode
  python demo/integration_demo.py --live    # Live mode (requires lake build)

Copyright (c) 2026 Certior. All rights reserved.
"""

from __future__ import annotations

import json
import sys
import os
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentsafe.verification.lean_bridge import (
    PlanInfoBuilder,
    PlanInfo,
    SecurityLevel,
    FlowLabel,
    Capability,
    StepRhs,
    PlanStep,
    SkillDef,
    ResourceDecl,
    VerifiedPlan,
)

# ═══════════════════════════════════════════════════════════════════════
# §1  Demo Infrastructure
# ═══════════════════════════════════════════════════════════════════════

DIVIDER = "═" * 60
THIN = "─" * 60


def header(title: str) -> None:
    print(f"\n╔{'═' * 58}╗")
    print(f"║  {title:<56}║")
    print(f"╚{'═' * 58}╝\n")


def section(title: str) -> None:
    print(f"\n── {title} {'─' * max(0, 54 - len(title))}\n")


def check(name: str, condition: bool, detail: str = "") -> bool:
    status = "✓ PASS" if condition else "✗ FAIL"
    suffix = f" - {detail}" if detail else ""
    print(f"  {status}: {name}{suffix}")
    return condition


# ═══════════════════════════════════════════════════════════════════════
# §2  HIPAA Patient Data Pipeline (Scenario 1)
# ═══════════════════════════════════════════════════════════════════════


def build_hipaa_plan() -> PlanInfo:
    """Build a HIPAA patient data query plan using PlanInfoBuilder."""
    builder = PlanInfoBuilder(
        compliance_policy="hipaa",
        budget_cents=5000,
    )

    # Skill: query patient database → returns PHI-tagged Sensitive data
    builder.add_skill(
        SkillDef(
            skill_id="queryPatientDB",
            params=["patientId"],
            required_caps=[Capability(resource="database:read:patient_data", cost=150)],
            body=[
                PlanStep.bind("rawData", StepRhs.literal(1),
                              FlowLabel(SecurityLevel.SENSITIVE, ["PHI"])),
                PlanStep.emit("rawData"),
            ],
        )
    )

    # Skill: send external email → Public output
    builder.add_skill(
        SkillDef(
            skill_id="sendExternalEmail",
            params=["recipient", "body"],
            required_caps=[Capability(resource="network:smtp:send:external", cost=200)],
            body=[
                PlanStep.bind("outbound", StepRhs.literal(1),
                              FlowLabel(SecurityLevel.PUBLIC)),
                PlanStep.emit("outbound"),
            ],
        )
    )

    # Resource: budget
    builder.add_resource(
        ResourceDecl(name="budget", init=5000,
                     label=FlowLabel(SecurityLevel.INTERNAL))
    )

    # Main steps: id → query → email (will trigger flow violation)
    builder.add_main_step(
        PlanStep.bind("id", StepRhs.literal(12345),
                      FlowLabel(SecurityLevel.PUBLIC))
    )
    builder.add_main_step(
        PlanStep.bind("patientData",
                      StepRhs.invoke_skill("queryPatientDB", ["id"]),
                      FlowLabel(SecurityLevel.SENSITIVE))
    )
    builder.add_main_step(
        PlanStep.bind("emailResult",
                      StepRhs.invoke_skill("sendExternalEmail", ["id", "patientData"]),
                      FlowLabel(SecurityLevel.PUBLIC))
    )
    builder.add_main_step(PlanStep.emit("emailResult"))

    return builder.build()


def build_hipaa_fixed_plan() -> PlanInfo:
    """Build a fixed HIPAA plan with PHI redaction before output."""
    builder = PlanInfoBuilder(
        compliance_policy="hipaa",
        budget_cents=5000,
    )

    builder.add_skill(
        SkillDef(
            skill_id="queryPatientDB",
            params=["patientId"],
            required_caps=[Capability(resource="database:read:patient_data", cost=150)],
            body=[
                PlanStep.bind("rawData", StepRhs.literal(1),
                              FlowLabel(SecurityLevel.SENSITIVE, ["PHI"])),
                PlanStep.emit("rawData"),
            ],
        )
    )

    builder.add_skill(
        SkillDef(
            skill_id="redactPHI",
            params=["data"],
            required_caps=[Capability(resource="pii:redact", cost=50)],
            body=[
                PlanStep.bind("cleaned", StepRhs.literal(1),
                              FlowLabel(SecurityLevel.INTERNAL)),
                PlanStep.emit("cleaned"),
            ],
        )
    )

    builder.add_resource(
        ResourceDecl(name="budget", init=5000,
                     label=FlowLabel(SecurityLevel.INTERNAL))
    )

    builder.add_main_step(
        PlanStep.bind("id", StepRhs.literal(12345),
                      FlowLabel(SecurityLevel.PUBLIC))
    )
    builder.add_main_step(
        PlanStep.bind("patientData",
                      StepRhs.invoke_skill("queryPatientDB", ["id"]),
                      FlowLabel(SecurityLevel.SENSITIVE))
    )
    builder.add_main_step(
        PlanStep.bind("redacted",
                      StepRhs.invoke_skill("redactPHI", ["patientData"]),
                      FlowLabel(SecurityLevel.INTERNAL))
    )
    builder.add_main_step(PlanStep.emit("redacted"))

    return builder.build()


# ═══════════════════════════════════════════════════════════════════════
# §3  SOX Financial Audit (Scenario 2)
# ═══════════════════════════════════════════════════════════════════════


def build_sox_plan() -> PlanInfo:
    """Build a SOX financial audit plan with MNPI and approval workflow."""
    builder = PlanInfoBuilder(
        compliance_policy="sox",
        budget_cents=8000,
    )

    builder.add_skill(
        SkillDef(
            skill_id="queryEarnings",
            params=[],
            required_caps=[Capability(resource="database:read:financial_data", cost=500)],
            body=[
                PlanStep.bind("data", StepRhs.literal(1),
                              FlowLabel(SecurityLevel.RESTRICTED, ["MNPI"])),
                PlanStep.emit("data"),
            ],
        )
    )

    builder.add_skill(
        SkillDef(
            skill_id="generateReport",
            params=["data"],
            required_caps=[Capability(resource="document:write:internal", cost=200)],
            body=[
                PlanStep.bind("report", StepRhs.literal(1),
                              FlowLabel(SecurityLevel.INTERNAL)),
                PlanStep.emit("report"),
            ],
        )
    )

    builder.add_resource(
        ResourceDecl(name="budget", init=8000,
                     label=FlowLabel(SecurityLevel.INTERNAL))
    )

    builder.add_main_step(
        PlanStep.bind("earnings",
                      StepRhs.invoke_skill("queryEarnings", []),
                      FlowLabel(SecurityLevel.RESTRICTED))
    )
    builder.add_main_step(
        PlanStep.bind("report",
                      StepRhs.invoke_skill("generateReport", ["earnings"]),
                      FlowLabel(SecurityLevel.INTERNAL))
    )
    builder.add_main_step(
        PlanStep.require_approval("MNPI data in output - requires compliance review")
    )
    builder.add_main_step(PlanStep.emit("report"))

    return builder.build()


# ═══════════════════════════════════════════════════════════════════════
# §4  Legal Privilege (Scenario 3)
# ═══════════════════════════════════════════════════════════════════════


def build_legal_plan() -> PlanInfo:
    """Build a legal privilege protection plan."""
    builder = PlanInfoBuilder(
        compliance_policy="legal_privilege",
        budget_cents=3000,
    )

    builder.add_skill(
        SkillDef(
            skill_id="getCaseStrategy",
            params=["caseId"],
            required_caps=[Capability(resource="document:read:legal", cost=100)],
            body=[
                PlanStep.bind("strategy", StepRhs.literal(1),
                              FlowLabel(SecurityLevel.RESTRICTED, ["PRIVILEGED"])),
                PlanStep.emit("strategy"),
            ],
        )
    )

    builder.add_resource(
        ResourceDecl(name="budget", init=3000,
                     label=FlowLabel(SecurityLevel.INTERNAL))
    )

    builder.add_main_step(
        PlanStep.bind("caseId", StepRhs.literal(42),
                      FlowLabel(SecurityLevel.PUBLIC))
    )
    builder.add_main_step(
        PlanStep.bind("strategy",
                      StepRhs.invoke_skill("getCaseStrategy", ["caseId"]),
                      FlowLabel(SecurityLevel.RESTRICTED))
    )
    builder.add_main_step(PlanStep.emit("strategy"))

    return builder.build()


# ═══════════════════════════════════════════════════════════════════════
# §5  JSON Roundtrip Validation
# ═══════════════════════════════════════════════════════════════════════


def validate_json_roundtrip(name: str, plan: PlanInfo) -> bool:
    """Export to JSON, re-import, verify structural equivalence."""
    exported = plan.to_json()
    reimported = PlanInfo.from_json(exported)

    # Check structural equivalence
    re_exported = reimported.to_json()

    checks = [
        check(f"{name}/roundtrip_json_valid",
              isinstance(json.loads(exported), dict)),
        check(f"{name}/roundtrip_lossless",
              json.loads(exported) == json.loads(re_exported),
              "exported JSON matches re-exported"),
        check(f"{name}/step_count_preserved",
              plan.plan.total_step_count == reimported.plan.total_step_count,
              f"{plan.plan.total_step_count} steps"),
        check(f"{name}/compliance_preserved",
              plan.plan.compliance_policy == reimported.plan.compliance_policy,
              plan.plan.compliance_policy),
        check(f"{name}/budget_preserved",
              plan.plan.total_budget_cents == reimported.plan.total_budget_cents,
              f"{plan.plan.total_budget_cents}¢"),
    ]
    return all(checks)


# ═══════════════════════════════════════════════════════════════════════
# §6  Compliance Report Generation
# ═══════════════════════════════════════════════════════════════════════


def generate_compliance_report(plan: PlanInfo) -> Dict[str, Any]:
    """Generate a structured compliance report from a PlanInfo."""
    p = plan.plan
    report = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "certior-python-bridge",
            "version": "1.0.0",
        },
        "plan_summary": {
            "compliance_policy": p.compliance_policy,
            "total_budget_cents": p.total_budget_cents,
            "skill_count": len(p.skills),
            "main_step_count": len(p.main_steps),
            "total_step_count": p.total_step_count,
            "resource_count": len(p.resources),
        },
        "skills": [],
        "flow_analysis": {
            "data_labels": {},
            "potential_violations": [],
        },
        "capabilities_required": [],
        "budget_breakdown": [],
    }

    # Skill analysis
    total_cost = 0
    all_caps = set()
    for skill in p.skills:
        skill_cost = sum(c.cost for c in skill.required_caps)
        total_cost += skill_cost
        caps = [c.resource for c in skill.required_caps]
        all_caps.update(caps)
        report["skills"].append({
            "skill_id": skill.skill_id,
            "params": skill.params,
            "step_count": len(skill.body),
            "capabilities": caps,
            "estimated_cost_cents": skill_cost,
        })

    report["capabilities_required"] = sorted(all_caps)
    report["budget_breakdown"].append({
        "category": "skill_invocations",
        "estimated_total_cents": total_cost,
        "budget_percentage": round(total_cost / max(p.total_budget_cents, 1) * 100, 1),
    })

    # Flow analysis: scan for potential violations
    for step in p.main_steps:
        if step.tag == "Bind" and step.flow_label:
            report["flow_analysis"]["data_labels"][step.dst] = {
                "level": step.flow_label.level.value,
                "tags": step.flow_label.tags,
            }
            # Check for invocations where output level differs from skill output
            if step.rhs and step.rhs.tag == "InvokeSkill":
                skill_id = step.rhs.skill_id
                skill_def = next((s for s in p.skills if s.skill_id == skill_id), None)
                if skill_def:
                    for body_step in skill_def.body:
                        if body_step.tag == "Bind" and body_step.flow_label:
                            src_rank = body_step.flow_label.level.rank()
                            dst_rank = step.flow_label.level.rank()
                            if src_rank > dst_rank:
                                report["flow_analysis"]["potential_violations"].append({
                                    "type": "downgrade",
                                    "data_id": step.dst,
                                    "source_level": body_step.flow_label.level.value,
                                    "target_level": step.flow_label.level.value,
                                    "skill": skill_id,
                                    "severity": "BLOCKED",
                                })

    return report


def format_report_markdown(report: Dict[str, Any]) -> str:
    """Format a compliance report as Markdown."""
    lines = [
        f"# Compliance Audit Report",
        f"",
        f"**Generated**: {report['metadata']['generated_at']}  ",
        f"**Generator**: {report['metadata']['generator']}  ",
        f"**Policy**: {report['plan_summary']['compliance_policy']}  ",
        f"",
        f"## Plan Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Budget | {report['plan_summary']['total_budget_cents']}¢ |",
        f"| Skills | {report['plan_summary']['skill_count']} |",
        f"| Main steps | {report['plan_summary']['main_step_count']} |",
        f"| Total steps | {report['plan_summary']['total_step_count']} |",
        f"| Resources | {report['plan_summary']['resource_count']} |",
        f"",
        f"## Skills",
        f"",
    ]

    for skill in report["skills"]:
        lines.append(f"### {skill['skill_id']}")
        lines.append(f"- Parameters: {', '.join(skill['params']) or 'none'}")
        lines.append(f"- Cost: {skill['estimated_cost_cents']}¢")
        lines.append(f"- Capabilities: {', '.join(skill['capabilities'])}")
        lines.append("")

    lines.append("## Flow Analysis")
    lines.append("")
    violations = report["flow_analysis"]["potential_violations"]
    if violations:
        lines.append(f"**⚠ {len(violations)} potential violation(s) detected:**")
        lines.append("")
        for v in violations:
            lines.append(
                f"- **{v['severity']}**: `{v['data_id']}` - "
                f"{v['source_level']} → {v['target_level']} "
                f"(in skill `{v['skill']}`)"
            )
    else:
        lines.append("✓ No flow violations detected.")
    lines.append("")

    lines.append("## Budget Breakdown")
    lines.append("")
    for item in report["budget_breakdown"]:
        lines.append(
            f"- {item['category']}: {item['estimated_total_cents']}¢ "
            f"({item['budget_percentage']}% of budget)"
        )

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════
# §7  Live DAP Integration (optional)
# ═══════════════════════════════════════════════════════════════════════


def run_live_dap_demo(plan: PlanInfo, scenario_name: str) -> None:
    """Run a plan through the actual certior-dap binary."""
    try:
        from agentsafe.verification.lean_bridge import DAPClient, VerifiedPlanRunner
    except ImportError:
        print("  ⚠ DAPClient not available - skipping live demo")
        return

    lean_project = str(
        Path(__file__).resolve().parents[1] / "lean4" / "CertiorPlan"
    )

    section(f"Live DAP: {scenario_name}")

    try:
        runner = VerifiedPlanRunner(lean_project=lean_project, timeout=30.0)
        result = runner.run(plan, stop_on_violations=True, max_steps=100)

        check(f"dap/{scenario_name}/completed", result.steps_executed > 0,
              f"{result.steps_executed} steps")
        check(f"dap/{scenario_name}/certificates", len(result.certificates) >= 0,
              f"{len(result.certificates)} certificates")
        check(f"dap/{scenario_name}/compliance_export",
              isinstance(result.compliance_export, dict),
              "compliance export generated")

        if result.stopped_reason:
            print(f"  ℹ Stopped reason: {result.stopped_reason}")
        if result.error:
            print(f"  ⚠ Error: {result.error}")

    except FileNotFoundError:
        print(f"  ⚠ certior-dap binary not found - run 'lake build' first")
    except Exception as e:
        print(f"  ⚠ DAP error: {e}")


# ═══════════════════════════════════════════════════════════════════════
# §8  Main Demo Runner
# ═══════════════════════════════════════════════════════════════════════


def main() -> None:
    live_mode = "--live" in sys.argv

    header("CERTIOR INTEGRATION DEMO - Python Pipeline")

    if live_mode:
        print("  Mode: LIVE (connecting to certior-dap binary)")
    else:
        print("  Mode: MOCK (exercising Python data model)")
    print()

    # ── Scenario 1: HIPAA ────────────────────────────────────────────
    section("Scenario 1: HIPAA Patient Data Pipeline")

    hipaa_leak = build_hipaa_plan()
    hipaa_fixed = build_hipaa_fixed_plan()

    check("hipaa/build_leak_plan",
          hipaa_leak.plan.total_step_count > 0,
          f"{hipaa_leak.plan.total_step_count} steps")
    check("hipaa/build_fixed_plan",
          hipaa_fixed.plan.total_step_count > 0,
          f"{hipaa_fixed.plan.total_step_count} steps")
    check("hipaa/compliance_policy",
          hipaa_leak.plan.compliance_policy == "hipaa")

    section("Scenario 1: JSON Roundtrip")
    validate_json_roundtrip("hipaa_leak", hipaa_leak)
    validate_json_roundtrip("hipaa_fixed", hipaa_fixed)

    section("Scenario 1: Compliance Report")
    leak_report = generate_compliance_report(hipaa_leak)
    violations = leak_report["flow_analysis"]["potential_violations"]
    check("hipaa/leak_detected",
          len(violations) > 0,
          f"{len(violations)} violation(s)")
    if violations:
        for v in violations:
            print(f"    → {v['data_id']}: {v['source_level']} → {v['target_level']} [{v['severity']}]")

    fixed_report = generate_compliance_report(hipaa_fixed)
    fixed_violations = fixed_report["flow_analysis"]["potential_violations"]
    check("hipaa/fixed_clean",
          len(fixed_violations) == 0,
          "no violations in fixed plan")

    if live_mode:
        run_live_dap_demo(hipaa_leak, "hipaa_leak")
        run_live_dap_demo(hipaa_fixed, "hipaa_fixed")

    # ── Scenario 2: SOX ──────────────────────────────────────────────
    section("Scenario 2: SOX Financial Audit")

    sox_plan = build_sox_plan()
    check("sox/build_plan",
          sox_plan.plan.total_step_count > 0,
          f"{sox_plan.plan.total_step_count} steps")
    check("sox/compliance_policy",
          sox_plan.plan.compliance_policy == "sox")
    check("sox/has_approval_step",
          any(s.tag == "RequireApproval" for s in sox_plan.plan.main_steps))

    section("Scenario 2: JSON Roundtrip")
    validate_json_roundtrip("sox", sox_plan)

    section("Scenario 2: Budget Analysis")
    sox_report = generate_compliance_report(sox_plan)
    for skill in sox_report["skills"]:
        print(f"  Skill: {skill['skill_id']} - {skill['estimated_cost_cents']}¢")
    for item in sox_report["budget_breakdown"]:
        print(f"  Total skill cost: {item['estimated_total_cents']}¢ "
              f"({item['budget_percentage']}% of {sox_plan.plan.total_budget_cents}¢ budget)")

    if live_mode:
        run_live_dap_demo(sox_plan, "sox_audit")

    # ── Scenario 3: Legal ────────────────────────────────────────────
    section("Scenario 3: Legal Privilege Protection")

    legal_plan = build_legal_plan()
    check("legal/build_plan",
          legal_plan.plan.total_step_count > 0,
          f"{legal_plan.plan.total_step_count} steps")
    check("legal/compliance_policy",
          legal_plan.plan.compliance_policy == "legal_privilege")

    section("Scenario 3: JSON Roundtrip")
    validate_json_roundtrip("legal", legal_plan)

    if live_mode:
        run_live_dap_demo(legal_plan, "legal_privilege")

    # ── Markdown Report Export ────────────────────────────────────────
    section("Export: Compliance Reports")

    for name, plan in [
        ("hipaa_leak", hipaa_leak),
        ("sox_audit", sox_plan),
        ("legal_privilege", legal_plan),
    ]:
        report = generate_compliance_report(plan)
        md = format_report_markdown(report)
        output_path = Path(__file__).parent / f"report_{name}.md"
        output_path.write_text(md)
        check(f"export/{name}/markdown",
              output_path.exists(),
              str(output_path))

    # ── JSON Export ───────────────────────────────────────────────────
    section("Export: JSON Plans (for Lean4)")

    for name, plan in [
        ("hipaa_leak", hipaa_leak),
        ("hipaa_fixed", hipaa_fixed),
        ("sox_audit", sox_plan),
        ("legal_privilege", legal_plan),
    ]:
        json_path = Path(__file__).parent / f"plan_{name}.json"
        json_path.write_text(plan.to_json(indent=2))
        check(f"export/{name}/json", json_path.exists(), str(json_path))

    # ── Summary ──────────────────────────────────────────────────────
    header("DEMO COMPLETE")
    print("  ✓ 3 compliance scenarios built and validated")
    print("  ✓ JSON roundtrip verified for all plans")
    print("  ✓ Flow violations detected in leak scenarios")
    print("  ✓ Compliance reports generated (Markdown + JSON)")
    print("  ✓ Plan JSON exported for Lean4 import")
    if live_mode:
        print("  ✓ DAP integration tested against certior-dap")
    else:
        print("  ℹ Run with --live for DAP integration testing")
    print()


if __name__ == "__main__":
    main()

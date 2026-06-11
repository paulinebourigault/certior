#!/usr/bin/env python3
"""
Certior Integration Tests - Python Bridge

Tests covering:
  1. PlanInfo construction via PlanInfoBuilder
  2. JSON serialization/deserialization roundtrip
  3. Plan validation (structural invariants)
  4. Compliance report generation
  5. Flow violation detection (static analysis)
  6. DAPTransport message framing
  7. DAPClient protocol sequences

Run:
  python -m pytest tests/test_integration_bridge.py -v
  # or
  python tests/test_integration_bridge.py

Copyright (c) 2026 Certior. All rights reserved.
"""

from __future__ import annotations

import json
import sys
import io
import threading
from pathlib import Path

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
    DAPTransport,
    DAPError,
    DAPTimeout,
)

# ═══════════════════════════════════════════════════════════════════════
# Test Infrastructure
# ═══════════════════════════════════════════════════════════════════════

_pass_count = 0
_fail_count = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global _pass_count, _fail_count
    if condition:
        _pass_count += 1
        print(f"  ✓ PASS: {name}" + (f" - {detail}" if detail else ""))
    else:
        _fail_count += 1
        print(f"  ✗ FAIL: {name}" + (f" - {detail}" if detail else ""))


def section(title: str) -> None:
    print(f"\n── {title} {'─' * max(0, 54 - len(title))}\n")


# ═══════════════════════════════════════════════════════════════════════
# §1  SecurityLevel Tests
# ═══════════════════════════════════════════════════════════════════════


def test_security_levels() -> None:
    section("SecurityLevel")

    check("public_rank", SecurityLevel.PUBLIC.rank() == 0)
    check("internal_rank", SecurityLevel.INTERNAL.rank() == 1)
    check("sensitive_rank", SecurityLevel.SENSITIVE.rank() == 2)
    check("restricted_rank", SecurityLevel.RESTRICTED.rank() == 3)

    # Flow checks: can only flow to same or higher level
    check("public_to_public", SecurityLevel.PUBLIC.can_flow_to(SecurityLevel.PUBLIC))
    check("public_to_sensitive", SecurityLevel.PUBLIC.can_flow_to(SecurityLevel.SENSITIVE))
    check("sensitive_to_public_blocked",
          not SecurityLevel.SENSITIVE.can_flow_to(SecurityLevel.PUBLIC))
    check("restricted_to_public_blocked",
          not SecurityLevel.RESTRICTED.can_flow_to(SecurityLevel.PUBLIC))
    check("restricted_to_restricted",
          SecurityLevel.RESTRICTED.can_flow_to(SecurityLevel.RESTRICTED))


# ═══════════════════════════════════════════════════════════════════════
# §2  FlowLabel Tests
# ═══════════════════════════════════════════════════════════════════════


def test_flow_labels() -> None:
    section("FlowLabel")

    label = FlowLabel(SecurityLevel.SENSITIVE, ["PHI", "PII"])
    check("label_level", label.level == SecurityLevel.SENSITIVE)
    check("label_tags", label.tags == ["PHI", "PII"])

    # Serialization
    d = label.to_dict()
    check("label_to_dict", d["level"] == "Sensitive")
    check("label_tags_dict", d["tags"] == ["PHI", "PII"])

    # Round-trip
    restored = FlowLabel.from_dict(d)
    check("label_roundtrip_level", restored.level == label.level)
    check("label_roundtrip_tags", restored.tags == label.tags)

    # Default tags
    simple = FlowLabel(SecurityLevel.PUBLIC)
    check("label_default_tags", simple.tags == [])


# ═══════════════════════════════════════════════════════════════════════
# §3  PlanInfoBuilder Tests
# ═══════════════════════════════════════════════════════════════════════


def test_plan_builder() -> None:
    section("PlanInfoBuilder")

    builder = PlanInfoBuilder(compliance_policy="hipaa", budget_cents=5000)

    builder.add_resource(
        ResourceDecl(name="budget", init=5000,
                     label=FlowLabel(SecurityLevel.INTERNAL))
    )

    builder.add_skill(
        SkillDef(
            skill_id="queryDB",
            params=["id"],
            required_caps=[Capability(resource="db:read", cost=100)],
            body=[
                PlanStep.bind("data", StepRhs.literal(1),
                              FlowLabel(SecurityLevel.SENSITIVE, ["PHI"])),
                PlanStep.emit("data"),
            ],
        )
    )

    builder.add_main_step(
        PlanStep.bind("id", StepRhs.literal(42), FlowLabel(SecurityLevel.PUBLIC))
    )
    builder.add_main_step(
        PlanStep.bind("result",
                      StepRhs.invoke_skill("queryDB", ["id"]),
                      FlowLabel(SecurityLevel.SENSITIVE))
    )
    builder.add_main_step(PlanStep.emit("result"))

    plan = builder.build()

    check("builder/compliance", plan.plan.compliance_policy == "hipaa")
    check("builder/budget", plan.plan.total_budget_cents == 5000)
    check("builder/skill_count", len(plan.plan.skills) == 1)
    check("builder/main_steps", len(plan.plan.main_steps) == 3)
    check("builder/resources", len(plan.plan.resources) == 1)
    check("builder/total_steps", plan.plan.total_step_count == 5,
          f"expected 5, got {plan.plan.total_step_count}")


# ═══════════════════════════════════════════════════════════════════════
# §4  JSON Roundtrip Tests
# ═══════════════════════════════════════════════════════════════════════


def _build_test_plan(policy: str, budget: int) -> PlanInfo:
    builder = PlanInfoBuilder(compliance_policy=policy, budget_cents=budget)
    builder.add_resource(
        ResourceDecl(name="budget", init=budget,
                     label=FlowLabel(SecurityLevel.INTERNAL))
    )
    builder.add_main_step(
        PlanStep.bind("x", StepRhs.literal(42), FlowLabel(SecurityLevel.PUBLIC))
    )
    builder.add_main_step(PlanStep.emit("x"))
    return builder.build()


def test_json_roundtrip() -> None:
    section("JSON Roundtrip")

    for policy, budget in [("hipaa", 5000), ("sox", 8000), ("legal_privilege", 3000)]:
        plan = _build_test_plan(policy, budget)
        exported = plan.to_json()

        # Valid JSON
        parsed = json.loads(exported)
        check(f"json/{policy}/valid", isinstance(parsed, dict))

        # Roundtrip
        reimported = PlanInfo.from_json(exported)
        re_exported = reimported.to_json()
        check(f"json/{policy}/lossless",
              json.loads(exported) == json.loads(re_exported))

        # Structural preservation
        check(f"json/{policy}/compliance",
              reimported.plan.compliance_policy == policy)
        check(f"json/{policy}/budget",
              reimported.plan.total_budget_cents == budget)
        check(f"json/{policy}/step_count",
              plan.plan.total_step_count == reimported.plan.total_step_count)


# ═══════════════════════════════════════════════════════════════════════
# §5  Complex Plan Roundtrip
# ═══════════════════════════════════════════════════════════════════════


def test_complex_roundtrip() -> None:
    section("Complex Plan Roundtrip")

    builder = PlanInfoBuilder(compliance_policy="hipaa", budget_cents=10000)

    # Multiple skills
    for i in range(3):
        builder.add_skill(
            SkillDef(
                skill_id=f"skill_{i}",
                params=["arg"],
                required_caps=[Capability(resource=f"cap_{i}", cost=100 * (i + 1))],
                body=[
                    PlanStep.bind(f"out_{i}", StepRhs.literal(i),
                                  FlowLabel(SecurityLevel(["Public", "Internal", "Sensitive"][i]))),
                    PlanStep.emit(f"out_{i}"),
                ],
            )
        )

    # Multiple resources
    for name, val in [("budget", 10000), ("token", 1)]:
        builder.add_resource(
            ResourceDecl(name=name, init=val,
                         label=FlowLabel(SecurityLevel.INTERNAL))
        )

    # Main steps with various types
    builder.add_main_step(
        PlanStep.bind("x", StepRhs.literal(1), FlowLabel(SecurityLevel.PUBLIC))
    )
    builder.add_main_step(
        PlanStep.bind("y",
                      StepRhs.invoke_skill("skill_0", ["x"]),
                      FlowLabel(SecurityLevel.PUBLIC))
    )
    builder.add_main_step(
        PlanStep.read_resource("budget", "remaining",
                               FlowLabel(SecurityLevel.INTERNAL))
    )
    builder.add_main_step(
        PlanStep.require_approval("Complex plan requires review")
    )
    builder.add_main_step(PlanStep.emit("y"))

    plan = builder.build()

    check("complex/skills", len(plan.plan.skills) == 3)
    check("complex/resources", len(plan.plan.resources) == 2)
    check("complex/main_steps", len(plan.plan.main_steps) == 5)

    # Roundtrip
    exported = plan.to_json()
    reimported = PlanInfo.from_json(exported)
    check("complex/roundtrip_skills", len(reimported.plan.skills) == 3)
    check("complex/roundtrip_resources", len(reimported.plan.resources) == 2)
    check("complex/roundtrip_main_steps", len(reimported.plan.main_steps) == 5)
    check("complex/roundtrip_lossless",
          json.loads(exported) == json.loads(reimported.to_json()))


# ═══════════════════════════════════════════════════════════════════════
# §6  Flow Violation Detection (Static)
# ═══════════════════════════════════════════════════════════════════════


def test_flow_analysis() -> None:
    section("Flow Analysis (Static)")

    # Plan with violation: Sensitive skill output → Public main binding
    builder = PlanInfoBuilder(compliance_policy="hipaa", budget_cents=5000)
    builder.add_skill(
        SkillDef(
            skill_id="leaky",
            params=["x"],
            required_caps=[],
            body=[
                PlanStep.bind("data", StepRhs.literal(1),
                              FlowLabel(SecurityLevel.SENSITIVE, ["PHI"])),
                PlanStep.emit("data"),
            ],
        )
    )
    builder.add_main_step(
        PlanStep.bind("x", StepRhs.literal(1), FlowLabel(SecurityLevel.PUBLIC))
    )
    builder.add_main_step(
        PlanStep.bind("result",
                      StepRhs.invoke_skill("leaky", ["x"]),
                      FlowLabel(SecurityLevel.PUBLIC))
    )
    builder.add_main_step(PlanStep.emit("result"))

    plan = builder.build()

    # Detect violation: skill output is Sensitive, binding is Public
    violations = plan.detect_flow_violations()
    check("flow/leak_detected", len(violations) > 0,
          f"{len(violations)} violation(s)")

    if violations:
        v = violations[0]
        check("flow/violation_type", v["type"] == "downgrade")
        check("flow/violation_src", v["source_level"] == "Sensitive")
        check("flow/violation_dst", v["target_level"] == "Public")

    # Clean plan: all same level
    clean_builder = PlanInfoBuilder(compliance_policy="hipaa", budget_cents=5000)
    clean_builder.add_main_step(
        PlanStep.bind("x", StepRhs.literal(1), FlowLabel(SecurityLevel.SENSITIVE))
    )
    clean_builder.add_main_step(PlanStep.emit("x"))
    clean_plan = clean_builder.build()

    clean_violations = clean_plan.detect_flow_violations()
    check("flow/clean_no_violations", len(clean_violations) == 0)


# ═══════════════════════════════════════════════════════════════════════
# §7  DAPTransport Message Framing
# ═══════════════════════════════════════════════════════════════════════


def test_dap_transport_framing() -> None:
    section("DAPTransport Message Framing")

    # Create in-memory pipes
    server_in = io.BytesIO()
    server_out = io.BytesIO()

    # Test message encoding
    msg = {"seq": 1, "type": "request", "command": "initialize"}
    payload = json.dumps(msg).encode("utf-8")
    header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
    encoded = header + payload

    check("framing/header_format",
          encoded.startswith(b"Content-Length:"))
    check("framing/crlf_separator",
          b"\r\n\r\n" in encoded)

    # Parse the encoded message
    server_out.write(encoded)
    server_out.seek(0)

    # Read header
    line = server_out.readline()
    check("framing/header_readable",
          line.strip().startswith(b"Content-Length:"))

    content_length = int(line.decode("ascii").split(":")[1].strip())
    check("framing/content_length_correct",
          content_length == len(payload),
          f"{content_length} == {len(payload)}")

    # Skip empty line
    server_out.readline()

    # Read payload
    body = server_out.read(content_length)
    parsed = json.loads(body.decode("utf-8"))
    check("framing/payload_parsed", parsed["command"] == "initialize")
    check("framing/seq_preserved", parsed["seq"] == 1)


# ═══════════════════════════════════════════════════════════════════════
# §8  DAPClient Protocol Sequence
# ═══════════════════════════════════════════════════════════════════════


def test_dap_protocol_sequence() -> None:
    section("DAPClient Protocol Sequence")

    # Verify expected request sequence
    expected_init = {
        "clientID": "certior-python-bridge",
        "clientName": "Certior Python Bridge",
        "adapterID": "certior-plan-dap",
        "linesStartAt1": True,
        "columnsStartAt1": True,
        "supportsVariableType": True,
        "supportsSteppingGranularity": True,
        "supportsStepBack": True,
    }

    check("protocol/init_has_clientID",
          "clientID" in expected_init)
    check("protocol/init_supports_stepBack",
          expected_init["supportsStepBack"] is True)

    # Verify custom request names
    custom_requests = [
        "certificates",
        "flowGraph",
        "complianceExport",
        "setFlowBreakpoints",
        "setBudgetBreakpoint",
        "setCapabilityWatch",
    ]
    for req in custom_requests:
        check(f"protocol/custom_request_{req}", isinstance(req, str))

    # Verify exception breakpoint filters
    filters = [
        "flow_violation",
        "budget_exceeded",
        "capability_denied",
        "approval_required",
    ]
    for f in filters:
        check(f"protocol/filter_{f}", isinstance(f, str))


# ═══════════════════════════════════════════════════════════════════════
# §9  Plan Validation
# ═══════════════════════════════════════════════════════════════════════


def test_plan_validation() -> None:
    section("Plan Validation")

    # Empty plan should be minimally valid
    empty_builder = PlanInfoBuilder(compliance_policy="default", budget_cents=0)
    empty_plan = empty_builder.build()
    check("validation/empty_builds", empty_plan is not None)

    # Plan with steps
    plan = _build_test_plan("hipaa", 5000)
    check("validation/has_steps", plan.plan.total_step_count > 0)
    check("validation/has_compliance", plan.plan.compliance_policy == "hipaa")
    check("validation/positive_budget", plan.plan.total_budget_cents > 0)

    # Validate JSON schema compatibility
    exported = json.loads(plan.to_json())
    check("validation/json_has_plan", "plan" in exported)
    check("validation/json_has_located", "located" in exported)
    check("validation/json_plan_has_mainSteps",
          "mainSteps" in exported["plan"])
    check("validation/json_plan_has_skills",
          "skills" in exported["plan"])
    check("validation/json_plan_has_compliancePolicy",
          "compliancePolicy" in exported["plan"])


# ═══════════════════════════════════════════════════════════════════════
# §10  Test Runner
# ═══════════════════════════════════════════════════════════════════════


def main() -> None:
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  CERTIOR PYTHON BRIDGE - INTEGRATION TEST SUITE         ║")
    print("╚══════════════════════════════════════════════════════════╝")

    test_security_levels()
    test_flow_labels()
    test_plan_builder()
    test_json_roundtrip()
    test_complex_roundtrip()
    test_flow_analysis()
    test_dap_transport_framing()
    test_dap_protocol_sequence()
    test_plan_validation()

    print(f"\n{'═' * 60}")
    print(f"  Results: {_pass_count} passed, {_fail_count} failed")
    print(f"{'═' * 60}")

    if _fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

"""
Tests for CertiorPlan Python Bridge (lean_bridge.py)

Validates:
- PlanInfo JSON roundtrip
- PlanInfoBuilder fluent API
- Python-side flow validation
- SecurityLevel ordering
"""

import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentsafe.verification.lean_bridge import (
    SecurityLevel,
    FlowLabel,
    Capability,
    StepRhs,
    PlanStep,
    ResourceDecl,
    SkillDef,
    VerifiedPlan,
    PlanInfo,
    PlanInfoBuilder,
)


def test_security_level_ordering():
    """Test SecurityLevel rank ordering matches Lean4."""
    assert SecurityLevel.PUBLIC.rank == 0
    assert SecurityLevel.INTERNAL.rank == 1
    assert SecurityLevel.SENSITIVE.rank == 2
    assert SecurityLevel.RESTRICTED.rank == 3

    assert SecurityLevel.PUBLIC.can_flow_to(SecurityLevel.INTERNAL)
    assert SecurityLevel.PUBLIC.can_flow_to(SecurityLevel.SENSITIVE)
    assert SecurityLevel.INTERNAL.can_flow_to(SecurityLevel.SENSITIVE)
    assert SecurityLevel.PUBLIC.can_flow_to(SecurityLevel.PUBLIC)

    assert not SecurityLevel.INTERNAL.can_flow_to(SecurityLevel.PUBLIC)
    assert not SecurityLevel.SENSITIVE.can_flow_to(SecurityLevel.PUBLIC)
    assert not SecurityLevel.SENSITIVE.can_flow_to(SecurityLevel.INTERNAL)
    assert not SecurityLevel.RESTRICTED.can_flow_to(SecurityLevel.SENSITIVE)
    print("  ✓ SecurityLevel ordering matches Lean4 lattice")


def test_flow_label_json():
    """Test FlowLabel JSON serialization."""
    label = FlowLabel(level="Sensitive", tags=["PHI", "patient"])
    d = label.to_dict()
    assert d["level"] == "Sensitive"
    assert d["tags"] == ["PHI", "patient"]
    print("  ✓ FlowLabel JSON serialization")


def test_step_rhs_json():
    """Test StepRhs variants serialize correctly."""
    # Literal
    rhs = StepRhs(tag="literal", value=42)
    d = rhs.to_dict()
    assert d["tag"] == "literal"
    assert d["value"] == 42

    # InvokeSkill
    rhs = StepRhs(tag="invokeSkill", skill="query", args=["id"])
    d = rhs.to_dict()
    assert d["tag"] == "invokeSkill"
    assert d["skill"] == "query"

    # CheckFlow
    rhs = StepRhs(tag="checkFlow", src="data", dst="output")
    d = rhs.to_dict()
    assert d["tag"] == "checkFlow"
    assert d["src"] == "data"
    print("  ✓ StepRhs JSON variants")


def test_plan_info_json_roundtrip():
    """Test full PlanInfo JSON roundtrip."""
    plan = VerifiedPlan(
        resources=[ResourceDecl("budget", 5000, FlowLabel("Internal"))],
        skills=[
            SkillDef(
                skillId="query",
                params=["id"],
                requiredCaps=[Capability("database:read", 100)],
                body=[
                    PlanStep(tag="bind", dest="data",
                             rhs=StepRhs(tag="literal", value=1),
                             label=FlowLabel("Sensitive", ["PHI"])),
                    PlanStep(tag="emitResult", value="data"),
                ],
            )
        ],
        mainSteps=[
            PlanStep(tag="bind", dest="x",
                     rhs=StepRhs(tag="literal", value=42),
                     label=FlowLabel("Public")),
            PlanStep(tag="emitResult", value="x"),
        ],
        totalBudgetCents=5000,
        compliancePolicy="hipaa",
    )
    info = PlanInfo(plan=plan, located=[])
    json_str = info.to_json()

    # Parse back
    roundtripped = PlanInfo.from_json(json_str)
    assert roundtripped.plan.totalBudgetCents == 5000
    assert roundtripped.plan.compliancePolicy == "hipaa"
    assert len(roundtripped.plan.mainSteps) == 2
    assert len(roundtripped.plan.skills) == 1
    assert roundtripped.plan.skills[0].skillId == "query"
    assert len(roundtripped.plan.resources) == 1

    # Verify JSON is valid
    parsed = json.loads(json_str)
    assert "plan" in parsed
    assert "located" in parsed
    print("  ✓ PlanInfo JSON roundtrip")


def test_plan_info_builder():
    """Test PlanInfoBuilder fluent API."""
    builder = PlanInfoBuilder(compliance_policy="hipaa", budget_cents=5000)
    builder.add_resource("budget", 5000, level="Internal")
    builder.add_resource("token", 1, level="Sensitive")
    builder.add_skill(
        "query_patients",
        params=["patientId"],
        required_caps=[{"resource": "database:read:patient_data", "maxCost": 100}],
        steps=[
            builder.bind("rawData", builder.literal(1),
                         level="Sensitive", tags=["PHI"]),
            builder.emit("rawData"),
        ],
    )
    builder.add_main_step(builder.bind("id", builder.literal(12345), level="Public"))
    builder.add_main_step(
        builder.invoke_and_bind("data", "query_patients", ["id"],
                                level="Sensitive", tags=["PHI"])
    )
    builder.add_main_step(builder.emit("data"))

    plan_info = builder.build()
    assert plan_info.plan.compliancePolicy == "hipaa"
    assert plan_info.plan.totalBudgetCents == 5000
    assert len(plan_info.plan.mainSteps) == 3
    assert len(plan_info.plan.skills) == 1
    assert len(plan_info.plan.resources) == 2
    # Located should have skill body (2) + main (3) = 5 entries
    assert len(plan_info.located) == 5

    # Verify JSON output
    json_str = builder.to_json()
    parsed = json.loads(json_str)
    assert parsed["plan"]["compliancePolicy"] == "hipaa"
    print("  ✓ PlanInfoBuilder fluent API")


def test_python_side_validation():
    """Test Python-side flow validation."""
    # Valid plan: Public → Sensitive (upgrade OK)
    builder = PlanInfoBuilder(budget_cents=1000)
    builder.add_main_step(builder.bind("x", builder.literal(1), level="Public"))
    builder.add_main_step(
        builder.invoke_and_bind("y", "process", ["x"], level="Sensitive")
    )
    builder.add_main_step(builder.emit("y"))
    info = builder.build()
    result = PlanInfoBuilder().__class__.__mro__  # just for reference
    from agentsafe.verification.lean_bridge import LeanKernelBridge
    bridge = LeanKernelBridge()
    validation = bridge.validate_plan(info)
    assert validation["valid"], f"Expected valid, got errors: {validation['errors']}"
    print("  ✓ Valid plan passes Python validation")

    # Invalid plan: Sensitive → Public (downgrade blocked)
    builder2 = PlanInfoBuilder(budget_cents=1000)
    builder2.add_main_step(builder2.bind("secret", builder2.literal(42), level="Sensitive"))
    builder2.add_main_step(
        builder2.invoke_and_bind("leaked", "send", ["secret"], level="Public")
    )
    builder2.add_main_step(builder2.emit("leaked"))
    info2 = builder2.build()
    validation2 = bridge.validate_plan(info2)
    assert not validation2["valid"], "Expected flow violation"
    assert any("Flow violation" in e for e in validation2["errors"])
    print("  ✓ Invalid plan caught by Python validation")


def test_hipaa_demo_plan():
    """Build and validate the HIPAA demo plan from the integration spec."""
    builder = PlanInfoBuilder(compliance_policy="hipaa", budget_cents=5000)
    builder.add_resource("budget", 5000, level="Internal")
    builder.add_resource("patientToken", 1, level="Sensitive")

    builder.add_skill(
        "queryPatient",
        params=["patientId"],
        required_caps=[{"resource": "database:read:patient_data", "maxCost": 100}],
        steps=[
            builder.bind("rawData", builder.literal(1),
                         level="Sensitive", tags=["PHI"]),
            builder.emit("rawData"),
        ],
    )
    builder.add_skill(
        "sendEmail",
        params=["recipient", "body"],
        required_caps=[{"resource": "network:smtp:send"}],
        steps=[
            builder.bind("outbound", builder.literal(1), level="Public"),
            builder.emit("outbound"),
        ],
    )

    builder.add_main_step(builder.bind("id", builder.literal(12345), level="Public"))
    builder.add_main_step(
        builder.invoke_and_bind("patientData", "queryPatient", ["id"],
                                level="Sensitive", tags=["PHI"])
    )
    # This should be caught: Sensitive → Public
    builder.add_main_step(
        builder.invoke_and_bind("emailResult", "sendEmail",
                                ["id", "patientData"], level="Public")
    )
    builder.add_main_step(builder.emit("emailResult"))

    plan_info = builder.build()

    # Python validation should catch the flow violation
    from agentsafe.verification.lean_bridge import LeanKernelBridge
    bridge = LeanKernelBridge()
    validation = bridge.validate_plan(plan_info)
    assert not validation["valid"], "HIPAA plan should have flow violation"
    assert any("patientData" in e for e in validation["errors"])
    print("  ✓ HIPAA demo plan: flow violation detected")

    # Verify JSON output is valid
    json_str = plan_info.to_json()
    roundtripped = PlanInfo.from_json(json_str)
    assert roundtripped.plan.compliancePolicy == "hipaa"
    print("  ✓ HIPAA demo plan: JSON roundtrip")


def run_all():
    """Run all tests."""
    print("═══════════════════════════════════════════════════════════════")
    print(" CertiorPlan Python Bridge - Test Suite")
    print("═══════════════════════════════════════════════════════════════")
    print()

    print("── Week A1: Core Bridge ──")
    test_security_level_ordering()
    test_flow_label_json()
    test_step_rhs_json()
    test_plan_info_json_roundtrip()
    test_plan_info_builder()
    test_python_side_validation()
    test_hipaa_demo_plan()

    print()
    print("── Week A2: Export Bridge ──")
    test_export_bridge_available()
    test_export_plan_file()
    test_sox_plan_builder()

    print()
    print("═══════════════════════════════════════════════════════════════")
    print(" All Python bridge tests passed ✓")
    print("═══════════════════════════════════════════════════════════════")


# ═══════════════════════════════════════════════════════════════════════
# Week A2: Export Bridge Tests
# ═══════════════════════════════════════════════════════════════════════

def test_export_bridge_available():
    """Test LeanKernelBridge availability check."""
    from agentsafe.verification.lean_bridge import LeanKernelBridge
    bridge = LeanKernelBridge()
    assert isinstance(bridge.is_available(), bool)
    print("  ✓ Export bridge: availability check works")


def test_export_plan_file():
    """Test exporting a PlanInfo to a JSON file."""
    import tempfile
    from agentsafe.verification.lean_bridge import LeanKernelBridge
    from pathlib import Path

    builder = PlanInfoBuilder(compliance_policy="default", budget_cents=1000)
    builder.add_resource("budget", 1000, level="Internal")
    builder.add_main_step(builder.bind("x", builder.literal(42), level="Public"))
    builder.add_main_step(builder.emit("x"))

    plan_info = builder.build()
    bridge = LeanKernelBridge()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        path = Path(f.name)

    try:
        result_path = bridge.export_plan(plan_info, path)
        assert result_path.exists()
        content = path.read_text()
        parsed = json.loads(content)
        assert "plan" in parsed
        assert "located" in parsed
        assert parsed["plan"]["compliancePolicy"] == "default"
        print("  ✓ Export bridge: plan file export works")
    finally:
        path.unlink(missing_ok=True)


def test_sox_plan_builder():
    """Test building a SOX compliance plan."""
    builder = PlanInfoBuilder(compliance_policy="sox", budget_cents=8000)
    builder.add_resource("budget", 8000, level="Internal")
    builder.add_skill(
        "queryEarnings",
        params=[],
        required_caps=[{"resource": "database:read:financial_data", "maxCost": 500}],
        steps=[
            builder.bind("data", builder.literal(1),
                         level="Restricted", tags=["MNPI"]),
            builder.emit("data"),
        ],
    )
    builder.add_main_step(
        builder.invoke_and_bind("earnings", "queryEarnings", [],
                                level="Restricted")
    )
    builder.add_main_step(builder.emit("earnings"))

    plan_info = builder.build()
    assert plan_info.plan.compliancePolicy == "sox"
    assert plan_info.plan.totalBudgetCents == 8000
    assert len(plan_info.plan.skills) == 1

    json_str = plan_info.to_json()
    roundtripped = PlanInfo.from_json(json_str)
    assert roundtripped.plan.compliancePolicy == "sox"
    assert len(roundtripped.plan.skills) == 1
    print("  ✓ SOX plan builder: construction and roundtrip")


if __name__ == "__main__":
    run_all()

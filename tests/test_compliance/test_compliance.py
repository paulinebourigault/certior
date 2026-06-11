"""Tests for agentsafe.compliance - presets and exporter."""
import time
import pytest
from agentsafe.compliance import (
    CompliancePresets,
    ComplianceConfig,
    ComplianceExporter,
    CompliancePackage,
    AuditEntry,
    FlowRule,
    AuditConfig,
    VerificationProfileResolver,
)
from agentsafe.cloud.state_store import Execution, ExecutionStatus


# ── FlowRule ──

class TestFlowRule:
    def test_allows_when_in_allowed_list(self):
        rule = FlowRule(source="PHI", allowed_destinations=["internal"])
        assert rule.allows("internal") is True
        assert rule.allows("external") is False

    def test_forbids_explicit(self):
        rule = FlowRule(source="MNPI", forbidden_destinations=["public"])
        assert rule.allows("public") is False
        assert rule.allows("internal") is True

    def test_allows_anything_when_no_lists(self):
        rule = FlowRule(source="any")
        assert rule.allows("wherever") is True

    def test_forbidden_takes_precedence(self):
        rule = FlowRule(
            source="x",
            allowed_destinations=["a", "b"],
            forbidden_destinations=["b"],
        )
        assert rule.allows("a") is True
        assert rule.allows("b") is False


# ── AuditConfig ──

class TestAuditConfig:
    def test_retention_years(self):
        cfg = AuditConfig(retention_days=2190)
        assert cfg.retention_years == 6.0

    def test_defaults(self):
        cfg = AuditConfig()
        assert cfg.log_all_access is True
        assert cfg.segregation_of_duties is False


# ── ComplianceConfig ──

class TestComplianceConfig:
    def test_requires_approval(self):
        config = ComplianceConfig(
            name="test",
            human_approvals=["send_email"],
        )
        assert config.requires_approval("send_email") is True
        assert config.requires_approval("read_data") is False

    def test_permission_allowed(self):
        config = ComplianceConfig(
            name="test",
            forbidden_permissions=["network:smtp:send:external"],
        )
        assert config.permission_allowed("database:read") is True
        assert config.permission_allowed("network:smtp:send:external") is False

    def test_permission_wildcard_forbidden(self):
        config = ComplianceConfig(
            name="test",
            forbidden_permissions=["network:*"],
        )
        assert config.permission_allowed("network:http:read") is False
        assert config.permission_allowed("database:read") is True

    def test_flow_allowed(self):
        config = ComplianceConfig(
            name="test",
            information_flow_rules=[
                FlowRule(source="PHI", forbidden_destinations=["external"]),
            ],
        )
        assert config.flow_allowed("PHI", "internal") is True
        assert config.flow_allowed("PHI", "external") is False
        # No rule for source "general" → allowed by default
        assert config.flow_allowed("general", "anywhere") is True

    def test_to_dict(self):
        config = ComplianceConfig(
            name="test",
            permissions=["a"],
            required_proofs=["p1"],
        )
        d = config.to_dict()
        assert d["name"] == "test"
        assert d["permissions"] == ["a"]
        assert d["required_proofs"] == ["p1"]


# ── CompliancePresets ──

class TestCompliancePresets:
    def test_hipaa(self):
        cfg = CompliancePresets.hipaa()
        assert cfg.name == "HIPAA"
        assert cfg.audit.retention_days == 2190
        assert cfg.audit.tamper_proof is True
        assert "no_phi_external_flow" in cfg.required_proofs
        assert "export_patient_data" in cfg.human_approvals
        assert cfg.flow_allowed("PHI", "internal") is True
        assert cfg.flow_allowed("PHI", "external") is False

    def test_sox(self):
        cfg = CompliancePresets.sox()
        assert cfg.name == "SOX"
        assert cfg.audit.retention_days == 2555
        assert cfg.audit.segregation_of_duties is True
        assert "no_mnpi_leak" in cfg.required_proofs
        assert cfg.flow_allowed("MNPI", "internal_finance") is True
        assert cfg.flow_allowed("MNPI", "external") is False

    def test_legal(self):
        cfg = CompliancePresets.legal_privilege()
        assert cfg.name == "Legal Privilege"
        assert "no_privilege_waiver" in cfg.required_proofs
        assert "send_email" in cfg.human_approvals
        assert cfg.flow_allowed("PRIVILEGED", "legal_team") is True
        assert cfg.flow_allowed("PRIVILEGED", "opposing_party") is False

    def test_default(self):
        cfg = CompliancePresets.default()
        assert cfg.name == "Default"
        assert "*" in cfg.permissions

    def test_get_by_name(self):
        assert CompliancePresets.get("hipaa").name == "HIPAA"
        assert CompliancePresets.get("sox").name == "SOX"
        assert CompliancePresets.get("LEGAL").name == "Legal Privilege"
        assert CompliancePresets.get("legal_privilege").name == "Legal Privilege"
        assert CompliancePresets.get("Default").name == "Default"

    def test_get_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown compliance preset"):
            CompliancePresets.get("gdpr")

    def test_available(self):
        avail = CompliancePresets.available()
        assert "hipaa" in avail
        assert "sox" in avail
        assert "default" in avail


# ── AuditEntry ──

class TestAuditEntry:
    def test_to_dict(self):
        e = AuditEntry(actor="agent-1", action="read", resource="db")
        d = e.to_dict()
        assert d["actor"] == "agent-1"
        assert d["action"] == "read"
        assert "timestamp" in d


# ── CompliancePackage ──

class TestCompliancePackage:
    def test_to_dict(self):
        p = CompliancePackage(
            package_id="pkg-1",
            compliance_regime="HIPAA",
            verification_runtime={"lean_status": "active", "mode": "dual_proof"},
        )
        d = p.to_dict()
        assert d["package_id"] == "pkg-1"
        assert d["compliance_regime"] == "HIPAA"
        assert d["verification_runtime"]["lean_status"] == "active"

    def test_to_json(self):
        p = CompliancePackage(package_id="pkg-1", compliance_regime="SOX")
        j = p.to_json()
        import json
        parsed = json.loads(j)
        assert parsed["compliance_regime"] == "SOX"


# ── ComplianceExporter ──

class TestComplianceExporter:
    def _make_execution(self, status=ExecutionStatus.COMPLETED):
        return Execution(
            id="exec-1",
            user_id="user-1",
            task="Analyse patient data",
            status=status,
            cost_cents=500,
            certificates=[
                {
                    "id": "cert-a",
                    "verified_properties": [
                        "no_phi_external_flow",
                        "minimum_necessary_access",
                    ],
                },
                {
                    "id": "cert-b",
                    "verified_properties": ["authorized_user_only"],
                },
            ],
            completed_at=time.time(),
        )

    def test_export_completed(self):
        config = CompliancePresets.hipaa()
        exporter = ComplianceExporter(config)
        execution = self._make_execution()

        trail = [
            AuditEntry(actor="planner", action="plan"),
            AuditEntry(actor="executor", action="execute"),
        ]

        package = exporter.export(execution, audit_trail=trail)
        assert package.compliance_regime == "HIPAA"
        assert package.execution_summary["execution_id"] == "exec-1"
        assert len(package.certificates) == 2
        assert len(package.audit_trail) == 2
        assert package.attestation["compliant"] is True
        assert len(package.attestation["proofs_satisfied"]) == 3

    def test_export_failed_not_compliant(self):
        config = CompliancePresets.hipaa()
        exporter = ComplianceExporter(config)
        execution = self._make_execution(status=ExecutionStatus.FAILED)

        package = exporter.export(execution)
        assert package.attestation["compliant"] is False
        assert len(package.attestation["proofs_missing"]) == 3

    def test_attestation_requires_matching_evidence(self):
        config = CompliancePresets.hipaa()
        exporter = ComplianceExporter(config)
        execution = Execution(
            id="exec-strict",
            user_id="user-1",
            task="Analyse patient data",
            status=ExecutionStatus.COMPLETED,
            certificates=["cert-id-only"],
            completed_at=time.time(),
        )

        package = exporter.export(execution)
        assert package.attestation["compliant"] is False
        assert sorted(package.attestation["proofs_missing"]) == sorted(config.required_proofs)

    def test_flow_analysis_no_records(self):
        config = CompliancePresets.sox()
        exporter = ComplianceExporter(config)
        execution = self._make_execution()
        package = exporter.export(execution)
        assert package.flow_analysis["violations_detected"] == 0

    def test_flow_analysis_with_violations(self):
        config = CompliancePresets.sox()
        exporter = ComplianceExporter(config)
        execution = self._make_execution()
        flows = [
            {"source": "MNPI", "dest": "external", "violation": True},
            {"source": "public", "dest": "internal", "violation": False},
        ]
        package = exporter.export(execution, flow_records=flows)
        assert package.flow_analysis["violations_detected"] == 1
        assert package.flow_analysis["flows_tracked"] == 2

    def test_export_with_safety_scans(self):
        config = CompliancePresets.hipaa()
        exporter = ComplianceExporter(config)
        execution = self._make_execution()
        scans = [{"type": "pii", "found": 2, "redacted": True}]
        package = exporter.export(execution, safety_scans=scans)
        assert len(package.safety_scans) == 1

    def test_validate_retention_within_window(self):
        config = CompliancePresets.hipaa()
        exporter = ComplianceExporter(config)
        execution = self._make_execution()
        assert exporter.validate_retention(execution) is True

    def test_validate_retention_expired(self):
        config = ComplianceConfig(
            name="short",
            audit=AuditConfig(retention_days=0),
        )
        exporter = ComplianceExporter(config)
        execution = self._make_execution()
        execution.completed_at = time.time() - 86400 * 2  # 2 days ago
        assert exporter.validate_retention(execution) is False

    def test_validate_retention_no_completed_at(self):
        config = CompliancePresets.hipaa()
        exporter = ComplianceExporter(config)
        execution = self._make_execution()
        execution.completed_at = None
        assert exporter.validate_retention(execution) is True

    def test_policy_applied_in_package(self):
        config = CompliancePresets.sox()
        exporter = ComplianceExporter(config)
        execution = self._make_execution()
        package = exporter.export(execution)
        assert package.policy_applied["name"] == "SOX"
        assert "no_mnpi_leak" in package.policy_applied["required_proofs"]

    def test_package_json_roundtrip(self):
        config = CompliancePresets.legal_privilege()
        exporter = ComplianceExporter(config)
        execution = self._make_execution()
        package = exporter.export(execution)
        import json
        parsed = json.loads(package.to_json())
        assert parsed["compliance_regime"] == "Legal Privilege"
        assert parsed["attestation"]["regime"] == "Legal Privilege"

    def test_export_derives_runtime_evidence_from_results(self):
        config = CompliancePresets.hipaa()
        exporter = ComplianceExporter(config)
        execution = self._make_execution()
        execution.certificates = []
        execution.results = {
            "output": "Reviewed successfully",
            "steps": [
                {
                    "step_index": 1,
                    "tool_name": "database_query",
                    "tool_output": "ok",
                    "verified": True,
                    "certificate_id": "cert-step-1",
                    "verification_properties": [
                        "capability_coverage: proven",
                        "budget_sufficient: proven",
                    ],
                    "content_scan": {
                        "tool_name": "database_query",
                        "step_index": 1,
                        "blocked": False,
                        "any_violations": True,
                        "output_scan": {
                            "phase": "output",
                            "action": "redact",
                            "clean": False,
                            "violation_count": 1,
                            "pii_count": 1,
                            "secrets_count": 0,
                        },
                    },
                    "ifc": {
                        "effective_level": "phi",
                        "promoted": True,
                        "flow_blocked": False,
                    },
                    "lean_verification": {"proven": True, "detail": "ok"},
                    "lean_proven": True,
                }
            ],
            "audit_trail": [
                {"timestamp": time.time(), "action": "verification", "result": "ok"}
            ],
            "ifc_summary": {
                "flows_checked": 1,
                "flows_blocked": 0,
                "violations": [],
            },
            "lean_verification_summary": {
                "lean_kernel_available": True,
                "steps_checked": 1,
                "flow_violations": 0,
            },
            "content_safety_summary": {
                "violations_total": 1,
            },
            "lean_certificates": [
                {
                    "step_id": "step_1_database_query",
                    "property": "flow_safe",
                    "detail": "PHI can flow to internal review context",
                    "input_labels": ["Sensitive"],
                    "output_label": "Internal",
                }
            ],
            "verification_profile": {
                "stage_role": "reviewer",
                "required_proofs": ["capability_coverage", "information_flow"],
            },
        }

        package = exporter.export(execution)

        assert package.execution_summary["output_preview"] == "Reviewed successfully"
        assert len(package.certificates) == 2
        assert package.certificates[0]["id"] == "cert-step-1"
        assert len(package.safety_scans) == 1
        assert package.flow_analysis["flows_tracked"] == 1
        assert len(package.audit_trail) == 1
        assert "information_flow: proven" in package.attestation["verified_properties"]
        assert any(cert["type"] == "lean_flow_certificate" for cert in package.certificates)
        assert package.execution_summary["verification_profile"]["stage_role"] == "reviewer"
        assert package.verification_runtime["lean_status"] == "active"
        assert package.verification_runtime["mode"] == "dual_proof"

    def test_export_marks_lean_runtime_unavailable_from_audit(self):
        config = CompliancePresets.hipaa()
        exporter = ComplianceExporter(config)
        execution = self._make_execution()
        execution.results = {
            "audit_trail": [
                {
                    "phase": "verification_strategy_selected",
                    "timestamp": time.time(),
                },
                {
                    "phase": "lean_kernel_unavailable",
                    "mode": "z3_only",
                    "timestamp": time.time(),
                },
            ],
        }

        package = exporter.export(execution)

        assert package.verification_runtime["lean_status"] == "unavailable"
        assert package.verification_runtime["mode"] == "z3_only"
        assert "Z3-only" in package.verification_runtime["detail"]

    def test_attestation_maps_runtime_evidence_to_hipaa_proofs(self):
        config = CompliancePresets.hipaa()
        exporter = ComplianceExporter(config)
        execution = self._make_execution()
        execution.certificates = []
        execution.results = {
            "steps": [
                {
                    "step_index": 1,
                    "tool_name": "database_query",
                    "verified": True,
                    "certificate_id": "cert-step-1",
                    "verification_properties": [
                        "capability_coverage: proven",
                        "budget_sufficient: proven",
                    ],
                    "ifc": {
                        "effective_level": "phi",
                        "promoted": True,
                        "flow_blocked": False,
                    },
                    "lean_verification": {"proven": True},
                    "lean_proven": True,
                }
            ],
            "ifc_summary": {
                "flows_checked": 1,
                "flows_blocked": 0,
                "violations": [],
            },
            "lean_verification_summary": {
                "lean_kernel_available": True,
                "steps_checked": 1,
                "flow_violations": 0,
            },
            "lean_certificates": [
                {
                    "step_id": "step_1_database_query",
                    "property": "flow_safe",
                    "detail": "PHI remains contained in internal workflow",
                    "input_labels": ["PHI"],
                    "output_label": "Internal",
                }
            ],
            "verification_profile": {
                "stage_role": "clinical_intake",
                "required_proofs": ["phi_stage_contained", "minimum_necessary_access"],
            },
        }

        package = exporter.export(execution)

        assert package.attestation["certificate_count"] == 2
        assert package.attestation["compliant"] is True
        assert "phi_stage_contained" in package.attestation["proofs_satisfied"]
        assert "minimum_necessary_access" in package.attestation["proofs_satisfied"]

    def test_export_includes_dafny_and_sandbox_runtime_evidence(self):
        config = CompliancePresets.default()
        exporter = ComplianceExporter(config)
        execution = self._make_execution()
        execution.certificates = []
        execution.results = {
            "steps": [
                {
                    "step_index": 1,
                    "tool_name": "python_eval",
                    "tool_output": "ok",
                    "verified": True,
                    "verification_properties": ["capability_coverage: proven"],
                    "tool_metadata": {
                        "sandbox_audit": {
                            "timestamp": time.time(),
                            "policy_name": "HIPAA",
                            "is_error": False,
                            "active_layers": ["python_sandbox", "seccomp_bpf"],
                        },
                        "seccomp_verified": {
                            "profile_name": "network_blocked",
                            "proof_certificate": {
                                "certificate_id": "dafny-cert-1",
                                "profile_name": "network_blocked",
                                "verified_properties": ["P34", "P35"],
                                "instruction_count": 10,
                                "syscall_count": 4,
                                "alignment_report": {"all_passed": True, "results": []},
                            },
                            "compliance_certificate": {
                                "certificate_id": "seccomp-cert-1",
                                "profile_name": "network_blocked",
                                "regime": "hipaa",
                                "all_passed": True,
                                "requirements": [],
                                "dafny_properties_verified": ["P34", "P35"],
                            },
                        },
                    },
                }
            ],
        }

        package = exporter.export(execution)
        certificate_ids = {cert["id"] for cert in package.certificates}
        assert "dafny-cert-1" in certificate_ids
        assert "seccomp-cert-1" in certificate_ids
        assert any(entry["actor"] == "sandbox" for entry in package.audit_trail)


class TestVerificationProfileResolver:
    def test_resolves_reviewer_profile(self):
        resolver = VerificationProfileResolver()
        policy = CompliancePresets.legal_privilege()
        profile = resolver.resolve(
            policy=policy,
            task="Review clinical intake note for privilege leakage and return GO/NO-GO.",
            task_class="privacy_review",
            stage_role="reviewer",
            stage_id="review",
            upstream_execution_ids=["exec-intake"],
        )

        composed = profile.compose(policy)
        assert composed["stage_role"] == "reviewer"
        assert composed["release_targets"] == ["internal"]
        assert "privilege_boundary_reviewed" in composed["required_proofs"]

    def test_resolves_public_safe_summary_profile(self):
        resolver = VerificationProfileResolver()
        policy = CompliancePresets.hipaa()
        profile = resolver.resolve(
            policy=policy,
            task=(
                "Summarize the patient encounter into a discharge summary, "
                "redact all direct patient identifiers, and apply minimum-necessary principle."
            ),
        )

        composed = profile.compose(policy)
        assert composed["task_class"] == "public_safe_summary"
        assert composed["stage_role"] == "single_agent"
        assert composed["release_targets"] == ["public"]
        assert "phi_stage_contained" not in composed["required_proofs"]
        assert "output_deidentification_verified" in composed["required_proofs"]
        assert "compute:python:eval" in composed["permission_ceiling"]

    def test_resolves_clinical_intake_profile_with_compute(self):
        resolver = VerificationProfileResolver()
        policy = CompliancePresets.hipaa()
        profile = resolver.resolve(
            policy=policy,
            task_class="clinical_intake",
            stage_role="single_agent",
            stage_id="intake-analysis",
            task="Read the patient chart and compute internal triage statistics.",
        )

        composed = profile.compose(policy)
        assert composed["task_class"] == "clinical_intake"
        assert composed["release_targets"] == ["internal"]
        assert "compute:python:eval" in composed["permission_ceiling"]

    def test_resolves_protected_release_profile(self):
        resolver = VerificationProfileResolver()
        policy = CompliancePresets.hipaa()
        profile = resolver.resolve(
            policy=policy,
            task=(
                "Read the patient encounter and publish the full raw patient note "
                "to a public website so external users can access it."
            ),
        )

        composed = profile.compose(policy)
        assert composed["task_class"] == "protected_release"
        assert composed["stage_role"] == "release"
        assert composed["sandbox_profile"] == "phi_release_attested"
        assert "review_completed_before_release" in composed["required_proofs"]
        assert "release_output_bound_to_review_artifact" in composed["required_proofs"]
        assert "send_external_communication" in composed["required_approvals"]

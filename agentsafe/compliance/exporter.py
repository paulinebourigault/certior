"""
Compliance audit package exporter.

Generates structured audit packages that include:
  - Execution metadata (task, timestamps, status)
  - Proof certificates with verified properties
  - Content safety scan results
  - Information flow analysis
  - Compliance policy applied
  - Full audit trail

Output is a JSON-serializable dict suitable for PDF rendering,
regulatory submission, or archival.
"""
from __future__ import annotations
import json
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from dataclasses import dataclass, field

from .presets import ComplianceConfig

if TYPE_CHECKING:
    from agentsafe.cloud.state_store import Execution


@dataclass
class AuditEntry:
    """A single entry in the audit trail."""
    timestamp: float = field(default_factory=time.time)
    actor: str = ""
    action: str = ""
    resource: str = ""
    result: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "result": self.result,
            "details": self.details,
        }


@dataclass
class CompliancePackage:
    """Complete audit package for regulatory export."""
    package_id: str = ""
    generated_at: float = field(default_factory=time.time)
    compliance_regime: str = ""
    execution_summary: Dict[str, Any] = field(default_factory=dict)
    certificates: List[Dict[str, Any]] = field(default_factory=list)
    safety_scans: List[Dict[str, Any]] = field(default_factory=list)
    flow_analysis: Dict[str, Any] = field(default_factory=dict)
    verification_runtime: Dict[str, Any] = field(default_factory=dict)
    policy_applied: Dict[str, Any] = field(default_factory=dict)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    attestation: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_id": self.package_id,
            "generated_at": self.generated_at,
            "compliance_regime": self.compliance_regime,
            "execution_summary": self.execution_summary,
            "certificates": self.certificates,
            "safety_scans": self.safety_scans,
            "flow_analysis": self.flow_analysis,
            "verification_runtime": self.verification_runtime,
            "policy_applied": self.policy_applied,
            "audit_trail": self.audit_trail,
            "attestation": self.attestation,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


class ComplianceExporter:
    """
    Builds compliance packages from execution data.

    Usage:
        exporter = ComplianceExporter(CompliancePresets.hipaa())
        package = exporter.export(execution, audit_trail=trail)
        json_str = package.to_json()
    """

    def __init__(self, config: ComplianceConfig):
        self.config = config

    def export(
        self,
        execution: Execution,
        audit_trail: Optional[List[AuditEntry]] = None,
        certificates: Optional[List[Dict[str, Any]]] = None,
        safety_scans: Optional[List[Dict[str, Any]]] = None,
        flow_records: Optional[List[Dict[str, Any]]] = None,
    ) -> CompliancePackage:
        """
        Build a compliance package from execution data.

        Args:
            execution: The completed execution record.
            audit_trail: Ordered list of audit entries.
            certificates: Proof certificate dicts.
            safety_scans: Content safety scan results.
            flow_records: Information flow tracking records.

        Returns:
            CompliancePackage ready for export.
        """
        import uuid

        package = CompliancePackage(
            package_id=str(uuid.uuid4()),
            compliance_regime=self.config.name,
        )
        results = execution.results if isinstance(execution.results, dict) else {}

        # Execution summary
        package.execution_summary = {
            "execution_id": execution.id,
            "task": execution.task,
            "user_id": execution.user_id,
            "status": execution.status.value if hasattr(execution.status, "value") else str(execution.status),
            "created_at": execution.created_at,
            "completed_at": execution.completed_at,
            "cost_cents": execution.cost_cents,
            "certificate_count": len(execution.certificates),
        }
        verification_profile = self._extract_verification_profile(execution, results)
        if verification_profile is not None:
            package.execution_summary["verification_profile"] = verification_profile
        if results.get("output"):
            package.execution_summary["output_preview"] = str(results["output"])[:2000]
        if isinstance(results.get("approved_artifact"), dict):
            artifact = results["approved_artifact"]
            package.execution_summary["approved_artifact"] = {
                "text": artifact.get("text"),
                "sha256": artifact.get("sha256"),
                "approved_for_release": artifact.get("approved_for_release"),
            }
        if isinstance(results.get("release_binding_summary"), dict):
            package.execution_summary["release_binding_summary"] = results["release_binding_summary"]
        if results.get("lean_verification_summary"):
            package.execution_summary["lean_verification_summary"] = results["lean_verification_summary"]
        if results.get("content_safety_summary"):
            package.execution_summary["content_safety_summary"] = results["content_safety_summary"]

        # Certificates
        package.certificates = certificates or self._extract_certificates(execution, results)

        # Safety scans
        package.safety_scans = safety_scans or self._extract_safety_scans(results)

        # Flow analysis
        package.flow_analysis = self._build_flow_analysis(flow_records, results)

        # Audit trail
        resolved_audit_trail = audit_trail if audit_trail is not None else self._extract_audit_trail(results)
        if resolved_audit_trail:
            package.audit_trail = [
                e.to_dict() if isinstance(e, AuditEntry) else e
                for e in resolved_audit_trail
            ]

        package.verification_runtime = self._build_verification_runtime(results, package.audit_trail)

        # Policy applied
        package.policy_applied = self.config.to_dict()
        if verification_profile is not None:
            package.policy_applied["verification_profile"] = verification_profile

        # Attestation
        package.attestation = self._build_attestation(execution, package.certificates, results)

        return package

    def _build_verification_runtime(
        self,
        results: Dict[str, Any],
        audit_trail: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Summarise whether Lean ran in dual-proof mode or fell back."""
        lean_summary = results.get("lean_verification_summary")
        if not isinstance(lean_summary, dict):
            lean_summary = {}

        started_event = next(
            (
                entry for entry in audit_trail
                if isinstance(entry, dict) and entry.get("phase") == "lean_kernel_started"
            ),
            None,
        )
        unavailable_event = next(
            (
                entry for entry in audit_trail
                if isinstance(entry, dict) and entry.get("phase") == "lean_kernel_unavailable"
            ),
            None,
        )

        if isinstance(started_event, dict):
            status = "active"
            mode = str(started_event.get("mode") or "dual_proof")
        elif isinstance(unavailable_event, dict):
            status = "unavailable"
            mode = str(unavailable_event.get("mode") or "z3_only")
        elif lean_summary.get("lean_kernel_available") is True:
            status = "active"
            mode = "dual_proof"
        elif lean_summary:
            status = "unavailable"
            mode = "z3_only"
        else:
            status = "unknown"
            mode = "unknown"

        steps_checked = int(lean_summary.get("steps_checked", 0) or 0)
        certificates_issued = int(lean_summary.get("certificates_issued", 0) or 0)
        flow_violations = int(lean_summary.get("flow_violations", 0) or 0)

        if status == "active" and steps_checked == 0:
            detail = "Lean kernel active; no flow checks were required for this execution."
        elif status == "active":
            detail = f"Lean kernel active in {mode.replace('_', '-')} mode with {steps_checked} flow check(s)."
        elif status == "unavailable":
            detail = "Lean kernel unavailable; execution fell back to Z3-only verification."
        else:
            detail = "Lean verification status was not recorded for this execution."

        return {
            "lean_status": status,
            "mode": mode,
            "detail": detail,
            "binary": lean_summary.get("binary_path") or (started_event or {}).get("binary"),
            "steps_checked": steps_checked,
            "certificates_issued": certificates_issued,
            "flow_violations": flow_violations,
            "total_requests": int(lean_summary.get("total_requests", 0) or 0),
            "avg_latency_ms": lean_summary.get("avg_latency_ms", 0.0) or 0.0,
        }

    def _build_flow_analysis(
        self,
        records: Optional[List[Dict[str, Any]]],
        results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Summarise information flow for the compliance package."""
        if not records:
            records = self._extract_flow_records(results or {})

        if not records:
            ifc_summary = (results or {}).get("ifc_summary", {})
            return {
                "rules_enforced": len(self.config.information_flow_rules),
                "violations_detected": int(ifc_summary.get("flows_blocked", 0)),
                "flows_tracked": int(ifc_summary.get("flows_checked", 0)),
            }

        violations = [r for r in records if r.get("violation")]
        return {
            "rules_enforced": len(self.config.information_flow_rules),
            "flows_tracked": len(records),
            "violations_detected": len(violations),
            "violation_details": violations,
        }

    def _build_attestation(
        self,
        execution: Execution,
        certificates: Optional[List[Dict[str, Any]]] = None,
        results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Machine-readable compliance attestation.

        Checks actual proof certificates against required proofs.
        A proof is satisfied if ANY certificate's verified_properties
        contain a matching entry.
        """
        proofs_satisfied = []
        proofs_missing = []
        results = results or {}
        resolved_certificates = list(certificates or [])

        # Collect all verified properties from certificates
        cert_properties: set = set()
        for cert in (resolved_certificates or execution.certificates or []):
            if isinstance(cert, dict):
                for prop in cert.get("verified_properties", []):
                    cert_properties.add(prop)
            elif isinstance(cert, str):
                # Certificate ID only - check results for details
                pass

        # Also pull properties from step results if available
        for step in results.get("steps", []):
            if not isinstance(step, dict):
                continue
            for prop in step.get("verification_properties", []):
                cert_properties.add(prop)
            if step.get("lean_proven") or (
                isinstance(step.get("lean_verification"), dict)
                and step["lean_verification"].get("proven")
            ):
                cert_properties.add("information_flow: proven")
            if step.get("verified"):
                if isinstance(step, dict) and step.get("verified"):
                    cert_properties.add("capability_coverage: proven")
                    cert_properties.add("budget_sufficient: proven")

        lean_summary = results.get("lean_verification_summary", {})
        if lean_summary.get("steps_checked", 0) > 0 and lean_summary.get("flow_violations", 0) == 0:
            cert_properties.add("information_flow: proven")

        ifc_summary = results.get("ifc_summary", {})
        if ifc_summary.get("flows_checked", 0) > 0 and ifc_summary.get("flows_blocked", 0) == 0:
            cert_properties.add("information_flow: proven")

        for step in results.get("steps", []):
            if not isinstance(step, dict):
                continue
            tool_metadata = step.get("tool_metadata")
            if not isinstance(tool_metadata, dict):
                continue
            sandbox_audit = tool_metadata.get("sandbox_audit")
            if isinstance(sandbox_audit, dict) and not sandbox_audit.get("is_error"):
                cert_properties.add("sandbox_containment: proven")
            network_audit = tool_metadata.get("network_audit")
            if isinstance(network_audit, dict):
                if network_audit.get("blocked"):
                    cert_properties.add("external_network_restricted: proven")
                else:
                    cert_properties.add("network_policy_enforced: proven")
            seccomp_verified = tool_metadata.get("seccomp_verified")
            if isinstance(seccomp_verified, dict):
                compliance_certificate = seccomp_verified.get("compliance_certificate")
                if isinstance(compliance_certificate, dict) and compliance_certificate.get("all_passed"):
                    cert_properties.add("sandbox_containment: proven")

        cert_properties |= self._derive_policy_proofs(cert_properties)

        required_proofs = self._required_proofs(results, execution)
        execution_status = (
            execution.status.value if hasattr(execution.status, "value") else str(execution.status)
        )

        if execution_status != "completed":
            return {
                "regime": self.config.name,
                "retention_days": self.config.audit.retention_days,
                "proofs_required": required_proofs,
                "proofs_satisfied": [],
                "proofs_missing": required_proofs,
                "human_approvals_required": self._required_approvals(results, execution),
                "certificate_count": len(resolved_certificates),
                "verified_properties": sorted(cert_properties),
                "compliant": False,
            }

        for proof in required_proofs:
            # Match proof name against certificate properties
            matched = any(
                proof in prop or prop.startswith(proof.split("_")[0])
                for prop in cert_properties
            )
            if matched:
                proofs_satisfied.append(proof)
            else:
                proofs_missing.append(proof)

        return {
            "regime": self.config.name,
            "retention_days": self.config.audit.retention_days,
            "proofs_required": required_proofs,
            "proofs_satisfied": proofs_satisfied,
            "proofs_missing": proofs_missing,
            "human_approvals_required": self._required_approvals(results, execution),
            "certificate_count": len(resolved_certificates),
            "verified_properties": sorted(cert_properties),
            "compliant": len(proofs_missing) == 0,
        }

    def _derive_policy_proofs(self, cert_properties: set[str]) -> set[str]:
        """Translate generic runtime evidence into policy-level proof names."""
        derived: set[str] = set()

        if "information_flow: proven" in cert_properties:
            derived.update({
                "no_phi_external_flow",
                "phi_stage_contained",
                "no_mnpi_leak",
                "no_privilege_waiver",
            })

        if "capability_coverage: proven" in cert_properties:
            derived.update({
                "minimum_necessary_access",
                "authorized_user_only",
                "authorized_access_only",
            })

        if "budget_sufficient: proven" in cert_properties:
            derived.add("budget_sufficient")

        if "sandbox_containment: proven" in cert_properties:
            derived.add("phi_stage_contained")

        return derived

    def _extract_certificates(
        self,
        execution: Execution,
        results: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Normalise runtime evidence into exportable certificate entries."""
        resolved: List[Dict[str, Any]] = []
        by_id: Dict[str, Dict[str, Any]] = {}

        for cert in execution.certificates or []:
            if isinstance(cert, dict):
                item = dict(cert)
            else:
                item = {"id": cert, "type": "proof_certificate"}
            cert_id = str(item.get("id", ""))
            if cert_id:
                by_id[cert_id] = item
            resolved.append(item)

        for step in results.get("steps", []):
            if not isinstance(step, dict):
                continue
            cert_id = step.get("certificate_id")
            if not cert_id:
                continue
            entry = by_id.get(cert_id, step.get("verification_certificate") or {
                "id": cert_id,
                "type": "proof_certificate",
                "step_index": step.get("step_index"),
                "tool": step.get("tool_name"),
            })
            props = list(entry.get("verified_properties", []))
            for prop in step.get("verification_properties", []):
                if prop not in props:
                    props.append(prop)
            if step.get("lean_proven") and "information_flow: proven" not in props:
                props.append("information_flow: proven")
            if props:
                entry["verified_properties"] = props
            if step.get("lean_proven"):
                entry["prover"] = "z3+lean4"
            elif step.get("verified"):
                entry.setdefault("prover", "z3")
            if cert_id not in by_id:
                by_id[cert_id] = entry
                resolved.append(entry)

        for lean_cert in results.get("lean_certificates", []):
            if not isinstance(lean_cert, dict):
                continue
            step_id = str(lean_cert.get("step_id", "")) or f"lean-{len(resolved)}"
            resolved.append({
                "id": step_id,
                "type": "lean_flow_certificate",
                "prover": "lean4",
                "verified_properties": [
                    lean_cert.get("property", "information_flow: proven")
                ],
                "detail": lean_cert.get("detail", ""),
                "input_labels": lean_cert.get("input_labels", []),
                "output_label": lean_cert.get("output_label"),
            })

        for step in results.get("steps", []):
            if not isinstance(step, dict):
                continue
            tool_metadata = step.get("tool_metadata")
            if not isinstance(tool_metadata, dict):
                continue
            seccomp_verified = tool_metadata.get("seccomp_verified")
            if not isinstance(seccomp_verified, dict):
                continue

            proof_certificate = seccomp_verified.get("proof_certificate")
            if isinstance(proof_certificate, dict):
                resolved.append({
                    "id": proof_certificate.get("certificate_id", f"dafny-{len(resolved)}"),
                    "type": "dafny_proof_certificate",
                    "prover": "dafny",
                    "verified_properties": proof_certificate.get("verified_properties", []),
                    "profile_name": proof_certificate.get("profile_name"),
                    "instruction_count": proof_certificate.get("instruction_count"),
                    "syscall_count": proof_certificate.get("syscall_count"),
                    "alignment_report": proof_certificate.get("alignment_report"),
                })

            compliance_certificate = seccomp_verified.get("compliance_certificate")
            if isinstance(compliance_certificate, dict):
                resolved.append({
                    "id": compliance_certificate.get("certificate_id", f"seccomp-{len(resolved)}"),
                    "type": "seccomp_compliance_certificate",
                    "prover": "dafny+runtime",
                    "verified_properties": compliance_certificate.get("dafny_properties_verified", []),
                    "regime": compliance_certificate.get("regime"),
                    "profile_name": compliance_certificate.get("profile_name"),
                    "requirements": compliance_certificate.get("requirements", []),
                    "all_passed": compliance_certificate.get("all_passed"),
                })

        if not resolved:
            lean_summary = results.get("lean_verification_summary", {})
            if lean_summary.get("steps_checked", 0) > 0 or lean_summary.get("lean_kernel_available"):
                props: List[str] = []
                if lean_summary.get("flow_violations", 0) == 0:
                    props.append("information_flow: proven")
                resolved.append({
                    "id": f"lean-runtime-{execution.id[:8]}",
                    "type": "runtime_verification",
                    "prover": "lean4",
                    "verified_properties": props,
                })

        return resolved

    def _extract_safety_scans(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Derive content-safety evidence from persisted execution results."""
        scans: List[Dict[str, Any]] = []

        for step in results.get("steps", []):
            if not isinstance(step, dict):
                continue
            content_scan = step.get("content_scan")
            if not isinstance(content_scan, dict):
                continue
            for phase_name in ("input_scan", "output_scan"):
                phase = content_scan.get(phase_name)
                if not isinstance(phase, dict):
                    continue
                if phase.get("clean") and not phase.get("violation_count"):
                    continue
                scans.append({
                    "category": f"{step.get('tool_name', 'tool')}:{phase.get('phase', phase_name)}",
                    "severity": phase.get("action", "warn"),
                    "matched_text": (
                        f"violations={phase.get('violation_count', 0)} "
                        f"pii={phase.get('pii_count', 0)} "
                        f"secrets={phase.get('secrets_count', 0)}"
                    ),
                    "step_index": step.get("step_index"),
                })

        return scans

    def _extract_flow_records(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Derive IFC evidence from persisted execution results."""
        records: List[Dict[str, Any]] = []
        ifc_summary = results.get("ifc_summary")
        if isinstance(ifc_summary, dict):
            for violation in ifc_summary.get("violations", []):
                if isinstance(violation, dict):
                    entry = dict(violation)
                    entry["violation"] = True
                    records.append(entry)

        for step in results.get("steps", []):
            if not isinstance(step, dict):
                continue
            ifc = step.get("ifc")
            if not isinstance(ifc, dict):
                continue
            records.append({
                "step_index": step.get("step_index"),
                "tool": step.get("tool_name"),
                "effective_level": ifc.get("effective_level"),
                "violation": bool(ifc.get("flow_blocked")),
                "lean_verification": step.get("lean_verification"),
            })

        return records

    def _extract_audit_trail(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prefer stored audit events, but derive a step-level trail when absent."""
        audit_trail = results.get("audit_trail")
        derived: List[Dict[str, Any]] = []
        has_explicit_audit = isinstance(audit_trail, list) and bool(audit_trail)
        if isinstance(audit_trail, list) and audit_trail:
            derived.extend(entry for entry in audit_trail if isinstance(entry, dict))

        for step in results.get("steps", []):
            if not isinstance(step, dict):
                continue
            tool_metadata = step.get("tool_metadata")
            if not has_explicit_audit:
                derived.append({
                    "timestamp": step.get("timestamp"),
                    "actor": "agent",
                    "action": step.get("tool_name", "tool_step"),
                    "resource": step.get("tool_name", ""),
                    "result": "error" if step.get("is_error") else "verified",
                    "details": step,
                })
            if not isinstance(tool_metadata, dict):
                continue
            sandbox_audit = tool_metadata.get("sandbox_audit")
            if isinstance(sandbox_audit, dict):
                derived.append({
                    "timestamp": sandbox_audit.get("timestamp"),
                    "actor": "sandbox",
                    "action": "sandbox_execute",
                    "resource": step.get("tool_name", ""),
                    "result": "error" if sandbox_audit.get("is_error") else "contained",
                    "details": sandbox_audit,
                })
            network_audit = tool_metadata.get("network_audit")
            if isinstance(network_audit, dict):
                derived.append({
                    "timestamp": step.get("timestamp"),
                    "actor": "network_guard",
                    "action": "network_access",
                    "resource": step.get("tool_name", ""),
                    "result": "blocked" if step.get("is_error") else "allowed",
                    "details": network_audit,
                })
        return derived

    def _extract_verification_profile(
        self,
        execution: Execution,
        results: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        profile = results.get("verification_profile")
        if isinstance(profile, dict):
            return profile
        token_data = execution.token_data if isinstance(execution.token_data, dict) else {}
        profile = token_data.get("verification_profile")
        if isinstance(profile, dict):
            return profile
        metadata = token_data.get("metadata")
        if isinstance(metadata, dict):
            profile = metadata.get("verification_profile")
            if isinstance(profile, dict):
                return profile
        return None

    def _required_proofs(self, results: Dict[str, Any], execution: Execution) -> List[str]:
        profile = self._extract_verification_profile(execution, results) or {}
        required = profile.get("required_proofs")
        if isinstance(required, list) and required:
            return list(required)
        return list(self.config.required_proofs)

    def _required_approvals(self, results: Dict[str, Any], execution: Execution) -> List[str]:
        profile = self._extract_verification_profile(execution, results) or {}
        required = profile.get("required_approvals")
        if isinstance(required, list) and required:
            return list(required)
        return list(self.config.human_approvals)

    def validate_retention(self, execution: Execution) -> bool:
        """Check if execution is still within required retention window."""
        if execution.completed_at is None:
            return True
        elapsed_days = (time.time() - execution.completed_at) / 86400
        return elapsed_days <= self.config.audit.retention_days

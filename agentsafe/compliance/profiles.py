from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .presets import ComplianceConfig


@dataclass(frozen=True)
class VerificationProfile:
    """Task-adaptive verification profile composed with a compliance regime."""

    profile_name: str
    task_class: str
    stage_role: str = "single_agent"
    stage_id: str = ""
    required_proofs: List[str] = field(default_factory=list)
    required_approvals: List[str] = field(default_factory=list)
    permission_ceiling: List[str] = field(default_factory=list)
    release_targets: List[str] = field(default_factory=lambda: ["public"])
    sandbox_profile: str = "standard"
    temporal_requirements: List[str] = field(default_factory=list)
    evidence_requirements: List[str] = field(default_factory=list)
    upstream_execution_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def compose(self, policy: ComplianceConfig) -> Dict[str, Any]:
        """Compose policy ceilings with task/stage-specific requirements."""
        max_permissions = policy.max_permissions or policy.permissions
        effective_ceiling = self.permission_ceiling or list(max_permissions)
        if max_permissions and "*" not in max_permissions:
            if "*" in effective_ceiling:
                effective_ceiling = list(max_permissions)
            else:
                effective_ceiling = [
                    perm for perm in effective_ceiling
                    if perm in max_permissions
                ]
        return {
            "profile_name": self.profile_name,
            "task_class": self.task_class,
            "stage_role": self.stage_role,
            "stage_id": self.stage_id,
            "required_proofs": _ordered_union(policy.required_proofs, self.required_proofs),
            "required_approvals": _ordered_union(policy.human_approvals, self.required_approvals),
            "permission_ceiling": effective_ceiling,
            "release_targets": list(self.release_targets),
            "sandbox_profile": self.sandbox_profile,
            "temporal_requirements": list(self.temporal_requirements),
            "evidence_requirements": _ordered_union(
                ["z3_certificate", "lean_certificate", "audit_trail"],
                self.evidence_requirements,
            ),
            "upstream_execution_ids": list(self.upstream_execution_ids),
            "metadata": dict(self.metadata),
        }


class VerificationProfileResolver:
    """Resolve task-specific verification requirements from task + stage."""

    _TASK_KEYWORDS: Dict[str, List[str]] = {
        "protected_release": ["publish", "public", "external", "share", "email", "upload", "export"],
        "public_safe_summary": ["summary", "redact", "de-ident", "deidentify", "minimum-necessary"],
        "clinical_intake": ["intake", "encounter", "discharge", "patient", "clinical"],
        "privacy_review": ["review", "privilege", "phi", "privacy", "go/no-go", "go no-go"],
        "release_decision": ["release", "attestation", "publish", "export", "hold notice"],
        "financial_audit": ["expense", "quarterly", "sox", "budget", "financial", "audit"],
    }

    def resolve(
        self,
        *,
        policy: ComplianceConfig,
        task: str,
        task_class: Optional[str] = None,
        stage_role: Optional[str] = None,
        stage_id: str = "",
        upstream_execution_ids: Optional[List[str]] = None,
    ) -> VerificationProfile:
        resolved_task_class = task_class or self._infer_task_class(task)
        resolved_stage_role = stage_role or self._infer_stage_role(task, resolved_task_class)
        upstream = upstream_execution_ids or []

        profile = self._base_profile(
            task_class=resolved_task_class,
            stage_role=resolved_stage_role,
            stage_id=stage_id,
            upstream_execution_ids=upstream,
        )

        if resolved_stage_role == "release" and not upstream:
            profile.temporal_requirements.append("review_must_occur_before_release")

        return profile

    def _infer_task_class(self, task: str) -> str:
        task_lower = task.lower()
        if self._looks_like_protected_release(task_lower):
            return "protected_release"
        if self._looks_like_public_safe_summary(task_lower):
            return "public_safe_summary"
        for task_class, keywords in self._TASK_KEYWORDS.items():
            if task_class in {"public_safe_summary", "protected_release"}:
                continue
            if any(keyword in task_lower for keyword in keywords):
                return task_class
        return "general_analysis"

    def _looks_like_protected_release(self, task_lower: str) -> bool:
        has_release_verb = any(
            term in task_lower for term in (
                "publish",
                "share externally",
                "send externally",
                "email",
                "upload",
                "release publicly",
                "public website",
                "publicly",
                "external",
            )
        )
        has_sensitive_context = any(
            term in task_lower for term in (
                "patient",
                "encounter",
                "clinical",
                "phi",
                "ssn",
                "mrn",
                "medical",
                "privileged",
                "earnings",
                "mnpi",
                "raw note",
                "full note",
            )
        )
        return has_release_verb and has_sensitive_context

    def _looks_like_public_safe_summary(self, task_lower: str) -> bool:
        has_summary = any(term in task_lower for term in ("summary", "discharge", "follow-up"))
        has_redaction = any(term in task_lower for term in ("redact", "de-ident", "deidentify"))
        has_patient_context = any(term in task_lower for term in ("patient", "encounter", "clinical"))
        return has_summary and has_redaction and has_patient_context

    def _infer_stage_role(self, task: str, task_class: str) -> str:
        task_lower = task.lower()
        if task_class == "protected_release":
            return "release"
        if task_class == "public_safe_summary":
            return "single_agent"
        if task_class == "privacy_review" or any(
            term in task_lower for term in ("go/no-go", "go no-go", "privilege leakage")
        ):
            return "reviewer"
        if any(term in task_lower for term in ("release", "publish", "attestation", "hold notice")):
            return "release"
        if task_class in {"clinical_intake", "financial_audit"}:
            return "intake"
        return "single_agent"

    def _base_profile(
        self,
        *,
        task_class: str,
        stage_role: str,
        stage_id: str,
        upstream_execution_ids: List[str],
    ) -> VerificationProfile:
        profile_name = f"{task_class}:{stage_role}"

        if task_class == "protected_release":
            return VerificationProfile(
                profile_name=profile_name,
                task_class=task_class,
                stage_role=stage_role,
                stage_id=stage_id,
                required_proofs=[
                    "release_gate_satisfied",
                    "review_completed_before_release",
                    "no_phi_external_flow",
                    "output_deidentification_verified",
                    "release_output_bound_to_review_artifact",
                ],
                required_approvals=[
                    "send_external_communication",
                    "export_patient_data",
                    "data_export",
                ],
                permission_ceiling=[
                    "document:read:reports",
                    "document:write:reports",
                    "database:read:patient_data",
                    "database:read:clinical_data",
                    "filesystem:read",
                    "filesystem:write:reports",
                ],
                release_targets=["public"],
                sandbox_profile="phi_release_attested",
                temporal_requirements=[
                    "review_must_occur_before_release",
                    "deidentification_must_precede_release",
                ],
                evidence_requirements=[
                    "approval_summary",
                    "content_safety_summary",
                    "lean_certificate",
                    "z3_certificate",
                ],
                upstream_execution_ids=upstream_execution_ids,
                metadata={"delivery_mode": "reviewed_protected_release"},
            )

        if stage_role == "reviewer":
            return VerificationProfile(
                profile_name=profile_name,
                task_class=task_class,
                stage_role=stage_role,
                stage_id=stage_id,
                required_proofs=["review_chain_integrity", "privilege_boundary_reviewed"],
                required_approvals=["send_external_communication"],
                permission_ceiling=[
                    "document:read:legal_docs",
                    "document:read:reports",
                    "document:write:reports",
                    "database:read:patient_data",
                    "database:read:financial_data",
                ],
                release_targets=["internal"],
                sandbox_profile="reviewer_restricted",
                temporal_requirements=["review_artifact_must_reference_prior_stage"],
                evidence_requirements=["approval_summary", "ifc_summary"],
                upstream_execution_ids=upstream_execution_ids,
            )

        if stage_role == "release":
            return VerificationProfile(
                profile_name=profile_name,
                task_class=task_class,
                stage_role=stage_role,
                stage_id=stage_id,
                required_proofs=["release_gate_satisfied", "review_completed_before_release"],
                required_approvals=["data_export", "send_external_communication"],
                permission_ceiling=[
                    "document:read:reports",
                    "document:write:reports",
                    "document:read:legal_docs",
                    "filesystem:write:reports",
                ],
                release_targets=["public"],
                sandbox_profile="release_attested",
                temporal_requirements=["review_must_occur_before_release"],
                evidence_requirements=["approval_summary", "lean_certificate", "z3_certificate"],
                upstream_execution_ids=upstream_execution_ids,
            )

        if task_class == "clinical_intake":
            return VerificationProfile(
                profile_name=profile_name,
                task_class=task_class,
                stage_role=stage_role,
                stage_id=stage_id,
                required_proofs=["phi_stage_contained", "minimum_necessary_access"],
                required_approvals=["export_patient_data"],
                permission_ceiling=[
                    "database:read:patient_data",
                    "database:read:clinical_data",
                    "document:write:reports",
                    "filesystem:read",
                    "filesystem:write:reports",
                    "compute:python:eval",
                ],
                release_targets=["internal"],
                sandbox_profile="phi_internal_only",
                evidence_requirements=["content_safety_summary", "lean_certificate"],
                upstream_execution_ids=upstream_execution_ids,
            )

        if task_class == "public_safe_summary":
            return VerificationProfile(
                profile_name=profile_name,
                task_class=task_class,
                stage_role=stage_role,
                stage_id=stage_id,
                required_proofs=[
                    "no_phi_external_flow",
                    "minimum_necessary_access",
                    "authorized_user_only",
                    "output_deidentification_verified",
                ],
                required_approvals=["data_export"],
                permission_ceiling=[
                    "database:read:patient_data",
                    "database:read:clinical_data",
                    "document:write:reports",
                    "filesystem:read",
                    "filesystem:write:reports",
                    "compute:python:eval",
                ],
                release_targets=["public"],
                sandbox_profile="phi_public_summary",
                evidence_requirements=["content_safety_summary", "lean_certificate", "z3_certificate"],
                upstream_execution_ids=upstream_execution_ids,
                metadata={"delivery_mode": "redacted_public_summary"},
            )

        if task_class == "financial_audit":
            return VerificationProfile(
                profile_name=profile_name,
                task_class=task_class,
                stage_role=stage_role,
                stage_id=stage_id,
                required_proofs=["segregation_of_duties", "budget_sufficient"],
                required_approvals=["modify_financial_records"],
                permission_ceiling=[
                    "database:read:financial_data",
                    "database:read:audit_logs",
                    "document:write:reports",
                    "document:read:reports",
                ],
                release_targets=["internal_finance"],
                sandbox_profile="sox_audit",
                evidence_requirements=["audit_trail", "lean_certificate"],
                upstream_execution_ids=upstream_execution_ids,
            )

        return VerificationProfile(
            profile_name=profile_name,
            task_class=task_class,
            stage_role=stage_role,
            stage_id=stage_id,
            required_proofs=["capability_coverage"],
            permission_ceiling=["*"],
            release_targets=["public"],
            sandbox_profile="standard",
            upstream_execution_ids=upstream_execution_ids,
        )


def _ordered_union(*items: List[str]) -> List[str]:
    seen = set()
    merged: List[str] = []
    for group in items:
        for item in group:
            if item not in seen:
                seen.add(item)
                merged.append(item)
    return merged
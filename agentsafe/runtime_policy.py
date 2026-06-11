from __future__ import annotations

from dataclasses import dataclass, replace
from functools import lru_cache
from typing import Any, Dict, Optional

from agentsafe.sandbox import ComplianceSandboxFactory, NetworkPolicy, SandboxPolicy
from agentsafe.sandbox.seccomp_deploy import deploy_verified_seccomp


@dataclass(frozen=True)
class RuntimePolicyBundle:
    compliance_policy: str
    sandbox_profile: str
    sandbox_policy_name: str
    sandbox_policy: SandboxPolicy
    network_policy: NetworkPolicy
    seccomp_profile_name: str
    seccomp_regime: str
    seccomp_evidence: Optional[Dict[str, Any]] = None


def resolve_runtime_policy_bundle(
    *,
    compliance_policy: str = "default",
    verification_profile: Optional[Dict[str, Any]] = None,
) -> RuntimePolicyBundle:
    policy_name = (compliance_policy or "default").lower()
    profile = verification_profile or {}
    sandbox_profile = str(profile.get("sandbox_profile") or "standard")

    if sandbox_profile == "phi_release_attested":
        executor = ComplianceSandboxFactory.for_hipaa()
        seccomp_profile_name = "network_blocked"
        seccomp_regime = "hipaa"
        sandbox_policy_name = "HIPAAReleaseAttested"
        sandbox_policy = replace(executor.policy, network=NetworkPolicy.disabled())
    elif sandbox_profile == "phi_internal_only":
        executor = ComplianceSandboxFactory.for_hipaa()
        seccomp_profile_name = "network_blocked"
        seccomp_regime = "hipaa"
        sandbox_policy_name = "HIPAA"
        sandbox_policy = executor.policy
    elif sandbox_profile == "release_attested":
        executor = ComplianceSandboxFactory.standard()
        seccomp_profile_name = "compute_only"
        seccomp_regime = "general"
        sandbox_policy_name = "ReleaseAttested"
        sandbox_policy = replace(executor.policy, network=NetworkPolicy.disabled())
    elif policy_name == "hipaa":
        executor = ComplianceSandboxFactory.for_hipaa()
        seccomp_profile_name = "network_blocked"
        seccomp_regime = "hipaa"
        sandbox_policy_name = "HIPAA"
        sandbox_policy = executor.policy
    elif sandbox_profile == "sox_audit" or policy_name == "sox":
        executor = ComplianceSandboxFactory.for_sox()
        seccomp_profile_name = "compute_only"
        seccomp_regime = "sox"
        sandbox_policy_name = "SOX"
        sandbox_policy = executor.policy
    elif sandbox_profile == "reviewer_restricted":
        executor = ComplianceSandboxFactory.for_legal()
        seccomp_profile_name = "compute_only"
        seccomp_regime = "legal"
        sandbox_policy_name = "ReviewerRestricted"
        sandbox_policy = replace(executor.policy, network=NetworkPolicy.disabled())
    elif policy_name in {"legal", "legal_privilege"}:
        executor = ComplianceSandboxFactory.for_legal()
        seccomp_profile_name = "compute_only"
        seccomp_regime = "legal"
        sandbox_policy_name = "Legal"
        sandbox_policy = executor.policy
    else:
        executor = ComplianceSandboxFactory.standard()
        seccomp_profile_name = "standard"
        seccomp_regime = "general"
        sandbox_policy_name = "Standard"
        sandbox_policy = executor.policy

    network_policy = sandbox_policy.effective_network_policy or NetworkPolicy.disabled()

    return RuntimePolicyBundle(
        compliance_policy=policy_name,
        sandbox_profile=sandbox_profile,
        sandbox_policy_name=sandbox_policy_name,
        sandbox_policy=sandbox_policy,
        network_policy=network_policy,
        seccomp_profile_name=seccomp_profile_name,
        seccomp_regime=seccomp_regime,
        seccomp_evidence=_build_seccomp_evidence(seccomp_profile_name, seccomp_regime),
    )


@lru_cache(maxsize=16)
def _build_seccomp_evidence(profile_name: str, regime: str) -> Dict[str, Any]:
    try:
        result = deploy_verified_seccomp(
            profile_name=profile_name,
            regime=regime,
            dry_run=True,
        )
    except Exception as exc:
        return {
            "status": "error",
            "profile_name": profile_name,
            "regime": regime,
            "error": str(exc),
        }

    evidence = result.to_dict()
    if result.alignment_report is not None:
        evidence["alignment_report"] = result.alignment_report.to_dict()
    if result.compliance_certificate is not None:
        evidence["compliance_certificate"] = result.compliance_certificate.to_dict()
    if result.proof_certificate is not None:
        evidence["proof_certificate"] = result.proof_certificate.to_dict()
    if result.policy_version is not None:
        evidence["policy_version"] = result.policy_version.to_dict()
    if result.audit_events:
        evidence["audit_events"] = [event.to_dict() for event in result.audit_events]
    if result.post_validation_checks:
        evidence["post_validation_checks"] = [
            check.to_dict() for check in result.post_validation_checks
        ]
    if result.program is not None:
        evidence["program"] = result.program.to_dict()
    return evidence
"""
Pre-built compliance configurations for regulated industries.

Each preset bundles:
  - Content safety policy (scanner config)
  - Capability permissions & denials
  - Information flow rules
  - Audit requirements
  - Required Z3 proof properties
  - Human approval gates
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from agentsafe.safety.scanner import ContentSafetyPolicy


@dataclass
class FlowRule:
    """Information flow restriction."""
    source: str
    allowed_destinations: List[str] = field(default_factory=list)
    forbidden_destinations: List[str] = field(default_factory=list)

    def allows(self, destination: str) -> bool:
        if self.forbidden_destinations and destination in self.forbidden_destinations:
            return False
        if self.allowed_destinations and destination not in self.allowed_destinations:
            return False
        return True


@dataclass
class AuditConfig:
    """Audit trail requirements."""
    log_all_access: bool = True
    retention_days: int = 2190  # 6 years default
    include_user_id: bool = True
    tamper_proof: bool = False
    segregation_of_duties: bool = False

    @property
    def retention_years(self) -> float:
        return self.retention_days / 365.0


@dataclass
class ComplianceConfig:
    """
    Full compliance configuration for a regulatory regime.

    Combines content safety, capability control, information flow
    restrictions, audit requirements and proof obligations into a
    single deployable preset.

    Permission fields
    -----------------
    permissions : list[str]
        The default/recommended permissions.  Used when the API caller
        does not supply explicit permissions.
    max_permissions : list[str]
        The absolute permission ceiling.  Even an ADMIN user cannot
        exceed this set under this compliance regime.  If empty, falls
        back to ``permissions`` as the ceiling.  A value of ``["*"]``
        means "unrestricted" (used by the Default preset).
    forbidden_permissions : list[str]
        Hard deny-list.  Any permission matching these (including
        wildcard prefixes) is unconditionally stripped.
    """
    name: str
    content_safety: ContentSafetyPolicy = field(
        default_factory=ContentSafetyPolicy.default,
    )
    permissions: List[str] = field(default_factory=list)
    max_permissions: List[str] = field(default_factory=list)
    forbidden_permissions: List[str] = field(default_factory=list)
    information_flow_rules: List[FlowRule] = field(default_factory=list)
    audit: AuditConfig = field(default_factory=AuditConfig)
    required_proofs: List[str] = field(default_factory=list)
    human_approvals: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def requires_approval(self, action: str) -> bool:
        """Check if an action requires human approval under this config."""
        return action in self.human_approvals

    def permission_allowed(self, perm: str) -> bool:
        """Check if a permission is allowed (not in forbidden list)."""
        for fp in self.forbidden_permissions:
            if fp == perm:
                return False
            if fp.endswith("*") and perm.startswith(fp[:-1]):
                return False
        return True

    def flow_allowed(self, source: str, destination: str) -> bool:
        """Check if an information flow is permitted."""
        for rule in self.information_flow_rules:
            if rule.source == source:
                return rule.allows(destination)
        # No rule for this source → allowed by default
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "permissions": self.permissions,
            "max_permissions": self.max_permissions,
            "forbidden_permissions": self.forbidden_permissions,
            "flow_rules": [
                {
                    "source": r.source,
                    "allowed": r.allowed_destinations,
                    "forbidden": r.forbidden_destinations,
                }
                for r in self.information_flow_rules
            ],
            "audit": {
                "log_all_access": self.audit.log_all_access,
                "retention_days": self.audit.retention_days,
                "tamper_proof": self.audit.tamper_proof,
                "segregation_of_duties": self.audit.segregation_of_duties,
            },
            "required_proofs": self.required_proofs,
            "human_approvals": self.human_approvals,
        }


class CompliancePresets:
    """Factory for industry compliance configurations."""

    @staticmethod
    def hipaa() -> ComplianceConfig:
        """
        HIPAA-compliant configuration.

        - PHI detection and auto-redaction
        - 6-year audit trail retention
        - No PHI via external email
        - Minimum necessary access principle
        - Human approval for data export
        """
        return ComplianceConfig(
            name="HIPAA",
            content_safety=ContentSafetyPolicy.hipaa_compliant(),
            permissions=[
                "database:read:patient_data",
                "document:write:reports",
                "filesystem:read",
            ],
            max_permissions=[
                "database:read:patient_data",
                "database:read:clinical_data",
                "document:write:reports",
                "document:read:reports",
                "filesystem:read",
                "filesystem:write:reports",
                "compute:python:eval",
            ],
            forbidden_permissions=[
                "network:smtp:send:external",
            ],
            information_flow_rules=[
                FlowRule(
                    source="PHI",
                    allowed_destinations=["internal", "covered_entity"],
                    forbidden_destinations=["external", "public"],
                ),
                FlowRule(
                    source="sensitive",
                    allowed_destinations=["internal"],
                    forbidden_destinations=["public", "external"],
                ),
            ],
            audit=AuditConfig(
                log_all_access=True,
                retention_days=2190,  # 6 years
                include_user_id=True,
                tamper_proof=True,
            ),
            required_proofs=[
                "no_phi_external_flow",
                "minimum_necessary_access",
                "authorized_user_only",
            ],
            human_approvals=[
                "send_external_communication",
                "export_patient_data",
                "data_export",
            ],
            metadata={"regulation": "HIPAA", "jurisdiction": "US"},
        )

    @staticmethod
    def sox() -> ComplianceConfig:
        """
        SOX-compliant configuration for financial data.

        - MNPI detection and blocking
        - 7-year audit trail retention
        - Segregation of duties
        - Insider trading keyword detection
        """
        return ComplianceConfig(
            name="SOX",
            content_safety=ContentSafetyPolicy.sox_compliant(),
            permissions=[
                "database:read:financial_data",
                "document:write:reports",
            ],
            max_permissions=[
                "database:read:financial_data",
                "database:read:audit_logs",
                "document:write:reports",
                "document:read:reports",
                "document:read:financial_data",
                "filesystem:read",
                "compute:python:eval",
            ],
            forbidden_permissions=[
                "database:write:financial_data",
            ],
            information_flow_rules=[
                FlowRule(
                    source="MNPI",
                    allowed_destinations=["internal_finance"],
                    forbidden_destinations=["external", "general_internal", "public"],
                ),
            ],
            audit=AuditConfig(
                log_all_access=True,
                retention_days=2555,  # 7 years
                include_user_id=True,
                tamper_proof=True,
                segregation_of_duties=True,
            ),
            required_proofs=[
                "no_mnpi_leak",
                "segregation_of_duties",
                "authorized_access_only",
            ],
            human_approvals=[
                "send_external_communication",
                "modify_financial_records",
            ],
            metadata={"regulation": "SOX", "jurisdiction": "US"},
        )

    @staticmethod
    def legal_privilege() -> ComplianceConfig:
        """
        Attorney-client privilege protection.

        - Block privilege-waiving communications
        - Require approval for ALL external communication
        - Protect work product
        """
        return ComplianceConfig(
            name="Legal Privilege",
            content_safety=ContentSafetyPolicy.legal_privilege(),
            permissions=[
                "document:read:legal_docs",
                "document:write:legal_docs",
            ],
            max_permissions=[
                "document:read:legal_docs",
                "document:write:legal_docs",
                "document:read:case_files",
                "filesystem:read",
                "filesystem:write:legal_docs",
                "compute:python:eval",
            ],
            forbidden_permissions=[
                "network:smtp:send:opposing_party",
            ],
            information_flow_rules=[
                FlowRule(
                    source="PRIVILEGED",
                    allowed_destinations=["legal_team", "client"],
                    forbidden_destinations=["external", "opposing_party", "public"],
                ),
            ],
            audit=AuditConfig(
                log_all_access=True,
                retention_days=3650,  # 10 years
                include_user_id=True,
                tamper_proof=True,
            ),
            required_proofs=[
                "no_privilege_waiver",
                "client_authorized",
            ],
            human_approvals=[
                "send_email",
                "external_communication",
                "document_sharing",
            ],
            metadata={"regulation": "Attorney-Client Privilege"},
        )

    @staticmethod
    def default() -> ComplianceConfig:
        """Baseline safety with no specific compliance regime."""
        return ComplianceConfig(
            name="Default",
            content_safety=ContentSafetyPolicy.default(),
            permissions=["*"],
            max_permissions=["*"],
            audit=AuditConfig(
                log_all_access=False,
                retention_days=365,
            ),
        )

    _REGISTRY: Dict[str, staticmethod] = {}

    @classmethod
    def get(cls, name: str) -> ComplianceConfig:
        """Look up a preset by name (case-insensitive)."""
        factories = {
            "hipaa": cls.hipaa,
            "sox": cls.sox,
            "legal": cls.legal_privilege,
            "legal_privilege": cls.legal_privilege,
            "default": cls.default,
        }
        factory = factories.get(name.lower())
        if factory is None:
            raise ValueError(
                f"Unknown compliance preset: {name}. "
                f"Available: {list(factories.keys())}"
            )
        return factory()

    @classmethod
    def available(cls) -> List[str]:
        return ["hipaa", "sox", "legal_privilege", "default"]

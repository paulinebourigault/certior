"""
Content Safety Scanner - multi-layer scanning engine.
"""
from __future__ import annotations
import re
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass, field

from .taxonomy import ContentRiskCategory
from .detectors.pii import PIIDetector, PIIConfig, PIIMatch
from .detectors.secrets import SecretsDetector, SecretMatch


@dataclass
class ScanViolation:
    category: ContentRiskCategory
    matched_text: str
    position: Tuple[int, int] = (0, 0)
    severity: str = "block"  # "block" or "warn"
    details: str = ""


@dataclass
class ScanResult:
    """Result of a content safety scan.

    Semantics
    ---------
    ``clean``
        **False** when *any* safety-relevant finding is present - including
        PII that was subsequently redacted.  A downstream consumer should
        never treat ``clean=True`` as "no sensitive data was encountered";
        it means "no sensitive data was encountered AND no policy violations
        were triggered."

    ``pii_found``
        **True** when PII was detected by regex or NER, regardless of
        whether it was redacted.  This flag is independent of ``clean``
        and exists so audit trails can record that PII *was* present in
        the original input.

    ``remediated``
        **True** when PII was detected AND ``redacted_text`` contains the
        sanitised version.  When ``remediated=True`` and ``violations`` is
        empty (no keyword / pattern / secrets violations), the content may
        proceed using ``redacted_text`` in place of the original - but
        ``clean`` will still be **False** for auditability.

    Decision matrix
    ---------------
    +------------------+--------+-----------+-------------+-----------+
    | Scenario         | clean  | pii_found | remediated  | action    |
    +------------------+--------+-----------+-------------+-----------+
    | No findings      | True   | False     | False       | allow     |
    | PII + redacted   | False  | True      | True        | allow w/  |
    |                  |        |           |             | redacted  |
    | PII + no redact  | False  | True      | False       | block     |
    | Keyword match    | False  | False*    | False       | block     |
    | PII + keyword    | False  | True      | True/False  | block     |
    +------------------+--------+-----------+-------------+-----------+
    """
    violations: List[ScanViolation] = field(default_factory=list)
    pii_detected: List[PIIMatch] = field(default_factory=list)
    secrets_detected: List[SecretMatch] = field(default_factory=list)
    clean: bool = True
    pii_found: bool = False
    remediated: bool = False
    redacted_text: Optional[str] = None

    def __post_init__(self) -> None:
        self._recompute()

    def _recompute(self) -> None:
        self.pii_found = len(self.pii_detected) > 0
        self.remediated = self.pii_found and self.redacted_text is not None
        self.clean = (
            len(self.violations) == 0
            and not self.pii_found
            and len(self.secrets_detected) == 0
        )

    @property
    def safe_to_proceed(self) -> bool:
        """True when the content can proceed (possibly via redacted_text).

        Unlike ``clean``, this returns True when PII was found and
        successfully redacted **and** no other blocking violations exist.
        Use this for flow-control decisions; use ``clean`` for audit.
        """
        has_blocking = any(v.severity == "block" for v in self.violations)
        if has_blocking:
            return False
        if self.pii_found and not self.remediated:
            return False
        return True


@dataclass
class ContentSafetyPolicy:
    """Policy configuration for content safety scanning."""
    name: str = "Default"
    blocked_categories: List[ContentRiskCategory] = field(default_factory=list)
    warn_categories: List[ContentRiskCategory] = field(default_factory=list)
    blocked_keywords: List[str] = field(default_factory=list)
    blocked_patterns: List[str] = field(default_factory=list)
    pii_config: Optional[PIIConfig] = None
    detect_secrets: bool = False
    requires_audit_trail: bool = False
    retention_years: Optional[int] = None
    requires_human_approval: List[str] = field(default_factory=list)

    @classmethod
    def hipaa_compliant(cls) -> ContentSafetyPolicy:
        return cls(
            name="HIPAA",
            blocked_categories=[
                ContentRiskCategory.HATE_BIAS_PII,
                ContentRiskCategory.PHI_EXPOSURE,
            ],
            warn_categories=[ContentRiskCategory.UNAUTHORIZED_ADVICE],
            blocked_keywords=[
                "patient name", "medical record", "diagnosis",
                "prescription", "treatment plan",
            ],
            pii_config=PIIConfig(detect=True, redact=True),
            detect_secrets=True,
            requires_audit_trail=True,
            retention_years=6,
            requires_human_approval=[
                "external_communication", "data_export", "send_email",
            ],
        )

    @classmethod
    def sox_compliant(cls) -> ContentSafetyPolicy:
        return cls(
            name="SOX",
            blocked_categories=[
                ContentRiskCategory.MNPI_LEAK,
                ContentRiskCategory.UNAUTHORIZED_ADVICE,
            ],
            blocked_keywords=[
                "material non-public", "insider", "unreleased earnings",
                "confidential projections", "executive compensation",
                "insider information",
            ],
            blocked_patterns=[
                r'\bunreleased\s+earnings\b',
                r'\bMNPI\b',
                r'\binsider\s+(?:information|trading)\b',
            ],
            detect_secrets=True,
            requires_audit_trail=True,
            retention_years=7,
            requires_human_approval=[
                "send_external_communication", "modify_financial_records",
            ],
        )

    @classmethod
    def legal_privilege(cls) -> ContentSafetyPolicy:
        return cls(
            name="Legal Privilege",
            blocked_categories=[ContentRiskCategory.PRIVILEGE_WAIVER],
            blocked_keywords=[
                "legal advice", "attorney notes", "case strategy",
                "settlement terms", "witness prep", "settlement discussion",
                "attorney-client",
            ],
            requires_audit_trail=True,
            requires_human_approval=[
                "send_email", "external_communication", "document_sharing",
            ],
        )

    @classmethod
    def default(cls) -> ContentSafetyPolicy:
        return cls(
            name="Default",
            blocked_categories=[
                ContentRiskCategory.HATE_BIAS_PII,
                ContentRiskCategory.THREATS,
                ContentRiskCategory.VIOLENCE,
            ],
            pii_config=PIIConfig(detect=True, redact=False),
        )


class ContentScanner:
    """Multi-layer content safety scanner."""

    def __init__(self, policy: ContentSafetyPolicy):
        self.policy = policy
        self._pii = PIIDetector(policy.pii_config) if policy.pii_config else None
        self._secrets = SecretsDetector() if policy.detect_secrets else None
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in policy.blocked_patterns
        ]

    def scan(self, text: str) -> ScanResult:
        """Scan text for all safety violations."""
        violations: List[ScanViolation] = []
        pii_detected: List[PIIMatch] = []
        secrets_detected: List[SecretMatch] = []

        # 1. Keyword matching
        text_lower = text.lower()
        for kw in self.policy.blocked_keywords:
            idx = text_lower.find(kw.lower())
            if idx >= 0:
                violations.append(ScanViolation(
                    category=self._infer_category(kw),
                    matched_text=kw,
                    position=(idx, idx + len(kw)),
                    severity="block",
                    details=f"Blocked keyword: {kw}",
                ))

        # 2. Pattern matching
        for pattern in self._compiled_patterns:
            for m in pattern.finditer(text):
                violations.append(ScanViolation(
                    category=ContentRiskCategory.MNPI_LEAK,
                    matched_text=m.group(),
                    position=m.span(),
                    severity="block",
                    details=f"Pattern match: {m.group()}",
                ))

        # 3. PII detection
        if self._pii:
            pii_detected = self._pii.detect(text)
            if pii_detected and not (self.policy.pii_config and self.policy.pii_config.redact):
                violations.append(ScanViolation(
                    category=ContentRiskCategory.HATE_BIAS_PII,
                    matched_text=f"{len(pii_detected)} PII instance(s)",
                    severity="block",
                    details=f"PII types: {set(m.pii_type for m in pii_detected)}",
                ))

        # 4. Secrets detection
        if self._secrets:
            secrets_detected = self._secrets.detect(text)
            for s in secrets_detected:
                violations.append(ScanViolation(
                    category=ContentRiskCategory.HATE_BIAS_PII,
                    matched_text=s.value,
                    position=(s.start, s.end),
                    severity="block",
                    details=f"Secret detected: {s.secret_type}",
                ))

        # 5. Redaction
        redacted_text = None
        if self._pii and self.policy.pii_config and self.policy.pii_config.redact and pii_detected:
            redacted_text = self._pii.redact(text, pii_detected)

        result = ScanResult(
            violations=violations,
            pii_detected=pii_detected,
            secrets_detected=secrets_detected,
            redacted_text=redacted_text,
        )
        # clean, pii_found, remediated are computed by ScanResult._recompute()
        return result

    def _infer_category(self, keyword: str) -> ContentRiskCategory:
        kw = keyword.lower()
        if any(t in kw for t in ["patient", "medical", "diagnosis", "prescription", "treatment"]):
            return ContentRiskCategory.PHI_EXPOSURE
        if any(t in kw for t in ["insider", "mnpi", "unreleased", "earnings", "confidential"]):
            return ContentRiskCategory.MNPI_LEAK
        if any(t in kw for t in ["attorney", "legal", "privilege", "settlement", "witness"]):
            return ContentRiskCategory.PRIVILEGE_WAIVER
        return ContentRiskCategory.HATE_BIAS_PII

    def requires_approval(self, action: str) -> bool:
        return action in self.policy.requires_human_approval

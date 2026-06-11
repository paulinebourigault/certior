"""Tests for content scanner and policies."""
import pytest
from agentsafe.safety.scanner import (
    ContentScanner, ContentSafetyPolicy, ScanResult, ScanViolation,
)
from agentsafe.safety.taxonomy import ContentRiskCategory


class TestContentSafetyPolicy:
    def test_hipaa(self):
        p = ContentSafetyPolicy.hipaa_compliant()
        assert p.name == "HIPAA"
        assert p.requires_audit_trail
        assert p.retention_years == 6
        assert ContentRiskCategory.PHI_EXPOSURE in p.blocked_categories
        assert "external_communication" in p.requires_human_approval

    def test_sox(self):
        p = ContentSafetyPolicy.sox_compliant()
        assert p.name == "SOX"
        assert p.retention_years == 7
        assert ContentRiskCategory.MNPI_LEAK in p.blocked_categories

    def test_legal(self):
        p = ContentSafetyPolicy.legal_privilege()
        assert p.name == "Legal Privilege"
        assert "legal advice" in p.blocked_keywords

    def test_default(self):
        p = ContentSafetyPolicy.default()
        assert p.pii_config is not None


class TestContentScanner:
    def test_hipaa_pii_detection(self):
        scanner = ContentScanner(ContentSafetyPolicy.hipaa_compliant())
        result = scanner.scan("Patient SSN: 123-45-6789 needs follow-up")
        assert len(result.pii_detected) >= 1
        assert result.redacted_text is not None
        assert "123-45-6789" not in result.redacted_text
        assert "[REDACTED-SSN]" in result.redacted_text
        # New semantics: PII was found → clean=False for audit trail,
        # but content is remediated → safe_to_proceed=True
        assert not result.clean, "clean must be False when PII detected"
        assert result.pii_found, "pii_found must be True"
        assert result.remediated, "remediated must be True when redaction applied"
        assert result.safe_to_proceed, "safe_to_proceed when PII redacted and no violations"

    def test_hipaa_keyword(self):
        scanner = ContentScanner(ContentSafetyPolicy.hipaa_compliant())
        result = scanner.scan("The patient name is John Smith and his diagnosis is critical")
        assert not result.clean

    def test_sox_mnpi(self):
        scanner = ContentScanner(ContentSafetyPolicy.sox_compliant())
        result = scanner.scan("Our unreleased earnings are $100M")
        assert not result.clean
        assert any("MNPI" in str(v.category) or "unreleased" in v.matched_text
                   for v in result.violations)

    def test_sox_insider(self):
        scanner = ContentScanner(ContentSafetyPolicy.sox_compliant())
        result = scanner.scan("This is insider information about the merger")
        assert not result.clean

    def test_legal_privilege(self):
        scanner = ContentScanner(ContentSafetyPolicy.legal_privilege())
        result = scanner.scan("Our legal advice is to settle for $5M")
        assert not result.clean

    def test_clean_content(self):
        scanner = ContentScanner(ContentSafetyPolicy.hipaa_compliant())
        result = scanner.scan("The weather is nice today")
        assert result.clean
        assert len(result.violations) == 0

    def test_secrets_detection(self):
        scanner = ContentScanner(ContentSafetyPolicy.sox_compliant())
        result = scanner.scan("Use key: AKIAIOSFODNN7EXAMPLE to access")
        assert not result.clean
        assert len(result.secrets_detected) >= 1

    def test_requires_approval(self):
        scanner = ContentScanner(ContentSafetyPolicy.hipaa_compliant())
        assert scanner.requires_approval("external_communication")
        assert not scanner.requires_approval("internal_query")

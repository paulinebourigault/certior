"""Tests for PII detection."""
import pytest
from agentsafe.safety.detectors.pii import PIIDetector, PIIConfig, PIIMatch


class TestPIIDetector:
    def test_detect_ssn(self):
        d = PIIDetector()
        matches = d.detect("SSN: 123-45-6789")
        assert len(matches) >= 1
        assert any(m.pii_type == "SSN" for m in matches)

    def test_detect_email(self):
        d = PIIDetector()
        matches = d.detect("Contact: user@example.com")
        assert any(m.pii_type == "EMAIL" for m in matches)

    def test_detect_phone(self):
        d = PIIDetector()
        matches = d.detect("Call 555-123-4567")
        assert any(m.pii_type == "PHONE" for m in matches)

    def test_detect_credit_card(self):
        d = PIIDetector()
        matches = d.detect("Card: 4111 1111 1111 1111")
        assert any(m.pii_type == "CREDIT_CARD" for m in matches)

    def test_detect_ip(self):
        d = PIIDetector()
        matches = d.detect("Server at 192.168.1.1")
        assert any(m.pii_type == "IP_ADDRESS" for m in matches)

    def test_no_pii(self):
        d = PIIDetector()
        matches = d.detect("This is a clean sentence.")
        assert len(matches) == 0

    def test_redact(self):
        d = PIIDetector()
        text = "SSN: 123-45-6789, email: a@b.com"
        redacted = d.redact(text)
        assert "123-45-6789" not in redacted
        assert "[REDACTED-SSN]" in redacted
        assert "a@b.com" not in redacted

    def test_disabled(self):
        d = PIIDetector(PIIConfig(detect=False))
        matches = d.detect("SSN: 123-45-6789")
        assert len(matches) == 0

    def test_match_positions(self):
        d = PIIDetector()
        matches = d.detect("SSN: 123-45-6789")
        ssn = [m for m in matches if m.pii_type == "SSN"][0]
        assert ssn.start >= 0
        assert ssn.end > ssn.start

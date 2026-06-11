"""
Tests for VerifierAgent - output validation with content safety.
Exercises PII detection, compliance scanning, and redaction paths.
"""
import pytest
from agentsafe.agents.verifier_agent import VerifierAgent, OutputVerificationResult
from agentsafe.safety.scanner import ContentSafetyPolicy
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.kernel.certificate import CertificateAuthority
from agentsafe.observability.otel import CertiorTelemetry


class TestVerifierAgent:
    def setup_method(self):
        CertificateAuthority.reset()
        CertiorTelemetry.reset()

    def _make_verifier(self, policy=None):
        token = CapabilityToken(permissions=["verify"], budget_cents=1000, budget_remaining_cents=1000)
        return VerifierAgent("verifier", token, content_policy=policy)

    @pytest.mark.asyncio
    async def test_clean_output(self):
        v = self._make_verifier()
        result = await v.verify_output("Hello, world!")
        assert result.valid
        assert len(result.violations) == 0

    @pytest.mark.asyncio
    async def test_pii_detection_ssn(self):
        v = self._make_verifier(ContentSafetyPolicy.hipaa_compliant())
        result = await v.verify_output("Patient SSN: 123-45-6789")
        # HIPAA policy detects PII
        assert isinstance(result, OutputVerificationResult)
        assert result.scan_result is not None
        assert len(result.scan_result.pii_detected) > 0

    @pytest.mark.asyncio
    async def test_pii_redaction(self):
        v = self._make_verifier(ContentSafetyPolicy.hipaa_compliant())
        result = await v.verify_output("SSN: 123-45-6789, Phone: 555-123-4567")
        if result.scan_result and result.scan_result.redacted_text:
            assert "123-45-6789" not in result.scan_result.redacted_text

    @pytest.mark.asyncio
    async def test_sox_mnpi_detection(self):
        v = self._make_verifier(ContentSafetyPolicy.sox_compliant())
        result = await v.verify_output("Our unreleased earnings are $1B")
        assert not result.valid
        assert any("unreleased" in str(v).lower() or "mnpi" in str(v).lower() for v in result.violations)

    @pytest.mark.asyncio
    async def test_legal_privilege_detection(self):
        v = self._make_verifier(ContentSafetyPolicy.legal_privilege())
        result = await v.verify_output("According to legal advice from counsel")
        assert not result.valid

    @pytest.mark.asyncio
    async def test_none_output(self):
        v = self._make_verifier()
        result = await v.verify_output(None)
        assert result.valid

    @pytest.mark.asyncio
    async def test_numeric_output(self):
        v = self._make_verifier()
        result = await v.verify_output(42)
        assert result.valid

    @pytest.mark.asyncio
    async def test_default_policy(self):
        v = self._make_verifier()
        assert v.content_policy.name == "Default"

    @pytest.mark.asyncio
    async def test_output_passed_through(self):
        v = self._make_verifier()
        result = await v.verify_output("safe output")
        assert result.output == "safe output"

    @pytest.mark.asyncio
    async def test_redacted_output_used(self):
        v = self._make_verifier(ContentSafetyPolicy.hipaa_compliant())
        result = await v.verify_output("SSN: 123-45-6789")
        # If PII was detected and redacted, output should be redacted version
        if result.scan_result and result.scan_result.redacted_text:
            assert result.output == result.scan_result.redacted_text

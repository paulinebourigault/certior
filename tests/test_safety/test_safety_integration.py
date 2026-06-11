"""Tests for safety verification integration."""
import pytest
from agentsafe.verification.safety_integration import (
    SafeVerifier, ComplianceVerifier, ContentSafetyError,
    SafetyVerificationResult, get_hipaa_verifier, get_sox_verifier,
    get_legal_verifier, with_safety_check, verify_with_safety,
)
from agentsafe.safety.scanner import ContentSafetyPolicy
from agentsafe.observability.otel import CertiorTelemetry


class TestSafeVerifier:
    def setup_method(self):
        CertiorTelemetry.reset()
        ComplianceVerifier.reset()

    @pytest.mark.asyncio
    async def test_clean_content(self):
        v = SafeVerifier(ContentSafetyPolicy.hipaa_compliant())
        result = await v.verify_and_scan(content="Normal message")
        assert result.approved
        assert result.clean

    @pytest.mark.asyncio
    async def test_pii_detected(self):
        v = SafeVerifier(ContentSafetyPolicy.hipaa_compliant())
        result = await v.verify_and_scan(
            content="Patient SSN: 123-45-6789"
        )
        # HIPAA auto-redacts, so it should still pass with redaction
        assert result.redacted_content is not None
        assert "123-45-6789" not in result.redacted_content

    @pytest.mark.asyncio
    async def test_sox_blocks_mnpi(self):
        v = get_sox_verifier()
        result = await v.verify_and_scan(
            content="Our unreleased earnings show $100M profit"
        )
        assert not result.approved
        assert len(result.safety_violations) > 0

    @pytest.mark.asyncio
    async def test_legal_blocks_privilege(self):
        v = get_legal_verifier()
        result = await v.verify_and_scan(
            content="Our legal advice is to settle"
        )
        assert not result.approved

    @pytest.mark.asyncio
    async def test_compliance_singletons(self):
        h1 = get_hipaa_verifier()
        h2 = get_hipaa_verifier()
        assert h1 is h2


class TestWithSafetyCheck:
    @pytest.mark.asyncio
    async def test_decorator_passes(self):
        @with_safety_check(ContentSafetyPolicy.default())
        async def my_func(content=""):
            return "ok"
        assert await my_func(content="hello") == "ok"

    @pytest.mark.asyncio
    async def test_decorator_blocks(self):
        @with_safety_check(ContentSafetyPolicy.sox_compliant())
        async def my_func(content=""):
            return "ok"
        with pytest.raises(ContentSafetyError):
            await my_func(content="unreleased earnings data")


class TestVerifyWithSafety:
    @pytest.mark.asyncio
    async def test_convenience(self):
        result = await verify_with_safety(
            "Normal text", ContentSafetyPolicy.default(),
        )
        assert result.approved

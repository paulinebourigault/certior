"""Shared test fixtures."""
import pytest
from agentsafe.kernel.certificate import CertificateAuthority
from agentsafe.observability.otel import CertiorTelemetry
from agentsafe.verification.safety_integration import ComplianceVerifier


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset all singletons between tests."""
    CertificateAuthority.reset()
    CertiorTelemetry.reset()
    ComplianceVerifier.reset()
    yield
    CertificateAuthority.reset()
    CertiorTelemetry.reset()
    ComplianceVerifier.reset()

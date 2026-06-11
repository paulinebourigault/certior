"""Integration tests for observability."""
import pytest
from agentsafe.verification.observability_integration import (
    ObservableVerifier, instrument_verification,
    VerificationMetrics, get_verification_metrics,
)
from agentsafe.observability.otel import CertiorTelemetry


class TestObservableVerifier:
    def setup_method(self):
        CertiorTelemetry.reset()

    @pytest.mark.asyncio
    async def test_verify_action(self):
        v = ObservableVerifier()
        result = await v.verify_action("test", "token-1")
        assert result["valid"]
        assert v.metrics.total == 1
        assert v.metrics.allowed == 1

    @pytest.mark.asyncio
    async def test_metrics_tracking(self):
        v = ObservableVerifier()
        await v.verify_action("a1", "t1")
        await v.verify_action("a2", "t2")
        assert v.metrics.total == 2
        assert v.metrics.avg_latency_ms > 0


class TestVerificationMetrics:
    def test_record(self):
        m = VerificationMetrics()
        m.record("allowed", 10.0)
        m.record("blocked", 5.0)
        assert m.total == 2
        assert m.allowed == 1
        assert m.blocked == 1
        assert m.avg_latency_ms == 7.5

    def test_empty(self):
        m = VerificationMetrics()
        assert m.avg_latency_ms == 0.0

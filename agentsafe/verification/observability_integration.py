"""
ObservableVerifier - transparent telemetry instrumentation.
"""
from __future__ import annotations
import time
import functools
from typing import Any, Dict, Optional, Callable
from dataclasses import dataclass, field

from agentsafe.observability.otel import CertiorTelemetry, TelemetryConfig


@dataclass
class VerificationMetrics:
    total: int = 0
    allowed: int = 0
    blocked: int = 0
    errors: int = 0
    total_latency_ms: float = 0.0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / max(self.total, 1)

    def record(self, result: str, latency_ms: float):
        self.total += 1
        self.total_latency_ms += latency_ms
        if result == "allowed":
            self.allowed += 1
        elif result == "blocked":
            self.blocked += 1
        else:
            self.errors += 1


class ObservableVerifier:
    """Wraps any verifier with OTel tracing and metrics."""

    def __init__(self, inner_verifier: Any = None, config: Optional[TelemetryConfig] = None):
        self._inner = inner_verifier
        self._tel = CertiorTelemetry.get_instance(config)
        self._metrics = VerificationMetrics()

    @property
    def metrics(self) -> VerificationMetrics:
        return self._metrics

    async def verify_action(
        self, action: str, token_id: str,
        constraints: Optional[Dict] = None, **kwargs,
    ) -> Dict[str, Any]:
        with self._tel.trace_verification(action, token_id) as span:
            start = time.perf_counter()
            try:
                if self._inner and hasattr(self._inner, 'verify_action'):
                    result = await self._inner.verify_action(
                        action=action, token_id=token_id,
                        constraints=constraints, **kwargs,
                    )
                else:
                    result = {"valid": True, "action": action}
                latency = (time.perf_counter() - start) * 1000
                self._metrics.record("allowed", latency)
                return result
            except Exception as e:
                latency = (time.perf_counter() - start) * 1000
                self._metrics.record("blocked", latency)
                raise


def instrument_verification(verifier: Any, config: Optional[TelemetryConfig] = None) -> ObservableVerifier:
    """Wrap an existing verifier with observability."""
    return ObservableVerifier(verifier, config)


def traced_verification(action_name: str):
    """Decorator for adding tracing to verification functions."""
    def decorator(fn: Callable):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            tel = CertiorTelemetry.get_instance()
            token_id = kwargs.get("token_id", "unknown")
            if token_id == "unknown":
                token = kwargs.get("token")
                if token is not None:
                    if hasattr(token, "id"):
                        token_id = token.id
                    elif isinstance(token, dict):
                        token_id = token.get("id", "unknown")
            with tel.trace_verification(action_name, str(token_id)):
                return await fn(*args, **kwargs)
        return wrapper
    return decorator


_metrics_singleton: Optional[VerificationMetrics] = None

def get_verification_metrics() -> VerificationMetrics:
    global _metrics_singleton
    if _metrics_singleton is None:
        _metrics_singleton = VerificationMetrics()
    return _metrics_singleton

"""
CertiorTelemetry - OpenTelemetry integration for Certior.

Provides distributed tracing, metrics, and logging with <2% overhead.
Gracefully degrades when OpenTelemetry SDK is not installed.
"""
from __future__ import annotations
import time
import os
from contextlib import contextmanager
from typing import Dict, Any, Optional, Generator
from dataclasses import dataclass

# Graceful degradation: work without OTel installed
_HAS_OTEL = False
try:
    from opentelemetry import trace, metrics
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor, ConsoleSpanExporter, SimpleSpanProcessor
    )
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import (
        PeriodicExportingMetricReader, ConsoleMetricExporter, InMemoryMetricReader
    )
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME
    from opentelemetry.trace import StatusCode
    _HAS_OTEL = True
except ImportError:
    pass

# Try OTLP exporters
_HAS_OTLP = False
try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    _HAS_OTLP = True
except ImportError:
    pass

# Try Jaeger exporter
_HAS_JAEGER = False
try:
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    _HAS_JAEGER = True
except ImportError:
    pass


class VerificationError(Exception):
    """Raised when verification fails."""
    pass


@dataclass
class TelemetryConfig:
    """Configuration for CertiorTelemetry."""
    service_name: str = "certior"
    otlp_endpoint: Optional[str] = None
    jaeger_host: Optional[str] = None
    jaeger_port: int = 6831
    enable_metrics: bool = True
    enable_tracing: bool = True
    console_export: bool = False
    sampling_rate: float = 1.0
    metric_export_interval_ms: int = 60000
    batch_max_queue: int = 2048
    batch_delay_ms: int = 5000


class _NoOpSpan:
    """No-op span for when OTel is unavailable."""
    def set_attribute(self, key: str, value: Any): pass
    def set_status(self, status: Any): pass
    def add_event(self, name: str, attributes: Optional[Dict] = None): pass
    def __enter__(self): return self
    def __exit__(self, *args): pass


class _NoOpCounter:
    def add(self, amount: int, attributes: Optional[Dict] = None): pass


class _NoOpHistogram:
    def record(self, value: float, attributes: Optional[Dict] = None): pass


class CertiorTelemetry:
    """
    Centralized OpenTelemetry integration for Certior.

    Provides:
    - Distributed tracing for verification workflows
    - 12 Prometheus metrics for performance and security events
    - Graceful degradation if OTel SDK unavailable
    - <2% CPU/memory overhead
    """
    _instance: Optional[CertiorTelemetry] = None

    def __init__(self, config: Optional[TelemetryConfig] = None):
        self.config = config or TelemetryConfig()
        self._otel_available = _HAS_OTEL
        self._spans_created = 0
        self._metrics_recorded = 0

        if self._otel_available:
            self._resource = Resource.create({
                SERVICE_NAME: self.config.service_name,
                "certior.version": self._get_version(),
                "deployment.environment": os.getenv("CERTIOR_ENV", "development"),
            })
            self.tracer = None  # Default to None
            if self.config.enable_tracing:
                self._setup_tracing()
            if self.config.enable_metrics:
                self._setup_metrics()
                self._init_metrics()
            else:
                self._init_noop_metrics()
        else:
            self.tracer = None
            self._init_noop_metrics()

    def _setup_tracing(self):
        provider = TracerProvider(resource=self._resource)
        if self.config.otlp_endpoint and _HAS_OTLP:
            exporter = OTLPSpanExporter(
                endpoint=self.config.otlp_endpoint, insecure=True
            )
            provider.add_span_processor(BatchSpanProcessor(
                exporter,
                max_queue_size=self.config.batch_max_queue,
                schedule_delay_millis=self.config.batch_delay_ms,
            ))
        elif self.config.jaeger_host and _HAS_JAEGER:
            exporter = JaegerExporter(
                agent_host_name=self.config.jaeger_host,
                agent_port=self.config.jaeger_port,
            )
            provider.add_span_processor(BatchSpanProcessor(exporter))
        elif self.config.console_export:
            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
        trace.set_tracer_provider(provider)
        self.tracer = trace.get_tracer(self.config.service_name)
        self._trace_provider = provider

    def _setup_metrics(self):
        if self.config.otlp_endpoint and _HAS_OTLP:
            exporter = OTLPMetricExporter(
                endpoint=self.config.otlp_endpoint, insecure=True
            )
        elif self.config.console_export:
            exporter = ConsoleMetricExporter()
        else:
            exporter = InMemoryMetricReader()
            self._metric_reader = exporter
            provider = MeterProvider(
                resource=self._resource, metric_readers=[exporter]
            )
            metrics.set_meter_provider(provider)
            self.meter = metrics.get_meter(self.config.service_name)
            self._meter_provider = provider
            return

        reader = PeriodicExportingMetricReader(
            exporter,
            export_interval_millis=self.config.metric_export_interval_ms,
        )
        self._metric_reader = reader
        provider = MeterProvider(
            resource=self._resource, metric_readers=[reader]
        )
        metrics.set_meter_provider(provider)
        self.meter = metrics.get_meter(self.config.service_name)
        self._meter_provider = provider

    def _init_metrics(self):
        """Initialize all 12 Certior metrics."""
        self.verifications_total = self.meter.create_counter(
            "certior.verifications.total",
            description="Total verification attempts", unit="1",
        )
        self.verifications_blocked = self.meter.create_counter(
            "certior.verifications.blocked",
            description="Blocked verifications", unit="1",
        )
        self.verification_latency = self.meter.create_histogram(
            "certior.verification.latency",
            description="Verification latency", unit="ms",
        )
        self.z3_invocations = self.meter.create_counter(
            "certior.z3.invocations",
            description="Z3 solver invocations", unit="1",
        )
        self.z3_solve_time = self.meter.create_histogram(
            "certior.z3.solve_time",
            description="Z3 solve time", unit="ms",
        )
        self.capability_grants = self.meter.create_counter(
            "certior.capabilities.granted",
            description="Capability tokens granted", unit="1",
        )
        self.capability_usage = self.meter.create_counter(
            "certior.capabilities.used",
            description="Capability token usage", unit="1",
        )
        self.ifc_violations = self.meter.create_counter(
            "certior.ifc.violations",
            description="Information flow violations", unit="1",
        )
        self.certificates_issued = self.meter.create_counter(
            "certior.certificates.issued",
            description="Proof certificates issued", unit="1",
        )
        self.budget_consumption = self.meter.create_histogram(
            "certior.budget.consumption",
            description="Budget consumption per task", unit="cents",
        )
        self.content_scans = self.meter.create_counter(
            "certior.content.scans",
            description="Content safety scans", unit="1",
        )
        self.safety_violations = self.meter.create_counter(
            "certior.safety.violations",
            description="Content safety violations", unit="1",
        )

    def _init_noop_metrics(self):
        """No-op metrics for when OTel is unavailable."""
        noop_counter = _NoOpCounter()
        noop_hist = _NoOpHistogram()
        self.verifications_total = noop_counter
        self.verifications_blocked = noop_counter
        self.verification_latency = noop_hist
        self.z3_invocations = noop_counter
        self.z3_solve_time = noop_hist
        self.capability_grants = noop_counter
        self.capability_usage = noop_counter
        self.ifc_violations = noop_counter
        self.certificates_issued = noop_counter
        self.budget_consumption = noop_hist
        self.content_scans = noop_counter
        self.safety_violations = noop_counter

    @contextmanager
    def trace_verification(
        self, action: str, token_id: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Generator:
        """Context manager for tracing verification operations."""
        if not self._otel_available or not self.tracer:
            yield _NoOpSpan()
            return

        with self.tracer.start_as_current_span(
            "certior.verify",
            attributes={
                "certior.action": action,
                "certior.token_id": token_id,
                **(attributes or {}),
            },
        ) as span:
            start = time.perf_counter()
            result = "allowed"
            self._spans_created += 1
            try:
                yield span
                span.set_attribute("certior.result", "allowed")
                self.verifications_total.add(1, {"action": action, "result": "allowed"})
            except VerificationError as e:
                result = "blocked"
                span.set_attribute("certior.result", "blocked")
                span.set_attribute("certior.violation", str(e))
                span.set_status(StatusCode.ERROR)
                self.verifications_total.add(1, {"action": action, "result": "blocked"})
                self.verifications_blocked.add(1, {"action": action, "reason": type(e).__name__})
                raise
            except Exception as e:
                result = "error"
                span.set_attribute("certior.result", "error")
                span.set_status(StatusCode.ERROR)
                self.verifications_total.add(1, {"action": action, "result": "error"})
                raise
            finally:
                latency_ms = (time.perf_counter() - start) * 1000
                span.set_attribute("certior.latency_ms", latency_ms)
                self.verification_latency.record(latency_ms, {"action": action, "result": result})
                self._metrics_recorded += 1

    def record_z3_invocation(self, solve_time_ms: float, result: str):
        self.z3_invocations.add(1, {"result": result})
        self.z3_solve_time.record(solve_time_ms, {"result": result})
        self._metrics_recorded += 1

    def record_capability_grant(self, token_id: str, permission_count: int):
        self.capability_grants.add(1, {"token_id": token_id, "count": str(permission_count)})

    def record_ifc_violation(self, from_label: str, to_label: str):
        self.ifc_violations.add(1, {"from": from_label, "to": to_label})

    def record_ifc_flow_check(
        self, source: str, target: str, allowed: bool,
        promoted: bool = False,
    ):
        """Record an IFC flow check (allowed or blocked)."""
        self.ifc_violations.add(
            0 if allowed else 1,
            {"from": source, "to": target},
        )

    def record_certificate_issuance(self, prover: str, property_count: int):
        self.certificates_issued.add(1, {"prover": prover, "count": str(property_count)})

    def record_content_scan(
        self, policy: str, clean: bool,
        phase: str = "final_output",
        action: str = "pass",
    ):
        """Record a content safety scan result.

        Parameters
        ----------
        policy : str
            Name of the content policy applied.
        clean : bool
            Whether the scan found no violations.
        phase : str
            Scan phase - one of ``"tool_input"``, ``"tool_output"``,
            ``"final_output"`` (default).
        action : str
            Action taken - one of ``"pass"``, ``"redact"``, ``"block"``,
            ``"warn"`` (default ``"pass"``).
        """
        self.content_scans.add(1, {
            "policy": policy, "clean": str(clean),
            "phase": phase, "action": action,
        })
        if not clean:
            self.safety_violations.add(1, {"policy": policy, "phase": phase})

    @classmethod
    def get_instance(cls, config: Optional[TelemetryConfig] = None) -> CertiorTelemetry:
        if cls._instance is None:
            cls._instance = cls(config)
        return cls._instance

    @classmethod
    def reset(cls):
        cls._instance = None

    @staticmethod
    def _get_version() -> str:
        try:
            from importlib.metadata import version
            return version("agentsafe")
        except Exception:
            return "0.4.0"

    def shutdown(self):
        if self._otel_available:
            if hasattr(self, '_trace_provider'):
                self._trace_provider.shutdown()
            if hasattr(self, '_meter_provider'):
                self._meter_provider.shutdown()

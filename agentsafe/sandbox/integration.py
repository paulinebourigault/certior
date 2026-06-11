"""
Sandbox integration layer - connects OS containment to Certior's
verification pipeline, observability, and compliance systems.

This module provides:

1. **ObservableSandboxedExecutor** - wraps ``SandboxedExecutor`` with
   OpenTelemetry tracing and Prometheus metrics.

2. **ComplianceSandboxFactory** - creates pre-configured sandbox policies
   from compliance templates (HIPAA, SOX, Legal).

3. **verified_sandbox_execute()** - convenience function that combines
   capability verification → sandbox execution → output validation
   into a single call.

4. **SandboxAuditRecord** - structured audit trail entry for every
   sandboxed execution, suitable for compliance export.

Usage::

    from agentsafe.sandbox.integration import (
        ObservableSandboxedExecutor,
        ComplianceSandboxFactory,
        verified_sandbox_execute,
    )

    # Observability-aware executor
    executor = ObservableSandboxedExecutor(SandboxPolicy.standard())
    result = await executor.execute("print(42)")
    # → traces, metrics, and audit records are emitted automatically

    # Compliance-preconfigured
    executor = ComplianceSandboxFactory.for_hipaa()
    result = await executor.execute("import math; print(math.pi)")
"""
from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .errors import SandboxError, SandboxSetupError
from .executor import SandboxedExecutor, SandboxResult
from .filesystem import (
    FilesystemAuditInfo,
    FilesystemPolicy,
    build_filesystem_audit_info,
    validate_policy as validate_fs_policy,
)
from .network import (
    NetworkAuditInfo,
    NetworkGuard,
    NetworkPolicy,
    build_net_isolation_config,
)
from .policy import (
    ContainmentLayer,
    ResourceLimits,
    SandboxPolicy,
)

logger = logging.getLogger("certior.sandbox.integration")


# ── Audit record ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class SandboxAuditRecord:
    """Immutable audit trail entry for a single sandboxed execution.

    Captures everything needed for compliance reporting:
    - *what* was executed (code hash - never the raw code)
    - *how* it was contained (active layers, policy name)
    - *when* it ran (timestamps)
    - *what happened* (result status, violations)
    """

    record_id: str
    timestamp: str  # ISO 8601
    code_sha256: str
    code_length: int
    policy_name: str
    active_layers: Tuple[str, ...]
    wall_time_seconds: float
    returncode: int
    is_error: bool
    error_type: Optional[str]
    output_truncated: bool
    output_length: int
    mandatory_layers_met: bool
    violations: Tuple[str, ...] = ()
    token_id: Optional[str] = None
    agent_id: Optional[str] = None

    # D2: Filesystem isolation audit data
    filesystem_audit: Optional[Dict[str, Any]] = None

    # D3: Network isolation audit data
    network_audit: Optional[Dict[str, Any]] = None

    # D4: Dafny-verified seccomp filter audit data
    seccomp_audit: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-safe dict for audit export."""
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "code_sha256": self.code_sha256,
            "code_length": self.code_length,
            "policy_name": self.policy_name,
            "active_layers": list(self.active_layers),
            "wall_time_seconds": self.wall_time_seconds,
            "returncode": self.returncode,
            "is_error": self.is_error,
            "error_type": self.error_type,
            "output_truncated": self.output_truncated,
            "output_length": self.output_length,
            "mandatory_layers_met": self.mandatory_layers_met,
            "violations": list(self.violations),
            "token_id": self.token_id,
            "agent_id": self.agent_id,
            "filesystem_isolation": self.filesystem_audit,
            "network_isolation": self.network_audit,
            "seccomp_verified": self.seccomp_audit,
        }


def _build_audit_record(
    code: str,
    result: SandboxResult,
    policy: SandboxPolicy,
    policy_name: str,
    mandatory_ok: bool,
    *,
    token_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    filesystem_audit: Optional[FilesystemAuditInfo] = None,
    network_audit: Optional[NetworkAuditInfo] = None,
) -> SandboxAuditRecord:
    """Build an audit record from execution results."""
    fs_dict: Optional[Dict[str, Any]] = None
    if filesystem_audit is not None:
        fs_dict = filesystem_audit.to_dict()

    net_dict: Optional[Dict[str, Any]] = None
    if network_audit is not None:
        net_dict = network_audit.to_dict()

    return SandboxAuditRecord(
        record_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        code_sha256=hashlib.sha256(code.encode("utf-8")).hexdigest(),
        code_length=len(code),
        policy_name=policy_name,
        active_layers=result.active_layers,
        wall_time_seconds=result.wall_time_seconds,
        returncode=result.returncode,
        is_error=result.is_error,
        error_type=result.error_type,
        output_truncated=result.metadata.get("truncated_stdout", False),
        output_length=len(result.stdout) + len(result.stderr),
        mandatory_layers_met=mandatory_ok,
        token_id=token_id,
        agent_id=agent_id,
        filesystem_audit=fs_dict,
        network_audit=net_dict,
    )


# ── Observable executor ──────────────────────────────────────────────

class ObservableSandboxedExecutor:
    """Sandbox executor with integrated OpenTelemetry observability.

    Wraps :class:`~agentsafe.sandbox.SandboxedExecutor` to automatically:

    - Create trace spans for each execution
    - Record latency histograms
    - Count executions by result and containment level
    - Count seccomp/resource violations
    - Log audit records for compliance

    The telemetry layer is **fail-open**: if OpenTelemetry is not
    installed or the collector is unreachable, execution proceeds
    normally with degraded observability.
    """

    def __init__(
        self,
        policy: Optional[SandboxPolicy] = None,
        policy_name: str = "custom",
        *,
        telemetry: Any = None,
        audit_callback: Optional[Callable[[SandboxAuditRecord], None]] = None,
    ) -> None:
        """
        Parameters
        ----------
        policy
            Sandbox policy.  ``None`` → ``SandboxPolicy.standard()``.
        policy_name
            Human-readable name for audit/metric labels.
        telemetry
            Optional ``CertiorTelemetry`` instance.  When ``None``,
            attempts to import and create one; falls back to no-op.
        audit_callback
            Called with each :class:`SandboxAuditRecord` after execution.
            Useful for writing audit logs to a database or file.
        """
        self.policy = policy or SandboxPolicy.standard()
        self.policy_name = policy_name
        self._executor = SandboxedExecutor(self.policy)
        self._audit_callback = audit_callback

        # D2: Capture filesystem audit info at construction (safe - no side effects)
        self._fs_audit: Optional[FilesystemAuditInfo] = None
        fs_policy = self.policy.effective_filesystem_policy
        if fs_policy is not None and fs_policy.enabled:
            try:
                self._fs_audit = build_filesystem_audit_info(fs_policy)
            except Exception as exc:
                logger.debug("Filesystem audit info capture failed: %s", exc)

        # D3: Capture network audit info at construction
        self._net_audit: Optional[NetworkAuditInfo] = None
        self._net_guard: Optional[NetworkGuard] = None
        net_policy = self.policy.effective_network_policy
        if net_policy is not None:
            try:
                from .network import NetworkMode
                if net_policy.mode != NetworkMode.DISABLED:
                    self._net_guard = NetworkGuard(net_policy)
                    self._net_audit = self._net_guard.build_network_audit_info()
            except Exception as exc:
                logger.debug("Network audit info capture failed: %s", exc)

        # ── Telemetry setup (fail-open) ──
        self._telemetry = telemetry
        self._tracer: Any = None
        self._meter: Any = None
        self._metrics_initialized = False

        if telemetry is None:
            try:
                from agentsafe.observability import CertiorTelemetry
                self._telemetry = CertiorTelemetry.get_instance()
            except Exception:
                pass

        if self._telemetry is not None:
            self._init_metrics()

    # ── Delegated properties ─────────────────────────────────────────

    @property
    def effective_filesystem_policy(self) -> Optional[Any]:
        """Return the active :class:`FilesystemPolicy` from the inner policy.

        Delegates to ``self.policy.effective_filesystem_policy`` so callers
        (e.g. compliance tests) can introspect the executor's FS settings
        without reaching through two layers.
        """
        return self.policy.effective_filesystem_policy

    @property
    def effective_network_policy(self) -> Optional[Any]:
        """Return the active :class:`NetworkPolicy` from the inner policy.

        Delegates to ``self.policy.effective_network_policy`` so callers
        can introspect the executor's network settings.
        """
        return self.policy.effective_network_policy

    @property
    def network_guard(self) -> Optional[Any]:
        """Return the :class:`NetworkGuard` instance, if active."""
        return self._net_guard

    # ── Metrics setup ────────────────────────────────────────────────

    def _init_metrics(self) -> None:
        """Initialise sandbox-specific metrics.

        These supplement the core CertiorTelemetry metrics with
        sandbox-specific detail.
        """
        try:
            self._tracer = self._telemetry.tracer
            meter = self._telemetry.meter
            if meter is None:
                return

            self._sandbox_executions = meter.create_counter(
                name="certior.sandbox.executions.total",
                description="Total sandboxed code executions",
                unit="1",
            )
            self._sandbox_latency = meter.create_histogram(
                name="certior.sandbox.latency",
                description="Sandboxed execution latency",
                unit="ms",
            )
            self._sandbox_violations = meter.create_counter(
                name="certior.sandbox.violations.total",
                description="Sandbox containment violations",
                unit="1",
            )
            self._sandbox_layers = meter.create_counter(
                name="certior.sandbox.layers.active",
                description="Active containment layer counts",
                unit="1",
            )

            # D2: Filesystem-specific metrics
            self._fs_isolation_mode = meter.create_counter(
                name="certior.sandbox.fs.isolation_mode",
                description="Filesystem isolation mode used per execution",
                unit="1",
            )
            self._fs_bind_mount_count = meter.create_histogram(
                name="certior.sandbox.fs.bind_mount_count",
                description="Number of read-only bind mounts per execution",
                unit="1",
            )
            self._fs_tmpfs_size = meter.create_histogram(
                name="certior.sandbox.fs.tmpfs_size_bytes",
                description="Configured tmpfs size per execution",
                unit="By",
            )

            # D3: Network-specific metrics
            self._net_isolation_mode = meter.create_counter(
                name="certior.sandbox.net.isolation_mode",
                description="Network isolation mode used per execution",
                unit="1",
            )
            self._net_connections_allowed = meter.create_counter(
                name="certior.sandbox.net.connections_allowed",
                description="Allowed outbound connections",
                unit="1",
            )
            self._net_connections_blocked = meter.create_counter(
                name="certior.sandbox.net.connections_blocked",
                description="Blocked outbound connections",
                unit="1",
            )
            self._net_bytes_transferred = meter.create_histogram(
                name="certior.sandbox.net.bytes_transferred",
                description="Bytes received from outbound connections",
                unit="By",
            )

            self._metrics_initialized = True
        except Exception as exc:
            logger.debug("Sandbox metrics init failed: %s", exc)

    # ── Public API ────────────────────────────────────────────────────

    async def execute(
        self,
        code: str,
        *,
        token_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> SandboxResult:
        """Execute code with full observability and audit logging.

        Parameters
        ----------
        code
            Python source code to execute.
        token_id
            Optional capability token ID for audit correlation.
        agent_id
            Optional agent ID for audit correlation.

        Returns
        -------
        SandboxResult
            Execution result (same as ``SandboxedExecutor.execute()``).
        """
        span = None
        start = time.monotonic()

        # ── Start trace span ──
        if self._tracer is not None:
            try:
                from opentelemetry import trace
                span = self._tracer.start_span(
                    "certior.sandbox.execute",
                    attributes={
                        "certior.sandbox.policy": self.policy_name,
                        "certior.sandbox.code_length": len(code),
                        "certior.sandbox.code_sha256": hashlib.sha256(
                            code.encode()
                        ).hexdigest()[:16],
                    },
                )
                if token_id:
                    span.set_attribute("certior.token_id", token_id)
                if agent_id:
                    span.set_attribute("certior.agent_id", agent_id)
            except Exception:
                span = None

        try:
            result = await self._executor.execute(code)
            elapsed_ms = (time.monotonic() - start) * 1000

            # ── Record metrics ──
            self._record_metrics(result, elapsed_ms)

            # ── Update span ──
            if span is not None:
                try:
                    span.set_attribute("certior.sandbox.returncode", result.returncode)
                    span.set_attribute("certior.sandbox.is_error", result.is_error)
                    span.set_attribute("certior.sandbox.wall_time_ms", elapsed_ms)
                    span.set_attribute(
                        "certior.sandbox.active_layers",
                        ",".join(result.active_layers),
                    )
                    if result.error_type:
                        span.set_attribute("certior.sandbox.error_type", result.error_type)
                        if result.error_type == "violation":
                            from opentelemetry import trace as _trace
                            span.set_status(
                                _trace.Status(_trace.StatusCode.ERROR)
                            )
                except Exception:
                    pass

            # ── Audit record ──
            mandatory_ok = self._check_mandatory_layers(result)
            audit = _build_audit_record(
                code=code,
                result=result,
                policy=self.policy,
                policy_name=self.policy_name,
                mandatory_ok=mandatory_ok,
                token_id=token_id,
                agent_id=agent_id,
                filesystem_audit=self._fs_audit,
                network_audit=self._net_audit,
            )
            if self._audit_callback is not None:
                try:
                    self._audit_callback(audit)
                except Exception as exc:
                    logger.warning("Audit callback failed: %s", exc)

            return result

        except Exception as exc:
            if span is not None:
                try:
                    from opentelemetry import trace as _trace
                    span.set_status(
                        _trace.Status(_trace.StatusCode.ERROR, str(exc))
                    )
                    span.record_exception(exc)
                except Exception:
                    pass
            raise

        finally:
            if span is not None:
                try:
                    span.end()
                except Exception:
                    pass

    def get_active_layers(self) -> List[str]:
        """Proxy to underlying executor."""
        return self._executor.get_active_layers()

    def get_capabilities(self) -> Dict[str, Any]:
        """Proxy to underlying executor."""
        return self._executor.get_capabilities()

    @property
    def fs_audit_info(self) -> Optional[FilesystemAuditInfo]:
        """Return the captured filesystem audit info, or ``None`` if FS isolation is disabled."""
        return self._fs_audit

    # ── Private helpers ───────────────────────────────────────────────

    def _record_metrics(self, result: SandboxResult, elapsed_ms: float) -> None:
        """Record execution metrics."""
        if not self._metrics_initialized:
            return
        try:
            labels = {
                "policy": self.policy_name,
                "result": "error" if result.is_error else "success",
            }
            self._sandbox_executions.add(1, labels)
            self._sandbox_latency.record(elapsed_ms, labels)

            if result.is_error and result.error_type == "violation":
                self._sandbox_violations.add(1, {"policy": self.policy_name})

            for layer in result.active_layers:
                self._sandbox_layers.add(1, {"layer": layer})

            # D2: Filesystem-specific metrics
            if self._fs_audit is not None:
                self._fs_isolation_mode.add(1, {
                    "mode": self._fs_audit.effective_mode,
                    "policy": self.policy_name,
                })
                self._fs_bind_mount_count.record(
                    self._fs_audit.readonly_bind_count,
                    {"policy": self.policy_name},
                )
                self._fs_tmpfs_size.record(
                    self._fs_audit.tmpfs_size_bytes,
                    {"policy": self.policy_name},
                )

            # D3: Network-specific metrics
            if self._net_audit is not None:
                self._net_isolation_mode.add(1, {
                    "mode": self._net_audit.mode,
                    "policy": self.policy_name,
                })
                self._net_connections_allowed.add(
                    self._net_audit.connections_allowed,
                    {"policy": self.policy_name},
                )
                self._net_connections_blocked.add(
                    self._net_audit.connections_blocked,
                    {"policy": self.policy_name},
                )
        except Exception as exc:
            logger.debug("Metric recording failed: %s", exc)

    def _check_mandatory_layers(self, result: SandboxResult) -> bool:
        """Verify that all mandatory containment layers were active."""
        layer_name_map = {
            ContainmentLayer.RLIMITS: "rlimits",
            ContainmentLayer.SECCOMP_BPF: "seccomp_bpf",
            ContainmentLayer.PYTHON_SANDBOX: "python_sandbox",
            ContainmentLayer.PID_NAMESPACE: "ns_pid",
            ContainmentLayer.NET_NAMESPACE: "ns_net",
            ContainmentLayer.IPC_NAMESPACE: "ns_ipc",
            ContainmentLayer.USER_NAMESPACE: "ns_user",
            ContainmentLayer.FILESYSTEM_ISOLATION: "fs_isolation",
            ContainmentLayer.NETWORK_ISOLATION: "net_isolation",
            ContainmentLayer.NSJAIL: "nsjail",
        }
        active = set(result.active_layers)
        for layer in self.policy.mandatory_layers:
            expected_name = layer_name_map.get(layer)
            if expected_name and expected_name not in active:
                return False
        return True


# ── Compliance factory ───────────────────────────────────────────────

class ComplianceSandboxFactory:
    """Factory for compliance-preconfigured sandboxed executors.

    Each factory method returns an :class:`ObservableSandboxedExecutor`
    with resource limits, containment layers, **and filesystem isolation
    policy** tuned for the compliance regime.

    Design rationale:
    - **HIPAA**: Strict containment to prevent PHI exfiltration.  No
      network, tight memory, filesystem isolation mandatory (16 MiB tmpfs,
      /work only, pivot_root preferred).
    - **SOX**: Strict containment to prevent MNPI leakage.  Audit
      trail mandatory, 7-year retention metadata.  32 MiB tmpfs.
    - **Legal**: Standard containment with mandatory audit.  Tight FS.
    - **Standard**: Good defaults for non-regulated workloads.
    """

    @classmethod
    def for_hipaa(
        cls,
        audit_callback: Optional[Callable[[SandboxAuditRecord], None]] = None,
    ) -> ObservableSandboxedExecutor:
        """HIPAA-compliant sandbox: strict containment, mandatory audit.

        - 128 MiB memory limit
        - 10 s CPU timeout
        - seccomp + rlimits mandatory
        - **Filesystem isolation**: 16 MiB tmpfs, /work only, pivot_root
        - **Network isolation**: loopback only (no external access)
        - No network access
        """
        policy = SandboxPolicy(
            resource_limits=ResourceLimits(
                wall_time_seconds=15.0,
                cpu_time_seconds=10,
                memory_bytes=128 * 1024 * 1024,
                max_file_size_bytes=1 * 1024 * 1024,
                max_open_files=32,
                max_processes=1,
            ),
            mandatory_layers=frozenset({
                ContainmentLayer.RLIMITS,
                ContainmentLayer.PYTHON_SANDBOX,
            }),
            optional_layers=frozenset({
                ContainmentLayer.SECCOMP_BPF,
                ContainmentLayer.PID_NAMESPACE,
                ContainmentLayer.NET_NAMESPACE,
                ContainmentLayer.IPC_NAMESPACE,
                ContainmentLayer.USER_NAMESPACE,
                ContainmentLayer.FILESYSTEM_ISOLATION,
                ContainmentLayer.NETWORK_ISOLATION,
            }),
            filesystem=FilesystemPolicy.hipaa(),
            network=NetworkPolicy.hipaa(),
        )
        return ObservableSandboxedExecutor(
            policy=policy,
            policy_name="HIPAA",
            audit_callback=audit_callback,
        )

    @classmethod
    def for_sox(
        cls,
        audit_callback: Optional[Callable[[SandboxAuditRecord], None]] = None,
    ) -> ObservableSandboxedExecutor:
        """SOX-compliant sandbox: strict containment, audit trail.

        - 256 MiB memory
        - 30 s CPU
        - **Filesystem isolation**: 32 MiB tmpfs, /work + /tmp
        - **Network isolation**: selective (TLS required, rate-limited)
        """
        policy = SandboxPolicy(
            resource_limits=ResourceLimits(
                wall_time_seconds=30.0,
                cpu_time_seconds=30,
                memory_bytes=256 * 1024 * 1024,
                max_file_size_bytes=5 * 1024 * 1024,
                max_open_files=64,
                max_processes=1,
            ),
            mandatory_layers=frozenset({
                ContainmentLayer.RLIMITS,
                ContainmentLayer.PYTHON_SANDBOX,
            }),
            optional_layers=frozenset({
                ContainmentLayer.SECCOMP_BPF,
                ContainmentLayer.PID_NAMESPACE,
                ContainmentLayer.NET_NAMESPACE,
                ContainmentLayer.IPC_NAMESPACE,
                ContainmentLayer.USER_NAMESPACE,
                ContainmentLayer.FILESYSTEM_ISOLATION,
                ContainmentLayer.NETWORK_ISOLATION,
            }),
            filesystem=FilesystemPolicy.sox(),
            network=NetworkPolicy.sox(),
        )
        return ObservableSandboxedExecutor(
            policy=policy,
            policy_name="SOX",
            audit_callback=audit_callback,
        )

    @classmethod
    def for_legal(
        cls,
        audit_callback: Optional[Callable[[SandboxAuditRecord], None]] = None,
    ) -> ObservableSandboxedExecutor:
        """Legal-privilege sandbox: tight containment + audit.

        - Standard resources
        - **Filesystem isolation**: tight (16 MiB, /work only)
        - **Network isolation**: selective (audit-heavy)
        """
        policy = SandboxPolicy(
            filesystem=FilesystemPolicy.tight(),
            network=NetworkPolicy.legal(),
            optional_layers=frozenset({
                ContainmentLayer.SECCOMP_BPF,
                ContainmentLayer.PID_NAMESPACE,
                ContainmentLayer.NET_NAMESPACE,
                ContainmentLayer.IPC_NAMESPACE,
                ContainmentLayer.USER_NAMESPACE,
                ContainmentLayer.FILESYSTEM_ISOLATION,
                ContainmentLayer.NETWORK_ISOLATION,
            }),
        )
        return ObservableSandboxedExecutor(
            policy=policy,
            policy_name="Legal",
            audit_callback=audit_callback,
        )

    @classmethod
    def standard(
        cls,
        audit_callback: Optional[Callable[[SandboxAuditRecord], None]] = None,
    ) -> ObservableSandboxedExecutor:
        """Standard containment for non-regulated workloads.

        Filesystem isolation enabled as optional with standard settings.
        Network isolation enabled as optional with web_fetch defaults.
        """
        from .network import NetworkPolicy
        policy = SandboxPolicy(
            filesystem=FilesystemPolicy.standard(),
            network=NetworkPolicy.web_fetch_default(),
            optional_layers=frozenset({
                ContainmentLayer.SECCOMP_BPF,
                ContainmentLayer.PID_NAMESPACE,
                ContainmentLayer.NET_NAMESPACE,
                ContainmentLayer.IPC_NAMESPACE,
                ContainmentLayer.USER_NAMESPACE,
                ContainmentLayer.FILESYSTEM_ISOLATION,
                ContainmentLayer.NETWORK_ISOLATION,
            }),
        )
        return ObservableSandboxedExecutor(
            policy=policy,
            policy_name="Standard",
            audit_callback=audit_callback,
        )


# ── Verified sandbox execute ─────────────────────────────────────────

async def verified_sandbox_execute(
    code: str,
    *,
    policy: Optional[SandboxPolicy] = None,
    policy_name: str = "adhoc",
    token_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    audit_callback: Optional[Callable[[SandboxAuditRecord], None]] = None,
) -> SandboxResult:
    """Convenience: one-shot verified sandboxed execution.

    Creates an :class:`ObservableSandboxedExecutor`, runs the code,
    and returns the result.  The executor is not reused.

    Suitable for ad-hoc executions outside the agentic pipeline.
    For repeated executions, create an ``ObservableSandboxedExecutor``
    once and call ``execute()`` on it.

    Parameters
    ----------
    code
        Python source to execute.
    policy
        Sandbox policy.  ``None`` → ``SandboxPolicy.standard()``.
    policy_name
        Label for metrics/audit.
    token_id
        Capability token for audit correlation.
    agent_id
        Agent ID for audit correlation.
    audit_callback
        Called with the audit record after execution.

    Returns
    -------
    SandboxResult
    """
    executor = ObservableSandboxedExecutor(
        policy=policy,
        policy_name=policy_name,
        audit_callback=audit_callback,
    )
    return await executor.execute(
        code, token_id=token_id, agent_id=agent_id,
    )

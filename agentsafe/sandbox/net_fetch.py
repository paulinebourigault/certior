"""
Verified HTTP client for web_fetch - policy-enforced, audited network access.

Provides :class:`SafeFetcher`, a high-level HTTP client that enforces the
:class:`NetworkPolicy` before, during, and after every request:

1. **Pre-flight** - DNS resolution + URL validation via :class:`NetworkGuard`
2. **Transport** - ``urllib.request`` with size, timeout, and TLS enforcement
3. **Post-flight** - response auditing (status, bytes, latency)
4. **Compliance** - every request→response lifecycle captured in
   :class:`ConnectionRecord` for audit export

Architecture
------------
::

    SafeFetcher
      │
      ├── NetworkGuard.resolve_and_validate(url)
      │    ├── Parse URL
      │    ├── Check scheme/host/port/rate-limit
      │    ├── DNS resolution + IP blocklist check
      │    └── Return ResolvedTarget (allowed/blocked)
      │
      ├── _do_fetch(target)
      │    ├── Build urllib Request (User-Agent, timeout)
      │    ├── TLS context (verify=True unless disabled)
      │    ├── Streaming read with byte limit
      │    └── Return FetchResult
      │
      └── guard.record_connection(target, ...)
           └── Append to NetworkAuditLog

Design principles
-----------------
* **No external dependencies** - uses ``urllib.request`` from stdlib to avoid
  pulling in ``httpx`` / ``aiohttp`` just for sandboxed fetches.
* **Streaming byte limit** - never reads more than ``max_response_bytes``
  into memory, even if Content-Length lies.
* **Fail-closed** - any error during fetch is recorded as a blocked/error
  connection, never silently swallowed.
* **Immutable results** - :class:`FetchResult` is frozen.

Usage::

    from agentsafe.sandbox.net_fetch import SafeFetcher
    from agentsafe.sandbox.network import NetworkPolicy

    fetcher = SafeFetcher(NetworkPolicy.web_fetch_default())

    # Single URL
    result = fetcher.fetch("https://example.com")
    if result.success:
        print(result.body[:500])
    else:
        print(result.error)

    # Batch with audit export
    results = fetcher.fetch_many(["https://a.com", "https://b.com"])
    audit = fetcher.export_audit()

"""
from __future__ import annotations

import hashlib
import io
import logging
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from .network import (
    ConnectionRecord,
    NetworkAuditInfo,
    NetworkAuditLog,
    NetworkGuard,
    NetworkMode,
    NetworkPolicy,
    ResolvedTarget,
    validate_network_policy,
)

logger = logging.getLogger("certior.sandbox.net_fetch")


# ── Fetch result ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class FetchResult:
    """Immutable result of a single HTTP fetch.

    Contains the response body (or error), timing, byte counts, and
    the underlying :class:`ConnectionRecord` for audit trails.
    """

    url: str
    success: bool
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    body_text: str = ""
    content_type: str = ""
    content_length: int = 0
    bytes_received: int = 0
    latency_ms: float = 0.0
    tls_verified: bool = False
    error: str = ""
    error_type: str = ""  # "blocked", "dns_error", "timeout", "tls_error",
    #                       "size_exceeded", "http_error", "network_error"
    truncated: bool = False  # True if body was truncated by size limit
    connection_record: Optional[ConnectionRecord] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to JSON-safe dict (body excluded to avoid huge payloads)."""
        return {
            "url": self.url,
            "success": self.success,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "bytes_received": self.bytes_received,
            "latency_ms": self.latency_ms,
            "tls_verified": self.tls_verified,
            "error": self.error,
            "error_type": self.error_type,
            "truncated": self.truncated,
            "body_sha256": hashlib.sha256(self.body).hexdigest() if self.body else "",
        }


# ── Fetch summary ────────────────────────────────────────────────────

@dataclass(frozen=True)
class FetchBatchSummary:
    """Summary of a batch of fetch operations.

    Useful for logging and compliance reporting without exposing
    response bodies.
    """

    total_requests: int
    successful: int
    blocked: int
    errored: int
    total_bytes_received: int
    total_latency_ms: float
    results: Tuple[FetchResult, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "successful": self.successful,
            "blocked": self.blocked,
            "errored": self.errored,
            "total_bytes_received": self.total_bytes_received,
            "total_latency_ms": self.total_latency_ms,
            "results": [r.to_dict() for r in self.results],
        }


# ── TLS context builder ─────────────────────────────────────────────

def _build_ssl_context(*, verify: bool = True) -> ssl.SSLContext:
    """Build an SSL context for HTTPS requests.

    Parameters
    ----------
    verify
        If True, verify server certificates against system CA bundle.
        If False, skip verification (only for testing!).
    """
    if verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ── Safe fetcher ─────────────────────────────────────────────────────

class SafeFetcher:
    """Verified HTTP client with full policy enforcement and auditing.

    Wraps :class:`NetworkGuard` to provide a high-level ``fetch()`` API
    that enforces all policy constraints:

    - DNS pre-resolution and IP validation
    - Host/port/scheme allowlists and blocklists
    - Rate limiting
    - TLS requirement
    - Response size limits (streaming enforcement)
    - Connection timeout
    - Full audit trail

    Parameters
    ----------
    policy
        Network policy to enforce.
    verify_tls
        Whether to verify TLS certificates.  Default is ``True``.
        Set to ``False`` only for testing against self-signed certs.
    """

    def __init__(
        self,
        policy: Optional[NetworkPolicy] = None,
        *,
        verify_tls: bool = True,
    ) -> None:
        self._policy = policy or NetworkPolicy.web_fetch_default()
        self._guard = NetworkGuard(self._policy)
        self._verify_tls = verify_tls
        self._ssl_ctx = _build_ssl_context(verify=verify_tls)
        self._fetch_count = 0
        self._total_bytes = 0

    # ── Properties ───────────────────────────────────────────────────

    @property
    def policy(self) -> NetworkPolicy:
        return self._policy

    @property
    def guard(self) -> NetworkGuard:
        return self._guard

    @property
    def audit_log(self) -> NetworkAuditLog:
        return self._guard.audit_log

    @property
    def fetch_count(self) -> int:
        return self._fetch_count

    @property
    def total_bytes_received(self) -> int:
        return self._total_bytes

    # ── Pre-resolve ──────────────────────────────────────────────────

    def pre_resolve_hosts(self) -> Dict[str, Tuple[str, ...]]:
        """Pre-resolve all allowed hosts for /etc/hosts injection.

        Returns a dict of hostname → resolved IPs.  Call this before
        entering a network namespace so that DNS resolution works
        without an external resolver.
        """
        return self._guard.generate_hosts_entries()

    # ── Single fetch ─────────────────────────────────────────────────

    def fetch(self, url: str) -> FetchResult:
        """Fetch a URL with full policy enforcement and auditing.

        Steps:
        1. Validate URL against policy (scheme, host, port, rate)
        2. Pre-resolve DNS and check IP blocklists
        3. Perform HTTP request with timeout and size limits
        4. Record connection to audit log

        Parameters
        ----------
        url
            The URL to fetch.  Must be HTTP or HTTPS.

        Returns
        -------
        FetchResult
            Always returns (never raises).  Check ``result.success``
            and ``result.error`` for the outcome.
        """
        start = time.monotonic()

        # Step 1: Validate through NetworkGuard
        # NOTE: resolve_and_validate already records blocked connections
        # to the audit log, so we must NOT call record_connection again
        # for blocked targets - that would create duplicate audit records.
        target = self._guard.resolve_and_validate(url)
        if not target.allowed:
            # Fetch the most recent record from the audit log
            # (resolve_and_validate just appended it)
            recent = self._guard.audit_log.records
            record = recent[-1] if recent else None
            return FetchResult(
                url=url,
                success=False,
                error=target.block_reason,
                error_type="blocked",
                latency_ms=(time.monotonic() - start) * 1000,
                connection_record=record,
            )

        # Step 2: Perform the fetch
        try:
            result = self._do_fetch(target, start)
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            record = self._guard.record_connection(
                target,
                outcome="error",
                latency_ms=elapsed,
                error_detail=str(exc),
            )
            return FetchResult(
                url=url,
                success=False,
                error=str(exc),
                error_type="network_error",
                latency_ms=elapsed,
                connection_record=record,
            )

        self._fetch_count += 1
        self._total_bytes += result.bytes_received
        return result

    # ── Batch fetch ──────────────────────────────────────────────────

    def fetch_many(self, urls: Sequence[str]) -> FetchBatchSummary:
        """Fetch multiple URLs sequentially with full auditing.

        Parameters
        ----------
        urls
            URLs to fetch.

        Returns
        -------
        FetchBatchSummary
            Summary with per-URL results.
        """
        results: List[FetchResult] = []
        for url in urls:
            results.append(self.fetch(url))

        successful = sum(1 for r in results if r.success)
        blocked = sum(1 for r in results if r.error_type == "blocked")
        errored = sum(1 for r in results if not r.success and r.error_type != "blocked")
        total_bytes = sum(r.bytes_received for r in results)
        total_latency = sum(r.latency_ms for r in results)

        return FetchBatchSummary(
            total_requests=len(results),
            successful=successful,
            blocked=blocked,
            errored=errored,
            total_bytes_received=total_bytes,
            total_latency_ms=total_latency,
            results=tuple(results),
        )

    # ── Audit export ─────────────────────────────────────────────────

    def export_audit(
        self,
        *,
        namespace_active: bool = False,
        firewall_applied: bool = False,
    ) -> Dict[str, Any]:
        """Export complete audit trail for compliance reporting.

        Returns a dict containing:
        - Network policy summary
        - All connection records
        - Aggregate statistics
        """
        audit_info = self._guard.build_network_audit_info(
            namespace_active=namespace_active,
            firewall_applied=firewall_applied,
        )
        return {
            "policy_summary": audit_info.to_dict(),
            "connection_log": self._guard.audit_log.to_dict(),
            "fetch_stats": {
                "total_fetches": self._fetch_count,
                "total_bytes_received": self._total_bytes,
            },
        }

    def build_audit_info(
        self,
        *,
        namespace_active: bool = False,
        firewall_applied: bool = False,
    ) -> NetworkAuditInfo:
        """Build a :class:`NetworkAuditInfo` for inclusion in audit records."""
        return self._guard.build_network_audit_info(
            namespace_active=namespace_active,
            firewall_applied=firewall_applied,
        )

    # ── Internal fetch ───────────────────────────────────────────────

    def _do_fetch(
        self,
        target: ResolvedTarget,
        start: float,
    ) -> FetchResult:
        """Perform the actual HTTP request with enforcement.

        Uses ``urllib.request`` from stdlib to avoid external dependencies.
        Enforces:
        - Timeout (from policy)
        - Response size limit (streaming read)
        - TLS verification (from ssl context)
        """
        timeout = self._policy.connection_timeout_seconds
        max_bytes = self._policy.max_response_bytes
        user_agent = self._policy.user_agent

        # Build request
        req = Request(
            target.url,
            headers={
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "identity",  # no compression for size accuracy
            },
            method="GET",
        )

        # Select SSL context
        ctx = self._ssl_ctx if target.scheme == "https" else None
        tls_verified = False

        try:
            resp = urlopen(req, timeout=timeout, context=ctx)
            tls_verified = target.scheme == "https" and self._verify_tls

            # Read with streaming byte limit
            body, truncated = self._read_limited(resp, max_bytes)

            status = resp.status
            headers = {k: v for k, v in resp.getheaders()}
            content_type = resp.getheader("Content-Type", "")
            content_length_hdr = resp.getheader("Content-Length", "0")
            try:
                content_length = int(content_length_hdr)
            except (ValueError, TypeError):
                content_length = 0

            elapsed = (time.monotonic() - start) * 1000

            # Decode body to text (best-effort)
            try:
                body_text = body.decode("utf-8", errors="replace")
            except Exception:
                body_text = ""

            # Record successful connection
            record = self._guard.record_connection(
                target,
                outcome="allowed",
                response_status=status,
                bytes_received=len(body),
                latency_ms=elapsed,
                tls_verified=tls_verified,
            )

            return FetchResult(
                url=target.url,
                success=True,
                status_code=status,
                headers=headers,
                body=body,
                body_text=body_text,
                content_type=content_type,
                content_length=content_length,
                bytes_received=len(body),
                latency_ms=elapsed,
                tls_verified=tls_verified,
                truncated=truncated,
                connection_record=record,
            )

        except HTTPError as exc:
            elapsed = (time.monotonic() - start) * 1000
            # Read error body (limited)
            try:
                err_body = exc.read(min(max_bytes, 4096))
            except Exception:
                err_body = b""

            record = self._guard.record_connection(
                target,
                outcome="error",
                response_status=exc.code,
                bytes_received=len(err_body),
                latency_ms=elapsed,
                error_detail=f"HTTP {exc.code}: {exc.reason}",
            )

            return FetchResult(
                url=target.url,
                success=False,
                status_code=exc.code,
                body=err_body,
                bytes_received=len(err_body),
                latency_ms=elapsed,
                tls_verified=tls_verified,
                error=f"HTTP {exc.code}: {exc.reason}",
                error_type="http_error",
                connection_record=record,
            )

        except ssl.SSLError as exc:
            elapsed = (time.monotonic() - start) * 1000
            record = self._guard.record_connection(
                target,
                outcome="error",
                latency_ms=elapsed,
                error_detail=f"TLS error: {exc}",
            )
            return FetchResult(
                url=target.url,
                success=False,
                latency_ms=elapsed,
                error=f"TLS error: {exc}",
                error_type="tls_error",
                connection_record=record,
            )

        except TimeoutError as exc:
            elapsed = (time.monotonic() - start) * 1000
            record = self._guard.record_connection(
                target,
                outcome="error",
                latency_ms=elapsed,
                error_detail=f"Connection timeout: {exc}",
            )
            return FetchResult(
                url=target.url,
                success=False,
                latency_ms=elapsed,
                error=f"Connection timeout: {exc}",
                error_type="timeout",
                connection_record=record,
            )

        except URLError as exc:
            elapsed = (time.monotonic() - start) * 1000
            error_detail = str(exc.reason) if hasattr(exc, "reason") else str(exc)
            record = self._guard.record_connection(
                target,
                outcome="error",
                latency_ms=elapsed,
                error_detail=error_detail,
            )

            # Classify error type
            error_type = "network_error"
            if "timed out" in error_detail.lower():
                error_type = "timeout"
            elif "ssl" in error_detail.lower() or "certificate" in error_detail.lower():
                error_type = "tls_error"

            return FetchResult(
                url=target.url,
                success=False,
                latency_ms=elapsed,
                error=error_detail,
                error_type=error_type,
                connection_record=record,
            )

    @staticmethod
    def _read_limited(resp: Any, max_bytes: int) -> Tuple[bytes, bool]:
        """Read response body with a streaming byte limit.

        Reads in chunks to avoid loading the entire response into memory
        if it exceeds the limit.  Returns ``(body, truncated)``.
        """
        CHUNK_SIZE = 64 * 1024  # 64 KiB chunks
        buf = io.BytesIO()
        total = 0
        truncated = False

        while True:
            remaining = max_bytes - total
            if remaining <= 0:
                truncated = True
                break
            read_size = min(CHUNK_SIZE, remaining)
            chunk = resp.read(read_size)
            if not chunk:
                break
            buf.write(chunk)
            total += len(chunk)

        return buf.getvalue(), truncated


# ── Factory functions ────────────────────────────────────────────────

def create_web_fetch_client(
    *,
    allowed_hosts: Optional[Sequence[str]] = None,
    require_tls: bool = True,
    max_connections_per_minute: int = 60,
    max_response_bytes: int = 10 * 1024 * 1024,
    verify_tls: bool = True,
) -> SafeFetcher:
    """Create a SafeFetcher with a custom policy for web_fetch tool.

    Convenience factory for the common case of a web_fetch tool that
    needs to access specific hosts.

    Parameters
    ----------
    allowed_hosts
        Domain names that may be contacted.  ``None`` → no restriction
        (all hosts allowed subject to other constraints).
    require_tls
        Require HTTPS.
    max_connections_per_minute
        Rate limit.
    max_response_bytes
        Maximum response body size.
    verify_tls
        Whether to verify TLS certificates.
    """
    policy = NetworkPolicy(
        mode=NetworkMode.SELECTIVE,
        allowed_hosts=frozenset(allowed_hosts or ()),
        require_tls=require_tls,
        block_private_ips=True,
        max_connections_per_minute=max_connections_per_minute,
        max_response_bytes=max_response_bytes,
        audit_connections=True,
    )
    return SafeFetcher(policy, verify_tls=verify_tls)


def create_hipaa_fetcher() -> SafeFetcher:
    """Create a SafeFetcher with HIPAA policy (loopback-only)."""
    return SafeFetcher(NetworkPolicy.hipaa())


def create_sox_fetcher(
    allowed_hosts: Optional[Sequence[str]] = None,
) -> SafeFetcher:
    """Create a SafeFetcher with SOX policy (selective, TLS, low rate)."""
    policy = NetworkPolicy.sox()
    if allowed_hosts:
        # Create a new policy with allowed hosts added
        policy = NetworkPolicy(
            mode=policy.mode,
            allowed_hosts=frozenset(allowed_hosts),
            blocked_hosts=policy.blocked_hosts,
            allowed_ports=policy.allowed_ports,
            blocked_ip_ranges=policy.blocked_ip_ranges,
            block_private_ips=policy.block_private_ips,
            dns_servers=policy.dns_servers,
            dns_resolve_timeout_seconds=policy.dns_resolve_timeout_seconds,
            max_connections_per_minute=policy.max_connections_per_minute,
            connection_timeout_seconds=policy.connection_timeout_seconds,
            require_tls=policy.require_tls,
            audit_connections=policy.audit_connections,
            user_agent=policy.user_agent,
            max_response_bytes=policy.max_response_bytes,
        )
    return SafeFetcher(policy)


# ── Build network audit for compliance ───────────────────────────────

def build_network_audit_info(
    policy: NetworkPolicy,
    *,
    guard: Optional[NetworkGuard] = None,
    namespace_active: bool = False,
    firewall_applied: bool = False,
) -> NetworkAuditInfo:
    """Build :class:`NetworkAuditInfo` from policy and optional guard state.

    This is a standalone builder for cases where a full SafeFetcher
    is not needed (e.g., loopback-only policies).
    """
    if guard is not None:
        return guard.build_network_audit_info(
            namespace_active=namespace_active,
            firewall_applied=firewall_applied,
        )

    return NetworkAuditInfo(
        mode=policy.mode.value,
        namespace_active=namespace_active,
        allowed_hosts_count=len(policy.allowed_hosts),
        blocked_hosts_count=len(policy.blocked_hosts),
        dns_servers=policy.dns_servers,
        require_tls=policy.require_tls,
        max_connections_per_minute=policy.max_connections_per_minute,
        connections_allowed=0,
        connections_blocked=0,
        firewall_rules_applied=firewall_applied,
    )

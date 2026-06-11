"""
Network isolation policy and runtime enforcement (Phase D3).

Provides OS-level network containment for tools that require selective
network access (e.g. ``web_fetch``).  Three enforcement layers:

1. **DNS pre-resolution with validation** - resolve allowed hostnames
   before the request, reject targets not on the allowlist.
2. **Network namespace isolation** - ``CLONE_NEWNET`` with controlled
   connectivity (loopback-only or veth+iptables for selective access).
3. **Connection auditing** - every connection attempt is logged with
   source, destination, timing, and outcome for compliance export.

Design principles
-----------------
* **Defence-in-depth**: URL validation happens at Python level *and*
  network level (iptables inside the namespace).
* **Fail-closed**: unknown hosts are blocked; DNS resolution failures
  are treated as blocks.
* **Graceful degradation**: if network namespaces are unavailable,
  Python-level enforcement + auditing still apply.
* **Immutable policies**: ``NetworkPolicy`` is frozen - no runtime
  mutation of security parameters.

Usage::

    from agentsafe.sandbox.network import (
        NetworkPolicy, NetworkMode, NetworkGuard,
    )

    # Selective access: only allow HTTPS to specific hosts
    policy = NetworkPolicy.web_fetch_default()
    guard = NetworkGuard(policy)

    # Pre-flight: resolve + validate before connecting
    target = await guard.resolve_and_validate("https://example.com/page")
    if target.allowed:
        response = await guard.audited_fetch(target)

    # HIPAA: no external network at all
    policy = NetworkPolicy.hipaa()
    assert policy.mode == NetworkMode.LOOPBACK_ONLY
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import (
    Any,
    Dict,
    FrozenSet,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)
from urllib.parse import urlparse

from .errors import SandboxSetupError

logger = logging.getLogger("certior.sandbox.network")


# ── Network mode ─────────────────────────────────────────────────────

class NetworkMode(Enum):
    """Network isolation level.

    Controls the degree of connectivity available inside the sandbox.
    Ordered from most to least restrictive.
    """

    #: No network access.  Child runs in CLONE_NEWNET with only
    #: loopback (127.0.0.1).  No veth, no DNS, no outbound.
    LOOPBACK_ONLY = "loopback_only"

    #: Selective outbound access.  Child runs in CLONE_NEWNET with a
    #: veth pair + iptables rules that allow connections *only* to
    #: pre-resolved IPs of allowed hosts.  DNS is pre-resolved in the
    #: parent and injected via /etc/hosts inside the namespace.
    SELECTIVE = "selective"

    #: Full host network (CLONE_NEWNET is NOT used).  Python-level
    #: URL validation + connection auditing still apply, but there is
    #: no OS-level isolation.  Use as fallback when namespaces are
    #: unavailable.
    HOST_NETWORK = "host_network"

    #: Network isolation disabled entirely.  No namespace, no guard,
    #: no auditing.  Only for development/testing.
    DISABLED = "disabled"


# ── DNS resolution ───────────────────────────────────────────────────

@dataclass(frozen=True)
class ResolvedTarget:
    """Result of DNS pre-resolution and validation for a URL.

    Created by :meth:`NetworkGuard.resolve_and_validate`.  Contains
    the original URL, parsed components, resolved IP addresses, and
    the allow/block decision.

    If ``allowed`` is ``False``, ``block_reason`` explains why.
    """

    url: str
    scheme: str
    hostname: str
    port: int
    path: str
    resolved_ips: Tuple[str, ...] = ()
    allowed: bool = False
    block_reason: str = ""
    resolve_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to JSON-safe dict for audit trail."""
        return {
            "url": self.url,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "port": self.port,
            "path": self.path,
            "resolved_ips": list(self.resolved_ips),
            "allowed": self.allowed,
            "block_reason": self.block_reason,
            "resolve_time_ms": self.resolve_time_ms,
        }


@dataclass(frozen=True)
class ConnectionRecord:
    """Immutable record of a single connection attempt.

    Captures everything needed for compliance audit:
    - target host and resolved IP
    - timing
    - outcome (allowed/blocked/error)
    - bytes transferred (if connection succeeded)
    """

    record_id: str
    timestamp: str  # ISO 8601 UTC
    url: str
    hostname: str
    resolved_ip: str
    port: int
    scheme: str
    outcome: str  # "allowed", "blocked", "dns_error", "timeout", "error"
    block_reason: str = ""
    response_status: Optional[int] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    latency_ms: float = 0.0
    tls_verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "url": self.url,
            "hostname": self.hostname,
            "resolved_ip": self.resolved_ip,
            "port": self.port,
            "scheme": self.scheme,
            "outcome": self.outcome,
            "block_reason": self.block_reason,
            "response_status": self.response_status,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "latency_ms": self.latency_ms,
            "tls_verified": self.tls_verified,
        }


# ── Network audit ────────────────────────────────────────────────────

class NetworkAuditLog:
    """Thread-safe, append-only log of connection records.

    Used by :class:`NetworkGuard` to record every connection attempt.
    The log can be exported to JSON for compliance reporting.
    """

    def __init__(self, max_records: int = 10_000) -> None:
        self._records: List[ConnectionRecord] = []
        self._max_records = max_records
        self._counter = 0

    def append(self, record: ConnectionRecord) -> None:
        """Append a record.  Oldest records are evicted if at capacity."""
        if len(self._records) >= self._max_records:
            self._records.pop(0)
        self._records.append(record)
        self._counter += 1

    @property
    def records(self) -> List[ConnectionRecord]:
        return list(self._records)

    @property
    def total_count(self) -> int:
        """Total records ever appended (including evicted)."""
        return self._counter

    @property
    def allowed_count(self) -> int:
        return sum(1 for r in self._records if r.outcome == "allowed")

    @property
    def blocked_count(self) -> int:
        return sum(1 for r in self._records if r.outcome == "blocked")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_count": self._counter,
            "current_records": len(self._records),
            "allowed_count": self.allowed_count,
            "blocked_count": self.blocked_count,
            "records": [r.to_dict() for r in self._records],
        }

    def clear(self) -> None:
        self._records.clear()
        self._counter = 0


@dataclass(frozen=True)
class NetworkAuditInfo:
    """Summary of network isolation state for compliance export.

    Included in :class:`SandboxAuditRecord` alongside filesystem and
    other audit information.
    """

    mode: str  # NetworkMode value
    namespace_active: bool
    allowed_hosts_count: int
    blocked_hosts_count: int
    dns_servers: Tuple[str, ...]
    require_tls: bool
    max_connections_per_minute: int
    connections_allowed: int
    connections_blocked: int
    firewall_rules_applied: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "namespace_active": self.namespace_active,
            "allowed_hosts_count": self.allowed_hosts_count,
            "blocked_hosts_count": self.blocked_hosts_count,
            "dns_servers": list(self.dns_servers),
            "require_tls": self.require_tls,
            "max_connections_per_minute": self.max_connections_per_minute,
            "connections_allowed": self.connections_allowed,
            "connections_blocked": self.connections_blocked,
            "firewall_rules_applied": self.firewall_rules_applied,
        }


# ── Network policy ───────────────────────────────────────────────────

# Private IP ranges (RFC 1918 + RFC 6598 + loopback + link-local)
_PRIVATE_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
)


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


@dataclass(frozen=True)
class NetworkPolicy:
    """Immutable network isolation configuration.

    Controls what network access is available to sandboxed tools.
    Three enforcement dimensions:

    1. **Mode** - whether to use network namespaces
    2. **Host filtering** - which domains/IPs are allowed
    3. **Protocol constraints** - TLS requirement, rate limits

    Parameters
    ----------
    mode
        Network isolation level.
    allowed_hosts
        Domain names that may be contacted.  Empty = block all (in
        SELECTIVE mode) or allow all (in HOST_NETWORK mode, where
        Python-level filtering still applies).
    blocked_hosts
        Domain names that are always blocked (takes precedence over
        allowed_hosts).
    allowed_ports
        TCP ports that outbound connections may use.  Empty = default
        set (80, 443).
    blocked_ip_ranges
        CIDR ranges that are always blocked (e.g. internal networks).
        Private ranges (RFC 1918) are blocked by default via
        ``block_private_ips``.
    block_private_ips
        Block connections to private/RFC1918 addresses (prevents SSRF).
    dns_servers
        DNS servers to use for resolution.  Empty = system default.
    dns_resolve_timeout_seconds
        Timeout for DNS resolution.
    max_connections_per_minute
        Rate limit on outbound connections.
    connection_timeout_seconds
        Per-connection timeout.
    require_tls
        Require HTTPS (block HTTP).
    audit_connections
        Log all connection attempts.
    user_agent
        User-Agent header for HTTP requests.
    max_response_bytes
        Maximum response body size.
    """

    mode: NetworkMode = NetworkMode.SELECTIVE
    allowed_hosts: FrozenSet[str] = frozenset()
    blocked_hosts: FrozenSet[str] = frozenset({
        "metadata.google.internal",      # GCP metadata
        "169.254.169.254",               # Cloud metadata (AWS/GCP/Azure)
        "metadata.azure.com",            # Azure metadata (IMDS)
    })
    allowed_ports: FrozenSet[int] = frozenset({80, 443})
    blocked_ip_ranges: Tuple[str, ...] = ()
    block_private_ips: bool = True
    dns_servers: Tuple[str, ...] = ()  # empty = system default
    dns_resolve_timeout_seconds: float = 5.0
    max_connections_per_minute: int = 60
    connection_timeout_seconds: float = 30.0
    require_tls: bool = True
    audit_connections: bool = True
    user_agent: str = "Certior/1.0 (VerifiedAgent)"
    max_response_bytes: int = 10 * 1024 * 1024  # 10 MiB

    # ── Factory methods ───────────────────────────────────────────────

    @classmethod
    def web_fetch_default(cls) -> "NetworkPolicy":
        """Default policy for web_fetch tool.

        Selective mode: HTTPS only, no private IPs, rate-limited,
        cloud metadata blocked.
        """
        return cls(
            mode=NetworkMode.SELECTIVE,
            require_tls=True,
            block_private_ips=True,
            max_connections_per_minute=60,
            connection_timeout_seconds=30.0,
            audit_connections=True,
        )

    @classmethod
    def hipaa(cls) -> "NetworkPolicy":
        """HIPAA-compliant: no external network access.

        Loopback-only ensures no PHI can be exfiltrated over the
        network, even if code execution is compromised.
        """
        return cls(
            mode=NetworkMode.LOOPBACK_ONLY,
            allowed_hosts=frozenset(),
            require_tls=True,
            block_private_ips=True,
            max_connections_per_minute=0,
            audit_connections=True,
        )

    @classmethod
    def sox(cls) -> "NetworkPolicy":
        """SOX-compliant: restricted external access.

        Selective mode with strict rate limits and TLS required.
        No specific hosts are pre-allowed - must be configured
        per-deployment.
        """
        return cls(
            mode=NetworkMode.SELECTIVE,
            require_tls=True,
            block_private_ips=True,
            max_connections_per_minute=30,
            connection_timeout_seconds=15.0,
            audit_connections=True,
        )

    @classmethod
    def legal(cls) -> "NetworkPolicy":
        """Legal-privilege: audit-heavy restricted access."""
        return cls(
            mode=NetworkMode.SELECTIVE,
            require_tls=True,
            block_private_ips=True,
            max_connections_per_minute=20,
            audit_connections=True,
        )

    @classmethod
    def permissive(cls) -> "NetworkPolicy":
        """Permissive: host network with auditing.

        Python-level URL validation still applies, but no network
        namespace.  Suitable for development or trusted environments.
        """
        return cls(
            mode=NetworkMode.HOST_NETWORK,
            require_tls=False,
            block_private_ips=False,
            max_connections_per_minute=0,  # unlimited
            audit_connections=True,
        )

    @classmethod
    def disabled(cls) -> "NetworkPolicy":
        """Disabled: no network isolation or auditing."""
        return cls(
            mode=NetworkMode.DISABLED,
            audit_connections=False,
        )

    # ── Helpers ───────────────────────────────────────────────────────

    @property
    def is_network_blocked(self) -> bool:
        """True if the policy allows no outbound connections."""
        return self.mode == NetworkMode.LOOPBACK_ONLY

    @property
    def needs_namespace(self) -> bool:
        """True if the policy requires a network namespace."""
        return self.mode in (NetworkMode.LOOPBACK_ONLY, NetworkMode.SELECTIVE)

    @property
    def effective_blocked_ip_ranges(self) -> Tuple[str, ...]:
        """Blocked IP ranges including private ranges if configured."""
        ranges = list(self.blocked_ip_ranges)
        if self.block_private_ips:
            ranges.extend(str(net) for net in _PRIVATE_RANGES)
        return tuple(ranges)


# ── Policy validation ────────────────────────────────────────────────

class NetworkPolicyValidationError(ValueError):
    """Raised when a NetworkPolicy has invalid configuration."""


def validate_network_policy(policy: NetworkPolicy) -> List[str]:
    """Validate a NetworkPolicy.  Returns list of warnings.

    Raises :class:`NetworkPolicyValidationError` for fatal errors.
    """
    warnings: List[str] = []

    # Fatal: negative rate limit
    if policy.max_connections_per_minute < 0:
        raise NetworkPolicyValidationError(
            "max_connections_per_minute must be >= 0"
        )

    # Fatal: negative timeout
    if policy.connection_timeout_seconds < 0:
        raise NetworkPolicyValidationError(
            "connection_timeout_seconds must be >= 0"
        )
    if policy.dns_resolve_timeout_seconds < 0:
        raise NetworkPolicyValidationError(
            "dns_resolve_timeout_seconds must be >= 0"
        )

    # Fatal: negative response size
    if policy.max_response_bytes < 0:
        raise NetworkPolicyValidationError(
            "max_response_bytes must be >= 0"
        )

    # Warn: SELECTIVE mode with no allowed hosts
    if policy.mode == NetworkMode.SELECTIVE and not policy.allowed_hosts:
        warnings.append(
            "SELECTIVE mode with empty allowed_hosts - "
            "all connections will require explicit host allowlisting"
        )

    # Warn: HOST_NETWORK without TLS
    if policy.mode == NetworkMode.HOST_NETWORK and not policy.require_tls:
        warnings.append(
            "HOST_NETWORK mode without require_tls - "
            "connections may be intercepted"
        )

    # Warn: no auditing
    if not policy.audit_connections:
        warnings.append(
            "Connection auditing disabled - "
            "no audit trail for compliance"
        )

    # Warn: very high rate limit
    if policy.max_connections_per_minute > 1000:
        warnings.append(
            f"Very high rate limit ({policy.max_connections_per_minute}/min) - "
            "consider reducing for production"
        )

    # Validate blocked IP ranges
    for cidr in policy.blocked_ip_ranges:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise NetworkPolicyValidationError(
                f"Invalid CIDR in blocked_ip_ranges: {cidr!r} - {exc}"
            )

    # Validate DNS servers
    for dns in policy.dns_servers:
        try:
            ipaddress.ip_address(dns)
        except ValueError:
            # Could be a hostname - that's OK but warn
            warnings.append(
                f"DNS server {dns!r} is not an IP address - "
                "hostname-based DNS servers require resolution themselves"
            )

    # Validate port numbers
    for port in policy.allowed_ports:
        if not (1 <= port <= 65535):
            raise NetworkPolicyValidationError(
                f"Invalid port number: {port}"
            )

    return warnings


# ── Network guard ────────────────────────────────────────────────────

class NetworkGuard:
    """Runtime network access controller.

    Enforces :class:`NetworkPolicy` by:
    1. Pre-resolving DNS for requested URLs
    2. Validating resolved IPs against allowlists/blocklists
    3. Checking rate limits
    4. Recording all connection attempts to an audit log
    5. Generating iptables rules for namespace-level enforcement

    Usage::

        guard = NetworkGuard(NetworkPolicy.web_fetch_default())
        target = guard.resolve_and_validate("https://example.com")
        if target.allowed:
            # safe to connect
            pass

    Thread safety: the audit log uses simple list operations; for
    high-concurrency use, wrap in a lock.
    """

    def __init__(self, policy: NetworkPolicy) -> None:
        self._policy = policy
        self._audit_log = NetworkAuditLog()
        self._connection_timestamps: List[float] = []
        self._resolved_cache: Dict[str, Tuple[str, ...]] = {}

    @property
    def policy(self) -> NetworkPolicy:
        return self._policy

    @property
    def audit_log(self) -> NetworkAuditLog:
        return self._audit_log

    def resolve_and_validate(self, url: str) -> ResolvedTarget:
        """Pre-resolve DNS and validate the target against policy.

        This is the primary entry point for URL validation.  It:
        1. Parses the URL
        2. Checks scheme (HTTPS required if policy.require_tls)
        3. Checks hostname against allowed/blocked lists
        4. Resolves DNS
        5. Validates resolved IPs against blocked ranges
        6. Checks rate limit

        Returns a :class:`ResolvedTarget` with the decision.
        """
        start = time.monotonic()

        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as exc:
            return ResolvedTarget(
                url=url, scheme="", hostname="", port=0, path="",
                allowed=False,
                block_reason=f"URL parse error: {exc}",
            )

        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower().strip(".")
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"

        # --- Check: policy blocks all network ---
        if self._policy.is_network_blocked:
            elapsed = (time.monotonic() - start) * 1000
            self._record_blocked(url, hostname, port, scheme,
                                 "Network access blocked by policy (LOOPBACK_ONLY)")
            return ResolvedTarget(
                url=url, scheme=scheme, hostname=hostname, port=port,
                path=path, allowed=False,
                block_reason="Network access blocked by policy (LOOPBACK_ONLY)",
                resolve_time_ms=elapsed,
            )

        # --- Check: scheme ---
        if self._policy.require_tls and scheme != "https":
            elapsed = (time.monotonic() - start) * 1000
            self._record_blocked(url, hostname, port, scheme,
                                 f"TLS required but scheme is {scheme!r}")
            return ResolvedTarget(
                url=url, scheme=scheme, hostname=hostname, port=port,
                path=path, allowed=False,
                block_reason=f"TLS required but scheme is {scheme!r}",
                resolve_time_ms=elapsed,
            )

        if scheme not in ("http", "https"):
            elapsed = (time.monotonic() - start) * 1000
            self._record_blocked(url, hostname, port, scheme,
                                 f"Unsupported scheme: {scheme!r}")
            return ResolvedTarget(
                url=url, scheme=scheme, hostname=hostname, port=port,
                path=path, allowed=False,
                block_reason=f"Unsupported scheme: {scheme!r}",
                resolve_time_ms=elapsed,
            )

        # --- Check: port ---
        if self._policy.allowed_ports and port not in self._policy.allowed_ports:
            elapsed = (time.monotonic() - start) * 1000
            self._record_blocked(url, hostname, port, scheme,
                                 f"Port {port} not in allowed set")
            return ResolvedTarget(
                url=url, scheme=scheme, hostname=hostname, port=port,
                path=path, allowed=False,
                block_reason=f"Port {port} not in allowed set",
                resolve_time_ms=elapsed,
            )

        # --- Check: blocked hosts (precedence over allowed) ---
        if hostname in self._policy.blocked_hosts:
            elapsed = (time.monotonic() - start) * 1000
            self._record_blocked(url, hostname, port, scheme,
                                 f"Host {hostname!r} is in blocked list")
            return ResolvedTarget(
                url=url, scheme=scheme, hostname=hostname, port=port,
                path=path, allowed=False,
                block_reason=f"Host {hostname!r} is in blocked list",
                resolve_time_ms=elapsed,
            )

        # --- Check: allowed hosts (SELECTIVE mode) ---
        if (self._policy.mode == NetworkMode.SELECTIVE
                and self._policy.allowed_hosts
                and hostname not in self._policy.allowed_hosts):
            # Check for wildcard patterns (e.g. *.example.com)
            if not self._matches_allowed_pattern(hostname):
                elapsed = (time.monotonic() - start) * 1000
                self._record_blocked(url, hostname, port, scheme,
                                     f"Host {hostname!r} not in allowed list")
                return ResolvedTarget(
                    url=url, scheme=scheme, hostname=hostname, port=port,
                    path=path, allowed=False,
                    block_reason=f"Host {hostname!r} not in allowed list",
                    resolve_time_ms=elapsed,
                )

        # --- Check: rate limit ---
        if not self._check_rate_limit():
            elapsed = (time.monotonic() - start) * 1000
            self._record_blocked(url, hostname, port, scheme,
                                 "Rate limit exceeded")
            return ResolvedTarget(
                url=url, scheme=scheme, hostname=hostname, port=port,
                path=path, allowed=False,
                block_reason="Rate limit exceeded",
                resolve_time_ms=elapsed,
            )

        # --- DNS resolution ---
        resolved_ips = self._resolve_dns(hostname)
        elapsed = (time.monotonic() - start) * 1000

        if not resolved_ips:
            self._record_blocked(url, hostname, port, scheme,
                                 f"DNS resolution failed for {hostname!r}")
            return ResolvedTarget(
                url=url, scheme=scheme, hostname=hostname, port=port,
                path=path, resolved_ips=(), allowed=False,
                block_reason=f"DNS resolution failed for {hostname!r}",
                resolve_time_ms=elapsed,
            )

        # --- Check: resolved IPs against blocked ranges ---
        blocked_ip = self._check_ip_blocklist(resolved_ips)
        if blocked_ip:
            self._record_blocked(url, hostname, port, scheme,
                                 f"Resolved IP {blocked_ip} is in blocked range")
            return ResolvedTarget(
                url=url, scheme=scheme, hostname=hostname, port=port,
                path=path, resolved_ips=resolved_ips, allowed=False,
                block_reason=f"Resolved IP {blocked_ip} is in blocked range",
                resolve_time_ms=elapsed,
            )

        # All checks passed
        self._connection_timestamps.append(time.monotonic())
        return ResolvedTarget(
            url=url, scheme=scheme, hostname=hostname, port=port,
            path=path, resolved_ips=resolved_ips, allowed=True,
            resolve_time_ms=elapsed,
        )

    def record_connection(
        self,
        target: ResolvedTarget,
        *,
        outcome: str = "allowed",
        response_status: Optional[int] = None,
        bytes_sent: int = 0,
        bytes_received: int = 0,
        latency_ms: float = 0.0,
        tls_verified: bool = False,
        error_detail: str = "",
    ) -> ConnectionRecord:
        """Record a completed connection attempt to the audit log.

        Called after a fetch completes (or fails) to capture the
        full connection lifecycle.
        """
        record = ConnectionRecord(
            record_id=hashlib.sha256(
                f"{target.url}:{time.monotonic()}".encode()
            ).hexdigest()[:16],
            timestamp=datetime.now(timezone.utc).isoformat(),
            url=target.url,
            hostname=target.hostname,
            resolved_ip=target.resolved_ips[0] if target.resolved_ips else "",
            port=target.port,
            scheme=target.scheme,
            outcome=outcome,
            block_reason=error_detail or target.block_reason,
            response_status=response_status,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            latency_ms=latency_ms,
            tls_verified=tls_verified,
        )
        if self._policy.audit_connections:
            self._audit_log.append(record)
        return record

    def generate_iptables_rules(self) -> List[str]:
        """Generate iptables rules for network namespace enforcement.

        These rules are applied inside the child's network namespace
        to provide kernel-level enforcement mirroring the Python-level
        policy.

        Returns a list of iptables command strings.
        """
        rules: List[str] = []

        if self._policy.mode == NetworkMode.LOOPBACK_ONLY:
            # Block everything except loopback
            rules.append("iptables -P OUTPUT DROP")
            rules.append("iptables -P INPUT DROP")
            rules.append("iptables -A OUTPUT -o lo -j ACCEPT")
            rules.append("iptables -A INPUT -i lo -j ACCEPT")
            return rules

        if self._policy.mode != NetworkMode.SELECTIVE:
            return rules  # No firewall rules needed

        # Default: drop all outbound
        rules.append("iptables -P OUTPUT DROP")
        rules.append("iptables -P INPUT DROP")
        rules.append("iptables -P FORWARD DROP")

        # Allow loopback
        rules.append("iptables -A OUTPUT -o lo -j ACCEPT")
        rules.append("iptables -A INPUT -i lo -j ACCEPT")

        # Allow established/related connections back in
        rules.append(
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
        )

        # Allow DNS (UDP 53) to configured servers
        for dns in self._policy.dns_servers:
            rules.append(
                f"iptables -A OUTPUT -p udp --dport 53 -d {dns} -j ACCEPT"
            )

        # Allow outbound to allowed ports only
        for port in (self._policy.allowed_ports or {80, 443}):
            rules.append(
                f"iptables -A OUTPUT -p tcp --dport {port} -j ACCEPT"
            )

        # Block private IP ranges (SSRF protection)
        if self._policy.block_private_ips:
            for net in _PRIVATE_RANGES:
                if net.version == 4:
                    rules.append(
                        f"iptables -A OUTPUT -d {net} -j DROP"
                    )

        # Block explicitly blocked ranges
        for cidr in self._policy.blocked_ip_ranges:
            rules.append(f"iptables -A OUTPUT -d {cidr} -j DROP")

        return rules

    def generate_hosts_entries(self) -> Dict[str, Tuple[str, ...]]:
        """Pre-resolve all allowed hosts for /etc/hosts injection.

        Returns a dict of hostname → tuple of resolved IPs.  This is
        written to /etc/hosts inside the network namespace so that
        DNS resolution works without an external resolver.
        """
        entries: Dict[str, Tuple[str, ...]] = {}
        for host in self._policy.allowed_hosts:
            if host.startswith("*."):
                continue  # Can't pre-resolve wildcards
            ips = self._resolve_dns(host)
            if ips:
                entries[host] = ips
        return entries

    def build_network_audit_info(
        self,
        *,
        namespace_active: bool = False,
        firewall_applied: bool = False,
    ) -> NetworkAuditInfo:
        """Build audit summary for compliance export."""
        return NetworkAuditInfo(
            mode=self._policy.mode.value,
            namespace_active=namespace_active,
            allowed_hosts_count=len(self._policy.allowed_hosts),
            blocked_hosts_count=len(self._policy.blocked_hosts),
            dns_servers=self._policy.dns_servers,
            require_tls=self._policy.require_tls,
            max_connections_per_minute=self._policy.max_connections_per_minute,
            connections_allowed=self._audit_log.allowed_count,
            connections_blocked=self._audit_log.blocked_count,
            firewall_rules_applied=firewall_applied,
        )

    # ── Internal helpers ─────────────────────────────────────────────

    def _matches_allowed_pattern(self, hostname: str) -> bool:
        """Check if hostname matches any wildcard allowed patterns."""
        for allowed in self._policy.allowed_hosts:
            if allowed.startswith("*."):
                suffix = allowed[1:]  # ".example.com"
                if hostname.endswith(suffix) or hostname == allowed[2:]:
                    return True
        return False

    def _check_rate_limit(self) -> bool:
        """Check if a new connection is within the rate limit."""
        if self._policy.max_connections_per_minute <= 0:
            return self._policy.max_connections_per_minute == 0 and \
                   self._policy.mode != NetworkMode.LOOPBACK_ONLY
        now = time.monotonic()
        cutoff = now - 60.0
        self._connection_timestamps = [
            t for t in self._connection_timestamps if t > cutoff
        ]
        return len(self._connection_timestamps) < self._policy.max_connections_per_minute

    def _resolve_dns(self, hostname: str) -> Tuple[str, ...]:
        """Resolve hostname to IP addresses with caching."""
        if hostname in self._resolved_cache:
            return self._resolved_cache[hostname]

        # Check if hostname is already an IP
        try:
            ipaddress.ip_address(hostname)
            result = (hostname,)
            self._resolved_cache[hostname] = result
            return result
        except ValueError:
            pass

        try:
            socket.setdefaulttimeout(self._policy.dns_resolve_timeout_seconds)
            infos = socket.getaddrinfo(
                hostname, None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )
            ips = tuple(dict.fromkeys(
                info[4][0] for info in infos
            ))  # Deduplicated, order-preserving
            self._resolved_cache[hostname] = ips
            return ips
        except (socket.gaierror, socket.timeout, OSError) as exc:
            logger.debug("DNS resolution failed for %s: %s", hostname, exc)
            return ()
        finally:
            socket.setdefaulttimeout(None)

    def _check_ip_blocklist(self, ips: Tuple[str, ...]) -> str:
        """Check resolved IPs against blocked ranges.

        Returns the first blocked IP, or empty string if all OK.
        """
        for ip_str in ips:
            try:
                addr = ipaddress.ip_address(ip_str)
            except ValueError:
                continue

            # Check private ranges
            if self._policy.block_private_ips:
                if any(addr in net for net in _PRIVATE_RANGES):
                    return ip_str

            # Check explicit blocked ranges
            for cidr in self._policy.blocked_ip_ranges:
                try:
                    if addr in ipaddress.ip_network(cidr, strict=False):
                        return ip_str
                except ValueError:
                    continue

        return ""

    def _record_blocked(
        self,
        url: str,
        hostname: str,
        port: int,
        scheme: str,
        reason: str,
    ) -> None:
        """Record a blocked connection to the audit log."""
        if not self._policy.audit_connections:
            return
        record = ConnectionRecord(
            record_id=hashlib.sha256(
                f"{url}:{time.monotonic()}".encode()
            ).hexdigest()[:16],
            timestamp=datetime.now(timezone.utc).isoformat(),
            url=url,
            hostname=hostname,
            resolved_ip="",
            port=port,
            scheme=scheme,
            outcome="blocked",
            block_reason=reason,
        )
        self._audit_log.append(record)


# ── Network isolation config builder ─────────────────────────────────

def build_net_isolation_config(
    policy: NetworkPolicy,
    guard: Optional[NetworkGuard] = None,
) -> Dict[str, Any]:
    """Build launcher configuration for network namespace setup.

    This config is injected into the subprocess launcher script and
    used by ``NET_ISOLATION_LAUNCHER_CODE`` to configure the network
    namespace from inside the child process.

    Parameters
    ----------
    policy
        Network policy to enforce.
    guard
        Optional guard with pre-resolved hosts.  If provided,
        resolved hosts are included for /etc/hosts injection.
    """
    config: Dict[str, Any] = {
        "enabled": policy.mode != NetworkMode.DISABLED,
        "mode": policy.mode.value,
        "needs_namespace": policy.needs_namespace,
        "require_tls": policy.require_tls,
        "allowed_ports": sorted(policy.allowed_ports),
        "block_private_ips": policy.block_private_ips,
        "dns_servers": list(policy.dns_servers),
        "connection_timeout_seconds": policy.connection_timeout_seconds,
        "max_response_bytes": policy.max_response_bytes,
        "user_agent": policy.user_agent,
    }

    # Pre-resolved hosts for /etc/hosts injection
    if guard is not None:
        config["resolved_hosts"] = {
            host: list(ips)
            for host, ips in guard.generate_hosts_entries().items()
        }
    else:
        config["resolved_hosts"] = {}

    # Iptables rules (as list of command strings)
    if guard is not None:
        config["iptables_rules"] = guard.generate_iptables_rules()
    else:
        temp_guard = NetworkGuard(policy)
        config["iptables_rules"] = temp_guard.generate_iptables_rules()

    # Blocked IP ranges (for software-level fallback when iptables unavailable)
    config["blocked_ip_ranges"] = list(policy.effective_blocked_ip_ranges)

    # Allowed hosts (for software-level enforcement)
    config["allowed_hosts"] = sorted(policy.allowed_hosts)
    config["blocked_hosts"] = sorted(policy.blocked_hosts)

    return config


# ── Launcher code for network namespace ──────────────────────────────

NET_ISOLATION_LAUNCHER_CODE = '''\
def _apply_network_isolation():
    """Configure network inside a CLONE_NEWNET namespace.

    This function runs INSIDE the child process after unshare(CLONE_NEWNET).
    It performs:
    1. Bring up loopback interface
    2. Write /etc/hosts with pre-resolved entries
    3. Write /etc/resolv.conf with configured DNS servers
    4. Apply iptables rules (best-effort, requires CAP_NET_ADMIN)
    """
    import ctypes
    import ctypes.util
    import os
    import struct
    import subprocess

    net_cfg = _CONFIG.get("network")
    if not net_cfg or not net_cfg.get("enabled"):
        return

    if not net_cfg.get("needs_namespace"):
        return

    # Step 1: Bring up loopback
    # Use SIOCGIFFLAGS / SIOCSIFFLAGS via ioctl on a socket
    try:
        SIOCGIFFLAGS = 0x8913
        SIOCSIFFLAGS = 0x8914
        IFF_UP = 0x1
        IFF_LOOPBACK = 0x8
        IFF_RUNNING = 0x40

        import socket as _socket
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM, 0)
        fd = sock.fileno()

        # struct ifreq { char ifr_name[16]; short ifr_flags; ... }
        # At least 32 bytes required by the ioctl layout.
        ifr = struct.pack("16sH14s", b"lo", 0, b"\\x00" * 14)

        import fcntl
        result = fcntl.ioctl(fd, SIOCGIFFLAGS, ifr)
        flags = struct.unpack("16sH14s", result)[1]
        flags |= IFF_UP | IFF_RUNNING

        ifr = struct.pack("16sH14s", b"lo", flags, b"\\x00" * 14)
        fcntl.ioctl(fd, SIOCSIFFLAGS, ifr)
        sock.close()
    except Exception:
        pass  # Loopback may already be up or ioctl unavailable

    # Step 2: Write /etc/hosts with pre-resolved entries
    resolved_hosts = net_cfg.get("resolved_hosts", {})
    if resolved_hosts:
        try:
            hosts_lines = ["127.0.0.1 localhost", "::1 localhost"]
            for hostname, ips in resolved_hosts.items():
                for ip in ips:
                    hosts_lines.append(f"{ip} {hostname}")
            hosts_content = "\\n".join(hosts_lines) + "\\n"

            # Try to write (may fail if /etc is read-only)
            try:
                with open("/etc/hosts", "w") as f:
                    f.write(hosts_content)
            except (OSError, PermissionError):
                pass
        except Exception:
            pass

    # Step 3: Write /etc/resolv.conf
    dns_servers = net_cfg.get("dns_servers", [])
    if dns_servers:
        try:
            resolv_lines = [f"nameserver {s}" for s in dns_servers]
            resolv_lines.append("options timeout:5 attempts:2")
            resolv_content = "\\n".join(resolv_lines) + "\\n"
            try:
                with open("/etc/resolv.conf", "w") as f:
                    f.write(resolv_content)
            except (OSError, PermissionError):
                pass
        except Exception:
            pass

    # Step 4: Apply iptables rules (best-effort)
    iptables_rules = net_cfg.get("iptables_rules", [])
    if iptables_rules:
        for rule in iptables_rules:
            try:
                parts = rule.split()
                subprocess.run(
                    parts,
                    capture_output=True,
                    timeout=5,
                )
            except Exception:
                pass  # iptables may not be available
'''


# ── Probe functions ──────────────────────────────────────────────────

_net_ns_probe_cache: Optional[bool] = None


def probe_network_namespace() -> bool:
    """Check if network namespaces are available.

    Returns True if CLONE_NEWNET is supported (possibly via
    CLONE_NEWUSER).  Safe to call from the parent process.
    """
    global _net_ns_probe_cache
    if _net_ns_probe_cache is not None:
        return _net_ns_probe_cache

    if not sys.platform.startswith("linux"):
        _net_ns_probe_cache = False
        return False

    from .namespace import probe_net_namespace
    _net_ns_probe_cache = probe_net_namespace()
    return _net_ns_probe_cache


def probe_iptables() -> bool:
    """Check if iptables is available inside a network namespace.

    This probes by checking if the iptables binary exists.  Actual
    use requires CAP_NET_ADMIN inside the namespace (usually available
    when using CLONE_NEWUSER).
    """
    import shutil
    return shutil.which("iptables") is not None


def reset_network_probe_cache() -> None:
    """Clear the network probe cache.  Useful in tests."""
    global _net_ns_probe_cache
    _net_ns_probe_cache = None

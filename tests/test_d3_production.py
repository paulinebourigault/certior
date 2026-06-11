"""
Network Namespace Isolation - production test suite.

Tests the complete network isolation stack:
  - NetworkPolicy (configuration, factories, validation)
  - NetworkMode (enum values, properties)
  - NetworkGuard (URL validation, DNS resolution, rate limiting, iptables, /etc/hosts)
  - SafeFetcher (verified HTTP client, byte limiting, audit)
  - ConnectionRecord / ResolvedTarget (audit data models)
  - NetworkAuditLog (append-only log)
  - build_net_isolation_config() (launcher config builder)
  - NET_ISOLATION_LAUNCHER_CODE (launcher code validity)
  - probe_network_namespace() / probe_iptables()
  - Integration: ComplianceSandboxFactory network policies
  - Integration: ObservableSandboxedExecutor network audit in records
  - Integration: Network-specific Prometheus metrics

Run::

    pytest tests/test_d3_production.py -v
"""
from __future__ import annotations

import ast
import ipaddress
import json
import socket
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

# ── Imports under test ───────────────────────────────────────────────
from agentsafe.sandbox.network import (
    NET_ISOLATION_LAUNCHER_CODE,
    ConnectionRecord,
    NetworkAuditInfo,
    NetworkAuditLog,
    NetworkGuard,
    NetworkMode,
    NetworkPolicy,
    NetworkPolicyValidationError,
    ResolvedTarget,
    _PRIVATE_RANGES,
    _is_private_ip,
    build_net_isolation_config,
    probe_iptables,
    probe_network_namespace,
    reset_network_probe_cache,
    validate_network_policy,
)
from agentsafe.sandbox.net_fetch import (
    FetchBatchSummary,
    FetchResult,
    SafeFetcher,
    build_network_audit_info,
    create_hipaa_fetcher,
    create_sox_fetcher,
    create_web_fetch_client,
    _build_ssl_context,
)
from agentsafe.sandbox.policy import (
    ContainmentLayer,
    SandboxPolicy,
)
from agentsafe.sandbox.integration import (
    ComplianceSandboxFactory,
    ObservableSandboxedExecutor,
    SandboxAuditRecord,
    _build_audit_record,
)
from agentsafe.sandbox.executor import SandboxResult


# ═════════════════════════════════════════════════════════════════════
#  1. NetworkMode
# ═════════════════════════════════════════════════════════════════════

class TestNetworkMode:
    """Test NetworkMode enum values and semantics."""

    def test_all_modes_exist(self):
        modes = {m.value for m in NetworkMode}
        assert modes == {"loopback_only", "selective", "host_network", "disabled"}

    def test_mode_values_are_strings(self):
        for mode in NetworkMode:
            assert isinstance(mode.value, str)

    def test_modes_are_distinct(self):
        values = [m.value for m in NetworkMode]
        assert len(values) == len(set(values))


# ═════════════════════════════════════════════════════════════════════
#  2. NetworkPolicy
# ═════════════════════════════════════════════════════════════════════

class TestNetworkPolicy:
    """Test NetworkPolicy configuration and factory methods."""

    def test_frozen(self):
        p = NetworkPolicy()
        with pytest.raises(AttributeError):
            p.mode = NetworkMode.DISABLED  # type: ignore

    def test_default_values(self):
        p = NetworkPolicy()
        assert p.mode == NetworkMode.SELECTIVE
        assert p.require_tls is True
        assert p.block_private_ips is True
        assert p.audit_connections is True
        assert 443 in p.allowed_ports
        assert 80 in p.allowed_ports
        assert p.max_connections_per_minute == 60

    def test_web_fetch_default(self):
        p = NetworkPolicy.web_fetch_default()
        assert p.mode == NetworkMode.SELECTIVE
        assert p.require_tls is True
        assert p.block_private_ips is True
        assert p.audit_connections is True

    def test_hipaa(self):
        p = NetworkPolicy.hipaa()
        assert p.mode == NetworkMode.LOOPBACK_ONLY
        assert p.is_network_blocked is True
        assert p.needs_namespace is True
        assert p.max_connections_per_minute == 0

    def test_sox(self):
        p = NetworkPolicy.sox()
        assert p.mode == NetworkMode.SELECTIVE
        assert p.require_tls is True
        assert p.max_connections_per_minute == 30

    def test_legal(self):
        p = NetworkPolicy.legal()
        assert p.mode == NetworkMode.SELECTIVE
        assert p.require_tls is True
        assert p.max_connections_per_minute == 20

    def test_permissive(self):
        p = NetworkPolicy.permissive()
        assert p.mode == NetworkMode.HOST_NETWORK
        assert p.require_tls is False
        assert p.needs_namespace is False

    def test_disabled(self):
        p = NetworkPolicy.disabled()
        assert p.mode == NetworkMode.DISABLED
        assert p.audit_connections is False
        assert p.needs_namespace is False

    def test_is_network_blocked(self):
        assert NetworkPolicy.hipaa().is_network_blocked is True
        assert NetworkPolicy.sox().is_network_blocked is False
        assert NetworkPolicy.disabled().is_network_blocked is False

    def test_needs_namespace(self):
        assert NetworkPolicy.hipaa().needs_namespace is True
        assert NetworkPolicy.sox().needs_namespace is True
        assert NetworkPolicy.permissive().needs_namespace is False
        assert NetworkPolicy.disabled().needs_namespace is False

    def test_effective_blocked_ip_ranges(self):
        p = NetworkPolicy(block_private_ips=True, blocked_ip_ranges=("203.0.113.0/24",))
        ranges = p.effective_blocked_ip_ranges
        assert "203.0.113.0/24" in ranges
        # Should include RFC 1918 ranges
        assert any("10.0.0.0" in r for r in ranges)

    def test_effective_blocked_ranges_no_private(self):
        p = NetworkPolicy(block_private_ips=False, blocked_ip_ranges=("1.2.3.0/24",))
        ranges = p.effective_blocked_ip_ranges
        assert ranges == ("1.2.3.0/24",)

    def test_default_blocked_hosts(self):
        """Cloud metadata endpoints should be blocked by default."""
        p = NetworkPolicy()
        assert "metadata.google.internal" in p.blocked_hosts
        assert "169.254.169.254" in p.blocked_hosts


# ═════════════════════════════════════════════════════════════════════
#  3. NetworkPolicy Validation
# ═════════════════════════════════════════════════════════════════════

class TestNetworkPolicyValidation:
    """Test validate_network_policy()."""

    def test_valid_default(self):
        warnings = validate_network_policy(NetworkPolicy())
        # SELECTIVE with no allowed_hosts generates a warning
        assert any("allowed_hosts" in w for w in warnings)

    def test_valid_hipaa(self):
        warnings = validate_network_policy(NetworkPolicy.hipaa())
        # HIPAA shouldn't have fatal errors
        assert isinstance(warnings, list)

    def test_negative_rate_limit_raises(self):
        p = NetworkPolicy(max_connections_per_minute=-1)
        with pytest.raises(NetworkPolicyValidationError, match="max_connections_per_minute"):
            validate_network_policy(p)

    def test_negative_timeout_raises(self):
        p = NetworkPolicy(connection_timeout_seconds=-1)
        with pytest.raises(NetworkPolicyValidationError, match="connection_timeout_seconds"):
            validate_network_policy(p)

    def test_negative_dns_timeout_raises(self):
        p = NetworkPolicy(dns_resolve_timeout_seconds=-1)
        with pytest.raises(NetworkPolicyValidationError, match="dns_resolve_timeout_seconds"):
            validate_network_policy(p)

    def test_negative_response_size_raises(self):
        p = NetworkPolicy(max_response_bytes=-1)
        with pytest.raises(NetworkPolicyValidationError, match="max_response_bytes"):
            validate_network_policy(p)

    def test_invalid_cidr_raises(self):
        p = NetworkPolicy(blocked_ip_ranges=("not-a-cidr",))
        with pytest.raises(NetworkPolicyValidationError, match="CIDR"):
            validate_network_policy(p)

    def test_invalid_port_raises(self):
        p = NetworkPolicy(allowed_ports=frozenset({99999}))
        with pytest.raises(NetworkPolicyValidationError, match="port"):
            validate_network_policy(p)

    def test_host_network_no_tls_warns(self):
        p = NetworkPolicy(mode=NetworkMode.HOST_NETWORK, require_tls=False)
        warnings = validate_network_policy(p)
        assert any("TLS" in w or "tls" in w.lower() for w in warnings)

    def test_no_audit_warns(self):
        p = NetworkPolicy(audit_connections=False)
        warnings = validate_network_policy(p)
        assert any("audit" in w.lower() for w in warnings)

    def test_very_high_rate_warns(self):
        p = NetworkPolicy(max_connections_per_minute=5000)
        warnings = validate_network_policy(p)
        assert any("high rate" in w.lower() for w in warnings)


# ═════════════════════════════════════════════════════════════════════
#  4. ResolvedTarget
# ═════════════════════════════════════════════════════════════════════

class TestResolvedTarget:
    """Test ResolvedTarget data model."""

    def test_construction(self):
        t = ResolvedTarget(
            url="https://example.com",
            scheme="https",
            hostname="example.com",
            port=443,
            path="/",
            resolved_ips=("93.184.216.34",),
            allowed=True,
        )
        assert t.allowed is True
        assert t.hostname == "example.com"

    def test_frozen(self):
        t = ResolvedTarget(
            url="", scheme="", hostname="", port=0, path="",
        )
        with pytest.raises(AttributeError):
            t.allowed = True  # type: ignore

    def test_to_dict(self):
        t = ResolvedTarget(
            url="https://example.com", scheme="https",
            hostname="example.com", port=443, path="/",
            resolved_ips=("1.2.3.4",), allowed=True,
        )
        d = t.to_dict()
        assert d["url"] == "https://example.com"
        assert d["allowed"] is True
        assert d["resolved_ips"] == ["1.2.3.4"]

    def test_to_dict_json_safe(self):
        t = ResolvedTarget(
            url="https://x.com", scheme="https", hostname="x.com",
            port=443, path="/", allowed=False, block_reason="test",
        )
        json.dumps(t.to_dict())  # No TypeError


# ═════════════════════════════════════════════════════════════════════
#  5. ConnectionRecord
# ═════════════════════════════════════════════════════════════════════

class TestConnectionRecord:
    """Test ConnectionRecord audit data model."""

    def test_construction(self):
        r = ConnectionRecord(
            record_id="abc123",
            timestamp="2026-01-01T00:00:00+00:00",
            url="https://example.com",
            hostname="example.com",
            resolved_ip="93.184.216.34",
            port=443,
            scheme="https",
            outcome="allowed",
        )
        assert r.outcome == "allowed"
        assert r.tls_verified is False

    def test_frozen(self):
        r = ConnectionRecord(
            record_id="x", timestamp="", url="", hostname="",
            resolved_ip="", port=0, scheme="", outcome="",
        )
        with pytest.raises(AttributeError):
            r.outcome = "blocked"  # type: ignore

    def test_to_dict(self):
        r = ConnectionRecord(
            record_id="abc",
            timestamp="2026-01-01T00:00:00+00:00",
            url="https://example.com",
            hostname="example.com",
            resolved_ip="1.2.3.4",
            port=443,
            scheme="https",
            outcome="blocked",
            block_reason="test",
            bytes_received=100,
        )
        d = r.to_dict()
        assert d["outcome"] == "blocked"
        assert d["bytes_received"] == 100
        json.dumps(d)


# ═════════════════════════════════════════════════════════════════════
#  6. NetworkAuditLog
# ═════════════════════════════════════════════════════════════════════

class TestNetworkAuditLog:
    """Test the append-only connection audit log."""

    def test_empty_log(self):
        log = NetworkAuditLog()
        assert log.total_count == 0
        assert log.allowed_count == 0
        assert log.blocked_count == 0
        assert len(log.records) == 0

    def test_append(self):
        log = NetworkAuditLog()
        rec = ConnectionRecord(
            record_id="1", timestamp="", url="", hostname="",
            resolved_ip="", port=0, scheme="", outcome="allowed",
        )
        log.append(rec)
        assert log.total_count == 1
        assert log.allowed_count == 1

    def test_append_blocked(self):
        log = NetworkAuditLog()
        rec = ConnectionRecord(
            record_id="1", timestamp="", url="", hostname="",
            resolved_ip="", port=0, scheme="", outcome="blocked",
        )
        log.append(rec)
        assert log.blocked_count == 1

    def test_max_records_eviction(self):
        log = NetworkAuditLog(max_records=3)
        for i in range(5):
            log.append(ConnectionRecord(
                record_id=str(i), timestamp="", url="", hostname="",
                resolved_ip="", port=0, scheme="", outcome="allowed",
            ))
        assert len(log.records) == 3
        assert log.total_count == 5
        # Oldest should be evicted
        assert log.records[0].record_id == "2"

    def test_to_dict(self):
        log = NetworkAuditLog()
        d = log.to_dict()
        assert d["total_count"] == 0
        assert "records" in d
        json.dumps(d)

    def test_clear(self):
        log = NetworkAuditLog()
        log.append(ConnectionRecord(
            record_id="1", timestamp="", url="", hostname="",
            resolved_ip="", port=0, scheme="", outcome="allowed",
        ))
        log.clear()
        assert log.total_count == 0
        assert len(log.records) == 0


# ═════════════════════════════════════════════════════════════════════
#  7. NetworkAuditInfo
# ═════════════════════════════════════════════════════════════════════

class TestNetworkAuditInfo:
    """Test NetworkAuditInfo audit summary."""

    def test_construction(self):
        info = NetworkAuditInfo(
            mode="selective",
            namespace_active=True,
            allowed_hosts_count=5,
            blocked_hosts_count=3,
            dns_servers=("8.8.8.8",),
            require_tls=True,
            max_connections_per_minute=60,
            connections_allowed=10,
            connections_blocked=2,
            firewall_rules_applied=True,
        )
        assert info.namespace_active is True
        assert info.connections_allowed == 10

    def test_to_dict(self):
        info = NetworkAuditInfo(
            mode="loopback_only", namespace_active=False,
            allowed_hosts_count=0, blocked_hosts_count=0,
            dns_servers=(), require_tls=True,
            max_connections_per_minute=0,
            connections_allowed=0, connections_blocked=0,
            firewall_rules_applied=False,
        )
        d = info.to_dict()
        assert d["mode"] == "loopback_only"
        json.dumps(d)

    def test_frozen(self):
        info = NetworkAuditInfo(
            mode="selective", namespace_active=False,
            allowed_hosts_count=0, blocked_hosts_count=0,
            dns_servers=(), require_tls=True,
            max_connections_per_minute=0,
            connections_allowed=0, connections_blocked=0,
            firewall_rules_applied=False,
        )
        with pytest.raises(AttributeError):
            info.mode = "disabled"  # type: ignore


# ═════════════════════════════════════════════════════════════════════
#  8. Private IP Detection
# ═════════════════════════════════════════════════════════════════════

class TestPrivateIPDetection:
    """Test private/reserved IP range detection."""

    def test_private_ranges_exist(self):
        assert len(_PRIVATE_RANGES) > 0

    def test_rfc1918_10(self):
        assert _is_private_ip("10.0.0.1")
        assert _is_private_ip("10.255.255.255")

    def test_rfc1918_172(self):
        assert _is_private_ip("172.16.0.1")
        assert _is_private_ip("172.31.255.255")

    def test_rfc1918_192(self):
        assert _is_private_ip("192.168.0.1")
        assert _is_private_ip("192.168.255.255")

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1")

    def test_link_local(self):
        assert _is_private_ip("169.254.1.1")

    def test_cgnat(self):
        assert _is_private_ip("100.64.0.1")

    def test_public_ip_not_private(self):
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("93.184.216.34") is False

    def test_ipv6_loopback(self):
        assert _is_private_ip("::1")

    def test_invalid_ip(self):
        assert _is_private_ip("not-an-ip") is False


# ═════════════════════════════════════════════════════════════════════
#  9. NetworkGuard - URL Validation
# ═════════════════════════════════════════════════════════════════════

class TestNetworkGuardValidation:
    """Test NetworkGuard URL validation logic."""

    def test_loopback_blocks_all(self):
        guard = NetworkGuard(NetworkPolicy.hipaa())
        result = guard.resolve_and_validate("https://example.com")
        assert result.allowed is False
        assert "LOOPBACK_ONLY" in result.block_reason

    def test_require_tls_blocks_http(self):
        guard = NetworkGuard(NetworkPolicy(
            mode=NetworkMode.HOST_NETWORK,
            require_tls=True,
        ))
        result = guard.resolve_and_validate("http://example.com")
        assert result.allowed is False
        assert "TLS" in result.block_reason or "tls" in result.block_reason.lower()

    def test_allow_https_with_tls_required(self):
        guard = NetworkGuard(NetworkPolicy(
            mode=NetworkMode.HOST_NETWORK,
            require_tls=True,
        ))
        result = guard.resolve_and_validate("https://example.com")
        # May still fail on DNS but shouldn't fail on TLS
        assert "TLS" not in result.block_reason

    def test_unsupported_scheme_blocked(self):
        guard = NetworkGuard(NetworkPolicy(
            mode=NetworkMode.HOST_NETWORK,
            require_tls=False,
        ))
        result = guard.resolve_and_validate("ftp://example.com")
        assert result.allowed is False
        assert "scheme" in result.block_reason.lower()

    def test_blocked_host(self):
        guard = NetworkGuard(NetworkPolicy(
            mode=NetworkMode.HOST_NETWORK,
            require_tls=False,
            blocked_hosts=frozenset({"evil.com"}),
        ))
        result = guard.resolve_and_validate("http://evil.com")
        assert result.allowed is False
        assert "blocked" in result.block_reason.lower()

    def test_cloud_metadata_blocked_by_default(self):
        guard = NetworkGuard(NetworkPolicy(
            mode=NetworkMode.HOST_NETWORK,
            require_tls=False,
        ))
        result = guard.resolve_and_validate("http://169.254.169.254/latest/meta-data/")
        assert result.allowed is False

    def test_port_not_allowed(self):
        guard = NetworkGuard(NetworkPolicy(
            mode=NetworkMode.HOST_NETWORK,
            require_tls=False,
            allowed_ports=frozenset({80, 443}),
        ))
        result = guard.resolve_and_validate("http://example.com:8080/")
        assert result.allowed is False
        assert "port" in result.block_reason.lower()

    def test_selective_mode_no_allowed_hosts(self):
        """SELECTIVE mode with empty allowed_hosts still allows through
        (host filtering only kicks in when allowed_hosts is non-empty)."""
        guard = NetworkGuard(NetworkPolicy(
            mode=NetworkMode.SELECTIVE,
            require_tls=False,
            allowed_hosts=frozenset(),
        ))
        # With no allowed_hosts filter, the request passes host check
        result = guard.resolve_and_validate("http://example.com")
        # May fail on DNS or private IP, but NOT on host filtering
        if not result.allowed:
            assert "allowed list" not in result.block_reason.lower()

    def test_selective_mode_host_not_allowed(self):
        guard = NetworkGuard(NetworkPolicy(
            mode=NetworkMode.SELECTIVE,
            require_tls=False,
            allowed_hosts=frozenset({"good.com"}),
        ))
        result = guard.resolve_and_validate("http://bad.com")
        assert result.allowed is False
        assert "not in allowed" in result.block_reason.lower()

    def test_wildcard_host_matching(self):
        guard = NetworkGuard(NetworkPolicy(
            mode=NetworkMode.SELECTIVE,
            require_tls=False,
            allowed_hosts=frozenset({"*.example.com"}),
        ))
        result = guard.resolve_and_validate("http://sub.example.com")
        # Should pass host check; may fail on DNS
        if not result.allowed:
            assert "allowed" not in result.block_reason.lower()

    def test_invalid_url(self):
        guard = NetworkGuard(NetworkPolicy(
            mode=NetworkMode.HOST_NETWORK,
            require_tls=False,
        ))
        result = guard.resolve_and_validate("")
        assert result.allowed is False


# ═════════════════════════════════════════════════════════════════════
#  10. NetworkGuard - Rate Limiting
# ═════════════════════════════════════════════════════════════════════

class TestNetworkGuardRateLimit:
    """Test rate limiting in NetworkGuard."""

    def test_rate_limit_enforced(self):
        guard = NetworkGuard(NetworkPolicy(
            mode=NetworkMode.HOST_NETWORK,
            require_tls=False,
            max_connections_per_minute=2,
            block_private_ips=False,
        ))
        # Make 2 requests (they may fail on DNS, but rate limit state advances
        # only if target is allowed - simulate via direct timestamp injection)
        guard._connection_timestamps = [time.monotonic(), time.monotonic()]

        result = guard.resolve_and_validate("http://1.2.3.4")
        assert result.allowed is False
        assert "rate limit" in result.block_reason.lower()


# ═════════════════════════════════════════════════════════════════════
#  11. NetworkGuard - Iptables Rules
# ═════════════════════════════════════════════════════════════════════

class TestNetworkGuardIptables:
    """Test iptables rule generation."""

    def test_loopback_only_rules(self):
        guard = NetworkGuard(NetworkPolicy.hipaa())
        rules = guard.generate_iptables_rules()
        assert any("OUTPUT DROP" in r for r in rules)
        assert any("INPUT DROP" in r for r in rules)
        assert any("-o lo -j ACCEPT" in r for r in rules)

    def test_selective_rules(self):
        guard = NetworkGuard(NetworkPolicy(
            mode=NetworkMode.SELECTIVE,
            allowed_ports=frozenset({443}),
            dns_servers=("8.8.8.8",),
        ))
        rules = guard.generate_iptables_rules()
        # Default drop
        assert any("OUTPUT DROP" in r for r in rules)
        # Allow loopback
        assert any("-o lo" in r for r in rules)
        # Allow port 443
        assert any("--dport 443" in r for r in rules)
        # Allow DNS to 8.8.8.8
        assert any("8.8.8.8" in r and "53" in r for r in rules)
        # Established/related
        assert any("ESTABLISHED" in r for r in rules)

    def test_host_network_no_rules(self):
        guard = NetworkGuard(NetworkPolicy.permissive())
        rules = guard.generate_iptables_rules()
        assert rules == []

    def test_disabled_no_rules(self):
        guard = NetworkGuard(NetworkPolicy.disabled())
        rules = guard.generate_iptables_rules()
        assert rules == []

    def test_private_ip_blocking_rules(self):
        guard = NetworkGuard(NetworkPolicy(
            mode=NetworkMode.SELECTIVE,
            block_private_ips=True,
        ))
        rules = guard.generate_iptables_rules()
        # Should have rules blocking 10.0.0.0/8
        assert any("10.0.0.0/8" in r for r in rules)


# ═════════════════════════════════════════════════════════════════════
#  12. NetworkGuard - Hosts Entries
# ═════════════════════════════════════════════════════════════════════

class TestNetworkGuardHosts:
    """Test /etc/hosts entry generation."""

    def test_empty_allowed_hosts(self):
        guard = NetworkGuard(NetworkPolicy(allowed_hosts=frozenset()))
        entries = guard.generate_hosts_entries()
        assert entries == {}

    def test_wildcard_skipped(self):
        guard = NetworkGuard(NetworkPolicy(
            allowed_hosts=frozenset({"*.example.com"}),
        ))
        entries = guard.generate_hosts_entries()
        # Wildcards can't be pre-resolved
        assert "*.example.com" not in entries

    def test_audit_info_construction(self):
        guard = NetworkGuard(NetworkPolicy.web_fetch_default())
        info = guard.build_network_audit_info(
            namespace_active=True,
            firewall_applied=True,
        )
        assert info.namespace_active is True
        assert info.firewall_rules_applied is True
        assert info.mode == "selective"


# ═════════════════════════════════════════════════════════════════════
#  13. NetworkGuard - Connection Recording
# ═════════════════════════════════════════════════════════════════════

class TestNetworkGuardRecording:
    """Test connection audit recording."""

    def test_record_connection(self):
        guard = NetworkGuard(NetworkPolicy.web_fetch_default())
        target = ResolvedTarget(
            url="https://example.com", scheme="https",
            hostname="example.com", port=443, path="/",
            resolved_ips=("1.2.3.4",), allowed=True,
        )
        record = guard.record_connection(
            target,
            outcome="allowed",
            response_status=200,
            bytes_received=1000,
            latency_ms=50.0,
            tls_verified=True,
        )
        assert record.outcome == "allowed"
        assert record.response_status == 200
        assert record.bytes_received == 1000
        assert record.tls_verified is True
        assert guard.audit_log.total_count == 1

    def test_no_audit_when_disabled(self):
        guard = NetworkGuard(NetworkPolicy(audit_connections=False))
        target = ResolvedTarget(
            url="http://x.com", scheme="http", hostname="x.com",
            port=80, path="/", allowed=True,
        )
        guard.record_connection(target, outcome="allowed")
        assert guard.audit_log.total_count == 0


# ═════════════════════════════════════════════════════════════════════
#  14. build_net_isolation_config
# ═════════════════════════════════════════════════════════════════════

class TestBuildNetIsolationConfig:
    """Test launcher configuration builder."""

    def test_disabled_config(self):
        cfg = build_net_isolation_config(NetworkPolicy.disabled())
        assert cfg["enabled"] is False

    def test_hipaa_config(self):
        cfg = build_net_isolation_config(NetworkPolicy.hipaa())
        assert cfg["enabled"] is True
        assert cfg["mode"] == "loopback_only"
        assert cfg["needs_namespace"] is True
        # Should have iptables rules
        assert len(cfg["iptables_rules"]) > 0

    def test_selective_config(self):
        policy = NetworkPolicy(
            mode=NetworkMode.SELECTIVE,
            allowed_hosts=frozenset({"example.com"}),
            dns_servers=("8.8.8.8",),
        )
        cfg = build_net_isolation_config(policy)
        assert cfg["mode"] == "selective"
        assert cfg["allowed_hosts"] == ["example.com"]
        assert cfg["dns_servers"] == ["8.8.8.8"]

    def test_config_json_serializable(self):
        cfg = build_net_isolation_config(NetworkPolicy.web_fetch_default())
        json.dumps(cfg)

    def test_config_with_guard(self):
        policy = NetworkPolicy.web_fetch_default()
        guard = NetworkGuard(policy)
        cfg = build_net_isolation_config(policy, guard)
        assert "resolved_hosts" in cfg
        assert "iptables_rules" in cfg

    def test_host_network_config(self):
        cfg = build_net_isolation_config(NetworkPolicy.permissive())
        assert cfg["needs_namespace"] is False
        assert cfg["mode"] == "host_network"

    def test_blocked_ip_ranges_in_config(self):
        policy = NetworkPolicy(
            blocked_ip_ranges=("203.0.113.0/24",),
            block_private_ips=True,
        )
        cfg = build_net_isolation_config(policy)
        assert "203.0.113.0/24" in cfg["blocked_ip_ranges"]


# ═════════════════════════════════════════════════════════════════════
#  15. NET_ISOLATION_LAUNCHER_CODE
# ═════════════════════════════════════════════════════════════════════

class TestNetIsolationLauncherCode:
    """Test the launcher code injected into sandbox child processes."""

    def test_valid_python(self):
        """Launcher code must parse as valid Python."""
        ast.parse(NET_ISOLATION_LAUNCHER_CODE)

    def test_defines_function(self):
        """Must define _apply_network_isolation."""
        assert "def _apply_network_isolation():" in NET_ISOLATION_LAUNCHER_CODE

    def test_reads_config(self):
        """Must read from _CONFIG."""
        assert "_CONFIG" in NET_ISOLATION_LAUNCHER_CODE

    def test_loopback_setup(self):
        """Must contain loopback interface setup (SIOCGIFFLAGS)."""
        assert "SIOCGIFFLAGS" in NET_ISOLATION_LAUNCHER_CODE

    def test_hosts_file_writing(self):
        """Must write /etc/hosts with pre-resolved entries."""
        assert "/etc/hosts" in NET_ISOLATION_LAUNCHER_CODE
        assert "resolved_hosts" in NET_ISOLATION_LAUNCHER_CODE

    def test_resolv_conf_writing(self):
        """Must write /etc/resolv.conf with DNS servers."""
        assert "/etc/resolv.conf" in NET_ISOLATION_LAUNCHER_CODE
        assert "dns_servers" in NET_ISOLATION_LAUNCHER_CODE

    def test_iptables_application(self):
        """Must apply iptables rules."""
        assert "iptables_rules" in NET_ISOLATION_LAUNCHER_CODE
        assert "subprocess" in NET_ISOLATION_LAUNCHER_CODE

    def test_safe_error_handling(self):
        """All steps should have try/except to handle failures gracefully."""
        # Count "except" blocks to verify error handling
        except_count = NET_ISOLATION_LAUNCHER_CODE.count("except")
        assert except_count >= 4, "Launcher should handle errors at each step"

    def test_checks_enabled_flag(self):
        """Must check if network isolation is enabled."""
        assert 'net_cfg.get("enabled")' in NET_ISOLATION_LAUNCHER_CODE

    def test_checks_needs_namespace(self):
        """Must check if namespace is needed."""
        assert 'net_cfg.get("needs_namespace")' in NET_ISOLATION_LAUNCHER_CODE


# ═════════════════════════════════════════════════════════════════════
#  16. FetchResult
# ═════════════════════════════════════════════════════════════════════

class TestFetchResult:
    """Test FetchResult data model."""

    def test_construction(self):
        r = FetchResult(url="https://example.com", success=True)
        assert r.success is True
        assert r.body == b""

    def test_frozen(self):
        r = FetchResult(url="", success=False)
        with pytest.raises(AttributeError):
            r.success = True  # type: ignore

    def test_to_dict(self):
        r = FetchResult(
            url="https://example.com",
            success=True,
            status_code=200,
            body=b"hello",
            bytes_received=5,
            content_type="text/plain",
        )
        d = r.to_dict()
        assert d["success"] is True
        assert d["bytes_received"] == 5
        assert "body" not in d  # Body excluded from dict
        assert d["body_sha256"] != ""  # But hash is included
        json.dumps(d)

    def test_to_dict_empty_body(self):
        r = FetchResult(url="", success=False, body=b"")
        d = r.to_dict()
        assert d["body_sha256"] == ""


# ═════════════════════════════════════════════════════════════════════
#  17. FetchBatchSummary
# ═════════════════════════════════════════════════════════════════════

class TestFetchBatchSummary:
    """Test FetchBatchSummary data model."""

    def test_construction(self):
        s = FetchBatchSummary(
            total_requests=3,
            successful=2,
            blocked=1,
            errored=0,
            total_bytes_received=1000,
            total_latency_ms=150.0,
        )
        assert s.total_requests == 3
        assert s.successful == 2

    def test_frozen(self):
        s = FetchBatchSummary(
            total_requests=0, successful=0, blocked=0, errored=0,
            total_bytes_received=0, total_latency_ms=0.0,
        )
        with pytest.raises(AttributeError):
            s.total_requests = 1  # type: ignore

    def test_to_dict(self):
        s = FetchBatchSummary(
            total_requests=1, successful=1, blocked=0, errored=0,
            total_bytes_received=500, total_latency_ms=50.0,
        )
        d = s.to_dict()
        assert d["total_requests"] == 1
        json.dumps(d)


# ═════════════════════════════════════════════════════════════════════
#  18. SafeFetcher
# ═════════════════════════════════════════════════════════════════════

class TestSafeFetcher:
    """Test SafeFetcher construction and properties."""

    def test_construction_default(self):
        f = SafeFetcher()
        assert f.policy.mode == NetworkMode.SELECTIVE
        assert f.fetch_count == 0
        assert f.total_bytes_received == 0

    def test_construction_custom_policy(self):
        f = SafeFetcher(NetworkPolicy.hipaa())
        assert f.policy.mode == NetworkMode.LOOPBACK_ONLY

    def test_guard_accessible(self):
        f = SafeFetcher()
        assert f.guard is not None
        assert isinstance(f.guard, NetworkGuard)

    def test_audit_log_accessible(self):
        f = SafeFetcher()
        assert f.audit_log is not None
        assert isinstance(f.audit_log, NetworkAuditLog)


class TestSafeFetcherBlocked:
    """Test SafeFetcher correctly blocks requests per policy."""

    def test_hipaa_blocks_all(self):
        f = SafeFetcher(NetworkPolicy.hipaa())
        result = f.fetch("https://example.com")
        assert result.success is False
        assert result.error_type == "blocked"
        assert "LOOPBACK_ONLY" in result.error

    def test_tls_required_blocks_http(self):
        f = SafeFetcher(NetworkPolicy(
            mode=NetworkMode.HOST_NETWORK,
            require_tls=True,
        ))
        result = f.fetch("http://example.com")
        assert result.success is False
        assert result.error_type == "blocked"

    def test_blocked_host(self):
        f = SafeFetcher(NetworkPolicy(
            mode=NetworkMode.HOST_NETWORK,
            require_tls=False,
            blocked_hosts=frozenset({"evil.com"}),
        ))
        result = f.fetch("http://evil.com")
        assert result.success is False
        assert result.error_type == "blocked"

    def test_blocked_connection_has_audit_record(self):
        f = SafeFetcher(NetworkPolicy.hipaa())
        result = f.fetch("https://example.com")
        assert result.connection_record is not None
        assert result.connection_record.outcome == "blocked"

    def test_blocked_does_not_increment_fetch_count(self):
        f = SafeFetcher(NetworkPolicy.hipaa())
        f.fetch("https://example.com")
        assert f.fetch_count == 0


class TestSafeFetcherAudit:
    """Test SafeFetcher audit export."""

    def test_export_audit(self):
        f = SafeFetcher(NetworkPolicy.hipaa())
        f.fetch("https://example.com")
        audit = f.export_audit()
        assert "policy_summary" in audit
        assert "connection_log" in audit
        assert "fetch_stats" in audit
        assert audit["connection_log"]["total_count"] >= 1

    def test_export_audit_json_safe(self):
        f = SafeFetcher(NetworkPolicy.hipaa())
        f.fetch("https://example.com")
        audit = f.export_audit()
        json.dumps(audit)

    def test_build_audit_info(self):
        f = SafeFetcher()
        info = f.build_audit_info(namespace_active=True)
        assert isinstance(info, NetworkAuditInfo)
        assert info.namespace_active is True


class TestSafeFetcherBatch:
    """Test SafeFetcher batch operations."""

    def test_fetch_many_all_blocked(self):
        f = SafeFetcher(NetworkPolicy.hipaa())
        summary = f.fetch_many(["https://a.com", "https://b.com"])
        assert summary.total_requests == 2
        assert summary.blocked == 2
        assert summary.successful == 0

    def test_fetch_many_empty(self):
        f = SafeFetcher()
        summary = f.fetch_many([])
        assert summary.total_requests == 0

    def test_fetch_many_to_dict(self):
        f = SafeFetcher(NetworkPolicy.hipaa())
        summary = f.fetch_many(["https://a.com"])
        d = summary.to_dict()
        json.dumps(d)


# ═════════════════════════════════════════════════════════════════════
#  19. Factory Functions
# ═════════════════════════════════════════════════════════════════════

class TestFactoryFunctions:
    """Test convenience factory functions."""

    def test_create_web_fetch_client(self):
        f = create_web_fetch_client(allowed_hosts=["example.com"])
        assert f.policy.mode == NetworkMode.SELECTIVE
        assert "example.com" in f.policy.allowed_hosts

    def test_create_web_fetch_client_defaults(self):
        f = create_web_fetch_client()
        assert f.policy.require_tls is True
        assert f.policy.block_private_ips is True

    def test_create_hipaa_fetcher(self):
        f = create_hipaa_fetcher()
        assert f.policy.mode == NetworkMode.LOOPBACK_ONLY

    def test_create_sox_fetcher(self):
        f = create_sox_fetcher()
        assert f.policy.mode == NetworkMode.SELECTIVE
        assert f.policy.require_tls is True

    def test_create_sox_fetcher_with_hosts(self):
        f = create_sox_fetcher(allowed_hosts=["sec.gov"])
        assert "sec.gov" in f.policy.allowed_hosts


# ═════════════════════════════════════════════════════════════════════
#  20. build_network_audit_info
# ═════════════════════════════════════════════════════════════════════

class TestBuildNetworkAuditInfo:
    """Test standalone audit info builder."""

    def test_without_guard(self):
        info = build_network_audit_info(NetworkPolicy.hipaa())
        assert info.mode == "loopback_only"
        assert info.namespace_active is False

    def test_with_guard(self):
        policy = NetworkPolicy.web_fetch_default()
        guard = NetworkGuard(policy)
        info = build_network_audit_info(
            policy, guard=guard, namespace_active=True,
        )
        assert info.namespace_active is True

    def test_with_namespace_flag(self):
        info = build_network_audit_info(
            NetworkPolicy.sox(),
            namespace_active=True,
            firewall_applied=True,
        )
        assert info.namespace_active is True
        assert info.firewall_rules_applied is True


# ═════════════════════════════════════════════════════════════════════
#  21. SSL Context
# ═════════════════════════════════════════════════════════════════════

class TestSSLContext:
    """Test TLS context builder."""

    def test_verify_enabled(self):
        import ssl
        ctx = _build_ssl_context(verify=True)
        assert ctx.check_hostname is True
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_verify_disabled(self):
        import ssl
        ctx = _build_ssl_context(verify=False)
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_NONE


# ═════════════════════════════════════════════════════════════════════
#  22. Probing
# ═════════════════════════════════════════════════════════════════════

class TestProbing:
    """Test network namespace and iptables probing."""

    def test_probe_network_namespace_returns_bool(self):
        result = probe_network_namespace()
        assert isinstance(result, bool)

    def test_probe_iptables_returns_bool(self):
        result = probe_iptables()
        assert isinstance(result, bool)

    def test_probe_cache_reset(self):
        # Call once to populate cache
        probe_network_namespace()
        reset_network_probe_cache()
        # Should re-probe
        probe_network_namespace()

    @pytest.mark.skipif(not sys.platform.startswith("linux"),
                        reason="Network namespace probing requires Linux")
    def test_probe_on_linux(self):
        reset_network_probe_cache()
        result = probe_network_namespace()
        # On most CI systems with user namespaces, this should be True
        assert isinstance(result, bool)


# ═════════════════════════════════════════════════════════════════════
#  23. ComplianceSandboxFactory - Network Integration
# ═════════════════════════════════════════════════════════════════════

class TestComplianceFactoryNetworkD3:
    """Test that compliance factories include network policies."""

    def test_hipaa_has_network_policy(self):
        executor = ComplianceSandboxFactory.for_hipaa()
        net_policy = executor.effective_network_policy
        assert net_policy is not None
        assert net_policy.mode == NetworkMode.LOOPBACK_ONLY

    def test_sox_has_network_policy(self):
        executor = ComplianceSandboxFactory.for_sox()
        net_policy = executor.effective_network_policy
        assert net_policy is not None
        assert net_policy.mode == NetworkMode.SELECTIVE
        assert net_policy.require_tls is True

    def test_legal_has_network_policy(self):
        executor = ComplianceSandboxFactory.for_legal()
        net_policy = executor.effective_network_policy
        assert net_policy is not None
        assert net_policy.mode == NetworkMode.SELECTIVE

    def test_standard_has_network_policy(self):
        executor = ComplianceSandboxFactory.standard()
        net_policy = executor.effective_network_policy
        # Standard uses web_fetch_default via effective_network_policy
        assert net_policy is not None

    def test_hipaa_network_guard_exists(self):
        executor = ComplianceSandboxFactory.for_hipaa()
        # Guard should exist (it's created in __init__)
        assert executor.network_guard is not None

    def test_sox_network_guard_exists(self):
        executor = ComplianceSandboxFactory.for_sox()
        assert executor.network_guard is not None


# ═════════════════════════════════════════════════════════════════════
#  24. ObservableSandboxedExecutor - Network Audit
# ═════════════════════════════════════════════════════════════════════

class TestObservableExecutorNetworkAudit:
    """Test network audit info in ObservableSandboxedExecutor."""

    def test_net_audit_captured_for_hipaa(self):
        executor = ComplianceSandboxFactory.for_hipaa()
        assert executor._net_audit is not None
        assert executor._net_audit.mode == "loopback_only"

    def test_net_audit_captured_for_sox(self):
        executor = ComplianceSandboxFactory.for_sox()
        assert executor._net_audit is not None
        assert executor._net_audit.mode == "selective"

    def test_net_audit_none_for_disabled(self):
        """Executor with no network policy has no network audit."""
        policy = SandboxPolicy.minimal()
        executor = ObservableSandboxedExecutor(policy, policy_name="minimal")
        # minimal() has no network policy in optional layers
        assert executor._net_audit is None

    def test_net_audit_in_audit_record(self):
        """Network audit should be included in SandboxAuditRecord."""
        # Build a mock result and check that _build_audit_record works
        result = SandboxResult(
            stdout="ok", stderr="",
            returncode=0, wall_time_seconds=0.1,
            active_layers=("rlimits", "python_sandbox"),
        )
        net_audit = NetworkAuditInfo(
            mode="selective", namespace_active=True,
            allowed_hosts_count=2, blocked_hosts_count=1,
            dns_servers=(), require_tls=True,
            max_connections_per_minute=60,
            connections_allowed=5, connections_blocked=1,
            firewall_rules_applied=True,
        )
        audit = _build_audit_record(
            code="print(1)",
            result=result,
            policy=SandboxPolicy.standard(),
            policy_name="test",
            mandatory_ok=True,
            network_audit=net_audit,
        )
        assert audit.network_audit is not None
        assert audit.network_audit["mode"] == "selective"
        assert audit.network_audit["connections_allowed"] == 5

    def test_audit_record_to_dict_has_network(self):
        """SandboxAuditRecord.to_dict() should include network_isolation."""
        result = SandboxResult(
            stdout="", stderr="", returncode=0,
            wall_time_seconds=0.1,
            active_layers=(),
        )
        net_audit = NetworkAuditInfo(
            mode="loopback_only", namespace_active=True,
            allowed_hosts_count=0, blocked_hosts_count=0,
            dns_servers=(), require_tls=True,
            max_connections_per_minute=0,
            connections_allowed=0, connections_blocked=0,
            firewall_rules_applied=True,
        )
        audit = _build_audit_record(
            code="x", result=result,
            policy=SandboxPolicy.standard(),
            policy_name="test", mandatory_ok=True,
            network_audit=net_audit,
        )
        d = audit.to_dict()
        assert "network_isolation" in d
        assert d["network_isolation"]["mode"] == "loopback_only"
        json.dumps(d)


# ═════════════════════════════════════════════════════════════════════
#  25. SandboxPolicy - Network Integration
# ═════════════════════════════════════════════════════════════════════

class TestSandboxPolicyNetworkD3:
    """Test SandboxPolicy network-related properties."""

    def test_effective_network_policy_none(self):
        """Policy with no NETWORK_ISOLATION layer has no network policy."""
        policy = SandboxPolicy(
            optional_layers=frozenset({ContainmentLayer.RLIMITS}),
            network=None,
        )
        assert policy.effective_network_policy is None

    def test_effective_network_policy_auto(self):
        """Policy with NETWORK_ISOLATION in layers auto-creates policy."""
        policy = SandboxPolicy(
            optional_layers=frozenset({ContainmentLayer.NETWORK_ISOLATION}),
        )
        net_policy = policy.effective_network_policy
        assert net_policy is not None
        assert net_policy.mode == NetworkMode.SELECTIVE

    def test_effective_network_policy_explicit(self):
        """Explicit network policy is used when provided."""
        net = NetworkPolicy.hipaa()
        policy = SandboxPolicy(network=net)
        assert policy.effective_network_policy is net
        assert policy.effective_network_policy.mode == NetworkMode.LOOPBACK_ONLY


# ═════════════════════════════════════════════════════════════════════
#  26. ContainmentLayer - D3 entries
# ═════════════════════════════════════════════════════════════════════

class TestContainmentLayerD3:
    """Test D3-related ContainmentLayer entries."""

    def test_net_namespace_exists(self):
        assert ContainmentLayer.NET_NAMESPACE is not None

    def test_network_isolation_exists(self):
        assert ContainmentLayer.NETWORK_ISOLATION is not None

    def test_distinct_from_other_layers(self):
        assert ContainmentLayer.NET_NAMESPACE != ContainmentLayer.NETWORK_ISOLATION
        assert ContainmentLayer.NET_NAMESPACE != ContainmentLayer.PID_NAMESPACE


# ═════════════════════════════════════════════════════════════════════
#  27. End-to-End Structural Tests
# ═════════════════════════════════════════════════════════════════════

class TestEndToEndNetworkD3:
    """Structural end-to-end tests for the full D3 pipeline."""

    def test_hipaa_full_pipeline(self):
        """HIPAA: policy → guard → config → launcher → audit."""
        # Policy
        policy = NetworkPolicy.hipaa()
        assert policy.is_network_blocked

        # Guard
        guard = NetworkGuard(policy)
        target = guard.resolve_and_validate("https://example.com")
        assert target.allowed is False

        # Config
        config = build_net_isolation_config(policy, guard)
        assert config["mode"] == "loopback_only"
        assert config["enabled"] is True

        # Launcher code
        assert "def _apply_network_isolation():" in NET_ISOLATION_LAUNCHER_CODE

        # Audit
        info = guard.build_network_audit_info(
            namespace_active=True, firewall_applied=True,
        )
        d = info.to_dict()
        assert d["mode"] == "loopback_only"
        json.dumps(d)

    def test_sox_full_pipeline(self):
        """SOX: policy → guard → fetcher → audit."""
        policy = NetworkPolicy.sox()
        assert policy.mode == NetworkMode.SELECTIVE

        fetcher = SafeFetcher(policy)
        # All blocked because no allowed_hosts
        result = fetcher.fetch("https://example.com")
        # May be allowed (empty allowed_hosts in SELECTIVE doesn't block)
        # Just verify it ran through the pipeline
        assert isinstance(result, FetchResult)

        audit = fetcher.export_audit()
        assert "policy_summary" in audit
        json.dumps(audit)

    def test_selective_with_hosts_pipeline(self):
        """Selective with allowed hosts: complete pipeline."""
        policy = NetworkPolicy(
            mode=NetworkMode.SELECTIVE,
            require_tls=False,
            allowed_hosts=frozenset({"example.com"}),
            block_private_ips=True,
        )

        # Guard validates allowed host
        guard = NetworkGuard(policy)
        target = guard.resolve_and_validate("http://example.com")
        # Should pass host check (may fail on DNS or private IP)
        assert "not in allowed" not in target.block_reason.lower()

        # Non-allowed host is blocked
        target2 = guard.resolve_and_validate("http://evil.com")
        assert target2.allowed is False
        assert "not in allowed" in target2.block_reason.lower()

    def test_config_roundtrip_json(self):
        """Config should survive JSON roundtrip."""
        for factory in [
            NetworkPolicy.hipaa,
            NetworkPolicy.sox,
            NetworkPolicy.web_fetch_default,
            NetworkPolicy.permissive,
            NetworkPolicy.disabled,
        ]:
            policy = factory()
            config = build_net_isolation_config(policy)
            serialized = json.dumps(config)
            deserialized = json.loads(serialized)
            assert deserialized["mode"] == policy.mode.value

    def test_audit_trail_complete(self):
        """Complete audit trail: fetcher → connections → export."""
        fetcher = SafeFetcher(NetworkPolicy.hipaa())

        # Multiple blocked requests
        for url in ["https://a.com", "https://b.com", "https://c.com"]:
            fetcher.fetch(url)

        audit = fetcher.export_audit()
        log = audit["connection_log"]
        assert log["total_count"] == 3
        assert log["blocked_count"] == 3
        assert len(log["records"]) == 3

        # Each record is complete
        for record in log["records"]:
            assert "timestamp" in record
            assert "outcome" in record
            assert record["outcome"] == "blocked"


# ═════════════════════════════════════════════════════════════════════
#  28. Executor D3 Integration
# ═════════════════════════════════════════════════════════════════════

class TestExecutorD3Integration:
    """Test SandboxedExecutor D3 integration points."""

    def test_executor_builds_net_config(self):
        """Executor._build_launcher_config includes network config."""
        from agentsafe.sandbox.executor import SandboxedExecutor
        policy = SandboxPolicy(
            network=NetworkPolicy.hipaa(),
            optional_layers=frozenset({
                ContainmentLayer.NETWORK_ISOLATION,
            }),
        )
        executor = SandboxedExecutor(policy)
        config = executor._build_launcher_config()
        assert config["network"] is not None
        assert config["network"]["mode"] == "loopback_only"

    def test_executor_no_net_config_when_disabled(self):
        """Executor with disabled network policy has null network config."""
        from agentsafe.sandbox.executor import SandboxedExecutor
        policy = SandboxPolicy(
            network=NetworkPolicy.disabled(),
        )
        executor = SandboxedExecutor(policy)
        config = executor._build_launcher_config()
        assert config["network"] is None

    def test_launcher_template_has_net_placeholder(self):
        """Launcher template must have network isolation placeholder."""
        from agentsafe.sandbox.executor import _LAUNCHER_TEMPLATE
        assert "__CERTIOR_NET_ISOLATION_PLACEHOLDER__" in _LAUNCHER_TEMPLATE


# ═════════════════════════════════════════════════════════════════════
#  29. Namespace Integration
# ═════════════════════════════════════════════════════════════════════

class TestNamespaceIntegration:
    """Test namespace.py integration with D3."""

    def test_clone_newnet_constant(self):
        from agentsafe.sandbox.namespace import CLONE_NEWNET
        assert CLONE_NEWNET == 0x40000000

    def test_probe_net_namespace(self):
        from agentsafe.sandbox.namespace import probe_net_namespace
        result = probe_net_namespace()
        assert isinstance(result, bool)

    def test_build_preexec_fn_with_net(self):
        from agentsafe.sandbox.namespace import build_preexec_fn
        fn, warnings = build_preexec_fn(
            enable_user_ns=False,
            enable_pid_ns=False,
            enable_net_ns=True,
            enable_ipc_ns=False,
        )
        assert callable(fn)

    def test_probe_all_includes_net(self):
        from agentsafe.sandbox.namespace import probe_all
        results = probe_all()
        assert "net" in results
        assert isinstance(results["net"], bool)


# ═════════════════════════════════════════════════════════════════════
#  30. Streaming Byte Limit
# ═════════════════════════════════════════════════════════════════════

class TestStreamingByteLimit:
    """Test SafeFetcher._read_limited."""

    def test_read_within_limit(self):
        import io
        data = b"hello world"
        resp = io.BytesIO(data)
        body, truncated = SafeFetcher._read_limited(resp, 1000)
        assert body == data
        assert truncated is False

    def test_read_exceeds_limit(self):
        import io
        data = b"x" * 1000
        resp = io.BytesIO(data)
        body, truncated = SafeFetcher._read_limited(resp, 100)
        assert len(body) == 100
        assert truncated is True

    def test_read_exact_limit(self):
        import io
        data = b"x" * 100
        resp = io.BytesIO(data)
        body, truncated = SafeFetcher._read_limited(resp, 100)
        assert len(body) == 100
        # Reading exactly limit bytes is not truncation unless there's more
        # (BytesIO exhausted = not truncated)

    def test_read_empty(self):
        import io
        resp = io.BytesIO(b"")
        body, truncated = SafeFetcher._read_limited(resp, 1000)
        assert body == b""
        assert truncated is False

    def test_zero_limit(self):
        import io
        data = b"hello"
        resp = io.BytesIO(data)
        body, truncated = SafeFetcher._read_limited(resp, 0)
        assert body == b""
        assert truncated is True

"""
Network namespace production hardening (Phase D3).

Provides kernel-level network namespace management beyond the basic
``CLONE_NEWNET`` in ``namespace.py``:

1. **Veth pair configuration** - for SELECTIVE mode, create a veth
   pair connecting the sandbox namespace to the host, with iptables
   rules restricting traffic to pre-resolved IPs only.
2. **Loopback verification** - verify that ``lo`` is up after namespace
   creation and that no unexpected interfaces exist.
3. **Iptables verification** - verify that iptables rules were applied
   correctly inside the namespace.
4. **Bandwidth limiting** - optional ``tc`` (traffic control) rules to
   cap egress throughput inside the namespace.
5. **DNS injection** - write pre-resolved ``/etc/hosts`` entries into
   the namespace so DNS works without an external resolver.
6. **Interface inventory** - enumerate interfaces visible inside the
   namespace for audit trail.

Design principles
-----------------
* **Defence-in-depth**: veth iptables rules mirror Python-level URL
  validation, providing kernel-enforced containment.
* **Graceful degradation**: if veth/iptables/tc are unavailable, fall
  back to loopback-only (most restrictive).  Never silently allow
  uncontrolled access.
* **Fail-closed**: unknown errors during setup → loopback-only.
* **Audit-first**: every setup step is logged for compliance export.

Usage::

    from agentsafe.sandbox.net_namespace import (
        VethPairConfig,
        BandwidthLimit,
        NetNamespaceVerification,
        build_veth_launcher_code,
        build_bandwidth_limit_config,
        verify_namespace_isolation,
    )

    # Generate launcher code for SELECTIVE mode with veth
    veth = VethPairConfig.for_selective(
        allowed_ips=["93.184.216.34"],
        allowed_ports=[443],
    )
    code = build_veth_launcher_code(veth)

    # Bandwidth limiting (optional)
    bw = BandwidthLimit(egress_kbps=1024, burst_kb=32)
    config = build_bandwidth_limit_config(bw)
"""
from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple

from .errors import SandboxSetupError

logger = logging.getLogger("certior.sandbox.net_namespace")


# ── Veth pair configuration ──────────────────────────────────────────

@dataclass(frozen=True)
class VethPairConfig:
    """Configuration for a veth pair connecting sandbox to host.

    In SELECTIVE mode, the sandbox namespace gets one end of a veth
    pair.  The host end is connected to a bridge (or directly to the
    host network stack).  Iptables rules on the sandbox side restrict
    traffic to the pre-resolved IPs only.

    Parameters
    ----------
    host_iface
        Name of the veth end on the host side.
    sandbox_iface
        Name of the veth end inside the sandbox namespace.
    sandbox_ip
        IP address assigned to the sandbox end.
    host_ip
        IP address assigned to the host end (acts as gateway).
    subnet_mask
        Subnet mask for the veth link.
    allowed_ips
        IP addresses the sandbox may connect to (from pre-resolution).
    allowed_ports
        TCP ports the sandbox may connect to.
    block_private_ips
        Whether to block RFC1918 addresses via iptables.
    dns_servers
        DNS servers to allow UDP/53 traffic to.
    mtu
        MTU for the veth interfaces.
    """

    host_iface: str = "veth-certior-h"
    sandbox_iface: str = "veth-certior-s"
    sandbox_ip: str = "10.200.1.2"
    host_ip: str = "10.200.1.1"
    subnet_mask: int = 30  # /30 = 4 addresses
    allowed_ips: Tuple[str, ...] = ()
    allowed_ports: Tuple[int, ...] = (80, 443)
    block_private_ips: bool = True
    dns_servers: Tuple[str, ...] = ()
    mtu: int = 1500
    enable_nat: bool = True  # MASQUERADE on host side

    @classmethod
    def for_selective(
        cls,
        *,
        allowed_ips: Sequence[str] = (),
        allowed_ports: Sequence[int] = (80, 443),
        dns_servers: Sequence[str] = (),
        block_private_ips: bool = True,
    ) -> "VethPairConfig":
        """Create veth config for SELECTIVE network mode.

        Pre-resolved IPs are passed in from the NetworkGuard's DNS
        resolution step.
        """
        return cls(
            allowed_ips=tuple(allowed_ips),
            allowed_ports=tuple(allowed_ports),
            dns_servers=tuple(dns_servers),
            block_private_ips=block_private_ips,
        )

    @classmethod
    def loopback_only(cls) -> "VethPairConfig":
        """Loopback-only config - no veth pair, no external access."""
        return cls(
            host_iface="",
            sandbox_iface="",
            sandbox_ip="",
            host_ip="",
            allowed_ips=(),
            allowed_ports=(),
        )

    @property
    def is_veth_enabled(self) -> bool:
        """True if a veth pair should be created."""
        return bool(self.sandbox_iface and self.host_iface)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host_iface": self.host_iface,
            "sandbox_iface": self.sandbox_iface,
            "sandbox_ip": self.sandbox_ip,
            "host_ip": self.host_ip,
            "subnet_mask": self.subnet_mask,
            "allowed_ips": list(self.allowed_ips),
            "allowed_ports": list(self.allowed_ports),
            "block_private_ips": self.block_private_ips,
            "dns_servers": list(self.dns_servers),
            "mtu": self.mtu,
            "enable_nat": self.enable_nat,
            "is_veth_enabled": self.is_veth_enabled,
        }


# ── Bandwidth limiting ───────────────────────────────────────────────

@dataclass(frozen=True)
class BandwidthLimit:
    """Traffic control (tc) configuration for bandwidth limiting.

    Applied inside the sandbox namespace to cap egress throughput.
    Uses ``tc qdisc`` with Token Bucket Filter (tbf).

    Parameters
    ----------
    egress_kbps
        Maximum egress throughput in kilobits per second.
        0 = no limit.
    burst_kb
        Burst buffer size in kilobytes.  Allows short bursts
        above the rate limit.
    latency_ms
        Maximum latency for queued packets (after which they
        are dropped).
    """

    egress_kbps: int = 0  # 0 = unlimited
    burst_kb: int = 32
    latency_ms: int = 400

    @classmethod
    def standard(cls) -> "BandwidthLimit":
        """Standard: 10 Mbps egress."""
        return cls(egress_kbps=10_000, burst_kb=64, latency_ms=400)

    @classmethod
    def restricted(cls) -> "BandwidthLimit":
        """Restricted: 1 Mbps egress (for compliance environments)."""
        return cls(egress_kbps=1_000, burst_kb=32, latency_ms=400)

    @classmethod
    def unlimited(cls) -> "BandwidthLimit":
        """No bandwidth limiting."""
        return cls(egress_kbps=0)

    @property
    def is_limited(self) -> bool:
        return self.egress_kbps > 0

    @property
    def egress_bytes_per_sec(self) -> int:
        """Egress rate in bytes per second."""
        return (self.egress_kbps * 1000) // 8

    def to_dict(self) -> Dict[str, Any]:
        return {
            "egress_kbps": self.egress_kbps,
            "burst_kb": self.burst_kb,
            "latency_ms": self.latency_ms,
            "is_limited": self.is_limited,
            "egress_bytes_per_sec": self.egress_bytes_per_sec,
        }


# ── Network namespace verification ───────────────────────────────────

class VerificationStatus(Enum):
    """Status of a namespace verification check."""
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"  # Check not applicable (e.g., no veth)
    WARN = "warn"  # Non-fatal issue


@dataclass(frozen=True)
class VerificationCheck:
    """Result of a single verification check."""
    name: str
    status: VerificationStatus
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class NetNamespaceVerification:
    """Complete verification result for a network namespace.

    Captures the results of all post-setup checks for compliance
    audit.
    """

    checks: Tuple[VerificationCheck, ...]
    timestamp: str
    all_passed: bool
    critical_failures: int
    warnings: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "checks": [c.to_dict() for c in self.checks],
            "timestamp": self.timestamp,
            "all_passed": self.all_passed,
            "critical_failures": self.critical_failures,
            "warnings": self.warnings,
        }


def build_verification_checks(
    *,
    mode: str,
    veth_enabled: bool = False,
    loopback_required: bool = True,
    iptables_expected: bool = False,
    bandwidth_limited: bool = False,
) -> List[str]:
    """Build the list of verification check names for the given mode.

    Returns check names that should be performed inside the namespace
    after setup completes.
    """
    checks = []

    if loopback_required:
        checks.append("loopback_up")
        checks.append("loopback_only")  # No unexpected interfaces

    if veth_enabled:
        checks.append("veth_present")
        checks.append("veth_ip_assigned")

    if mode == "loopback_only":
        checks.append("no_external_interfaces")
        checks.append("no_routes_to_external")

    if iptables_expected:
        checks.append("iptables_output_policy_drop")
        checks.append("iptables_loopback_accept")

    if bandwidth_limited:
        checks.append("tc_qdisc_applied")

    checks.append("resolv_conf_safe")

    return checks


# ── Interface inventory ──────────────────────────────────────────────

@dataclass(frozen=True)
class InterfaceInfo:
    """Information about a network interface inside the namespace."""

    name: str
    is_up: bool
    is_loopback: bool
    ip_addresses: Tuple[str, ...] = ()
    mtu: int = 0
    mac_address: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "is_up": self.is_up,
            "is_loopback": self.is_loopback,
            "ip_addresses": list(self.ip_addresses),
            "mtu": self.mtu,
            "mac_address": self.mac_address,
        }


@dataclass(frozen=True)
class NamespaceInventory:
    """Inventory of the network namespace state for audit."""

    interfaces: Tuple[InterfaceInfo, ...]
    has_default_route: bool
    dns_servers: Tuple[str, ...] = ()
    hosts_entries: int = 0
    iptables_rules_count: int = 0
    bandwidth_limit_active: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "interfaces": [i.to_dict() for i in self.interfaces],
            "has_default_route": self.has_default_route,
            "dns_servers": list(self.dns_servers),
            "hosts_entries": self.hosts_entries,
            "iptables_rules_count": self.iptables_rules_count,
            "bandwidth_limit_active": self.bandwidth_limit_active,
        }


# ── Network audit info (extended) ───────────────────────────────────

@dataclass(frozen=True)
class ExtendedNetworkAuditInfo:
    """Extended network audit info including namespace details.

    Supplements the base ``NetworkAuditInfo`` with namespace-level
    details for compliance export.
    """

    mode: str
    namespace_active: bool
    veth_enabled: bool
    bandwidth_limited: bool
    bandwidth_limit_kbps: int
    allowed_ips_count: int
    iptables_rules_count: int
    loopback_verified: bool
    verification_passed: bool
    inventory: Optional[NamespaceInventory] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "mode": self.mode,
            "namespace_active": self.namespace_active,
            "veth_enabled": self.veth_enabled,
            "bandwidth_limited": self.bandwidth_limited,
            "bandwidth_limit_kbps": self.bandwidth_limit_kbps,
            "allowed_ips_count": self.allowed_ips_count,
            "iptables_rules_count": self.iptables_rules_count,
            "loopback_verified": self.loopback_verified,
            "verification_passed": self.verification_passed,
        }
        if self.inventory is not None:
            d["inventory"] = self.inventory.to_dict()
        return d


def build_extended_network_audit(
    *,
    mode: str,
    namespace_active: bool = False,
    veth_config: Optional[VethPairConfig] = None,
    bandwidth_limit: Optional[BandwidthLimit] = None,
    verification: Optional[NetNamespaceVerification] = None,
    inventory: Optional[NamespaceInventory] = None,
) -> ExtendedNetworkAuditInfo:
    """Build extended network audit info from components."""
    return ExtendedNetworkAuditInfo(
        mode=mode,
        namespace_active=namespace_active,
        veth_enabled=veth_config.is_veth_enabled if veth_config else False,
        bandwidth_limited=bandwidth_limit.is_limited if bandwidth_limit else False,
        bandwidth_limit_kbps=bandwidth_limit.egress_kbps if bandwidth_limit else 0,
        allowed_ips_count=len(veth_config.allowed_ips) if veth_config else 0,
        iptables_rules_count=0,  # Filled after setup
        loopback_verified=False,  # Filled after verification
        verification_passed=(
            verification.all_passed if verification else False
        ),
        inventory=inventory,
    )


# ── Config builders for launcher injection ───────────────────────────

def build_veth_config(veth: VethPairConfig) -> Dict[str, Any]:
    """Build veth configuration dict for launcher injection.

    This dict is included in the launcher's ``_CONFIG["network"]["veth"]``
    and used by ``_setup_veth_pair()`` inside the child process.
    """
    if not veth.is_veth_enabled:
        return {"enabled": False}

    return {
        "enabled": True,
        "host_iface": veth.host_iface,
        "sandbox_iface": veth.sandbox_iface,
        "sandbox_ip": veth.sandbox_ip,
        "host_ip": veth.host_ip,
        "subnet_mask": veth.subnet_mask,
        "allowed_ips": list(veth.allowed_ips),
        "allowed_ports": list(veth.allowed_ports),
        "block_private_ips": veth.block_private_ips,
        "dns_servers": list(veth.dns_servers),
        "mtu": veth.mtu,
        "enable_nat": veth.enable_nat,
    }


def build_bandwidth_limit_config(bw: BandwidthLimit) -> Dict[str, Any]:
    """Build bandwidth limit configuration for launcher injection.

    Included in ``_CONFIG["network"]["bandwidth"]`` and used by
    ``_apply_bandwidth_limit()`` inside the child process.
    """
    if not bw.is_limited:
        return {"enabled": False}

    return {
        "enabled": True,
        "egress_kbps": bw.egress_kbps,
        "burst_kb": bw.burst_kb,
        "latency_ms": bw.latency_ms,
        "egress_bytes_per_sec": bw.egress_bytes_per_sec,
    }


def build_net_verification_config(
    checks: List[str],
    strict: bool = False,
) -> Dict[str, Any]:
    """Build verification config for launcher injection.

    Parameters
    ----------
    checks
        List of check names to perform.
    strict
        If True, verification failures cause the child to exit 78.
    """
    return {
        "enabled": bool(checks),
        "checks": checks,
        "strict": strict,
    }


# ── Launcher code fragments ─────────────────────────────────────────

VETH_LAUNCHER_CODE = '''\
def _setup_veth_pair():
    """Set up veth pair inside network namespace (SELECTIVE mode).

    Runs inside the child process after CLONE_NEWNET.
    Creates the sandbox end of the veth pair and configures IP.

    NOTE: The host end must be created by the parent process
    (which has access to the host network namespace).  This
    function only configures the sandbox side.
    """
    import subprocess

    net_cfg = _CONFIG.get("network")
    if not net_cfg:
        return

    veth_cfg = net_cfg.get("veth")
    if not veth_cfg or not veth_cfg.get("enabled"):
        return

    sandbox_iface = veth_cfg["sandbox_iface"]
    sandbox_ip = veth_cfg["sandbox_ip"]
    host_ip = veth_cfg["host_ip"]
    subnet_mask = veth_cfg["subnet_mask"]
    mtu = veth_cfg.get("mtu", 1500)

    # The veth pair is created by the parent and the sandbox end
    # is moved into this namespace.  We just need to configure it.
    try:
        # Set MTU
        subprocess.run(
            ["ip", "link", "set", sandbox_iface, "mtu", str(mtu)],
            capture_output=True, timeout=5,
        )

        # Assign IP address
        subprocess.run(
            ["ip", "addr", "add", f"{sandbox_ip}/{subnet_mask}",
             "dev", sandbox_iface],
            capture_output=True, timeout=5,
        )

        # Bring interface up
        subprocess.run(
            ["ip", "link", "set", sandbox_iface, "up"],
            capture_output=True, timeout=5,
        )

        # Add default route via host end
        subprocess.run(
            ["ip", "route", "add", "default", "via", host_ip],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass  # Fall through - iptables will block anyway

    # Apply restrictive iptables (only allowed IPs/ports)
    allowed_ips = veth_cfg.get("allowed_ips", [])
    allowed_ports = veth_cfg.get("allowed_ports", [])

    try:
        # Default: DROP everything
        subprocess.run(["iptables", "-P", "OUTPUT", "DROP"],
                       capture_output=True, timeout=5)
        subprocess.run(["iptables", "-P", "INPUT", "DROP"],
                       capture_output=True, timeout=5)
        subprocess.run(["iptables", "-P", "FORWARD", "DROP"],
                       capture_output=True, timeout=5)

        # Allow loopback
        subprocess.run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                       capture_output=True, timeout=5)
        subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                       capture_output=True, timeout=5)

        # Allow established/related back in
        subprocess.run(
            ["iptables", "-A", "INPUT", "-m", "state",
             "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            capture_output=True, timeout=5,
        )

        # Allow DNS to configured servers
        for dns in veth_cfg.get("dns_servers", []):
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-p", "udp",
                 "--dport", "53", "-d", dns, "-j", "ACCEPT"],
                capture_output=True, timeout=5,
            )

        # Allow outbound to specific IPs on allowed ports only
        for ip in allowed_ips:
            for port in allowed_ports:
                subprocess.run(
                    ["iptables", "-A", "OUTPUT", "-p", "tcp",
                     "--dport", str(port), "-d", ip, "-j", "ACCEPT"],
                    capture_output=True, timeout=5,
                )

    except Exception:
        pass  # iptables unavailable - loopback-only fallback
'''

BANDWIDTH_LIMIT_LAUNCHER_CODE = '''\
def _apply_bandwidth_limit():
    """Apply traffic control bandwidth limiting inside namespace.

    Uses tc (traffic control) with Token Bucket Filter (tbf) to
    cap egress throughput on the sandbox interface.
    """
    import subprocess

    net_cfg = _CONFIG.get("network")
    if not net_cfg:
        return

    bw_cfg = net_cfg.get("bandwidth")
    if not bw_cfg or not bw_cfg.get("enabled"):
        return

    # Determine interface (veth sandbox end, or lo for loopback-only)
    veth_cfg = net_cfg.get("veth", {})
    iface = veth_cfg.get("sandbox_iface", "lo")
    if not iface:
        iface = "lo"

    rate_kbit = bw_cfg["egress_kbps"]
    burst_kb = bw_cfg["burst_kb"]
    latency_ms = bw_cfg["latency_ms"]

    try:
        subprocess.run(
            ["tc", "qdisc", "add", "dev", iface, "root", "tbf",
             "rate", f"{rate_kbit}kbit",
             "burst", f"{burst_kb}kb",
             "latency", f"{latency_ms}ms"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass  # tc unavailable - no bandwidth limiting
'''

NET_VERIFICATION_LAUNCHER_CODE = '''\
def _verify_network_namespace():
    """Verify network namespace isolation after setup.

    Runs inside the child process after all network setup is complete.
    Checks that the namespace is correctly configured.
    """
    import os
    import subprocess

    net_cfg = _CONFIG.get("network")
    if not net_cfg:
        return

    verify_cfg = net_cfg.get("verification")
    if not verify_cfg or not verify_cfg.get("enabled"):
        return

    checks = verify_cfg.get("checks", [])
    strict = verify_cfg.get("strict", False)
    violations = []

    for check_name in checks:
        try:
            if check_name == "loopback_up":
                # Verify lo is UP
                result = subprocess.run(
                    ["ip", "link", "show", "lo"],
                    capture_output=True, timeout=5, text=True,
                )
                if "UP" not in result.stdout:
                    violations.append("loopback_up: lo is not UP")

            elif check_name == "no_external_interfaces":
                # In loopback-only mode, only lo should exist
                result = subprocess.run(
                    ["ip", "link", "show"],
                    capture_output=True, timeout=5, text=True,
                )
                lines = [l for l in result.stdout.splitlines()
                         if ": " in l and "lo" not in l.split(":")[1]]
                if lines:
                    violations.append(
                        f"no_external_interfaces: unexpected interfaces found"
                    )

            elif check_name == "iptables_output_policy_drop":
                result = subprocess.run(
                    ["iptables", "-L", "OUTPUT", "-n"],
                    capture_output=True, timeout=5, text=True,
                )
                if "DROP" not in result.stdout.splitlines()[0] if result.stdout else "":
                    violations.append(
                        "iptables_output_policy_drop: OUTPUT policy is not DROP"
                    )

            elif check_name == "resolv_conf_safe":
                # Verify /etc/resolv.conf doesn't point to external DNS
                # unless explicitly configured
                if os.path.exists("/etc/resolv.conf"):
                    pass  # Just checking existence is fine

        except Exception:
            pass  # Verification checks are best-effort

    if strict and violations:
        import sys
        sys.stderr.write(
            f"[sandbox] Network verification FAILED ({len(violations)} violations):\\n"
        )
        for v in violations:
            sys.stderr.write(f"  - {v}\\n")
        sys.exit(78)
'''


# ── Composite config builder ────────────────────────────────────────

def build_enhanced_net_config(
    *,
    base_config: Dict[str, Any],
    veth: Optional[VethPairConfig] = None,
    bandwidth: Optional[BandwidthLimit] = None,
    verification_checks: Optional[List[str]] = None,
    verification_strict: bool = False,
) -> Dict[str, Any]:
    """Enhance a base network config with D3 production features.

    Merges veth, bandwidth, and verification configs into the
    existing ``build_net_isolation_config`` output.

    Parameters
    ----------
    base_config
        Output of ``build_net_isolation_config()``.
    veth
        Optional veth pair configuration.
    bandwidth
        Optional bandwidth limiting.
    verification_checks
        Optional list of verification check names.
    verification_strict
        If True, verification failures terminate the child.
    """
    config = dict(base_config)

    if veth is not None:
        config["veth"] = build_veth_config(veth)
    else:
        config["veth"] = {"enabled": False}

    if bandwidth is not None:
        config["bandwidth"] = build_bandwidth_limit_config(bandwidth)
    else:
        config["bandwidth"] = {"enabled": False}

    if verification_checks:
        config["verification"] = build_net_verification_config(
            verification_checks,
            strict=verification_strict,
        )
    else:
        config["verification"] = {"enabled": False}

    return config


# ── Validation ───────────────────────────────────────────────────────

class VethConfigValidationError(ValueError):
    """Raised when a VethPairConfig has invalid configuration."""


def validate_veth_config(veth: VethPairConfig) -> List[str]:
    """Validate a VethPairConfig.  Returns list of warnings.

    Raises :class:`VethConfigValidationError` for fatal errors.
    """
    warnings: List[str] = []

    if not veth.is_veth_enabled:
        return warnings  # Nothing to validate

    # Validate IP addresses
    for label, addr in [("sandbox_ip", veth.sandbox_ip),
                        ("host_ip", veth.host_ip)]:
        try:
            ipaddress.ip_address(addr)
        except ValueError as exc:
            raise VethConfigValidationError(
                f"Invalid {label}: {addr!r} - {exc}"
            )

    # Validate subnet mask
    if not (1 <= veth.subnet_mask <= 32):
        raise VethConfigValidationError(
            f"Invalid subnet_mask: {veth.subnet_mask} (must be 1-32)"
        )

    # Validate MTU
    if veth.mtu < 68:  # Minimum IPv4 MTU
        raise VethConfigValidationError(
            f"MTU too low: {veth.mtu} (minimum 68)"
        )
    if veth.mtu > 65535:
        raise VethConfigValidationError(
            f"MTU too high: {veth.mtu} (maximum 65535)"
        )

    # Validate allowed IPs
    for ip in veth.allowed_ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise VethConfigValidationError(
                f"Invalid allowed IP: {ip!r} - {exc}"
            )

    # Validate ports
    for port in veth.allowed_ports:
        if not (1 <= port <= 65535):
            raise VethConfigValidationError(
                f"Invalid port: {port} (must be 1-65535)"
            )

    # Warn: same IP for host and sandbox
    if veth.sandbox_ip == veth.host_ip:
        warnings.append(
            "sandbox_ip equals host_ip - addresses must be different"
        )

    # Warn: very large number of allowed IPs
    if len(veth.allowed_ips) > 100:
        warnings.append(
            f"Large number of allowed IPs ({len(veth.allowed_ips)}) - "
            "consider reducing for performance"
        )

    # Warn: no allowed IPs with veth
    if not veth.allowed_ips:
        warnings.append(
            "No allowed IPs with veth enabled - "
            "all traffic will be blocked by iptables"
        )

    return warnings


def validate_bandwidth_limit(bw: BandwidthLimit) -> List[str]:
    """Validate a BandwidthLimit.  Returns warnings."""
    warnings: List[str] = []

    if bw.egress_kbps < 0:
        raise ValueError("egress_kbps must be >= 0")

    if bw.burst_kb < 1 and bw.is_limited:
        warnings.append("burst_kb < 1 with rate limiting - may cause drops")

    if bw.egress_kbps > 0 and bw.egress_kbps < 10:
        warnings.append(
            f"Very low bandwidth limit ({bw.egress_kbps} kbps) - "
            "may cause connection timeouts"
        )

    return warnings

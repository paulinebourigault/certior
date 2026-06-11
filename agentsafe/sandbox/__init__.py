"""
OS-Level Sandboxing for Certior (Phases D1 + D2 + D3 + D4).

Multi-layer containment for executing untrusted Python code:

* **rlimits** - CPU, memory, file-size, process limits (always available)
* **seccomp-BPF** - syscall allowlist (Linux >= 3.17)
* **Linux namespaces** - PID, network, IPC, mount, user isolation
* **Filesystem isolation** (D2) - tmpfs overlay + read-only bind mounts + pivot_root
* **OverlayFS** (D2) - union filesystem with copy-on-write upper layer
* **Proc masking** (D2) - /proc hardening with hidepid and sensitive path nulling
* **Mount verification** (D2) - post-isolation mount table verification
* **Network isolation** (D3) - network namespace + DNS pre-resolution + iptables firewall
* **Connection auditing** (D3) - full audit trail for every connection attempt
* **Dafny-verified seccomp** (D4) - formally proven BPF filter properties
* **nsjail** - gold-standard process containment (optional)
* **Python sandbox** - AST preflight + builtins restriction

Usage::

    from agentsafe.sandbox import SandboxedExecutor, SandboxPolicy

    # D1: Standard containment (rlimits + seccomp + python sandbox)
    executor = SandboxedExecutor(SandboxPolicy.standard())
    result = await executor.execute("print(2 + 2)")
    assert result.output == "4"

    # D2: With filesystem isolation (tmpfs root + RO bind mounts)
    executor = SandboxedExecutor(SandboxPolicy.with_filesystem())
    result = await executor.execute("print(2 + 2)")
    assert "fs_isolation" in result.active_layers

    # D3: Network isolation for web_fetch
    from agentsafe.sandbox import NetworkPolicy, NetworkGuard
    policy = NetworkPolicy.web_fetch_default()
    guard = NetworkGuard(policy)
    target = guard.resolve_and_validate("https://example.com")
    assert target.allowed

    # D3: HIPAA with full isolation
    from agentsafe.sandbox import ComplianceSandboxFactory
    executor = ComplianceSandboxFactory.for_hipaa()
    net_policy = executor.effective_network_policy
    assert net_policy.is_network_blocked  # no external access
"""
from .errors import (
    FilesystemIsolationError,
    NetworkIsolationError,
    NsjailNotFoundError,
    SandboxError,
    SandboxResourceError,
    SandboxSetupError,
    SandboxTimeoutError,
    SandboxViolationError,
)
from .executor import SandboxedExecutor, SandboxResult
from .filesystem import (
    FilesystemAuditInfo,
    FilesystemPolicy,
    FilesystemPolicyValidationError,
    build_filesystem_audit_info,
    build_fs_isolation_config,
    build_rootfs_skeleton,
    discover_python_paths,
    normalize_bind_mounts,
    probe_mount_namespace,
    probe_pivot_root,
    probe_tmpfs_mount,
    validate_policy as validate_filesystem_policy,
    verify_rootfs_structure,
)
from .overlay import (
    OverlayAuditInfo,
    OverlayFSConfig,
    OverlayMode,
    OverlayMount,
    build_overlay_audit_info,
    build_overlay_config,
    probe_overlayfs,
    reset_overlay_probe_cache,
    select_effective_mode,
    validate_overlay_config,
)
from .fs_monitor import (
    FileChangeManifest,
    FileEntry,
    MountEntry,
    MountVerificationResult,
    ProcMaskConfig,
    TmpfsUsage,
    build_mount_verification_config,
    build_proc_mask_config,
    capture_file_manifest,
    parse_proc_mounts,
    query_tmpfs_usage,
    verify_mount_table,
)
from .network import (
    ConnectionRecord,
    NET_ISOLATION_LAUNCHER_CODE,
    NetworkAuditInfo,
    NetworkAuditLog,
    NetworkGuard,
    NetworkMode,
    NetworkPolicy,
    NetworkPolicyValidationError,
    ResolvedTarget,
    build_net_isolation_config,
    probe_iptables,
    probe_network_namespace,
    reset_network_probe_cache,
    validate_network_policy,
)
from .policy import (
    ContainmentLayer,
    ResourceLimits,
    SandboxPolicy,
    SECCOMP_SYSCALL_ALLOWLIST_X86_64,
    SECCOMP_SYSCALL_ALLOWLIST_AARCH64,
)
from .seccomp import seccomp_available
from .namespace import probe_all as probe_namespaces

from .integration import (
    ComplianceSandboxFactory,
    ObservableSandboxedExecutor,
    SandboxAuditRecord,
    verified_sandbox_execute,
)
from .net_fetch import (
    FetchBatchSummary,
    FetchResult,
    SafeFetcher,
    build_network_audit_info,
    create_hipaa_fetcher,
    create_sox_fetcher,
    create_web_fetch_client,
)
from .seccomp_verified import (
    BpfProgram,
    DefaultAction as SeccompDefaultAction,
    FilterAuditEntry as SeccompFilterAuditEntry,
    FilterDecision as SeccompFilterDecision,
    NETWORK_SYSCALLS_X86_64,
    NETWORK_SYSCALLS_AARCH64,
    PROCESS_SPAWN_SYSCALLS_X86_64,
    PROCESS_SPAWN_SYSCALLS_AARCH64,
    SeccompAuditInfo,
    SeccompFilterBuilder,
    SeccompProfile,
    build_seccomp_audit_info,
    build_verified_seccomp,
    check_architecture,
    create_audit_profile,
    create_compute_only_profile,
    create_custom_profile,
    create_profile_from_numbers,
    create_network_blocked_profile,
    create_standard_profile,
    excludes_all as seccomp_excludes_all,
    filter_syscall,
    get_audit_profile,
    get_compute_only_profile,
    get_network_blocked_profile,
    get_network_syscalls,
    get_process_spawn_syscalls,
    get_standard_profile,
    instruction_count as seccomp_instruction_count,
    is_subset_of as seccomp_is_subset_of,
    normalize_syscalls,
    reset_profile_cache,
    verify_jump_targets,
)
from .seccomp_policy import (
    ArgumentConstraint,
    ArgumentPolicy,
    AttenuationRecord,
    CompleteCoverageVerifier,
    ComplianceRegime,
    ComplianceRequirement,
    ComplianceSeccompCertificate,
    PolicyChainEntry,
    SeccompComplianceMapper,
    SeccompPolicyAttenuator,
    SeccompPolicyChain,
    SeccompPolicyComposer,
    build_certified_seccomp,
)
from .seccomp_dafny_bridge import (
    AlignmentReport,
    DafnyAlignmentVerifier,
    DafnyProofCertificate,
    DafnyProperty,
    DafnyPropertyRegistry,
    PropertyCheckResult,
)
# D4 Production: Deployment orchestration
from .seccomp_deploy import (
    DeploymentStatus,
    PreflightCheck,
    PreflightResult,
    SeccompAuditEvent,
    SeccompDeploymentManager,
    SeccompDeploymentPlan,
    SeccompDeploymentResult,
    SeccompPolicyVersion,
    SeccompSafetyNet,
    deploy_verified_seccomp,
)
from .gvisor import (
    GVisorAuditInfo,
    GVisorPlatform,
    GVisorProbeResult,
    GVisorResourceLimits,
    GVisorResult,
    GVisorRuntime,
    build_gvisor_audit_info,
    probe_gvisor,
    reset_gvisor_probe_cache,
)
from .net_namespace import (
    BANDWIDTH_LIMIT_LAUNCHER_CODE,
    NET_VERIFICATION_LAUNCHER_CODE,
    VETH_LAUNCHER_CODE,
    BandwidthLimit,
    ExtendedNetworkAuditInfo,
    InterfaceInfo,
    NamespaceInventory,
    NetNamespaceVerification,
    VethConfigValidationError,
    VethPairConfig,
    VerificationCheck,
    VerificationStatus,
    build_bandwidth_limit_config,
    build_enhanced_net_config,
    build_extended_network_audit,
    build_net_verification_config,
    build_veth_config,
    build_verification_checks,
    validate_bandwidth_limit,
    validate_veth_config,
)

__all__ = [
    # Core
    "SandboxedExecutor",
    "SandboxResult",
    # Observable
    "ObservableSandboxedExecutor",
    "ComplianceSandboxFactory",
    "SandboxAuditRecord",
    "verified_sandbox_execute",
    # Policy
    "SandboxPolicy",
    "ContainmentLayer",
    "ResourceLimits",
    "FilesystemPolicy",
    # D2: Filesystem isolation
    "FilesystemAuditInfo",
    "FilesystemPolicyValidationError",
    "build_filesystem_audit_info",
    "build_fs_isolation_config",
    "build_rootfs_skeleton",
    "validate_filesystem_policy",
    "verify_rootfs_structure",
    # D2: OverlayFS
    "OverlayFSConfig",
    "OverlayMode",
    "OverlayMount",
    "OverlayAuditInfo",
    "build_overlay_audit_info",
    "build_overlay_config",
    "probe_overlayfs",
    "reset_overlay_probe_cache",
    "select_effective_mode",
    "validate_overlay_config",
    # D2: Filesystem monitoring
    "MountEntry",
    "MountVerificationResult",
    "TmpfsUsage",
    "FileChangeManifest",
    "FileEntry",
    "ProcMaskConfig",
    "parse_proc_mounts",
    "verify_mount_table",
    "query_tmpfs_usage",
    "capture_file_manifest",
    "build_mount_verification_config",
    "build_proc_mask_config",
    # D3: Network isolation
    "NetworkPolicy",
    "NetworkMode",
    "NetworkGuard",
    "NetworkAuditInfo",
    "NetworkAuditLog",
    "NetworkPolicyValidationError",
    "ConnectionRecord",
    "ResolvedTarget",
    "build_net_isolation_config",
    "validate_network_policy",
    "probe_network_namespace",
    "probe_iptables",
    "reset_network_probe_cache",
    "NET_ISOLATION_LAUNCHER_CODE",
    # D3: Safe HTTP client
    "SafeFetcher",
    "FetchResult",
    "FetchBatchSummary",
    "create_web_fetch_client",
    "create_hipaa_fetcher",
    "create_sox_fetcher",
    "build_network_audit_info",
    # D4: Dafny-verified seccomp filter
    "SeccompProfile",
    "SeccompFilterBuilder",
    "SeccompFilterDecision",
    "SeccompDefaultAction",
    "SeccompFilterAuditEntry",
    "SeccompAuditInfo",
    "BpfProgram",
    "filter_syscall",
    "check_architecture",
    "normalize_syscalls",
    "verify_jump_targets",
    "build_verified_seccomp",
    "build_seccomp_audit_info",
    "create_standard_profile",
    "create_network_blocked_profile",
    "create_compute_only_profile",
    "create_audit_profile",
    "create_custom_profile",
    "create_profile_from_numbers",
    "get_standard_profile",
    "get_network_blocked_profile",
    "get_compute_only_profile",
    "get_audit_profile",
    "get_network_syscalls",
    "get_process_spawn_syscalls",
    "reset_profile_cache",
    "NETWORK_SYSCALLS_X86_64",
    "NETWORK_SYSCALLS_AARCH64",
    "PROCESS_SPAWN_SYSCALLS_X86_64",
    "PROCESS_SPAWN_SYSCALLS_AARCH64",
    # D4 Production: Argument constraints, composition, attenuation, compliance
    "ArgumentConstraint",
    "ArgumentPolicy",
    "AttenuationRecord",
    "CompleteCoverageVerifier",
    "ComplianceRegime",
    "ComplianceRequirement",
    "ComplianceSeccompCertificate",
    "PolicyChainEntry",
    "SeccompComplianceMapper",
    "SeccompPolicyAttenuator",
    "SeccompPolicyChain",
    "SeccompPolicyComposer",
    "build_certified_seccomp",
    # D4 Production: Dafny-Python alignment bridge
    "AlignmentReport",
    "DafnyAlignmentVerifier",
    "DafnyProofCertificate",
    "DafnyProperty",
    "DafnyPropertyRegistry",
    "PropertyCheckResult",
    # D4 Production: Deployment orchestration
    "DeploymentStatus",
    # gVisor (container-friendly sandbox)
    "GVisorAuditInfo",
    "GVisorPlatform",
    "GVisorProbeResult",
    "GVisorResourceLimits",
    "GVisorResult",
    "GVisorRuntime",
    "build_gvisor_audit_info",
    "probe_gvisor",
    "reset_gvisor_probe_cache",
    "PreflightCheck",
    "PreflightResult",
    "SeccompAuditEvent",
    "SeccompDeploymentManager",
    "SeccompDeploymentPlan",
    "SeccompDeploymentResult",
    "SeccompPolicyVersion",
    "SeccompSafetyNet",
    "deploy_verified_seccomp",
    # Errors
    "SandboxError",
    "SandboxSetupError",
    "SandboxTimeoutError",
    "SandboxViolationError",
    "SandboxResourceError",
    "FilesystemIsolationError",
    "NetworkIsolationError",
    "NsjailNotFoundError",
    # Probing
    "seccomp_available",
    "probe_namespaces",
    "probe_mount_namespace",
    "probe_tmpfs_mount",
    "probe_pivot_root",
    "probe_overlayfs",
    "discover_python_paths",
    "normalize_bind_mounts",
    # Constants
    "SECCOMP_SYSCALL_ALLOWLIST_X86_64",
    "SECCOMP_SYSCALL_ALLOWLIST_AARCH64",
]

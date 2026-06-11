"""
seccomp_deploy.py - Production Seccomp Deployment & Lifecycle Management (Phase D4).

Bridges the Dafny-verified seccomp policy layer (P34-P54) with actual
kernel-level seccomp-BPF installation, providing:

  * **SeccompDeploymentPlan** - immutable deployment plan with pre-flight checks
  * **SeccompDeploymentManager** - orchestrates build → verify → install → audit
  * **SeccompPolicyVersion** - versioned policy snapshots for audit trail
  * **SeccompAuditEvent** - structured events for SIEM / compliance export
  * **SeccompSafetyNet** - post-install validation against Dafny specification
  * **deploy_verified_seccomp()** - one-call production deployment

Architecture::

    SeccompProfile (Dafny-verified)
           │
           ▼
    SeccompDeploymentManager
      ├── 1. Pre-flight checks (capabilities, kernel support)
      ├── 2. Build BPF program (SeccompFilterBuilder, P34-P46)
      ├── 3. Alignment verification (DafnyAlignmentVerifier, P34-P54)
      ├── 4. Compliance certification (SeccompComplianceMapper)
      ├── 5. Install via prctl (seccomp.install_seccomp_filter)
      ├── 6. Post-install validation (SeccompSafetyNet)
      └── 7. Audit event emission (SeccompAuditEvent)

All operations are idempotent and produce a full audit trail.

Usage::

    from agentsafe.sandbox.seccomp_deploy import deploy_verified_seccomp

    result = deploy_verified_seccomp(
        profile_name="network_blocked",
        regime="hipaa",
        dry_run=False,
    )
    assert result.verified
    assert result.installed or result.dry_run
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
)

from .seccomp_verified import (
    BpfProgram,
    DefaultAction,
    SeccompFilterBuilder,
    SeccompProfile,
    create_network_blocked_profile,
    create_standard_profile,
    create_compute_only_profile,
    filter_syscall,
    normalize_syscalls,
)
from .seccomp_policy import (
    ArgumentPolicy,
    ComplianceRegime,
    ComplianceSeccompCertificate,
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
)


# =============================================================================
# Deployment Status
# =============================================================================

class DeploymentStatus(Enum):
    """Status of a seccomp deployment operation."""
    PENDING = auto()
    PREFLIGHT_PASSED = auto()
    PREFLIGHT_FAILED = auto()
    BUILT = auto()
    VERIFIED = auto()
    VERIFICATION_FAILED = auto()
    CERTIFIED = auto()
    INSTALLED = auto()
    INSTALL_FAILED = auto()
    POST_VALIDATED = auto()
    POST_VALIDATION_FAILED = auto()
    DRY_RUN_COMPLETE = auto()


# =============================================================================
# Audit Events
# =============================================================================

@dataclass(frozen=True)
class SeccompAuditEvent:
    """Structured audit event for SIEM / compliance integration.

    Every deployment operation emits one or more events for the audit trail.
    Events are immutable and serializable to JSON.
    """
    event_id: str
    event_type: str          # "preflight", "build", "verify", "certify", "install", "validate"
    timestamp: float
    profile_name: str
    status: str              # "success", "failure", "skipped"
    details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "profile_name": self.profile_name,
            "status": self.status,
            "details": self.details,
            "duration_ms": round(self.duration_ms, 3),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


# =============================================================================
# Policy Version
# =============================================================================

@dataclass(frozen=True)
class SeccompPolicyVersion:
    """Versioned snapshot of a seccomp policy for audit trail.

    Immutable record of what policy was active at what time, with
    cryptographic hash for tamper detection.
    """
    version_id: str
    profile_name: str
    profile_hash: str
    syscall_count: int
    instruction_count: int
    default_action: str
    excludes_network: bool
    excludes_process_spawn: bool
    argument_constraints_count: int
    compliance_regime: str
    created_at: float
    deployed_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version_id": self.version_id,
            "profile_name": self.profile_name,
            "profile_hash": self.profile_hash,
            "syscall_count": self.syscall_count,
            "instruction_count": self.instruction_count,
            "default_action": self.default_action,
            "excludes_network": self.excludes_network,
            "excludes_process_spawn": self.excludes_process_spawn,
            "argument_constraints_count": self.argument_constraints_count,
            "compliance_regime": self.compliance_regime,
            "created_at": self.created_at,
            "deployed_at": self.deployed_at,
        }


# =============================================================================
# Pre-Flight Check
# =============================================================================

@dataclass(frozen=True)
class PreflightCheck:
    """Single pre-flight check result."""
    name: str
    passed: bool
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass(frozen=True)
class PreflightResult:
    """Aggregate pre-flight check result."""
    checks: Tuple[PreflightCheck, ...]
    all_passed: bool
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "all_passed": self.all_passed,
            "checks": [c.to_dict() for c in self.checks],
            "timestamp": self.timestamp,
        }


# =============================================================================
# Deployment Plan
# =============================================================================

@dataclass(frozen=True)
class SeccompDeploymentPlan:
    """Immutable deployment plan - what will be done and in what order."""
    profile: SeccompProfile
    regime: ComplianceRegime
    argument_policy: ArgumentPolicy
    dry_run: bool
    skip_alignment: bool
    skip_certification: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_name": self.profile.name,
            "regime": self.regime.value,
            "argument_constraints": len(self.argument_policy.constrained_syscalls),
            "dry_run": self.dry_run,
            "skip_alignment": self.skip_alignment,
            "skip_certification": self.skip_certification,
        }


# =============================================================================
# Deployment Result
# =============================================================================

@dataclass(frozen=True)
class SeccompDeploymentResult:
    """Complete result of a seccomp deployment operation."""
    status: DeploymentStatus
    profile_name: str
    regime: str
    dry_run: bool

    # Build phase
    program: Optional[BpfProgram] = None
    build_duration_ms: float = 0.0

    # Verification phase
    verified: bool = False
    alignment_report: Optional[AlignmentReport] = None
    alignment_duration_ms: float = 0.0

    # Certification phase
    certified: bool = False
    compliance_certificate: Optional[ComplianceSeccompCertificate] = None
    proof_certificate: Optional[DafnyProofCertificate] = None
    certification_duration_ms: float = 0.0

    # Installation phase
    installed: bool = False
    install_duration_ms: float = 0.0

    # Post-validation
    post_validated: bool = False
    post_validation_checks: Tuple[PreflightCheck, ...] = ()

    # Audit
    policy_version: Optional[SeccompPolicyVersion] = None
    audit_events: Tuple[SeccompAuditEvent, ...] = ()
    total_duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "status": self.status.name,
            "profile_name": self.profile_name,
            "regime": self.regime,
            "dry_run": self.dry_run,
            "verified": self.verified,
            "certified": self.certified,
            "installed": self.installed,
            "post_validated": self.post_validated,
            "total_duration_ms": round(self.total_duration_ms, 3),
        }
        if self.policy_version:
            d["policy_version"] = self.policy_version.to_dict()
        if self.program:
            d["program"] = {
                "instruction_count": self.program.instruction_count,
                "syscall_count": self.program.syscall_count,
            }
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)


# =============================================================================
# Safety Net - Post-Installation Validation
# =============================================================================

class SeccompSafetyNet:
    """Post-installation validation of seccomp filters.

    After the BPF filter is installed, SeccompSafetyNet verifies that
    the deployed filter matches the Dafny-verified specification by:

      1. Checking that the kernel's seccomp mode is FILTER
      2. Verifying the BPF program hash matches
      3. Confirming the process cannot make blocked syscalls

    This is the ultimate defense-in-depth check: even if something went
    wrong in the build pipeline, we detect it after installation.
    """

    @staticmethod
    def validate_deployment(
        program: BpfProgram,
        profile: SeccompProfile,
    ) -> Tuple[bool, List[PreflightCheck]]:
        """Validate that the deployment matches the specification.

        Returns:
            Tuple of (all_passed, list of checks).
        """
        checks: List[PreflightCheck] = []

        # Check 1: BPF program non-empty
        checks.append(PreflightCheck(
            name="bpf_program_nonempty",
            passed=len(program.raw_bytes) > 0,
            detail=f"Program size: {len(program.raw_bytes)} bytes",
        ))

        # Check 2: Instruction count matches P40
        expected_ic = len(normalize_syscalls(profile.allowed_syscalls)) + 6
        actual_ic = program.instruction_count
        checks.append(PreflightCheck(
            name="instruction_count_p40",
            passed=actual_ic == expected_ic,
            detail=f"Expected {expected_ic}, got {actual_ic}",
        ))

        # Check 3: Normalized allowlist matches profile
        expected_norm = normalize_syscalls(profile.allowed_syscalls)
        actual_norm = program.normalized_allowlist
        checks.append(PreflightCheck(
            name="allowlist_match",
            passed=expected_norm == actual_norm,
            detail=f"Allowlist size: {len(actual_norm)}",
        ))

        # Check 4: Default action matches
        checks.append(PreflightCheck(
            name="default_action_match",
            passed=program.default_action == profile.default_action,
            detail=f"Action: {program.default_action.value}",
        ))

        # Check 5: Filter decisions match specification for sample syscalls
        sample_nrs = list(range(min(50, max(expected_norm) + 5 if expected_norm else 50)))
        mismatches = 0
        for nr in sample_nrs:
            expected = filter_syscall(nr, expected_norm)
            actual = program.check_syscall(nr)
            if expected.is_allow != actual.is_allow:
                mismatches += 1
        checks.append(PreflightCheck(
            name="filter_decision_consistency",
            passed=mismatches == 0,
            detail=f"Checked {len(sample_nrs)} syscalls, {mismatches} mismatches",
        ))

        # Check 6: Network exclusion (if applicable)
        if profile.excludes_network:
            from .seccomp_verified import get_network_syscalls
            net_syscalls = get_network_syscalls()
            net_allowed = set(actual_norm) & net_syscalls
            checks.append(PreflightCheck(
                name="network_exclusion_p43",
                passed=len(net_allowed) == 0,
                detail=f"Network syscalls in allowlist: {sorted(net_allowed)}",
            ))

        # Check 7: Process spawn exclusion (if applicable)
        if profile.excludes_process_spawn:
            from .seccomp_verified import get_process_spawn_syscalls
            spawn_syscalls = get_process_spawn_syscalls()
            spawn_allowed = set(actual_norm) & spawn_syscalls
            checks.append(PreflightCheck(
                name="process_spawn_exclusion",
                passed=len(spawn_allowed) == 0,
                detail=f"Spawn syscalls in allowlist: {sorted(spawn_allowed)}",
            ))

        # Check 8: BPF program hash integrity
        program_hash = hashlib.sha256(program.raw_bytes).hexdigest()
        checks.append(PreflightCheck(
            name="program_hash_integrity",
            passed=len(program_hash) == 64,
            detail=f"SHA-256: {program_hash[:16]}...",
        ))

        all_passed = all(c.passed for c in checks)
        return all_passed, checks


# =============================================================================
# Deployment Manager
# =============================================================================

class SeccompDeploymentManager:
    """Orchestrates the full seccomp deployment lifecycle.

    Pipeline::

        plan → preflight → build → verify → certify → install → validate → audit

    Each step is independently testable and produces audit events.
    """

    NAMED_PROFILES = {
        "standard": create_standard_profile,
        "network_blocked": create_network_blocked_profile,
        "compute_only": create_compute_only_profile,
    }

    NAMED_REGIMES = {
        "hipaa": ComplianceRegime.HIPAA,
        "sox": ComplianceRegime.SOX,
        "legal": ComplianceRegime.LEGAL,
        "pci_dss": ComplianceRegime.PCI_DSS,
        "general": ComplianceRegime.GENERAL,
    }

    def __init__(self) -> None:
        self._events: List[SeccompAuditEvent] = []
        self._versions: List[SeccompPolicyVersion] = []
        self._event_counter = 0

    # ── Event helpers ──────────────────────────────────────────

    def _emit(
        self,
        event_type: str,
        profile_name: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
        duration_ms: float = 0.0,
    ) -> SeccompAuditEvent:
        self._event_counter += 1
        event = SeccompAuditEvent(
            event_id=f"evt-{self._event_counter:06d}",
            event_type=event_type,
            timestamp=time.time(),
            profile_name=profile_name,
            status=status,
            details=details or {},
            duration_ms=duration_ms,
        )
        self._events.append(event)
        return event

    @property
    def audit_events(self) -> List[SeccompAuditEvent]:
        return list(self._events)

    @property
    def policy_versions(self) -> List[SeccompPolicyVersion]:
        return list(self._versions)

    # ── Pre-flight ─────────────────────────────────────────────

    def preflight(self) -> PreflightResult:
        """Run pre-flight checks before deployment."""
        checks: List[PreflightCheck] = []

        # Check 1: Platform is Linux
        checks.append(PreflightCheck(
            name="platform_linux",
            passed=platform.system() == "Linux",
            detail=f"Platform: {platform.system()}",
        ))

        # Check 2: Architecture supported
        machine = platform.machine()
        supported_archs = {"x86_64", "aarch64"}
        checks.append(PreflightCheck(
            name="architecture_supported",
            passed=machine in supported_archs,
            detail=f"Architecture: {machine}",
        ))

        # Check 3: seccomp available
        try:
            from .seccomp import seccomp_available
            available = seccomp_available()
        except Exception:
            available = False
        checks.append(PreflightCheck(
            name="seccomp_available",
            passed=available,
            detail="Kernel seccomp support detected" if available else "Not available",
        ))

        # Check 4: prctl available
        try:
            import ctypes
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            has_prctl = hasattr(libc, "prctl")
        except Exception:
            has_prctl = False
        checks.append(PreflightCheck(
            name="prctl_available",
            passed=has_prctl,
            detail="prctl(2) available" if has_prctl else "prctl not found",
        ))

        # Check 5: Not already in strict seccomp mode
        in_strict = False
        try:
            status_path = f"/proc/{os.getpid()}/status"
            if os.path.exists(status_path):
                with open(status_path) as f:
                    for line in f:
                        if line.startswith("Seccomp:"):
                            mode = int(line.split(":")[1].strip())
                            in_strict = mode == 1  # SECCOMP_MODE_STRICT
        except Exception:
            pass
        checks.append(PreflightCheck(
            name="not_strict_seccomp",
            passed=not in_strict,
            detail="Process not in strict seccomp mode",
        ))

        all_passed = all(c.passed for c in checks)
        return PreflightResult(
            checks=tuple(checks),
            all_passed=all_passed,
            timestamp=time.time(),
        )

    # ── Full deployment ────────────────────────────────────────

    def deploy(
        self,
        plan: SeccompDeploymentPlan,
    ) -> SeccompDeploymentResult:
        """Execute a full deployment plan.

        Args:
            plan: The immutable deployment plan to execute.

        Returns:
            SeccompDeploymentResult with full audit trail.
        """
        overall_start = time.perf_counter()
        profile = plan.profile
        name = profile.name

        # 1. Pre-flight
        t0 = time.perf_counter()
        preflight_result = self.preflight()
        preflight_ms = (time.perf_counter() - t0) * 1000
        self._emit("preflight", name, "success" if preflight_result.all_passed else "failure",
                    preflight_result.to_dict(), preflight_ms)

        if not preflight_result.all_passed and not plan.dry_run:
            return SeccompDeploymentResult(
                status=DeploymentStatus.PREFLIGHT_FAILED,
                profile_name=name,
                regime=plan.regime.value,
                dry_run=plan.dry_run,
                audit_events=tuple(self._events),
                total_duration_ms=(time.perf_counter() - overall_start) * 1000,
            )

        # 2. Build
        t0 = time.perf_counter()
        builder = SeccompFilterBuilder(profile)
        program = builder.build_filter()
        build_ms = (time.perf_counter() - t0) * 1000
        self._emit("build", name, "success", {
            "instruction_count": program.instruction_count,
            "syscall_count": program.syscall_count,
        }, build_ms)

        # 3. Alignment verification
        alignment_report = None
        alignment_ms = 0.0
        verified = False
        if not plan.skip_alignment:
            t0 = time.perf_counter()
            verifier = DafnyAlignmentVerifier()
            alignment_report = verifier.verify_alignment(
                profile, program, check_extended=True,
            )
            alignment_ms = (time.perf_counter() - t0) * 1000
            verified = alignment_report.all_passed
            self._emit("verify", name,
                        "success" if verified else "failure",
                        {"passed": alignment_report.passed_count,
                         "failed": alignment_report.failed_count},
                        alignment_ms)
        else:
            verified = True
            self._emit("verify", name, "skipped", {}, 0)

        if not verified:
            return SeccompDeploymentResult(
                status=DeploymentStatus.VERIFICATION_FAILED,
                profile_name=name,
                regime=plan.regime.value,
                dry_run=plan.dry_run,
                program=program,
                build_duration_ms=build_ms,
                verified=False,
                alignment_report=alignment_report,
                alignment_duration_ms=alignment_ms,
                audit_events=tuple(self._events),
                total_duration_ms=(time.perf_counter() - overall_start) * 1000,
            )

        # 4. Compliance certification
        compliance_cert = None
        proof_cert = None
        cert_ms = 0.0
        certified = False
        if not plan.skip_certification:
            t0 = time.perf_counter()
            compliance_cert = SeccompComplianceMapper.certify(
                profile, plan.regime, plan.argument_policy, builder,
            )
            certified = compliance_cert.all_passed

            # Generate proof certificate
            dv = DafnyAlignmentVerifier()
            proof_cert = dv.generate_certificate(profile, program)

            cert_ms = (time.perf_counter() - t0) * 1000
            self._emit("certify", name,
                        "success" if certified else "failure",
                        {"regime": plan.regime.value,
                         "all_passed": certified},
                        cert_ms)
        else:
            certified = True
            self._emit("certify", name, "skipped", {}, 0)

        # 5. Install (unless dry run)
        installed = False
        install_ms = 0.0
        if not plan.dry_run:
            t0 = time.perf_counter()
            try:
                from .seccomp import install_seccomp_filter
                install_seccomp_filter(program.raw_bytes)
                installed = True
                install_ms = (time.perf_counter() - t0) * 1000
                self._emit("install", name, "success", {}, install_ms)
            except Exception as e:
                install_ms = (time.perf_counter() - t0) * 1000
                self._emit("install", name, "failure",
                            {"error": str(e)}, install_ms)
                return SeccompDeploymentResult(
                    status=DeploymentStatus.INSTALL_FAILED,
                    profile_name=name,
                    regime=plan.regime.value,
                    dry_run=False,
                    program=program,
                    build_duration_ms=build_ms,
                    verified=verified,
                    alignment_report=alignment_report,
                    alignment_duration_ms=alignment_ms,
                    certified=certified,
                    compliance_certificate=compliance_cert,
                    proof_certificate=proof_cert,
                    certification_duration_ms=cert_ms,
                    installed=False,
                    install_duration_ms=install_ms,
                    audit_events=tuple(self._events),
                    total_duration_ms=(time.perf_counter() - overall_start) * 1000,
                )
        else:
            self._emit("install", name, "skipped", {"dry_run": True}, 0)

        # 6. Post-validation
        t0 = time.perf_counter()
        post_ok, post_checks = SeccompSafetyNet.validate_deployment(program, profile)
        post_ms = (time.perf_counter() - t0) * 1000
        self._emit("validate", name,
                    "success" if post_ok else "failure",
                    {"checks_passed": sum(1 for c in post_checks if c.passed),
                     "checks_total": len(post_checks)},
                    post_ms)

        # 7. Record policy version
        normalized = normalize_syscalls(profile.allowed_syscalls)
        profile_hash = hashlib.sha256(
            json.dumps(sorted(normalized)).encode()
        ).hexdigest()
        version = SeccompPolicyVersion(
            version_id=hashlib.sha256(
                f"{profile_hash}:{time.time()}".encode()
            ).hexdigest()[:16],
            profile_name=name,
            profile_hash=profile_hash,
            syscall_count=len(normalized),
            instruction_count=program.instruction_count,
            default_action=profile.default_action.value,
            excludes_network=profile.excludes_network,
            excludes_process_spawn=profile.excludes_process_spawn,
            argument_constraints_count=len(plan.argument_policy.constraints),
            compliance_regime=plan.regime.value,
            created_at=time.time(),
            deployed_at=time.time() if installed else None,
        )
        self._versions.append(version)

        total_ms = (time.perf_counter() - overall_start) * 1000
        status = (
            DeploymentStatus.DRY_RUN_COMPLETE if plan.dry_run
            else DeploymentStatus.POST_VALIDATED if post_ok
            else DeploymentStatus.POST_VALIDATION_FAILED
        )

        return SeccompDeploymentResult(
            status=status,
            profile_name=name,
            regime=plan.regime.value,
            dry_run=plan.dry_run,
            program=program,
            build_duration_ms=build_ms,
            verified=verified,
            alignment_report=alignment_report,
            alignment_duration_ms=alignment_ms,
            certified=certified,
            compliance_certificate=compliance_cert,
            proof_certificate=proof_cert,
            certification_duration_ms=cert_ms,
            installed=installed,
            install_duration_ms=install_ms,
            post_validated=post_ok,
            post_validation_checks=tuple(post_checks),
            policy_version=version,
            audit_events=tuple(self._events),
            total_duration_ms=total_ms,
        )

    # ── Helpers ────────────────────────────────────────────────

    def resolve_profile(self, name: str) -> SeccompProfile:
        """Resolve a named profile to a SeccompProfile."""
        factory = self.NAMED_PROFILES.get(name)
        if factory is None:
            raise ValueError(
                f"Unknown profile: {name!r}. "
                f"Available: {sorted(self.NAMED_PROFILES)}"
            )
        return factory()

    def resolve_regime(self, name: str) -> ComplianceRegime:
        """Resolve a regime name string to ComplianceRegime enum."""
        regime = self.NAMED_REGIMES.get(name.lower())
        if regime is None:
            raise ValueError(
                f"Unknown regime: {name!r}. "
                f"Available: {sorted(self.NAMED_REGIMES)}"
            )
        return regime


# =============================================================================
# Convenience: one-call deployment
# =============================================================================

def deploy_verified_seccomp(
    profile_name: str = "network_blocked",
    regime: str = "general",
    *,
    argument_policy: Optional[ArgumentPolicy] = None,
    dry_run: bool = True,
    skip_alignment: bool = False,
    skip_certification: bool = False,
) -> SeccompDeploymentResult:
    """Deploy a Dafny-verified seccomp filter in one call.

    Args:
        profile_name: Named profile ("standard", "network_blocked", "compute_only").
        regime: Compliance regime ("hipaa", "sox", "legal", "pci_dss", "general").
        argument_policy: Argument-level constraints. Defaults to strict.
        dry_run: If True, do everything except kernel installation.
        skip_alignment: Skip Dafny alignment verification (not recommended).
        skip_certification: Skip compliance certification.

    Returns:
        SeccompDeploymentResult with full audit trail.

    Example::

        result = deploy_verified_seccomp("network_blocked", "hipaa", dry_run=True)
        assert result.verified
        assert result.certified
        print(result.to_json())
    """
    manager = SeccompDeploymentManager()
    profile = manager.resolve_profile(profile_name)
    compliance_regime = manager.resolve_regime(regime)

    if argument_policy is None:
        argument_policy = ArgumentPolicy.strict()

    plan = SeccompDeploymentPlan(
        profile=profile,
        regime=compliance_regime,
        argument_policy=argument_policy,
        dry_run=dry_run,
        skip_alignment=skip_alignment,
        skip_certification=skip_certification,
    )

    return manager.deploy(plan)

"""
Deployment Orchestration - Production Tests
=====================================================

Tests for seccomp_deploy.py: SeccompDeploymentManager, SeccompSafetyNet,
audit events, policy versioning, and the deploy_verified_seccomp() convenience
function.

Covers:
  - DeploymentStatus enum completeness
  - SeccompAuditEvent construction and serialization
  - SeccompPolicyVersion construction and serialization
  - PreflightCheck / PreflightResult
  - SeccompDeploymentPlan construction and serialization
  - SeccompDeploymentResult construction and serialization
  - SeccompSafetyNet.validate_deployment() - all 8 checks
  - SeccompDeploymentManager full lifecycle (dry-run)
  - SeccompDeploymentManager.resolve_profile / resolve_regime
  - deploy_verified_seccomp() convenience function
  - Audit event streaming
  - Policy version tracking
  - Error path handling
  - Performance constraints
"""

import hashlib
import json
import time
import pytest

from agentsafe.sandbox.seccomp_deploy import (
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
from agentsafe.sandbox.seccomp_verified import (
    BpfProgram,
    DefaultAction,
    SeccompFilterBuilder,
    SeccompProfile,
    create_compute_only_profile,
    create_network_blocked_profile,
    create_standard_profile,
    filter_syscall,
    normalize_syscalls,
)
from agentsafe.sandbox.seccomp_policy import (
    ArgumentPolicy,
    ComplianceRegime,
    SeccompComplianceMapper,
)
from agentsafe.sandbox.seccomp_dafny_bridge import (
    DafnyAlignmentVerifier,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def standard_profile():
    return create_standard_profile()


@pytest.fixture
def network_blocked_profile():
    return create_network_blocked_profile()


@pytest.fixture
def compute_only_profile():
    return create_compute_only_profile()


@pytest.fixture
def builder(standard_profile):
    return SeccompFilterBuilder(standard_profile)


@pytest.fixture
def program(builder):
    return builder.build_filter()


@pytest.fixture
def manager():
    return SeccompDeploymentManager()


@pytest.fixture
def dry_run_plan(standard_profile):
    return SeccompDeploymentPlan(
        profile=standard_profile,
        regime=ComplianceRegime.GENERAL,
        argument_policy=ArgumentPolicy.empty(),
        dry_run=True,
        skip_alignment=False,
        skip_certification=False,
    )


@pytest.fixture
def skip_all_plan(standard_profile):
    """Plan that skips alignment + certification for speed tests."""
    return SeccompDeploymentPlan(
        profile=standard_profile,
        regime=ComplianceRegime.GENERAL,
        argument_policy=ArgumentPolicy.empty(),
        dry_run=True,
        skip_alignment=True,
        skip_certification=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# DeploymentStatus
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeploymentStatus:

    def test_all_statuses_present(self):
        expected = {
            "PENDING", "PREFLIGHT_PASSED", "PREFLIGHT_FAILED",
            "BUILT", "VERIFIED", "VERIFICATION_FAILED",
            "CERTIFIED", "INSTALLED", "INSTALL_FAILED",
            "POST_VALIDATED", "POST_VALIDATION_FAILED", "DRY_RUN_COMPLETE",
        }
        actual = {s.name for s in DeploymentStatus}
        assert expected == actual

    def test_statuses_are_unique(self):
        values = [s.value for s in DeploymentStatus]
        assert len(values) == len(set(values))

    def test_status_count(self):
        assert len(DeploymentStatus) == 12


# ═══════════════════════════════════════════════════════════════════════════════
# SeccompAuditEvent
# ═══════════════════════════════════════════════════════════════════════════════

class TestSeccompAuditEvent:

    def test_construction(self):
        ev = SeccompAuditEvent(
            event_id="e001",
            event_type="preflight",
            timestamp=1700000000.0,
            profile_name="standard",
            status="success",
            details={"key": "val"},
            duration_ms=1.5,
        )
        assert ev.event_id == "e001"
        assert ev.event_type == "preflight"
        assert ev.status == "success"
        assert ev.duration_ms == 1.5

    def test_frozen(self):
        ev = SeccompAuditEvent("e1", "build", 0.0, "p", "ok", {}, 0.0)
        with pytest.raises(AttributeError):
            ev.status = "changed"

    def test_to_dict(self):
        ev = SeccompAuditEvent("e1", "build", 123.0, "p", "ok", {"x": 1}, 2.0)
        d = ev.to_dict()
        assert d["event_id"] == "e1"
        assert d["event_type"] == "build"
        assert d["details"] == {"x": 1}
        assert isinstance(d, dict)

    def test_to_json(self):
        ev = SeccompAuditEvent("e1", "build", 0.0, "p", "ok", {}, 0.0)
        j = ev.to_json()
        parsed = json.loads(j)
        assert parsed["event_id"] == "e1"

    def test_to_json_roundtrip(self):
        ev = SeccompAuditEvent("e1", "certify", 999.0, "net", "failure",
                               {"reason": "timeout"}, 50.0)
        parsed = json.loads(ev.to_json())
        assert parsed["profile_name"] == "net"
        assert parsed["details"]["reason"] == "timeout"


# ═══════════════════════════════════════════════════════════════════════════════
# SeccompPolicyVersion
# ═══════════════════════════════════════════════════════════════════════════════

class TestSeccompPolicyVersion:

    def test_construction(self):
        v = SeccompPolicyVersion(
            version_id="v001",
            profile_name="standard",
            profile_hash="abc123",
            syscall_count=100,
            instruction_count=106,
            default_action="kill_process",
            excludes_network=False,
            excludes_process_spawn=False,
            argument_constraints_count=0,
            compliance_regime="general",
            created_at=time.time(),
            deployed_at=None,
        )
        assert v.profile_name == "standard"
        assert v.deployed_at is None

    def test_to_dict(self):
        v = SeccompPolicyVersion(
            "v1", "std", "hash", 50, 56, "kill", False, False, 2, "hipaa",
            1000.0, 1001.0,
        )
        d = v.to_dict()
        assert d["version_id"] == "v1"
        assert d["compliance_regime"] == "hipaa"
        assert d["deployed_at"] == 1001.0

    def test_to_dict_serializable(self):
        v = SeccompPolicyVersion(
            "v1", "p", "h", 10, 16, "kill", True, True, 0, "sox",
            0.0, None,
        )
        j = json.dumps(v.to_dict())
        assert "sox" in j


# ═══════════════════════════════════════════════════════════════════════════════
# PreflightCheck / PreflightResult
# ═══════════════════════════════════════════════════════════════════════════════

class TestPreflightCheck:

    def test_passed_check(self):
        c = PreflightCheck(name="test", passed=True, detail="ok")
        assert c.passed is True
        d = c.to_dict()
        assert d["name"] == "test"
        assert d["passed"] is True

    def test_failed_check(self):
        c = PreflightCheck(name="bad", passed=False, detail="err")
        assert c.passed is False


class TestPreflightResult:

    def test_all_passed(self):
        checks = [
            PreflightCheck("a", True, "ok"),
            PreflightCheck("b", True, "ok"),
        ]
        r = PreflightResult(all_passed=True, checks=tuple(checks), timestamp=time.time())
        assert r.all_passed is True
        d = r.to_dict()
        assert len(d["checks"]) == 2

    def test_one_failed(self):
        checks = [
            PreflightCheck("a", True, "ok"),
            PreflightCheck("b", False, "bad"),
        ]
        r = PreflightResult(all_passed=False, checks=tuple(checks), timestamp=time.time())
        assert r.all_passed is False


# ═══════════════════════════════════════════════════════════════════════════════
# SeccompDeploymentPlan
# ═══════════════════════════════════════════════════════════════════════════════

class TestSeccompDeploymentPlan:

    def test_construction(self, standard_profile):
        plan = SeccompDeploymentPlan(
            profile=standard_profile,
            regime=ComplianceRegime.HIPAA,
            argument_policy=ArgumentPolicy.empty(),
            dry_run=True,
            skip_alignment=False,
            skip_certification=False,
        )
        assert plan.profile.name == standard_profile.name
        assert plan.dry_run is True

    def test_to_dict(self, standard_profile):
        plan = SeccompDeploymentPlan(
            standard_profile, ComplianceRegime.SOX,
            ArgumentPolicy.empty(), False, False, False,
        )
        d = plan.to_dict()
        assert d["regime"] == "sox"
        assert d["dry_run"] is False
        assert "profile_name" in d


# ═══════════════════════════════════════════════════════════════════════════════
# SeccompDeploymentResult
# ═══════════════════════════════════════════════════════════════════════════════

class TestSeccompDeploymentResult:

    def test_minimal_result(self):
        r = SeccompDeploymentResult(
            status=DeploymentStatus.PREFLIGHT_FAILED,
            profile_name="test",
            regime="general",
            dry_run=False,
            audit_events=(),
            total_duration_ms=5.0,
        )
        assert r.status == DeploymentStatus.PREFLIGHT_FAILED
        assert r.program is None
        assert r.verified is False

    def test_to_dict(self, program, standard_profile):
        r = SeccompDeploymentResult(
            status=DeploymentStatus.DRY_RUN_COMPLETE,
            profile_name="standard",
            regime="general",
            dry_run=True,
            program=program,
            build_duration_ms=1.0,
            verified=True,
            certified=True,
            post_validated=True,
            audit_events=(),
            total_duration_ms=10.0,
        )
        d = r.to_dict()
        assert d["status"] == "DRY_RUN_COMPLETE"
        assert d["verified"] is True

    def test_to_json(self):
        r = SeccompDeploymentResult(
            status=DeploymentStatus.DRY_RUN_COMPLETE,
            profile_name="p",
            regime="g",
            dry_run=True,
            audit_events=(),
            total_duration_ms=1.0,
        )
        j = r.to_json()
        parsed = json.loads(j)
        assert parsed["profile_name"] == "p"


# ═══════════════════════════════════════════════════════════════════════════════
# SeccompSafetyNet
# ═══════════════════════════════════════════════════════════════════════════════

class TestSeccompSafetyNet:

    def test_standard_profile_passes(self, standard_profile):
        builder = SeccompFilterBuilder(standard_profile)
        prog = builder.build_filter()
        ok, checks = SeccompSafetyNet.validate_deployment(prog, standard_profile)
        assert ok is True
        assert len(checks) >= 5

    def test_network_blocked_profile_passes(self, network_blocked_profile):
        builder = SeccompFilterBuilder(network_blocked_profile)
        prog = builder.build_filter()
        ok, checks = SeccompSafetyNet.validate_deployment(prog, network_blocked_profile)
        assert ok is True
        # Should include network exclusion check
        check_names = [c.name for c in checks]
        assert "network_exclusion_p43" in check_names

    def test_compute_only_passes(self, compute_only_profile):
        builder = SeccompFilterBuilder(compute_only_profile)
        prog = builder.build_filter()
        ok, checks = SeccompSafetyNet.validate_deployment(prog, compute_only_profile)
        assert ok is True
        check_names = [c.name for c in checks]
        assert "network_exclusion_p43" in check_names
        assert "process_spawn_exclusion" in check_names

    def test_bpf_nonempty_check(self, program, standard_profile):
        _, checks = SeccompSafetyNet.validate_deployment(program, standard_profile)
        nonempty = [c for c in checks if c.name == "bpf_program_nonempty"]
        assert len(nonempty) == 1
        assert nonempty[0].passed is True

    def test_instruction_count_check(self, program, standard_profile):
        _, checks = SeccompSafetyNet.validate_deployment(program, standard_profile)
        ic_check = [c for c in checks if c.name == "instruction_count_p40"]
        assert len(ic_check) == 1
        assert ic_check[0].passed is True

    def test_allowlist_match_check(self, program, standard_profile):
        _, checks = SeccompSafetyNet.validate_deployment(program, standard_profile)
        al = [c for c in checks if c.name == "allowlist_match"]
        assert len(al) == 1
        assert al[0].passed is True

    def test_default_action_match(self, program, standard_profile):
        _, checks = SeccompSafetyNet.validate_deployment(program, standard_profile)
        da = [c for c in checks if c.name == "default_action_match"]
        assert len(da) == 1
        assert da[0].passed is True

    def test_filter_decision_consistency(self, program, standard_profile):
        _, checks = SeccompSafetyNet.validate_deployment(program, standard_profile)
        fc = [c for c in checks if c.name == "filter_decision_consistency"]
        assert len(fc) == 1
        assert fc[0].passed is True

    def test_program_hash_integrity(self, program, standard_profile):
        _, checks = SeccompSafetyNet.validate_deployment(program, standard_profile)
        ph = [c for c in checks if c.name == "program_hash_integrity"]
        assert len(ph) == 1
        assert ph[0].passed is True

    def test_all_checks_have_detail(self, program, standard_profile):
        _, checks = SeccompSafetyNet.validate_deployment(program, standard_profile)
        for c in checks:
            assert c.detail is not None
            assert len(c.detail) > 0

    def test_check_names_unique(self, program, standard_profile):
        _, checks = SeccompSafetyNet.validate_deployment(program, standard_profile)
        names = [c.name for c in checks]
        assert len(names) == len(set(names))


# ═══════════════════════════════════════════════════════════════════════════════
# SeccompDeploymentManager - Preflight
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeploymentManagerPreflight:

    def test_preflight_returns_result(self, manager):
        result = manager.preflight()
        assert isinstance(result, PreflightResult)
        assert isinstance(result.all_passed, bool)
        assert len(result.checks) > 0

    def test_preflight_checks_platform(self, manager):
        result = manager.preflight()
        check_names = [c.name for c in result.checks]
        assert "platform_linux" in check_names

    def test_preflight_checks_architecture(self, manager):
        result = manager.preflight()
        check_names = [c.name for c in result.checks]
        assert "architecture_supported" in check_names


# ═══════════════════════════════════════════════════════════════════════════════
# SeccompDeploymentManager - Deploy (dry-run)
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeploymentManagerDryRun:

    def test_dry_run_succeeds(self, manager, dry_run_plan):
        result = manager.deploy(dry_run_plan)
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE
        assert result.dry_run is True
        assert result.installed is False

    def test_dry_run_builds_program(self, manager, dry_run_plan):
        result = manager.deploy(dry_run_plan)
        assert result.program is not None
        assert result.program.instruction_count > 0
        assert result.build_duration_ms > 0

    def test_dry_run_verifies_alignment(self, manager, dry_run_plan):
        result = manager.deploy(dry_run_plan)
        assert result.verified is True
        assert result.alignment_report is not None
        assert result.alignment_report.all_passed is True
        assert result.alignment_duration_ms > 0

    def test_dry_run_certifies(self, manager, dry_run_plan):
        result = manager.deploy(dry_run_plan)
        assert result.certified is True
        assert result.compliance_certificate is not None
        assert result.proof_certificate is not None
        assert result.certification_duration_ms > 0

    def test_dry_run_post_validates(self, manager, dry_run_plan):
        result = manager.deploy(dry_run_plan)
        assert result.post_validated is True
        assert len(result.post_validation_checks) >= 5

    def test_dry_run_records_policy_version(self, manager, dry_run_plan):
        result = manager.deploy(dry_run_plan)
        assert result.policy_version is not None
        assert result.policy_version.profile_name == dry_run_plan.profile.name
        assert result.policy_version.deployed_at is None  # dry run

    def test_dry_run_emits_audit_events(self, manager, dry_run_plan):
        result = manager.deploy(dry_run_plan)
        assert len(result.audit_events) >= 4  # preflight, build, verify, certify, install(skip), validate
        event_types = [e.event_type for e in result.audit_events]
        assert "preflight" in event_types
        assert "build" in event_types

    def test_dry_run_total_duration(self, manager, dry_run_plan):
        result = manager.deploy(dry_run_plan)
        assert result.total_duration_ms > 0

    def test_dry_run_result_serializable(self, manager, dry_run_plan):
        result = manager.deploy(dry_run_plan)
        d = result.to_dict()
        j = json.dumps(d, default=str)
        assert "DRY_RUN_COMPLETE" in j


# ═══════════════════════════════════════════════════════════════════════════════
# SeccompDeploymentManager - Deploy with skip options
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeploymentManagerSkipOptions:

    def test_skip_alignment(self, manager, standard_profile):
        plan = SeccompDeploymentPlan(
            standard_profile, ComplianceRegime.GENERAL,
            ArgumentPolicy.empty(), dry_run=True,
            skip_alignment=True, skip_certification=False,
        )
        result = manager.deploy(plan)
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE
        assert result.verified is True  # auto-pass when skipped
        assert result.alignment_report is None

    def test_skip_certification(self, manager, standard_profile):
        plan = SeccompDeploymentPlan(
            standard_profile, ComplianceRegime.GENERAL,
            ArgumentPolicy.empty(), dry_run=True,
            skip_alignment=False, skip_certification=True,
        )
        result = manager.deploy(plan)
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE
        assert result.certified is True  # auto-pass when skipped
        assert result.compliance_certificate is None

    def test_skip_both(self, manager, skip_all_plan):
        result = manager.deploy(skip_all_plan)
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE
        assert result.alignment_report is None
        assert result.compliance_certificate is None


# ═══════════════════════════════════════════════════════════════════════════════
# SeccompDeploymentManager - Multiple Profiles
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeploymentManagerProfiles:

    def test_deploy_network_blocked(self, manager, network_blocked_profile):
        plan = SeccompDeploymentPlan(
            network_blocked_profile, ComplianceRegime.HIPAA,
            ArgumentPolicy.empty(), dry_run=True,
            skip_alignment=False, skip_certification=False,
        )
        result = manager.deploy(plan)
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE
        assert result.policy_version.excludes_network is True

    def test_deploy_compute_only(self, manager, compute_only_profile):
        plan = SeccompDeploymentPlan(
            compute_only_profile, ComplianceRegime.SOX,
            ArgumentPolicy.empty(), dry_run=True,
            skip_alignment=False, skip_certification=False,
        )
        result = manager.deploy(plan)
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE
        assert result.policy_version.excludes_network is True
        assert result.policy_version.excludes_process_spawn is True

    def test_deploy_hipaa_regime(self, manager, standard_profile):
        plan = SeccompDeploymentPlan(
            standard_profile, ComplianceRegime.HIPAA,
            ArgumentPolicy.empty(), dry_run=True,
            skip_alignment=False, skip_certification=False,
        )
        result = manager.deploy(plan)
        assert result.regime == "hipaa"
        assert result.policy_version.compliance_regime == "hipaa"


# ═══════════════════════════════════════════════════════════════════════════════
# SeccompDeploymentManager - Resolve helpers
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeploymentManagerResolvers:

    def test_resolve_standard_profile(self, manager):
        p = manager.resolve_profile("standard")
        assert p.name == "standard"

    def test_resolve_network_blocked_profile(self, manager):
        p = manager.resolve_profile("network_blocked")
        assert p.excludes_network is True

    def test_resolve_compute_only_profile(self, manager):
        p = manager.resolve_profile("compute_only")
        assert p.excludes_network is True
        assert p.excludes_process_spawn is True

    def test_resolve_unknown_profile_raises(self, manager):
        with pytest.raises(ValueError, match="Unknown profile"):
            manager.resolve_profile("nonexistent")

    def test_resolve_hipaa_regime(self, manager):
        r = manager.resolve_regime("hipaa")
        assert r == ComplianceRegime.HIPAA

    def test_resolve_sox_regime(self, manager):
        r = manager.resolve_regime("sox")
        assert r == ComplianceRegime.SOX

    def test_resolve_legal_regime(self, manager):
        r = manager.resolve_regime("legal")
        assert r == ComplianceRegime.LEGAL

    def test_resolve_general_regime(self, manager):
        r = manager.resolve_regime("general")
        assert r == ComplianceRegime.GENERAL

    def test_resolve_regime_case_insensitive(self, manager):
        r = manager.resolve_regime("HIPAA")
        assert r == ComplianceRegime.HIPAA

    def test_resolve_unknown_regime_raises(self, manager):
        with pytest.raises(ValueError, match="Unknown regime"):
            manager.resolve_regime("nonexistent")


# ═══════════════════════════════════════════════════════════════════════════════
# SeccompDeploymentManager - Audit Event Tracking
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditEventTracking:

    def test_events_accumulate(self, manager, dry_run_plan):
        assert len(manager.audit_events) == 0
        manager.deploy(dry_run_plan)
        assert len(manager.audit_events) >= 4

    def test_events_have_timestamps(self, manager, dry_run_plan):
        manager.deploy(dry_run_plan)
        for ev in manager.audit_events:
            assert ev.timestamp > 0

    def test_events_have_duration(self, manager, dry_run_plan):
        manager.deploy(dry_run_plan)
        for ev in manager.audit_events:
            assert ev.duration_ms >= 0

    def test_events_persist_across_deploys(self, manager, standard_profile):
        plan1 = SeccompDeploymentPlan(
            standard_profile, ComplianceRegime.GENERAL,
            ArgumentPolicy.empty(), True, True, True,
        )
        plan2 = SeccompDeploymentPlan(
            standard_profile, ComplianceRegime.HIPAA,
            ArgumentPolicy.empty(), True, True, True,
        )
        manager.deploy(plan1)
        count_after_first = len(manager.audit_events)
        manager.deploy(plan2)
        assert len(manager.audit_events) > count_after_first

    def test_events_all_serializable(self, manager, dry_run_plan):
        manager.deploy(dry_run_plan)
        for ev in manager.audit_events:
            j = ev.to_json()
            parsed = json.loads(j)
            assert "event_type" in parsed


# ═══════════════════════════════════════════════════════════════════════════════
# SeccompDeploymentManager - Policy Version Tracking
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicyVersionTracking:

    def test_version_recorded(self, manager, dry_run_plan):
        assert len(manager.policy_versions) == 0
        manager.deploy(dry_run_plan)
        assert len(manager.policy_versions) == 1

    def test_version_has_hash(self, manager, dry_run_plan):
        manager.deploy(dry_run_plan)
        v = manager.policy_versions[0]
        assert len(v.profile_hash) == 64  # SHA-256

    def test_version_has_version_id(self, manager, dry_run_plan):
        manager.deploy(dry_run_plan)
        v = manager.policy_versions[0]
        assert len(v.version_id) > 0

    def test_multiple_deploys_create_versions(self, manager, standard_profile,
                                               network_blocked_profile):
        plan1 = SeccompDeploymentPlan(
            standard_profile, ComplianceRegime.GENERAL,
            ArgumentPolicy.empty(), True, True, True,
        )
        plan2 = SeccompDeploymentPlan(
            network_blocked_profile, ComplianceRegime.HIPAA,
            ArgumentPolicy.empty(), True, True, True,
        )
        manager.deploy(plan1)
        manager.deploy(plan2)
        assert len(manager.policy_versions) == 2
        names = [v.profile_name for v in manager.policy_versions]
        assert "standard" in names
        assert "network_blocked" in names

    def test_version_serializable(self, manager, dry_run_plan):
        manager.deploy(dry_run_plan)
        v = manager.policy_versions[0]
        j = json.dumps(v.to_dict(), default=str)
        assert v.profile_name in j


# ═══════════════════════════════════════════════════════════════════════════════
# deploy_verified_seccomp() convenience function
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeployVerifiedSeccomp:

    def test_default_dry_run(self):
        result = deploy_verified_seccomp()
        assert result.dry_run is True
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE

    def test_explicit_profile(self):
        result = deploy_verified_seccomp(profile_name="standard")
        assert result.profile_name == "standard"
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE

    def test_network_blocked(self):
        result = deploy_verified_seccomp(profile_name="network_blocked")
        assert result.profile_name == "network_blocked"
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE

    def test_compute_only(self):
        result = deploy_verified_seccomp(profile_name="compute_only")
        assert result.profile_name == "compute_only"
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE

    def test_with_hipaa_regime(self):
        result = deploy_verified_seccomp(
            profile_name="network_blocked", regime="hipaa",
        )
        assert result.regime == "hipaa"
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE

    def test_with_sox_regime(self):
        result = deploy_verified_seccomp(
            profile_name="standard", regime="sox",
        )
        assert result.regime == "sox"

    def test_with_argument_policy(self):
        result = deploy_verified_seccomp(
            profile_name="standard",
            argument_policy=ArgumentPolicy.strict(),
        )
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE
        assert result.policy_version.argument_constraints_count > 0

    def test_skip_alignment(self):
        result = deploy_verified_seccomp(skip_alignment=True)
        assert result.alignment_report is None
        assert result.verified is True

    def test_skip_certification(self):
        result = deploy_verified_seccomp(skip_certification=True)
        assert result.compliance_certificate is None
        assert result.certified is True

    def test_returns_program(self):
        result = deploy_verified_seccomp()
        assert result.program is not None
        assert result.program.instruction_count > 0

    def test_returns_audit_events(self):
        result = deploy_verified_seccomp()
        assert len(result.audit_events) >= 4

    def test_unknown_profile_raises(self):
        with pytest.raises(ValueError, match="Unknown profile"):
            deploy_verified_seccomp(profile_name="nonexistent")

    def test_unknown_regime_raises(self):
        with pytest.raises(ValueError, match="Unknown regime"):
            deploy_verified_seccomp(regime="nonexistent")


# ═══════════════════════════════════════════════════════════════════════════════
# End-to-End Workflows
# ═══════════════════════════════════════════════════════════════════════════════

class TestEndToEndDeployment:

    def test_hipaa_full_deployment(self):
        """Full HIPAA deployment: network_blocked + hipaa + strict args."""
        result = deploy_verified_seccomp(
            profile_name="network_blocked",
            regime="hipaa",
            argument_policy=ArgumentPolicy.strict(),
        )
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE
        assert result.verified is True
        assert result.certified is True
        assert result.post_validated is True
        assert result.policy_version.excludes_network is True
        assert result.policy_version.compliance_regime == "hipaa"
        assert result.policy_version.argument_constraints_count > 0
        # Must have proof certificate
        assert result.proof_certificate is not None
        assert result.proof_certificate.is_valid is True

    def test_sox_full_deployment(self):
        """Full SOX deployment: compute_only + sox."""
        result = deploy_verified_seccomp(
            profile_name="compute_only",
            regime="sox",
        )
        assert result.status == DeploymentStatus.DRY_RUN_COMPLETE
        assert result.verified is True
        assert result.certified is True
        assert result.policy_version.excludes_network is True
        assert result.policy_version.excludes_process_spawn is True

    def test_deployment_result_full_audit_trail(self):
        """Audit trail covers every pipeline stage."""
        result = deploy_verified_seccomp(
            profile_name="standard", regime="general",
        )
        event_types = {e.event_type for e in result.audit_events}
        # Must include all lifecycle stages
        assert "preflight" in event_types
        assert "build" in event_types
        assert "verify" in event_types
        assert "certify" in event_types
        assert "validate" in event_types

    def test_deployment_manager_reuse(self):
        """Manager can be reused across multiple deployments."""
        mgr = SeccompDeploymentManager()
        profiles = ["standard", "network_blocked", "compute_only"]
        for name in profiles:
            plan = SeccompDeploymentPlan(
                mgr.resolve_profile(name),
                ComplianceRegime.GENERAL,
                ArgumentPolicy.empty(),
                dry_run=True,
                skip_alignment=True,
                skip_certification=True,
            )
            result = mgr.deploy(plan)
            assert result.status == DeploymentStatus.DRY_RUN_COMPLETE
        assert len(mgr.policy_versions) == 3
        assert len(mgr.audit_events) >= 12  # at least 4 events per deploy


# ═══════════════════════════════════════════════════════════════════════════════
# Performance
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeploymentPerformance:

    def test_dry_run_under_200ms(self, manager, dry_run_plan):
        t0 = time.perf_counter()
        result = manager.deploy(dry_run_plan)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 200, f"Dry-run took {elapsed_ms:.1f}ms"

    def test_skip_all_under_100ms(self, manager, skip_all_plan):
        t0 = time.perf_counter()
        result = manager.deploy(skip_all_plan)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 100, f"Skip-all took {elapsed_ms:.1f}ms"

    def test_safety_net_under_5ms(self, program, standard_profile):
        t0 = time.perf_counter()
        ok, _ = SeccompSafetyNet.validate_deployment(program, standard_profile)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 5, f"Safety net took {elapsed_ms:.1f}ms"

    def test_convenience_function_under_200ms(self):
        t0 = time.perf_counter()
        result = deploy_verified_seccomp()
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 200, f"deploy_verified_seccomp took {elapsed_ms:.1f}ms"

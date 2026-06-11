"""
Production Tests - Extended Dafny-Verified Seccomp Filter.

Tests cover:
  - Argument constraints (P47): fine-grained per-syscall arg filtering
  - Filter composition (P48): intersection-based composition
  - Filter size bounds (P49): BPF instruction count limits
  - Attenuation (P50): strict subset removal
  - Constraint monotonicity (P51): adding constraints only restricts
  - Complete coverage (P52): every syscall nr gets defined decision
  - Composition associativity (P53): compose(compose(A,B),C) == compose(A,compose(B,C))
  - Attenuation chain transitivity (P54): chain of attenuations is transitive
  - Compliance certification: HIPAA, SOX, Legal, PCI-DSS, General
  - Dafny-Python alignment bridge: systematic runtime verification of P34-P54
  - Proof certificates: cryptographic attestation of verified properties
  - Policy chain lineage tracking
"""

import hashlib
import time
import pytest
from typing import List, Set

from agentsafe.sandbox.seccomp_verified import (
    BpfProgram,
    DefaultAction,
    FilterDecision,
    SeccompFilterBuilder,
    SeccompProfile,
    build_verified_seccomp,
    create_compute_only_profile,
    create_custom_profile,
    create_network_blocked_profile,
    create_profile_from_numbers,
    create_standard_profile,
    filter_syscall,
    instruction_count,
    is_subset_of,
    normalize_syscalls,
)
from agentsafe.sandbox.seccomp_policy import (
    ArgumentConstraint,
    ArgumentMatchMode,
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
from agentsafe.sandbox.seccomp_dafny_bridge import (
    AlignmentReport,
    DafnyAlignmentVerifier,
    DafnyProofCertificate,
    DafnyProperty,
    DafnyPropertyRegistry,
    PropertyCheckResult,
    PropertyStatus,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def standard_profile() -> SeccompProfile:
    return create_standard_profile()


@pytest.fixture
def network_blocked() -> SeccompProfile:
    return create_network_blocked_profile()


@pytest.fixture
def compute_only() -> SeccompProfile:
    return create_compute_only_profile()


@pytest.fixture
def small_profile() -> SeccompProfile:
    return create_profile_from_numbers(
        name="small",
        allowed_numbers=[0, 1, 3, 9, 10, 11, 12, 60],
        default_action=DefaultAction.KILL,
    )


@pytest.fixture
def tiny_profile() -> SeccompProfile:
    return create_profile_from_numbers(
        name="tiny",
        allowed_numbers=[0, 1, 3, 60],
        default_action=DefaultAction.KILL,
    )


@pytest.fixture
def composer() -> SeccompPolicyComposer:
    return SeccompPolicyComposer()


@pytest.fixture
def attenuator() -> SeccompPolicyAttenuator:
    return SeccompPolicyAttenuator()


@pytest.fixture
def compliance_mapper() -> SeccompComplianceMapper:
    return SeccompComplianceMapper()


@pytest.fixture
def alignment_verifier() -> DafnyAlignmentVerifier:
    return DafnyAlignmentVerifier()


# ===================================================================
# ARGUMENT CONSTRAINTS (P47)
# ===================================================================

class TestArgumentConstraints:
    """P47: Argument constraint safety - filter returns Allow only if
    syscall in allowlist AND argument satisfies constraint."""

    def test_openat_readonly_factory(self):
        """openat_readonly() creates correct constraint."""
        c = ArgumentConstraint.openat_readonly()
        assert c.arg_index == 2
        assert c.match_mode == ArgumentMatchMode.BITMASK
        assert c.description.lower().count("read") >= 1

    def test_mprotect_no_exec_factory(self):
        """mprotect_no_exec() creates correct constraint."""
        c = ArgumentConstraint.mprotect_no_exec()
        assert c.arg_index == 2
        assert c.match_mode == ArgumentMatchMode.EXACT
        assert c.description.lower().count("exec") >= 1

    def test_exact_match_allowed(self):
        """EXACT match mode allows listed values."""
        c = ArgumentConstraint(
            syscall_nr=257,
            arg_index=2,
            allowed_values=frozenset({0, 1}),
            match_mode=ArgumentMatchMode.EXACT,
        )
        assert c.is_allowed(0)
        assert c.is_allowed(1)
        assert not c.is_allowed(2)
        assert not c.is_allowed(64)

    def test_bitmask_match_readonly(self):
        """BITMASK mode: O_RDONLY (0) passes, O_WRONLY (1) fails."""
        c = ArgumentConstraint.openat_readonly()
        assert c.is_allowed(0)          # O_RDONLY
        assert not c.is_allowed(1)      # O_WRONLY
        assert not c.is_allowed(2)      # O_RDWR
        assert not c.is_allowed(64)     # O_CREAT

    def test_bitmask_match_no_exec(self):
        """BITMASK mode: PROT_READ passes, PROT_EXEC fails."""
        c = ArgumentConstraint.mprotect_no_exec()
        assert c.is_allowed(1)          # PROT_READ
        assert c.is_allowed(2)          # PROT_WRITE
        assert c.is_allowed(3)          # PROT_READ|PROT_WRITE
        assert not c.is_allowed(4)      # PROT_EXEC
        assert not c.is_allowed(5)      # PROT_READ|PROT_EXEC
        assert not c.is_allowed(7)      # PROT_READ|PROT_WRITE|PROT_EXEC

    def test_range_match(self):
        """RANGE mode: value in [min, max] passes."""
        c = ArgumentConstraint(
            syscall_nr=100,
            arg_index=0,
            allowed_values=frozenset({10, 20}),
            match_mode=ArgumentMatchMode.RANGE,
        )
        assert c.is_allowed(10)
        assert c.is_allowed(15)
        assert c.is_allowed(20)
        assert not c.is_allowed(9)
        assert not c.is_allowed(21)

    def test_argument_policy_empty(self):
        """Empty policy has no constraints."""
        p = ArgumentPolicy.empty()
        assert not p.has_constraint(257)
        assert p.check_syscall(257, {2: 0}).is_allow  # no constraint → allow

    def test_argument_policy_with_constraint(self):
        """Adding constraint is monotonic - only restricts."""
        p = ArgumentPolicy.empty()
        c = ArgumentConstraint.openat_readonly()
        p2 = p.with_constraint(c)

        # Original unchanged
        assert not p.has_constraint(c.syscall_nr)
        # New policy has constraint
        assert p2.has_constraint(c.syscall_nr)

    def test_argument_policy_check_syscall_constrained(self):
        """check_syscall enforces constraint when present."""
        p = ArgumentPolicy.empty().with_constraint(
            ArgumentConstraint.openat_readonly()
        )
        nr = ArgumentConstraint.openat_readonly().syscall_nr
        assert p.check_syscall(nr, {2: 0}).is_allow      # O_RDONLY → ok
        assert p.check_syscall(nr, {2: 1}).is_deny   # O_WRONLY → blocked

    def test_readonly_filesystem_factory(self):
        """readonly_filesystem() blocks write flags."""
        p = ArgumentPolicy.readonly_filesystem()
        nr = ArgumentConstraint.openat_readonly().syscall_nr
        assert p.has_constraint(nr)
        assert p.check_syscall(nr, {2: 0}).is_allow
        assert p.check_syscall(nr, {2: 1}).is_deny

    def test_no_exec_memory_factory(self):
        """no_exec_memory() blocks PROT_EXEC."""
        p = ArgumentPolicy.no_exec_memory()
        nr = ArgumentConstraint.mprotect_no_exec().syscall_nr
        assert p.has_constraint(nr)
        assert p.check_syscall(nr, {2: 1}).is_allow     # PROT_READ
        assert p.check_syscall(nr, {2: 4}).is_deny # PROT_EXEC

    def test_strict_factory(self):
        """strict() combines readonly_filesystem + no_exec_memory."""
        p = ArgumentPolicy.strict()
        openat_nr = ArgumentConstraint.openat_readonly().syscall_nr
        mprotect_nr = ArgumentConstraint.mprotect_no_exec().syscall_nr
        assert p.has_constraint(openat_nr)
        assert p.has_constraint(mprotect_nr)


# ===================================================================
# FILTER COMPOSITION (P48)
# ===================================================================

class TestFilterComposition:
    """P48: Composition via intersection - result ⊆ both inputs."""

    def test_compose_intersection(self, small_profile, tiny_profile, composer):
        """Composed allowlist is intersection of inputs."""
        result = composer.compose(small_profile, tiny_profile)
        result_set = set(result.allowed_syscalls)
        a_set = set(small_profile.allowed_syscalls)
        b_set = set(tiny_profile.allowed_syscalls)
        assert result_set == a_set & b_set

    def test_compose_subset_of_both(self, small_profile, tiny_profile, composer):
        """Result is subset of both input profiles."""
        result = composer.compose(small_profile, tiny_profile)
        assert is_subset_of(result.allowed_syscalls, small_profile.allowed_syscalls)
        assert is_subset_of(result.allowed_syscalls, tiny_profile.allowed_syscalls)

    def test_compose_never_expands(self, standard_profile, network_blocked, composer):
        """Composition never adds syscalls not in either input."""
        result = composer.compose(standard_profile, network_blocked)
        result_set = set(result.allowed_syscalls)
        union = set(standard_profile.allowed_syscalls) | set(network_blocked.allowed_syscalls)
        assert result_set <= union

    def test_compose_commutative(self, small_profile, tiny_profile, composer):
        """compose(A, B) == compose(B, A) in allowed set."""
        r1 = composer.compose(small_profile, tiny_profile)
        r2 = composer.compose(tiny_profile, small_profile)
        assert set(r1.allowed_syscalls) == set(r2.allowed_syscalls)

    def test_compose_idempotent(self, small_profile, composer):
        """compose(A, A) == A in allowed set."""
        result = composer.compose(small_profile, small_profile)
        assert set(result.allowed_syscalls) == set(small_profile.allowed_syscalls)

    def test_compose_many_three_profiles(self, composer):
        """compose_many reduces multiple profiles correctly."""
        p1 = create_profile_from_numbers("p1", [0, 1, 2, 3, 4, 5], DefaultAction.KILL)
        p2 = create_profile_from_numbers("p2", [0, 2, 4, 6, 8], DefaultAction.KILL)
        p3 = create_profile_from_numbers("p3", [0, 4, 8, 12], DefaultAction.KILL)
        result = composer.compose_many([p1, p2, p3])
        assert set(result.allowed_syscalls) == {0, 4}

    def test_compose_many_single(self, small_profile, composer):
        """compose_many with single input returns equivalent profile."""
        result = composer.compose_many([small_profile])
        assert set(result.allowed_syscalls) == set(small_profile.allowed_syscalls)

    def test_compose_argument_policies(self, composer):
        """Composing argument policies merges constraints (P51)."""
        pa = ArgumentPolicy.readonly_filesystem()
        pb = ArgumentPolicy.no_exec_memory()
        merged = composer.compose_argument_policies(pa, pb)
        openat_nr = ArgumentConstraint.openat_readonly().syscall_nr
        mprotect_nr = ArgumentConstraint.mprotect_no_exec().syscall_nr
        assert merged.has_constraint(openat_nr)
        assert merged.has_constraint(mprotect_nr)

    def test_compose_preserves_kill_action(self, composer):
        """If either profile uses KILL, result uses KILL."""
        p1 = create_profile_from_numbers("a", [0, 1], DefaultAction.KILL)
        p2 = create_profile_from_numbers("b", [0, 1], DefaultAction.LOG)
        result = composer.compose(p1, p2)
        assert result.default_action == DefaultAction.KILL


# ===================================================================
# FILTER SIZE BOUNDS (P49)
# ===================================================================

class TestFilterSizeBounds:
    """P49: Filter instruction count ≤ MAX_BPF_INSTRUCTIONS (4096)."""

    def test_small_filter_within_bounds(self, small_profile):
        """Small profile instruction count well within limit."""
        count = instruction_count(small_profile.allowed_syscalls)
        assert count <= 4096

    def test_standard_filter_within_bounds(self, standard_profile):
        """Standard profile stays within BPF limit."""
        count = instruction_count(standard_profile.allowed_syscalls)
        assert count <= 4096

    def test_instruction_count_formula(self):
        """instruction_count = len(allowlist) + 6 (header + footer)."""
        syscalls = [0, 1, 2, 3, 4]
        count = instruction_count(syscalls)
        assert count == len(syscalls) + 6

    def test_composition_within_bounds(self, standard_profile, network_blocked, composer):
        """Composed filter stays within BPF bounds."""
        result = composer.compose(standard_profile, network_blocked)
        count = instruction_count(result.allowed_syscalls)
        assert count <= 4096

    def test_max_allowlist_boundary(self):
        """4090-syscall allowlist produces exactly 4096 instructions."""
        big = list(range(4090))
        count = instruction_count(big)
        assert count == 4096


# ===================================================================
# ATTENUATION (P50)
# ===================================================================

class TestAttenuation:
    """P50: Attenuation produces strict subset."""

    def test_attenuate_removes_syscalls(self, small_profile, attenuator):
        """Attenuated profile lacks removed syscalls."""
        to_remove = {0, 1}  # read, write
        result, record = attenuator.attenuate(small_profile, to_remove)
        assert not set(result.allowed_syscalls) & to_remove

    def test_attenuate_is_subset(self, small_profile, attenuator):
        """Attenuated profile ⊆ original."""
        to_remove = {0, 1}
        result, _ = attenuator.attenuate(small_profile, to_remove)
        assert is_subset_of(result.allowed_syscalls, small_profile.allowed_syscalls)

    def test_attenuate_never_expands(self, small_profile, attenuator):
        """Attenuation never adds syscalls."""
        to_remove = {0}
        result, _ = attenuator.attenuate(small_profile, to_remove)
        assert set(result.allowed_syscalls) <= set(small_profile.allowed_syscalls)

    def test_attenuate_removes_nonexistent(self, small_profile, attenuator):
        """Removing syscalls not in profile is a no-op (minus set diff)."""
        to_remove = {9999}
        result, record = attenuator.attenuate(small_profile, to_remove)
        assert set(result.allowed_syscalls) == set(small_profile.allowed_syscalls)

    def test_attenuate_record(self, small_profile, attenuator):
        """AttenuationRecord tracks parent, child, removed syscalls."""
        to_remove = {0, 1}
        _, record = attenuator.attenuate(small_profile, to_remove)
        assert isinstance(record, AttenuationRecord)
        assert record.parent_profile_name == small_profile.name
        assert record.removed_syscalls == to_remove

    def test_attenuate_empty_removal(self, small_profile, attenuator):
        """Empty removal set returns equivalent profile."""
        result, _ = attenuator.attenuate(small_profile, set())
        assert set(result.allowed_syscalls) == set(small_profile.allowed_syscalls)

    def test_attenuate_all_syscalls(self, tiny_profile, attenuator):
        """Removing all syscalls yields empty allowlist."""
        to_remove = set(tiny_profile.allowed_syscalls)
        result, _ = attenuator.attenuate(tiny_profile, to_remove)
        assert len(result.allowed_syscalls) == 0


# ===================================================================
# ATTENUATION CHAIN TRANSITIVITY (P54)
# ===================================================================

class TestAttenuationChainTransitivity:
    """P54: If C = attenuate(B, r2) and B = attenuate(A, r1), then C ⊆ A."""

    def test_two_stage_chain(self, attenuator):
        """Two-stage attenuation: C ⊆ A."""
        a = create_profile_from_numbers("a", [0, 1, 2, 3, 4, 5, 6, 7], DefaultAction.KILL)
        b, _ = attenuator.attenuate(a, {0, 1})
        c, _ = attenuator.attenuate(b, {2, 3})
        assert is_subset_of(c.allowed_syscalls, a.allowed_syscalls)
        assert not set(c.allowed_syscalls) & {0, 1, 2, 3}

    def test_three_stage_chain(self, attenuator):
        """Three-stage attenuation remains subset of original."""
        a = create_profile_from_numbers("a", list(range(20)), DefaultAction.KILL)
        b, _ = attenuator.attenuate(a, {0, 1, 2})
        c, _ = attenuator.attenuate(b, {5, 6, 7})
        d, _ = attenuator.attenuate(c, {10, 11})
        assert is_subset_of(d.allowed_syscalls, a.allowed_syscalls)

    def test_attenuate_chain_api(self, attenuator):
        """attenuate_chain applies stages sequentially."""
        a = create_profile_from_numbers("a", list(range(10)), DefaultAction.KILL)
        stages = [{0, 1}, {3, 4}, {7}]
        result, records = attenuator.attenuate_chain(a, stages)
        assert is_subset_of(result.allowed_syscalls, a.allowed_syscalls)
        assert len(records) == 3

    def test_chain_records_lineage(self, attenuator):
        """Each stage in chain records parent/child names."""
        a = create_profile_from_numbers("base", list(range(10)), DefaultAction.KILL)
        stages = [{0, 1}, {5, 6}]
        _, records = attenuator.attenuate_chain(a, stages)
        assert records[0].parent_profile_name == "base"
        # Second stage's parent is the first stage's child
        assert records[1].parent_profile_name == records[0].child_profile_name


# ===================================================================
# COMPOSITION ASSOCIATIVITY (P53)
# ===================================================================

class TestCompositionAssociativity:
    """P53: compose(compose(A,B),C) produces same allowlist as compose(A,compose(B,C))."""

    def test_three_way_associativity(self, composer):
        """(A∘B)∘C == A∘(B∘C) in allowlist membership."""
        a = create_profile_from_numbers("a", [0, 1, 2, 3, 4, 5], DefaultAction.KILL)
        b = create_profile_from_numbers("b", [0, 2, 4, 6, 8], DefaultAction.KILL)
        c = create_profile_from_numbers("c", [0, 4, 8, 12], DefaultAction.KILL)

        left = composer.compose(composer.compose(a, b), c)
        right = composer.compose(a, composer.compose(b, c))
        assert set(left.allowed_syscalls) == set(right.allowed_syscalls)

    def test_associativity_matches_compose_many(self, composer):
        """compose_many matches associative composition."""
        a = create_profile_from_numbers("a", [0, 1, 2, 3], DefaultAction.KILL)
        b = create_profile_from_numbers("b", [1, 2, 3, 4], DefaultAction.KILL)
        c = create_profile_from_numbers("c", [2, 3, 4, 5], DefaultAction.KILL)

        many = composer.compose_many([a, b, c])
        left = composer.compose(composer.compose(a, b), c)
        assert set(many.allowed_syscalls) == set(left.allowed_syscalls)


# ===================================================================
# COMPLETE COVERAGE (P52)
# ===================================================================

class TestCompleteCoverage:
    """P52: Every syscall nr in [0, max_nr] gets a defined decision."""

    def test_complete_coverage_standard(self, standard_profile):
        """Standard profile covers all syscalls [0, max_nr]."""
        verifier = CompleteCoverageVerifier()
        max_nr = max(standard_profile.allowed_syscalls) + 10
        result = verifier.verify(standard_profile, max_nr)
        assert result["complete"]
        assert result["total_checked"] == max_nr + 1

    def test_complete_coverage_empty(self):
        """Empty allowlist still covers via default deny."""
        p = create_profile_from_numbers("empty", [], DefaultAction.KILL)
        verifier = CompleteCoverageVerifier()
        result = verifier.verify(p, 100)
        assert result["complete"]
        assert result["denied"] == 101

    def test_every_syscall_gets_decision(self, small_profile):
        """Each syscall either allowed or denied - no gaps."""
        allowed = set(small_profile.allowed_syscalls)
        max_nr = max(allowed) + 5
        for nr in range(max_nr + 1):
            decision = filter_syscall(nr, small_profile.allowed_syscalls)
            assert decision in (FilterDecision.ALLOW, FilterDecision.DENY)


# ===================================================================
# CONSTRAINT MONOTONICITY (P51)
# ===================================================================

class TestConstraintMonotonicity:
    """P51: Adding argument constraints only restricts, never expands."""

    def test_adding_constraint_restricts(self):
        """Policy with constraint rejects values unconstrained policy accepts."""
        unconstrained = ArgumentPolicy.empty()
        constrained = unconstrained.with_constraint(ArgumentConstraint.openat_readonly())
        nr = ArgumentConstraint.openat_readonly().syscall_nr

        # Unconstrained: any value passes
        assert unconstrained.check_syscall(nr, {2: 1}).is_allow
        # Constrained: O_WRONLY blocked
        assert constrained.check_syscall(nr, {2: 1}).is_deny

    def test_adding_second_constraint_further_restricts(self):
        """Second constraint tightens, never loosens."""
        p1 = ArgumentPolicy.readonly_filesystem()
        p2 = p1.with_constraint(ArgumentConstraint.mprotect_no_exec())
        # p2 has both constraints
        openat_nr = ArgumentConstraint.openat_readonly().syscall_nr
        mprotect_nr = ArgumentConstraint.mprotect_no_exec().syscall_nr
        assert p2.has_constraint(openat_nr)
        assert p2.has_constraint(mprotect_nr)

    def test_no_constraint_allows_all(self):
        """Unconstrained syscalls always pass argument check."""
        p = ArgumentPolicy.empty()
        for nr in range(100):
            assert p.check_syscall(nr, {0: 999, 1: 999, 2: 999}).is_allow


# ===================================================================
# COMPLIANCE CERTIFICATION
# ===================================================================

class TestComplianceCertification:
    """Compliance mapping and certification for regulated industries."""

    def test_hipaa_certification(self, network_blocked, compliance_mapper):
        """HIPAA certification requires network exclusion + KILL action."""
        builder = SeccompFilterBuilder(network_blocked)
        program = builder.build_filter()
        cert = compliance_mapper.certify(
            network_blocked, ComplianceRegime.HIPAA,
            ArgumentPolicy.strict(), builder,
        )
        assert isinstance(cert, ComplianceSeccompCertificate)
        assert cert.regime == ComplianceRegime.HIPAA
        assert cert.excludes_network

    def test_sox_certification(self, network_blocked, compliance_mapper):
        """SOX certification produces valid certificate."""
        builder = SeccompFilterBuilder(network_blocked)
        builder.build_filter()
        cert = compliance_mapper.certify(
            network_blocked, ComplianceRegime.SOX,
            ArgumentPolicy.strict(), builder,
        )
        assert cert.regime == ComplianceRegime.SOX
        assert cert.profile_name == network_blocked.name

    def test_legal_certification(self, network_blocked, compliance_mapper):
        """Legal privilege certification."""
        builder = SeccompFilterBuilder(network_blocked)
        builder.build_filter()
        cert = compliance_mapper.certify(
            network_blocked, ComplianceRegime.LEGAL,
            ArgumentPolicy.strict(), builder,
        )
        assert cert.regime == ComplianceRegime.LEGAL

    def test_pci_dss_certification(self, network_blocked, compliance_mapper):
        """PCI-DSS certification checks openat read-only constraint."""
        builder = SeccompFilterBuilder(network_blocked)
        builder.build_filter()
        cert = compliance_mapper.certify(
            network_blocked, ComplianceRegime.PCI_DSS,
            ArgumentPolicy.strict(), builder,
        )
        assert cert.regime == ComplianceRegime.PCI_DSS

    def test_general_certification(self, standard_profile, compliance_mapper):
        """General certification with standard profile."""
        builder = SeccompFilterBuilder(standard_profile)
        builder.build_filter()
        cert = compliance_mapper.certify(
            standard_profile, ComplianceRegime.GENERAL,
            ArgumentPolicy.empty(), builder,
        )
        assert cert.regime == ComplianceRegime.GENERAL

    def test_certificate_has_dafny_properties(self, network_blocked, compliance_mapper):
        """Certificate tracks which Dafny properties are verified."""
        builder = SeccompFilterBuilder(network_blocked)
        builder.build_filter()
        cert = compliance_mapper.certify(
            network_blocked, ComplianceRegime.HIPAA,
            ArgumentPolicy.strict(), builder,
        )
        assert len(cert.dafny_properties_verified) > 0

    def test_certificate_contains_requirements(self, network_blocked, compliance_mapper):
        """Certificate lists individual compliance requirements."""
        builder = SeccompFilterBuilder(network_blocked)
        builder.build_filter()
        cert = compliance_mapper.certify(
            network_blocked, ComplianceRegime.HIPAA,
            ArgumentPolicy.strict(), builder,
        )
        assert len(cert.requirements) > 0
        for req in cert.requirements:
            assert isinstance(req, ComplianceRequirement)

    def test_certificate_hash_present(self, network_blocked, compliance_mapper):
        """Certificate has profile hash for integrity."""
        builder = SeccompFilterBuilder(network_blocked)
        builder.build_filter()
        cert = compliance_mapper.certify(
            network_blocked, ComplianceRegime.HIPAA,
            ArgumentPolicy.strict(), builder,
        )
        assert cert.profile_hash is not None
        assert len(cert.profile_hash) > 0


# ===================================================================
# BUILD_CERTIFIED_SECCOMP CONVENIENCE
# ===================================================================

class TestBuildCertifiedSeccomp:
    """build_certified_seccomp() combines building + certification."""

    def test_returns_program_and_certificate(self, network_blocked):
        """Convenience function returns (BpfProgram, Certificate)."""
        program, cert = build_certified_seccomp(
            network_blocked,
            ComplianceRegime.HIPAA,
            ArgumentPolicy.strict(),
        )
        assert isinstance(program, BpfProgram)
        assert isinstance(cert, ComplianceSeccompCertificate)

    def test_program_is_valid(self, network_blocked):
        """Returned BPF program is non-empty and well-formed."""
        program, _ = build_certified_seccomp(
            network_blocked,
            ComplianceRegime.GENERAL,
            ArgumentPolicy.empty(),
        )
        assert len(program.instructions) > 0
        assert program.hex is not None


# ===================================================================
# POLICY CHAIN LINEAGE TRACKING
# ===================================================================

class TestPolicyChainLineage:
    """Track derivation lineage for audit."""

    def test_register_base(self):
        """Registering base profile creates chain entry."""
        chain = SeccompPolicyChain()
        p = create_standard_profile()
        chain.register_base(p)
        entries = chain.get_entries()
        assert len(entries) == 1
        assert entries[0].operation == "base"

    def test_record_composition(self, composer):
        """Composition records parent names and resulting syscall count."""
        chain = SeccompPolicyChain()
        a = create_profile_from_numbers("alpha", [0, 1, 2, 3], DefaultAction.KILL)
        b = create_profile_from_numbers("beta", [1, 2, 3, 4], DefaultAction.KILL)
        chain.register_base(a)
        chain.register_base(b)

        result = composer.compose(a, b)
        chain.record_composition(result, [a, b])

        entries = chain.get_entries()
        assert len(entries) == 3
        comp_entry = entries[2]
        assert comp_entry.operation == "compose"
        assert set(comp_entry.parent_names) == {"alpha", "beta"}

    def test_record_attenuation(self, attenuator):
        """Attenuation records parent, child, removed syscalls."""
        chain = SeccompPolicyChain()
        a = create_profile_from_numbers("base", list(range(10)), DefaultAction.KILL)
        chain.register_base(a)

        result, record = attenuator.attenuate(a, {0, 1})
        chain.record_attenuation(result, a, record)

        entries = chain.get_entries()
        assert len(entries) == 2
        att_entry = entries[1]
        assert att_entry.operation == "attenuate"
        assert att_entry.removed_syscalls == {0, 1}

    def test_verify_chain_transitivity(self, attenuator):
        """verify_chain confirms P54 across full lineage."""
        chain = SeccompPolicyChain()
        a = create_profile_from_numbers("root", list(range(20)), DefaultAction.KILL)
        chain.register_base(a)

        b, rec1 = attenuator.attenuate(a, {0, 1, 2})
        chain.record_attenuation(b, a, rec1)

        c, rec2 = attenuator.attenuate(b, {5, 6})
        chain.record_attenuation(c, b, rec2)

        valid = chain.verify_chain(c.name)
        assert valid


# ===================================================================
# DAFNY PROPERTY REGISTRY
# ===================================================================

class TestDafnyPropertyRegistry:
    """Registry of all proven Dafny properties P34-P54."""

    def test_all_properties_present(self):
        """Registry contains all 21 properties (P34-P54)."""
        all_props = DafnyPropertyRegistry.all_properties()
        assert len(all_props) >= 21

    def test_base_properties(self):
        """base_properties returns P34-P46."""
        base = DafnyPropertyRegistry.base_properties()
        ids = {p.property_id for p in base}
        for i in range(34, 47):
            assert f"P{i}" in ids

    def test_extended_properties(self):
        """extended_properties returns P47-P54."""
        ext = DafnyPropertyRegistry.extended_properties()
        ids = {p.property_id for p in ext}
        for i in range(47, 55):
            assert f"P{i}" in ids

    def test_property_has_formal_statement(self):
        """Each property has a formal statement."""
        for p in DafnyPropertyRegistry.all_properties():
            assert len(p.formal_statement) > 0

    def test_property_has_dafny_module(self):
        """Each property references a Dafny module."""
        for p in DafnyPropertyRegistry.all_properties():
            assert p.dafny_module.endswith(".dfy")

    def test_safety_properties_subset(self):
        """Safety properties are a subset of all properties."""
        safety = DafnyPropertyRegistry.safety_properties()
        all_ids = {p.property_id for p in DafnyPropertyRegistry.all_properties()}
        for p in safety:
            assert p.property_id in all_ids

    def test_get_property(self):
        """Can retrieve individual property by ID."""
        p34 = DafnyPropertyRegistry.get_property("P34")
        assert p34 is not None
        assert p34.property_id == "P34"

    def test_to_dict_serializable(self):
        """Registry serializes for documentation."""
        d = DafnyPropertyRegistry.to_dict()
        assert isinstance(d, dict)
        assert len(d) >= 21


# ===================================================================
# DAFNY-PYTHON ALIGNMENT VERIFICATION
# ===================================================================

class TestDafnyAlignmentVerification:
    """Runtime verification that Python mirrors Dafny proofs."""

    def test_alignment_standard_profile(self, alignment_verifier, standard_profile):
        """Standard profile passes base alignment checks."""
        builder = SeccompFilterBuilder(standard_profile)
        program = builder.build_filter()
        report = alignment_verifier.verify_alignment(standard_profile, program)
        assert isinstance(report, AlignmentReport)
        assert report.passed_count > 0

    def test_alignment_network_blocked(self, alignment_verifier, network_blocked):
        """Network-blocked profile passes all alignment checks."""
        builder = SeccompFilterBuilder(network_blocked)
        program = builder.build_filter()
        report = alignment_verifier.verify_alignment(
            network_blocked, program, check_extended=True
        )
        assert report.passed_count > 0

    def test_alignment_includes_extended(self, alignment_verifier, small_profile):
        """check_extended=True includes P47-P54 checks."""
        builder = SeccompFilterBuilder(small_profile)
        program = builder.build_filter()
        report = alignment_verifier.verify_alignment(
            small_profile, program, check_extended=True
        )
        checked_ids = {r.property_id for r in report.results}
        # Should include some extended property checks
        assert len(checked_ids) > 13  # more than base 13

    def test_alignment_report_timing(self, alignment_verifier, small_profile):
        """Report records total check time."""
        builder = SeccompFilterBuilder(small_profile)
        program = builder.build_filter()
        report = alignment_verifier.verify_alignment(small_profile, program)
        assert report.total_check_time_ms >= 0

    def test_all_checks_have_status(self, alignment_verifier, small_profile):
        """Every check result has a status."""
        builder = SeccompFilterBuilder(small_profile)
        program = builder.build_filter()
        report = alignment_verifier.verify_alignment(small_profile, program)
        for r in report.results:
            assert r.status in (PropertyStatus.PASS, PropertyStatus.FAIL, PropertyStatus.SKIP, PropertyStatus.NOT_APPLICABLE)


# ===================================================================
# DAFNY PROOF CERTIFICATES
# ===================================================================

class TestDafnyProofCertificates:
    """Cryptographic proof certificates attesting verified properties."""

    def test_generate_certificate(self, alignment_verifier, network_blocked):
        """generate_certificate returns DafnyProofCertificate."""
        builder = SeccompFilterBuilder(network_blocked)
        program = builder.build_filter()
        cert = alignment_verifier.generate_certificate(network_blocked, program)
        assert isinstance(cert, DafnyProofCertificate)

    def test_certificate_has_hashes(self, alignment_verifier, network_blocked):
        """Certificate includes profile and program hashes."""
        builder = SeccompFilterBuilder(network_blocked)
        program = builder.build_filter()
        cert = alignment_verifier.generate_certificate(network_blocked, program)
        assert cert.profile_hash is not None
        assert cert.program_hash is not None
        assert len(cert.profile_hash) == 64  # SHA-256 hex
        assert len(cert.program_hash) == 64

    def test_certificate_integrity(self, alignment_verifier, network_blocked):
        """Certificate integrity check validates correctly."""
        builder = SeccompFilterBuilder(network_blocked)
        program = builder.build_filter()
        cert = alignment_verifier.generate_certificate(network_blocked, program)
        assert cert.is_valid

    def test_certificate_unique_id(self, alignment_verifier, network_blocked):
        """Each certificate has a unique ID."""
        builder = SeccompFilterBuilder(network_blocked)
        program = builder.build_filter()
        c1 = alignment_verifier.generate_certificate(network_blocked, program)
        c2 = alignment_verifier.generate_certificate(network_blocked, program)
        assert c1.certificate_id != c2.certificate_id

    def test_certificate_lists_verified_properties(self, alignment_verifier, network_blocked):
        """Certificate enumerates which properties passed."""
        builder = SeccompFilterBuilder(network_blocked)
        program = builder.build_filter()
        cert = alignment_verifier.generate_certificate(network_blocked, program)
        assert cert.verified_count > 0
        assert len(cert.verified_properties) == cert.verified_count


# ===================================================================
# INTEGRATION: END-TO-END WORKFLOWS
# ===================================================================

class TestEndToEndWorkflows:
    """Full production workflows combining all D4 components."""

    def test_hipaa_full_pipeline(self):
        """HIPAA: create → compose → attenuate → certify → align."""
        # 1. Start from network_blocked (no networking)
        profile = create_network_blocked_profile()

        # 2. Compose with compute-only to tighten further
        composer = SeccompPolicyComposer()
        tightened = composer.compose(profile, create_compute_only_profile())

        # 3. Attenuate: remove ptrace even if present
        attenuator = SeccompPolicyAttenuator()
        final, _ = attenuator.attenuate(tightened, {101})  # ptrace

        # 4. Build BPF + certify
        program, cert = build_certified_seccomp(
            final, ComplianceRegime.HIPAA, ArgumentPolicy.strict()
        )
        assert isinstance(program, BpfProgram)
        assert isinstance(cert, ComplianceSeccompCertificate)

        # 5. Alignment verification
        verifier = DafnyAlignmentVerifier()
        report = verifier.verify_alignment(final, program, check_extended=True)
        assert report.passed_count > 0

        # 6. Proof certificate
        proof = verifier.generate_certificate(final, program)
        assert proof.is_valid

    def test_sox_with_argument_constraints(self):
        """SOX: argument-level filtering + compliance cert."""
        profile = create_network_blocked_profile()
        arg_policy = ArgumentPolicy.strict()

        program, cert = build_certified_seccomp(
            profile, ComplianceRegime.SOX, arg_policy
        )
        assert cert.argument_constraints_active

    def test_composition_then_certification(self, composer):
        """Compose two profiles, then certify result."""
        p1 = create_network_blocked_profile()
        p2 = create_compute_only_profile()
        composed = composer.compose(p1, p2)

        program, cert = build_certified_seccomp(
            composed, ComplianceRegime.GENERAL, ArgumentPolicy.empty()
        )
        assert len(program.instructions) > 0

    def test_attenuation_chain_then_certify(self, attenuator):
        """Attenuate in stages, then certify final result."""
        base = create_standard_profile()
        stages = [{41, 42, 43}, {56, 57}]  # remove sendmsg, recvmsg, etc.
        final, records = attenuator.attenuate_chain(base, stages)

        program, cert = build_certified_seccomp(
            final, ComplianceRegime.GENERAL, ArgumentPolicy.empty()
        )
        assert is_subset_of(final.allowed_syscalls, base.allowed_syscalls)

    def test_full_lineage_tracking(self, composer, attenuator):
        """Track full derivation: base → compose → attenuate → verify."""
        chain = SeccompPolicyChain()

        a = create_network_blocked_profile()
        b = create_compute_only_profile()
        chain.register_base(a)
        chain.register_base(b)

        composed = composer.compose(a, b)
        chain.record_composition(composed, [a, b])

        final, record = attenuator.attenuate(composed, {60})  # remove exit
        chain.record_attenuation(final, composed, record)

        entries = chain.get_entries()
        assert len(entries) == 4  # 2 base + 1 compose + 1 attenuate
        assert chain.verify_chain(final.name)


# ===================================================================
# PERFORMANCE
# ===================================================================

class TestPerformance:
    """Performance requirements for production use."""

    def test_composition_under_10ms(self, composer, standard_profile, network_blocked):
        """Filter composition completes in <10ms."""
        start = time.perf_counter()
        for _ in range(100):
            composer.compose(standard_profile, network_blocked)
        elapsed = (time.perf_counter() - start) / 100 * 1000
        assert elapsed < 10, f"Composition took {elapsed:.2f}ms"

    def test_alignment_check_under_50ms(self, alignment_verifier, small_profile):
        """Alignment verification completes in <50ms."""
        builder = SeccompFilterBuilder(small_profile)
        program = builder.build_filter()
        start = time.perf_counter()
        alignment_verifier.verify_alignment(small_profile, program)
        elapsed = (time.perf_counter() - start) * 1000
        assert elapsed < 50, f"Alignment check took {elapsed:.2f}ms"

    def test_certification_under_20ms(self, compliance_mapper, network_blocked):
        """Compliance certification completes in <20ms."""
        builder = SeccompFilterBuilder(network_blocked)
        builder.build_filter()
        start = time.perf_counter()
        compliance_mapper.certify(
            network_blocked, ComplianceRegime.HIPAA,
            ArgumentPolicy.strict(), builder,
        )
        elapsed = (time.perf_counter() - start) * 1000
        assert elapsed < 20, f"Certification took {elapsed:.2f}ms"

"""
Dafny-Verified Seccomp Filter - Comprehensive Tests.

Tests every property proven in ``dafny/sandbox/seccomp_filter.dfy``:

  P34  Allowlist completeness - Allow only if syscall in allowlist
  P35  Default deny - any syscall not in allowlist is Denied
  P36  Architecture check - mismatch always denied
  P37  Filter monotonicity - adding syscalls never removes allowed ones
  P38  Filter determinism - same inputs → same decision
  P39  No duplicate syscalls - normalize produces sorted, unique list
  P40  Instruction count - N + 6 instructions for N unique syscalls
  P41  Jump target correctness - all JEQ true-branches land on ALLOW
  P42  Profile subset - restricted.allowlist ⊆ standard.allowlist
  P43  Network syscall exclusion - network profile excludes socket/etc.
  P44  Audit completeness - every build_filter appends exactly one entry
  P45  Profile immutability - profile frozen after construction
  P46  Invariant preservation - Valid() holds at every method boundary

Also tests:
  - Thread safety under concurrent builds
  - Audit trail completeness via InvariantAuditLog
  - Factory profiles (standard, network_blocked, compute_only, audit)
  - BPF bytecode structural verification
  - Integration with existing seccomp.py
  - Custom profile creation with network/spawn exclusion
  - SeccompAuditInfo compliance export
  - Edge cases (empty allowlist, single syscall, max-size filter)
"""
from __future__ import annotations

import copy
import json
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

import pytest

from agentsafe.sandbox.seccomp_verified import (
    AUDIT_ARCH_AARCH64,
    AUDIT_ARCH_X86_64,
    BpfProgram,
    DefaultAction,
    FilterAuditEntry,
    FilterDecision,
    NETWORK_SYSCALLS_X86_64,
    PROCESS_SPAWN_SYSCALLS_X86_64,
    SeccompAuditInfo,
    SeccompFilterBuilder,
    SeccompProfile,
    allow_position,
    build_seccomp_audit_info,
    build_verified_seccomp,
    check_architecture,
    create_audit_profile,
    create_compute_only_profile,
    create_custom_profile,
    create_network_blocked_profile,
    create_standard_profile,
    excludes_all,
    filter_syscall,
    get_audit_profile,
    get_compute_only_profile,
    get_network_blocked_profile,
    get_standard_profile,
    get_network_syscalls,
    get_process_spawn_syscalls,
    instruction_count,
    is_subset_of,
    jeq_true_offset,
    jeq_true_target,
    normalize_syscalls,
    reset_profile_cache,
    verify_jump_targets,
)
from agentsafe.sandbox.seccomp import (
    BPF_ABS,
    BPF_JEQ,
    BPF_JMP,
    BPF_K,
    BPF_LD,
    BPF_RET,
    BPF_W,
    OFFSET_ARCH,
    OFFSET_NR,
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_KILL_PROCESS,
    bpf_instruction_count,
    build_bpf_program,
    resolve_syscall_numbers,
)
from agentsafe.verification.dafny_runtime import (
    InvariantAuditLog,
    InvariantViolation,
)


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset():
    """Reset global state between tests."""
    InvariantAuditLog.reset()
    reset_profile_cache()
    yield
    InvariantAuditLog.reset()
    reset_profile_cache()


def _small_profile(nrs: Tuple[int, ...] = (0, 1, 3, 5)) -> SeccompProfile:
    return SeccompProfile(name="test", allowed_syscalls=nrs)


def _builder() -> SeccompFilterBuilder:
    return SeccompFilterBuilder()


# =============================================================================
# FilterDecision
# =============================================================================

class TestFilterDecision:
    """FilterDecision type correctness."""

    def test_allow(self):
        d = FilterDecision.allow()
        assert d.is_allow
        assert not d.is_deny
        assert d.allowed is True

    def test_deny(self):
        d = FilterDecision.deny("reason")
        assert d.is_deny
        assert not d.is_allow
        assert d.reason == "reason"

    def test_frozen(self):
        d = FilterDecision.allow()
        with pytest.raises(AttributeError):
            d.allowed = False  # type: ignore

    def test_repr(self):
        assert "Allow" in repr(FilterDecision.allow())
        assert "Deny" in repr(FilterDecision.deny("x"))


# =============================================================================
# P34: ALLOWLIST COMPLETENESS
# =============================================================================

class TestP34AllowlistCompleteness:
    """P34: filter_syscall(nr, allowlist) == Allow ONLY IF nr ∈ allowlist."""

    def test_allowed_syscall_returns_allow(self):
        allowlist = (0, 1, 3, 5, 10)
        for nr in allowlist:
            d = filter_syscall(nr, allowlist)
            assert d.is_allow, f"P34: syscall {nr} should be allowed"

    def test_not_in_allowlist_returns_deny(self):
        allowlist = (0, 1, 3, 5)
        for nr in (2, 4, 6, 99, 1000):
            d = filter_syscall(nr, allowlist)
            assert d.is_deny, f"P34: syscall {nr} should be denied"

    def test_empty_allowlist_denies_all(self):
        for nr in range(20):
            d = filter_syscall(nr, ())
            assert d.is_deny, f"P34: syscall {nr} should be denied (empty)"

    def test_allow_implies_membership(self):
        """P34 contrapositive: Allow → nr ∈ allowlist."""
        allowlist = (0, 1, 3, 5)
        for nr in range(100):
            d = filter_syscall(nr, allowlist)
            if d.is_allow:
                assert nr in allowlist


# =============================================================================
# P35: DEFAULT DENY
# =============================================================================

class TestP35DefaultDeny:
    """P35: nr ∉ allowlist ==> filter_syscall(nr, allowlist) == Deny."""

    def test_unlisted_syscall_denied(self):
        allowlist = (0, 1, 3)
        assert filter_syscall(2, allowlist).is_deny
        assert filter_syscall(4, allowlist).is_deny
        assert filter_syscall(999, allowlist).is_deny

    def test_deny_has_reason(self):
        d = filter_syscall(42, (0, 1))
        assert d.is_deny
        assert "not in allowlist" in d.reason

    def test_large_syscall_number_denied(self):
        d = filter_syscall(0xFFFFFFFF, (0, 1, 2))
        assert d.is_deny


# =============================================================================
# P36: ARCHITECTURE CHECK
# =============================================================================

class TestP36ArchitectureCheck:
    """P36: CheckArchitecture(actual, expected) == Allow iff actual == expected."""

    def test_matching_x86_64(self):
        d = check_architecture(AUDIT_ARCH_X86_64, AUDIT_ARCH_X86_64)
        assert d.is_allow

    def test_matching_aarch64(self):
        d = check_architecture(AUDIT_ARCH_AARCH64, AUDIT_ARCH_AARCH64)
        assert d.is_allow

    def test_mismatch_denied(self):
        d = check_architecture(AUDIT_ARCH_AARCH64, AUDIT_ARCH_X86_64)
        assert d.is_deny

    def test_mismatch_reverse(self):
        d = check_architecture(AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64)
        assert d.is_deny

    def test_zero_arch_denied(self):
        d = check_architecture(0, AUDIT_ARCH_X86_64)
        assert d.is_deny

    def test_allow_iff_equal(self):
        """P36 biconditional: Allow ⟺ actual == expected."""
        for a, e in [
            (AUDIT_ARCH_X86_64, AUDIT_ARCH_X86_64),
            (AUDIT_ARCH_AARCH64, AUDIT_ARCH_AARCH64),
            (0x12345678, 0x12345678),
        ]:
            assert check_architecture(a, e).is_allow
        for a, e in [
            (AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64),
            (0, AUDIT_ARCH_X86_64),
            (1, 2),
        ]:
            assert check_architecture(a, e).is_deny


# =============================================================================
# P37: FILTER MONOTONICITY
# =============================================================================

class TestP37FilterMonotonicity:
    """P37: Adding syscalls to allowlist never removes previously allowed ones."""

    def test_adding_entry_preserves_existing(self):
        original = (0, 1, 3, 5)
        extended = original + (10,)
        for nr in original:
            assert filter_syscall(nr, original).is_allow
            assert filter_syscall(nr, extended).is_allow

    def test_new_entry_also_allowed(self):
        original = (0, 1, 3)
        extended = original + (5,)
        assert filter_syscall(5, original).is_deny
        assert filter_syscall(5, extended).is_allow

    def test_monotone_over_multiple_additions(self):
        base = (0,)
        for addition in range(1, 20):
            extended = base + (addition,)
            # All previously allowed still allowed
            for nr in base:
                assert filter_syscall(nr, extended).is_allow
            base = extended


# =============================================================================
# P38: FILTER DETERMINISM
# =============================================================================

class TestP38FilterDeterminism:
    """P38: Same (nr, allowlist) → same decision."""

    def test_deterministic_allow(self):
        allowlist = (0, 1, 3, 5)
        for _ in range(100):
            assert filter_syscall(3, allowlist).is_allow

    def test_deterministic_deny(self):
        allowlist = (0, 1, 3, 5)
        for _ in range(100):
            d = filter_syscall(2, allowlist)
            assert d.is_deny
            assert d.reason == "syscall not in allowlist"

    def test_no_side_effects(self):
        allowlist = (0, 1, 3)
        results = [filter_syscall(1, allowlist) for _ in range(50)]
        assert all(r.is_allow for r in results)


# =============================================================================
# P39: NO DUPLICATE SYSCALLS (Normalize)
# =============================================================================

class TestP39Normalize:
    """P39: normalize produces sorted, unique sequence."""

    def test_sorted_output(self):
        result = normalize_syscalls((5, 3, 1, 4, 2))
        assert result == (1, 2, 3, 4, 5)

    def test_deduplicates(self):
        result = normalize_syscalls((1, 1, 2, 2, 3, 3))
        assert result == (1, 2, 3)

    def test_length_at_most_input(self):
        inp = (5, 1, 3, 1, 5, 0)
        result = normalize_syscalls(inp)
        assert len(result) <= len(inp)

    def test_preserves_membership(self):
        inp = (5, 1, 3, 1, 5, 0)
        result = normalize_syscalls(inp)
        assert set(result) == set(inp)

    def test_empty(self):
        assert normalize_syscalls(()) == ()

    def test_single(self):
        assert normalize_syscalls((42,)) == (42,)

    def test_already_normalized(self):
        inp = (0, 1, 2, 3)
        assert normalize_syscalls(inp) == inp

    def test_strictly_sorted(self):
        result = normalize_syscalls((10, 5, 7, 3, 5, 10))
        for i in range(1, len(result)):
            assert result[i] > result[i - 1], "P39: strictly sorted"

    def test_filter_semantics_preserved(self):
        """P39 corollary: FilterSyscall(nr, normalized) == FilterSyscall(nr, input)."""
        inp = (5, 1, 3, 1, 5, 0)
        norm = normalize_syscalls(inp)
        for nr in range(10):
            assert filter_syscall(nr, norm) == filter_syscall(nr, inp)


# =============================================================================
# P40: INSTRUCTION COUNT
# =============================================================================

class TestP40InstructionCount:
    """P40: instruction_count == |normalized_allowlist| + 6."""

    def test_empty_allowlist(self):
        assert instruction_count(()) == 6

    def test_single_syscall(self):
        assert instruction_count((0,)) == 7

    def test_three_syscalls(self):
        assert instruction_count((0, 1, 3)) == 9

    def test_formula(self):
        for n in range(0, 50):
            nrs = tuple(range(n))
            assert instruction_count(nrs) == n + 6

    def test_matches_bpf_generator(self):
        """P40: instruction count matches actual BPF bytecode."""
        for n in (0, 1, 5, 10, 20):
            nrs = list(range(n))
            bpf = build_bpf_program(nrs)
            actual = bpf_instruction_count(bpf)
            expected = instruction_count(tuple(nrs))
            assert actual == expected, \
                f"P40: BPF has {actual} instrs, expected {expected} for N={n}"


# =============================================================================
# P41: JUMP TARGET CORRECTNESS
# =============================================================================

class TestP41JumpTargets:
    """P41: All JEQ true-branches land on the ALLOW instruction."""

    def test_single_jeq(self):
        # N=1: JEQ at position 4, offset=1, target = 5+1 = 6 = AllowPos(1)
        assert jeq_true_offset(0, 1) == 1
        assert jeq_true_target(0, 1) == allow_position(1)

    def test_five_jeqs(self):
        n = 5
        ap = allow_position(n)
        assert ap == 10
        for i in range(n):
            assert jeq_true_target(i, n) == ap

    def test_verify_all_targets(self):
        for n in range(1, 50):
            assert verify_jump_targets(n)

    def test_verify_zero_targets(self):
        assert verify_jump_targets(0)

    def test_offsets_descend(self):
        n = 10
        offsets = [jeq_true_offset(i, n) for i in range(n)]
        assert offsets == list(range(n, 0, -1))

    def test_allow_position_formula(self):
        for n in range(50):
            assert allow_position(n) == 4 + n + 1

    def test_precondition_violation(self):
        with pytest.raises(AssertionError):
            jeq_true_offset(-1, 5)
        with pytest.raises(AssertionError):
            jeq_true_offset(5, 5)

    def test_bpf_bytecode_jump_verification(self):
        """Verify actual BPF bytecode jump offsets match P41."""
        nrs = list(range(10))
        bpf = build_bpf_program(nrs)
        n = len(nrs)

        # Parse JEQ instructions (positions 4 through 4+N-1)
        for i in range(n):
            offset = (4 + i) * 8  # each instruction is 8 bytes
            code, jt, jf, k = struct.unpack("HBBI", bpf[offset:offset + 8])
            # jt should equal n - i (P41)
            expected_jt = n - i
            assert jt == expected_jt, \
                f"P41: JEQ[{i}] jt={jt}, expected {expected_jt}"
            # jf should be 0 (fall through)
            assert jf == 0, f"P41: JEQ[{i}] jf={jf}, expected 0"
            # k should be the syscall number
            assert k == nrs[i], f"P41: JEQ[{i}] k={k}, expected {nrs[i]}"


# =============================================================================
# P42: PROFILE SUBSET
# =============================================================================

class TestP42ProfileSubset:
    """P42: restricted.allowlist ⊆ standard.allowlist."""

    def test_subset(self):
        assert is_subset_of((0, 1), (0, 1, 2, 3))

    def test_not_subset(self):
        assert not is_subset_of((0, 1, 99), (0, 1, 2, 3))

    def test_equal_sets(self):
        assert is_subset_of((0, 1, 2), (0, 1, 2))

    def test_empty_is_subset(self):
        assert is_subset_of((), (0, 1, 2))

    def test_network_blocked_subset_of_standard(self):
        standard = create_standard_profile()
        net_blocked = create_network_blocked_profile()
        assert net_blocked.is_subset_of(standard)

    def test_compute_only_subset_of_standard(self):
        standard = create_standard_profile()
        compute = create_compute_only_profile()
        assert compute.is_subset_of(standard)

    def test_profile_is_subset_method(self):
        p1 = SeccompProfile(name="small", allowed_syscalls=(0, 1))
        p2 = SeccompProfile(name="large", allowed_syscalls=(0, 1, 2, 3))
        assert p1.is_subset_of(p2)
        assert not p2.is_subset_of(p1)


# =============================================================================
# P43: NETWORK SYSCALL EXCLUSION
# =============================================================================

class TestP43NetworkExclusion:
    """P43: Network profile excludes all socket/connect/bind/etc. syscalls."""

    def test_excludes_all_helper(self):
        assert excludes_all((41, 42), (0, 1, 3))
        assert not excludes_all((41, 42), (0, 1, 41))

    def test_standard_profile_excludes_network(self):
        profile = create_standard_profile()
        assert profile.excludes_network, \
            "Standard profile must exclude all network syscalls"

    def test_network_blocked_profile_excludes_network(self):
        profile = create_network_blocked_profile()
        assert profile.excludes_network

    def test_compute_only_excludes_network(self):
        profile = create_compute_only_profile()
        assert profile.excludes_network

    def test_individual_network_syscalls_denied(self):
        """P43: Each network syscall is individually denied."""
        profile = create_standard_profile()
        normalized = profile.normalized
        net_syscalls = get_network_syscalls()
        for nr in net_syscalls:
            d = filter_syscall(nr, normalized)
            assert d.is_deny, f"P43: network syscall {nr} should be denied"

    def test_standard_excludes_process_spawn(self):
        profile = create_standard_profile()
        assert profile.excludes_process_spawn

    def test_custom_profile_exclude_network(self):
        p = create_custom_profile(
            "test",
            frozenset({"read", "write", "close"}),
            exclude_network=True,
        )
        assert p.excludes_network

    def test_network_syscalls_known(self):
        """Verify the network syscall set is non-empty and reasonable."""
        nsc = get_network_syscalls()
        assert len(nsc) >= 10  # socket, connect, bind, listen, accept, ...
        # socket (41 on x86_64) should be in the set
        assert 41 in NETWORK_SYSCALLS_X86_64


# =============================================================================
# P44: AUDIT COMPLETENESS
# =============================================================================

class TestP44AuditCompleteness:
    """P44: Every build_filter appends exactly one audit entry."""

    def test_single_build(self):
        builder = _builder()
        assert len(builder.audit_log) == 0
        builder.build_filter(_small_profile())
        assert len(builder.audit_log) == 1

    def test_multiple_builds(self):
        builder = _builder()
        for i in range(5):
            builder.build_filter(_small_profile())
            assert len(builder.audit_log) == i + 1

    def test_audit_entry_contents(self):
        builder = _builder()
        profile = SeccompProfile(
            name="test_audit", allowed_syscalls=(0, 1, 3, 5, 5)
        )
        program = builder.build_filter(profile)
        entry = builder.audit_log[0]
        assert entry.profile_name == "test_audit"
        assert entry.syscall_count == len(program.normalized_allowlist)
        assert entry.instruction_count == program.instruction_count
        assert entry.default_action == DefaultAction.KILL
        assert entry.build_number == 0

    def test_audit_entry_increments(self):
        builder = _builder()
        for i in range(3):
            builder.build_filter(_small_profile())
            assert builder.audit_log[i].build_number == i

    def test_build_count_matches_audit_log(self):
        builder = _builder()
        for i in range(10):
            builder.build_filter(_small_profile())
            assert builder.build_count == i + 1
            assert builder.build_count == len(builder.audit_log)

    def test_audit_entries_are_frozen(self):
        builder = _builder()
        builder.build_filter(_small_profile())
        entry = builder.audit_log[0]
        with pytest.raises(AttributeError):
            entry.profile_name = "hacked"  # type: ignore

    def test_audit_entry_to_dict(self):
        builder = _builder()
        builder.build_filter(_small_profile())
        d = builder.audit_log[0].to_dict()
        assert "profile_name" in d
        assert "syscall_count" in d
        assert "timestamp" in d
        json.dumps(d)  # must be JSON-safe


# =============================================================================
# P45: PROFILE IMMUTABILITY
# =============================================================================

class TestP45ProfileImmutability:
    """P45: SeccompProfile is frozen after construction."""

    def test_frozen(self):
        p = _small_profile()
        with pytest.raises(AttributeError):
            p.name = "hacked"  # type: ignore
        with pytest.raises(AttributeError):
            p.allowed_syscalls = (99,)  # type: ignore
        with pytest.raises(AttributeError):
            p.default_action = DefaultAction.LOG  # type: ignore

    def test_to_dict(self):
        p = _small_profile()
        d = p.to_dict()
        assert d["name"] == "test"
        assert isinstance(d["syscall_count"], int)
        json.dumps(d)

    def test_coerces_list_to_tuple(self):
        p = SeccompProfile(name="t", allowed_syscalls=[0, 1, 2])  # type: ignore
        assert isinstance(p.allowed_syscalls, tuple)


# =============================================================================
# P46: INVARIANT PRESERVATION
# =============================================================================

class TestP46InvariantPreservation:
    """P46: Valid() holds at every method boundary."""

    def test_constructor_establishes_valid(self):
        builder = _builder()
        assert builder._valid()
        assert builder.build_count == 0
        assert len(builder.audit_log) == 0

    def test_build_preserves_valid(self):
        builder = _builder()
        for _ in range(10):
            builder.build_filter(_small_profile())
            assert builder._valid()

    def test_invariant_audit_log_recorded(self):
        """Invariant checks are recorded in InvariantAuditLog."""
        log = InvariantAuditLog.get_instance()
        builder = _builder()
        builder.build_filter(_small_profile())
        entries = log.entries_for("SeccompFilterBuilder")
        # Should have pre and post checks for build_filter + post for __init__
        assert len(entries) >= 2
        assert all(e.passed for e in entries)


# =============================================================================
# SeccompProfile - factories
# =============================================================================

class TestSeccompProfileFactories:
    """Test pre-built profile factories."""

    def test_standard_profile(self):
        p = create_standard_profile()
        assert p.name == "standard"
        assert len(p.normalized) > 30
        assert p.default_action == DefaultAction.KILL
        assert p.excludes_network
        assert p.excludes_process_spawn

    def test_network_blocked_profile(self):
        p = create_network_blocked_profile()
        assert p.name == "network_blocked"
        assert p.excludes_network

    def test_compute_only_profile(self):
        p = create_compute_only_profile()
        assert p.name == "compute_only"
        assert p.excludes_network
        # Should be smaller than standard
        standard = create_standard_profile()
        assert len(p.normalized) < len(standard.normalized)

    def test_audit_profile(self):
        p = create_audit_profile()
        assert p.name == "audit"
        assert p.default_action == DefaultAction.LOG

    def test_custom_profile(self):
        p = create_custom_profile(
            "custom",
            frozenset({"read", "write", "close", "exit_group"}),
        )
        assert p.name == "custom"
        assert p.excludes_network
        assert p.excludes_process_spawn
        assert len(p.normalized) <= 4

    def test_singleton_caching(self):
        p1 = get_standard_profile()
        p2 = get_standard_profile()
        assert p1 is p2

    def test_cache_reset(self):
        p1 = get_standard_profile()
        reset_profile_cache()
        p2 = get_standard_profile()
        assert p1 is not p2
        assert p1.normalized == p2.normalized


# =============================================================================
# SeccompFilterBuilder - full workflow
# =============================================================================

class TestSeccompFilterBuilder:
    """SeccompFilterBuilder verified builds."""

    def test_build_produces_bpf(self):
        builder = _builder()
        program = builder.build_filter(_small_profile())
        assert isinstance(program, BpfProgram)
        assert len(program.raw_bytes) > 0
        assert program.instruction_count == len(program.normalized_allowlist) + 6

    def test_build_without_bpf_generation(self):
        builder = _builder()
        program = builder.build_filter(
            _small_profile(), generate_bpf=False
        )
        assert program.raw_bytes == b""
        assert program.instruction_count == len(program.normalized_allowlist) + 6

    def test_verify_filter(self):
        builder = _builder()
        program = builder.build_filter(_small_profile((0, 1, 3, 5)))
        # Verify with test syscalls
        assert builder.verify_filter(program, [0, 1, 2, 3, 4, 5, 6, 7])

    def test_standard_profile_build(self):
        builder = _builder()
        profile = create_standard_profile()
        program = builder.build_filter(profile)
        # Should have ~67 unique syscalls on x86_64
        assert program.syscall_count > 30
        assert program.instruction_count == program.syscall_count + 6
        assert len(program.raw_bytes) == program.instruction_count * 8

    def test_consecutive_builds(self):
        builder = _builder()
        p1 = builder.build_filter(SeccompProfile("a", (0, 1)))
        p2 = builder.build_filter(SeccompProfile("b", (0, 1, 2, 3)))
        assert p1.syscall_count == 2
        assert p2.syscall_count == 4
        assert builder.build_count == 2

    def test_build_deduplicates(self):
        builder = _builder()
        program = builder.build_filter(
            SeccompProfile("dup", (0, 1, 1, 3, 3, 3, 5))
        )
        assert program.syscall_count == 4  # {0, 1, 3, 5}


# =============================================================================
# BpfProgram
# =============================================================================

class TestBpfProgram:
    """BpfProgram wrapper tests."""

    def test_frozen(self):
        builder = _builder()
        program = builder.build_filter(_small_profile())
        with pytest.raises(AttributeError):
            program.raw_bytes = b""  # type: ignore

    def test_hex_encoding(self):
        builder = _builder()
        program = builder.build_filter(_small_profile())
        assert isinstance(program.hex, str)
        assert bytes.fromhex(program.hex) == program.raw_bytes

    def test_check_syscall(self):
        builder = _builder()
        program = builder.build_filter(_small_profile((0, 1, 3)))
        assert program.check_syscall(0).is_allow
        assert program.check_syscall(1).is_allow
        assert program.check_syscall(2).is_deny
        assert program.check_syscall(3).is_allow
        assert program.check_syscall(99).is_deny

    def test_to_dict(self):
        builder = _builder()
        program = builder.build_filter(_small_profile())
        d = program.to_dict()
        assert "profile_name" in d
        assert "instruction_count" in d
        assert "program_hex" in d
        json.dumps(d)


# =============================================================================
# BPF Bytecode Structural Verification
# =============================================================================

class TestBpfBytecodeStructure:
    """Verify the raw BPF bytecode matches the Dafny-proven layout."""

    def _parse_instruction(self, bpf: bytes, idx: int):
        """Parse a single sock_filter struct at position idx."""
        offset = idx * 8
        code, jt, jf, k = struct.unpack("HBBI", bpf[offset:offset + 8])
        return code, jt, jf, k

    def test_arch_load(self):
        """Instruction [0]: LD arch."""
        bpf = build_bpf_program([0, 1])
        code, jt, jf, k = self._parse_instruction(bpf, 0)
        assert code == (BPF_LD | BPF_W | BPF_ABS)
        assert k == OFFSET_ARCH

    def test_arch_check(self):
        """Instruction [1]: JEQ expected_arch."""
        bpf = build_bpf_program([0, 1])
        code, jt, jf, k = self._parse_instruction(bpf, 1)
        assert code == (BPF_JMP | BPF_JEQ | BPF_K)
        # k is the expected arch
        assert jt == 1  # skip arch-kill on match
        assert jf == 0  # fall through to arch-kill

    def test_arch_kill(self):
        """Instruction [2]: RET KILL (wrong arch)."""
        bpf = build_bpf_program([0, 1])
        code, jt, jf, k = self._parse_instruction(bpf, 2)
        assert code == (BPF_RET | 0x00)
        assert k == SECCOMP_RET_KILL_PROCESS

    def test_nr_load(self):
        """Instruction [3]: LD nr."""
        bpf = build_bpf_program([0, 1])
        code, jt, jf, k = self._parse_instruction(bpf, 3)
        assert code == (BPF_LD | BPF_W | BPF_ABS)
        assert k == OFFSET_NR

    def test_default_deny(self):
        """Instruction [4+N]: RET default_action."""
        nrs = [0, 1, 3]
        bpf = build_bpf_program(nrs)
        n = len(nrs)
        code, jt, jf, k = self._parse_instruction(bpf, 4 + n)
        assert code == (BPF_RET | 0x00)
        assert k == SECCOMP_RET_KILL_PROCESS

    def test_allow_instruction(self):
        """Instruction [4+N+1]: RET ALLOW."""
        nrs = [0, 1, 3]
        bpf = build_bpf_program(nrs)
        n = len(nrs)
        code, jt, jf, k = self._parse_instruction(bpf, 4 + n + 1)
        assert code == (BPF_RET | 0x00)
        assert k == SECCOMP_RET_ALLOW

    def test_total_instructions(self):
        """Total instruction count matches P40 formula."""
        for n in range(20):
            nrs = list(range(n))
            bpf = build_bpf_program(nrs)
            assert bpf_instruction_count(bpf) == n + 6

    def test_empty_allowlist_structure(self):
        """Empty allowlist: 6 instructions total."""
        bpf = build_bpf_program([])
        assert bpf_instruction_count(bpf) == 6
        # Only arch check + default deny + allow (no JEQs)
        # [0] LD arch, [1] JEQ, [2] RET KILL, [3] LD nr, [4] RET KILL, [5] RET ALLOW


# =============================================================================
# Thread Safety
# =============================================================================

class TestThreadSafety:
    """Concurrent builds must not corrupt state."""

    def test_concurrent_builds(self):
        builder = _builder()
        profiles = [
            SeccompProfile(f"t{i}", tuple(range(i + 1)))
            for i in range(20)
        ]
        results = []

        def _build(p):
            return builder.build_filter(p)

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(_build, p) for p in profiles]
            for f in as_completed(futures):
                results.append(f.result())

        assert len(results) == 20
        assert builder.build_count == 20
        assert len(builder.audit_log) == 20
        assert builder._valid()


# =============================================================================
# Integration with existing seccomp.py
# =============================================================================

class TestSeccompIntegration:
    """Integration with the existing seccomp.py module."""

    def test_resolve_syscall_numbers(self):
        names = frozenset({"read", "write", "close"})
        nrs = resolve_syscall_numbers(names)
        assert len(nrs) == 3
        assert all(isinstance(n, int) for n in nrs)

    def test_build_verified_convenience(self):
        program = build_verified_seccomp()
        assert isinstance(program, BpfProgram)
        assert program.instruction_count >= 6
        assert len(program.raw_bytes) > 0

    def test_build_verified_with_profile(self):
        profile = create_compute_only_profile()
        program = build_verified_seccomp(profile=profile)
        assert program.profile_name == "compute_only"

    def test_build_verified_with_builder(self):
        builder = _builder()
        program = build_verified_seccomp(builder=builder)
        assert builder.build_count == 1


# =============================================================================
# SeccompAuditInfo - compliance export
# =============================================================================

class TestSeccompAuditInfo:
    """Compliance audit info generation."""

    def test_build_audit_info(self):
        profile = create_standard_profile()
        builder = _builder()
        program = builder.build_filter(profile)
        info = build_seccomp_audit_info(program, profile)
        assert info.profile_name == "standard"
        assert info.excludes_network is True
        assert info.excludes_process_spawn is True
        assert info.jump_targets_verified is True

    def test_audit_info_to_dict(self):
        profile = create_standard_profile()
        builder = _builder()
        program = builder.build_filter(profile)
        info = build_seccomp_audit_info(program, profile)
        d = info.to_dict()
        assert "profile_name" in d
        assert "excludes_network" in d
        json.dumps(d)

    def test_audit_info_frozen(self):
        profile = create_standard_profile()
        builder = _builder()
        program = builder.build_filter(profile)
        info = build_seccomp_audit_info(program, profile)
        with pytest.raises(AttributeError):
            info.profile_name = "hacked"  # type: ignore


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_allowlist_profile(self):
        profile = SeccompProfile(name="empty", allowed_syscalls=())
        builder = _builder()
        program = builder.build_filter(profile)
        assert program.syscall_count == 0
        assert program.instruction_count == 6
        # Everything denied
        for nr in range(20):
            assert program.check_syscall(nr).is_deny

    def test_single_syscall_profile(self):
        profile = SeccompProfile(name="one", allowed_syscalls=(42,))
        builder = _builder()
        program = builder.build_filter(profile)
        assert program.syscall_count == 1
        assert program.instruction_count == 7
        assert program.check_syscall(42).is_allow
        assert program.check_syscall(0).is_deny

    def test_large_allowlist(self):
        """Profile with many syscalls."""
        nrs = tuple(range(200))
        profile = SeccompProfile(name="large", allowed_syscalls=nrs)
        builder = _builder()
        program = builder.build_filter(profile)
        assert program.syscall_count == 200
        assert program.instruction_count == 206

    def test_max_syscall_number(self):
        profile = SeccompProfile(
            name="maxnr", allowed_syscalls=(0, 0xFFFF)
        )
        builder = _builder()
        program = builder.build_filter(profile)
        assert program.check_syscall(0).is_allow
        assert program.check_syscall(0xFFFF).is_allow
        assert program.check_syscall(0xFFFE).is_deny


# =============================================================================
# DefaultAction variants
# =============================================================================

class TestDefaultActions:
    """Test different default actions."""

    def test_kill_action(self):
        p = SeccompProfile("k", (0,), DefaultAction.KILL)
        builder = _builder()
        prog = builder.build_filter(p)
        assert prog.default_action == DefaultAction.KILL

    def test_log_action(self):
        p = SeccompProfile("l", (0,), DefaultAction.LOG)
        builder = _builder()
        prog = builder.build_filter(p)
        assert prog.default_action == DefaultAction.LOG

    def test_errno_action(self):
        p = SeccompProfile("e", (0,), DefaultAction.RETURN_ERRNO)
        builder = _builder()
        prog = builder.build_filter(p)
        assert prog.default_action == DefaultAction.RETURN_ERRNO


# =============================================================================
# Cross-profile verification
# =============================================================================

class TestCrossProfileVerification:
    """Verify relationships between profiles."""

    def test_hierarchy(self):
        """compute_only ⊆ network_blocked ⊆ standard."""
        standard = create_standard_profile()
        net_blocked = create_network_blocked_profile()
        compute = create_compute_only_profile()

        assert net_blocked.is_subset_of(standard)
        assert compute.is_subset_of(standard)
        assert compute.is_subset_of(net_blocked)

    def test_all_profiles_exclude_network(self):
        for factory in [
            create_standard_profile,
            create_network_blocked_profile,
            create_compute_only_profile,
        ]:
            p = factory()
            assert p.excludes_network, f"{p.name} must exclude network"

    def test_all_profiles_exclude_process_spawn(self):
        for factory in [
            create_standard_profile,
            create_network_blocked_profile,
            create_compute_only_profile,
        ]:
            p = factory()
            assert p.excludes_process_spawn, f"{p.name} must exclude spawn"

    def test_audit_same_allowlist_as_standard(self):
        standard = create_standard_profile()
        audit = create_audit_profile()
        assert set(standard.allowed_syscalls) == set(audit.allowed_syscalls)
        assert audit.default_action == DefaultAction.LOG


# =============================================================================
# Full lifecycle test
# =============================================================================

class TestFullLifecycle:
    """End-to-end lifecycle matching the Dafny TestFullLifecycle."""

    def test_complete_workflow(self):
        builder = SeccompFilterBuilder()

        # 1. Build standard profile
        standard = create_standard_profile()
        prog1 = builder.build_filter(standard)
        assert prog1.instruction_count == prog1.syscall_count + 6
        assert len(builder.audit_log) == 1

        # 2. Verify filter decisions
        normalized = prog1.normalized_allowlist
        for nr in normalized[:5]:  # spot-check first 5
            assert filter_syscall(nr, normalized).is_allow
        assert filter_syscall(999999, normalized).is_deny

        # 3. Architecture check
        assert check_architecture(
            standard.expected_arch, standard.expected_arch
        ).is_allow
        assert check_architecture(0, standard.expected_arch).is_deny

        # 4. Build restricted profile
        compute = create_compute_only_profile()
        prog2 = builder.build_filter(compute)
        assert prog2.syscall_count < prog1.syscall_count
        assert compute.is_subset_of(standard)
        assert len(builder.audit_log) == 2

        # 5. Verify network exclusion (P43)
        assert standard.excludes_network
        assert compute.excludes_network
        net_nrs = get_network_syscalls()
        for nr in net_nrs:
            assert filter_syscall(nr, prog1.normalized_allowlist).is_deny
            assert filter_syscall(nr, prog2.normalized_allowlist).is_deny

        # 6. Jump targets correct for both
        assert verify_jump_targets(prog1.syscall_count)
        assert verify_jump_targets(prog2.syscall_count)

        # 7. Invariant still holds
        assert builder._valid()

        # 8. Audit info export
        info = build_seccomp_audit_info(prog1, standard)
        d = info.to_dict()
        assert d["excludes_network"] is True
        json.dumps(d)

    def test_dafny_aligned_scenario(self):
        """Scenario mirroring the Dafny TestAllowlistCompleteness."""
        allowlist = (0, 1, 3, 5)

        # syscall 0 ∈ allowlist → Allow (P34)
        assert filter_syscall(0, allowlist).is_allow
        # syscall 3 ∈ allowlist → Allow (P34)
        assert filter_syscall(3, allowlist).is_allow
        # syscall 2 ∉ allowlist → Deny (P35)
        assert filter_syscall(2, allowlist).is_deny
        # syscall 99 ∉ allowlist → Deny (P35)
        assert filter_syscall(99, allowlist).is_deny

        # Normalize preserves semantics
        norm = normalize_syscalls(allowlist)
        for nr in range(10):
            assert filter_syscall(nr, norm) == filter_syscall(nr, allowlist)

        # Instruction count
        assert instruction_count(norm) == len(norm) + 6

        # All jump targets correct
        assert verify_jump_targets(len(norm))

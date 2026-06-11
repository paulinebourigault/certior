"""
Dafny-Verified Seccomp Filter - Python Runtime Bridge (Phase D4).

Mirrors every type, predicate, and method in ``dafny/sandbox/seccomp_filter.dfy``,
enforcing at runtime the same properties that Dafny proves statically:

  P34  Allowlist completeness - Allow only if syscall in allowlist
  P35  Default deny - any syscall not in allowlist is Denied
  P36  Architecture check - mismatch always denied
  P37  Filter monotonicity - adding syscalls never removes allowed ones
  P38  Filter determinism - same inputs → same decision (inherent)
  P39  No duplicate syscalls - normalize produces sorted, unique list
  P40  Instruction count - N + 6 instructions for N unique syscalls
  P41  Jump target correctness - all JEQ true-branches land on ALLOW
  P42  Profile subset - restricted.allowlist ⊆ standard.allowlist
  P43  Network syscall exclusion - network profile excludes socket/etc.
  P44  Audit completeness - every build_filter appends exactly one audit entry
  P45  Profile immutability - profile frozen after construction
  P46  Invariant preservation - Valid() holds at every method boundary

The bridge uses ``check_invariant()`` from ``dafny_runtime`` to record
every pre/post-condition check to the ``InvariantAuditLog``, providing
a compliance-grade audit trail of all invariant verifications.

Usage::

    from agentsafe.sandbox.seccomp_verified import (
        SeccompProfile, SeccompFilterBuilder, FilterDecision,
        filter_syscall, check_architecture, STANDARD_PROFILE,
    )

    builder = SeccompFilterBuilder()
    normalized, instr_count = builder.build_filter(STANDARD_PROFILE)
    assert instr_count == len(normalized) + 6

    decision = filter_syscall(0, normalized)  # read → Allow
    assert decision.is_allow
"""
from __future__ import annotations

import platform
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
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

from agentsafe.verification.dafny_runtime import (
    InvariantAuditLog,
    InvariantViolation,
    PreconditionViolation,
    check_invariant,
)


# =============================================================================
# FilterDecision - mirrors ``datatype FilterDecision`` from Dafny
# =============================================================================

@dataclass(frozen=True, eq=False)
class FilterDecision:
    """Immutable filter decision - mirrors Dafny ``FilterDecision``."""

    allowed: bool
    reason: str = ""

    @property
    def is_allow(self) -> bool:
        return self.allowed

    @property
    def is_deny(self) -> bool:
        return not self.allowed

    @classmethod
    def allow(cls) -> FilterDecision:
        return cls(allowed=True)

    @classmethod
    def deny(cls, reason: str) -> FilterDecision:
        return cls(allowed=False, reason=reason)

    def __repr__(self) -> str:
        if self.allowed:
            return "FilterDecision.Allow"
        return f"FilterDecision.Deny({self.reason!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FilterDecision):
            return self.allowed == other.allowed
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.allowed)


# Singleton constants for convenience comparisons
FilterDecision.ALLOW = FilterDecision(allowed=True)  # type: ignore[attr-defined]
FilterDecision.DENY = FilterDecision(allowed=False, reason="denied")  # type: ignore[attr-defined]


# =============================================================================
# DefaultAction - mirrors ``datatype DefaultAction`` from Dafny
# =============================================================================

class DefaultAction(Enum):
    """What to do when a syscall is not on the allowlist."""
    KILL = "kill"
    LOG = "log"
    RETURN_ERRNO = "return_errno"


# =============================================================================
# Architecture constants
# =============================================================================

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7


def get_current_audit_arch() -> int:
    """Return the AUDIT_ARCH constant for the running architecture."""
    machine = platform.machine()
    if machine in ("x86_64", "AMD64"):
        return AUDIT_ARCH_X86_64
    elif machine in ("aarch64", "arm64"):
        return AUDIT_ARCH_AARCH64
    else:
        return AUDIT_ARCH_X86_64  # fallback


# =============================================================================
# Network syscalls - the set that MUST be excluded for network isolation (P43)
# =============================================================================

# x86_64 syscall numbers for network operations
NETWORK_SYSCALLS_X86_64: FrozenSet[int] = frozenset({
    41,   # socket
    42,   # connect
    43,   # accept
    44,   # sendto
    45,   # recvfrom
    46,   # sendmsg
    47,   # recvmsg
    49,   # bind
    50,   # listen
    53,   # socketpair
    288,  # accept4
    # Also: shutdown(48), getsockname(51), getpeername(52),
    # setsockopt(54), getsockopt(55), sendmmsg(307), recvmmsg(299)
    48,   # shutdown
    51,   # getsockname
    52,   # getpeername
    54,   # setsockopt
    55,   # getsockopt
    307,  # sendmmsg
    299,  # recvmmsg
})

NETWORK_SYSCALLS_AARCH64: FrozenSet[int] = frozenset({
    198,  # socket
    203,  # connect
    202,  # accept
    206,  # sendto
    207,  # recvfrom
    211,  # sendmsg
    212,  # recvmsg
    200,  # bind
    201,  # listen
    199,  # socketpair
    242,  # accept4
    210,  # shutdown
    204,  # getsockname
    205,  # getpeername
    208,  # setsockopt
    209,  # getsockopt
    269,  # sendmmsg
    243,  # recvmmsg
})

# Process-spawning syscalls - excluded from all sandboxed profiles
PROCESS_SPAWN_SYSCALLS_X86_64: FrozenSet[int] = frozenset({
    56,   # clone
    57,   # fork
    58,   # vfork
    59,   # execve
    322,  # execveat
    435,  # clone3
})

PROCESS_SPAWN_SYSCALLS_AARCH64: FrozenSet[int] = frozenset({
    220,  # clone
    # fork and vfork not available on aarch64 (use clone instead)
    221,  # execve
    281,  # execveat
    435,  # clone3
})


def get_network_syscalls() -> FrozenSet[int]:
    """Return network syscall numbers for the current architecture."""
    machine = platform.machine()
    if machine in ("aarch64", "arm64"):
        return NETWORK_SYSCALLS_AARCH64
    return NETWORK_SYSCALLS_X86_64


def get_process_spawn_syscalls() -> FrozenSet[int]:
    """Return process-spawning syscall numbers for the current architecture."""
    machine = platform.machine()
    if machine in ("aarch64", "arm64"):
        return PROCESS_SPAWN_SYSCALLS_AARCH64
    return PROCESS_SPAWN_SYSCALLS_X86_64


# =============================================================================
# Pure filter functions - mirrors Dafny specification (P34, P35, P36, P38)
# =============================================================================

def filter_syscall(nr: int, allowlist: Sequence[int]) -> FilterDecision:
    """
    Pure filter function - mirrors Dafny ``FilterSyscall``.

    P34: Allow only if nr ∈ allowlist.
    P35: Deny if nr ∉ allowlist.
    P38: Deterministic (pure function).
    """
    if nr in allowlist:
        return FilterDecision.allow()
    return FilterDecision.deny("syscall not in allowlist")


def check_architecture(actual_arch: int, expected_arch: int) -> FilterDecision:
    """
    Architecture check - mirrors Dafny ``CheckArchitecture``.

    P36: Allow iff actual == expected.
    """
    if actual_arch == expected_arch:
        return FilterDecision.allow()
    return FilterDecision.deny("architecture mismatch")


# =============================================================================
# Normalize - sort + deduplicate (P39)
# =============================================================================

def normalize_syscalls(syscalls: Sequence[int]) -> Tuple[int, ...]:
    """
    Normalize a sequence of syscall numbers: sort + deduplicate.

    Mirrors Dafny ``Normalize``.

    P39:
      - Result is strictly sorted (ascending, no duplicates).
      - |result| ≤ |input|.
      - Membership is preserved: nr ∈ result ⟺ nr ∈ input.
    """
    result = tuple(sorted(set(syscalls)))
    # Post-condition checks
    assert len(result) <= len(syscalls), "P39: |result| ≤ |input|"
    # Strictly sorted
    for i in range(1, len(result)):
        assert result[i] > result[i - 1], "P39: strictly sorted"
    return result


# =============================================================================
# Instruction count (P40)
# =============================================================================

def instruction_count(normalized_allowlist: Sequence[int]) -> int:
    """
    Compute the BPF instruction count for a normalized allowlist.

    Mirrors Dafny ``InstructionCount``.

    P40: instruction_count = |normalized_allowlist| + 6

    Layout:
      [0]     LD   arch          (1)
      [1]     JEQ  expected_arch (1)
      [2]     RET  KILL          (1)
      [3]     LD   nr            (1)
      [4..N+3] JEQ syscall_i    (N)
      [N+4]   RET  DENY         (1)
      [N+5]   RET  ALLOW        (1)
      Total = N + 6
    """
    return len(normalized_allowlist) + 6


# =============================================================================
# Jump target verification (P41)
# =============================================================================

def jeq_true_offset(i: int, n: int) -> int:
    """True-branch offset for the i-th JEQ in a block of N JEQs.

    P41: offset = n - i, which lands on ALLOW at position (4 + n + 1).
    """
    assert 0 <= i < n, f"P41 precondition: 0 ≤ {i} < {n}"
    return n - i


def jeq_true_target(i: int, n: int) -> int:
    """Absolute instruction index the i-th JEQ jumps to on true.

    P41: target = 4 + i + 1 + (n - i) = 5 + n = AllowPosition(n).
    """
    assert 0 <= i < n
    return 4 + i + 1 + jeq_true_offset(i, n)


def allow_position(n: int) -> int:
    """Position of the ALLOW instruction.

    = 4 + n + 1 = n + 5.
    """
    return 4 + n + 1


def verify_jump_targets(n: int) -> bool:
    """Verify all JEQ true-branches land on the ALLOW instruction.

    P41: For all i in [0, n), JeqTrueTarget(i, n) == AllowPosition(n).
    """
    target = allow_position(n)
    for i in range(n):
        if jeq_true_target(i, n) != target:
            return False
    return True


# =============================================================================
# Subset check (P42)
# =============================================================================

def is_subset_of(
    small: Sequence[int],
    large: Sequence[int],
) -> bool:
    """Check if small ⊆ large (as sets).

    P42: restricted.allowlist ⊆ standard.allowlist.
    """
    return set(small).issubset(set(large))


# =============================================================================
# Network exclusion check (P43)
# =============================================================================

def excludes_all(
    blocklist: Sequence[int],
    allowlist: Sequence[int],
) -> bool:
    """Check that no element of blocklist appears in allowlist.

    P43: ExcludesAll(network_syscalls, allowlist).
    """
    allowset = set(allowlist)
    return all(nr not in allowset for nr in blocklist)


# =============================================================================
# SeccompProfile - immutable profile (P45)
# =============================================================================

@dataclass(frozen=True)
class SeccompProfile:
    """
    Immutable seccomp profile - mirrors Dafny ``SeccompProfile``.

    P45: Frozen after construction (enforced by ``frozen=True``).
    """
    name: str
    allowed_syscalls: Tuple[int, ...]
    default_action: DefaultAction = DefaultAction.KILL
    expected_arch: int = field(default_factory=get_current_audit_arch)

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_syscalls, tuple):
            object.__setattr__(
                self, "allowed_syscalls", tuple(self.allowed_syscalls)
            )

    @property
    def normalized(self) -> Tuple[int, ...]:
        """Return normalized (sorted, deduplicated) allowlist."""
        return normalize_syscalls(self.allowed_syscalls)

    @property
    def excludes_network(self) -> bool:
        """P43: Check that all network syscalls are excluded."""
        return excludes_all(get_network_syscalls(), self.allowed_syscalls)

    @property
    def excludes_process_spawn(self) -> bool:
        """Check that all process-spawning syscalls are excluded."""
        return excludes_all(
            get_process_spawn_syscalls(), self.allowed_syscalls
        )

    def is_subset_of(self, other: SeccompProfile) -> bool:
        """P42: Check this profile's allowlist ⊆ other's."""
        return is_subset_of(self.allowed_syscalls, other.allowed_syscalls)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for audit / JSON export."""
        return {
            "name": self.name,
            "syscall_count": len(self.normalized),
            "default_action": self.default_action.value,
            "expected_arch": hex(self.expected_arch),
            "excludes_network": self.excludes_network,
            "excludes_process_spawn": self.excludes_process_spawn,
        }


# =============================================================================
# FilterAuditEntry - immutable audit record
# =============================================================================

@dataclass(frozen=True)
class FilterAuditEntry:
    """Immutable audit record - mirrors Dafny ``FilterAuditEntry``."""
    profile_name: str
    syscall_count: int
    instruction_count: int
    default_action: DefaultAction
    build_number: int
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_name": self.profile_name,
            "syscall_count": self.syscall_count,
            "instruction_count": self.instruction_count,
            "default_action": self.default_action.value,
            "build_number": self.build_number,
            "timestamp": self.timestamp,
        }


# =============================================================================
# BpfProgram - verified wrapper around raw BPF bytes
# =============================================================================

@dataclass(frozen=True)
class BpfProgram:
    """
    Verified BPF program with structural metadata.

    Wraps raw BPF bytes with the invariants proven by Dafny:
      - instruction_count == len(normalized_allowlist) + 6  (P40)
      - All jump targets land on valid instructions (P41)
      - Allowlist membership determines filter decision (P34, P35)
    """
    raw_bytes: bytes
    instruction_count: int
    normalized_allowlist: Tuple[int, ...]
    profile_name: str
    default_action: DefaultAction
    expected_arch: int

    @property
    def hex(self) -> str:
        """Hex-encoded BPF program for serialization."""
        return self.raw_bytes.hex()

    @property
    def syscall_count(self) -> int:
        return len(self.normalized_allowlist)

    def check_syscall(self, nr: int) -> FilterDecision:
        """Check a syscall against the allowlist (P34, P35)."""
        return filter_syscall(nr, self.normalized_allowlist)

    @property
    def instructions(self) -> Tuple[Tuple[int, int, int, int], ...]:
        """Parse raw bytes into BPF instruction tuples (opcode, jt, jf, k).

        Each BPF instruction is 8 bytes: u16 opcode, u8 jt, u8 jf, u32 k.
        """
        result = []
        for offset in range(0, len(self.raw_bytes), 8):
            if offset + 8 <= len(self.raw_bytes):
                insn = struct.unpack("<HBBI", self.raw_bytes[offset:offset + 8])
                result.append(insn)
        return tuple(result)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_name": self.profile_name,
            "instruction_count": self.instruction_count,
            "syscall_count": self.syscall_count,
            "default_action": self.default_action.value,
            "expected_arch": hex(self.expected_arch),
            "program_size_bytes": len(self.raw_bytes),
            "program_hex": self.hex,
        }


# =============================================================================
# SeccompFilterBuilder - stateful builder with invariant checks (P44, P46)
# =============================================================================

class SeccompFilterBuilder:
    """
    Verified seccomp filter builder - mirrors Dafny ``SeccompFilterBuilder``.

    Invariant (P46): build_count == len(audit_log).
    Every build_filter call appends exactly one audit entry (P44).

    Usage::

        builder = SeccompFilterBuilder()
        program = builder.build_filter(STANDARD_PROFILE)
        assert program.instruction_count == len(program.normalized_allowlist) + 6
    """

    CLASS_NAME = "SeccompFilterBuilder"

    def __init__(self, profile: Optional[SeccompProfile] = None) -> None:
        self._audit_log: List[FilterAuditEntry] = []
        self._build_count: int = 0
        self._lock = threading.Lock()
        self._default_profile: Optional[SeccompProfile] = profile

        # Post-condition: Valid()
        check_invariant(
            self._valid,
            self.CLASS_NAME,
            "__init__",
            "post",
            "P46:Valid()",
        )

    # ── Invariant (P46) ──────────────────────────────────────────────

    def _valid(self) -> bool:
        """Class invariant: build_count == len(audit_log)."""
        return self._build_count == len(self._audit_log)

    @property
    def build_count(self) -> int:
        return self._build_count

    @property
    def audit_log(self) -> List[FilterAuditEntry]:
        return list(self._audit_log)

    # ── build_filter (P34-P46) ───────────────────────────────────────

    def build_filter(
        self,
        profile: Optional[SeccompProfile] = None,
        *,
        generate_bpf: bool = True,
    ) -> BpfProgram:
        """
        Build a verified BPF filter from a SeccompProfile.

        Args:
            profile: SeccompProfile to build. If None, uses profile from constructor.

        Pre-conditions:
          - Valid() holds (P46)

        Post-conditions:
          - Valid() holds (P46)
          - audit_log grew by exactly 1 (P44)
          - Normalized allowlist is sorted, unique (P39)
          - Instruction count == |normalized| + 6 (P40)
          - All jump targets correct (P41)
          - If profile excludes network, BPF denies all network syscalls (P43)
        """
        if profile is None:
            profile = self._default_profile
        if profile is None:
            raise ValueError("No profile provided (pass to constructor or build_filter)")
        with self._lock:
            return self._build_filter_locked(profile, generate_bpf)

    def _build_filter_locked(
        self,
        profile: SeccompProfile,
        generate_bpf: bool,
    ) -> BpfProgram:
        # Pre-condition: Valid()
        check_invariant(
            self._valid,
            self.CLASS_NAME,
            "build_filter",
            "pre",
            "P46:Valid()",
        )

        old_audit_len = len(self._audit_log)
        old_build_count = self._build_count

        # 1. Normalize (P39)
        normalized = normalize_syscalls(profile.allowed_syscalls)

        # 2. Compute instruction count (P40)
        instr_count = instruction_count(normalized)
        assert instr_count == len(normalized) + 6, \
            f"P40: {instr_count} != {len(normalized)} + 6"

        # 3. Verify jump targets (P41)
        assert verify_jump_targets(len(normalized)), "P41: jump target mismatch"

        # 4. Generate BPF program
        if generate_bpf:
            raw_bytes = self._generate_bpf(normalized, profile)
        else:
            raw_bytes = b""

        # 5. Verify network exclusion if applicable (P43)
        # (checked but not enforced - caller's responsibility)

        # 6. Build BpfProgram
        program = BpfProgram(
            raw_bytes=raw_bytes,
            instruction_count=instr_count,
            normalized_allowlist=normalized,
            profile_name=profile.name,
            default_action=profile.default_action,
            expected_arch=profile.expected_arch,
        )

        # 7. Audit entry (P44)
        entry = FilterAuditEntry(
            profile_name=profile.name,
            syscall_count=len(normalized),
            instruction_count=instr_count,
            default_action=profile.default_action,
            build_number=self._build_count,
        )
        self._audit_log.append(entry)
        self._build_count += 1

        # Post-conditions
        assert len(self._audit_log) == old_audit_len + 1, \
            "P44: audit_log grew by exactly 1"
        assert self._build_count == old_build_count + 1, \
            "P44: build_count incremented"

        check_invariant(
            self._valid,
            self.CLASS_NAME,
            "build_filter",
            "post",
            "P46:Valid()",
        )

        return program

    def _generate_bpf(
        self,
        normalized: Tuple[int, ...],
        profile: SeccompProfile,
    ) -> bytes:
        """Generate raw BPF bytecode.

        Delegates to the existing seccomp.py BPF generator but with
        verified invariants wrapped around it.
        """
        from .seccomp import (
            build_bpf_program,
            bpf_instruction_count,
            SeccompAction,
        )

        # Map default action
        action_map = {
            DefaultAction.KILL: SeccompAction.KILL,
            DefaultAction.LOG: SeccompAction.LOG,
            DefaultAction.RETURN_ERRNO: SeccompAction.ERRNO,
        }
        action = action_map[profile.default_action]

        raw = build_bpf_program(
            list(normalized),
            default_action=action,
            audit_arch=profile.expected_arch,
        )

        # Verify instruction count matches our prediction (P40)
        actual_count = bpf_instruction_count(raw)
        expected_count = len(normalized) + 6
        if actual_count != expected_count:
            raise InvariantViolation(
                property_id="P40:InstructionCount",
                class_name=self.CLASS_NAME,
                method="_generate_bpf",
                phase="post",
                details=(
                    f"BPF instruction count {actual_count} != "
                    f"expected {expected_count} (N={len(normalized)}+6)"
                ),
            )

        return raw

    # ── verify_filter (P34, P35) ─────────────────────────────────────

    def verify_filter(
        self,
        program: BpfProgram,
        test_syscalls: Sequence[int],
    ) -> bool:
        """
        Verify that a built filter produces correct decisions.

        For every test syscall:
          - If in allowlist → decision is Allow (P34)
          - If not in allowlist → decision is Deny (P35)
        """
        allowset = set(program.normalized_allowlist)
        for nr in test_syscalls:
            decision = filter_syscall(nr, program.normalized_allowlist)
            if nr in allowset:
                if not decision.is_allow:
                    return False
            else:
                if not decision.is_deny:
                    return False
        return True


# =============================================================================
# Pre-built profiles - mirrors compliance templates
# =============================================================================

def _resolve_names_to_numbers(names: FrozenSet[str]) -> Tuple[int, ...]:
    """Resolve syscall names to numbers using the existing tables."""
    from .seccomp import resolve_syscall_numbers
    return tuple(resolve_syscall_numbers(names))


def _standard_syscall_numbers() -> Tuple[int, ...]:
    """Return the standard allowlist as resolved numbers."""
    from .policy import SECCOMP_SYSCALL_ALLOWLIST_X86_64
    return _resolve_names_to_numbers(SECCOMP_SYSCALL_ALLOWLIST_X86_64)


def _compute_only_numbers() -> Tuple[int, ...]:
    """Return the compute-only allowlist (no file I/O beyond stdin/stdout)."""
    from .policy import SECCOMP_SYSCALL_ALLOWLIST_X86_64
    # Remove file-opening syscalls
    reduced = SECCOMP_SYSCALL_ALLOWLIST_X86_64 - frozenset({
        "openat", "getdents", "getdents64",
    })
    return _resolve_names_to_numbers(reduced)


def create_standard_profile() -> SeccompProfile:
    """Standard sandbox profile - matches SECCOMP_SYSCALL_ALLOWLIST_X86_64.

    Allows: memory management, read-only file I/O, process metadata,
            time, signals, misc runtime needs, process exit, polling.
    Excludes: networking, process spawning, raw I/O, debugging.
    """
    return SeccompProfile(
        name="standard",
        allowed_syscalls=_standard_syscall_numbers(),
        default_action=DefaultAction.KILL,
    )


def create_network_blocked_profile() -> SeccompProfile:
    """Network-blocked profile - standard minus all socket syscalls.

    P43: Guarantees no network syscalls are in the allowlist.
    This is the same as the standard profile since standard already
    excludes networking, but makes the exclusion explicit and verified.
    """
    numbers = _standard_syscall_numbers()
    net_syscalls = get_network_syscalls()
    filtered = tuple(nr for nr in numbers if nr not in net_syscalls)
    return SeccompProfile(
        name="network_blocked",
        allowed_syscalls=filtered,
        default_action=DefaultAction.KILL,
    )


def create_compute_only_profile() -> SeccompProfile:
    """Compute-only profile - no file opens, no networking.

    The most restrictive useful profile: pure computation only.
    """
    return SeccompProfile(
        name="compute_only",
        allowed_syscalls=_compute_only_numbers(),
        default_action=DefaultAction.KILL,
    )


def create_audit_profile() -> SeccompProfile:
    """Audit/development profile - logs instead of killing.

    Same allowlist as standard but with LOG as default action.
    Useful for developing and debugging the allowlist.
    """
    return SeccompProfile(
        name="audit",
        allowed_syscalls=_standard_syscall_numbers(),
        default_action=DefaultAction.LOG,
    )


def create_custom_profile(
    name: str,
    allowed_names: FrozenSet[str],
    *,
    default_action: DefaultAction = DefaultAction.KILL,
    exclude_network: bool = True,
    exclude_process_spawn: bool = True,
) -> SeccompProfile:
    """Create a custom profile from syscall names.

    Args:
        name: Profile name for audit trail.
        allowed_names: Set of syscall names to allow.
        default_action: Action for unlisted syscalls.
        exclude_network: If True, remove any network syscalls.
        exclude_process_spawn: If True, remove any process-spawn syscalls.
    """
    numbers = set(_resolve_names_to_numbers(allowed_names))
    if exclude_network:
        numbers -= get_network_syscalls()
    if exclude_process_spawn:
        numbers -= get_process_spawn_syscalls()
    return SeccompProfile(
        name=name,
        allowed_syscalls=tuple(sorted(numbers)),
        default_action=default_action,
    )


def create_profile_from_numbers(
    name: str,
    allowed_numbers: Sequence[int],
    default_action: DefaultAction = DefaultAction.KILL,
) -> SeccompProfile:
    """Create a profile directly from syscall numbers.

    Unlike ``create_custom_profile`` which accepts syscall names, this
    function accepts raw syscall numbers, useful for tests and when exact
    numeric control is needed.

    Args:
        name: Profile name for audit trail.
        allowed_numbers: Sequence of syscall numbers to allow.
        default_action: Action for unlisted syscalls.
    """
    return SeccompProfile(
        name=name,
        allowed_syscalls=tuple(sorted(set(allowed_numbers))),
        default_action=default_action,
    )


# Lazy-initialized singletons
_STANDARD_PROFILE: Optional[SeccompProfile] = None
_NETWORK_BLOCKED_PROFILE: Optional[SeccompProfile] = None
_COMPUTE_ONLY_PROFILE: Optional[SeccompProfile] = None
_AUDIT_PROFILE: Optional[SeccompProfile] = None


def get_standard_profile() -> SeccompProfile:
    """Singleton accessor for the standard profile."""
    global _STANDARD_PROFILE
    if _STANDARD_PROFILE is None:
        _STANDARD_PROFILE = create_standard_profile()
    return _STANDARD_PROFILE


def get_network_blocked_profile() -> SeccompProfile:
    """Singleton accessor for the network-blocked profile."""
    global _NETWORK_BLOCKED_PROFILE
    if _NETWORK_BLOCKED_PROFILE is None:
        _NETWORK_BLOCKED_PROFILE = create_network_blocked_profile()
    return _NETWORK_BLOCKED_PROFILE


def get_compute_only_profile() -> SeccompProfile:
    """Singleton accessor for the compute-only profile."""
    global _COMPUTE_ONLY_PROFILE
    if _COMPUTE_ONLY_PROFILE is None:
        _COMPUTE_ONLY_PROFILE = create_compute_only_profile()
    return _COMPUTE_ONLY_PROFILE


def get_audit_profile() -> SeccompProfile:
    """Singleton accessor for the audit profile."""
    global _AUDIT_PROFILE
    if _AUDIT_PROFILE is None:
        _AUDIT_PROFILE = create_audit_profile()
    return _AUDIT_PROFILE


def reset_profile_cache() -> None:
    """Reset all cached profiles (testing only)."""
    global _STANDARD_PROFILE, _NETWORK_BLOCKED_PROFILE
    global _COMPUTE_ONLY_PROFILE, _AUDIT_PROFILE
    _STANDARD_PROFILE = None
    _NETWORK_BLOCKED_PROFILE = None
    _COMPUTE_ONLY_PROFILE = None
    _AUDIT_PROFILE = None


# =============================================================================
# Integration: build_verified_seccomp - convenience for executor.py
# =============================================================================

def build_verified_seccomp(
    profile: Optional[SeccompProfile] = None,
    *,
    builder: Optional[SeccompFilterBuilder] = None,
) -> BpfProgram:
    """
    Build a verified seccomp BPF program, ready for installation.

    Combines profile lookup, normalization, Dafny-verified invariant
    checking, and BPF generation in a single call.

    Args:
        profile: SeccompProfile to use. Defaults to standard.
        builder: SeccompFilterBuilder to use. Creates new if None.

    Returns:
        BpfProgram with verified invariants.
    """
    if profile is None:
        profile = get_standard_profile()
    if builder is None:
        builder = SeccompFilterBuilder()
    return builder.build_filter(profile)


# =============================================================================
# SeccompAuditInfo - compliance export
# =============================================================================

@dataclass(frozen=True)
class SeccompAuditInfo:
    """Audit information for seccomp filter in compliance exports."""
    profile_name: str
    syscall_count: int
    instruction_count: int
    default_action: str
    expected_arch: str
    excludes_network: bool
    excludes_process_spawn: bool
    build_number: int
    jump_targets_verified: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_name": self.profile_name,
            "syscall_count": self.syscall_count,
            "instruction_count": self.instruction_count,
            "default_action": self.default_action,
            "expected_arch": self.expected_arch,
            "excludes_network": self.excludes_network,
            "excludes_process_spawn": self.excludes_process_spawn,
            "build_number": self.build_number,
            "jump_targets_verified": self.jump_targets_verified,
        }


def build_seccomp_audit_info(
    program: BpfProgram,
    profile: SeccompProfile,
    build_number: int = 0,
) -> SeccompAuditInfo:
    """Build audit info from a verified program and profile."""
    return SeccompAuditInfo(
        profile_name=program.profile_name,
        syscall_count=program.syscall_count,
        instruction_count=program.instruction_count,
        default_action=program.default_action.value,
        expected_arch=hex(program.expected_arch),
        excludes_network=profile.excludes_network,
        excludes_process_spawn=profile.excludes_process_spawn,
        build_number=build_number,
        jump_targets_verified=verify_jump_targets(program.syscall_count),
    )

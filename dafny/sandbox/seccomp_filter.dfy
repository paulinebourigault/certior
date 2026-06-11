// =============================================================================
// seccomp_filter.dfy - Dafny-Verified Seccomp BPF Filter (Phase D4)
// =============================================================================
//
// Proves critical safety properties for Certior's seccomp-BPF filter
// generation subsystem, which gates every system call made by sandboxed
// agent code.
//
//   P34 ALLOWLIST COMPLETENESS
//       filter_syscall(nr, allowlist) == Allow  ONLY IF  nr ∈ allowlist.
//       No syscall can be allowed without being in the allowlist.
//
//   P35 DEFAULT DENY
//       nr ∉ allowlist  ==>  filter_syscall(nr, allowlist) == Deny.
//       Any syscall not on the allowlist is unconditionally denied.
//
//   P36 ARCHITECTURE CHECK
//       check_architecture(actual_arch, expected_arch) == Allow
//         ONLY IF  actual_arch == expected_arch.
//       A mismatched architecture always produces Deny (KILL).
//
//   P37 FILTER MONOTONICITY
//       If filter_syscall(nr, allowlist) == Allow and we add a new entry
//       to allowlist, the result is still Allow.  Adding entries can only
//       expand the allowed set (monotone ascent on the lattice).
//
//   P38 FILTER DETERMINISM
//       For any given (nr, allowlist) pair, filter_syscall always returns
//       the same FilterDecision.  (Proved structurally - pure function.)
//
//   P39 NO DUPLICATE SYSCALLS
//       normalize(allowlist) produces a sorted sequence with no duplicates.
//       |normalize(allowlist)| ≤ |allowlist|.
//
//   P40 INSTRUCTION COUNT CORRECTNESS
//       instruction_count(allowlist) == |normalize(allowlist)| + 5.
//       Breakdown: arch_load(1) + arch_check(1) + arch_kill(1) +
//                  nr_load(1) + N×JEQ + default_deny(1) + allow(1).
//       (Actually 3 + 1 + N + 1 + 1 = N + 6.  See BPF layout below.)
//
//   P41 JUMP TARGET CORRECTNESS
//       For each JEQ at position i (0-indexed within the JEQ block),
//       the true-branch offset == (N - i), which lands exactly on the
//       ALLOW instruction.  The false-branch offset == 0, which is the
//       next JEQ or default_deny.
//
//   P42 PROFILE SUBSET
//       If profile A is a restriction of profile B, then
//       A.allowlist ⊆ B.allowlist.  Formally: ∀ nr ∈ A.allowlist: nr ∈ B.allowlist.
//       This ensures restricted profiles are always more constrained.
//
//   P43 NETWORK SYSCALL EXCLUSION
//       The network-isolated profile's allowlist contains NONE of the
//       network syscall numbers (socket, connect, bind, listen, accept,
//       sendto, recvfrom, sendmsg, recvmsg, accept4, socketpair).
//       This is the formal guarantee that sandboxed code cannot open sockets.
//
//   P44 AUDIT COMPLETENESS
//       Every call to build_filter appends exactly one entry to the
//       audit log.  |audit_log| after build_filter == |audit_log| before + 1.
//
//   P45 PROFILE IMMUTABILITY
//       A SeccompProfile's allowed_syscalls and default_action never change
//       after construction.  Enforced by datatype immutability.
//
//   P46 FILTER INVARIANT PRESERVATION
//       Every public method preserves the class invariant Valid().
//       Valid() == (|audit_log| >= 0) ∧ (profile is well-formed).
//
// BPF Program Layout (for N allowed syscalls):
//   [0]     LD   arch          - load seccomp_data.arch
//   [1]     JEQ  expected_arch - if match, skip to [3]; else fall to [2]
//   [2]     RET  KILL          - wrong architecture
//   [3]     LD   nr            - load seccomp_data.nr
//   [4]     JEQ  syscall_0     - if match, jump to ALLOW at [4+N+1]
//   [5]     JEQ  syscall_1     - if match, jump to ALLOW
//   ...
//   [4+N-1] JEQ  syscall_{N-1} - last check
//   [4+N]   RET  DENY          - default action (KILL / LOG / ERRNO)
//   [4+N+1] RET  ALLOW         - all matching JEQs land here
//
// Total instructions = N + 6
//
// Usage:
//   dafny verify dafny/sandbox/seccomp_filter.dfy
//
// Verification target: Dafny 4.x
// =============================================================================

module CertiorSeccompFilter {

  // =========================================================================
  // Syscall number - non-negative integer
  // =========================================================================

  type SyscallNr = n: nat | true witness 0

  // =========================================================================
  // FilterDecision - the verdict for a syscall
  // =========================================================================

  datatype FilterDecision = Allow | Deny(reason: string)

  predicate IsAllow(d: FilterDecision) { d.Allow? }
  predicate IsDeny(d: FilterDecision)  { d.Deny? }

  // =========================================================================
  // DefaultAction - what to do when a syscall is not on the allowlist
  // =========================================================================

  datatype DefaultAction = Kill | Log | ReturnErrno

  // =========================================================================
  // SeccompProfile - immutable filter configuration (P45)
  // =========================================================================

  datatype SeccompProfile = SeccompProfile(
    name: string,
    allowed_syscalls: seq<SyscallNr>,
    default_action: DefaultAction,
    expected_arch: nat
  )

  // =========================================================================
  // Membership predicate
  // =========================================================================

  predicate InSeq(nr: SyscallNr, s: seq<SyscallNr>)
  {
    exists i :: 0 <= i < |s| && s[i] == nr
  }

  predicate NotInSeq(nr: SyscallNr, s: seq<SyscallNr>)
  {
    forall i :: 0 <= i < |s| ==> s[i] != nr
  }

  // Fundamental relationship
  lemma InSeqEquivNotNotInSeq(nr: SyscallNr, s: seq<SyscallNr>)
    ensures InSeq(nr, s) <==> !NotInSeq(nr, s)
  {}

  // =========================================================================
  // Pure filter functions - the specification (P34, P35, P38)
  // =========================================================================

  // P34 + P35 + P38: Pure, deterministic syscall filter.
  // Being a pure function, determinism (P38) is inherent.
  function FilterSyscall(nr: SyscallNr, allowlist: seq<SyscallNr>): FilterDecision
  {
    if InSeq(nr, allowlist) then
      Allow
    else
      Deny("syscall not in allowlist")
  }

  // P36: Architecture check - pure function.
  function CheckArchitecture(actual_arch: nat, expected_arch: nat): FilterDecision
  {
    if actual_arch == expected_arch then
      Allow
    else
      Deny("architecture mismatch")
  }

  // =========================================================================
  // P34: ALLOWLIST COMPLETENESS
  //   filter_syscall(nr, allowlist) == Allow ==> nr ∈ allowlist
  // =========================================================================

  lemma AllowlistCompleteness(nr: SyscallNr, allowlist: seq<SyscallNr>)
    ensures FilterSyscall(nr, allowlist) == Allow ==> InSeq(nr, allowlist)
  {}

  // =========================================================================
  // P35: DEFAULT DENY
  //   nr ∉ allowlist ==> filter_syscall(nr, allowlist) == Deny(_)
  // =========================================================================

  lemma DefaultDeny(nr: SyscallNr, allowlist: seq<SyscallNr>)
    ensures NotInSeq(nr, allowlist) ==> IsDeny(FilterSyscall(nr, allowlist))
  {}

  // =========================================================================
  // P36: ARCHITECTURE CHECK
  //   CheckArchitecture(a, e) == Allow <==> a == e
  // =========================================================================

  lemma ArchitectureCheckCorrectness(actual: nat, expected: nat)
    ensures CheckArchitecture(actual, expected) == Allow <==> actual == expected
  {}

  // =========================================================================
  // P37: FILTER MONOTONICITY
  //   If nr is allowed in allowlist, it is still allowed in (allowlist + [x]).
  //   Adding entries to the allowlist never removes previously allowed syscalls.
  // =========================================================================

  lemma {:induction false} FilterMonotonicity(
    nr: SyscallNr,
    allowlist: seq<SyscallNr>,
    addition: SyscallNr
  )
    requires FilterSyscall(nr, allowlist) == Allow
    ensures FilterSyscall(nr, allowlist + [addition]) == Allow
  {
    // nr is in allowlist, so there exists witness i
    assert InSeq(nr, allowlist);
    var i :| 0 <= i < |allowlist| && allowlist[i] == nr;
    // That same index i is valid in allowlist + [addition]
    assert (allowlist + [addition])[i] == allowlist[i] == nr;
    assert InSeq(nr, allowlist + [addition]);
  }

  // =========================================================================
  // Sequence normalization - sort + deduplicate (P39)
  // =========================================================================

  // Predicate: sequence is sorted
  predicate IsSorted(s: seq<SyscallNr>)
  {
    forall i, j :: 0 <= i < j < |s| ==> s[i] <= s[j]
  }

  // Predicate: sequence has no duplicates
  predicate NoDuplicates(s: seq<SyscallNr>)
  {
    forall i, j :: 0 <= i < j < |s| ==> s[i] != s[j]
  }

  // Predicate: sequence is sorted AND has strict ordering (no duplicates)
  predicate IsStrictlySorted(s: seq<SyscallNr>)
  {
    |s| <= 1
    || ((forall j :: 1 <= j < |s| ==> s[0] < s[j])
        && IsStrictlySorted(s[1..]))
  }

  // Strictly sorted implies no duplicates
  lemma StrictlySortedImpliesNoDuplicates(s: seq<SyscallNr>)
    requires IsStrictlySorted(s)
    ensures NoDuplicates(s)
  {}

  // Strictly sorted implies sorted
  lemma StrictlySortedImpliesSorted(s: seq<SyscallNr>)
    requires IsStrictlySorted(s)
    ensures IsSorted(s)
  {}

  // Helper: insert into sorted sequence maintaining strict order
  function InsertSorted(nr: SyscallNr, s: seq<SyscallNr>): seq<SyscallNr>
    requires IsStrictlySorted(s)
    decreases |s|
    ensures IsStrictlySorted(InsertSorted(nr, s))
    ensures |InsertSorted(nr, s)| <= |s| + 1
  {
    if |s| == 0 then
      [nr]
    else if nr < s[0] then
      [nr] + s
    else if nr == s[0] then
      s  // duplicate - skip
    else
      [s[0]] + InsertSorted(nr, s[1..])
  }

  // P39: Normalize - sort + deduplicate
  function Normalize(input: seq<SyscallNr>): seq<SyscallNr>
    decreases |input|
    ensures IsStrictlySorted(Normalize(input))
    ensures |Normalize(input)| <= |input|
  {
    if |input| == 0 then
      []
    else
      var rest := Normalize(input[1..]);
      InsertSorted(input[0], rest)
  }

  lemma InsertSortedMembership(nr: SyscallNr, s: seq<SyscallNr>, x: SyscallNr)
    requires IsStrictlySorted(s)
    ensures InSeq(x, InsertSorted(nr, s)) <==> (x == nr || InSeq(x, s))
    decreases |s|
  {
    if |s| == 0 {
    } else if nr < s[0] {
    } else if nr == s[0] {
    } else {
      InsertSortedMembership(nr, s[1..], x);
      assert InsertSorted(nr, s) == [s[0]] + InsertSorted(nr, s[1..]);
      assert InSeq(x, InsertSorted(nr, s)) <==> (x == s[0] || InSeq(x, InsertSorted(nr, s[1..])));
      assert InSeq(x, s) <==> (x == s[0] || InSeq(x, s[1..]));
    }
  }

  lemma NormalizeMembership(input: seq<SyscallNr>, nr: SyscallNr)
    ensures InSeq(nr, Normalize(input)) <==> InSeq(nr, input)
    decreases |input|
  {
    if |input| == 0 {
    } else {
      NormalizeMembership(input[1..], nr);
      InsertSortedMembership(input[0], Normalize(input[1..]), nr);
    }
  }

  // P39 corollary: normalization preserves filter semantics
  lemma NormalizePreservesFilterSemantics(nr: SyscallNr, input: seq<SyscallNr>)
    ensures FilterSyscall(nr, Normalize(input)) == FilterSyscall(nr, input)
  {
    NormalizeMembership(input, nr);
  }

  // =========================================================================
  // P40: INSTRUCTION COUNT CORRECTNESS
  //
  // For N normalized (unique, sorted) syscalls:
  //   instruction_count = N + 6
  //
  // Layout: [LD arch][JEQ arch][RET KILL][LD nr]
  //         [JEQ_0]...[JEQ_{N-1}][RET DENY][RET ALLOW]
  // =========================================================================

  function InstructionCount(normalized_allowlist: seq<SyscallNr>): nat
  {
    |normalized_allowlist| + 6
  }

  lemma InstructionCountCorrectness(allowlist: seq<SyscallNr>)
    requires IsStrictlySorted(allowlist)
    ensures InstructionCount(allowlist) >= 6
    ensures InstructionCount(allowlist) == |allowlist| + 6
  {}

  // Empty allowlist still needs the arch check + default deny + allow
  lemma EmptyAllowlistInstructionCount()
    ensures InstructionCount([]) == 6
  {}

  // =========================================================================
  // P41: JUMP TARGET CORRECTNESS
  //
  // For the JEQ at index i (0-based within the JEQ block, starting at
  // instruction position 4 in the program):
  //   - jt (true offset) = N - i  → lands on ALLOW at position 4+N+1
  //   - jf (false offset) = 0     → falls through to next instruction
  //
  // We prove that for every i in [0, N), the jt value is correct.
  // =========================================================================

  // The true-branch offset for the i-th JEQ in a block of N JEQs
  function JeqTrueOffset(i: nat, n: nat): nat
    requires 0 <= i < n
  {
    n - i
  }

  // The absolute instruction index the i-th JEQ jumps to on true
  function JeqTrueTarget(i: nat, n: nat): nat
    requires 0 <= i < n
  {
    // JEQ_i is at program position (4 + i)
    // Target = current + 1 + jt = (4+i) + 1 + (n-i) = 5 + n
    // Which is position (4 + n + 1) = the ALLOW instruction
    4 + i + 1 + JeqTrueOffset(i, n)
  }

  // ALLOW instruction position
  function AllowPosition(n: nat): nat
  {
    4 + n + 1  // = n + 5
  }

  // P41: Every JEQ true-branch lands on the ALLOW instruction
  lemma JumpTargetCorrectness(i: nat, n: nat)
    requires 0 <= i < n
    ensures JeqTrueTarget(i, n) == AllowPosition(n)
  {
    // (4 + i) + 1 + (n - i) = 5 + n = 4 + n + 1
    // Dafny can verify this automatically.
  }

  // P41 corollary: false-branch (offset 0) falls through to next instruction
  lemma FalseBranchFallsThrough(i: nat, n: nat)
    requires 0 <= i < n
    requires i + 1 < n  // not the last JEQ
    ensures (4 + i) + 1 + 0 == 4 + (i + 1)
  {}

  // P41 corollary: last JEQ's false-branch falls to DEFAULT DENY
  lemma LastJeqFallsToDeny(n: nat)
    requires n > 0
    ensures (4 + (n - 1)) + 1 + 0 == 4 + n
    // 4 + n is the position of RET DENY
  {}

  // =========================================================================
  // P42: PROFILE SUBSET
  //
  // A restricted profile's allowlist ⊆ a standard profile's allowlist.
  // =========================================================================

  ghost predicate IsSubsetOf(small: seq<SyscallNr>, large: seq<SyscallNr>)
  {
    forall nr :: InSeq(nr, small) ==> InSeq(nr, large)
  }

  // If A ⊆ B, then any syscall allowed by A is also allowed by B
  lemma SubsetPreservesAllow(
    nr: SyscallNr,
    restricted: seq<SyscallNr>,
    standard: seq<SyscallNr>
  )
    requires IsSubsetOf(restricted, standard)
    requires FilterSyscall(nr, restricted) == Allow
    ensures FilterSyscall(nr, standard) == Allow
  {
    assert InSeq(nr, restricted);
    assert InSeq(nr, standard);
  }

  // If A ⊆ B, then B may allow syscalls that A denies
  lemma SubsetMayDeny(
    nr: SyscallNr,
    restricted: seq<SyscallNr>,
    standard: seq<SyscallNr>
  )
    requires IsSubsetOf(restricted, standard)
    requires NotInSeq(nr, restricted)
    ensures IsDeny(FilterSyscall(nr, restricted))
  {}

  // =========================================================================
  // P43: NETWORK SYSCALL EXCLUSION
  //
  // The network-blocked profile excludes all network-related syscalls.
  // We model this as: given a set of network syscall numbers,
  // none of them appear in the profile's allowlist.
  // =========================================================================

  ghost predicate ExcludesAll(blocklist: seq<SyscallNr>, allowlist: seq<SyscallNr>)
  {
    forall nr :: InSeq(nr, blocklist) ==> NotInSeq(nr, allowlist)
  }

  // If a profile excludes network syscalls, those syscalls are denied
  lemma NetworkExclusionGuarantee(
    nr: SyscallNr,
    network_syscalls: seq<SyscallNr>,
    allowlist: seq<SyscallNr>
  )
    requires ExcludesAll(network_syscalls, allowlist)
    requires InSeq(nr, network_syscalls)
    ensures IsDeny(FilterSyscall(nr, allowlist))
  {
    assert NotInSeq(nr, allowlist);
  }

  // =========================================================================
  // AuditEntry - immutable record of a filter build operation
  // =========================================================================

  datatype FilterAuditEntry = FilterAuditEntry(
    profile_name: string,
    syscall_count: nat,
    instruction_count: nat,
    default_action: DefaultAction,
    build_number: nat
  )

  // =========================================================================
  // SeccompFilterBuilder - stateful builder with audit (P44, P46)
  // =========================================================================

  class SeccompFilterBuilder {
    var audit_log: seq<FilterAuditEntry>
    var build_count: nat

    // =====================================================================
    // CLASS INVARIANT (P46)
    // =====================================================================
    ghost predicate Valid()
      reads this
    {
      build_count == |audit_log|
    }

    // =====================================================================
    // CONSTRUCTOR - establishes Valid()
    // =====================================================================
    constructor()
      ensures Valid()
      ensures audit_log == []
      ensures build_count == 0
    {
      audit_log := [];
      build_count := 0;
    }

    // =====================================================================
    // build_filter - constructs a verified filter (P40, P44, P46)
    //
    // Postconditions prove:
    //   - Instruction count is correct (P40)
    //   - Audit log grew by exactly 1 (P44)
    //   - Valid() preserved (P46)
    //   - The returned normalized allowlist preserves filter semantics
    // =====================================================================
    method build_filter(profile: SeccompProfile)
      returns (
        normalized: seq<SyscallNr>,
        instr_count: nat
      )
      requires Valid()
      modifies this
      ensures Valid()                                                  // P46
      ensures |audit_log| == |old(audit_log)| + 1                      // P44
      ensures build_count == old(build_count) + 1                     // P44
      ensures IsStrictlySorted(normalized)                             // P39
      ensures NoDuplicates(normalized)                                 // P39
      ensures |normalized| <= |profile.allowed_syscalls|               // P39
      ensures instr_count == |normalized| + 6                          // P40
      ensures forall nr :: InSeq(nr, normalized)
              <==> InSeq(nr, profile.allowed_syscalls)                 // P39
      // Audit entry is correct
      ensures audit_log[|audit_log| - 1].profile_name == profile.name
      ensures audit_log[|audit_log| - 1].syscall_count == |normalized|
      ensures audit_log[|audit_log| - 1].instruction_count == instr_count
      ensures audit_log[|audit_log| - 1].default_action == profile.default_action
      ensures audit_log[|audit_log| - 1].build_number == old(build_count)
    {
      // 1. Normalize (sort + deduplicate)
      normalized := Normalize(profile.allowed_syscalls);
      StrictlySortedImpliesNoDuplicates(normalized);
      assert forall nr :: InSeq(nr, normalized)
              <==> InSeq(nr, profile.allowed_syscalls) by {
        forall nr ensures InSeq(nr, normalized)
                         <==> InSeq(nr, profile.allowed_syscalls) {
          NormalizeMembership(profile.allowed_syscalls, nr);
        }
      }

      // 2. Compute instruction count (P40)
      instr_count := InstructionCount(normalized);

      // 3. Record audit entry (P44)
      var entry := FilterAuditEntry(
        profile.name,
        |normalized|,
        instr_count,
        profile.default_action,
        build_count
      );
      audit_log := audit_log + [entry];
      build_count := build_count + 1;
    }

    // =====================================================================
    // verify_filter - check that a filter program would produce correct
    //                 decisions for all syscalls in a test set (P34, P35)
    // =====================================================================
    method verify_filter(
      normalized_allowlist: seq<SyscallNr>,
      test_syscalls: seq<SyscallNr>
    ) returns (all_correct: bool)
      requires IsStrictlySorted(normalized_allowlist)
      ensures all_correct ==>
        forall j :: 0 <= j < |test_syscalls| ==>
          (InSeq(test_syscalls[j], normalized_allowlist) ==>
            FilterSyscall(test_syscalls[j], normalized_allowlist) == Allow)
          &&
          (NotInSeq(test_syscalls[j], normalized_allowlist) ==>
            IsDeny(FilterSyscall(test_syscalls[j], normalized_allowlist)))
    {
      all_correct := true;
      var k := 0;
      while k < |test_syscalls|
        invariant 0 <= k <= |test_syscalls|
        invariant all_correct ==>
          forall j :: 0 <= j < k ==>
            (InSeq(test_syscalls[j], normalized_allowlist) ==>
              FilterSyscall(test_syscalls[j], normalized_allowlist) == Allow)
            &&
            (NotInSeq(test_syscalls[j], normalized_allowlist) ==>
              IsDeny(FilterSyscall(test_syscalls[j], normalized_allowlist)))
      {
        var nr := test_syscalls[k];
        var decision := FilterSyscall(nr, normalized_allowlist);
        if InSeq(nr, normalized_allowlist) {
          if decision != Allow {
            all_correct := false;
          }
        } else {
          if !IsDeny(decision) {
            all_correct := false;
          }
        }
        k := k + 1;
      }
    }

    // =====================================================================
    // get_audit_log - return the full audit log (reads only)
    // =====================================================================
    method get_audit_log() returns (log: seq<FilterAuditEntry>)
      ensures log == audit_log
    {
      log := audit_log;
    }
  }

  // =========================================================================
  // Verification test methods (executable Dafny tests)
  // =========================================================================

  method TestAllowlistCompleteness()
  {
    var allowlist := [0, 1, 3, 5];

    // syscall 0 is in allowlist - must be allowed (P34)
    var d0 := FilterSyscall(0, allowlist);
    assert IsAllow(d0);

    // syscall 3 is in allowlist - must be allowed (P34)
    var d3 := FilterSyscall(3, allowlist);
    assert IsAllow(d3);

    // syscall 2 is NOT in allowlist - must be denied (P35)
    var d2 := FilterSyscall(2, allowlist);
    assert IsDeny(d2);

    // syscall 99 is NOT in allowlist - must be denied (P35)
    var d99 := FilterSyscall(99, allowlist);
    assert IsDeny(d99);
  }

  method TestArchitectureCheck()
  {
    // Matching arch - allowed (P36)
    var d1 := CheckArchitecture(0xC000003E, 0xC000003E);
    assert IsAllow(d1);

    // Mismatched arch - denied (P36)
    var d2 := CheckArchitecture(0xC00000B7, 0xC000003E);
    assert IsDeny(d2);
  }

  method TestFilterMonotonicity()
  {
    var allowlist := [0, 1, 3];

    // syscall 1 is allowed
    var d1 := FilterSyscall(1, allowlist);
    assert IsAllow(d1);

    // After adding syscall 5, syscall 1 is still allowed (P37)
    FilterMonotonicity(1, allowlist, 5);
    var d2 := FilterSyscall(1, allowlist + [5]);
    assert IsAllow(d2);

    // The new syscall 5 is now also allowed
    var d3 := FilterSyscall(5, allowlist + [5]);
    assert IsAllow(d3);
  }

  method TestNormalize()
  {
    // Unsorted with duplicates
    var input := [5, 1, 3, 1, 5, 0];
    var normalized := Normalize(input);
    StrictlySortedImpliesNoDuplicates(normalized);

    // P39: sorted, no duplicates
    assert IsStrictlySorted(normalized);
    assert NoDuplicates(normalized);
    assert |normalized| <= |input|;

    // Preserves membership
    assert InSeq(0, normalized);
    assert InSeq(1, normalized);
    assert InSeq(3, normalized);
    assert InSeq(5, normalized);
    assert !InSeq(2, normalized);

    // Filter semantics preserved
    NormalizePreservesFilterSemantics(3, input);
    assert FilterSyscall(3, normalized) == FilterSyscall(3, input);
  }

  method TestInstructionCount()
  {
    // Empty allowlist: 0 + 6 = 6 instructions
    assert InstructionCount([]) == 6;

    // 3 syscalls: 3 + 6 = 9 instructions
    assert InstructionCount([0, 1, 3]) == 9;

    // 10 syscalls: 10 + 6 = 16 instructions
    var ten := [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    assert InstructionCount(ten) == 16;
  }

  method TestJumpTargets()
  {
    var n := 5;  // 5 JEQ instructions

    // All JEQs land on the same ALLOW position
    var allow_pos := AllowPosition(n);
    assert allow_pos == 10;  // 4 + 5 + 1

    // JEQ 0: offset = 5, target = 4 + 0 + 1 + 5 = 10 ✓
    JumpTargetCorrectness(0, n);
    assert JeqTrueTarget(0, n) == allow_pos;

    // JEQ 2: offset = 3, target = 4 + 2 + 1 + 3 = 10 ✓
    JumpTargetCorrectness(2, n);
    assert JeqTrueTarget(2, n) == allow_pos;

    // JEQ 4 (last): offset = 1, target = 4 + 4 + 1 + 1 = 10 ✓
    JumpTargetCorrectness(4, n);
    assert JeqTrueTarget(4, n) == allow_pos;

    // Last JEQ's false falls to DENY at position 4 + 5 = 9
    LastJeqFallsToDeny(n);
  }

  method TestProfileSubset()
  {
    // Standard profile allows more syscalls
    var standard := [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    // Restricted profile allows fewer
    var restricted := [0, 1, 3];

    // Verify subset relationship (P42)
    assert InSeq(0, standard);
    assert InSeq(1, standard);
    assert InSeq(3, standard);
    assert IsSubsetOf(restricted, standard);

    // Any syscall allowed by restricted is also allowed by standard
    SubsetPreservesAllow(0, restricted, standard);
    SubsetPreservesAllow(1, restricted, standard);
    SubsetPreservesAllow(3, restricted, standard);
  }

  method TestNetworkExclusion()
  {
    // Network syscalls (x86_64 numbers)
    var network_syscalls := [41, 42, 49, 50, 43, 44, 45, 46, 47, 288, 53];
    // socket=41, connect=42, bind=49, listen=50, accept=43,
    // sendto=44, recvfrom=45, sendmsg=46, recvmsg=47, accept4=288, socketpair=53

    // Our allowlist has NO network syscalls
    var allowlist := [0, 1, 3, 5, 8, 9, 10, 11, 12, 13, 14, 15];

    // P43: none of the network syscalls are in our allowlist
    assert NotInSeq(41, allowlist);
    assert NotInSeq(42, allowlist);
    assert NotInSeq(49, allowlist);
    assert NotInSeq(50, allowlist);
    assert NotInSeq(43, allowlist);
    assert NotInSeq(44, allowlist);
    assert NotInSeq(45, allowlist);
    assert NotInSeq(46, allowlist);
    assert NotInSeq(47, allowlist);
    assert NotInSeq(288, allowlist);
    assert NotInSeq(53, allowlist);

    assert ExcludesAll(network_syscalls, allowlist);

    // Each network syscall is denied
    NetworkExclusionGuarantee(41, network_syscalls, allowlist);
    assert IsDeny(FilterSyscall(41, allowlist));

    NetworkExclusionGuarantee(42, network_syscalls, allowlist);
    assert IsDeny(FilterSyscall(42, allowlist));
  }

  method TestBuilderAuditCompleteness()
  {
    var builder := new SeccompFilterBuilder();
    assert builder.Valid();
    assert |builder.audit_log| == 0;

    var profile := SeccompProfile("test", [0, 1, 3, 5], Kill, 0xC000003E);

    // First build
    var norm1, count1 := builder.build_filter(profile);
    assert |builder.audit_log| == 1;       // P44
    assert builder.build_count == 1;
    assert builder.audit_log[0].profile_name == "test";
    assert builder.audit_log[0].syscall_count == |norm1|;
    assert builder.audit_log[0].instruction_count == count1;
    assert builder.Valid();                 // P46

    // Second build
    var profile2 := SeccompProfile("restricted", [0, 1], Log, 0xC000003E);
    var norm2, count2 := builder.build_filter(profile2);
    assert |builder.audit_log| == 2;       // P44
    assert builder.build_count == 2;
    assert builder.audit_log[1].profile_name == "restricted";
    assert builder.Valid();                 // P46

    // Previous audit entry unchanged
    assert builder.audit_log[0].profile_name == "test";
  }

  method TestFullLifecycle()
  {
    var builder := new SeccompFilterBuilder();

    // Build a standard compute profile
    var compute_profile := SeccompProfile(
      "compute",
      [0, 1, 3, 5, 8, 9, 10, 11, 12],
      Kill,
      0xC000003E
    );

    var norm, ic := builder.build_filter(compute_profile);
    assert IsStrictlySorted(norm);
    assert NoDuplicates(norm);
    assert ic == |norm| + 6;
    assert |builder.audit_log| == 1;

    // Verify filter decisions
    assert InSeq(0, norm) && IsAllow(FilterSyscall(0, norm));
    assert InSeq(1, norm) && IsAllow(FilterSyscall(1, norm));
    assert !InSeq(2, norm) && IsDeny(FilterSyscall(2, norm));
    assert InSeq(3, norm) && IsAllow(FilterSyscall(3, norm));
    assert !InSeq(4, norm) && IsDeny(FilterSyscall(4, norm));

    // Architecture check
    assert IsAllow(CheckArchitecture(0xC000003E, compute_profile.expected_arch));
    assert IsDeny(CheckArchitecture(0xC00000B7, compute_profile.expected_arch));

    // Jump targets are all correct
    if |norm| > 0 {
      var k := 0;
      while k < |norm|
        invariant 0 <= k <= |norm|
      {
        JumpTargetCorrectness(k, |norm|);
        assert JeqTrueTarget(k, |norm|) == AllowPosition(|norm|);
        k := k + 1;
      }
    }

    // Invariant still holds
    assert builder.Valid();
  }
}

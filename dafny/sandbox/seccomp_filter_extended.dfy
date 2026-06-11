// =============================================================================
// seccomp_filter_extended.dfy - Extended Dafny Proofs for Phase D4 Production
// =============================================================================
//
// Extends seccomp_filter.dfy with production-critical properties:
//
//   P47 ARGUMENT CONSTRAINT SAFETY
//       If an argument constraint exists for a syscall, then the syscall
//       is only fully allowed when BOTH the syscall number is in the
//       allowlist AND the argument satisfies the constraint.
//       This enables fine-grained control (e.g., openat O_RDONLY only).
//
//   P48 FILTER COMPOSITION (INTERSECTION)
//       Combining two profiles via intersection: the resulting allowlist
//       is a subset of BOTH inputs.  Composition never expands permissions.
//       Formally: compose(A, B).allowlist ⊆ A.allowlist ∧
//                 compose(A, B).allowlist ⊆ B.allowlist
//
//   P49 FILTER SIZE BOUNDS
//       The BPF instruction count never exceeds MAX_BPF_INSTRUCTIONS (4096).
//       If the normalized allowlist has N entries, N + 6 ≤ 4096, so N ≤ 4090.
//
//   P50 ATTENUATION
//       Removing syscalls from a profile produces a strict subset.
//       Attenuation never adds permissions.
//       Formally: attenuate(profile, removals).allowlist ⊆ profile.allowlist
//
//   P51 ARGUMENT CONSTRAINT MONOTONICITY
//       Adding argument constraints can only reduce the set of allowed
//       operations.  A constrained filter is always at least as restrictive
//       as an unconstrained one.
//
//   P52 COMPLETE COVERAGE
//       For every syscall number in [0, max_nr], the filter produces
//       a defined decision (either Allow or Deny).  No gaps exist.
//
//   P53 COMPOSITION ASSOCIATIVITY
//       compose(compose(A, B), C) == compose(A, compose(B, C))
//       in terms of the resulting allowlist membership.
//
//   P54 ATTENUATION CHAIN TRANSITIVITY
//       If C is an attenuation of B, and B is an attenuation of A,
//       then C is an attenuation of A.  Attenuation chains are transitive.
//
// Verification target: Dafny 4.x
// =============================================================================

module CertiorSeccompFilterExtended {

  // =========================================================================
  // Types (shared with base module)
  // =========================================================================

  type SyscallNr = n: nat | true witness 0

  datatype FilterDecision = Allow | Deny(reason: string)

  predicate IsAllow(d: FilterDecision) { d.Allow? }
  predicate IsDeny(d: FilterDecision)  { d.Deny? }

  datatype DefaultAction = Kill | Log | ReturnErrno

  // =========================================================================
  // Membership predicates (same as base)
  // =========================================================================

  predicate InSeq(nr: SyscallNr, s: seq<SyscallNr>)
  {
    exists i :: 0 <= i < |s| && s[i] == nr
  }

  predicate NotInSeq(nr: SyscallNr, s: seq<SyscallNr>)
  {
    forall i :: 0 <= i < |s| ==> s[i] != nr
  }

  lemma InSeqEquivNotNotInSeq(nr: SyscallNr, s: seq<SyscallNr>)
    ensures InSeq(nr, s) <==> !NotInSeq(nr, s)
  {}

  // Base filter function (from P34/P35)
  function FilterSyscall(nr: SyscallNr, allowlist: seq<SyscallNr>): FilterDecision
  {
    if InSeq(nr, allowlist) then Allow
    else Deny("syscall not in allowlist")
  }

  // Subset predicate (from P42)
  ghost predicate IsSubsetOf(small: seq<SyscallNr>, large: seq<SyscallNr>)
  {
    forall nr :: InSeq(nr, small) ==> InSeq(nr, large)
  }

  // ExcludesAll (from P43)
  ghost predicate ExcludesAll(blocklist: seq<SyscallNr>, allowlist: seq<SyscallNr>)
  {
    forall nr :: InSeq(nr, blocklist) ==> NotInSeq(nr, allowlist)
  }

  // =========================================================================
  // P47: ARGUMENT CONSTRAINT SAFETY
  //
  // An ArgumentConstraint narrows a syscall's permission beyond just
  // "allowed by number".  The constrained filter returns Allow only when
  // the syscall number is in the allowlist AND the argument value
  // satisfies the constraint.
  // =========================================================================

  // Argument constraint: (syscall_nr, argument_index, allowed_values)
  datatype ArgumentConstraint = ArgumentConstraint(
    syscall_nr: SyscallNr,
    arg_index: nat,
    allowed_values: seq<nat>
  )

  predicate ArgValueAllowed(arg_val: nat, constraint: ArgumentConstraint)
  {
    exists i :: 0 <= i < |constraint.allowed_values| &&
                constraint.allowed_values[i] == arg_val
  }

  // Constrained filter: Allow only if syscall is in allowlist AND
  // if a constraint exists for this syscall, the argument is in
  // the constraint's allowed_values.
  function FilterSyscallConstrained(
    nr: SyscallNr,
    arg_val: nat,
    allowlist: seq<SyscallNr>,
    constraints: seq<ArgumentConstraint>
  ): FilterDecision
  {
    if !InSeq(nr, allowlist) then
      Deny("syscall not in allowlist")
    else
      // Check if any constraint applies to this syscall
      if HasConstraintForSyscall(nr, constraints) then
        var c := GetConstraintForSyscall(nr, constraints);
        if ArgValueAllowed(arg_val, c) then Allow
        else Deny("argument not in allowed values")
      else
        Allow  // No constraint - syscall-level allow is sufficient
  }

  // Check if any constraint targets this syscall
  predicate HasConstraintForSyscall(nr: SyscallNr, constraints: seq<ArgumentConstraint>)
  {
    exists i :: 0 <= i < |constraints| && constraints[i].syscall_nr == nr
  }

  // Get the first constraint for a given syscall
  // (deterministic due to first-match semantics)
  function GetConstraintForSyscall(
    nr: SyscallNr,
    constraints: seq<ArgumentConstraint>
  ): ArgumentConstraint
    requires HasConstraintForSyscall(nr, constraints)
  {
    if constraints[0].syscall_nr == nr then constraints[0]
    else GetConstraintForSyscall(nr, constraints[1..])
  }

  // P47: Constrained Allow implies both syscall-level and arg-level allowed
  lemma ArgumentConstraintSafety(
    nr: SyscallNr,
    arg_val: nat,
    allowlist: seq<SyscallNr>,
    constraints: seq<ArgumentConstraint>
  )
    ensures IsAllow(FilterSyscallConstrained(nr, arg_val, allowlist, constraints))
            ==> InSeq(nr, allowlist)
    ensures IsAllow(FilterSyscallConstrained(nr, arg_val, allowlist, constraints))
            && HasConstraintForSyscall(nr, constraints)
            ==> ArgValueAllowed(arg_val, GetConstraintForSyscall(nr, constraints))
  {}

  // P47 corollary: Constrained filter is at least as restrictive as base
  lemma ConstrainedIsAtLeastAsRestrictive(
    nr: SyscallNr,
    arg_val: nat,
    allowlist: seq<SyscallNr>,
    constraints: seq<ArgumentConstraint>
  )
    ensures IsAllow(FilterSyscallConstrained(nr, arg_val, allowlist, constraints))
            ==> IsAllow(FilterSyscall(nr, allowlist))
  {}

  // =========================================================================
  // P48: FILTER COMPOSITION (INTERSECTION)
  //
  // Composing two allowlists produces the intersection: only syscalls
  // present in BOTH lists are allowed.
  // =========================================================================

  // Intersection of two sequences (as sets)
  function SeqIntersection(a: seq<SyscallNr>, b: seq<SyscallNr>): seq<SyscallNr>
  {
    SeqIntersectionHelper(a, b, 0)
  }

  function SeqIntersectionHelper(
    a: seq<SyscallNr>,
    b: seq<SyscallNr>,
    idx: nat
  ): seq<SyscallNr>
    requires idx <= |a|
    decreases |a| - idx
  {
    if idx == |a| then []
    else if InSeq(a[idx], b) then
      [a[idx]] + SeqIntersectionHelper(a, b, idx + 1)
    else
      SeqIntersectionHelper(a, b, idx + 1)
  }

  lemma SeqIntersectionHelperMembership(
    a: seq<SyscallNr>,
    b: seq<SyscallNr>,
    idx: nat,
    nr: SyscallNr
  )
    requires idx <= |a|
    ensures InSeq(nr, SeqIntersectionHelper(a, b, idx)) <==>
            (exists j :: idx <= j < |a| && a[j] == nr && InSeq(nr, b))
    decreases |a| - idx
  {
    if idx == |a| {
    } else if InSeq(a[idx], b) {
      SeqIntersectionHelperMembership(a, b, idx + 1, nr);
      var rest := SeqIntersectionHelper(a, b, idx + 1);
      assert SeqIntersectionHelper(a, b, idx) == [a[idx]] + rest;
          assert InSeq(nr, SeqIntersectionHelper(a, b, idx))
             ==> (nr == a[idx] || InSeq(nr, rest));
            if nr == a[idx] {
        assert 0 <= 0 < |SeqIntersectionHelper(a, b, idx)|;
        assert SeqIntersectionHelper(a, b, idx)[0] == nr;
         assert InSeq(nr, SeqIntersectionHelper(a, b, idx));
      } else if InSeq(nr, rest) {
        var j :| 0 <= j < |rest| && rest[j] == nr;
        assert 0 <= j + 1 < |SeqIntersectionHelper(a, b, idx)|;
        assert SeqIntersectionHelper(a, b, idx)[j + 1] == nr;
         assert InSeq(nr, SeqIntersectionHelper(a, b, idx));
            }
      assert (exists j :: idx <= j < |a| && a[j] == nr && InSeq(nr, b))
             <==> ((nr == a[idx] && InSeq(nr, b))
                  || (exists j :: idx + 1 <= j < |a| && a[j] == nr && InSeq(nr, b)));
    } else {
      SeqIntersectionHelperMembership(a, b, idx + 1, nr);
      assert SeqIntersectionHelper(a, b, idx) == SeqIntersectionHelper(a, b, idx + 1);
      assert (exists j :: idx <= j < |a| && a[j] == nr && InSeq(nr, b))
             <==> (exists j :: idx + 1 <= j < |a| && a[j] == nr && InSeq(nr, b));
    }
  }

  lemma SeqIntersectionMembership(a: seq<SyscallNr>, b: seq<SyscallNr>, nr: SyscallNr)
    ensures InSeq(nr, SeqIntersection(a, b)) <==> (InSeq(nr, a) && InSeq(nr, b))
  {
    SeqIntersectionHelperMembership(a, b, 0, nr);
  }

  // P48: Composed allowlist is subset of both inputs
  lemma CompositionSubsetOfBoth(
    a: seq<SyscallNr>,
    b: seq<SyscallNr>
  )
    ensures IsSubsetOf(SeqIntersection(a, b), a)
    ensures IsSubsetOf(SeqIntersection(a, b), b)
  {
    forall nr ensures InSeq(nr, SeqIntersection(a, b)) ==> InSeq(nr, a) {
      SeqIntersectionMembership(a, b, nr);
    }
    forall nr ensures InSeq(nr, SeqIntersection(a, b)) ==> InSeq(nr, b) {
      SeqIntersectionMembership(a, b, nr);
    }
  }

  // P48 corollary: composition never expands permissions
  lemma CompositionNeverExpands(
    nr: SyscallNr,
    a: seq<SyscallNr>,
    b: seq<SyscallNr>
  )
    ensures IsAllow(FilterSyscall(nr, SeqIntersection(a, b)))
            ==> IsAllow(FilterSyscall(nr, a))
    ensures IsAllow(FilterSyscall(nr, SeqIntersection(a, b)))
            ==> IsAllow(FilterSyscall(nr, b))
  {
    SeqIntersectionMembership(a, b, nr);
  }

  // P48 corollary: if denied by either, denied by composition
  lemma CompositionDeniedByEither(
    nr: SyscallNr,
    a: seq<SyscallNr>,
    b: seq<SyscallNr>
  )
    requires IsDeny(FilterSyscall(nr, a)) || IsDeny(FilterSyscall(nr, b))
    ensures IsDeny(FilterSyscall(nr, SeqIntersection(a, b)))
  {
    SeqIntersectionMembership(a, b, nr);
    if IsDeny(FilterSyscall(nr, a)) {
      assert NotInSeq(nr, a);
      InSeqEquivNotNotInSeq(nr, a);
      assert !InSeq(nr, a);
      // SeqIntersection requires InSeq(nr, a) for Allow
      assert !InSeq(nr, SeqIntersection(a, b));
    } else {
      assert IsDeny(FilterSyscall(nr, b));
      assert NotInSeq(nr, b);
      InSeqEquivNotNotInSeq(nr, b);
      assert !InSeq(nr, b);
      assert !InSeq(nr, SeqIntersection(a, b));
    }
  }

  // =========================================================================
  // P49: FILTER SIZE BOUNDS
  //
  // The BPF program must not exceed the kernel's maximum (4096 instructions).
  // For N syscalls: N + 6 ≤ 4096, so N ≤ 4090.
  // =========================================================================

  const MAX_BPF_INSTRUCTIONS: nat := 4096
  const MAX_ALLOWLIST_SIZE: nat := 4090  // MAX_BPF_INSTRUCTIONS - 6

  function InstructionCount(allowlist: seq<SyscallNr>): nat
  {
    |allowlist| + 6
  }

  predicate FilterSizeValid(allowlist: seq<SyscallNr>)
  {
    InstructionCount(allowlist) <= MAX_BPF_INSTRUCTIONS
  }

  // P49: If allowlist fits, instruction count is within kernel limit
  lemma FilterSizeBound(allowlist: seq<SyscallNr>)
    requires |allowlist| <= MAX_ALLOWLIST_SIZE
    ensures InstructionCount(allowlist) <= MAX_BPF_INSTRUCTIONS
  {}

  // P49 corollary: Composition cannot produce oversized filter
  // (since |intersection| ≤ min(|a|, |b|))
  lemma CompositionSizeBound(
    a: seq<SyscallNr>,
    b: seq<SyscallNr>
  )
    requires |a| <= MAX_ALLOWLIST_SIZE
    ensures |SeqIntersection(a, b)| <= |a|
    ensures |SeqIntersection(a, b)| <= MAX_ALLOWLIST_SIZE
  {
    // SeqIntersection picks elements from a, so |result| ≤ |a|
    SeqIntersectionSizeBound(a, b);
  }

  lemma SeqIntersectionSizeBound(a: seq<SyscallNr>, b: seq<SyscallNr>)
    ensures |SeqIntersection(a, b)| <= |a|
  {
    SeqIntersectionSizeBoundHelper(a, b, 0);
  }

  lemma SeqIntersectionSizeBoundHelper(
    a: seq<SyscallNr>,
    b: seq<SyscallNr>,
    idx: nat
  )
    requires idx <= |a|
    decreases |a| - idx
    ensures |SeqIntersectionHelper(a, b, idx)| <= |a| - idx
  {
    if idx == |a| {
      // base case: empty
    } else if InSeq(a[idx], b) {
      SeqIntersectionSizeBoundHelper(a, b, idx + 1);
    } else {
      SeqIntersectionSizeBoundHelper(a, b, idx + 1);
    }
  }

  // =========================================================================
  // P50: ATTENUATION
  //
  // Removing syscalls from an allowlist produces a strict subset.
  // Attenuation never adds permissions.
  // =========================================================================

  // Remove elements from a sequence
  function Attenuate(
    allowlist: seq<SyscallNr>,
    removals: seq<SyscallNr>
  ): seq<SyscallNr>
    ensures |Attenuate(allowlist, removals)| <= |allowlist|
  {
    AttenuateHelper(allowlist, removals, 0)
  }

  function AttenuateHelper(
    allowlist: seq<SyscallNr>,
    removals: seq<SyscallNr>,
    idx: nat
  ): seq<SyscallNr>
    requires idx <= |allowlist|
    decreases |allowlist| - idx
    ensures |AttenuateHelper(allowlist, removals, idx)| <= |allowlist| - idx
  {
    if idx == |allowlist| then []
    else if InSeq(allowlist[idx], removals) then
      AttenuateHelper(allowlist, removals, idx + 1)
    else
      [allowlist[idx]] + AttenuateHelper(allowlist, removals, idx + 1)
  }

  lemma AttenuateHelperMembership(
    allowlist: seq<SyscallNr>,
    removals: seq<SyscallNr>,
    idx: nat,
    nr: SyscallNr
  )
    requires idx <= |allowlist|
    ensures InSeq(nr, AttenuateHelper(allowlist, removals, idx)) ==>
            (exists j :: idx <= j < |allowlist| && allowlist[j] == nr)
    ensures InSeq(nr, AttenuateHelper(allowlist, removals, idx)) ==>
            NotInSeq(nr, removals)
    decreases |allowlist| - idx
  {
    if idx == |allowlist| {
    } else if InSeq(allowlist[idx], removals) {
      AttenuateHelperMembership(allowlist, removals, idx + 1, nr);
    } else {
      AttenuateHelperMembership(allowlist, removals, idx + 1, nr);
    }
  }

  lemma AttenuateMembership(
    allowlist: seq<SyscallNr>,
    removals: seq<SyscallNr>,
    nr: SyscallNr
  )
    ensures InSeq(nr, Attenuate(allowlist, removals)) ==> InSeq(nr, allowlist)
    ensures InSeq(nr, Attenuate(allowlist, removals)) ==> NotInSeq(nr, removals)
  {
    AttenuateHelperMembership(allowlist, removals, 0, nr);
  }

  lemma GetConstraintForSyscallPreservedOnAppend(
    nr: SyscallNr,
    constraints: seq<ArgumentConstraint>,
    new_constraint: ArgumentConstraint
  )
    requires HasConstraintForSyscall(nr, constraints)
    ensures HasConstraintForSyscall(nr, constraints + [new_constraint])
    ensures GetConstraintForSyscall(nr, constraints + [new_constraint])
            == GetConstraintForSyscall(nr, constraints)
    decreases |constraints|
  {
    var i :| 0 <= i < |constraints| && constraints[i].syscall_nr == nr;
    assert 0 <= i < |constraints + [new_constraint]|;
    assert (constraints + [new_constraint])[i].syscall_nr == nr;
    assert HasConstraintForSyscall(nr, constraints + [new_constraint]);
    if constraints[0].syscall_nr == nr {
    } else {
      assert HasConstraintForSyscall(nr, constraints[1..]);
      GetConstraintForSyscallPreservedOnAppend(nr, constraints[1..], new_constraint);
          assert constraints + [new_constraint]
            == [constraints[0]] + (constraints[1..] + [new_constraint]);
          assert GetConstraintForSyscall(nr, constraints + [new_constraint])
            == GetConstraintForSyscall(nr, constraints[1..] + [new_constraint]);
          assert GetConstraintForSyscall(nr, constraints)
            == GetConstraintForSyscall(nr, constraints[1..]);
    }
  }

  // P50: Attenuated allowlist is a subset of the original
  lemma AttenuationIsSubset(
    allowlist: seq<SyscallNr>,
    removals: seq<SyscallNr>
  )
    ensures IsSubsetOf(Attenuate(allowlist, removals), allowlist)
  {
    forall nr ensures InSeq(nr, Attenuate(allowlist, removals)) ==> InSeq(nr, allowlist) {
      AttenuateMembership(allowlist, removals, nr);
    }
  }

  // P50 corollary: Attenuation never allows anything the original denied
  lemma AttenuationNeverExpands(
    nr: SyscallNr,
    allowlist: seq<SyscallNr>,
    removals: seq<SyscallNr>
  )
    ensures IsAllow(FilterSyscall(nr, Attenuate(allowlist, removals)))
            ==> IsAllow(FilterSyscall(nr, allowlist))
  {
    AttenuateMembership(allowlist, removals, nr);
  }

  // P50 corollary: Removed syscalls are denied in attenuated filter
  lemma AttenuationRemovesDenied(
    nr: SyscallNr,
    allowlist: seq<SyscallNr>,
    removals: seq<SyscallNr>
  )
    requires InSeq(nr, removals)
    ensures IsDeny(FilterSyscall(nr, Attenuate(allowlist, removals)))
  {
    AttenuateMembership(allowlist, removals, nr);
    // Attenuate ensures all results have NotInSeq(nr, removals)
    // Since nr is in removals, it cannot be in the attenuated list
    assert NotInSeq(nr, Attenuate(allowlist, removals))
      || !InSeq(nr, Attenuate(allowlist, removals));
    if InSeq(nr, Attenuate(allowlist, removals)) {
      assert NotInSeq(nr, removals);  // from Attenuate postcondition
      assert false;  // contradiction with requires
    }
  }

  // =========================================================================
  // P51: ARGUMENT CONSTRAINT MONOTONICITY
  //
  // Adding argument constraints can only reduce allowed operations.
  // =========================================================================

  // P51: Unconstrained filter is at least as permissive as constrained
  lemma ArgumentConstraintMonotonicity(
    nr: SyscallNr,
    arg_val: nat,
    allowlist: seq<SyscallNr>,
    constraints: seq<ArgumentConstraint>,
    new_constraint: ArgumentConstraint
  )
    ensures IsAllow(FilterSyscallConstrained(nr, arg_val, allowlist,
                                             constraints + [new_constraint]))
            ==> IsAllow(FilterSyscallConstrained(nr, arg_val, allowlist, constraints))
  {
    if IsAllow(FilterSyscallConstrained(nr, arg_val, allowlist,
                                        constraints + [new_constraint])) {
      ArgumentConstraintSafety(nr, arg_val, allowlist, constraints + [new_constraint]);
      assert InSeq(nr, allowlist);
      if HasConstraintForSyscall(nr, constraints) {
        GetConstraintForSyscallPreservedOnAppend(nr, constraints, new_constraint);
        assert IsAllow(FilterSyscallConstrained(nr, arg_val, allowlist,
                                                constraints + [new_constraint]))
               && HasConstraintForSyscall(nr, constraints + [new_constraint]);
        assert ArgValueAllowed(arg_val,
                               GetConstraintForSyscall(nr, constraints + [new_constraint]));
        assert ArgValueAllowed(arg_val, GetConstraintForSyscall(nr, constraints));
      }
      assert IsAllow(FilterSyscallConstrained(nr, arg_val, allowlist, constraints));
    }
  }

  // =========================================================================
  // P52: COMPLETE COVERAGE
  //
  // For every syscall number in [0, max_nr], the filter produces
  // a defined decision.  No gap exists.
  // =========================================================================

  // P52: Every syscall number has a decision
  lemma CompleteCoverage(max_nr: nat, allowlist: seq<SyscallNr>)
    ensures forall nr: SyscallNr :: nr <= max_nr ==>
              (IsAllow(FilterSyscall(nr, allowlist)) ||
               IsDeny(FilterSyscall(nr, allowlist)))
  {
    // FilterSyscall always returns either Allow or Deny - trivially complete.
    // This lemma documents the property explicitly for audit purposes.
  }

  // =========================================================================
  // P53: COMPOSITION ASSOCIATIVITY
  //
  // compose(compose(A, B), C) has the same membership as compose(A, compose(B, C))
  // =========================================================================

  lemma CompositionAssociativity(
    nr: SyscallNr,
    a: seq<SyscallNr>,
    b: seq<SyscallNr>,
    c: seq<SyscallNr>
  )
    ensures InSeq(nr, SeqIntersection(SeqIntersection(a, b), c)) <==>
            InSeq(nr, SeqIntersection(a, SeqIntersection(b, c)))
  {
    SeqIntersectionMembership(SeqIntersection(a, b), c, nr);
    SeqIntersectionMembership(a, b, nr);
    SeqIntersectionMembership(a, SeqIntersection(b, c), nr);
    SeqIntersectionMembership(b, c, nr);
  }

  // =========================================================================
  // P54: ATTENUATION CHAIN TRANSITIVITY
  //
  // If C = attenuate(B, r2) and B = attenuate(A, r1), then
  // C.allowlist ⊆ A.allowlist (transitivity).
  // =========================================================================

  lemma AttenuationChainTransitivity(
    a: seq<SyscallNr>,
    r1: seq<SyscallNr>,
    r2: seq<SyscallNr>
  )
    ensures IsSubsetOf(
              Attenuate(Attenuate(a, r1), r2),
              a)
  {
    // Attenuate(a, r1) ⊆ a              (from P50)
    // Attenuate(Attenuate(a, r1), r2) ⊆ Attenuate(a, r1)  (from P50)
    // By transitivity of ⊆: result ⊆ a
    AttenuationIsSubset(a, r1);
    AttenuationIsSubset(Attenuate(a, r1), r2);
    SubsetTransitivity(
      Attenuate(Attenuate(a, r1), r2),
      Attenuate(a, r1),
      a
    );
  }

  lemma SubsetTransitivity(
    a: seq<SyscallNr>,
    b: seq<SyscallNr>,
    c: seq<SyscallNr>
  )
    requires IsSubsetOf(a, b)
    requires IsSubsetOf(b, c)
    ensures IsSubsetOf(a, c)
  {}

  // =========================================================================
  // Executable test methods
  // =========================================================================

  method TestArgumentConstraintSafety()
  {
    var allowlist := [0, 1, 3, 5, 257]; // read, write, close, fstat, openat
    // Constraint: openat (257) only with O_RDONLY (0)
    var constraints := [ArgumentConstraint(257, 2, [0])]; // arg 2 = flags

    // openat with O_RDONLY → allowed
    var d1 := FilterSyscallConstrained(257, 0, allowlist, constraints);
    assert IsAllow(d1);

    // openat with O_WRONLY (1) → denied
    var d2 := FilterSyscallConstrained(257, 1, allowlist, constraints);
    assert IsDeny(d2);

    // read (0) has no constraint → allowed
    var d3 := FilterSyscallConstrained(0, 999, allowlist, constraints);
    assert IsAllow(d3);

    // unlisted syscall → denied regardless of args
    var d4 := FilterSyscallConstrained(42, 0, allowlist, constraints);
    assert IsDeny(d4);
  }

  method TestFilterComposition()
  {
    var a := [0, 1, 3, 5, 8, 9];
    var b := [0, 1, 5, 10, 11];

    var composed := SeqIntersection(a, b);

    // Only 0, 1, 5 are in both
    assert InSeq(0, composed);
    assert InSeq(1, composed);
    assert InSeq(5, composed);
    assert !InSeq(3, composed);   // only in a
    assert !InSeq(8, composed);   // only in a
    assert !InSeq(10, composed);  // only in b

    // P48: subset of both
    CompositionSubsetOfBoth(a, b);
    assert IsSubsetOf(composed, a);
    assert IsSubsetOf(composed, b);
  }

  method TestFilterSizeBounds()
  {
    // 4090 syscalls → 4096 instructions (at limit)
    assert InstructionCount([]) == 6;
    assert FilterSizeValid([]);

    // Build a 10-element list for testing
    var ten := [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    assert InstructionCount(ten) == 16;
    assert FilterSizeValid(ten);
  }

  method TestAttenuation()
  {
    var allowlist := [0, 1, 3, 5, 8, 9, 10, 11, 12];
    var removals := [8, 9, 10];  // remove these

    var attenuated := Attenuate(allowlist, removals);

    // Removed syscalls are denied
    AttenuationRemovesDenied(8, allowlist, removals);
    assert IsDeny(FilterSyscall(8, attenuated));

    AttenuationRemovesDenied(9, allowlist, removals);
    assert IsDeny(FilterSyscall(9, attenuated));

    // Retained syscalls are still allowed
    assert InSeq(0, attenuated);
    assert InSeq(1, attenuated);
    assert InSeq(3, attenuated);
    assert InSeq(5, attenuated);
    assert InSeq(11, attenuated);
    assert InSeq(12, attenuated);

    // P50: subset of original
    AttenuationIsSubset(allowlist, removals);
    assert IsSubsetOf(attenuated, allowlist);
  }

  method TestAttenuationChain()
  {
    var a := [0, 1, 3, 5, 8, 9, 10, 11, 12];
    var r1 := [8, 9, 10];
    var r2 := [3, 5];

    // First attenuation
    var b := Attenuate(a, r1);
    // Second attenuation
    var c := Attenuate(b, r2);

    // P54: c ⊆ a (transitivity)
    AttenuationChainTransitivity(a, r1, r2);
    assert IsSubsetOf(c, a);

    // Verify specific elements
    assert InSeq(0, c);
    assert InSeq(1, c);
    assert !InSeq(3, c);   // removed in r2
    assert !InSeq(8, c);   // removed in r1
    assert InSeq(11, c);
    assert InSeq(12, c);
  }

  method TestCompleteCoverage()
  {
    var allowlist := [0, 1, 3];

    // Every nr in [0, 10] has a decision
    CompleteCoverage(10, allowlist);

    // Verify specific decisions
    assert IsAllow(FilterSyscall(0, allowlist));
    assert IsAllow(FilterSyscall(1, allowlist));
    assert IsDeny(FilterSyscall(2, allowlist));
    assert IsAllow(FilterSyscall(3, allowlist));
    assert IsDeny(FilterSyscall(4, allowlist));
    assert IsDeny(FilterSyscall(10, allowlist));
  }

  method TestCompositionAssociativity()
  {
    var a := [0, 1, 2, 3, 4, 5];
    var b := [0, 2, 4, 6, 8];
    var c := [0, 1, 4, 7, 8];

    // (A ∩ B) ∩ C should have same membership as A ∩ (B ∩ C)
    // Both should contain only {0, 4}
    CompositionAssociativity(0, a, b, c);
    CompositionAssociativity(4, a, b, c);
    CompositionAssociativity(1, a, b, c);
    CompositionAssociativity(2, a, b, c);
  }
}

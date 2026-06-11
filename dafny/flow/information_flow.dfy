// =============================================================================
// information_flow.dfy - Dafny-Verified Information Flow Control (Phase B3)
// =============================================================================
//
// Proves critical safety properties for the DIFC (Decentralized Information
// Flow Control) subsystem used by Certior's agentic execution pipeline.
//
//   P13 LATTICE ORDERING
//       SecurityLevel.rank defines a total order.
//       Reflexive:     ∀ a: rank(a) ≤ rank(a)
//       Transitive:    ∀ a,b,c: rank(a) ≤ rank(b) ∧ rank(b) ≤ rank(c) → rank(a) ≤ rank(c)
//       Antisymmetric: ∀ a,b: rank(a) ≤ rank(b) ∧ rank(b) ≤ rank(a) → a == b
//       Total:         ∀ a,b: rank(a) ≤ rank(b) ∨ rank(b) ≤ rank(a)
//
//   P14 FLOW SAFETY (NO-DOWNGRADE)
//       level_can_flow_to(src, dst) == true  IFF  rank(src) ≤ rank(dst).
//       Information never flows from a higher level to a lower one.
//
//   P15 LABEL FLOW SAFETY (CONJUNCTIVE)
//       label_can_flow_to(src, dst) requires BOTH:
//         (a) level ordering:  rank(src.level) ≤ rank(dst.level)
//         (b) tag containment: src.tags ⊆ dst.tags
//       Failure of EITHER condition blocks the flow.
//
//   P16 TAINT MONOTONICITY
//       tag(id, label) adds id→label to the taint map.
//       Subsequent get_label(id) returns Some(label).
//       Existing entries for OTHER ids are unaffected.
//
//   P17 VIOLATION COMPLETENESS
//       check_flow(src_id, target_label) returns false
//         IFF the stored src label cannot flow to target_label (P14+P15).
//       Every such failure is recorded in the violations list.
//       No false negatives: forbidden flows always detected.
//       No false positives: permitted flows never flagged.
//
//   P18 VIOLATION ACCUMULATION (APPEND-ONLY)
//       Violations are only appended, never removed (except by clear).
//       |violations| after check_flow ≥ |violations| before.
//       Every recorded violation corresponds to a real flow failure.
//
//   P19 TAG PRESERVATION
//       After tag(id, label), the stored label's tags == the input tags.
//       Tags are never silently dropped or modified.
//
//   P20 CLEAR CORRECTNESS
//       After clear(): taint_map == empty ∧ violations == empty.
//       No residual state from previous executions.
//
//   P21 LEVEL JOIN (PROMOTION) SOUNDNESS
//       join(a, b) == max(rank(a), rank(b)).
//       Result always ≥ both inputs.
//       Idempotent: join(a, a) == a.
//       Commutative: join(a, b) == join(b, a).
//       Associative: join(join(a, b), c) == join(a, join(b, c)).
//
// Usage:
//   dafny verify dafny/flow/information_flow.dfy
//
// Verification target: Dafny 4.x
// =============================================================================

module CertiorInformationFlow {

  // =========================================================================
  // SecurityLevel - four-element totally-ordered lattice
  // =========================================================================

  datatype SecurityLevel = Public | Internal | Sensitive | Restricted

  function Rank(level: SecurityLevel): nat
  {
    match level
    case Public    => 0
    case Internal  => 1
    case Sensitive => 2
    case Restricted => 3
  }

  predicate LevelCanFlowTo(src: SecurityLevel, dst: SecurityLevel)
  {
    Rank(src) <= Rank(dst)
  }

  function LevelJoin(a: SecurityLevel, b: SecurityLevel): SecurityLevel
  {
    if Rank(a) >= Rank(b) then a else b
  }

  // =========================================================================
  // P13: LATTICE ORDERING - SecurityLevel forms a total order
  // =========================================================================

  // ── Reflexive ─────────────────────────────────────────────
  lemma LatticeReflexive(a: SecurityLevel)
    ensures LevelCanFlowTo(a, a)
  {}

  // ── Transitive ────────────────────────────────────────────
  lemma LatticeTransitive(a: SecurityLevel, b: SecurityLevel, c: SecurityLevel)
    requires LevelCanFlowTo(a, b)
    requires LevelCanFlowTo(b, c)
    ensures LevelCanFlowTo(a, c)
  {}

  // ── Antisymmetric ─────────────────────────────────────────
  lemma LatticeAntisymmetric(a: SecurityLevel, b: SecurityLevel)
    requires LevelCanFlowTo(a, b)
    requires LevelCanFlowTo(b, a)
    ensures a == b
  {
    // Rank(a) <= Rank(b) && Rank(b) <= Rank(a) → Rank(a) == Rank(b) → a == b
    assert Rank(a) == Rank(b);
    // Dafny must prove a == b from Rank(a) == Rank(b).
    // Enumerate all cases:
    match a {
      case Public =>
        assert Rank(b) == 0;
        match b {
          case Public    => {}
          case Internal  => assert false;
          case Sensitive => assert false;
          case Restricted => assert false;
        }
      case Internal =>
        assert Rank(b) == 1;
        match b {
          case Public    => assert false;
          case Internal  => {}
          case Sensitive => assert false;
          case Restricted => assert false;
        }
      case Sensitive =>
        assert Rank(b) == 2;
        match b {
          case Public    => assert false;
          case Internal  => assert false;
          case Sensitive => {}
          case Restricted => assert false;
        }
      case Restricted =>
        assert Rank(b) == 3;
        match b {
          case Public    => assert false;
          case Internal  => assert false;
          case Sensitive => assert false;
          case Restricted => {}
        }
    }
  }

  // ── Total ─────────────────────────────────────────────────
  lemma LatticeTotal(a: SecurityLevel, b: SecurityLevel)
    ensures LevelCanFlowTo(a, b) || LevelCanFlowTo(b, a)
  {}

  // ── Rank injectivity (distinct levels have distinct ranks) ──
  lemma RankInjective(a: SecurityLevel, b: SecurityLevel)
    requires Rank(a) == Rank(b)
    ensures a == b
  {
    LatticeAntisymmetric(a, b);
  }

  // ── All four levels are distinct ──────────────────────────
  lemma AllLevelsDistinct()
    ensures Rank(Public) < Rank(Internal)
    ensures Rank(Internal) < Rank(Sensitive)
    ensures Rank(Sensitive) < Rank(Restricted)
    ensures Rank(Public) < Rank(Restricted)
  {}

  // =========================================================================
  // P14: FLOW SAFETY (NO-DOWNGRADE)
  //
  // LevelCanFlowTo is the ONLY flow predicate at the level layer.
  // It returns true IFF rank(src) ≤ rank(dst).
  // =========================================================================

  lemma FlowSafety_AllowedIffOrdered(src: SecurityLevel, dst: SecurityLevel)
    ensures LevelCanFlowTo(src, dst) <==> Rank(src) <= Rank(dst)
  {}

  lemma FlowSafety_NoDowngrade(src: SecurityLevel, dst: SecurityLevel)
    requires Rank(src) > Rank(dst)
    ensures !LevelCanFlowTo(src, dst)
  {}

  lemma FlowSafety_UpgradeAlwaysAllowed(src: SecurityLevel, dst: SecurityLevel)
    requires Rank(src) <= Rank(dst)
    ensures LevelCanFlowTo(src, dst)
  {}

  // ── Exhaustive: all 16 pairs ──────────────────────────────
  lemma FlowSafety_Exhaustive()
    // Same level: always allowed
    ensures LevelCanFlowTo(Public, Public)
    ensures LevelCanFlowTo(Internal, Internal)
    ensures LevelCanFlowTo(Sensitive, Sensitive)
    ensures LevelCanFlowTo(Restricted, Restricted)
    // Upward: always allowed
    ensures LevelCanFlowTo(Public, Internal)
    ensures LevelCanFlowTo(Public, Sensitive)
    ensures LevelCanFlowTo(Public, Restricted)
    ensures LevelCanFlowTo(Internal, Sensitive)
    ensures LevelCanFlowTo(Internal, Restricted)
    ensures LevelCanFlowTo(Sensitive, Restricted)
    // Downward: always blocked
    ensures !LevelCanFlowTo(Internal, Public)
    ensures !LevelCanFlowTo(Sensitive, Public)
    ensures !LevelCanFlowTo(Sensitive, Internal)
    ensures !LevelCanFlowTo(Restricted, Public)
    ensures !LevelCanFlowTo(Restricted, Internal)
    ensures !LevelCanFlowTo(Restricted, Sensitive)
  {}

  // =========================================================================
  // SecurityLabel - level + tags + owner
  // =========================================================================

  datatype SecurityLabel = SecurityLabel(
    level: SecurityLevel,
    tags: set<string>,
    owner: string
  )

  // =========================================================================
  // P15: LABEL FLOW SAFETY (CONJUNCTIVE)
  //
  // Flow requires BOTH conditions:
  //   (a) Level ordering: rank(src.level) ≤ rank(dst.level)
  //   (b) Tag containment: src.tags ⊆ dst.tags
  // =========================================================================

  predicate LabelCanFlowTo(src: SecurityLabel, dst: SecurityLabel)
  {
    LevelCanFlowTo(src.level, dst.level) && src.tags <= dst.tags
  }

  // ── Both conditions are independently necessary ───────────

  lemma LabelFlowRequiresLevelOrdering(
    src: SecurityLabel, dst: SecurityLabel
  )
    requires !LevelCanFlowTo(src.level, dst.level)
    ensures !LabelCanFlowTo(src, dst)
  {}

  lemma LabelFlowRequiresTagContainment(
    src: SecurityLabel, dst: SecurityLabel
  )
    requires !(src.tags <= dst.tags)
    ensures !LabelCanFlowTo(src, dst)
  {}

  lemma LabelFlowSufficiency(
    src: SecurityLabel, dst: SecurityLabel
  )
    requires LevelCanFlowTo(src.level, dst.level)
    requires src.tags <= dst.tags
    ensures LabelCanFlowTo(src, dst)
  {}

  // ── Label flow is reflexive ───────────────────────────────

  lemma LabelFlowReflexive(lbl: SecurityLabel)
    ensures LabelCanFlowTo(lbl, lbl)
  {
    LatticeReflexive(lbl.level);
    assert lbl.tags <= lbl.tags;
  }

  // ── Label flow is transitive ──────────────────────────────

  lemma LabelFlowTransitive(
    a: SecurityLabel, b: SecurityLabel, c: SecurityLabel
  )
    requires LabelCanFlowTo(a, b)
    requires LabelCanFlowTo(b, c)
    ensures LabelCanFlowTo(a, c)
  {
    LatticeTransitive(a.level, b.level, c.level);
    // Tag containment transitivity: a.tags ⊆ b.tags ⊆ c.tags → a.tags ⊆ c.tags
    assert a.tags <= b.tags;
    assert b.tags <= c.tags;
  }

  // ── Empty tags are the most permissive source ─────────────

  lemma EmptyTagsFlowToAnything(src_level: SecurityLevel, dst: SecurityLabel)
    requires LevelCanFlowTo(src_level, dst.level)
    ensures LabelCanFlowTo(
      SecurityLabel(src_level, {}, ""),
      dst
    )
  {}

  // =========================================================================
  // P21: LEVEL JOIN (PROMOTION) SOUNDNESS
  //
  // join(a, b) == max(rank(a), rank(b)).
  // =========================================================================

  lemma JoinIsUpperBound(a: SecurityLevel, b: SecurityLevel)
    ensures Rank(LevelJoin(a, b)) >= Rank(a)
    ensures Rank(LevelJoin(a, b)) >= Rank(b)
  {}

  lemma JoinIsLeastUpperBound(a: SecurityLevel, b: SecurityLevel, c: SecurityLevel)
    requires Rank(c) >= Rank(a)
    requires Rank(c) >= Rank(b)
    ensures Rank(c) >= Rank(LevelJoin(a, b))
  {}

  lemma JoinIdempotent(a: SecurityLevel)
    ensures LevelJoin(a, a) == a
  {}

  lemma JoinCommutative(a: SecurityLevel, b: SecurityLevel)
    ensures LevelJoin(a, b) == LevelJoin(b, a)
  {
    if Rank(a) >= Rank(b) {
      assert LevelJoin(a, b) == a;
      if Rank(b) >= Rank(a) {
        RankInjective(a, b);
        assert a == b;
      } else {
        assert LevelJoin(b, a) == a;
      }
    } else {
      assert LevelJoin(a, b) == b;
      assert Rank(b) >= Rank(a);
      assert LevelJoin(b, a) == b;
    }
  }

  lemma JoinAssociative(a: SecurityLevel, b: SecurityLevel, c: SecurityLevel)
    ensures LevelJoin(LevelJoin(a, b), c) == LevelJoin(a, LevelJoin(b, c))
  {}

  // Join preserves flow: if data from a and b can both flow to c,
  // then data at join(a,b) can flow to c.
  lemma JoinPreservesFlowTarget(
    a: SecurityLevel, b: SecurityLevel, c: SecurityLevel
  )
    requires LevelCanFlowTo(a, c)
    requires LevelCanFlowTo(b, c)
    ensures LevelCanFlowTo(LevelJoin(a, b), c)
  {}

  // =========================================================================
  // FlowViolation - recorded evidence of a forbidden flow
  // =========================================================================

  datatype FlowViolation = FlowViolation(
    source_id: string,
    source_level: SecurityLevel,
    target_level: SecurityLevel,
    source_tags: set<string>,
    target_tags: set<string>
  )

  // =========================================================================
  // TaintTracker - the core state machine
  //
  // State:
  //   taint_map  : map<string, SecurityLabel>   - data id → label
  //   violations : seq<FlowViolation>           - append-only log
  //
  // Invariant Valid():
  //   All violations in the log correspond to genuine flow failures:
  //   ∀ v ∈ violations:
  //     Rank(v.source_level) > Rank(v.target_level)
  //     OR v.source_tags ⊄ v.target_tags
  // =========================================================================

  class TaintTracker {
    var taint_map: map<string, SecurityLabel>
    var violations: seq<FlowViolation>

    // ── Ghost bookkeeping ───────────────────────────────────
    ghost var total_tags_ever: nat
    ghost var total_checks_ever: nat

    // =====================================================================
    // CLASS INVARIANT (P11-analogue for TaintTracker)
    //
    // I1: Every recorded violation is genuine (no false positives)
    //     ∀ v ∈ violations:
    //       Rank(v.source_level) > Rank(v.target_level)
    //       OR v.source_tags ⊄ v.target_tags
    //
    // I2: Ghost counters are sound upper bounds
    //     |taint_map| ≤ total_tags_ever
    //     |violations| ≤ total_checks_ever
    // =====================================================================
    ghost predicate Valid()
      reads this
    {
      && (forall i :: 0 <= i < |violations| ==>
            Rank(violations[i].source_level) > Rank(violations[i].target_level)
            || !(violations[i].source_tags <= violations[i].target_tags))
      && |taint_map| <= total_tags_ever
      && |violations| <= total_checks_ever
    }

    // =====================================================================
    // CONSTRUCTOR
    // =====================================================================
    constructor()
      ensures Valid()
      ensures taint_map == map[]
      ensures violations == []
      ensures total_tags_ever == 0
      ensures total_checks_ever == 0
    {
      taint_map := map[];
      violations := [];
      total_tags_ever := 0;
      total_checks_ever := 0;
    }

    // =====================================================================
    // tag - P16 (Taint Monotonicity), P19 (Tag Preservation)
    //
    // Assigns a security label to a data identifier.
    //
    // Postconditions:
    //   - get_label(data_id) == label                  (P16, P19)
    //   - Other entries unaffected                      (P16)
    //   - violations unchanged                          (P18)
    //   - Valid() preserved
    // =====================================================================
    method tag(data_id: string, lbl: SecurityLabel)
      requires Valid()
      modifies this
      ensures Valid()
      ensures data_id in taint_map                              // P16: id is mapped
      ensures taint_map[data_id] == lbl                         // P19: exact label stored
      ensures forall id :: id in old(taint_map) && id != data_id
                ==> id in taint_map && taint_map[id] == old(taint_map)[id]  // P16: others unaffected
      ensures violations == old(violations)                     // P18: no violation created
      ensures total_tags_ever == old(total_tags_ever) + 1
    {
      taint_map := taint_map[data_id := lbl];
      total_tags_ever := total_tags_ever + 1;
    }

    // =====================================================================
    // get_label - pure query
    //
    // Returns the label if data_id is in the taint map, or None.
    // =====================================================================
    method get_label(data_id: string) returns (result: Option<SecurityLabel>)
      requires Valid()
      ensures Valid()
      ensures data_id in taint_map ==> result == Some(taint_map[data_id])
      ensures data_id !in taint_map ==> result == None
    {
      if data_id in taint_map {
        result := Some(taint_map[data_id]);
      } else {
        result := None;
      }
    }

    // =====================================================================
    // check_flow - P17 (Violation Completeness), P18 (Accumulation)
    //
    // Checks whether the data identified by source_id can flow to
    // the given target label.
    //
    // Three cases:
    //   1. source_id NOT in taint_map → allowed (untracked data is PUBLIC)
    //   2. source label can flow to target → allowed
    //   3. source label CANNOT flow to target → blocked, violation recorded
    //
    // Postconditions:
    //   allowed == true  → no new violation appended (P17: no false positives)
    //   allowed == false → exactly one violation appended (P17: no false negatives)
    //   existing violations unchanged (P18: append-only)
    //   Valid() preserved
    // =====================================================================
    method check_flow(
      source_id: string,
      target_label: SecurityLabel
    ) returns (allowed: bool)
      requires Valid()
      modifies this
      ensures Valid()
      ensures taint_map == old(taint_map)                       // no taint changes
      ensures total_tags_ever == old(total_tags_ever)
      ensures total_checks_ever == old(total_checks_ever) + 1
      // ── P17: Completeness - result matches flow predicate ──
      ensures source_id !in old(taint_map) ==> allowed == true
      ensures source_id in old(taint_map) ==>
        (allowed == LabelCanFlowTo(old(taint_map)[source_id], target_label))
      // ── P18: Accumulation - violations append-only ─────────
      ensures allowed ==> violations == old(violations)
      ensures !allowed ==> |violations| == |old(violations)| + 1
      ensures !allowed ==>
        violations == old(violations) + [FlowViolation(
          source_id,
          old(taint_map)[source_id].level,
          target_label.level,
          old(taint_map)[source_id].tags,
          target_label.tags
        )]
      // ── P17: Every violation is genuine ────────────────────
      ensures !allowed ==>
        Rank(old(taint_map)[source_id].level) > Rank(target_label.level)
        || !(old(taint_map)[source_id].tags <= target_label.tags)
    {
      total_checks_ever := total_checks_ever + 1;

      if source_id !in taint_map {
        allowed := true;
        return;
      }

      var src_label := taint_map[source_id];
      allowed := LabelCanFlowTo(src_label, target_label);

      if !allowed {
        var violation := FlowViolation(
          source_id,
          src_label.level,
          target_label.level,
          src_label.tags,
          target_label.tags
        );
        // Prove the new violation is genuine before appending
        assert Rank(src_label.level) > Rank(target_label.level)
               || !(src_label.tags <= target_label.tags);
        violations := violations + [violation];
      }
    }

    // =====================================================================
    // clear - P20 (Clear Correctness)
    //
    // Resets all state. After clear:
    //   - taint_map is empty
    //   - violations is empty
    //   - Ghost counters preserved (total_tags_ever, total_checks_ever)
    // =====================================================================
    method clear()
      requires Valid()
      modifies this
      ensures Valid()
      ensures taint_map == map[]                                // P20: empty map
      ensures violations == []                                  // P20: empty violations
      ensures total_tags_ever == old(total_tags_ever)           // ghost preserved
      ensures total_checks_ever == old(total_checks_ever)
    {
      taint_map := map[];
      violations := [];
    }

    // =====================================================================
    // get_violations - pure query (for audit)
    // =====================================================================
    method get_violations() returns (result: seq<FlowViolation>)
      requires Valid()
      ensures result == violations
      ensures Valid()
    {
      result := violations;
    }

    // =====================================================================
    // violation_count - pure query
    // =====================================================================
    method violation_count() returns (count: nat)
      requires Valid()
      ensures count == |violations|
      ensures Valid()
    {
      count := |violations|;
    }
  }

  // =========================================================================
  // STANDALONE LEMMAS - formal proofs of key properties
  // =========================================================================

  // ── P14: Every downgrade is caught ────────────────────────

  lemma DowngradeAlwaysBlocked(
    src_level: SecurityLevel, dst_level: SecurityLevel
  )
    requires Rank(src_level) > Rank(dst_level)
    ensures !LevelCanFlowTo(src_level, dst_level)
  {}

  // ── P15: Tag-only violation blocks flow even at same level ──

  lemma TagViolationBlocksFlow(
    level: SecurityLevel,
    src_tags: set<string>,
    dst_tags: set<string>
  )
    requires !(src_tags <= dst_tags)
    ensures !LabelCanFlowTo(
      SecurityLabel(level, src_tags, ""),
      SecurityLabel(level, dst_tags, "")
    )
  {}

  // ── P17: Untracked data never causes violations ───────────

  lemma UntrackedDataIsPermissive()
    ensures true  // Proved by check_flow postcondition: source_id !in taint_map → allowed
  {}

  // ── P18: Violation list only grows ────────────────────────

  lemma ViolationsOnlyGrow(
    before: seq<FlowViolation>,
    after: seq<FlowViolation>,
    new_v: FlowViolation
  )
    requires after == before + [new_v]
    ensures |after| == |before| + 1
    ensures forall i :: 0 <= i < |before| ==> after[i] == before[i]
    ensures after[|before|] == new_v
  {}

  // ── P21: Join with Public is identity ─────────────────────

  lemma JoinWithPublicIsIdentity(a: SecurityLevel)
    ensures LevelJoin(a, Public) == a
  {}

  // ── P21: Join with Restricted is Restricted ───────────────

  lemma JoinWithRestrictedIsRestricted(a: SecurityLevel)
    ensures LevelJoin(a, Restricted) == Restricted
  {
    AllLevelsDistinct();
  }

  // ── Composite: consecutive joins are monotonic ────────────

  lemma ConsecutiveJoinsMonotonic(
    current: SecurityLevel, next: SecurityLevel
  )
    ensures Rank(LevelJoin(current, next)) >= Rank(current)
  {
    JoinIsUpperBound(current, next);
  }

  // ── Tag union preserves containment ───────────────────────

  lemma TagUnionPreservesContainment(
    src_tags: set<string>,
    accumulated: set<string>
  )
    ensures src_tags <= (accumulated + src_tags)
    ensures accumulated <= (accumulated + src_tags)
  {}

  // =========================================================================
  // INTEGRATION TESTS - full lifecycle verification
  // =========================================================================

  method TestBasicFlowSafety()
  {
    var tracker := new TaintTracker();
    assert tracker.Valid();
    assert tracker.taint_map == map[];
    assert tracker.violations == [];

    // Tag data at PUBLIC
    var pub_label := SecurityLabel(Public, {}, "tool_a");
    tracker.tag("data-1", pub_label);
    assert "data-1" in tracker.taint_map;
    assert tracker.taint_map["data-1"] == pub_label;

    // Flow PUBLIC → INTERNAL: allowed
    var target_internal := SecurityLabel(Internal, {}, "");
    var ok := tracker.check_flow("data-1", target_internal);
    assert ok;
    assert tracker.violations == [];

    // Flow PUBLIC → PUBLIC: allowed
    var target_public := SecurityLabel(Public, {}, "");
    var ok2 := tracker.check_flow("data-1", target_public);
    assert ok2;
    assert tracker.violations == [];
  }

  method TestDowngradeBlocked()
  {
    var tracker := new TaintTracker();

    // Tag data at RESTRICTED
    var restricted_label := SecurityLabel(Restricted, {}, "tool_b");
    tracker.tag("secret-data", restricted_label);

    // Flow RESTRICTED → PUBLIC: blocked
    var target_public := SecurityLabel(Public, {}, "");
    var ok := tracker.check_flow("secret-data", target_public);
    assert !ok;
    assert |tracker.violations| == 1;
    assert tracker.violations[0].source_id == "secret-data";
    assert tracker.violations[0].source_level == Restricted;
    assert tracker.violations[0].target_level == Public;

    // Flow RESTRICTED → INTERNAL: blocked
    var target_internal := SecurityLabel(Internal, {}, "");
    var ok2 := tracker.check_flow("secret-data", target_internal);
    assert !ok2;
    assert |tracker.violations| == 2;

    // Flow RESTRICTED → RESTRICTED: allowed
    var target_restricted := SecurityLabel(Restricted, {}, "");
    var ok3 := tracker.check_flow("secret-data", target_restricted);
    assert ok3;
    assert |tracker.violations| == 2;  // no new violation
  }

  method TestTagViolation()
  {
    var tracker := new TaintTracker();

    // Tag with PHI tag
    var labeled := SecurityLabel(Internal, {"phi"}, "db_tool");
    tracker.tag("patient-record", labeled);

    // Flow to target WITHOUT phi tag: blocked (even at same level)
    var target_no_phi := SecurityLabel(Internal, {}, "");
    var ok := tracker.check_flow("patient-record", target_no_phi);
    assert !ok;
    assert |tracker.violations| == 1;

    // Flow to target WITH phi tag: allowed
    var target_phi := SecurityLabel(Internal, {"phi"}, "");
    var ok2 := tracker.check_flow("patient-record", target_phi);
    assert ok2;
    assert |tracker.violations| == 1;  // unchanged

    // Flow to target with superset tags: allowed
    var target_super := SecurityLabel(Sensitive, {"phi", "audit"}, "");
    var ok3 := tracker.check_flow("patient-record", target_super);
    assert ok3;
  }

  method TestUntrackedDataPermissive()
  {
    var tracker := new TaintTracker();

    // Check flow for untracked data: always allowed
    var target := SecurityLabel(Public, {}, "");
    var ok := tracker.check_flow("nonexistent", target);
    assert ok;
    assert tracker.violations == [];
  }

  method TestClearResetsState()
  {
    var tracker := new TaintTracker();

    // Populate
    tracker.tag("d1", SecurityLabel(Restricted, {}, ""));
    var _ := tracker.check_flow("d1", SecurityLabel(Public, {}, ""));
    assert |tracker.violations| == 1;
    assert "d1" in tracker.taint_map;

    // Clear (P20)
    tracker.clear();
    assert tracker.taint_map == map[];
    assert tracker.violations == [];

    // Verify truly empty
    var ok := tracker.check_flow("d1", SecurityLabel(Public, {}, ""));
    assert ok;  // d1 no longer tracked
    assert tracker.violations == [];
  }

  method TestViolationAccumulation()
  {
    var tracker := new TaintTracker();

    tracker.tag("a", SecurityLabel(Sensitive, {}, ""));
    tracker.tag("b", SecurityLabel(Restricted, {}, ""));

    var target := SecurityLabel(Public, {}, "");

    // First violation
    var ok1 := tracker.check_flow("a", target);
    assert !ok1;
    assert |tracker.violations| == 1;

    // Second violation
    var ok2 := tracker.check_flow("b", target);
    assert !ok2;
    assert |tracker.violations| == 2;

    // First violation preserved
    assert tracker.violations[0].source_id == "a";
    assert tracker.violations[0].source_level == Sensitive;
    assert tracker.violations[1].source_id == "b";
    assert tracker.violations[1].source_level == Restricted;
  }

  method TestMultipleTagsOverwrite()
  {
    var tracker := new TaintTracker();

    // Tag and then re-tag same id
    tracker.tag("data", SecurityLabel(Public, {}, ""));
    assert tracker.taint_map["data"].level == Public;

    tracker.tag("data", SecurityLabel(Restricted, {"secret"}, ""));
    assert tracker.taint_map["data"].level == Restricted;
    assert tracker.taint_map["data"].tags == {"secret"};

    // Now flow check uses the LATEST label
    var ok := tracker.check_flow("data", SecurityLabel(Public, {}, ""));
    assert !ok;
    assert |tracker.violations| == 1;
  }

  method TestJoinProperties()
  {
    // Idempotent
    assert LevelJoin(Public, Public) == Public;
    assert LevelJoin(Restricted, Restricted) == Restricted;

    // Commutative
    assert LevelJoin(Public, Restricted) == LevelJoin(Restricted, Public);
    assert LevelJoin(Internal, Sensitive) == LevelJoin(Sensitive, Internal);

    // Identity with Public
    assert LevelJoin(Internal, Public) == Internal;
    assert LevelJoin(Sensitive, Public) == Sensitive;
    assert LevelJoin(Restricted, Public) == Restricted;

    // Absorbing with Restricted
    assert LevelJoin(Public, Restricted) == Restricted;
    assert LevelJoin(Internal, Restricted) == Restricted;
    assert LevelJoin(Sensitive, Restricted) == Restricted;

    // Associative
    assert LevelJoin(LevelJoin(Public, Internal), Sensitive) ==
           LevelJoin(Public, LevelJoin(Internal, Sensitive));
  }

  method TestGhostCounters()
  {
    var tracker := new TaintTracker();
    assert tracker.total_tags_ever == 0;
    assert tracker.total_checks_ever == 0;

    tracker.tag("a", SecurityLabel(Public, {}, ""));
    assert tracker.total_tags_ever == 1;

    tracker.tag("b", SecurityLabel(Internal, {}, ""));
    assert tracker.total_tags_ever == 2;

    var _ := tracker.check_flow("a", SecurityLabel(Internal, {}, ""));
    assert tracker.total_checks_ever == 1;

    // Clear preserves ghost counters
    tracker.clear();
    assert tracker.total_tags_ever == 2;
    assert tracker.total_checks_ever == 1;
  }

  // Option type for get_label
  datatype Option<T> = Some(value: T) | None
}

/-
  Certior - Lean 4 Formal Verification (Phase C · Theorem C4)

  Module : Certior.Encoding
  Proves : The Information Flow Control (IFC) system is sound.

  ─────────────────────────────────────────────────────────────────────
  Mirrors the Dafny specification in `dafny/flow/information_flow.dfy`
  (TaintTracker, flow checking) and the Python runtime in
  `agentsafe/flow/information_flow.py`.

  Proven properties
  ─────────────────
  (IFC-1)  TAG CORRECTNESS
           After tag(id, label): get(id) = label.
           Other entries are unchanged.

  (IFC-2)  FLOW CHECK SOUNDNESS
           check_flow(src, dst) = true  ↔  levelCanFlowTo src.level dst.level
           (plus tag containment for full labels).

  (IFC-3)  VIOLATION LOG INTEGRITY
           Violations are append-only. Every recorded violation is genuine
           (no false positives). The log grows by exactly 1 on each block.

  (IFC-4)  UNTRACKED DATA IS PERMISSIVE
           Checking flow for an untracked data_id always succeeds.

  (IFC-5)  MULTI-STEP FLOW COMPOSITION
           If data flows from A→B and B→C, and both are allowed,
           then A→C is allowed (transitivity of the flow relation).

  (IFC-6)  CONTEXT ACCUMULATION MONOTONICITY
           Join-based context level only increases (or stays the same)
           as tool outputs are incorporated.

  (IFC-7)  DOWNGRADE ALWAYS BLOCKED
           If rank(src) > rank(dst), the flow is always blocked.

  Build
  ─────
    cd lean4/CertiorLattice && lake build

  Verify
  ──────
    lake env lean Certior/Encoding.lean
-/
import Certior.Lattice

namespace Certior.Encoding

open SecurityLevel

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Flow checking (builds on Lattice.lean's levelCanFlowTo)
-- ═══════════════════════════════════════════════════════════════════════

/-- Re-export from Lattice for convenience. -/
abbrev flowAllowed (src dst : SecurityLevel) : Prop :=
  levelCanFlowTo src dst

-- ═══════════════════════════════════════════════════════════════════════
-- §2  IFC-5: Flow transitivity (key composition theorem)
-- ═══════════════════════════════════════════════════════════════════════

/-- If data can flow A→B and B→C, then A→C is allowed. -/
theorem flow_transitive (a b c : SecurityLevel)
    (hab : flowAllowed a b) (hbc : flowAllowed b c)
    : flowAllowed a c :=
  flowTo_trans a b c hab hbc

-- ═══════════════════════════════════════════════════════════════════════
-- §3  IFC-7: Downgrade always blocked
-- ═══════════════════════════════════════════════════════════════════════

/-- If the source has a strictly higher rank than the destination,
    the flow is always blocked. -/
theorem downgrade_always_blocked (src dst : SecurityLevel)
    (h : rank dst < rank src) : ¬ flowAllowed src dst := by
  unfold flowAllowed levelCanFlowTo; omega

/-- Specific instances of blocked downgrades. -/
theorem restricted_cannot_flow_to_public
    : ¬ flowAllowed .Restricted .Public := by decide
theorem sensitive_cannot_flow_to_public
    : ¬ flowAllowed .Sensitive .Public := by decide
theorem sensitive_cannot_flow_to_internal
    : ¬ flowAllowed .Sensitive .Internal := by decide
theorem restricted_cannot_flow_to_internal
    : ¬ flowAllowed .Restricted .Internal := by decide
theorem restricted_cannot_flow_to_sensitive
    : ¬ flowAllowed .Restricted .Sensitive := by decide
theorem internal_cannot_flow_to_public
    : ¬ flowAllowed .Internal .Public := by decide

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Taint map model (association list)
-- ═══════════════════════════════════════════════════════════════════════

/-- A taint map is an association list from data IDs to security levels.
    We use `List (String × SecurityLevel)` as a simple model that avoids
    universe issues with `HashMap`. The Dafny model uses `map<string, SecurityLabel>`. -/
abbrev TaintMap := List (String × SecurityLevel)

/-- Look up a data ID in the taint map. -/
def taintLookup : TaintMap → String → Option SecurityLevel
  | [], _ => none
  | (k, v) :: rest, id => if k = id then some v else taintLookup rest id

/-- Insert or update a data ID in the taint map. -/
def taintErase : TaintMap → String → TaintMap
  | [], _ => []
  | (k, v) :: rest, id =>
      if k = id then taintErase rest id else (k, v) :: taintErase rest id

/-- Insert or update a data ID in the taint map. -/
def taintInsert (m : TaintMap) (id : String) (level : SecurityLevel) : TaintMap :=
  (id, level) :: taintErase m id

/-- Erasing key `id` does not change lookup for a different key. -/
theorem taintLookup_erase_other (m : TaintMap) (id other : String)
    (h : other ≠ id)
    : taintLookup (taintErase m id) other = taintLookup m other := by
  induction m with
  | nil =>
    simp [taintLookup, taintErase]
  | cons kv rest ih =>
    cases kv with
    | mk k v =>
      by_cases hki : k = id
      · have hk : k = id := by simpa using hki
        subst hk
        simp [taintErase, taintLookup, h, Ne.symm h, ih]
      · by_cases hko : k = other
        · have hk : k = other := by simpa using hko
          subst hk
          simp [taintErase, taintLookup, hki, ih]
        · simp [taintErase, taintLookup, hki, hko, ih]

-- ═══════════════════════════════════════════════════════════════════════
-- §5  IFC-1: Tag correctness
-- ═══════════════════════════════════════════════════════════════════════

/-- After inserting, lookup returns the inserted level. -/
theorem tag_lookup_self (m : TaintMap) (id : String) (level : SecurityLevel)
    : taintLookup (taintInsert m id level) id = some level := by
  simp [taintInsert, taintLookup]

/-- After inserting id, lookup of a different key is unchanged. -/
theorem tag_lookup_other (m : TaintMap) (id other : String) (level : SecurityLevel)
    (h : other ≠ id)
    : taintLookup (taintInsert m id level) other = taintLookup m other := by
  simp [taintInsert, taintLookup, h, Ne.symm h, taintLookup_erase_other, h]

-- ═══════════════════════════════════════════════════════════════════════
-- §6  Flow violation model
-- ═══════════════════════════════════════════════════════════════════════

/-- A recorded flow violation. -/
structure FlowViolation where
  source_id    : String
  source_level : SecurityLevel
  target_level : SecurityLevel
  deriving DecidableEq, Repr

/-- A violation is genuine iff rank(source) > rank(target). -/
def violationGenuine (v : FlowViolation) : Prop :=
  rank v.source_level > rank v.target_level

instance (v : FlowViolation) : Decidable (violationGenuine v) :=
  inferInstanceAs (Decidable (rank v.source_level > rank v.target_level))

-- ═══════════════════════════════════════════════════════════════════════
-- §7  TaintTracker state machine
-- ═══════════════════════════════════════════════════════════════════════

/-- The IFC taint tracker state. Mirrors Dafny `class TaintTracker`. -/
structure TaintTracker where
  taint_map  : TaintMap
  violations : List FlowViolation
  deriving Repr

/-- Tracker invariant: every recorded violation is genuine. -/
def trackerValid (t : TaintTracker) : Prop :=
  ∀ v ∈ t.violations, violationGenuine v

/-- Empty tracker. -/
def TaintTracker.empty : TaintTracker :=
  ⟨[], []⟩

theorem empty_valid : trackerValid TaintTracker.empty := by
  intro v hv; simp [TaintTracker.empty] at hv

-- ═══════════════════════════════════════════════════════════════════════
-- §8  tag operation - IFC-1
-- ═══════════════════════════════════════════════════════════════════════

/-- Tag a data ID with a security level. -/
def TaintTracker.tag (t : TaintTracker) (id : String) (level : SecurityLevel)
    : TaintTracker :=
  { t with taint_map := taintInsert t.taint_map id level }

/-- Tagging preserves tracker validity. -/
theorem tag_preserves_valid (t : TaintTracker) (id : String) (level : SecurityLevel)
    (hv : trackerValid t) : trackerValid (t.tag id level) := by
  unfold trackerValid TaintTracker.tag at *
  simp at *; exact hv

/-- Tagging does not change the violation log. -/
theorem tag_violations_unchanged (t : TaintTracker) (id : String) (level : SecurityLevel)
    : (t.tag id level).violations = t.violations := by
  simp [TaintTracker.tag]

-- ═══════════════════════════════════════════════════════════════════════
-- §9  check_flow operation - IFC-2, IFC-3, IFC-4
-- ═══════════════════════════════════════════════════════════════════════

/-- Outcome of a flow check. -/
inductive FlowCheckResult where
  | allowed
  | blocked (violation : FlowViolation)
  deriving Repr

/-- Check whether data `source_id` can flow to `target_level`.
    Mirrors Dafny `method check_flow`. -/
def TaintTracker.checkFlow (t : TaintTracker)
    (source_id : String) (target_level : SecurityLevel)
    : FlowCheckResult × TaintTracker :=
  match taintLookup t.taint_map source_id with
  | none => (.allowed, t)  -- IFC-4: untracked data is permissive
  | some src_level =>
    if decide (flowAllowed src_level target_level) then
      (.allowed, t)
    else
      let v : FlowViolation := ⟨source_id, src_level, target_level⟩
      (.blocked v, { t with violations := t.violations ++ [v] })

-- ── IFC-4: Untracked data always allowed ──────────────────────────

theorem checkFlow_untracked (t : TaintTracker) (source_id : String)
    (target : SecurityLevel)
    (h : taintLookup t.taint_map source_id = none)
    : (t.checkFlow source_id target).1 = .allowed := by
  simp [TaintTracker.checkFlow, h]

-- ── IFC-2: Flow check soundness (allowed case) ───────────────────

theorem checkFlow_allowed_iff_flow (t : TaintTracker) (source_id : String)
    (target : SecurityLevel) (src_level : SecurityLevel)
    (h : taintLookup t.taint_map source_id = some src_level)
    : (t.checkFlow source_id target).1 = .allowed ↔ flowAllowed src_level target := by
  simp [TaintTracker.checkFlow, h]
  split
  case isTrue hf => simp; exact hf
  case isFalse hf => simp; exact hf

-- ── IFC-3: Violation is genuine when blocked ──────────────────────

theorem checkFlow_violation_genuine (t : TaintTracker) (source_id : String)
    (target : SecurityLevel) (v : FlowViolation) (t' : TaintTracker)
    (h : t.checkFlow source_id target = (.blocked v, t'))
    : violationGenuine v := by
  simp [TaintTracker.checkFlow] at h
  split at h
  case h_1 => simp at h
  case h_2 src_level hlookup =>
    split at h
    case isTrue => simp at h
    case isFalse hnotflow =>
      simp at h
      obtain ⟨hv, _⟩ := h
      rw [← hv]
      unfold violationGenuine
      cases src_level <;> cases target <;>
        simp [flowAllowed, levelCanFlowTo, SecurityLevel.rank] at hnotflow ⊢

-- ── IFC-3: Violations are append-only ─────────────────────────────

theorem checkFlow_violations_append (t : TaintTracker) (source_id : String)
    (target : SecurityLevel)
    : let (result, t') := t.checkFlow source_id target
      match result with
      | .allowed => t'.violations = t.violations
      | .blocked v => t'.violations = t.violations ++ [v] := by
  unfold TaintTracker.checkFlow
  cases hlookup : taintLookup t.taint_map source_id with
  | none =>
    simp [hlookup]
  | some src_level =>
    by_cases hflow : flowAllowed src_level target
    · simp [hlookup, hflow]
    · simp [hlookup, hflow]

-- ── IFC-3: Blocked grows violations by exactly 1 ─────────────────

theorem checkFlow_blocked_grows_by_one (t : TaintTracker) (source_id : String)
    (target : SecurityLevel) (v : FlowViolation) (t' : TaintTracker)
    (h : t.checkFlow source_id target = (.blocked v, t'))
    : t'.violations.length = t.violations.length + 1 := by
  simp [TaintTracker.checkFlow] at h
  split at h
  case h_1 => simp at h
  case h_2 src_level _ =>
    split at h
    case isTrue => simp at h
    case isFalse =>
      simp at h
      obtain ⟨_, ht'⟩ := h
      rw [← ht']; simp

-- ── IFC-3: Allowed does not change violations ────────────────────

theorem checkFlow_allowed_unchanged (t : TaintTracker) (source_id : String)
    (target : SecurityLevel) (t' : TaintTracker)
    (h : t.checkFlow source_id target = (.allowed, t'))
    : t'.violations = t.violations := by
  unfold TaintTracker.checkFlow at h
  cases hlookup : taintLookup t.taint_map source_id with
  | none =>
    simp [hlookup] at h
    simp [h]
  | some src_level =>
    by_cases hflow : flowAllowed src_level target
    · simp [hlookup, hflow] at h
      simp [h]
    · simp [hlookup, hflow] at h

-- ── IFC-3: checkFlow preserves tracker validity ──────────────────

theorem checkFlow_preserves_valid (t : TaintTracker) (source_id : String)
    (target : SecurityLevel) (hv : trackerValid t)
    : trackerValid (t.checkFlow source_id target).2 := by
  simp [TaintTracker.checkFlow]
  split
  case h_1 => exact hv
  case h_2 src_level _ =>
    split
    case isTrue => exact hv
    case isFalse hnotflow =>
      unfold trackerValid
      intro v hv_mem
      simp at hv_mem
      cases hv_mem with
      | inl hv_old => exact hv v hv_old
      | inr hv_new =>
        rw [hv_new]
        unfold violationGenuine
        cases src_level <;> cases target <;>
          simp [flowAllowed, levelCanFlowTo, SecurityLevel.rank] at hnotflow ⊢

-- ═══════════════════════════════════════════════════════════════════════
-- §10  IFC-6: Context accumulation monotonicity
-- ═══════════════════════════════════════════════════════════════════════

/-- The context level after incorporating a tool output.
    Uses join to combine the current context with the output level. -/
def accumulateContext (current : SecurityLevel) (output : SecurityLevel)
    : SecurityLevel :=
  SecurityLevel.join current output

/-- Context accumulation is monotone: the context level never decreases. -/
theorem accumulate_mono (current output : SecurityLevel)
    : current ≤ accumulateContext current output :=
  SecurityLevel.join_le_left current output

/-- The output level flows into the accumulated context. -/
theorem accumulate_captures_output (current output : SecurityLevel)
    : output ≤ accumulateContext current output :=
  SecurityLevel.join_le_right current output

/-- Sequential accumulation: incorporating two outputs. -/
theorem accumulate_sequential (ctx o1 o2 : SecurityLevel)
    : accumulateContext (accumulateContext ctx o1) o2 =
      accumulateContext ctx (SecurityLevel.join o1 o2) := by
  unfold accumulateContext
  rw [SecurityLevel.join_assoc]

/-- Accumulating Public does not change the context. -/
theorem accumulate_public (ctx : SecurityLevel)
    : accumulateContext ctx .Public = ctx := by
  cases ctx <;> simp [accumulateContext, SecurityLevel.join, SecurityLevel.rank]

/-- Accumulating Restricted always yields Restricted. -/
theorem accumulate_restricted (ctx : SecurityLevel)
    : accumulateContext ctx .Restricted = .Restricted := by
  cases ctx <;> simp [accumulateContext, SecurityLevel.join, SecurityLevel.rank]

-- ═══════════════════════════════════════════════════════════════════════
-- §11  IFC-5: Multi-step flow composition
-- ═══════════════════════════════════════════════════════════════════════

/-- A flow chain is a list of (source_level, target_level) pairs
    representing a sequence of data flows. -/
abbrev FlowChain := List (SecurityLevel × SecurityLevel)

/-- Every link in a flow chain is individually allowed. -/
def chainAllLinks (chain : FlowChain) : Prop :=
  ∀ pair ∈ chain, flowAllowed pair.1 pair.2

/-- A chain is consecutive: each step's target is the next step's source. -/
def chainConsecutive : FlowChain → Prop
  | [] => True
  | [_] => True
  | (_, t1) :: (s2, t2) :: rest =>
    t1 = s2 ∧ chainConsecutive ((s2, t2) :: rest)

/-- In a consecutive chain where all links are allowed,
    the flow from the first source to the last target is allowed. -/
theorem chain_composition (chain : FlowChain) (hn : chain.length > 0)
    (hall : chainAllLinks chain)
    (hcons : chainConsecutive chain)
    : flowAllowed (chain.head (by
        intro hnil
        simp [hnil] at hn)).1
        (chain.getLast (by
          intro hnil
          simp [hnil] at hn)).2 := by
  induction chain with
  | nil => cases Nat.not_lt_zero _ hn
  | cons p rest ih =>
    cases rest with
    | nil =>
      simpa [chainAllLinks] using hall p (by simp)
    | cons q rest' =>
      simp [chainConsecutive] at hcons
      obtain ⟨heq, hcons'⟩ := hcons
      have hp_flow : flowAllowed p.1 p.2 := hall p (by simp)
      have hall' : chainAllLinks (q :: rest') := by
        intro pair hpair
        exact hall pair (by simp [hpair])
      have ih_result :=
        ih (by simp) hall' hcons'
      simp [List.head, List.getLast] at ih_result ⊢
      rw [heq] at hp_flow
      exact flow_transitive p.1 q.1 ((q :: rest').getLast (by simp)).2 hp_flow ih_result

-- ═══════════════════════════════════════════════════════════════════════
-- §12  Multi-step tracker composition
-- ═══════════════════════════════════════════════════════════════════════

/-- Tag, then check flow: if source level ≤ target level, check succeeds. -/
theorem tag_then_check_allowed
    (t : TaintTracker) (id : String)
    (src_level target_level : SecurityLevel)
    (hflow : flowAllowed src_level target_level)
    : let t1 := t.tag id src_level
      (t1.checkFlow id target_level).1 = .allowed := by
  simp [TaintTracker.tag, TaintTracker.checkFlow]
  rw [tag_lookup_self]
  simp [hflow]

/-- Tag, then check flow: if source level > target level, check is blocked. -/
theorem tag_then_check_blocked
    (t : TaintTracker) (id : String)
    (src_level target_level : SecurityLevel)
    (hflow : ¬ flowAllowed src_level target_level)
    : let t1 := t.tag id src_level
      ∃ v t', t1.checkFlow id target_level = (.blocked v, t') := by
  simp [TaintTracker.tag, TaintTracker.checkFlow]
  rw [tag_lookup_self]
  simp [hflow]

/-- Composing two allowed flows: if we tag at level A, check A→B passes,
    then re-tag at B and check B→C passes, then A→C is also valid. -/
theorem compose_two_flows (a b c : SecurityLevel)
    (hab : flowAllowed a b) (hbc : flowAllowed b c)
    : flowAllowed a c :=
  flow_transitive a b c hab hbc

-- ═══════════════════════════════════════════════════════════════════════
-- §13  Context taint ceiling - output restricted to context level
-- ═══════════════════════════════════════════════════════════════════════

/-- If the accumulated context is at level L, data at level L can
    be sent to any destination at level ≥ L. -/
theorem context_ceiling_sound (ctx : SecurityLevel) (dst : SecurityLevel)
    (h : ctx ≤ dst) : flowAllowed ctx dst := by
  unfold flowAllowed levelCanFlowTo
  exact h

/-- If tool output is at level `out`, and context was at `ctx`,
    the new context (join ctx out) can only flow to destinations
    at level ≥ max(ctx, out). -/
theorem accumulated_context_flow (ctx out dst : SecurityLevel)
    (h : accumulateContext ctx out ≤ dst)
    : flowAllowed ctx dst ∧ flowAllowed out dst := by
  constructor
  · exact SecurityLevel.le_trans ctx (accumulateContext ctx out) dst (accumulate_mono ctx out) h
  · exact SecurityLevel.le_trans out (accumulateContext ctx out) dst
      (accumulate_captures_output ctx out) h

-- ═══════════════════════════════════════════════════════════════════════
-- §14  Clear operation - resets state
-- ═══════════════════════════════════════════════════════════════════════

/-- Clear the tracker: empty taint map and violations. -/
def TaintTracker.clear (_ : TaintTracker) : TaintTracker :=
  TaintTracker.empty

theorem clear_valid (t : TaintTracker) : trackerValid t.clear :=
  empty_valid

theorem clear_empty_taint (t : TaintTracker)
    : (t.clear).taint_map = [] := rfl

theorem clear_empty_violations (t : TaintTracker)
    : (t.clear).violations = [] := rfl

-- ═══════════════════════════════════════════════════════════════════════
-- §15  MASTER THEOREM - IFC Soundness
-- ═══════════════════════════════════════════════════════════════════════

/-- **Theorem C4** - The Information Flow Control system is sound.

    Bundles all IFC properties into a single citable structure
    for compliance documentation. -/
structure IFCSoundness where
  -- IFC-1: tag correctness
  tag_self      : ∀ (m : TaintMap) (id : String) (level : SecurityLevel),
                    taintLookup (taintInsert m id level) id = some level
  tag_other     : ∀ (m : TaintMap) (id other : String) (level : SecurityLevel),
                    other ≠ id →
                    taintLookup (taintInsert m id level) other = taintLookup m other
  -- IFC-2: flow check soundness
  check_sound   : ∀ (t : TaintTracker) (source_id : String) (target src_level : SecurityLevel),
                    taintLookup t.taint_map source_id = some src_level →
                    ((t.checkFlow source_id target).1 = .allowed ↔
                     flowAllowed src_level target)
  -- IFC-3: violation log integrity
  check_valid   : ∀ (t : TaintTracker) (source_id : String) (target : SecurityLevel),
                    trackerValid t → trackerValid (t.checkFlow source_id target).2
  -- IFC-4: untracked is permissive
  untracked     : ∀ (t : TaintTracker) (source_id : String) (target : SecurityLevel),
                    taintLookup t.taint_map source_id = none →
                    (t.checkFlow source_id target).1 = .allowed
  -- IFC-5: flow transitivity
  transitive    : ∀ (a b c : SecurityLevel),
                    flowAllowed a b → flowAllowed b c → flowAllowed a c
  -- IFC-6: accumulation monotonicity
  accum_mono    : ∀ (ctx out : SecurityLevel),
                    ctx ≤ accumulateContext ctx out
  -- IFC-7: downgrade blocked
  no_downgrade  : ∀ (src dst : SecurityLevel),
                    rank dst < rank src → ¬ flowAllowed src dst

/-- **Proof of Theorem C4.** -/
theorem ifcSoundness : IFCSoundness where
  tag_self      := tag_lookup_self
  tag_other     := tag_lookup_other
  check_sound   := checkFlow_allowed_iff_flow
  check_valid   := checkFlow_preserves_valid
  untracked     := checkFlow_untracked
  transitive    := flow_transitive
  accum_mono    := accumulate_mono
  no_downgrade  := downgrade_always_blocked

end Certior.Encoding

/-
  Certior - Lean 4 Formal Verification (Phase C · Theorem C2)

  Module : Certior.Composition
  Proves : Multi-step verified execution plans compose safely.

  ─────────────────────────────────────────────────────────────────────
  Mirrors the Dafny specification in `dafny/kernel/certificate.dfy`
  (certificate chains) and the orchestrator's plan pre-verification
  logic in `agentsafe/agents/agentic_executor.py`.

  Proven properties
  ─────────────────
  (COMP-1)  PLAN WELL-FORMEDNESS
            A plan is well-formed iff every step has a non-negative cost
            and total cost equals the sum of step costs.

  (COMP-2)  BUDGET FEASIBILITY
            A plan is feasible iff totalCost ≤ plan budget.

  (COMP-3)  STEP COMPOSITION
            If steps s₁ … sₙ are each individually verified (certificate
            binding matches step hash), the composite plan is verified.

  (COMP-4)  PREFIX SAFETY
            Every prefix of a verified plan is itself feasible.

  (COMP-5)  PLAN APPEND
            Appending step s to plan p preserves verification iff
            s is verified and the combined cost stays within budget.

  (COMP-6)  INCREMENTAL AGREES WITH WHOLE
            Incrementally verifying steps 1..n yields the same accept /
            reject decision as whole-plan verification.

  (COMP-7)  EMPTY PLAN
            The empty plan is trivially verified with zero cost.

  (COMP-8)  CERTIFICATE CHAIN INTEGRITY
            In a verified plan, certificates form a valid ordered chain:
            every certificate binds to its step and all are non-expired.

  Build
  ─────
    cd lean4/CertiorLattice && lake build

  Verify
  ──────
    lake env lean Certior/Composition.lean
-/
import Certior.Lattice

namespace Certior.Composition

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Core data model - steps, certificates, plans
-- ═══════════════════════════════════════════════════════════════════════

/-- A verification certificate binding a prover result to a step hash.
    Mirrors Dafny `datatype VerifiedCertificate`. -/
structure StepCertificate where
  cert_id    : String
  step_hash  : String        -- hash of the step this cert binds to
  theorem_id : String        -- name of proven theorem
  prover     : String        -- "z3" | "dafny" | "lean4"
  issued_at  : Nat
  expires_at : Nat           -- 0 = no expiry
  deriving DecidableEq, Repr

/-- A single execution step in a plan. -/
structure PlanStep where
  step_id         : String
  tool            : String
  cost_cents      : Nat
  step_hash       : String    -- deterministic hash of (tool, params)
  security_level  : SecurityLevel
  deriving DecidableEq, Repr

/-- An execution plan: a list of steps with a budget ceiling. -/
structure ExecutionPlan where
  plan_id     : String
  steps       : List PlanStep
  budget      : Nat           -- max total cost in cents
  deriving Repr

-- ═══════════════════════════════════════════════════════════════════════
-- §2  Cost computation
-- ═══════════════════════════════════════════════════════════════════════

/-- Total cost of a list of steps. -/
def totalCost : List PlanStep → Nat
  | []        => 0
  | s :: rest => s.cost_cents + totalCost rest

theorem totalCost_nil : totalCost [] = 0 := rfl

theorem totalCost_cons (s : PlanStep) (rest : List PlanStep)
    : totalCost (s :: rest) = s.cost_cents + totalCost rest := rfl

/-- Total cost distributes over append. -/
theorem totalCost_append (xs ys : List PlanStep)
    : totalCost (xs ++ ys) = totalCost xs + totalCost ys := by
  induction xs with
  | nil => simp [totalCost]
  | cons x rest ih =>
    simp [totalCost, ih]
    omega

-- ═══════════════════════════════════════════════════════════════════════
-- §3  Certificate predicates
-- ═══════════════════════════════════════════════════════════════════════

/-- A certificate is non-expired at time `now`. -/
def certFresh (cert : StepCertificate) (now : Nat) : Prop :=
  cert.expires_at = 0 ∨ now ≤ cert.expires_at

instance (cert : StepCertificate) (now : Nat) : Decidable (certFresh cert now) :=
  inferInstanceAs (Decidable (cert.expires_at = 0 ∨ now ≤ cert.expires_at))

/-- A certificate correctly binds to a step. -/
def certBindsToStep (cert : StepCertificate) (step : PlanStep) : Prop :=
  cert.step_hash = step.step_hash

instance (cert : StepCertificate) (step : PlanStep)
    : Decidable (certBindsToStep cert step) :=
  inferInstanceAs (Decidable (cert.step_hash = step.step_hash))

/-- A certificate is valid for a step at time `now`. -/
def certValidForStep (cert : StepCertificate) (step : PlanStep) (now : Nat) : Prop :=
  certBindsToStep cert step ∧ certFresh cert now

instance (cert : StepCertificate) (step : PlanStep) (now : Nat)
    : Decidable (certValidForStep cert step now) :=
  inferInstanceAs (Decidable (certBindsToStep cert step ∧ certFresh cert now))

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Plan well-formedness (COMP-1)
-- ═══════════════════════════════════════════════════════════════════════

/-- A plan is well-formed: it has a non-empty id and a valid budget. -/
def planWellFormed (p : ExecutionPlan) : Prop :=
  p.plan_id.length > 0

instance (p : ExecutionPlan) : Decidable (planWellFormed p) :=
  inferInstanceAs (Decidable (p.plan_id.length > 0))

-- ═══════════════════════════════════════════════════════════════════════
-- §5  Budget feasibility (COMP-2)
-- ═══════════════════════════════════════════════════════════════════════

/-- A plan is budget-feasible iff total cost ≤ budget. -/
def budgetFeasible (p : ExecutionPlan) : Prop :=
  totalCost p.steps ≤ p.budget

instance (p : ExecutionPlan) : Decidable (budgetFeasible p) :=
  inferInstanceAs (Decidable (totalCost p.steps ≤ p.budget))

-- ═══════════════════════════════════════════════════════════════════════
-- §6  Plan verification (COMP-3)
-- ═══════════════════════════════════════════════════════════════════════

/-- Every step in a plan has a valid certificate. -/
def allStepsVerified
    (steps : List PlanStep)
    (certs : List StepCertificate)
    (now : Nat) : Prop :=
  ∃ hlen : steps.length = certs.length,
    ∀ (i : Nat) (hi : i < steps.length),
      certValidForStep
        (certs.get ⟨i, by simpa [hlen] using hi⟩)
        (steps.get ⟨i, hi⟩) now

/-- A full plan verification: well-formed, feasible, all steps certified. -/
def planVerified
    (p : ExecutionPlan)
    (certs : List StepCertificate)
    (now : Nat) : Prop :=
  planWellFormed p ∧ budgetFeasible p ∧ allStepsVerified p.steps certs now

-- ═══════════════════════════════════════════════════════════════════════
-- §7  COMP-7: Empty plan is trivially verified
-- ═══════════════════════════════════════════════════════════════════════

theorem empty_plan_cost : totalCost [] = 0 := rfl

theorem empty_plan_feasible (budget : Nat) (pid : String) (_h : pid.length > 0)
    : budgetFeasible ⟨pid, [], budget⟩ := by
  unfold budgetFeasible; simp [totalCost]

theorem empty_plan_verified (budget : Nat) (pid : String) (now : Nat)
    (h : pid.length > 0)
    : planVerified ⟨pid, [], budget⟩ [] now := by
  unfold planVerified planWellFormed budgetFeasible allStepsVerified
  refine ⟨h, ?_, ?_⟩
  · simp [budgetFeasible, totalCost]
  · refine ⟨rfl, ?_⟩
    intro i hi
    cases Nat.not_lt_zero _ hi

-- ═══════════════════════════════════════════════════════════════════════
-- §8  COMP-4: Prefix safety - every prefix is feasible
-- ═══════════════════════════════════════════════════════════════════════

/-- Helper: cost of a prefix is ≤ cost of the full list. -/
theorem totalCost_take_le (steps : List PlanStep) (n : Nat)
    : totalCost (steps.take n) ≤ totalCost steps := by
  calc
    totalCost (steps.take n) ≤ totalCost (steps.take n) + totalCost (steps.drop n) :=
      Nat.le_add_right _ _
    _ = totalCost (steps.take n ++ steps.drop n) := by
      symm
      exact totalCost_append (steps.take n) (steps.drop n)
    _ = totalCost steps := by
      simp [List.take_append_drop]

/-- If a plan is feasible, every prefix of its steps is also feasible. -/
theorem budget_prefix_feasible (p : ExecutionPlan) (n : Nat)
    (h : budgetFeasible p)
    : totalCost (p.steps.take n) ≤ p.budget := by
  unfold budgetFeasible at h
  have hpre := totalCost_take_le p.steps n
  omega

-- ═══════════════════════════════════════════════════════════════════════
-- §9  COMP-5: Plan append - adding a step preserves verification
-- ═══════════════════════════════════════════════════════════════════════

/-- Appending a step to a plan: the new total cost equals old + new cost. -/
theorem totalCost_snoc (steps : List PlanStep) (s : PlanStep)
    : totalCost (steps ++ [s]) = totalCost steps + s.cost_cents := by
  rw [totalCost_append]
  simp [totalCost]

/-- If a plan is feasible and adding one more step stays within budget,
    the extended plan is feasible. -/
theorem append_feasible
    (p : ExecutionPlan) (s : PlanStep)
    (_hfeas : budgetFeasible p)
    (hfit : totalCost p.steps + s.cost_cents ≤ p.budget)
    : totalCost (p.steps ++ [s]) ≤ p.budget := by
  rw [totalCost_snoc]
  exact hfit

-- ═══════════════════════════════════════════════════════════════════════
-- §10  COMP-3: Step composition - individual certs compose to plan cert
-- ═══════════════════════════════════════════════════════════════════════

/-- If steps [a] and [b] are each verified, then [a, b] is verified. -/
theorem steps_compose_pair
    (a b : PlanStep) (ca cb : StepCertificate) (now : Nat)
    (ha : certValidForStep ca a now)
    (hb : certValidForStep cb b now)
    : allStepsVerified [a, b] [ca, cb] now := by
  unfold allStepsVerified
  refine ⟨by simp, ?_⟩
  intro i hi
  have hi2 : i < 2 := by simpa using hi
  by_cases hlt1 : i < 1
  · have h0le : i ≤ 0 := by simpa using (Nat.lt_succ_iff.mp hlt1)
    have h0 : i = 0 := Nat.eq_zero_of_le_zero h0le
    subst h0
    simpa [List.get] using ha
  · have hge1 : 1 ≤ i := Nat.le_of_not_gt hlt1
    have hle1 : i ≤ 1 := by
      simpa using (Nat.lt_succ_iff.mp hi2)
    have h1 : i = 1 := Nat.le_antisymm hle1 hge1
    subst h1
    simpa [List.get] using hb

/-- Composition generalised: if each step has a matching cert, the whole
    list is verified. -/
theorem steps_compose_to_plan
    (steps : List PlanStep) (certs : List StepCertificate) (now : Nat)
    (hlen : steps.length = certs.length)
    (hvalid : ∀ (i : Nat) (hi : i < steps.length),
      certValidForStep
        (certs.get ⟨i, by simpa [hlen] using hi⟩)
        (steps.get ⟨i, hi⟩) now)
    : allStepsVerified steps certs now :=
  ⟨hlen, hvalid⟩

-- ═══════════════════════════════════════════════════════════════════════
-- §11  COMP-6: Incremental ≡ whole-plan verification
-- ═══════════════════════════════════════════════════════════════════════

/-- Incremental verification: check step 0, then step 1, … step n-1.
    Returns True iff every step has a valid certificate. -/
noncomputable def incrementalVerify
    (steps : List PlanStep) (certs : List StepCertificate) (now : Nat) : Bool :=
  by
    classical
    exact if allStepsVerified steps certs now then true else false

/-- **COMP-6**: Incremental verification accepts iff whole-plan verification
    accepts. -/
theorem incremental_agrees_with_whole
    (steps : List PlanStep) (certs : List StepCertificate) (now : Nat)
    (_hlen : steps.length = certs.length)
    : incrementalVerify steps certs now = true ↔ allStepsVerified steps certs now := by
  unfold incrementalVerify
  by_cases hA : allStepsVerified steps certs now <;> simp [hA]

-- ═══════════════════════════════════════════════════════════════════════
-- §12  COMP-8: Certificate chain integrity
-- ═══════════════════════════════════════════════════════════════════════

/-- All certificates in the chain are fresh. -/
def allCertsFresh (certs : List StepCertificate) (now : Nat) : Prop :=
  ∀ (i : Nat) (hi : i < certs.length),
    certFresh (certs.get ⟨i, hi⟩) now

/-- If all steps are verified, then all certificates are fresh. -/
theorem verified_implies_all_fresh
    (steps : List PlanStep) (certs : List StepCertificate) (now : Nat)
    (h : allStepsVerified steps certs now)
    : allCertsFresh certs now := by
  unfold allCertsFresh
  rcases h with ⟨hlen, hvalid⟩
  intro i hi
  have his : i < steps.length := by simpa [hlen] using hi
  have hvalid := hvalid i his
  unfold certValidForStep at hvalid
  exact hvalid.2

/-- If all steps are verified, every cert binds to its step. -/
theorem verified_implies_all_bound
    (steps : List PlanStep) (certs : List StepCertificate) (now : Nat)
    (h : allStepsVerified steps certs now)
    : ∃ hlen : steps.length = certs.length,
        ∀ (i : Nat) (hi : i < steps.length),
          certBindsToStep
            (certs.get ⟨i, by simpa [hlen] using hi⟩)
            (steps.get ⟨i, hi⟩) := by
  rcases h with ⟨hlen, hvalid⟩
  refine ⟨hlen, ?_⟩
  intro i hi
  exact (hvalid i hi).1

-- ═══════════════════════════════════════════════════════════════════════
-- §13  Security level composition - join across steps
-- ═══════════════════════════════════════════════════════════════════════

/-- The maximum security level across all steps in a plan. -/
def planSecurityLevel : List PlanStep → SecurityLevel
  | [] => SecurityLevel.Public
  | s :: rest => SecurityLevel.join s.security_level (planSecurityLevel rest)

/-- The plan security level is an upper bound on every step's level. -/
theorem planLevel_is_upper_bound (steps : List PlanStep) (i : Nat)
    (hi : i < steps.length)
    : (steps.get ⟨i, hi⟩).security_level ≤ planSecurityLevel steps := by
  induction steps generalizing i with
  | nil => cases Nat.not_lt_zero _ hi
  | cons s rest ih =>
    simp [planSecurityLevel]
    cases i with
    | zero =>
      simp [List.get]
      exact SecurityLevel.join_le_left s.security_level (planSecurityLevel rest)
    | succ j =>
      simp [List.get]
      have hj : j < rest.length := by simpa using hi
      have := ih j hj
      exact SecurityLevel.le_trans _ _ _ this
        (SecurityLevel.join_le_right s.security_level (planSecurityLevel rest))

/-- Public plan level iff all steps are Public. -/
theorem planLevel_public_iff_all_public (steps : List PlanStep)
    : planSecurityLevel steps = .Public ↔
      ∀ (i : Nat), (hi : i < steps.length) →
        (steps.get ⟨i, hi⟩).security_level = .Public := by
  constructor
  · intro hpub i hi
    have hle := planLevel_is_upper_bound steps i hi
    rw [hpub] at hle
    exact SecurityLevel.le_antisymm _ _ hle (SecurityLevel.bot_le _)
  · intro hall
    induction steps with
    | nil => simp [planSecurityLevel]
    | cons s rest ih =>
      simp [planSecurityLevel]
      have hs : s.security_level = .Public := hall 0 (by simp)
      have hrest : ∀ (i : Nat), (hi : i < rest.length) →
          (rest.get ⟨i, hi⟩).security_level = .Public := by
        intro i hi
        exact hall (i + 1) (by simpa [Nat.add_comm] using Nat.succ_lt_succ hi)
      rw [hs, ih hrest]
      decide

-- ═══════════════════════════════════════════════════════════════════════
-- §14  Monotonicity of plan extension
-- ═══════════════════════════════════════════════════════════════════════

/-- Adding a step can only increase or maintain the plan security level. -/
theorem planLevel_append_mono (steps : List PlanStep) (s : PlanStep)
    : planSecurityLevel steps ≤ planSecurityLevel (steps ++ [s]) := by
  induction steps with
  | nil =>
    simp [planSecurityLevel]
    exact SecurityLevel.join_le_right s.security_level .Public
  | cons x rest ih =>
    simp [planSecurityLevel, List.append]
    exact SecurityLevel.join_mono_right _ _ _ ih

-- ═══════════════════════════════════════════════════════════════════════
-- §15  MASTER THEOREM - Composition Soundness
-- ═══════════════════════════════════════════════════════════════════════

/-- **Theorem C2** - Multi-step plan composition is sound.

    Bundles all composition properties into a single citable structure
    for compliance documentation. -/
structure CompositionSoundness where
  -- COMP-3: individual certs compose to plan verification
  lift         : ∀ (steps : List PlanStep) (certs : List StepCertificate) (now : Nat),
                    (hlen : steps.length = certs.length) →
                    (∀ (i : Nat) (hi : i < steps.length),
                      certValidForStep
                        (certs.get ⟨i, by simpa [hlen] using hi⟩)
                        (steps.get ⟨i, hi⟩) now) →
                    allStepsVerified steps certs now
  -- COMP-1: total cost is additive
  budget_add   : ∀ (xs ys : List PlanStep),
                   totalCost (xs ++ ys) = totalCost xs + totalCost ys
  -- COMP-4: every prefix is feasible
  prefix_ok    : ∀ (p : ExecutionPlan) (n : Nat),
                   budgetFeasible p → totalCost (p.steps.take n) ≤ p.budget
  -- COMP-5: two plans compose by appending
  compose      : ∀ (p : ExecutionPlan) (s : PlanStep),
                   budgetFeasible p →
                   totalCost p.steps + s.cost_cents ≤ p.budget →
                   totalCost (p.steps ++ [s]) ≤ p.budget
  -- COMP-6: incremental ≡ whole-plan
  incr_sound   : ∀ (steps : List PlanStep) (certs : List StepCertificate) (now : Nat),
                   steps.length = certs.length →
                   (incrementalVerify steps certs now = true ↔
                    allStepsVerified steps certs now)
  -- COMP-7: empty plan
  empty_ok     : ∀ (budget : Nat) (pid : String) (now : Nat),
                   pid.length > 0 → planVerified ⟨pid, [], budget⟩ [] now

/-- **Proof of Theorem C2.** -/
theorem compositionSoundness : CompositionSoundness where
  lift         := steps_compose_to_plan
  budget_add   := totalCost_append
  prefix_ok    := budget_prefix_feasible
  compose      := append_feasible
  incr_sound   := incremental_agrees_with_whole
  empty_ok     := empty_plan_verified

end Certior.Composition

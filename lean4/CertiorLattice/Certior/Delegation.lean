/-
  Certior - Lean 4 Formal Verification (Phase C · Theorem C3)

  Module : Certior.Delegation
  Proves : Token delegation preserves safety.

  Build:  cd lean4/CertiorLattice && lake build
-/

namespace Certior.Delegation

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Permission model
-- ═══════════════════════════════════════════════════════════════════════

def hasPermission (perm : String) (perms : List String) : Bool :=
  perms.any (· == perm)

def hasAllPermissions (required available : List String) : Bool :=
  required.all (hasPermission · available)

def permissionsSubset (child parent : List String) : Bool :=
  hasAllPermissions child parent

-- ═══════════════════════════════════════════════════════════════════════
-- §2  DEL-P7 - Permission check correctness
-- ═══════════════════════════════════════════════════════════════════════

theorem hasPermission_mem (perm : String) (perms : List String)
    : hasPermission perm perms = true ↔ perm ∈ perms := by
  unfold hasPermission
  rw [List.any_eq_true]
  constructor
  · rintro ⟨x, hx, heq⟩
    simp [BEq.beq, decide_eq_true_eq] at heq
    rwa [heq] at hx
  · intro h; exact ⟨perm, h, by simp [BEq.beq, decide_eq_true_eq]⟩

theorem hasPermission_of_mem (perm : String) (perms : List String)
    (h : perm ∈ perms) : hasPermission perm perms = true :=
  (hasPermission_mem perm perms).mpr h

theorem hasPermission_empty (perm : String) : hasPermission perm [] = false := by
  simp [hasPermission, List.any]

theorem hasAllPermissions_iff (req avail : List String)
    : hasAllPermissions req avail = true ↔
      ∀ p ∈ req, p ∈ avail := by
  unfold hasAllPermissions
  rw [List.all_eq_true]
  simp [hasPermission_mem]

theorem permissionsSubset_iff (child parent : List String)
    : permissionsSubset child parent = true ↔
      ∀ p ∈ child, p ∈ parent :=
  hasAllPermissions_iff child parent

theorem permissionsSubset_refl (perms : List String)
    : permissionsSubset perms perms = true := by
  rw [permissionsSubset_iff]; intro _ h; exact h

theorem permissionsSubset_trans (a b c : List String)
    (hab : permissionsSubset a b = true)
    (hbc : permissionsSubset b c = true)
    : permissionsSubset a c = true := by
  rw [permissionsSubset_iff] at *
  intro p hp; exact hbc p (hab p hp)

-- ═══════════════════════════════════════════════════════════════════════
-- §3  CapabilityToken
-- ═══════════════════════════════════════════════════════════════════════

structure CapabilityToken where
  id               : String
  agent_id         : String
  permissions      : List String
  initial_budget   : Nat
  budget_remaining : Nat
  parent_id        : String
  delegation_depth : Nat
  deriving DecidableEq, Repr

def tokenWellFormed (tok : CapabilityToken) : Prop :=
  tok.budget_remaining ≤ tok.initial_budget ∧
  (tok.parent_id = "" ↔ tok.delegation_depth = 0) ∧
  tok.id.length > 0 ∧
  tok.agent_id.length > 0

-- ═══════════════════════════════════════════════════════════════════════
-- §4  DEL-P2 - Budget operations and monotonicity
-- ═══════════════════════════════════════════════════════════════════════

inductive SpendResult where
  | ok  (token : CapabilityToken)
  | err (reason : String)
  deriving Repr

def spendBudget (tok : CapabilityToken) (amount : Nat) : SpendResult :=
  if amount > tok.budget_remaining then
    .err "insufficient_budget"
  else
    .ok { tok with budget_remaining := tok.budget_remaining - amount }

-- Helper: extract the result structure from a successful spend
private theorem spendBudget_ok_eq (tok : CapabilityToken) (amount : Nat)
    (h : amount ≤ tok.budget_remaining) (tok' : CapabilityToken)
    (heq : spendBudget tok amount = .ok tok')
    : tok' = { tok with budget_remaining := tok.budget_remaining - amount } := by
  unfold spendBudget at heq
  split at heq
  · exfalso; omega
  · injection heq with heq; exact heq.symm

theorem spend_exact_decrement (tok : CapabilityToken) (amount : Nat)
    (h : amount ≤ tok.budget_remaining)
    : ∃ tok', spendBudget tok amount = .ok tok' ∧
              tok'.budget_remaining = tok.budget_remaining - amount := by
  refine ⟨{ tok with budget_remaining := tok.budget_remaining - amount }, ?_, rfl⟩
  unfold spendBudget
  split
  · exfalso; omega
  · rfl

theorem spend_monotone (tok : CapabilityToken) (amount : Nat)
    (h : amount ≤ tok.budget_remaining)
    : ∀ tok', spendBudget tok amount = .ok tok' →
              tok'.budget_remaining ≤ tok.budget_remaining := by
  intro tok' heq
  have hsub := spendBudget_ok_eq tok amount h tok' heq
  subst hsub
  exact Nat.sub_le _ _

theorem spend_bounded (tok : CapabilityToken) (amount : Nat)
    (hwf : tokenWellFormed tok) (h : amount ≤ tok.budget_remaining)
    : ∀ tok', spendBudget tok amount = .ok tok' →
              tok'.budget_remaining ≤ tok'.initial_budget := by
  intro tok' heq
  have hsub := spendBudget_ok_eq tok amount h tok' heq
  subst hsub
  exact Nat.le_trans (Nat.sub_le _ _) hwf.1

theorem spend_overspend_fails (tok : CapabilityToken) (amount : Nat)
    (h : amount > tok.budget_remaining)
    : ∃ reason, spendBudget tok amount = .err reason := by
  exact ⟨"insufficient_budget", by unfold spendBudget; simp [h]⟩

theorem spend_preserves_wf (tok : CapabilityToken) (amount : Nat)
    (hwf : tokenWellFormed tok) (h : amount ≤ tok.budget_remaining)
    : ∀ tok', spendBudget tok amount = .ok tok' → tokenWellFormed tok' := by
  intro tok' heq
  have hsub := spendBudget_ok_eq tok amount h tok' heq
  subst hsub
  exact ⟨Nat.le_trans (Nat.sub_le _ _) hwf.1, hwf.2.1, hwf.2.2.1, hwf.2.2.2⟩

theorem spend_consecutive (tok : CapabilityToken) (a b : Nat)
    (ha : a ≤ tok.budget_remaining) (hb : b ≤ tok.budget_remaining - a)
    : ∀ t1 t2,
      spendBudget tok a = .ok t1 →
      spendBudget t1 b = .ok t2 →
      t2.budget_remaining = tok.budget_remaining - a - b := by
  intro t1 t2 h1 h2
  have ht1 := spendBudget_ok_eq tok a ha t1 h1
  subst ht1
  have ht2 := spendBudget_ok_eq _ b hb t2 h2
  subst ht2
  simp

-- ═══════════════════════════════════════════════════════════════════════
-- §5  DEL-P1 - Attenuation (delegation)
-- ═══════════════════════════════════════════════════════════════════════

inductive AttenuateResult where
  | ok  (child : CapabilityToken)
  | err (reason : String)
  deriving Repr

def attenuate
    (parent : CapabilityToken)
    (child_id child_agent : String)
    (child_perms : List String) (child_budget : Nat)
    : AttenuateResult :=
  if ¬(permissionsSubset child_perms parent.permissions) then
    .err "permissions_not_subset"
  else if child_budget > parent.budget_remaining then
    .err "budget_exceeds_parent"
  else if child_id.length = 0 then
    .err "empty_child_id"
  else if child_agent.length = 0 then
    .err "empty_child_agent"
  else
    .ok {
      id               := child_id
      agent_id         := child_agent
      permissions      := child_perms
      initial_budget   := child_budget
      budget_remaining := child_budget
      parent_id        := parent.id
      delegation_depth := parent.delegation_depth + 1
    }

-- Helper: destructure successful attenuate into equality + conditions
private theorem attenuate_ok_eq
    (parent : CapabilityToken) (cid cag : String) (cp : List String) (cb : Nat)
    (child : CapabilityToken)
    (h : attenuate parent cid cag cp cb = .ok child)
    : child = { id := cid, agent_id := cag, permissions := cp,
                initial_budget := cb, budget_remaining := cb,
                parent_id := parent.id,
                delegation_depth := parent.delegation_depth + 1 }
      ∧ permissionsSubset cp parent.permissions = true
      ∧ cb ≤ parent.budget_remaining
      ∧ cid.length > 0
      ∧ cag.length > 0 := by
  unfold attenuate at h
  split at h
  · injection h
  · split at h
    · injection h
    · split at h
      · injection h
      · split at h
        · injection h
        · rename_i hcag hcid hbudget hperms
          have hp : permissionsSubset cp parent.permissions = true := by
            exact Classical.not_not.mp hcag
          have hb : cb ≤ parent.budget_remaining := Nat.le_of_not_gt hcid
          have hci : cid.length > 0 := Nat.pos_of_ne_zero hbudget
          have hca : cag.length > 0 := Nat.pos_of_ne_zero hperms
          injection h with h
          exact ⟨h.symm, hp, hb, hci, hca⟩

-- ── P1a: child permissions ⊆ parent permissions ───────────────────

theorem attenuate_perms_subset
    (parent : CapabilityToken) (cid cag : String) (cp : List String) (cb : Nat)
    (child : CapabilityToken)
    (h : attenuate parent cid cag cp cb = .ok child)
    : permissionsSubset child.permissions parent.permissions = true := by
  have ⟨heq, hps, _, _, _⟩ := attenuate_ok_eq parent cid cag cp cb child h
  subst heq; exact hps

-- ── P1b: child budget ≤ parent remaining ─────────────────────────

theorem attenuate_budget_bound
    (parent : CapabilityToken) (cid cag : String) (cp : List String) (cb : Nat)
    (child : CapabilityToken)
    (h : attenuate parent cid cag cp cb = .ok child)
    : child.initial_budget ≤ parent.budget_remaining := by
  have ⟨heq, _, hle, _, _⟩ := attenuate_ok_eq parent cid cag cp cb child h
  subst heq; exact hle

-- ── P1: child starts with full budget ────────────────────────────

theorem attenuate_fresh_budget
    (parent : CapabilityToken) (cid cag : String) (cp : List String) (cb : Nat)
    (child : CapabilityToken)
    (h : attenuate parent cid cag cp cb = .ok child)
    : child.budget_remaining = child.initial_budget := by
  have ⟨heq, _, _, _, _⟩ := attenuate_ok_eq parent cid cag cp cb child h
  subst heq; rfl

-- ── P1: provenance tracking ─────────────────────────────────────

theorem attenuate_provenance
    (parent : CapabilityToken) (cid cag : String) (cp : List String) (cb : Nat)
    (child : CapabilityToken)
    (h : attenuate parent cid cag cp cb = .ok child)
    : child.parent_id = parent.id := by
  have ⟨heq, _, _, _, _⟩ := attenuate_ok_eq parent cid cag cp cb child h
  subst heq; rfl

-- ── P1: depth tracking ──────────────────────────────────────────

theorem attenuate_depth
    (parent : CapabilityToken) (cid cag : String) (cp : List String) (cb : Nat)
    (child : CapabilityToken)
    (h : attenuate parent cid cag cp cb = .ok child)
    : child.delegation_depth = parent.delegation_depth + 1 := by
  have ⟨heq, _, _, _, _⟩ := attenuate_ok_eq parent cid cag cp cb child h
  subst heq; rfl

-- ── P1c: escalation rejected ────────────────────────────────────

theorem attenuate_escalation_rejected
    (parent : CapabilityToken) (cid cag : String) (cp : List String) (cb : Nat)
    (h : ¬(permissionsSubset cp parent.permissions = true))
    : ∃ reason, attenuate parent cid cag cp cb = .err reason := by
  simp [attenuate, h]

-- ── P1d: overbudget rejected ────────────────────────────────────

theorem attenuate_overbudget_rejected
    (parent : CapabilityToken) (cid cag : String) (cp : List String) (cb : Nat)
    (hperm : permissionsSubset cp parent.permissions = true)
    (hbudget : cb > parent.budget_remaining)
    : ∃ reason, attenuate parent cid cag cp cb = .err reason := by
  simp [attenuate, hperm, hbudget]

-- ═══════════════════════════════════════════════════════════════════════
-- §6  DEL-P1: Well-formedness preserved
-- ═══════════════════════════════════════════════════════════════════════

theorem attenuate_preserves_wf
    (parent : CapabilityToken) (cid cag : String) (cp : List String) (cb : Nat)
    (hwf : tokenWellFormed parent)
    (child : CapabilityToken)
    (h : attenuate parent cid cag cp cb = .ok child)
    : tokenWellFormed child := by
  have ⟨heq, _, _, hcid, hcag⟩ := attenuate_ok_eq parent cid cag cp cb child h
  subst heq
  refine ⟨Nat.le_refl _, ?_, hcid, hcag⟩
  -- Need: parent.id = "" ↔ parent.delegation_depth + 1 = 0
  constructor
  · -- parent.id = "" → impossible (parent.id.length > 0 from hwf)
    intro hpid
    have h1 : parent.id.length > 0 := hwf.2.2.1
    have hpid' : parent.id = "" := by simpa using hpid
    rw [hpid'] at h1
    exact absurd h1 (by decide)
  · -- parent.delegation_depth + 1 = 0 → impossible for Nat
    intro hdepth
    exfalso
    have hdepth0 : parent.delegation_depth + 1 = 0 := hdepth
    have : Nat.succ parent.delegation_depth = 0 := by
      rw [Nat.succ_eq_add_one]
      exact hdepth0
    exact Nat.succ_ne_zero _ this

-- ═══════════════════════════════════════════════════════════════════════
-- §7  DEL-P8 - Attenuation transitivity
-- ═══════════════════════════════════════════════════════════════════════

theorem transitivity_permissions
    (gp : CapabilityToken)
    (pid pag : String) (pperms : List String) (pbudget : Nat)
    (cid cag : String) (cperms : List String) (cbudget : Nat)
    (parent child : CapabilityToken)
    (hp : attenuate gp pid pag pperms pbudget = .ok parent)
    (hc : attenuate parent cid cag cperms cbudget = .ok child)
    : permissionsSubset child.permissions gp.permissions = true := by
  have hcp := attenuate_perms_subset parent cid cag cperms cbudget child hc
  have hpp := attenuate_perms_subset gp pid pag pperms pbudget parent hp
  exact permissionsSubset_trans child.permissions parent.permissions gp.permissions hcp hpp

theorem transitivity_budget
    (gp : CapabilityToken)
    (pid pag : String) (pperms : List String) (pbudget : Nat)
    (cid cag : String) (cperms : List String) (cbudget : Nat)
    (parent child : CapabilityToken)
    (hp : attenuate gp pid pag pperms pbudget = .ok parent)
    (hc : attenuate parent cid cag cperms cbudget = .ok child)
    : child.initial_budget ≤ gp.budget_remaining := by
  have hcb : child.initial_budget ≤ parent.budget_remaining :=
    attenuate_budget_bound parent cid cag cperms cbudget child hc
  have hpb : parent.initial_budget ≤ gp.budget_remaining :=
    attenuate_budget_bound gp pid pag pperms pbudget parent hp
  have hpr : parent.budget_remaining = parent.initial_budget :=
    attenuate_fresh_budget gp pid pag pperms pbudget parent hp
  have hpb' : parent.budget_remaining ≤ gp.budget_remaining := by
    simpa [hpr] using hpb
  exact Nat.le_trans hcb hpb'

theorem transitivity_depth
    (gp : CapabilityToken)
    (pid pag : String) (pperms : List String) (pbudget : Nat)
    (cid cag : String) (cperms : List String) (cbudget : Nat)
    (parent child : CapabilityToken)
    (hp : attenuate gp pid pag pperms pbudget = .ok parent)
    (hc : attenuate parent cid cag cperms cbudget = .ok child)
    : child.delegation_depth = gp.delegation_depth + 2 := by
  have hpd := attenuate_depth gp pid pag pperms pbudget parent hp
  have hcd := attenuate_depth parent cid cag cperms cbudget child hc
  omega

theorem transitivity_wellformed
    (gp : CapabilityToken)
    (pid pag : String) (pperms : List String) (pbudget : Nat)
    (cid cag : String) (cperms : List String) (cbudget : Nat)
    (hwf : tokenWellFormed gp)
    (parent child : CapabilityToken)
    (hp : attenuate gp pid pag pperms pbudget = .ok parent)
    (hc : attenuate parent cid cag cperms cbudget = .ok child)
    : tokenWellFormed child := by
  have hwf_p := attenuate_preserves_wf gp pid pag pperms pbudget hwf parent hp
  exact attenuate_preserves_wf parent cid cag cperms cbudget hwf_p child hc

-- ═══════════════════════════════════════════════════════════════════════
-- §8  Inductive delegation chains
-- ═══════════════════════════════════════════════════════════════════════

inductive DelegationChain : CapabilityToken → List CapabilityToken → Prop where
  | root (tok : CapabilityToken) : DelegationChain tok [tok]
  | step (root : CapabilityToken) (chain : List CapabilityToken)
         (parent child : CapabilityToken)
         (hchain : DelegationChain root (parent :: chain))
         (hatt : ∃ cid cag cperms cbudget,
           attenuate parent cid cag cperms cbudget = .ok child)
         : DelegationChain root (child :: parent :: chain)

theorem chain_permissions_subset
    (rt : CapabilityToken) (chain : List CapabilityToken)
    (hchain : DelegationChain rt chain)
    : ∀ tok ∈ chain, permissionsSubset tok.permissions rt.permissions = true := by
  induction hchain with
  | root =>
    intro t ht
    cases ht with
    | head => exact permissionsSubset_refl _
    | tail _ h => exact absurd h (List.not_mem_nil _)
  | step ch parent child hch hatt ih =>
    intro t ht
    cases ht with
    | head =>
      obtain ⟨cid, cag, cperms, cbudget, hok⟩ := hatt
      exact permissionsSubset_trans child.permissions parent.permissions rt.permissions
        (attenuate_perms_subset parent cid cag cperms cbudget child hok)
        (ih parent (List.mem_cons_self _ _))
    | tail _ hin => exact ih t hin

inductive WFDelegationChain : CapabilityToken → List CapabilityToken → Prop where
  | root (tok : CapabilityToken) (hwf : tokenWellFormed tok)
    : WFDelegationChain tok [tok]
  | step (rt : CapabilityToken) (ch : List CapabilityToken)
         (parent child : CapabilityToken)
         (hchain : WFDelegationChain rt (parent :: ch))
         (hatt : ∃ cid cag cperms cbudget,
           attenuate parent cid cag cperms cbudget = .ok child)
    : WFDelegationChain rt (child :: parent :: ch)

theorem wfchain_all_wf
    (rt : CapabilityToken) (chain : List CapabilityToken)
    (hc : WFDelegationChain rt chain)
    : ∀ tok ∈ chain, tokenWellFormed tok := by
  induction hc with
  | root hwf =>
    intro t ht
    cases ht with
    | head => exact hwf
    | tail _ h => exact absurd h (List.not_mem_nil _)
  | step ch parent child hch hatt ih =>
    intro t ht
    cases ht with
    | head =>
      obtain ⟨cid, cag, cperms, cbudget, hok⟩ := hatt
      exact attenuate_preserves_wf parent cid cag cperms cbudget
        (ih parent (List.mem_cons_self _ _)) child hok
    | tail _ hin => exact ih t hin

theorem chain_budget_bound
    (rt : CapabilityToken) (chain : List CapabilityToken)
    (hc : WFDelegationChain rt chain)
    : ∀ tok ∈ chain, tok.initial_budget ≤ rt.initial_budget := by
  induction hc with
  | root _ =>
    intro t ht
    cases ht with
    | head => exact Nat.le_refl _
    | tail _ h => exact absurd h (List.not_mem_nil _)
  | step ch parent child hch hatt ih =>
    intro t ht
    cases ht with
    | head =>
      obtain ⟨cid, cag, cperms, cbudget, hok⟩ := hatt
      have hcb := attenuate_budget_bound parent cid cag cperms cbudget child hok
      have hwf_p := wfchain_all_wf rt (parent :: ch) hch parent (List.mem_cons_self _ _)
      have hpb := ih parent (List.mem_cons_self parent ch)
      exact Nat.le_trans hcb (Nat.le_trans hwf_p.1 hpb)
    | tail _ hin => exact ih t hin

theorem budget_bound_two_step
    (gp parent child : CapabilityToken)
    (pid pag : String) (pperms : List String) (pbudget : Nat)
    (cid cag : String) (cperms : List String) (cbudget : Nat)
    (hp : attenuate gp pid pag pperms pbudget = .ok parent)
    (hc : attenuate parent cid cag cperms cbudget = .ok child)
    : child.initial_budget ≤ gp.budget_remaining :=
  transitivity_budget gp pid pag pperms pbudget cid cag cperms cbudget parent child hp hc

-- ═══════════════════════════════════════════════════════════════════════
-- §9  MASTER THEOREM - Delegation Safety
-- ═══════════════════════════════════════════════════════════════════════

structure DelegationSafety where
  perms_subset     : ∀ (parent : CapabilityToken) cid cag cperms cbudget child,
                       attenuate parent cid cag cperms cbudget = .ok child →
                       permissionsSubset child.permissions parent.permissions = true
  budget_bound     : ∀ (parent : CapabilityToken) cid cag cperms cbudget child,
                       attenuate parent cid cag cperms cbudget = .ok child →
                       child.initial_budget ≤ parent.budget_remaining
  fresh_budget     : ∀ (parent : CapabilityToken) cid cag cperms cbudget child,
                       attenuate parent cid cag cperms cbudget = .ok child →
                       child.budget_remaining = child.initial_budget
  provenance       : ∀ (parent : CapabilityToken) cid cag cperms cbudget child,
                       attenuate parent cid cag cperms cbudget = .ok child →
                       child.parent_id = parent.id
  depth            : ∀ (parent : CapabilityToken) cid cag cperms cbudget child,
                       attenuate parent cid cag cperms cbudget = .ok child →
                       child.delegation_depth = parent.delegation_depth + 1
  wellformed       : ∀ (parent : CapabilityToken) cid cag cperms cbudget child,
                       tokenWellFormed parent →
                       attenuate parent cid cag cperms cbudget = .ok child →
                       tokenWellFormed child
  spend_mono       : ∀ (tok : CapabilityToken) amount tok',
                       amount ≤ tok.budget_remaining →
                       spendBudget tok amount = .ok tok' →
                       tok'.budget_remaining ≤ tok.budget_remaining
  spend_bnd        : ∀ (tok : CapabilityToken) amount tok',
                       tokenWellFormed tok →
                       amount ≤ tok.budget_remaining →
                       spendBudget tok amount = .ok tok' →
                       tok'.budget_remaining ≤ tok'.initial_budget
  perm_found       : ∀ (perm : String) (perms : List String),
                       perm ∈ perms → hasPermission perm perms = true
  perm_empty       : ∀ (perm : String), hasPermission perm [] = false
  subset_trans     : ∀ (a b c : List String),
                       permissionsSubset a b = true →
                       permissionsSubset b c = true →
                       permissionsSubset a c = true
  trans_perms      : ∀ (gp : CapabilityToken) pid pag pperms pbudget
                       cid cag cperms cbudget parent child,
                       attenuate gp pid pag pperms pbudget = .ok parent →
                       attenuate parent cid cag cperms cbudget = .ok child →
                       permissionsSubset child.permissions gp.permissions = true
  trans_budget     : ∀ (gp : CapabilityToken) pid pag pperms pbudget
                       cid cag cperms cbudget parent child,
                       attenuate gp pid pag pperms pbudget = .ok parent →
                       attenuate parent cid cag cperms cbudget = .ok child →
                       child.initial_budget ≤ gp.budget_remaining
  trans_depth      : ∀ (gp : CapabilityToken) pid pag pperms pbudget
                       cid cag cperms cbudget parent child,
                       attenuate gp pid pag pperms pbudget = .ok parent →
                       attenuate parent cid cag cperms cbudget = .ok child →
                       child.delegation_depth = gp.delegation_depth + 2
  trans_wf         : ∀ (gp : CapabilityToken) pid pag pperms pbudget
                       cid cag cperms cbudget parent child,
                       tokenWellFormed gp →
                       attenuate gp pid pag pperms pbudget = .ok parent →
                       attenuate parent cid cag cperms cbudget = .ok child →
                       tokenWellFormed child

theorem delegationSafety : DelegationSafety where
  perms_subset   := attenuate_perms_subset
  budget_bound   := attenuate_budget_bound
  fresh_budget   := attenuate_fresh_budget
  provenance     := attenuate_provenance
  depth          := attenuate_depth
  wellformed     := fun parent cid cag cp cb child hwf h =>
                      attenuate_preserves_wf parent cid cag cp cb hwf child h
  spend_mono     := fun tok amount tok' h heq =>
                      spend_monotone tok amount h tok' heq
  spend_bnd      := fun tok amount tok' hwf h heq =>
                      spend_bounded tok amount hwf h tok' heq
  perm_found     := hasPermission_of_mem
  perm_empty     := hasPermission_empty
  subset_trans   := permissionsSubset_trans
  trans_perms    := transitivity_permissions
  trans_budget   := transitivity_budget
  trans_depth    := transitivity_depth
  trans_wf       := fun gp pid pag pp pb cid cag cp cb parent child hwf hp hc =>
                      transitivity_wellformed gp pid pag pp pb cid cag cp cb hwf parent child hp hc

end Certior.Delegation

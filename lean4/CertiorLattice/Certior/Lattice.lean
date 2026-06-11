/-
  Certior - Lean 4 Formal Verification (Phase C · Theorem C1)

  Module : Certior.Lattice
  Proves : `SecurityLevel` is a valid bounded lattice.

  Build:  cd lean4/CertiorLattice && lake build
-/

inductive SecurityLevel where
  | Public
  | Internal
  | Sensitive
  | Restricted
  deriving DecidableEq, Repr

namespace SecurityLevel

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Rank
-- ═══════════════════════════════════════════════════════════════════════

def rank : SecurityLevel → Nat
  | .Public     => 0
  | .Internal   => 1
  | .Sensitive  => 2
  | .Restricted => 3

theorem rank_injective (a b : SecurityLevel) (h : rank a = rank b) : a = b := by
  cases a <;> cases b <;> simp_all [rank]

theorem rank_distinct_Public_Internal     : rank .Public ≠ rank .Internal     := by decide
theorem rank_distinct_Public_Sensitive    : rank .Public ≠ rank .Sensitive    := by decide
theorem rank_distinct_Public_Restricted   : rank .Public ≠ rank .Restricted   := by decide
theorem rank_distinct_Internal_Sensitive  : rank .Internal ≠ rank .Sensitive  := by decide
theorem rank_distinct_Internal_Restricted : rank .Internal ≠ rank .Restricted := by decide
theorem rank_distinct_Sensitive_Restricted: rank .Sensitive ≠ rank .Restricted:= by decide

theorem rank_Public_lt_Internal     : rank .Public < rank .Internal     := by decide
theorem rank_Internal_lt_Sensitive  : rank .Internal < rank .Sensitive  := by decide
theorem rank_Sensitive_lt_Restricted: rank .Sensitive < rank .Restricted:= by decide
theorem rank_Public_lt_Restricted   : rank .Public < rank .Restricted   := by decide

-- ═══════════════════════════════════════════════════════════════════════
-- §2  Flow predicate
-- ═══════════════════════════════════════════════════════════════════════

def levelCanFlowTo (src dst : SecurityLevel) : Prop :=
  rank src ≤ rank dst

instance instDecidableLevelCanFlowTo (src dst : SecurityLevel)
    : Decidable (levelCanFlowTo src dst) :=
  inferInstanceAs (Decidable (rank src ≤ rank dst))

-- ═══════════════════════════════════════════════════════════════════════
-- §3  P13 - LATTICE ORDERING
-- ═══════════════════════════════════════════════════════════════════════

theorem flowTo_refl (a : SecurityLevel) : levelCanFlowTo a a :=
  Nat.le_refl _

theorem flowTo_trans (a b c : SecurityLevel)
    (hab : levelCanFlowTo a b) (hbc : levelCanFlowTo b c)
    : levelCanFlowTo a c :=
  Nat.le_trans hab hbc

theorem flowTo_antisymm (a b : SecurityLevel)
    (hab : levelCanFlowTo a b) (hba : levelCanFlowTo b a) : a = b :=
  rank_injective a b (Nat.le_antisymm hab hba)

theorem flowTo_total (a b : SecurityLevel)
    : levelCanFlowTo a b ∨ levelCanFlowTo b a := by
  unfold levelCanFlowTo; omega

-- ═══════════════════════════════════════════════════════════════════════
-- §4  P14 - FLOW SAFETY
-- ═══════════════════════════════════════════════════════════════════════

theorem flowSafety_iff (src dst : SecurityLevel)
    : levelCanFlowTo src dst ↔ rank src ≤ rank dst :=
  Iff.rfl

theorem flowSafety_noDowngrade (src dst : SecurityLevel)
    (h : rank src > rank dst) : ¬ levelCanFlowTo src dst := by
  unfold levelCanFlowTo; omega

theorem flowSafety_upgradeAllowed (src dst : SecurityLevel)
    (h : rank src ≤ rank dst) : levelCanFlowTo src dst := h

theorem flow_exhaustive_allowed :
    levelCanFlowTo .Public .Public ∧
    levelCanFlowTo .Public .Internal ∧
    levelCanFlowTo .Public .Sensitive ∧
    levelCanFlowTo .Public .Restricted ∧
    levelCanFlowTo .Internal .Internal ∧
    levelCanFlowTo .Internal .Sensitive ∧
    levelCanFlowTo .Internal .Restricted ∧
    levelCanFlowTo .Sensitive .Sensitive ∧
    levelCanFlowTo .Sensitive .Restricted ∧
    levelCanFlowTo .Restricted .Restricted := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> unfold levelCanFlowTo <;> simp [rank]

theorem flow_exhaustive_blocked :
    ¬ levelCanFlowTo .Internal .Public ∧
    ¬ levelCanFlowTo .Sensitive .Public ∧
    ¬ levelCanFlowTo .Sensitive .Internal ∧
    ¬ levelCanFlowTo .Restricted .Public ∧
    ¬ levelCanFlowTo .Restricted .Internal ∧
    ¬ levelCanFlowTo .Restricted .Sensitive := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;> unfold levelCanFlowTo <;> simp [rank]

-- ═══════════════════════════════════════════════════════════════════════
-- §5  LE / LT instances
-- ═══════════════════════════════════════════════════════════════════════

instance : LE SecurityLevel where le a b := rank a ≤ rank b
instance : LT SecurityLevel where lt a b := rank a < rank b

instance instDecidableLE (a b : SecurityLevel) : Decidable (a ≤ b) :=
  inferInstanceAs (Decidable (rank a ≤ rank b))

instance instDecidableLT (a b : SecurityLevel) : Decidable (a < b) :=
  inferInstanceAs (Decidable (rank a < rank b))

theorem le_def (a b : SecurityLevel) : (a ≤ b) = (rank a ≤ rank b) := rfl
theorem lt_def (a b : SecurityLevel) : (a < b) = (rank a < rank b) := rfl

theorem le_refl (a : SecurityLevel) : a ≤ a := Nat.le_refl _
theorem le_trans (a b c : SecurityLevel) (hab : a ≤ b) (hbc : b ≤ c) : a ≤ c :=
  Nat.le_trans hab hbc
theorem le_antisymm (a b : SecurityLevel) (hab : a ≤ b) (hba : b ≤ a) : a = b :=
  rank_injective a b (Nat.le_antisymm hab hba)
theorem le_total (a b : SecurityLevel) : a ≤ b ∨ b ≤ a := by
  show rank a ≤ rank b ∨ rank b ≤ rank a; omega

-- ═══════════════════════════════════════════════════════════════════════
-- §6  JOIN (least upper bound)
-- ═══════════════════════════════════════════════════════════════════════

def join (a b : SecurityLevel) : SecurityLevel :=
  if rank a ≥ rank b then a else b

theorem join_le_left (a b : SecurityLevel) : a ≤ join a b := by
  show rank a ≤ rank (if rank a ≥ rank b then a else b)
  split <;> omega

theorem join_le_right (a b : SecurityLevel) : b ≤ join a b := by
  show rank b ≤ rank (if rank a ≥ rank b then a else b)
  split <;> omega

theorem join_least (a b c : SecurityLevel) (ha : a ≤ c) (hb : b ≤ c)
    : join a b ≤ c := by
  show rank (if rank a ≥ rank b then a else b) ≤ rank c
  split
  · exact ha
  · exact hb

theorem join_idem (a : SecurityLevel) : join a a = a := by
  simp [join]

theorem join_comm (a b : SecurityLevel) : join a b = join b a := by
  cases a <;> cases b <;> simp [join, rank]

theorem join_assoc (a b c : SecurityLevel)
    : join (join a b) c = join a (join b c) := by
  cases a <;> cases b <;> cases c <;> simp [join, rank]

theorem join_mono_left (a b c : SecurityLevel) (h : a ≤ b) : join a c ≤ join b c :=
  join_least a c (join b c) (le_trans a b (join b c) h (join_le_left b c)) (join_le_right b c)

theorem join_mono_right (a b c : SecurityLevel) (h : b ≤ c) : join a b ≤ join a c :=
  join_least a b (join a c) (join_le_left a c) (le_trans b c (join a c) h (join_le_right a c))

theorem join_preserves_flowTarget (a b c : SecurityLevel)
    (ha : levelCanFlowTo a c) (hb : levelCanFlowTo b c)
    : levelCanFlowTo (join a b) c :=
  join_least a b c ha hb

-- ═══════════════════════════════════════════════════════════════════════
-- §7  MEET (greatest lower bound)
-- ═══════════════════════════════════════════════════════════════════════

def meet (a b : SecurityLevel) : SecurityLevel :=
  if rank a ≤ rank b then a else b

theorem meet_le_left (a b : SecurityLevel) : meet a b ≤ a := by
  show rank (if rank a ≤ rank b then a else b) ≤ rank a
  split <;> omega

theorem meet_le_right (a b : SecurityLevel) : meet a b ≤ b := by
  show rank (if rank a ≤ rank b then a else b) ≤ rank b
  split <;> omega

theorem meet_greatest (a b c : SecurityLevel) (ha : c ≤ a) (hb : c ≤ b)
    : c ≤ meet a b := by
  show rank c ≤ rank (if rank a ≤ rank b then a else b)
  split
  · exact ha
  · exact hb

theorem meet_idem (a : SecurityLevel) : meet a a = a := by
  simp [meet]

theorem meet_comm (a b : SecurityLevel) : meet a b = meet b a := by
  cases a <;> cases b <;> simp [meet, rank]

theorem meet_assoc (a b c : SecurityLevel)
    : meet (meet a b) c = meet a (meet b c) := by
  cases a <;> cases b <;> cases c <;> simp [meet, rank]

theorem meet_mono_left (a b c : SecurityLevel) (h : a ≤ b) : meet a c ≤ meet b c :=
  meet_greatest b c (meet a c) (le_trans (meet a c) a b (meet_le_left a c) h) (meet_le_right a c)

-- ═══════════════════════════════════════════════════════════════════════
-- §8  ABSORPTION & DISTRIBUTIVITY
-- ═══════════════════════════════════════════════════════════════════════

theorem join_meet_absorb (a b : SecurityLevel) : join a (meet a b) = a := by
  cases a <;> cases b <;> simp [join, meet, rank]

theorem meet_join_absorb (a b : SecurityLevel) : meet a (join a b) = a := by
  cases a <;> cases b <;> simp [meet, join, rank]

theorem meet_join_distrib (a b c : SecurityLevel)
    : meet a (join b c) = join (meet a b) (meet a c) := by
  cases a <;> cases b <;> cases c <;> simp [meet, join, rank]

theorem join_meet_distrib (a b c : SecurityLevel)
    : join a (meet b c) = meet (join a b) (join a c) := by
  cases a <;> cases b <;> cases c <;> simp [join, meet, rank]

-- ═══════════════════════════════════════════════════════════════════════
-- §9  BOUNDED LATTICE
-- ═══════════════════════════════════════════════════════════════════════

def bot : SecurityLevel := .Public
def top : SecurityLevel := .Restricted

-- Use `show` to reduce LE to Nat, then `cases` + `decide` to avoid simp recursion
theorem bot_le (a : SecurityLevel) : bot ≤ a := by
  show rank bot ≤ rank a; cases a <;> decide

theorem le_top (a : SecurityLevel) : a ≤ top := by
  show rank a ≤ rank top; cases a <;> decide

theorem join_bot (a : SecurityLevel) : join bot a = a := by
  cases a <;> simp [join, bot, rank]

theorem bot_join (a : SecurityLevel) : join a bot = a := by
  cases a <;> simp [join, bot, rank]

theorem meet_top (a : SecurityLevel) : meet top a = a := by
  cases a <;> simp [meet, top, rank]

theorem top_meet (a : SecurityLevel) : meet a top = a := by
  cases a <;> simp [meet, top, rank]

theorem join_top (a : SecurityLevel) : join top a = top := by
  cases a <;> simp [join, top, rank]

theorem top_join (a : SecurityLevel) : join a top = top := by
  cases a <;> simp [join, top, rank]

theorem meet_bot (a : SecurityLevel) : meet bot a = bot := by
  cases a <;> simp [meet, bot, rank]

theorem bot_meet (a : SecurityLevel) : meet a bot = bot := by
  cases a <;> simp [meet, bot, rank]

-- ═══════════════════════════════════════════════════════════════════════
-- §10  FINITENESS
-- ═══════════════════════════════════════════════════════════════════════

theorem bot_ne_top : (bot : SecurityLevel) ≠ top := by decide
theorem rank_bot : rank bot = 0 := rfl
theorem rank_top : rank top = 3 := rfl

def all : List SecurityLevel := [.Public, .Internal, .Sensitive, .Restricted]

theorem all_complete (a : SecurityLevel) : a ∈ all := by cases a <;> simp [all]
theorem all_nodup : all.Nodup := by decide
theorem card_eq_four : all.length = 4 := rfl

theorem is_chain (a b : SecurityLevel) : a ≤ b ∨ b ≤ a := le_total a b

-- ═══════════════════════════════════════════════════════════════════════
-- §11  SecurityLabel
-- ═══════════════════════════════════════════════════════════════════════

structure SecurityLabel where
  level : SecurityLevel
  tags  : List String
  owner : String := ""
  deriving DecidableEq, Repr

namespace SecurityLabel

def tagsSubset (a b : List String) : Prop :=
  ∀ (t : String), t ∈ a → t ∈ b

instance instDecidableTagsSubset (a b : List String) : Decidable (tagsSubset a b) :=
  show Decidable (∀ t, t ∈ a → t ∈ b) from
    inferInstanceAs (Decidable (∀ t ∈ a, t ∈ b))

def canFlowTo (src dst : SecurityLabel) : Prop :=
  levelCanFlowTo src.level dst.level ∧ tagsSubset src.tags dst.tags

theorem canFlowTo_requires_level (src dst : SecurityLabel)
    (h : ¬ levelCanFlowTo src.level dst.level) : ¬ canFlowTo src dst :=
  fun ⟨hlev, _⟩ => h hlev

theorem canFlowTo_requires_tags (src dst : SecurityLabel)
    (h : ¬ tagsSubset src.tags dst.tags) : ¬ canFlowTo src dst :=
  fun ⟨_, htags⟩ => h htags

theorem canFlowTo_sufficient (src dst : SecurityLabel)
    (hlev : levelCanFlowTo src.level dst.level)
    (htags : tagsSubset src.tags dst.tags) : canFlowTo src dst :=
  ⟨hlev, htags⟩

theorem canFlowTo_refl (l : SecurityLabel) : canFlowTo l l :=
  ⟨flowTo_refl l.level, fun _ h => h⟩

theorem canFlowTo_trans (a b c : SecurityLabel)
    (hab : canFlowTo a b) (hbc : canFlowTo b c) : canFlowTo a c :=
  ⟨flowTo_trans a.level b.level c.level hab.1 hbc.1,
   fun t ht => hbc.2 t (hab.2 t ht)⟩

theorem emptyTags_flowTo (lev : SecurityLevel) (dst : SecurityLabel)
    (h : levelCanFlowTo lev dst.level) : canFlowTo ⟨lev, [], ""⟩ dst :=
  ⟨h, fun _ h => absurd h (List.not_mem_nil _)⟩

end SecurityLabel

-- ═══════════════════════════════════════════════════════════════════════
-- §12  MASTER THEOREM
-- ═══════════════════════════════════════════════════════════════════════

structure IsValidBoundedLattice where
  refl          : ∀ (a : SecurityLevel), a ≤ a
  trans         : ∀ (a b c : SecurityLevel), a ≤ b → b ≤ c → a ≤ c
  antisymm      : ∀ (a b : SecurityLevel), a ≤ b → b ≤ a → a = b
  total         : ∀ (a b : SecurityLevel), a ≤ b ∨ b ≤ a
  join_ub_l     : ∀ (a b : SecurityLevel), a ≤ join a b
  join_ub_r     : ∀ (a b : SecurityLevel), b ≤ join a b
  join_lub      : ∀ (a b c : SecurityLevel), a ≤ c → b ≤ c → join a b ≤ c
  meet_lb_l     : ∀ (a b : SecurityLevel), meet a b ≤ a
  meet_lb_r     : ∀ (a b : SecurityLevel), meet a b ≤ b
  meet_glb      : ∀ (a b c : SecurityLevel), c ≤ a → c ≤ b → c ≤ meet a b
  absorb_jm     : ∀ (a b : SecurityLevel), join a (meet a b) = a
  absorb_mj     : ∀ (a b : SecurityLevel), meet a (join a b) = a
  distrib       : ∀ (a b c : SecurityLevel), meet a (join b c) = join (meet a b) (meet a c)
  bot_least     : ∀ (a : SecurityLevel), bot ≤ a
  top_greatest  : ∀ (a : SecurityLevel), a ≤ top
  rank_inj      : ∀ (a b : SecurityLevel), rank a = rank b → a = b
  card          : all.length = 4

theorem isValidBoundedLattice : IsValidBoundedLattice where
  refl         := le_refl
  trans        := le_trans
  antisymm     := le_antisymm
  total        := le_total
  join_ub_l    := join_le_left
  join_ub_r    := join_le_right
  join_lub     := join_least
  meet_lb_l    := meet_le_left
  meet_lb_r    := meet_le_right
  meet_glb     := meet_greatest
  absorb_jm    := join_meet_absorb
  absorb_mj    := meet_join_absorb
  distrib      := meet_join_distrib
  bot_least    := bot_le
  top_greatest := le_top
  rank_inj     := rank_injective
  card         := card_eq_four

end SecurityLevel

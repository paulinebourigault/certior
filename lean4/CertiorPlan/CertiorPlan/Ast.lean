/-
  CertiorPlan.Ast - Verified Agent Plan AST

  Maps ImpLab's language AST to the verified agent domain:

    ImpLab Concept     →  Certior Concept       →  Lean Type
    ─────────────────────────────────────────────────────────
    Stmt               →  PlanStep              →  inductive PlanStep
    Rhs                →  StepRhs               →  inductive StepRhs
    FuncDef            →  SkillDef              →  structure SkillDef
    Program            →  VerifiedPlan          →  structure VerifiedPlan
    Var                →  DataBinding           →  abbrev DataId
    GlobalDecl         →  ResourceDecl          →  structure ResourceDecl
    BinOp              →  FlowOp                →  inductive FlowOp
    ProgramInfo        →  PlanInfo              →  structure PlanInfo

  Every data binding carries a FlowLabel containing a SecurityLevel
  from CertiorLattice's proven bounded distributive lattice.

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import Lean
import Certior.Lattice

open Lean
open SecurityLevel

namespace CertiorPlan

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Name abbreviations - analogous to ImpLab's Var/FuncName/GlobalName
-- ═══════════════════════════════════════════════════════════════════════

/-- Identifier for a data binding within a skill scope. -/
abbrev DataId := String

/-- Identifier for a skill definition. -/
abbrev SkillId := String

/-- Identifier for a capability token. -/
abbrev TokenId := String

/-- Identifier for a mutable resource (budget counter, token slot). -/
abbrev ResourceId := String

-- ═══════════════════════════════════════════════════════════════════════
-- §2  SecurityLevel JSON/Expr instances (bridge from CertiorLattice)
-- ═══════════════════════════════════════════════════════════════════════

-- CertiorLattice defines SecurityLevel but not JSON/Expr - we add them here.

instance : ToString SecurityLevel where
  toString
    | .Public     => "Public"
    | .Internal   => "Internal"
    | .Sensitive  => "Sensitive"
    | .Restricted => "Restricted"

def SecurityLevel.fromString? (s : String) : Option SecurityLevel :=
  match s with
  | "Public"     => some .Public
  | "Internal"   => some .Internal
  | "Sensitive"  => some .Sensitive
  | "Restricted" => some .Restricted
  | _            => none

instance : ToJson SecurityLevel where
  toJson level := Json.str (toString level)

instance : FromJson SecurityLevel where
  fromJson? json := do
    let s ← json.getStr?
    match SecurityLevel.fromString? s with
    | some level => pure level
    | none => throw s!"unknown SecurityLevel: {s}"

instance : ToExpr SecurityLevel where
  toExpr
    | .Public     => mkConst ``SecurityLevel.Public
    | .Internal   => mkConst ``SecurityLevel.Internal
    | .Sensitive  => mkConst ``SecurityLevel.Sensitive
    | .Restricted => mkConst ``SecurityLevel.Restricted
  toTypeExpr := mkConst ``SecurityLevel

instance : Inhabited SecurityLevel where
  default := .Public

-- ═══════════════════════════════════════════════════════════════════════
-- §3  FlowLabel - security label attached to every data binding
-- ═══════════════════════════════════════════════════════════════════════

/-- Security label attached to every data binding.
    Combines a proven SecurityLevel with optional string tags
    for fine-grained DIFC labeling.

    Mirrors `SecurityLabel` from `Certior.Lattice` but optimized
    for the plan execution domain. -/
structure FlowLabel where
  /-- The security clearance level (from the proven lattice). -/
  level : SecurityLevel
  /-- Optional tags for domain-specific labeling (e.g., "PHI", "MNPI"). -/
  tags : List String := []
  deriving Repr, BEq, DecidableEq, Inhabited

instance : ToString FlowLabel where
  toString label :=
    let tagStr := if label.tags.isEmpty then "" else s!" [{String.intercalate ", " label.tags}]"
    s!"@{label.level}{tagStr}"

instance : ToJson FlowLabel where
  toJson label := Json.mkObj [
    ("level", toJson label.level),
    ("tags", toJson label.tags)
  ]

instance : FromJson FlowLabel where
  fromJson? json := do
    let level ← json.getObjValAs? SecurityLevel "level"
    let tags ← json.getObjValAs? (List String) "tags" <|> pure []
    pure { level, tags }

instance : ToExpr FlowLabel where
  toExpr label :=
    mkApp2 (mkConst ``FlowLabel.mk) (toExpr label.level) (toExpr label.tags)
  toTypeExpr := mkConst ``FlowLabel

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Capability - resource permission required by a skill
-- ═══════════════════════════════════════════════════════════════════════

/-- Capability required by a skill invocation.
    Maps to the capability-based security model from CertiorLattice. -/
structure Capability where
  /-- Resource identifier (e.g., "network:http:read", "database:read:patient_data"). -/
  resource : String
  /-- Maximum cost in cents this capability may incur. 0 = no cost. -/
  maxCost : Nat := 0
  deriving Repr, BEq, DecidableEq, Inhabited

instance : ToString Capability where
  toString cap :=
    if cap.maxCost > 0 then s!"{cap.resource}(≤{cap.maxCost}¢)"
    else cap.resource

instance : ToJson Capability where
  toJson cap := Json.mkObj [
    ("resource", toJson cap.resource),
    ("maxCost", toJson cap.maxCost)
  ]

instance : FromJson Capability where
  fromJson? json := do
    let resource ← json.getObjValAs? String "resource"
    let maxCost ← json.getObjValAs? Nat "maxCost" <|> pure 0
    pure { resource, maxCost }

instance : ToExpr Capability where
  toExpr cap :=
    mkApp2 (mkConst ``Capability.mk) (toExpr cap.resource) (toExpr cap.maxCost)
  toTypeExpr := mkConst ``Capability

-- ═══════════════════════════════════════════════════════════════════════
-- §5  FlowOp - operations on security labels
-- ═══════════════════════════════════════════════════════════════════════

/-- Operations on security labels and capabilities.
    Analogous to ImpLab's BinOp but for the security domain. -/
inductive FlowOp where
  /-- Join (⊔) two security levels - least upper bound. -/
  | joinLevels
  /-- Meet (⊓) two security levels - greatest lower bound. -/
  | meetLevels
  /-- Check if flow from src to dst is allowed (rank src ≤ rank dst). -/
  | checkFlow
  /-- Attenuate a capability (remove permissions). -/
  | attenuate
  deriving Repr, BEq, DecidableEq, Inhabited, FromJson, ToJson

instance : ToString FlowOp where
  toString
    | .joinLevels  => "join"
    | .meetLevels  => "meet"
    | .checkFlow   => "checkFlow"
    | .attenuate   => "attenuate"

instance : ToExpr FlowOp where
  toExpr
    | .joinLevels => mkConst ``FlowOp.joinLevels
    | .meetLevels => mkConst ``FlowOp.meetLevels
    | .checkFlow => mkConst ``FlowOp.checkFlow
    | .attenuate => mkConst ``FlowOp.attenuate
  toTypeExpr := mkConst ``FlowOp

-- ═══════════════════════════════════════════════════════════════════════
-- §6  StepRhs - right-hand side of a plan step (analogous to ImpLab.Rhs)
-- ═══════════════════════════════════════════════════════════════════════

/-- Right-hand side of a plan step.
    Analogous to ImpLab's `Rhs` but for verified agent execution.

    Each variant represents a computation that produces a value
    with an associated FlowLabel. -/
inductive StepRhs where
  /-- Literal integer constant. -/
  | literal (value : Int)
  /-- Invoke a skill with arguments. -/
  | invokeSkill (skill : SkillId) (args : Array DataId)
  /-- Check if information flow from src to dst is permitted.
      Returns 1 if allowed, throws FlowViolation if not. -/
  | checkFlow (src dst : DataId)
  /-- Join (⊔) the labels of two data bindings. -/
  | joinLabels (a b : DataId)
  /-- Attenuate a capability token by removing specified capabilities. -/
  | attenuateToken (tokenId : TokenId) (removeCaps : Array String)
  /-- Read a resource value (budget counter, token slot). -/
  | readResource (name : ResourceId)
  deriving Repr, BEq, DecidableEq, Inhabited

instance : ToString StepRhs where
  toString
    | .literal value            => s!"{value}"
    | .invokeSkill skill args   =>
      s!"invoke {skill}({String.intercalate ", " args.toList})"
    | .checkFlow src dst        => s!"checkFlow {src} → {dst}"
    | .joinLabels a b           => s!"joinLabels({a}, {b})"
    | .attenuateToken tid caps  =>
      s!"attenuate {tid} -{String.intercalate ", " caps.toList}"
    | .readResource name        => s!"readResource {name}"

instance : ToJson StepRhs where
  toJson
    | .literal value =>
      Json.mkObj [("tag", "literal"), ("value", toJson value)]
    | .invokeSkill skill args =>
      Json.mkObj [("tag", "invokeSkill"), ("skill", toJson skill), ("args", toJson args)]
    | .checkFlow src dst =>
      Json.mkObj [("tag", "checkFlow"), ("src", toJson src), ("dst", toJson dst)]
    | .joinLabels a b =>
      Json.mkObj [("tag", "joinLabels"), ("a", toJson a), ("b", toJson b)]
    | .attenuateToken tokenId removeCaps =>
      Json.mkObj [("tag", "attenuateToken"), ("tokenId", toJson tokenId),
                  ("removeCaps", toJson removeCaps)]
    | .readResource name =>
      Json.mkObj [("tag", "readResource"), ("name", toJson name)]

instance : FromJson StepRhs where
  fromJson? json := do
    let tag ← json.getObjValAs? String "tag"
    match tag with
    | "literal" =>
      let value ← json.getObjValAs? Int "value"
      pure (.literal value)
    | "invokeSkill" =>
      let skill ← json.getObjValAs? SkillId "skill"
      let args ← json.getObjValAs? (Array DataId) "args"
      pure (.invokeSkill skill args)
    | "checkFlow" =>
      let src ← json.getObjValAs? DataId "src"
      let dst ← json.getObjValAs? DataId "dst"
      pure (.checkFlow src dst)
    | "joinLabels" =>
      let a ← json.getObjValAs? DataId "a"
      let b ← json.getObjValAs? DataId "b"
      pure (.joinLabels a b)
    | "attenuateToken" =>
      let tokenId ← json.getObjValAs? TokenId "tokenId"
      let removeCaps ← json.getObjValAs? (Array String) "removeCaps"
      pure (.attenuateToken tokenId removeCaps)
    | "readResource" =>
      let name ← json.getObjValAs? ResourceId "name"
      pure (.readResource name)
    | _ => throw s!"unknown StepRhs tag: {tag}"

instance : ToExpr StepRhs where
  toExpr
    | .literal value =>
      mkApp (mkConst ``StepRhs.literal) (toExpr value)
    | .invokeSkill skill args =>
      mkApp2 (mkConst ``StepRhs.invokeSkill) (toExpr skill) (toExpr args)
    | .checkFlow src dst =>
      mkApp2 (mkConst ``StepRhs.checkFlow) (toExpr src) (toExpr dst)
    | .joinLabels a b =>
      mkApp2 (mkConst ``StepRhs.joinLabels) (toExpr a) (toExpr b)
    | .attenuateToken tokenId removeCaps =>
      mkApp2 (mkConst ``StepRhs.attenuateToken) (toExpr tokenId) (toExpr removeCaps)
    | .readResource name =>
      mkApp (mkConst ``StepRhs.readResource) (toExpr name)
  toTypeExpr := mkConst ``StepRhs

-- ═══════════════════════════════════════════════════════════════════════
-- §7  PlanStep - a single step in a verified agent plan (ImpLab.Stmt)
-- ═══════════════════════════════════════════════════════════════════════

/-- A single step in a verified agent plan.
    Analogous to ImpLab's `Stmt` but with flow labels on every binding
    and additional verification-specific step types.

    Every `bind` carries a declared FlowLabel that the interpreter
    verifies against the lattice before execution. -/
inductive PlanStep where
  /-- Bind a named data value from a computation, declaring its flow label.
      Analogous to ImpLab's `assign`. -/
  | bind (dest : DataId) (rhs : StepRhs) (label : FlowLabel)
  /-- Set a mutable resource value.
      Analogous to ImpLab's `set`. -/
  | setResource (name : ResourceId) (value : DataId)
  /-- Emit a final result value (analogous to ImpLab's `return`). -/
  | emitResult (value : DataId)
  /-- Require human approval before proceeding.
      Halts execution until external approval is granted. -/
  | requireApproval (reason : String)
  deriving Repr, BEq, DecidableEq, Inhabited

instance : ToString PlanStep where
  toString
    | .bind dest rhs label     => s!"let {dest} := {rhs} {label}"
    | .setResource name value  => s!"set {name} := {value}"
    | .emitResult value        => s!"emit {value}"
    | .requireApproval reason  => s!"requireApproval \"{reason}\""

instance : ToJson PlanStep where
  toJson
    | .bind dest rhs label =>
      Json.mkObj [("tag", "bind"), ("dest", toJson dest),
                  ("rhs", toJson rhs), ("label", toJson label)]
    | .setResource name value =>
      Json.mkObj [("tag", "setResource"), ("name", toJson name),
                  ("value", toJson value)]
    | .emitResult value =>
      Json.mkObj [("tag", "emitResult"), ("value", toJson value)]
    | .requireApproval reason =>
      Json.mkObj [("tag", "requireApproval"), ("reason", toJson reason)]

instance : FromJson PlanStep where
  fromJson? json := do
    let tag ← json.getObjValAs? String "tag"
    match tag with
    | "bind" =>
      let dest ← json.getObjValAs? DataId "dest"
      let rhs ← json.getObjValAs? StepRhs "rhs"
      let label ← json.getObjValAs? FlowLabel "label"
      pure (.bind dest rhs label)
    | "setResource" =>
      let name ← json.getObjValAs? ResourceId "name"
      let value ← json.getObjValAs? DataId "value"
      pure (.setResource name value)
    | "emitResult" =>
      let value ← json.getObjValAs? DataId "value"
      pure (.emitResult value)
    | "requireApproval" =>
      let reason ← json.getObjValAs? String "reason"
      pure (.requireApproval reason)
    | _ => throw s!"unknown PlanStep tag: {tag}"

instance : ToExpr PlanStep where
  toExpr
    | .bind dest rhs label =>
      mkApp3 (mkConst ``PlanStep.bind) (toExpr dest) (toExpr rhs) (toExpr label)
    | .setResource name value =>
      mkApp2 (mkConst ``PlanStep.setResource) (toExpr name) (toExpr value)
    | .emitResult value =>
      mkApp (mkConst ``PlanStep.emitResult) (toExpr value)
    | .requireApproval reason =>
      mkApp (mkConst ``PlanStep.requireApproval) (toExpr reason)
  toTypeExpr := mkConst ``PlanStep

-- ═══════════════════════════════════════════════════════════════════════
-- §8  ResourceDecl - mutable resource (ImpLab.GlobalDecl)
-- ═══════════════════════════════════════════════════════════════════════

/-- Resource declaration: a mutable value (budget counter, token slot)
    with an initial value and security label.
    Analogous to ImpLab's `GlobalDecl`. -/
structure ResourceDecl where
  /-- Resource name (e.g., "budget", "patientToken"). -/
  name : ResourceId
  /-- Initial integer value. -/
  init : Int
  /-- Security label on this resource. -/
  label : FlowLabel := { level := .Internal }
  deriving Repr, BEq, DecidableEq, Inhabited, FromJson, ToJson

instance : ToString ResourceDecl where
  toString res := s!"resource {res.name} := {res.init} {res.label}"

instance : ToExpr ResourceDecl where
  toExpr res :=
    mkApp3 (mkConst ``ResourceDecl.mk) (toExpr res.name) (toExpr res.init) (toExpr res.label)
  toTypeExpr := mkConst ``ResourceDecl

-- ═══════════════════════════════════════════════════════════════════════
-- §9  SkillDef - skill definition (ImpLab.FuncDef)
-- ═══════════════════════════════════════════════════════════════════════

/-- Skill definition with verification requirements.
    Analogous to ImpLab's `FuncDef` but with required capabilities
    and formal verification metadata. -/
structure SkillDef where
  /-- Unique skill identifier. -/
  skillId : SkillId
  /-- Parameter names (data bindings passed to the skill). -/
  params : Array DataId := #[]
  /-- Capabilities required to execute this skill. -/
  requiredCaps : Array Capability := #[]
  /-- Skill body - sequence of plan steps. -/
  body : Array PlanStep := #[]
  deriving Repr, BEq, DecidableEq, Inhabited, FromJson, ToJson

instance : ToString SkillDef where
  toString skill :=
    let caps := if skill.requiredCaps.isEmpty then ""
      else s!" requires [{String.intercalate ", " (skill.requiredCaps.toList.map toString)}]"
    s!"skill {skill.skillId}({String.intercalate ", " skill.params.toList}){caps}"

instance : ToExpr SkillDef where
  toExpr skill :=
    mkApp4 (mkConst ``SkillDef.mk)
      (toExpr skill.skillId) (toExpr skill.params) (toExpr skill.requiredCaps) (toExpr skill.body)
  toTypeExpr := mkConst ``SkillDef

-- ═══════════════════════════════════════════════════════════════════════
-- §10  VerifiedPlan - complete plan (ImpLab.Program)
-- ═══════════════════════════════════════════════════════════════════════

/-- Complete verified plan - the top-level execution unit.
    Analogous to ImpLab's `Program` with additional verification
    metadata: budget, required tokens, and compliance policy. -/
structure VerifiedPlan where
  /-- Mutable resource declarations (budget, tokens). -/
  resources : Array ResourceDecl := #[]
  /-- Skill definitions (reusable, verified sub-plans). -/
  skills : Array SkillDef := #[]
  /-- Main execution steps (entry point). -/
  mainSteps : Array PlanStep := #[]
  /-- Total budget ceiling in cents. -/
  totalBudgetCents : Nat := 10000
  /-- Capability tokens required to execute this plan. -/
  requiredTokens : Array TokenId := #[]
  /-- Compliance policy identifier ("default", "hipaa", "sox", "legal"). -/
  compliancePolicy : String := "default"
  deriving Repr, BEq, DecidableEq, Inhabited, FromJson, ToJson

namespace VerifiedPlan

/-- Name of the implicit main skill. -/
def mainName : SkillId := "main"

/-- Find a resource declaration by name. -/
def findResource? (plan : VerifiedPlan) (name : ResourceId) : Option ResourceDecl :=
  plan.resources.find? (fun r => r.name == name)

/-- Check if a resource is declared. -/
def isDeclaredResource (plan : VerifiedPlan) (name : ResourceId) : Bool :=
  (plan.findResource? name).isSome

/-- Find a skill definition by ID. -/
def findSkill? (plan : VerifiedPlan) (name : SkillId) : Option SkillDef :=
  if name == mainName then
    some { skillId := mainName, body := plan.mainSteps }
  else
    plan.skills.find? (fun s => s.skillId == name)

/-- Get the body of a skill (or main). -/
def bodyOf? (plan : VerifiedPlan) (name : SkillId) : Option (Array PlanStep) :=
  (plan.findSkill? name).map (·.body)

/-- Size of a skill's body. -/
def bodySizeOf (plan : VerifiedPlan) (name : SkillId) : Nat :=
  (plan.bodyOf? name).map (·.size) |>.getD 0

/-- Get statement at a specific program counter within a skill. -/
def stepAt? (plan : VerifiedPlan) (name : SkillId) (pc : Nat) : Option PlanStep :=
  (plan.bodyOf? name).bind (·[pc]?)

/-- Total number of steps across all skills + main. -/
def totalStepCount (plan : VerifiedPlan) : Nat :=
  plan.skills.foldl (init := plan.mainSteps.size) fun acc skill => acc + skill.body.size

/-- Default fuel = total steps × 64 + 1 (same heuristic as ImpLab). -/
def defaultFuel (plan : VerifiedPlan) : Nat :=
  (max plan.totalStepCount 1) * 64 + 1

/-- Check plan has main steps. -/
def hasMain (plan : VerifiedPlan) : Bool :=
  !plan.mainSteps.isEmpty

/-- Check for duplicate resource names. -/
def hasDuplicateResourceNames (plan : VerifiedPlan) : Bool :=
  (plan.resources.foldl (init := ((#[] : Array ResourceId), false)) fun (seen, dup) res =>
    if dup then (seen, true)
    else if seen.contains res.name then (seen, true)
    else (seen.push res.name, false)).2

/-- Check for duplicate skill IDs. -/
def hasDuplicateSkillIds (plan : VerifiedPlan) : Bool :=
  (plan.skills.foldl (init := ((#[] : Array SkillId), false)) fun (seen, dup) skill =>
    if dup then (seen, true)
    else if seen.contains skill.skillId then (seen, true)
    else (seen.push skill.skillId, false)).2

/-- Render main steps as strings. -/
def render (plan : VerifiedPlan) : Array String :=
  plan.mainSteps.map toString

end VerifiedPlan

instance : ToExpr VerifiedPlan where
  toExpr plan :=
    mkApp6 (mkConst ``VerifiedPlan.mk)
      (toExpr plan.resources) (toExpr plan.skills) (toExpr plan.mainSteps)
      (toExpr plan.totalBudgetCents) (toExpr plan.requiredTokens) (toExpr plan.compliancePolicy)
  toTypeExpr := mkConst ``VerifiedPlan

-- ═══════════════════════════════════════════════════════════════════════
-- §11  Proof certificate - issued per verified step
-- ═══════════════════════════════════════════════════════════════════════

/-- Proof certificate issued when a plan step passes verification.
    Each step that executes successfully produces a micro-certificate
    recording what was verified. -/
structure ProofCert where
  /-- Which data binding or step this certifies. -/
  stepId : String
  /-- Property name that was verified (e.g., "flow_safe", "budget_ok"). -/
  property : String
  /-- Input labels that were checked. -/
  inputLabels : Array FlowLabel := #[]
  /-- Output label that was verified safe. -/
  outputLabel : FlowLabel := { level := .Public }
  /-- Optional extra detail. -/
  detail : String := ""
  deriving Repr, BEq, DecidableEq, Inhabited, FromJson, ToJson

instance : ToString ProofCert where
  toString cert :=
    s!"cert[{cert.property}]: {cert.stepId} ({cert.detail})"

instance : ToExpr ProofCert where
  toExpr cert :=
    mkApp5 (mkConst ``ProofCert.mk)
      (toExpr cert.stepId) (toExpr cert.property) (toExpr cert.inputLabels)
      (toExpr cert.outputLabel) (toExpr cert.detail)
  toTypeExpr := mkConst ``ProofCert

-- ═══════════════════════════════════════════════════════════════════════
-- §12  Source mapping - enables DAP source-level debugging
-- ═══════════════════════════════════════════════════════════════════════

/-- Source span - identical to ImpLab's StmtSpan.
    Maps a plan step back to its position in the Lean source file
    for DAP source-level debugging. -/
structure StepSpan where
  startLine : Nat
  startColumn : Nat
  endLine : Nat
  endColumn : Nat
  deriving Repr, BEq, DecidableEq, Inhabited, FromJson, ToJson

instance : ToExpr StepSpan where
  toExpr span :=
    mkApp4 (mkConst ``StepSpan.mk)
      (toExpr span.startLine) (toExpr span.startColumn) (toExpr span.endLine) (toExpr span.endColumn)
  toTypeExpr := mkConst ``StepSpan

/-- Skill-local step location (for breakpoint resolution). -/
structure StepLocation where
  skillId : SkillId
  stepLine : Nat
  deriving Repr, BEq, DecidableEq, Inhabited, FromJson, ToJson

instance : ToExpr StepLocation where
  toExpr loc :=
    mkApp2 (mkConst ``StepLocation.mk) (toExpr loc.skillId) (toExpr loc.stepLine)
  toTypeExpr := mkConst ``StepLocation

/-- Located step - plan step with its skill ID, line, and source span.
    Analogous to ImpLab's LocatedStmt. -/
structure LocatedStep where
  skillId : SkillId
  stepLine : Nat
  step : PlanStep
  span : StepSpan
  deriving Repr, BEq, DecidableEq, Inhabited, FromJson, ToJson

instance : ToExpr LocatedStep where
  toExpr st :=
    mkApp4 (mkConst ``LocatedStep.mk)
      (toExpr st.skillId) (toExpr st.stepLine) (toExpr st.step) (toExpr st.span)
  toTypeExpr := mkConst ``LocatedStep

-- ═══════════════════════════════════════════════════════════════════════
-- §13  PlanInfo - plan + source mapping (ImpLab.ProgramInfo)
-- ═══════════════════════════════════════════════════════════════════════

/-- PlanInfo = VerifiedPlan + source mapping.
    Analogous to ImpLab's ProgramInfo.
    This is the JSON interchange format between:
      - The Lean execution kernel
      - The Python orchestrator
      - The VS Code DAP debugger extension -/
structure PlanInfo where
  plan : VerifiedPlan
  located : Array LocatedStep
  deriving Repr, BEq, DecidableEq, Inhabited, FromJson, ToJson

instance : Coe PlanInfo VerifiedPlan where
  coe info := info.plan

instance : ToExpr PlanInfo where
  toExpr info :=
    mkApp2 (mkConst ``PlanInfo.mk) (toExpr info.plan) (toExpr info.located)
  toTypeExpr := mkConst ``PlanInfo

namespace PlanInfo

/-- Check that located array matches total step count. -/
def hasCompatibleLocations (info : PlanInfo) : Bool :=
  info.located.size == info.plan.totalStepCount

/-- Validate a PlanInfo for well-formedness. -/
def validate (info : PlanInfo) : Except String PlanInfo := do
  if !info.plan.hasMain then
    throw "Invalid PlanInfo: plan has no main steps."
  if info.plan.hasDuplicateResourceNames then
    throw "Invalid PlanInfo: duplicate resource names are not allowed."
  if info.plan.hasDuplicateSkillIds then
    throw "Invalid PlanInfo: duplicate skill IDs are not allowed."
  if !info.hasCompatibleLocations then
    throw <|
      s!"Invalid PlanInfo: plan has {info.plan.totalStepCount} steps but `located` has {info.located.size}."
  pure info

/-- Resolve a source line to a step location. -/
def sourceLineToLocation? (info : PlanInfo) (line : Nat) : Option StepLocation :=
  let rec go (idx : Nat) : Option StepLocation :=
    if h : idx < info.located.size then
      let loc := info.located[idx]
      if loc.span.startLine ≤ line && line ≤ loc.span.endLine then
        some { skillId := loc.skillId, stepLine := loc.stepLine }
      else
        go (idx + 1)
    else
      none
  go 0

/-- Resolve a step location back to a source line. -/
def locationToSourceLine? (info : PlanInfo) (loc : StepLocation) : Option Nat := do
  let found := info.located.find? (fun l =>
    l.skillId == loc.skillId && l.stepLine == loc.stepLine)
  found.map (·.span.startLine)

/-- Resolve with fallback. -/
def locationToSourceLine (info : PlanInfo) (loc : StepLocation) : Nat :=
  (locationToSourceLine? info loc).getD loc.stepLine

end PlanInfo

-- ═══════════════════════════════════════════════════════════════════════
-- §14  Convenience constructors - for test and example plan authoring
-- ═══════════════════════════════════════════════════════════════════════

namespace PlanStep

/-- Bind a literal constant. -/
def letConst (dest : DataId) (value : Int) (level : SecurityLevel := .Public) : PlanStep :=
  .bind dest (.literal value) { level }

/-- Bind a skill invocation result. -/
def letInvoke (dest : DataId) (skill : SkillId) (args : Array DataId)
    (level : SecurityLevel := .Internal) : PlanStep :=
  .bind dest (.invokeSkill skill args) { level }

/-- Bind a resource read. -/
def letRead (dest : DataId) (resource : ResourceId)
    (level : SecurityLevel := .Internal) : PlanStep :=
  .bind dest (.readResource resource) { level }

/-- Bind a flow check result. -/
def letCheck (dest : DataId) (src dst : DataId)
    (level : SecurityLevel := .Public) : PlanStep :=
  .bind dest (.checkFlow src dst) { level }

/-- Bind a label join result. -/
def letJoin (dest : DataId) (a b : DataId)
    (level : SecurityLevel := .Internal) : PlanStep :=
  .bind dest (.joinLabels a b) { level }

end PlanStep

end CertiorPlan

/-
  CertiorPlan.Dsl - Verified Agent Plan DSL Elaborator

  Analogous to ImpLab's `Lang/Dsl.lean`. Provides the `plan%[...]`
  syntax for authoring verified agent plans directly in Lean4.

  ## Target syntax:

  ```
  plan%[
    resource budget := 10000 @Internal,
    resource token  := 1 @Sensitive ["PHI"],

    skill queryPatient(patientId)
        requires [database:read:patient_data] := {
      let data := invoke database_query(patientId) @Sensitive ["PHI"],
      emit data
    },

    main budget := 5000, compliance := "hipaa", tokens := ["cap-db"] in {
      let id := 42 @Public,
      let result := invoke queryPatient(id) @Sensitive,
      requireApproval "external data access",
      emit result
    }
  ]
  ```

  ## Architecture (following ImpLab patterns):

  1. `declare_syntax_cat` for `plan_step`, `plan_skill`, `plan_resource`,
     `plan_item`, `plan_level`, `plan_rhs`
  2. Elaboration via `elab` that:
     a. Parses syntax trees into AST nodes
     b. Collects source spans via `(← getFileMap).toPosition`
     c. Builds `PlanInfo` with `LocatedStep` array
     d. Validates (has main, no duplicates, budget non-negative)
     e. Returns `toExpr planInfo`

  ## Source Mapping (Tuesday deliverable):

  Every plan step records its Lean source position as a `StepSpan`.
  The elaborator collects these into the `PlanInfo.located` array,
  enabling DAP source-level debugging and IDE hover information.

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import Lean
import Lean.Elab
import Lean.Elab.Term
import CertiorPlan.Ast
import CertiorPlan.Eval

open Lean Elab Term Meta
open CertiorPlan

namespace CertiorPlan.Dsl

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Syntax Categories - analogous to ImpLab's stmt, rhs, funcDef
-- ═══════════════════════════════════════════════════════════════════════

/- Security level annotation: @Public, @Internal, @Sensitive, @Restricted -/
declare_syntax_cat plan_level
syntax "@Public"     : plan_level
syntax "@Internal"   : plan_level
syntax "@Sensitive"  : plan_level
syntax "@Restricted" : plan_level

/- Optional tag list: ["PHI", "MNPI"] -/
declare_syntax_cat plan_tags
syntax "[" str,* "]" : plan_tags

/- Internal identifier syntax for RHS parsing (supports `_` wildcard in quotes). -/
declare_syntax_cat plan_ident
syntax ident : plan_ident
syntax "_"   : plan_ident

/- Right-hand side of a bind step -/
declare_syntax_cat plan_rhs
syntax num                                          : plan_rhs  -- literal
syntax "-" num                                      : plan_rhs  -- negative literal
syntax "invoke" plan_ident "(" plan_ident,* ")"     : plan_rhs  -- skill invocation
syntax "checkFlow" plan_ident plan_ident            : plan_rhs  -- flow check
syntax "joinLabels" "(" plan_ident "," plan_ident ")" : plan_rhs -- label join
syntax "attenuate" plan_ident "[" str,* "]"         : plan_rhs  -- token attenuate
syntax "readResource" plan_ident                    : plan_rhs  -- read resource

/- Plan step - analogous to ImpLab's stmt -/
declare_syntax_cat plan_step
syntax "let" ident ":=" plan_rhs plan_level (plan_tags)?                   : plan_step
syntax "set" ident ":=" ident                                              : plan_step
syntax "setResource" str ":=" ident                                        : plan_step
syntax "emit" ident                                                        : plan_step
syntax "requireApproval" str                                               : plan_step
syntax "checkFlow" plan_level plan_level                                   : plan_step
syntax "joinLabels" plan_level plan_level                                  : plan_step

/- Capability item in a requires clause -/
declare_syntax_cat plan_cap
syntax str                           : plan_cap  -- "database:read"
syntax str "(" num ")"               : plan_cap  -- "database:read" (100)

/- Skill definition -/
declare_syntax_cat plan_skill_def
syntax "skill" ident "(" ident,* ")"
    ("requires" "[" plan_cap,* "]")?
    ":=" "{" plan_step,* "}"                       : plan_skill_def

/- Resource declaration -/
declare_syntax_cat plan_resource_def
syntax "resource" ident ":=" num plan_level (plan_tags)?      : plan_resource_def

/- Main block declaration -/
declare_syntax_cat plan_main_def
syntax "main"
    ("budget" ":=" num ",")?
    ("compliance" ":=" str ",")?
    ("tokens" ":=" "[" str,* "]")?
    "in" "{" plan_step,* "}"                       : plan_main_def

/- Top-level plan items -/
declare_syntax_cat plan_item
syntax plan_resource_def : plan_item
syntax plan_skill_def    : plan_item
syntax plan_main_def     : plan_item

/- The plan%[...] term syntax -/
syntax (name := certiorPlanTerm) "plan%[" plan_item,* "]" : term

-- ═══════════════════════════════════════════════════════════════════════
-- §2  Source Span Extraction - Tuesday deliverable
-- ═══════════════════════════════════════════════════════════════════════

/-- Extract a `StepSpan` from a `Syntax` node using the file map.
    Analogous to ImpLab's source location tracking via `fileMap.toPosition`. -/
private def extractSpan (stx : Syntax) : TermElabM StepSpan := do
  let fileMap ← getFileMap
  let pos := stx.getPos?.getD 0
  let endPos := stx.getTailPos?.getD pos
  let startPos := fileMap.toPosition pos
  let endPosition := fileMap.toPosition endPos
  pure {
    startLine := startPos.line
    startColumn := startPos.column
    endLine := endPosition.line
    endColumn := endPosition.column
  }

-- ═══════════════════════════════════════════════════════════════════════
-- §3  Elaboration Helpers - parse syntax into AST types
-- ═══════════════════════════════════════════════════════════════════════

/-- Elaborate a security level annotation. -/
private def elabLevel : TSyntax `plan_level → TermElabM SecurityLevel
  | `(plan_level| @Public)     => pure .Public
  | `(plan_level| @Internal)   => pure .Internal
  | `(plan_level| @Sensitive)  => pure .Sensitive
  | `(plan_level| @Restricted) => pure .Restricted
  | stx => throwErrorAt stx "expected @Public, @Internal, @Sensitive, or @Restricted"

/-- Elaborate an optional tag list. -/
private def elabTags : Option (TSyntax `plan_tags) → TermElabM (List String)
  | none => pure []
  | some stx => do
    match stx with
    | `(plan_tags| [ $tags,* ]) =>
      let tagStrs ← tags.getElems.toList.mapM fun t => do
        let s := t.getString
        pure s
      pure tagStrs
    | _ => pure []

/-- Elaborate a FlowLabel from level + optional tags. -/
private def elabFlowLabel (levelStx : TSyntax `plan_level)
    (tagsOpt : Option (TSyntax `plan_tags)) : TermElabM FlowLabel := do
  let level ← elabLevel levelStx
  let tags ← elabTags tagsOpt
  pure { level, tags }

/-- Extract identifier text from an ident syntax node. -/
private def identString (stx : TSyntax `ident) : String :=
  stx.getId.toString

/-- Collect identifiers from syntax (left-to-right). -/
private partial def collectIdents (stx : Syntax) : Array String :=
  match stx with
  | Syntax.ident _ _ val _ => #[val.toString]
  | Syntax.node _ _ args =>
    args.foldl (init := #[]) fun acc a => acc ++ collectIdents a
  | _ => #[]

/-- Elaborate a right-hand side. -/
private def elabRhs (stx : TSyntax `plan_rhs) : TermElabM StepRhs := do
  match stx with
  | `(plan_rhs| $n:num) =>
    pure (.literal (Int.ofNat n.getNat))
  | `(plan_rhs| - $n:num) =>
    pure (.literal (-(Int.ofNat n.getNat)))
  | `(plan_rhs| invoke $_skill:plan_ident ( $_args:plan_ident,* )) => do
    let ids := collectIdents stx.raw |>.toList
    match ids with
    | [] => throwErrorAt stx "invoke requires a skill identifier"
    | skillName :: argNames =>
      pure (.invokeSkill skillName argNames.toArray)
  | `(plan_rhs| checkFlow $_src:plan_ident $_dst:plan_ident) => do
    let ids := collectIdents stx.raw |>.toList
    match ids with
    | [srcId, dstId] => pure (.checkFlow srcId dstId)
    | _ => throwErrorAt stx "checkFlow requires exactly two identifiers"
  | `(plan_rhs| joinLabels ( $_a:plan_ident , $_b:plan_ident )) => do
    let ids := collectIdents stx.raw |>.toList
    match ids with
    | [aId, bId] => pure (.joinLabels aId bId)
    | _ => throwErrorAt stx "joinLabels requires exactly two identifiers"
  | `(plan_rhs| attenuate $_tok:plan_ident [ $caps:str,* ]) => do
    let ids := collectIdents stx.raw |>.toList
    let tokenId ← match ids with
      | tok :: _ => pure tok
      | [] => throwErrorAt stx "attenuate requires a token identifier"
    let capStrs := caps.getElems.map (·.getString)
    pure (.attenuateToken tokenId capStrs)
  | `(plan_rhs| readResource $_res:plan_ident) => do
    let ids := collectIdents stx.raw |>.toList
    match ids with
    | [resId] => pure (.readResource resId)
    | _ => throwErrorAt stx "readResource requires exactly one identifier"
  | _ => throwErrorAt stx "invalid plan_rhs"

/-- Elaborate a plan step, returning the step and its source span. -/
private def elabStep (stx : TSyntax `plan_step) :
    TermElabM (PlanStep × StepSpan) := do
  let span ← extractSpan stx
  let step ← match stx with
    | `(plan_step| let $dest:ident := $rhs:plan_rhs $level:plan_level $[$tags:plan_tags]?) => do
      let destName := identString dest
      let rhsVal ← elabRhs rhs
      let label ← elabFlowLabel level tags
      pure (.bind destName rhsVal label)
    | `(plan_step| set $res:ident := $val:ident) => do
      let resName := identString res
      let valName := identString val
      pure (.setResource resName valName)
    | `(plan_step| setResource $res:str := $val:ident) => do
      let valName := identString val
      pure (.setResource res.getString valName)
    | `(plan_step| emit $val:ident) => do
      let valName := identString val
      pure (.emitResult valName)
    | `(plan_step| requireApproval $reason) =>
      pure (.requireApproval reason.getString)
    | `(plan_step| checkFlow $srcLevel:plan_level $dstLevel:plan_level) => do
      -- Standalone checkFlow: asserts that srcLevel can flow to dstLevel.
      -- Desugars to a bind with Restricted label (top of lattice) so the
      -- bind itself always accepts, and the actual flow check happens inside
      -- evalRhs which calls flowAllowed(srcLevel, dstLevel).
      let srcLvl ← elabLevel srcLevel
      let dstLvl ← elabLevel dstLevel
      pure (.bind s!"_checkFlow_{srcLvl}_{dstLvl}"
        (.checkFlow s!"__level_{srcLvl}" s!"__level_{dstLvl}")
        { level := .Restricted })
    | `(plan_step| joinLabels $aLevel:plan_level $bLevel:plan_level) => do
      let aLvl ← elabLevel aLevel
      let bLvl ← elabLevel bLevel
      pure (.bind s!"_joinLabels_{aLvl}_{bLvl}"
        (.joinLabels s!"__level_{aLvl}" s!"__level_{bLvl}")
        { level := .Restricted })
    | _ => throwErrorAt stx "invalid plan_step"
  pure (step, span)

/-- Elaborate a capability requirement. -/
private def elabCap : TSyntax `plan_cap → TermElabM Capability
  | `(plan_cap| $res:str) =>
    pure ⟨res.getString, 0⟩
  | `(plan_cap| $res:str ( $cost:num )) =>
    pure ⟨res.getString, cost.getNat⟩
  | stx => throwErrorAt stx "invalid plan_cap"

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Plan Item Elaboration - resources, skills, main
-- ═══════════════════════════════════════════════════════════════════════

/-- Intermediate state during plan elaboration. -/
structure PlanElabState where
  resources    : Array ResourceDecl := #[]
  skills       : Array SkillDef := #[]
  mainSteps    : Array PlanStep := #[]
  located      : Array LocatedStep := #[]
  defaultBudgetCents      : Nat := 10000
  defaultCompliancePolicy : String := "default"
  defaultRequiredTokens   : Array TokenId := #[]
  hasMain      : Bool := false
  deriving Repr, Inhabited

/-- Elaborate a resource declaration. -/
private def elabResourceDef (stx : TSyntax `plan_resource_def)
    (st : PlanElabState) : TermElabM PlanElabState := do
  match stx with
  | `(plan_resource_def| resource $name:ident := $val:num $level:plan_level $[$tags:plan_tags]?) => do
    let resName := identString name
    -- Check for duplicates
    if st.resources.any (·.name == resName) then
      throwErrorAt stx s!"duplicate resource declaration: {resName}"
    let label ← elabFlowLabel level tags
    let decl : ResourceDecl := {
      name := resName
      init := Int.ofNat val.getNat
      label := label
    }
    pure { st with resources := st.resources.push decl }
  | _ => throwErrorAt stx "invalid plan_resource_def"

/-- Elaborate a skill definition. -/
private def elabSkillDef (stx : TSyntax `plan_skill_def)
    (st : PlanElabState) : TermElabM PlanElabState := do
  match stx with
  | `(plan_skill_def| skill $name:ident ( $params:ident,* )
      $[requires [ $caps:plan_cap,* ]]?
      := { $steps:plan_step,* }) => do
    let skillName := identString name
    -- Check for duplicates
    if st.skills.any (·.skillId == skillName) then
      throwErrorAt stx s!"duplicate skill definition: {skillName}"
    if skillName == "main" then
      throwErrorAt stx "'main' is reserved and cannot be used as a skill name"
    let paramNames := (params.getElems.map identString)
    let capsList ← match caps with
      | some capArr => capArr.getElems.toList.mapM elabCap
      | none        => pure []
    -- Elaborate body steps with source spans
    let mut bodySteps : Array PlanStep := #[]
    let mut located := st.located
    for stepStx in steps.getElems do
      let (step, span) ← elabStep stepStx
      bodySteps := bodySteps.push step
      located := located.push {
        skillId := skillName
        stepLine := bodySteps.size - 1
        step := step
        span := span
      }
    let skillDef : SkillDef := {
      skillId := skillName
      params := paramNames
      requiredCaps := capsList.toArray
      body := bodySteps
    }
    pure { st with
      skills := st.skills.push skillDef
      located := located }
  | _ => throwErrorAt stx "invalid plan_skill_def"

/-- Elaborate the main block. -/
private def elabMainDef (stx : TSyntax `plan_main_def)
    (st : PlanElabState) : TermElabM PlanElabState := do
  if st.hasMain then
    throwErrorAt stx "duplicate main block - only one main block is allowed"
  match stx with
  | `(plan_main_def| main
      $[budget := $budgetVal:num ,]?
      $[compliance := $compVal:str ,]?
      $[tokens := [ $toks:str,* ]]?
      in { $steps:plan_step,* }) => do
    let finalBudget := match budgetVal with
      | some n => n.getNat
      | none   => st.defaultBudgetCents
    let finalCompliance := match compVal with
      | some s => s.getString
      | none   => st.defaultCompliancePolicy
    let tokenList := match toks with
      | some tokArr => tokArr.getElems.map (·.getString)
      | none        => st.defaultRequiredTokens
    -- Elaborate main steps with source spans
    let mut mainSteps : Array PlanStep := #[]
    let mut located := st.located
    for stepStx in steps.getElems do
      let (step, span) ← elabStep stepStx
      mainSteps := mainSteps.push step
      located := located.push {
        skillId := VerifiedPlan.mainName
        stepLine := mainSteps.size - 1
        step := step
        span := span
      }
    pure { st with
      mainSteps := mainSteps
      located := located
      defaultBudgetCents := finalBudget
      defaultCompliancePolicy := finalCompliance
      defaultRequiredTokens := tokenList
      hasMain := true }
  | _ => throwErrorAt stx "invalid plan_main_def"

/-- Elaborate a single plan item (resource, skill, or main). -/
private def elabItem (stx : TSyntax `plan_item)
    (st : PlanElabState) : TermElabM PlanElabState := do
  match stx with
  | `(plan_item| $res:plan_resource_def) => elabResourceDef res st
  | `(plan_item| $sk:plan_skill_def)     => elabSkillDef sk st
  | `(plan_item| $m:plan_main_def)       => elabMainDef m st
  | _ => throwErrorAt stx "expected resource, skill, or main declaration"

-- ═══════════════════════════════════════════════════════════════════════
-- §5  Plan Validation - compile-time safety checks
-- ═══════════════════════════════════════════════════════════════════════

/-- Validate the elaborated plan state. Called at the end of elaboration
    to catch errors before producing the PlanInfo expression.

    Checks:
    - Plan has a main block
    - No duplicate resources (already checked during elab)
    - No duplicate skills (already checked during elab)
    - Budget is non-negative
    - Located step count matches total step count -/
private def validatePlan (stx : Syntax) (st : PlanElabState) :
    TermElabM Unit := do
  if !st.hasMain then
    throwErrorAt stx "plan requires a 'main' block"
  let totalSteps := st.mainSteps.size +
    st.skills.foldl (init := 0) fun acc s => acc + s.body.size
  if st.located.size != totalSteps then
    throwErrorAt stx
      (s!"internal error: located step count ({st.located.size}) != " ++
      s!"total step count ({totalSteps})")

-- ═══════════════════════════════════════════════════════════════════════
-- §6  Main Elaborator - plan%[...] → PlanInfo expression
-- ═══════════════════════════════════════════════════════════════════════

/-- Build a `PlanInfo` from the elaboration state. -/
private def buildPlanInfo (st : PlanElabState) : PlanInfo :=
  let plan : VerifiedPlan := {
    resources := st.resources
    skills := st.skills
    mainSteps := st.mainSteps
    totalBudgetCents := st.defaultBudgetCents
    requiredTokens := st.defaultRequiredTokens
    compliancePolicy := st.defaultCompliancePolicy
  }
  { plan, located := st.located }

/-- The plan%[...] elaborator.

    Transforms a `plan%[item, item, ...]` term into a `PlanInfo` value.
    At elaboration time:
    1. Parses all plan items (resources, skills, main)
    2. Collects source spans for every step
    3. Validates the plan (main exists, no duplicates, etc.)
    4. Returns `toExpr planInfo`

    This is analogous to ImpLab's `imp%[...]` elaborator. -/
elab_rules : term
  | `(certiorPlanTerm| plan%[ $items:plan_item,* ]) => do
    -- Phase 1: Elaborate all items
    let mut st : PlanElabState := {}
    for item in items.getElems do
      st ← elabItem item st
    -- Phase 2: Validate
    validatePlan (← getRef) st
    -- Phase 3: Build PlanInfo
    let info := buildPlanInfo st
    -- Phase 4: Return as expression
    let infoExpr := toExpr info
    pure infoExpr

-- ═══════════════════════════════════════════════════════════════════════
-- §7  Convenience: plan_run%[...] - elaborate and execute immediately
-- ═══════════════════════════════════════════════════════════════════════

/-- `plan_run%[...]` elaborates a plan and runs it, returning the
    pretty-printed execution result as a String.
    Useful for quick testing and #eval demos. -/
syntax (name := certiorPlanRunTerm) "plan_run%[" plan_item,* "]" : term

elab_rules : term
  | `(certiorPlanRunTerm| plan_run%[ $items:plan_item,* ]) => do
    let mut st : PlanElabState := {}
    for item in items.getElems do
      st ← elabItem item st
    validatePlan (← getRef) st
    let info := buildPlanInfo st
    let resultStr := prettyRunResult info.plan
    pure (toExpr resultStr)

-- ═══════════════════════════════════════════════════════════════════════
-- §8  Convenience: plan_json%[...] - elaborate and export as JSON
-- ═══════════════════════════════════════════════════════════════════════

/-- `plan_json%[...]` elaborates a plan and returns its JSON representation
    as a String. Useful for testing the export pipeline. -/
syntax (name := certiorPlanJsonTerm) "plan_json%[" plan_item,* "]" : term

elab_rules : term
  | `(certiorPlanJsonTerm| plan_json%[ $items:plan_item,* ]) => do
    let mut st : PlanElabState := {}
    for item in items.getElems do
      st ← elabItem item st
    validatePlan (← getRef) st
    let info := buildPlanInfo st
    let jsonStr := toString (Lean.toJson info)
    pure (toExpr jsonStr)

end CertiorPlan.Dsl

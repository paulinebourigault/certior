/-
  CertiorPlan.Export - PlanInfo JSON Export & Import

  Analogous to ImpLab's `DAP/Export.lean`. Provides utilities for:
  - Serializing `PlanInfo` to JSON for the Python bridge
  - Deserializing JSON back to `PlanInfo`
  - Validating imported plans
  - Pretty-printing plan structure

  The JSON interchange format is the bridge between:
    - The Lean4 execution kernel (CertiorPlan)
    - The Python orchestrator (agentsafe)
    - The VS Code DAP extension (client/)

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import Lean
import CertiorPlan.Ast
import CertiorPlan.Eval

open Lean
open CertiorPlan

namespace CertiorPlan.Export

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Export: PlanInfo → JSON String
-- ═══════════════════════════════════════════════════════════════════════

/-- Export a `PlanInfo` to a formatted JSON string. -/
def exportJson (info : PlanInfo) : String :=
  Json.pretty (toJson info)

/-- Export a `PlanInfo` to a compact (single-line) JSON string. -/
def exportJsonCompact (info : PlanInfo) : String :=
  toString (toJson info)

/-- Export a `VerifiedPlan` (without source mapping) to JSON.
    Constructs a minimal `PlanInfo` with synthetic located steps. -/
def exportPlanJson (plan : VerifiedPlan) : String :=
  Id.run <| do
    -- Build synthetic located steps for plans without source mapping
    let mut located : Array LocatedStep := #[]
    -- Skills first
    for skill in plan.skills do
      for (idx, step) in skill.body.toList.enum do
        located := located.push {
          skillId := skill.skillId
          stepLine := idx
          step := step
          span := { startLine := 0, startColumn := 0, endLine := 0, endColumn := 0 }
        }
    -- Then main
    for (idx, step) in plan.mainSteps.toList.enum do
      located := located.push {
        skillId := VerifiedPlan.mainName
        stepLine := idx
        step := step
        span := { startLine := 0, startColumn := 0, endLine := 0, endColumn := 0 }
      }
    let info : PlanInfo := { plan, located }
    pure <| exportJson info

-- ═══════════════════════════════════════════════════════════════════════
-- §2  Import: JSON String → PlanInfo
-- ═══════════════════════════════════════════════════════════════════════

/-- Parse a JSON string into a `PlanInfo`.
    Returns an error message on failure. -/
def importJson (jsonStr : String) : Except String PlanInfo := do
  let json ← match Json.parse jsonStr with
    | .ok j => pure j
    | .error msg => throw s!"JSON parse error: {msg}"
  match fromJson? json with
  | .ok info => pure info
  | .error msg => throw s!"PlanInfo decode error: {msg}"

/-- Parse and validate a JSON string into a `PlanInfo`.
    Runs both JSON parsing and plan validation. -/
def importAndValidateJson (jsonStr : String) : Except String PlanInfo := do
  let info ← importJson jsonStr
  PlanInfo.validate info

-- ═══════════════════════════════════════════════════════════════════════
-- §3  Validation Summary
-- ═══════════════════════════════════════════════════════════════════════

/-- Detailed validation result with structured diagnostics. -/
structure ValidationReport where
  valid : Bool
  errors : Array String := #[]
  warnings : Array String := #[]
  stepCount : Nat := 0
  skillCount : Nat := 0
  resourceCount : Nat := 0
  compliancePolicy : String := "default"
  budgetCents : Nat := 0
  hasSourceMapping : Bool := false
  deriving Repr, Inhabited, FromJson, ToJson

/-- Collect all skill IDs that are referenced in invocation steps. -/
private def collectReferencedSkills (plan : VerifiedPlan) : Array SkillId :=
  Id.run <| do
    let mut refs : Array SkillId := #[]
    let allSteps := plan.mainSteps ++
      plan.skills.foldl (init := #[]) fun acc s => acc ++ s.body
    for step in allSteps do
      match step with
      | .bind _ (.invokeSkill skill _) _ =>
        if !refs.contains skill then
          refs := refs.push skill
      | _ => pure ()
    pure refs

/-- Generate a detailed validation report for a `PlanInfo`. -/
def validateDetailed (info : PlanInfo) : ValidationReport :=
  Id.run <| do
    let mut errors : Array String := #[]
    let mut warnings : Array String := #[]
    if !info.plan.hasMain then
      errors := errors.push "Plan has no main steps"
    if info.plan.hasDuplicateResourceNames then
      errors := errors.push "Plan has duplicate resource names"
    if info.plan.hasDuplicateSkillIds then
      errors := errors.push "Plan has duplicate skill IDs"
    if !info.hasCompatibleLocations then
      errors := errors.push <|
        s!"Located step count ({info.located.size}) does not match " ++
        s!"total step count ({info.plan.totalStepCount})"
    if info.plan.totalBudgetCents == 0 then
      warnings := warnings.push "Budget is 0 - plan may not execute any steps"
    let hasRealSpans := info.located.any fun loc =>
      loc.span.startLine > 0 || loc.span.startColumn > 0
    let referencedSkills := collectReferencedSkills info.plan
    for skill in info.plan.skills do
      if !referencedSkills.contains skill.skillId then
        warnings := warnings.push s!"Skill '{skill.skillId}' is defined but never invoked"
    pure {
      valid := errors.isEmpty
      errors := errors
      warnings := warnings
      stepCount := info.plan.totalStepCount
      skillCount := info.plan.skills.size
      resourceCount := info.plan.resources.size
      compliancePolicy := info.plan.compliancePolicy
      budgetCents := info.plan.totalBudgetCents
      hasSourceMapping := hasRealSpans
    }

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Pretty Printing - human-readable plan summary
-- ═══════════════════════════════════════════════════════════════════════

/-- Render a plan as a human-readable summary string.
    Useful for CLI output and debugging. -/
def prettyPlan (info : PlanInfo) : String :=
  let plan := info.plan
  let lines : Array String := #[
    "═══════════════════════════════════════════════════════════",
    s!"CertiorPlan: {plan.compliancePolicy} compliance",
    s!"Budget: {plan.totalBudgetCents}¢ | Skills: {plan.skills.size} | " ++
      s!"Resources: {plan.resources.size} | Steps: {plan.totalStepCount}",
    "═══════════════════════════════════════════════════════════",
    ""
  ] ++ (if plan.resources.isEmpty then #[]
    else #["Resources:"] ++ plan.resources.map fun r =>
      s!"  {r.name} = {r.init} {r.label}"
  ) ++ (if plan.resources.isEmpty then #[] else #[""]
  ) ++ plan.skills.foldl (init := #[]) fun acc skill =>
    acc ++ #[s!"Skill: {skill}"] ++
      skill.body.map (fun step => s!"  {step}") ++ #[""]
  ++ #["Main:"] ++ plan.mainSteps.map (fun step => s!"  {step}")
  ++ #["", "═══════════════════════════════════════════════════════════"]
  String.intercalate "\n" lines.toList

/-- Render a validation report as a human-readable string. -/
def prettyValidation (report : ValidationReport) : String :=
  let statusStr := if report.valid then "✓ VALID" else "✗ INVALID"
  let lines : Array String := #[
    s!"Validation: {statusStr}",
    s!"  Steps: {report.stepCount} | Skills: {report.skillCount} | " ++
      s!"Resources: {report.resourceCount}",
    s!"  Compliance: {report.compliancePolicy} | Budget: {report.budgetCents}¢",
    s!"  Source mapping: {if report.hasSourceMapping then "yes" else "no (synthetic)"}"
  ]
  let errorLines := report.errors.map (s!"  ✗ " ++ ·)
  let warnLines := report.warnings.map (s!"  ⚠ " ++ ·)
  let all := lines ++ (if errorLines.isEmpty then #[] else #["  Errors:"] ++ errorLines)
    ++ (if warnLines.isEmpty then #[] else #["  Warnings:"] ++ warnLines)
  String.intercalate "\n" all.toList

-- ═══════════════════════════════════════════════════════════════════════
-- §5  Execution Report Export
-- ═══════════════════════════════════════════════════════════════════════

/-- Complete execution report for compliance audit export. -/
structure ExecutionReport where
  planInfo : PlanInfo
  validation : ValidationReport
  executionResult : String
  certificates : Array ProofCert := #[]
  finalContext : Option String := none
  deriving Repr, FromJson, ToJson

/-- Run a plan and generate a complete execution report. -/
def generateReport (info : PlanInfo) : ExecutionReport :=
  let validation := validateDetailed info
  let execResult := prettyRunResult info.plan
  let certs := match runPlan info.plan with
    | .ok ctx => ctx.certificates
    | .error _ => #[]
  let finalCtx := match runPlan info.plan with
    | .ok ctx => some (renderBindings ctx.localBindings)
    | .error _ => none
  { planInfo := info
    validation
    executionResult := execResult
    certificates := certs
    finalContext := finalCtx }

/-- Export execution report as JSON. -/
def exportReport (info : PlanInfo) : String :=
  Json.pretty (toJson (generateReport info))

-- ═══════════════════════════════════════════════════════════════════════
-- §6  File I/O Utilities (for CLI)
-- ═══════════════════════════════════════════════════════════════════════

/-- Write a PlanInfo to a JSON file. -/
def writeJsonFile (info : PlanInfo) (path : System.FilePath) : IO Unit := do
  let content := exportJson info
  IO.FS.writeFile path content

/-- Read a PlanInfo from a JSON file. -/
def readJsonFile (path : System.FilePath) : IO (Except String PlanInfo) := do
  let content ← IO.FS.readFile path
  pure (importAndValidateJson content)

/-- Write an execution report to a JSON file. -/
def writeReportFile (info : PlanInfo) (path : System.FilePath) : IO Unit := do
  let content := exportReport info
  IO.FS.writeFile path content

end CertiorPlan.Export

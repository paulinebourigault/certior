/-
  CertiorPlan Example: Basic Data Flow

  Demonstrates the plan%[...] DSL with:
  - Resource declarations with security labels
  - Simple literal bindings at different security levels
  - Resource reads
  - Public → Internal flow (allowed by lattice)
  - Budget tracking
  - Proof certificate issuance

  Expected: Executes successfully with 3 proof certificates.

  Copyright (c) 2026 Certior. All rights reserved.
-/

import CertiorPlan
import CertiorPlan.Dsl
import CertiorPlan.Export

open CertiorPlan
open CertiorPlan.Dsl
open CertiorPlan.Export

namespace examples.Basic

-- ═══════════════════════════════════════════════════════════════════════
-- The plan, authored in plan%[...] DSL
-- ═══════════════════════════════════════════════════════════════════════

/-- Basic verified plan: simple data flow with budget tracking.

    Flow graph:
      42 @Public → id
      100 @Internal → data        (Public → Internal ✓)
      readResource planBudget @Internal → remaining  (Internal → Internal ✓)
      emit data
-/
def basicPlanInfo : PlanInfo := plan%[
  resource planBudget := 1000 @Internal,

  main budget := 1000, compliance := "default", in {
    let id := 42 @Public,
    let data := 100 @Internal,
    let remaining := readResource planBudget @Internal,
    emit data
  }
]

-- ═══════════════════════════════════════════════════════════════════════
-- Compile-time verification
-- ═══════════════════════════════════════════════════════════════════════

/-- Run the plan at compile time. -/
def runResult : String := prettyRunResult basicPlanInfo.plan

/-- JSON export. -/
def jsonExport : String := exportJson basicPlanInfo

/-- Validation report. -/
def validationResult : ValidationReport := validateDetailed basicPlanInfo

-- Compile-time checks
#eval! IO.println "═══ Basic Plan ═══"
#eval! IO.println runResult
#eval! IO.println ""
#eval! IO.println (prettyValidation validationResult)

-- Verify the plan is valid
#eval! do
  match PlanInfo.validate basicPlanInfo with
  | .ok _ => IO.println "✓ Plan validation passed"
  | .error msg => IO.println s!"✗ Validation failed: {msg}"

-- Verify step count matches located array
#eval! do
  let info := basicPlanInfo
  IO.println s!"  Steps: {info.plan.totalStepCount}"
  IO.println s!"  Located: {info.located.size}"
  IO.println s!"  Match: {info.hasCompatibleLocations}"

end examples.Basic

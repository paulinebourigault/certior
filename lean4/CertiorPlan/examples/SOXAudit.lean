/-
  CertiorPlan Example: SOX Financial Audit

  Demonstrates compliance enforcement through the plan%[...] DSL:
  - Financial data labeled @Restricted with MNPI tag
  - Budget tracking and enforcement
  - requireApproval halting execution for human compliance review
  - Multiple security levels interacting

  This showcases the "verify-before-execute" paradigm:
  agents operating on Material Non-Public Information (MNPI)
  are automatically halted for compliance officer review.

  Expected: Execution halts at requireApproval step.

  Copyright (c) 2026 Certior. All rights reserved.
-/

import CertiorPlan
import CertiorPlan.Dsl
import CertiorPlan.Export

open CertiorPlan
open CertiorPlan.Dsl
open CertiorPlan.Export

namespace examples.SOX

-- ═══════════════════════════════════════════════════════════════════════
-- The plan, authored in plan%[...] DSL
-- ═══════════════════════════════════════════════════════════════════════

/-- SOX financial audit plan.

    Flow graph:
      invoke queryEarnings() @Restricted → earnings
        [inside skill: literal → data @Restricted["MNPI"], emit data]
      readResource planBudget @Internal → remaining
      literal → report @Internal
      requireApproval "MNPI data in output"  ← HALTS HERE
      emit report (unreachable without approval)

    The requireApproval step is a mandatory compliance checkpoint.
    In production, the DAP debugger or Python bridge would pause here
    and wait for a compliance officer to approve continuation.
-/
def soxPlanInfo : PlanInfo := plan%[
  resource planBudget := 8000 @Internal,

  skill queryEarnings()
      requires ["database:read:financial_data" (500)] := {
    let data := 1 @Restricted ["MNPI"],
    emit data
  },

  main budget := 8000, compliance := "sox", in {
    let earnings := invoke queryEarnings() @Restricted,
    let remaining := readResource planBudget @Internal,
    let report := 1 @Internal,
    requireApproval "MNPI data in output - requires compliance review",
    emit report
  }
]

-- ═══════════════════════════════════════════════════════════════════════
-- Compile-time verification
-- ═══════════════════════════════════════════════════════════════════════

def runResult : String := prettyRunResult soxPlanInfo.plan

def validationResult : ValidationReport := validateDetailed soxPlanInfo

#eval! IO.println "═══ SOX Financial Audit ═══"
#eval! IO.println runResult
#eval! IO.println ""
#eval! IO.println (prettyValidation validationResult)
#eval! IO.println ""
#eval! IO.println (prettyPlan soxPlanInfo)

-- ═══════════════════════════════════════════════════════════════════════
-- Variant: SOX plan that completes (no approval needed for internal)
-- ═══════════════════════════════════════════════════════════════════════

/-- SOX internal-only plan: no MNPI in output, completes normally.

    Demonstrates that when Restricted data is processed internally
    and the output is labeled @Restricted (no downgrade), execution
    proceeds without requiring approval.
-/
def soxInternalPlanInfo : PlanInfo := plan%[
  resource planBudget := 8000 @Internal,

  skill queryEarnings()
      requires ["database:read:financial_data" (500)] := {
    let data := 1 @Restricted ["MNPI"],
    emit data
  },

  skill generateInternalReport(data)
      requires ["document:write:internal"] := {
    let report := 1 @Restricted,
    emit report
  },

  main budget := 8000, compliance := "sox", in {
    let earnings := invoke queryEarnings() @Restricted,
    let report := invoke generateInternalReport(earnings) @Restricted,
    emit report
  }
]

def runInternalResult : String := prettyRunResult soxInternalPlanInfo.plan

#eval! IO.println ""
#eval! IO.println "═══ SOX Internal-Only (completes) ═══"
#eval! IO.println runInternalResult

-- ═══════════════════════════════════════════════════════════════════════
-- Variant: SOX flow violation (Restricted → Public leak)
-- ═══════════════════════════════════════════════════════════════════════

/-- SOX data leak plan: Restricted earnings leaked to Public channel.
    Demonstrates lattice blocking: rank(Restricted)=3 > rank(Public)=0.
-/
def soxLeakPlanInfo : PlanInfo := plan%[
  resource planBudget := 8000 @Internal,

  skill queryEarnings()
      requires ["database:read:financial_data" (500)] := {
    let data := 1 @Restricted ["MNPI"],
    emit data
  },

  main budget := 8000, compliance := "sox", in {
    let earnings := invoke queryEarnings() @Restricted,
    let publicReport := invoke queryEarnings() @Public,
    emit publicReport
  }
]

def runLeakResult : String := prettyRunResult soxLeakPlanInfo.plan

#eval! IO.println ""
#eval! IO.println "═══ SOX Data Leak (flow violation) ═══"
#eval! IO.println runLeakResult

end examples.SOX

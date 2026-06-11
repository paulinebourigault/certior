/-
  CertiorPlan Examples - Fixture Plans

  Week A1: Manual plan construction (basic, HIPAA, SOX)
  Week A2: DSL-based plans via plan%[...] syntax

  Copyright (c) 2026 Certior. All rights reserved.
-/

import CertiorPlan
import CertiorPlan.Dsl
import CertiorPlan.Export

open CertiorPlan
open CertiorPlan.Dsl
open CertiorPlan.Export
open SecurityLevel

namespace examples

-- ═══════════════════════════════════════════════════════════════════════
-- Example 1: Basic plan - simple data flow
-- ═══════════════════════════════════════════════════════════════════════

/-- A minimal plan that binds two values and emits the result.
    Demonstrates that Public → Internal flow is allowed. -/
def basicPlan : VerifiedPlan := {
  resources := #[
    { name := "budget", init := 1000, label := { level := .Internal } }
  ]
  mainSteps := #[
    -- Step 1: Bind a public constant
    PlanStep.letConst "id" 42,
    -- Step 2: Bind an internal-level computation
    .bind "data" (.literal 100) { level := .Internal },
    -- Step 3: Read budget resource
    PlanStep.letRead "remaining" "budget" .Internal,
    -- Step 4: Emit result
    .emitResult "data"
  ]
  totalBudgetCents := 1000
}

/-- Run the basic example. -/
def runBasic : String :=
  prettyRunResult basicPlan

-- ═══════════════════════════════════════════════════════════════════════
-- Example 2: HIPAA patient query - flow violation detection
-- ═══════════════════════════════════════════════════════════════════════

/-- HIPAA scenario: query patient data, attempt to send externally.
    The flow checker should detect that Sensitive data cannot flow
    to a Public (external) channel.

    This is the "aha moment" demo:
    - Patient data is labeled @Sensitive
    - External email is labeled @Public
    - The proven lattice blocks the flow: rank(Sensitive)=2 > rank(Public)=0 -/
def hipaaPatientPlan : VerifiedPlan := {
  resources := #[
    { name := "budget", init := 5000, label := { level := .Internal } },
    { name := "patientToken", init := 1, label := { level := .Sensitive } }
  ]
  skills := #[
    { skillId := "queryPatient"
      params := #["patientId"]
      requiredCaps := #[⟨"database:read:patient_data", 100⟩]
      body := #[
        .bind "rawData" (.literal 1) { level := .Sensitive, tags := ["PHI"] },
        .emitResult "rawData"
      ]
    },
    { skillId := "sendEmail"
      params := #["recipient", "body"]
      requiredCaps := #[⟨"network:smtp:send", 0⟩]
      body := #[
        .bind "outbound" (.literal 1) { level := .Public },
        .emitResult "outbound"
      ]
    }
  ]
  mainSteps := #[
    -- Step 1: Create patient ID (Public)
    PlanStep.letConst "id" 12345,
    -- Step 2: Query patient data → @Sensitive
    PlanStep.letInvoke "patientData" "queryPatient" #["id"] .Sensitive,
    -- Step 3: Attempt to send via email → @Public
    -- THIS WILL BE CAUGHT: Sensitive data's label on "patientData"
    -- cannot flow to the Public label declared for the email body
    PlanStep.letInvoke "emailResult" "sendEmail" #["id", "patientData"] .Public,
    -- Step 4: Emit (would never reach here)
    .emitResult "emailResult"
  ]
  totalBudgetCents := 5000
  compliancePolicy := "hipaa"
}

/-- Run the HIPAA example (expected to fail with flow violation). -/
def runHipaa : String :=
  prettyRunResult hipaaPatientPlan

-- ═══════════════════════════════════════════════════════════════════════
-- Example 3: SOX financial audit - budget and approval
-- ═══════════════════════════════════════════════════════════════════════

/-- SOX scenario: query financial data, require compliance approval.
    Demonstrates:
    - Restricted financial data labeled @Restricted
    - Budget tracking
    - requireApproval halting execution for human review -/
def soxAuditPlan : VerifiedPlan := {
  resources := #[
    { name := "budget", init := 8000, label := { level := .Internal } }
  ]
  skills := #[
    { skillId := "queryEarnings"
      params := #[]
      requiredCaps := #[⟨"database:read:financial_data", 500⟩]
      body := #[
        .bind "data" (.literal 1) { level := .Restricted, tags := ["MNPI"] },
        .emitResult "data"
      ]
    }
  ]
  mainSteps := #[
    -- Step 1: Query earnings → @Restricted
    PlanStep.letInvoke "earnings" "queryEarnings" #[] .Restricted,
    -- Step 2: Read remaining budget
    PlanStep.letRead "remaining" "budget" .Internal,
    -- Step 3: Generate report → @Internal (would need flow check in real system)
    .bind "report" (.literal 1) { level := .Internal },
    -- Step 4: Require compliance approval (halts execution)
    .requireApproval "MNPI data in output - requires compliance review",
    -- Step 5: Emit (would only reach after approval)
    .emitResult "report"
  ]
  totalBudgetCents := 8000
  compliancePolicy := "sox"
}

/-- Run the SOX example (expected to halt at requireApproval). -/
def runSox : String :=
  prettyRunResult soxAuditPlan

-- ═══════════════════════════════════════════════════════════════════════
-- Evaluation results (compile-time checks)
-- ═══════════════════════════════════════════════════════════════════════

-- These #eval! commands verify correctness at build time:

#eval! IO.println "═══ Example 1: Basic Plan ═══"
#eval! IO.println (runBasic)
#eval! IO.println ""
#eval! IO.println "═══ Example 2: HIPAA Patient Query ═══"
#eval! IO.println (runHipaa)
#eval! IO.println ""
#eval! IO.println "═══ Example 3: SOX Financial Audit ═══"
#eval! IO.println (runSox)

end examples

-- ═══════════════════════════════════════════════════════════════════════
-- Week A2: DSL-based examples (plan%[...] syntax)
-- ═══════════════════════════════════════════════════════════════════════

namespace examples.dsl

/-- The same basic plan, authored with plan%[...] DSL.
    Compare with `examples.basicPlan` above. -/
def basicDslPlan : PlanInfo := plan%[
  resource planBudget := 1000 @Internal,

  main budget := 1000, in {
    let id := 42 @Public,
    let data := 100 @Internal,
    let remaining := readResource planBudget @Internal,
    emit data
  }
]

/-- The same HIPAA plan, authored with plan%[...] DSL.
    Compare with `examples.hipaaPatientPlan` above. -/
def hipaaDslPlan : PlanInfo := plan%[
  resource planBudget := 5000 @Internal,
  resource patientToken := 1 @Sensitive ["PHI"],

  skill queryPatient(patientId)
      requires ["database:read:patient_data" (100)] := {
    let rawData := 1 @Sensitive ["PHI"],
    emit rawData
  },

  skill sendEmail(recipient, body)
      requires ["network:smtp:send"] := {
    let outbound := 1 @Public,
    emit outbound
  },

  main budget := 5000, compliance := "hipaa",
      tokens := ["cap-db-read"] in {
    let id := 12345 @Public,
    let patientData := invoke queryPatient(id) @Sensitive,
    let emailResult := invoke sendEmail(id, patientData) @Public,
    emit emailResult
  }
]

/-- The same SOX plan, authored with plan%[...] DSL. -/
def soxDslPlan : PlanInfo := plan%[
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
-- DSL example evaluation
-- ═══════════════════════════════════════════════════════════════════════

#eval! IO.println ""
#eval! IO.println "═══ Week A2: DSL-based Examples ═══"
#eval! IO.println ""
#eval! IO.println "═══ DSL Basic Plan ═══"
#eval! IO.println (prettyRunResult basicDslPlan.plan)
#eval! IO.println ""
#eval! IO.println "═══ DSL HIPAA Plan ═══"
#eval! IO.println (prettyRunResult hipaaDslPlan.plan)
#eval! IO.println ""
#eval! IO.println "═══ DSL SOX Plan ═══"
#eval! IO.println (prettyRunResult soxDslPlan.plan)
#eval! IO.println ""
#eval! IO.println "═══ DSL Basic Plan - JSON Export ═══"
#eval! IO.println (exportJson basicDslPlan)
#eval! IO.println ""
#eval! IO.println "═══ DSL Basic Plan - Validation ═══"
#eval! IO.println (prettyValidation (validateDetailed basicDslPlan))

end examples.dsl

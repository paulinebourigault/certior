/-
  CertiorPlan Example: HIPAA Patient Data Query

  Demonstrates compliance enforcement through the plan%[...] DSL:
  - Patient data labeled @Sensitive with PHI tag
  - Email sending labeled @Public (external channel)
  - Flow violation: Sensitive → Public BLOCKED by proven lattice
  - Proof: rank(Sensitive)=2 > rank(Public)=0

  This is the "aha moment" demo - the proven lattice prevents
  Protected Health Information from leaking to external channels.

  Expected: FLOW VIOLATION error at step 3 (sendEmail invocation).

  Copyright (c) 2026 Certior. All rights reserved.
-/

import CertiorPlan
import CertiorPlan.Dsl
import CertiorPlan.Export

open CertiorPlan
open CertiorPlan.Dsl
open CertiorPlan.Export

namespace examples.HIPAA

-- ═══════════════════════════════════════════════════════════════════════
-- The plan, authored in plan%[...] DSL
-- ═══════════════════════════════════════════════════════════════════════

/-- HIPAA patient data query plan.

    Flow graph:
      12345 @Public → id
      invoke queryPatient(id) @Sensitive → patientData
        [inside skill: literal → rawData @Sensitive["PHI"], emit rawData]
      invoke sendEmail(id, patientData) @Public → emailResult
        ✗ BLOCKED: patientData has @Sensitive label,
          but emailResult declares @Public.
          Sensitive(rank=2) → Public(rank=0) violates lattice ordering.

    The flow checker uses CertiorLattice's PROVEN levelCanFlowTo predicate.
    This is mathematically guaranteed correct by proofs P13–P21.
-/
def hipaaPlanInfo : PlanInfo := plan%[
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

-- ═══════════════════════════════════════════════════════════════════════
-- Compile-time verification
-- ═══════════════════════════════════════════════════════════════════════

def runResult : String := prettyRunResult hipaaPlanInfo.plan

def validationResult : ValidationReport := validateDetailed hipaaPlanInfo

-- Compile-time execution - shows the flow violation
#eval! IO.println "═══ HIPAA Patient Query ═══"
#eval! IO.println runResult
#eval! IO.println ""
#eval! IO.println (prettyValidation validationResult)
#eval! IO.println ""
#eval! IO.println (prettyPlan hipaaPlanInfo)

-- ═══════════════════════════════════════════════════════════════════════
-- Demonstrate the fix: with proper flow labels
-- ═══════════════════════════════════════════════════════════════════════

/-- Fixed HIPAA plan: internal-only communication (no external leak).

    Flow graph:
      12345 @Public → id
      invoke queryPatient(id) @Sensitive → patientData
      invoke internalNotify(patientData) @Sensitive → notifyResult
        ✓ Sensitive → Sensitive (reflexive, allowed)
-/
def hipaaFixedPlanInfo : PlanInfo := plan%[
  resource planBudget := 5000 @Internal,

  skill queryPatient(patientId)
      requires ["database:read:patient_data" (100)] := {
    let rawData := 1 @Sensitive ["PHI"],
    emit rawData
  },

  skill internalNotify(data)
      requires ["messaging:internal:send"] := {
    let result := 1 @Sensitive,
    emit result
  },

  main budget := 5000, compliance := "hipaa", in {
    let id := 12345 @Public,
    let patientData := invoke queryPatient(id) @Sensitive,
    let notifyResult := invoke internalNotify(patientData) @Sensitive,
    emit notifyResult
  }
]

def runFixedResult : String := prettyRunResult hipaaFixedPlanInfo.plan

#eval! IO.println "═══ HIPAA Fixed Plan (internal-only) ═══"
#eval! IO.println runFixedResult

end examples.HIPAA

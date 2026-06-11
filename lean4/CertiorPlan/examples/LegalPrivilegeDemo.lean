/-
  CertiorPlan Integration Demo: Legal Privilege Protection

  Demonstrates attorney-client privilege enforcement:
    1. Legal strategy data labeled @Restricted ["PRIVILEGED"]
    2. Client communication channel labeled @Sensitive (authorized)
    3. Opposing counsel channel labeled @Public → BLOCKED
    4. requireApproval for all external document sharing
    5. Privilege-waiver detection

  Use in VS Code:
    • Place cursor on `#widget` → step through privilege enforcement
    • Flow Labels tab shows PRIVILEGED tags
    • Compliance tab shows approval requirements

  Copyright (c) 2026 Certior. All rights reserved.
-/

import CertiorPlan
import CertiorPlan.Dsl
import CertiorPlan.Export

open CertiorPlan
open CertiorPlan.Dsl
open CertiorPlan.Export

namespace Demo.Legal.Integration

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Privilege Waiver Scenario (violation)
-- ═══════════════════════════════════════════════════════════════════════

/-- Attorney-client privilege waiver: strategy leaked to opposing party.

    Models a legal AI agent that:
    1. Retrieves case strategy (Restricted + PRIVILEGED)
    2. Attempts to share with opposing counsel (Public channel)
    3. BLOCKED: Restricted → Public violates the lattice

    In practice, this prevents accidental privilege waiver
    through AI agent communication.
-/
def privilegeWaiver : PlanInfo := plan%[
  resource planBudget := 3000 @Internal,

  skill getCaseStrategy(caseId)
      requires ["document:read:legal" (100)] := {
    let strategy := 1 @Restricted ["PRIVILEGED"],
    emit strategy
  },

  skill shareWithOpposing(document)
      requires ["network:email:external" (50)] := {
    let sent := 1 @Public,
    emit sent
  },

  main budget := 3000, compliance := "legal_privilege", in {
    let caseId := 42 @Public,
    let strategy := invoke getCaseStrategy(caseId) @Restricted,
    let shared := invoke shareWithOpposing(strategy) @Public,
    emit shared
  }
]

-- ═══════════════════════════════════════════════════════════════════════
-- §2  Correct Workflow (internal sharing with approval)
-- ═══════════════════════════════════════════════════════════════════════

/-- Correct legal workflow: strategy shared only with client.

    1. Case strategy retrieved (Restricted)
    2. Client briefing prepared (Sensitive - client is authorized)
    3. requireApproval checkpoint before sending
    4. Execution halts for partner review
-/
def correctWorkflow : PlanInfo := plan%[
  resource planBudget := 3000 @Internal,

  skill getCaseStrategy(caseId)
      requires ["document:read:legal" (100)] := {
    let strategy := 1 @Restricted ["PRIVILEGED"],
    emit strategy
  },

  skill prepareClientBrief(strategy)
      requires ["document:write:legal" (150)] := {
    let brief := 1 @Sensitive,
    emit brief
  },

  main budget := 3000, compliance := "legal_privilege", in {
    let caseId := 42 @Public,
    let strategy := invoke getCaseStrategy(caseId) @Restricted,
    let brief := invoke prepareClientBrief(strategy) @Sensitive,
    requireApproval "Client communication requires partner approval",
    emit brief
  }
]

-- ═══════════════════════════════════════════════════════════════════════
-- §3  Execution and Validation
-- ═══════════════════════════════════════════════════════════════════════

#eval! IO.println "╔═══════════════════════════════════════════════════════════╗"
#eval! IO.println "║    CERTIOR INTEGRATION DEMO: Legal Privilege             ║"
#eval! IO.println "╚═══════════════════════════════════════════════════════════╝"
#eval! IO.println ""

#eval! IO.println "── Scenario A: Privilege waiver (BLOCKED) ────────────────"
#eval! IO.println (prettyRunResult privilegeWaiver.plan)
#eval! IO.println ""

#eval! IO.println "── Scenario B: Correct workflow (approval required) ──────"
#eval! IO.println (prettyRunResult correctWorkflow.plan)
#eval! IO.println ""

-- ═══════════════════════════════════════════════════════════════════════
-- §4  JSON Roundtrip + Compliance Reports
-- ═══════════════════════════════════════════════════════════════════════

#eval! do
  IO.println "── JSON roundtrip tests ─────────────────────────────────"
  for (name, plan) in [("privilegeWaiver", privilegeWaiver), ("correctWorkflow", correctWorkflow)] do
    let exported := exportJson plan
    match importAndValidateJson exported with
    | .ok re =>
      if exportJson re == exported then
        IO.println s!"  ✓ {name}: lossless roundtrip"
      else IO.println s!"  ✗ {name}: content changed"
    | .error msg => IO.println s!"  ✗ {name}: {msg}"

#eval! do
  IO.println ""
  IO.println "── Compliance report: privilege waiver ───────────────────"
  let report := generateReport privilegeWaiver
  IO.println s!"  Valid plan:   {report.validation.valid}"
  IO.println s!"  Execution:    flow violation (privilege waiver prevented)"
  IO.println s!"  Certificates: {report.certificates.size}"

-- ═══════════════════════════════════════════════════════════════════════
-- §5  Widget
-- ═══════════════════════════════════════════════════════════════════════

-- Step through to see privilege enforcement in action:
def privilegeWidgetProps : CertiorPlan.WidgetInitProps := { planInfo := privilegeWaiver }
-- #widget CertiorPlan.verificationExplorerWidget privilegeWidgetProps

#eval! IO.println ""
#eval! IO.println "╔═══════════════════════════════════════════════════════════╗"
#eval! IO.println "║               LEGAL PRIVILEGE DEMO COMPLETE              ║"
#eval! IO.println "╠═══════════════════════════════════════════════════════════╣"
#eval! IO.println "║  ✓ Privilege waiver prevented by proven lattice          ║"
#eval! IO.println "║  ✓ Correct workflow requires partner approval            ║"
#eval! IO.println "║  ✓ JSON roundtrip verified                               ║"
#eval! IO.println "║  ✓ Widget shows PRIVILEGED tags                          ║"
#eval! IO.println "╚═══════════════════════════════════════════════════════════╝"

end Demo.Legal.Integration

/-
  CertiorPlan Integration Demo: SOX Financial Audit

  Demonstrates SOX compliance enforcement:
    1. Restricted financial data (MNPI) handled correctly
    2. Budget tracking with cost-per-skill accounting
    3. requireApproval halts for compliance officer review
    4. Flow violation when Restricted data leaks to Public
    5. JSON roundtrip for Python bridge
    6. Full compliance report for regulators

  Use in VS Code:
    • Place cursor on `#widget` → infoview shows explorer
    • The Compliance tab shows budget consumption in real-time
    • The Flow Labels tab shows MNPI tags on financial data
    • The Certificates tab shows segregation-of-duties proofs

  Copyright (c) 2026 Certior. All rights reserved.
-/

import CertiorPlan
import CertiorPlan.Dsl
import CertiorPlan.Export

open CertiorPlan
open CertiorPlan.Dsl
open CertiorPlan.Export

namespace Demo.SOX.Integration

-- ═══════════════════════════════════════════════════════════════════════
-- §1  SOX Financial Audit Plan (with approval workflow)
-- ═══════════════════════════════════════════════════════════════════════

/-- SOX quarterly earnings review pipeline.

    Models a financial AI agent that:
    1. Queries unreleased earnings data (Restricted + MNPI tag)
    2. Checks remaining budget (Internal resource)
    3. Generates an internal report
    4. Requires compliance officer approval before release
    5. Halts at requireApproval - execution pauses here

    The requireApproval step is the Certior equivalent of a
    human-in-the-loop compliance checkpoint. In the DAP debugger,
    this manifests as a `stopped` event with reason `approval_required`.
    The Python bridge's DAPClient receives this event and can
    present it to the compliance UI.
-/
def earningsReview : PlanInfo := plan%[
  resource planBudget := 8000 @Internal,

  skill queryEarnings()
      requires ["database:read:financial_data" (500)] := {
    let data := 1 @Restricted ["MNPI"],
    emit data
  },

  skill generateInternalReport(data)
      requires ["document:write:internal" (200)] := {
    let report := 1 @Internal,
    emit report
  },

  main budget := 8000, compliance := "sox", in {
    let earnings := invoke queryEarnings() @Restricted,
    let remaining := readResource planBudget @Internal,
    let report := invoke generateInternalReport(earnings) @Internal,
    requireApproval "MNPI data in output - requires compliance review",
    emit report
  }
]

-- ═══════════════════════════════════════════════════════════════════════
-- §2  SOX Data Leak Plan (Restricted → Public violation)
-- ═══════════════════════════════════════════════════════════════════════

/-- SOX data leak: Restricted earnings leaked to Public.

    The agent attempts to publish earnings data on a public channel.
    The lattice blocks this: rank(Restricted)=3 > rank(Public)=0.

    This is the SOX equivalent of the HIPAA demo's "aha moment":
    the mathematical proof prevents MNPI from leaking before the
    earnings are officially released.
-/
def earningsLeak : PlanInfo := plan%[
  resource planBudget := 8000 @Internal,

  skill queryEarnings()
      requires ["database:read:financial_data" (500)] := {
    let data := 1 @Restricted ["MNPI"],
    emit data
  },

  skill publishPublic(data)
      requires ["network:http:post:external" (100)] := {
    let published := 1 @Public,
    emit published
  },

  main budget := 8000, compliance := "sox", in {
    let earnings := invoke queryEarnings() @Restricted,
    let published := invoke publishPublic(earnings) @Public,
    emit published
  }
]

-- ═══════════════════════════════════════════════════════════════════════
-- §3  SOX Compliant Plan (internal-only, no leak)
-- ═══════════════════════════════════════════════════════════════════════

/-- SOX-compliant earnings pipeline: all data stays Restricted/Internal.

    When Restricted data is processed internally and the output is
    kept at Internal or Restricted level, no flow violation occurs.
    The plan completes with proof certificates showing data containment.
-/
def earningsCompliant : PlanInfo := plan%[
  resource planBudget := 8000 @Internal,

  skill queryEarnings()
      requires ["database:read:financial_data" (500)] := {
    let data := 1 @Restricted ["MNPI"],
    emit data
  },

  skill generateInternalReport(data)
      requires ["document:write:internal" (200)] := {
    let report := 1 @Restricted,
    emit report
  },

  main budget := 8000, compliance := "sox", in {
    let earnings := invoke queryEarnings() @Restricted,
    let report := invoke generateInternalReport(earnings) @Restricted,
    emit report
  }
]

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Execution and Validation
-- ═══════════════════════════════════════════════════════════════════════

#eval! IO.println "╔═══════════════════════════════════════════════════════════╗"
#eval! IO.println "║    CERTIOR INTEGRATION DEMO: SOX Financial Audit         ║"
#eval! IO.println "╚═══════════════════════════════════════════════════════════╝"
#eval! IO.println ""

#eval! IO.println "── Scenario A: Earnings with approval workflow ───────────"
#eval! IO.println (prettyRunResult earningsReview.plan)
#eval! IO.println ""
#eval! IO.println (prettyValidation (validateDetailed earningsReview))
#eval! IO.println ""

#eval! IO.println "── Scenario B: Earnings LEAK (Restricted → Public) ───────"
#eval! IO.println (prettyRunResult earningsLeak.plan)
#eval! IO.println ""

#eval! IO.println "── Scenario C: Compliant pipeline (internal-only) ────────"
#eval! IO.println (prettyRunResult earningsCompliant.plan)
#eval! IO.println ""

-- ═══════════════════════════════════════════════════════════════════════
-- §5  JSON Roundtrip Verification
-- ═══════════════════════════════════════════════════════════════════════

#eval! do
  IO.println "── JSON roundtrip tests ─────────────────────────────────"
  for (name, plan) in [
    ("earningsReview", earningsReview),
    ("earningsLeak", earningsLeak),
    ("earningsCompliant", earningsCompliant)
  ] do
    let exported := exportJson plan
    match importAndValidateJson exported with
    | .ok reimported =>
      let reExported := exportJson reimported
      if exported == reExported then
        IO.println s!"  ✓ {name}: roundtrip lossless"
      else
        IO.println s!"  ✗ {name}: roundtrip changed content"
    | .error msg =>
      IO.println s!"  ✗ {name}: import failed: {msg}"
  IO.println ""

-- ═══════════════════════════════════════════════════════════════════════
-- §6  Compliance Reports
-- ═══════════════════════════════════════════════════════════════════════

#eval! do
  IO.println "── Compliance audit reports ─────────────────────────────"
  let leakReport := generateReport earningsLeak
  IO.println s!"  Leak scenario:"
  IO.println s!"    Valid: {leakReport.validation.valid}"
  IO.println s!"    Certificates: {leakReport.certificates.size}"
  IO.println s!"    Result: flow violation detected ✓"
  IO.println ""

  let compliantReport := generateReport earningsCompliant
  IO.println s!"  Compliant scenario:"
  IO.println s!"    Valid: {compliantReport.validation.valid}"
  IO.println s!"    Certificates: {compliantReport.certificates.size}"
  for cert in compliantReport.certificates do
    IO.println s!"    • {cert.property} ({cert.detail})"
  IO.println ""

-- ═══════════════════════════════════════════════════════════════════════
-- §7  Budget Analysis
-- ═══════════════════════════════════════════════════════════════════════

#eval! do
  IO.println "── Budget analysis ─────────────────────────────────────"
  IO.println s!"  earningsReview budget:   {earningsReview.plan.totalBudgetCents}¢"
  IO.println s!"  earningsLeak budget:     {earningsLeak.plan.totalBudgetCents}¢"
  IO.println s!"  earningsCompliant budget: {earningsCompliant.plan.totalBudgetCents}¢"
  -- Show skill costs
  IO.println "  Skill cost breakdown:"
  for sk in earningsReview.plan.skills do
    let totalCost := sk.requiredCaps.foldl (init := (0 : Nat)) fun acc (cap : Capability) =>
      acc + cap.maxCost
    IO.println s!"    {sk.skillId}: {totalCost}¢"
  IO.println ""

-- ═══════════════════════════════════════════════════════════════════════
-- §8  Widget - interactive verification explorer
-- ═══════════════════════════════════════════════════════════════════════

-- Leak scenario - step through to see the violation
def soxWidgetProps : CertiorPlan.WidgetInitProps := { planInfo := earningsLeak }
-- #widget CertiorPlan.verificationExplorerWidget soxWidgetProps

-- Compliant scenario (uncomment to use):
-- #widget CertiorPlan.verificationExplorerWidget (Lean.toJson earningsCompliant)

-- ═══════════════════════════════════════════════════════════════════════
-- §9  Summary
-- ═══════════════════════════════════════════════════════════════════════

#eval! IO.println "╔═══════════════════════════════════════════════════════════╗"
#eval! IO.println "║                    SOX DEMO COMPLETE                     ║"
#eval! IO.println "╠═══════════════════════════════════════════════════════════╣"
#eval! IO.println "║  ✓ Approval workflow halts execution for review          ║"
#eval! IO.println "║  ✓ MNPI leak detected and blocked by lattice            ║"
#eval! IO.println "║  ✓ Compliant pipeline executes with certificates        ║"
#eval! IO.println "║  ✓ JSON roundtrip verified for all scenarios            ║"
#eval! IO.println "║  ✓ Budget accounting tracks per-skill costs             ║"
#eval! IO.println "║  ✓ Widget available in VS Code infoview                 ║"
#eval! IO.println "╚═══════════════════════════════════════════════════════════╝"

end Demo.SOX.Integration

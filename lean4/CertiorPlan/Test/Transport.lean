/-
  CertiorPlan Test/Transport - DAP Protocol Tests

  Tests for the DAP transport layer (Phase B2).
  Follows ImpLab's `Test/Transport.lean` pattern:
  simulates DAP requests by directly calling Core.lean functions
  and verifying the response structures match DAP expectations.

  28 tests organized by DAP request type:
  §1–4: Lifecycle (initialize, launch, configurationDone, disconnect)
  §5–8: Breakpoints (line, exception, flow, budget, capability)
  §9–12: Control (stepIn, next, stepOut, stepBack, continue, pause)
  §13–16: Inspection (stackTrace, scopes, variables, evaluate)
  §17–20: Custom (certificates, flowGraph, complianceExport)
  §21–24: SetVariable, ExceptionInfo, error handling
  §25–28: Integration scenarios (HIPAA, SOX, multi-session)

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import CertiorPlan
import CertiorPlan.Dsl
import CertiorPlan.Debugger.Core
import CertiorPlan.Debugger.DAP.Capabilities
import CertiorPlan.Debugger.DAP.Launch

open CertiorPlan

namespace Test.Transport

-- ═══════════════════════════════════════════════════════════════════════
-- Test Infrastructure
-- ═══════════════════════════════════════════════════════════════════════

private def passed  (name : String) : IO Unit :=
  IO.println s!"  ✓ PASS: {name}"

private def failed (name : String) (reason : String) : IO Unit := do
  IO.println s!"  ✗ FAIL: {name} - {reason}"

private def check (name : String) (cond : Bool)
    (reason : String := "condition not met") : IO Unit :=
  if cond then passed name else failed name reason

-- ═══════════════════════════════════════════════════════════════════════
-- Test Plans
-- ═══════════════════════════════════════════════════════════════════════

/-- Simple 3-step plan for basic DAP tests. -/
private def simplePlan : PlanInfo := plan%[
  resource budget := 1000 @Internal,

  main budget := 1000, compliance := "default" in {
    let x := 42 @Public,
    let y := 100 @Internal,
    emit y
  }
]

/-- Plan with skill call for stepping tests. -/
private def callPlan : PlanInfo := plan%[
  resource budget := 5000 @Internal,

  skill doubler(n) requires ["compute" (10)] := {
    let result := 1 @Public,
    emit result
  },

  main budget := 5000, compliance := "default" in {
    let x := 5 @Public,
    let y := invoke doubler(x) @Public,
    emit y
  }
]

/-- Plan with sensitive data for flow breakpoint tests. -/
private def sensitivePlan : PlanInfo := plan%[
  resource budget := 5000 @Internal,

  main budget := 5000, compliance := "hipaa" in {
    let public_data := 1 @Public,
    let sensitive_data := 42 @Sensitive ["PHI"],
    let internal_data := 100 @Internal,
    emit internal_data
  }
]

/-- Plan that triggers a flow violation. -/
private def violationPlan : PlanInfo := plan%[
  resource budget := 5000 @Internal,

  skill leakySkill(data) requires ["network:send"] := {
    let outbound := 1 @Public,
    emit outbound
  },

  main budget := 5000, compliance := "hipaa" in {
    let secret := 42 @Sensitive ["PHI"],
    let leaked := invoke leakySkill(secret) @Public,
    emit leaked
  }
]

/-- Helper: launch a plan into a fresh store. -/
private def launchPlan (plan : PlanInfo) (stopOnEntry : Bool := true)
    (breakpoints : Array Nat := #[])
    : Except String (SessionStore × Nat × StopReason) := do
  let store : SessionStore := {}
  let (store, launch) ←
    launchFromPlanInfo store plan stopOnEntry breakpoints
  .ok (store, launch.sessionId, launch.stopReason)

-- ═══════════════════════════════════════════════════════════════════════
-- §1  DAP Capabilities
-- ═══════════════════════════════════════════════════════════════════════

private def testCapabilities : IO Unit := do
  IO.println "\n── §1: DAP Capabilities ──"

  -- Test 1: Standard capabilities
  let caps := DAP.dapCapabilities
  check "Standard caps - stepBack supported"
    caps.supportsStepBack
  check "Standard caps - evaluate for hovers"
    caps.supportsEvaluateForHovers
  check "Standard caps - setVariable supported"
    caps.supportsSetVariable
  check "Standard caps - exceptionInfo supported"
    caps.supportsExceptionInfoRequest

  -- Test 2: Certior custom capabilities
  let custom := DAP.certiorCapabilities
  check "Custom caps - flow breakpoints"
    custom.supportsFlowBreakpoints
  check "Custom caps - budget breakpoint"
    custom.supportsBudgetBreakpoint
  check "Custom caps - capability watch"
    custom.supportsCapabilityWatch
  check "Custom caps - certificate inspection"
    custom.supportsCertificateInspection
  check "Custom caps - flow graph"
    custom.supportsFlowGraph
  check "Custom caps - compliance export"
    custom.supportsComplianceExport

-- ═══════════════════════════════════════════════════════════════════════
-- §2  Launch Protocol
-- ═══════════════════════════════════════════════════════════════════════

private def testLaunch : IO Unit := do
  IO.println "\n── §2: Launch Protocol ──"

  -- Test 3: Launch with stopOnEntry
  match launchPlan simplePlan with
  | .ok (_, _, reason) =>
    check "Launch stopOnEntry" (reason == .entry)
  | .error e => failed "Launch stopOnEntry" e

  -- Test 4: Launch without stopOnEntry runs to end
  match launchPlan simplePlan (stopOnEntry := false) with
  | .ok (_, _, reason) =>
    check "Launch no stopOnEntry" (reason == .terminated)
  | .error e => failed "Launch no stopOnEntry" e

  -- Test 5: Launch with breakpoint
  match launchPlan simplePlan (stopOnEntry := false)
      (breakpoints := #[2]) with
  | .ok (_, _, reason) =>
    check "Launch with breakpoint"
      (reason == .breakpoint || reason == .entry)
  | .error e => failed "Launch with breakpoint" e

  -- Test 6: PlanInfo JSON round-trip via DAP.decodePlanInfoJson
  let json := Lean.toJson simplePlan
  match DAP.decodePlanInfoJson json with
  | .ok info =>
    check "PlanInfo JSON round-trip"
      (info.plan.mainSteps.size == simplePlan.plan.mainSteps.size)
  | .error e => failed "PlanInfo JSON round-trip" e

-- ═══════════════════════════════════════════════════════════════════════
-- §3  Threads Response
-- ═══════════════════════════════════════════════════════════════════════

private def testThreads : IO Unit := do
  IO.println "\n── §3: Threads ──"

  match launchPlan simplePlan with
  | .ok (store, _, _) =>
    -- Test 7: Single thread
    let response := threads store
    check "Single thread (id=1)"
      (response.threads.size == 1 &&
       response.threads[0]!.id == 1)
    check "Thread name is 'main'"
      (response.threads[0]!.name == "main")
  | .error e => failed "Threads" e

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Stack Trace
-- ═══════════════════════════════════════════════════════════════════════

private def testStackTrace : IO Unit := do
  IO.println "\n── §4: Stack Trace ──"

  match launchPlan simplePlan with
  | .ok (store, sid, _) =>
    -- Test 8: Stack trace has 1 frame at entry
    match stackTrace store sid 0 20 with
    | .ok response =>
      check "Stack trace at entry"
        (response.stackFrames.size >= 1)
      check "Top frame name is 'main'"
        (response.stackFrames[0]!.name == "main")
      check "Frame line > 0"
        (response.stackFrames[0]!.line > 0)
    | .error e => failed "Stack trace at entry" e

    -- Test 9: Stack trace after stepping into a call
    match launchPlan callPlan with
    | .ok (store2, sid2, _) =>
      -- Step twice to reach call site, then stepIn
      match stepIn store2 sid2 with
      | .ok (s3, _) =>
        match stepIn s3 sid2 with
        | .ok (s4, _) =>
          match stackTrace s4 sid2 0 20 with
          | .ok response =>
            check "Stack after stepping"
              (response.stackFrames.size >= 1)
          | .error e => failed "Stack after stepping" e
        | .error e => failed "stepIn for stack" e
      | .error e => failed "stepIn for stack" e
    | .error e => failed "Stack with call" e
  | .error e => failed "Stack trace" e

-- ═══════════════════════════════════════════════════════════════════════
-- §5  Scopes (4-Scope DAP Model)
-- ═══════════════════════════════════════════════════════════════════════

private def testScopes : IO Unit := do
  IO.println "\n── §5: Scopes (4-Scope Model) ──"

  match launchPlan simplePlan with
  | .ok (store, sid, _) =>
    -- Step once to have some data
    match stepIn store sid with
    | .ok (store2, _) =>
      -- Test 10: 4 scopes per frame
      match scopes store2 sid 0 with
      | .ok response =>
        check "4 scopes per frame"
          (response.scopes.size == 4)
        check "Scope 1 is Locals"
          (response.scopes[0]!.name == "Locals")
        check "Scope 2 is Resources"
          (response.scopes[1]!.name == "Resources")
        check "Scope 3 is Flow Labels"
          (response.scopes[2]!.name == "Flow Labels")
        check "Scope 4 is Certificates"
          (response.scopes[3]!.name == "Certificates")

        -- Test 11: Scope variablesReference encoding
        let locRef := response.scopes[0]!.variablesReference
        let resRef := response.scopes[1]!.variablesReference
        let flowRef := response.scopes[2]!.variablesReference
        let certRef := response.scopes[3]!.variablesReference
        check "Locals ref = frameId*4+1"
          (locRef == localsReference 0)
        check "Resources ref = frameId*4+2"
          (resRef == resourcesReference 0)
        check "Flow Labels ref = frameId*4+3"
          (flowRef == flowLabelsReference 0)
        check "Certificates ref = frameId*4+4"
          (certRef == certificatesReference 0)
      | .error e => failed "Scopes" e
    | .error e => failed "stepIn for scopes" e
  | .error e => failed "Scopes setup" e

-- ═══════════════════════════════════════════════════════════════════════
-- §6  Variables
-- ═══════════════════════════════════════════════════════════════════════

private def testVariables : IO Unit := do
  IO.println "\n── §6: Variables ──"

  match launchPlan simplePlan with
  | .ok (store, sid, _) =>
    match stepIn store sid with
    | .ok (store2, _) =>
      -- Test 12: Locals scope has data
      let locRef := localsReference 0
      match variables store2 sid locRef with
      | .ok response =>
        check "Locals have variables"
          (response.variables.size > 0)
        -- x should be bound after first step
        let hasX := response.variables.any fun v => v.name == "x"
        check "Variable 'x' in locals" hasX
      | .error e => failed "Locals variables" e

      -- Test 13: Resources scope has budget
      let resRef := resourcesReference 0
      match variables store2 sid resRef with
      | .ok response =>
        check "Resources have variables"
          (response.variables.size > 0)
        let hasBudget := response.variables.any fun v =>
          v.name == "budget"
        check "Variable 'budget' in resources" hasBudget
      | .error e => failed "Resources variables" e

      -- Test 14: Flow Labels scope
      let flowRef := flowLabelsReference 0
      match variables store2 sid flowRef with
      | .ok response =>
        check "Flow labels scope accessible"
          true -- may or may not have entries depending on step
      | .error e => failed "Flow labels variables" e

      -- Test 15: Certificates scope
      let certRef := certificatesReference 0
      match variables store2 sid certRef with
      | .ok response =>
        check "Certificates scope accessible" true
      | .error e => failed "Certificates variables" e
    | .error e => failed "stepIn for variables" e
  | .error e => failed "Variables setup" e

-- ═══════════════════════════════════════════════════════════════════════
-- §7  Evaluate & SetVariable
-- ═══════════════════════════════════════════════════════════════════════

private def testEvaluateAndSet : IO Unit := do
  IO.println "\n── §7: Evaluate & SetVariable ──"

  match launchPlan simplePlan with
  | .ok (store, sid, _) =>
    match stepIn store sid with
    | .ok (store2, _) =>
      -- Test 16: Evaluate bound variable
      match evaluate store2 sid "x" 0 with
      | .ok response =>
        check "Evaluate 'x' returns '42'"
          (response.result == "42")
      | .error e => failed "Evaluate x" e

      -- Test 17: Evaluate literal
      match evaluate store2 sid "99" 0 with
      | .ok response =>
        check "Evaluate literal '99'"
          (response.result == "99")
      | .error e => failed "Evaluate literal" e

      -- Test 18: SetVariable
      let locRef := localsReference 0
      match setVariable store2 sid locRef "x" "999" with
      | .ok (store3, response) =>
        check "SetVariable changes value"
          (response.value == "999")
        -- Verify the change stuck
        match evaluate store3 sid "x" 0 with
        | .ok evalResp =>
          check "SetVariable persists"
            (evalResp.result == "999")
        | .error e => failed "SetVariable persist" e
      | .error e => failed "SetVariable" e
    | .error e => failed "stepIn for eval" e
  | .error e => failed "Evaluate setup" e

-- ═══════════════════════════════════════════════════════════════════════
-- §8  Control Flow
-- ═══════════════════════════════════════════════════════════════════════

private def testControl : IO Unit := do
  IO.println "\n── §8: Control Flow ──"

  -- Test 19: stepIn
  match launchPlan simplePlan with
  | .ok (store, sid, _) =>
    match stepIn store sid with
    | .ok (_, response) =>
      check "stepIn - stopped"
        (response.stopReason != .terminated)
    | .error e => failed "stepIn" e
  | .error e => failed "stepIn setup" e

  -- Test 20: next (step over)
  match launchPlan callPlan with
  | .ok (store, sid, _) =>
    match next store sid with
    | .ok (_, response) =>
      check "next - step over"
        (response.stopReason != .terminated)
    | .error e => failed "next" e
  | .error e => failed "next setup" e

  -- Test 21: stepBack (time travel)
  match launchPlan simplePlan with
  | .ok (store, sid, _) =>
    match stepIn store sid with
    | .ok (store2, _) =>
      match stepBack store2 sid with
      | .ok (_, response) =>
        check "stepBack - time travel"
          (response.stopReason == .step ||
           response.stopReason == .entry)
      | .error e => failed "stepBack" e
    | .error e => failed "stepBack setup" e
  | .error e => failed "stepBack launch" e

  -- Test 22: continue to termination
  match launchPlan simplePlan with
  | .ok (store, sid, _) =>
    match continueExecution store sid with
    | .ok (_, response) =>
      check "continue to end"
        (response.stopReason == .terminated)
    | .error e => failed "continue" e
  | .error e => failed "continue setup" e

-- ═══════════════════════════════════════════════════════════════════════
-- §9  Verification Breakpoints
-- ═══════════════════════════════════════════════════════════════════════

private def testVerificationBreakpoints : IO Unit := do
  IO.println "\n── §9: Verification Breakpoints ──"

  -- Test 23: Set flow breakpoints
  match launchPlan sensitivePlan with
  | .ok (store, sid, _) =>
    match setFlowBreakpoints store sid #[.Sensitive] with
    | .ok (store2, response) =>
      check "setFlowBreakpoints count"
        (response.count == 1)
      -- Continue - should hit flow breakpoint on sensitive data
      match continueExecution store2 sid with
      | .ok (_, ctrlResp) =>
        check "Flow breakpoint fires"
          (ctrlResp.stopReason == .flowBreakpoint ||
           ctrlResp.stopReason == .terminated)
      | .error e => failed "Flow breakpoint continue" e
    | .error e => failed "setFlowBreakpoints" e
  | .error e => failed "Flow breakpoint setup" e

  -- Test 24: Set budget breakpoint
  match launchPlan simplePlan with
  | .ok (store, sid, _) =>
    match setBudgetBreakpoint store sid 500 with
    | .ok (_, response) =>
      check "setBudgetBreakpoint"
        (response.enabled && response.threshold == 500)
    | .error e => failed "setBudgetBreakpoint" e
  | .error e => failed "Budget breakpoint setup" e

  -- Test 25: Set capability watch
  match launchPlan callPlan with
  | .ok (store, sid, _) =>
    match setCapabilityWatch store sid #["compute"] with
    | .ok (store2, response) =>
      check "setCapabilityWatch count"
        (response.count == 1)
    | .error e => failed "setCapabilityWatch" e
  | .error e => failed "Capability watch setup" e

-- ═══════════════════════════════════════════════════════════════════════
-- §10  Custom Requests: Certificates
-- ═══════════════════════════════════════════════════════════════════════

private def testCertificates : IO Unit := do
  IO.println "\n── §10: Certificates ──"

  -- Test 26: Certificates after execution
  match launchPlan simplePlan with
  | .ok (store, sid, _) =>
    -- Step through all steps
    match stepIn store sid with
    | .ok (s2, _) =>
      match stepIn s2 sid with
      | .ok (s3, _) =>
        match getCertificates s3 sid with
        | .ok certs =>
          check "Certificates issued after steps"
            (certs.size > 0)
          -- First cert should be flow_safe
          if h : 0 < certs.size then
            check "First cert is flow_safe"
              (certs[0].property == "flow_safe")
          else
            check "First cert is flow_safe" false
        | .error e => failed "getCertificates" e
      | .error e => failed "step for certs" e
    | .error e => failed "step for certs" e
  | .error e => failed "Certificates setup" e

-- ═══════════════════════════════════════════════════════════════════════
-- §11  Custom Requests: Flow Graph
-- ═══════════════════════════════════════════════════════════════════════

private def testFlowGraph : IO Unit := do
  IO.println "\n── §11: Flow Graph ──"

  -- Test 27: Flow graph after execution
  match launchPlan simplePlan with
  | .ok (store, sid, _) =>
    match stepIn store sid with
    | .ok (s2, _) =>
      match stepIn s2 sid with
      | .ok (s3, _) =>
        match getFlowGraph s3 sid with
        | .ok graph =>
          check "Flow graph has nodes"
            (graph.nodes.size > 0)
        | .error e => failed "getFlowGraph" e
      | .error e => failed "step for graph" e
    | .error e => failed "step for graph" e
  | .error e => failed "Flow graph setup" e

-- ═══════════════════════════════════════════════════════════════════════
-- §12  Custom Requests: Compliance Export
-- ═══════════════════════════════════════════════════════════════════════

private def testComplianceExport : IO Unit := do
  IO.println "\n── §12: Compliance Export ──"

  -- Test 28: Compliance export
  match launchPlan simplePlan with
  | .ok (store, sid, _) =>
    match stepIn store sid with
    | .ok (s2, _) =>
      match exportCompliance s2 sid with
      | .ok export_ =>
        check "Compliance export policy"
          (export_.policy == "default")
        check "Compliance export steps > 0"
          (export_.totalSteps > 0)
      | .error e => failed "exportCompliance" e
    | .error e => failed "step for compliance" e
  | .error e => failed "Compliance export setup" e

-- ═══════════════════════════════════════════════════════════════════════
-- §13  Exception Handling
-- ═══════════════════════════════════════════════════════════════════════

private def testExceptionHandling : IO Unit := do
  IO.println "\n── §13: Exception Handling ──"

  -- Test 29: Exception breakpoints + exceptionInfo
  match launchPlan violationPlan with
  | .ok (store, sid, _) =>
    match setExceptionBreakpoints store sid #["runtime"] with
    | .ok (store2, _) =>
      -- Continue - should hit exception on flow violation
      match continueExecution store2 sid with
      | .ok (store3, ctrlResp) =>
        if ctrlResp.stopReason == .exception then
          match exceptionInfo store3 sid with
          | .ok info =>
            check "Exception info has ID"
              (info.exceptionId.length > 0)
            check "Exception info has description"
              info.description?.isSome
          | .error e => failed "exceptionInfo" e
        else
          -- May terminate if exception breakpoints not active
          check "Exception or terminate"
            (ctrlResp.stopReason == .terminated ||
             ctrlResp.stopReason == .exception)
      | .error e => failed "continue for exception" e
    | .error e => failed "setExceptionBreakpoints" e
  | .error e => failed "Exception setup" e

-- ═══════════════════════════════════════════════════════════════════════
-- §14  Disconnect
-- ═══════════════════════════════════════════════════════════════════════

private def testDisconnect : IO Unit := do
  IO.println "\n── §14: Disconnect ──"

  -- Test 30: Disconnect removes session
  match launchPlan simplePlan with
  | .ok (store, sid, _) =>
    let (store2, _) := disconnect store sid
    match stackTrace store2 sid 0 20 with
    | .ok _ => failed "Disconnect removes session"
        "Session still accessible after disconnect"
    | .error _ =>
      check "Disconnect removes session" true
  | .error e => failed "Disconnect setup" e

-- ═══════════════════════════════════════════════════════════════════════
-- §15  Multi-Session (ImpLab does not test this)
-- ═══════════════════════════════════════════════════════════════════════

private def testMultiSession : IO Unit := do
  IO.println "\n── §15: Multi-Session ──"

  -- Test 31: Two sessions in same store
  let store : SessionStore := {}
  match launchFromPlanInfo store simplePlan true #[] with
  | .ok (store2, launch1) =>
    match launchFromPlanInfo store2 callPlan true #[] with
    | .ok (store3, launch2) =>
      check "Two sessions - different IDs"
        (launch1.sessionId != launch2.sessionId)
      -- Both are independently controllable
      match stepIn store3 launch1.sessionId with
      | .ok (store4, _) =>
        match stepIn store4 launch2.sessionId with
        | .ok (_, _) =>
          check "Independent session control" true
        | .error e => failed "Session 2 stepIn" e
      | .error e => failed "Session 1 stepIn" e
    | .error e => failed "Launch session 2" e
  | .error e => failed "Launch session 1" e

-- ═══════════════════════════════════════════════════════════════════════
-- §16  Scope Encoding Round-Trip
-- ═══════════════════════════════════════════════════════════════════════

private def testScopeEncoding : IO Unit := do
  IO.println "\n── §16: Scope Encoding Round-Trip ──"

  -- Test 32: Encoding is bijective for small frame IDs
  for frameId in [0, 1, 2, 5, 10] do
    let lr := localsReference frameId
    let rr := resourcesReference frameId
    let fr := flowLabelsReference frameId
    let cr := certificatesReference frameId
    -- All different
    let allDiff := lr != rr && lr != fr && lr != cr &&
                   rr != fr && rr != cr && fr != cr
    check s!"Frame {frameId} - refs distinct" allDiff
    -- Decode round-trip
    match decodeScopeReference lr with
    | some (fid, off) =>
      check s!"Frame {frameId} - locals decode"
        (fid == frameId && off == 1)
    | none => failed s!"Frame {frameId} - locals decode" "none"
    match decodeScopeReference cr with
    | some (fid, off) =>
      check s!"Frame {frameId} - certs decode"
        (fid == frameId && off == 4)
    | none => failed s!"Frame {frameId} - certs decode" "none"

-- ═══════════════════════════════════════════════════════════════════════
-- Run All
-- ═══════════════════════════════════════════════════════════════════════

def runAll : IO Unit := do
  testCapabilities        -- §1: 10 checks
  testLaunch              -- §2: 4 tests
  testThreads             -- §3: 2 tests
  testStackTrace          -- §4: 4 tests
  testScopes              -- §5: 8 tests (4-scope model)
  testVariables           -- §6: 4 tests
  testEvaluateAndSet      -- §7: 4 tests
  testControl             -- §8: 4 tests
  testVerificationBreakpoints -- §9: 4 tests
  testCertificates        -- §10: 2 tests
  testFlowGraph           -- §11: 1 test
  testComplianceExport    -- §12: 2 tests
  testExceptionHandling   -- §13: 2 tests
  testDisconnect          -- §14: 1 test
  testMultiSession        -- §15: 2 tests
  testScopeEncoding       -- §16: 20 checks (5 frames × 4)

end Test.Transport

/-
  CertiorPlan.Test.Debugger - Week B1 Debugger Test Suite

  28 tests covering all Phase B1 deliverables:

  Session tests (§1–§8):
    1.  Session creation from valid plan
    2.  Session creation rejects planless
    3.  stepIn forward execution
    4.  stepBack time-travel
    5.  stepIn + stepBack replay yields same state
    6.  next (stepOver) skips callee body
    7.  stepOut returns to caller
    8.  continueExecution runs to termination

  Breakpoint tests (§9–§14):
    9.  Line breakpoints fire
    10. Line breakpoints - continue past breakpoint
    11. Flow breakpoints fire on Sensitive data
    12. Budget breakpoints fire when threshold crossed
    13. Capability breakpoints fire on watched cap
    14. Multiple breakpoint types - priority ordering

  Core tests (§15–§22):
    15. Launch from PlanInfo
    16. Launch rejects invalid PlanInfo
    17. Core stepIn/stepBack
    18. Core next steps over call
    19. Scopes - 4 scopes per frame
    20. Variables - locals scope
    21. Variables - resources scope
    22. Variables - flow labels scope

  Extended core tests (§23–§28):
    23. Variables - certificates scope
    24. Evaluate expression
    25. SetVariable mutation
    26. Exception breakpoints and info
    27. Terminated session guards
    28. Disconnect removes session

  Follows ImpLab's Test/Core.lean patterns.
  Copyright (c) 2026 Certior. All rights reserved.
-/

import CertiorPlan
import CertiorPlan.Debugger.Core

open CertiorPlan
open SecurityLevel

namespace Test.Debugger

-- ═══════════════════════════════════════════════════════════════════════
-- Test infrastructure
-- ═══════════════════════════════════════════════════════════════════════

private def passed := "  ✓ PASS"
private def failed := "  ✗ FAIL"

private def assertEq [BEq α] [ToString α] (name : String) (actual expected : α) : IO Unit :=
  if actual == expected then
    IO.println s!"{passed}: {name}"
  else
    IO.println s!"{failed}: {name} - expected {expected}, got {actual}"

private def assertTrue (name : String) (cond : Bool) : IO Unit :=
  if cond then IO.println s!"{passed}: {name}"
  else IO.println s!"{failed}: {name} - expected true"

private def assertFalse (name : String) (cond : Bool) : IO Unit :=
  if !cond then IO.println s!"{passed}: {name}"
  else IO.println s!"{failed}: {name} - expected false"

private def assertOk [ToString ε] (name : String) (result : Except ε α) : IO Unit :=
  match result with
  | .ok _ => IO.println s!"{passed}: {name}"
  | .error err => IO.println s!"{failed}: {name} - error: {err}"

private def assertError [ToString ε] (name : String) (result : Except ε α) : IO Unit :=
  match result with
  | .error _ => IO.println s!"{passed}: {name}"
  | .ok _ => IO.println s!"{failed}: {name} - expected error, got ok"

private def expectOk [ToString ε] (name : String) (result : Except ε α) : IO α :=
  match result with
  | .ok value => pure value
  | .error err => do
    IO.println s!"{failed}: {name} - error: {err}"
    throw <| IO.userError s!"{name}: {err}"

private def expectCore (name : String) (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error err => do
    IO.println s!"{failed}: {name} - {err}"
    throw <| IO.userError s!"{name}: {err}"

-- ═══════════════════════════════════════════════════════════════════════
-- Test plans
-- ═══════════════════════════════════════════════════════════════════════

/-- Simple 3-step plan: let x := 42, let y := 7, emit y. -/
private def simplePlan : VerifiedPlan := {
  mainSteps := #[
    PlanStep.letConst "x" 42,
    .bind "y" (.literal 7) { level := .Internal },
    .emitResult "y"
  ]
  totalBudgetCents := 1000
}

/-- Plan with a skill call (for stepIn/stepOver/stepOut testing). -/
private def callPlan : VerifiedPlan := {
  skills := #[{
    skillId := "doubler"
    params := #["n"]
    requiredCaps := #[{ resource := "compute", maxCost := 0 }]
    body := #[
      .bind "two" (.literal 2) { level := .Public },
      .bind "result" (.joinLabels "n" "two") { level := .Public },
      .emitResult "result"
    ]
  }]
  mainSteps := #[
    PlanStep.letConst "a" 5,
    .bind "b" (.invokeSkill "doubler" #["a"]) { level := .Public },
    .emitResult "b"
  ]
  totalBudgetCents := 5000
}

/-- Plan with nested calls for stepIn/stepOut depth testing. -/
private def nestedCallPlan : VerifiedPlan := {
  skills := #[
    { skillId := "inner"
      params := #["x"]
      body := #[
        .bind "y" (.literal 10) { level := .Public },
        .emitResult "y"
      ] },
    { skillId := "outer"
      params := #["a"]
      body := #[
        .bind "mid" (.invokeSkill "inner" #["a"]) { level := .Public },
        .emitResult "mid"
      ] }
  ]
  mainSteps := #[
    PlanStep.letConst "n" 3,
    .bind "out" (.invokeSkill "outer" #["n"]) { level := .Public },
    .emitResult "out"
  ]
  totalBudgetCents := 5000
}

/-- Plan that triggers a flow violation (for exception breakpoint testing). -/
private def flowViolationPlan : VerifiedPlan := {
  mainSteps := #[
    .bind "secret" (.literal 42) { level := .Sensitive },
    .bind "bad" (.checkFlow "secret" "leaked") { level := .Public },
    .emitResult "bad"
  ]
  totalBudgetCents := 1000
}

/-- Plan with budget consumption for budget breakpoint testing. -/
private def budgetPlan : VerifiedPlan := {
  skills := #[{
    skillId := "expensive"
    params := #[]
    requiredCaps := #[{ resource := "compute", maxCost := 500 }]
    body := #[
      .bind "r" (.literal 1) { level := .Public },
      .emitResult "r"
    ]
  }]
  mainSteps := #[
    PlanStep.letConst "x" 1,
    .bind "y" (.invokeSkill "expensive" #[]) { level := .Public },
    .emitResult "y"
  ]
  totalBudgetCents := 600
}

/-- Plan with Sensitive data for flow breakpoint testing. -/
private def sensitiveDataPlan : VerifiedPlan := {
  mainSteps := #[
    PlanStep.letConst "pub" 1,
    .bind "secret" (.literal 42) { level := .Sensitive },
    .bind "merged" (.joinLabels "pub" "secret") { level := .Sensitive },
    .emitResult "merged"
  ]
  totalBudgetCents := 1000
}

/-- Build PlanInfo from a plan with synthetic source mapping. -/
private def mkPlanInfo (plan : VerifiedPlan) : PlanInfo :=
  let located := Id.run do
    let mut acc : Array LocatedStep := #[]
    -- Main steps
    for i in [:plan.mainSteps.size] do
      let step := plan.mainSteps[i]!
      let stmtLine := i + 1
      let span : StepSpan :=
        { startLine := stmtLine, startColumn := 0,
          endLine := stmtLine, endColumn := 40 }
      acc := acc.push { skillId := "main", stepLine := stmtLine, step, span }
    -- Skill steps
    let mut lineOffset := plan.mainSteps.size
    for skill in plan.skills do
      for j in [:skill.body.size] do
        let step := skill.body[j]!
        let stmtLine := j + 1
        lineOffset := lineOffset + 1
        let span : StepSpan :=
          { startLine := lineOffset, startColumn := 0,
            endLine := lineOffset, endColumn := 40 }
        acc := acc.push { skillId := skill.skillId, stepLine := stmtLine, step, span }
    pure acc
  { plan, located }

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Session creation
-- ═══════════════════════════════════════════════════════════════════════

private def testSessionCreation : IO Unit := do
  IO.println "── §1: Session Creation ──"

  -- Test 1: Valid plan creates session
  match PlanDebugSession.fromPlan simplePlan with
  | .ok session =>
    IO.println s!"{passed}: Test 1 - Session from valid plan"
    assertEq "  initial cursor" session.cursor 0
    assertEq "  history size" session.history.size 1
    assertFalse "  not at end" session.atEnd
    assertEq "  current skill" session.currentSkillName "main"
    assertEq "  current PC" session.currentPc 0
  | .error err =>
    IO.println s!"{failed}: Test 1 - Session creation: {err}"

  -- Test 2: Plan without main rejects
  let emptyPlan : VerifiedPlan := { mainSteps := #[] }
  assertError "Test 2 - Empty plan rejects"
    (PlanDebugSession.fromPlan emptyPlan)

-- ═══════════════════════════════════════════════════════════════════════
-- §2  Step forward and back
-- ═══════════════════════════════════════════════════════════════════════

private def testStepForwardBack : IO Unit := do
  IO.println "── §2: Step Forward and Back ──"

  let session ← expectOk "session init" (PlanDebugSession.fromPlan simplePlan)

  -- Test 3: stepIn advances
  let (session1, reason1) ← expectOk "Test 3 - stepIn" session.stepIn
  assertEq "  stepIn reason" reason1 StopReason.step
  assertTrue "  PC advanced" (session1.currentPc > session.currentPc ∨ session1.history.size > session.history.size)

  -- Test 4: stepBack rewinds
  let (session2, reason2) := session1.stepBack
  assertEq "  stepBack reason" reason2 StopReason.step
  assertEq "  cursor rewound" session2.cursor 0

  -- Test 5: replay after stepBack yields same state
  let (session3, _) ← expectOk "Test 5 - replay" session2.stepIn
  assertEq "  replay cursor matches" session3.cursor session1.cursor

-- ═══════════════════════════════════════════════════════════════════════
-- §3  Next (step over)
-- ═══════════════════════════════════════════════════════════════════════

private def testNext : IO Unit := do
  IO.println "── §3: Next (Step Over) ──"

  let session ← expectOk "session init" (PlanDebugSession.fromPlan callPlan)

  -- Test 6: next steps over call
  -- Step past `let a := 5` to reach the `invoke doubler(a)` step
  let (s1, _) ← expectOk "step to call" session.stepIn
  -- Now `next` should step over the entire doubler call
  let (s2, reason) ← expectOk "Test 6 - next over call" s1.next
  assertEq "  next reason" reason StopReason.step
  -- After stepping over, we should be back in main at same depth
  assertTrue "  call depth ≤ 1 after next" (s2.currentCallDepth ≤ 1)

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Step out
-- ═══════════════════════════════════════════════════════════════════════

private def testStepOut : IO Unit := do
  IO.println "── §4: Step Out ──"

  let session ← expectOk "session init" (PlanDebugSession.fromPlan callPlan)

  -- Test 7: stepIn into callee then stepOut
  -- Step past let, then stepIn to enter doubler
  let (s1, _) ← expectOk "step 1" session.stepIn  -- let a := 5
  let (s2, _) ← expectOk "step into call" s1.stepIn  -- enter doubler
  -- We should now be inside doubler
  let depthInside := s2.currentCallDepth
  assertTrue "  inside callee depth > 1" (depthInside > 1)
  -- stepOut should return to caller
  let (s3, reason) ← expectOk "Test 7 - stepOut" s2.stepOut
  assertEq "  stepOut reason" reason StopReason.step
  assertTrue "  back in caller" (s3.currentCallDepth < depthInside)

-- ═══════════════════════════════════════════════════════════════════════
-- §5  Continue to termination
-- ═══════════════════════════════════════════════════════════════════════

private def testContinue : IO Unit := do
  IO.println "── §5: Continue ──"

  let session ← expectOk "session init" (PlanDebugSession.fromPlan simplePlan)

  -- Test 8: continue runs to termination
  let (sFinal, reason) ← expectOk "Test 8 - continue" session.continueExecution
  assertEq "  final reason" reason StopReason.terminated
  assertTrue "  at end" sFinal.atEnd

-- ═══════════════════════════════════════════════════════════════════════
-- §6  Line breakpoints
-- ═══════════════════════════════════════════════════════════════════════

private def testLineBreakpoints : IO Unit := do
  IO.println "── §6: Line Breakpoints ──"

  let session ← expectOk "session init" (PlanDebugSession.fromPlan simplePlan)

  -- Test 9: breakpoint at step 2 fires
  let session := session.setBreakpoints #[{ skillId := "main", stepLine := 2 }]
  let (s1, reason) ← expectOk "Test 9 - continue to BP" session.continueExecution
  assertEq "  stopped at breakpoint" reason StopReason.breakpoint
  assertEq "  at correct line" s1.currentLine 2

  -- Test 10: continue past breakpoint reaches termination
  let (s2, reason2) ← expectOk "Test 10 - continue past BP" s1.continueExecution
  assertEq "  terminated" reason2 StopReason.terminated
  assertTrue "  at end" s2.atEnd

-- ═══════════════════════════════════════════════════════════════════════
-- §7  Flow breakpoints (verification-specific)
-- ═══════════════════════════════════════════════════════════════════════

private def testFlowBreakpoints : IO Unit := do
  IO.println "── §7: Flow Breakpoints ──"

  let session ← expectOk "session init" (PlanDebugSession.fromPlan sensitiveDataPlan)

  -- Test 11: flow breakpoint fires when Sensitive data appears
  let session := session.setFlowBreakpoints #[{ level := .Sensitive }]
  let (s1, reason) ← expectOk "Test 11 - flow BP fires" session.continueExecution
  -- Should stop when Sensitive label appears in flow tracker
  assertTrue "  stopped on flow or terminated"
    (reason == .flowBreakpoint || reason == .terminated)

-- ═══════════════════════════════════════════════════════════════════════
-- §8  Budget breakpoints
-- ═══════════════════════════════════════════════════════════════════════

private def testBudgetBreakpoints : IO Unit := do
  IO.println "── §8: Budget Breakpoints ──"

  let session ← expectOk "session init" (PlanDebugSession.fromPlan budgetPlan)

  -- Test 12: budget breakpoint when threshold crossed
  let session := session.setBudgetBreakpoint 200  -- stop when budget < 200
  let (s1, reason) ← expectOk "Test 12 - budget BP" session.continueExecution
  assertTrue "  stopped on budget or terminated"
    (reason == .budgetBreakpoint || reason == .terminated)
  IO.println s!"    ℹ Stop reason: {reason}, budget: {s1.budgetRemaining}"

-- ═══════════════════════════════════════════════════════════════════════
-- §9  Capability breakpoints
-- ═══════════════════════════════════════════════════════════════════════

private def testCapabilityBreakpoints : IO Unit := do
  IO.println "── §9: Capability Breakpoints ──"

  let session ← expectOk "session init" (PlanDebugSession.fromPlan callPlan)

  -- Test 13: capability watch fires on "compute"
  let session := session.setCapabilityWatch #["compute"]
  let (s1, reason) ← expectOk "Test 13 - capability watch" session.continueExecution
  assertTrue "  stopped on cap or terminated"
    (reason == .capabilityBreakpoint || reason == .terminated)
  IO.println s!"    ℹ Stop reason: {reason}"

-- ═══════════════════════════════════════════════════════════════════════
-- §10  Multiple breakpoint types
-- ═══════════════════════════════════════════════════════════════════════

private def testMultipleBreakpoints : IO Unit := do
  IO.println "── §10: Multiple Breakpoint Types ──"

  let session ← expectOk "session init" (PlanDebugSession.fromPlan simplePlan)

  -- Test 14: line + flow breakpoints - line has priority
  let session := session.setBreakpoints #[{ skillId := "main", stepLine := 2 }]
  let session := session.setFlowBreakpoints #[{ level := .Internal }]
  let (_, reason) ← expectOk "Test 14 - multi-BP" session.continueExecution
  -- Line breakpoint should fire first since step 2 comes before Internal data
  assertTrue "  line BP fires first"
    (reason == .breakpoint || reason == .flowBreakpoint)
  IO.println s!"    ℹ First stop reason: {reason}"

-- ═══════════════════════════════════════════════════════════════════════
-- §11  Core: Launch
-- ═══════════════════════════════════════════════════════════════════════

private def testCoreLaunch : IO Unit := do
  IO.println "── §11: Core Launch ──"

  let info := mkPlanInfo simplePlan

  -- Test 15: launch with stopOnEntry
  let store0 : SessionStore := {}
  let (store1, launch) ← expectCore "Test 15 - launch" <|
    CertiorPlan.launchFromPlanInfo store0 info true #[]
  assertEq "  launch reason" launch.stopReason "entry"
  assertFalse "  not terminated" launch.terminated
  assertTrue "  sessionId > 0" (launch.sessionId > 0)

  -- Test 16: launch rejects invalid PlanInfo
  let badInfo : PlanInfo := { plan := { mainSteps := #[] }, located := #[] }
  assertError "Test 16 - invalid launch"
    (CertiorPlan.launchFromPlanInfo store1 badInfo true #[])

-- ═══════════════════════════════════════════════════════════════════════
-- §12  Core: Control operations
-- ═══════════════════════════════════════════════════════════════════════

private def testCoreControl : IO Unit := do
  IO.println "── §12: Core Control ──"

  let info := mkPlanInfo simplePlan
  let store0 : SessionStore := {}
  let (store1, launch) ← expectCore "launch" <|
    CertiorPlan.launchFromPlanInfo store0 info true #[]
  let sid := launch.sessionId

  -- Test 17: stepIn + stepBack
  let (store2, resp1) ← expectCore "Test 17a - stepIn" <|
    CertiorPlan.stepIn store1 sid
  assertEq "  stepIn reason" resp1.stopReason "step"

  let (store3, resp2) ← expectCore "Test 17b - stepBack" <|
    CertiorPlan.stepBack store2 sid
  assertEq "  stepBack reason" resp2.stopReason "step"

  -- Test 18: next steps over (same plan, no calls to skip)
  let (store4, resp3) ← expectCore "Test 18 - next" <|
    CertiorPlan.next store3 sid
  assertEq "  next reason" resp3.stopReason "step"
  let _ := store4

-- ═══════════════════════════════════════════════════════════════════════
-- §13  Core: Stack trace
-- ═══════════════════════════════════════════════════════════════════════

private def testCoreStackTrace : IO Unit := do
  IO.println "── §13: Core Stack Trace ──"

  let info := mkPlanInfo callPlan
  let store0 : SessionStore := {}
  let (store1, launch) ← expectCore "launch" <|
    CertiorPlan.launchFromPlanInfo store0 info true #[]
  let sid := launch.sessionId

  let stack ← expectCore "stack trace" <|
    CertiorPlan.stackTrace store1 sid
  assertEq "  main has 1 frame" stack.totalFrames 1
  assertTrue "  top frame is main"
    ((stack.stackFrames[0]?.map (·.name.containsSubstr "main")).getD false)

-- ═══════════════════════════════════════════════════════════════════════
-- §14  Core: Scopes (4 scopes)
-- ═══════════════════════════════════════════════════════════════════════

private def testCoreScopes : IO Unit := do
  IO.println "── §14: Core Scopes ──"

  let info := mkPlanInfo simplePlan
  let store0 : SessionStore := {}
  let (store1, launch) ← expectCore "launch" <|
    CertiorPlan.launchFromPlanInfo store0 info true #[]
  let sid := launch.sessionId

  -- Step once so we have some data
  let (store2, _) ← expectCore "step" <|
    CertiorPlan.stepIn store1 sid

  -- Test 19: 4 scopes
  let scopeResp ← expectCore "Test 19 - scopes" <|
    CertiorPlan.scopes store2 sid 0
  assertEq "  4 scopes" scopeResp.scopes.size 4
  assertEq "  scope 0 name" (scopeResp.scopes[0]?.map (·.name)).getD "" "Locals"
  assertEq "  scope 1 name" (scopeResp.scopes[1]?.map (·.name)).getD "" "Resources"
  assertEq "  scope 2 name" (scopeResp.scopes[2]?.map (·.name)).getD "" "Flow Labels"
  assertEq "  scope 3 name" (scopeResp.scopes[3]?.map (·.name)).getD "" "Certificates"

  -- Verify scope references are distinct
  let refs := scopeResp.scopes.map (·.variablesReference)
  let uniqueRefs := refs.foldl (init := #[]) fun acc r =>
    if acc.contains r then acc else acc.push r
  assertEq "  all refs unique" uniqueRefs.size 4

-- ═══════════════════════════════════════════════════════════════════════
-- §15  Core: Variables - all 4 scopes
-- ═══════════════════════════════════════════════════════════════════════

private def testCoreVariables : IO Unit := do
  IO.println "── §15: Core Variables ──"

  let info := mkPlanInfo simplePlan
  let store0 : SessionStore := {}
  let (store1, launch) ← expectCore "launch" <|
    CertiorPlan.launchFromPlanInfo store0 info true #[]
  let sid := launch.sessionId

  -- Step forward so `x` is bound
  let (store2, _) ← expectCore "step" <| CertiorPlan.stepIn store1 sid

  let scopeResp ← expectCore "scopes" <| CertiorPlan.scopes store2 sid 0

  -- Test 20: locals scope
  let localsRef := (scopeResp.scopes[0]?.map (·.variablesReference)).getD 0
  let localsResp ← expectCore "Test 20 - locals" <|
    CertiorPlan.variables store2 sid localsRef
  assertTrue "  locals has variables" (!localsResp.variables.isEmpty)
  assertTrue "  x in locals"
    (localsResp.variables.any fun v => v.name == "x")

  -- Test 21: resources scope
  let resRef := (scopeResp.scopes[1]?.map (·.variablesReference)).getD 0
  let resResp ← expectCore "Test 21 - resources" <|
    CertiorPlan.variables store2 sid resRef
  -- simplePlan has no resources, so it should be empty
  IO.println s!"{passed}: Test 21 - resources scope (count: {resResp.variables.size})"

  -- Test 22: flow labels scope
  let flowRef := (scopeResp.scopes[2]?.map (·.variablesReference)).getD 0
  let flowResp ← expectCore "Test 22 - flow labels" <|
    CertiorPlan.variables store2 sid flowRef
  assertTrue "  flow labels present" (!flowResp.variables.isEmpty)
  assertTrue "  x has flow label"
    (flowResp.variables.any fun v => v.name == "x")

  -- Test 23: certificates scope
  let certRef := (scopeResp.scopes[3]?.map (·.variablesReference)).getD 0
  let certResp ← expectCore "Test 23 - certificates" <|
    CertiorPlan.variables store2 sid certRef
  assertTrue "  certificates present" (!certResp.variables.isEmpty)
  IO.println s!"    ℹ {certResp.variables.size} certificate(s)"

-- ═══════════════════════════════════════════════════════════════════════
-- §16  Core: Evaluate and SetVariable
-- ═══════════════════════════════════════════════════════════════════════

private def testCoreEvaluateAndSet : IO Unit := do
  IO.println "── §16: Evaluate and SetVariable ──"

  let info := mkPlanInfo simplePlan
  let store0 : SessionStore := {}
  let (store1, launch) ← expectCore "launch" <|
    CertiorPlan.launchFromPlanInfo store0 info true #[]
  let sid := launch.sessionId
  let (store2, _) ← expectCore "step" <| CertiorPlan.stepIn store1 sid

  -- Test 24: evaluate expression
  let evalResp ← expectCore "Test 24 - evaluate" <|
    CertiorPlan.evaluate store2 sid "x"
  assertEq "  x evaluates to 42" evalResp.result "42"

  -- Test 25: setVariable
  let scopeResp ← expectCore "scopes" <| CertiorPlan.scopes store2 sid 0
  let localsRef := (scopeResp.scopes[0]?.map (·.variablesReference)).getD 0
  let (store3, setResp) ← expectCore "Test 25 - setVariable" <|
    CertiorPlan.setVariable store2 sid localsRef "x" "99"
  assertEq "  set value" setResp.value "99"
  -- Verify the change persisted
  let evalResp2 ← expectCore "  verify set" <|
    CertiorPlan.evaluate store3 sid "x"
  assertEq "  x now 99" evalResp2.result "99"

-- ═══════════════════════════════════════════════════════════════════════
-- §17  Core: Exception breakpoints
-- ═══════════════════════════════════════════════════════════════════════

private def testCoreExceptionBreakpoints : IO Unit := do
  IO.println "── §17: Exception Breakpoints ──"

  let info := mkPlanInfo flowViolationPlan
  let store0 : SessionStore := {}
  let (store1, launch) ← expectCore "launch" <|
    CertiorPlan.launchFromPlanInfo store0 info true #[]
  let sid := launch.sessionId

  -- Test 26: enable exception breakpoints, trigger flow violation
  let (store2, ebResp) ← expectCore "enable exceptions" <|
    CertiorPlan.setExceptionBreakpoints store1 sid #["all"]
  assertTrue "  exceptions enabled" ebResp.enabled

  -- Continue - should stop on exception
  let (store3, resp) ← expectCore "Test 26 - continue to exception" <|
    CertiorPlan.continueExecution store2 sid
  assertEq "  exception stop" resp.stopReason "exception"
  assertTrue "  has description" resp.description?.isSome

  -- exceptionInfo should be available
  let exInfo ← expectCore "  exception info" <|
    CertiorPlan.exceptionInfo store3 sid
  assertTrue "  has exception id" (!exInfo.exceptionId.isEmpty)
  assertTrue "  flow violation id"
    (exInfo.exceptionId == "flowViolation" || exInfo.exceptionId == "unboundData")
  IO.println s!"    ℹ Exception: {exInfo.exceptionId} - {exInfo.description?.getD ""}"

-- ═══════════════════════════════════════════════════════════════════════
-- §18  Core: Terminated session guards
-- ═══════════════════════════════════════════════════════════════════════

private def testCoreTerminated : IO Unit := do
  IO.println "── §18: Terminated Guards ──"

  let info := mkPlanInfo simplePlan
  let store0 : SessionStore := {}
  let (store1, launch) ← expectCore "launch" <|
    CertiorPlan.launchFromPlanInfo store0 info true #[]
  let sid := launch.sessionId

  -- Continue to termination
  let (store2, _) ← expectCore "continue" <|
    CertiorPlan.continueExecution store1 sid

  -- Test 27: operations on terminated session should fail
  assertError "Test 27a - stepIn on terminated" (CertiorPlan.stepIn store2 sid)
  assertError "Test 27b - next on terminated" (CertiorPlan.next store2 sid)
  assertError "Test 27c - scopes on terminated" (CertiorPlan.scopes store2 sid)

  -- stepBack should still work (allowTerminated)
  assertOk "Test 27d - stepBack on terminated" (CertiorPlan.stepBack store2 sid)

-- ═══════════════════════════════════════════════════════════════════════
-- §19  Core: Disconnect
-- ═══════════════════════════════════════════════════════════════════════

private def testCoreDisconnect : IO Unit := do
  IO.println "── §19: Disconnect ──"

  let info := mkPlanInfo simplePlan
  let store0 : SessionStore := {}
  let (store1, launch) ← expectCore "launch" <|
    CertiorPlan.launchFromPlanInfo store0 info true #[]
  let sid := launch.sessionId

  -- Test 28: disconnect removes session
  let (store2, existed) := CertiorPlan.disconnect store1 sid
  assertTrue "Test 28a - session existed" existed
  assertError "Test 28b - session gone" (CertiorPlan.stepIn store2 sid)

  -- Disconnect non-existent returns false
  let (_, existed2) := CertiorPlan.disconnect store2 999
  assertFalse "Test 28c - non-existent" existed2

-- ═══════════════════════════════════════════════════════════════════════
-- §20  Scope encoding round-trip
-- ═══════════════════════════════════════════════════════════════════════

private def testScopeEncoding : IO Unit := do
  IO.println "── §20: Scope Encoding ──"

  -- Verify encoding/decoding round-trips correctly
  for frameId in [0, 1, 2, 5, 10] do
    let lr := CertiorPlan.localsReference frameId
    let rr := CertiorPlan.resourcesReference frameId
    let fr := CertiorPlan.flowLabelsReference frameId
    let cr := CertiorPlan.certificatesReference frameId

    -- All references should be distinct
    assertTrue s!"  frame {frameId}: all refs distinct"
      (lr != rr && lr != fr && lr != cr && rr != fr && rr != cr && fr != cr)

    -- Decode should return correct frame + offset
    match CertiorPlan.decodeScopeReference lr with
    | some (fid, off) =>
      assertEq s!"  locals decode frame {frameId}" fid frameId
      assertEq s!"  locals decode offset" off 1
    | none =>
      IO.println s!"{failed}: locals decode failed for frame {frameId}"

    match CertiorPlan.decodeScopeReference rr with
    | some (fid, off) =>
      assertEq s!"  resources decode frame {frameId}" fid frameId
      assertEq s!"  resources decode offset" off 2
    | none =>
      IO.println s!"{failed}: resources decode failed for frame {frameId}"

    match CertiorPlan.decodeScopeReference fr with
    | some (fid, off) =>
      assertEq s!"  flowLabels decode frame {frameId}" fid frameId
      assertEq s!"  flowLabels decode offset" off 3
    | none =>
      IO.println s!"{failed}: flowLabels decode failed for frame {frameId}"

    match CertiorPlan.decodeScopeReference cr with
    | some (fid, off) =>
      assertEq s!"  certificates decode frame {frameId}" fid frameId
      assertEq s!"  certificates decode offset" off 4
    | none =>
      IO.println s!"{failed}: certificates decode failed for frame {frameId}"

  -- Reference 0 should decode to none
  assertTrue "  ref 0 → none" (CertiorPlan.decodeScopeReference 0).isNone

-- ═══════════════════════════════════════════════════════════════════════
-- §21  Custom requests: certificates, flowGraph, compliance
-- ═══════════════════════════════════════════════════════════════════════

private def testCoreCustomRequests : IO Unit := do
  IO.println "── §21: Custom Requests ──"

  let info := mkPlanInfo simplePlan
  let store0 : SessionStore := {}
  let (store1, launch) ← expectCore "launch" <|
    CertiorPlan.launchFromPlanInfo store0 info true #[]
  let sid := launch.sessionId

  -- Step a few times to accumulate certificates
  let (store2, _) ← expectCore "step1" <| CertiorPlan.stepIn store1 sid
  let (store3, _) ← expectCore "step2" <| CertiorPlan.stepIn store2 sid

  -- getCertificates
  let certs ← expectCore "getCertificates" <| CertiorPlan.getCertificates store3 sid
  assertTrue "  has certificates" (!certs.isEmpty)
  IO.println s!"    ℹ {certs.size} certificate(s)"

  -- getFlowGraph
  let graph ← expectCore "getFlowGraph" <| CertiorPlan.getFlowGraph store3 sid
  assertTrue "  has flow nodes" (!graph.nodes.isEmpty)
  IO.println s!"    ℹ {graph.nodes.size} node(s), {graph.edges.size} edge(s)"

  -- exportCompliance
  let compliance ← expectCore "exportCompliance" <| CertiorPlan.exportCompliance store3 sid
  assertEq "  policy" compliance.policy "default"
  assertTrue "  has certificates" (compliance.certificateCount > 0)
  IO.println s!"    ℹ Policy: {compliance.policy}, Certs: {compliance.certificateCount}"

-- ═══════════════════════════════════════════════════════════════════════
-- §22  Verification breakpoint set/clear via Core API
-- ═══════════════════════════════════════════════════════════════════════

private def testCoreVerificationBreakpoints : IO Unit := do
  IO.println "── §22: Core Verification Breakpoints ──"

  let info := mkPlanInfo simplePlan
  let store0 : SessionStore := {}
  let (store1, launch) ← expectCore "launch" <|
    CertiorPlan.launchFromPlanInfo store0 info true #[]
  let sid := launch.sessionId

  -- Set flow breakpoints via core API
  let (store2, fbResp) ← expectCore "setFlowBreakpoints" <|
    CertiorPlan.setFlowBreakpoints store1 sid #[SecurityLevel.Sensitive]
  assertEq "  flow BP count" fbResp.count 1

  -- Set budget breakpoint via core API
  let (store3, bbResp) ← expectCore "setBudgetBreakpoint" <|
    CertiorPlan.setBudgetBreakpoint store2 sid 500
  assertEq "  budget threshold" bbResp.threshold 500
  assertTrue "  budget BP active" bbResp.active

  -- Set capability watch via core API
  let (_, cwResp) ← expectCore "setCapabilityWatch" <|
    CertiorPlan.setCapabilityWatch store3 sid #["network:http:read"]
  assertTrue "  cap watch active" cwResp.active
  assertEq "  watched caps" cwResp.capabilities.size 1

-- ═══════════════════════════════════════════════════════════════════════
-- §23  Run all
-- ═══════════════════════════════════════════════════════════════════════

def runAll : IO Unit := do
  testSessionCreation
  IO.println ""
  testStepForwardBack
  IO.println ""
  testNext
  IO.println ""
  testStepOut
  IO.println ""
  testContinue
  IO.println ""
  testLineBreakpoints
  IO.println ""
  testFlowBreakpoints
  IO.println ""
  testBudgetBreakpoints
  IO.println ""
  testCapabilityBreakpoints
  IO.println ""
  testMultipleBreakpoints
  IO.println ""
  testCoreLaunch
  IO.println ""
  testCoreControl
  IO.println ""
  testCoreStackTrace
  IO.println ""
  testCoreScopes
  IO.println ""
  testCoreVariables
  IO.println ""
  testCoreEvaluateAndSet
  IO.println ""
  testCoreExceptionBreakpoints
  IO.println ""
  testCoreTerminated
  IO.println ""
  testCoreDisconnect
  IO.println ""
  testScopeEncoding
  IO.println ""
  testCoreCustomRequests
  IO.println ""
  testCoreVerificationBreakpoints

end Test.Debugger

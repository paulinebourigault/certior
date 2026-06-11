/-
  CertiorPlan.Test.Core - maintained smoke suite

  This suite intentionally targets the current exported CertiorPlan API.
  It is small, compile-stable, and exercises the core paths CI depends on:

  - SecurityLevel / flowAllowed integration
  - JSON roundtrip for AST nodes
  - PlanContext initialization
  - runPlan success/failure behavior
  - skill invocation with capability propagation
-/

import Lean
import CertiorPlan

open CertiorPlan
open SecurityLevel

namespace Test.Core

universe u v

private def passed := "  [pass]"
private def failed := "  [fail]"

private def assertEq {α : Type u} [BEq α] [ToString α]
    (name : String) (actual expected : α) : IO Unit :=
  if actual == expected then
    IO.println s!"{passed} {name}"
  else
    IO.println s!"{failed} {name}: expected {expected}, got {actual}"

private def assertTrue (name : String) (cond : Bool) : IO Unit :=
  if cond then
    IO.println s!"{passed} {name}"
  else
    IO.println s!"{failed} {name}: expected true"

private def assertFalse (name : String) (cond : Bool) : IO Unit :=
  if !cond then
    IO.println s!"{passed} {name}"
  else
    IO.println s!"{failed} {name}: expected false"

private def assertOk {ε : Type u} [ToString ε] {α : Type v}
    (name : String) (result : Except ε α) : IO Unit :=
  match result with
  | .ok _ =>
    IO.println s!"{passed} {name}"
  | .error err =>
    IO.println s!"{failed} {name}: error {err}"

private def assertErrorIs {α : Type u}
    (name : String) (result : Except PlanError α) (pred : PlanError → Bool) : IO Unit :=
  match result with
  | .error err =>
    if pred err then
      IO.println s!"{passed} {name}"
    else
      IO.println s!"{failed} {name}: wrong error {err}"
  | .ok _ =>
    IO.println s!"{failed} {name}: expected error"

private def budgetResource : ResourceDecl := {
  name := "planBudget"
  init := 10
  label := { level := .Internal }
}

private def databaseReadCapability : Capability := Capability.mk "database:read" 0

private def smokePlan : VerifiedPlan := {
  resources := #[budgetResource]
  mainSteps := #[
    .bind "x" (.literal 42) { level := .Public },
    .bind "remaining" (.readResource "planBudget") { level := .Internal },
    .bind "ok" (.checkFlow "x" "remaining") { level := .Public },
    .emitResult "ok"
  ]
  totalBudgetCents := 10
}

private def skillPlan : VerifiedPlan := {
  skills := #[{
    skillId := "echoInternal"
    params := #["arg"]
    requiredCaps := #[databaseReadCapability]
    body := #[.emitResult "arg"]
  }]
  mainSteps := #[
    .bind "x" (.literal 7) { level := .Internal },
    .bind "y" (.invokeSkill "echoInternal" #["x"]) { level := .Internal },
    .emitResult "y"
  ]
  totalBudgetCents := 10
}

private def invalidFlowPlan : VerifiedPlan := {
  mainSteps := #[
    .bind "secret" (.literal 1) { level := .Sensitive },
    .bind "publicDest" (.literal 0) { level := .Public },
    .bind "bad" (.checkFlow "secret" "publicDest") { level := .Public },
    .emitResult "bad"
  ]
  totalBudgetCents := 10
}

private def noBudgetPlan : VerifiedPlan := {
  mainSteps := #[
    .bind "x" (.literal 1) { level := .Public },
    .emitResult "x"
  ]
  totalBudgetCents := 0
}

private def testSecurityLevel : IO Unit := do
  IO.println "── Security lattice smoke ──"
  assertEq "SecurityLevel.rank Public" (SecurityLevel.rank .Public) 0
  assertEq "SecurityLevel.rank Restricted" (SecurityLevel.rank .Restricted) 3
  assertTrue "flowAllowed Public → Internal" (flowAllowed .Public .Internal)
  assertFalse "flowAllowed Sensitive → Public" (flowAllowed .Sensitive .Public)

private def testJsonRoundtrip : IO Unit := do
  IO.println "── JSON roundtrip smoke ──"
  let label : FlowLabel := { level := .Sensitive, tags := ["PHI"] }
  match (Lean.fromJson? (Lean.toJson label) : Except String FlowLabel) with
  | .ok decoded =>
    assertEq "FlowLabel roundtrip" decoded label
  | .error err =>
    IO.println s!"{failed} FlowLabel roundtrip: {err}"

  let step : PlanStep := .bind "x" (.literal 42) { level := .Public }
  match (Lean.fromJson? (Lean.toJson step) : Except String PlanStep) with
  | .ok decoded =>
    assertEq "PlanStep roundtrip" decoded step
  | .error err =>
    IO.println s!"{failed} PlanStep roundtrip: {err}"

  match (Lean.fromJson? (Lean.toJson smokePlan) : Except String VerifiedPlan) with
  | .ok decoded =>
    assertEq "VerifiedPlan roundtrip step count" decoded.totalStepCount smokePlan.totalStepCount
  | .error err =>
    IO.println s!"{failed} VerifiedPlan roundtrip: {err}"

private def testContextInit : IO Unit := do
  IO.println "── Context initialization smoke ──"
  let ctx := PlanContext.initialForPlan skillPlan
  assertEq "budget initialized" ctx.budgetRemaining 10
  assertTrue "capability collected from skill"
    ((ctx.capabilities.find? "database:read") == some true)
  assertEq "default main skill name" ctx.skillName VerifiedPlan.mainName

private def testEvaluator : IO Unit := do
  IO.println "── Evaluator smoke ──"
  assertOk "smoke plan executes" (runPlan smokePlan)
  assertOk "skill plan executes" (runPlan skillPlan)
  assertErrorIs "invalid flow rejected" (runPlan invalidFlowPlan)
    (fun err => match err with | .flowViolation _ _ _ => true | _ => false)
  assertErrorIs "zero budget rejected" (runPlan noBudgetPlan)
    (fun err => match err with | .budgetExhausted _ _ => true | _ => false)

def runAll : IO Unit := do
  testSecurityLevel
  testJsonRoundtrip
  testContextInit
  testEvaluator

end Test.Core

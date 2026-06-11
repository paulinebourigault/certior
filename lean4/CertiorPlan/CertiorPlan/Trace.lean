/-
  CertiorPlan.Trace - Execution Trace and Time-Travel Explorer

  Adapted from ImpLab's `Lang/Trace.lean`.

  Records every execution state during plan evaluation, enabling:
  - Time-travel debugging (rewind to any step)
  - Compliance audit replay (inspect flow labels at any point)
  - Certificate chain inspection (see proof accumulation over time)

  The compliance officer can rewind an agent's execution to any point
  and inspect what capabilities were held, what data labels existed,
  what budget remained, and what certificates had been issued.

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import CertiorPlan.Eval
import CertiorPlan.History

namespace CertiorPlan

-- ═══════════════════════════════════════════════════════════════════════
-- §1  ExecutionTrace - full history of all states
-- ═══════════════════════════════════════════════════════════════════════

/-- Complete execution trace: the plan plus every intermediate state.
    Analogous to ImpLab's `ExecutionTrace`. -/
structure ExecutionTrace where
  /-- The plan that was executed. -/
  plan : VerifiedPlan
  /-- Every state visited during execution (initial state first). -/
  states : Array PlanContext
  /-- Terminal error, if execution failed. -/
  terminalError? : Option PlanError := none
  deriving Repr

namespace ExecutionTrace

/-- Initial state (if any). -/
def initial? (trace : ExecutionTrace) : Option PlanContext :=
  trace.states[0]?

/-- Final state (if any). -/
def final? (trace : ExecutionTrace) : Option PlanContext :=
  trace.states[trace.states.size - 1]?

/-- State at a specific index. -/
def state? (trace : ExecutionTrace) (idx : Nat) : Option PlanContext :=
  trace.states[idx]?

/-- Number of recorded states. -/
def length (trace : ExecutionTrace) : Nat :=
  trace.states.size

/-- Did execution complete successfully? -/
def succeeded (trace : ExecutionTrace) : Bool :=
  trace.terminalError?.isNone

/-- Total certificates issued during execution. -/
def totalCertificates (trace : ExecutionTrace) : Nat :=
  match trace.final? with
  | some ctx => ctx.certificates.size
  | none => 0

/--
  Build an execution trace by running the plan step-by-step,
  recording every intermediate context.

  Unlike ImpLab's `build` which stops on error, we record
  states up to the error point AND capture the error.
  This enables post-mortem analysis of failed executions.
-/
def build (plan : VerifiedPlan)
    (start : PlanContext := PlanContext.initialForPlan plan) :
    ExecutionTrace :=
  let fuel := plan.defaultFuel
  let rec go : Nat → PlanContext → Array PlanContext → ExecutionTrace
    | 0, _, acc =>
      { plan, states := acc, terminalError? := some (.outOfFuel fuel) }
    | fuel' + 1, ctx, acc =>
      match step plan ctx with
      | .error err =>
        { plan, states := acc, terminalError? := some err }
      | .ok none =>
        { plan, states := acc, terminalError? := none }
      | .ok (some next) =>
        go fuel' next (acc.push next)
  go fuel start #[start]

end ExecutionTrace

-- ═══════════════════════════════════════════════════════════════════════
-- §2  Explorer - time-travel cursor over execution trace
-- ═══════════════════════════════════════════════════════════════════════

/-- Time-travel explorer: navigate forward/backward through execution states.
    Analogous to ImpLab's `Explorer`.

    This is the data structure backing the debugger's step/back/continue
    operations and the compliance officer's audit replay. -/
structure Explorer where
  /-- The full execution trace. -/
  trace : ExecutionTrace
  /-- Current cursor position in the trace. -/
  cursor : Nat := 0
  deriving Repr

namespace Explorer

/-- Create an explorer from a pre-built trace. -/
def ofTrace (trace : ExecutionTrace) : Explorer :=
  { trace, cursor := 0 }

/-- Build trace and create explorer in one step. -/
def ofPlan (plan : VerifiedPlan) : Explorer :=
  let trace := ExecutionTrace.build plan
  ofTrace trace

/-- Maximum cursor position. -/
def maxCursor (explorer : Explorer) : Nat :=
  History.maxCursor explorer.trace.states

/-- Normalize cursor to valid range. -/
def normalized (explorer : Explorer) : Explorer :=
  { explorer with cursor := History.normalizeCursor explorer.trace.states explorer.cursor }

/-- Get current execution state. -/
def current? (explorer : Explorer) : Option PlanContext :=
  History.current? explorer.trace.states explorer.cursor

/-- Can we step backward? -/
def hasPrev (explorer : Explorer) : Bool :=
  History.hasPrev explorer.trace.states explorer.cursor

/-- Can we step forward? -/
def hasNext (explorer : Explorer) : Bool :=
  History.hasNext explorer.trace.states explorer.cursor

/-- Step one state backward. -/
def back (explorer : Explorer) : Explorer :=
  { explorer with cursor := History.backCursor explorer.trace.states explorer.cursor }

/-- Step one state forward. -/
def forward (explorer : Explorer) : Explorer :=
  { explorer with cursor := History.forwardCursor explorer.trace.states explorer.cursor }

/-- Jump to a specific state index. -/
def jump (explorer : Explorer) (cursor : Nat) : Explorer :=
  { explorer with cursor := History.jumpCursor explorer.trace.states cursor }

/-- Jump to the first state. -/
def jumpToStart (explorer : Explorer) : Explorer :=
  jump explorer 0

/-- Jump to the last state. -/
def jumpToEnd (explorer : Explorer) : Explorer :=
  jump explorer explorer.maxCursor

-- ── Explorer queries (for debugging UI / compliance audit) ───────────

/-- Current skill name. -/
def currentSkill? (explorer : Explorer) : Option SkillId :=
  (explorer.current?).map (·.skillName)

/-- Current program counter. -/
def currentPc? (explorer : Explorer) : Option Nat :=
  (explorer.current?).map (·.pc)

/-- Current flow labels. -/
def currentFlowLabels? (explorer : Explorer) : Option (Array (DataId × FlowLabel)) :=
  (explorer.current?).map (·.flowBindings)

/-- Current certificates. -/
def currentCertificates? (explorer : Explorer) : Option (Array ProofCert) :=
  (explorer.current?).map (·.certificates)

/-- Current budget remaining. -/
def currentBudget? (explorer : Explorer) : Option Int :=
  (explorer.current?).map (·.budgetRemaining)

/-- Current call depth. -/
def currentCallDepth? (explorer : Explorer) : Option Nat :=
  (explorer.current?).map (·.callDepth)

/-- Did execution end in error? -/
def isAtError (explorer : Explorer) : Bool :=
  explorer.cursor >= explorer.maxCursor &&
  explorer.trace.terminalError?.isSome

/-- Get terminal error (if cursor is at end and execution failed). -/
def terminalError? (explorer : Explorer) : Option PlanError :=
  if explorer.isAtError then
    explorer.trace.terminalError?
  else
    none

end Explorer

-- ═══════════════════════════════════════════════════════════════════════
-- §3  Pretty-printing for trace inspection
-- ═══════════════════════════════════════════════════════════════════════

def prettyExplorerState (explorer : Explorer) : String :=
  match explorer.current? with
  | none => "(no state)"
  | some ctx =>
    let errorStr := match explorer.terminalError? with
      | some err => s!"\n  ✗ Error at this state: {err}"
      | none => ""
    String.intercalate "\n"
      [ s!"═══ State {explorer.cursor}/{explorer.maxCursor} ═══"
      , s!"  Skill: {ctx.skillName} @ pc {ctx.pc}"
      , s!"  Locals: {renderBindings ctx.localBindings}"
      , s!"  Resources: {renderBindings ctx.resourceBindings}"
      , s!"  Flow Labels: {renderFlowBindings ctx.flowBindings}"
      , s!"  Budget: {ctx.budgetRemaining}¢"
      , s!"  Certificates: {ctx.certificates.size}"
      , s!"  Steps: {ctx.stepsExecuted}"
      , s!"  Can back: {explorer.hasPrev} | Can forward: {explorer.hasNext}"
      , errorStr ]

end CertiorPlan

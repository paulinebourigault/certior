/-
  CertiorPlan.Debugger.Session - Plan Debug Session

  Mirrors ImpLab's `Debugger/Session.lean` with extensions for
  verification-specific breakpoints (flow, budget, capability).

  ## Week B1: Mon (session + advanceOne) + Tue (stepping strategies)

  Key adaptations from ImpLab:
    DebugSession     →  PlanDebugSession
    CallFrame        →  PlanFrame (from Eval.lean)
    Context          →  PlanContext (from Eval.lean)
    EvalError        →  PlanError (from Eval.lean)
    StmtLocation     →  StepLocation (from Ast.lean)

  New verification-specific breakpoint types:
    FlowBreakpoint   - Triggers when data at/above a security level is accessed
    BudgetBreakpoint - Triggers when budget drops below a threshold
    CapabilityWatch  - Triggers when a specific capability is invoked

  Copyright (c) 2026 Certior. All rights reserved.
-/

import CertiorPlan.Eval
import CertiorPlan.History

namespace CertiorPlan

-- ═══════════════════════════════════════════════════════════════════════
-- §1  StopReason - why the debugger paused
-- ═══════════════════════════════════════════════════════════════════════

/-- Why the debugger stopped. Extends ImpLab's StopReason with
    verification-specific reasons. -/
inductive StopReason where
  | entry              -- stopped on entry (stopOnEntry=true)
  | step               -- completed a step command
  | breakpoint         -- hit a line-based breakpoint
  | flowBreakpoint     -- hit a flow-level breakpoint
  | budgetBreakpoint   -- budget dropped below threshold
  | capabilityBreakpoint -- watched capability was invoked
  | exception          -- plan error caught (exception breakpoints enabled)
  | pause              -- fuel exhausted during multi-step operation
  | terminated         -- plan execution completed
  deriving Repr, BEq, DecidableEq, Inhabited

instance : ToString StopReason where
  toString
    | .entry => "entry"
    | .step => "step"
    | .breakpoint => "breakpoint"
    | .flowBreakpoint => "flowBreakpoint"
    | .budgetBreakpoint => "budgetBreakpoint"
    | .capabilityBreakpoint => "capabilityBreakpoint"
    | .exception => "exception"
    | .pause => "pause"
    | .terminated => "terminated"

-- ═══════════════════════════════════════════════════════════════════════
-- §2  Verification breakpoint types
-- ═══════════════════════════════════════════════════════════════════════

/-- Flow breakpoint: stop when data with a label at or above the given
    security level is accessed or produced. -/
structure FlowBreakpoint where
  /-- Security level threshold. -/
  level : SecurityLevel
  /-- Optional: restrict to specific data IDs. Empty means all. -/
  dataIds : Array DataId := #[]
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Budget breakpoint: stop when budget drops below this threshold. -/
structure BudgetBreakpoint where
  threshold : Int
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Capability watch: stop when any of these capabilities is invoked. -/
structure CapabilityWatch where
  capabilities : Array String
  deriving Repr, BEq, DecidableEq, Inhabited

-- ═══════════════════════════════════════════════════════════════════════
-- §3  PlanDebugSession - core session state
-- ═══════════════════════════════════════════════════════════════════════

/-- Core debug session for verified agent plans.
    Mirrors ImpLab's `DebugSession` with verification extensions.

    The session maintains a history of `PlanContext` snapshots (one per
    step), a cursor for time-travel navigation, and multiple breakpoint
    types for both standard and verification-specific debugging. -/
structure PlanDebugSession where
  /-- The plan being debugged. -/
  plan : VerifiedPlan
  /-- Complete history of execution contexts (one per step). -/
  history : Array PlanContext := #[]
  /-- Current position in history (supports time-travel). -/
  cursor : Nat := 0
  /-- Line-based breakpoints (standard DAP). -/
  breakpoints : Array StepLocation := #[]
  /-- Flow-level breakpoints (verification-specific). -/
  flowBreakpoints : Array FlowBreakpoint := #[]
  /-- Budget threshold breakpoint (verification-specific). -/
  budgetBreakpoint? : Option BudgetBreakpoint := none
  /-- Capability watch list (verification-specific). -/
  capabilityWatch? : Option CapabilityWatch := none
  deriving Repr

namespace PlanDebugSession

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Session creation and navigation
-- ═══════════════════════════════════════════════════════════════════════

/-- Create a debug session from a verified plan. -/
def fromPlan (plan : VerifiedPlan) : Except PlanError PlanDebugSession := do
  if !plan.hasMain then
    throw (.unknownSkill VerifiedPlan.mainName)
  let initial := PlanContext.initialForPlan plan
  pure { plan, history := #[initial], cursor := 0 }

/-- Maximum valid cursor position. -/
def maxCursor (session : PlanDebugSession) : Nat :=
  History.maxCursor session.history

/-- Normalize cursor to valid range. -/
def normalize (session : PlanDebugSession) : PlanDebugSession :=
  { session with cursor := History.normalizeCursor session.history session.cursor }

/-- Current execution context (if any). -/
def current? (session : PlanDebugSession) : Option PlanContext :=
  History.current? session.history session.cursor

/-- Current program counter. -/
def currentPc (session : PlanDebugSession) : Nat :=
  (session.current?.map (·.pc)).getD 0

/-- Current skill name. -/
def currentSkillName (session : PlanDebugSession) : SkillId :=
  (session.current?.map (·.skillName)).getD VerifiedPlan.mainName

/-- Current line number (1-based, for DAP display). -/
def currentLine (session : PlanDebugSession) : Nat :=
  let bodySize := session.plan.bodySizeOf session.currentSkillName
  let fallback := max bodySize 1
  if bodySize = 0 then 1
  else
    match session.current? with
    | none => fallback
    | some ctx =>
      if ctx.pc < bodySize then ctx.pc + 1
      else bodySize

/-- Compute display line for a specific frame. -/
def frameLine (session : PlanDebugSession) (frame : PlanFrame) : Nat :=
  let bodySize := session.plan.bodySizeOf frame.skillId
  if bodySize = 0 then 1
  else if frame.pc < bodySize then frame.pc + 1
  else bodySize

/-- Current step location. -/
def currentLocation? (session : PlanDebugSession) : Option StepLocation := do
  let ctx ← session.current?
  let line := session.frameLine ctx.current
  pure { skillId := ctx.skillName, stepLine := line }

/-- Step location for a specific frame. -/
def frameLocation (session : PlanDebugSession) (frame : PlanFrame) : StepLocation :=
  { skillId := frame.skillId, stepLine := session.frameLine frame }

/-- Current step being executed. -/
def currentStep? (session : PlanDebugSession) : Option PlanStep := do
  let ctx ← session.current?
  session.plan.stepAt? ctx.skillName ctx.pc

/-- Step at a specific frame. -/
def frameStep? (session : PlanDebugSession) (frame : PlanFrame) : Option PlanStep :=
  session.plan.stepAt? frame.skillId frame.pc

/-- All call frames in the current context. -/
def callFrames (session : PlanDebugSession) : Array PlanFrame :=
  (session.current?.map PlanContext.frames).getD #[]

/-- Whether execution has completed. -/
def atEnd (session : PlanDebugSession) : Bool :=
  match session.current? with
  | none => true
  | some ctx =>
    let bodySize := session.plan.bodySizeOf ctx.skillName
    ctx.callers.isEmpty && ctx.current.retDest?.isNone && ctx.pc ≥ bodySize

/-- Current call depth. -/
def currentCallDepth (session : PlanDebugSession) : Nat :=
  (session.current?.map PlanContext.callDepth).getD 0

-- ═══════════════════════════════════════════════════════════════════════
-- §5  Breakpoint management
-- ═══════════════════════════════════════════════════════════════════════

/-- Check if a step location is a valid breakpoint. -/
def isValidBreakpointLocation (plan : VerifiedPlan) (loc : StepLocation) : Bool :=
  match plan.bodyOf? loc.skillId with
  | some body => 0 < loc.stepLine && loc.stepLine ≤ body.size
  | none => false

/-- Normalize breakpoints: remove invalids and duplicates. -/
def normalizeBreakpoints (plan : VerifiedPlan) (locs : Array StepLocation) : Array StepLocation :=
  locs.foldl (init := #[]) fun acc loc =>
    if isValidBreakpointLocation plan loc && !acc.contains loc then
      acc.push loc
    else
      acc

/-- Set line-based breakpoints. -/
def setBreakpoints (session : PlanDebugSession) (locs : Array StepLocation) : PlanDebugSession :=
  { session with breakpoints := normalizeBreakpoints session.plan locs }

/-- Set flow-level breakpoints. -/
def setFlowBreakpoints (session : PlanDebugSession) (fbs : Array FlowBreakpoint) : PlanDebugSession :=
  { session with flowBreakpoints := fbs }

/-- Set budget threshold breakpoint. -/
def setBudgetBreakpoint (session : PlanDebugSession) (threshold : Int) : PlanDebugSession :=
  { session with budgetBreakpoint? := some { threshold } }

/-- Clear budget breakpoint. -/
def clearBudgetBreakpoint (session : PlanDebugSession) : PlanDebugSession :=
  { session with budgetBreakpoint? := none }

/-- Set capability watch list. -/
def setCapabilityWatch (session : PlanDebugSession) (caps : Array String) : PlanDebugSession :=
  { session with capabilityWatch? := some { capabilities := caps } }

/-- Clear capability watch. -/
def clearCapabilityWatch (session : PlanDebugSession) : PlanDebugSession :=
  { session with capabilityWatch? := none }

-- ═══════════════════════════════════════════════════════════════════════
-- §6  Breakpoint hit detection
-- ═══════════════════════════════════════════════════════════════════════

/-- Check if current location matches a line breakpoint. -/
def hitLineBreakpoint (session : PlanDebugSession) : Bool :=
  match session.currentLocation? with
  | some loc => session.breakpoints.contains loc
  | none => false

/-- Check if current state triggers a flow breakpoint.
    A flow breakpoint fires if the most recent certificate references a
    flow label whose level ≥ the breakpoint threshold. -/
def hitFlowBreakpoint (session : PlanDebugSession) : Bool :=
  if session.flowBreakpoints.isEmpty then false
  else
    match session.current? with
    | none => false
    | some ctx =>
      session.flowBreakpoints.any fun fb =>
        ctx.flowTracker.toArray.any fun (dataId, label) =>
          -- Check: data's level is at or above the threshold
          flowAllowed fb.level label.level &&
          -- Optionally filter by specific data IDs
          (fb.dataIds.isEmpty || fb.dataIds.any fun did => did == dataId)

/-- Check if budget has dropped below the threshold. -/
def hitBudgetBreakpoint (session : PlanDebugSession) : Bool :=
  match session.budgetBreakpoint?, session.current? with
  | some bp, some ctx => ctx.budgetRemaining < bp.threshold
  | _, _ => false

/-- Check if a watched capability was just invoked.
    We detect this by checking the most recent certificate for
    a `call_verified` property. -/
def hitCapabilityBreakpoint (session : PlanDebugSession) : Bool :=
  match session.capabilityWatch?, session.current? with
  | some cw, some ctx =>
    -- Check if any recent certificate mentions a watched capability
    ctx.certificates.any fun cert =>
      cert.property == "call_verified" &&
      cw.capabilities.any fun cap =>
        cap.isEmpty || (cert.detail.splitOn cap).length > 1
  | _, _ => false

/-- Check all breakpoint types. Returns the most specific stop reason, or none. -/
def checkBreakpoints (session : PlanDebugSession) : Option StopReason :=
  if session.hitLineBreakpoint then some .breakpoint
  else if session.hitFlowBreakpoint then some .flowBreakpoint
  else if session.hitBudgetBreakpoint then some .budgetBreakpoint
  else if session.hitCapabilityBreakpoint then some .capabilityBreakpoint
  else none

-- ═══════════════════════════════════════════════════════════════════════
-- §7  Accessor helpers
-- ═══════════════════════════════════════════════════════════════════════

/-- Local data bindings in the current context. -/
def bindings (session : PlanDebugSession) : Array (DataId × Value) :=
  (session.current?.map PlanContext.localBindings).getD #[]

/-- Resource bindings in the current context. -/
def resourceBindings (session : PlanDebugSession) : Array (ResourceId × Value) :=
  (session.current?.map PlanContext.resourceBindings).getD #[]

/-- Flow label bindings in the current context. -/
def flowBindings (session : PlanDebugSession) : Array (DataId × FlowLabel) :=
  (session.current?.map PlanContext.flowBindings).getD #[]

/-- Proof certificates issued so far. -/
def certificates (session : PlanDebugSession) : Array ProofCert :=
  (session.current?.map (·.certificates)).getD #[]

/-- Remaining budget. -/
def budgetRemaining (session : PlanDebugSession) : Int :=
  (session.current?.map (·.budgetRemaining)).getD 0

-- ═══════════════════════════════════════════════════════════════════════
-- §8  advanceOne - single-step execution
-- ═══════════════════════════════════════════════════════════════════════

/-- Execute a single step forward in the plan.

    This is the core stepping primitive. All other control operations
    (stepIn, next, stepOut, continue) are built on top of this.

    Two modes:
    1. If the cursor is behind the history frontier → replay (no execution)
    2. If at the frontier → execute one step via `step` from Eval.lean

    Adapted from ImpLab's `advanceOne`. -/
private def advanceOne (session : PlanDebugSession) :
    Except PlanError (PlanDebugSession × StopReason) := do
  let session := session.normalize
  -- Mode 1: Replay from history
  if History.hasNext session.history session.cursor then
    let next := { session with
      cursor := History.forwardCursor session.history session.cursor }
    if next.atEnd then pure (next, .terminated)
    else pure (next, .step)
  -- Mode 2: Execute one new step
  else
    let ctx ← match session.current? with
      | some ctx => pure ctx
      | none => throw (.invalidPc session.cursor session.history.size)
    if session.atEnd then
      pure (session, .terminated)
    else
      match ← step session.plan ctx with
      | none =>
        pure (session, .terminated)
      | some nextCtx =>
        let history := session.history.push nextCtx
        let nextSession := { session with
          history
          cursor := History.forwardCursor history session.cursor }
        if nextSession.atEnd then pure (nextSession, .terminated)
        else pure (nextSession, .step)

-- ═══════════════════════════════════════════════════════════════════════
-- §9  Control operations - the full stepping API
-- ═══════════════════════════════════════════════════════════════════════

/-- Control failure: carries the session state at the point of failure
    plus the error. Used for exception breakpoints. -/
abbrev ControlFailure := PlanDebugSession × PlanError

/-- Step into: advance one step, preserving session on error. -/
def stepInWithState (session : PlanDebugSession) :
    Except ControlFailure (PlanDebugSession × StopReason) :=
  match advanceOne session with
  | .ok value => .ok value
  | .error err => .error (session.normalize, err)

/-- Next: step over skill invocations (stay in current frame depth).
    Adapted from ImpLab's `nextWithState`. -/
def nextWithState (session : PlanDebugSession) :
    Except ControlFailure (PlanDebugSession × StopReason) := do
  let session := session.normalize
  if session.atEnd then pure (session, .terminated)
  else
    let startDepth := session.currentCallDepth
    let (session, reason) ← session.stepInWithState
    match reason with
    | .terminated => pure (session, .terminated)
    | _ =>
      -- If we're at the same or lower depth, we've stepped over
      if session.currentCallDepth ≤ startDepth then
        pure (session, .step)
      else
        -- We entered a callee - keep running until we return or hit breakpoint
        match session.checkBreakpoints with
        | some stopReason => pure (session, stopReason)
        | none =>
          let fuel := session.plan.defaultFuel
          let rec go : Nat → PlanDebugSession →
              Except ControlFailure (PlanDebugSession × StopReason)
            | 0, s => pure (s, .pause)
            | fuel' + 1, s => do
              let (s, reason) ← s.stepInWithState
              match reason with
              | .terminated => pure (s, .terminated)
              | _ =>
                if s.currentCallDepth ≤ startDepth then
                  match s.checkBreakpoints with
                  | some stopReason => pure (s, stopReason)
                  | none => pure (s, .step)
                else
                  match s.checkBreakpoints with
                  | some stopReason => pure (s, stopReason)
                  | none => go fuel' s
          go fuel session

/-- Step back: rewind one step in history. Always succeeds. -/
def stepBack (session : PlanDebugSession) : PlanDebugSession × StopReason :=
  let session := session.normalize
  if !History.hasPrev session.history session.cursor then
    (session, .pause)
  else
    ({ session with
      cursor := History.backCursor session.history session.cursor }, .step)

/-- Continue execution: run until breakpoint or termination.
    Adapted from ImpLab's `continueExecutionWithState`. -/
def continueExecutionWithState (session : PlanDebugSession) :
    Except ControlFailure (PlanDebugSession × StopReason) := do
  let session := session.normalize
  if session.atEnd then pure (session, .terminated)
  else
    let fuel := session.plan.defaultFuel
    let rec go : Nat → PlanDebugSession →
        Except ControlFailure (PlanDebugSession × StopReason)
      | 0, s => pure (s, .pause)
      | fuel' + 1, s => do
        let (s, reason) ← s.stepInWithState
        match reason with
        | .terminated => pure (s, .terminated)
        | _ =>
          match s.checkBreakpoints with
          | some stopReason => pure (s, stopReason)
          | none => go fuel' s
    go fuel session

/-- Step out: run until the call depth decreases.
    Adapted from ImpLab's `stepOutWithState`. -/
def stepOutWithState (session : PlanDebugSession) :
    Except ControlFailure (PlanDebugSession × StopReason) := do
  let session := session.normalize
  if session.atEnd then pure (session, .terminated)
  else
    let startDepth := session.currentCallDepth
    if startDepth ≤ 1 then
      -- Already at top level, continue to end
      session.continueExecutionWithState
    else
      let fuel := session.plan.defaultFuel
      let rec go : Nat → PlanDebugSession →
          Except ControlFailure (PlanDebugSession × StopReason)
        | 0, s => pure (s, .pause)
        | fuel' + 1, s => do
          let (s, reason) ← s.stepInWithState
          match reason with
          | .terminated => pure (s, .terminated)
          | _ =>
            if s.currentCallDepth < startDepth then
              pure (s, .step)
            else
              match s.checkBreakpoints with
              | some stopReason => pure (s, stopReason)
              | none => go fuel' s
      go fuel session

-- ═══════════════════════════════════════════════════════════════════════
-- §10  Convenience wrappers (discard session on error)
-- ═══════════════════════════════════════════════════════════════════════

/-- Step in (discard session on error). -/
def stepIn (session : PlanDebugSession) :
    Except PlanError (PlanDebugSession × StopReason) :=
  match session.stepInWithState with
  | .ok value => .ok value
  | .error (_, err) => .error err

/-- Next (discard session on error). -/
def next (session : PlanDebugSession) :
    Except PlanError (PlanDebugSession × StopReason) :=
  match session.nextWithState with
  | .ok value => .ok value
  | .error (_, err) => .error err

/-- Continue execution (discard session on error). -/
def continueExecution (session : PlanDebugSession) :
    Except PlanError (PlanDebugSession × StopReason) :=
  match session.continueExecutionWithState with
  | .ok value => .ok value
  | .error (_, err) => .error err

/-- Step out (discard session on error). -/
def stepOut (session : PlanDebugSession) :
    Except PlanError (PlanDebugSession × StopReason) :=
  match session.stepOutWithState with
  | .ok value => .ok value
  | .error (_, err) => .error err

/-- Initial stop: optionally stop on entry, then check breakpoints,
    then continue. -/
def initialStop (session : PlanDebugSession) (stopOnEntry : Bool) :
    Except PlanError (PlanDebugSession × StopReason) := do
  let session := session.normalize
  if stopOnEntry then
    pure (session, .entry)
  else
    match session.checkBreakpoints with
    | some stopReason => pure (session, stopReason)
    | none => session.continueExecution

end PlanDebugSession

end CertiorPlan

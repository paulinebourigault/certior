/-
  CertiorPlan.Debugger.Core - Session Store & Core DAP API

  Mirrors ImpLab's `Debugger/Core.lean` with extensions:
    - 4 scopes per frame (locals, resources, flowLabels, certificates)
      vs ImpLab's 2 scopes (locals, heap)
    - FlowLabelView and CertificateView response types
    - Verification breakpoint management
    - Compliance export support

  ## Week B1: Wed (SessionStore, scopes, variables, launch API)

  Scope encoding (stateless, no per-session reference table):
    ImpLab uses:  frameId * 2 + offset (offset 1=locals, 2=heap)
    Certior uses: frameId * 4 + offset
      offset 1 = locals
      offset 2 = resources
      offset 3 = flow labels
      offset 4 = certificates

  Copyright (c) 2026 Certior. All rights reserved.
-/

import Lean
import CertiorPlan.Debugger.Session

open Lean

namespace CertiorPlan

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Session status and data
-- ═══════════════════════════════════════════════════════════════════════

/-- Session lifecycle status. -/
inductive SessionStatus where
  | stopped
  | terminated
  deriving Repr, BEq, DecidableEq, Inhabited

instance : ToString SessionStatus where
  toString
    | .stopped => "stopped"
    | .terminated => "terminated"

/-- Per-session data: wraps the session, plan info, and exception state. -/
structure SessionData where
  session : PlanDebugSession
  planInfo : PlanInfo
  status : SessionStatus := .stopped
  exceptionBreakpointsEnabled : Bool := false
  lastException? : Option PlanError := none
  deriving Repr

/-- Global session store: maps session IDs to session data. -/
structure SessionStore where
  nextId : Nat := 1
  sessions : Lean.RBMap Nat SessionData compare := Lean.RBMap.empty

instance : Inhabited SessionStore where
  default := { nextId := 1, sessions := Lean.RBMap.empty }

-- ═══════════════════════════════════════════════════════════════════════
-- §2  DAP response types
-- ═══════════════════════════════════════════════════════════════════════

structure LaunchResponse where
  sessionId : Nat
  threadId : Nat
  line : Nat
  stopReason : String
  terminated : Bool
  deriving Inhabited, Repr, FromJson, ToJson

structure BreakpointView where
  line : Nat
  verified : Bool
  message? : Option String := none
  deriving Inhabited, Repr, FromJson, ToJson

structure SetBreakpointsResponse where
  breakpoints : Array BreakpointView
  deriving Inhabited, Repr, FromJson, ToJson

structure ThreadView where
  id : Nat
  name : String
  deriving Inhabited, Repr, FromJson, ToJson

structure ThreadsResponse where
  threads : Array ThreadView
  deriving Inhabited, Repr, FromJson, ToJson

structure ControlResponse where
  line : Nat
  stopReason : String
  terminated : Bool
  description? : Option String := none
  deriving Inhabited, Repr, FromJson, ToJson

structure StackFrameView where
  id : Nat
  name : String
  line : Nat
  column : Nat
  deriving Inhabited, Repr, FromJson, ToJson

structure StackTraceResponse where
  stackFrames : Array StackFrameView
  totalFrames : Nat
  deriving Inhabited, Repr, FromJson, ToJson

structure ScopeView where
  name : String
  variablesReference : Nat
  expensive : Bool := false
  deriving Inhabited, Repr, FromJson, ToJson

structure ScopesResponse where
  scopes : Array ScopeView
  deriving Inhabited, Repr, FromJson, ToJson

structure VariableView where
  name : String
  value : String
  variablesReference : Nat := 0
  deriving Inhabited, Repr, FromJson, ToJson

structure VariablesResponse where
  variables : Array VariableView
  deriving Inhabited, Repr, FromJson, ToJson

structure EvaluateResponse where
  result : String
  variablesReference : Nat := 0
  deriving Inhabited, Repr, FromJson, ToJson

structure SetVariableResponse where
  value : String
  variablesReference : Nat := 0
  deriving Inhabited, Repr, FromJson, ToJson

structure SetExceptionBreakpointsResponse where
  enabled : Bool
  deriving Inhabited, Repr, FromJson, ToJson

structure ExceptionInfoResponse where
  exceptionId : String
  description? : Option String := none
  breakMode : String := "always"
  deriving Inhabited, Repr, FromJson, ToJson

-- ═══════════════════════════════════════════════════════════════════════
-- §3  Certior-specific view types (NEW - beyond ImpLab)
-- ═══════════════════════════════════════════════════════════════════════

/-- View model for a flow label binding (displayed in Flow Labels scope). -/
structure FlowLabelView where
  dataId : String
  level : String
  tags : Array String
  deriving Inhabited, Repr, FromJson, ToJson

/-- View model for a proof certificate (displayed in Certificates scope). -/
structure CertificateView where
  stepId : String
  property : String
  inputLabels : Array String
  outputLabel : String
  detail : String := ""
  deriving Inhabited, Repr, FromJson, ToJson

/-- Flow graph edge (for flowGraph custom request). -/
structure FlowEdgeView where
  source : String
  target : String
  label : String
  allowed : Bool
  deriving Inhabited, Repr, FromJson, ToJson

/-- Flow graph response (for custom flowGraph request). -/
structure FlowGraphResponse where
  edges : Array FlowEdgeView
  nodes : Array FlowLabelView
  deriving Inhabited, Repr, FromJson, ToJson

/-- Compliance export response. -/
structure ComplianceExportResponse where
  policy : String
  totalSteps : Nat
  certificateCount : Nat
  flowViolations : Nat
  budgetUsed : Int
  budgetTotal : Int
  certificates : Array CertificateView
  auditTrail : Array String
  deriving Inhabited, Repr, FromJson, ToJson

/-- Verification breakpoint set response. -/
structure SetFlowBreakpointsResponse where
  count : Nat
  deriving Inhabited, Repr, FromJson, ToJson

structure SetBudgetBreakpointResponse where
  threshold : Int
  active : Bool
  deriving Inhabited, Repr, FromJson, ToJson

structure SetCapabilityWatchResponse where
  capabilities : Array String
  active : Bool
  deriving Inhabited, Repr, FromJson, ToJson

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Internal helpers
-- ═══════════════════════════════════════════════════════════════════════

private def getSessionData (store : SessionStore) (sessionId : Nat) :
    Except String SessionData :=
  match store.sessions.find? sessionId with
  | some data => pure data
  | none => throw s!"Unknown DAP session id: {sessionId}"

private def putSessionData (store : SessionStore) (sessionId : Nat)
    (data : SessionData) : SessionStore :=
  { store with sessions := store.sessions.insert sessionId data }

private def statusFromStopReason (reason : StopReason) : SessionStatus :=
  if reason = .terminated then .terminated else .stopped

private def ensureControllable (data : SessionData) (sessionId : Nat) :
    Except String Unit := do
  if data.status = .terminated then
    throw s!"Session {sessionId} is terminated"

private def requestedLineToLocation? (info : PlanInfo) (line : Nat) :
    Option StepLocation :=
  let loc? := info.sourceLineToLocation? line
  loc?.bind fun loc =>
    if PlanDebugSession.isValidBreakpointLocation info.plan loc then
      some loc
    else
      none

private def normalizeRequestedBreakpoints (info : PlanInfo)
    (lines : Array Nat) : Array StepLocation :=
  lines.foldl (init := #[]) fun acc line =>
    match requestedLineToLocation? info line with
    | some loc =>
      if !acc.contains loc then acc.push loc
      else acc
    | none => acc

private def mkBreakpointView (info : PlanInfo) (line : Nat) : BreakpointView :=
  match info.sourceLineToLocation? line with
  | none =>
    { line, verified := false,
      message? := some s!"No step maps to source line {line}" }
  | some loc =>
    if PlanDebugSession.isValidBreakpointLocation info.plan loc then
      { line, verified := true }
    else
      { line, verified := false,
        message? := some s!"Source line {line} maps to invalid location {loc.skillId}:{loc.stepLine}" }

private def frameName (session : PlanDebugSession) (frame : PlanFrame) : String :=
  match session.frameStep? frame with
  | some step => s!"{frame.skillId}: {step}"
  | none => s!"{frame.skillId}: <terminated>"

private def stackFramesInDisplayOrder (session : PlanDebugSession) :
    Array PlanFrame :=
  session.callFrames.reverse

private def stackFrameAt? (session : PlanDebugSession) (frameId : Nat) :
    Option PlanFrame :=
  (stackFramesInDisplayOrder session)[frameId]?

private def frameSourceLine (info : PlanInfo) (session : PlanDebugSession)
    (frame : PlanFrame) : Nat :=
  info.locationToSourceLine (session.frameLocation frame)

private def requireStackFrame (session : PlanDebugSession) (frameId : Nat) :
    Except String PlanFrame := do
  match stackFrameAt? session frameId with
  | some frame => pure frame
  | none => throw s!"Unknown stack frame id: {frameId}"

private def mkControlResponse (data : SessionData) (reason : StopReason)
    (description? : Option String := none) : ControlResponse :=
  let session := data.session
  let line := match stackFrameAt? session 0 with
    | some frame => frameSourceLine data.planInfo session frame
    | none => 1
  { line
    stopReason := toString reason
    terminated := session.atEnd || reason = .terminated
    description? }

private def planErrorId (err : PlanError) : String :=
  match err with
  | .capabilityDenied .. => "capabilityDenied"
  | .flowViolation .. => "flowViolation"
  | .budgetExhausted .. => "budgetExhausted"
  | .approvalRequired .. => "approvalRequired"
  | .unboundData .. => "unboundData"
  | .unknownSkill .. => "unknownSkill"
  | .resourceUndeclared .. => "resourceUndeclared"
  | .outOfFuel .. => "outOfFuel"
  | .invalidPc .. => "invalidPc"
  | .missingEmit .. => "missingEmit"
  | .arityMismatch .. => "arityMismatch"

-- ═══════════════════════════════════════════════════════════════════════
-- §5  Expression evaluation (for evaluate + setVariable)
-- ═══════════════════════════════════════════════════════════════════════

/-- Tokenize a whitespace-separated expression. -/
private def tokenizeExpression (expression : String) : Array String :=
  ((expression.trim.splitOn " ").filter (· != "")).toArray

/-- Evaluate a single token as a value (integer literal or data binding). -/
private def evalToken (env : DataEnv) (token : String) : Except String Value :=
  match token.toInt? with
  | some value => pure value
  | none =>
    match env.find? token with
    | some value => pure value
    | none => throw s!"Unknown data binding '{token}'"

/-- Simple expression evaluator for the evaluate/setVariable API. -/
private def evalExpression (env : DataEnv) (expression : String) :
    Except String Value := do
  let tokens := tokenizeExpression expression
  match tokens.size with
  | 0 => throw "evaluate requires a non-empty expression"
  | 1 => evalToken env tokens[0]!
  | _ => throw s!"Unsupported expression form '{expression}' (only literals and variables)"

-- ═══════════════════════════════════════════════════════════════════════
-- §6  Session context mutation (for setVariable)
-- ═══════════════════════════════════════════════════════════════════════

private def updateSessionContext (session : PlanDebugSession) (ctx : PlanContext) :
    PlanDebugSession :=
  let session := session.normalize
  { session with history := (session.history.extract 0 session.cursor).push ctx }

private def updateFrameEnv (session : PlanDebugSession) (frameId : Nat)
    (f : DataEnv → Except String DataEnv) : Except String PlanDebugSession := do
  let session := session.normalize
  let some ctx := session.current?
    | throw "Session has no active frame"
  let framesDisplay := ctx.frames.reverse
  if h : frameId < framesDisplay.size then
    let frame := framesDisplay[frameId]'h
    let updatedEnv ← f frame.env
    let updatedFrame : PlanFrame := { frame with env := updatedEnv }
    let updatedDisplay := framesDisplay.set ⟨frameId, h⟩ updatedFrame
    let updatedFrames := updatedDisplay.reverse
    let some current := updatedFrames.back?
      | throw "Session has no active frame"
    let callers := updatedFrames.pop
    let updatedCtx : PlanContext := { ctx with current, callers }
    pure <| updateSessionContext session updatedCtx
  else
    throw s!"Unknown stack frame id: {frameId}"

-- ═══════════════════════════════════════════════════════════════════════
-- §7  Scope encoding - 4 scopes per frame
--     ImpLab uses frameId*2+{1,2} for locals/heap
--     We use frameId*4+{1,2,3,4} for locals/resources/flow/certificates
-- ═══════════════════════════════════════════════════════════════════════

/-- Number of scope types. -/
private def scopeCount : Nat := 4

/-- Encode (frameId, locals) → variablesReference. -/
def localsReference (frameId : Nat) : Nat :=
  frameId * scopeCount + 1

/-- Encode (frameId, resources) → variablesReference. -/
def resourcesReference (frameId : Nat) : Nat :=
  frameId * scopeCount + 2

/-- Encode (frameId, flowLabels) → variablesReference. -/
def flowLabelsReference (frameId : Nat) : Nat :=
  frameId * scopeCount + 3

/-- Encode (frameId, certificates) → variablesReference. -/
def certificatesReference (frameId : Nat) : Nat :=
  frameId * scopeCount + 4

/-- Decode variablesReference → (frameId, scopeOffset) where offset ∈ {1,2,3,4}.
    Returns none for invalid references. -/
def decodeScopeReference (ref : Nat) : Option (Nat × Nat) :=
  if ref = 0 then none
  else
    let offset := ((ref - 1) % scopeCount) + 1
    let frameId := (ref - 1) / scopeCount
    some (frameId, offset)

/-- Convenience: decode and check for specific scope type. -/
private def decodeScope (ref : Nat) (expectedOffset : Nat) : Option Nat :=
  match decodeScopeReference ref with
  | some (frameId, offset) => if offset = expectedOffset then some frameId else none
  | none => none

private def localsFrameId? (ref : Nat) : Option Nat := decodeScope ref 1
private def resourcesFrameId? (ref : Nat) : Option Nat := decodeScope ref 2
private def flowLabelsFrameId? (ref : Nat) : Option Nat := decodeScope ref 3
private def certificatesFrameId? (ref : Nat) : Option Nat := decodeScope ref 4

-- ═══════════════════════════════════════════════════════════════════════
-- §8  Launch
-- ═══════════════════════════════════════════════════════════════════════

/-- Launch a new debug session from a PlanInfo.
    Analogous to ImpLab's `launchFromProgramInfo`. -/
def launchFromPlanInfo (store : SessionStore) (planInfo : PlanInfo)
    (stopOnEntry : Bool) (breakpoints : Array Nat) :
    Except String (SessionStore × LaunchResponse) := do
  let planInfo ← planInfo.validate
  let session ← match PlanDebugSession.fromPlan planInfo.plan with
    | .ok session => pure session
    | .error err => throw s!"Launch failed: {err}"
  let normalizedBreakpoints := normalizeRequestedBreakpoints planInfo breakpoints
  let session := session.setBreakpoints normalizedBreakpoints
  let (session, stopReason) ← match session.initialStop stopOnEntry with
    | .ok value => pure value
    | .error err => throw s!"Launch failed: {err}"
  let sessionId := store.nextId
  let data : SessionData :=
    { session, planInfo, status := statusFromStopReason stopReason }
  let store :=
    { nextId := sessionId + 1
      sessions := store.sessions.insert sessionId data }
  let line := match stackFrameAt? session 0 with
    | some frame => frameSourceLine planInfo session frame
    | none => 1
  let response : LaunchResponse :=
    { sessionId
      threadId := 1
      line
      stopReason := toString stopReason
      terminated := session.atEnd || stopReason = .terminated }
  pure (store, response)

-- ═══════════════════════════════════════════════════════════════════════
-- §9  Breakpoint management
-- ═══════════════════════════════════════════════════════════════════════

/-- Set line-based breakpoints. -/
def setBreakpoints (store : SessionStore) (sessionId : Nat)
    (breakpoints : Array Nat) :
    Except String (SessionStore × SetBreakpointsResponse) := do
  let data ← getSessionData store sessionId
  ensureControllable data sessionId
  let normalized := normalizeRequestedBreakpoints data.planInfo breakpoints
  let data := { data with session := data.session.setBreakpoints normalized }
  let store := putSessionData store sessionId data
  let views := breakpoints.map (mkBreakpointView data.planInfo)
  pure (store, { breakpoints := views })

/-- Set exception breakpoints. -/
def setExceptionBreakpoints (store : SessionStore) (sessionId : Nat)
    (filters : Array String) :
    Except String (SessionStore × SetExceptionBreakpointsResponse) := do
  let data ← getSessionData store sessionId
  ensureControllable data sessionId
  let enabled := !filters.isEmpty
  let data := { data with
    exceptionBreakpointsEnabled := enabled, lastException? := none }
  let store := putSessionData store sessionId data
  pure (store, { enabled })

/-- Set flow-level breakpoints (Certior-specific). -/
def setFlowBreakpoints (store : SessionStore) (sessionId : Nat)
    (levels : Array SecurityLevel) :
    Except String (SessionStore × SetFlowBreakpointsResponse) := do
  let data ← getSessionData store sessionId
  ensureControllable data sessionId
  let fbs := levels.map fun lvl => ({ level := lvl } : FlowBreakpoint)
  let data := { data with
    session := data.session.setFlowBreakpoints fbs }
  let store := putSessionData store sessionId data
  pure (store, { count := fbs.size })

/-- Set budget threshold breakpoint (Certior-specific). -/
def setBudgetBreakpoint (store : SessionStore) (sessionId : Nat)
    (threshold : Int) :
    Except String (SessionStore × SetBudgetBreakpointResponse) := do
  let data ← getSessionData store sessionId
  ensureControllable data sessionId
  let data := { data with
    session := data.session.setBudgetBreakpoint threshold }
  let store := putSessionData store sessionId data
  pure (store, { threshold, active := true })

/-- Set capability watch (Certior-specific). -/
def setCapabilityWatch (store : SessionStore) (sessionId : Nat)
    (capabilities : Array String) :
    Except String (SessionStore × SetCapabilityWatchResponse) := do
  let data ← getSessionData store sessionId
  ensureControllable data sessionId
  let data := { data with
    session := data.session.setCapabilityWatch capabilities }
  let store := putSessionData store sessionId data
  pure (store, { capabilities, active := true })

-- ═══════════════════════════════════════════════════════════════════════
-- §10  Threads (single-threaded - same as ImpLab)
-- ═══════════════════════════════════════════════════════════════════════

def threads (_store : SessionStore) : ThreadsResponse :=
  { threads := #[{ id := 1, name := "main" }] }

-- ═══════════════════════════════════════════════════════════════════════
-- §11  Control operations
-- ═══════════════════════════════════════════════════════════════════════

private def applyControl (store : SessionStore) (sessionId : Nat)
    (allowTerminated : Bool := false)
    (f : PlanDebugSession →
      Except PlanDebugSession.ControlFailure (PlanDebugSession × StopReason)) :
    Except String (SessionStore × ControlResponse) := do
  let data ← getSessionData store sessionId
  if !allowTerminated then
    ensureControllable data sessionId
  match f data.session with
  | .ok (session, reason) =>
    let data := { data with
      session, status := statusFromStopReason reason, lastException? := none }
    let store := putSessionData store sessionId data
    pure (store, mkControlResponse data reason)
  | .error (failedSession, err) =>
    if data.exceptionBreakpointsEnabled then
      let data := { data with
        session := failedSession
        status := .stopped
        lastException? := some err }
      let store := putSessionData store sessionId data
      pure (store, mkControlResponse data .exception
        (description? := some (toString err)))
    else
      throw s!"Debug operation failed: {err}"

/-- Next: step over. -/
def next (store : SessionStore) (sessionId : Nat) :
    Except String (SessionStore × ControlResponse) :=
  applyControl store sessionId (f := PlanDebugSession.nextWithState)

/-- Step in: single step. -/
def stepIn (store : SessionStore) (sessionId : Nat) :
    Except String (SessionStore × ControlResponse) :=
  applyControl store sessionId (f := PlanDebugSession.stepInWithState)

/-- Step out: run until caller. -/
def stepOut (store : SessionStore) (sessionId : Nat) :
    Except String (SessionStore × ControlResponse) :=
  applyControl store sessionId (f := PlanDebugSession.stepOutWithState)

/-- Step back: time-travel backward. -/
def stepBack (store : SessionStore) (sessionId : Nat) :
    Except String (SessionStore × ControlResponse) :=
  applyControl store sessionId (allowTerminated := true)
    (fun s => pure (PlanDebugSession.stepBack s))

/-- Continue: run until breakpoint or termination. -/
def continueExecution (store : SessionStore) (sessionId : Nat) :
    Except String (SessionStore × ControlResponse) :=
  applyControl store sessionId (f := PlanDebugSession.continueExecutionWithState)

/-- Pause: return current position (no-op for synchronous debugger). -/
def pause (store : SessionStore) (sessionId : Nat) :
    Except String ControlResponse := do
  let data ← getSessionData store sessionId
  ensureControllable data sessionId
  pure (mkControlResponse data .pause)

-- ═══════════════════════════════════════════════════════════════════════
-- §12  Stack trace
-- ═══════════════════════════════════════════════════════════════════════

def stackTrace (store : SessionStore) (sessionId : Nat)
    (startFrame : Nat := 0) (levels : Nat := 20) :
    Except String StackTraceResponse := do
  let data ← getSessionData store sessionId
  ensureControllable data sessionId
  let session := data.session
  let fullFrames :=
    (stackFramesInDisplayOrder session).foldl (init := #[]) fun acc frame =>
      let frameId := acc.size
      acc.push
        { id := frameId
          name := frameName session frame
          line := frameSourceLine data.planInfo session frame
          column := 1 : StackFrameView }
  let start := min startFrame fullFrames.size
  let stop :=
    if levels = 0 then start
    else min (start + levels) fullFrames.size
  pure
    { stackFrames := fullFrames.extract start stop
      totalFrames := fullFrames.size }

-- ═══════════════════════════════════════════════════════════════════════
-- §13  Scopes - 4 scopes per frame
-- ═══════════════════════════════════════════════════════════════════════

/-- Return 4 scopes for the given frame. -/
def scopes (store : SessionStore) (sessionId : Nat) (frameId : Nat := 0) :
    Except String ScopesResponse := do
  let data ← getSessionData store sessionId
  ensureControllable data sessionId
  if (stackFrameAt? data.session frameId).isSome then
    pure
      { scopes :=
          #[ { name := "Locals"
               variablesReference := localsReference frameId }
           , { name := "Resources"
               variablesReference := resourcesReference frameId }
           , { name := "Flow Labels"
               variablesReference := flowLabelsReference frameId }
           , { name := "Certificates"
               variablesReference := certificatesReference frameId } ] }
  else
    pure { scopes := #[] }

-- ═══════════════════════════════════════════════════════════════════════
-- §14  Variables - dispatches on scope type
-- ═══════════════════════════════════════════════════════════════════════

/-- Return variables for the given scope reference. -/
def variables (store : SessionStore) (sessionId : Nat)
    (variablesReference : Nat) : Except String VariablesResponse := do
  let data ← getSessionData store sessionId
  ensureControllable data sessionId
  if variablesReference = 0 then
    pure { variables := #[] }
  -- Scope 1: Locals
  else if let some frameId := localsFrameId? variablesReference then
    match stackFrameAt? data.session frameId with
    | none => pure { variables := #[] }
    | some frame =>
      let vars := frame.env.toArray.map fun (name, value) =>
        { name, value := toString value : VariableView }
      pure { variables := vars }
  -- Scope 2: Resources
  else if let some _frameId := resourcesFrameId? variablesReference then
    let vars := data.session.resourceBindings.map fun (name, value) =>
      { name, value := toString value : VariableView }
    pure { variables := vars }
  -- Scope 3: Flow Labels
  else if let some _frameId := flowLabelsFrameId? variablesReference then
    let vars := data.session.flowBindings.map fun (dataId, label) =>
      { name := dataId
        value := s!"{label.level} {label.tags}" : VariableView }
    pure { variables := vars }
  -- Scope 4: Certificates
  else if let some _frameId := certificatesFrameId? variablesReference then
    let certs := data.session.certificates
    let vars := certs.foldl (init := (#[] : Array VariableView)) fun acc cert =>
      acc.push
        { name := s!"cert[{acc.size}]"
          value := s!"{cert.property}: {cert.stepId} ({cert.detail})" }
    pure { variables := vars }
  else
    pure { variables := #[] }

-- ═══════════════════════════════════════════════════════════════════════
-- §15  Evaluate and SetVariable
-- ═══════════════════════════════════════════════════════════════════════

/-- Evaluate an expression in the context of a frame. -/
def evaluate (store : SessionStore) (sessionId : Nat)
    (expression : String) (frameId : Nat := 0) :
    Except String EvaluateResponse := do
  let data ← getSessionData store sessionId
  ensureControllable data sessionId
  let frame ← requireStackFrame data.session frameId
  let value ← evalExpression frame.env expression
  pure { result := toString value }

/-- Set a local variable's value. -/
def setVariable (store : SessionStore) (sessionId : Nat)
    (variablesReference : Nat) (name : String) (valueExpression : String) :
    Except String (SessionStore × SetVariableResponse) := do
  let data ← getSessionData store sessionId
  ensureControllable data sessionId
  if variablesReference = 0 then
    throw "setVariable requires variablesReference > 0"
  let (session, value) ←
    if let some frameId := localsFrameId? variablesReference then
      let frame ← requireStackFrame data.session frameId
      if (frame.env.find? name).isNone then
        throw s!"Unknown data binding '{name}' in selected frame"
      let value ← evalExpression frame.env valueExpression
      let session ←
        updateFrameEnv data.session frameId fun env =>
          pure <| env.insert name value
      pure (session, value)
    else if let some _frameId := resourcesFrameId? variablesReference then
      -- Resource mutation: global but expression eval uses selected frame env
      let frame ← requireStackFrame data.session 0
      let session := data.session.normalize
      let some ctx := session.current?
        | throw "Session has no active frame"
      if (ctx.resources.find? name).isNone then
        throw s!"Unknown resource '{name}'"
      let value ← evalExpression frame.env valueExpression
      let updatedCtx : PlanContext :=
        { ctx with resources := ctx.resources.insert name value }
      pure (updateSessionContext session updatedCtx, value)
    else
      throw s!"Cannot set variables in this scope (ref={variablesReference})"
  let data := { data with session, lastException? := none }
  let store := putSessionData store sessionId data
  pure (store, { value := toString value })

-- ═══════════════════════════════════════════════════════════════════════
-- §16  Exception info
-- ═══════════════════════════════════════════════════════════════════════

def exceptionInfo (store : SessionStore) (sessionId : Nat) :
    Except String ExceptionInfoResponse := do
  let data ← getSessionData store sessionId
  ensureControllable data sessionId
  let some err := data.lastException?
    | throw s!"No exception information available for session {sessionId}"
  pure
    { exceptionId := planErrorId err
      description? := some (toString err)
      breakMode := "always" }

-- ═══════════════════════════════════════════════════════════════════════
-- §17  Certior-specific custom requests
-- ═══════════════════════════════════════════════════════════════════════

/-- Return all proof certificates for the current session state. -/
def getCertificates (store : SessionStore) (sessionId : Nat) :
    Except String (Array CertificateView) := do
  let data ← getSessionData store sessionId
  let certs := data.session.certificates
  pure <| certs.map fun cert =>
    { stepId := cert.stepId
      property := cert.property
      inputLabels := cert.inputLabels.map fun l => toString l.level
      outputLabel := toString cert.outputLabel.level
      detail := cert.detail }

/-- Return the flow graph: all data bindings and their flow labels,
    plus edges representing actual flow relationships. -/
def getFlowGraph (store : SessionStore) (sessionId : Nat) :
    Except String FlowGraphResponse := do
  let data ← getSessionData store sessionId
  let nodes := data.session.flowBindings.map fun (dataId, label) =>
    { dataId, level := toString label.level, tags := label.tags.toArray }
  -- Derive edges from certificates
  let edges := data.session.certificates.foldl (init := #[]) fun acc cert =>
    if cert.property == "flow_safe" || cert.property == "call_verified" then
      let srcLabels := cert.inputLabels.map (toString ·.level)
      srcLabels.foldl (init := acc) fun acc' srcLvl =>
        acc'.push
          { source := srcLvl
            target := toString cert.outputLabel.level
            label := cert.property
            allowed := true }
    else acc
  pure { edges, nodes }

/-- Export compliance audit trail. -/
def exportCompliance (store : SessionStore) (sessionId : Nat) :
    Except String ComplianceExportResponse := do
  let data ← getSessionData store sessionId
  let session := data.session
  let certs := session.certificates
  let certViews := certs.map fun cert =>
    { stepId := cert.stepId
      property := cert.property
      inputLabels := cert.inputLabels.map fun l => toString l.level
      outputLabel := toString cert.outputLabel.level
      detail := cert.detail : CertificateView }
  let auditTrail := certs.map fun cert =>
    s!"[{cert.property}] {cert.stepId}: {cert.detail}"
  -- Count flow violations from exception history
  let flowViolations := certs.foldl (init := 0) fun count cert =>
    if cert.property == "flow_violation" then count + 1 else count
  pure
    { policy := data.planInfo.plan.compliancePolicy
      totalSteps := (session.current?.map (·.stepsExecuted)).getD 0
      certificateCount := certs.size
      flowViolations
      budgetUsed := data.planInfo.plan.totalBudgetCents - session.budgetRemaining
      budgetTotal := data.planInfo.plan.totalBudgetCents
      certificates := certViews
      auditTrail }

-- ═══════════════════════════════════════════════════════════════════════
-- §18  Disconnect and inspect
-- ═══════════════════════════════════════════════════════════════════════

def disconnect (store : SessionStore) (sessionId : Nat) : SessionStore × Bool :=
  let existed := (store.sessions.find? sessionId).isSome
  let store := { store with sessions := store.sessions.erase sessionId }
  (store, existed)

def inspectSession (store : SessionStore) (sessionId : Nat) :
    Except String SessionData :=
  getSessionData store sessionId

end CertiorPlan

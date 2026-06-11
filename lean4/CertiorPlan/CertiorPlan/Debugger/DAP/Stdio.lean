/-
  CertiorPlan.Debugger.DAP.Stdio - DAP Transport Layer

  Full Debug Adapter Protocol server over stdio. Fork of ImpLab's
  `Debugger/DAP/Stdio.lean` (538 lines) adapted for CertiorPlan with:

    Standard DAP requests (20):
      initialize, launch, configurationDone, threads, stackTrace,
      scopes, variables, evaluate, setVariable, exceptionInfo,
      setBreakpoints, setExceptionBreakpoints,
      next, stepIn, stepOut, stepBack, continue, pause,
      disconnect, terminate

    Custom Certior requests (6):
      setFlowBreakpoints, setBudgetBreakpoint, setCapabilityWatch,
      certificates, flowGraph, complianceExport

  Transport: LSP base protocol (Content-Length framed JSON over stdio)
  Threading: Single-threaded (threadId=1), matching ImpLab's model

  ## Wire Protocol

  DAP uses the same base protocol as LSP:
    Content-Length: <n>\r\n
    \r\n
    <JSON payload of n bytes>

  Lean's `Lean.Data.Lsp.Communication` provides read/write for this.

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import Lean
import Lean.Data.Lsp.Communication
import CertiorPlan.Debugger.Core
import CertiorPlan.Debugger.DAP.Launch
import CertiorPlan.Debugger.DAP.Capabilities

open Lean

namespace CertiorPlan.DAP

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Adapter State
-- ═══════════════════════════════════════════════════════════════════════

/-- Mutable adapter state held across the lifetime of the DAP session.
    Follows ImpLab's `AdapterState` with additional Certior fields. -/
structure AdapterState where
  /-- Monotonic sequence counter for DAP message `seq` fields. -/
  nextSeq : Nat := 1
  /-- The underlying session store from Core.lean. -/
  core : CertiorPlan.SessionStore := {}
  /-- Default session ID (set after first successful launch). -/
  defaultSessionId? : Option Nat := none
  /-- Breakpoints pending until a session is launched. -/
  pendingBreakpoints : Array Nat := #[]
  /-- Exception filters pending until a session is launched. -/
  pendingExceptionFilters : Array String := #[]
  /-- Source file path per session (for stack trace display). -/
  sourcePathBySession : Std.HashMap Nat String := {}
  /-- Pending flow breakpoints (applied on next launch). -/
  pendingFlowBreakpoints : Array SecurityLevel := #[]
  /-- Pending budget breakpoint (applied on next launch). -/
  pendingBudgetBreakpoint : Option Int := none
  /-- Pending capability watch list (applied on next launch). -/
  pendingCapabilityWatch : Array String := #[]
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════
-- §2  DAP Message Types
-- ═══════════════════════════════════════════════════════════════════════

/-- Decoded DAP request. -/
structure DapRequest where
  seq : Nat
  command : String
  arguments : Json := Json.null

-- ═══════════════════════════════════════════════════════════════════════
-- §3  Low-Level Protocol Helpers
-- ═══════════════════════════════════════════════════════════════════════

/-- Normalize stop reasons for DAP compliance.
    DAP uses "pause" where we internally use "terminated" for non-final stops. -/
private def normalizedStoppedReason (reason : String) : String :=
  if reason = "terminated" then "pause" else reason

/-- Extract arguments object from a request, defaulting to empty. -/
private def requestArgs (req : DapRequest) : Json :=
  match req.arguments with
  | .obj _ => req.arguments
  | _ => Json.mkObj []

/-- Decode a DAP request from a raw JSON payload string.
    Returns `none` for non-request messages (events, responses). -/
private def decodeRequest? (payload : String) : Except String (Option DapRequest) := do
  let json ← Json.parse payload
  let msgType ← json.getObjValAs? String "type"
  if msgType != "request" then
    pure none
  else
    pure <| some
      { seq := (← json.getObjValAs? Nat "seq")
        command := (← json.getObjValAs? String "command")
        arguments := (json.getObjVal? "arguments").toOption.getD Json.null }

/-- Allocate the next sequence number. -/
private def nextSeq (stRef : IO.Ref AdapterState) : IO Nat := do
  stRef.modifyGet fun st =>
    (st.nextSeq, { st with nextSeq := st.nextSeq + 1 })

/-- Send a JSON object using LSP base protocol framing. -/
private def sendJson (stdout : IO.FS.Stream) (msg : Json) : IO Unit := do
  let payload := msg.compress
  let header := s!"Content-Length: {payload.utf8ByteSize}\r\n\r\n"
  stdout.putStr (header ++ payload)
  stdout.flush

/-- Read a Content-Length framed JSON payload from stdin. -/
private partial def readPayload (stdin : IO.FS.Stream) : IO String := do
  let contentLengthRef ← IO.mkRef (none : Option Nat)
  let rec readHeaders : IO Unit := do
    let line ← stdin.getLine
    if line.isEmpty then
      throw <| IO.userError "Stream was closed"
    if line = "\r\n" then
      pure ()
    else
      if line.startsWith "Content-Length: " then
        let raw := line.drop 16 |>.trim
        let raw := if raw.endsWith "\r\n" then raw.dropRight 2 else raw
        match raw.toNat? with
        | some n => contentLengthRef.set (some n)
        | none => throw <| IO.userError s!"Invalid Content-Length header: {raw}"
      readHeaders
  readHeaders
  let contentLength? ← contentLengthRef.get
  let n ←
    match contentLength? with
    | some v => pure v
    | none => throw <| IO.userError "Missing Content-Length header"
  let bytes ← stdin.read (UInt64.toUSize n.toUInt64)
  match String.fromUTF8? bytes with
  | some s => pure s
  | none => throw <| IO.userError "Invalid UTF-8 payload"

/-- Send a DAP response. -/
private def sendResponse (stdout : IO.FS.Stream) (stRef : IO.Ref AdapterState)
    (req : DapRequest) (body : Json := Json.mkObj [])
    (success : Bool := true) (message? : Option String := none) : IO Unit := do
  let seq ← nextSeq stRef
  let fields :=
    [ ("seq", toJson seq),
      ("type", toJson "response"),
      ("request_seq", toJson req.seq),
      ("success", toJson success),
      ("command", toJson req.command),
      ("body", body) ] ++
    match message? with
    | some message => [("message", toJson message)]
    | none => []
  sendJson stdout (Json.mkObj fields)

/-- Send a DAP error response. -/
private def sendErrorResponse (stdout : IO.FS.Stream) (stRef : IO.Ref AdapterState)
    (req : DapRequest) (message : String) : IO Unit := do
  let body := Json.mkObj
    [("error", Json.mkObj
      [("id", toJson (1 : Nat)),
       ("format", toJson message)])]
  sendResponse stdout stRef req (body := body) (success := false)
    (message? := some message)

/-- Send a DAP event. -/
private def sendEvent (stdout : IO.FS.Stream) (stRef : IO.Ref AdapterState)
    (event : String) (body : Json := Json.mkObj []) : IO Unit := do
  let seq ← nextSeq stRef
  sendJson stdout <| Json.mkObj
    [ ("seq", toJson seq),
      ("type", toJson "event"),
      ("event", toJson event),
      ("body", body) ]

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Stop/Terminate Emission
-- ═══════════════════════════════════════════════════════════════════════

/-- Map CertiorPlan StopReason to DAP stopped-event reason string. -/
private def stopReasonToDAP (reason : CertiorPlan.StopReason) : String :=
  match reason with
  | .entry => "entry"
  | .step => "step"
  | .breakpoint => "breakpoint"
  | .exception => "exception"
  | .pause => "pause"
  | .terminated => "terminated"
  | .flowBreakpoint => "breakpoint"
  | .budgetBreakpoint => "breakpoint"
  | .capabilityBreakpoint => "breakpoint"

/-- Parse `ControlResponse.stopReason` text to a StopReason. -/
private def stopReasonOfString (s : String) : CertiorPlan.StopReason :=
  match s with
  | "entry" => .entry
  | "step" => .step
  | "breakpoint" => .breakpoint
  | "exception" => .exception
  | "pause" => .pause
  | "terminated" => .terminated
  | "flowBreakpoint" => .flowBreakpoint
  | "budgetBreakpoint" => .budgetBreakpoint
  | "capabilityBreakpoint" => .capabilityBreakpoint
  | _ => .pause

/-- Map StopReason to a human-readable description for verification stops. -/
private def stopReasonDescription? (reason : CertiorPlan.StopReason) : Option String :=
  match reason with
  | .flowBreakpoint => some "Flow breakpoint: data with security level ≥ threshold detected"
  | .budgetBreakpoint => some "Budget breakpoint: budget below threshold"
  | .capabilityBreakpoint => some "Capability breakpoint: watched capability invoked"
  | .exception => some "Plan execution error"
  | _ => none

/-- Emit a DAP `stopped` or `terminated` event. -/
private def emitStopOrTerminate (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState)
    (reason : CertiorPlan.StopReason) : IO Unit := do
  if reason == .terminated then
    sendEvent stdout stRef "terminated"
  else
    let dapReason := stopReasonToDAP reason
    let fields :=
      [ ("reason", toJson (normalizedStoppedReason dapReason)),
        ("threadId", toJson (1 : Nat)),
        ("allThreadsStopped", toJson true) ] ++
      match stopReasonDescription? reason with
      | some desc => [("text", toJson desc), ("description", toJson desc)]
      | none => []
    sendEvent stdout stRef "stopped" <| Json.mkObj fields

/-- Emit stop or terminate from a ControlResponse. -/
private def emitControlResult (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState)
    (response : CertiorPlan.ControlResponse) : IO Unit := do
  emitStopOrTerminate stdout stRef (stopReasonOfString response.stopReason)

-- ═══════════════════════════════════════════════════════════════════════
-- §5  Argument Parsing Helpers
-- ═══════════════════════════════════════════════════════════════════════

/-- Parse an array of breakpoint objects, extracting `line` fields. -/
private def parseBreakpointsArray (json : Json) : Array Nat :=
  match json.getArr?.toOption with
  | none => #[]
  | some breakpoints =>
    breakpoints.foldl (init := #[]) fun acc bp =>
      match (bp.getObjValAs? Nat "line").toOption with
      | some line => if line > 0 then acc.push line else acc
      | none => acc

/-- Parse breakpoint lines from `setBreakpoints` arguments. -/
private def parseBreakpointLines (args : Json) : Array Nat :=
  match (args.getObjVal? "breakpoints").toOption with
  | some breakpointsJson => parseBreakpointsArray breakpointsJson
  | none => #[]

/-- Parse a string array from a JSON field. -/
private def parseStringArrayField (args : Json) (field : String) : Array String :=
  match (args.getObjVal? field).toOption with
  | none => #[]
  | some value =>
    match value.getArr?.toOption with
    | none => #[]
    | some values =>
      values.foldl (init := #[]) fun acc item =>
        match (fromJson? item : Except String String) with
        | .ok str => acc.push str
        | .error _ => acc

/-- Parse security levels from JSON array (for flow breakpoints). -/
private def parseSecurityLevels (args : Json) (field : String) : Array SecurityLevel :=
  let strings := parseStringArrayField args field
  strings.foldl (init := #[]) fun acc s =>
    match s with
    | "Public" => acc.push .Public
    | "Internal" => acc.push .Internal
    | "Sensitive" => acc.push .Sensitive
    | "Restricted" => acc.push .Restricted
    | _ => acc

/-- Require a PlanInfo from launch arguments. -/
private def requirePlanInfo (args : Json) : IO PlanInfo := do
  let planInfoJson ←
    match (args.getObjVal? "planInfo").toOption with
    | some json => pure json
    | none =>
      throw <| IO.userError
        "launch requires 'planInfo' (a CertiorPlan.PlanInfo JSON payload)."
  match decodePlanInfoJson planInfoJson with
  | .ok planInfo => pure planInfo
  | .error err => throw <| IO.userError err

/-- Build a `source` JSON object for stack frames. -/
private def sourceJson? (sourcePath? : Option String) : Option Json := do
  let sourcePath ← sourcePath?
  let name := (System.FilePath.mk sourcePath).fileName.getD sourcePath
  pure <| Json.mkObj [("name", toJson name), ("path", toJson sourcePath)]

/-- Convert a BreakpointView to DAP JSON. -/
private def toBreakpointJson (view : CertiorPlan.BreakpointView) : Json :=
  Json.mkObj <|
    [ ("line", toJson view.line),
      ("verified", toJson view.verified) ] ++
    match view.message? with
    | some msg => [("message", toJson msg)]
    | none => []

/-- Extract sessionId from arguments, falling back to default. -/
private def sessionIdFromArgs? (args : Json) : Option Nat :=
  (args.getObjValAs? Nat "sessionId").toOption

/-- Require a session ID (from args or default). -/
private def requireSessionId (stRef : IO.Ref AdapterState)
    (args : Json) : IO Nat := do
  match sessionIdFromArgs? args with
  | some sessionId => pure sessionId
  | none =>
    let some sessionId := (← stRef.get).defaultSessionId?
      | throw <| IO.userError
          "No default DAP session. Launch first or pass arguments.sessionId."
    pure sessionId

-- ═══════════════════════════════════════════════════════════════════════
-- §6  Standard DAP Handlers: Lifecycle
-- ═══════════════════════════════════════════════════════════════════════

/-- Handle `initialize` - advertise capabilities. -/
private def handleInitialize (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let exceptionBreakpointFilters := Json.arr
    #[Json.mkObj
      [ ("filter", toJson "runtime"),
        ("label", toJson "Plan execution errors"),
        ("default", toJson true),
        ("description", toJson
          "Break on flow violations, budget exhaustion, and capability denials") ]]
  sendResponse stdout stRef req <| Json.mkObj
    [ ("supportsConfigurationDoneRequest",
        toJson dapCapabilities.supportsConfigurationDoneRequest),
      ("supportsStepBack",
        toJson dapCapabilities.supportsStepBack),
      ("supportsRestartRequest",
        toJson dapCapabilities.supportsRestartRequest),
      ("supportsEvaluateForHovers",
        toJson dapCapabilities.supportsEvaluateForHovers),
      ("supportsSetVariable",
        toJson dapCapabilities.supportsSetVariable),
      ("supportsExceptionInfoRequest",
        toJson dapCapabilities.supportsExceptionInfoRequest),
      -- Certior custom capabilities
      ("supportsFlowBreakpoints",
        toJson certiorCapabilities.supportsFlowBreakpoints),
      ("supportsBudgetBreakpoint",
        toJson certiorCapabilities.supportsBudgetBreakpoint),
      ("supportsCapabilityWatch",
        toJson certiorCapabilities.supportsCapabilityWatch),
      ("supportsCertificateInspection",
        toJson certiorCapabilities.supportsCertificateInspection),
      ("supportsFlowGraph",
        toJson certiorCapabilities.supportsFlowGraph),
      ("supportsComplianceExport",
        toJson certiorCapabilities.supportsComplianceExport),
      ("exceptionBreakpointFilters", exceptionBreakpointFilters) ]
  sendEvent stdout stRef "initialized"

/-- Handle `launch` - create a debug session from PlanInfo. -/
private def handleLaunch (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let args := requestArgs req
  let planInfo ← requirePlanInfo args
  let stopOnEntry :=
    (args.getObjValAs? Bool "stopOnEntry").toOption.getD true
  let sourcePath? :=
    (args.getObjValAs? String "source").toOption
  let breakpoints := parseBreakpointLines args
  let pending := (← stRef.get).pendingBreakpoints
  let activeBreakpoints :=
    if breakpoints.isEmpty then pending else breakpoints

  let st ← stRef.get
  let (coreAfterLaunch, launch) ←
    match CertiorPlan.launchFromPlanInfo st.core planInfo
        stopOnEntry activeBreakpoints with
    | .ok value => pure value
    | .error err => throw <| IO.userError err

  -- Apply pending exception filters
  let core ←
    if st.pendingExceptionFilters.isEmpty then
      pure coreAfterLaunch
    else
      match CertiorPlan.setExceptionBreakpoints coreAfterLaunch
          launch.sessionId st.pendingExceptionFilters with
      | .ok (core, _) => pure core
      | .error err => throw <| IO.userError err

  -- Apply pending flow breakpoints
  let core ←
    if st.pendingFlowBreakpoints.isEmpty then pure core
    else
      match CertiorPlan.setFlowBreakpoints core
          launch.sessionId st.pendingFlowBreakpoints with
      | .ok (c, _) => pure c
      | .error err => throw <| IO.userError err

  -- Apply pending budget breakpoint
  let core ←
    match st.pendingBudgetBreakpoint with
    | none => pure core
    | some threshold =>
      match CertiorPlan.setBudgetBreakpoint core
          launch.sessionId threshold with
      | .ok (c, _) => pure c
      | .error err => throw <| IO.userError err

  -- Apply pending capability watch
  let core ←
    if st.pendingCapabilityWatch.isEmpty then pure core
    else
      match CertiorPlan.setCapabilityWatch core
          launch.sessionId st.pendingCapabilityWatch with
      | .ok (c, _) => pure c
      | .error err => throw <| IO.userError err

  stRef.modify fun st =>
    let sourcePathBySession :=
      match sourcePath? with
      | some sourcePath =>
        st.sourcePathBySession.insert launch.sessionId sourcePath
      | none => st.sourcePathBySession.erase launch.sessionId
    { st with
      core
      defaultSessionId? := some launch.sessionId
      pendingBreakpoints := activeBreakpoints
      sourcePathBySession }
  sendResponse stdout stRef req
  emitStopOrTerminate stdout stRef (stopReasonOfString launch.stopReason)

-- ═══════════════════════════════════════════════════════════════════════
-- §7  Standard DAP Handlers: Breakpoints
-- ═══════════════════════════════════════════════════════════════════════

/-- Handle `setBreakpoints` - line-based breakpoints. -/
private def handleSetBreakpoints (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let args := requestArgs req
  let lines := parseBreakpointLines args
  stRef.modify fun st => { st with pendingBreakpoints := lines }
  let st ← stRef.get
  let targetSessionId? :=
    (sessionIdFromArgs? args) <|> st.defaultSessionId?
  match targetSessionId? with
  | none =>
    let breakpoints := Json.arr <| lines.map fun line =>
      toBreakpointJson
        { line
          verified := false
          message? := some "Pending: verified when plan launches."
          : CertiorPlan.BreakpointView }
    sendResponse stdout stRef req <|
      Json.mkObj [("breakpoints", breakpoints)]
  | some sessionId =>
    let (core, response) ←
      match CertiorPlan.setBreakpoints st.core sessionId lines with
      | .ok value => pure value
      | .error err => throw <| IO.userError err
    stRef.modify fun st => { st with core }
    let breakpoints := Json.arr <|
      response.breakpoints.map toBreakpointJson
    sendResponse stdout stRef req <|
      Json.mkObj [("breakpoints", breakpoints)]

/-- Handle `setExceptionBreakpoints`. -/
private def handleSetExceptionBreakpoints (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let args := requestArgs req
  let filters := parseStringArrayField args "filters"
  stRef.modify fun st => { st with pendingExceptionFilters := filters }
  let st ← stRef.get
  let targetSessionId? :=
    (sessionIdFromArgs? args) <|> st.defaultSessionId?
  match targetSessionId? with
  | none =>
    sendResponse stdout stRef req
  | some sessionId =>
    let (core, response) ←
      match CertiorPlan.setExceptionBreakpoints st.core sessionId
          filters with
      | .ok value => pure value
      | .error err => throw <| IO.userError err
    stRef.modify fun st => { st with core }
    sendResponse stdout stRef req <|
      Json.mkObj [("enabled", toJson response.enabled)]

-- ═══════════════════════════════════════════════════════════════════════
-- §8  Standard DAP Handlers: Threads & Stack
-- ═══════════════════════════════════════════════════════════════════════

/-- Handle `threads`. -/
private def handleThreads (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let threads := CertiorPlan.threads (← stRef.get).core
  let payload := Json.arr <| threads.threads.map fun t =>
    Json.mkObj [("id", toJson t.id), ("name", toJson t.name)]
  sendResponse stdout stRef req <|
    Json.mkObj [("threads", payload)]

/-- Handle `stackTrace`. -/
private def handleStackTrace (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let args := requestArgs req
  let sessionId ← requireSessionId stRef args
  let startFrame :=
    (args.getObjValAs? Nat "startFrame").toOption.getD 0
  let levels :=
    (args.getObjValAs? Nat "levels").toOption.getD 20
  let st ← stRef.get
  let response ←
    match CertiorPlan.stackTrace st.core sessionId startFrame levels
      with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  let sourceField? :=
    sourceJson? (st.sourcePathBySession.get? sessionId)
  let stackFrames := response.stackFrames.map fun frame =>
    let base :=
      [ ("id", toJson frame.id),
        ("name", toJson frame.name),
        ("line", toJson frame.line),
        ("column", toJson frame.column) ]
    match sourceField? with
    | some source => Json.mkObj <| base ++ [("source", source)]
    | none => Json.mkObj base
  sendResponse stdout stRef req <| Json.mkObj
    [ ("stackFrames", Json.arr stackFrames),
      ("totalFrames", toJson response.totalFrames) ]

-- ═══════════════════════════════════════════════════════════════════════
-- §9  Standard DAP Handlers: Scopes & Variables
-- ═══════════════════════════════════════════════════════════════════════

/-- Handle `scopes` - returns 4 scopes per frame. -/
private def handleScopes (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let args := requestArgs req
  let sessionId ← requireSessionId stRef args
  let frameId :=
    (args.getObjValAs? Nat "frameId").toOption.getD 0
  let response ←
    match CertiorPlan.scopes (← stRef.get).core sessionId frameId with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  let scopes := response.scopes.map fun scope =>
    Json.mkObj
      [ ("name", toJson scope.name),
        ("variablesReference", toJson scope.variablesReference),
        ("expensive", toJson scope.expensive) ]
  sendResponse stdout stRef req <|
    Json.mkObj [("scopes", Json.arr scopes)]

/-- Handle `variables`. -/
private def handleVariables (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let args := requestArgs req
  let sessionId ← requireSessionId stRef args
  let variablesReference :=
    (args.getObjValAs? Nat "variablesReference").toOption.getD 0
  let response ←
    match CertiorPlan.variables (← stRef.get).core sessionId
        variablesReference with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  let variables := response.variables.map fun var =>
    Json.mkObj
      [ ("name", toJson var.name),
        ("value", toJson var.value),
        ("variablesReference", toJson var.variablesReference) ]
  sendResponse stdout stRef req <|
    Json.mkObj [("variables", Json.arr variables)]

-- ═══════════════════════════════════════════════════════════════════════
-- §10  Standard DAP Handlers: Evaluate & SetVariable
-- ═══════════════════════════════════════════════════════════════════════

/-- Handle `evaluate`. -/
private def handleEvaluate (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let args := requestArgs req
  let sessionId ← requireSessionId stRef args
  let expression ←
    match (args.getObjValAs? String "expression").toOption with
    | some e => pure e
    | none => throw <| IO.userError "evaluate requires arguments.expression"
  let frameId :=
    (args.getObjValAs? Nat "frameId").toOption.getD 0
  let response ←
    match CertiorPlan.evaluate (← stRef.get).core sessionId expression
        frameId with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  sendResponse stdout stRef req <| Json.mkObj
    [ ("result", toJson response.result),
      ("variablesReference", toJson response.variablesReference) ]

/-- Handle `setVariable`. -/
private def handleSetVariable (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let args := requestArgs req
  let sessionId ← requireSessionId stRef args
  let variablesReference ←
    match (args.getObjValAs? Nat "variablesReference").toOption with
    | some v => pure v
    | none => throw <| IO.userError "setVariable requires arguments.variablesReference"
  let name ←
    match (args.getObjValAs? String "name").toOption with
    | some n => pure n
    | none => throw <| IO.userError "setVariable requires arguments.name"
  let valueExpression ←
    match (args.getObjValAs? String "value").toOption with
    | some v => pure v
    | none => throw <| IO.userError "setVariable requires arguments.value"
  let (core, response) ←
    match CertiorPlan.setVariable (← stRef.get).core sessionId
        variablesReference name valueExpression with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  stRef.modify fun st => { st with core }
  sendResponse stdout stRef req <| Json.mkObj
    [ ("value", toJson response.value),
      ("variablesReference", toJson response.variablesReference) ]

/-- Handle `exceptionInfo`. -/
private def handleExceptionInfo (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let sessionId ← requireSessionId stRef (requestArgs req)
  let response ←
    match CertiorPlan.exceptionInfo (← stRef.get).core sessionId with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  let fields :=
    [ ("exceptionId", toJson response.exceptionId),
      ("breakMode", toJson response.breakMode) ] ++
    match response.description? with
    | some desc => [("description", toJson desc)]
    | none => []
  sendResponse stdout stRef req <| Json.mkObj fields

-- ═══════════════════════════════════════════════════════════════════════
-- §11  Standard DAP Handlers: Control Flow
-- ═══════════════════════════════════════════════════════════════════════

/-- Handle `next` (step over). -/
private def handleNext (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let sessionId ← requireSessionId stRef (requestArgs req)
  let (core, response) ←
    match CertiorPlan.next (← stRef.get).core sessionId with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  stRef.modify fun st => { st with core }
  sendResponse stdout stRef req
  emitControlResult stdout stRef response

/-- Handle `stepIn`. -/
private def handleStepIn (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let sessionId ← requireSessionId stRef (requestArgs req)
  let (core, response) ←
    match CertiorPlan.stepIn (← stRef.get).core sessionId with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  stRef.modify fun st => { st with core }
  sendResponse stdout stRef req
  emitControlResult stdout stRef response

/-- Handle `stepOut`. -/
private def handleStepOut (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let sessionId ← requireSessionId stRef (requestArgs req)
  let (core, response) ←
    match CertiorPlan.stepOut (← stRef.get).core sessionId with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  stRef.modify fun st => { st with core }
  sendResponse stdout stRef req
  emitControlResult stdout stRef response

/-- Handle `stepBack` (time travel). -/
private def handleStepBack (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let sessionId ← requireSessionId stRef (requestArgs req)
  let (core, response) ←
    match CertiorPlan.stepBack (← stRef.get).core sessionId with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  stRef.modify fun st => { st with core }
  sendResponse stdout stRef req
  emitControlResult stdout stRef response

/-- Handle `continue`. -/
private def handleContinue (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let sessionId ← requireSessionId stRef (requestArgs req)
  let (core, response) ←
    match CertiorPlan.continueExecution (← stRef.get).core sessionId
      with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  stRef.modify fun st => { st with core }
  sendEvent stdout stRef "continued" <| Json.mkObj
    [ ("threadId", toJson (1 : Nat)),
      ("allThreadsContinued", toJson true) ]
  sendResponse stdout stRef req <|
    Json.mkObj [("allThreadsContinued", toJson true)]
  emitControlResult stdout stRef response

/-- Handle `pause`. -/
private def handlePause (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let sessionId ← requireSessionId stRef (requestArgs req)
  let response ←
    match CertiorPlan.pause (← stRef.get).core sessionId with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  sendResponse stdout stRef req
  emitControlResult stdout stRef response

-- ═══════════════════════════════════════════════════════════════════════
-- §12  Standard DAP Handlers: Disconnect
-- ═══════════════════════════════════════════════════════════════════════

/-- Handle `disconnect` / `terminate`. -/
private def handleDisconnect (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let args := requestArgs req
  let st ← stRef.get
  let targetSessionId? :=
    (sessionIdFromArgs? args) <|> st.defaultSessionId?
  let core :=
    match targetSessionId? with
    | some sessionId =>
      (CertiorPlan.disconnect st.core sessionId).1
    | none => st.core
  let sourcePathBySession :=
    match targetSessionId? with
    | some sessionId =>
      st.sourcePathBySession.erase sessionId
    | none => st.sourcePathBySession
  let defaultSessionId? :=
    match st.defaultSessionId? with
    | some defaultSessionId =>
      if (core.sessions.find? defaultSessionId).isSome then
        some defaultSessionId
      else
        none
    | none => none
  stRef.modify fun st =>
    { st with core, defaultSessionId?, sourcePathBySession }
  sendResponse stdout stRef req

-- ═══════════════════════════════════════════════════════════════════════
-- §13  Custom Certior Handlers: Verification Breakpoints
-- ═══════════════════════════════════════════════════════════════════════

/-- Handle `setFlowBreakpoints` - set security level thresholds. -/
private def handleSetFlowBreakpoints (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let args := requestArgs req
  let levels := parseSecurityLevels args "levels"
  stRef.modify fun st =>
    { st with pendingFlowBreakpoints := levels }
  let st ← stRef.get
  let targetSessionId? :=
    (sessionIdFromArgs? args) <|> st.defaultSessionId?
  match targetSessionId? with
  | none =>
    sendResponse stdout stRef req <| Json.mkObj
      [("count", toJson levels.size), ("pending", toJson true)]
  | some sessionId =>
    let (core, response) ←
      match CertiorPlan.setFlowBreakpoints st.core sessionId levels
        with
      | .ok value => pure value
      | .error err => throw <| IO.userError err
    stRef.modify fun st => { st with core }
    sendResponse stdout stRef req <| Json.mkObj
      [("count", toJson response.count)]

/-- Handle `setBudgetBreakpoint` - set budget threshold. -/
private def handleSetBudgetBreakpoint (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let args := requestArgs req
  let threshold :=
    (args.getObjValAs? Int "threshold").toOption
  stRef.modify fun st =>
    { st with pendingBudgetBreakpoint := threshold }
  let st ← stRef.get
  let targetSessionId? :=
    (sessionIdFromArgs? args) <|> st.defaultSessionId?
  match targetSessionId?, threshold with
  | some sessionId, some t =>
    let (core, response) ←
      match CertiorPlan.setBudgetBreakpoint st.core sessionId t with
      | .ok value => pure value
      | .error err => throw <| IO.userError err
    stRef.modify fun st => { st with core }
    sendResponse stdout stRef req <| Json.mkObj
      [("threshold", toJson response.threshold),
       ("enabled", toJson response.active)]
  | _, _ =>
    sendResponse stdout stRef req <| Json.mkObj
      [("threshold", toJson threshold),
       ("enabled", toJson threshold.isSome),
       ("pending", toJson true)]

/-- Handle `setCapabilityWatch` - watch capability invocations. -/
private def handleSetCapabilityWatch (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let args := requestArgs req
  let capabilities :=
    parseStringArrayField args "capabilities"
  stRef.modify fun st =>
    { st with pendingCapabilityWatch := capabilities }
  let st ← stRef.get
  let targetSessionId? :=
    (sessionIdFromArgs? args) <|> st.defaultSessionId?
  match targetSessionId? with
  | none =>
    sendResponse stdout stRef req <| Json.mkObj
      [("count", toJson capabilities.size), ("pending", toJson true)]
  | some sessionId =>
    let (core, response) ←
      match CertiorPlan.setCapabilityWatch st.core sessionId
          capabilities with
      | .ok value => pure value
      | .error err => throw <| IO.userError err
    stRef.modify fun st => { st with core }
    sendResponse stdout stRef req <| Json.mkObj
      [("count", toJson response.capabilities.size),
       ("capabilities", toJson response.capabilities),
       ("active", toJson response.active)]

-- ═══════════════════════════════════════════════════════════════════════
-- §14  Custom Certior Handlers: Inspection
-- ═══════════════════════════════════════════════════════════════════════

/-- Handle `certificates` - return all proof certificates. -/
private def handleCertificates (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let sessionId ← requireSessionId stRef (requestArgs req)
  let certs ←
    match CertiorPlan.getCertificates (← stRef.get).core sessionId with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  let json := Json.arr <| certs.map fun c =>
    Json.mkObj
      [ ("stepId", toJson c.stepId),
        ("property", toJson c.property),
        ("inputLabels", Json.arr <| c.inputLabels.map toJson),
        ("outputLabel", toJson c.outputLabel),
        ("detail", toJson c.detail) ]
  sendResponse stdout stRef req <|
    Json.mkObj [("certificates", json)]

/-- Handle `flowGraph` - return information flow graph. -/
private def handleFlowGraph (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let sessionId ← requireSessionId stRef (requestArgs req)
  let graph ←
    match CertiorPlan.getFlowGraph (← stRef.get).core sessionId with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  let edges := Json.arr <| graph.edges.map fun e =>
    Json.mkObj
      [ ("from", toJson e.source),
        ("to", toJson e.target),
        ("label", toJson e.label),
        ("allowed", toJson e.allowed) ]
  let nodes := Json.arr <| graph.nodes.map toJson
  sendResponse stdout stRef req <| Json.mkObj
    [ ("nodes", nodes),
      ("edges", edges) ]

/-- Handle `complianceExport` - full audit trail for regulators. -/
private def handleComplianceExport (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  let sessionId ← requireSessionId stRef (requestArgs req)
  let export_ ←
    match CertiorPlan.exportCompliance (← stRef.get).core sessionId
      with
    | .ok value => pure value
    | .error err => throw <| IO.userError err
  let certificates := Json.arr <| export_.certificates.map fun c =>
    Json.mkObj
      [ ("stepId", toJson c.stepId),
        ("property", toJson c.property),
        ("inputLabels", Json.arr <| c.inputLabels.map toJson),
        ("outputLabel", toJson c.outputLabel),
        ("detail", toJson c.detail) ]
  let auditTrail := Json.arr <| export_.auditTrail.map toJson
  sendResponse stdout stRef req <| Json.mkObj
    [ ("policy", toJson export_.policy),
      ("totalSteps", toJson export_.totalSteps),
      ("certificateCount", toJson export_.certificateCount),
      ("flowViolations", toJson export_.flowViolations),
      ("budgetUsed", toJson export_.budgetUsed),
      ("certificates", certificates),
      ("auditTrail", auditTrail) ]

-- ═══════════════════════════════════════════════════════════════════════
-- §15  Request Dispatch
-- ═══════════════════════════════════════════════════════════════════════

/-- Dispatch a DAP request to the appropriate handler. -/
private def handleRequest (stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) (req : DapRequest) : IO Unit := do
  try
    match req.command with
    -- Standard DAP: Lifecycle
    | "initialize"               => handleInitialize stdout stRef req
    | "launch"                   => handleLaunch stdout stRef req
    | "configurationDone"        => sendResponse stdout stRef req
    -- Standard DAP: Breakpoints
    | "setBreakpoints"           =>
        handleSetBreakpoints stdout stRef req
    | "setExceptionBreakpoints"  =>
        handleSetExceptionBreakpoints stdout stRef req
    -- Standard DAP: Threads & Stack
    | "threads"                  => handleThreads stdout stRef req
    | "stackTrace"               => handleStackTrace stdout stRef req
    -- Standard DAP: Scopes & Variables
    | "scopes"                   => handleScopes stdout stRef req
    | "variables"                => handleVariables stdout stRef req
    | "evaluate"                 => handleEvaluate stdout stRef req
    | "setVariable"              => handleSetVariable stdout stRef req
    | "exceptionInfo"            =>
        handleExceptionInfo stdout stRef req
    -- Standard DAP: Control
    | "next"                     => handleNext stdout stRef req
    | "stepIn"                   => handleStepIn stdout stRef req
    | "stepOut"                  => handleStepOut stdout stRef req
    | "stepBack"                 => handleStepBack stdout stRef req
    | "continue"                 => handleContinue stdout stRef req
    | "pause"                    => handlePause stdout stRef req
    -- Standard DAP: Termination
    | "disconnect"               => handleDisconnect stdout stRef req
    | "terminate"                => handleDisconnect stdout stRef req
    -- Custom Certior: Verification Breakpoints
    | "setFlowBreakpoints"       =>
        handleSetFlowBreakpoints stdout stRef req
    | "setBudgetBreakpoint"      =>
        handleSetBudgetBreakpoint stdout stRef req
    | "setCapabilityWatch"       =>
        handleSetCapabilityWatch stdout stRef req
    -- Custom Certior: Inspection
    | "certificates"             =>
        handleCertificates stdout stRef req
    | "flowGraph"                =>
        handleFlowGraph stdout stRef req
    | "complianceExport"         =>
        handleComplianceExport stdout stRef req
    -- Unknown
    | _ => sendErrorResponse stdout stRef req
             s!"Unsupported request: {req.command}"
  catch e =>
    sendErrorResponse stdout stRef req e.toString

-- ═══════════════════════════════════════════════════════════════════════
-- §16  Main Loop
-- ═══════════════════════════════════════════════════════════════════════

/-- Main DAP server loop: read → decode → dispatch → repeat. -/
partial def loop (stdin stdout : IO.FS.Stream)
    (stRef : IO.Ref AdapterState) : IO Unit := do
  let payload? ←
    try
      pure <| some (← readPayload stdin)
    catch e =>
      let msg := e.toString
      if (msg.splitOn "Stream was closed").length > 1 then
        pure none
      else
        throw e
  match payload? with
  | none => pure ()
  | some payload =>
    match decodeRequest? payload with
    | .ok none =>
      -- Non-request message (event/response) - skip
      loop stdin stdout stRef
    | .ok (some req) =>
      handleRequest stdout stRef req
      loop stdin stdout stRef
    | .error err =>
      IO.eprintln s!"[certior-dap] ignoring malformed message: {err}"
      loop stdin stdout stRef

/-- Entry point: run the DAP server on stdin/stdout. -/
def run : IO Unit := do
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout
  let stRef ← IO.mkRef ({} : AdapterState)
  loop stdin stdout stRef

end CertiorPlan.DAP

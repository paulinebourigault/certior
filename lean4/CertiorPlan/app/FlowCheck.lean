/-
  CertiorPlan.FlowCheck - Live Flow Verification Service

  A persistent stdin/stdout JSON service that the Python agent loop
  invokes for mathematically-certified information flow checking.

  Protocol:
    - Reads one JSON request per line from stdin
    - Writes one JSON response per line to stdout
    - Stays alive for the duration of an agent session
    - Maintains cumulative flow state across requests

  Request types:
    { "cmd": "init", "budget": 10000, "capabilities": [...], "compliance": "hipaa" }
    { "cmd": "check_flow", "step_index": 0, "tool": "web_fetch",
      "input_labels": ["Public"], "output_label": "Internal",
      "data_id": "result_0", "cost": 100 }
    { "cmd": "check_tool_output_flow", "step_index": 0, "tool": "web_fetch",
      "data_label": "Sensitive", "target_label": "Public", "data_id": "output_0" }
    { "cmd": "get_state" }
    { "cmd": "get_certificates" }
    { "cmd": "shutdown" }

  Response:
    { "ok": true, "certificates": [...], "flow_state": {...} }
    { "ok": false, "error": "flow_violation", "detail": "..." }

  The critical property: every `check_flow` invocation uses the
  *proven* `SecurityLevel.levelCanFlowTo` from `Certior.Lattice`.
  This means every flow decision in the live agent loop is backed
  by the lattice proofs (P13–P21, absorption, distributivity).

  Copyright (c) 2026 Certior. All rights reserved.
-/

import Lean
import Certior.Lattice
import CertiorPlan.Ast
import CertiorPlan.Eval

open Lean
open SecurityLevel
open CertiorPlan

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Session State
-- ═══════════════════════════════════════════════════════════════════════

/-- Mutable session state for the flow-check service. -/
structure FlowCheckState where
  /-- Flow label of every data binding produced so far. -/
  flowTracker : FlowState := {}
  /-- Available capabilities. -/
  capabilities : CapabilityStore := {}
  /-- Remaining budget in cents. -/
  budgetRemaining : Int := 10000
  /-- Total budget. -/
  budgetTotal : Int := 10000
  /-- Proof certificates issued so far. -/
  certificates : Array ProofCert := #[]
  /-- Total steps checked. -/
  stepsChecked : Nat := 0
  /-- Flow violations detected (non-fatal in advisory mode). -/
  flowViolations : Nat := 0
  /-- Compliance policy name. -/
  compliancePolicy : String := "default"
  deriving Repr, Inhabited

-- ═══════════════════════════════════════════════════════════════════════
-- §2  Request / Response JSON Types
-- ═══════════════════════════════════════════════════════════════════════

/-- Parse a SecurityLevel from a JSON string, defaulting to Internal. -/
def parseLevel (s : String) : SecurityLevel :=
  match s with
  | "Public"     => .Public
  | "Internal"   => .Internal
  | "Sensitive"  => .Sensitive
  | "Restricted" => .Restricted
  | _            => .Internal

/-- Render a SecurityLevel to a string. -/
def renderLevel (l : SecurityLevel) : String :=
  match l with
  | .Public     => "Public"
  | .Internal   => "Internal"
  | .Sensitive  => "Sensitive"
  | .Restricted => "Restricted"

/-- Build a JSON response indicating success. -/
def okResponse (state : FlowCheckState) (extra : List (String × Json) := []) : Json :=
  let base : List (String × Json) :=
    [ ("ok", Json.bool true)
    , ("steps_checked", toJson state.stepsChecked)
    , ("budget_remaining", toJson state.budgetRemaining)
    , ("certificates_count", toJson state.certificates.size)
    , ("flow_violations", toJson state.flowViolations)
    ]
  Json.mkObj (base ++ extra)

/-- Build a JSON error response. -/
def errorResponse (error : String) (detail : String) (state : FlowCheckState)
    (extra : List (String × Json) := []) : Json :=
  Json.mkObj <|
    [ ("ok", Json.bool false)
    , ("error", Json.str error)
    , ("detail", Json.str detail)
    , ("steps_checked", toJson state.stepsChecked)
    , ("budget_remaining", toJson state.budgetRemaining)
    , ("flow_violations", toJson state.flowViolations)
    ] ++ extra

-- ═══════════════════════════════════════════════════════════════════════
-- §3  Command Handlers
-- ═══════════════════════════════════════════════════════════════════════

/-- Handle `init` command: reset state with given parameters. -/
def handleInit (json : Json) (_state : FlowCheckState) : FlowCheckState × Json :=
  let budget := (json.getObjValAs? Nat "budget").toOption.getD 10000
  let compliance := (json.getObjValAs? String "compliance").toOption.getD "default"
  let capsArr := (json.getObjValAs? (Array String) "capabilities").toOption.getD #[]
  let caps := capsArr.foldl (init := ({} : CapabilityStore)) fun s c => s.insert c true
  let newState : FlowCheckState :=
    { flowTracker := {}
      capabilities := caps
      budgetRemaining := budget
      budgetTotal := budget
      certificates := #[]
      stepsChecked := 0
      flowViolations := 0
      compliancePolicy := compliance }
  (newState, okResponse newState [("cmd", Json.str "init")])

/-- Handle `check_flow` command: verify that input labels can flow to output label.
    This is the critical path - uses the *proven* `flowAllowed` from Certior.Lattice. -/
def handleCheckFlow (json : Json) (state : FlowCheckState) : FlowCheckState × Json :=
  let stepIndex := (json.getObjValAs? Nat "step_index").toOption.getD state.stepsChecked
  let tool := (json.getObjValAs? String "tool").toOption.getD "unknown"
  let inputLabelStrs := (json.getObjValAs? (Array String) "input_labels").toOption.getD #[]
  let outputLabelStr := (json.getObjValAs? String "output_label").toOption.getD "Internal"
  let dataId := (json.getObjValAs? String "data_id").toOption.getD s!"step_{stepIndex}"
  let cost := (json.getObjValAs? Int "cost").toOption.getD 0

  let outputLevel := parseLevel outputLabelStr
  let inputLevels := inputLabelStrs.map parseLevel

  -- Budget check
  if state.budgetRemaining < cost then
    let detail := s!"Budget exhausted: need {cost}, have {state.budgetRemaining}"
    (state, errorResponse "budget_exhausted" detail state)
  else
    Id.run <| do
      let mut violations : Array String := #[]
      for inputLevel in inputLevels do
        if ¬(flowAllowed inputLevel outputLevel) then
          violations := violations.push
            s!"{renderLevel inputLevel} cannot flow to {renderLevel outputLevel}"
      if violations.isEmpty then
        let inputLabels := inputLevels.map fun l => FlowLabel.mk l []
        let outputLabel := FlowLabel.mk outputLevel []
        let cert : ProofCert :=
          { stepId := dataId
            property := "flow_safe"
            inputLabels := inputLabels
            outputLabel := outputLabel
            detail := s!"step[{stepIndex}] {tool}: " ++
              s!"{inputLabelStrs} → {outputLabelStr} ✓ (lattice-proven)" }
        let newState :=
          { state with
            flowTracker := state.flowTracker.insert dataId outputLabel
            budgetRemaining := state.budgetRemaining - cost
            certificates := state.certificates.push cert
            stepsChecked := state.stepsChecked + 1 }
        let certJson : Json := Json.mkObj
          [ ("step_id", Json.str cert.stepId)
          , ("property", Json.str cert.property)
          , ("detail", Json.str cert.detail) ]
        pure (newState, okResponse newState
          [ ("cmd", Json.str "check_flow")
          , ("certificate", certJson)
          , ("data_id", Json.str dataId)
          , ("proven", Json.bool true) ])
      else
        let detail := String.intercalate "; " violations.toList
        let newState :=
          { state with
            stepsChecked := state.stepsChecked + 1
            flowViolations := state.flowViolations + 1 }
        pure (newState, errorResponse "flow_violation" detail newState
          [("proven", Json.bool true)])

/-- Handle `check_tool_output_flow`: verify a specific data→target flow.
    Used after tool execution to check if the output can flow to the intended
    destination (e.g., can Sensitive data flow to Public user output?). -/
def handleCheckToolOutputFlow (json : Json) (state : FlowCheckState) : FlowCheckState × Json :=
  let dataLabelStr := (json.getObjValAs? String "data_label").toOption.getD "Internal"
  let targetLabelStr := (json.getObjValAs? String "target_label").toOption.getD "Public"
  let dataId := (json.getObjValAs? String "data_id").toOption.getD "output"
  let tool := (json.getObjValAs? String "tool").toOption.getD "unknown"
  let stepIndex := (json.getObjValAs? Nat "step_index").toOption.getD state.stepsChecked

  let dataLevel := parseLevel dataLabelStr
  let targetLevel := parseLevel targetLabelStr

  -- THE CRITICAL FLOW CHECK: proven lattice operation
  if flowAllowed dataLevel targetLevel then
    let cert : ProofCert :=
      { stepId := dataId
        property := "output_flow_safe"
        inputLabels := #[FlowLabel.mk dataLevel []]
        outputLabel := FlowLabel.mk targetLevel []
        detail := s!"step[{stepIndex}] {tool} output: " ++
          s!"{dataLabelStr} → {targetLabelStr} ✓ (lattice-proven)" }
    let newState :=
      { state with certificates := state.certificates.push cert }
    (newState, okResponse newState
      [ ("cmd", Json.str "check_tool_output_flow")
      , ("allowed", Json.bool true)
      , ("proven", Json.bool true) ])
  else
    let detail := s!"{dataLabelStr} cannot flow to {targetLabelStr} (lattice-proven denial)"
    let newState :=
      { state with flowViolations := state.flowViolations + 1 }
    (newState, errorResponse "flow_violation" detail newState [("proven", Json.bool true)])

/-- Handle `get_state`: return current flow state. -/
def handleGetState (state : FlowCheckState) : Json :=
  let flowEntries := state.flowTracker.toArray.map fun (id, label) =>
    Json.mkObj [("data_id", Json.str id), ("level", Json.str (renderLevel label.level))]
  okResponse state
    [ ("cmd", Json.str "get_state")
    , ("flow_tracker", Json.arr flowEntries)
    , ("compliance_policy", Json.str state.compliancePolicy)
    , ("budget_total", toJson state.budgetTotal) ]

/-- Handle `get_certificates`: return all issued certificates. -/
def handleGetCertificates (state : FlowCheckState) : Json :=
  let certs := state.certificates.map fun cert =>
    Json.mkObj
      [ ("step_id", Json.str cert.stepId)
      , ("property", Json.str cert.property)
      , ("detail", Json.str cert.detail)
      , ("input_labels", Json.arr (cert.inputLabels.map fun l =>
          Json.str (renderLevel l.level)))
      , ("output_label", Json.str (renderLevel cert.outputLabel.level)) ]
  okResponse state
    [ ("cmd", Json.str "get_certificates")
    , ("certificates", Json.arr certs) ]

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Main Loop
-- ═══════════════════════════════════════════════════════════════════════

/-- Process a single JSON request line. Returns updated state and response.
    Returns `none` on shutdown. -/
def processRequest (line : String) (state : FlowCheckState) :
    Option (FlowCheckState × Json) :=
  match Json.parse line with
  | .error msg =>
    some (state, errorResponse "parse_error" s!"Invalid JSON: {msg}" state)
  | .ok json =>
    let cmd := (json.getObjValAs? String "cmd").toOption.getD ""
    match cmd with
    | "init"                   => some (handleInit json state)
    | "check_flow"             => some (handleCheckFlow json state)
    | "check_tool_output_flow" => some (handleCheckToolOutputFlow json state)
    | "get_state"              => some (state, handleGetState state)
    | "get_certificates"       => some (state, handleGetCertificates state)
    | "shutdown"               => none
    | _                        => some (state, errorResponse "unknown_cmd" s!"Unknown command: {cmd}" state)

/-- Main entry point: read JSON lines from stdin, write responses to stdout. -/
partial def main : IO UInt32 := do
  -- Write ready signal
  let readyMsg := Json.mkObj [("ready", Json.bool true), ("version", Json.str "1.0.0")]
  IO.println (toString readyMsg)
  (← IO.getStdout).flush

  let stdin ← IO.getStdin
  let stdout ← IO.getStdout

  let rec loop (state : FlowCheckState) : IO UInt32 := do
    let line ← stdin.getLine
    let line := line.trimRight  -- strip trailing newline
    if line.isEmpty then
      return 0  -- EOF
    match processRequest line state with
    | none =>
      -- Shutdown requested
      let shutdownMsg := okResponse state [("cmd", Json.str "shutdown")]
      IO.println (toString shutdownMsg)
      stdout.flush
      return 0
    | some (newState, response) =>
      IO.println (toString response)
      stdout.flush
      loop newState

  loop {}

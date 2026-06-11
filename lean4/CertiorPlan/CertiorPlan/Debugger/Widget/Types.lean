/-
  CertiorPlan.Debugger.Widget.Types - View Models for Verification Explorer

  Extends ImpLab's `Debugger/Widget/Types.lean` with Certior-specific
  view models: flow labels, proof certificates, compliance status, and
  the flow graph visualization.

  These types bridge Lean4 execution state → ProofWidgets React UI.

  View models:
    PlanLineView           - single plan step with syntax highlight info
    TraceCallFrameView     - frame in the call stack
    BindingView            - data binding with value
    FlowLabelPanelView     - data binding + security label (NEW)
    CertificatePanelView   - proof certificate (NEW)
    CompliancePanelView    - compliance status summary (NEW)
    FlowEdgePanelView      - edge in the flow graph (NEW)
    PlanStateView          - full execution state (extended)
    WidgetInitProps         - widget initialization parameters
    WidgetSessionView       - complete session view for React
    FlowGraphView          - standalone flow graph for RPC
    CertificatesView       - standalone certificate list for RPC
    ComplianceView         - standalone compliance status for RPC

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import Lean
import CertiorPlan.Debugger.Core

open Lean

namespace CertiorPlan

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Standard view types (mirrors ImpLab)
-- ═══════════════════════════════════════════════════════════════════════

/-- Single plan step rendered for display. -/
structure PlanLineView where
  skillName : String
  stepLine : Nat
  sourceLine : Nat
  text : String
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

/-- Call frame in the stack trace. -/
structure TraceCallFrameView where
  skillName : String
  stepLine : Nat
  sourceLine : Nat
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

/-- Data binding (name + integer value). -/
structure BindingView where
  name : String
  value : Int
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

-- ═══════════════════════════════════════════════════════════════════════
-- §2  Certior-specific view types (NEW)
-- ═══════════════════════════════════════════════════════════════════════

/-- Security level color codes for the UI.
    Green (Public) → Blue (Internal) → Amber (Sensitive) → Red (Restricted) -/
def securityLevelColor : SecurityLevel → String
  | .Public => "#22c55e"
  | .Internal => "#3b82f6"
  | .Sensitive => "#f59e0b"
  | .Restricted => "#ef4444"

/-- Background color for security level badges. -/
def securityLevelBgColor : SecurityLevel → String
  | .Public => "#f0fdf4"
  | .Internal => "#eff6ff"
  | .Sensitive => "#fffbeb"
  | .Restricted => "#fef2f2"

/-- Border color for security level badges. -/
def securityLevelBorderColor : SecurityLevel → String
  | .Public => "#86efac"
  | .Internal => "#93c5fd"
  | .Sensitive => "#fcd34d"
  | .Restricted => "#fca5a5"

/-- Flow label binding for the Flow Labels panel. -/
structure FlowLabelPanelView where
  dataId : String
  level : String
  levelColor : String
  levelBgColor : String
  levelBorderColor : String
  tags : Array String
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

/-- Proof certificate for the Certificates panel. -/
structure CertificatePanelView where
  index : Nat
  stepId : String
  property : String
  inputLabels : Array String
  outputLabel : String
  detail : String
  verified : Bool := true
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

/-- Flow graph edge for the Flow Graph panel. -/
structure FlowEdgePanelView where
  source : String
  target : String
  sourceLevel : String
  targetLevel : String
  label : String
  allowed : Bool
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

/-- Compliance status summary. -/
structure CompliancePanelView where
  policy : String
  totalSteps : Nat
  certificateCount : Nat
  flowViolations : Nat
  budgetUsed : Int
  budgetTotal : Int
  approvalsPending : Nat
  allClear : Bool
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

-- ═══════════════════════════════════════════════════════════════════════
-- §3  Extended state view (Certior-specific)
-- ═══════════════════════════════════════════════════════════════════════

/-- Full execution state including Certior-specific panels.
    Extends ImpLab's `StateView` with flowLabels, certificates,
    flowEdges, compliance, and budgetRemaining. -/
structure PlanStateView where
  skillName : String
  pc : Nat
  stepLine : Nat
  sourceLine : Nat
  callDepth : Nat
  callStack : Array TraceCallFrameView
  -- ImpLab equivalents
  bindings : Array BindingView
  resourceBindings : Array BindingView
  -- Certior extensions
  flowLabels : Array FlowLabelPanelView
  certificates : Array CertificatePanelView
  flowEdges : Array FlowEdgePanelView
  compliance : CompliancePanelView
  budgetRemaining : Int
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Widget initialization and session view
-- ═══════════════════════════════════════════════════════════════════════

/-- Widget initialization props (passed from Lean `#widget` directive). -/
structure WidgetInitProps where
  planInfo : PlanInfo
  stopOnEntry : Bool := true
  breakpoints : Array Nat := #[]
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

/-- Complete session view sent to the React UI on every update. -/
structure WidgetSessionView where
  sessionId : Nat
  program : Array PlanLineView
  state : PlanStateView
  stopReason : String
  terminated : Bool
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

-- ═══════════════════════════════════════════════════════════════════════
-- §5  Standalone RPC response types
-- ═══════════════════════════════════════════════════════════════════════

/-- Flow graph response for the widgetFlowGraph RPC. -/
structure FlowGraphView where
  sessionId : Nat
  edges : Array FlowEdgePanelView
  nodeCount : Nat
  violationCount : Nat
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

/-- Certificates response for the widgetCertificates RPC. -/
structure CertificatesView where
  sessionId : Nat
  certificates : Array CertificatePanelView
  totalCount : Nat
  allVerified : Bool
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

/-- Compliance response for the widgetComplianceStatus RPC. -/
structure ComplianceView where
  sessionId : Nat
  compliance : CompliancePanelView
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

/-- Human-in-the-loop approval request params. -/
structure ApprovalParams where
  sessionId : Nat
  stepId : String
  approved : Bool
  reason : String := ""
  deriving Repr, Inhabited, BEq, Server.RpcEncodable, FromJson, ToJson

-- ═══════════════════════════════════════════════════════════════════════
-- §6  Conversion functions
-- ═══════════════════════════════════════════════════════════════════════

def PlanLineView.ofLocatedStep (located : LocatedStep) : PlanLineView :=
  { skillName := located.skillId
    stepLine := located.stepLine
    sourceLine := located.span.startLine
    text := toString located.step }

def BindingView.ofPair (entry : DataId × Value) : BindingView :=
  { name := entry.1, value := entry.2 }

def TraceCallFrameView.ofFrame
    (planInfo : PlanInfo) (session : PlanDebugSession)
    (frame : PlanFrame) : TraceCallFrameView :=
  let stepLine := session.frameLine frame
  let sourceLine := planInfo.locationToSourceLine (session.frameLocation frame)
  { skillName := frame.skillId, stepLine, sourceLine }

def FlowLabelPanelView.ofBinding (dataId : DataId) (label : FlowLabel) :
    FlowLabelPanelView :=
  { dataId
    level := toString label.level
    levelColor := securityLevelColor label.level
    levelBgColor := securityLevelBgColor label.level
    levelBorderColor := securityLevelBorderColor label.level
    tags := label.tags.toArray }

def CertificatePanelView.ofCert (idx : Nat) (cert : ProofCert) :
    CertificatePanelView :=
  { index := idx
    stepId := cert.stepId
    property := cert.property
    inputLabels := cert.inputLabels.map fun l => toString l.level
    outputLabel := toString cert.outputLabel.level
    detail := cert.detail }

/-- Build the flow edges array from proof certificates. -/
private def buildFlowEdges (certs : Array ProofCert) : Array FlowEdgePanelView :=
  certs.foldl (init := #[]) fun acc cert =>
    if cert.property == "flow_safe" || cert.property == "call_verified" then
      cert.inputLabels.foldl (init := acc) fun acc' inLabel =>
        acc'.push {
          source := cert.stepId
          target := cert.stepId ++ "_out"
          sourceLevel := toString inLabel.level
          targetLevel := toString cert.outputLabel.level
          label := cert.property
          allowed := true }
    else if cert.property == "flow_violation" then
      cert.inputLabels.foldl (init := acc) fun acc' inLabel =>
        acc'.push {
          source := cert.stepId
          target := cert.stepId ++ "_out"
          sourceLevel := toString inLabel.level
          targetLevel := toString cert.outputLabel.level
          label := cert.property
          allowed := false }
    else acc

/-- Count flow violations from proof certificates. -/
private def countFlowViolations (certs : Array ProofCert) : Nat :=
  certs.foldl (init := 0) fun count cert =>
    if cert.property == "flow_violation" then count + 1 else count

def PlanStateView.ofSession (planInfo : PlanInfo)
    (session : PlanDebugSession) : PlanStateView :=
  let stepLine := session.currentLine
  let sourceLine := planInfo.locationToSourceLine
    { skillId := session.currentSkillName, stepLine }
  let callStack := session.callFrames.reverse.map
    (TraceCallFrameView.ofFrame planInfo session)
  let flowLabels := session.flowBindings.map fun (did, label) =>
    FlowLabelPanelView.ofBinding did label
  let certs := session.certificates
  let certViews := certs.foldl (init := #[]) fun acc cert =>
    acc.push (CertificatePanelView.ofCert acc.size cert)
  let flowEdges := buildFlowEdges certs
  let flowViolations := countFlowViolations certs
  let budgetRem := session.budgetRemaining
  let compliance : CompliancePanelView :=
    { policy := planInfo.plan.compliancePolicy
      totalSteps := (session.current?.map (·.stepsExecuted)).getD 0
      certificateCount := certs.size
      flowViolations
      budgetUsed := planInfo.plan.totalBudgetCents - budgetRem
      budgetTotal := planInfo.plan.totalBudgetCents
      approvalsPending := 0
      allClear := flowViolations == 0 }
  { skillName := session.currentSkillName
    pc := session.currentPc
    stepLine
    sourceLine
    callDepth := session.currentCallDepth
    callStack
    bindings := session.bindings.map BindingView.ofPair
    resourceBindings := session.resourceBindings.map BindingView.ofPair
    flowLabels
    certificates := certViews
    flowEdges
    compliance
    budgetRemaining := budgetRem }

def PlanLineView.ofPlanInfo (planInfo : PlanInfo) : Array PlanLineView :=
  planInfo.located.map PlanLineView.ofLocatedStep

def WidgetSessionView.ofSessionData (sessionId : Nat) (data : SessionData)
    (stopReason : String := "entry") : WidgetSessionView :=
  { sessionId
    program := PlanLineView.ofPlanInfo data.planInfo
    state := PlanStateView.ofSession data.planInfo data.session
    stopReason
    terminated := data.status = .terminated || data.session.atEnd }

def FlowGraphView.ofSessionData (sessionId : Nat) (data : SessionData) :
    FlowGraphView :=
  let certs := data.session.certificates
  let edges := buildFlowEdges certs
  let nodes := edges.foldl (init := #[]) fun acc e =>
    let acc' := if acc.contains e.source then acc else acc.push e.source
    if acc'.contains e.target then acc' else acc'.push e.target
  { sessionId, edges, nodeCount := nodes.size
    violationCount := countFlowViolations certs }

def CertificatesView.ofSessionData (sessionId : Nat) (data : SessionData) :
    CertificatesView :=
  let certs := data.session.certificates
  let certViews := certs.foldl (init := #[]) fun acc cert =>
    acc.push (CertificatePanelView.ofCert acc.size cert)
  { sessionId
    certificates := certViews
    totalCount := certs.size
    allVerified := certs.all (·.property != "flow_violation") }

def ComplianceView.ofSessionData (sessionId : Nat) (data : SessionData) :
    ComplianceView :=
  let state := PlanStateView.ofSession data.planInfo data.session
  { sessionId, compliance := state.compliance }

end CertiorPlan

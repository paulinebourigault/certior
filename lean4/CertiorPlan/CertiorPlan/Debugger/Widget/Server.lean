/-
  CertiorPlan.Debugger.Widget.Server - RPC Methods for Verification Explorer

  Extends ImpLab's `Debugger/Widget/Server.lean` with Certior-specific
  RPC endpoints for flow graph inspection, proof certificate viewing,
  compliance status, and human-in-the-loop approval.

  RPC Methods (7 base + 4 Certior-specific = 11 total):
    widgetLaunch             - launch debug session (ImpLab pattern)
    widgetStepIn             - step forward (ImpLab pattern)
    widgetStepBack           - step backward (ImpLab pattern)
    widgetNext               - step over (Certior addition)
    widgetStepOut            - step out of skill (Certior addition)
    widgetContinue           - run to breakpoint (ImpLab pattern)
    widgetDisconnect         - teardown session (ImpLab pattern)
    widgetFlowGraph          - flow graph snapshot (NEW)
    widgetCertificates       - proof certificate list (NEW)
    widgetComplianceStatus   - compliance dashboard data (NEW)
    widgetApprove            - human-in-the-loop approval (NEW)

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import Lean
import CertiorPlan.Debugger.Core
import CertiorPlan.Debugger.Widget.Types

open Lean Lean.Server

namespace CertiorPlan.Debugger.Widget.Server

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Global session store (mirrors ImpLab pattern)
-- ═══════════════════════════════════════════════════════════════════════

/-- Global mutable reference to the debug session store.
    Initialized once per Lean server process. Shared across all
    widget instances in the same infoview. -/
initialize dapSessionStoreRef : IO.Ref SessionStore ←
  IO.mkRef { nextId := 1, sessions := {} }

-- ═══════════════════════════════════════════════════════════════════════
-- §2  Parameter / response types
-- ═══════════════════════════════════════════════════════════════════════

structure DisconnectResponse where
  disconnected : Bool
  deriving Inhabited, Repr, FromJson, ToJson, Server.RpcEncodable

/-- Launch params: carries the full PlanInfo to instantiate a session. -/
abbrev WidgetLaunchParams := CertiorPlan.WidgetInitProps

/-- Control params: sessionId is sufficient for stepping. -/
structure WidgetControlParams where
  sessionId : Nat
  deriving Inhabited, Repr, FromJson, ToJson, Server.RpcEncodable

/-- Alias for the full session view returned after each control action. -/
abbrev WidgetSessionViewT := CertiorPlan.WidgetSessionView

-- ═══════════════════════════════════════════════════════════════════════
-- §3  Helper functions
-- ═══════════════════════════════════════════════════════════════════════

private def mkInvalidParams (message : String) : RequestError :=
  RequestError.invalidParams message

/-- Unwrap a Core `Except String α` or throw an RPC error. -/
private def runCoreResult {α : Type} (result : Except String α) : RequestM α :=
  match result with
  | .ok value => pure value
  | .error err => throw <| mkInvalidParams err

/-- Persist the updated store back to the global ref. -/
private def updateStore (store : SessionStore) : IO Unit :=
  dapSessionStoreRef.set store

/-- Build a full WidgetSessionView from a session ID and stop reason. -/
private def widgetView (sessionId : Nat)
    (stopReason : String := "entry") : RequestM WidgetSessionViewT := do
  let data ← runCoreResult <|
    CertiorPlan.inspectSession (← dapSessionStoreRef.get) sessionId
  pure <| CertiorPlan.WidgetSessionView.ofSessionData sessionId data stopReason

-- ═══════════════════════════════════════════════════════════════════════
-- §4  Standard control RPCs (mirrors ImpLab)
-- ═══════════════════════════════════════════════════════════════════════

/-- Launch a new debug session from PlanInfo.
    Creates the session, stops on entry (or first breakpoint), returns
    the full initial view. -/
@[server_rpc_method]
def widgetLaunch (params : WidgetLaunchParams) :
    RequestM (RequestTask WidgetSessionViewT) :=
  RequestM.asTask do
    let store ← dapSessionStoreRef.get
    let (store, launch) ← runCoreResult <|
      CertiorPlan.launchFromPlanInfo store params.planInfo
        params.stopOnEntry params.breakpoints
    updateStore store
    widgetView launch.sessionId launch.stopReason

/-- Step into the next instruction. Single step forward. -/
@[server_rpc_method]
def widgetStepIn (params : WidgetControlParams) :
    RequestM (RequestTask WidgetSessionViewT) :=
  RequestM.asTask do
    let store ← dapSessionStoreRef.get
    let (store, control) ← runCoreResult <|
      CertiorPlan.stepIn store params.sessionId
    updateStore store
    widgetView params.sessionId control.stopReason

/-- Step backward one instruction (time-travel). -/
@[server_rpc_method]
def widgetStepBack (params : WidgetControlParams) :
    RequestM (RequestTask WidgetSessionViewT) :=
  RequestM.asTask do
    let store ← dapSessionStoreRef.get
    let (store, control) ← runCoreResult <|
      CertiorPlan.stepBack store params.sessionId
    updateStore store
    widgetView params.sessionId control.stopReason

/-- Step over: advance to next instruction at same call depth. -/
@[server_rpc_method]
def widgetNext (params : WidgetControlParams) :
    RequestM (RequestTask WidgetSessionViewT) :=
  RequestM.asTask do
    let store ← dapSessionStoreRef.get
    let (store, control) ← runCoreResult <|
      CertiorPlan.next store params.sessionId
    updateStore store
    widgetView params.sessionId control.stopReason

/-- Step out: run until call depth decreases (exit current skill). -/
@[server_rpc_method]
def widgetStepOut (params : WidgetControlParams) :
    RequestM (RequestTask WidgetSessionViewT) :=
  RequestM.asTask do
    let store ← dapSessionStoreRef.get
    let (store, control) ← runCoreResult <|
      CertiorPlan.stepOut store params.sessionId
    updateStore store
    widgetView params.sessionId control.stopReason

/-- Continue execution until next breakpoint or termination. -/
@[server_rpc_method]
def widgetContinue (params : WidgetControlParams) :
    RequestM (RequestTask WidgetSessionViewT) :=
  RequestM.asTask do
    let store ← dapSessionStoreRef.get
    let (store, control) ← runCoreResult <|
      CertiorPlan.continueExecution store params.sessionId
    updateStore store
    widgetView params.sessionId control.stopReason

/-- Disconnect and destroy the session. -/
@[server_rpc_method]
def widgetDisconnect (params : WidgetControlParams) :
    RequestM (RequestTask DisconnectResponse) :=
  RequestM.asTask do
    let (store, disconnected) :=
      CertiorPlan.disconnect (← dapSessionStoreRef.get) params.sessionId
    updateStore store
    pure { disconnected }

-- ═══════════════════════════════════════════════════════════════════════
-- §5  Certior-specific RPCs (NEW - not in ImpLab)
-- ═══════════════════════════════════════════════════════════════════════

/-- Return the current information flow graph for the session.
    Shows all edges derived from proof certificates with
    source/target security levels and allowed/blocked status. -/
@[server_rpc_method]
def widgetFlowGraph (params : WidgetControlParams) :
    RequestM (RequestTask CertiorPlan.FlowGraphView) :=
  RequestM.asTask do
    let data ← runCoreResult <|
      CertiorPlan.inspectSession (← dapSessionStoreRef.get) params.sessionId
    pure <| CertiorPlan.FlowGraphView.ofSessionData params.sessionId data

/-- Return all proof certificates issued so far in the session.
    Each certificate records the Z3/lattice proof for a single
    flow check or capability verification. -/
@[server_rpc_method]
def widgetCertificates (params : WidgetControlParams) :
    RequestM (RequestTask CertiorPlan.CertificatesView) :=
  RequestM.asTask do
    let data ← runCoreResult <|
      CertiorPlan.inspectSession (← dapSessionStoreRef.get) params.sessionId
    pure <| CertiorPlan.CertificatesView.ofSessionData params.sessionId data

/-- Return the current compliance status for the session.
    Shows policy, violation counts, budget consumption,
    and pending approval status. -/
@[server_rpc_method]
def widgetComplianceStatus (params : WidgetControlParams) :
    RequestM (RequestTask CertiorPlan.ComplianceView) :=
  RequestM.asTask do
    let data ← runCoreResult <|
      CertiorPlan.inspectSession (← dapSessionStoreRef.get) params.sessionId
    pure <| CertiorPlan.ComplianceView.ofSessionData params.sessionId data

/-- Human-in-the-loop approval for steps requiring manual authorization.
    Used for HIPAA external communication, SOX financial record changes,
    and legal privilege document sharing.

    After approval, the session continues execution from the approved step. -/
@[server_rpc_method]
def widgetApprove (params : CertiorPlan.ApprovalParams) :
    RequestM (RequestTask WidgetSessionViewT) :=
  RequestM.asTask do
    let store ← dapSessionStoreRef.get
    if params.approved then
      -- Continue execution from the approved step
      let (store', control) ← runCoreResult <|
        CertiorPlan.continueExecution store params.sessionId
      updateStore store'
      widgetView params.sessionId control.stopReason
    else
      -- Stay paused; mark step as rejected
      widgetView params.sessionId "approval_rejected"

end CertiorPlan.Debugger.Widget.Server

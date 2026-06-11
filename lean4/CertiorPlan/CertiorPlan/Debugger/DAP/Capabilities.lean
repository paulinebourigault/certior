/-
  CertiorPlan.Debugger.DAP.Capabilities - DAP Capability Declaration

  Declares which Debug Adapter Protocol features this server supports.
  Fork of ImpLab's `DAP/Capabilities.lean` with extensions for:
    - Flow breakpoints (custom)
    - Budget breakpoints (custom)
    - Capability watch (custom)
    - Compliance export (custom)

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import Lean

open Lean

namespace CertiorPlan.DAP

/-- Standard DAP capabilities supported by the Certior adapter. -/
structure DapCapabilities where
  supportsConfigurationDoneRequest : Bool := true
  supportsStepBack : Bool := true
  supportsRestartRequest : Bool := false
  supportsEvaluateForHovers : Bool := true
  supportsSetVariable : Bool := true
  supportsExceptionInfoRequest : Bool := true
  deriving Inhabited, Repr, FromJson, ToJson

/-- Default capability set. -/
def dapCapabilities : DapCapabilities := {}

/-- Custom Certior capabilities advertised via `initialize` response.
    These extend the standard DAP with verification-specific features. -/
structure CertiorCustomCapabilities where
  supportsFlowBreakpoints : Bool := true
  supportsBudgetBreakpoint : Bool := true
  supportsCapabilityWatch : Bool := true
  supportsCertificateInspection : Bool := true
  supportsFlowGraph : Bool := true
  supportsComplianceExport : Bool := true
  deriving Inhabited, Repr, FromJson, ToJson

/-- Default Certior custom capabilities (all enabled). -/
def certiorCapabilities : CertiorCustomCapabilities := {}

end CertiorPlan.DAP

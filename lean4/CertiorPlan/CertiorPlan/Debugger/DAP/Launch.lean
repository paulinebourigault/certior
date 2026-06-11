/-
  CertiorPlan.Debugger.DAP.Launch - PlanInfo Decoder for DAP

  Decodes PlanInfo from the JSON payload in DAP `launch` requests.
  Analogous to ImpLab's `DAP/Launch.lean` which decodes ProgramInfo.

  The launch request provides PlanInfo either:
  1. Inline as `arguments.planInfo` JSON object
  2. Pre-exported to `.dap/planInfo.generated.json` (resolved by extension)

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import Lean
import CertiorPlan.Ast

open Lean

namespace CertiorPlan.DAP

/-- Decode and validate a PlanInfo from a JSON value.
    Returns the validated PlanInfo or an error message. -/
def decodePlanInfoJson (json : Json) : Except String PlanInfo :=
  match (fromJson? json : Except String PlanInfo) with
  | .ok planInfo =>
    planInfo.validate
  | .error err =>
    throw s!"Invalid 'planInfo' payload: {err}"

/-- Extract compliance policy from launch arguments. -/
def extractCompliancePolicy? (args : Json) : Option String :=
  (args.getObjValAs? String "compliancePolicy").toOption

/-- Extract capability tokens from launch arguments. -/
def extractCapabilityTokens (args : Json) : Array String :=
  match (args.getObjVal? "capabilityTokens").toOption with
  | none => #[]
  | some tokensJson =>
    match tokensJson.getArr?.toOption with
    | none => #[]
    | some arr =>
      arr.foldl (init := #[]) fun acc item =>
        match (fromJson? item : Except String String) with
        | .ok s => acc.push s
        | .error _ => acc

end CertiorPlan.DAP

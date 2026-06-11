/-
  CertiorPlan.Debugger.DAP.Resolve - Plan Declaration Resolution

  Resolves plan declarations by name. Simpler than ImpLab's
  `DAP/Resolve.lean` which does full Lean environment introspection -
  we resolve from built-in plans or JSON files instead.

  Resolution order:
  1. Exact name match in built-in plans
  2. JSON file at `.dap/planInfo.generated.json`
  3. JSON file at specified path

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import Lean
import CertiorPlan.Ast
import CertiorPlan.Debugger.DAP.Launch

open Lean

namespace CertiorPlan.DAP

/-- Parse a dot-separated declaration name.
    Follows ImpLab's pattern for name resolution. -/
def parseDeclName? (raw : String) : Option Name :=
  let parts := raw.toSubstring.trim.toString.splitOn "." |>.filter (· != "")
  match parts with
  | [] => none
  | _ =>
    some <| parts.foldl Name.str Name.anonymous

/-- Check if a name is unqualified (single component). -/
def isUnqualifiedName (n : Name) : Bool :=
  match n with
  | .str .anonymous _ => true
  | .num .anonymous _ => true
  | _ => false

/-- Generate candidate declaration names for resolution.
    Tries:
    1. The name as-is
    2. Main.<name>
    3. CertiorPlan.Examples.<name> -/
def candidateDeclNames
    (decl : Name)
    (moduleName? : Option Name := none) : Array Name :=
  let names := #[decl]
  let names :=
    match moduleName? with
    | some moduleName =>
      if moduleName == .anonymous then names
      else
        if names.contains (moduleName ++ decl) then names
        else names.push (moduleName ++ decl)
    | none => names
  if names.contains (`CertiorPlan.Examples ++ decl) then names
  else names.push (`CertiorPlan.Examples ++ decl)

/-- Render candidate names for error messages. -/
def renderCandidateDecls (candidates : Array Name) : String :=
  String.intercalate ", " <| candidates.toList.map (fun n => s!"'{n}'")

/-- Default generated plan info path (relative to workspace). -/
def defaultPlanInfoPath : System.FilePath :=
  System.FilePath.mk ".dap" / "planInfo.generated.json"

end CertiorPlan.DAP

/-
  CertiorPlan.Debugger.DAP.Export - DAP-Aware Plan Export

  Extends the base Export module with DAP-specific functionality:
  - Export PlanInfo to the `.dap/` directory for VS Code auto-discovery
  - Include source path mapping in the exported JSON
  - Generate launch.json configuration snippets

  Analogous to ImpLab's `DAP/Export.lean`.

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import Lean
import CertiorPlan.Ast
import CertiorPlan.Export
import CertiorPlan.Debugger.DAP.Resolve

open Lean
open CertiorPlan.Export

namespace CertiorPlan.DAP.Export

/-- CLI options for DAP export. -/
structure DapExportOptions where
  decl : String := "basic"
  out : System.FilePath := CertiorPlan.DAP.defaultPlanInfoPath
  pretty : Bool := true
  source? : Option String := none
  deriving Inhabited

/-- Usage text for the DAP export CLI. -/
def usage : String := String.intercalate "\n"
  [ "Usage: lake exe dap-export [--decl <n>] [--out <path>] [--compact]",
    "",
    "Export a PlanInfo for the Certior Plan DAP debugger.",
    "",
    "--decl must name a built-in plan (basic, hipaa, sox).",
    "",
    "Default: --decl basic --out .dap/planInfo.generated.json" ]

/-- Parse CLI arguments. -/
private def parseArgs : DapExportOptions → List String
    → Except String DapExportOptions
  | opts, [] => pure opts
  | opts, "--decl" :: value :: rest =>
    parseArgs { opts with decl := value } rest
  | opts, "--out" :: value :: rest =>
    parseArgs { opts with out := System.FilePath.mk value } rest
  | opts, "--source" :: value :: rest =>
    parseArgs { opts with source? := some value } rest
  | opts, "--compact" :: rest =>
    parseArgs { opts with pretty := false } rest
  | opts, "--pretty" :: rest =>
    parseArgs { opts with pretty := true } rest
  | _, "--decl" :: [] => throw "Missing value for --decl"
  | _, "--out" :: [] => throw "Missing value for --out"
  | _, "--source" :: [] => throw "Missing value for --source"
  | _, arg :: _ => throw s!"Unknown argument '{arg}'"

/-- Generate a VS Code launch.json configuration for this plan. -/
def generateLaunchConfig (planName : String) (sourcePath? : Option String)
    (planInfoPath : System.FilePath) : Json :=
  let base :=
    [ ("name", toJson s!"Certior Plan: {planName}"),
      ("type", toJson "certior-plan-dap"),
      ("request", toJson "launch"),
      ("stopOnEntry", toJson true) ]
  let withSource :=
    match sourcePath? with
    | some path => base ++ [("source", toJson path)]
    | none => base
  Json.mkObj <| withSource ++
    [("planInfoPath", toJson planInfoPath.toString)]

/-- Write JSON to a file, creating parent directories as needed. -/
private def writeJsonFile (output : System.FilePath)
    (content : String) : IO Unit := do
  if let some parent := output.parent then
    IO.FS.createDirAll parent
  IO.FS.writeFile output content

end CertiorPlan.DAP.Export

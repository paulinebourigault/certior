/-
  CertiorPlan Export CLI - `lake exe plan-export`

  Analogous to ImpLab's `app/ExportMain.lean`.
  Exports a PlanInfo as JSON for the Python bridge and DAP.

  Usage:
    lake exe plan-export --decl <declName>
    lake exe plan-export --file <inputFile.json> --validate
    lake exe plan-export --file <inputFile.json> --report --out <report.json>

  Options:
    --decl <name>    Export a Lean declaration of type `PlanInfo`
    --file <path>    Read a PlanInfo from a JSON file
    --validate       Validate and print validation report
    --report         Generate full execution report
    --out <path>     Write output to file (default: stdout)
    --compact        Use compact JSON (no pretty-printing)
    --run            Execute the plan and print result

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import CertiorPlan
import CertiorPlan.Dsl
import CertiorPlan.Export

open CertiorPlan
open CertiorPlan.Export

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Built-in Example Plans (for --decl demo)
-- ═══════════════════════════════════════════════════════════════════════

/-- Basic example plan for export demo. -/
def builtinBasicPlan : PlanInfo := plan%[
  resource planBudget := 1000 @Internal,

  main budget := 1000, compliance := "default", in {
    let x := 42 @Public,
    let data := 100 @Internal,
    let remaining := readResource planBudget @Internal,
    emit data
  }
]

/-- HIPAA example plan for export demo. -/
def builtinHipaaPlan : PlanInfo := plan%[
  resource planBudget := 5000 @Internal,
  resource patientToken := 1 @Sensitive ["PHI"],

  skill queryPatient(patientId)
      requires ["database:read:patient_data" (100)] := {
    let rawData := 1 @Sensitive ["PHI"],
    emit rawData
  },

  skill sendEmail(recipient, body)
      requires ["network:smtp:send"] := {
    let outbound := 1 @Public,
    emit outbound
  },

  main budget := 5000, compliance := "hipaa",
      tokens := ["cap-db-read"] in {
    let id := 12345 @Public,
    let patientData := invoke queryPatient(id) @Sensitive,
    let emailResult := invoke sendEmail(id, patientData) @Public,
    emit emailResult
  }
]

/-- SOX example plan for export demo. -/
def builtinSoxPlan : PlanInfo := plan%[
  resource planBudget := 8000 @Internal,

  skill queryEarnings()
      requires ["database:read:financial_data" (500)] := {
    let data := 1 @Restricted ["MNPI"],
    emit data
  },

  main budget := 8000, compliance := "sox", in {
    let earnings := invoke queryEarnings() @Restricted,
    let remaining := readResource planBudget @Internal,
    let report := 1 @Internal,
    requireApproval "MNPI data in output - requires compliance review",
    emit report
  }
]

/-- Lookup a built-in plan by name. -/
def lookupBuiltinPlan (name : String) : Option PlanInfo :=
  match name with
  | "basic"  => some builtinBasicPlan
  | "hipaa"  => some builtinHipaaPlan
  | "sox"    => some builtinSoxPlan
  | _        => none

-- ═══════════════════════════════════════════════════════════════════════
-- §2  CLI Argument Parsing
-- ═══════════════════════════════════════════════════════════════════════

structure ExportArgs where
  declName    : Option String := none
  inputFile   : Option String := none
  outputFile  : Option String := none
  validate    : Bool := false
  report      : Bool := false
  compact     : Bool := false
  run         : Bool := false
  help        : Bool := false
  listPlans   : Bool := false
  deriving Repr, Inhabited

private def parseArgs (args : List String) : ExportArgs :=
  let rec go : List String → ExportArgs → ExportArgs
    | [], acc => acc
    | "--decl" :: name :: rest, acc => go rest { acc with declName := some name }
    | "--file" :: path :: rest, acc => go rest { acc with inputFile := some path }
    | "--out" :: path :: rest, acc  => go rest { acc with outputFile := some path }
    | "--validate" :: rest, acc    => go rest { acc with validate := true }
    | "--report" :: rest, acc      => go rest { acc with report := true }
    | "--compact" :: rest, acc     => go rest { acc with compact := true }
    | "--run" :: rest, acc         => go rest { acc with run := true }
    | "--help" :: rest, acc        => go rest { acc with help := true }
    | "--list" :: rest, acc        => go rest { acc with listPlans := true }
    | _ :: rest, acc               => go rest acc
  go args {}

private def printHelp : IO Unit := do
  IO.println "Usage: lake exe plan-export [OPTIONS]"
  IO.println ""
  IO.println "Options:"
  IO.println "  --decl <name>    Export a built-in plan (basic, hipaa, sox)"
  IO.println "  --file <path>    Read PlanInfo from JSON file"
  IO.println "  --out <path>     Write output to file (default: stdout)"
  IO.println "  --validate       Print validation report"
  IO.println "  --report         Generate full execution report (JSON)"
  IO.println "  --compact        Use compact JSON"
  IO.println "  --run            Execute the plan and print result"
  IO.println "  --list           List available built-in plans"
  IO.println "  --help           Show this help message"

-- ═══════════════════════════════════════════════════════════════════════
-- §3  Main Entry Point
-- ═══════════════════════════════════════════════════════════════════════

def «main» (args : List String) : IO UInt32 := do
  let parsed := parseArgs args

  if parsed.help then
    printHelp
    return 0

  if parsed.listPlans then
    IO.println "Available built-in plans:"
    IO.println "  basic  - Simple data flow with budget tracking"
    IO.println "  hipaa  - HIPAA patient query with flow violation"
    IO.println "  sox    - SOX financial audit with approval halt"
    return 0

  -- Resolve PlanInfo from either --decl or --file
  let info ← match parsed.declName, parsed.inputFile with
    | some name, _ =>
      match lookupBuiltinPlan name with
      | some info => pure info
      | none =>
        IO.eprintln s!"error: unknown plan declaration '{name}'"
        IO.eprintln "  Available: basic, hipaa, sox"
        return 1
    | none, some path =>
      let result ← readJsonFile ⟨path⟩
      match result with
      | .ok info => pure info
      | .error msg =>
        IO.eprintln s!"error: {msg}"
        return 1
    | none, none =>
      IO.eprintln "error: specify --decl <name> or --file <path>"
      IO.eprintln "  Run with --help for usage"
      return 1

  -- Generate output based on mode
  let output ← do
    if parsed.validate then
      let report := validateDetailed info
      pure (prettyValidation report)
    else if parsed.report then
      pure (exportReport info)
    else if parsed.run then
      pure (prettyRunResult info.plan)
    else
      if parsed.compact then
        pure (exportJsonCompact info)
      else
        pure (exportJson info)

  -- Write output
  match parsed.outputFile with
  | some path => do
    IO.FS.writeFile ⟨path⟩ (output ++ "\n")
    IO.println s!"✓ Written to {path}"
  | none =>
    IO.println output

  return 0

import Lean

open Lean

structure DeclSummary where
  name : String
  kind : String
  theoremFamily : Option String := none
  dependencyModules : Array String := #[]
  deriving ToJson

structure ModuleSummary where
  name : String
  sourcePath : String
  imports : Array String
  declarations : Array DeclSummary
  sorryCount : Nat
  moduleFamily : Option String := none
  dependencyModules : Array String := #[]
  theoremFamilies : Array String := #[]
  deriving ToJson

structure BinarySummary where
  name : String
  rootModule : String
  runtimeCritical : Bool
  dependencyModules : Array String := #[]
  deriving ToJson

structure PackageSummary where
  schemaVersion : Nat
  package : String
  rootModule : String
  modules : Array ModuleSummary
  binaries : Array BinarySummary
  deriving ToJson

private def planModules : Array (String × String) := #[(
  "CertiorPlan.Ast", "CertiorPlan/Ast.lean"
), (
  "CertiorPlan.Dsl", "CertiorPlan/Dsl.lean"
), (
  "CertiorPlan.Eval", "CertiorPlan/Eval.lean"
), (
  "CertiorPlan.Export", "CertiorPlan/Export.lean"
), (
  "CertiorPlan.History", "CertiorPlan/History.lean"
), (
  "CertiorPlan.Trace", "CertiorPlan/Trace.lean"
), (
  "CertiorPlan.Debugger.Core", "CertiorPlan/Debugger/Core.lean"
), (
  "CertiorPlan.Debugger.Session", "CertiorPlan/Debugger/Session.lean"
), (
  "CertiorPlan.Debugger.DAP.Capabilities", "CertiorPlan/Debugger/DAP/Capabilities.lean"
), (
  "CertiorPlan.Debugger.DAP.Export", "CertiorPlan/Debugger/DAP/Export.lean"
), (
  "CertiorPlan.Debugger.DAP.Launch", "CertiorPlan/Debugger/DAP/Launch.lean"
), (
  "CertiorPlan.Debugger.DAP.Resolve", "CertiorPlan/Debugger/DAP/Resolve.lean"
), (
  "CertiorPlan.Debugger.DAP.Stdio", "CertiorPlan/Debugger/DAP/Stdio.lean"
), (
  "CertiorPlan.Debugger.Widget.Server", "CertiorPlan/Debugger/Widget/Server.lean"
), (
  "CertiorPlan.Debugger.Widget.Types", "CertiorPlan/Debugger/Widget/Types.lean"
), (
  "CertiorPlan.Debugger.Widget.UI", "CertiorPlan/Debugger/Widget/UI.lean"
)]

private def binaries : Array BinarySummary := #[(
  { name := "plan-export", rootModule := "app.ExportMain", runtimeCritical := false, dependencyModules := #["CertiorPlan.Export"] }
), (
  { name := "certior-dap", rootModule := "app.CertiorDap", runtimeCritical := false, dependencyModules := #["CertiorPlan.Debugger.Core", "CertiorPlan.Debugger.Session"] }
), (
  { name := "certior-flow-check", rootModule := "app.FlowCheck", runtimeCritical := true, dependencyModules := #["CertiorPlan.Eval", "CertiorPlan.Trace"] }
)]

private def pushUnique (items additions : Array String) : Array String :=
  additions.foldl (init := items) fun acc item =>
    if item.isEmpty || acc.contains item then acc else acc.push item

private def moduleFamilyFor (moduleName : String) : Option String :=
  if moduleName = "CertiorPlan.Ast" then some "ast"
  else if moduleName = "CertiorPlan.Dsl" then some "dsl"
  else if moduleName = "CertiorPlan.Eval" then some "eval"
  else if moduleName = "CertiorPlan.Export" then some "export"
  else if moduleName = "CertiorPlan.History" then some "history"
  else if moduleName = "CertiorPlan.Trace" then some "trace"
  else if moduleName.startsWith "CertiorPlan.Debugger.DAP." then some "debugger_dap"
  else if moduleName.startsWith "CertiorPlan.Debugger.Widget." then some "debugger_widget"
  else if moduleName.startsWith "CertiorPlan.Debugger." then some "debugger_core"
  else none

private def theoremFamilyFor (moduleName declKind declName : String) : Option String :=
  if declKind = "theorem" || declKind = "lemma" then
    match moduleFamilyFor moduleName with
    | some family => some family
    | none =>
      if declName.endsWith "Soundness" then some "soundness"
      else if declName.endsWith "Safety" then some "safety"
      else none
  else
    none

private def parseDecl? (line : String) : Option DeclSummary :=
  let trimmed := line.trim
  let patterns : Array (String × String) := #[("theorem ", "theorem"), ("lemma ", "lemma"), ("def ", "def"), ("abbrev ", "abbrev"), ("structure ", "structure"), ("class ", "class"), ("inductive ", "inductive")]
  patterns.foldl (init := none) fun acc pair =>
    match acc with
    | some decl => some decl
    | none =>
      if trimmed.startsWith pair.fst then
        let rest := trimmed.drop pair.fst.length
        let name := rest.takeWhile fun ch => !(ch.isWhitespace || ch = ':' || ch = '(' || ch = '{' || ch = '[')
        if name.isEmpty then none else some { name := name, kind := pair.snd }
      else
        none

private def importsFromLine (line : String) : Array String :=
  let trimmed := line.trim
  if trimmed.startsWith "import " then
    ((trimmed.drop 7).splitOn " ").foldl (init := #[]) fun acc part =>
      let item := part.trim
      if item.isEmpty then acc else acc.push item
  else
    #[]

private def summarizeModule (moduleName sourcePath : String) : IO ModuleSummary := do
  let content ← IO.FS.readFile ⟨sourcePath⟩
  let mut imports : Array String := #[]
  let mut declarations : Array DeclSummary := #[]
  let mut theoremFamilies : Array String := #[]
  let mut sorryCount := 0
  for line in content.splitOn "\n" do
    imports := pushUnique imports (importsFromLine line)
    match parseDecl? line with
    | some decl =>
      let theoremFamily := theoremFamilyFor moduleName decl.kind decl.name
      declarations := declarations.push {
        name := decl.name
        kind := decl.kind
        theoremFamily := theoremFamily
        dependencyModules := if decl.kind = "theorem" || decl.kind = "lemma" then imports else #[]
      }
      theoremFamilies := pushUnique theoremFamilies (match theoremFamily with | some family => #[family] | none => #[])
    | none => pure ()
    if (line.splitOn "sorry").length > 1 then
      sorryCount := sorryCount + 1
  return {
    name := moduleName
    sourcePath := sourcePath
    imports := imports
    declarations := declarations
    sorryCount := sorryCount
    moduleFamily := moduleFamilyFor moduleName
    dependencyModules := imports
    theoremFamilies := theoremFamilies
  }

private def render (summary : PackageSummary) : String :=
  Json.pretty (toJson summary)

def main (_args : List String) : IO UInt32 := do
  let mut modules : Array ModuleSummary := #[]
  for (moduleName, sourcePath) in planModules do
    modules := modules.push (← summarizeModule moduleName sourcePath)
  IO.println <| render {
    schemaVersion := 2
    package := "CertiorPlan"
    rootModule := "CertiorPlan"
    modules := modules
    binaries := binaries
  }
  return 0

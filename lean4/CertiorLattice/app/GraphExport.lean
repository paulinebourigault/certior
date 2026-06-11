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

structure PackageSummary where
  schemaVersion : Nat
  package : String
  rootModule : String
  modules : Array ModuleSummary
  binaries : Array Json := #[]
  deriving ToJson

private def latticeModules : Array (String × String) := #[(
  "Certior.Lattice", "Certior/Lattice.lean"
), (
  "Certior.Composition", "Certior/Composition.lean"
), (
  "Certior.Delegation", "Certior/Delegation.lean"
), (
  "Certior.Encoding", "Certior/Encoding.lean"
)]

private def pushUnique (items additions : Array String) : Array String :=
  additions.foldl (init := items) fun acc item =>
    if item.isEmpty || acc.contains item then acc else acc.push item

private def moduleFamilyFor (moduleName : String) : Option String :=
  if moduleName = "Certior.Lattice" then some "lattice"
  else if moduleName = "Certior.Composition" then some "composition"
  else if moduleName = "Certior.Delegation" then some "delegation"
  else if moduleName = "Certior.Encoding" then some "encoding"
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
  for (moduleName, sourcePath) in latticeModules do
    modules := modules.push (← summarizeModule moduleName sourcePath)
  IO.println <| render {
    schemaVersion := 2
    package := "CertiorLattice"
    rootModule := "Certior"
    modules := modules
  }
  return 0

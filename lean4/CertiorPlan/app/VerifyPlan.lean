import Lean
import CertiorPlan.Ast
import CertiorPlan.Eval

open Lean
open CertiorPlan

/--
  VerifyPlan - Stateless Plan Verification CLI
  Reads a JSON representation of a `VerifiedPlan` from stdin.
  Evaluates it via `runPlan`.
  Writes a VerificationResponse JSON to stdout.
-/
def main (args : List String) : IO UInt32 := do
  if args.length != 1 then
    IO.println "Usage: lake exe verify-plan <plan.json>"
    return 1

  let input ← IO.FS.readFile args[0]!

  let responseJson : Json ←
    match Json.parse input with
    | Except.error err =>
      pure <| Json.mkObj [
        ("allowed", Json.bool false),
        ("reason", Json.str s!"JSON Parse Error: {err}")
      ]
    | Except.ok json =>
      match fromJson? (α := VerifiedPlan) json with
      | Except.error err =>
        pure <| Json.mkObj [
          ("allowed", Json.bool false),
          ("reason", Json.str s!"AST Deserialization Error: {err}")
        ]
      | Except.ok plan =>
        match runPlan plan with
        | Except.ok _ =>
          pure <| Json.mkObj [
            ("allowed", Json.bool true),
            ("reason", Json.str "Lattice structural invariants hold.")
          ]
        | Except.error planErr =>
          pure <| Json.mkObj [
            ("allowed", Json.bool false),
            ("reason", Json.str s!"FlowCheck Violation: {toString planErr}")
          ]

  IO.println responseJson.compress
  return 0

import Lean
import Certior.Delegation

open Lean
open Certior.Delegation

structure DelegationRequest where
  parent_id : String
  parent_agent_id : String
  parent_permissions : List String
  parent_budget : Nat
  child_id : String
  child_agent_id : String
  child_permissions : List String
  child_budget : Nat
deriving Repr, FromJson, ToJson

def main (args : List String) : IO UInt32 := do
  if args.length != 1 then
    IO.println "Usage: lake exe verify-delegation <req.json>"
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
      match fromJson? (α := DelegationRequest) json with
      | Except.error err =>
        pure <| Json.mkObj [
          ("allowed", Json.bool false),
          ("reason", Json.str s!"AST Deserialization Error: {err}")
        ]
      | Except.ok req =>
        let parentToken : CapabilityToken := {
          id := req.parent_id,
          agent_id := req.parent_agent_id,
          permissions := req.parent_permissions,
          initial_budget := req.parent_budget,
          budget_remaining := req.parent_budget,
          parent_id := "root", delegation_depth := 0
        }
        match attenuate parentToken req.child_id req.child_agent_id req.child_permissions req.child_budget with
        | .ok child =>
          pure <| Json.mkObj [
            ("allowed", Json.bool true),
            ("reason", Json.str "Token delegation proven safe."),
            ("token_id", Json.str child.id)
          ]
        | .err errStr =>
          pure <| Json.mkObj [
            ("allowed", Json.bool false),
            ("reason", Json.str s!"Delegation Check Failure: {errStr}")
          ]

  IO.println responseJson.compress
  return 0

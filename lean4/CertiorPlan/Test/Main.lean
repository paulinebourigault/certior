/-
  CertiorPlan Test Suite - Entry Point

  Run: lake exe plan-tests
-/

import Test.Core

def «main» (_args : List String) : IO UInt32 := do
  IO.println "═══════════════════════════════════════════════════════════════"
  IO.println " CertiorPlan Test Suite"
  IO.println "═══════════════════════════════════════════════════════════════"
  IO.println ""
  IO.println "────────────────────────────────────────────────────────────"
  IO.println " Week A1: AST + Interpreter"
  IO.println "────────────────────────────────────────────────────────────"
  IO.println ""
  Test.Core.runAll
  IO.println ""
  IO.println "═══════════════════════════════════════════════════════════════"
  IO.println " Maintained core tests complete."
  IO.println "═══════════════════════════════════════════════════════════════"
  return 0

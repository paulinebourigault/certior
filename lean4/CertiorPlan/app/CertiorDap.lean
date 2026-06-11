/-
  CertiorDap - Verified Agent Plan DAP Server

  Entry point for the `certior-dap` binary. Runs the Debug Adapter
  Protocol server on stdin/stdout for VS Code integration.

  Build:  lake build certior-dap
  Run:    .lake/build/bin/certior-dap

  This binary is launched by the `certior-plan-dap` VS Code extension
  as a debug adapter executable.

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import CertiorPlan.Debugger.DAP.Stdio

def main : IO Unit :=
  CertiorPlan.DAP.run

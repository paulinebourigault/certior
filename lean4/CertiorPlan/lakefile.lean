/-
  CertiorPlan - Verified Agent Execution Kernel

  Depends on CertiorLattice for proven SecurityLevel lattice operations.
  Adapts ImpLab's interpreter/debugger architecture for verified agent plans.

  Build:  lake build
  Test:   lake exe plan-tests
-/
import Lake
open Lake DSL

package CertiorPlan where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

-- Local dependency on CertiorLattice (proven lattice proofs)
require CertiorLattice from "../CertiorLattice"

@[default_target]
lean_lib CertiorPlan where
  srcDir := "."
  roots := #[`CertiorPlan]

lean_lib «Test» where
  srcDir := "."
  -- Keep the build surface aligned with the maintained smoke-suite entrypoint.
  roots := #[`Test.Core, `Test.Main]

lean_lib «examples» where
  srcDir := "."
  roots := #[`examples]

lean_lib «app» where
  srcDir := "."
  roots := #[`app]

lean_exe «plan-tests» where
  root := `Test.Main

lean_exe «plan-export» where
  root := `app.ExportMain

lean_exe «certior-dap» where
  root := `app.CertiorDap

lean_exe «certior-flow-check» where
  root := `app.FlowCheck

lean_exe «certior-plan-graph-export» where
  root := `app.GraphExport

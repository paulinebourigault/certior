import Lake
open Lake DSL

package CertiorLattice where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib Certior where
  srcDir := "."
  roots := #[`Certior]

lean_lib «app» where
  srcDir := "."
  roots := #[`app]

lean_exe «certior-lattice-graph-export» where
  root := `app.GraphExport

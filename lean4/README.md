# Certior Lean4 - Formal Verification & Verified Execution

## Overview

Two Lean4 packages forming Certior's formal verification backbone:

### CertiorLattice - Proofs
Mathematical guarantees: SecurityLevel is a bounded distributive lattice (P13–P21, absorption, distributivity). Multi-step flow composition, capability delegation, and IFC soundness.

### CertiorPlan - Verified Execution Kernel
A verify-before-step interpreter for AI agent plans. **Uses the proven `levelCanFlowTo` from CertiorLattice as the actual runtime flow check.** Architecture adapted from [ImpLab](https://github.com/leanprover/imp-lab) (Lean FRO).

## The Key Innovation

CertiorPlan imports CertiorLattice and uses proven predicates as runtime safety:

```
CertiorLattice (proofs)  →  import  →  CertiorPlan (execution)
                                         │
                                         Every bind step:
                                         1. Resolve input flow labels
                                         2. flowAllowed = decide(levelCanFlowTo src dst)
                                            ↑ THIS IS THE PROVEN PREDICATE
                                         3. Execute only if all flows pass
                                         4. Issue proof certificate
```

## Build

```bash
# Install Lean4 v4.14.0
elan default leanprover/lean4:v4.14.0

# Build + test
cd CertiorLattice && lake build
cd ../CertiorPlan && lake build && lake exe plan-tests

# Python bridge tests
python tests/test_lean_bridge.py
```

## Structure

```
CertiorLattice/       # Proofs: lattice, composition, delegation, encoding
CertiorPlan/          # Execution kernel
  CertiorPlan/Ast.lean    # Plan AST, JSON serialization, source mapping
  CertiorPlan/Eval.lean   # Verify-before-step interpreter
  CertiorPlan/History.lean # Time-travel cursor (from ImpLab)
  CertiorPlan/Trace.lean  # Execution trace + explorer
  Test/Core.lean          # 40+ tests
  examples/Main.lean      # HIPAA, SOX, basic demo plans
```

## Python Bridge

```python
from agentsafe.verification.lean_bridge import PlanInfoBuilder

builder = PlanInfoBuilder(compliance_policy="hipaa", budget_cents=5000)
builder.add_main_step(builder.bind("id", builder.literal(123), level="Public"))
builder.add_main_step(builder.invoke_and_bind("data", "query", ["id"], level="Sensitive"))
builder.add_main_step(builder.emit("data"))
plan_json = builder.to_json()  # JSON for Lean4 kernel
```

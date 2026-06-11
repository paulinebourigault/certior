import Certior
import Lean

/-!
# Axiom audit - the "no holes" gate (Mathlib-style)

A theorem can typecheck while secretly resting on `sorryAx` (an unfinished
proof) or some bespoke `axiom`. `#print axioms` reveals that; Mathlib enforces
it in CI. This module does the same as a HARD build failure: elaborating it
checks that every headline guarantee depends only on Lean's standard trusted
axioms. If any guarantee uses `sorryAx` or an untrusted axiom, `lake build`
fails here - so "machine-checked" cannot silently rot.

Build it with `lake build Certior.Audit` (CI does this).
-/

open Lean Elab Command

namespace Certior.Audit

/-- Lean's standard classical foundation. Anything outside this - above all
    `sorryAx` - means a "proven" guarantee is not actually proven. -/
def trusted : List Name := [``propext, ``Classical.choice, ``Quot.sound]

/-- The headline guarantees the product's claims rest on. Add new top-level
    soundness/safety bundles here as the policy model grows. -/
def guarantees : List Name :=
  [``Certior.Delegation.delegationSafety,
   ``Certior.Encoding.ifcSoundness,
   ``Certior.Composition.compositionSoundness,
   ``SecurityLevel.isValidBoundedLattice]

run_cmd do
  for g in Certior.Audit.guarantees do
    let axs ← collectAxioms g
    for a in axs do
      unless Certior.Audit.trusted.contains a do
        throwError m!"AXIOM AUDIT FAILED: `{g}` depends on untrusted axiom `{a}` \
          (a `sorryAx` here means an unfinished proof)."
    logInfo m!"✓ {g} - axioms: {axs.toList}"
  logInfo m!"✓ Axiom audit passed: {Certior.Audit.guarantees.length} guarantees depend only on trusted axioms."

end Certior.Audit

/-
  CertiorPlan.History - Generic Time-Travel History

  Direct adaptation of ImpLab's `Lang/History.lean`.
  Provides cursor-based navigation over an array of states,
  enabling time-travel debugging for verified agent plans.

  The compliance officer can rewind to any execution point
  and inspect capabilities, flow labels, budget, and certificates.

  Copyright (c) 2026 Lean FRO LLC. All rights reserved.
  Released under Apache 2.0 license as described in the file LICENSE.
  Original Author: Emilio J. Gallego Arias
  Adapted for CertiorPlan.
-/

namespace CertiorPlan.History

/-- Maximum valid cursor index (0-based). -/
def maxCursor {α : Type} (items : Array α) : Nat :=
  items.size - 1

/-- Clamp cursor to valid range. -/
def normalizeCursor {α : Type} (items : Array α) (cursor : Nat) : Nat :=
  min cursor (maxCursor items)

/-- Get item at cursor position (clamped). -/
def current? {α : Type} (items : Array α) (cursor : Nat) : Option α :=
  items[normalizeCursor items cursor]?

/-- Can we move backward from this cursor? -/
def hasPrev {α : Type} (_items : Array α) (cursor : Nat) : Bool :=
  cursor > 0

/-- Can we move forward from this cursor? -/
def hasNext {α : Type} (items : Array α) (cursor : Nat) : Bool :=
  let cursor := normalizeCursor items cursor
  cursor + 1 < items.size

/-- Move cursor one position backward (clamped at 0). -/
def backCursor {α : Type} (items : Array α) (cursor : Nat) : Nat :=
  let cursor := normalizeCursor items cursor
  if hasPrev items cursor then
    cursor - 1
  else
    cursor

/-- Move cursor one position forward (clamped at end). -/
def forwardCursor {α : Type} (items : Array α) (cursor : Nat) : Nat :=
  if hasNext items cursor then
    normalizeCursor items cursor + 1
  else
    normalizeCursor items cursor

/-- Jump cursor to an arbitrary position (clamped). -/
def jumpCursor {α : Type} (items : Array α) (cursor : Nat) : Nat :=
  normalizeCursor items cursor

end CertiorPlan.History

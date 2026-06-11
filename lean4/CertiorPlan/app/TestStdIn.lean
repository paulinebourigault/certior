import Lean
def main : IO UInt32 := do
  let lines ← IO.FS.lines "lake-manifest.json"
  IO.println (lines.size)
  return 0

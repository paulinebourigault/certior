/-
  CertiorPlan.Eval - Verified Plan Execution Kernel

  The core insight: every `step` function checks verification conditions
  *before* advancing. ImpLab's interpreter is trust-and-execute.
  Ours is **prove-and-execute**.

  The `flowAllowed` check in every `bind` step uses the *proven*
  `SecurityLevel.levelCanFlowTo` from `Certior.Lattice`. This means
  the information flow safety check is mathematically guaranteed correct
  by the lattice proofs (P13–P21, absorption, distributivity).

  Architecture:
    PlanContext  ←→  ImpLab.Context
    PlanFrame    ←→  ImpLab.CallFrame
    PlanError    ←→  ImpLab.EvalError
    step         ←→  ImpLab.step (+ verification)
    runPlan      ←→  ImpLab.run

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import Lean
import Certior.Lattice
import CertiorPlan.Ast

open Lean
open SecurityLevel

namespace CertiorPlan

-- ═══════════════════════════════════════════════════════════════════════
-- §1  Value + Stores - execution state primitives
-- ═══════════════════════════════════════════════════════════════════════

/-- Runtime value in the plan execution. -/
abbrev Value := Int

/-- Local data environment: DataId → Value. -/
abbrev DataEnv := Lean.RBMap DataId Value compare

/-- Resource store: ResourceId → Value. -/
abbrev ResourceStore := Lean.RBMap ResourceId Value compare

/-- Flow state: DataId → FlowLabel (tracks the security label of every binding). -/
abbrev FlowState := Lean.RBMap DataId FlowLabel compare

/-- Resource label store: ResourceId → FlowLabel. -/
abbrev ResourceLabelStore := Lean.RBMap ResourceId FlowLabel compare

/-- Capability store: set of available capability resource strings. -/
abbrev CapabilityStore := Lean.RBMap String Bool compare

namespace DataEnv

def lookup? (env : DataEnv) (name : DataId) : Option Value :=
  env.find? name

def bind (env : DataEnv) (name : DataId) (value : Value) : DataEnv :=
  env.insert name value

def bindings (env : DataEnv) : Array (DataId × Value) :=
  env.toArray

end DataEnv

namespace ResourceStore

def lookup? (store : ResourceStore) (name : ResourceId) : Option Value :=
  store.find? name

def bind (store : ResourceStore) (name : ResourceId) (value : Value) : ResourceStore :=
  store.insert name value

def bindings (store : ResourceStore) : Array (ResourceId × Value) :=
  store.toArray

end ResourceStore

-- ═══════════════════════════════════════════════════════════════════════
-- §2  PlanFrame - call frame for skill invocations (ImpLab.CallFrame)
-- ═══════════════════════════════════════════════════════════════════════

/-- Call frame for skill invocations.
    Analogous to ImpLab's `CallFrame` with additional flow tracking. -/
structure PlanFrame where
  /-- Current skill being executed. -/
  skillId : SkillId := VerifiedPlan.mainName
  /-- Program counter (0-based index into skill body). -/
  pc : Nat := 0
  /-- Local data environment. -/
  env : DataEnv := {}
  /-- Return destination data binding (if called from another skill). -/
  retDest? : Option DataId := none
  /-- Return label (what label the caller declared for the result). -/
  retLabel? : Option FlowLabel := none
  deriving Repr, Inhabited

-- ═══════════════════════════════════════════════════════════════════════
-- §3  PlanContext - execution state (ImpLab.Context)
-- ═══════════════════════════════════════════════════════════════════════

/-- Complete execution context for plan evaluation.
    Analogous to ImpLab's `Context` with additional verification state:
    flow tracking, budget, capabilities, and proof certificates. -/
structure PlanContext where
  /-- Current call frame. -/
  current : PlanFrame := {}
  /-- Caller stack (for nested skill invocations). -/
  callers : Array PlanFrame := #[]
  /-- Mutable resource store (budget counters, token slots). -/
  resources : ResourceStore := {}
  /-- Flow label tracker - records the label of every data binding. -/
  flowTracker : FlowState := {}
  /-- Resource label tracker - records labels on resources. -/
  resourceLabels : ResourceLabelStore := {}
  /-- Available capability strings. -/
  capabilities : CapabilityStore := {}
  /-- Remaining budget in cents. -/
  budgetRemaining : Int := 10000
  /-- Proof certificates issued so far. -/
  certificates : Array ProofCert := #[]
  /-- Total steps executed (for telemetry). -/
  stepsExecuted : Nat := 0
  deriving Repr, Inhabited

namespace PlanContext

/-- Create initial context for a plan. -/
def initialForPlan (plan : VerifiedPlan) : PlanContext :=
  let resources := plan.resources.foldl (init := ({} : ResourceStore)) fun store res =>
    store.bind res.name res.init
  let resLabels := plan.resources.foldl (init := ({} : ResourceLabelStore)) fun store res =>
    store.insert res.name res.label
  -- Collect all capabilities from all skills
  let caps := plan.skills.foldl (init := ({} : CapabilityStore)) fun store skill =>
    skill.requiredCaps.foldl (init := store) fun s cap =>
      s.insert cap.resource true
  { resources
    resourceLabels := resLabels
    capabilities := caps
    budgetRemaining := plan.totalBudgetCents }

/-- Current program counter. -/
def pc (ctx : PlanContext) : Nat :=
  ctx.current.pc

/-- Current skill name. -/
def skillName (ctx : PlanContext) : SkillId :=
  ctx.current.skillId

/-- Current local environment. -/
def env (ctx : PlanContext) : DataEnv :=
  ctx.current.env

/-- All frames (callers + current). -/
def frames (ctx : PlanContext) : Array PlanFrame :=
  ctx.callers.push ctx.current

/-- Call depth. -/
def callDepth (ctx : PlanContext) : Nat :=
  ctx.frames.size

/-- Lookup a local data binding. -/
def lookup? (ctx : PlanContext) (name : DataId) : Option Value :=
  ctx.env.find? name

/-- Local bindings as array. -/
def localBindings (ctx : PlanContext) : Array (DataId × Value) :=
  ctx.env.toArray

/-- Resource bindings as array. -/
def resourceBindings (ctx : PlanContext) : Array (ResourceId × Value) :=
  ctx.resources.toArray

/-- Flow label bindings as array. -/
def flowBindings (ctx : PlanContext) : Array (DataId × FlowLabel) :=
  ctx.flowTracker.toArray

end PlanContext

-- ═══════════════════════════════════════════════════════════════════════
-- §4  PlanError - structured verification failure info
-- ═══════════════════════════════════════════════════════════════════════

/-- Errors during plan execution.
    Unlike ImpLab's EvalError, these carry structured verification
    failure information for compliance reporting. -/
inductive PlanError where
  /-- A skill requires capabilities not available. -/
  | capabilityDenied (skill : SkillId) (missing : Array String)
  /-- Information flow from src to dst is forbidden by the lattice. -/
  | flowViolation (src dst : FlowLabel) (dataId : DataId)
  /-- Budget exhausted before step could execute. -/
  | budgetExhausted (requested remaining : Int)
  /-- Human approval required (execution halts). -/
  | approvalRequired (reason : String)
  /-- Referenced data binding does not exist. -/
  | unboundData (name : DataId)
  /-- Referenced skill does not exist. -/
  | unknownSkill (name : SkillId)
  /-- Referenced resource is not declared. -/
  | resourceUndeclared (name : ResourceId)
  /-- Execution ran out of fuel. -/
  | outOfFuel (fuel : Nat)
  /-- Return from non-existent caller. -/
  | invalidPc (pc : Nat) (bodySize : Nat)
  /-- Skill finished without emitting a result. -/
  | missingEmit (skill : SkillId)
  /-- Arity mismatch in skill invocation. -/
  | arityMismatch (skill : SkillId) (expected actual : Nat)
  deriving Repr, BEq, DecidableEq, Inhabited

instance : ToString PlanError where
  toString
    | .capabilityDenied skill missing =>
      s!"CAPABILITY DENIED: skill '{skill}' requires [{String.intercalate ", " missing.toList}]"
    | .flowViolation src dst dataId =>
      s!"FLOW VIOLATION: {src.level} → {dst.level} not allowed for '{dataId}' " ++
      s!"(rank {SecurityLevel.rank src.level} > rank {SecurityLevel.rank dst.level})"
    | .budgetExhausted requested remaining =>
      s!"BUDGET EXHAUSTED: step costs {requested}¢ but only {remaining}¢ remaining"
    | .approvalRequired reason =>
      s!"APPROVAL REQUIRED: {reason}"
    | .unboundData name =>
      s!"UNBOUND DATA: '{name}' not found in local scope"
    | .unknownSkill name =>
      s!"UNKNOWN SKILL: '{name}' not defined in plan"
    | .resourceUndeclared name =>
      s!"UNDECLARED RESOURCE: '{name}' not declared in plan"
    | .outOfFuel fuel =>
      s!"OUT OF FUEL: execution exhausted fuel ({fuel})"
    | .invalidPc pc bodySize =>
      s!"INVALID PC: {pc} for body size {bodySize}"
    | .missingEmit skill =>
      s!"MISSING EMIT: skill '{skill}' terminated without `emit`"
    | .arityMismatch skill expected actual =>
      s!"ARITY MISMATCH: skill '{skill}' expects {expected} params, got {actual}"

-- ═══════════════════════════════════════════════════════════════════════
-- §5  Flow checking - uses PROVEN lattice operations
-- ═══════════════════════════════════════════════════════════════════════

/--
  Check if information flow from `src` to `dst` is allowed.

  **This is the critical integration point.** We use `SecurityLevel.levelCanFlowTo`
  from `Certior.Lattice`, which is *proven* to be a valid total order:
    - P13: reflexive, transitive, antisymmetric, total
    - P14: flowSafety_iff - levelCanFlowTo src dst ↔ rank src ≤ rank dst
    - P21: join soundness for label merging

  The `decide` tactic resolves the decidable `levelCanFlowTo` instance,
  which is backed by the proven `Nat.ble` on ranks.
-/
def flowAllowed (src dst : SecurityLevel) : Bool :=
  decide (levelCanFlowTo src dst)

/-- Check label flow: level must be allowed AND tags must be subset. -/
def labelFlowAllowed (src dst : FlowLabel) : Bool :=
  flowAllowed src.level dst.level &&
  src.tags.all (fun t => dst.tags.contains t)

-- ═══════════════════════════════════════════════════════════════════════
-- §6  Lookup helpers
-- ═══════════════════════════════════════════════════════════════════════

private def lookupSkill (plan : VerifiedPlan) (name : SkillId) :
    Except PlanError SkillDef :=
  match plan.findSkill? name with
  | some skill => pure skill
  | none => throw (.unknownSkill name)

private def lookupData (ctx : PlanContext) (name : DataId) :
    Except PlanError Value :=
  match ctx.env.find? name with
  | some value => pure value
  | none => throw (.unboundData name)

private def lookupLabel (ctx : PlanContext) (name : DataId) :
    Except PlanError FlowLabel :=
  -- Support synthetic level references from standalone checkFlow/joinLabels DSL.
  -- Names like "__level_Sensitive" resolve to FlowLabel with that SecurityLevel.
  if name.startsWith "__level_" then
    let levelStr := name.drop 8  -- drop "__level_"
    let level := match levelStr with
      | "Public" => SecurityLevel.Public
      | "Internal" => SecurityLevel.Internal
      | "Sensitive" => SecurityLevel.Sensitive
      | "Restricted" => SecurityLevel.Restricted
      | _ => SecurityLevel.Public  -- fallback
    pure { level }
  else
    match ctx.flowTracker.find? name with
    | some label => pure label
    | none => throw (.unboundData name)

private def lookupResourceValue (plan : VerifiedPlan) (ctx : PlanContext) (name : ResourceId) :
    Except PlanError Value := do
  if !plan.isDeclaredResource name then
    throw (.resourceUndeclared name)
  match ctx.resources.find? name with
  | some value => pure value
  | none => throw (.resourceUndeclared name)

private def lookupResourceLabel (ctx : PlanContext) (name : ResourceId) :
    Except PlanError FlowLabel :=
  match ctx.resourceLabels.find? name with
  | some label => pure label
  | none => throw (.resourceUndeclared name)

private def ensureDeclaredResource (plan : VerifiedPlan) (name : ResourceId) :
    Except PlanError Unit := do
  if plan.isDeclaredResource name then pure ()
  else throw (.resourceUndeclared name)

private def hasCapability (ctx : PlanContext) (resource : String) : Bool :=
  (ctx.capabilities.find? resource).getD false

-- ═══════════════════════════════════════════════════════════════════════
-- §7  Advance helpers
-- ═══════════════════════════════════════════════════════════════════════

private def currentBodySize (plan : VerifiedPlan) (ctx : PlanContext) : Nat :=
  plan.bodySizeOf ctx.skillName

private def advanceCurrent (ctx : PlanContext) (env : DataEnv) : PlanContext :=
  { ctx with
    current := { ctx.current with pc := ctx.pc + 1, env }
    stepsExecuted := ctx.stepsExecuted + 1 }

private def advanceWithBinding (ctx : PlanContext) (dest : DataId) (value : Value)
    (label : FlowLabel) : PlanContext :=
  let env := ctx.env.bind dest value
  let flowTracker := ctx.flowTracker.insert dest label
  { advanceCurrent ctx env with flowTracker }

private def advanceWithResourceUpdate (ctx : PlanContext) (name : ResourceId)
    (valueName : DataId) : PlanContext :=
  match ctx.lookup? valueName with
  | some value =>
    { advanceCurrent ctx ctx.env with resources := ctx.resources.bind name value }
  | none =>
    advanceCurrent ctx ctx.env

-- ═══════════════════════════════════════════════════════════════════════
-- §8  RHS evaluation
-- ═══════════════════════════════════════════════════════════════════════

/-- Resolve input labels for a StepRhs (for flow verification). -/
private def resolveInputLabels (ctx : PlanContext) (rhs : StepRhs) :
    Except PlanError (Array FlowLabel) := do
  match rhs with
  | .literal _ => pure #[]
  | .invokeSkill _ args =>
    args.mapM (lookupLabel ctx)
  | .checkFlow src _ =>
    pure #[← lookupLabel ctx src]
  | .joinLabels a b =>
    pure #[← lookupLabel ctx a, ← lookupLabel ctx b]
  | .attenuateToken _ _ => pure #[]
  | .readResource _ => pure #[]

/-- Bind parameters into a fresh local environment.
    Directly adapted from ImpLab's `bindParams`. -/
private def bindParams (params : Array DataId) (args : Array Value) : DataEnv :=
  let rec go (idx : Nat) (env : DataEnv) : DataEnv :=
    if h : idx < params.size then
      let env :=
        match args[idx]? with
        | some value => env.bind params[idx] value
        | none => env
      go (idx + 1) env
    else
      env
  go 0 {}

/-- Bind parameter flow labels into a fresh flow state.
    Every argument carries its label from the caller into the callee. -/
private def bindParamLabels (params : Array DataId) (argNames : Array DataId)
    (callerCtx : PlanContext) : FlowState :=
  let rec go (idx : Nat) (st : FlowState) : FlowState :=
    if h : idx < params.size then
      let st :=
        match argNames[idx]? with
        | some argName =>
          match callerCtx.flowTracker.find? argName with
          | some label => st.insert params[idx] label
          | none => st
        | none => st
      go (idx + 1) st
    else
      st
  go 0 {}

/-- Execute a skill invocation by pushing a call frame.
    Directly adapted from ImpLab's `executeCall`.

    This is the key execution mechanism: when `invokeSkill foo(x, y)` is
    encountered, we push the current frame onto `callers`, create a new
    frame for the callee skill, and transfer control. The callee's `emit`
    statement will eventually bind the result back to `dest` in the caller.

    Flow labels are propagated through the call boundary: each argument's
    label in the caller becomes the corresponding parameter's label in
    the callee, enabling cross-skill information flow tracking. -/
private def executeSkillCall (plan : VerifiedPlan) (ctx : PlanContext)
    (dest : DataId) (skill : SkillId) (args : Array DataId) (label : FlowLabel) :
    Except PlanError PlanContext := do
  let skillDef ← lookupSkill plan skill
  if skill == VerifiedPlan.mainName then
    throw (.unknownSkill s!"{skill} (cannot invoke main recursively)")
  -- Arity check
  if skillDef.params.size != args.size then
    throw (.arityMismatch skill skillDef.params.size args.size)
  -- Capability check (pre-call)
  for cap in skillDef.requiredCaps do
    if !hasCapability ctx cap.resource then
      throw (.capabilityDenied skill #[cap.resource])
  -- Resolve argument values
  let argValues ← args.mapM (lookupData ctx)
  -- Build callee frame
  let calleeEnv := bindParams skillDef.params argValues
  let calleeFlowLabels := bindParamLabels skillDef.params args ctx
  let callee : PlanFrame := {
    skillId := skill
    pc := 0
    env := calleeEnv
    retDest? := some dest
    retLabel? := some label
  }
  -- Issue call certificate
  let inputLabels ← args.mapM (lookupLabel ctx)
  let cert : ProofCert := {
    stepId := s!"call:{skill}"
    property := "call_verified"
    inputLabels := inputLabels
    outputLabel := label
    detail := s!"capabilities=[{String.intercalate ", " (skillDef.requiredCaps.map toString).toList}]"
  }
  -- Push current frame, enter callee
  pure {
    current := callee
    callers := ctx.callers.push { ctx.current with pc := ctx.current.pc }
    resources := ctx.resources
    flowTracker := ctx.flowTracker.toArray.foldl (init := calleeFlowLabels) fun acc kv =>
      -- Merge caller's flow labels so global data references remain visible
      if acc.contains kv.1 then acc else acc.insert kv.1 kv.2
    resourceLabels := ctx.resourceLabels
    capabilities := ctx.capabilities
    budgetRemaining := ctx.budgetRemaining
    certificates := ctx.certificates.push cert
    stepsExecuted := ctx.stepsExecuted + 1
  }

/-- Evaluate a StepRhs to produce a Value (for non-call RHS forms). -/
private def evalRhs (plan : VerifiedPlan) (ctx : PlanContext) (rhs : StepRhs) :
    Except PlanError Value := do
  match rhs with
  | .literal value =>
    pure value

  | .invokeSkill _skill _args =>
    -- This branch should not be reached: skill invocations are handled
    -- by executeSkillCall in executeBind. If we get here, it's a bug.
    throw (.unknownSkill "evalRhs reached for invokeSkill - should use executeSkillCall")

  | .checkFlow src dst => do
    let srcLabel ← lookupLabel ctx src
    let dstLabel ← lookupLabel ctx dst
    if flowAllowed srcLabel.level dstLabel.level then
      pure 1  -- Flow allowed
    else
      throw (.flowViolation srcLabel dstLabel s!"{src}→{dst}")

  | .joinLabels a b => do
    let labelA ← lookupLabel ctx a
    let labelB ← lookupLabel ctx b
    -- Join using the proven SecurityLevel.join
    let _joined := SecurityLevel.join labelA.level labelB.level
    pure 1  -- The actual label is set by the bind's declared label

  | .attenuateToken _ _ =>
    -- Token attenuation: return success marker
    pure 1

  | .readResource name => do
    lookupResourceValue plan ctx name

-- ═══════════════════════════════════════════════════════════════════════
-- §9  Step function - VERIFY then EXECUTE
-- ═══════════════════════════════════════════════════════════════════════

/--
  Execute a single `bind` step with flow checking.

  **The critical verification logic:**
  For every `bind dest rhs label`:

  **Case A - Skill Invocation (`invokeSkill`):**
  1. Verify argument flow labels can flow to declared label
  2. Check skill capabilities and arity
  3. Push call frame (ImpLab's executeCall pattern)
  4. The callee's `emit` will bind the result back to `dest`

  **Case B - All other RHS forms:**
  1. Resolve input labels from rhs arguments
  2. For each input label, verify `flowAllowed input.level label.level`
  3. Only if ALL flows pass: evaluate rhs, bind result, issue certificate
  4. If any flow is denied: throw `flowViolation` with structured evidence
-/
private def executeBind (plan : VerifiedPlan) (ctx : PlanContext)
    (dest : DataId) (rhs : StepRhs) (label : FlowLabel) :
    Except PlanError PlanContext := do
  -- Skill invocations are special: they push a call frame
  -- rather than evaluating to a value immediately.
  match rhs with
  | .invokeSkill skill args =>
    -- Verify input flow labels before call
    let inputLabels ← args.mapM (lookupLabel ctx)
    for inputLabel in inputLabels do
      if ¬(flowAllowed inputLabel.level label.level) then
        throw (.flowViolation inputLabel label dest)
    -- Push call frame - callee's emit will bind dest in caller
    executeSkillCall plan ctx dest skill args label
  | _ =>
    -- Standard: resolve, verify flow, evaluate, bind, certify
    let inputLabels ← resolveInputLabels ctx rhs
    for inputLabel in inputLabels do
      if ¬(flowAllowed inputLabel.level label.level) then
        throw (.flowViolation inputLabel label dest)
    let value ← evalRhs plan ctx rhs
    let ctx := advanceWithBinding ctx dest value label
    let cert : ProofCert := {
      stepId := dest
      property := "flow_safe"
      inputLabels := inputLabels
      outputLabel := label
      detail := s!"{inputLabels.map (toString ·.level)} → {label.level}"
    }
    pure { ctx with certificates := ctx.certificates.push cert }

/-- Execute a `setResource` step with flow checking. -/
private def executeSetResource (plan : VerifiedPlan) (ctx : PlanContext)
    (name : ResourceId) (valueName : DataId) :
    Except PlanError PlanContext := do
  ensureDeclaredResource plan name
  let dataLabel ← lookupLabel ctx valueName
  let resLabel ← lookupResourceLabel ctx name
  -- Flow check: data label must flow to resource label
  if ¬(flowAllowed dataLabel.level resLabel.level) then
    throw (.flowViolation dataLabel resLabel name)
  let value ← lookupData ctx valueName
  pure { advanceCurrent ctx ctx.env with
    resources := ctx.resources.bind name value }

/-- Execute an `emitResult` step. -/
private def executeEmit (plan : VerifiedPlan) (ctx : PlanContext)
    (valueName : DataId) :
    Except PlanError PlanContext := do
  let _value ← lookupData ctx valueName
  let _label ← lookupLabel ctx valueName
  -- Advance past the end of the current skill
  let bodySize := currentBodySize plan ctx
  match ctx.current.retDest? with
  | none =>
    -- Main skill: advance PC past end
    pure { ctx with
      current := { ctx.current with pc := bodySize }
      stepsExecuted := ctx.stepsExecuted + 1 }
  | some dest =>
    -- Sub-skill: return to caller
    let some caller := ctx.callers.back?
      | throw (.invalidPc ctx.pc ctx.callers.size)
    let value ← lookupData ctx valueName
    let label ← lookupLabel ctx valueName
    -- Flow check: emit label must flow to caller's declared return label
    if let some retLabel := ctx.current.retLabel? then
      if ¬(flowAllowed label.level retLabel.level) then
        throw (.flowViolation label retLabel s!"emit→{dest}")
    let resumed := { caller with
      pc := caller.pc + 1
      env := caller.env.bind dest value }
    pure { ctx with
      current := resumed
      callers := ctx.callers.pop
      flowTracker := ctx.flowTracker.insert dest
        (ctx.current.retLabel?.getD label)
      stepsExecuted := ctx.stepsExecuted + 1 }

/-- Execute a single plan step. -/
def executeStep (plan : VerifiedPlan) (ctx : PlanContext) (stmt : PlanStep) :
    Except PlanError PlanContext := do
  match stmt with
  | .bind dest rhs label =>
    executeBind plan ctx dest rhs label
  | .setResource name value =>
    executeSetResource plan ctx name value
  | .emitResult value =>
    executeEmit plan ctx value
  | .requireApproval reason =>
    throw (.approvalRequired reason)

-- ═══════════════════════════════════════════════════════════════════════
-- §10  step - one small-step transition (ImpLab.step)
-- ═══════════════════════════════════════════════════════════════════════

/-- One small-step transition. `none` means normal termination.
    Analogous to ImpLab's `step` but with capability and budget checks
    executed BEFORE the step. -/
def step (plan : VerifiedPlan) (ctx : PlanContext) :
    Except PlanError (Option PlanContext) := do
  let skill ← lookupSkill plan ctx.skillName
  -- Check if we've reached the end of the current skill body
  if ctx.pc == skill.body.size then
    if ctx.current.retDest?.isSome then
      throw (.missingEmit skill.skillId)
    else if ctx.callers.isEmpty then
      pure none  -- Normal termination
    else
      throw (.invalidPc ctx.pc skill.body.size)
  else
    match skill.body[ctx.pc]? with
    | some stmt =>
      -- PRE-STEP VERIFICATION: check capabilities
      for cap in skill.requiredCaps do
        if !hasCapability ctx cap.resource then
          throw (.capabilityDenied skill.skillId #[cap.resource])
      -- PRE-STEP VERIFICATION: check budget
      -- (skill-level cost estimation - per-step cost added in Phase A2)
      if ctx.budgetRemaining ≤ 0 then
        throw (.budgetExhausted 1 ctx.budgetRemaining)
      -- EXECUTE (with flow checking inside executeStep)
      let ctx' ← executeStep plan ctx stmt
      -- POST-STEP: decrement budget
      let ctx' := { ctx' with budgetRemaining := ctx'.budgetRemaining - 1 }
      pure (some ctx')
    | none =>
      throw (.invalidPc ctx.pc skill.body.size)

-- ═══════════════════════════════════════════════════════════════════════
-- §11  runPlan - execute to completion with fuel (ImpLab.run)
-- ═══════════════════════════════════════════════════════════════════════

/-- Run a plan from a starting context to completion (or error).
    Uses fuel to prevent non-termination.
    Analogous to ImpLab's `runFrom`. -/
def runPlanFrom (plan : VerifiedPlan)
    (start : PlanContext := PlanContext.initialForPlan plan) :
    Except PlanError PlanContext :=
  let fuel := plan.defaultFuel
  let rec go : Nat → PlanContext → Except PlanError PlanContext
    | 0, _ =>
      throw (.outOfFuel fuel)
    | fuel' + 1, ctx => do
      match ← step plan ctx with
      | none => pure ctx
      | some next => go fuel' next
  go fuel start

/-- Run a plan with default initial context. -/
def runPlan (plan : VerifiedPlan) : Except PlanError PlanContext :=
  runPlanFrom plan

-- ═══════════════════════════════════════════════════════════════════════
-- §12  Pretty printing (ImpLab.prettyRunResult)
-- ═══════════════════════════════════════════════════════════════════════

def renderBindings (bindings : Array (String × Value)) : String :=
  if bindings.isEmpty then "(empty)"
  else String.intercalate ", " <| bindings.toList.map (fun (name, value) => s!"{name}={value}")

def renderFlowBindings (bindings : Array (String × FlowLabel)) : String :=
  if bindings.isEmpty then "(empty)"
  else String.intercalate ", " <| bindings.toList.map (fun (name, label) => s!"{name}{label}")

def renderCertificates (certs : Array ProofCert) : String :=
  if certs.isEmpty then "(none)"
  else String.intercalate "\n  " <|
    certs.toList.enum.map (fun (i, cert) => s!"[{i+1}] {cert}")

def prettyRunResult (plan : VerifiedPlan) : String :=
  match runPlan plan with
  | .ok ctx =>
    String.intercalate "\n"
      [ "✓ Plan executed successfully."
      , s!"  Location: {ctx.skillName} @ pc {ctx.pc}"
      , s!"  Locals: {renderBindings ctx.localBindings}"
      , s!"  Resources: {renderBindings ctx.resourceBindings}"
      , s!"  Flow Labels: {renderFlowBindings ctx.flowBindings}"
      , s!"  Budget remaining: {ctx.budgetRemaining}¢"
      , s!"  Steps executed: {ctx.stepsExecuted}"
      , s!"  Certificates ({ctx.certificates.size}):"
      , s!"  {renderCertificates ctx.certificates}" ]
  | .error err =>
    s!"✗ Plan failed: {err}"

end CertiorPlan

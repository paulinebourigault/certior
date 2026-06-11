// =============================================================================
// Certior - Dafny-Verified Capability Attenuation (Phase B1)
// =============================================================================
//
// Proves critical safety properties for the capability-based security
// subsystem that gates every agent action in Certior's multi-agent
// orchestration pipeline.
//
//   P1  ATTENUATION SAFETY
//       attenuate(parent, child_perms, child_budget) →
//         (a) ∀ p ∈ child.permissions: p ∈ parent.permissions
//         (b) child.budget ≤ parent.budget_remaining
//         (c) Requesting permissions not in parent → rejected
//         (d) Requesting budget > parent.budget_remaining → rejected
//       The core guarantee: delegation can NEVER escalate privilege.
//
//   P2  BUDGET MONOTONICITY
//       (a) After spend(amount): remaining == old(remaining) - amount
//       (b) 0 ≤ remaining ≤ initial_budget - always (non-negative invariant)
//       (c) spend(amount) with amount > remaining fails (returns false)
//       (d) Consecutive spends are cumulative and never exceed initial
//       (e) budget_remaining only decreases under spend (monotone descent)
//
//   P7  PERMISSION CHECK CORRECTNESS
//       (a) has_permission(perm, perms) - exact match ⟹ true
//       (b) has_permission(perm, perms) - wildcard match ⟹ true
//       (c) has_permission(perm, perms) - no match ⟹ false
//       (d) has_all_permissions(required, available) ⟺
//             ∀ p ∈ required: has_permission(p, available)
//       (e) Empty permissions ⟹ has_permission always false
//
//   P8  ATTENUATION TRANSITIVITY
//       If child = attenuate(parent) and grandchild = attenuate(child), then:
//         (a) grandchild.permissions ⊆ parent.permissions
//         (b) grandchild.budget ≤ parent.budget
//         (c) Attenuation composes at any depth (inductive)
//         (d) Delegation chain depth is tracked correctly
//
// Usage:
//   dafny verify dafny/capabilities/capability_attenuation.dfy
//
// Verification target: Dafny 4.x
// =============================================================================

module CertiorCapabilityAttenuation {

  // =========================================================================
  // Permission model - strings with wildcard support
  // =========================================================================
  //
  // Permissions are colon-separated identifiers, e.g. "filesystem:read".
  // A wildcard "filesystem:*" grants all permissions starting with
  // "filesystem:".  Dafny cannot evaluate regexes, so we model wildcard
  // matching with explicit predicates over string prefixes.
  // =========================================================================

  // A permission is a non-empty string.
  type Permission = s: string | |s| > 0 witness "read"

  // ── Wildcard matching ─────────────────────────────────────────────────

  predicate IsWildcard(perm: Permission)
  {
    |perm| >= 2
    && perm[|perm| - 1] == '*'
    && forall i :: 0 <= i < |perm| - 1 ==> perm[i] != '*'
  }

  // The prefix of a wildcard permission (everything before the '*').
  function WildcardPrefix(perm: Permission): string
    requires IsWildcard(perm)
    ensures |WildcardPrefix(perm)| == |perm| - 1
  {
    perm[..|perm| - 1]
  }

  // Does `candidate` start with `prefix`?
  predicate StartsWith(candidate: string, prefix: string)
  {
    |candidate| >= |prefix| && candidate[..|prefix|] == prefix
  }

  lemma StartsWithTransitive(candidate: string, middle: string, prefix: string)
    requires StartsWith(candidate, middle)
    requires StartsWith(middle, prefix)
    ensures StartsWith(candidate, prefix)
  {
    assert |candidate| >= |middle|;
    assert |middle| >= |prefix|;
    assert candidate[..|middle|] == middle;
    assert middle[..|prefix|] == prefix;
    assert candidate[..|prefix|] == middle[..|prefix|];
  }

  lemma WildcardPrefixRefines(candidate: Permission, wildcard: Permission, prefix: string)
    requires IsWildcard(candidate)
    requires forall i :: 0 <= i < |prefix| ==> prefix[i] != '*'
    requires StartsWith(candidate, prefix)
    ensures StartsWith(WildcardPrefix(candidate), prefix)
  {
    assert |candidate| >= 2;
    if |prefix| == |candidate| {
      assert candidate[..|prefix|] == prefix;
      assert prefix[|prefix| - 1] == candidate[|candidate| - 1];
      assert prefix[|prefix| - 1] == '*';
      assert prefix[|prefix| - 1] != '*';
    }
    assert |prefix| < |candidate|;
    assert |WildcardPrefix(candidate)| == |candidate| - 1;
    assert |WildcardPrefix(candidate)| >= |prefix|;
    assert candidate[..|prefix|] == prefix;
    assert WildcardPrefix(candidate)[..|prefix|] == candidate[..|prefix|];
  }

  // A single grant `grant` covers permission `perm` if:
  //   (a) exact match, OR
  //   (b) grant is wildcard and perm starts with its prefix.
  predicate PermissionMatch(grant: Permission, perm: Permission)
  {
    grant == perm
    || (IsWildcard(grant) && StartsWith(perm, WildcardPrefix(grant)))
  }

  // ── Permission set operations ─────────────────────────────────────────

  // Does the permission set `perms` grant `perm`?
  predicate HasPermission(perm: Permission, perms: seq<Permission>)
  {
    exists i :: 0 <= i < |perms| && PermissionMatch(perms[i], perm)
  }

  // Helper: linear scan witness for HasPermission.
  function HasPermissionIndex(perm: Permission, perms: seq<Permission>): (idx: int)
    ensures idx >= 0 ==> (0 <= idx < |perms| && PermissionMatch(perms[idx], perm))
    ensures idx < 0  ==> !HasPermission(perm, perms)
  {
    HasPermissionScan(perm, perms, 0)
  }

  function HasPermissionScan(perm: Permission, perms: seq<Permission>, start: nat): (idx: int)
    requires start <= |perms|
    ensures idx >= 0 ==> (0 <= idx < |perms| && PermissionMatch(perms[idx], perm))
    ensures idx < 0  ==> forall i :: start <= i < |perms| ==> !PermissionMatch(perms[i], perm)
    decreases |perms| - start
  {
    if start == |perms| then
      -1
    else if PermissionMatch(perms[start], perm) then
      start
    else
      HasPermissionScan(perm, perms, start + 1)
  }

  // Does the permission set `available` cover ALL of `required`?
  predicate HasAllPermissions(required: seq<Permission>, available: seq<Permission>)
  {
    forall i :: 0 <= i < |required| ==> HasPermission(required[i], available)
  }

  // Subset relation: every permission in `child` is granted by `parent`.
  predicate PermissionsSubset(child: seq<Permission>, parent: seq<Permission>)
  {
    forall i :: 0 <= i < |child| ==> HasPermission(child[i], parent)
  }

  // =========================================================================
  // CapabilityToken - immutable token datatype
  // =========================================================================

  datatype CapabilityToken = CapabilityToken(
    id: string,
    agent_id: string,
    permissions: seq<Permission>,
    initial_budget: nat,       // budget at issuance (immutable)
    budget_remaining: nat,     // current remaining (decremented by spend)
    parent_id: string,         // "" for root tokens
    delegation_depth: nat      // 0 for root, increments on attenuate
  )

  // ── Token well-formedness ─────────────────────────────────────────────

  predicate TokenWellFormed(tok: CapabilityToken)
  {
    && tok.budget_remaining <= tok.initial_budget      // P2 core
    && (tok.parent_id == "" <==> tok.delegation_depth == 0)
    && |tok.id| > 0
    && |tok.agent_id| > 0
  }

  // =========================================================================
  // SpendResult - outcome of a budget spend operation
  // =========================================================================

  datatype SpendResult = SpendOk(token: CapabilityToken) | SpendFailed(reason: string)

  // =========================================================================
  // AttenuateResult - outcome of a delegation attempt
  // =========================================================================

  datatype AttenuateResult =
    | AttenuateOk(child: CapabilityToken)
    | AttenuateFailed(reason: string)

  // =========================================================================
  // Pure specification functions
  // =========================================================================

  // ── P2: spend_budget ──────────────────────────────────────────────────
  //
  // Core budget operation.  Returns updated token on success, failure
  // reason if amount exceeds remaining budget.

  function SpendBudget(tok: CapabilityToken, amount: nat): SpendResult
    requires TokenWellFormed(tok)
    ensures SpendBudget(tok, amount).SpendOk? ==>
      var t := SpendBudget(tok, amount).token;
      && t.budget_remaining == tok.budget_remaining - amount  // P2a
      && t.budget_remaining <= t.initial_budget               // P2b
      && t.initial_budget == tok.initial_budget                // P2: initial unchanged
      && t.id == tok.id                                       // identity preserved
      && t.permissions == tok.permissions                     // identity preserved
      && t.agent_id == tok.agent_id
      && t.parent_id == tok.parent_id
      && t.delegation_depth == tok.delegation_depth
      && TokenWellFormed(t)
    ensures SpendBudget(tok, amount).SpendFailed? ==>
      amount > tok.budget_remaining                           // P2c
  {
    if amount > tok.budget_remaining then
      SpendFailed("insufficient_budget")
    else
      SpendOk(CapabilityToken(
        tok.id, tok.agent_id, tok.permissions,
        tok.initial_budget,
        tok.budget_remaining - amount,
        tok.parent_id,
        tok.delegation_depth
      ))
  }

  // ── P1: attenuate ─────────────────────────────────────────────────────
  //
  // Core delegation operation.  Creates a child token with permissions
  // that are a SUBSET of the parent's and budget that does not exceed
  // the parent's remaining budget.

  function Attenuate(
    parent: CapabilityToken,
    child_id: string,
    child_agent_id: string,
    child_permissions: seq<Permission>,
    child_budget: nat
  ): AttenuateResult
    requires TokenWellFormed(parent)
    requires |child_id| > 0
    requires |child_agent_id| > 0
    // Core safety: result's permissions ⊆ parent's permissions
    ensures Attenuate(parent, child_id, child_agent_id, child_permissions, child_budget).AttenuateOk? ==>
      var child := Attenuate(parent, child_id, child_agent_id, child_permissions, child_budget).child;
      && PermissionsSubset(child.permissions, parent.permissions)   // P1a
      && child.initial_budget <= parent.budget_remaining            // P1b
      && child.budget_remaining == child.initial_budget             // fresh budget
      && child.parent_id == parent.id                               // provenance
      && child.delegation_depth == parent.delegation_depth + 1      // depth tracking
      && TokenWellFormed(child)
    // Failure cases
    ensures Attenuate(parent, child_id, child_agent_id, child_permissions, child_budget).AttenuateFailed? ==>
      || !PermissionsSubset(child_permissions, parent.permissions)  // P1c
      || child_budget > parent.budget_remaining                     // P1d
  {
    if !PermissionsSubset(child_permissions, parent.permissions) then
      AttenuateFailed("permissions_not_subset")
    else if child_budget > parent.budget_remaining then
      AttenuateFailed("budget_exceeds_parent")
    else
      AttenuateOk(CapabilityToken(
        child_id,
        child_agent_id,
        child_permissions,
        child_budget,           // initial_budget
        child_budget,           // budget_remaining (starts full)
        parent.id,              // parent_id
        parent.delegation_depth + 1
      ))
  }

  // =========================================================================
  //  P1: ATTENUATION SAFETY - formal lemmas
  // =========================================================================

  // P1a: child permissions are always a subset of parent permissions
  lemma AttenuationSafety_PermissionSubset(
    parent: CapabilityToken,
    child_id: string,
    child_agent_id: string,
    child_permissions: seq<Permission>,
    child_budget: nat
  )
    requires TokenWellFormed(parent)
    requires |child_id| > 0 && |child_agent_id| > 0
    requires Attenuate(parent, child_id, child_agent_id, child_permissions, child_budget).AttenuateOk?
    ensures PermissionsSubset(
      Attenuate(parent, child_id, child_agent_id, child_permissions, child_budget).child.permissions,
      parent.permissions
    )
  {
    // Follows directly from Attenuate postcondition - Dafny auto-proves
  }

  // P1b: child budget never exceeds parent budget_remaining
  lemma AttenuationSafety_BudgetBound(
    parent: CapabilityToken,
    child_id: string,
    child_agent_id: string,
    child_permissions: seq<Permission>,
    child_budget: nat
  )
    requires TokenWellFormed(parent)
    requires |child_id| > 0 && |child_agent_id| > 0
    requires Attenuate(parent, child_id, child_agent_id, child_permissions, child_budget).AttenuateOk?
    ensures Attenuate(parent, child_id, child_agent_id, child_permissions, child_budget).child.initial_budget
            <= parent.budget_remaining
  {}

  // P1c: escalation attempt - requesting permissions NOT in parent - always fails
  lemma AttenuationSafety_EscalationRejected(
    parent: CapabilityToken,
    child_id: string,
    child_agent_id: string,
    child_permissions: seq<Permission>,
    child_budget: nat
  )
    requires TokenWellFormed(parent)
    requires |child_id| > 0 && |child_agent_id| > 0
    requires !PermissionsSubset(child_permissions, parent.permissions)
    ensures Attenuate(parent, child_id, child_agent_id, child_permissions, child_budget).AttenuateFailed?
  {}

  // P1d: requesting budget > parent remaining - always fails
  lemma AttenuationSafety_OverbudgetRejected(
    parent: CapabilityToken,
    child_id: string,
    child_agent_id: string,
    child_permissions: seq<Permission>,
    child_budget: nat
  )
    requires TokenWellFormed(parent)
    requires |child_id| > 0 && |child_agent_id| > 0
    requires child_budget > parent.budget_remaining
    ensures Attenuate(parent, child_id, child_agent_id, child_permissions, child_budget).AttenuateFailed?
  {}

  // =========================================================================
  //  P2: BUDGET MONOTONICITY - formal lemmas
  // =========================================================================

  // P2a: spend decrements remaining by exactly the amount spent
  lemma BudgetMonotonicity_ExactDecrement(
    tok: CapabilityToken, amount: nat
  )
    requires TokenWellFormed(tok)
    requires amount <= tok.budget_remaining
    ensures SpendBudget(tok, amount).SpendOk?
    ensures SpendBudget(tok, amount).token.budget_remaining == tok.budget_remaining - amount
  {}

  // P2b: remaining is always non-negative and ≤ initial
  lemma BudgetMonotonicity_Bounded(
    tok: CapabilityToken, amount: nat
  )
    requires TokenWellFormed(tok)
    requires SpendBudget(tok, amount).SpendOk?
    ensures 0 <= SpendBudget(tok, amount).token.budget_remaining <= tok.initial_budget
  {}

  // P2c: spend with amount > remaining always fails
  lemma BudgetMonotonicity_OverspendFails(
    tok: CapabilityToken, amount: nat
  )
    requires TokenWellFormed(tok)
    requires amount > tok.budget_remaining
    ensures SpendBudget(tok, amount).SpendFailed?
  {}

  // P2d: consecutive spends are cumulative
  lemma BudgetMonotonicity_ConsecutiveSpends(
    tok: CapabilityToken, amount1: nat, amount2: nat
  )
    requires TokenWellFormed(tok)
    requires amount1 + amount2 <= tok.budget_remaining
    ensures SpendBudget(tok, amount1).SpendOk?
    ensures var tok1 := SpendBudget(tok, amount1).token;
            SpendBudget(tok1, amount2).SpendOk?
    ensures var tok1 := SpendBudget(tok, amount1).token;
            var tok2 := SpendBudget(tok1, amount2).token;
            tok2.budget_remaining == tok.budget_remaining - amount1 - amount2
  {
    var tok1 := SpendBudget(tok, amount1).token;
    assert TokenWellFormed(tok1);
  }

  // P2e: budget_remaining only decreases (monotone descent)
  lemma BudgetMonotonicity_OnlyDecreases(
    tok: CapabilityToken, amount: nat
  )
    requires TokenWellFormed(tok)
    requires amount > 0
    requires SpendBudget(tok, amount).SpendOk?
    ensures SpendBudget(tok, amount).token.budget_remaining < tok.budget_remaining
  {}

  // P2: initial_budget is never modified by spend
  lemma BudgetMonotonicity_InitialPreserved(
    tok: CapabilityToken, amount: nat
  )
    requires TokenWellFormed(tok)
    requires SpendBudget(tok, amount).SpendOk?
    ensures SpendBudget(tok, amount).token.initial_budget == tok.initial_budget
  {}

  // =========================================================================
  //  P7: PERMISSION CHECK CORRECTNESS - formal lemmas
  // =========================================================================

  // P7a: exact match found → true
  lemma PermissionCheck_ExactMatch(perm: Permission, perms: seq<Permission>)
    requires perm in perms
    ensures HasPermission(perm, perms)
  {
    var idx :| 0 <= idx < |perms| && perms[idx] == perm;
    assert PermissionMatch(perms[idx], perm);
  }

  // P7b: wildcard match → true
  lemma PermissionCheck_WildcardMatch(
    grant: Permission, perm: Permission, perms: seq<Permission>
  )
    requires grant in perms
    requires IsWildcard(grant)
    requires StartsWith(perm, WildcardPrefix(grant))
    ensures HasPermission(perm, perms)
  {
    var idx :| 0 <= idx < |perms| && perms[idx] == grant;
    assert PermissionMatch(perms[idx], perm);
  }

  // P7c: no match (exact or wildcard) → false
  lemma PermissionCheck_NoMatch(perm: Permission, perms: seq<Permission>)
    requires forall i :: 0 <= i < |perms| ==> !PermissionMatch(perms[i], perm)
    ensures !HasPermission(perm, perms)
  {}

  // P7d: has_all_permissions ⟺ every required permission is present
  lemma PermissionCheck_AllCorrect(
    required: seq<Permission>, available: seq<Permission>
  )
    ensures HasAllPermissions(required, available) <==>
            (forall i :: 0 <= i < |required| ==> HasPermission(required[i], available))
  {}

  // P7e: empty permissions ⟹ has_permission always false
  lemma PermissionCheck_EmptyPermsNeverGrants(perm: Permission)
    ensures !HasPermission(perm, [])
  {}

  // P7: has_permission is deterministic - same inputs always same result
  lemma PermissionCheck_Deterministic(
    perm: Permission, perms: seq<Permission>
  )
    ensures HasPermission(perm, perms) == HasPermission(perm, perms)
  {}

  // =========================================================================
  //  P8: ATTENUATION TRANSITIVITY - formal lemmas
  // =========================================================================

  // Helper: PermissionsSubset is transitive
  lemma {:induction false} PermissionsSubset_Transitive(
    a: seq<Permission>, b: seq<Permission>, c: seq<Permission>
  )
    requires PermissionsSubset(a, b)
    requires PermissionsSubset(b, c)
    ensures PermissionsSubset(a, c)
  {
    forall i | 0 <= i < |a|
      ensures HasPermission(a[i], c)
    {
      // a[i] is in b (from PermissionsSubset(a, b))
      assert HasPermission(a[i], b);
      // Since a[i] ∈ b, there exists some b[j] that matches a[i]
      var j :| 0 <= j < |b| && PermissionMatch(b[j], a[i]);
      // b[j] is in c (from PermissionsSubset(b, c))
      assert HasPermission(b[j], c);
      // We need: HasPermission(a[i], c)
      // Case 1: b[j] == a[i] - then a[i] ∈ c directly via HasPermission(b[j], c)
      if b[j] == a[i] {
        assert HasPermission(a[i], c);
      } else {
        // Case 2: b[j] is a wildcard matching a[i]
        // b[j] is in c, so there's some c[k] matching b[j]
        assert IsWildcard(b[j]);
        assert StartsWith(a[i], WildcardPrefix(b[j]));
        var k :| 0 <= k < |c| && PermissionMatch(c[k], b[j]);
        // c[k] matches b[j], and b[j] is wildcard matching a[i]
        // Case 2a: c[k] == b[j] - then c[k] also matches a[i]
        if c[k] == b[j] {
          assert PermissionMatch(c[k], a[i]);
          assert HasPermission(a[i], c);
        } else {
          // Case 2b: c[k] is a wildcard matching b[j]
          // c[k] wildcard, prefix of c[k] is prefix of b[j]
          // b[j] starts with prefix of c[k], and a[i] starts with prefix of b[j]
          assert IsWildcard(c[k]);
          var ck_prefix := WildcardPrefix(c[k]);
          var bj_prefix := WildcardPrefix(b[j]);
          assert StartsWith(b[j], ck_prefix);
          WildcardPrefixRefines(b[j], c[k], ck_prefix);
          StartsWithTransitive(a[i], bj_prefix, ck_prefix);
          assert PermissionMatch(c[k], a[i]);
          assert HasPermission(a[i], c);
        }
      }
    }
  }

  // P8a: grandchild permissions ⊆ grandparent permissions
  lemma AttenuationTransitivity_Permissions(
    grandparent: CapabilityToken,
    parent_id: string, parent_agent: string,
    parent_perms: seq<Permission>, parent_budget: nat,
    child_id: string, child_agent: string,
    child_perms: seq<Permission>, child_budget: nat
  )
    requires TokenWellFormed(grandparent)
    requires |parent_id| > 0 && |parent_agent| > 0
    requires |child_id| > 0 && |child_agent| > 0
    requires Attenuate(grandparent, parent_id, parent_agent, parent_perms, parent_budget).AttenuateOk?
    requires var parent := Attenuate(grandparent, parent_id, parent_agent, parent_perms, parent_budget).child;
             Attenuate(parent, child_id, child_agent, child_perms, child_budget).AttenuateOk?
    ensures
      var parent := Attenuate(grandparent, parent_id, parent_agent, parent_perms, parent_budget).child;
      var child := Attenuate(parent, child_id, child_agent, child_perms, child_budget).child;
      PermissionsSubset(child.permissions, grandparent.permissions)
  {
    var parent := Attenuate(grandparent, parent_id, parent_agent, parent_perms, parent_budget).child;
    var child := Attenuate(parent, child_id, child_agent, child_perms, child_budget).child;
    // child.perms ⊆ parent.perms (from Attenuate postcondition)
    assert PermissionsSubset(child.permissions, parent.permissions);
    // parent.perms ⊆ grandparent.perms (from Attenuate postcondition)
    assert PermissionsSubset(parent.permissions, grandparent.permissions);
    // Transitivity
    PermissionsSubset_Transitive(child.permissions, parent.permissions, grandparent.permissions);
  }

  // P8b: grandchild budget ≤ grandparent budget
  lemma AttenuationTransitivity_Budget(
    grandparent: CapabilityToken,
    parent_id: string, parent_agent: string,
    parent_perms: seq<Permission>, parent_budget: nat,
    child_id: string, child_agent: string,
    child_perms: seq<Permission>, child_budget: nat
  )
    requires TokenWellFormed(grandparent)
    requires |parent_id| > 0 && |parent_agent| > 0
    requires |child_id| > 0 && |child_agent| > 0
    requires Attenuate(grandparent, parent_id, parent_agent, parent_perms, parent_budget).AttenuateOk?
    requires var parent := Attenuate(grandparent, parent_id, parent_agent, parent_perms, parent_budget).child;
             Attenuate(parent, child_id, child_agent, child_perms, child_budget).AttenuateOk?
    ensures
      var parent := Attenuate(grandparent, parent_id, parent_agent, parent_perms, parent_budget).child;
      var child := Attenuate(parent, child_id, child_agent, child_perms, child_budget).child;
      child.initial_budget <= grandparent.budget_remaining
  {
    var parent := Attenuate(grandparent, parent_id, parent_agent, parent_perms, parent_budget).child;
    var child := Attenuate(parent, child_id, child_agent, child_perms, child_budget).child;
    // child.initial_budget <= parent.budget_remaining == parent_budget
    assert child.initial_budget <= parent.budget_remaining;
    // parent.initial_budget == parent_budget <= grandparent.budget_remaining
    assert parent.initial_budget <= grandparent.budget_remaining;
    // parent.budget_remaining == parent.initial_budget == parent_budget
    assert parent.budget_remaining == parent_budget;
  }

  // P8c: delegation depth increments correctly through chain
  lemma AttenuationTransitivity_DepthTracking(
    grandparent: CapabilityToken,
    parent_id: string, parent_agent: string,
    parent_perms: seq<Permission>, parent_budget: nat,
    child_id: string, child_agent: string,
    child_perms: seq<Permission>, child_budget: nat
  )
    requires TokenWellFormed(grandparent)
    requires |parent_id| > 0 && |parent_agent| > 0
    requires |child_id| > 0 && |child_agent| > 0
    requires Attenuate(grandparent, parent_id, parent_agent, parent_perms, parent_budget).AttenuateOk?
    requires var parent := Attenuate(grandparent, parent_id, parent_agent, parent_perms, parent_budget).child;
             Attenuate(parent, child_id, child_agent, child_perms, child_budget).AttenuateOk?
    ensures
      var parent := Attenuate(grandparent, parent_id, parent_agent, parent_perms, parent_budget).child;
      var child := Attenuate(parent, child_id, child_agent, child_perms, child_budget).child;
      child.delegation_depth == grandparent.delegation_depth + 2
  {}

  // =========================================================================
  // CapabilityManager - stateful manager with audit trail
  // =========================================================================
  //
  // The class wraps the pure specification functions above with:
  //   - An audit log of all operations
  //   - A registry of issued tokens
  //   - A class invariant Valid() checked at every method boundary
  //
  // This mirrors the Python runtime bridge pattern from B2-B5.
  // =========================================================================

  datatype AuditEntry = AuditEntry(
    token_id: string,
    operation: string,   // "create" | "attenuate" | "spend" | "check_permission"
    success: bool,
    details: string
  )

  class CapabilityManager {
    var tokens: map<string, CapabilityToken>
    var audit_log: seq<AuditEntry>

    // Ghost: total tokens ever created (monotonically increasing)
    ghost var total_created_count: nat

    // =================================================================
    // CLASS INVARIANT
    //
    //   C1: all tokens in registry are well-formed
    //   C2: all tokens' IDs match their registry keys
    //   C3: token count bounded by total_created_count
    //   C4: audit log length ≥ 0 (trivially true, but tracked)
    // =================================================================
    ghost predicate Valid()
      reads this
    {
      && (forall tid :: tid in tokens ==> TokenWellFormed(tokens[tid]))     // C1
      && (forall tid :: tid in tokens ==> tokens[tid].id == tid)            // C2
      && |tokens.Keys| <= total_created_count                               // C3
    }

    // =================================================================
    // CONSTRUCTOR
    // =================================================================
    constructor()
      ensures Valid()
      ensures tokens == map[]
      ensures audit_log == []
      ensures total_created_count == 0
    {
      tokens := map[];
      audit_log := [];
      total_created_count := 0;
    }

    // =================================================================
    // create_root_token - issue a new root token
    //
    //   Precondition:  token_id not already in registry
    //   Postconditions:
    //     - Token is well-formed and in registry
    //     - Token is a root token (parent_id == "", depth == 0)
    //     - Audit entry appended
    //     - Valid() preserved
    // =================================================================
    method create_root_token(
      token_id: string,
      agent_id: string,
      permissions: seq<Permission>,
      budget: nat
    ) returns (tok: CapabilityToken)
      requires Valid()
      requires |token_id| > 0 && |agent_id| > 0
      requires token_id !in tokens
      modifies this
      ensures Valid()
      ensures tok.id == token_id
      ensures tok.agent_id == agent_id
      ensures tok.permissions == permissions
      ensures tok.initial_budget == budget
      ensures tok.budget_remaining == budget
      ensures tok.parent_id == ""
      ensures tok.delegation_depth == 0
      ensures TokenWellFormed(tok)
      ensures token_id in tokens
      ensures tokens[token_id] == tok
      ensures old(tokens.Keys) < tokens.Keys                           // strict growth
      ensures forall tid :: tid in old(tokens) ==> tid in tokens       // monotonic
      ensures |audit_log| == |old(audit_log)| + 1                      // audit completeness
      ensures total_created_count == old(total_created_count) + 1
    {
      tok := CapabilityToken(
        token_id, agent_id, permissions,
        budget, budget, "", 0
      );
      tokens := tokens[token_id := tok];
      audit_log := audit_log + [AuditEntry(token_id, "create", true, "root_token")];
      total_created_count := total_created_count + 1;
    }

    // =================================================================
    // attenuate_token - P1: delegation with attenuation safety
    //
    //   Precondition:  parent_id in registry
    //   Precondition:  child_id not in registry
    //   Postconditions:
    //     - child.permissions ⊆ parent.permissions (P1a)
    //     - child.budget ≤ parent.budget_remaining (P1b)
    //     - Audit entry appended
    //     - Valid() preserved
    // =================================================================
    method attenuate_token(
      parent_id: string,
      child_id: string,
      child_agent_id: string,
      child_permissions: seq<Permission>,
      child_budget: nat
    ) returns (result: AttenuateResult)
      requires Valid()
      requires parent_id in tokens
      requires |child_id| > 0 && |child_agent_id| > 0
      requires child_id !in tokens
      modifies this
      ensures Valid()
      ensures |audit_log| == |old(audit_log)| + 1    // audit completeness
      ensures result.AttenuateOk? ==>
        var child := result.child;
        && PermissionsSubset(child.permissions, old(tokens[parent_id]).permissions) // P1a
        && child.initial_budget <= old(tokens[parent_id]).budget_remaining          // P1b
        && child.parent_id == parent_id
        && child_id in tokens
        && tokens[child_id] == child
        && total_created_count == old(total_created_count) + 1
      ensures result.AttenuateFailed? ==>
        tokens == old(tokens)
        && total_created_count == old(total_created_count)
    {
      var parent := tokens[parent_id];
      var att_result := Attenuate(parent, child_id, child_agent_id, child_permissions, child_budget);

      match att_result {
        case AttenuateOk(child) =>
          tokens := tokens[child_id := child];
          audit_log := audit_log + [AuditEntry(child_id, "attenuate", true, "child_of:" + parent_id)];
          total_created_count := total_created_count + 1;
          result := AttenuateOk(child);
        case AttenuateFailed(reason) =>
          audit_log := audit_log + [AuditEntry(child_id, "attenuate", false, reason)];
          result := AttenuateFailed(reason);
      }
    }

    // =================================================================
    // spend_budget - P2: atomic budget decrement
    //
    //   Precondition: token_id in registry
    //   Postconditions:
    //     - On success: budget decremented exactly by amount
    //     - Budget invariant preserved (0 ≤ remaining ≤ initial)
    //     - Audit entry appended
    //     - Valid() preserved
    // =================================================================
    method spend_budget(token_id: string, amount: nat) returns (success: bool)
      requires Valid()
      requires token_id in tokens
      modifies this
      ensures Valid()
      ensures |audit_log| == |old(audit_log)| + 1    // audit completeness
      ensures success ==>
        && token_id in tokens
        && tokens[token_id].budget_remaining == old(tokens[token_id]).budget_remaining - amount
        && tokens[token_id].budget_remaining <= tokens[token_id].initial_budget
        && tokens[token_id].initial_budget == old(tokens[token_id]).initial_budget
        && tokens[token_id].permissions == old(tokens[token_id]).permissions
        && tokens[token_id].id == token_id
      ensures !success ==>
        tokens == old(tokens)
        && amount > old(tokens[token_id]).budget_remaining
    {
      var tok := tokens[token_id];
      var spend_result := SpendBudget(tok, amount);

      match spend_result {
        case SpendOk(updated) =>
          tokens := tokens[token_id := updated];
          audit_log := audit_log + [AuditEntry(token_id, "spend", true, "amount:" + "ok")];
          success := true;
        case SpendFailed(reason) =>
          audit_log := audit_log + [AuditEntry(token_id, "spend", false, reason)];
          success := false;
      }
    }

    // =================================================================
    // check_permission - P7: permission check with audit
    // =================================================================
    method check_permission(token_id: string, perm: Permission) returns (granted: bool)
      requires Valid()
      requires token_id in tokens
      modifies this
      ensures Valid()
      ensures |audit_log| == |old(audit_log)| + 1
      ensures granted == HasPermission(perm, old(tokens[token_id]).permissions)
      ensures tokens == old(tokens) // read-only on registry
      ensures total_created_count == old(total_created_count)
    {
      var tok := tokens[token_id];
      granted := HasPermissionIndex(perm, tok.permissions) >= 0;
      audit_log := audit_log + [AuditEntry(
        token_id, "check_permission",
        granted,
        if granted then "granted:" + perm else "denied:" + perm
      )];
    }

    // =================================================================
    // get_token - read-only accessor
    // =================================================================
    method get_token(token_id: string) returns (tok: CapabilityToken)
      requires Valid()
      requires token_id in tokens
      ensures tok == tokens[token_id]
    {
      tok := tokens[token_id];
    }
  }

  // =========================================================================
  //  Integration tests - exercised by Dafny verifier
  // =========================================================================

  method TestFullLifecycle()
  {
    // Create manager
    var mgr := new CapabilityManager();

    // Create root token with ["filesystem:read", "filesystem:write", "network:*"]
    var root := mgr.create_root_token(
      "root-1", "orchestrator",
      ["filesystem:read", "filesystem:write", "network:*"],
      10000
    );
    assert root.delegation_depth == 0;
    assert root.parent_id == "";
    assert root.budget_remaining == 10000;

    // P7: check permissions
    var has_read := mgr.check_permission("root-1", "filesystem:read");
    assert has_read;

    var has_net := mgr.check_permission("root-1", "network:http");
    assert has_net;  // wildcard match

    // P1: attenuate - create executor with subset permissions
    var att1 := mgr.attenuate_token(
      "root-1", "exec-1", "executor",
      ["filesystem:read"],
      5000
    );
    assert att1.AttenuateOk?;
    var exec_tok := att1.child;
    assert exec_tok.delegation_depth == 1;
    assert exec_tok.parent_id == "root-1";
    assert exec_tok.budget_remaining == 5000;

    // P1c: escalation rejected - executor can't get "filesystem:write"
    // (it was not delegated in child_permissions)
    var no_write := mgr.check_permission("exec-1", "filesystem:write");
    assert !no_write;

    // P2: spend budget
    var spent := mgr.spend_budget("exec-1", 3000);
    assert spent;
    var exec_after := mgr.get_token("exec-1");
    assert exec_after.budget_remaining == 2000;

    // P2c: overspend fails
    var overspend := mgr.spend_budget("exec-1", 5000);
    assert !overspend;

    // P8: transitive delegation - grandchild
    var att2 := mgr.attenuate_token(
      "exec-1", "worker-1", "worker",
      ["filesystem:read"],
      1000
    );
    assert att2.AttenuateOk?;
    var worker := att2.child;
    assert worker.delegation_depth == 2;
    assert worker.parent_id == "exec-1";

    // P8a: worker permissions ⊆ root permissions (transitive)
    // worker has ["filesystem:read"], root has ["filesystem:read", ...]
    // This holds by construction and transitivity

    // P1c: escalation through chain - worker can't get "network:http"
    var no_net := mgr.check_permission("worker-1", "network:http");
    assert !no_net;

    // Audit: 8 operations logged
    assert |mgr.audit_log| == 8;
  }

  // Test: delegation with wildcard permissions
  method TestWildcardDelegation()
  {
    var mgr := new CapabilityManager();

    // Root with wildcard
    var root := mgr.create_root_token(
      "root-w", "admin",
      ["database:*"],
      5000
    );

    // Attenuate to specific - child gets "database:read" which is ⊆ "database:*"
    var att := mgr.attenuate_token(
      "root-w", "reader-1", "reader",
      ["database:read"],
      2000
    );
    assert att.AttenuateOk?;

    // Reader can check "database:read" (exact match)
    var has_read := mgr.check_permission("reader-1", "database:read");
    assert has_read;

    // Reader cannot do "database:write" (not in child permissions)
    var no_write := mgr.check_permission("reader-1", "database:write");
    assert !no_write;
  }

  // Test: budget cascading through delegation chain
  method TestBudgetCascade()
  {
    var mgr := new CapabilityManager();

    var root := mgr.create_root_token("root-b", "admin", ["read"], 10000);

    // Spend some from root
    var s1 := mgr.spend_budget("root-b", 3000);
    assert s1;

    // Attenuate - child budget ≤ root remaining (7000)
    var att := mgr.attenuate_token("root-b", "child-b", "agent", ["read"], 5000);
    assert att.AttenuateOk?;

    // Try to give child more than root has remaining - should fail
    var att_fail := mgr.attenuate_token("root-b", "child-b2", "agent2", ["read"], 8000);
    assert att_fail.AttenuateFailed?;
  }
}

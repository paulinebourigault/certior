"""
Dafny-Verified Capability Attenuation - Comprehensive Tests.

Tests every property proven in ``dafny/capabilities/capability_attenuation.dfy``:

  P1   Attenuation safety - delegation can NEVER escalate privilege
       P1a  child.permissions ⊆ parent.permissions
       P1b  child.budget ≤ parent.budget_remaining
       P1c  Non-subset permissions → rejected
       P1d  Over-budget → rejected

  P2   Budget monotonicity - budget only goes down, never overdraws
       P2a  After spend: remaining == old(remaining) - amount
       P2b  0 ≤ remaining ≤ initial_budget always
       P2c  Overspend fails
       P2d  Consecutive spends cumulative
       P2e  budget_remaining only decreases (monotone descent)

  P7   Permission check correctness
       P7a  Exact match → True
       P7b  Wildcard match → True
       P7c  No match → False
       P7d  has_all_permissions ⟺ ∀ p ∈ required: has_permission(p)
       P7e  Empty permissions → has_permission always False

  P8   Attenuation transitivity - composes through delegation chains
       P8a  grandchild.permissions ⊆ grandparent.permissions
       P8b  grandchild.budget ≤ grandparent.budget
       P8c  delegation depth tracked correctly
       P8d  N-level chain preserves all invariants (inductive)

Also tests:
  - Thread safety under concurrent operations
  - Audit trail completeness (every operation logged)
  - Invariant preservation at every method boundary
  - Edge cases (empty perms, zero budget, max depth)
  - Multi-agent orchestration scenario (Planner/Executor/Verifier)
  - Frozen immutability of VerifiedCapabilityToken
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from agentsafe.capabilities.capability_attenuation_verified import (
    AttenuateResult,
    CapabilityAuditEntry,
    CapabilityManager,
    SpendResult,
    VerifiedCapabilityToken,
    attenuate,
    has_all_permissions,
    has_permission,
    is_wildcard,
    permission_match,
    permissions_subset,
    spend_budget,
    starts_with,
    wildcard_prefix,
)
from agentsafe.verification.dafny_runtime import (
    InvariantAuditLog,
    InvariantViolation,
    PreconditionViolation,
)


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_audit():
    InvariantAuditLog.reset()
    yield
    InvariantAuditLog.reset()


def _mgr() -> CapabilityManager:
    """Fresh manager for isolation."""
    return CapabilityManager()


def _root_token(
    mgr: CapabilityManager,
    token_id: str = "root-1",
    agent_id: str = "orchestrator",
    permissions: tuple = ("filesystem:read", "filesystem:write", "network:*"),
    budget: int = 10000,
) -> VerifiedCapabilityToken:
    """Helper to create a root token with defaults."""
    return mgr.create_root_token(token_id, agent_id, list(permissions), budget)


# =============================================================================
# P1: ATTENUATION SAFETY
# =============================================================================

class TestP1AttenuationSafety:
    """Delegation can NEVER escalate privilege."""

    # ── P1a: child permissions ⊆ parent permissions ──────────────────

    def test_p1a_child_perms_subset_of_parent(self):
        """Successful attenuate ⟹ child.permissions ⊆ parent.permissions."""
        mgr = _mgr()
        _root_token(mgr)
        r = mgr.attenuate_token("root-1", "child-1", "executor",
                                ["filesystem:read"], 5000)
        assert r.success
        child = r.child
        assert permissions_subset(child.permissions, ("filesystem:read", "filesystem:write", "network:*"))

    def test_p1a_exact_match_subset(self):
        """Same permissions as parent is valid (equal is subset)."""
        mgr = _mgr()
        _root_token(mgr, permissions=("a", "b", "c"))
        r = mgr.attenuate_token("root-1", "child-1", "exec", ["a", "b", "c"], 5000)
        assert r.success

    def test_p1a_empty_child_perms_always_valid(self):
        """Empty child permissions is always a valid subset."""
        mgr = _mgr()
        _root_token(mgr)
        r = mgr.attenuate_token("root-1", "child-1", "exec", [], 5000)
        assert r.success
        assert r.child.permissions == ()

    def test_p1a_wildcard_grant_covers_specific(self):
        """Parent 'network:*' covers child 'network:http'."""
        mgr = _mgr()
        _root_token(mgr, permissions=("network:*",))
        r = mgr.attenuate_token("root-1", "child-1", "exec",
                                ["network:http"], 5000)
        assert r.success

    def test_p1a_wildcard_grant_covers_multiple_specifics(self):
        """Parent 'db:*' covers child 'db:read' and 'db:write'."""
        mgr = _mgr()
        _root_token(mgr, permissions=("db:*",))
        r = mgr.attenuate_token("root-1", "child-1", "exec",
                                ["db:read", "db:write"], 5000)
        assert r.success

    # ── P1b: child budget ≤ parent budget_remaining ──────────────────

    def test_p1b_child_budget_lte_parent_remaining(self):
        """Child budget ≤ parent.budget_remaining."""
        mgr = _mgr()
        _root_token(mgr, budget=10000)
        r = mgr.attenuate_token("root-1", "child-1", "exec", ["filesystem:read"], 5000)
        assert r.success
        assert r.child.initial_budget == 5000
        assert r.child.initial_budget <= 10000

    def test_p1b_equal_budget_succeeds(self):
        """Child budget == parent.budget_remaining is allowed."""
        mgr = _mgr()
        _root_token(mgr, budget=5000)
        r = mgr.attenuate_token("root-1", "child-1", "exec", ["filesystem:read"], 5000)
        assert r.success

    def test_p1b_zero_budget_succeeds(self):
        """Child budget == 0 is valid."""
        mgr = _mgr()
        _root_token(mgr, budget=5000)
        r = mgr.attenuate_token("root-1", "child-1", "exec", ["filesystem:read"], 0)
        assert r.success
        assert r.child.initial_budget == 0
        assert r.child.budget_remaining == 0

    # ── P1c: escalation rejected - non-subset permissions ────────────

    def test_p1c_extra_permission_rejected(self):
        """Requesting permission not in parent → failure."""
        mgr = _mgr()
        _root_token(mgr, permissions=("filesystem:read",))
        r = mgr.attenuate_token("root-1", "child-1", "exec",
                                ["filesystem:read", "filesystem:write"], 5000)
        assert not r.success
        assert r.reason == "permissions_not_subset"

    def test_p1c_completely_disjoint_rejected(self):
        """Completely disjoint permissions → failure."""
        mgr = _mgr()
        _root_token(mgr, permissions=("filesystem:read",))
        r = mgr.attenuate_token("root-1", "child-1", "exec",
                                ["network:http"], 5000)
        assert not r.success

    def test_p1c_wildcard_child_not_in_parent_rejected(self):
        """Child requests wildcard not covered by parent."""
        mgr = _mgr()
        _root_token(mgr, permissions=("filesystem:read",))
        r = mgr.attenuate_token("root-1", "child-1", "exec",
                                ["filesystem:*"], 5000)
        assert not r.success

    def test_p1c_specific_not_covered_by_different_wildcard(self):
        """Parent 'fs:*' does not cover 'network:http'."""
        mgr = _mgr()
        _root_token(mgr, permissions=("filesystem:*",))
        r = mgr.attenuate_token("root-1", "child-1", "exec",
                                ["network:http"], 5000)
        assert not r.success

    # ── P1d: over-budget rejected ────────────────────────────────────

    def test_p1d_overbudget_rejected(self):
        """Budget > parent.budget_remaining → failure."""
        mgr = _mgr()
        _root_token(mgr, budget=5000)
        r = mgr.attenuate_token("root-1", "child-1", "exec",
                                ["filesystem:read"], 6000)
        assert not r.success
        assert r.reason == "budget_exceeds_parent"

    def test_p1d_overbudget_after_spend_rejected(self):
        """After parent spends, child can't exceed remaining."""
        mgr = _mgr()
        _root_token(mgr, budget=10000)
        mgr.spend_budget("root-1", 7000)
        r = mgr.attenuate_token("root-1", "child-1", "exec",
                                ["filesystem:read"], 4000)
        assert not r.success
        assert r.reason == "budget_exceeds_parent"

    def test_p1d_budget_at_remaining_boundary(self):
        """Budget == remaining (after spend) succeeds."""
        mgr = _mgr()
        _root_token(mgr, budget=10000)
        mgr.spend_budget("root-1", 7000)
        r = mgr.attenuate_token("root-1", "child-1", "exec",
                                ["filesystem:read"], 3000)
        assert r.success

    # ── P1: attenuate preserves provenance ───────────────────────────

    def test_p1_provenance_tracking(self):
        """Child records parent_id."""
        mgr = _mgr()
        _root_token(mgr)
        r = mgr.attenuate_token("root-1", "child-1", "executor",
                                ["filesystem:read"], 5000)
        assert r.child.parent_id == "root-1"

    def test_p1_delegation_depth_increments(self):
        """Depth increments on each attenuate."""
        mgr = _mgr()
        _root_token(mgr)
        r = mgr.attenuate_token("root-1", "child-1", "exec", ["filesystem:read"], 5000)
        assert r.child.delegation_depth == 1

    def test_p1_child_starts_with_full_budget(self):
        """Child budget_remaining == initial_budget (fresh)."""
        mgr = _mgr()
        _root_token(mgr, budget=10000)
        r = mgr.attenuate_token("root-1", "child-1", "exec",
                                ["filesystem:read"], 3000)
        assert r.child.budget_remaining == r.child.initial_budget == 3000

    def test_p1_attenuate_does_not_modify_parent(self):
        """Attenuate is read-only on parent token."""
        mgr = _mgr()
        root = _root_token(mgr, budget=10000)
        mgr.attenuate_token("root-1", "child-1", "exec", ["filesystem:read"], 5000)
        root_after = mgr.get_token("root-1")
        assert root_after.budget_remaining == root.budget_remaining
        assert root_after.permissions == root.permissions


# =============================================================================
# P2: BUDGET MONOTONICITY
# =============================================================================

class TestP2BudgetMonotonicity:
    """Budget only goes down, never overdraws."""

    # ── P2a: exact decrement ─────────────────────────────────────────

    def test_p2a_exact_decrement(self):
        """spend(amount) ⟹ remaining == old(remaining) - amount."""
        mgr = _mgr()
        _root_token(mgr, budget=10000)
        old_remaining = mgr.get_token("root-1").budget_remaining
        mgr.spend_budget("root-1", 3000)
        new_remaining = mgr.get_token("root-1").budget_remaining
        assert new_remaining == old_remaining - 3000

    def test_p2a_spend_zero_is_noop(self):
        """spend(0) ⟹ remaining unchanged."""
        mgr = _mgr()
        _root_token(mgr, budget=10000)
        mgr.spend_budget("root-1", 0)
        assert mgr.get_token("root-1").budget_remaining == 10000

    # ── P2b: 0 ≤ remaining ≤ initial_budget ─────────────────────────

    def test_p2b_remaining_bounded_after_spend(self):
        """After spend: 0 ≤ remaining ≤ initial."""
        mgr = _mgr()
        _root_token(mgr, budget=10000)
        for amount in [1000, 2000, 3000, 4000]:
            mgr.spend_budget("root-1", amount)
        tok = mgr.get_token("root-1")
        assert 0 <= tok.budget_remaining <= tok.initial_budget

    def test_p2b_spend_to_zero(self):
        """Can spend entire budget."""
        mgr = _mgr()
        _root_token(mgr, budget=5000)
        assert mgr.spend_budget("root-1", 5000)
        tok = mgr.get_token("root-1")
        assert tok.budget_remaining == 0
        assert tok.budget_remaining <= tok.initial_budget

    def test_p2b_initial_budget_never_changes(self):
        """initial_budget is immutable across spends."""
        mgr = _mgr()
        _root_token(mgr, budget=10000)
        for _ in range(5):
            mgr.spend_budget("root-1", 1000)
        assert mgr.get_token("root-1").initial_budget == 10000

    # ── P2c: overspend fails ─────────────────────────────────────────

    def test_p2c_overspend_rejected(self):
        """amount > remaining ⟹ failure."""
        mgr = _mgr()
        _root_token(mgr, budget=5000)
        assert not mgr.spend_budget("root-1", 5001)

    def test_p2c_spend_after_exhaustion_rejected(self):
        """Once exhausted, any spend > 0 fails."""
        mgr = _mgr()
        _root_token(mgr, budget=100)
        assert mgr.spend_budget("root-1", 100)
        assert not mgr.spend_budget("root-1", 1)

    def test_p2c_rejected_spend_leaves_state_unchanged(self):
        """Failed spend does not modify remaining."""
        mgr = _mgr()
        _root_token(mgr, budget=5000)
        mgr.spend_budget("root-1", 3000)
        remaining_before = mgr.get_token("root-1").budget_remaining
        assert not mgr.spend_budget("root-1", 3000)  # only 2000 left
        assert mgr.get_token("root-1").budget_remaining == remaining_before

    # ── P2d: consecutive spends cumulative ───────────────────────────

    def test_p2d_cumulative_spends(self):
        """Multiple spends: total == sum of amounts."""
        mgr = _mgr()
        _root_token(mgr, budget=10000)
        amounts = [1000, 2000, 500, 1500, 3000]
        for a in amounts:
            assert mgr.spend_budget("root-1", a)
        expected = 10000 - sum(amounts)
        assert mgr.get_token("root-1").budget_remaining == expected

    def test_p2d_cumulative_cannot_exceed_initial(self):
        """Sum of spends bounded by initial_budget."""
        mgr = _mgr()
        _root_token(mgr, budget=100)
        for _ in range(10):
            mgr.spend_budget("root-1", 10)
        assert mgr.get_token("root-1").budget_remaining == 0
        assert not mgr.spend_budget("root-1", 1)

    # ── P2e: monotone descent ────────────────────────────────────────

    def test_p2e_monotone_descent(self):
        """Each successful spend(>0) strictly decreases remaining."""
        mgr = _mgr()
        _root_token(mgr, budget=10000)
        prev = 10000
        for amount in [100, 200, 300, 400]:
            mgr.spend_budget("root-1", amount)
            curr = mgr.get_token("root-1").budget_remaining
            assert curr < prev
            prev = curr


# =============================================================================
# P7: PERMISSION CHECK CORRECTNESS
# =============================================================================

class TestP7PermissionCheck:
    """Permission checks are sound and complete."""

    # ── P7a: exact match ─────────────────────────────────────────────

    def test_p7a_exact_match(self):
        """Exact permission string ⟹ True."""
        assert has_permission("filesystem:read", ("filesystem:read", "filesystem:write"))

    def test_p7a_exact_match_via_manager(self):
        """Manager check_permission with exact match."""
        mgr = _mgr()
        _root_token(mgr, permissions=("a", "b", "c"))
        assert mgr.check_permission("root-1", "a")
        assert mgr.check_permission("root-1", "b")
        assert mgr.check_permission("root-1", "c")

    # ── P7b: wildcard match ──────────────────────────────────────────

    def test_p7b_wildcard_match(self):
        """Wildcard 'a:*' matches 'a:b'."""
        assert has_permission("network:http", ("network:*",))

    def test_p7b_wildcard_deep_path(self):
        """Wildcard 'a:*' matches 'a:b:c:d'."""
        assert has_permission("a:b:c:d", ("a:*",))

    def test_p7b_wildcard_via_manager(self):
        """Manager check_permission with wildcard."""
        mgr = _mgr()
        _root_token(mgr, permissions=("network:*",))
        assert mgr.check_permission("root-1", "network:http")
        assert mgr.check_permission("root-1", "network:smtp")

    def test_p7b_wildcard_does_not_match_different_prefix(self):
        """Wildcard 'a:*' does NOT match 'b:c'."""
        assert not has_permission("b:c", ("a:*",))

    def test_p7b_wildcard_predicate(self):
        """is_wildcard correctly identifies wildcards."""
        assert is_wildcard("a:*")
        assert is_wildcard("fs:*")
        assert not is_wildcard("a")
        assert not is_wildcard("*")  # single char not enough (need >= 2)

    # ── P7c: no match ────────────────────────────────────────────────

    def test_p7c_no_match(self):
        """No matching permission ⟹ False."""
        assert not has_permission("filesystem:write", ("filesystem:read",))

    def test_p7c_no_match_via_manager(self):
        """Manager check_permission with no match."""
        mgr = _mgr()
        _root_token(mgr, permissions=("filesystem:read",))
        assert not mgr.check_permission("root-1", "network:http")

    def test_p7c_partial_string_no_match(self):
        """'file' is not matched by 'filesystem:read'."""
        assert not has_permission("file", ("filesystem:read",))

    # ── P7d: has_all_permissions ─────────────────────────────────────

    def test_p7d_all_present(self):
        """All required present ⟹ True."""
        available = ("a", "b", "c")
        assert has_all_permissions(["a", "b"], available)

    def test_p7d_one_missing(self):
        """One missing ⟹ False."""
        available = ("a", "b")
        assert not has_all_permissions(["a", "b", "c"], available)

    def test_p7d_empty_required(self):
        """Empty required ⟹ always True."""
        assert has_all_permissions([], ("a", "b"))
        assert has_all_permissions([], ())

    def test_p7d_via_manager(self):
        """Manager check_all_permissions."""
        mgr = _mgr()
        _root_token(mgr, permissions=("a", "b", "c"))
        assert mgr.check_all_permissions("root-1", ["a", "b"])
        assert not mgr.check_all_permissions("root-1", ["a", "d"])

    # ── P7e: empty permissions ───────────────────────────────────────

    def test_p7e_empty_perms_never_grants(self):
        """Empty permission set ⟹ has_permission always False."""
        assert not has_permission("anything", ())
        assert not has_permission("a:b:c", ())

    def test_p7e_empty_perms_via_manager(self):
        """Manager with empty-perms token never grants."""
        mgr = _mgr()
        _root_token(mgr, permissions=())
        assert not mgr.check_permission("root-1", "anything")

    # ── P7: determinism ──────────────────────────────────────────────

    def test_p7_deterministic(self):
        """Same inputs ⟹ same result (100 repetitions)."""
        perms = ("a:*", "b", "c:d")
        for _ in range(100):
            assert has_permission("a:x", perms) is True
            assert has_permission("z:q", perms) is False


# =============================================================================
# P8: ATTENUATION TRANSITIVITY
# =============================================================================

class TestP8AttenuationTransitivity:
    """Attenuation composes through delegation chains."""

    # ── P8a: grandchild permissions ⊆ grandparent permissions ────────

    def test_p8a_grandchild_perms_subset_grandparent(self):
        """Two-level chain: grandchild.perms ⊆ grandparent.perms."""
        mgr = _mgr()
        _root_token(mgr, permissions=("fs:read", "fs:write", "net:*"))
        mgr.attenuate_token("root-1", "parent-1", "p-agent",
                            ["fs:read", "net:http"], 5000)
        r = mgr.attenuate_token("parent-1", "child-1", "c-agent",
                                ["fs:read"], 2000)
        assert r.success
        assert permissions_subset(r.child.permissions, ("fs:read", "fs:write", "net:*"))

    def test_p8a_grandchild_cannot_escalate(self):
        """Grandchild can't get perms removed in parent delegation."""
        mgr = _mgr()
        _root_token(mgr, permissions=("a", "b", "c"))
        mgr.attenuate_token("root-1", "parent-1", "p", ["a", "b"], 5000)
        # Try to give grandchild "c" which parent doesn't have
        r = mgr.attenuate_token("parent-1", "child-1", "c-agent",
                                ["a", "c"], 2000)
        assert not r.success

    # ── P8b: grandchild budget ≤ grandparent budget ──────────────────

    def test_p8b_grandchild_budget_bounded(self):
        """Grandchild budget ≤ grandparent's original remaining."""
        mgr = _mgr()
        _root_token(mgr, budget=10000)
        mgr.attenuate_token("root-1", "parent-1", "p", ["filesystem:read"], 5000)
        r = mgr.attenuate_token("parent-1", "child-1", "c", ["filesystem:read"], 3000)
        assert r.success
        assert r.child.initial_budget <= 10000

    # ── P8c: delegation depth tracked ────────────────────────────────

    def test_p8c_depth_tracking(self):
        """Depth increments at each level."""
        mgr = _mgr()
        root = _root_token(mgr, permissions=("a",))
        assert root.delegation_depth == 0
        r1 = mgr.attenuate_token("root-1", "d1", "a1", ["a"], 5000)
        assert r1.child.delegation_depth == 1
        r2 = mgr.attenuate_token("d1", "d2", "a2", ["a"], 3000)
        assert r2.child.delegation_depth == 2
        r3 = mgr.attenuate_token("d2", "d3", "a3", ["a"], 1000)
        assert r3.child.delegation_depth == 3

    # ── P8d: N-level chain (inductive) ───────────────────────────────

    def test_p8d_deep_chain_preserves_all_invariants(self):
        """5-level delegation chain - all invariants hold at every level."""
        mgr = _mgr()
        _root_token(mgr, permissions=("a", "b", "c"), budget=100000)
        root_perms = ("a", "b", "c")

        prev_id = "root-1"
        prev_budget = 100000
        for depth in range(1, 6):
            child_id = f"level-{depth}"
            child_budget = prev_budget // 2
            r = mgr.attenuate_token(prev_id, child_id, f"agent-{depth}",
                                    ["a"], child_budget)
            assert r.success, f"Attenuate failed at depth {depth}: {r.reason}"
            child = r.child
            # P1a: perms ⊆ root
            assert permissions_subset(child.permissions, root_perms)
            # P1b: budget ≤ parent remaining
            assert child.initial_budget <= prev_budget
            # P2b: well-formed
            assert child.is_well_formed()
            # P8c: depth correct
            assert child.delegation_depth == depth
            # Provenance chain
            assert child.parent_id == prev_id
            prev_id = child_id
            prev_budget = child_budget

    def test_p8_parent_id_chain(self):
        """Parent_id forms a traceable provenance chain."""
        mgr = _mgr()
        _root_token(mgr, permissions=("x",), budget=10000)
        mgr.attenuate_token("root-1", "l1", "a", ["x"], 5000)
        mgr.attenuate_token("l1", "l2", "b", ["x"], 2500)
        mgr.attenuate_token("l2", "l3", "c", ["x"], 1000)

        assert mgr.get_token("root-1").parent_id == ""
        assert mgr.get_token("l1").parent_id == "root-1"
        assert mgr.get_token("l2").parent_id == "l1"
        assert mgr.get_token("l3").parent_id == "l2"


# =============================================================================
# Pure predicate tests
# =============================================================================

class TestPurePredicates:
    """Test pure specification functions directly."""

    def test_permission_match_exact(self):
        assert permission_match("a:b", "a:b")

    def test_permission_match_wildcard(self):
        assert permission_match("a:*", "a:b")
        assert permission_match("a:*", "a:b:c:d")

    def test_permission_match_no_match(self):
        assert not permission_match("a:b", "a:c")
        assert not permission_match("a:*", "b:c")

    def test_starts_with(self):
        assert starts_with("hello", "he")
        assert starts_with("hello", "hello")
        assert starts_with("hello", "")
        assert not starts_with("he", "hello")

    def test_spend_budget_pure(self):
        tok = VerifiedCapabilityToken("t1", "a", ("r",), 100, 100)
        r = spend_budget(tok, 30)
        assert r.success
        assert r.token.budget_remaining == 70

    def test_spend_budget_pure_fail(self):
        tok = VerifiedCapabilityToken("t1", "a", ("r",), 100, 50)
        r = spend_budget(tok, 51)
        assert not r.success

    def test_attenuate_pure_success(self):
        parent = VerifiedCapabilityToken("p1", "admin", ("a", "b"), 1000, 1000)
        r = attenuate(parent, "c1", "exec", ["a"], 500)
        assert r.success
        assert r.child.parent_id == "p1"
        assert r.child.delegation_depth == 1

    def test_attenuate_pure_permission_fail(self):
        parent = VerifiedCapabilityToken("p1", "admin", ("a",), 1000, 1000)
        r = attenuate(parent, "c1", "exec", ["a", "z"], 500)
        assert not r.success

    def test_attenuate_pure_budget_fail(self):
        parent = VerifiedCapabilityToken("p1", "admin", ("a",), 1000, 500)
        r = attenuate(parent, "c1", "exec", ["a"], 501)
        assert not r.success


# =============================================================================
# Token immutability
# =============================================================================

class TestTokenImmutability:
    """VerifiedCapabilityToken is frozen (dataclass frozen=True)."""

    def test_frozen_fields(self):
        tok = VerifiedCapabilityToken("t1", "a", ("r",), 100, 100)
        with pytest.raises(AttributeError):
            tok.id = "modified"
        with pytest.raises(AttributeError):
            tok.permissions = ("x",)
        with pytest.raises(AttributeError):
            tok.budget_remaining = 0

    def test_permissions_tuple(self):
        """Permissions stored as tuple (not list)."""
        tok = VerifiedCapabilityToken("t1", "a", ["r", "w"], 100, 100)
        assert isinstance(tok.permissions, tuple)

    def test_well_formed_validation(self):
        good = VerifiedCapabilityToken("t1", "a", ("r",), 100, 100)
        assert good.is_well_formed()

        bad_budget = VerifiedCapabilityToken("t1", "a", ("r",), 100, 200)
        assert not bad_budget.is_well_formed()

        bad_depth = VerifiedCapabilityToken("t1", "a", ("r",), 100, 100,
                                            parent_id="", delegation_depth=1)
        assert not bad_depth.is_well_formed()

        bad_parent = VerifiedCapabilityToken("t1", "a", ("r",), 100, 100,
                                             parent_id="x", delegation_depth=0)
        assert not bad_parent.is_well_formed()


# =============================================================================
# Invariant preservation (P11-equivalent for B1)
# =============================================================================

class TestInvariantPreservation:
    """Valid() holds at every method boundary."""

    def test_valid_after_create(self):
        mgr = _mgr()
        _root_token(mgr)
        assert mgr.stats()["valid"]

    def test_valid_after_attenuate_success(self):
        mgr = _mgr()
        _root_token(mgr)
        mgr.attenuate_token("root-1", "c1", "a", ["filesystem:read"], 5000)
        assert mgr.stats()["valid"]

    def test_valid_after_attenuate_failure(self):
        mgr = _mgr()
        _root_token(mgr, permissions=("a",))
        mgr.attenuate_token("root-1", "c1", "a", ["z"], 5000)
        assert mgr.stats()["valid"]

    def test_valid_after_spend_success(self):
        mgr = _mgr()
        _root_token(mgr)
        mgr.spend_budget("root-1", 5000)
        assert mgr.stats()["valid"]

    def test_valid_after_spend_failure(self):
        mgr = _mgr()
        _root_token(mgr, budget=100)
        mgr.spend_budget("root-1", 200)
        assert mgr.stats()["valid"]

    def test_valid_after_check_permission(self):
        mgr = _mgr()
        _root_token(mgr)
        mgr.check_permission("root-1", "anything")
        assert mgr.stats()["valid"]

    def test_valid_through_mixed_operations(self):
        """Invariant holds after a complex sequence."""
        mgr = _mgr()
        _root_token(mgr, permissions=("a", "b", "c"), budget=10000)
        mgr.spend_budget("root-1", 1000)
        mgr.attenuate_token("root-1", "c1", "x", ["a"], 3000)
        mgr.spend_budget("c1", 500)
        mgr.check_permission("c1", "a")
        mgr.attenuate_token("c1", "gc1", "y", ["a"], 1000)
        mgr.spend_budget("gc1", 200)
        mgr.attenuate_token("root-1", "c2", "z", ["b"], 2000)
        assert mgr.stats()["valid"]

    def test_audit_log_records_invariant_checks(self):
        """InvariantAuditLog records pre/post checks."""
        mgr = _mgr()
        _root_token(mgr)
        log = InvariantAuditLog.get_instance()
        entries = log.entries_for("CapabilityManager")
        # __init__ (post) + create_root_token (pre + post) = 3 checks minimum
        assert len(entries) >= 3
        assert all(e.passed for e in entries)


# =============================================================================
# Audit trail completeness
# =============================================================================

class TestAuditTrail:
    """Every operation appends exactly one audit entry."""

    def test_create_logs_entry(self):
        mgr = _mgr()
        _root_token(mgr)
        assert len(mgr.audit_log) == 1
        entry = mgr.audit_log[0]
        assert entry.operation == "create"
        assert entry.success is True
        assert entry.token_id == "root-1"

    def test_attenuate_success_logs_entry(self):
        mgr = _mgr()
        _root_token(mgr)
        mgr.attenuate_token("root-1", "c1", "a", ["filesystem:read"], 5000)
        assert len(mgr.audit_log) == 2
        entry = mgr.audit_log[1]
        assert entry.operation == "attenuate"
        assert entry.success is True

    def test_attenuate_failure_logs_entry(self):
        mgr = _mgr()
        _root_token(mgr, permissions=("a",))
        mgr.attenuate_token("root-1", "c1", "a", ["z"], 5000)
        assert len(mgr.audit_log) == 2
        entry = mgr.audit_log[1]
        assert entry.operation == "attenuate"
        assert entry.success is False

    def test_spend_success_logs_entry(self):
        mgr = _mgr()
        _root_token(mgr)
        mgr.spend_budget("root-1", 100)
        assert len(mgr.audit_log) == 2
        entry = mgr.audit_log[1]
        assert entry.operation == "spend"
        assert entry.success is True

    def test_spend_failure_logs_entry(self):
        mgr = _mgr()
        _root_token(mgr, budget=50)
        mgr.spend_budget("root-1", 100)
        entry = mgr.audit_log[-1]
        assert entry.operation == "spend"
        assert entry.success is False

    def test_check_permission_logs_entry(self):
        mgr = _mgr()
        _root_token(mgr, permissions=("a",))
        mgr.check_permission("root-1", "a")
        entry = mgr.audit_log[-1]
        assert entry.operation == "check_permission"
        assert entry.success is True

    def test_audit_entry_count_matches_operations(self):
        """N operations ⟹ exactly N audit entries."""
        mgr = _mgr()
        _root_token(mgr)                                         # 1
        mgr.attenuate_token("root-1", "c1", "a", ["filesystem:read"], 5000)  # 2
        mgr.spend_budget("c1", 100)                              # 3
        mgr.check_permission("c1", "filesystem:read")            # 4
        mgr.spend_budget("root-1", 50)                           # 5
        assert len(mgr.audit_log) == 5


# =============================================================================
# Precondition violations
# =============================================================================

class TestPreconditionViolations:
    """Precondition failures raise PreconditionViolation."""

    def test_create_empty_token_id(self):
        mgr = _mgr()
        with pytest.raises(PreconditionViolation):
            mgr.create_root_token("", "agent", ["a"], 100)

    def test_create_empty_agent_id(self):
        mgr = _mgr()
        with pytest.raises(PreconditionViolation):
            mgr.create_root_token("t1", "", ["a"], 100)

    def test_create_duplicate_token_id(self):
        mgr = _mgr()
        _root_token(mgr, token_id="dup")
        with pytest.raises(PreconditionViolation):
            mgr.create_root_token("dup", "agent", ["a"], 100)

    def test_attenuate_missing_parent(self):
        mgr = _mgr()
        with pytest.raises(PreconditionViolation):
            mgr.attenuate_token("nonexistent", "c1", "a", ["r"], 100)

    def test_attenuate_duplicate_child_id(self):
        mgr = _mgr()
        _root_token(mgr)
        mgr.attenuate_token("root-1", "c1", "a", ["filesystem:read"], 5000)
        with pytest.raises(PreconditionViolation):
            mgr.attenuate_token("root-1", "c1", "b", ["filesystem:read"], 5000)

    def test_attenuate_empty_child_id(self):
        mgr = _mgr()
        _root_token(mgr)
        with pytest.raises(PreconditionViolation):
            mgr.attenuate_token("root-1", "", "a", ["filesystem:read"], 5000)

    def test_spend_missing_token(self):
        mgr = _mgr()
        with pytest.raises(PreconditionViolation):
            mgr.spend_budget("nonexistent", 100)

    def test_check_permission_missing_token(self):
        mgr = _mgr()
        with pytest.raises(PreconditionViolation):
            mgr.check_permission("nonexistent", "a")

    def test_get_token_missing(self):
        mgr = _mgr()
        with pytest.raises(PreconditionViolation):
            mgr.get_token("nonexistent")


# =============================================================================
# Thread safety
# =============================================================================

class TestThreadSafety:
    """Concurrent operations maintain invariants."""

    def test_concurrent_spends_no_overdraw(self):
        """100 threads spending 100 each from 10000 budget.
        At most 100 should succeed."""
        mgr = _mgr()
        _root_token(mgr, budget=10000)
        results = []

        def worker():
            return mgr.spend_budget("root-1", 100)

        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = [pool.submit(worker) for _ in range(200)]
            for f in as_completed(futures):
                results.append(f.result())

        successes = sum(1 for r in results if r)
        tok = mgr.get_token("root-1")
        assert successes == 100  # exactly 10000 / 100
        assert tok.budget_remaining == 0
        assert tok.budget_remaining >= 0  # P2b: never negative

    def test_concurrent_creates_no_duplicates(self):
        """Concurrent creates with unique IDs all succeed."""
        mgr = _mgr()

        def worker(i):
            try:
                mgr.create_root_token(f"tok-{i}", f"agent-{i}", ["r"], 100)
                return True
            except PreconditionViolation:
                return False

        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = [pool.submit(worker, i) for i in range(50)]
            results = [f.result() for f in as_completed(futures)]

        assert all(results)
        assert mgr.token_count() == 50

    def test_concurrent_mixed_operations(self):
        """Mix of creates, attenuates, spends, checks all maintain Valid()."""
        mgr = _mgr()
        _root_token(mgr, permissions=("a", "b"), budget=1000000)

        errors = []

        def spender():
            try:
                for _ in range(100):
                    mgr.spend_budget("root-1", 1)
            except Exception as e:
                errors.append(e)

        def checker():
            try:
                for _ in range(100):
                    mgr.check_permission("root-1", "a")
            except Exception as e:
                errors.append(e)

        threads = []
        for _ in range(5):
            threads.append(threading.Thread(target=spender))
            threads.append(threading.Thread(target=checker))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert mgr.stats()["valid"]


# =============================================================================
# Multi-agent orchestration scenario
# =============================================================================

class TestMultiAgentOrchestration:
    """Real-world Planner → Executor → Verifier delegation pattern."""

    def test_orchestrator_delegates_to_agents(self):
        """Orchestrator creates root, delegates to Planner/Executor/Verifier."""
        mgr = _mgr()

        # Orchestrator: full permissions
        root = mgr.create_root_token(
            "orchestrator-1", "orchestrator",
            ["filesystem:read", "filesystem:write", "database:read",
             "database:write", "network:http", "network:smtp"],
            100000,
        )

        # Planner: read-only, needs network for LLM
        r_planner = mgr.attenuate_token(
            "orchestrator-1", "planner-1", "planner",
            ["filesystem:read", "database:read", "network:http"],
            20000,
        )
        assert r_planner.success

        # Executor: read+write, most budget
        r_executor = mgr.attenuate_token(
            "orchestrator-1", "executor-1", "executor",
            ["filesystem:read", "filesystem:write", "database:read", "database:write"],
            60000,
        )
        assert r_executor.success

        # Verifier: read-only, small budget
        r_verifier = mgr.attenuate_token(
            "orchestrator-1", "verifier-1", "verifier",
            ["filesystem:read", "database:read"],
            10000,
        )
        assert r_verifier.success

        # Verify privilege separation
        assert mgr.check_permission("planner-1", "network:http")
        assert not mgr.check_permission("planner-1", "filesystem:write")
        assert not mgr.check_permission("planner-1", "network:smtp")

        assert mgr.check_permission("executor-1", "filesystem:write")
        assert not mgr.check_permission("executor-1", "network:http")

        assert mgr.check_permission("verifier-1", "filesystem:read")
        assert not mgr.check_permission("verifier-1", "filesystem:write")
        assert not mgr.check_permission("verifier-1", "database:write")

    def test_executor_sub_delegates_to_workers(self):
        """Executor further delegates to specialized workers."""
        mgr = _mgr()
        _root_token(mgr, permissions=("fs:read", "fs:write", "db:read", "db:write"),
                    budget=100000)

        mgr.attenuate_token("root-1", "executor-1", "executor",
                            ["fs:read", "fs:write", "db:read"], 50000)

        # Worker: only database read
        r = mgr.attenuate_token("executor-1", "db-worker-1", "db-worker",
                                ["db:read"], 10000)
        assert r.success
        assert r.child.delegation_depth == 2

        # Worker cannot escalate to db:write
        r_bad = mgr.attenuate_token("executor-1", "bad-worker", "bad",
                                    ["db:write"], 10000)
        assert not r_bad.success

    def test_budget_isolation_between_agents(self):
        """Each agent's budget is independent."""
        mgr = _mgr()
        _root_token(mgr, budget=100000)

        mgr.attenuate_token("root-1", "agent-a", "a", ["filesystem:read"], 30000)
        mgr.attenuate_token("root-1", "agent-b", "b", ["filesystem:read"], 30000)

        # Agent A spends its budget
        mgr.spend_budget("agent-a", 25000)
        assert mgr.get_token("agent-a").budget_remaining == 5000

        # Agent B unaffected
        assert mgr.get_token("agent-b").budget_remaining == 30000

    def test_full_lifecycle_with_budget_tracking(self):
        """Complete orchestration lifecycle with budget consumption."""
        mgr = _mgr()
        _root_token(mgr, permissions=("compute", "storage", "network"),
                    budget=50000)

        # Delegate
        mgr.attenuate_token("root-1", "exec-1", "executor",
                            ["compute", "storage"], 30000)

        # Execute steps
        assert mgr.spend_budget("exec-1", 5000)   # step 1
        assert mgr.spend_budget("exec-1", 8000)   # step 2
        assert mgr.spend_budget("exec-1", 12000)  # step 3

        tok = mgr.get_token("exec-1")
        assert tok.budget_remaining == 5000
        assert tok.initial_budget == 30000

        # Can't overspend
        assert not mgr.spend_budget("exec-1", 6000)

        # Final budget check
        assert 0 <= tok.budget_remaining <= tok.initial_budget

    def test_hipaa_agent_cannot_access_network(self):
        """HIPAA scenario: data-processing agent has no network access."""
        mgr = _mgr()
        mgr.create_root_token(
            "hipaa-root", "hipaa-orchestrator",
            ["patient_data:read", "patient_data:write", "audit:write",
             "network:internal"],
            50000,
        )

        # Data processor: no network at all
        r = mgr.attenuate_token(
            "hipaa-root", "processor-1", "data-processor",
            ["patient_data:read", "audit:write"],
            20000,
        )
        assert r.success
        assert not mgr.check_permission("processor-1", "network:internal")
        assert not mgr.check_permission("processor-1", "patient_data:write")
        assert mgr.check_permission("processor-1", "patient_data:read")


# =============================================================================
# Edge cases
# =============================================================================

class TestEdgeCases:
    """Boundary conditions and unusual inputs."""

    def test_zero_budget_root(self):
        """Root with 0 budget - valid but can't spend."""
        mgr = _mgr()
        tok = mgr.create_root_token("t1", "a", ["r"], 0)
        assert tok.is_well_formed()
        assert not mgr.spend_budget("t1", 1)

    def test_single_permission(self):
        mgr = _mgr()
        _root_token(mgr, permissions=("only:one",))
        assert mgr.check_permission("root-1", "only:one")
        assert not mgr.check_permission("root-1", "anything:else")

    def test_many_permissions(self):
        """Token with 100 permissions."""
        mgr = _mgr()
        perms = [f"perm:{i}" for i in range(100)]
        _root_token(mgr, permissions=tuple(perms))
        assert mgr.check_permission("root-1", "perm:50")
        assert not mgr.check_permission("root-1", "perm:100")

    def test_wildcard_only_permissions(self):
        """Token with only wildcard grants.
        Note: "*" alone is NOT a valid wildcard (length < 2 per Dafny spec).
        Use ":*" or similar for universal wildcard."""
        mgr = _mgr()
        # "*" is length 1 → not a wildcard per spec, only exact-matches "*"
        _root_token(mgr, permissions=("*",))
        assert mgr.check_permission("root-1", "*")
        assert not mgr.check_permission("root-1", "anything")

        # ":*" IS a valid universal wildcard (prefix "" matches everything)
        mgr2 = _mgr()
        mgr2.create_root_token("root-2", "admin", [":*"], 1000)
        assert mgr2.check_permission("root-2", ":http")
        assert mgr2.check_permission("root-2", ":anything")

    def test_long_permission_string(self):
        """Very long permission string."""
        long_perm = "a:" * 100 + "read"
        mgr = _mgr()
        _root_token(mgr, permissions=(long_perm,))
        assert mgr.check_permission("root-1", long_perm)

    def test_multiple_wildcards_in_set(self):
        """Multiple wildcards in permission set."""
        perms = ("fs:*", "net:*", "db:*")
        assert has_permission("fs:read", perms)
        assert has_permission("net:http", perms)
        assert has_permission("db:query", perms)
        assert not has_permission("audit:write", perms)

    def test_attenuate_preserves_parent_in_registry(self):
        """Parent remains in registry after attenuate."""
        mgr = _mgr()
        _root_token(mgr)
        mgr.attenuate_token("root-1", "c1", "a", ["filesystem:read"], 5000)
        assert "root-1" in mgr.token_ids
        assert "c1" in mgr.token_ids

    def test_total_created_count_monotonic(self):
        """total_created_count only increases."""
        mgr = _mgr()
        counts = [mgr.total_created_count]
        _root_token(mgr)
        counts.append(mgr.total_created_count)
        mgr.attenuate_token("root-1", "c1", "a", ["filesystem:read"], 5000)
        counts.append(mgr.total_created_count)
        # Failed attenuate does not increment
        mgr.attenuate_token("root-1", "c2", "b", ["nonexistent"], 5000)
        counts.append(mgr.total_created_count)

        assert counts == [0, 1, 2, 2]
        assert all(counts[i] <= counts[i + 1] for i in range(len(counts) - 1))

    def test_repr(self):
        mgr = _mgr()
        _root_token(mgr)
        s = repr(mgr)
        assert "tokens=1" in s
        assert "total_created=1" in s

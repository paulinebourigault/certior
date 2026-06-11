"""
Dafny-Verified Capability Attenuation - Phase B1 Production Runtime Bridge.

Mirrors ``dafny/capabilities/capability_attenuation.dfy`` at every method boundary.

Proven properties (Dafny static, Python runtime enforcement):

  P1   ATTENUATION SAFETY
       attenuate(parent, child_perms, child_budget) →
         (a) ∀ p ∈ child.permissions: p ∈ parent.permissions
         (b) child.budget ≤ parent.budget_remaining
         (c) Requesting permissions NOT in parent → rejected
         (d) Requesting budget > parent.budget_remaining → rejected
       Delegation can NEVER escalate privilege.

  P2   BUDGET MONOTONICITY
         (a) After spend(amount): remaining == old(remaining) - amount
         (b) 0 ≤ remaining ≤ initial_budget always
         (c) spend with amount > remaining fails
         (d) Consecutive spends are cumulative
         (e) budget_remaining only decreases (monotone descent)

  P7   PERMISSION CHECK CORRECTNESS
         (a) Exact match found → True
         (b) Wildcard match ("a:*" matches "a:b") → True
         (c) No match → False
         (d) has_all_permissions ⟺ ∀ p ∈ required: has_permission(p)
         (e) Empty permissions → has_permission always False

  P8   ATTENUATION TRANSITIVITY
         (a) grandchild.permissions ⊆ grandparent.permissions
         (b) grandchild.budget ≤ grandparent.budget
         (c) Delegation chain depth tracked correctly
         (d) Attenuation composes at any depth (inductive)

Thread safety: All state mutations guarded by ``threading.Lock``.
Audit trail:   Every invariant check recorded to ``InvariantAuditLog``.

Usage::

    from agentsafe.capabilities.capability_attenuation_verified import (
        VerifiedCapabilityToken, CapabilityManager,
        has_permission, has_all_permissions, permissions_subset,
    )

    mgr = CapabilityManager()
    root = mgr.create_root_token("root-1", "orchestrator",
                                  ["filesystem:read", "network:*"], 10000)

    # P1: attenuate - child ⊆ parent
    child = mgr.attenuate_token("root-1", "exec-1", "executor",
                                 ["filesystem:read"], 5000)

    # P7: permission check
    assert mgr.check_permission("root-1", "network:http")  # wildcard match

    # P2: spend budget
    assert mgr.spend_budget("exec-1", 3000)
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple

from agentsafe.verification.dafny_runtime import (
    InvariantAuditLog,
    InvariantViolation,
    PreconditionViolation,
    check_invariant,
)


# =============================================================================
# Pure predicates - mirror Dafny specification exactly
# =============================================================================


def is_wildcard(perm: str) -> bool:
    """A permission is a wildcard if it ends with '*' and has length ≥ 2.

    Mirrors Dafny ``IsWildcard(perm)``.
    """
    return len(perm) >= 2 and perm[-1] == "*"


def wildcard_prefix(perm: str) -> str:
    """Return the prefix of a wildcard permission (everything before '*').

    Mirrors Dafny ``WildcardPrefix(perm)``.

    Precondition: ``is_wildcard(perm)`` must be True.
    """
    assert is_wildcard(perm), f"wildcard_prefix requires wildcard: {perm!r}"
    return perm[:-1]


def starts_with(candidate: str, prefix: str) -> bool:
    """Does ``candidate`` start with ``prefix``?

    Mirrors Dafny ``StartsWith(candidate, prefix)``.
    """
    return len(candidate) >= len(prefix) and candidate[:len(prefix)] == prefix


def permission_match(grant: str, perm: str) -> bool:
    """Does the grant cover the requested permission?

    Exact match OR wildcard match.
    Mirrors Dafny ``PermissionMatch(grant, perm)``.
    """
    if grant == perm:
        return True
    if is_wildcard(grant) and starts_with(perm, wildcard_prefix(grant)):
        return True
    return False


def has_permission(perm: str, perms: Sequence[str]) -> bool:
    """Does the permission set ``perms`` grant ``perm``?

    Mirrors Dafny ``HasPermission(perm, perms)``.
    P7: returns True ⟺ ∃ p ∈ perms: permission_match(p, perm).
    """
    return any(permission_match(p, perm) for p in perms)


def has_all_permissions(required: Sequence[str], available: Sequence[str]) -> bool:
    """Does ``available`` cover ALL of ``required``?

    Mirrors Dafny ``HasAllPermissions(required, available)``.
    P7d: ⟺ ∀ p ∈ required: has_permission(p, available).
    """
    return all(has_permission(p, available) for p in required)


def permissions_subset(child: Sequence[str], parent: Sequence[str]) -> bool:
    """Is every permission in ``child`` granted by ``parent``?

    Mirrors Dafny ``PermissionsSubset(child, parent)``.
    P1a core check.
    """
    return all(has_permission(p, parent) for p in child)


# =============================================================================
# VerifiedCapabilityToken - immutable token datatype
# =============================================================================


@dataclass(frozen=True)
class VerifiedCapabilityToken:
    """Capability token with formally verified invariants.

    Mirrors Dafny ``CapabilityToken`` datatype.

    All fields are frozen (immutable) after construction.
    ``budget_remaining`` changes are tracked through the
    ``CapabilityManager`` which issues new snapshot objects -
    mirroring Dafny's functional-update semantics.
    """

    id: str
    agent_id: str
    permissions: Tuple[str, ...]
    initial_budget: int
    budget_remaining: int
    parent_id: str = ""          # "" for root tokens
    delegation_depth: int = 0    # 0 for root, increments on attenuate

    def __post_init__(self) -> None:
        # Coerce list → tuple for immutability
        if isinstance(self.permissions, list):
            object.__setattr__(self, "permissions", tuple(self.permissions))

    def is_well_formed(self) -> bool:
        """Mirrors Dafny ``TokenWellFormed(tok)``.

        Checks:
          - budget_remaining ≤ initial_budget (P2 core)
          - parent_id == "" ⟺ delegation_depth == 0
          - non-empty id and agent_id
        """
        return (
            self.budget_remaining >= 0
            and self.budget_remaining <= self.initial_budget
            and (self.parent_id == "") == (self.delegation_depth == 0)
            and len(self.id) > 0
            and len(self.agent_id) > 0
        )


# =============================================================================
# Result types
# =============================================================================


@dataclass(frozen=True)
class SpendResult:
    """Outcome of a budget spend operation."""
    success: bool
    token: Optional[VerifiedCapabilityToken] = None
    reason: str = ""


@dataclass(frozen=True)
class AttenuateResult:
    """Outcome of a delegation/attenuation attempt."""
    success: bool
    child: Optional[VerifiedCapabilityToken] = None
    reason: str = ""


# =============================================================================
# Pure specification functions - mirror Dafny exactly
# =============================================================================


def spend_budget(tok: VerifiedCapabilityToken, amount: int) -> SpendResult:
    """Pure specification for budget spend.

    Mirrors Dafny ``SpendBudget(tok, amount)``.

    P2a: On success, remaining == old(remaining) - amount.
    P2b: 0 ≤ remaining ≤ initial_budget.
    P2c: If amount > remaining, fails.
    """
    assert tok.is_well_formed(), "spend_budget precondition: token must be well-formed"
    assert amount >= 0, "spend_budget precondition: amount must be non-negative"

    if amount > tok.budget_remaining:
        return SpendResult(success=False, reason="insufficient_budget")

    updated = VerifiedCapabilityToken(
        id=tok.id,
        agent_id=tok.agent_id,
        permissions=tok.permissions,
        initial_budget=tok.initial_budget,
        budget_remaining=tok.budget_remaining - amount,
        parent_id=tok.parent_id,
        delegation_depth=tok.delegation_depth,
    )
    return SpendResult(success=True, token=updated)


def attenuate(
    parent: VerifiedCapabilityToken,
    child_id: str,
    child_agent_id: str,
    child_permissions: Sequence[str],
    child_budget: int,
) -> AttenuateResult:
    """Pure specification for capability attenuation.

    Mirrors Dafny ``Attenuate(parent, child_id, child_agent_id, child_permissions, child_budget)``.

    P1a: child.permissions ⊆ parent.permissions.
    P1b: child.budget ≤ parent.budget_remaining.
    P1c: Non-subset permissions → failure.
    P1d: Over-budget → failure.
    """
    assert parent.is_well_formed(), "attenuate precondition: parent must be well-formed"
    assert len(child_id) > 0, "attenuate precondition: child_id must be non-empty"
    assert len(child_agent_id) > 0, "attenuate precondition: child_agent_id must be non-empty"

    if not permissions_subset(child_permissions, parent.permissions):
        return AttenuateResult(success=False, reason="permissions_not_subset")

    if child_budget > parent.budget_remaining:
        return AttenuateResult(success=False, reason="budget_exceeds_parent")

    child = VerifiedCapabilityToken(
        id=child_id,
        agent_id=child_agent_id,
        permissions=tuple(child_permissions),
        initial_budget=child_budget,
        budget_remaining=child_budget,
        parent_id=parent.id,
        delegation_depth=parent.delegation_depth + 1,
    )
    return AttenuateResult(success=True, child=child)


# =============================================================================
# AuditEntry - operation record
# =============================================================================


@dataclass(frozen=True)
class CapabilityAuditEntry:
    """Single capability operation record.

    Mirrors Dafny ``AuditEntry`` datatype.
    """
    token_id: str
    operation: str        # "create" | "attenuate" | "spend" | "check_permission"
    success: bool
    details: str
    timestamp: float = field(default_factory=time.time)


# =============================================================================
# CapabilityManager - stateful manager with invariant enforcement
# =============================================================================


class CapabilityManager:
    """Dafny-verified capability token manager.

    Mirrors ``CapabilityManager`` class in
    ``dafny/capabilities/capability_attenuation.dfy``.

    Every method enforces Valid() as a pre- and post-condition,
    recorded to the ``InvariantAuditLog`` for compliance audit.

    Thread-safe: all state mutations under ``self._lock``.
    """

    _CLASS_NAME = "CapabilityManager"

    def __init__(self) -> None:
        self._tokens: Dict[str, VerifiedCapabilityToken] = {}
        self._audit_log: List[CapabilityAuditEntry] = []
        self._total_created_count: int = 0
        self._lock = threading.Lock()

        # Enforce Valid() postcondition (P11-equivalent)
        check_invariant(
            self._valid,
            self._CLASS_NAME,
            "__init__",
            "post",
            "Valid()",
        )

    # ── Class invariant ──────────────────────────────────────────────────

    def _valid(self) -> bool:
        """Mirrors Dafny ``Valid()`` ghost predicate.

        C1: all tokens well-formed
        C2: all token IDs match registry keys
        C3: token count ≤ total_created_count
        """
        # C1: all tokens well-formed
        if not all(tok.is_well_formed() for tok in self._tokens.values()):
            return False
        # C2: all token IDs match registry keys
        if not all(tok.id == tid for tid, tok in self._tokens.items()):
            return False
        # C3: count bounded
        if len(self._tokens) > self._total_created_count:
            return False
        return True

    def _check_valid(self, method: str, phase: str) -> None:
        """Check invariant and record to audit log."""
        check_invariant(
            self._valid,
            self._CLASS_NAME,
            method,
            phase,
            "Valid()",
        )

    # ── Public API ───────────────────────────────────────────────────────

    def create_root_token(
        self,
        token_id: str,
        agent_id: str,
        permissions: Sequence[str],
        budget: int,
    ) -> VerifiedCapabilityToken:
        """Create a new root capability token.

        Mirrors Dafny ``create_root_token`` method.

        Preconditions:
          - token_id and agent_id non-empty
          - token_id not already in registry

        Postconditions:
          - Token is well-formed, root (depth == 0, parent_id == "")
          - In registry
          - Audit entry appended
          - Valid() preserved
        """
        with self._lock:
            self._check_valid("create_root_token", "pre")

            # Preconditions
            if not token_id or not agent_id:
                raise PreconditionViolation(
                    "create_root_token.requires",
                    self._CLASS_NAME,
                    "create_root_token",
                    "pre",
                    "token_id and agent_id must be non-empty",
                )
            if token_id in self._tokens:
                raise PreconditionViolation(
                    "create_root_token.requires",
                    self._CLASS_NAME,
                    "create_root_token",
                    "pre",
                    f"token_id {token_id!r} already in registry",
                )

            tok = VerifiedCapabilityToken(
                id=token_id,
                agent_id=agent_id,
                permissions=tuple(permissions),
                initial_budget=budget,
                budget_remaining=budget,
                parent_id="",
                delegation_depth=0,
            )

            self._tokens[token_id] = tok
            self._total_created_count += 1
            self._audit_log.append(CapabilityAuditEntry(
                token_id=token_id,
                operation="create",
                success=True,
                details="root_token",
            ))

            self._check_valid("create_root_token", "post")
            return tok

    def attenuate_token(
        self,
        parent_id: str,
        child_id: str,
        child_agent_id: str,
        child_permissions: Sequence[str],
        child_budget: int,
    ) -> AttenuateResult:
        """Delegate a capability token with attenuation.

        Mirrors Dafny ``attenuate_token`` method.

        P1a: child.permissions ⊆ parent.permissions
        P1b: child.budget ≤ parent.budget_remaining
        P1c: Non-subset permissions → failure
        P1d: Over-budget → failure
        """
        with self._lock:
            self._check_valid("attenuate_token", "pre")

            # Preconditions
            if parent_id not in self._tokens:
                raise PreconditionViolation(
                    "attenuate_token.requires",
                    self._CLASS_NAME,
                    "attenuate_token",
                    "pre",
                    f"parent_id {parent_id!r} not in registry",
                )
            if not child_id or not child_agent_id:
                raise PreconditionViolation(
                    "attenuate_token.requires",
                    self._CLASS_NAME,
                    "attenuate_token",
                    "pre",
                    "child_id and child_agent_id must be non-empty",
                )
            if child_id in self._tokens:
                raise PreconditionViolation(
                    "attenuate_token.requires",
                    self._CLASS_NAME,
                    "attenuate_token",
                    "pre",
                    f"child_id {child_id!r} already in registry",
                )

            parent = self._tokens[parent_id]
            result = attenuate(parent, child_id, child_agent_id, child_permissions, child_budget)

            if result.success:
                assert result.child is not None
                self._tokens[child_id] = result.child
                self._total_created_count += 1
                self._audit_log.append(CapabilityAuditEntry(
                    token_id=child_id,
                    operation="attenuate",
                    success=True,
                    details=f"child_of:{parent_id}",
                ))
            else:
                self._audit_log.append(CapabilityAuditEntry(
                    token_id=child_id,
                    operation="attenuate",
                    success=False,
                    details=result.reason,
                ))

            self._check_valid("attenuate_token", "post")
            return result

    def spend_budget(self, token_id: str, amount: int) -> bool:
        """Atomically spend budget from a token.

        Mirrors Dafny ``spend_budget`` method.

        P2a: remaining == old(remaining) - amount
        P2b: 0 ≤ remaining ≤ initial_budget
        P2c: amount > remaining → failure
        """
        with self._lock:
            self._check_valid("spend_budget", "pre")

            # Precondition
            if token_id not in self._tokens:
                raise PreconditionViolation(
                    "spend_budget.requires",
                    self._CLASS_NAME,
                    "spend_budget",
                    "pre",
                    f"token_id {token_id!r} not in registry",
                )

            tok = self._tokens[token_id]
            result = spend_budget(tok, amount)

            if result.success:
                assert result.token is not None
                self._tokens[token_id] = result.token
                self._audit_log.append(CapabilityAuditEntry(
                    token_id=token_id,
                    operation="spend",
                    success=True,
                    details=f"amount:{amount}",
                ))
            else:
                self._audit_log.append(CapabilityAuditEntry(
                    token_id=token_id,
                    operation="spend",
                    success=False,
                    details=result.reason,
                ))

            self._check_valid("spend_budget", "post")
            return result.success

    def check_permission(self, token_id: str, perm: str) -> bool:
        """Check if a token grants a specific permission.

        Mirrors Dafny ``check_permission`` method.

        P7: Returns True ⟺ has_permission(perm, token.permissions).
        """
        with self._lock:
            self._check_valid("check_permission", "pre")

            # Precondition
            if token_id not in self._tokens:
                raise PreconditionViolation(
                    "check_permission.requires",
                    self._CLASS_NAME,
                    "check_permission",
                    "pre",
                    f"token_id {token_id!r} not in registry",
                )

            tok = self._tokens[token_id]
            granted = has_permission(perm, tok.permissions)

            self._audit_log.append(CapabilityAuditEntry(
                token_id=token_id,
                operation="check_permission",
                success=granted,
                details=f"{'granted' if granted else 'denied'}:{perm}",
            ))

            self._check_valid("check_permission", "post")
            return granted

    def check_all_permissions(self, token_id: str, perms: Sequence[str]) -> bool:
        """Check if a token grants ALL of the specified permissions.

        Mirrors Dafny ``HasAllPermissions``.
        P7d: ⟺ ∀ p ∈ perms: has_permission(p, token.permissions).
        """
        with self._lock:
            self._check_valid("check_all_permissions", "pre")

            if token_id not in self._tokens:
                raise PreconditionViolation(
                    "check_all_permissions.requires",
                    self._CLASS_NAME,
                    "check_all_permissions",
                    "pre",
                    f"token_id {token_id!r} not in registry",
                )

            tok = self._tokens[token_id]
            granted = has_all_permissions(perms, tok.permissions)

            self._audit_log.append(CapabilityAuditEntry(
                token_id=token_id,
                operation="check_all_permissions",
                success=granted,
                details=f"{'granted' if granted else 'denied'}:{','.join(perms)}",
            ))

            self._check_valid("check_all_permissions", "post")
            return granted

    def get_token(self, token_id: str) -> VerifiedCapabilityToken:
        """Read-only accessor. Mirrors Dafny ``get_token``."""
        with self._lock:
            if token_id not in self._tokens:
                raise PreconditionViolation(
                    "get_token.requires",
                    self._CLASS_NAME,
                    "get_token",
                    "pre",
                    f"token_id {token_id!r} not in registry",
                )
            return self._tokens[token_id]

    # ── Read-only accessors ──────────────────────────────────────────────

    @property
    def token_ids(self) -> FrozenSet[str]:
        """All token IDs in registry."""
        with self._lock:
            return frozenset(self._tokens.keys())

    @property
    def audit_log(self) -> List[CapabilityAuditEntry]:
        """Copy of the audit log."""
        with self._lock:
            return list(self._audit_log)

    @property
    def total_created_count(self) -> int:
        """Total tokens ever created (monotonically increasing)."""
        with self._lock:
            return self._total_created_count

    def token_count(self) -> int:
        """Current number of tokens in registry."""
        with self._lock:
            return len(self._tokens)

    # ── Stats ────────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Diagnostic statistics."""
        with self._lock:
            return {
                "token_count": len(self._tokens),
                "total_created": self._total_created_count,
                "audit_entries": len(self._audit_log),
                "valid": self._valid(),
            }

    def __repr__(self) -> str:
        return (
            f"CapabilityManager(tokens={len(self._tokens)}, "
            f"total_created={self._total_created_count}, "
            f"audit_entries={len(self._audit_log)})"
        )

"""
Capability-based security tokens - unforgeable access credentials.

Tokens use HMAC-SHA256 signatures to prevent tampering.  The signing
key defaults to a per-process random secret but can be set explicitly
for multi-process deployments via ``CapabilityToken.set_signing_key()``.

A6: All budget mutations are guarded by a per-token ``threading.Lock``
to prevent concurrent overdraw.  ``reserve_budget()`` returns a
``BudgetReservation`` context-manager that auto-releases on failure.

**Structural immutability (A11)**: Identity fields (``id``, ``agent_id``,
``permissions``, ``budget_cents``, ``created_at``, ``expires_at``,
``metadata``) are frozen after construction.  ``permissions`` is stored
as a ``tuple`` to prevent in-place mutation (e.g. ``.append()``).
Only ``budget_remaining_cents`` remains mutable (guarded by ``_lock``).
The HMAC signature is retained as defence-in-depth for serialisation
boundaries where structural immutability cannot be enforced.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set, Generator, Tuple

# Per-process signing key (override with set_signing_key for multi-process)
_SIGNING_KEY: bytes = secrets.token_bytes(32)

# Fields that remain writable after construction.
# Everything else is frozen to prevent identity mutation.
_MUTABLE_FIELDS: frozenset[str] = frozenset({
    "budget_remaining_cents",  # consumed during execution (A6)
    "_lock",                   # set once in __post_init__
    "_frozen",                 # sentinel itself
})


def set_signing_key(key: bytes | str) -> None:
    """Set the global token signing key (call once at startup)."""
    global _SIGNING_KEY
    _SIGNING_KEY = key.encode() if isinstance(key, str) else key


@dataclass
class CapabilityToken:
    """Unforgeable capability token for agent authorization.

    Identity fields are **structurally frozen** after construction.
    Attempting to assign to ``permissions``, ``agent_id``, ``id``, etc.
    raises ``AttributeError``.  ``permissions`` is stored as a ``tuple``
    so in-place mutation (``list.append``) is impossible.

    ``budget_remaining_cents`` is the only mutable field, guarded by a
    per-token ``threading.Lock`` (see ``reserve_budget``).
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    permissions: Tuple[str, ...] = field(default_factory=tuple)
    budget_cents: int = 10000
    budget_remaining_cents: int = 10000
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    _signature: str = ""

    # ── Structural immutability ─────────────────────────────────

    def __setattr__(self, name: str, value: Any) -> None:
        """Block writes to identity fields after construction.

        During ``__init__`` / ``__post_init__``, ``_frozen`` has not yet
        been set, so all writes pass through.  Once ``_frozen`` is True,
        only fields in ``_MUTABLE_FIELDS`` can be written.
        """
        if getattr(self, "_frozen", False) and name not in _MUTABLE_FIELDS:
            raise AttributeError(
                f"CapabilityToken.{name} is frozen after construction "
                f"(identity fields are structurally immutable)"
            )
        object.__setattr__(self, name, value)

    def __post_init__(self):
        # Coerce list → tuple so callers can pass either
        if isinstance(self.permissions, list):
            object.__setattr__(self, "permissions", tuple(self.permissions))
        # Freeze metadata (shallow copy to dict - deep-freeze not needed
        # because HMAC does not cover metadata contents)
        if isinstance(self.metadata, dict):
            from types import MappingProxyType
            object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
        if not self._signature:
            object.__setattr__(self, "_signature", self._compute_signature())
        # A6: per-token lock for atomic budget mutations
        object.__setattr__(self, "_lock", threading.Lock())
        # Freeze identity fields - all subsequent writes to non-mutable
        # fields will raise AttributeError.
        object.__setattr__(self, "_frozen", True)

    def _compute_signature(self) -> str:
        """HMAC-SHA256 over the immutable token fields."""
        payload = json.dumps({
            "id": self.id, "agent_id": self.agent_id,
            "permissions": sorted(self.permissions),
            "budget_cents": self.budget_cents,
        }, sort_keys=True)
        return hmac.new(
            _SIGNING_KEY, payload.encode(), hashlib.sha256,
        ).hexdigest()

    def has_permission(self, perm: str) -> bool:
        """Check if token grants a specific permission."""
        for p in self.permissions:
            if p == perm:
                return True
            if p.endswith("*") and perm.startswith(p[:-1]):
                return True
        return False

    def has_all_permissions(self, perms: List[str]) -> bool:
        return all(self.has_permission(p) for p in perms)

    def has_budget(self, cost_cents: int) -> bool:
        with self._lock:
            return self.budget_remaining_cents >= cost_cents

    def consume_budget(self, cost_cents: int) -> bool:
        """Atomically consume budget.  Returns False if insufficient."""
        with self._lock:
            if self.budget_remaining_cents < cost_cents:
                return False
            self.budget_remaining_cents -= cost_cents
            return True

    # ── A6: Atomic budget reservation ─────────────────────────

    def reserve_budget(self, cost_cents: int) -> "BudgetReservation":
        """Atomically reserve *cost_cents* **before** execution.

        Returns a ``BudgetReservation`` that can be used as a context
        manager.  If the ``with`` block raises, the reserved amount is
        automatically credited back to the token.

        Usage::

            reservation = token.reserve_budget(cost)
            with reservation:
                await tool.execute(...)
            # budget permanently consumed on success
            # budget returned on exception

        Raises ``BudgetExhaustedError`` if insufficient funds.
        """
        with self._lock:
            if self.budget_remaining_cents < cost_cents:
                raise BudgetExhaustedError(
                    cost_cents, self.budget_remaining_cents, self.id,
                )
            self.budget_remaining_cents -= cost_cents
        return BudgetReservation(self, cost_cents)

    def _release_budget(self, cost_cents: int) -> None:
        """Return a previously reserved amount (called on rollback)."""
        with self._lock:
            self.budget_remaining_cents += cost_cents

    # ── Granular validity checks ────────────────────────────────

    @property
    def is_expired(self) -> bool:
        """True if the token has passed its expiration time."""
        return bool(self.expires_at and time.time() > self.expires_at)

    @property
    def is_tampered(self) -> bool:
        """True if the HMAC signature no longer matches (fields were mutated)."""
        return self._signature != self._compute_signature()

    @property
    def is_budget_exhausted(self) -> bool:
        """True if remaining budget is zero or negative."""
        return self.budget_remaining_cents <= 0

    def is_valid(self) -> bool:
        """
        Comprehensive validity check.

        Returns False if the token is expired, tampered, or budget-exhausted.
        Callers needing a *reason* should check the individual properties.
        """
        if self.is_expired:
            return False
        if self.is_tampered:
            return False
        # Budget exhaustion: token still 'structurally valid' but cannot
        # authorise any further spend.  We treat it as invalid at the
        # gate so that verify_action rejects before Z3 even runs.
        if self.is_budget_exhausted:
            return False
        return True

    def validation_error(self) -> Optional[str]:
        """
        Return a human-readable reason the token is invalid, or None.

        Order mirrors ``is_valid()`` - first failure wins.
        """
        if self.is_expired:
            return "token_expired"
        if self.is_tampered:
            return "token_tampered"
        if self.is_budget_exhausted:
            return "token_budget_exhausted"
        return None

    # ── Convenience ───────────────────────────────────────────

    @property
    def permission_set(self) -> Set[str]:
        return set(self.permissions)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "agent_id": self.agent_id,
            "permissions": list(self.permissions),
            "budget_cents": self.budget_cents,
            "budget_remaining_cents": self.budget_remaining_cents,
        }


# ── A6: Budget reservation helpers ────────────────────────────────


class BudgetExhaustedError(Exception):
    """Raised when ``reserve_budget`` cannot satisfy the requested cost."""

    def __init__(self, cost_cents: int, remaining_cents: int, token_id: str = ""):
        self.cost_cents = cost_cents
        self.remaining_cents = remaining_cents
        self.token_id = token_id
        super().__init__(
            f"Budget exhausted on token {token_id}: "
            f"need {cost_cents}, only {remaining_cents} remaining"
        )


class BudgetReservation:
    """Context-manager returned by ``CapabilityToken.reserve_budget()``.

    On *successful* exit the budget is permanently consumed (no-op).
    On *exception* the reserved amount is credited back to the token,
    guaranteeing that a failed execution does not drain budget.

    This is the core of the A6 "atomic reserve-before-execute" pattern.
    """

    __slots__ = ("_token", "_cost", "_committed")

    def __init__(self, token: CapabilityToken, cost_cents: int):
        self._token = token
        self._cost = cost_cents
        self._committed = False

    def __enter__(self) -> "BudgetReservation":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is not None:
            # Execution failed → rollback
            self._token._release_budget(self._cost)
        else:
            # Success → budget stays consumed
            self._committed = True
        return False  # never swallow exceptions

    @property
    def committed(self) -> bool:
        return self._committed

    @property
    def cost_cents(self) -> int:
        return self._cost

"""
Dafny Runtime Bridge - shared infrastructure for Dafny-verified modules.

Provides:
  - ``InvariantViolation``: raised when a Dafny ``Valid()`` predicate fails at runtime
  - ``PreconditionViolation``: raised when a Dafny ``requires`` clause fails at runtime
  - ``InvariantAuditLog``: singleton recording every invariant check for compliance audit
  - ``check_invariant()``: helper for instrumented pre/post-condition checks

Every Dafny-verified Python module (B1 tokens, B2 certificates, etc.) uses this
infrastructure to enforce at runtime the properties that Dafny proves statically.

Design principle: Dafny proves correctness under the formal model; the Python
runtime bridge enforces the *same* predicates at every method boundary, so that
any violation is caught immediately rather than silently corrupting state.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# =============================================================================
# Exceptions
# =============================================================================

class InvariantViolation(Exception):
    """Raised when a Dafny ``Valid()`` predicate fails at runtime.

    Attributes:
        property_id: The specific property that failed (e.g. "Valid()", "C1", "P3").
        class_name:  The class whose invariant was violated.
        method:      The method boundary where the violation was detected.
        phase:       "pre" or "post" - whether the violation was before or after
                     the method body executed.
        details:     Optional diagnostic information.
    """

    def __init__(
        self,
        property_id: str,
        class_name: str = "",
        method: str = "",
        phase: str = "",
        details: str = "",
    ):
        self.property_id = property_id
        self.class_name = class_name
        self.method = method
        self.phase = phase
        self.details = details
        parts = [f"{class_name}.{method}" if class_name else method,
                 f"[{phase}]" if phase else "",
                 f"invariant {property_id} violated"]
        if details:
            parts.append(f"- {details}")
        super().__init__(" ".join(p for p in parts if p))


class PreconditionViolation(InvariantViolation):
    """Raised when a Dafny ``requires`` clause fails at runtime.

    This is a subclass of ``InvariantViolation`` so callers catching
    invariant errors also catch precondition failures.
    """
    pass


# =============================================================================
# Audit log
# =============================================================================

@dataclass
class AuditEntry:
    """Single invariant-check record."""
    timestamp: float
    class_name: str
    method: str
    phase: str         # "pre" | "post"
    property_id: str
    passed: bool
    details: str = ""


class InvariantAuditLog:
    """Singleton recording every invariant check for compliance audit.

    Thread-safe.  All ``_check_invariant()`` calls across all Dafny-verified
    modules are recorded here.

    Usage::

        log = InvariantAuditLog.get_instance()
        entries = log.entries          # list of AuditEntry
        log.clear()                    # reset (testing only)
    """

    _instance: Optional["InvariantAuditLog"] = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []
        self._entry_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "InvariantAuditLog":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (testing only)."""
        cls._instance = None

    def record(
        self,
        class_name: str,
        method: str,
        phase: str,
        property_id: str,
        passed: bool,
        details: str = "",
    ) -> None:
        entry = AuditEntry(
            timestamp=time.time(),
            class_name=class_name,
            method=method,
            phase=phase,
            property_id=property_id,
            passed=passed,
            details=details,
        )
        with self._entry_lock:
            self._entries.append(entry)

    @property
    def entries(self) -> List[AuditEntry]:
        with self._entry_lock:
            return list(self._entries)

    def clear(self) -> None:
        with self._entry_lock:
            self._entries.clear()

    def entries_for(self, class_name: str, method: str = "") -> List[AuditEntry]:
        """Filter entries by class and optionally method."""
        with self._entry_lock:
            return [
                e for e in self._entries
                if e.class_name == class_name
                and (not method or e.method == method)
            ]


# =============================================================================
# Helper: check_invariant
# =============================================================================

def check_invariant(
    valid_fn,
    class_name: str,
    method: str,
    phase: str,
    property_id: str = "Valid()",
    details_fn=None,
) -> None:
    """Check an invariant predicate and record to audit log.

    Args:
        valid_fn:     Callable returning bool - the predicate to check.
        class_name:   Name of the class being checked.
        method:       Method boundary where the check occurs.
        phase:        "pre" or "post".
        property_id:  Human-readable property identifier.
        details_fn:   Optional callable returning diagnostic string on failure.

    Raises:
        InvariantViolation: if ``valid_fn()`` returns False.
    """
    log = InvariantAuditLog.get_instance()
    passed = valid_fn()
    details = ""
    if not passed and details_fn is not None:
        details = details_fn()
    log.record(class_name, method, phase, property_id, passed, details)
    if not passed:
        raise InvariantViolation(
            property_id=property_id,
            class_name=class_name,
            method=method,
            phase=phase,
            details=details,
        )

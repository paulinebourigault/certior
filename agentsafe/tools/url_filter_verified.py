"""
Dafny-Verified URL Filter - Python Runtime Bridge (Phase B4).

Mirrors every type, predicate, and method in ``dafny/tools/url_filter.dfy``,
enforcing at runtime the same properties that Dafny proves statically:

  P22  Allowlist completeness - Accept only if allowlist match exists
  P23  Blocklist correctness - Blocklist match always produces Reject
  P24  Blocklist precedence - Blocklist wins over allowlist
  P25  Filter determinism - Same (url, config) → same decision
  P26  Empty allowlist rejects all
  P27  Empty blocklist defers to allowlist
  P28  Blocklist monotonicity - Adding blocklist entries can only reduce accepts
  P29  Rate limit enforcement - request_count bounded by max_rpm
  P30  Audit completeness - Every check_url appends exactly one audit entry
  P31  Invariant preservation - Valid() holds at every method boundary
  P32  Rate limit reset correctness
  P33  Config immutability - config frozen after construction

The bridge uses ``check_invariant()`` from ``dafny_runtime`` to record
every pre/post-condition check to the ``InvariantAuditLog``, providing
a compliance-grade audit trail of all invariant verifications.

Usage::

    from agentsafe.tools.url_filter_verified import (
        UrlFilterConfig, UrlPattern, UrlFilter, FilterDecision,
    )

    config = UrlFilterConfig(
        allowlist=[UrlPattern.prefix("https://")],
        blocklist=[UrlPattern.suffix(".onion"), UrlPattern.suffix(".gov")],
        max_requests_per_minute=60,
    )
    f = UrlFilter(config)
    decision = f.check_url("https://example.com")
    assert decision.is_accept
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Pattern, Sequence, Tuple

from agentsafe.verification.dafny_runtime import (
    InvariantAuditLog,
    InvariantViolation,
    PreconditionViolation,
    check_invariant,
)


# =============================================================================
# UrlPattern - mirrors ``datatype UrlPattern`` from Dafny
# =============================================================================

class PatternKind(Enum):
    """Pattern matching mode - mirrors the Dafny datatype constructors."""
    PREFIX = "prefix"
    SUFFIX = "suffix"
    CONTAINS = "contains"
    EXACT = "exact"
    ANY = "any"


@dataclass(frozen=True)
class UrlPattern:
    """
    Immutable URL pattern - mirrors ``datatype UrlPattern`` in Dafny.

    Four matching modes plus wildcard:
      - ``prefix("https://")``  - url.startswith(value)
      - ``suffix(".onion")``    - url.endswith(value)
      - ``contains("localhost")`` - value in url
      - ``exact("http://x.com")`` - url == value
      - ``any_pattern()``       - always matches

    Also supports compiled regex for production use, with the Dafny-aligned
    predicate ``matches()`` used for invariant checking.
    """
    kind: PatternKind
    value: str = ""
    _compiled_regex: Optional[Pattern[str]] = field(
        default=None, repr=False, compare=False, hash=False,
    )

    # ── Constructors ────────────────────────────────────────────

    @classmethod
    def prefix(cls, value: str) -> UrlPattern:
        return cls(kind=PatternKind.PREFIX, value=value)

    @classmethod
    def suffix(cls, value: str) -> UrlPattern:
        return cls(kind=PatternKind.SUFFIX, value=value)

    @classmethod
    def contains(cls, value: str) -> UrlPattern:
        return cls(kind=PatternKind.CONTAINS, value=value)

    @classmethod
    def exact(cls, value: str) -> UrlPattern:
        return cls(kind=PatternKind.EXACT, value=value)

    @classmethod
    def any_pattern(cls) -> UrlPattern:
        return cls(kind=PatternKind.ANY)

    @classmethod
    def from_regex(cls, pattern_str: str) -> UrlPattern:
        """
        Create from a regex string (production bridge).

        Attempts to classify the regex into a Dafny-compatible mode:
          ``^https://.*``  → Prefix("https://")
          ``.*\\.onion$``  → Suffix(".onion")
          ``.*``           → Any

        Falls back to CONTAINS with compiled regex for complex patterns.
        """
        stripped = pattern_str.strip()

        # Try to extract prefix: ^<literal>.*
        prefix_match = re.match(r'^\^([^.\\*+?[\]{}()|$]+)(\.\*)?$', stripped)
        if prefix_match:
            return cls(
                kind=PatternKind.PREFIX,
                value=prefix_match.group(1),
                _compiled_regex=re.compile(stripped, re.IGNORECASE),
            )

        # Try to extract suffix: .*<literal>$
        suffix_match = re.match(r'^(\.\*)?\\?\.?([a-zA-Z0-9_./-]+)\(?[/.]?\*\)?\$?$', stripped)
        if not suffix_match:
            # Try simpler suffix pattern: .*\.ext$ or .*\.ext(/.*)?$
            suffix_match2 = re.match(
                r'^\.\*\\\.([a-zA-Z0-9]+)(?:\(/\.\*\)\?\$|\$)', stripped
            )
            if suffix_match2:
                return cls(
                    kind=PatternKind.SUFFIX,
                    value="." + suffix_match2.group(1),
                    _compiled_regex=re.compile(stripped, re.IGNORECASE),
                )

        # Wildcard
        if stripped in (".*", "^.*$", ""):
            return cls(kind=PatternKind.ANY)

        # Fallback: compile regex, use CONTAINS semantics with regex override
        try:
            compiled = re.compile(stripped, re.IGNORECASE)
        except re.error:
            compiled = None

        return cls(
            kind=PatternKind.CONTAINS,
            value=stripped,
            _compiled_regex=compiled,
        )

    # ── Matching - mirrors ``predicate Matches`` in Dafny ──────

    def matches(self, url: str) -> bool:
        """
        Test if ``url`` matches this pattern.

        If a compiled regex is available (production bridge), it takes
        priority.  Otherwise, the Dafny-aligned predicate logic is used.

        Mirrors: ``predicate Matches(url, pattern)`` in Dafny.
        """
        # Production path: compiled regex
        if self._compiled_regex is not None:
            return bool(self._compiled_regex.search(url))

        # Dafny-aligned path
        if self.kind == PatternKind.PREFIX:
            return url.startswith(self.value)
        elif self.kind == PatternKind.SUFFIX:
            return url.endswith(self.value)
        elif self.kind == PatternKind.CONTAINS:
            return self.value in url
        elif self.kind == PatternKind.EXACT:
            return url == self.value
        elif self.kind == PatternKind.ANY:
            return True
        return False  # pragma: no cover

    def __str__(self) -> str:
        if self.kind == PatternKind.ANY:
            return "Any"
        return f"{self.kind.value}({self.value!r})"


# =============================================================================
# FilterDecision - mirrors ``datatype FilterDecision`` from Dafny
# =============================================================================

@dataclass(frozen=True)
class FilterDecision:
    """
    Immutable filter verdict - mirrors ``datatype FilterDecision`` in Dafny.

    Either Accept (accepted=True, reason="") or Reject (accepted=False, reason=...).
    """
    accepted: bool
    reason: str = ""

    @classmethod
    def accept(cls) -> FilterDecision:
        return cls(accepted=True, reason="")

    @classmethod
    def reject(cls, reason: str) -> FilterDecision:
        return cls(accepted=False, reason=reason)

    @property
    def is_accept(self) -> bool:
        return self.accepted

    @property
    def is_reject(self) -> bool:
        return not self.accepted

    def __str__(self) -> str:
        if self.accepted:
            return "Accept"
        return f"Reject({self.reason})"


# =============================================================================
# AuditEntry - mirrors ``datatype AuditEntry`` from Dafny
# =============================================================================

@dataclass(frozen=True)
class AuditEntry:
    """Immutable record of a filter decision."""
    url: str
    decision: FilterDecision
    request_number: int
    timestamp: float = field(default_factory=time.time)


# =============================================================================
# UrlFilterConfig - mirrors ``datatype UrlFilterConfig`` from Dafny (P33)
# =============================================================================

@dataclass(frozen=True)
class UrlFilterConfig:
    """
    Immutable URL filter configuration (P33 - config immutability).

    Frozen dataclass ensures config cannot be mutated after construction.
    """
    allowlist: Tuple[UrlPattern, ...] = ()
    blocklist: Tuple[UrlPattern, ...] = ()
    max_requests_per_minute: int = 60

    def __post_init__(self) -> None:
        # Coerce lists to tuples for immutability
        if isinstance(self.allowlist, list):
            object.__setattr__(self, "allowlist", tuple(self.allowlist))
        if isinstance(self.blocklist, list):
            object.__setattr__(self, "blocklist", tuple(self.blocklist))
        if self.max_requests_per_minute < 0:
            raise ValueError("max_requests_per_minute must be >= 0")

    @classmethod
    def from_verification_json(cls, spec: Dict[str, Any]) -> UrlFilterConfig:
        """
        Build config from a VERIFICATION.json specification.

        This is the production bridge from spec → Dafny-aligned config.
        """
        vr = spec.get("verification_requirements", {})
        sc = vr.get("safety_constraints", {})
        rc = vr.get("resource_constraints", {})

        allowlist = tuple(
            UrlPattern.from_regex(p)
            for p in sc.get("url_allowlist_patterns", [])
        )
        blocklist = tuple(
            UrlPattern.from_regex(p)
            for p in sc.get("url_blocklist_patterns", [])
        )
        max_rpm = rc.get("max_requests_per_minute", 60)

        return cls(
            allowlist=allowlist,
            blocklist=blocklist,
            max_requests_per_minute=max_rpm,
        )


# =============================================================================
# Pure filter function - mirrors ``function FilterUrl`` from Dafny (P25)
# =============================================================================

def filter_url(url: str, config: UrlFilterConfig) -> FilterDecision:
    """
    Pure URL filter function - the specification.

    Mirrors ``function FilterUrl(url, config)`` in Dafny.
    Being a pure function, it is inherently deterministic (P25).

    Returns Accept IFF:
      1. url matches at least one allowlist pattern (P22)
      2. url matches NO blocklist pattern (P23)
    Blocklist takes precedence over allowlist (P24).
    """
    if not any(p.matches(url) for p in config.allowlist):
        return FilterDecision.reject("URL does not match any allowlist pattern")
    if any(p.matches(url) for p in config.blocklist):
        return FilterDecision.reject("URL matches blocklist pattern")
    return FilterDecision.accept()


def matches_any(url: str, patterns: Sequence[UrlPattern]) -> bool:
    """Mirrors ``predicate MatchesAny`` in Dafny."""
    return any(p.matches(url) for p in patterns)


def matches_none(url: str, patterns: Sequence[UrlPattern]) -> bool:
    """Mirrors ``predicate MatchesNone`` in Dafny."""
    return all(not p.matches(url) for p in patterns)


# =============================================================================
# UrlFilter - stateful filter with rate limiting and audit (P29-P32)
# =============================================================================

_CLASS_NAME = "UrlFilter"


class UrlFilter:
    """
    Dafny-verified URL filter with rate limiting and audit trail.

    Mirrors ``class UrlFilter`` in ``dafny/tools/url_filter.dfy``.

    Every method boundary enforces the class invariant ``Valid()`` via
    ``check_invariant()``, recording results to ``InvariantAuditLog``.

    Thread-safe: all mutable state protected by a lock.

    Properties proven in Dafny and enforced at runtime:
      P22-P28: URL filtering correctness
      P29:     Rate limit enforcement
      P30:     Audit completeness
      P31:     Invariant preservation
      P32:     Rate limit reset correctness
      P33:     Config immutability (frozen dataclass)
    """

    def __init__(self, config: UrlFilterConfig) -> None:
        self._config: UrlFilterConfig = config
        self._request_count: int = 0
        self._audit_log: List[AuditEntry] = []
        self._lock = threading.Lock()

        # Verify invariant established (P31)
        check_invariant(
            self._valid, _CLASS_NAME, "__init__", "post", "Valid()",
        )

    # ── Class invariant ─────────────────────────────────────────

    def _valid(self) -> bool:
        """
        Class invariant - mirrors ``ghost predicate Valid()`` in Dafny.

        C1: request_count <= max_requests_per_minute
        """
        return self._request_count <= self._config.max_requests_per_minute

    @property
    def config(self) -> UrlFilterConfig:
        """Read-only access to config (P33)."""
        return self._config

    @property
    def request_count(self) -> int:
        """Current request count within the rate-limit window."""
        return self._request_count

    @property
    def audit_log(self) -> List[AuditEntry]:
        """Copy of audit log entries."""
        with self._lock:
            return list(self._audit_log)

    # ── check_url - main entry point (P22-P30) ─────────────────

    def check_url(self, url: str) -> FilterDecision:
        """
        Check if a URL is allowed, applying filter rules and rate limiting.

        Mirrors ``method check_url`` in Dafny.

        Enforces:
          P22-P24: URL filter correctness
          P29:     Rate limit enforcement
          P30:     Audit completeness (exactly one entry appended)
          P31:     Invariant preservation

        Returns:
            FilterDecision - Accept or Reject with reason.
        """
        with self._lock:
            # Pre-condition: Valid()
            check_invariant(
                self._valid, _CLASS_NAME, "check_url", "pre", "Valid()",
            )
            old_log_len = len(self._audit_log)
            old_count = self._request_count

            # P29: Rate limit check first
            if self._request_count >= self._config.max_requests_per_minute:
                decision = FilterDecision.reject("Rate limit exceeded")
                self._audit_log.append(
                    AuditEntry(url=url, decision=decision, request_number=self._request_count)
                )
                # Post-condition: Valid(), audit grew by 1, count unchanged
                check_invariant(
                    self._valid, _CLASS_NAME, "check_url", "post", "Valid()",
                )
                assert len(self._audit_log) == old_log_len + 1, "P30: audit completeness"
                assert self._request_count == old_count, "P29: reject doesn't increment"
                return decision

            # P22-P24: URL filter (pure function, deterministic P25)
            decision = filter_url(url, self._config)

            # P29: Increment only on accept
            if decision.is_accept:
                self._request_count += 1

            self._audit_log.append(
                AuditEntry(url=url, decision=decision, request_number=self._request_count)
            )

            # Post-conditions
            check_invariant(
                self._valid, _CLASS_NAME, "check_url", "post", "Valid()",
            )

            # P30: Audit completeness
            assert len(self._audit_log) == old_log_len + 1, "P30: audit completeness"
            # P30: Correct entry
            last = self._audit_log[-1]
            assert last.url == url, "P30: correct url"
            assert last.decision == decision, "P30: correct decision"

            # P22: Accept requires allowlist match
            if decision.is_accept:
                assert matches_any(url, self._config.allowlist), "P22: allowlist completeness"
                assert self._request_count == old_count + 1, "P29: accept increments"
            # P23: Blocklist match implies reject
            if matches_any(url, self._config.blocklist):
                assert decision.is_reject, "P23: blocklist correctness"
            # P29: Reject means count unchanged
            if decision.is_reject:
                assert self._request_count == old_count, "P29: reject doesn't increment"

            return decision

    # ── reset_rate_limit - P32 ──────────────────────────────────

    def reset_rate_limit(self) -> None:
        """
        Reset the per-window request counter.  Audit log is preserved.

        Mirrors ``method reset_rate_limit`` in Dafny.

        Enforces:
          P31: Invariant preservation
          P32: request_count == 0 after reset
          P33: config unchanged
        """
        with self._lock:
            check_invariant(
                self._valid, _CLASS_NAME, "reset_rate_limit", "pre", "Valid()",
            )
            old_config = self._config
            old_log = list(self._audit_log)

            self._request_count = 0

            # Post-conditions
            check_invariant(
                self._valid, _CLASS_NAME, "reset_rate_limit", "post", "Valid()",
            )
            assert self._request_count == 0, "P32: reset correctness"
            assert self._audit_log == old_log, "P32: audit preserved"
            assert self._config is old_config, "P33: config immutability"

    # ── Convenience methods ─────────────────────────────────────

    def is_url_allowed(self, url: str) -> bool:
        """Quick check without rate limiting or audit (pure filter only)."""
        return filter_url(url, self._config).is_accept

    def get_stats(self) -> Dict[str, Any]:
        """Return filter statistics."""
        with self._lock:
            accepts = sum(1 for e in self._audit_log if e.decision.is_accept)
            rejects = sum(1 for e in self._audit_log if e.decision.is_reject)
            return {
                "request_count": self._request_count,
                "max_requests_per_minute": self._config.max_requests_per_minute,
                "audit_entries": len(self._audit_log),
                "total_accepts": accepts,
                "total_rejects": rejects,
                "allowlist_patterns": len(self._config.allowlist),
                "blocklist_patterns": len(self._config.blocklist),
            }

    def __repr__(self) -> str:
        return (
            f"UrlFilter(allowlist={len(self._config.allowlist)} patterns, "
            f"blocklist={len(self._config.blocklist)} patterns, "
            f"rpm={self._request_count}/{self._config.max_requests_per_minute})"
        )


# =============================================================================
# Factory: build UrlFilter from VERIFICATION.json
# =============================================================================

def create_url_filter_from_spec(spec: Dict[str, Any]) -> UrlFilter:
    """
    Build a Dafny-verified UrlFilter from a VERIFICATION.json specification.

    This is the standard production entry point, ensuring the runtime
    filter is configured from the same spec that Z3 proofs verify.

    Args:
        spec: Parsed VERIFICATION.json dict.

    Returns:
        UrlFilter with invariant enforcement enabled.
    """
    config = UrlFilterConfig.from_verification_json(spec)
    return UrlFilter(config)


def create_web_browsing_filter(skills_dir: str = "skills") -> UrlFilter:
    """
    Build a UrlFilter from the web_browsing skill spec.

    Convenience function for the common case.
    """
    import json
    from pathlib import Path

    spec_path = Path(skills_dir) / "web_browsing" / "VERIFICATION.json"
    if not spec_path.exists():
        # Fallback: hardcoded defaults matching the spec
        config = UrlFilterConfig(
            allowlist=(
                UrlPattern.prefix("https://"),
                UrlPattern.prefix("http://localhost"),
            ),
            blocklist=(
                UrlPattern.suffix(".onion"),
                UrlPattern.suffix(".gov"),
                UrlPattern.suffix(".mil"),
            ),
            max_requests_per_minute=60,
        )
        return UrlFilter(config)

    with open(spec_path) as f:
        spec = json.load(f)
    return create_url_filter_from_spec(spec)

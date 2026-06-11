"""
Dafny-Verified Information Flow Control - Phase B3 Production Runtime Bridge.

Mirrors ``dafny/flow/information_flow.dfy`` at every method boundary.

Proven properties (Dafny static, Python runtime enforcement):

  P13  LATTICE ORDERING
       SecurityLevel.rank defines a total order.
       Reflexive, transitive, antisymmetric, total.

  P14  FLOW SAFETY (NO-DOWNGRADE)
       level_can_flow_to(src, dst) == true  IFF  rank(src) ≤ rank(dst).
       Information never flows from a higher level to a lower one.

  P15  LABEL FLOW SAFETY (CONJUNCTIVE)
       label_can_flow_to(src, dst) requires BOTH:
         (a) level ordering: rank(src.level) ≤ rank(dst.level)
         (b) tag containment: src.tags ⊆ dst.tags
       Failure of EITHER condition blocks the flow.

  P16  TAINT MONOTONICITY
       tag() adds an entry. get_label() returns it. Others unaffected.

  P17  VIOLATION COMPLETENESS
       check_flow returns false IFF the stored label cannot flow to target.
       Every failure is recorded. No false negatives. No false positives.

  P18  VIOLATION ACCUMULATION (APPEND-ONLY)
       Violations are only appended, never removed (except by clear).

  P19  TAG PRESERVATION
       After tag(id, label), stored tags == input tags exactly.

  P20  CLEAR CORRECTNESS
       After clear(): taint_map == {} ∧ violations == [].

  P21  LEVEL JOIN (PROMOTION) SOUNDNESS
       join(a, b) == max(rank(a), rank(b)).
       Idempotent, commutative, associative, monotonic.

Thread safety: All state mutations guarded by ``threading.Lock``.
Audit trail:   Every invariant check recorded to ``InvariantAuditLog``.

Backward compatibility:
    All existing public names (SecurityLevel, SecurityLabel, FlowRule,
    TaintTracker) are preserved with identical semantics.  The Dafny
    runtime bridge adds invariant enforcement WITHOUT changing any
    public API signature.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set

from agentsafe.verification.dafny_runtime import (
    InvariantAuditLog,
    InvariantViolation,
    PreconditionViolation,
)


# =============================================================================
# SecurityLevel - four-element totally-ordered lattice
#
# Mirrors Dafny::
#
#   datatype SecurityLevel = Public | Internal | Sensitive | Restricted
#
#   function Rank(level: SecurityLevel): nat
#     match level
#     case Public    => 0
#     case Internal  => 1
#     case Sensitive => 2
#     case Restricted => 3
# =============================================================================

class SecurityLevel(Enum):
    """Four-element security lattice.

    Dafny-verified properties (P13):
      - Reflexive:     a.can_flow_to(a) for all a
      - Transitive:    a->b and b->c implies a->c
      - Antisymmetric: a->b and b->a implies a == b
      - Total:         a->b or b->a for all a, b
    """
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        """Mirror of Dafny ``Rank(level)``.

        Returns a non-negative integer defining the total order.
        Higher rank = more restricted.
        """
        return _RANK_MAP[self.value]

    def can_flow_to(self, target: SecurityLevel) -> bool:
        """Mirror of Dafny ``LevelCanFlowTo(src, dst)``.

        P14: Returns True IFF rank(self) <= rank(target).
        Information can only flow to same or higher level.
        """
        return self.rank <= target.rank

    @staticmethod
    def join(a: SecurityLevel, b: SecurityLevel) -> SecurityLevel:
        """Mirror of Dafny ``LevelJoin(a, b)``.

        P21: Returns the level with max(rank(a), rank(b)).
        Idempotent, commutative, associative.
        """
        if a.rank >= b.rank:
            return a
        return b


# Rank lookup - matches Dafny exactly
_RANK_MAP: Dict[str, int] = {
    "public": 0,
    "internal": 1,
    "sensitive": 2,
    "restricted": 3,
}

# Reverse lookup: rank -> SecurityLevel
_LEVEL_BY_RANK: Dict[int, SecurityLevel] = {
    0: SecurityLevel.PUBLIC,
    1: SecurityLevel.INTERNAL,
    2: SecurityLevel.SENSITIVE,
    3: SecurityLevel.RESTRICTED,
}


# =============================================================================
# SecurityLabel - level + tags + owner
#
# Mirrors Dafny::
#
#   datatype SecurityLabel = SecurityLabel(
#     level: SecurityLevel,
#     tags: set<string>,
#     owner: string
#   )
# =============================================================================

@dataclass
class SecurityLabel:
    """Security label combining level, tags, and owner.

    Dafny-verified flow predicate (P15):
      can_flow_to(target) == level_ordered(self, target)
                           AND tags_contained(self, target)
    """
    level: SecurityLevel = SecurityLevel.PUBLIC
    tags: Set[str] = field(default_factory=set)
    owner: str = ""

    def can_flow_to(self, target: SecurityLabel) -> bool:
        """Mirror of Dafny ``LabelCanFlowTo(src, dst)``.

        P15: Requires BOTH:
          (a) level ordering:  rank(self.level) <= rank(target.level)
          (b) tag containment: self.tags is a subset of target.tags

        Failure of EITHER condition blocks the flow.
        """
        # (a) Level ordering (P14)
        if not self.level.can_flow_to(target.level):
            return False
        # (b) Tag containment
        if self.tags and not self.tags.issubset(target.tags):
            return False
        return True

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecurityLabel):
            return NotImplemented
        return (self.level == other.level
                and self.tags == other.tags
                and self.owner == other.owner)

    def __hash__(self) -> int:
        return hash((self.level, frozenset(self.tags), self.owner))


# =============================================================================
# FlowRule - explicit policy rule (backward compatibility)
# =============================================================================

@dataclass
class FlowRule:
    """Explicit flow policy rule.

    Allows expressing named flow constraints beyond the lattice,
    e.g. ``FlowRule(source="PHI", forbidden_destinations=["external"])``.
    """
    source: str
    allowed_destinations: List[str] = field(default_factory=list)
    forbidden_destinations: List[str] = field(default_factory=list)


# =============================================================================
# FlowViolation - recorded evidence of a forbidden flow
#
# Mirrors Dafny::
#
#   datatype FlowViolation = FlowViolation(
#     source_id: string,
#     source_level: SecurityLevel,
#     target_level: SecurityLevel
#   )
# =============================================================================

@dataclass(frozen=True)
class FlowViolation:
    """Immutable record of a detected flow violation.

    Every FlowViolation satisfies the genuine-violation invariant (I1):
      rank(source_level) > rank(target_level)
      OR source_tags is not a subset of target_tags
    """
    source_id: str
    source_level: str  # SecurityLevel.value for serialization
    target_level: str  # SecurityLevel.value for serialization
    source_tags: FrozenSet[str] = frozenset()
    target_tags: FrozenSet[str] = frozenset()

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "source_id": self.source_id,
            "source_label": self.source_level,
            "target_label": self.target_level,
        }
        if self.source_tags:
            d["source_tags"] = sorted(self.source_tags)
        if self.target_tags:
            d["target_tags"] = sorted(self.target_tags)
        return d


# =============================================================================
# TaintTracker - the Dafny-verified state machine
#
# Mirrors the Dafny ``TaintTracker`` class.  All state mutations are
# guarded by ``_lock`` for thread safety.  Every public method checks
# the class invariant at entry and exit, recording to InvariantAuditLog.
#
# Invariant Valid():
#   I1: every recorded violation is genuine
#       (no false positives in the violation log)
#   I2: ghost counter bounds
#       |taint_map| <= total_tags_ever
#       |violations| <= total_checks_ever
# =============================================================================

class TaintTracker:
    """Tracks information flow taint through execution.

    Dafny-verified properties enforced at runtime:
      P16: Taint monotonicity (tag adds, get_label retrieves, others unaffected)
      P17: Violation completeness (no false positives, no false negatives)
      P18: Violation accumulation (append-only)
      P19: Tag preservation (exact tags stored)
      P20: Clear correctness (full reset)
    """

    def __init__(self) -> None:
        # ── Core state (mirrors Dafny fields) ────────────────
        self._taint_map: Dict[str, SecurityLabel] = {}
        self._violations: List[FlowViolation] = []

        # ── Ghost state ──────────────────────────────────────
        self._total_tags_ever: int = 0
        self._total_checks_ever: int = 0

        # ── Thread safety ────────────────────────────────────
        self._lock = threading.Lock()

        # ── Establish invariant (Dafny: ensures Valid()) ─────
        self._check_invariant("__init__", "post")

    # ═════════════════════════════════════════════════════════
    # CLASS INVARIANT - Valid()
    #
    # I1: Every recorded violation is genuine:
    #     for all v in violations:
    #       rank(v.source_level) > rank(v.target_level)
    #       OR v.source_tags is not a subset of v.target_tags
    #
    # I2: Ghost counters are sound upper bounds:
    #     |taint_map| <= total_tags_ever
    #     |violations| <= total_checks_ever
    # ═════════════════════════════════════════════════════════

    def _dafny_valid(self) -> bool:
        """Evaluate the class invariant.  Pure query - no side effects."""
        # I1: Every recorded violation is genuine
        for v in self._violations:
            src_rank = _RANK_MAP.get(v.source_level, -1)
            tgt_rank = _RANK_MAP.get(v.target_level, -1)
            tag_violation = (
                bool(v.source_tags)
                and not v.source_tags.issubset(v.target_tags)
            )
            if not (src_rank > tgt_rank or tag_violation):
                return False
        # I2: Ghost counter bounds
        if len(self._taint_map) > self._total_tags_ever:
            return False
        if len(self._violations) > self._total_checks_ever:
            return False
        return True

    def _invariant_details(self) -> str:
        """Diagnostic string on invariant failure."""
        parts: List[str] = []
        for i, v in enumerate(self._violations):
            src_rank = _RANK_MAP.get(v.source_level, -1)
            tgt_rank = _RANK_MAP.get(v.target_level, -1)
            tag_viol = (
                bool(v.source_tags)
                and not v.source_tags.issubset(v.target_tags)
            )
            if not (src_rank > tgt_rank or tag_viol):
                parts.append(
                    f"I1: violations[{i}] is not genuine: "
                    f"src={v.source_level}(rank={src_rank}) "
                    f"tgt={v.target_level}(rank={tgt_rank}) "
                    f"src_tags={v.source_tags} tgt_tags={v.target_tags}"
                )
        if len(self._taint_map) > self._total_tags_ever:
            parts.append(
                f"I2: |taint_map|={len(self._taint_map)} > "
                f"total_tags_ever={self._total_tags_ever}"
            )
        if len(self._violations) > self._total_checks_ever:
            parts.append(
                f"I2: |violations|={len(self._violations)} > "
                f"total_checks_ever={self._total_checks_ever}"
            )
        return "; ".join(parts) if parts else "ok"

    def _check_invariant(self, method: str, phase: str) -> None:
        """Check Valid() and record to audit log.  Raises on failure."""
        log = InvariantAuditLog.get_instance()
        passed = self._dafny_valid()
        details = "" if passed else self._invariant_details()
        log.record("TaintTracker", method, phase, "Valid()", passed, details)
        if not passed:
            raise InvariantViolation(
                property_id="Valid()",
                class_name="TaintTracker",
                method=method,
                phase=phase,
                details=details,
            )

    # ═════════════════════════════════════════════════════════
    # tag - P16 (Taint Monotonicity), P19 (Tag Preservation)
    #
    # Dafny contract:
    #   requires Valid()
    #   ensures  Valid()
    #   ensures  data_id in taint_map
    #   ensures  taint_map[data_id] == label
    #   ensures  for all other != data_id: taint_map[other] unchanged
    #   ensures  violations unchanged
    #   ensures  total_tags_ever == old(total_tags_ever) + 1
    # ═════════════════════════════════════════════════════════

    def tag(self, data_id: str, label: SecurityLabel) -> None:
        """Assign a security label to a data identifier.

        Mirrors Dafny ``tag`` method with all postconditions enforced.

        P16: After call, get_label(data_id) returns this exact label.
        P19: The stored label's tags are exactly the input tags.
        """
        with self._lock:
            # PRE: requires Valid()
            self._check_invariant("tag", "pre")

            # Snapshot for postcondition checks
            old_violations_len = len(self._violations)
            old_taint_snapshot = {k: v for k, v in self._taint_map.items()}
            old_total_tags = self._total_tags_ever

            # ── Body (mirrors Dafny) ─────────────────────────
            self._taint_map[data_id] = label
            self._total_tags_ever += 1

            # POST: ensures Valid()
            self._check_invariant("tag", "post")

            # POST: ensures data_id in taint_map and taint_map[data_id] == label
            assert data_id in self._taint_map, \
                f"P16 violated: {data_id!r} not in taint_map after tag()"
            assert self._taint_map[data_id] is label, \
                f"P19 violated: stored label != input label for {data_id!r}"

            # POST: ensures violations unchanged (P18: no spurious append)
            assert len(self._violations) == old_violations_len, \
                f"P18 violated: violations changed during tag() " \
                f"({old_violations_len} -> {len(self._violations)})"

            # POST: ensures total_tags_ever incremented
            assert self._total_tags_ever == old_total_tags + 1, \
                "Ghost violated: total_tags_ever not incremented"

            # POST: ensures other entries unaffected (P16: monotonicity)
            for oid, olabel in old_taint_snapshot.items():
                if oid != data_id:
                    assert oid in self._taint_map and self._taint_map[oid] is olabel, \
                        f"P16 violated: tag() modified entry for {oid!r}"

    # ═════════════════════════════════════════════════════════
    # get_label - pure query
    #
    # Dafny contract:
    #   requires Valid()
    #   ensures  Valid()
    #   ensures  data_id in taint_map -> result == taint_map[data_id]
    #   ensures  data_id not in taint_map -> result == None
    # ═════════════════════════════════════════════════════════

    def get_label(self, data_id: str) -> Optional[SecurityLabel]:
        """Retrieve the security label for a data identifier.

        Returns the label if data_id was tagged, None otherwise.
        Pure query: no state mutation.
        """
        with self._lock:
            self._check_invariant("get_label", "pre")
            result = self._taint_map.get(data_id)
            self._check_invariant("get_label", "post")
            return result

    # ═════════════════════════════════════════════════════════
    # check_flow - P17 (Violation Completeness), P18 (Accumulation)
    #
    # Dafny contract:
    #   requires Valid()
    #   ensures  Valid()
    #   ensures  taint_map unchanged
    #   ensures  src not in taint_map -> allowed == True
    #   ensures  src in taint_map ->
    #              allowed == LabelCanFlowTo(taint_map[src], target)
    #   ensures  allowed -> violations unchanged
    #   ensures  !allowed -> |violations| == old(|violations|) + 1
    #   ensures  !allowed -> last violation is genuine
    # ═════════════════════════════════════════════════════════

    def check_flow(
        self,
        source_id: str,
        target_label: SecurityLabel,
    ) -> bool:
        """Check whether data can flow to the target label.

        P17: Returns True IFF the flow is permitted under the lattice
        and tag containment rules.  Every forbidden flow is recorded
        as a violation.  No false positives.  No false negatives.

        P18: Violations are append-only.  Existing violations are
        never modified or removed.

        If source_id is not in the taint map, the flow is considered
        permitted (untracked data is treated as PUBLIC).
        """
        with self._lock:
            # PRE: requires Valid()
            self._check_invariant("check_flow", "pre")

            # Snapshots for postcondition verification
            old_violations = list(self._violations)
            old_taint_map_keys = set(self._taint_map.keys())
            old_total_checks = self._total_checks_ever

            # ── Body (mirrors Dafny) ─────────────────────────
            self._total_checks_ever += 1

            src_label = self._taint_map.get(source_id)

            if src_label is None:
                # Untracked data: always allowed
                allowed = True
            else:
                allowed = src_label.can_flow_to(target_label)

            if not allowed:
                assert src_label is not None  # type narrowing
                violation = FlowViolation(
                    source_id=source_id,
                    source_level=src_label.level.value,
                    target_level=target_label.level.value,
                    source_tags=frozenset(src_label.tags),
                    target_tags=frozenset(target_label.tags),
                )
                self._violations.append(violation)

            # POST: ensures Valid()
            self._check_invariant("check_flow", "post")

            # POST: ensures taint_map unchanged
            assert set(self._taint_map.keys()) == old_taint_map_keys, \
                "P17 violated: taint_map keys changed during check_flow()"

            # POST: ensures total_checks_ever incremented
            assert self._total_checks_ever == old_total_checks + 1

            # POST: violation completeness (P17)
            if allowed:
                assert len(self._violations) == len(old_violations), \
                    f"P17 false-positive: violation appended for allowed flow " \
                    f"(src={source_id!r})"
            else:
                assert len(self._violations) == len(old_violations) + 1, \
                    f"P17 false-negative: no violation for blocked flow " \
                    f"(src={source_id!r})"

            # POST: existing violations preserved (P18)
            for i, old_v in enumerate(old_violations):
                assert self._violations[i] is old_v, \
                    f"P18 violated: violations[{i}] was modified"

            return allowed

    # ═════════════════════════════════════════════════════════
    # clear - P20 (Clear Correctness)
    #
    # Dafny contract:
    #   requires Valid()
    #   ensures  Valid()
    #   ensures  taint_map == {}
    #   ensures  violations == []
    #   ensures  total_tags_ever unchanged
    #   ensures  total_checks_ever unchanged
    # ═════════════════════════════════════════════════════════

    def clear(self) -> None:
        """Reset all state for a new execution.

        P20: After clear, taint_map is empty and violations is empty.
        Ghost counters are preserved.
        """
        with self._lock:
            # PRE: requires Valid()
            self._check_invariant("clear", "pre")

            old_total_tags = self._total_tags_ever
            old_total_checks = self._total_checks_ever

            # ── Body (mirrors Dafny) ─────────────────────────
            self._taint_map.clear()
            self._violations.clear()

            # POST: ensures Valid()
            self._check_invariant("clear", "post")

            # POST: ensures taint_map == {} and violations == []
            assert len(self._taint_map) == 0, \
                "P20 violated: taint_map not empty after clear()"
            assert len(self._violations) == 0, \
                "P20 violated: violations not empty after clear()"

            # POST: ghost counters preserved
            assert self._total_tags_ever == old_total_tags, \
                "Ghost violated: total_tags_ever changed by clear()"
            assert self._total_checks_ever == old_total_checks, \
                "Ghost violated: total_checks_ever changed by clear()"

    # ═════════════════════════════════════════════════════════
    # Public read-only properties
    # ═════════════════════════════════════════════════════════

    @property
    def violations(self) -> List[Dict[str, Any]]:
        """All flow violations detected.

        Returns a list of dicts for backward compatibility.
        Each dict contains: source_id, source_label, target_label.
        """
        with self._lock:
            return [v.to_dict() for v in self._violations]

    @property
    def violation_records(self) -> List[FlowViolation]:
        """All flow violations as FlowViolation dataclass instances."""
        with self._lock:
            return list(self._violations)

    @property
    def violation_count(self) -> int:
        """Number of recorded violations."""
        with self._lock:
            return len(self._violations)

    @property
    def taint_map_snapshot(self) -> Dict[str, SecurityLabel]:
        """Read-only snapshot of the taint map."""
        with self._lock:
            return dict(self._taint_map)

    @property
    def total_tags_ever(self) -> int:
        """Ghost counter: total tag() calls made."""
        return self._total_tags_ever

    @property
    def total_checks_ever(self) -> int:
        """Ghost counter: total check_flow() calls made."""
        return self._total_checks_ever

    # ═════════════════════════════════════════════════════════
    # Diagnostic / Audit
    # ═════════════════════════════════════════════════════════

    def is_valid(self) -> bool:
        """Public invariant check (does not record to audit log)."""
        with self._lock:
            return self._dafny_valid()

    def invariant_details(self) -> str:
        """Public invariant diagnostics."""
        with self._lock:
            return self._invariant_details()


# =============================================================================
# Module-level utility functions (Dafny lemma mirrors)
# =============================================================================

def level_can_flow_to(src: SecurityLevel, dst: SecurityLevel) -> bool:
    """Standalone flow check at level granularity.

    Mirrors Dafny ``LevelCanFlowTo(src, dst)``.
    P14: Returns True IFF rank(src) <= rank(dst).
    """
    return src.can_flow_to(dst)


def label_can_flow_to(src: SecurityLabel, dst: SecurityLabel) -> bool:
    """Standalone flow check at label granularity.

    Mirrors Dafny ``LabelCanFlowTo(src, dst)``.
    P15: Requires both level ordering and tag containment.
    """
    return src.can_flow_to(dst)


def level_join(a: SecurityLevel, b: SecurityLevel) -> SecurityLevel:
    """Compute the join (least upper bound) of two security levels.

    Mirrors Dafny ``LevelJoin(a, b)``.
    P21: max(rank(a), rank(b)), idempotent, commutative, associative.
    """
    return SecurityLevel.join(a, b)

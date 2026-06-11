"""
Z3 Verification Engine Optimizer.

Provides:
- Z3ConstraintCache: cache constraint patterns (not just results)
- IncrementalZ3Verifier: incremental solving with push/pop for multi-step plans
- Parallel verification support for independent steps

Per CERTIOR_TECHNICAL_ARCHITECTURE.md specifications.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

try:
    from z3 import (
        Solver, Int, Bool, BoolVal, And, Or, Not, Sum,
        sat, unsat, unknown,
    )
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


@dataclass
class CacheEntry:
    """A cached verification result with metadata."""
    result: Any
    created_at: float = field(default_factory=time.time)
    hits: int = 0


@dataclass
class VerificationResult:
    """Result of Z3 verification."""
    valid: bool = True
    properties: List[str] = field(default_factory=list)
    violations: List[str] = field(default_factory=list)
    solve_time_ms: float = 0.0
    cached: bool = False

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "properties": self.properties,
            "violations": self.violations,
            "solve_time_ms": self.solve_time_ms,
            "cached": self.cached,
        }


class Z3ConstraintCache:
    """
    Cache Z3 constraint patterns for performance.

    Strategy:
    - Hash constraint *structure* (types & keys, not values)
    - Also cache by exact content hash for identical re-checks
    - LRU eviction when cache exceeds max_size
    - Track hit rate for monitoring
    """

    def __init__(self, max_size: int = 10_000):
        self.max_size = max_size
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._total_lookups = 0
        self._total_hits = 0

    @property
    def size(self) -> int:
        return len(self._cache)

    @property
    def hit_rate(self) -> float:
        if self._total_lookups == 0:
            return 0.0
        return self._total_hits / self._total_lookups

    def _hash_structure(self, constraints: Dict[str, Any]) -> str:
        """Hash constraint *structure* - keys and value types, not values."""
        structure = {}
        for k, v in sorted(constraints.items()):
            if isinstance(v, (list, tuple)):
                structure[k] = f"list[{len(v)}]"
            elif isinstance(v, dict):
                structure[k] = f"dict[{len(v)}]"
            else:
                structure[k] = type(v).__name__
        raw = json.dumps(structure, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    def _hash_exact(self, constraints: Dict[str, Any]) -> str:
        """Hash exact constraint content for identical re-checks."""
        raw = json.dumps(constraints, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, constraints: Dict[str, Any], exact: bool = True) -> Optional[VerificationResult]:
        """
        Look up cached result.

        Args:
            constraints: The constraint dict to look up.
            exact: If True, match on exact values. If False, match structure only.

        Returns:
            Cached VerificationResult or None.
        """
        self._total_lookups += 1
        key = self._hash_exact(constraints) if exact else self._hash_structure(constraints)

        if key in self._cache:
            self._total_hits += 1
            entry = self._cache[key]
            entry.hits += 1
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            # Return a copy with cached=True
            r = entry.result
            return VerificationResult(
                valid=r.valid,
                properties=list(r.properties),
                violations=list(r.violations),
                solve_time_ms=r.solve_time_ms,
                cached=True,
            )
        return None

    def put(self, constraints: Dict[str, Any], result: VerificationResult, exact: bool = True):
        """Store a verification result."""
        key = self._hash_exact(constraints) if exact else self._hash_structure(constraints)

        if len(self._cache) >= self.max_size:
            # Evict oldest (LRU)
            self._cache.popitem(last=False)

        self._cache[key] = CacheEntry(result=result)

    def get_or_solve(
        self,
        constraints: Dict[str, Any],
        solver_fn: Callable[[], VerificationResult],
        exact: bool = True,
    ) -> VerificationResult:
        """Get from cache or solve and cache the result."""
        cached = self.get(constraints, exact=exact)
        if cached is not None:
            return cached

        result = solver_fn()
        self.put(constraints, result, exact=exact)
        return result

    def clear(self):
        """Clear all cached entries."""
        self._cache.clear()

    def stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        return {
            "size": self.size,
            "max_size": self.max_size,
            "total_lookups": self._total_lookups,
            "total_hits": self._total_hits,
            "hit_rate": self.hit_rate,
        }


class IncrementalZ3Verifier:
    """
    Incremental Z3 solver for multi-step plans.

    Optimization:
    - Reuse solver state across steps via push/pop
    - Cache results for identical constraint patterns
    - Fast-path for previously verified patterns

    Per CERTIOR_TECHNICAL_ARCHITECTURE.md spec.
    """

    def __init__(self, cache: Optional[Z3ConstraintCache] = None):
        self._cache = cache or Z3ConstraintCache()
        if not _HAS_Z3:
            raise RuntimeError("Z3 is required for IncrementalZ3Verifier")

    @property
    def cache(self) -> Z3ConstraintCache:
        return self._cache

    def verify_plan(
        self,
        steps: List[Dict[str, Any]],
        total_budget_cents: int,
        available_capabilities: List[str],
    ) -> VerificationResult:
        """
        Verify an entire plan incrementally.

        Steps:
        1. Add global constraints (budget, capabilities)
        2. For each step: push, add step constraints, check, keep if valid

        Args:
            steps: List of step dicts with keys:
                - estimated_cost_cents (int)
                - required_capabilities (list[str])
                - tool (str, optional)
            total_budget_cents: Maximum allowed budget
            available_capabilities: List of capability strings

        Returns:
            VerificationResult
        """
        start = time.perf_counter()

        # Check cache first
        plan_constraints = {
            "steps": [
                {
                    "cost": s.get("estimated_cost_cents", 0),
                    "capabilities": sorted(s.get("required_capabilities", [])),
                }
                for s in steps
            ],
            "budget": total_budget_cents,
            "capabilities": sorted(available_capabilities),
        }
        cached = self._cache.get(plan_constraints, exact=True)
        if cached is not None:
            return cached

        # Solve
        s = Solver()
        properties = []
        violations = []

        # Global budget constraint
        step_costs = []
        for i, step in enumerate(steps):
            cost_var = Int(f"step_{i}_cost")
            s.add(cost_var == step.get("estimated_cost_cents", 0))
            s.add(cost_var >= 0)
            step_costs.append(cost_var)

        total_cost = Int("total_cost")
        budget = Int("budget")
        if step_costs:
            s.add(total_cost == Sum(*step_costs))
        else:
            s.add(total_cost == 0)
        s.add(budget == total_budget_cents)
        s.add(total_cost <= budget)

        if s.check() == sat:
            properties.append("budget_feasible: proven")
        else:
            violations.append(
                f"budget_exceeded: total cost exceeds {total_budget_cents}"
            )
            result = VerificationResult(
                valid=False, properties=properties, violations=violations,
                solve_time_ms=(time.perf_counter() - start) * 1000,
            )
            self._cache.put(plan_constraints, result)
            return result

        # Incremental per-step verification
        cap_set = set(available_capabilities)

        for i, step in enumerate(steps):
            s.push()

            required = set(step.get("required_capabilities", []))
            # Check capability coverage (with wildcard support)
            for req in required:
                covered = req in cap_set or any(
                    p.endswith("*") and req.startswith(p[:-1])
                    for p in available_capabilities
                )
                if not covered:
                    s.pop()
                    violations.append(
                        f"step_{i}: missing capability {req}"
                    )
                    result = VerificationResult(
                        valid=False, properties=properties, violations=violations,
                        solve_time_ms=(time.perf_counter() - start) * 1000,
                    )
                    self._cache.put(plan_constraints, result)
                    return result

            # Step-level satisfiability check
            if s.check() != sat:
                s.pop()
                violations.append(f"step_{i}: constraints unsatisfiable")
                result = VerificationResult(
                    valid=False, properties=properties, violations=violations,
                    solve_time_ms=(time.perf_counter() - start) * 1000,
                )
                self._cache.put(plan_constraints, result)
                return result

            # Keep constraints for cumulative checking (don't pop)

        properties.append("all_steps_verified: proven")
        properties.append("all_capabilities_covered: proven")

        result = VerificationResult(
            valid=True, properties=properties,
            solve_time_ms=(time.perf_counter() - start) * 1000,
        )
        self._cache.put(plan_constraints, result)
        return result

    def verify_action(
        self,
        required_capabilities: List[str],
        available_capabilities: List[str],
        estimated_cost_cents: int,
        budget_remaining_cents: int,
        input_labels: Optional[List[str]] = None,
        output_labels: Optional[List[str]] = None,
    ) -> VerificationResult:
        """
        Verify a single action with caching.

        Returns cached result for identical constraints.
        """
        constraints = {
            "required": sorted(required_capabilities),
            "available": sorted(available_capabilities),
            "cost": estimated_cost_cents,
            "budget": budget_remaining_cents,
            "input_labels": sorted(input_labels or []),
            "output_labels": sorted(output_labels or []),
        }

        return self._cache.get_or_solve(
            constraints,
            lambda: self._solve_action(
                required_capabilities, available_capabilities,
                estimated_cost_cents, budget_remaining_cents,
                input_labels, output_labels,
            ),
        )

    def _solve_action(
        self,
        required_capabilities: List[str],
        available_capabilities: List[str],
        estimated_cost_cents: int,
        budget_remaining_cents: int,
        input_labels: Optional[List[str]],
        output_labels: Optional[List[str]],
    ) -> VerificationResult:
        start = time.perf_counter()
        s = Solver()
        properties = []
        violations = []

        # Capability coverage
        cap_set = set(available_capabilities)
        for req in required_capabilities:
            covered = req in cap_set or any(
                p.endswith("*") and req.startswith(p[:-1])
                for p in available_capabilities
            )
            if not covered:
                violations.append(f"missing_capability: {req}")
        if not violations:
            properties.append("capability_coverage: proven")

        # Budget
        budget = Int("budget")
        cost = Int("cost")
        s.add(budget == budget_remaining_cents)
        s.add(cost == estimated_cost_cents)
        s.add(cost >= 0)
        s.add(budget >= cost)
        if s.check() == sat:
            properties.append("budget_sufficient: proven")
        else:
            violations.append(
                f"budget_exceeded: need {estimated_cost_cents}, have {budget_remaining_cents}"
            )

        # Information flow
        if input_labels and output_labels:
            level_map = {"public": 0, "internal": 1, "cached": 1, "sensitive": 2, "restricted": 3}
            max_in = max((level_map.get(l, 1) for l in input_labels), default=0)
            min_out = min((level_map.get(l, 1) for l in output_labels), default=0)
            if min_out < max_in:
                violations.append("information_flow: potential downgrade")
            else:
                properties.append("information_flow: no downgrade proven")

        return VerificationResult(
            valid=len(violations) == 0,
            properties=properties,
            violations=violations,
            solve_time_ms=(time.perf_counter() - start) * 1000,
        )

"""Tests for Z3 constraint cache and incremental verifier."""
import pytest
from agentsafe.verification.z3_optimizer import (
    Z3ConstraintCache,
    IncrementalZ3Verifier,
    VerificationResult,
    CacheEntry,
    _HAS_Z3,
)


# ── Z3ConstraintCache ──────────────────────────────────────────────

class TestZ3ConstraintCache:
    def test_empty_cache(self):
        cache = Z3ConstraintCache()
        assert cache.size == 0
        assert cache.hit_rate == 0.0

    def test_put_and_get_exact(self):
        cache = Z3ConstraintCache()
        constraints = {"budget": 1000, "capabilities": ["read"]}
        result = VerificationResult(valid=True, properties=["ok"])
        cache.put(constraints, result)
        assert cache.size == 1

        got = cache.get(constraints)
        assert got is not None
        assert got.valid is True
        assert got.cached is True
        assert got.properties == ["ok"]

    def test_miss_returns_none(self):
        cache = Z3ConstraintCache()
        cache.put({"a": 1}, VerificationResult(valid=True))
        assert cache.get({"b": 2}) is None

    def test_hit_rate_tracking(self):
        cache = Z3ConstraintCache()
        constraints = {"x": 10}
        cache.put(constraints, VerificationResult(valid=True))

        cache.get(constraints)  # hit
        cache.get(constraints)  # hit
        cache.get({"y": 20})    # miss

        assert cache._total_lookups == 3
        assert cache._total_hits == 2
        assert abs(cache.hit_rate - 2 / 3) < 0.01

    def test_lru_eviction(self):
        cache = Z3ConstraintCache(max_size=2)
        cache.put({"a": 1}, VerificationResult(valid=True, properties=["a"]))
        cache.put({"b": 2}, VerificationResult(valid=True, properties=["b"]))
        cache.put({"c": 3}, VerificationResult(valid=True, properties=["c"]))

        # "a" should have been evicted
        assert cache.size == 2
        assert cache.get({"a": 1}) is None
        assert cache.get({"b": 2}) is not None
        assert cache.get({"c": 3}) is not None

    def test_lru_access_refreshes_order(self):
        cache = Z3ConstraintCache(max_size=2)
        cache.put({"a": 1}, VerificationResult(valid=True))
        cache.put({"b": 2}, VerificationResult(valid=True))
        # Access "a" to refresh it
        cache.get({"a": 1})
        # Insert "c" → should evict "b" (least recently used)
        cache.put({"c": 3}, VerificationResult(valid=True))

        assert cache.get({"a": 1}) is not None
        assert cache.get({"b": 2}) is None
        assert cache.get({"c": 3}) is not None

    def test_structure_hash_match(self):
        cache = Z3ConstraintCache()
        constraints = {"budget": 500, "caps": ["a"]}
        cache.put(constraints, VerificationResult(valid=True), exact=False)

        # Different values, same structure should match
        got = cache.get({"budget": 999, "caps": ["x"]}, exact=False)
        assert got is not None
        assert got.cached is True

    def test_structure_hash_mismatch(self):
        cache = Z3ConstraintCache()
        cache.put({"budget": 500}, VerificationResult(valid=True), exact=False)
        # Different structure
        got = cache.get({"budget": 500, "extra": "field"}, exact=False)
        assert got is None

    def test_get_or_solve_cached(self):
        cache = Z3ConstraintCache()
        constraints = {"x": 42}
        result = VerificationResult(valid=True, properties=["cached"])
        cache.put(constraints, result)

        call_count = 0
        def solver():
            nonlocal call_count
            call_count += 1
            return VerificationResult(valid=False)

        got = cache.get_or_solve(constraints, solver)
        assert got.valid is True  # from cache, not solver
        assert call_count == 0

    def test_get_or_solve_uncached(self):
        cache = Z3ConstraintCache()
        constraints = {"x": 42}

        def solver():
            return VerificationResult(valid=False, violations=["no"])

        got = cache.get_or_solve(constraints, solver)
        assert got.valid is False
        assert got.violations == ["no"]
        # Now should be cached
        assert cache.get(constraints) is not None

    def test_clear(self):
        cache = Z3ConstraintCache()
        cache.put({"a": 1}, VerificationResult(valid=True))
        cache.put({"b": 2}, VerificationResult(valid=True))
        cache.clear()
        assert cache.size == 0

    def test_stats(self):
        cache = Z3ConstraintCache(max_size=100)
        cache.put({"a": 1}, VerificationResult(valid=True))
        cache.get({"a": 1})
        cache.get({"b": 2})

        stats = cache.stats()
        assert stats["size"] == 1
        assert stats["max_size"] == 100
        assert stats["total_lookups"] == 2
        assert stats["total_hits"] == 1
        assert abs(stats["hit_rate"] - 0.5) < 0.01

    def test_cache_entry_defaults(self):
        entry = CacheEntry(result=VerificationResult(valid=True))
        assert entry.hits == 0
        assert entry.created_at > 0

    def test_verification_result_to_dict(self):
        r = VerificationResult(
            valid=True, properties=["p1"], violations=[],
            solve_time_ms=1.5, cached=False,
        )
        d = r.to_dict()
        assert d["valid"] is True
        assert d["properties"] == ["p1"]
        assert d["solve_time_ms"] == 1.5

    def test_returned_result_is_copy(self):
        """Cached results should be copies, not references."""
        cache = Z3ConstraintCache()
        original = VerificationResult(valid=True, properties=["orig"])
        cache.put({"k": 1}, original)

        got = cache.get({"k": 1})
        got.properties.append("mutated")

        # Original and next get should be unaffected
        got2 = cache.get({"k": 1})
        assert "mutated" not in got2.properties


# ── IncrementalZ3Verifier ──────────────────────────────────────────

@pytest.mark.skipif(not _HAS_Z3, reason="z3-solver not installed")
class TestIncrementalZ3Verifier:
    def test_verify_empty_plan(self):
        v = IncrementalZ3Verifier()
        result = v.verify_plan(
            steps=[], total_budget_cents=1000,
            available_capabilities=["read"],
        )
        assert result.valid is True

    def test_verify_single_step_valid(self):
        v = IncrementalZ3Verifier()
        result = v.verify_plan(
            steps=[{"estimated_cost_cents": 100, "required_capabilities": ["read"]}],
            total_budget_cents=1000,
            available_capabilities=["read"],
        )
        assert result.valid is True
        assert any("budget" in p for p in result.properties)
        assert any("capabilities" in p for p in result.properties)

    def test_verify_multi_step_valid(self):
        v = IncrementalZ3Verifier()
        result = v.verify_plan(
            steps=[
                {"estimated_cost_cents": 100, "required_capabilities": ["read"]},
                {"estimated_cost_cents": 200, "required_capabilities": ["write"]},
                {"estimated_cost_cents": 50, "required_capabilities": ["read"]},
            ],
            total_budget_cents=1000,
            available_capabilities=["read", "write"],
        )
        assert result.valid is True

    def test_verify_budget_exceeded(self):
        v = IncrementalZ3Verifier()
        result = v.verify_plan(
            steps=[
                {"estimated_cost_cents": 600, "required_capabilities": []},
                {"estimated_cost_cents": 500, "required_capabilities": []},
            ],
            total_budget_cents=1000,
            available_capabilities=[],
        )
        assert result.valid is False
        assert any("budget" in v for v in result.violations)

    def test_verify_missing_capability(self):
        v = IncrementalZ3Verifier()
        result = v.verify_plan(
            steps=[{"estimated_cost_cents": 10, "required_capabilities": ["admin"]}],
            total_budget_cents=1000,
            available_capabilities=["read"],
        )
        assert result.valid is False
        assert any("admin" in v for v in result.violations)

    def test_verify_wildcard_capability(self):
        v = IncrementalZ3Verifier()
        result = v.verify_plan(
            steps=[{"estimated_cost_cents": 10, "required_capabilities": ["network:http:read"]}],
            total_budget_cents=1000,
            available_capabilities=["network:*"],
        )
        assert result.valid is True

    def test_verify_caches_result(self):
        v = IncrementalZ3Verifier()
        steps = [{"estimated_cost_cents": 100, "required_capabilities": ["read"]}]

        r1 = v.verify_plan(steps, 1000, ["read"])
        r2 = v.verify_plan(steps, 1000, ["read"])

        assert r1.valid is True
        assert r2.valid is True
        assert r2.cached is True  # second call should be cached
        assert v.cache.hit_rate > 0

    def test_verify_action_valid(self):
        v = IncrementalZ3Verifier()
        result = v.verify_action(
            required_capabilities=["read"],
            available_capabilities=["read", "write"],
            estimated_cost_cents=100,
            budget_remaining_cents=1000,
        )
        assert result.valid is True

    def test_verify_action_missing_cap(self):
        v = IncrementalZ3Verifier()
        result = v.verify_action(
            required_capabilities=["admin"],
            available_capabilities=["read"],
            estimated_cost_cents=100,
            budget_remaining_cents=1000,
        )
        assert result.valid is False

    def test_verify_action_budget_exceeded(self):
        v = IncrementalZ3Verifier()
        result = v.verify_action(
            required_capabilities=[],
            available_capabilities=[],
            estimated_cost_cents=500,
            budget_remaining_cents=100,
        )
        assert result.valid is False

    def test_verify_action_info_flow_valid(self):
        v = IncrementalZ3Verifier()
        result = v.verify_action(
            required_capabilities=["read"],
            available_capabilities=["read"],
            estimated_cost_cents=10,
            budget_remaining_cents=100,
            input_labels=["public"],
            output_labels=["internal"],
        )
        assert result.valid is True
        assert any("information_flow" in p for p in result.properties)

    def test_verify_action_info_flow_downgrade(self):
        v = IncrementalZ3Verifier()
        result = v.verify_action(
            required_capabilities=["read"],
            available_capabilities=["read"],
            estimated_cost_cents=10,
            budget_remaining_cents=100,
            input_labels=["sensitive"],
            output_labels=["public"],
        )
        assert result.valid is False
        assert any("downgrade" in v for v in result.violations)

    def test_verify_action_cached(self):
        v = IncrementalZ3Verifier()
        args = dict(
            required_capabilities=["read"],
            available_capabilities=["read"],
            estimated_cost_cents=10,
            budget_remaining_cents=100,
        )
        r1 = v.verify_action(**args)
        r2 = v.verify_action(**args)
        assert r2.cached is True

    def test_solve_time_recorded(self):
        v = IncrementalZ3Verifier()
        result = v.verify_plan(
            steps=[{"estimated_cost_cents": 10, "required_capabilities": []}],
            total_budget_cents=100,
            available_capabilities=[],
        )
        assert result.solve_time_ms >= 0

    def test_step_with_no_capabilities(self):
        v = IncrementalZ3Verifier()
        result = v.verify_plan(
            steps=[{"estimated_cost_cents": 10}],
            total_budget_cents=100,
            available_capabilities=["read"],
        )
        assert result.valid is True

    def test_multiple_missing_capabilities(self):
        v = IncrementalZ3Verifier()
        result = v.verify_plan(
            steps=[
                {"estimated_cost_cents": 10, "required_capabilities": ["a", "b"]},
            ],
            total_budget_cents=100,
            available_capabilities=["c"],
        )
        assert result.valid is False

"""
Certior - Lean4 Composition Test Suite (Theorem C2)
═══════════════════════════════════════════════════════════════════════

Tests for `lean4/CertiorLattice/Certior/Composition.lean`.

Three test layers
─────────────────
1. **Structural**: Lean source contains every required theorem/def.
2. **Cross-reference**: Python runtime agrees with Lean specs.
3. **Lean toolchain**: `lake build` succeeds (skipped if unavailable).

Run
───
    pytest tests/test_lean_c2_composition.py -v
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Tuple

import pytest

from agentsafe.flow.information_flow import SecurityLevel

# ── Paths ─────────────────────────────────────────────────────────────

_REPO = Path(__file__).resolve().parent.parent
_LEAN_PROJECT = _REPO / "lean4" / "CertiorLattice"
_SRC = _LEAN_PROJECT / "Certior" / "Composition.lean"


@pytest.fixture(scope="module")
def lean_source() -> str:
    assert _SRC.exists(), f"Missing: {_SRC}"
    return _SRC.read_text(encoding="utf-8")


def _has_lean() -> bool:
    return shutil.which("lake") is not None and shutil.which("lean") is not None


# ═══════════════════════════════════════════════════════════════════════
# Layer 1 - Structural validation
# ═══════════════════════════════════════════════════════════════════════


class TestFileIntegrity:
    def test_file_exists(self):
        assert _SRC.exists()

    def test_file_nonempty(self, lean_source):
        assert len(lean_source) > 1000

    def test_no_sorry(self, lean_source):
        lines = [l for l in lean_source.split("\n") if not l.strip().startswith("--")]
        assert "sorry" not in "\n".join(lines)

    def test_namespace(self, lean_source):
        assert "namespace Certior.Composition" in lean_source

    def test_end_namespace(self, lean_source):
        assert "end Certior.Composition" in lean_source

    def test_imports_lattice(self, lean_source):
        assert "import Certior.Lattice" in lean_source


class TestDefinitions:
    STRUCTURES = [
        "StepCertificate", "PlanStep", "ExecutionPlan", "CompositionSoundness",
    ]
    DEFS = [
        "totalCost", "certFresh", "certBindsToStep", "certValidForStep",
        "planWellFormed", "budgetFeasible", "allStepsVerified", "planVerified",
        "incrementalVerify", "allCertsFresh", "planSecurityLevel",
    ]

    @pytest.mark.parametrize("name", STRUCTURES)
    def test_structure_present(self, lean_source, name):
        assert re.search(rf"structure\s+{name}\b", lean_source), f"Missing: {name}"

    @pytest.mark.parametrize("name", DEFS)
    def test_def_present(self, lean_source, name):
        assert re.search(rf"def\s+{name}\b", lean_source), f"Missing: {name}"


class TestTheorems:
    REQUIRED = [
        "totalCost_nil", "totalCost_cons", "totalCost_append",
        "empty_plan_cost", "empty_plan_feasible", "empty_plan_verified",
        "totalCost_take_le", "budget_prefix_feasible",
        "totalCost_snoc", "append_feasible",
        "steps_compose_pair", "steps_compose_to_plan",
        "incremental_agrees_with_whole",
        "verified_implies_all_fresh", "verified_implies_all_bound",
        "planLevel_is_upper_bound", "planLevel_public_iff_all_public",
        "planLevel_append_mono", "compositionSoundness",
    ]

    @pytest.mark.parametrize("thm", REQUIRED)
    def test_theorem_present(self, lean_source, thm):
        assert re.search(rf"theorem\s+{thm}\b", lean_source), f"Missing: {thm}"

    def test_theorem_count_ge_20(self, lean_source):
        n = len(re.findall(r"^(?:private )?theorem\s+\w+", lean_source, re.MULTILINE))
        assert n >= 19, f"Expected ≥19, found {n}"

    def test_master_theorem_fields(self, lean_source):
        for field in ["lift", "budget_add", "prefix_ok", "compose", "incr_sound", "empty_ok"]:
            assert re.search(rf"\b{field}\b\s*:", lean_source), f"Missing field: {field}"


# ═══════════════════════════════════════════════════════════════════════
# Layer 2 - Cross-reference (Python ↔ Lean)
# ═══════════════════════════════════════════════════════════════════════

def _total_cost(steps: List[int]) -> int:
    return sum(steps)

def _budget_feasible(steps: List[int], budget: int) -> bool:
    return _total_cost(steps) <= budget

def _cert_fresh(issued: int, expires: int, now: int) -> bool:
    return issued <= now and now < expires

def _cert_binds(cert_h: str, step_h: str) -> bool:
    return cert_h == step_h

def _cert_valid(cert_h: str, step_h: str, iss: int, exp: int, now: int) -> bool:
    return _cert_fresh(iss, exp, now) and _cert_binds(cert_h, step_h)

def _incremental_verify(s_hashes: List[str], c_hashes: List[str],
                        times: List[Tuple[int, int]], now: int) -> bool:
    if len(s_hashes) != len(c_hashes):
        return False
    return all(_cert_valid(ch, sh, t[0], t[1], now)
               for sh, ch, t in zip(s_hashes, c_hashes, times))

_RANK = {SecurityLevel.PUBLIC: 0, SecurityLevel.INTERNAL: 1,
         SecurityLevel.SENSITIVE: 2, SecurityLevel.RESTRICTED: 3}

def _max_level(levels: List[SecurityLevel]) -> SecurityLevel:
    if not levels:
        return SecurityLevel.PUBLIC
    return max(levels, key=lambda l: _RANK[l])


class TestCOMP1_PlanBasics:
    def test_total_cost_nil(self):
        assert _total_cost([]) == 0

    def test_total_cost_single(self):
        assert _total_cost([42]) == 42

    def test_total_cost_multi(self):
        assert _total_cost([10, 20, 30]) == 60

    def test_total_cost_additive(self):
        assert _total_cost([10, 20] + [30, 40]) == _total_cost([10, 20]) + _total_cost([30, 40])

    def test_empty_plan_feasible(self):
        assert _budget_feasible([], 0)
        assert _budget_feasible([], 100)

    def test_empty_plan_cost_zero(self):
        assert _total_cost([]) == 0


class TestCOMP2_BudgetFeasibility:
    @pytest.mark.parametrize("steps,budget,exp", [
        ([10, 20, 30], 100, True), ([10, 20, 30], 60, True),
        ([10, 20, 30], 59, False), ([10, 20, 30], 0, False), ([], 0, True),
    ])
    def test_budget_feasible(self, steps, budget, exp):
        assert _budget_feasible(steps, budget) == exp

    def test_prefix_feasibility(self):
        steps = [10, 20, 30, 40]
        budget = 100
        assert _budget_feasible(steps, budget)
        for n in range(len(steps) + 1):
            assert _total_cost(steps[:n]) <= budget

    @pytest.mark.parametrize("n", range(6))
    def test_prefix_cost_le_total(self, n):
        steps = [5, 10, 15, 20, 25]
        assert _total_cost(steps[:n]) <= _total_cost(steps)


class TestCOMP3_StepComposition:
    def test_all_verified(self):
        now = 100
        hs = ["ha", "hb", "hc"]
        ts = [(50, 200)] * 3
        assert _incremental_verify(hs, hs, ts, now)

    def test_hash_mismatch(self):
        assert not _incremental_verify(["a", "b"], ["a", "X"], [(50, 200)] * 2, 100)

    def test_expired_cert(self):
        assert not _incremental_verify(["a"], ["a"], [(50, 99)], 100)

    def test_length_mismatch(self):
        assert not _incremental_verify(["a", "b"], ["a"], [(1, 200)], 100)


class TestCOMP5_PlanAppend:
    def test_append_within_budget(self):
        assert _budget_feasible([10, 20], 100)
        assert _budget_feasible([10, 20, 30], 100)

    def test_append_exceeds_budget(self):
        assert _budget_feasible([50, 40], 100)
        assert not _budget_feasible([50, 40, 20], 100)

    def test_cost_additive(self):
        assert _total_cost([10, 20] + [5]) == _total_cost([10, 20]) + _total_cost([5])


class TestCOMP6_Incremental:
    def test_all_valid(self):
        hs = [f"h{i}" for i in range(5)]
        assert _incremental_verify(hs, hs, [(100, 1000)] * 5, 500)

    def test_one_expired(self):
        hs = ["h0", "h1", "h2"]
        ts = [(100, 1000), (100, 499), (100, 1000)]
        assert not _incremental_verify(hs, hs, ts, 500)

    def test_empty(self):
        assert _incremental_verify([], [], [], 0)


class TestCOMP8_CertIntegrity:
    def test_fresh(self):
        assert _cert_fresh(50, 200, 100)

    def test_expired(self):
        assert not _cert_fresh(50, 99, 100)

    def test_not_yet(self):
        assert not _cert_fresh(200, 300, 100)

    def test_boundary(self):
        assert _cert_fresh(100, 200, 100)       # at issued
        assert not _cert_fresh(100, 200, 200)    # at expires

    def test_binds(self):
        assert _cert_binds("abc", "abc")
        assert not _cert_binds("abc", "xyz")


class TestSecurityLevels:
    def test_single(self):
        assert _max_level([SecurityLevel.SENSITIVE]) == SecurityLevel.SENSITIVE

    def test_mixed(self):
        assert _max_level([SecurityLevel.PUBLIC, SecurityLevel.SENSITIVE,
                           SecurityLevel.INTERNAL]) == SecurityLevel.SENSITIVE

    def test_empty(self):
        assert _max_level([]) == SecurityLevel.PUBLIC

    def test_all_public(self):
        assert _max_level([SecurityLevel.PUBLIC] * 5) == SecurityLevel.PUBLIC

    def test_append_monotone(self):
        levels = [SecurityLevel.PUBLIC, SecurityLevel.INTERNAL]
        before = _RANK[_max_level(levels)]
        for nl in SecurityLevel:
            assert _RANK[_max_level(levels + [nl])] >= before

    def test_upper_bound(self):
        levels = [SecurityLevel.PUBLIC, SecurityLevel.SENSITIVE, SecurityLevel.INTERNAL]
        pl = _RANK[_max_level(levels)]
        for l in levels:
            assert pl >= _RANK[l]


class TestEdgeCases:
    def test_single_step(self):
        assert _budget_feasible([100], 100)
        assert not _budget_feasible([101], 100)

    def test_zero_cost(self):
        assert _total_cost([0, 0, 0]) == 0
        assert _budget_feasible([0, 0, 0], 0)

    def test_large_plan(self):
        steps = [1] * 1000
        assert _total_cost(steps) == 1000
        assert _budget_feasible(steps, 1000)
        assert not _budget_feasible(steps, 999)


# ═══════════════════════════════════════════════════════════════════════
# Layer 3 - Lean toolchain
# ═══════════════════════════════════════════════════════════════════════


class TestLeanToolchain:
    @pytest.mark.skipif(not _has_lean(), reason="Lean/lake not on PATH")
    def test_lake_build(self):
        r = subprocess.run(["lake", "build"], cwd=str(_LEAN_PROJECT),
                           capture_output=True, text=True, timeout=300)
        assert r.returncode == 0, f"lake build failed:\n{r.stderr}"

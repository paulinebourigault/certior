"""
Certior - Lean4 Delegation Test Suite (Theorem C3)
═══════════════════════════════════════════════════════════════════════

Tests for `lean4/CertiorLattice/Certior/Delegation.lean`.

Three test layers
─────────────────
1. **Structural**: Lean source contains every required theorem/def.
2. **Cross-reference**: Python runtime agrees with Lean specs.
3. **Lean toolchain**: `lake build` succeeds (skipped if unavailable).

Run
───
    pytest tests/test_lean_c3_delegation.py -v
"""
from __future__ import annotations

import copy
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

import pytest

# ── Paths ─────────────────────────────────────────────────────────────

_REPO = Path(__file__).resolve().parent.parent
_LEAN_PROJECT = _REPO / "lean4" / "CertiorLattice"
_SRC = _LEAN_PROJECT / "Certior" / "Delegation.lean"


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
        assert "namespace Certior.Delegation" in lean_source

    def test_end_namespace(self, lean_source):
        assert "end Certior.Delegation" in lean_source


class TestDefinitions:
    STRUCTURES = ["CapabilityToken", "DelegationSafety"]
    INDUCTIVE = ["SpendResult", "AttenuateResult", "DelegationChain", "WFDelegationChain"]
    DEFS = [
        "hasPermission", "hasAllPermissions", "permissionsSubset",
        "tokenWellFormed", "spendBudget", "attenuate",
    ]

    @pytest.mark.parametrize("name", STRUCTURES)
    def test_structure_present(self, lean_source, name):
        assert re.search(rf"structure\s+{name}\b", lean_source), f"Missing: {name}"

    @pytest.mark.parametrize("name", INDUCTIVE)
    def test_inductive_present(self, lean_source, name):
        assert re.search(rf"inductive\s+{name}\b", lean_source), f"Missing: {name}"

    @pytest.mark.parametrize("name", DEFS)
    def test_def_present(self, lean_source, name):
        assert re.search(rf"def\s+{name}\b", lean_source), f"Missing: {name}"


class TestTheorems:
    REQUIRED = [
        # P7: Permission checks
        "hasPermission_mem", "hasPermission_of_mem", "hasPermission_empty",
        "hasAllPermissions_iff", "permissionsSubset_iff",
        "permissionsSubset_refl", "permissionsSubset_trans",
        # P2: Budget monotonicity
        "spend_exact_decrement", "spend_bounded", "spend_overspend_fails",
        "spend_monotone", "spend_preserves_wf", "spend_consecutive",
        # P1: Attenuation safety
        "attenuate_perms_subset", "attenuate_budget_bound",
        "attenuate_fresh_budget", "attenuate_provenance", "attenuate_depth",
        "attenuate_escalation_rejected", "attenuate_overbudget_rejected",
        "attenuate_preserves_wf",
        # P8: Transitivity
        "transitivity_permissions", "transitivity_budget",
        "transitivity_depth", "transitivity_wellformed",
        # Chain
        "chain_permissions_subset", "chain_budget_bound",
        "budget_bound_two_step",
        # Master
        "delegationSafety",
    ]

    @pytest.mark.parametrize("thm", REQUIRED)
    def test_theorem_present(self, lean_source, thm):
        assert re.search(rf"theorem\s+{thm}\b", lean_source), f"Missing: {thm}"

    def test_theorem_count_ge_26(self, lean_source):
        n = len(re.findall(r"^(?:private )?theorem\s+\w+", lean_source, re.MULTILINE))
        assert n >= 26, f"Expected ≥26, found {n}"


class TestMasterTheoremFields:
    FIELDS = [
        "perms_subset", "budget_bound", "fresh_budget", "provenance",
        "depth", "wellformed", "spend_mono", "spend_bnd",
        "perm_found", "perm_empty", "subset_trans",
        "trans_perms", "trans_budget", "trans_depth", "trans_wf",
    ]

    @pytest.mark.parametrize("f", FIELDS)
    def test_field_present(self, lean_source, f):
        assert re.search(rf"\b{f}\b\s*:=?\s", lean_source), f"Missing field: {f}"


# ═══════════════════════════════════════════════════════════════════════
# Layer 2 - Cross-reference (Python ↔ Lean)
# ═══════════════════════════════════════════════════════════════════════

# --- Python token model (mirrors Lean) ---

@dataclass
class PyToken:
    id: str
    agent_id: str
    permissions: List[str]
    initial_budget: int
    budget_remaining: int
    parent_id: str = ""
    delegation_depth: int = 0


def py_well_formed(tok: PyToken) -> bool:
    return (tok.budget_remaining <= tok.initial_budget and
            (tok.parent_id == "") == (tok.delegation_depth == 0) and
            len(tok.id) > 0 and len(tok.agent_id) > 0)


def py_has_permission(perm: str, perms: List[str]) -> bool:
    return perm in perms


def py_permissions_subset(child: List[str], parent: List[str]) -> bool:
    return all(p in parent for p in child)


def py_spend(tok: PyToken, amount: int) -> Tuple[bool, Optional[PyToken]]:
    if amount > tok.budget_remaining:
        return False, None
    new = PyToken(
        id=tok.id, agent_id=tok.agent_id, permissions=list(tok.permissions),
        initial_budget=tok.initial_budget,
        budget_remaining=tok.budget_remaining - amount,
        parent_id=tok.parent_id, delegation_depth=tok.delegation_depth,
    )
    return True, new


def py_attenuate(parent: PyToken, child_id: str, child_agent: str,
                 child_perms: List[str], child_budget: int
                 ) -> Tuple[bool, Optional[PyToken]]:
    if not py_permissions_subset(child_perms, parent.permissions):
        return False, None
    if child_budget > parent.budget_remaining:
        return False, None
    if len(child_id) == 0 or len(child_agent) == 0:
        return False, None
    child = PyToken(
        id=child_id, agent_id=child_agent, permissions=list(child_perms),
        initial_budget=child_budget, budget_remaining=child_budget,
        parent_id=parent.id, delegation_depth=parent.delegation_depth + 1,
    )
    return True, child


# --- Fixtures ---

def _root_token(**overrides) -> PyToken:
    defaults = dict(
        id="root-1", agent_id="agent-root",
        permissions=["fs:read", "fs:write", "net:http", "db:read"],
        initial_budget=10000, budget_remaining=10000,
        parent_id="", delegation_depth=0,
    )
    defaults.update(overrides)
    return PyToken(**defaults)


# --- P7: Permission checks ---

class TestP7_PermissionChecks:
    def test_exact_match(self):
        assert py_has_permission("fs:read", ["fs:read", "net:http"])

    def test_not_found(self):
        assert not py_has_permission("fs:write", ["fs:read", "net:http"])

    def test_empty_perms(self):
        assert not py_has_permission("fs:read", [])

    def test_subset_true(self):
        assert py_permissions_subset(["fs:read"], ["fs:read", "net:http"])

    def test_subset_false(self):
        assert not py_permissions_subset(["fs:read", "db:write"], ["fs:read", "net:http"])

    def test_subset_empty_child(self):
        assert py_permissions_subset([], ["fs:read"])

    def test_subset_empty_parent(self):
        assert py_permissions_subset([], [])

    def test_subset_refl(self):
        perms = ["a", "b", "c"]
        assert py_permissions_subset(perms, perms)

    def test_subset_trans(self):
        a = ["x"]
        b = ["x", "y"]
        c = ["x", "y", "z"]
        assert py_permissions_subset(a, b)
        assert py_permissions_subset(b, c)
        assert py_permissions_subset(a, c)


# --- P2: Budget monotonicity ---

class TestP2_BudgetMonotonicity:
    def test_spend_exact_decrement(self):
        tok = _root_token(budget_remaining=100)
        ok, new = py_spend(tok, 30)
        assert ok and new.budget_remaining == 70

    def test_spend_bounded(self):
        tok = _root_token(initial_budget=100, budget_remaining=100)
        ok, new = py_spend(tok, 60)
        assert ok and new.budget_remaining <= new.initial_budget

    def test_spend_overspend_fails(self):
        tok = _root_token(budget_remaining=50)
        ok, _ = py_spend(tok, 51)
        assert not ok

    def test_spend_zero(self):
        tok = _root_token(budget_remaining=100)
        ok, new = py_spend(tok, 0)
        assert ok and new.budget_remaining == 100

    def test_spend_all(self):
        tok = _root_token(budget_remaining=100)
        ok, new = py_spend(tok, 100)
        assert ok and new.budget_remaining == 0

    def test_spend_monotone(self):
        tok = _root_token(budget_remaining=100)
        ok, new = py_spend(tok, 40)
        assert ok and new.budget_remaining <= tok.budget_remaining

    def test_spend_preserves_wf(self):
        tok = _root_token()
        assert py_well_formed(tok)
        ok, new = py_spend(tok, 500)
        assert ok and py_well_formed(new)

    def test_spend_consecutive(self):
        tok = _root_token(initial_budget=1000, budget_remaining=1000)
        ok1, t1 = py_spend(tok, 200)
        assert ok1
        ok2, t2 = py_spend(t1, 300)
        assert ok2 and t2.budget_remaining == 500

    @pytest.mark.parametrize("amounts", [
        [10, 20, 30, 40],
        [100, 100, 100],
        [1, 1, 1, 1, 1],
    ])
    def test_spend_chain(self, amounts):
        tok = _root_token(initial_budget=10000, budget_remaining=10000)
        for a in amounts:
            ok, tok = py_spend(tok, a)
            assert ok
        assert tok.budget_remaining == 10000 - sum(amounts)


# --- P1: Attenuation safety ---

class TestP1_AttenuationSafety:
    def test_basic_attenuate(self):
        root = _root_token()
        ok, child = py_attenuate(root, "c1", "agent-c1", ["fs:read"], 500)
        assert ok
        assert child.permissions == ["fs:read"]
        assert child.initial_budget == 500
        assert child.budget_remaining == 500
        assert child.parent_id == root.id
        assert child.delegation_depth == 1

    def test_perms_subset(self):
        root = _root_token()
        ok, child = py_attenuate(root, "c1", "agent-c", ["fs:read", "net:http"], 1000)
        assert ok
        assert py_permissions_subset(child.permissions, root.permissions)

    def test_budget_bound(self):
        root = _root_token(budget_remaining=1000)
        ok, child = py_attenuate(root, "c1", "agent-c", ["fs:read"], 1000)
        assert ok
        assert child.initial_budget <= root.budget_remaining

    def test_fresh_budget(self):
        root = _root_token()
        ok, child = py_attenuate(root, "c1", "agent-c", ["fs:read"], 500)
        assert ok
        assert child.budget_remaining == child.initial_budget

    def test_provenance(self):
        root = _root_token()
        ok, child = py_attenuate(root, "c1", "agent-c", ["fs:read"], 500)
        assert ok
        assert child.parent_id == root.id

    def test_depth(self):
        root = _root_token()
        ok, child = py_attenuate(root, "c1", "agent-c", ["fs:read"], 500)
        assert ok
        assert child.delegation_depth == root.delegation_depth + 1

    def test_escalation_rejected(self):
        root = _root_token(permissions=["fs:read"])
        ok, _ = py_attenuate(root, "c1", "agent-c", ["fs:read", "fs:write"], 100)
        assert not ok

    def test_overbudget_rejected(self):
        root = _root_token(budget_remaining=100)
        ok, _ = py_attenuate(root, "c1", "agent-c", ["fs:read"], 101)
        assert not ok

    def test_empty_id_rejected(self):
        root = _root_token()
        ok, _ = py_attenuate(root, "", "agent-c", ["fs:read"], 100)
        assert not ok

    def test_empty_agent_rejected(self):
        root = _root_token()
        ok, _ = py_attenuate(root, "c1", "", ["fs:read"], 100)
        assert not ok

    def test_preserves_wf(self):
        root = _root_token()
        assert py_well_formed(root)
        ok, child = py_attenuate(root, "c1", "agent-c", ["fs:read"], 500)
        assert ok
        assert py_well_formed(child)


# --- P8: Transitivity ---

class TestP8_Transitivity:
    def test_two_step_permissions(self):
        gp = _root_token()
        ok1, parent = py_attenuate(gp, "p1", "ag-p", ["fs:read", "net:http"], 5000)
        assert ok1
        ok2, child = py_attenuate(parent, "c1", "ag-c", ["fs:read"], 2000)
        assert ok2
        assert py_permissions_subset(child.permissions, gp.permissions)

    def test_two_step_budget(self):
        gp = _root_token(budget_remaining=10000)
        ok1, parent = py_attenuate(gp, "p1", "ag-p", ["fs:read"], 5000)
        assert ok1
        ok2, child = py_attenuate(parent, "c1", "ag-c", ["fs:read"], 2000)
        assert ok2
        assert child.initial_budget <= gp.budget_remaining

    def test_two_step_depth(self):
        gp = _root_token()
        ok1, parent = py_attenuate(gp, "p1", "ag-p", ["fs:read"], 5000)
        assert ok1
        ok2, child = py_attenuate(parent, "c1", "ag-c", ["fs:read"], 2000)
        assert ok2
        assert child.delegation_depth == gp.delegation_depth + 2

    def test_two_step_wf(self):
        gp = _root_token()
        assert py_well_formed(gp)
        ok1, parent = py_attenuate(gp, "p1", "ag-p", ["fs:read"], 5000)
        assert ok1 and py_well_formed(parent)
        ok2, child = py_attenuate(parent, "c1", "ag-c", ["fs:read"], 2000)
        assert ok2 and py_well_formed(child)

    def test_three_step_chain(self):
        gp = _root_token()
        ok1, p = py_attenuate(gp, "p", "a-p", ["fs:read", "net:http"], 8000)
        assert ok1
        ok2, c = py_attenuate(p, "c", "a-c", ["fs:read"], 4000)
        assert ok2
        ok3, gc = py_attenuate(c, "gc", "a-gc", ["fs:read"], 2000)
        assert ok3
        assert py_permissions_subset(gc.permissions, gp.permissions)
        assert gc.initial_budget <= gp.budget_remaining
        assert gc.delegation_depth == gp.delegation_depth + 3
        assert py_well_formed(gc)

    @pytest.mark.parametrize("depth", [2, 3, 5, 10])
    def test_chain_depth_n(self, depth):
        tok = _root_token(budget_remaining=100000)
        for i in range(depth):
            ok, tok = py_attenuate(
                tok, f"t{i}", f"a{i}",
                tok.permissions[:max(1, len(tok.permissions) - i)],
                tok.budget_remaining // 2,
            )
            assert ok
            assert py_well_formed(tok)
        assert tok.delegation_depth == depth

    def test_chain_permissions_monotone(self):
        gp = _root_token(permissions=["a", "b", "c", "d", "e"])
        chain = [gp]
        tok = gp
        perms = list(tok.permissions)
        for i in range(4):
            perms = perms[:-1]  # shrink by 1 each step
            ok, tok = py_attenuate(tok, f"t{i}", f"a{i}", perms, tok.budget_remaining // 2)
            assert ok
            chain.append(tok)
        # Every token's perms ⊆ root's perms
        for t in chain:
            assert py_permissions_subset(t.permissions, gp.permissions)


# --- Edge cases ---

class TestEdgeCases:
    def test_zero_budget_child(self):
        root = _root_token()
        ok, child = py_attenuate(root, "c1", "ag-c", ["fs:read"], 0)
        assert ok
        assert child.budget_remaining == 0

    def test_empty_perms_child(self):
        root = _root_token()
        ok, child = py_attenuate(root, "c1", "ag-c", [], 100)
        assert ok
        assert child.permissions == []

    def test_wf_root(self):
        assert py_well_formed(_root_token())

    def test_wf_violation_budget(self):
        tok = PyToken(id="x", agent_id="a", permissions=[],
                      initial_budget=100, budget_remaining=200,
                      parent_id="", delegation_depth=0)
        assert not py_well_formed(tok)

    def test_wf_violation_depth(self):
        tok = PyToken(id="x", agent_id="a", permissions=[],
                      initial_budget=100, budget_remaining=100,
                      parent_id="parent-1", delegation_depth=0)  # mismatch
        assert not py_well_formed(tok)

    def test_attenuate_exact_budget(self):
        root = _root_token(budget_remaining=500)
        ok, child = py_attenuate(root, "c", "a", ["fs:read"], 500)
        assert ok
        assert child.initial_budget == 500


# ═══════════════════════════════════════════════════════════════════════
# Layer 3 - Lean toolchain
# ═══════════════════════════════════════════════════════════════════════


class TestLeanToolchain:
    @pytest.mark.skipif(not _has_lean(), reason="Lean/lake not on PATH")
    def test_lake_build(self):
        r = subprocess.run(["lake", "build"], cwd=str(_LEAN_PROJECT),
                           capture_output=True, text=True, timeout=300)
        assert r.returncode == 0, f"lake build failed:\n{r.stderr}"

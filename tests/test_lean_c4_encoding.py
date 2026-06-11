"""
Certior - Lean4 Encoding Test Suite (Theorem C4)
═══════════════════════════════════════════════════════════════════════

Tests for `lean4/CertiorLattice/Certior/Encoding.lean`.

Three test layers
─────────────────
1. **Structural**: Lean source contains every required theorem/def.
2. **Cross-reference**: Python runtime agrees with Lean specs.
3. **Lean toolchain**: `lake build` succeeds (skipped if unavailable).

Run
───
    pytest tests/test_lean_c4_encoding.py -v
"""
from __future__ import annotations

import itertools
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

from agentsafe.flow.information_flow import (
    SecurityLabel,
    SecurityLevel,
    label_can_flow_to,
    level_can_flow_to,
    level_join,
)

# ── Paths ─────────────────────────────────────────────────────────────

_REPO = Path(__file__).resolve().parent.parent
_LEAN_PROJECT = _REPO / "lean4" / "CertiorLattice"
_SRC = _LEAN_PROJECT / "Certior" / "Encoding.lean"

ALL_LEVELS = [
    SecurityLevel.PUBLIC, SecurityLevel.INTERNAL,
    SecurityLevel.SENSITIVE, SecurityLevel.RESTRICTED,
]

_RANK = {SecurityLevel.PUBLIC: 0, SecurityLevel.INTERNAL: 1,
         SecurityLevel.SENSITIVE: 2, SecurityLevel.RESTRICTED: 3}


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
        assert "namespace Certior.Encoding" in lean_source

    def test_imports_lattice(self, lean_source):
        assert "import Certior.Lattice" in lean_source


class TestDefinitions:
    STRUCTURES = ["FlowViolation", "TaintTracker", "IFCSoundness"]
    INDUCTIVE = ["FlowCheckResult"]
    DEFS = [
        "taintLookup", "taintInsert", "violationGenuine", "trackerValid",
        "accumulateContext", "chainAllLinks", "chainConsecutive",
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
        # IFC-1: Tag correctness
        "tag_lookup_self", "tag_lookup_other",
        "tag_preserves_valid", "tag_violations_unchanged",
        # IFC-2: Flow check soundness
        "checkFlow_allowed_iff_flow", "checkFlow_violation_genuine",
        # IFC-3: Violation log integrity
        "checkFlow_violations_append", "checkFlow_blocked_grows_by_one",
        "checkFlow_allowed_unchanged", "checkFlow_preserves_valid",
        # IFC-4: Untracked data
        "checkFlow_untracked",
        # IFC-5: Multi-step flow
        "flow_transitive", "chain_composition",
        "compose_two_flows", "tag_then_check_allowed", "tag_then_check_blocked",
        # IFC-6: Context accumulation
        "accumulate_mono", "accumulate_captures_output",
        "accumulate_sequential", "accumulate_public", "accumulate_restricted",
        # IFC-7: Downgrade blocked
        "downgrade_always_blocked",
        "restricted_cannot_flow_to_public",
        "sensitive_cannot_flow_to_public",
        "sensitive_cannot_flow_to_internal",
        "restricted_cannot_flow_to_internal",
        "restricted_cannot_flow_to_sensitive",
        "internal_cannot_flow_to_public",
        # Clear
        "clear_valid", "clear_empty_taint", "clear_empty_violations",
        # Context ceiling
        "context_ceiling_sound", "accumulated_context_flow",
        # Tracker validity
        "empty_valid",
        # Master
        "ifcSoundness",
    ]

    @pytest.mark.parametrize("thm", REQUIRED)
    def test_theorem_present(self, lean_source, thm):
        assert re.search(rf"theorem\s+{thm}\b", lean_source), f"Missing: {thm}"

    def test_theorem_count_ge_35(self, lean_source):
        n = len(re.findall(r"^(?:private )?theorem\s+\w+", lean_source, re.MULTILINE))
        assert n >= 35, f"Expected ≥35, found {n}"


class TestMasterTheoremFields:
    FIELDS = [
        "tag_self", "tag_other",
        "check_sound", "check_valid",
        "untracked", "transitive",
        "accum_mono", "no_downgrade",
    ]

    @pytest.mark.parametrize("f", FIELDS)
    def test_field_present(self, lean_source, f):
        assert re.search(rf"\b{f}\b\s*:=?\s", lean_source), f"Missing field: {f}"


# ═══════════════════════════════════════════════════════════════════════
# Layer 2 - Cross-reference (Python ↔ Lean)
# ═══════════════════════════════════════════════════════════════════════

# --- Python taint tracker (mirrors Lean) ---

@dataclass
class PyViolation:
    source_id: str
    source_level: SecurityLevel
    target_level: SecurityLevel


@dataclass
class PyTracker:
    taint_map: Dict[str, SecurityLevel] = field(default_factory=dict)
    violations: List[PyViolation] = field(default_factory=list)


def py_tag(tracker: PyTracker, data_id: str, level: SecurityLevel) -> PyTracker:
    new_map = dict(tracker.taint_map)
    new_map[data_id] = level
    return PyTracker(taint_map=new_map, violations=list(tracker.violations))


def py_check_flow(tracker: PyTracker, data_id: str,
                  target_level: SecurityLevel) -> Tuple[bool, PyTracker]:
    src_level = tracker.taint_map.get(data_id)
    if src_level is None:
        return True, tracker  # untracked → allowed
    if level_can_flow_to(src_level, target_level):
        return True, tracker
    else:
        v = PyViolation(source_id=data_id, source_level=src_level,
                        target_level=target_level)
        new_viols = list(tracker.violations) + [v]
        return False, PyTracker(taint_map=dict(tracker.taint_map), violations=new_viols)


def py_clear(tracker: PyTracker) -> PyTracker:
    return PyTracker()


def py_accumulate(ctx: SecurityLevel, output: SecurityLevel) -> SecurityLevel:
    return level_join(ctx, output)


def py_tracker_valid(tracker: PyTracker) -> bool:
    """All violations are genuine: source cannot flow to target."""
    return all(not level_can_flow_to(v.source_level, v.target_level)
               for v in tracker.violations)


# --- IFC-1: Tag correctness ---

class TestIFC1_TagCorrectness:
    def test_tag_lookup_self(self):
        t = py_tag(PyTracker(), "data1", SecurityLevel.SENSITIVE)
        assert t.taint_map["data1"] == SecurityLevel.SENSITIVE

    def test_tag_lookup_other(self):
        t = py_tag(PyTracker(taint_map={"x": SecurityLevel.PUBLIC}),
                   "y", SecurityLevel.RESTRICTED)
        assert t.taint_map["x"] == SecurityLevel.PUBLIC

    def test_tag_preserves_valid(self):
        t = PyTracker()
        assert py_tracker_valid(t)
        t2 = py_tag(t, "d", SecurityLevel.INTERNAL)
        assert py_tracker_valid(t2)

    def test_tag_violations_unchanged(self):
        v = PyViolation("x", SecurityLevel.RESTRICTED, SecurityLevel.PUBLIC)
        t = PyTracker(violations=[v])
        t2 = py_tag(t, "y", SecurityLevel.INTERNAL)
        assert len(t2.violations) == 1
        assert t2.violations[0] is v

    def test_tag_overwrite(self):
        t = py_tag(PyTracker(), "d", SecurityLevel.PUBLIC)
        t = py_tag(t, "d", SecurityLevel.RESTRICTED)
        assert t.taint_map["d"] == SecurityLevel.RESTRICTED


# --- IFC-2: Flow check soundness ---

class TestIFC2_FlowCheckSoundness:
    @pytest.mark.parametrize("src,dst", [
        (SecurityLevel.PUBLIC, SecurityLevel.PUBLIC),
        (SecurityLevel.PUBLIC, SecurityLevel.INTERNAL),
        (SecurityLevel.PUBLIC, SecurityLevel.SENSITIVE),
        (SecurityLevel.PUBLIC, SecurityLevel.RESTRICTED),
        (SecurityLevel.INTERNAL, SecurityLevel.INTERNAL),
        (SecurityLevel.INTERNAL, SecurityLevel.SENSITIVE),
        (SecurityLevel.INTERNAL, SecurityLevel.RESTRICTED),
        (SecurityLevel.SENSITIVE, SecurityLevel.SENSITIVE),
        (SecurityLevel.SENSITIVE, SecurityLevel.RESTRICTED),
        (SecurityLevel.RESTRICTED, SecurityLevel.RESTRICTED),
    ])
    def test_allowed_flows(self, src, dst):
        t = py_tag(PyTracker(), "d", src)
        allowed, _ = py_check_flow(t, "d", dst)
        assert allowed
        assert level_can_flow_to(src, dst)

    @pytest.mark.parametrize("src,dst", [
        (SecurityLevel.RESTRICTED, SecurityLevel.PUBLIC),
        (SecurityLevel.RESTRICTED, SecurityLevel.INTERNAL),
        (SecurityLevel.RESTRICTED, SecurityLevel.SENSITIVE),
        (SecurityLevel.SENSITIVE, SecurityLevel.PUBLIC),
        (SecurityLevel.SENSITIVE, SecurityLevel.INTERNAL),
        (SecurityLevel.INTERNAL, SecurityLevel.PUBLIC),
    ])
    def test_blocked_flows(self, src, dst):
        t = py_tag(PyTracker(), "d", src)
        allowed, _ = py_check_flow(t, "d", dst)
        assert not allowed
        assert not level_can_flow_to(src, dst)

    def test_check_iff_flow(self):
        """Exhaustive: checkFlow agrees with level_can_flow_to for all pairs."""
        for src in ALL_LEVELS:
            for dst in ALL_LEVELS:
                t = py_tag(PyTracker(), "d", src)
                allowed, _ = py_check_flow(t, "d", dst)
                assert allowed == level_can_flow_to(src, dst)


# --- IFC-3: Violation log integrity ---

class TestIFC3_ViolationLog:
    def test_allowed_unchanged(self):
        t = py_tag(PyTracker(), "d", SecurityLevel.PUBLIC)
        allowed, t2 = py_check_flow(t, "d", SecurityLevel.RESTRICTED)
        assert allowed
        assert len(t2.violations) == 0

    def test_blocked_grows_by_one(self):
        t = py_tag(PyTracker(), "d", SecurityLevel.RESTRICTED)
        allowed, t2 = py_check_flow(t, "d", SecurityLevel.PUBLIC)
        assert not allowed
        assert len(t2.violations) == 1

    def test_violation_genuine(self):
        t = py_tag(PyTracker(), "d", SecurityLevel.SENSITIVE)
        _, t2 = py_check_flow(t, "d", SecurityLevel.PUBLIC)
        assert py_tracker_valid(t2)
        v = t2.violations[0]
        assert v.source_level == SecurityLevel.SENSITIVE
        assert v.target_level == SecurityLevel.PUBLIC
        assert not level_can_flow_to(v.source_level, v.target_level)

    def test_preserves_valid(self):
        t = PyTracker()
        assert py_tracker_valid(t)
        t = py_tag(t, "d", SecurityLevel.RESTRICTED)
        _, t = py_check_flow(t, "d", SecurityLevel.PUBLIC)
        assert py_tracker_valid(t)

    def test_multiple_violations(self):
        t = PyTracker()
        t = py_tag(t, "a", SecurityLevel.RESTRICTED)
        t = py_tag(t, "b", SecurityLevel.SENSITIVE)
        _, t = py_check_flow(t, "a", SecurityLevel.PUBLIC)
        _, t = py_check_flow(t, "b", SecurityLevel.PUBLIC)
        assert len(t.violations) == 2
        assert py_tracker_valid(t)

    def test_append_only(self):
        t = py_tag(PyTracker(), "d", SecurityLevel.RESTRICTED)
        _, t = py_check_flow(t, "d", SecurityLevel.PUBLIC)
        v0 = t.violations[0]
        _, t = py_check_flow(t, "d", SecurityLevel.INTERNAL)
        assert t.violations[0] is v0  # first unchanged
        assert len(t.violations) == 2


# --- IFC-4: Untracked data ---

class TestIFC4_Untracked:
    def test_untracked_allowed(self):
        t = PyTracker()
        allowed, _ = py_check_flow(t, "unknown", SecurityLevel.RESTRICTED)
        assert allowed

    def test_untracked_to_public(self):
        allowed, _ = py_check_flow(PyTracker(), "x", SecurityLevel.PUBLIC)
        assert allowed


# --- IFC-5: Multi-step flow ---

class TestIFC5_MultiStepFlow:
    def test_flow_transitive(self):
        """A→B and B→C ⟹ A→C."""
        for a in ALL_LEVELS:
            for b in ALL_LEVELS:
                for c in ALL_LEVELS:
                    if level_can_flow_to(a, b) and level_can_flow_to(b, c):
                        assert level_can_flow_to(a, c)

    def test_tag_then_check_allowed(self):
        t = py_tag(PyTracker(), "d", SecurityLevel.PUBLIC)
        ok, t2 = py_check_flow(t, "d", SecurityLevel.RESTRICTED)
        assert ok

    def test_tag_then_check_blocked(self):
        t = py_tag(PyTracker(), "d", SecurityLevel.RESTRICTED)
        ok, t2 = py_check_flow(t, "d", SecurityLevel.PUBLIC)
        assert not ok

    def test_compose_two_flows(self):
        """If A flows to B and B flows to C, then A flows to C."""
        assert level_can_flow_to(SecurityLevel.PUBLIC, SecurityLevel.INTERNAL)
        assert level_can_flow_to(SecurityLevel.INTERNAL, SecurityLevel.SENSITIVE)
        assert level_can_flow_to(SecurityLevel.PUBLIC, SecurityLevel.SENSITIVE)

    def test_chain(self):
        chain = [
            (SecurityLevel.PUBLIC, SecurityLevel.INTERNAL),
            (SecurityLevel.INTERNAL, SecurityLevel.SENSITIVE),
            (SecurityLevel.SENSITIVE, SecurityLevel.RESTRICTED),
        ]
        for src, dst in chain:
            assert level_can_flow_to(src, dst)
        # End-to-end
        assert level_can_flow_to(chain[0][0], chain[-1][1])


# --- IFC-6: Context accumulation ---

class TestIFC6_ContextAccumulation:
    def test_accumulate_mono(self):
        """Context never decreases."""
        for ctx in ALL_LEVELS:
            for out in ALL_LEVELS:
                result = py_accumulate(ctx, out)
                assert _RANK[result] >= _RANK[ctx]

    def test_accumulate_captures_output(self):
        """Output flows to accumulated context."""
        for ctx in ALL_LEVELS:
            for out in ALL_LEVELS:
                result = py_accumulate(ctx, out)
                assert level_can_flow_to(out, result)

    def test_accumulate_public(self):
        """PUBLIC doesn't change context."""
        for ctx in ALL_LEVELS:
            assert py_accumulate(ctx, SecurityLevel.PUBLIC) == ctx

    def test_accumulate_restricted(self):
        """RESTRICTED always yields RESTRICTED."""
        for ctx in ALL_LEVELS:
            assert py_accumulate(ctx, SecurityLevel.RESTRICTED) == SecurityLevel.RESTRICTED

    def test_accumulate_sequential(self):
        """Two outputs compose via join."""
        ctx = SecurityLevel.PUBLIC
        ctx = py_accumulate(ctx, SecurityLevel.INTERNAL)
        assert ctx == SecurityLevel.INTERNAL
        ctx = py_accumulate(ctx, SecurityLevel.SENSITIVE)
        assert ctx == SecurityLevel.SENSITIVE

    def test_accumulate_idempotent(self):
        for l in ALL_LEVELS:
            assert py_accumulate(l, l) == l


# --- IFC-7: Downgrade always blocked ---

class TestIFC7_DowngradeBlocked:
    DOWNGRADE_PAIRS = [
        (SecurityLevel.RESTRICTED, SecurityLevel.PUBLIC),
        (SecurityLevel.RESTRICTED, SecurityLevel.INTERNAL),
        (SecurityLevel.RESTRICTED, SecurityLevel.SENSITIVE),
        (SecurityLevel.SENSITIVE, SecurityLevel.PUBLIC),
        (SecurityLevel.SENSITIVE, SecurityLevel.INTERNAL),
        (SecurityLevel.INTERNAL, SecurityLevel.PUBLIC),
    ]

    @pytest.mark.parametrize("src,dst", DOWNGRADE_PAIRS)
    def test_downgrade_blocked(self, src, dst):
        assert not level_can_flow_to(src, dst)

    def test_exhaustive_downgrade(self):
        """Every pair where rank(src) > rank(dst) is blocked."""
        for src in ALL_LEVELS:
            for dst in ALL_LEVELS:
                if _RANK[src] > _RANK[dst]:
                    assert not level_can_flow_to(src, dst)

    def test_exhaustive_upflow(self):
        """Every pair where rank(src) ≤ rank(dst) is allowed."""
        for src in ALL_LEVELS:
            for dst in ALL_LEVELS:
                if _RANK[src] <= _RANK[dst]:
                    assert level_can_flow_to(src, dst)


# --- Clear ---

class TestClear:
    def test_clear_valid(self):
        t = py_tag(PyTracker(), "d", SecurityLevel.RESTRICTED)
        _, t = py_check_flow(t, "d", SecurityLevel.PUBLIC)
        t2 = py_clear(t)
        assert py_tracker_valid(t2)

    def test_clear_empty_taint(self):
        t = py_tag(PyTracker(), "d", SecurityLevel.RESTRICTED)
        t2 = py_clear(t)
        assert len(t2.taint_map) == 0

    def test_clear_empty_violations(self):
        t = PyTracker(violations=[PyViolation("x", SecurityLevel.RESTRICTED, SecurityLevel.PUBLIC)])
        t2 = py_clear(t)
        assert len(t2.violations) == 0


# --- Context ceiling ---

class TestContextCeiling:
    def test_ceiling_sound(self):
        """If ctx ≤ dst, then flow from ctx to dst is allowed."""
        for ctx in ALL_LEVELS:
            for dst in ALL_LEVELS:
                if _RANK[ctx] <= _RANK[dst]:
                    assert level_can_flow_to(ctx, dst)

    def test_accumulated_context_flow(self):
        """After accumulation, context can flow to higher destinations."""
        ctx = SecurityLevel.PUBLIC
        ctx = py_accumulate(ctx, SecurityLevel.INTERNAL)
        ctx = py_accumulate(ctx, SecurityLevel.SENSITIVE)
        assert ctx == SecurityLevel.SENSITIVE
        assert level_can_flow_to(ctx, SecurityLevel.SENSITIVE)
        assert level_can_flow_to(ctx, SecurityLevel.RESTRICTED)
        assert not level_can_flow_to(ctx, SecurityLevel.PUBLIC)


# --- Edge cases ---

class TestEdgeCases:
    def test_same_level_flow(self):
        for l in ALL_LEVELS:
            assert level_can_flow_to(l, l)

    def test_public_flows_everywhere(self):
        for dst in ALL_LEVELS:
            assert level_can_flow_to(SecurityLevel.PUBLIC, dst)

    def test_nothing_flows_below_public(self):
        # PUBLIC is bottom, nothing below it
        for src in ALL_LEVELS:
            if src != SecurityLevel.PUBLIC:
                assert not level_can_flow_to(src, SecurityLevel.PUBLIC)

    def test_restricted_only_to_self(self):
        for dst in ALL_LEVELS:
            if dst == SecurityLevel.RESTRICTED:
                assert level_can_flow_to(SecurityLevel.RESTRICTED, dst)
            else:
                assert not level_can_flow_to(SecurityLevel.RESTRICTED, dst)

    def test_join_commutative(self):
        for a in ALL_LEVELS:
            for b in ALL_LEVELS:
                assert level_join(a, b) == level_join(b, a)

    def test_join_associative(self):
        for a in ALL_LEVELS:
            for b in ALL_LEVELS:
                for c in ALL_LEVELS:
                    assert level_join(level_join(a, b), c) == level_join(a, level_join(b, c))

    def test_join_idempotent(self):
        for l in ALL_LEVELS:
            assert level_join(l, l) == l

    def test_multiple_data_ids(self):
        t = PyTracker()
        t = py_tag(t, "public_data", SecurityLevel.PUBLIC)
        t = py_tag(t, "secret_data", SecurityLevel.RESTRICTED)
        ok1, t = py_check_flow(t, "public_data", SecurityLevel.PUBLIC)
        assert ok1
        ok2, t = py_check_flow(t, "secret_data", SecurityLevel.PUBLIC)
        assert not ok2
        assert len(t.violations) == 1

    def test_stress_many_tags(self):
        t = PyTracker()
        for i in range(100):
            t = py_tag(t, f"d{i}", ALL_LEVELS[i % 4])
        assert len(t.taint_map) == 100
        assert py_tracker_valid(t)


# ═══════════════════════════════════════════════════════════════════════
# Layer 3 - Lean toolchain
# ═══════════════════════════════════════════════════════════════════════


class TestLeanToolchain:
    @pytest.mark.skipif(not _has_lean(), reason="Lean/lake not on PATH")
    def test_lake_build(self):
        r = subprocess.run(["lake", "build"], cwd=str(_LEAN_PROJECT),
                           capture_output=True, text=True, timeout=300)
        assert r.returncode == 0, f"lake build failed:\n{r.stderr}"

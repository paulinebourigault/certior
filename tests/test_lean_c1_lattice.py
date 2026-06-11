"""
Certior - Lean4 Lattice Test Suite (Theorem C1)
═══════════════════════════════════════════════════════════════════════

Tests for `lean4/CertiorLattice/Certior/Lattice.lean`.

Three test layers
─────────────────
1. **Structural**: The Lean source contains every required theorem and
   definition, using correct syntax.  Always runs.

2. **Cross-reference**: The Python runtime (`SecurityLevel`) agrees with
   every decidable property stated in Lean.  Always runs.

3. **Lean toolchain**: If `lean` / `lake` are on PATH, invoke `lake build`
   and assert exit-code 0 (full proof verification).  Skipped otherwise.

Run
───
    pytest tests/test_lean_c1_lattice.py -v
    pytest tests/test_lean_c1_lattice.py -v -k "not toolchain"  # skip Lean
"""
from __future__ import annotations

import itertools
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple

import pytest

# ── Paths ─────────────────────────────────────────────────────────────

_REPO = Path(__file__).resolve().parent.parent
_LEAN_PROJECT = _REPO / "lean4" / "CertiorLattice"
_LATTICE_LEAN = _LEAN_PROJECT / "Certior" / "Lattice.lean"
_LAKEFILE = _LEAN_PROJECT / "lakefile.lean"
_TOOLCHAIN = _LEAN_PROJECT / "lean-toolchain"

# ── Python runtime import ────────────────────────────────────────────

from agentsafe.flow.information_flow import (
    SecurityLabel,
    SecurityLevel,
    label_can_flow_to,
    level_can_flow_to,
    level_join,
)

# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

ALL_LEVELS: List[SecurityLevel] = [
    SecurityLevel.PUBLIC,
    SecurityLevel.INTERNAL,
    SecurityLevel.SENSITIVE,
    SecurityLevel.RESTRICTED,
]

LEAN_SRC: str = ""  # loaded in fixture


@pytest.fixture(scope="module")
def lean_source() -> str:
    """Load and cache the Lean source file."""
    assert _LATTICE_LEAN.exists(), f"Lean file missing: {_LATTICE_LEAN}"
    return _LATTICE_LEAN.read_text(encoding="utf-8")


def _has_lean_toolchain() -> bool:
    return shutil.which("lake") is not None and shutil.which("lean") is not None


# ═══════════════════════════════════════════════════════════════════════
# Layer 1 - Structural validation of Lean source
# ═══════════════════════════════════════════════════════════════════════


class TestLeanProjectStructure:
    """Verify the Lean4 project has all required files and configuration."""

    def test_lean_file_exists(self) -> None:
        assert _LATTICE_LEAN.exists(), "Certior/Lattice.lean must exist"

    def test_lakefile_exists(self) -> None:
        assert _LAKEFILE.exists(), "lakefile.lean must exist"

    def test_toolchain_file_exists(self) -> None:
        assert _TOOLCHAIN.exists(), "lean-toolchain must exist"

    def test_toolchain_version_format(self) -> None:
        content = _TOOLCHAIN.read_text().strip()
        assert re.match(r"leanprover/lean4:v\d+\.\d+\.\d+", content), (
            f"lean-toolchain must specify a version, got: {content!r}"
        )

    def test_root_import_exists(self) -> None:
        root = _LEAN_PROJECT / "Certior.lean"
        assert root.exists(), "Root import Certior.lean must exist"
        content = root.read_text()
        assert "import Certior.Lattice" in content


class TestLeanSourceDefinitions:
    """Verify every required definition is present in the Lean source."""

    # ── Inductive type ────────────────────────────────────────────────

    def test_securitylevel_inductive(self, lean_source: str) -> None:
        assert "inductive SecurityLevel" in lean_source

    def test_all_constructors_present(self, lean_source: str) -> None:
        for ctor in ["Public", "Internal", "Sensitive", "Restricted"]:
            assert f"| .{ctor}" in lean_source or f"| {ctor}" in lean_source, (
                f"Constructor {ctor} missing"
            )

    def test_decidable_eq_derived(self, lean_source: str) -> None:
        assert "DecidableEq" in lean_source

    # ── Rank function ─────────────────────────────────────────────────

    def test_rank_function(self, lean_source: str) -> None:
        assert "def rank" in lean_source

    def test_rank_values(self, lean_source: str) -> None:
        # Extract rank assignments
        for lvl, expected in [("Public", "0"), ("Internal", "1"),
                              ("Sensitive", "2"), ("Restricted", "3")]:
            pattern = rf"\.{lvl}\s*=>\s*{expected}"
            assert re.search(pattern, lean_source), (
                f"rank .{lvl} => {expected} not found"
            )

    # ── Flow predicate ────────────────────────────────────────────────

    def test_levelCanFlowTo_defined(self, lean_source: str) -> None:
        assert "def levelCanFlowTo" in lean_source

    def test_flow_uses_rank_le(self, lean_source: str) -> None:
        # The flow predicate should use rank comparison
        assert "rank src ≤ rank dst" in lean_source or \
               "rank src <= rank dst" in lean_source

    # ── Join and Meet ─────────────────────────────────────────────────

    def test_join_defined(self, lean_source: str) -> None:
        assert "def join" in lean_source

    def test_meet_defined(self, lean_source: str) -> None:
        assert "def meet" in lean_source

    # ── Bounds ────────────────────────────────────────────────────────

    def test_bot_defined(self, lean_source: str) -> None:
        assert "def bot" in lean_source

    def test_top_defined(self, lean_source: str) -> None:
        assert "def top" in lean_source

    # ── SecurityLabel ─────────────────────────────────────────────────

    def test_security_label_defined(self, lean_source: str) -> None:
        assert "structure SecurityLabel" in lean_source

    def test_label_canFlowTo(self, lean_source: str) -> None:
        assert "def canFlowTo" in lean_source


class TestLeanSourceTheorems:
    """Verify every required theorem statement is present."""

    # ── Theorem manifest ──────────────────────────────────────────────

    REQUIRED_THEOREMS: List[str] = [
        # P13 - Order axioms
        "theorem flowTo_refl",
        "theorem flowTo_trans",
        "theorem flowTo_antisymm",
        "theorem flowTo_total",
        # P14 - Flow safety
        "theorem flowSafety_iff",
        "theorem flowSafety_noDowngrade",
        "theorem flowSafety_upgradeAllowed",
        "theorem flow_exhaustive_allowed",
        "theorem flow_exhaustive_blocked",
        # LE/LT order
        "theorem le_refl",
        "theorem le_trans",
        "theorem le_antisymm",
        "theorem le_total",
        # P21 - Join
        "theorem join_le_left",
        "theorem join_le_right",
        "theorem join_least",
        "theorem join_idem",
        "theorem join_comm",
        "theorem join_assoc",
        "theorem join_mono_left",
        "theorem join_mono_right",
        "theorem join_preserves_flowTarget",
        # Meet
        "theorem meet_le_left",
        "theorem meet_le_right",
        "theorem meet_greatest",
        "theorem meet_idem",
        "theorem meet_comm",
        "theorem meet_assoc",
        "theorem meet_mono_left",
        # Absorption
        "theorem join_meet_absorb",
        "theorem meet_join_absorb",
        # Distributivity
        "theorem meet_join_distrib",
        "theorem join_meet_distrib",
        # Bounds
        "theorem bot_le",
        "theorem le_top",
        "theorem join_bot",
        "theorem meet_top",
        "theorem join_top",
        "theorem meet_bot",
        # Rank
        "theorem rank_injective",
        # Finiteness
        "theorem card_eq_four",
        # Chain
        "theorem is_chain",
        # Label flow (P15)
        "theorem canFlowTo_requires_level",
        "theorem canFlowTo_requires_tags",
        "theorem canFlowTo_sufficient",
        "theorem canFlowTo_refl",
        "theorem canFlowTo_trans",
        "theorem emptyTags_flowTo",
        # Master theorem
        "theorem isValidBoundedLattice",
    ]

    @pytest.mark.parametrize("thm", REQUIRED_THEOREMS)
    def test_theorem_present(self, lean_source: str, thm: str) -> None:
        assert thm in lean_source, f"Required theorem missing: {thm}"

    def test_master_structure_defined(self, lean_source: str) -> None:
        assert "structure IsValidBoundedLattice" in lean_source

    def test_master_structure_fields(self, lean_source: str) -> None:
        """The master structure must contain all lattice axiom fields."""
        required_fields = [
            "refl", "trans", "antisymm", "total",
            "join_ub_l", "join_ub_r", "join_lub",
            "meet_lb_l", "meet_lb_r", "meet_glb",
            "absorb_jm", "absorb_mj",
            "distrib",
            "bot_least", "top_greatest",
            "rank_inj", "card",
        ]
        for field in required_fields:
            # Match "fieldname :" or "fieldname:" at start of line (indented)
            pattern = rf"^\s+{field}\s*:"
            assert re.search(pattern, lean_source, re.MULTILINE), (
                f"IsValidBoundedLattice missing field: {field}"
            )

    def test_no_sorry(self, lean_source: str) -> None:
        """No `sorry` allowed - all proofs must be complete."""
        lines = lean_source.split("\n")
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Ignore comments
            if stripped.startswith("--") or stripped.startswith("/-"):
                continue
            assert "sorry" not in stripped, (
                f"Incomplete proof (sorry) at line {i}: {line.strip()}"
            )

    def test_no_axiom(self, lean_source: str) -> None:
        """No `axiom` - everything must be proved, not assumed."""
        lines = lean_source.split("\n")
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("--") or stripped.startswith("/-"):
                continue
            assert not re.match(r"^axiom\s", stripped), (
                f"Unproved axiom at line {i}: {line.strip()}"
            )

    def test_theorem_count(self, lean_source: str) -> None:
        """At least 45 theorems must be present."""
        count = len(re.findall(r"^theorem\s", lean_source, re.MULTILINE))
        assert count >= 45, f"Expected ≥45 theorems, found {count}"


# ═══════════════════════════════════════════════════════════════════════
# Layer 2 - Cross-reference: Lean claims vs. Python runtime
# ═══════════════════════════════════════════════════════════════════════


class TestCrossRefRank:
    """Verify rank values match between Lean and Python."""

    def test_rank_public(self) -> None:
        assert SecurityLevel.PUBLIC.rank == 0

    def test_rank_internal(self) -> None:
        assert SecurityLevel.INTERNAL.rank == 1

    def test_rank_sensitive(self) -> None:
        assert SecurityLevel.SENSITIVE.rank == 2

    def test_rank_restricted(self) -> None:
        assert SecurityLevel.RESTRICTED.rank == 3

    def test_rank_injective(self) -> None:
        """Distinct levels have distinct ranks."""
        ranks = [l.rank for l in ALL_LEVELS]
        assert len(set(ranks)) == len(ALL_LEVELS)

    def test_rank_strictly_increasing(self) -> None:
        for i in range(len(ALL_LEVELS) - 1):
            assert ALL_LEVELS[i].rank < ALL_LEVELS[i + 1].rank


class TestCrossRefP13Order:
    """Cross-reference P13 lattice ordering properties."""

    def test_reflexive(self) -> None:
        for a in ALL_LEVELS:
            assert level_can_flow_to(a, a), f"Reflexivity fails for {a}"

    def test_transitive(self) -> None:
        for a, b, c in itertools.product(ALL_LEVELS, repeat=3):
            if level_can_flow_to(a, b) and level_can_flow_to(b, c):
                assert level_can_flow_to(a, c), (
                    f"Transitivity fails: {a}→{b}→{c}"
                )

    def test_antisymmetric(self) -> None:
        for a, b in itertools.product(ALL_LEVELS, repeat=2):
            if level_can_flow_to(a, b) and level_can_flow_to(b, a):
                assert a == b, f"Antisymmetry fails: {a} ↔ {b}"

    def test_total(self) -> None:
        for a, b in itertools.product(ALL_LEVELS, repeat=2):
            assert level_can_flow_to(a, b) or level_can_flow_to(b, a), (
                f"Totality fails: {a}, {b}"
            )


class TestCrossRefP14FlowSafety:
    """Cross-reference P14 flow safety properties."""

    def test_flow_iff_rank(self) -> None:
        for src, dst in itertools.product(ALL_LEVELS, repeat=2):
            expected = src.rank <= dst.rank
            actual = level_can_flow_to(src, dst)
            assert actual == expected, (
                f"Flow mismatch: {src}→{dst}: "
                f"expected={expected}, actual={actual}"
            )

    def test_no_downgrade(self) -> None:
        for src, dst in itertools.product(ALL_LEVELS, repeat=2):
            if src.rank > dst.rank:
                assert not level_can_flow_to(src, dst), (
                    f"Downgrade allowed: {src}→{dst}"
                )

    def test_all_16_pairs(self) -> None:
        """Exhaustive check of all 16 (src, dst) pairs."""
        expected_allowed = {
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
        }
        for src, dst in itertools.product(ALL_LEVELS, repeat=2):
            allowed = level_can_flow_to(src, dst)
            should_allow = (src, dst) in expected_allowed
            assert allowed == should_allow, (
                f"Pair ({src}, {dst}): expected={should_allow}, got={allowed}"
            )


class TestCrossRefP21Join:
    """Cross-reference P21 join (LUB) properties."""

    def test_upper_bound(self) -> None:
        for a, b in itertools.product(ALL_LEVELS, repeat=2):
            j = level_join(a, b)
            assert a.rank <= j.rank, f"join not UB for left: {a}, {b}"
            assert b.rank <= j.rank, f"join not UB for right: {a}, {b}"

    def test_least_upper_bound(self) -> None:
        for a, b in itertools.product(ALL_LEVELS, repeat=2):
            j = level_join(a, b)
            for c in ALL_LEVELS:
                if a.rank <= c.rank and b.rank <= c.rank:
                    assert j.rank <= c.rank, (
                        f"join not least: {a}⊔{b}={j}, c={c}"
                    )

    def test_idempotent(self) -> None:
        for a in ALL_LEVELS:
            assert level_join(a, a) == a

    def test_commutative(self) -> None:
        for a, b in itertools.product(ALL_LEVELS, repeat=2):
            assert level_join(a, b) == level_join(b, a)

    def test_associative(self) -> None:
        for a, b, c in itertools.product(ALL_LEVELS, repeat=3):
            lhs = level_join(level_join(a, b), c)
            rhs = level_join(a, level_join(b, c))
            assert lhs == rhs, f"Assoc fails: ({a}⊔{b})⊔{c} ≠ {a}⊔({b}⊔{c})"


class TestCrossRefMeet:
    """Cross-reference meet (GLB) properties against Python min-rank."""

    @staticmethod
    def _meet(a: SecurityLevel, b: SecurityLevel) -> SecurityLevel:
        """Python-side meet: level with min rank."""
        if a.rank <= b.rank:
            return a
        return b

    def test_lower_bound(self) -> None:
        for a, b in itertools.product(ALL_LEVELS, repeat=2):
            m = self._meet(a, b)
            assert m.rank <= a.rank
            assert m.rank <= b.rank

    def test_greatest_lower_bound(self) -> None:
        for a, b in itertools.product(ALL_LEVELS, repeat=2):
            m = self._meet(a, b)
            for c in ALL_LEVELS:
                if c.rank <= a.rank and c.rank <= b.rank:
                    assert c.rank <= m.rank

    def test_idempotent(self) -> None:
        for a in ALL_LEVELS:
            assert self._meet(a, a) == a

    def test_commutative(self) -> None:
        for a, b in itertools.product(ALL_LEVELS, repeat=2):
            assert self._meet(a, b) == self._meet(b, a)

    def test_associative(self) -> None:
        for a, b, c in itertools.product(ALL_LEVELS, repeat=3):
            assert (self._meet(self._meet(a, b), c)
                    == self._meet(a, self._meet(b, c)))


class TestCrossRefAbsorption:
    """Cross-reference absorption laws."""

    @staticmethod
    def _meet(a: SecurityLevel, b: SecurityLevel) -> SecurityLevel:
        return a if a.rank <= b.rank else b

    def test_join_meet_absorb(self) -> None:
        """a ⊔ (a ⊓ b) = a"""
        for a, b in itertools.product(ALL_LEVELS, repeat=2):
            result = level_join(a, self._meet(a, b))
            assert result == a, f"Absorption 1 fails: {a}, {b}"

    def test_meet_join_absorb(self) -> None:
        """a ⊓ (a ⊔ b) = a"""
        for a, b in itertools.product(ALL_LEVELS, repeat=2):
            result = self._meet(a, level_join(a, b))
            assert result == a, f"Absorption 2 fails: {a}, {b}"


class TestCrossRefDistributivity:
    """Cross-reference distributivity."""

    @staticmethod
    def _meet(a: SecurityLevel, b: SecurityLevel) -> SecurityLevel:
        return a if a.rank <= b.rank else b

    def test_meet_distributes_over_join(self) -> None:
        """a ⊓ (b ⊔ c) = (a ⊓ b) ⊔ (a ⊓ c)"""
        for a, b, c in itertools.product(ALL_LEVELS, repeat=3):
            lhs = self._meet(a, level_join(b, c))
            rhs = level_join(self._meet(a, b), self._meet(a, c))
            assert lhs == rhs, f"Distrib fails: {a}, {b}, {c}"


class TestCrossRefBounds:
    """Cross-reference bounded lattice properties."""

    def test_public_is_bottom(self) -> None:
        for a in ALL_LEVELS:
            assert level_can_flow_to(SecurityLevel.PUBLIC, a)

    def test_restricted_is_top(self) -> None:
        for a in ALL_LEVELS:
            assert level_can_flow_to(a, SecurityLevel.RESTRICTED)

    def test_cardinality(self) -> None:
        assert len(ALL_LEVELS) == 4


class TestCrossRefP15LabelFlow:
    """Cross-reference P15 label flow (level + tags)."""

    def test_label_reflexive(self) -> None:
        for lvl in ALL_LEVELS:
            label = SecurityLabel(level=lvl, tags={"a", "b"})
            assert label.can_flow_to(label)

    def test_label_requires_level(self) -> None:
        src = SecurityLabel(level=SecurityLevel.SENSITIVE, tags=set())
        dst = SecurityLabel(level=SecurityLevel.PUBLIC, tags=set())
        assert not src.can_flow_to(dst)

    def test_label_requires_tags(self) -> None:
        src = SecurityLabel(level=SecurityLevel.PUBLIC, tags={"secret"})
        dst = SecurityLabel(level=SecurityLevel.RESTRICTED, tags=set())
        assert not src.can_flow_to(dst)

    def test_label_both_conditions_sufficient(self) -> None:
        src = SecurityLabel(level=SecurityLevel.PUBLIC, tags={"a"})
        dst = SecurityLabel(level=SecurityLevel.INTERNAL, tags={"a", "b"})
        assert src.can_flow_to(dst)

    def test_empty_tags_most_permissive(self) -> None:
        for lvl in ALL_LEVELS:
            src = SecurityLabel(level=SecurityLevel.PUBLIC, tags=set())
            dst = SecurityLabel(level=lvl, tags={"any", "tags"})
            assert src.can_flow_to(dst)


# ═══════════════════════════════════════════════════════════════════════
# Layer 3 - Lean toolchain verification (optional)
# ═══════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(
    not _has_lean_toolchain(),
    reason="Lean4 toolchain (lean/lake) not available"
)
class TestLeanToolchainVerification:
    """Invoke `lake build` to fully verify all Lean proofs."""

    def test_lake_build_succeeds(self) -> None:
        """Run lake build and assert all proofs check."""
        result = subprocess.run(
            ["lake", "build"],
            cwd=str(_LEAN_PROJECT),
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert result.returncode == 0, (
            f"lake build failed:\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

    def test_no_warnings(self) -> None:
        """Verify no warnings emitted during type-checking."""
        result = subprocess.run(
            ["lake", "env", "lean", "Certior/Lattice.lean"],
            cwd=str(_LEAN_PROJECT),
            capture_output=True,
            text=True,
            timeout=300,
        )
        # Lean emits warnings to stderr
        warnings = [
            line for line in result.stderr.splitlines()
            if "warning" in line.lower()
        ]
        assert len(warnings) == 0, f"Lean warnings: {warnings}"


# ═══════════════════════════════════════════════════════════════════════
# Summary report
# ═══════════════════════════════════════════════════════════════════════


class TestProofManifest:
    """Generate and validate a manifest of all proven properties."""

    PROPERTY_MANIFEST: Dict[str, List[str]] = {
        "P13 (Lattice Ordering)": [
            "flowTo_refl",
            "flowTo_trans",
            "flowTo_antisymm",
            "flowTo_total",
        ],
        "P14 (Flow Safety)": [
            "flowSafety_iff",
            "flowSafety_noDowngrade",
            "flowSafety_upgradeAllowed",
            "flow_exhaustive_allowed",
            "flow_exhaustive_blocked",
        ],
        "P21 (Join Soundness)": [
            "join_le_left",
            "join_le_right",
            "join_least",
            "join_idem",
            "join_comm",
            "join_assoc",
            "join_mono_left",
            "join_mono_right",
            "join_preserves_flowTarget",
        ],
        "Meet Soundness": [
            "meet_le_left",
            "meet_le_right",
            "meet_greatest",
            "meet_idem",
            "meet_comm",
            "meet_assoc",
            "meet_mono_left",
        ],
        "Absorption Laws": [
            "join_meet_absorb",
            "meet_join_absorb",
        ],
        "Distributivity": [
            "meet_join_distrib",
            "join_meet_distrib",
        ],
        "Bounded Lattice": [
            "bot_le",
            "le_top",
            "join_bot",
            "bot_join",
            "meet_top",
            "top_meet",
            "join_top",
            "top_join",
            "meet_bot",
            "bot_meet",
        ],
        "Rank Properties": [
            "rank_injective",
            "rank_distinct_Public_Internal",
            "rank_distinct_Public_Sensitive",
            "rank_distinct_Public_Restricted",
            "rank_distinct_Internal_Sensitive",
            "rank_distinct_Internal_Restricted",
            "rank_distinct_Sensitive_Restricted",
            "rank_Public_lt_Internal",
            "rank_Internal_lt_Sensitive",
            "rank_Sensitive_lt_Restricted",
            "rank_Public_lt_Restricted",
        ],
        "Finiteness": [
            "all_complete",
            "all_nodup",
            "card_eq_four",
        ],
        "P15 (Label Flow)": [
            "canFlowTo_requires_level",
            "canFlowTo_requires_tags",
            "canFlowTo_sufficient",
            "canFlowTo_refl",
            "canFlowTo_trans",
            "emptyTags_flowTo",
        ],
        "Master Theorem": [
            "isValidBoundedLattice",
        ],
    }

    def test_all_manifest_theorems_in_source(self, lean_source: str) -> None:
        """Every theorem in the manifest exists in the Lean source."""
        missing = []
        for group, theorems in self.PROPERTY_MANIFEST.items():
            for thm in theorems:
                if f"theorem {thm}" not in lean_source:
                    missing.append(f"{group}: {thm}")
        assert not missing, f"Missing theorems:\n" + "\n".join(missing)

    def test_total_theorem_count(self) -> None:
        total = sum(len(ts) for ts in self.PROPERTY_MANIFEST.values())
        assert total >= 55, f"Expected ≥55 manifest entries, got {total}"

    def test_manifest_categories(self) -> None:
        expected = {
            "P13 (Lattice Ordering)",
            "P14 (Flow Safety)",
            "P21 (Join Soundness)",
            "Meet Soundness",
            "Absorption Laws",
            "Distributivity",
            "Bounded Lattice",
            "Rank Properties",
            "Finiteness",
            "P15 (Label Flow)",
            "Master Theorem",
        }
        assert set(self.PROPERTY_MANIFEST.keys()) == expected

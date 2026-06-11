"""
Verified Skill Loader - JIT loading with Z3 verification.

Production hardening:
  A1: ``load_skill`` rejects expired / tampered / budget-exhausted tokens
      before any schema validation or Z3 work.
  A3: When a ``ComplianceConfig`` is provided, skill capabilities are
      intersected with the compliance forbidden list and ceiling.
"""
from __future__ import annotations
import json
import importlib.util
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field

from agentsafe.capabilities.tokens import CapabilityToken
from .schema import validate_skill_spec, load_and_validate
from .z3_verifier import verify_skill_constraints, Z3VerificationResult
from .exceptions import (
    SkillNotFoundError, SkillValidationError, CapabilityError,
    InformationFlowError,
)


@dataclass
class SkillSummary:
    """Lightweight skill metadata (~50 tokens)."""
    skill_id: str
    name: str
    description: str
    capabilities_required: List[str]
    risk_level: str = "medium"
    compliance_relevant: List[str] = field(default_factory=list)


@dataclass
class VerifiedSkill:
    """Full skill with verification results."""
    summary: SkillSummary
    verification: Dict[str, Any]
    verification_result: Z3VerificationResult
    implementation: Any = None
    skill_path: Optional[Path] = None


class VerifiedSkillLoader:
    """JIT skill loading with Z3 verification.

    Parameters
    ----------
    skills_dir : Path
        Root directory containing skill subdirectories.
    compliance_config : optional
        If provided, ``load_skill`` enforces the compliance policy
        ceiling and forbidden permission list (A3).
    """

    def __init__(self, skills_dir: Path, compliance_config: Any = None):
        self.skills_dir = Path(skills_dir)
        self._compliance = compliance_config
        self._summaries_cache: Optional[List[SkillSummary]] = None

    def list_skills(
        self, capability_token: Optional[CapabilityToken] = None,
    ) -> List[SkillSummary]:
        """List available skills, optionally filtered by token."""
        if self._summaries_cache is None:
            self._load_summaries()

        summaries = list(self._summaries_cache)
        if capability_token:
            summaries = [
                s for s in summaries
                if capability_token.has_all_permissions(s.capabilities_required)
            ]
        return summaries

    def load_skill(
        self, skill_id: str, capability_token: CapabilityToken,
        runtime_context: Optional[Dict[str, Any]] = None,
    ) -> VerifiedSkill:
        """JIT load, validate, and verify a skill.

        Production gates (in order):
        1. A1 - ``token.is_valid()`` rejects expired / tampered / exhausted
        2. A3 - compliance forbidden & ceiling check on required capabilities
        3. Z3  - deep constraint verification
        """
        # ── A1: Token validity gate ────────────────────────────────
        if not capability_token.is_valid():
            reason = capability_token.validation_error() or "token_invalid"
            raise CapabilityError(
                {reason},
                f"Token invalid ({reason}): cannot load skill '{skill_id}'",
            )

        skill_path = self.skills_dir / skill_id
        if not skill_path.exists():
            raise SkillNotFoundError(f"Skill not found: {skill_id}")

        # Load and validate VERIFICATION.json
        vj_path = skill_path / "VERIFICATION.json"
        spec = load_and_validate(vj_path)

        # ── A3: Compliance permission intersection ─────────────────
        vr = spec.get("verification_requirements", {})
        required_caps = vr.get("capabilities_required", [])
        if self._compliance is not None and required_caps:
            denials = self._check_compliance(required_caps)
            if denials:
                raise CapabilityError(
                    set(denials),
                    f"Compliance policy blocks skill '{skill_id}': "
                    + "; ".join(denials),
                )

        # Deep Z3 verification
        result = verify_skill_constraints(
            spec, capability_token.permissions,
            context=runtime_context,
        )
        if not result.valid:
            # Check if it's a capability issue
            required = set(required_caps)
            if not capability_token.has_all_permissions(list(required)):
                missing = required - capability_token.permission_set
                raise CapabilityError(missing)
            raise SkillValidationError(
                f"Verification failed for {skill_id}",
                errors=result.properties_failed,
            )

        # Load implementation
        impl = self._load_implementation(skill_path)

        summary = self._create_summary(skill_id, spec)
        return VerifiedSkill(
            summary=summary,
            verification=spec,
            verification_result=result,
            implementation=impl,
            skill_path=skill_path,
        )

    # ── A3: compliance permission checking ─────────────────────────

    def _check_compliance(self, required_caps: List[str]) -> List[str]:
        """Intersect skill capabilities with compliance policy."""
        denials: List[str] = []
        cfg = self._compliance
        policy_name = getattr(cfg, "name", "unknown")

        # Forbidden check
        forbidden = getattr(cfg, "forbidden_permissions", [])
        for cap in required_caps:
            if self._perm_matches_any(cap, forbidden):
                denials.append(
                    f"'{cap}' forbidden by '{policy_name}' policy"
                )

        # Ceiling check
        max_perms = getattr(cfg, "max_permissions", [])
        if max_perms and max_perms != ["*"]:
            for cap in required_caps:
                if cap not in [d.split("'")[1] for d in denials if "'" in d]:
                    if not self._perm_covered_by(cap, max_perms):
                        denials.append(
                            f"'{cap}' exceeds '{policy_name}' ceiling"
                        )

        return denials

    @staticmethod
    def _perm_matches_any(perm: str, patterns: List[str]) -> bool:
        for p in patterns:
            if p == perm:
                return True
            if p.endswith("*") and perm.startswith(p[:-1]):
                return True
        return False

    @staticmethod
    def _perm_covered_by(perm: str, allowed: List[str]) -> bool:
        for a in allowed:
            if a == perm or a == "*":
                return True
            if a.endswith("*") and perm.startswith(a[:-1]):
                return True
        return False

    def search_skills(
        self, query: str,
        capability_token: Optional[CapabilityToken] = None,
        compliance_filter: Optional[List[str]] = None,
    ) -> List[SkillSummary]:
        """Search skills by keyword with optional filters."""
        summaries = self.list_skills(capability_token)
        if compliance_filter:
            summaries = [
                s for s in summaries
                if any(c in s.compliance_relevant for c in compliance_filter)
            ]
        query_lower = query.lower()
        scored = []
        for s in summaries:
            score = 0
            if query_lower in s.name.lower():
                score += 3
            if query_lower in s.description.lower():
                score += 2
            if query_lower in s.skill_id:
                score += 1
            if score > 0:
                scored.append((s, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [s for s, _ in scored]

    def _load_summaries(self):
        self._summaries_cache = []
        if not self.skills_dir.exists():
            return
        for d in sorted(self.skills_dir.iterdir()):
            vj = d / "VERIFICATION.json"
            if vj.exists():
                try:
                    with open(vj) as f:
                        spec = json.load(f)
                    self._summaries_cache.append(
                        self._create_summary(d.name, spec)
                    )
                except (json.JSONDecodeError, KeyError):
                    pass

    def _create_summary(self, skill_id: str, spec: Dict) -> SkillSummary:
        meta = spec.get("metadata", {})
        vr = spec.get("verification_requirements", {})
        cm = spec.get("compliance_mappings", {})
        return SkillSummary(
            skill_id=skill_id,
            name=meta.get("name", skill_id),
            description=meta.get("description", ""),
            capabilities_required=vr.get("capabilities_required", []),
            risk_level=meta.get("risk_level", "medium"),
            compliance_relevant=[
                k for k, v in cm.items() if v.get("applies")
            ],
        )

    def _load_implementation(self, skill_path: Path) -> Any:
        impl_file = skill_path / "implementation.py"
        if not impl_file.exists():
            return None
        spec = importlib.util.spec_from_file_location(
            f"skill_{skill_path.name}", impl_file,
        )
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
                return module
            except Exception:
                return None
        return None

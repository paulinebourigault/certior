"""
CertiorPlan Python Bridge - PlanInfo JSON Generator

Translates Python agent plans (AgentAction, AgentPlan) into the
Lean4 PlanInfo JSON interchange format that the CertiorPlan kernel
can load, verify, and execute.

This bridges:
  Python (agentsafe/agents/orchestrator.py)  →  JSON  →  Lean4 (CertiorPlan/Eval.lean)

The PlanInfo format matches the Lean4 AST types exactly:
  - VerifiedPlan.mainSteps  ↔  PlanStep[] in JSON
  - VerifiedPlan.skills     ↔  SkillDef[] in JSON
  - VerifiedPlan.resources  ↔  ResourceDecl[] in JSON
  - FlowLabel              ↔  {"level": "Public"|"Internal"|"Sensitive"|"Restricted", "tags": [...]}

Usage:
    from agentsafe.verification.lean_bridge import PlanInfoBuilder

    builder = PlanInfoBuilder(compliance_policy="hipaa", budget_cents=5000)
    builder.add_resource("budget", 5000, level="Internal")
    builder.add_skill("query_patients",
        params=["patientId"],
        required_caps=[{"resource": "database:read:patient_data"}],
        steps=[
            builder.bind("rawData", builder.invoke_skill("database_query", ["patientId"]),
                         level="Sensitive", tags=["PHI"]),
            builder.emit("rawData"),
        ])
    builder.add_main_step(builder.bind("id", builder.literal(12345), level="Public"))
    builder.add_main_step(builder.invoke_and_bind("data", "query_patients", ["id"],
                                                   level="Sensitive"))
    builder.add_main_step(builder.emit("data"))

    plan_info_json = builder.to_json()
    # → Feed to `certior-dap` or `lake exe plan-export`
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional



# ═══════════════════════════════════════════════════════════════════════
# §1  Security Level (mirrors Lean4 SecurityLevel)
# ═══════════════════════════════════════════════════════════════════════

_RANK_TABLE: Dict[str, int] = {
    "Public": 0, "Internal": 1, "Sensitive": 2, "Restricted": 3,
}


class _RankValue(int):
    """Int-like rank wrapper that also supports legacy call syntax."""

    def __call__(self) -> int:
        return int(self)


class SecurityLevel(str, Enum):
    """
    Security clearance levels forming the DIFC lattice.
    Must match Lean4: Public(0) < Internal(1) < Sensitive(2) < Restricted(3)
    """
    PUBLIC = "Public"
    INTERNAL = "Internal"
    SENSITIVE = "Sensitive"
    RESTRICTED = "Restricted"

    @property
    def rank(self) -> _RankValue:
        """Numeric rank in the DIFC lattice. Works as both `.rank` and `.rank()`."""
        return _RankValue(_RANK_TABLE[self.value])

    def can_flow_to(self, dst: "SecurityLevel") -> bool:
        """Information flow check: rank(src) ≤ rank(dst)."""
        return self.rank <= dst.rank

    @classmethod
    def from_str(cls, s: str) -> "SecurityLevel":
        """Parse from the Lean4 string representation."""
        for member in cls:
            if member.value == s:
                return member
        raise ValueError(f"Unknown SecurityLevel: {s!r}")


# ═══════════════════════════════════════════════════════════════════════
# §2  AST types (mirrors Lean4 CertiorPlan.Ast)
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class FlowLabel:
    """
    Information-flow label attached to every binding.
    Accepts either a ``str`` or a :class:`SecurityLevel` for *level*.
    """
    level: str = "Public"
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Accept SecurityLevel enum transparently
        if isinstance(self.level, SecurityLevel):
            self.level = self.level.value

    def to_dict(self) -> Dict[str, Any]:
        return {"level": self.level, "tags": list(self.tags)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FlowLabel":
        """Reconstruct from a dictionary (inverse of ``to_dict``)."""
        return cls(level=d.get("level", "Public"), tags=d.get("tags", []))

    def security_level(self) -> SecurityLevel:
        """Return the typed :class:`SecurityLevel`."""
        return SecurityLevel.from_str(self.level)


@dataclass
class Capability:
    """
    A single capability requirement for a skill.

    Accepts both camelCase (``maxCost``) and snake_case (``cost``) for
    the cost field.
    """
    resource: str = ""
    maxCost: int = 0

    def __init__(self, resource: str = "", maxCost: int = 0,
                 *, cost: int = 0) -> None:
        self.resource = resource
        self.maxCost = cost if cost else maxCost

    @property
    def cost(self) -> int:
        """Alias for ``maxCost``."""
        return self.maxCost

    def to_dict(self) -> Dict[str, Any]:
        return {"resource": self.resource, "maxCost": self.maxCost}


@dataclass
class StepRhs:
    """
    Right-hand side of a plan step.
    Tagged union matching Lean4 ``StepRhs``.

    Prefer the class-method constructors (``literal``, ``invoke_skill``, …)
    over the raw dataclass constructor.
    """
    tag: str = "literal"
    value: Optional[int] = None
    skill: Optional[str] = None
    args: Optional[List[str]] = None
    src: Optional[str] = None
    dst: Optional[str] = None
    a: Optional[str] = None
    b: Optional[str] = None
    tokenId: Optional[str] = None
    removeCaps: Optional[List[str]] = None
    name: Optional[str] = None

    # ── Class-method constructors ───────────────────────────────────────

    @classmethod
    def literal(cls, value: int) -> "StepRhs":
        return cls(tag="literal", value=value)

    @classmethod
    def invoke_skill(cls, skill: str,
                     args: Optional[List[str]] = None) -> "StepRhs":
        return cls(tag="invokeSkill", skill=skill, args=args or [])

    @classmethod
    def check_flow(cls, src: str, dst: str) -> "StepRhs":
        return cls(tag="checkFlow", src=src, dst=dst)

    @classmethod
    def join_labels(cls, a: str, b: str) -> "StepRhs":
        return cls(tag="joinLabels", a=a, b=b)

    @classmethod
    def read_resource(cls, name: str) -> "StepRhs":
        return cls(tag="readResource", name=name)

    @classmethod
    def attenuate_token(
        cls, token_id: str, remove_caps: Optional[List[str]] = None,
    ) -> "StepRhs":
        return cls(tag="attenuateToken", tokenId=token_id,
                   removeCaps=remove_caps or [])

    # ── Serialisation ───────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"tag": self.tag}
        if self.tag == "literal":
            d["value"] = self.value
        elif self.tag == "invokeSkill":
            d["skill"] = self.skill
            d["args"] = self.args or []
        elif self.tag == "checkFlow":
            d["src"] = self.src
            d["dst"] = self.dst
        elif self.tag == "joinLabels":
            d["a"] = self.a
            d["b"] = self.b
        elif self.tag == "attenuateToken":
            d["tokenId"] = self.tokenId
            d["removeCaps"] = self.removeCaps or []
        elif self.tag == "readResource":
            d["name"] = self.name
        return d


@dataclass
class PlanStep:
    """
    A single plan step.  Tagged union matching Lean4 ``PlanStep``.

    Prefer the class-method constructors (``bind``, ``emit``, …) over
    the raw dataclass constructor.
    """
    tag: str = "bind"
    dest: Optional[str] = None
    rhs: Optional[StepRhs] = None
    label: Optional[FlowLabel] = None
    name: Optional[str] = None
    value: Optional[str] = None
    reason: Optional[str] = None

    # ── Class-method constructors ───────────────────────────────────────

    @classmethod
    def bind(
        cls,
        dest: str,
        rhs: StepRhs,
        label: Optional[FlowLabel] = None,
        *,
        level: str = "Public",
        tags: Optional[List[str]] = None,
    ) -> "PlanStep":
        """
        Create a ``bind`` step.

        *label* takes precedence; if ``None`` a :class:`FlowLabel` is
        constructed from *level* / *tags*.
        """
        if label is None:
            label = FlowLabel(level, tags or [])
        return cls(tag="bind", dest=dest, rhs=rhs, label=label)

    @classmethod
    def emit(cls, value: str) -> "PlanStep":
        return cls(tag="emitResult", value=value)

    @classmethod
    def set_resource(cls, name: str, value: str) -> "PlanStep":
        return cls(tag="setResource", name=name, value=value)

    @classmethod
    def require_approval(cls, reason: str) -> "PlanStep":
        return cls(tag="requireApproval", reason=reason)

    @classmethod
    def read_resource(
        cls, resource: str, dest: str,
        label: Optional[FlowLabel] = None,
    ) -> "PlanStep":
        """Convenience: ``bind(dest, readResource(resource), label)``."""
        return cls.bind(dest, StepRhs.read_resource(resource), label)

    # ── Serialisation ───────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"tag": self.tag}
        if self.tag == "bind":
            d["dest"] = self.dest
            d["rhs"] = self.rhs.to_dict() if self.rhs else {}
            d["label"] = (self.label.to_dict() if self.label
                          else FlowLabel().to_dict())
        elif self.tag == "setResource":
            d["name"] = self.name
            d["value"] = self.value
        elif self.tag == "emitResult":
            d["value"] = self.value
        elif self.tag == "requireApproval":
            d["reason"] = self.reason
        return d


@dataclass
class StepSpan:
    startLine: int = 0
    startColumn: int = 0
    endLine: int = 0
    endColumn: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LocatedStep:
    skillId: str = ""
    stepLine: int = 0
    step: PlanStep = field(default_factory=PlanStep)
    span: StepSpan = field(default_factory=StepSpan)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "skillId": self.skillId,
            "stepLine": self.stepLine,
            "step": self.step.to_dict(),
            "span": self.span.to_dict(),
        }


@dataclass
class ResourceDecl:
    name: str = ""
    init: int = 0
    label: FlowLabel = field(default_factory=lambda: FlowLabel("Internal"))

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "init": self.init,
                "label": self.label.to_dict()}


class SkillDef:
    """
    Skill definition matching Lean4 ``SkillDef``.

    Accepts both Lean-style camelCase (``skillId``, ``requiredCaps``)
    and pythonic snake_case (``skill_id``, ``required_caps``).
    """

    __slots__ = ("skillId", "params", "requiredCaps", "body")

    def __init__(
        self,
        skillId: Optional[str] = None,
        params: Optional[List[str]] = None,
        requiredCaps: Optional[List[Capability]] = None,
        body: Optional[List[PlanStep]] = None,
        *,
        skill_id: Optional[str] = None,
        required_caps: Optional[List[Capability]] = None,
    ) -> None:
        self.skillId: str = skill_id or skillId or ""
        self.params: List[str] = params if params is not None else []
        self.requiredCaps: List[Capability] = (
            required_caps if required_caps is not None
            else requiredCaps if requiredCaps is not None
            else []
        )
        self.body: List[PlanStep] = body if body is not None else []

    @property
    def skill_id(self) -> str:
        return self.skillId

    @property
    def required_caps(self) -> List[Capability]:
        return self.requiredCaps

    def to_dict(self) -> Dict[str, Any]:
        return {
            "skillId": self.skillId,
            "params": self.params,
            "requiredCaps": [c.to_dict() for c in self.requiredCaps],
            "body": [s.to_dict() for s in self.body],
        }

    def __repr__(self) -> str:
        return (f"SkillDef(skillId={self.skillId!r}, params={self.params!r}, "
                f"requiredCaps={self.requiredCaps!r}, body=<{len(self.body)} steps>)")


class VerifiedPlan:
    """
    Top-level plan object matching Lean4 ``VerifiedPlan``.

    Provides both camelCase fields (for JSON/Lean4 compat) and
    snake_case property aliases (for pythonic access).
    """

    __slots__ = (
        "resources", "skills", "mainSteps",
        "totalBudgetCents", "requiredTokens", "compliancePolicy",
    )

    def __init__(
        self,
        resources: Optional[List[ResourceDecl]] = None,
        skills: Optional[List[SkillDef]] = None,
        mainSteps: Optional[List[PlanStep]] = None,
        totalBudgetCents: int = 10000,
        requiredTokens: Optional[List[str]] = None,
        compliancePolicy: str = "default",
    ) -> None:
        self.resources: List[ResourceDecl] = (
            resources if resources is not None else [])
        self.skills: List[SkillDef] = (
            skills if skills is not None else [])
        self.mainSteps: List[PlanStep] = (
            mainSteps if mainSteps is not None else [])
        self.totalBudgetCents: int = totalBudgetCents
        self.requiredTokens: List[str] = (
            requiredTokens if requiredTokens is not None else [])
        self.compliancePolicy: str = compliancePolicy

    # ── snake_case property aliases ─────────────────────────────────────

    @property
    def main_steps(self) -> List[PlanStep]:
        return self.mainSteps

    @property
    def total_budget_cents(self) -> int:
        return self.totalBudgetCents

    @property
    def required_tokens(self) -> List[str]:
        return self.requiredTokens

    @property
    def compliance_policy(self) -> str:
        return self.compliancePolicy

    @property
    def total_step_count(self) -> int:
        """Total steps across all skills + main body."""
        return sum(len(s.body) for s in self.skills) + len(self.mainSteps)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resources": [r.to_dict() for r in self.resources],
            "skills": [s.to_dict() for s in self.skills],
            "mainSteps": [s.to_dict() for s in self.mainSteps],
            "totalBudgetCents": self.totalBudgetCents,
            "requiredTokens": self.requiredTokens,
            "compliancePolicy": self.compliancePolicy,
        }

    def __repr__(self) -> str:
        return (f"VerifiedPlan(policy={self.compliancePolicy!r}, "
                f"skills={len(self.skills)}, steps={self.total_step_count})")


@dataclass
class PlanInfo:
    plan: VerifiedPlan = field(default_factory=VerifiedPlan)
    located: List[LocatedStep] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan": self.plan.to_dict(),
            "located": [ls.to_dict() for ls in self.located],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    # ── Static flow analysis ────────────────────────────────────────────

    def detect_flow_violations(self) -> List[Dict[str, Any]]:
        """
        Static information-flow analysis over the plan AST.

        Walks every skill body and the main step list.  For each
        ``invokeSkill`` binding, looks up the invoked skill's body
        and computes the *maximum* security level produced by that
        skill.  If the binding label is *lower* than the skill's
        output level, a **downgrade violation** is reported.

        Returns a (possibly empty) list of violation dicts::

            {"type": "downgrade",
             "source_level": "Sensitive",
             "target_level": "Public",
             "step_tag": "bind",
             "step_dest": "result",
             "skill": "main"}
        """
        violations: List[Dict[str, Any]] = []
        level_name = {v: k for k, v in _RANK_TABLE.items()}

        # Build lookup: skill_id → max output level rank
        skill_max_rank: Dict[str, int] = {}
        for skill in self.plan.skills:
            max_r = 0
            for step in skill.body:
                if step.tag == "bind" and step.label:
                    r = _RANK_TABLE.get(step.label.level, 0)
                    if r > max_r:
                        max_r = r
            skill_max_rank[skill.skillId] = max_r

        def _check_steps(steps: List[PlanStep], ctx: str) -> None:
            for step in steps:
                if step.tag != "bind":
                    continue
                lbl_rank = _RANK_TABLE.get(
                    step.label.level if step.label else "Public", 0)
                # If rhs invokes a skill, compare skill output to binding
                if (step.rhs and step.rhs.tag == "invokeSkill"
                        and step.rhs.skill):
                    src_rank = skill_max_rank.get(step.rhs.skill, 0)
                    if src_rank > lbl_rank:
                        violations.append({
                            "type": "downgrade",
                            "source_level": level_name[src_rank],
                            "target_level": level_name[lbl_rank],
                            "step_tag": "bind",
                            "step_dest": step.dest or "?",
                            "skill": ctx,
                        })

        for skill in self.plan.skills:
            _check_steps(skill.body, skill.skillId)
        _check_steps(self.plan.mainSteps, "main")

        return violations

    # ── JSON deserialisation ────────────────────────────────────────────

    @classmethod
    def from_json(cls, json_str: str) -> "PlanInfo":
        data = json.loads(json_str)
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict) -> "PlanInfo":
        plan_data = data["plan"]
        plan = VerifiedPlan(
            resources=[
                ResourceDecl(
                    name=r["name"],
                    init=r["init"],
                    label=FlowLabel.from_dict(r.get("label", {})),
                )
                for r in plan_data.get("resources", [])
            ],
            skills=[cls._parse_skill(s) for s in plan_data.get("skills", [])],
            mainSteps=[cls._parse_step(s)
                       for s in plan_data.get("mainSteps", [])],
            totalBudgetCents=plan_data.get("totalBudgetCents", 10000),
            requiredTokens=plan_data.get("requiredTokens", []),
            compliancePolicy=plan_data.get("compliancePolicy", "default"),
        )
        located = [
            LocatedStep(
                skillId=loc["skillId"],
                stepLine=loc["stepLine"],
                step=cls._parse_step(loc["step"]),
                span=StepSpan(**loc["span"]),
            )
            for loc in data.get("located", [])
        ]
        return cls(plan=plan, located=located)

    @classmethod
    def _parse_skill(cls, data: dict) -> SkillDef:
        return SkillDef(
            skillId=data["skillId"],
            params=data.get("params", []),
            requiredCaps=[
                Capability(**c) for c in data.get("requiredCaps", [])],
            body=[cls._parse_step(s) for s in data.get("body", [])],
        )

    @classmethod
    def _parse_step(cls, data: dict) -> PlanStep:
        tag = data["tag"]
        if tag == "bind":
            rhs_data = data.get("rhs", {})
            rhs = StepRhs(tag=rhs_data.get("tag", "literal"), **{
                k: v for k, v in rhs_data.items() if k != "tag"
            })
            label = FlowLabel.from_dict(data.get("label", {}))
            return PlanStep(tag="bind", dest=data.get("dest"),
                            rhs=rhs, label=label)
        elif tag == "setResource":
            return PlanStep(tag="setResource", name=data.get("name"),
                            value=data.get("value"))
        elif tag == "emitResult":
            return PlanStep(tag="emitResult", value=data.get("value"))
        elif tag == "requireApproval":
            return PlanStep(tag="requireApproval",
                            reason=data.get("reason"))
        raise ValueError(f"Unknown PlanStep tag: {tag}")


# ═══════════════════════════════════════════════════════════════════════
# §3  PlanInfoBuilder - fluent API for constructing plans
# ═══════════════════════════════════════════════════════════════════════

class PlanInfoBuilder:
    """
    Fluent API for building PlanInfo JSON that the Lean4 CertiorPlan
    kernel can import and verify.

    Example::

        builder = PlanInfoBuilder(compliance_policy="hipaa", budget_cents=5000)
        builder.add_resource("budget", 5000, level="Internal")
        builder.add_skill(
            SkillDef(skill_id="read_patients", params=["id"],
                     required_caps=[Capability(resource="db:read", cost=100)],
                     body=[PlanStep.bind("d", StepRhs.literal(1),
                                         FlowLabel("Sensitive", ["PHI"])),
                           PlanStep.emit("d")]))
        builder.add_main_step(PlanStep.bind("id", StepRhs.literal(42)))
        builder.add_main_step(PlanStep.emit("data"))
        plan_json = builder.to_json()
    """

    def __init__(
        self,
        compliance_policy: str = "default",
        budget_cents: int = 10000,
        required_tokens: Optional[List[str]] = None,
    ):
        self._compliance_policy = compliance_policy
        self._budget_cents = budget_cents
        self._required_tokens = required_tokens or []
        self._resources: List[ResourceDecl] = []
        self._skills: List[SkillDef] = []
        self._main_steps: List[PlanStep] = []

    # ── Resource management ─────────────────────────────────────────────

    def add_resource(
        self,
        name_or_decl: Any = None,
        init: Optional[int] = None,
        level: str = "Internal",
        tags: Optional[List[str]] = None,
        *,
        name: Optional[str] = None,
    ) -> "PlanInfoBuilder":
        """Add a resource.  Accepts a :class:`ResourceDecl` or keyword args."""
        if isinstance(name_or_decl, ResourceDecl):
            self._resources.append(name_or_decl)
            return self
        n = name_or_decl or name or ""
        self._resources.append(
            ResourceDecl(n, init or 0, FlowLabel(level, tags or [])))
        return self

    # ── Skill management ────────────────────────────────────────────────

    def add_skill(
        self,
        skill_or_id: Any = None,
        params: Optional[List[str]] = None,
        required_caps: Optional[List[Any]] = None,
        steps: Optional[List[PlanStep]] = None,
        *,
        skill_id: Optional[str] = None,
    ) -> "PlanInfoBuilder":
        """
        Add a skill.  Accepts either a pre-built :class:`SkillDef`
        instance **or** keyword args forwarded to :class:`SkillDef`.
        """
        if isinstance(skill_or_id, SkillDef):
            self._skills.append(skill_or_id)
            return self
        sid = skill_or_id or skill_id or ""
        caps = [
            Capability(**c) if isinstance(c, dict) else c
            for c in (required_caps or [])
        ]
        self._skills.append(SkillDef(
            skillId=sid, params=params or [],
            requiredCaps=caps, body=steps or [],
        ))
        return self

    # ── Main step management ───────────────────────────────────────────

    def add_main_step(self, step: PlanStep) -> "PlanInfoBuilder":
        self._main_steps.append(step)
        return self

    # ── Legacy step constructors (delegate to class methods) ───────────

    @staticmethod
    def literal(value: int) -> StepRhs:
        return StepRhs.literal(value)

    @staticmethod
    def invoke_skill(skill: str,
                     args: Optional[List[str]] = None) -> StepRhs:
        return StepRhs.invoke_skill(skill, args)

    @staticmethod
    def check_flow(src: str, dst: str) -> StepRhs:
        return StepRhs.check_flow(src, dst)

    @staticmethod
    def join_labels(a: str, b: str) -> StepRhs:
        return StepRhs.join_labels(a, b)

    @staticmethod
    def read_resource(name: str) -> StepRhs:
        return StepRhs.read_resource(name)

    @staticmethod
    def bind(
        dest: str,
        rhs: StepRhs,
        level: str = "Public",
        tags: Optional[List[str]] = None,
    ) -> PlanStep:
        return PlanStep.bind(dest, rhs, level=level, tags=tags)

    @staticmethod
    def set_resource(name: str, value: str) -> PlanStep:
        return PlanStep.set_resource(name, value)

    @staticmethod
    def emit(value: str) -> PlanStep:
        return PlanStep.emit(value)

    @staticmethod
    def require_approval(reason: str) -> PlanStep:
        return PlanStep.require_approval(reason)

    def invoke_and_bind(
        self,
        dest: str,
        skill: str,
        args: Optional[List[str]] = None,
        level: str = "Internal",
        tags: Optional[List[str]] = None,
    ) -> PlanStep:
        return PlanStep.bind(dest, StepRhs.invoke_skill(skill, args),
                             level=level, tags=tags)

    # ── Build ──────────────────────────────────────────────────────────

    def build(self) -> PlanInfo:
        plan = VerifiedPlan(
            resources=self._resources,
            skills=self._skills,
            mainSteps=self._main_steps,
            totalBudgetCents=self._budget_cents,
            requiredTokens=self._required_tokens,
            compliancePolicy=self._compliance_policy,
        )
        # Auto-generate located steps with synthetic spans
        located: List[LocatedStep] = []
        line = 1
        for skill in self._skills:
            for i, step in enumerate(skill.body):
                located.append(LocatedStep(
                    skillId=skill.skillId, stepLine=i + 1, step=step,
                    span=StepSpan(line, 0, line, 40),
                ))
                line += 1
        for i, step in enumerate(self._main_steps):
            located.append(LocatedStep(
                skillId="main", stepLine=i + 1, step=step,
                span=StepSpan(line, 0, line, 40),
            ))
            line += 1
        return PlanInfo(plan=plan, located=located)

    def to_json(self, indent: int = 2) -> str:
        return self.build().to_json(indent=indent)


# ═══════════════════════════════════════════════════════════════════════
# §4  Lean4 kernel execution bridge
# ═══════════════════════════════════════════════════════════════════════

class LeanKernelBridge:
    """
    Execute plans through the Lean4 verified kernel.

    Requires: CertiorPlan built with `lake build` in lean4/CertiorPlan/
    """

    def __init__(self, lean_project_dir: Optional[Path] = None):
        if lean_project_dir is None:
            # Default: relative to this file
            self.project_dir = Path(__file__).parent.parent.parent / "lean4" / "CertiorPlan"
        else:
            self.project_dir = lean_project_dir

    def is_available(self) -> bool:
        """Check if the Lean4 kernel is built and available."""
        return (self.project_dir / "lakefile.lean").exists()

    def export_plan(self, plan_info: PlanInfo, output_path: Path) -> Path:
        """Export PlanInfo as JSON for the Lean kernel."""
        output_path.write_text(plan_info.to_json())
        return output_path

    def validate_plan(self, plan_info: PlanInfo) -> Dict[str, Any]:
        """
        Validate a plan using Python-side flow checking.
        Returns validation result dict.
        """
        errors = []
        plan = plan_info.plan

        # Check main steps exist
        if not plan.mainSteps:
            errors.append("Plan has no main steps")

        # Check flow labels on bind steps
        label_store: Dict[str, FlowLabel] = {}
        for step in plan.mainSteps:
            if step.tag == "bind" and step.rhs and step.label:
                # Check input labels flow to declared label
                if step.rhs.tag == "invokeSkill" and step.rhs.args:
                    for arg in step.rhs.args:
                        if arg in label_store:
                            src = SecurityLevel(label_store[arg].level)
                            dst = SecurityLevel(step.label.level)
                            if not src.can_flow_to(dst):
                                errors.append(
                                    f"Flow violation: {arg} ({src.value}) → "
                                    f"{step.dest} ({dst.value})"
                                )
                if step.dest:
                    label_store[step.dest] = step.label

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "steps_checked": len(plan.mainSteps),
            "labels_tracked": len(label_store),
        }

    # ── Export CLI Bridge (Week A2) ────────────────────────────────────

    def export_builtin(self, plan_name: str, output_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Export a built-in plan using `lake exe plan-export --decl <name>`.

        Args:
            plan_name: One of "basic", "hipaa", "sox"
            output_path: Optional file to write JSON to

        Returns:
            Dict with "success", "json", and optionally "error" keys
        """
        cmd = ["lake", "exe", "plan-export", "--decl", plan_name]
        if output_path:
            cmd.extend(["--out", str(output_path)])
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.project_dir),
                timeout=60,
            )
            if result.returncode == 0:
                return {"success": True, "json": result.stdout.strip()}
            else:
                return {"success": False, "error": result.stderr.strip()}
        except FileNotFoundError:
            return {"success": False, "error": "lake not found in PATH"}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Export timed out after 60s"}

    def validate_builtin(self, plan_name: str) -> Dict[str, Any]:
        """
        Validate a built-in plan using `lake exe plan-export --decl <name> --validate`.

        Returns:
            Dict with validation report
        """
        cmd = ["lake", "exe", "plan-export", "--decl", plan_name, "--validate"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.project_dir),
                timeout=60,
            )
            return {"success": result.returncode == 0, "output": result.stdout.strip()}
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return {"success": False, "error": str(e)}

    def run_builtin(self, plan_name: str) -> Dict[str, Any]:
        """
        Execute a built-in plan using `lake exe plan-export --decl <name> --run`.

        Returns:
            Dict with execution result
        """
        cmd = ["lake", "exe", "plan-export", "--decl", plan_name, "--run"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.project_dir),
                timeout=60,
            )
            return {"success": result.returncode == 0, "output": result.stdout.strip()}
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return {"success": False, "error": str(e)}

    def import_and_validate_json(self, json_path: Path) -> Dict[str, Any]:
        """
        Import and validate a PlanInfo JSON file using the Lean kernel.

        Args:
            json_path: Path to PlanInfo JSON file

        Returns:
            Dict with validation result
        """
        cmd = ["lake", "exe", "plan-export", "--file", str(json_path), "--validate"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.project_dir),
                timeout=60,
            )
            return {"success": result.returncode == 0, "output": result.stdout.strip()}
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return {"success": False, "error": str(e)}

    def generate_report(self, plan_name: str, output_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Generate a full execution report for a built-in plan.

        Args:
            plan_name: One of "basic", "hipaa", "sox"
            output_path: Optional file to write report JSON to

        Returns:
            Dict with report data
        """
        cmd = ["lake", "exe", "plan-export", "--decl", plan_name, "--report"]
        if output_path:
            cmd.extend(["--out", str(output_path)])
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.project_dir),
                timeout=60,
            )
            if result.returncode == 0:
                try:
                    report = json.loads(result.stdout.strip())
                    return {"success": True, "report": report}
                except json.JSONDecodeError:
                    return {"success": True, "output": result.stdout.strip()}
            else:
                return {"success": False, "error": result.stderr.strip()}
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return {"success": False, "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════
# §7  DAP Subprocess Manager (NEW - Phase C)
# ═══════════════════════════════════════════════════════════════════════

import threading
import io
import os
import time
import logging
from typing import Callable

logger = logging.getLogger("certior.dap")


class DAPError(Exception):
    """Raised when the DAP adapter returns an error response."""

    def __init__(self, command: str, message: str, body: Optional[Dict] = None):
        self.command = command
        self.message = message
        self.body = body or {}
        super().__init__(f"DAP error on '{command}': {message}")


class DAPTimeout(DAPError):
    """Raised when a DAP request times out."""

    def __init__(self, command: str, timeout: float):
        super().__init__(command, f"Timed out after {timeout:.1f}s")
        self.timeout = timeout


class DAPTransport:
    """
    Low-level DAP message framing over stdin/stdout.

    Implements the base protocol used by DAP (identical to LSP):
      Content-Length: <length>\r\n
      \r\n
      <JSON payload>

    Thread-safe: reading runs on a background thread, writing
    is protected by a lock.
    """

    def __init__(
        self,
        stdin: io.BufferedWriter,
        stdout: io.BufferedReader,
    ):
        self._stdin = stdin
        self._stdout = stdout
        self._write_lock = threading.Lock()
        self._seq = 0
        self._pending: Dict[int, threading.Event] = {}
        self._responses: Dict[int, Dict] = {}
        self._events: List[Dict] = []
        self._event_lock = threading.Lock()
        self._event_callbacks: Dict[str, List[Callable]] = {}
        self._reader_thread: Optional[threading.Thread] = None
        self._alive = False

    def start(self) -> None:
        """Start the background reader thread."""
        self._alive = True
        self._reader_thread = threading.Thread(
            target=self._read_loop, daemon=True, name="dap-reader"
        )
        self._reader_thread.start()

    def stop(self) -> None:
        """Signal the reader thread to stop."""
        self._alive = False
        # Unblock all pending requests
        for evt in self._pending.values():
            evt.set()

    def send_request(
        self,
        command: str,
        arguments: Optional[Dict] = None,
        timeout: float = 30.0,
    ) -> Dict:
        """
        Send a DAP request and wait for the corresponding response.

        Args:
            command: DAP command name (e.g., "initialize", "launch")
            arguments: Optional request arguments
            timeout: Max seconds to wait

        Returns:
            The response body dict

        Raises:
            DAPError: If the adapter returns success=false
            DAPTimeout: If no response within timeout
        """
        self._seq += 1
        seq = self._seq
        event = threading.Event()
        self._pending[seq] = event

        message: Dict[str, Any] = {
            "seq": seq,
            "type": "request",
            "command": command,
        }
        if arguments is not None:
            message["arguments"] = arguments

        self._write_message(message)
        logger.debug("→ request #%d %s", seq, command)

        if not event.wait(timeout=timeout):
            self._pending.pop(seq, None)
            raise DAPTimeout(command, timeout)

        self._pending.pop(seq, None)
        response = self._responses.pop(seq, {})

        if not response.get("success", False):
            raise DAPError(
                command,
                response.get("message", "Unknown error"),
                response.get("body"),
            )

        return response.get("body", {})

    def on_event(self, event_type: str, callback: Callable[[Dict], None]) -> None:
        """Register a callback for a specific DAP event type."""
        self._event_callbacks.setdefault(event_type, []).append(callback)

    def drain_events(self, event_type: Optional[str] = None) -> List[Dict]:
        """Return and clear buffered events, optionally filtered by type."""
        with self._event_lock:
            if event_type is None:
                events = list(self._events)
                self._events.clear()
            else:
                events = [e for e in self._events if e.get("event") == event_type]
                self._events = [
                    e for e in self._events if e.get("event") != event_type
                ]
        return events

    # ── Internal ──────────────────────────────────────────────────────

    def _write_message(self, msg: Dict) -> None:
        payload = json.dumps(msg).encode("utf-8")
        header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
        with self._write_lock:
            self._stdin.write(header + payload)
            self._stdin.flush()

    def _read_loop(self) -> None:
        """Background thread: read messages from stdout."""
        try:
            while self._alive:
                msg = self._read_one_message()
                if msg is None:
                    break
                msg_type = msg.get("type")
                if msg_type == "response":
                    seq = msg.get("request_seq", -1)
                    logger.debug(
                        "← response #%d %s success=%s",
                        seq,
                        msg.get("command"),
                        msg.get("success"),
                    )
                    self._responses[seq] = msg
                    evt = self._pending.get(seq)
                    if evt:
                        evt.set()
                elif msg_type == "event":
                    event_name = msg.get("event", "")
                    logger.debug("← event %s", event_name)
                    with self._event_lock:
                        self._events.append(msg)
                    for cb in self._event_callbacks.get(event_name, []):
                        try:
                            cb(msg)
                        except Exception:
                            logger.exception("Event callback error for %s", event_name)
        except Exception:
            if self._alive:
                logger.exception("DAP reader thread crashed")
        finally:
            self._alive = False
            for evt in self._pending.values():
                evt.set()

    def _read_one_message(self) -> Optional[Dict]:
        """Read one Content-Length-framed message."""
        content_length = -1
        while True:
            line = self._stdout.readline()
            if not line:
                return None
            line_str = line.decode("ascii", errors="replace").strip()
            if not line_str:
                break
            if line_str.lower().startswith("content-length:"):
                try:
                    content_length = int(line_str.split(":", 1)[1].strip())
                except ValueError:
                    return None
        if content_length < 0:
            return None
        payload = self._stdout.read(content_length)
        if len(payload) < content_length:
            return None
        try:
            return json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError:
            logger.warning("Malformed JSON payload from DAP adapter")
            return None


class DAPClient:
    """
    High-level Python client for the Certior DAP debug adapter.

    Manages the lifecycle of a ``certior-dap`` subprocess and provides a
    Pythonic interface for every DAP operation, including the 6 Certior-specific
    custom requests (``certificates``, ``flowGraph``, ``complianceExport``,
    ``setFlowBreakpoints``, ``setBudgetBreakpoint``, ``setCapabilityWatch``).

    Usage::

        from agentsafe.verification.lean_bridge import DAPClient, PlanInfoBuilder

        builder = PlanInfoBuilder(compliance_policy="hipaa", budget_cents=5000)
        # ... build plan ...
        plan_info = builder.build()

        async with DAPClient.from_plan(plan_info) as client:
            client.step_in()
            state = client.stack_trace()
            certs = client.certificates()
            flow = client.flow_graph()
            client.continue_execution()

    The subprocess is automatically cleaned up on context-manager exit,
    ``disconnect()``, or garbage collection.
    """

    DEFAULT_BINARY = ".lake/build/bin/certior-dap"
    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        binary: Optional[str] = None,
        cwd: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        env: Optional[Dict[str, str]] = None,
    ):
        """
        Args:
            binary: Path to the certior-dap executable.
                    Defaults to ``.lake/build/bin/certior-dap`` relative to ``cwd``.
            cwd: Working directory (usually the CertiorPlan project root).
            timeout: Default timeout for DAP requests in seconds.
            env: Extra environment variables for the subprocess.
        """
        self._binary = binary or self.DEFAULT_BINARY
        self._cwd = cwd
        self._timeout = timeout
        self._env = env
        self._process: Optional[subprocess.Popen] = None
        self._transport: Optional[DAPTransport] = None
        self._thread_id: Optional[int] = 1  # DAP thread ID (Certior uses 1)
        self._initialized = False
        self._launched = False
        self._terminated = False

    # ── Lifecycle ──────────────────────────────────────────────────────

    def start(self) -> "DAPClient":
        """
        Start the DAP adapter subprocess.

        The subprocess communicates over stdin/stdout using the DAP base
        protocol (Content-Length framed JSON, identical to LSP).
        """
        if self._process is not None:
            raise RuntimeError("DAPClient already started")

        env = dict(os.environ)
        if self._env:
            env.update(self._env)

        logger.info("Starting DAP adapter: %s", self._binary)
        self._process = subprocess.Popen(
            [self._binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self._cwd,
            env=env,
        )

        self._transport = DAPTransport(self._process.stdin, self._process.stdout)
        self._transport.start()

        # Wire up terminated event
        self._transport.on_event("terminated", self._on_terminated)

        return self

    def stop(self, timeout: float = 5.0) -> None:
        """Gracefully shut down the subprocess."""
        if self._process is None:
            return

        try:
            if self._launched and not self._terminated:
                self._send("disconnect", terminateDebuggee=True)
        except Exception:
            pass

        if self._transport:
            self._transport.stop()

        try:
            self._process.terminate()
            self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.warning("DAP adapter did not terminate; killing")
            self._process.kill()
            self._process.wait(timeout=2)
        finally:
            self._process = None
            self._transport = None
            self._initialized = False
            self._launched = False

    def __enter__(self) -> "DAPClient":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def __del__(self) -> None:
        try:
            self.stop()
        except Exception:
            pass

    # ── Initialization ────────────────────────────────────────────────

    def initialize(self) -> Dict:
        """
        Send ``initialize`` request.

        Called automatically by ``launch()`` if not yet initialized.
        Returns the adapter capabilities.
        """
        if self._initialized:
            return {}

        caps = self._send(
            "initialize",
            clientID="certior-python-bridge",
            clientName="Certior Python Bridge",
            adapterID="certior-plan-dap",
            linesStartAt1=True,
            columnsStartAt1=True,
            supportsVariableType=True,
            supportsSteppingGranularity=True,
            supportsStepBack=True,
        )
        self._initialized = True
        return caps

    def launch(
        self,
        plan_info: Optional["PlanInfo"] = None,
        plan_info_json: Optional[str] = None,
        plan_info_path: Optional[str] = None,
        stop_on_entry: bool = True,
    ) -> Dict:
        """
        Send ``launch`` request to start a debug session.

        Exactly one of ``plan_info``, ``plan_info_json``, or
        ``plan_info_path`` must be provided.

        Args:
            plan_info: A ``PlanInfo`` object to serialize and send.
            plan_info_json: Raw JSON string of PlanInfo.
            plan_info_path: Path to a PlanInfo JSON file on disk.
            stop_on_entry: Whether to pause at the first instruction.

        Returns:
            Launch response body.
        """
        if not self._initialized:
            self.initialize()

        args: Dict[str, Any] = {"stopOnEntry": stop_on_entry, "noDebug": False}

        if plan_info is not None:
            args["planInfo"] = plan_info.to_dict()
        elif plan_info_json is not None:
            args["planInfo"] = json.loads(plan_info_json)
        elif plan_info_path is not None:
            args["planInfoPath"] = str(plan_info_path)
        else:
            raise ValueError(
                "Provide exactly one of plan_info, plan_info_json, or plan_info_path"
            )

        body = self._send("launch", **args)
        self._launched = True

        # Send configurationDone
        self._send("configurationDone")

        return body

    @classmethod
    def from_plan(
        cls,
        plan_info: "PlanInfo",
        binary: Optional[str] = None,
        cwd: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> "DAPClient":
        """
        Convenience constructor: create, start, and launch with a PlanInfo.

        Usage::

            with DAPClient.from_plan(plan_info) as client:
                client.step_in()
        """
        client = cls(binary=binary, cwd=cwd, timeout=timeout)
        client.start()
        client.initialize()
        client.launch(plan_info=plan_info)
        return client

    # ── Breakpoints ───────────────────────────────────────────────────

    def set_breakpoints(self, source: str, lines: List[int]) -> List[Dict]:
        """
        Set line breakpoints.

        Args:
            source: Source path or skill name.
            lines: List of line numbers.

        Returns:
            List of breakpoint dicts with ``verified`` status.
        """
        body = self._send(
            "setBreakpoints",
            source={"path": source},
            breakpoints=[{"line": ln} for ln in lines],
        )
        return body.get("breakpoints", [])

    def set_exception_breakpoints(self, filters: List[str]) -> List[Dict]:
        """
        Set exception breakpoints.

        Supported filters: ``flow_violation``, ``budget_exceeded``,
        ``capability_denied``, ``approval_required``.
        """
        body = self._send("setExceptionBreakpoints", filters=filters)
        return body.get("breakpoints", [])

    def set_flow_breakpoints(
        self, breakpoints: List[Dict[str, Any]]
    ) -> List[Dict]:
        """
        Set Certior-specific flow breakpoints (custom request).

        Each breakpoint: ``{"level": "Sensitive", "dataId": "optional-var"}``.
        Triggers when data at or above the specified security level is accessed.
        """
        body = self._send(
            "setFlowBreakpoints", breakpoints=breakpoints
        )
        return body.get("breakpoints", [])

    def set_budget_breakpoint(self, threshold: int) -> Dict:
        """
        Set a budget breakpoint (custom request).

        Triggers when remaining budget drops below ``threshold`` cents.
        """
        return self._send("setBudgetBreakpoint", threshold=threshold)

    def set_capability_watch(self, capabilities: List[str]) -> Dict:
        """
        Set capability watches (custom request).

        Triggers when any of the specified capabilities are invoked.
        """
        return self._send("setCapabilityWatch", capabilities=capabilities)

    # ── Execution Control ─────────────────────────────────────────────

    def continue_execution(self) -> Dict:
        """Continue execution until next breakpoint or termination."""
        return self._send("continue", threadId=self._thread_id)

    def step_in(self) -> Dict:
        """Single step forward (into skill calls)."""
        return self._send("stepIn", threadId=self._thread_id)

    def step_back(self) -> Dict:
        """Single step backward (time-travel)."""
        return self._send("stepBack", threadId=self._thread_id)

    def next(self) -> Dict:
        """Step over (advance to next instruction at same depth)."""
        return self._send("next", threadId=self._thread_id)

    def step_out(self) -> Dict:
        """Step out of the current skill frame."""
        return self._send("stepOut", threadId=self._thread_id)

    def pause(self) -> Dict:
        """Pause execution."""
        return self._send("pause", threadId=self._thread_id)

    # ── Inspection ────────────────────────────────────────────────────

    def threads(self) -> List[Dict]:
        """Return list of threads (Certior always has 1)."""
        body = self._send("threads")
        return body.get("threads", [])

    def stack_trace(self, start_frame: int = 0, levels: int = 50) -> List[Dict]:
        """
        Return the current stack trace.

        Each frame includes skillName, stepLine, sourceLine.
        """
        body = self._send(
            "stackTrace",
            threadId=self._thread_id,
            startFrame=start_frame,
            levels=levels,
        )
        return body.get("stackFrames", [])

    def scopes(self, frame_id: int = 0) -> List[Dict]:
        """
        Return scopes for a stack frame.

        Certior uses 4 scopes per frame:
        - Locals (frameId*4 + 1)
        - Resources (frameId*4 + 2)
        - Flow Labels (frameId*4 + 3)
        - Certificates (frameId*4 + 4)
        """
        body = self._send("scopes", frameId=frame_id)
        return body.get("scopes", [])

    def variables(self, variables_reference: int) -> List[Dict]:
        """Return variables for a given scope reference."""
        body = self._send("variables", variablesReference=variables_reference)
        return body.get("variables", [])

    def evaluate(self, expression: str, frame_id: int = 0) -> Dict:
        """
        Evaluate an expression in the current context.

        Supports: variable names, ``budget``, ``certificates.count``,
        ``flow(varName)``.
        """
        return self._send(
            "evaluate",
            expression=expression,
            frameId=frame_id,
            context="watch",
        )

    # ── Certior Custom Requests ───────────────────────────────────────

    def certificates(self) -> Dict:
        """
        Return all proof certificates issued so far (custom request).

        Returns a dict with ``sessionId``, ``certificates`` (list),
        ``totalCount``, and ``allVerified`` flag.
        """
        return self._send("certificates")

    def flow_graph(self) -> Dict:
        """
        Return the information flow graph snapshot (custom request).

        Returns a dict with ``sessionId``, ``edges`` (list of
        source→target with level and allowed status), and
        ``violationCount``.
        """
        return self._send("flowGraph")

    def compliance_export(self) -> Dict:
        """
        Export the full compliance audit trail (custom request).

        Returns a comprehensive JSON including:
        - Plan metadata and policy
        - All execution steps with flow labels
        - All proof certificates
        - Budget consumption timeline
        - Flow graph with violation markers
        - Approval decisions

        This is the data a compliance officer would submit to regulators.
        """
        return self._send("complianceExport")

    # ── Session Info ──────────────────────────────────────────────────

    def exception_info(self) -> Dict:
        """Return details of the current exception/violation (if stopped on one)."""
        return self._send("exceptionInfo", threadId=self._thread_id)

    @property
    def is_alive(self) -> bool:
        """True if the subprocess is running and transport is active."""
        return (
            self._process is not None
            and self._process.poll() is None
            and self._transport is not None
            and self._transport._alive
        )

    @property
    def is_terminated(self) -> bool:
        return self._terminated

    @property
    def stderr_output(self) -> str:
        """Read any accumulated stderr from the subprocess (non-blocking)."""
        if self._process and self._process.stderr:
            try:
                import select

                if select.select([self._process.stderr], [], [], 0)[0]:
                    return self._process.stderr.read1().decode("utf-8", errors="replace")
            except Exception:
                pass
        return ""

    # ── Internal ──────────────────────────────────────────────────────

    def _send(self, command: str, **kwargs) -> Dict:
        """Send a DAP request and return the response body."""
        if self._transport is None:
            raise RuntimeError("DAPClient not started - call start() first")
        args = kwargs if kwargs else None
        return self._transport.send_request(command, args, timeout=self._timeout)

    def _on_terminated(self, event: Dict) -> None:
        self._terminated = True


# ═══════════════════════════════════════════════════════════════════════
# §8  Convenience: end-to-end verified execution from Python
# ═══════════════════════════════════════════════════════════════════════

class VerifiedPlanRunner:
    """
    High-level facade that combines PlanInfoBuilder + DAPClient to run
    a verified agent plan from Python and collect the compliance report.

    This is the primary integration point for the Python orchestrator.

    Usage::

        runner = VerifiedPlanRunner(lean_project="/path/to/CertiorPlan")
        result = runner.run(plan_info, stop_on_violations=True)
        print(result.certificates)
        print(result.compliance_export)
    """

    @dataclass
    class RunResult:
        """Result of a verified plan execution."""

        success: bool
        steps_executed: int
        certificates: List[Dict]
        flow_violations: int
        compliance_export: Dict
        budget_used: int
        budget_total: int
        stopped_reason: Optional[str] = None
        error: Optional[str] = None

    def __init__(
        self,
        lean_project: Optional[str] = None,
        binary: Optional[str] = None,
        timeout: float = 60.0,
    ):
        """
        Args:
            lean_project: Path to the CertiorPlan Lean4 project root.
            binary: Path to the certior-dap binary (auto-resolved if lean_project given).
            timeout: Per-request timeout.
        """
        self._lean_project = lean_project
        if binary:
            self._binary = binary
        elif lean_project:
            self._binary = str(Path(lean_project) / ".lake" / "build" / "bin" / "certior-dap")
        else:
            self._binary = DAPClient.DEFAULT_BINARY
        self._timeout = timeout

    def run(
        self,
        plan_info: PlanInfo,
        stop_on_violations: bool = True,
        max_steps: int = 10000,
    ) -> "VerifiedPlanRunner.RunResult":
        """
        Execute a plan through the Lean4 verified kernel via DAP.

        The execution proceeds step-by-step. If ``stop_on_violations`` is True
        and a flow violation or budget exceeded event occurs, execution halts
        and the violation is reported.

        Args:
            plan_info: The plan to execute.
            stop_on_violations: Halt on security violations.
            max_steps: Safety limit on total steps.

        Returns:
            RunResult with certificates, compliance export, and metrics.
        """
        client = DAPClient(
            binary=self._binary,
            cwd=self._lean_project,
            timeout=self._timeout,
        )

        steps = 0
        stopped_reason = None
        error_msg = None

        try:
            client.start()
            client.initialize()
            client.launch(plan_info=plan_info, stop_on_entry=True)

            # Set exception breakpoints for violations
            if stop_on_violations:
                client.set_exception_breakpoints([
                    "flow_violation",
                    "budget_exceeded",
                ])

            # Step through execution
            while steps < max_steps:
                try:
                    client.continue_execution()
                except DAPError:
                    break

                events = client._transport.drain_events("stopped") if client._transport else []
                if events:
                    last_event = events[-1]
                    reason = last_event.get("body", {}).get("reason", "")
                    if reason in ("flow_violation", "budget_exceeded", "capability_denied"):
                        stopped_reason = reason
                        if stop_on_violations:
                            break
                    elif reason == "terminated":
                        break

                steps += 1

                if client.is_terminated:
                    break

            # Collect results
            certs_response = client.certificates()
            compliance = client.compliance_export()

            return self.RunResult(
                success=stopped_reason is None,
                steps_executed=steps,
                certificates=certs_response.get("certificates", []),
                flow_violations=sum(
                    1
                    for c in certs_response.get("certificates", [])
                    if c.get("property") == "flow_violation"
                ),
                compliance_export=compliance,
                budget_used=compliance.get("budgetUsed", 0),
                budget_total=compliance.get("budgetTotal", 0),
                stopped_reason=stopped_reason,
            )

        except DAPError as e:
            return self.RunResult(
                success=False,
                steps_executed=steps,
                certificates=[],
                flow_violations=0,
                compliance_export={},
                budget_used=0,
                budget_total=0,
                error=str(e),
            )
        except FileNotFoundError:
            return self.RunResult(
                success=False,
                steps_executed=0,
                certificates=[],
                flow_violations=0,
                compliance_export={},
                budget_used=0,
                budget_total=0,
                error=f"certior-dap binary not found: {self._binary}. "
                "Run 'lake build certior-dap' in the CertiorPlan project.",
            )
        finally:
            client.stop()

    def validate_only(self, plan_info: PlanInfo) -> Dict[str, Any]:
        """
        Validate a plan without full execution.

        Launches, inspects the initial state (certificates from pre-verification),
        then disconnects. Useful for quick plan validation from Python.
        """
        client = DAPClient(
            binary=self._binary,
            cwd=self._lean_project,
            timeout=self._timeout,
        )
        try:
            client.start()
            client.initialize()
            client.launch(plan_info=plan_info, stop_on_entry=True)

            # Collect initial certificates (from plan pre-verification)
            certs = client.certificates()
            flow = client.flow_graph()
            scopes_list = client.scopes(frame_id=0)

            return {
                "valid": True,
                "certificates": certs.get("certificates", []),
                "flow_graph": flow.get("edges", []),
                "scopes": scopes_list,
                "violation_count": flow.get("violationCount", 0),
            }
        except DAPError as e:
            return {"valid": False, "error": str(e)}
        except FileNotFoundError:
            return {
                "valid": False,
                "error": f"certior-dap binary not found: {self._binary}",
            }
        finally:
            client.stop()

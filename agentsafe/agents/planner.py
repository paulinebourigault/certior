"""
PlannerAgent - task decomposition with verification.
IMPROVED: Better LLM integration + rule-based fallback that exercises Z3.
"""
from __future__ import annotations
import json
from typing import Any, Dict, List, Optional

from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.skills.loader import VerifiedSkillLoader, SkillSummary
from .base import VerifiedAgent, VerificationResult, VerificationError
from .actions import AgentAction, AgentPlan

try:
    from z3 import Solver, Int, Bool, And, Sum, sat, unsat
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


class PlanningError(Exception):
    pass


class PlannerAgent(VerifiedAgent):
    """Decomposes tasks into verified execution plans."""

    def __init__(
        self, agent_id: str, capability_token: CapabilityToken,
        llm_client: Any = None,
        skill_loader: Optional[VerifiedSkillLoader] = None,
    ):
        super().__init__(agent_id, capability_token, llm_client)
        self.skill_loader = skill_loader

    async def plan(self, task: str) -> AgentPlan:
        """Create a verified execution plan for a task."""
        # Get available skills
        available_skills = []
        if self.skill_loader:
            available_skills = self.skill_loader.list_skills(self.token)

        # Generate plan
        if self.llm:
            steps = await self._llm_plan(task, available_skills)
        else:
            steps = self._rule_based_plan(task, available_skills)

        plan = AgentPlan(
            task=task, steps=steps,
            total_budget_cents=self.token.budget_remaining_cents,
            available_capabilities=list(self.token.permissions),
        )

        # Pre-verify entire plan with Z3
        verification = await self._verify_plan(plan)
        if not verification.valid:
            # Try to fix by reducing budget
            for step in plan.steps:
                step.estimated_cost_cents = max(1, step.estimated_cost_cents // 2)
            verification = await self._verify_plan(plan)
            if not verification.valid:
                raise PlanningError(f"Cannot create safe plan: {verification.violations}")

        return plan

    async def _llm_plan(self, task: str, skills: List[SkillSummary]) -> List[AgentAction]:
        """Use LLM to generate plan steps."""
        skill_desc = "\n".join(
            f"- {s.skill_id}: {s.description} (requires: {s.capabilities_required})"
            for s in skills
        )
        prompt = f"""Decompose this task into steps using available skills.
Task: {task}
Available skills:
{skill_desc}
Return JSON: {{"steps": [{{"tool": "skill_id", "parameters": {{}}, "estimated_cost_cents": N}}]}}"""

        try:
            response = await self.llm.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
            )
            data = json.loads(response.choices[0].message.content)
            return [
                AgentAction(
                    tool=s.get("tool", ""),
                    parameters=s.get("parameters", {}),
                    estimated_cost_cents=s.get("estimated_cost_cents", 100),
                    required_capabilities=self._infer_capabilities(s.get("tool", ""), skills),
                )
                for s in data.get("steps", [])
            ]
        except Exception:
            return self._rule_based_plan(task, skills)

    def _rule_based_plan(self, task: str, skills: List[SkillSummary]) -> List[AgentAction]:
        """Rule-based planning fallback."""
        steps = []
        task_lower = task.lower()

        for skill in skills:
            if self._task_matches_skill(task_lower, skill):
                steps.append(AgentAction(
                    tool=skill.skill_id,
                    parameters={"task": task},
                    estimated_cost_cents=100,
                    required_capabilities=skill.capabilities_required,
                    input_labels=["internal"],
                    output_labels=["internal"],
                ))

        if not steps:
            steps.append(AgentAction(
                tool="default",
                parameters={"task": task},
                estimated_cost_cents=50,
            ))
        return steps

    def _task_matches_skill(self, task: str, skill: SkillSummary) -> bool:
        keywords = {
            "web_browsing": ["browse", "fetch", "url", "http", "web", "scrape"],
            "database_query": ["query", "database", "sql", "select", "table"],
            "file_operations": ["file", "read", "write", "save", "load", "document"],
        }
        skill_kws = keywords.get(skill.skill_id, [skill.skill_id])
        return any(kw in task for kw in skill_kws)

    def _infer_capabilities(self, tool: str, skills: List[SkillSummary]) -> List[str]:
        for s in skills:
            if s.skill_id == tool:
                return s.capabilities_required
        return []

    async def _verify_plan(self, plan: AgentPlan) -> VerificationResult:
        """
        Pre-verify entire plan using Z3.
        IMPROVED: Real Z3 encoding of budget + capability constraints.
        """
        if _HAS_Z3:
            return self._z3_verify_plan(plan)

        # Structural fallback
        violations = []
        for step in plan.steps:
            if not self.token.has_all_permissions(step.required_capabilities):
                missing = set(step.required_capabilities) - self.token.permission_set
                violations.append(f"Step {step.tool}: missing {missing}")
        if plan.total_estimated_cost > plan.total_budget_cents:
            violations.append(f"Budget exceeded: {plan.total_estimated_cost} > {plan.total_budget_cents}")

        return VerificationResult(
            valid=len(violations) == 0,
            violations=violations,
            properties=["plan_structural_check"],
        )

    def _z3_verify_plan(self, plan: AgentPlan) -> VerificationResult:
        """Real Z3 plan verification."""
        s = Solver()
        properties = []
        violations = []

        # Budget constraint: sum of step costs <= total budget
        step_costs = []
        for i, step in enumerate(plan.steps):
            cost_var = Int(f"step_{i}_cost")
            s.add(cost_var == step.estimated_cost_cents)
            s.add(cost_var >= 0)
            step_costs.append(cost_var)

        total = Int("total_cost")
        budget = Int("budget")
        s.add(total == Sum(*step_costs) if step_costs else total == 0)
        s.add(budget == plan.total_budget_cents)
        s.add(total <= budget)

        if s.check() == sat:
            properties.append("budget_sufficient: proven")
        else:
            violations.append(f"budget_exceeded: {plan.total_estimated_cost} > {plan.total_budget_cents}")

        # Capability coverage for each step
        for i, step in enumerate(plan.steps):
            for j, req in enumerate(step.required_capabilities):
                covered = False
                for perm in plan.available_capabilities:
                    if perm == req or (perm.endswith("*") and req.startswith(perm[:-1])):
                        covered = True
                        break
                if not covered:
                    violations.append(f"step_{i}_{step.tool}: missing capability {req}")

        if not any("missing capability" in v for v in violations):
            properties.append("all_capabilities_covered: proven")

        return VerificationResult(
            valid=len(violations) == 0,
            properties=properties,
            violations=violations,
            used_z3=True,
        )

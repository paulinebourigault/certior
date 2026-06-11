"""
ExecutorAgent - verified plan execution.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from agentsafe.capabilities.tokens import CapabilityToken
from .base import VerifiedAgent, VerificationError, BudgetExceededError, TokenInvalidError
from .actions import AgentPlan, ExecutionResult, StepResult


class ExecutorAgent(VerifiedAgent):
    """Executes verified plans step-by-step with budget tracking."""

    async def execute_plan(self, plan: AgentPlan) -> ExecutionResult:
        results = []
        total_cost = 0

        for step in plan.steps:
            # Verify each step (token validity checked inside verify_action)
            try:
                verification = await self.verify_action(step)
            except TokenInvalidError as exc:
                return ExecutionResult(
                    plan_id=plan.id,
                    step_results=results,
                    total_cost_cents=total_cost,
                    success=False,
                    error=f"Token invalid ({exc.reason}): cannot verify step {step.tool}",
                )
            if not verification.valid:
                return ExecutionResult(
                    plan_id=plan.id,
                    step_results=results,
                    total_cost_cents=total_cost,
                    success=False,
                    error=f"Step {step.tool} verification failed: {verification.violations}",
                )

            # Execute with certificate
            result = await self.execute_action(step, verification.certificate)
            results.append(result)

            if not result.success:
                return ExecutionResult(
                    plan_id=plan.id,
                    step_results=results,
                    total_cost_cents=total_cost,
                    success=False,
                    error=result.error,
                )

            total_cost += result.cost_cents

            # Budget check
            if total_cost > plan.total_budget_cents:
                return ExecutionResult(
                    plan_id=plan.id,
                    step_results=results,
                    total_cost_cents=total_cost,
                    success=False,
                    error="Budget exceeded",
                )

        return ExecutionResult(
            plan_id=plan.id,
            step_results=results,
            total_cost_cents=total_cost,
            certificates=[r.certificate_id for r in results if r.certificate_id],
            success=True,
        )

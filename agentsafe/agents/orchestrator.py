"""
VerifiedOrchestrator - coordinates Planner, Executor, Verifier.
"""
from __future__ import annotations
import time
from typing import Any, Dict, List, Optional, Callable, Awaitable
from dataclasses import dataclass, field

from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.safety.scanner import ContentSafetyPolicy
from agentsafe.skills.loader import VerifiedSkillLoader
from .planner import PlannerAgent
from .executor import ExecutorAgent
from .verifier_agent import VerifierAgent
from .actions import AgentPlan, ExecutionResult


@dataclass
class TaskResult:
    task: str = ""
    output: Any = None
    certificates: List[str] = field(default_factory=list)
    audit_trail: List[Dict] = field(default_factory=list)
    cost_cents: int = 0
    success: bool = True
    error: str = ""
    duration_ms: float = 0.0


class VerifiedOrchestrator:
    """End-to-end verified task execution."""

    def __init__(
        self,
        capability_token: CapabilityToken,
        llm_client: Any = None,
        tools: Optional[Dict[str, Any]] = None,
        skill_loader: Optional[VerifiedSkillLoader] = None,
        content_policy: Optional[ContentSafetyPolicy] = None,
        on_status: Optional[Callable] = None,
    ):
        self.token = capability_token
        self.tools = tools or {}
        self.on_status = on_status

        self.planner = PlannerAgent(
            "planner", capability_token, llm_client, skill_loader,
        )
        self.executor = ExecutorAgent("executor", capability_token, llm_client)
        self.verifier = VerifierAgent(
            "verifier", capability_token, llm_client, content_policy,
        )

        # Register tools with executor
        for name, tool in self.tools.items():
            self.executor.register_tool(name, tool)

    async def execute(self, task: str) -> TaskResult:
        """End-to-end verified task execution."""
        start = time.perf_counter()
        audit = []

        try:
            # Plan
            await self._emit("planning", task)
            audit.append({"phase": "planning", "time": time.time()})
            plan = await self.planner.plan(task)
            audit.append({"phase": "planned", "steps": len(plan.steps)})

            # Execute
            await self._emit("executing", task)
            exec_result = await self.executor.execute_plan(plan)
            audit.append({
                "phase": "executed",
                "success": exec_result.success,
                "cost": exec_result.total_cost_cents,
            })

            if not exec_result.success:
                return TaskResult(
                    task=task, success=False,
                    error=exec_result.error,
                    audit_trail=audit,
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

            # Verify output
            await self._emit("verifying", task)
            output_check = await self.verifier.verify_output(exec_result.output)
            audit.append({
                "phase": "verified",
                "valid": output_check.valid,
            })

            if not output_check.valid:
                return TaskResult(
                    task=task, success=False,
                    error=f"Output verification failed: {output_check.violations}",
                    audit_trail=audit,
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

            await self._emit("complete", task)
            return TaskResult(
                task=task,
                output=output_check.output,
                certificates=exec_result.certificates,
                audit_trail=audit,
                cost_cents=exec_result.total_cost_cents,
                success=True,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        except Exception as e:
            audit.append({"phase": "error", "error": str(e)})
            return TaskResult(
                task=task, success=False, error=str(e),
                audit_trail=audit,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

    async def _emit(self, status: str, task: str):
        if self.on_status:
            if callable(self.on_status):
                result = self.on_status(status, task)
                if hasattr(result, '__await__'):
                    await result

"""
AgenticOrchestrator - production orchestrator using the reactive agent loop.

This replaces the previous plan→execute→verify sequential pipeline with
a reactive LLM agent loop (AgenticExecutor) while maintaining the same
interface expected by ExecutorService and the cloud layer.

The key difference:
  - Old: Planner produces a static plan → Executor runs each step → Verifier checks output
  - New: LLM decides each tool call dynamically → each call is verified before execution →
         final output is safety-scanned

The old VerifiedOrchestrator is preserved for backward compatibility.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.safety.scanner import ContentSafetyPolicy
from agentsafe.safety.approval_gate import ApprovalCallback
from agentsafe.llm.config import LLMConfig
from agentsafe.tools.registry import ToolRegistry
from agentsafe.agents.agentic_executor import AgenticExecutor, AgenticResult

log = logging.getLogger(__name__)


@dataclass
class TaskResult:
    """Result compatible with the cloud ExecutorService."""
    task: str = ""
    output: Any = None
    certificates: List[str] = field(default_factory=list)
    audit_trail: List[Dict] = field(default_factory=list)
    cost_cents: int = 0
    success: bool = True
    error: str = ""
    duration_ms: float = 0.0
    steps: List[Dict] = field(default_factory=list)
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    approved_artifact: Optional[Dict[str, Any]] = None
    release_binding_summary: Optional[Dict[str, Any]] = None


StatusCallback = Callable[[str, str], Any]


class AgenticOrchestrator:
    """
    Orchestrator that uses the reactive AgenticExecutor.

    Drop-in replacement for VerifiedOrchestrator with the same
    ``execute(task) -> TaskResult`` interface.
    """

    def __init__(
        self,
        capability_token: CapabilityToken,
        llm_config: Optional[LLMConfig] = None,
        tool_registry: Optional[ToolRegistry] = None,
        content_policy: Optional[ContentSafetyPolicy] = None,
        on_status: Optional[StatusCallback] = None,
        system_prompt: Optional[str] = None,
        approval_callback: Optional[ApprovalCallback] = None,
        pre_approved_categories: Optional[Set[str]] = None,
        # Legacy compat kwargs (ignored)
        llm_client: Any = None,
        tools: Optional[Dict[str, Any]] = None,
        skill_loader: Any = None,
    ) -> None:
        self.token = capability_token
        self.on_status = on_status

        self._llm_config = llm_config or LLMConfig()
        self._tool_registry = tool_registry
        self._content_policy = content_policy
        self._system_prompt = system_prompt
        self._approval_callback = approval_callback
        self._pre_approved_categories = pre_approved_categories

    async def execute(self, task: str) -> TaskResult:
        """Run the task through the reactive agent loop."""
        start = time.perf_counter()

        if not self._tool_registry:
            from agentsafe.tools import create_default_registry
            self._tool_registry = create_default_registry()

        # Build a status bridge: translate agentic status events into
        # the (status, task) signature the cloud layer expects
        async def _status_bridge(status: str, data: Dict[str, Any]) -> None:
            if self.on_status:
                try:
                    result = self.on_status(status, task)
                    if hasattr(result, "__await__"):
                        await result
                except Exception:
                    pass

        executor = AgenticExecutor(
            llm_config=self._llm_config,
            tool_registry=self._tool_registry,
            capability_token=self.token,
            content_policy=self._content_policy,
            on_status=_status_bridge,
            system_prompt=self._system_prompt,
            approval_callback=self._approval_callback,
            pre_approved_categories=self._pre_approved_categories,
        )

        try:
            result = await executor.run(task)
            return self._to_task_result(result)
        except Exception as exc:
            log.exception("AgenticOrchestrator.execute() failed")
            return TaskResult(
                task=task,
                success=False,
                error=str(exc),
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        finally:
            await executor.close()

    @staticmethod
    def _to_task_result(ar: AgenticResult) -> TaskResult:
        return TaskResult(
            task=ar.task,
            output=ar.output,
            certificates=ar.certificates,
            audit_trail=ar.audit_trail,
            cost_cents=ar.total_cost_cents,
            success=ar.success,
            error=ar.error,
            duration_ms=ar.duration_ms,
            steps=[s.to_dict() for s in ar.steps],
            total_input_tokens=ar.total_input_tokens,
            total_output_tokens=ar.total_output_tokens,
            approved_artifact=ar.approved_artifact,
            release_binding_summary=ar.release_binding_summary,
        )

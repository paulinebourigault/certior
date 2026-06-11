"""
Agent action and plan definitions.
"""
from __future__ import annotations
import hashlib
import json
import uuid
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class AgentAction:
    """A single action an agent wants to perform."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tool: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    required_capabilities: List[str] = field(default_factory=list)
    estimated_cost_cents: int = 0
    input_labels: List[str] = field(default_factory=list)
    output_labels: List[str] = field(default_factory=list)
    content: str = ""

    def to_hash(self) -> str:
        payload = json.dumps({
            "tool": self.tool,
            "parameters": self.parameters,
            "capabilities": sorted(self.required_capabilities),
        }, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class AgentPlan:
    """A plan consisting of multiple steps."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task: str = ""
    steps: List[AgentAction] = field(default_factory=list)
    total_budget_cents: int = 10000
    available_capabilities: List[str] = field(default_factory=list)
    expected_output_labels: List[str] = field(default_factory=list)

    def to_hash(self) -> str:
        step_hashes = [s.to_hash() for s in self.steps]
        payload = json.dumps({"task": self.task, "steps": step_hashes})
        return hashlib.sha256(payload.encode()).hexdigest()

    @property
    def total_estimated_cost(self) -> int:
        return sum(s.estimated_cost_cents for s in self.steps)


@dataclass
class StepResult:
    step_id: str = ""
    success: bool = True
    output: Any = None
    output_labels: List[str] = field(default_factory=list)
    certificate_id: str = ""
    cost_cents: int = 0
    error: str = ""


@dataclass
class ExecutionResult:
    plan_id: str = ""
    step_results: List[StepResult] = field(default_factory=list)
    total_cost_cents: int = 0
    certificates: List[str] = field(default_factory=list)
    success: bool = True
    error: str = ""

    @property
    def output(self) -> Any:
        if self.step_results:
            return self.step_results[-1].output
        return None

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class WorkflowStatus(Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WorkflowStageStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


@dataclass
class WorkflowStage:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    task: str = ""
    compliance_policy: str = "default"
    budget_cents: int = 10000
    stage_role: str = "worker"
    provider: Optional[str] = None
    model: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    upstream_stage_ids: List[str] = field(default_factory=list)
    status: WorkflowStageStatus = WorkflowStageStatus.PENDING
    execution_id: Optional[str] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error: str = ""
    output_summary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "task": self.task,
            "compliance_policy": self.compliance_policy,
            "budget_cents": self.budget_cents,
            "stage_role": self.stage_role,
            "provider": self.provider,
            "model": self.model,
            "permissions": list(self.permissions),
            "upstream_stage_ids": list(self.upstream_stage_ids),
            "status": self.status.value,
            "execution_id": self.execution_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "output_summary": self.output_summary,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WorkflowStage":
        return cls(
            id=data.get("id") or str(uuid.uuid4()),
            name=data.get("name", ""),
            task=data.get("task", ""),
            compliance_policy=data.get("compliance_policy") or "default",
            budget_cents=int(data.get("budget_cents", 10000)),
            stage_role=data.get("stage_role") or "worker",
            provider=data.get("provider"),
            model=data.get("model"),
            permissions=list(data.get("permissions") or []),
            upstream_stage_ids=list(data.get("upstream_stage_ids") or []),
            status=WorkflowStageStatus(data.get("status", WorkflowStageStatus.PENDING.value)),
            execution_id=data.get("execution_id"),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            error=data.get("error", ""),
            output_summary=data.get("output_summary"),
        )


@dataclass
class Workflow:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    user_role: str = "operator"
    name: str = ""
    description: str = ""
    mode: str = "sequential"
    status: WorkflowStatus = WorkflowStatus.QUEUED
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    current_stage_index: int = 0
    error: str = ""
    stages: List[WorkflowStage] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        completed_stage_count = len([
            stage for stage in self.stages if stage.status == WorkflowStageStatus.COMPLETED
        ])
        return {
            "id": self.id,
            "user_id": self.user_id,
            "user_role": self.user_role,
            "name": self.name,
            "description": self.description,
            "mode": self.mode,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "current_stage_index": self.current_stage_index,
            "error": self.error,
            "stage_count": len(self.stages),
            "completed_stage_count": completed_stage_count,
            "stages": [stage.to_dict() for stage in self.stages],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Workflow":
        return cls(
            id=data.get("id") or str(uuid.uuid4()),
            user_id=data.get("user_id", ""),
            user_role=data.get("user_role") or "operator",
            name=data.get("name", ""),
            description=data.get("description", ""),
            mode=data.get("mode") or "sequential",
            status=WorkflowStatus(data.get("status", WorkflowStatus.QUEUED.value)),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
            completed_at=data.get("completed_at"),
            current_stage_index=int(data.get("current_stage_index", 0)),
            error=data.get("error", ""),
            stages=[WorkflowStage.from_dict(stage) for stage in data.get("stages") or []],
        )


class WorkflowStore:
    def __init__(self):
        self._workflows: Dict[str, Workflow] = {}

    async def create(self, workflow: Workflow) -> Workflow:
        self._workflows[workflow.id] = workflow
        return workflow

    async def get(self, workflow_id: str) -> Optional[Workflow]:
        return self._workflows.get(workflow_id)

    async def update(self, workflow: Workflow) -> Workflow:
        workflow.updated_at = time.time()
        self._workflows[workflow.id] = workflow
        return workflow

    async def list_by_user(
        self,
        user_id: str,
        status: Optional[WorkflowStatus] = None,
        limit: int = 20,
    ) -> List[Workflow]:
        results = [workflow for workflow in self._workflows.values() if workflow.user_id == user_id]
        if status:
            results = [workflow for workflow in results if workflow.status == status]
        results.sort(key=lambda workflow: workflow.created_at, reverse=True)
        return results[:limit]

    async def delete(self, workflow_id: str) -> bool:
        return self._workflows.pop(workflow_id, None) is not None
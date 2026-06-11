from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.cloud import Workflow, WorkflowStage, WorkflowStageStatus, WorkflowStatus
from agentsafe.cloud.event_bus import Event
from agentsafe.cloud.state_store import ExecutionStatus
from agentsafe.compliance import ComplianceExporter, CompliancePresets, PermissionResolver, PermissionResolution, VerificationProfileResolver
from .auth import User, get_current_user, UserRole

router = APIRouter(prefix="/api/v1", tags=["workflows"])

_resolver = PermissionResolver()
_profile_resolver = VerificationProfileResolver()


class WorkflowStageRequest(BaseModel):
    id: str = Field("", description="Optional stable workflow stage identifier for cross-stage references")
    name: str = Field(..., min_length=1, max_length=120)
    task: str = Field(..., min_length=1)
    compliance_policy: str = Field("default")
    budget_cents: int = Field(1500, ge=100, le=1_000_000)
    stage_role: str = Field("worker", description="e.g. intake, reviewer, release, worker")
    provider: Optional[str] = Field(None, pattern="^(anthropic|openai)$")
    model: Optional[str] = None
    api_key: Optional[str] = Field(None, min_length=8)
    permissions: List[str] = Field(default_factory=list)
    upstream_stage_ids: List[str] = Field(default_factory=list)


class WorkflowRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=160)
    description: str = Field("", max_length=400)
    stages: List[WorkflowStageRequest] = Field(..., min_length=1, max_length=12)


class WorkflowStageResponse(BaseModel):
    id: str
    name: str
    task: str
    compliance_policy: str
    budget_cents: int
    stage_role: str
    provider: Optional[str] = None
    model: Optional[str] = None
    permissions: List[str]
    upstream_stage_ids: List[str]
    status: str
    execution_id: Optional[str] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error: str = ""
    output_summary: Optional[str] = None


class WorkflowResponse(BaseModel):
    id: str
    user_id: str
    user_role: str
    name: str
    description: str
    mode: str
    status: str
    created_at: float
    updated_at: float
    completed_at: Optional[float] = None
    current_stage_index: int
    error: str = ""
    stage_count: int
    completed_stage_count: int
    stages: List[WorkflowStageResponse]


class WorkflowCancelResponse(BaseModel):
    workflow_id: str
    status: str


class WorkflowExportStageResponse(BaseModel):
    stage: WorkflowStageResponse
    execution: Optional[Dict[str, Any]] = None
    compliance_package: Optional[Dict[str, Any]] = None


class WorkflowExportResponse(BaseModel):
    workflow: WorkflowResponse
    exported_at: float
    stages: List[WorkflowExportStageResponse]


def _workflow_to_response(workflow: Workflow) -> WorkflowResponse:
    return WorkflowResponse(**workflow.to_dict())


def _resolve_upstream_execution_ids(workflow: Workflow, stage: WorkflowStage) -> List[str]:
    if stage.upstream_stage_ids:
        upstream = []
        for upstream_stage_id in stage.upstream_stage_ids:
            match = next((candidate for candidate in workflow.stages if candidate.id == upstream_stage_id), None)
            if match and match.execution_id:
                upstream.append(match.execution_id)
        return upstream

    if workflow.current_stage_index == 0:
        return []

    previous_stage = workflow.stages[workflow.current_stage_index - 1]
    return [previous_stage.execution_id] if previous_stage.execution_id else []


def _summarize_output(execution_output: Optional[str]) -> Optional[str]:
    if not execution_output:
        return None
    collapsed = " ".join(execution_output.split())
    return collapsed[:180] + ("…" if len(collapsed) > 180 else "")


def _mark_workflow_cancelled(workflow: Workflow) -> Workflow:
    workflow.status = WorkflowStatus.CANCELLED
    workflow.completed_at = workflow.completed_at or time.time()
    workflow.error = workflow.error or "Workflow cancelled by operator"
    for stage in workflow.stages:
        if stage.status in (WorkflowStageStatus.PENDING, WorkflowStageStatus.RUNNING):
            stage.status = WorkflowStageStatus.CANCELLED
            stage.completed_at = stage.completed_at or workflow.completed_at
            stage.error = stage.error or "Workflow cancelled by operator"
    return workflow


async def _execute_workflow(app_ref, workflow_id: str) -> Dict[str, Any]:
    workflow_store = app_ref.state.workflow_store
    executor = app_ref.state.executor
    event_bus = app_ref.state.event_bus
    workflow_runtime_llm_credentials = app_ref.state.workflow_runtime_llm_credentials

    workflow = await workflow_store.get(workflow_id)
    if not workflow:
        raise ValueError(f"Workflow not found: {workflow_id}")

    workflow.status = WorkflowStatus.RUNNING
    workflow.error = ""
    await workflow_store.update(workflow)
    await event_bus.emit(Event(type="workflow.started", execution_id=workflow.id, data={"name": workflow.name}))

    for index, stage in enumerate(workflow.stages):
        latest = await workflow_store.get(workflow.id)
        if latest and latest.status == WorkflowStatus.CANCELLED:
            return {"workflow_id": workflow.id, "status": WorkflowStatus.CANCELLED.value}
        if latest:
            workflow = latest
            stage = workflow.stages[index]

        workflow.current_stage_index = index
        stage.status = WorkflowStageStatus.RUNNING
        stage.started_at = time.time()
        stage.error = ""
        await workflow_store.update(workflow)
        await event_bus.emit(
            Event(
                type="workflow.stage.started",
                execution_id=workflow.id,
                data={"stage_id": stage.id, "stage_name": stage.name, "index": index},
            )
        )

        try:
            config = CompliancePresets.get(stage.compliance_policy or "default")
            upstream_execution_ids = _resolve_upstream_execution_ids(workflow, stage)
            profile = _profile_resolver.resolve(
                policy=config,
                task=stage.task,
                task_class=None,
                stage_role=stage.stage_role,
                stage_id=stage.id,
                upstream_execution_ids=upstream_execution_ids,
            )
            profile_dict = profile.compose(config)

            if profile.stage_role == "release" and not upstream_execution_ids:
                raise PermissionError(
                    "Release-stage workflow steps require an upstream execution so Certior can enforce review-before-release constraints"
                )

            resolution: PermissionResolution = _resolver.resolve(
                requested_permissions=stage.permissions or None,
                policy=config,
                user_role=workflow.user_role,
                profile_ceiling=profile_dict.get("permission_ceiling"),
            )
            if resolution.is_empty:
                raise PermissionError(
                    f"No effective permissions remain for stage '{stage.name}' after applying '{stage.compliance_policy}'"
                )

            token = CapabilityToken(
                agent_id=workflow.user_id,
                permissions=resolution.effective_permissions,
                budget_cents=stage.budget_cents,
                budget_remaining_cents=stage.budget_cents,
                metadata={
                    "verification_profile": profile_dict,
                    "compliance_policy": stage.compliance_policy or "default",
                    "workflow_id": workflow.id,
                    "workflow_stage_id": stage.id,
                    "workflow_stage_name": stage.name,
                },
            )

            execution = await executor.submit(
                task=stage.task,
                user_id=workflow.user_id,
                token=token,
                llm_provider=stage.provider,
                llm_model=stage.model,
                llm_api_key=((workflow_runtime_llm_credentials.get(workflow.id) or {}).get(stage.id) or {}).get("api_key"),
                verification_profile=profile_dict,
            )
            stage.execution_id = execution.id
            await workflow_store.update(workflow)

            executed = await executor.execute(execution.id)
            if executed.status != ExecutionStatus.COMPLETED:
                raise RuntimeError(executed.error or f"Stage '{stage.name}' failed")

            latest = await workflow_store.get(workflow.id)
            if latest:
                workflow = latest
                stage = workflow.stages[index]

            if workflow.status == WorkflowStatus.CANCELLED:
                if stage.status != WorkflowStageStatus.COMPLETED:
                    stage.status = WorkflowStageStatus.CANCELLED
                    stage.completed_at = stage.completed_at or time.time()
                    stage.error = stage.error or "Workflow cancelled by operator"
                workflow.completed_at = workflow.completed_at or time.time()
                await workflow_store.update(workflow)
                await event_bus.emit(Event(type="workflow.cancelled", execution_id=workflow.id, data={"stage_id": stage.id}))
                return {"workflow_id": workflow.id, "status": workflow.status.value}

            stage.status = WorkflowStageStatus.COMPLETED
            stage.completed_at = time.time()
            stage.output_summary = _summarize_output((executed.results or {}).get("output") if isinstance(executed.results, dict) else None)
            await workflow_store.update(workflow)
            await event_bus.emit(
                Event(
                    type="workflow.stage.completed",
                    execution_id=workflow.id,
                    data={"stage_id": stage.id, "stage_name": stage.name, "execution_id": execution.id},
                )
            )
        except Exception as exc:
            stage.status = WorkflowStageStatus.FAILED
            stage.completed_at = time.time()
            stage.error = str(exc)
            workflow.status = WorkflowStatus.FAILED
            workflow.error = str(exc)
            workflow.completed_at = time.time()
            await workflow_store.update(workflow)
            await event_bus.emit(
                Event(
                    type="workflow.failed",
                    execution_id=workflow.id,
                    data={"stage_id": stage.id, "stage_name": stage.name, "error": stage.error},
                )
            )
            workflow_runtime_llm_credentials.pop(workflow.id, None)
            return {"workflow_id": workflow.id, "status": workflow.status.value}

    workflow.status = WorkflowStatus.COMPLETED
    workflow.completed_at = time.time()
    await workflow_store.update(workflow)
    await event_bus.emit(Event(type="workflow.completed", execution_id=workflow.id, data={"stage_count": len(workflow.stages)}))
    workflow_runtime_llm_credentials.pop(workflow.id, None)
    return {"workflow_id": workflow.id, "status": workflow.status.value}


@router.post("/workflows", response_model=WorkflowResponse, status_code=201)
async def create_workflow(
    body: WorkflowRequest,
    request: Request,
    user: User = Depends(get_current_user),
):
    if user.role == UserRole.VIEWER:
        raise HTTPException(status_code=403, detail="Viewer role cannot create workflows")

    workflow_store = request.app.state.workflow_store
    stages = [
        WorkflowStage(
            id=stage.id or str(uuid.uuid4()),
            name=stage.name,
            task=stage.task,
            compliance_policy=stage.compliance_policy or "default",
            budget_cents=stage.budget_cents,
            stage_role=stage.stage_role,
            provider=stage.provider,
            model=stage.model,
            permissions=list(stage.permissions),
            upstream_stage_ids=list(stage.upstream_stage_ids),
        )
        for stage in body.stages
    ]
    workflow = Workflow(
        user_id=user.id,
        user_role=user.role.value,
        name=body.name,
        description=body.description,
        stages=stages,
    )
    await workflow_store.create(workflow)
    request.app.state.workflow_runtime_llm_credentials[workflow.id] = {
        stored_stage.id: {"api_key": body.stages[index].api_key or ""}
        for index, stored_stage in enumerate(workflow.stages)
        if body.stages[index].api_key
    }
    await request.app.state.event_bus.emit(
        Event(type="workflow.created", execution_id=workflow.id, data={"name": workflow.name, "stage_count": len(stages)})
    )

    queue = request.app.state.queue
    app_ref = request.app

    async def _execute_workflow_handler(wid: str):
        return await _execute_workflow(app_ref, wid)

    if "execute_workflow" not in getattr(queue, "_handlers", {}):
        queue.register("execute_workflow", _execute_workflow_handler)

    await queue.enqueue("execute_workflow", workflow.id)
    return _workflow_to_response(workflow)


@router.get("/workflows", response_model=List[WorkflowResponse])
async def list_workflows(
    request: Request,
    user: User = Depends(get_current_user),
    status: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
):
    workflow_store = request.app.state.workflow_store
    status_enum = None
    if status:
        try:
            status_enum = WorkflowStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid workflow status: {status}")
    workflows = await workflow_store.list_by_user(user.id, status=status_enum, limit=limit)
    return [_workflow_to_response(workflow) for workflow in workflows]


@router.get("/workflows/{workflow_id}", response_model=WorkflowResponse)
async def get_workflow(
    workflow_id: str,
    request: Request,
    user: User = Depends(get_current_user),
):
    workflow_store = request.app.state.workflow_store
    workflow = await workflow_store.get(workflow_id)
    if not workflow or workflow.user_id != user.id:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return _workflow_to_response(workflow)


@router.delete("/workflows/{workflow_id}", response_model=WorkflowCancelResponse)
async def cancel_workflow(
    workflow_id: str,
    request: Request,
    user: User = Depends(get_current_user),
):
    workflow_store = request.app.state.workflow_store
    workflow = await workflow_store.get(workflow_id)
    if not workflow or workflow.user_id != user.id:
        raise HTTPException(status_code=404, detail="Workflow not found")

    if workflow.status in (WorkflowStatus.COMPLETED, WorkflowStatus.FAILED, WorkflowStatus.CANCELLED):
        raise HTTPException(status_code=409, detail="Workflow is already terminal")

    workflow = _mark_workflow_cancelled(workflow)
    await workflow_store.update(workflow)
    request.app.state.workflow_runtime_llm_credentials.pop(workflow.id, None)
    await request.app.state.event_bus.emit(
        Event(type="workflow.cancelled", execution_id=workflow.id, data={"name": workflow.name})
    )
    return WorkflowCancelResponse(workflow_id=workflow.id, status=workflow.status.value)


@router.get("/workflows/{workflow_id}/export", response_model=WorkflowExportResponse)
async def export_workflow(
    workflow_id: str,
    request: Request,
    user: User = Depends(get_current_user),
):
    workflow_store = request.app.state.workflow_store
    state_store = request.app.state.state_store
    workflow = await workflow_store.get(workflow_id)
    if not workflow or workflow.user_id != user.id:
        raise HTTPException(status_code=404, detail="Workflow not found")

    stage_exports: List[WorkflowExportStageResponse] = []
    for stage in workflow.stages:
        execution_payload: Optional[Dict[str, Any]] = None
        compliance_payload: Optional[Dict[str, Any]] = None
        if stage.execution_id:
            execution = await state_store.get(stage.execution_id)
            if execution and execution.user_id == user.id:
                execution_payload = execution.to_dict()
                if execution.status == ExecutionStatus.COMPLETED:
                    config = CompliancePresets.get(stage.compliance_policy or execution_payload.get("compliance_policy") or "default")
                    compliance_payload = ComplianceExporter(config).export(execution).to_dict()
        stage_exports.append(
            WorkflowExportStageResponse(
                stage=WorkflowStageResponse(**stage.to_dict()),
                execution=execution_payload,
                compliance_package=compliance_payload,
            )
        )

    payload = WorkflowExportResponse(
        workflow=_workflow_to_response(workflow),
        exported_at=time.time(),
        stages=stage_exports,
    )
    return JSONResponse(
        content=payload.model_dump(),
        headers={"Content-Disposition": f'attachment; filename="workflow-{workflow.id[:8]}.json"'},
    )
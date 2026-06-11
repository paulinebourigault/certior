"""
GET /api/v1/executions/{id}  - execution status and results.
GET /api/v1/executions       - list user executions.
DELETE /api/v1/executions/{id} - cancel a queued execution.
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Request, HTTPException, Query, Depends

from .auth import get_current_user, User

router = APIRouter(prefix="/api/v1", tags=["executions"])


@router.get("/executions/{execution_id}")
async def get_execution(
    execution_id: str,
    request: Request,
    user: User = Depends(get_current_user),
):
    """Retrieve execution status and results."""
    store = request.app.state.state_store
    execution = await store.get(execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    return execution.to_dict()


@router.get("/executions")
async def list_executions(
    request: Request,
    user: User = Depends(get_current_user),
    status: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
):
    """List executions for the authenticated user, optionally filtered by status."""
    from agentsafe.cloud.state_store import ExecutionStatus

    store = request.app.state.state_store
    status_enum = None
    if status:
        try:
            status_enum = ExecutionStatus(status)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status: {status}. Valid: {[s.value for s in ExecutionStatus]}",
            )

    results = await store.list_by_user(user.id, status=status_enum, limit=limit)
    return [e.to_dict() for e in results]


@router.delete("/executions/{execution_id}")
async def cancel_execution(
    execution_id: str,
    request: Request,
    user: User = Depends(get_current_user),
):
    """Cancel a queued or planning execution."""
    executor = request.app.state.executor
    cancelled = await executor.cancel(execution_id)
    if not cancelled:
        raise HTTPException(
            status_code=409,
            detail="Execution cannot be cancelled (already running or completed)",
        )
    return {"execution_id": execution_id, "status": "cancelled"}

"""
POST /api/v1/tasks - submit a task for verified execution.

Security: user-supplied permissions are intersected with the compliance
policy ceiling via ``PermissionResolver``.  This prevents BYPASS #1
(arbitrary permission escalation through the API).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel, Field

from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.compliance import (
    CompliancePresets,
    PermissionResolver,
    PermissionResolution,
    VerificationProfileResolver,
)
from .auth import get_current_user, User, UserRole

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["tasks"])

# Singleton resolver - stateless, safe to share
_resolver = PermissionResolver()
_profile_resolver = VerificationProfileResolver()


# ── Request / Response models ─────────────────────────────────────────

class VerificationProfileRequest(BaseModel):
    task_class: Optional[str] = Field(None, description="Task class override for verification composition")
    stage_role: Optional[str] = Field(None, description="Stage role: intake, reviewer, release, single_agent")
    stage_id: str = Field("", description="Optional workflow stage identifier")
    upstream_execution_ids: List[str] = Field(
        default_factory=list,
        description="Prior stage executions required by this stage",
    )


class TaskRequest(BaseModel):
    task: str = Field(..., min_length=1, description="Task description")
    compliance_policy: Optional[str] = Field(
        None, description="Compliance preset: hipaa, sox, legal, default"
    )
    budget_cents: int = Field(10000, ge=100, le=1_000_000)
    webhook_url: Optional[str] = None
    permissions: Optional[List[str]] = Field(
        None,
        description=(
            "Requested permissions.  If supplied, these are intersected "
            "with the compliance policy ceiling - not used verbatim.  "
            "Omit to use the policy's default permissions."
        ),
    )
    provider: Optional[str] = Field(
        None,
        pattern="^(anthropic|openai)$",
        description=(
            "LLM provider override for this task.  "
            "If omitted, the server's default provider is used."
        ),
    )
    model: Optional[str] = Field(
        None,
        description=(
            "Model override (e.g. 'gpt-4o-mini', 'claude-haiku-4-5-20251001').  "
            "If omitted, the provider's default model is used."
        ),
    )
    api_key: Optional[str] = Field(
        None,
        min_length=8,
        description=(
            "Optional per-request provider API key. When supplied, Certior uses it for this run only "
            "and keeps it in memory rather than persisting it to execution history."
        ),
    )
    verification_profile: Optional[VerificationProfileRequest] = Field(
        None,
        description=(
            "Optional task-adaptive verification profile. When omitted, Certior infers a profile "
            "from the task text and compliance regime."
        ),
    )
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "task": (
                        "Summarize a patient encounter into a discharge summary. "
                        "Redact all direct identifiers. Apply minimum-necessary principle."
                    ),
                    "compliance_policy": "hipaa",
                    "budget_cents": 2000,
                    "provider": "openai",
                    "model": "gpt-4o",
                    "verification_profile": {
                        "task_class": "clinical_intake",
                        "stage_role": "intake",
                        "stage_id": "intake",
                    },
                },
                {
                    "task": (
                        "Review clinical intake note for residual PHI, privilege leakage, "
                        "and minimum-necessary compliance. Return structured GO/NO-GO."
                    ),
                    "compliance_policy": "legal_privilege",
                    "budget_cents": 1200,
                    "provider": "openai",
                    "model": "gpt-4o",
                    "verification_profile": {
                        "task_class": "privacy_review",
                        "stage_role": "reviewer",
                        "stage_id": "privacy-review",
                        "upstream_execution_ids": ["intake-exec-id"],
                    },
                },
            ]
        }
    }


class TaskResponse(BaseModel):
    execution_id: str
    status: str
    websocket_url: str
    verification_profile: Optional[Dict[str, Any]] = Field(
        None,
        description="Composed task-specific verification profile applied to this execution.",
    )
    permission_resolution: Optional[Dict[str, Any]] = Field(
        None,
        description=(
            "Included when user-supplied permissions were modified by "
            "the compliance policy.  Shows what was granted vs denied."
        ),
    )

class PermissionDenial(BaseModel):
    permission: str
    reason: str
    detail: str


class ErrorResponse(BaseModel):
    detail: Any


# ── Route ─────────────────────────────────────────────────────────────

@router.post(
    "/tasks",
    response_model=TaskResponse,
    status_code=201,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid compliance policy or request"},
        401: {"model": ErrorResponse, "description": "Missing or invalid API key"},
        403: {
            "model": ErrorResponse,
            "description": "Request denied by role/policy permission ceiling",
            "content": {
                "application/json": {
                    "example": {
                        "detail": {
                            "message": "No effective permissions after applying 'hipaa' compliance policy",
                            "denied": [
                                {
                                    "permission": "network:http:read",
                                    "reason": "exceeds_policy_ceiling",
                                    "detail": "Permission is not within the HIPAA policy allowed set",
                                }
                            ],
                        }
                    }
                }
            },
        },
        422: {"model": ErrorResponse, "description": "Validation error"},
    },
    openapi_extra={
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "single_agent_hipaa": {
                            "summary": "Single-agent HIPAA clinical summarization",
                            "value": {
                                "task": (
                                    "Summarize a patient encounter into a discharge summary. "
                                    "Redact all direct identifiers. Apply minimum-necessary principle."
                                ),
                                "compliance_policy": "hipaa",
                                "budget_cents": 2000,
                                "provider": "openai",
                                "model": "gpt-4o",
                            },
                        },
                        "multi_agent_stage_reviewer": {
                            "summary": "Multi-agent privacy reviewer stage",
                            "value": {
                                "task": (
                                    "Review clinical intake note for residual PHI, "
                                    "privilege leakage, and minimum-necessary compliance. "
                                    "Return structured GO/NO-GO assessment."
                                ),
                                "compliance_policy": "legal_privilege",
                                "budget_cents": 1200,
                                "provider": "openai",
                                "model": "gpt-4o",
                            },
                        },
                    }
                }
            }
        }
    },
)
async def create_task(
    body: TaskRequest,
    request: Request,
    user: User = Depends(get_current_user),
):
    """
    Submit a task for verified execution.

    Permissions are resolved against the compliance policy:
    - **No permissions supplied**: policy defaults are used.
    - **Permissions supplied**: intersected with the policy ceiling;
      forbidden permissions are stripped; role restrictions apply.
    - **VIEWER role**: rejected (cannot create tasks).
    - **Production pattern**: submit one request per specialist agent stage
      (e.g., intake + reviewer), then track and merge via execution IDs.
    """
    executor = request.app.state.executor

    # ── Resolve compliance policy ───────────────────────────────
    policy_name = body.compliance_policy or "default"
    try:
        config = CompliancePresets.get(policy_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    profile_request = body.verification_profile or VerificationProfileRequest()
    profile = _profile_resolver.resolve(
        policy=config,
        task=body.task,
        task_class=profile_request.task_class,
        stage_role=profile_request.stage_role,
        stage_id=profile_request.stage_id,
        upstream_execution_ids=profile_request.upstream_execution_ids,
    )
    profile_dict = profile.compose(config)

    if profile.stage_role == "release" and not profile_request.upstream_execution_ids:
        raise HTTPException(
            status_code=400,
            detail=(
                "Release-stage tasks require upstream_execution_ids so the runtime can enforce "
                "review-before-release temporal constraints"
            ),
        )

    # ── Resolve permissions (BYPASS #1 fix) ─────────────────────
    try:
        resolution: PermissionResolution = _resolver.resolve(
            requested_permissions=body.permissions,
            policy=config,
            user_role=user.role.value,
            profile_ceiling=profile_dict.get("permission_ceiling"),
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    # If every requested permission was denied → reject the task
    if resolution.is_empty:
        denied_details = [d.to_dict() for d in resolution.denied]
        raise HTTPException(
            status_code=403,
            detail={
                "message": (
                    "No effective permissions after applying "
                    f"'{policy_name}' compliance policy"
                ),
                "denied": denied_details,
            },
        )

    # Log for audit
    if resolution.has_denials:
        log.warning(
            "Permission denials for user=%s policy=%s: %s",
            user.id,
            policy_name,
            [d.to_dict() for d in resolution.denied],
        )

    # ── Build token with resolved permissions ───────────────────
    token = CapabilityToken(
        agent_id=user.id,
        permissions=resolution.effective_permissions,
        budget_cents=body.budget_cents,
        budget_remaining_cents=body.budget_cents,
        metadata={
            "verification_profile": profile_dict,
            "compliance_policy": policy_name,
        },
    )

    # ── Submit execution ────────────────────────────────────────
    execution = await executor.submit(
        task=body.task,
        user_id=user.id,
        token=token,
        webhook_url=body.webhook_url or "",
        llm_provider=body.provider,
        llm_model=body.model,
        llm_api_key=body.api_key,
        verification_profile=profile_dict,
    )

    # Kick off async execution
    queue = request.app.state.queue
    
    # The handler fetches the executor from the app state at call time
    # to avoid capturing a stale request object.
    app_ref = request.app
    
    async def _execute_verified_task_handler(eid: str):
        # Always resolve fresh executor from app state
        exc = app_ref.state.executor
        return await exc.execute(eid)

    # Register only if not present (idempotent)
    if "execute_verified_task" not in getattr(queue, "_handlers", {}):
        queue.register("execute_verified_task", _execute_verified_task_handler)

    await queue.enqueue("execute_verified_task", execution.id)

    base = str(request.base_url).rstrip("/")

    # Include resolution details if permissions were narrowed
    resolution_info = None
    if not resolution.used_defaults and resolution.has_denials:
        resolution_info = resolution.to_dict()

    return TaskResponse(
        execution_id=execution.id,
        status="queued",
        websocket_url=f"{base.replace('http', 'ws')}/ws/executions/{execution.id}",
        verification_profile=profile_dict,
        permission_resolution=resolution_info,
    )

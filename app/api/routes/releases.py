"""Release decision API endpoints."""
from __future__ import annotations
import json
import os
import logging
from fastapi import APIRouter, HTTPException, Request, Query, Depends
from pydantic import BaseModel, Field
import asyncpg

from agentsafe.verification_graph.tools import VerificationGraphTools
from .auth import require_role, UserRole, User

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/releases", tags=["releases"])


class ReleaseDecisionQuery(BaseModel):
    repo_root: str = Field(..., description="Repository root or git origin url")
    commit_sha: str | None = None
    release_artifact_digest: str | None = None


class ExplanationItem(BaseModel):
    """
    Individual policy evaluation result. Part of the v1 contract.
    New fields may be added. Existing fields will not be removed or renamed.
    """
    policy: str = Field(description="Policy code/identifier")
    requirement: str = Field(description="Human-readable policy condition")
    satisfied: bool = Field(description="Whether the release satisfies this policy")
    evidence_id: str | None = Field(default=None, description="Graph evidence ID, if applicable")
    remediation: str | None = Field(default=None, description="Suggested remediation if failed")

class BlockerItem(BaseModel):
    """
    A hard blocker preventing release. Part of the v1 contract.
    """
    component: str = Field(description="Subsystem or manifest item owning the failure")
    reason: str = Field(description="Reason for failure")
    remediation_suggestion: str | None = Field(default=None, description="How to fix")

class CheckRunSummary(BaseModel):
    workflow: str
    check_run_name: str
    conclusion: str
    url: str | None = None

class ComponentProvenance(BaseModel):
    name: str
    version: str
    source_commit: str

class ProvenanceSummary(BaseModel):
    components: list[ComponentProvenance] = Field(default_factory=list)
    checks: list[CheckRunSummary] = Field(default_factory=list)


class InventoryChange(BaseModel):
    current_count: int
    baseline_count: int
    delta: int
    added: list[str]
    removed: list[str]

class BaselineComparison(BaseModel):
    has_baseline: bool
    baseline_commit_sha: str | None = None
    components: InventoryChange | None = None
    verified_properties: InventoryChange | None = None


class IngestIssue(BaseModel):
    health_state: str
    severity: str
    code: str
    detail: str
    component_name: str | None = None
    property_key: str | None = None

class EvidenceFreshness(BaseModel):
    state: str
    recent_timestamp: str | None = None
    property_key: str | None = None

class HealthStatusResponse(BaseModel):
    repo_root: str
    commit_sha: str | None = None
    ingest_status: str
    ingest_issues: list[IngestIssue] = Field(default_factory=list)
    freshness_summary: dict = Field(default_factory=dict)
    

class IngestIssue(BaseModel):
    health_state: str
    severity: str
    code: str
    detail: str
    component_name: str | None = None
    property_key: str | None = None

class EvidenceFreshness(BaseModel):
    state: str
    recent_timestamp: str | None = None
    property_key: str | None = None

class HealthStatusResponse(BaseModel):
    repo_root: str
    commit_sha: str | None = None
    ingest_status: str
    ingest_issues: list[IngestIssue] = Field(default_factory=list)
    freshness_summary: dict = Field(default_factory=dict)
    
class ReleaseDecisionResponse(BaseModel):
    """
    The canonical v1 release decision contract.
    
    COMPATIBILITY GUARANTEES:
    - This schema guarantees response shape stability. Existing fields, types, and constraints will not break.
    - Additive changes (new optional fields) may occur in minor versions.
    - 'decision' will reliably return "SHIP" or "NO_SHIP". 
    - Deprecations will be clearly announced with a 6-month window via v2 routing.
    """
    decision: str = Field(description="'SHIP' or 'NO_SHIP'")
    repo_root: str = Field(description="Target repository root")
    commit_sha: str | None = Field(default=None, description="Target commit")
    release_artifact_digest: str | None = Field(default=None, description="Optional release artifact")
    blockers: list[BlockerItem] = Field(default_factory=list)
    explanation: list[ExplanationItem] = Field(default_factory=list)
    provenance: ProvenanceSummary = Field(default_factory=ProvenanceSummary)
    baseline: BaselineComparison | None = None


def _get_tools() -> VerificationGraphTools:
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not configured")
    return VerificationGraphTools(dsn)




class PromotionRecord(BaseModel):
    id: str
    snapshot_id: str
    status: str
    release_label: str | None = None
    created_at: float
    metadata: dict | None = None
    commit_sha: str | None = None

class PromotionHistoryResponse(BaseModel):
    promotions: list[PromotionRecord]
class PromotionRequest(BaseModel):
    repo_root: str = Field(..., description="Repository root or git org url")
    operator_identity: str = Field(..., description="Email, badge ID, or username of the reviewer")
    reason: str = Field(..., description="Explanation for approval or rejection")
    bound_artifact_digest: str = Field(..., description="SHA256 representation of the release artifact")
    commit_sha: str | None = Field(None, description="Optional specific commit SHA")
    status: str = Field("attested", description="'attested' for approval, 'rejected' for halt, 'revoked' for reversal")
    release_label: str | None = Field(None, description="Tag, e.g. v1.2.3")

class PromotionResponse(BaseModel):
    tool: str
    snapshot: dict
    promotion: dict | None


def _decode_promotion_metadata(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


async def _list_promotions_fast(repo_root: str, commit_sha: str | None = None, limit: int = 50) -> list[PromotionRecord]:
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not configured")

    clauses = ["r.root_path = $1"]
    params: list[object] = [repo_root]
    if commit_sha:
        params.append(commit_sha)
        clauses.append(f"c.commit_sha = ${len(params)}")

    safe_limit = max(1, min(limit, 100))
    where_clause = " AND ".join(clauses)
    conn = await asyncpg.connect(dsn, timeout=5)
    try:
        rows = await conn.fetch(
            f"""SELECT sp.id, sp.snapshot_id, sp.status, sp.release_label,
                       sp.created_at, sp.metadata, c.commit_sha AS commit_sha
                FROM snapshot_promotions sp
                JOIN ingest_snapshots s ON s.id = sp.snapshot_id
                JOIN repos r ON r.id = s.repo_id
                JOIN repo_commits c ON c.id = s.commit_id
                WHERE {where_clause}
                ORDER BY sp.created_at DESC
                LIMIT {safe_limit}""",
            *params,
            timeout=5,
        )
    finally:
        await conn.close(timeout=2)

    return [
        PromotionRecord(
            id=row["id"],
            snapshot_id=row["snapshot_id"],
            status=row["status"],
            release_label=row["release_label"],
            created_at=row["created_at"],
            metadata=_decode_promotion_metadata(row["metadata"]),
            commit_sha=row["commit_sha"],
        )
        for row in rows
    ]

@router.get("/decision", response_model=ReleaseDecisionResponse, dependencies=[Depends(require_role(UserRole.ADMIN, UserRole.AUDITOR, UserRole.VIEWER, UserRole.OPERATOR, UserRole.APPROVER, UserRole.POLICY_AUTHOR))])
async def get_release_decision(
    repo_root: str = Query(..., description="Repository root to query"),
    commit_sha: str | None = Query(None, description="Optional specific commit SHA"),
    release_artifact_digest: str | None = Query(None, description="Optional release artifact digest")
):
    """
    Get the canonical release decision for a repository/commit.
    Returns whether the release can ship, along with explanations and blockers.
    """
    tools = _get_tools()
    
    try:
        raw_result = await tools.release_decision(
            repo_root=repo_root,
            commit_sha=commit_sha,
            release_artifact_digest=release_artifact_digest
        )
    except Exception as e:
        log.exception("Graph query failed")
        import traceback
        with open("/tmp/certior-error.log", "w") as _f:
            _f.write(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Query failed: {e}")

    decision_dict = raw_result.get("decision", {})
    decision_state = "SHIP" if decision_dict.get("decision_status") == "attested" else "NO_SHIP"
    
    blockers = []
    explanations = []
    
    for item in decision_dict.get("remediation_items", []):
        if item.get("severity") == "blocking":
            blockers.append(BlockerItem(
                component=item.get("owner_subsystem", "Unknown"), 
                reason=item.get("message", "Unknown Blocker"),
                remediation_suggestion=", ".join(item.get("remediation_steps", []))
            ))
        explanations.append(ExplanationItem(
            policy=item.get("code", "Unknown"),
            requirement=item.get("message", "Unknown"),
            satisfied=item.get("severity") not in {"blocking", "degraded"},
            remediation=", ".join(item.get("remediation_steps", []))
        ))
         
    prov_raw = raw_result.get("provenance", {})
    components = [
        ComponentProvenance(name=c.get("name", "Unknown"), version=c.get("version", ""), source_commit=c.get("source_commit", ""))
        for c in prov_raw.get("components", [])
    ]
    checks = [
        CheckRunSummary(workflow=ch.get("workflow", ""), check_run_name=ch.get("check_run_name", ""), conclusion=ch.get("conclusion", ""), url=ch.get("url"))
        for ch in prov_raw.get("checks", [])
    ]


    baseline_info = None
    try:
        compare_result = await tools.snapshot_compare(
            repo_root=repo_root,
            commit_sha=commit_sha
        )
        b_summary = compare_result.get("baseline_summary", {})
        baseline_sha = b_summary.get("commit_sha")
        inv = compare_result.get("inventory_changes", {})
        
        baseline_info = BaselineComparison(
            has_baseline=True,
            baseline_commit_sha=baseline_sha,
            components=InventoryChange(**inv.get("components", {})) if "components" in inv else None,
            verified_properties=InventoryChange(**inv.get("verified_properties", {})) if "verified_properties" in inv else None
        )
    except LookupError:
        baseline_info = BaselineComparison(has_baseline=False)
    except Exception as e:
        log.warning(f"Failed to fetch baseline info: {e}")
        baseline_info = BaselineComparison(has_baseline=False)

    return ReleaseDecisionResponse(
        decision=decision_state,
        repo_root=repo_root,
        commit_sha=commit_sha,
        release_artifact_digest=release_artifact_digest,
        blockers=blockers,
        explanation=explanations,
        provenance=ProvenanceSummary(components=components, checks=checks),
        baseline=baseline_info
    )



@router.get("/health", response_model=HealthStatusResponse, dependencies=[Depends(require_role(UserRole.ADMIN, UserRole.AUDITOR, UserRole.VIEWER, UserRole.OPERATOR, UserRole.APPROVER, UserRole.POLICY_AUTHOR))])
async def get_release_health(
    repo_root: str = Query(..., description="Repository root to query"),
    commit_sha: str | None = Query(None, description="Optional specific commit SHA")
):
    """Surface ingest health and evidence freshness distinct from policy decisions."""
    tools = _get_tools()
    
    try:
        health_data = await tools.ingest_health(repo_root=repo_root, commit_sha=commit_sha)
        fresh_data = await tools.runtime_evidence_freshness(repo_root=repo_root, commit_sha=commit_sha)
    except Exception as e:
        log.exception("Graph health query failed")
        import traceback
        with open("/tmp/certior-error.log", "w") as _f:
            _f.write(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Query failed: {e}")

    ingest_rows = health_data.get("rows", [])
    counts = health_data.get("counts", {})
    
    # Simple derivation: if blocking errors exist in ingest, status is failed.
    # Otherwise it might be stale or healthy.
    status = "healthy"
    if counts.get("blocking", 0) > 0:
        status = "failed"
    elif counts.get("warning", 0) > 0 or counts.get("stale", 0) > 0:
        status = "degraded"

    issues = []
    for r in ingest_rows:
        issues.append(IngestIssue(
            health_state=r.get("health_state", "unknown"),
            severity=r.get("severity", "unknown"),
            code=r.get("code", "unknown"),
            detail=r.get("detail", "unknown"),
            component_name=r.get("component_name"),
            property_key=r.get("property_key")
        ))
        
    f_counts = fresh_data.get("counts", {})
    
    return HealthStatusResponse(
        repo_root=repo_root,
        commit_sha=health_data.get("snapshot", {}).get("commit_sha", commit_sha),
        ingest_status=status,
        ingest_issues=issues,
        freshness_summary=f_counts
    )





@router.post("/promote", response_model=PromotionResponse)
async def promote_release(req: PromotionRequest, user: User = Depends(require_role(UserRole.ADMIN, UserRole.APPROVER))):
    """
    Audit-grade promotion and review workflow.

    Captures the reviewer identity and reason, and binds the snapshot to
    the artifact.
    """
    tools = _get_tools()
    
    # P2.2 Enforcement: Map verified identity exactly into the record
    actor_identity = user.email or user.id
    
    try:
        res = await tools.promote_snapshot(
            repo_root=req.repo_root,
            commit_sha=req.commit_sha,
            status=req.status,
            release_label=req.release_label,
            operator_identity=actor_identity,
            reason=req.reason,
            bound_artifact_digest=req.bound_artifact_digest
        )
        return PromotionResponse(**res)
    except Exception as e:
        log.exception("Promotion failed")
        raise HTTPException(status_code=500, detail=f"Promotion failed: {e}")


@router.get("/promotions", response_model=PromotionHistoryResponse, dependencies=[Depends(require_role(UserRole.ADMIN, UserRole.AUDITOR, UserRole.VIEWER, UserRole.OPERATOR, UserRole.APPROVER, UserRole.POLICY_AUTHOR))])
async def get_promotion_history(
    repo_root: str = Query(..., description="Repository root or git org url"),
    commit_sha: str | None = Query(None, description="Optional specific commit SHA")
):
    """Expose historical promotion actions."""
    try:
        return PromotionHistoryResponse(promotions=await _list_promotions_fast(repo_root=repo_root, commit_sha=commit_sha))
    except Exception as e:
        log.exception("History query failed")
        raise HTTPException(status_code=500, detail=f"History query failed: {e}")


import httpx

@router.post("/github-webhook")
async def github_webhook(request: Request):
    """
    GitHub webhook for release-decision PR commenting and checks.

    When a CI run finishes or a PR is synchronised, evaluates the release
    decision and posts the verdict back to the originating pull request.
    """
    payload = await request.json()

    # Only handle pull-request events
    if "pull_request" not in payload:
        return {"status": "ignored", "reason": "not a pull_request event"}

    action = payload.get("action")
    if action not in ["opened", "synchronize", "reopened"]:
        return {"status": "ignored", "reason": f"action {action} not handled"}

    pr = payload["pull_request"]
    repo_info = payload.get("repository", {})
    repo_full_name = repo_info.get("full_name")  # e.g., paulinebourigault/certior
    repo_html_url = repo_info.get("html_url")
    commit_sha = pr.get("head", {}).get("sha")
    pr_number = pr.get("number")
    
    if not commit_sha or not repo_html_url:
        return {"status": "error", "reason": "Missing commit SHA or repo URL"}

    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        log.warning("GITHUB_TOKEN not set, cannot comment on PR.")

    tools = _get_tools()
    
    # Run a release decision on this commit
    try:
        raw_result = await tools.release_decision(
            repo_root=repo_html_url,
            commit_sha=commit_sha
        )
    except Exception as e:
        log.exception("Graph query failed during GitHub webhook")
        return {"status": "error", "reason": str(e)}

    decision_dict = raw_result.get("decision", {})
    decision_state = "SHIP" if decision_dict.get("decision_status") == "attested" else "NO_SHIP"
    
    blockers = []
    for item in decision_dict.get("remediation_items", []):
        if item.get("severity") == "blocking":
            reason = item.get("message", "Unknown Blocker")
            comp = item.get("owner_subsystem", "Unknown")
            rem = ", ".join(item.get("remediation_steps", []))
            blockers.append(f"❌ blocked: Component {comp} failed '{reason}'. Fix: {rem}")
            
    if decision_state == "SHIP":
        comment = f"✅ **Certior Trust Shield Passed**\n\nThe AI Agent constraints for commit `{commit_sha}` have been formally verified. No blockers found."
    else:
        comment = f"❌ **Certior Trust Shield Blocked**\n\nThe AI Agent constraints failed formal verification for commit `{commit_sha}`.\n\n"
        for b in blockers:
            comment += f"- {b}\n"

    # Post to github checks API / PR comments
    if github_token and repo_full_name:
        url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"Bearer {github_token}"
        }
        
        async with httpx.AsyncClient() as session:
            resp = await session.post(url, headers=headers, json={"body": comment})
            resp_text = resp.text
            if resp.status_code not in (200, 201):
                log.error(f"Failed to post to GitHub PR: {resp.status_code} {resp_text}")
            else:
                log.info(f"Successfully posted Certior verification comment to {repo_full_name} PR #{pr_number}")
                    
    return {"status": "processed", "decision": decision_state, "blockers": len(blockers)}

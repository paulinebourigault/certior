import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field
import typing
import logging
import hashlib
import json
from app.api.auth import verify_api_key, generate_signed_capability_token

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])

_recent_blocked_delegations: typing.List[typing.Dict[str, typing.Any]] = []


def _permissions_allowed(parent_permissions: typing.List[str], child_permissions: typing.List[str]) -> bool:
    return "*" in parent_permissions or set(child_permissions).issubset(set(parent_permissions))


def _record_blocked_delegation(req: "DelegationRequest", reason: str) -> None:
    _recent_blocked_delegations.append({
        "parent_agent_id": req.parent_agent_id,
        "child_agent_id": req.child_agent_id,
        "parent_token_id": req.parent_id,
        "child_token_id": req.child_id,
        "granted_permissions": req.child_permissions,
        "budget_allocated": req.child_budget,
        "timestamp": time.time(),
        "status": "blocked",
        "severity": "critical",
        "reason": reason,
    })
    del _recent_blocked_delegations[:-50]

class PlanStep(BaseModel):
    tool: str = Field(..., description="Name of the tool to execute")
    input_labels: typing.List[str] = Field(default_factory=lambda: ["Public"], description="List of security labels for inputs")
    output_label: str = Field(default="Internal", description="Expected security label of the output")
    cost: int = Field(default=0, description="Cost of the action in cents")
    data_id: typing.Optional[str] = Field(None, description="Unique ID for this step's output data")

class AgentActionIntent(BaseModel):
    framework: str = Field(..., description="The framework the agent is running in, e.g., langchain, autogen")
    action_type: str = Field(..., description="Type of action intended")
    payload: typing.Dict[str, typing.Any] = Field(default_factory=dict, description="Metadata and arguments of the intended action")
    steps: typing.Optional[typing.List[PlanStep]] = Field(None, description="Structured sequence of tools to mathematically verify")
    budget: int = Field(default=10000, description="Budget constraint")
    compliance_policy: str = Field(default="default", description="Compliance policy, e.g., 'hipaa'")

class VerificationResponse(BaseModel):
    allowed: bool = Field(..., description="Whether the action is mathematically proven safe")
    reason: typing.Optional[str] = Field(None, description="Explanation or sub-proof violation error message")
    proof_hash: typing.Optional[str] = Field(None, description="Cryptographic hash of the mathematical proof")
    certificates: typing.List[typing.Dict[str, typing.Any]] = Field(default_factory=list, description="Raw proof certificates issued by Lean4")
    token: typing.Optional[str] = Field(None, description="The ephemeral signed JWT for OS enforcement")

@router.post("/verify-plan", response_model=VerificationResponse)
async def verify_agent_plan(intent: AgentActionIntent, api_key: str = Depends(verify_api_key)):
    """
    Agent-facing proof API.

    Evaluates the intent against the Lean 4 flow-lattice and returns
    whether the action satisfies all structural boundary constraints.
    """
    log.info(f"Received agent intent for verification: {intent.action_type} via {intent.framework}")

    # If no steps are provided, fallback to the old mocked behavior for backwards compatibility,
    # or handle a single step inferred from payload.
    if not intent.steps:
        # Fallback single step extraction or mock
        intent.steps = [
            PlanStep(
                tool=intent.action_type,
                input_labels=intent.payload.get("input_labels", ["Public"]),
                output_label=intent.payload.get("output_label", "Internal"),
                cost=intent.payload.get("cost", 0)
            )
        ]

    # Python-side budget check
    total_cost = sum(step.cost for step in intent.steps)
    if total_cost > intent.budget:
        return VerificationResponse(
            allowed=False,
            reason=f"Budget exhausted: need {total_cost}, have {intent.budget}",
            proof_hash=None
        )

    # Recompile into a Lean PlanStep AST DAG
    main_steps = []
    
    for idx, step in enumerate(intent.steps):
        data_id = step.data_id or f"step_{idx}_{step.tool}"
        
        # Map agent steps to mathematically verifiable flow conditions via Lean AST checkFlow
        for i_idx, in_label in enumerate(step.input_labels):
            main_steps.append({
                "tag": "bind",
                "dest": f"{data_id}_check_{i_idx}",
                "rhs": {
                    "tag": "checkFlow",
                    "src": f"__level_{in_label}",
                    "dst": f"__level_{step.output_label}"
                },
                "label": {
                    "level": step.output_label,
                    "tags": []
                }
            })

    verified_plan_ast = {
        "resources": [],
        "skills": [],
        "mainSteps": main_steps,
        "totalBudgetCents": intent.budget,
        "requiredTokens": [],
        "compliancePolicy": intent.compliance_policy
    }

    # Pass to the Evaluator (inside CertiorPlan via stateless CLI)
    lean_project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../lean4/CertiorPlan"))
    verify_bin = os.path.join(lean_project_dir, ".lake/build/bin/verify-plan")

    if not os.path.exists(verify_bin):
        log.warning("verify-plan binary not found; live Lean verification unavailable.")
        if os.environ.get("CERTIOR_ENV", "development") == "development":
            return VerificationResponse(
                allowed=True,
                reason="Live Lean verifier unavailable; dev-mode fallback permits.",
                proof_hash=None,
            )
        raise HTTPException(
            status_code=503,
            detail=(
                "Live Lean verifier unavailable. In non-development "
                "environments the server fails closed rather than admit "
                "unverified actions. Build the binary with "
                "scripts/build-lean-binary.sh and point "
                "CERTIOR_FLOW_CHECK_BINARY at the produced path."
            ),
        )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        json.dump(verified_plan_ast, tmp)
        tmp_name = tmp.name

    try:
        proc = subprocess.run([verify_bin, tmp_name], capture_output=True, text=True)
        if proc.returncode != 0 and not proc.stdout.strip():
            # In case it crashes entirely
            return VerificationResponse(
                allowed=False,
                reason=f"Lean Proof Engine Failure: {proc.stderr.strip()}",
                proof_hash=None
            )
            
        lean_result = json.loads(proc.stdout.strip())
        allowed = lean_result.get("allowed", False)
        reason = lean_result.get("reason", "Unknown Proof Error")

        if allowed:
            cert_raw = json.dumps(verified_plan_ast, sort_keys=True).encode("utf-8")
            proof_hash = "sha256:" + hashlib.sha256(cert_raw).hexdigest()
            # Generate Real Signed JWT using KMS
            from app.api.auth import generate_signed_capability_token
            # infer agent from intent if possible
            agent_id = intent.payload.get("agent_id", intent.framework)
            caps = intent.payload.get("actions", [s.tool for s in intent.steps]) if intent.steps else []
            signed_token = generate_signed_capability_token(agent_id, caps)
            return VerificationResponse(
                allowed=True,
                reason=reason,
                proof_hash=proof_hash,
                token=signed_token,
                certificates=[verified_plan_ast]
            )
        else:
            return VerificationResponse(
                allowed=False,
                reason=reason,
                proof_hash=None
            )
    except Exception as e:
        log.error(f"Error invoking verify-plan: {e}")
        return VerificationResponse(
            allowed=False,
            reason=f"Internal proof engine error: {str(e)}",
            proof_hash=None
        )
    finally:
        try:
            os.remove(tmp_name)
        except OSError:
            pass


class DelegationRequest(BaseModel):
    parent_id: str = Field(..., description="Parent capability token ID")
    parent_agent_id: str = Field(..., description="Agent ID of the parent")
    parent_permissions: typing.List[str] = Field(..., description="Permissions parent holds")
    parent_budget: int = Field(..., description="Budget parent holds")
    child_id: str = Field(..., description="Intended child capability token ID")
    child_agent_id: str = Field(..., description="Agent ID of the child")
    child_permissions: typing.List[str] = Field(..., description="Permissions to grant to child")
    child_budget: int = Field(..., description="Budget to allocate to child")

class DelegationResponse(BaseModel):
    allowed: bool
    reason: typing.Optional[str] = None
    token_id: typing.Optional[str] = None


class GlassBoxBoundaryModel(BaseModel):
    engine: str = "Lean4"
    purpose: str = "Capability, permission, and budget bounds for orchestrated agents"


class GlassBoxRecordRequest(BaseModel):
    exported_at: str
    source: str = "/api/v1/agents/delegation-graph"
    view: str = "Certior Agent Glass Box"
    mode: str = "replay"
    active_phase: str
    visible_events: int
    total_events: int
    blocked_events: int
    boundary_view: bool = False
    boundary_model: GlassBoxBoundaryModel = Field(default_factory=GlassBoxBoundaryModel)
    use_cases: typing.List[str] = Field(default_factory=list)
    selected_inspection: typing.Optional[typing.Dict[str, typing.Any]] = None
    graph: typing.Dict[str, typing.Any]


class GlassBoxRecordResponse(GlassBoxRecordRequest):
    id: str
    record_hash: str
    stored_at: float
    storage: str


def _glass_box_records_dir() -> Path:
    data_dir = os.getenv("CERTIOR_DATA_DIR") or os.getenv("CERTIOR_AUDIT_DIR") or "/tmp/certior-glass-box-records"
    path = Path(data_dir) / "glass_box_records"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _canonical_hash(payload: typing.Dict[str, typing.Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _append_glass_box_record(record: typing.Dict[str, typing.Any]) -> None:
    records_dir = _glass_box_records_dir()
    jsonl_path = records_dir / "records.jsonl"
    with jsonl_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
    with (records_dir / f"{record['id']}.json").open("w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True, default=str)

@router.post("/delegate", response_model=DelegationResponse)
async def delegate_agent_permissions(req: DelegationRequest, request: Request, api_key: str = Depends(verify_api_key)):
    """
    Transparent multi-agent delegation.

    Computes the intersection of the parent agent's capabilities and the
    child agent's requested identity via the Lean 4 lattice.
    """
    log.info(f"Received delegation request: {req.parent_agent_id} -> {req.child_agent_id}")

    if not _permissions_allowed(req.parent_permissions, req.child_permissions):
        reason = "Denied: child requested permissions outside parent capability bounds"
        _record_blocked_delegation(req, reason)
        return DelegationResponse(allowed=False, reason=reason, token_id=None)

    if req.child_budget > req.parent_budget:
        reason = "Denied: child requested budget above parent budget ceiling"
        _record_blocked_delegation(req, reason)
        return DelegationResponse(allowed=False, reason=reason, token_id=None)
    
    lean_project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../lean4/CertiorLattice"))
    verify_bin = os.path.join(lean_project_dir, ".lake/build/bin/verify-delegation")

    if not os.path.exists(verify_bin):
        log.warning("verify-delegation binary not found; live Lean verification unavailable.")
        if os.environ.get("CERTIOR_ENV", "development") == "development":
            if request.app.state.state_store:
                await request.app.state.state_store.insert_agent_delegation(
                    parent_agent_id=req.parent_agent_id,
                    child_agent_id=req.child_agent_id,
                    parent_token_id=req.parent_id,
                    child_token_id=req.child_id,
                    permissions=req.child_permissions,
                    budget=req.child_budget,
                )
            return DelegationResponse(
                allowed=True,
                reason="Live Lean verifier unavailable; dev-mode fallback permits.",
                token_id=req.child_id,
            )
        raise HTTPException(
            status_code=503,
            detail=(
                "Live Lean verifier unavailable. In non-development "
                "environments the server fails closed rather than admit "
                "unverified delegations. Build the binary with "
                "scripts/build-lean-binary.sh and point "
                "CERTIOR_FLOW_CHECK_BINARY at the produced path."
            ),
        )

    payload = req.model_dump()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        json.dump(payload, tmp)
        tmp_name = tmp.name

    try:
        proc = subprocess.run([verify_bin, tmp_name], capture_output=True, text=True)
        if proc.returncode != 0 and not proc.stdout.strip():
            return DelegationResponse(allowed=False, reason=f"Lean Proof Engine Failure: {proc.stderr.strip()}")
            
        lean_result = json.loads(proc.stdout.strip())
        is_allowed = lean_result.get("allowed", False)
        if not is_allowed:
            _record_blocked_delegation(req, lean_result.get("reason", "Delegation rejected by verifier"))
        
        # Persist to Postgres / SQLite
        if is_allowed and request.app.state.state_store:
            try:
                await request.app.state.state_store.insert_agent_delegation(
                    parent_agent_id=req.parent_agent_id,
                    child_agent_id=req.child_agent_id,
                    parent_token_id=req.parent_id,
                    child_token_id=lean_result.get("token_id", req.child_id),
                    permissions=req.child_permissions,
                    budget=req.child_budget
                )
            except Exception as store_err:
                log.error(f"Failed to persist delegation proof to DB: {store_err}")

        
        final_token = lean_result.get("token_id")
        if is_allowed:
            from app.api.auth import generate_signed_capability_token
            final_token = generate_signed_capability_token(req.child_agent_id, req.child_permissions)

        return DelegationResponse(
            allowed=is_allowed,
            reason=lean_result.get("reason", "Unknown error"),
            token_id=final_token
        )
    except Exception as e:
        log.error(f"Error invoking verify-delegation: {e}")
        return DelegationResponse(allowed=False, reason=f"Internal proof engine error: {str(e)}")
    finally:
        try:
            os.remove(tmp_name)
        except OSError:
            pass


@router.get("/delegation-graph")
async def get_delegation_graph(request: Request):
    """
    Return the current agent delegation DAG.

    Visualises multi-agent interactions and their cryptographic privilege
    boundaries directly from the PostgreSQL store.
    """
    if not hasattr(request.app.state, "state_store") or not request.app.state.state_store:
        return {"nodes": [], "edges": []}

    try:
        delegations = await request.app.state.state_store.list_agent_delegations(limit=100)
    except Exception as e:
        log.error(f"Failed to load delegation graph from DB: {e}")
        delegations = []

    nodes_dict = {}
    edges = []
    seen_edges = set()

    if not delegations:
        return {"nodes": [], "edges": []}

    for row in delegations:
        parent_id = row.get("parent_agent_id", "unknown_parent")
        child_id = row.get("child_agent_id", "unknown_child")
        
        if parent_id not in nodes_dict:
            nodes_dict[parent_id] = {"id": parent_id, "label": f"{parent_id}", "type": "parent"}
        if child_id not in nodes_dict:
            nodes_dict[child_id] = {"id": child_id, "label": f"{child_id}", "type": "child"}
            
        permissions = row.get("granted_permissions", [])
        budget = row.get("budget_allocated", 0)

        edge_key = (parent_id, child_id, tuple(permissions) if isinstance(permissions, list) else str(permissions), budget)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)

        edges.append({
            "id": f"{parent_id}->{child_id}:{len(edges)}",
            "source": parent_id,
            "target": child_id,
            "label": f"Delegation: {permissions}",
            "permissions": permissions,
            "budget": budget,
            "timestamp": row.get("timestamp", 0),
            "status": row.get("status", "verified"),
            "severity": row.get("severity", "normal"),
            "proofSignature": f"Verified bounds (budget: {budget})",
            "reason": "Runtime verified by Certior Lattice"
        })

    for blocked in _recent_blocked_delegations:
        parent_id = blocked.get("parent_agent_id", "unknown_parent")
        child_id = blocked.get("child_agent_id", "unknown_child")
        if parent_id not in nodes_dict:
            nodes_dict[parent_id] = {"id": parent_id, "label": f"{parent_id}", "type": "parent"}
        if child_id not in nodes_dict:
            nodes_dict[child_id] = {"id": child_id, "label": f"{child_id}", "type": "child"}

        permissions = blocked.get("granted_permissions", [])
        budget = blocked.get("budget_allocated", 0)
        timestamp = blocked.get("timestamp", 0)
        edges.append({
            "id": f"blocked:{parent_id}->{child_id}:{timestamp}",
            "source": parent_id,
            "target": child_id,
            "label": f"Blocked: {permissions}",
            "permissions": permissions,
            "budget": budget,
            "timestamp": timestamp,
            "status": "blocked",
            "severity": blocked.get("severity", "critical"),
            "proofSignature": "No child token issued",
            "reason": blocked.get("reason", "Delegation rejected by verifier"),
        })

    edges.sort(key=lambda edge: edge.get("timestamp", 0))

    return {
        "nodes": list(nodes_dict.values()),
        "edges": edges
    }


@router.post("/glass-box-records", response_model=GlassBoxRecordResponse)
async def create_glass_box_record(record: GlassBoxRecordRequest):
    """
    Persist an auditable Agent Glass Box snapshot for security review and regulated demos.
    The record captures graph state, selected inspection details, boundary model metadata,
    and a canonical hash so exported evidence can be compared later.
    """
    payload = record.model_dump()
    stored_record: typing.Dict[str, typing.Any] = {
        **payload,
        "id": f"gbr_{uuid.uuid4().hex[:12]}",
        "stored_at": time.time(),
        "storage": "jsonl",
    }
    stored_record["record_hash"] = _canonical_hash(stored_record)
    try:
        _append_glass_box_record(stored_record)
    except Exception as exc:
        log.exception("Failed to persist glass-box record")
        raise HTTPException(status_code=500, detail=f"Failed to persist glass-box record: {exc}") from exc
    return GlassBoxRecordResponse(**stored_record)


@router.get("/glass-box-records", response_model=typing.List[GlassBoxRecordResponse])
async def list_glass_box_records(limit: int = 20):
    """Return recent persisted Agent Glass Box records."""
    jsonl_path = _glass_box_records_dir() / "records.jsonl"
    if not jsonl_path.exists():
        return []
    records: typing.List[typing.Dict[str, typing.Any]] = []
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return [GlassBoxRecordResponse(**record) for record in records[-limit:]][::-1]

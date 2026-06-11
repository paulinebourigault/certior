"""
GET /api/v1/compliance/{execution_id}/export - export compliance package.
GET /api/v1/compliance/presets               - list available presets.
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends, Request, HTTPException, Query
from fastapi.responses import JSONResponse, Response

from agentsafe.compliance import (
    CompliancePresets,
    ComplianceExporter,
    CompliancePDFExporter,
    AuditEntry,
)
from .auth import get_current_user, User

router = APIRouter(prefix="/api/v1", tags=["compliance"])


def _infer_execution_preset(execution) -> str:
    token_data = execution.token_data if isinstance(execution.token_data, dict) else {}
    metadata = token_data.get("metadata") if isinstance(token_data.get("metadata"), dict) else {}
    policy_name = metadata.get("compliance_policy")
    if isinstance(policy_name, str) and policy_name:
        return policy_name
    return "default"


@router.get("/compliance/presets")
async def list_presets():
    """List available compliance presets (public)."""
    presets = []
    for name in CompliancePresets.available():
        config = CompliancePresets.get(name)
        presets.append({
            "name": config.name,
            "key": name,
            "required_proofs": config.required_proofs,
            "human_approvals": config.human_approvals,
            "retention_days": config.audit.retention_days,
        })
    return presets


@router.get("/compliance/{execution_id}/export")
async def export_compliance(
    execution_id: str,
    request: Request,
    preset: Optional[str] = Query(None, description="Compliance preset to apply"),
    format: str = Query("json", description="Export format: json or pdf"),
    user: User = Depends(get_current_user),
):
    """
    Export compliance audit package for an execution.

    Formats:
      - ``json`` (default): JSON response with full package
      - ``pdf``: Downloadable PDF audit report

    Includes proof certificates, audit trail, policy applied,
    flow analysis, and attestation.
    """
    store = request.app.state.state_store
    execution = await store.get(execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    preset_name = preset or _infer_execution_preset(execution)
    try:
        config = CompliancePresets.get(preset_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    exporter = ComplianceExporter(config)
    package = exporter.export(execution=execution)

    if format == "pdf":
        if not CompliancePDFExporter.available():
            raise HTTPException(
                status_code=501,
                detail="PDF export requires reportlab. Install: pip install reportlab",
            )
        pdf_bytes = CompliancePDFExporter.render(package)
        filename = f"certior-audit-{execution_id[:8]}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return JSONResponse(
        content=package.to_dict(),
        headers={"Content-Disposition": f'attachment; filename="compliance-{execution_id[:8]}.json"'},
    )

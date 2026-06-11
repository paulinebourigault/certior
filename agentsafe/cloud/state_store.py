"""
Execution state store - async-compatible with SQLite/PostgreSQL.
"""
from __future__ import annotations
import json
import time
import uuid
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class ExecutionStatus(Enum):
    QUEUED = "queued"
    PLANNING = "planning"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Execution:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    task: str = ""
    status: ExecutionStatus = ExecutionStatus.QUEUED
    plan: Optional[Dict] = None
    current_step: int = 0
    results: Optional[Dict] = None
    certificates: List[str] = field(default_factory=list)
    error: str = ""
    webhook_url: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    token_id: str = ""
    cost_cents: int = 0
    token_data: Optional[Dict] = None  # full token info for reconstruction
    llm_provider: Optional[str] = None  # per-task provider override
    llm_model: Optional[str] = None     # per-task model override

    def to_dict(self) -> Dict[str, Any]:
        token_data = self.token_data if isinstance(self.token_data, dict) else {}
        metadata = token_data.get("metadata") if isinstance(token_data.get("metadata"), dict) else {}
        results = self.results if isinstance(self.results, dict) else {}

        proof_properties: List[str] = []
        certificate_ids: List[str] = []
        seen_properties = set()
        seen_certificate_ids = set()

        for step in results.get("steps", []) if isinstance(results.get("steps"), list) else []:
            if not isinstance(step, dict):
                continue
            certificate_id = step.get("certificate_id")
            if isinstance(certificate_id, str) and certificate_id and certificate_id not in seen_certificate_ids:
                seen_certificate_ids.add(certificate_id)
                certificate_ids.append(certificate_id)

            for key in ("verification_properties", "verified_properties"):
                properties = step.get(key)
                if isinstance(properties, list):
                    for prop in properties:
                        if isinstance(prop, str) and prop not in seen_properties:
                            seen_properties.add(prop)
                            proof_properties.append(prop)

        for cert in results.get("lean_certificates", []) if isinstance(results.get("lean_certificates"), list) else []:
            if not isinstance(cert, dict):
                continue
            property_name = cert.get("property")
            if isinstance(property_name, str):
                prop = f"{property_name}: proven"
                if prop not in seen_properties:
                    seen_properties.add(prop)
                    proof_properties.append(prop)

        total_certificates = len(self.certificates)
        if certificate_ids:
            total_certificates = max(total_certificates, len(certificate_ids))
        elif isinstance(results.get("lean_certificates"), list):
            total_certificates = max(total_certificates, len(results.get("lean_certificates", [])))

        d: Dict[str, Any] = {
            "id": self.id, "user_id": self.user_id,
            "task": self.task, "status": self.status.value,
            "current_step": self.current_step,
            "error": self.error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "cost_cents": self.cost_cents,
            "certificate_count": total_certificates,
            "llm_provider": self.llm_provider,
            "llm_model": self.llm_model,
            "compliance_policy": metadata.get("compliance_policy") or "default",
            "proof_properties": proof_properties,
            "certificate_ids": certificate_ids,
        }
        # Include agent output when execution has completed
        if results:
            d["output"] = results.get("output")
            d["verification_summary"] = {
                "steps": len(results.get("steps", [])),
                "duration_ms": results.get("duration_ms"),
                "total_input_tokens": results.get("total_input_tokens", 0),
                "total_output_tokens": results.get("total_output_tokens", 0),
            }
            if isinstance(results.get("verification_profile"), dict):
                d["verification_profile"] = results.get("verification_profile")
        elif token_data:
            profile = token_data.get("verification_profile")
            if isinstance(profile, dict):
                d["verification_profile"] = profile
        return d


class StateStore:
    """In-memory state store (swap for SQLAlchemy in production)."""

    def __init__(self):
        self._executions: Dict[str, Execution] = {}

    async def create(self, execution: Execution) -> Execution:
        self._executions[execution.id] = execution
        return execution

    async def get(self, execution_id: str) -> Optional[Execution]:
        return self._executions.get(execution_id)

    async def update(self, execution: Execution) -> Execution:
        execution.updated_at = time.time()
        self._executions[execution.id] = execution
        return execution

    async def list_by_user(
        self, user_id: str,
        status: Optional[ExecutionStatus] = None,
        limit: int = 20,
    ) -> List[Execution]:
        results = [
            e for e in self._executions.values()
            if e.user_id == user_id
        ]
        if status:
            results = [e for e in results if e.status == status]
        results.sort(key=lambda e: e.created_at, reverse=True)
        return results[:limit]

    async def delete(self, execution_id: str) -> bool:
        return self._executions.pop(execution_id, None) is not None

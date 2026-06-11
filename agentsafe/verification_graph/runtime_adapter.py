from __future__ import annotations

import json
from typing import Any, Iterable

from agentsafe.cloud.state_store import Execution, ExecutionStatus
from agentsafe.compliance.exporter import ComplianceExporter
from agentsafe.compliance.presets import CompliancePresets

from .models import (
    ExecutionArtifactRecord,
    GraphEdgeRecord,
    IngestIssueRecord,
    PolicyProfileRecord,
    RuntimeArtifactRecord,
    VerifiedPropertyRecord,
    WorkflowProfileRecord,
    stable_id,
)

try:
    import asyncpg  # type: ignore[import-untyped]
except ImportError:
    asyncpg = None  # type: ignore[assignment]


def _json_value(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _coerce_execution_status(status: Any) -> ExecutionStatus:
    if isinstance(status, ExecutionStatus):
        return status
    try:
        return ExecutionStatus(str(status))
    except ValueError:
        return ExecutionStatus.QUEUED


def _coerce_execution(row: dict[str, Any]) -> Execution:
    return Execution(
        id=str(row.get("id", "")),
        user_id=str(row.get("user_id", "")),
        task=str(row.get("task", "")),
        status=_coerce_execution_status(row.get("status", ExecutionStatus.QUEUED.value)),
        plan=_json_value(row.get("plan")),
        current_step=int(row.get("current_step", 0) or 0),
        results=_json_value(row.get("results")),
        certificates=list(_json_value(row.get("certificates")) or []),
        error=str(row.get("error", "")),
        webhook_url=str(row.get("webhook_url", "")),
        created_at=float(row.get("created_at", 0.0) or 0.0),
        updated_at=float(row.get("updated_at", 0.0) or 0.0),
        completed_at=row.get("completed_at"),
        token_id=str(row.get("token_id", "")),
        cost_cents=int(row.get("cost_cents", 0) or 0),
        token_data=_json_value(row.get("token_data")),
        llm_provider=row.get("llm_provider"),
        llm_model=row.get("llm_model"),
    )


def _normalise_property(property_name: str) -> tuple[str, dict[str, Any]]:
    raw = property_name.strip()
    if ":" not in raw:
        return raw, {"source_label": raw}
    name, _, suffix = raw.partition(":")
    return name.strip(), {
        "source_label": raw,
        "status": suffix.strip(),
    }


def _proof_system_for_certificate(certificate: dict[str, Any]) -> str:
    cert_type = str(certificate.get("type", "")).lower()
    prover = str(certificate.get("prover", "")).lower()
    if "lean" in cert_type or "lean" in prover:
        return "lean4"
    if "dafny" in cert_type or "dafny" in prover:
        return "dafny"
    if "z3" in prover:
        return "z3"
    if "runtime" in prover or "compliance" in cert_type:
        return "runtime"
    return "runtime"


def _policy_name(execution: Execution) -> str:
    token_data = execution.token_data if isinstance(execution.token_data, dict) else {}
    metadata = token_data.get("metadata") if isinstance(token_data.get("metadata"), dict) else {}
    policy_name = metadata.get("compliance_policy")
    if isinstance(policy_name, str) and policy_name:
        return policy_name
    return "default"


def _verification_profile(execution: Execution) -> dict[str, Any]:
    token_data = execution.token_data if isinstance(execution.token_data, dict) else {}
    profile = token_data.get("verification_profile")
    if isinstance(profile, dict):
        return profile
    metadata = token_data.get("metadata") if isinstance(token_data.get("metadata"), dict) else {}
    profile = metadata.get("verification_profile")
    if isinstance(profile, dict):
        return profile
    results = execution.results if isinstance(execution.results, dict) else {}
    profile = results.get("verification_profile")
    return profile if isinstance(profile, dict) else {}


def _first_string(mapping: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _execution_identity_metadata(execution: Execution, results: dict[str, Any]) -> dict[str, Any]:
    token_data = execution.token_data if isinstance(execution.token_data, dict) else {}
    metadata = token_data.get("metadata") if isinstance(token_data.get("metadata"), dict) else {}
    verification_profile = _verification_profile(execution)
    profile_metadata = verification_profile.get("metadata") if isinstance(verification_profile.get("metadata"), dict) else {}
    exported_at = execution.completed_at or execution.updated_at or execution.created_at
    stage_role = str(verification_profile.get("stage_role") or "") or None
    build_identity = _first_string(
        metadata,
        "build_identity",
        "build_id",
        "release_build_id",
    ) or _first_string(profile_metadata, "build_identity", "build_id", "release_build_id")
    source_commit_sha = _first_string(
        metadata,
        "repo_commit_sha",
        "commit_sha",
        "git_commit_sha",
        "workspace_commit_sha",
    ) or _first_string(profile_metadata, "repo_commit_sha", "commit_sha", "git_commit_sha", "workspace_commit_sha")
    release_label = _first_string(metadata, "release_label") or _first_string(profile_metadata, "release_label")
    attestation_scope = bool(
        stage_role in {"reviewer", "release"}
        or isinstance(results.get("approved_artifact"), dict)
        or isinstance(results.get("release_binding_summary"), dict)
    )
    return {
        "source_commit_sha": source_commit_sha,
        "build_identity": build_identity,
        "release_label": release_label,
        "exported_at": exported_at,
        "stage_role": stage_role,
        "attestation_scope": attestation_scope,
    }


def _artifact_identity_metadata(
    *,
    identity_kind: str,
    identity_key: str,
    execution: Execution,
    results: dict[str, Any],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = _execution_identity_metadata(execution, results)
    payload = {
        "identity_kind": identity_kind,
        "identity_key": identity_key,
        **metadata,
    }
    if extra:
        payload.update(extra)
    return payload


def _certificate_key(certificate: dict[str, Any]) -> str:
    certificate_id = str(certificate.get("id", "")).strip()
    if certificate_id:
        return f"certificate:{certificate_id}"
    return f"certificate:{stable_id('runtime_certificate', json.dumps(certificate, sort_keys=True, default=str))}"


def _seccomp_deployment_key(certificate: dict[str, Any], runtime_key: str) -> str:
    certificate_id = str(certificate.get("id", "")).strip()
    if certificate_id:
        return f"seccomp_deployment:{certificate_id}"
    return f"seccomp_deployment:{stable_id('seccomp_deployment', runtime_key)}"


def _add_edge(
    edges: dict[str, GraphEdgeRecord],
    edge_type: str,
    source_ref: str,
    source_kind: str,
    target_ref: str,
    target_kind: str,
    provenance_kind: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    edge = GraphEdgeRecord(
        id=stable_id("edge", edge_type, source_kind, source_ref, target_kind, target_ref),
        edge_type=edge_type,
        source_ref=source_ref,
        source_kind=source_kind,
        target_ref=target_ref,
        target_kind=target_kind,
        provenance_kind=provenance_kind,
        metadata=metadata or {},
    )
    edges[edge.id] = edge


def build_runtime_metadata(
    execution_rows: Iterable[dict[str, Any]],
    workflow_rows: Iterable[dict[str, Any]],
) -> dict[str, list[Any]]:
    runtime_artifacts: dict[str, RuntimeArtifactRecord] = {}
    execution_artifacts: dict[str, ExecutionArtifactRecord] = {}
    policy_profiles: dict[str, PolicyProfileRecord] = {}
    workflow_profiles: dict[str, WorkflowProfileRecord] = {}
    properties: dict[str, VerifiedPropertyRecord] = {}
    edges: dict[str, GraphEdgeRecord] = {}
    issues: dict[str, IngestIssueRecord] = {}

    for raw_row in execution_rows:
        execution = _coerce_execution(raw_row)
        results = execution.results if isinstance(execution.results, dict) else {}
        policy_name = _policy_name(execution)
        verification_profile = _verification_profile(execution)
        identity_metadata = _execution_identity_metadata(execution, results)

        try:
            config = CompliancePresets.get(policy_name)
            package = ComplianceExporter(config).export(execution)
        except Exception as exc:
            issues[stable_id("issue", "runtime_export", execution.id)] = IngestIssueRecord(
                id=stable_id("issue", "runtime_export", execution.id),
                severity="warning",
                code="runtime_export_failed",
                message=f"failed to export compliance evidence for execution {execution.id}: {exc}",
                metadata={"execution_id": execution.id},
            )
            continue

        execution_key = f"execution:{execution.id}"
        execution_artifacts[execution_key] = ExecutionArtifactRecord(
            id=stable_id("execution_artifact", execution.id, "summary"),
            artifact_key=execution_key,
            execution_id=execution.id,
            artifact_type="execution_summary",
            metadata={
                "identity_kind": "execution",
                "identity_key": execution.id,
                "task": execution.task,
                "status": execution.status.value,
                "created_at": execution.created_at,
                "completed_at": execution.completed_at,
                "cost_cents": execution.cost_cents,
                "llm_provider": execution.llm_provider,
                "llm_model": execution.llm_model,
                "policy_name": policy_name,
                "verification_profile": verification_profile,
                "execution_summary": package.execution_summary,
                "verification_runtime": package.verification_runtime,
                "attestation": package.attestation,
                **identity_metadata,
            },
        )

        evidence_package_key = f"evidence_package:{execution.id}"
        runtime_artifacts[evidence_package_key] = RuntimeArtifactRecord(
            id=stable_id("runtime_artifact", evidence_package_key),
            artifact_key=evidence_package_key,
            artifact_type="evidence_package",
            metadata=_artifact_identity_metadata(
                identity_kind="evidence_package",
                identity_key=execution.id,
                execution=execution,
                results=results,
                extra={
                    "execution_id": execution.id,
                    "policy_name": policy_name,
                    "verification_runtime": package.verification_runtime,
                    "attestation": package.attestation,
                },
            ),
        )
        _add_edge(edges, "EMITS_EVIDENCE", execution_key, "execution_artifact", evidence_package_key, "runtime_artifact", "runtime_state")

        policy_key = f"policy:{policy_name}"
        policy_profiles[policy_key] = PolicyProfileRecord(
            id=stable_id("policy_profile", policy_key),
            profile_key=policy_key,
            name=policy_name,
            metadata={"policy": config.to_dict()},
        )
        _add_edge(edges, "USES_POLICY", execution_key, "execution_artifact", policy_key, "policy_profile", "runtime_state")

        if verification_profile:
            profile_key = f"verification_profile:{execution.id}"
            profile_name = str(verification_profile.get("stage_role") or execution.id)
            policy_profiles[profile_key] = PolicyProfileRecord(
                id=stable_id("policy_profile", profile_key),
                profile_key=profile_key,
                name=profile_name,
                metadata={"verification_profile": verification_profile},
            )
            _add_edge(edges, "USES_VERIFICATION_PROFILE", execution_key, "execution_artifact", profile_key, "policy_profile", "runtime_state")

        for proof_name in package.attestation.get("proofs_satisfied", []):
            if not isinstance(proof_name, str) or not proof_name:
                continue
            properties[proof_name] = VerifiedPropertyRecord(
                id=stable_id("property", proof_name),
                property_key=proof_name,
                name=proof_name,
                proof_system="compliance_attestation",
                source_path=None,
                metadata={"regime": package.attestation.get("regime"), "source": "attestation"},
            )
            _add_edge(edges, "PROVES", execution_key, "execution_artifact", proof_name, "verified_property", "runtime_state")

        for certificate in package.certificates:
            if not isinstance(certificate, dict):
                continue
            runtime_key = _certificate_key(certificate)
            runtime_artifacts[runtime_key] = RuntimeArtifactRecord(
                id=stable_id("runtime_artifact", runtime_key),
                artifact_key=runtime_key,
                artifact_type=str(certificate.get("type") or "runtime_certificate"),
                metadata=_artifact_identity_metadata(
                    identity_kind="runtime_certificate",
                    identity_key=str(certificate.get("id") or runtime_key),
                    execution=execution,
                    results=results,
                    extra=dict(certificate),
                ),
            )
            _add_edge(edges, "EMITS_EVIDENCE", execution_key, "execution_artifact", runtime_key, "runtime_artifact", "runtime_state")
            for proof_name in certificate.get("verified_properties", []):
                if not isinstance(proof_name, str) or not proof_name:
                    continue
                property_key, property_metadata = _normalise_property(proof_name)
                properties[property_key] = VerifiedPropertyRecord(
                    id=stable_id("property", property_key),
                    property_key=property_key,
                    name=property_key,
                    proof_system=_proof_system_for_certificate(certificate),
                    source_path=None,
                    metadata=property_metadata,
                )
                _add_edge(edges, "SUPPORTS_PROPERTY", runtime_key, "runtime_artifact", property_key, "verified_property", "runtime_state")
                _add_edge(edges, "PROVES", execution_key, "execution_artifact", property_key, "verified_property", "runtime_state")

            if runtime_artifacts[runtime_key].artifact_type == "seccomp_compliance_certificate" and certificate.get("all_passed"):
                deployment_key = _seccomp_deployment_key(certificate, runtime_key)
                runtime_artifacts[deployment_key] = RuntimeArtifactRecord(
                    id=stable_id("runtime_artifact", deployment_key),
                    artifact_key=deployment_key,
                    artifact_type="seccomp_deployment_evidence",
                    metadata=_artifact_identity_metadata(
                        identity_kind="seccomp_deployment_evidence",
                        identity_key=str(certificate.get("id") or deployment_key),
                        execution=execution,
                        results=results,
                        extra={
                            "certificate_ref": runtime_key,
                            "regime": certificate.get("regime"),
                            "profile_name": certificate.get("profile_name"),
                            "requirements": certificate.get("requirements", []),
                            "verified_properties": certificate.get("verified_properties", []),
                        },
                    ),
                )
                _add_edge(edges, "EMITS_EVIDENCE", execution_key, "execution_artifact", deployment_key, "runtime_artifact", "runtime_state")
                for proof_name in certificate.get("verified_properties", []):
                    if not isinstance(proof_name, str) or not proof_name:
                        continue
                    property_key, _ = _normalise_property(proof_name)
                    _add_edge(edges, "SUPPORTS_PROPERTY", deployment_key, "runtime_artifact", property_key, "verified_property", "runtime_state")

        approved_artifact = results.get("approved_artifact")
        if isinstance(approved_artifact, dict) and approved_artifact.get("sha256"):
            approved_key = f"approved_artifact:{execution.id}"
            artifact_key = f"artifact_sha256:{approved_artifact['sha256']}"
            execution_artifacts[approved_key] = ExecutionArtifactRecord(
                id=stable_id("execution_artifact", execution.id, "approved_artifact"),
                artifact_key=approved_key,
                execution_id=execution.id,
                artifact_type="approved_artifact",
                metadata={
                    **dict(approved_artifact),
                    **_artifact_identity_metadata(
                        identity_kind="approved_artifact_record",
                        identity_key=str(approved_artifact["sha256"]),
                        execution=execution,
                        results=results,
                    ),
                },
            )
            runtime_artifacts[artifact_key] = RuntimeArtifactRecord(
                id=stable_id("runtime_artifact", artifact_key),
                artifact_key=artifact_key,
                artifact_type="artifact_hash",
                metadata=_artifact_identity_metadata(
                    identity_kind="release_artifact",
                    identity_key=str(approved_artifact["sha256"]),
                    execution=execution,
                    results=results,
                    extra={
                    "sha256": approved_artifact["sha256"],
                    "approved_for_release": approved_artifact.get("approved_for_release", False),
                    "stage_role": approved_artifact.get("stage_role"),
                    "task_class": approved_artifact.get("task_class"),
                    },
                ),
            )
            _add_edge(edges, "PRODUCES", execution_key, "execution_artifact", approved_key, "execution_artifact", "runtime_state")
            _add_edge(edges, "ATTESTS_ARTIFACT", approved_key, "execution_artifact", artifact_key, "runtime_artifact", "runtime_state")

        release_binding = results.get("release_binding_summary")
        if isinstance(release_binding, dict):
            binding_key = f"release_binding:{execution.id}"
            execution_artifacts[binding_key] = ExecutionArtifactRecord(
                id=stable_id("execution_artifact", execution.id, "release_binding"),
                artifact_key=binding_key,
                execution_id=execution.id,
                artifact_type="release_binding_summary",
                metadata={
                    **dict(release_binding),
                    **_artifact_identity_metadata(
                        identity_kind="release_binding",
                        identity_key=str(release_binding.get("artifact_hash") or execution.id),
                        execution=execution,
                        results=results,
                    ),
                },
            )
            _add_edge(edges, "PRODUCES", execution_key, "execution_artifact", binding_key, "execution_artifact", "runtime_state")
            for artifact in release_binding.get("approved_artifacts", []):
                if isinstance(artifact, dict) and artifact.get("sha256"):
                    _add_edge(
                        edges,
                        "BINDS_ARTIFACT",
                        binding_key,
                        "execution_artifact",
                        f"artifact_sha256:{artifact['sha256']}",
                        "runtime_artifact",
                        "runtime_state",
                    )
            for upstream_id in verification_profile.get("upstream_execution_ids", []):
                if isinstance(upstream_id, str) and upstream_id:
                    _add_edge(
                        edges,
                        "DEPENDS_ON_EXECUTION",
                        binding_key,
                        "execution_artifact",
                        f"execution:{upstream_id}",
                        "execution_artifact",
                        "runtime_state",
                    )

    for workflow in workflow_rows:
        workflow_id = str(workflow.get("id", "")).strip()
        if not workflow_id:
            continue
        stages = _json_value(workflow.get("stages")) or []
        workflow_key = f"workflow:{workflow_id}"
        workflow_profiles[workflow_key] = WorkflowProfileRecord(
            id=stable_id("workflow_profile", workflow_key),
            profile_key=workflow_key,
            name=str(workflow.get("name") or workflow_id),
            metadata={
                "id": workflow_id,
                "status": workflow.get("status"),
                "mode": workflow.get("mode"),
                "user_role": workflow.get("user_role"),
                "description": workflow.get("description"),
                "created_at": workflow.get("created_at"),
                "updated_at": workflow.get("updated_at"),
                "completed_at": workflow.get("completed_at"),
            },
        )
        for stage in stages:
            if not isinstance(stage, dict):
                continue
            stage_id = str(stage.get("id") or "")
            if not stage_id:
                continue
            stage_key = f"workflow_stage:{workflow_id}:{stage_id}"
            workflow_profiles[stage_key] = WorkflowProfileRecord(
                id=stable_id("workflow_profile", stage_key),
                profile_key=stage_key,
                name=str(stage.get("name") or stage_id),
                metadata=dict(stage),
            )
            _add_edge(edges, "CONTAINS_STAGE", workflow_key, "workflow_profile", stage_key, "workflow_profile", "workflow_state")

            stage_policy = stage.get("compliance_policy")
            if isinstance(stage_policy, str) and stage_policy:
                policy_key = f"policy:{stage_policy}"
                if policy_key not in policy_profiles:
                    stage_config = CompliancePresets.get(stage_policy)
                    policy_profiles[policy_key] = PolicyProfileRecord(
                        id=stable_id("policy_profile", policy_key),
                        profile_key=policy_key,
                        name=stage_policy,
                        metadata={"policy": stage_config.to_dict()},
                    )
                _add_edge(edges, "USES_POLICY", stage_key, "workflow_profile", policy_key, "policy_profile", "workflow_state")

            execution_id = stage.get("execution_id")
            if isinstance(execution_id, str) and execution_id:
                _add_edge(
                    edges,
                    "EXECUTES",
                    stage_key,
                    "workflow_profile",
                    f"execution:{execution_id}",
                    "execution_artifact",
                    "workflow_state",
                )

            for upstream_stage_id in stage.get("upstream_stage_ids") or []:
                if isinstance(upstream_stage_id, str) and upstream_stage_id:
                    _add_edge(
                        edges,
                        "DEPENDS_ON_STAGE",
                        stage_key,
                        "workflow_profile",
                        f"workflow_stage:{workflow_id}:{upstream_stage_id}",
                        "workflow_profile",
                        "workflow_state",
                    )

    return {
        "runtime_artifacts": list(runtime_artifacts.values()),
        "execution_artifacts": list(execution_artifacts.values()),
        "policy_profiles": list(policy_profiles.values()),
        "workflow_profiles": list(workflow_profiles.values()),
        "properties": list(properties.values()),
        "edges": list(edges.values()),
        "issues": list(issues.values()),
    }


async def extract_runtime_metadata(dsn: str) -> dict[str, list[Any]]:
    if asyncpg is None:
        raise ImportError("asyncpg is required for runtime evidence ingestion")

    execution_rows: list[dict[str, Any]] = []
    workflow_rows: list[dict[str, Any]] = []
    issues: list[IngestIssueRecord] = []
    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2)
    try:
        async with pool.acquire() as conn:
            tables = await conn.fetchrow(
                "SELECT to_regclass('public.executions') AS executions, to_regclass('public.workflows') AS workflows"
            )
            if tables and tables["executions"]:
                rows = await conn.fetch("SELECT * FROM executions ORDER BY created_at DESC")
                execution_rows = [dict(row) for row in rows]
            else:
                issues.append(
                    IngestIssueRecord(
                        id=stable_id("issue", "runtime_table_missing", "executions"),
                        severity="warning",
                        code="runtime_table_missing",
                        message="executions table not found; skipping runtime execution evidence ingest",
                        metadata={"table": "executions"},
                    )
                )

            if tables and tables["workflows"]:
                rows = await conn.fetch("SELECT * FROM workflows ORDER BY created_at DESC")
                workflow_rows = [dict(row) for row in rows]
            else:
                issues.append(
                    IngestIssueRecord(
                        id=stable_id("issue", "runtime_table_missing", "workflows"),
                        severity="warning",
                        code="runtime_table_missing",
                        message="workflows table not found; skipping runtime workflow ingest",
                        metadata={"table": "workflows"},
                    )
                )
    finally:
        await pool.close()

    runtime = build_runtime_metadata(execution_rows, workflow_rows)
    runtime["issues"] = runtime["issues"] + issues
    return runtime
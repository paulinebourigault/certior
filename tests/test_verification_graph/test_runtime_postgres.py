from __future__ import annotations

import os
import time

import pytest

DATABASE_URL = os.getenv("DATABASE_URL")

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")


@pytest.mark.asyncio
async def test_extract_runtime_metadata_from_postgres_roundtrip() -> None:
    pytest.importorskip("asyncpg")

    from agentsafe.cloud.postgres_backend import PgStateStore, PgWorkflowStore
    from agentsafe.cloud.state_store import Execution, ExecutionStatus
    from agentsafe.cloud.workflow_store import Workflow, WorkflowStage, WorkflowStageStatus, WorkflowStatus
    from agentsafe.verification_graph.runtime_adapter import extract_runtime_metadata

    store = PgStateStore(DATABASE_URL, min_pool=1, max_pool=2)
    workflow_store = PgWorkflowStore(DATABASE_URL, min_pool=1, max_pool=2)
    await store.initialize()
    await workflow_store.initialize()

    reviewer = Execution(
        user_id="graph-test-user",
        task="review approved artifact",
        status=ExecutionStatus.COMPLETED,
        completed_at=time.time(),
        token_data={
            "metadata": {"compliance_policy": "hipaa"},
            "verification_profile": {
                "stage_role": "reviewer",
                "upstream_execution_ids": [],
            },
        },
        results={
            "steps": [
                {
                    "step_index": 1,
                    "tool_name": "sandbox_python_eval",
                    "verified": True,
                    "certificate_id": "graph-test-cert-z3",
                    "verification_properties": [
                        "capability_coverage: proven",
                        "budget_sufficient: proven",
                    ],
                    "tool_metadata": {
                        "seccomp_verified": {
                            "proof_certificate": {
                                "certificate_id": "graph-test-dafny-cert",
                                "verified_properties": ["P47", "P48", "P49"],
                            },
                            "compliance_certificate": {
                                "certificate_id": "graph-test-seccomp-cert",
                                "dafny_properties_verified": ["P47", "P48", "P49"],
                                "all_passed": True,
                                "regime": "hipaa",
                            },
                        }
                    },
                }
            ],
            "lean_certificates": [
                {
                    "step_id": "graph-test-lean-step",
                    "property": "P50",
                    "detail": "Lean flow check approved protected internal flow.",
                }
            ],
            "lean_verification_summary": {
                "lean_kernel_available": True,
                "steps_checked": 1,
                "flow_violations": 0,
            },
            "approved_artifact": {
                "text": "Approved de-identified artifact",
                "sha256": "graph-test-approved-hash",
                "approved_for_release": True,
                "stage_role": "reviewer",
                "task_class": "privacy_review",
            },
            "verification_profile": {
                "stage_role": "reviewer",
                "upstream_execution_ids": [],
            },
        },
    )

    release = Execution(
        user_id="graph-test-user",
        task="release reviewed artifact",
        status=ExecutionStatus.COMPLETED,
        completed_at=time.time(),
        token_data={
            "metadata": {"compliance_policy": "hipaa"},
            "verification_profile": {
                "stage_role": "release",
                "upstream_execution_ids": [reviewer.id],
            },
        },
        results={
            "release_binding_summary": {
                "bound": True,
                "rebound": True,
                "artifact_hash": "graph-test-approved-hash",
                "upstream_execution_id": reviewer.id,
                "approved_artifacts": [
                    {"sha256": "graph-test-approved-hash"},
                ],
            },
            "verification_profile": {
                "stage_role": "release",
                "upstream_execution_ids": [reviewer.id],
            },
        },
    )

    workflow = Workflow(
        user_id="graph-test-user",
        user_role="operator",
        name="Graph Evidence Workflow",
        description="Deterministic review and release chain for verification graph integration testing.",
        mode="sequential",
        status=WorkflowStatus.COMPLETED,
        completed_at=time.time(),
        current_stage_index=1,
        stages=[
            WorkflowStage(
                id="review-stage",
                name="Review",
                task="review approved artifact",
                compliance_policy="hipaa",
                stage_role="reviewer",
                execution_id=reviewer.id,
                status=WorkflowStageStatus.COMPLETED,
                completed_at=time.time(),
            ),
            WorkflowStage(
                id="release-stage",
                name="Release",
                task="release reviewed artifact",
                compliance_policy="hipaa",
                stage_role="release",
                execution_id=release.id,
                upstream_stage_ids=["review-stage"],
                status=WorkflowStageStatus.COMPLETED,
                completed_at=time.time(),
            ),
        ],
    )

    await store.create(reviewer)
    await store.create(release)
    await workflow_store.create(workflow)

    try:
        runtime = await extract_runtime_metadata(DATABASE_URL)
    finally:
        await workflow_store.delete(workflow.id)
        await store.delete(release.id)
        await store.delete(reviewer.id)
        await workflow_store.close()
        await store.close()

    runtime_keys = {row.artifact_key for row in runtime["runtime_artifacts"]}
    execution_keys = {row.artifact_key for row in runtime["execution_artifacts"]}
    workflow_keys = {row.profile_key for row in runtime["workflow_profiles"]}
    property_keys = {row.property_key for row in runtime["properties"]}
    edges = {(row.edge_type, row.source_ref, row.target_ref) for row in runtime["edges"]}

    assert "certificate:graph-test-cert-z3" in runtime_keys
    assert "certificate:graph-test-dafny-cert" in runtime_keys
    assert "certificate:graph-test-seccomp-cert" in runtime_keys
    assert "artifact_sha256:graph-test-approved-hash" in runtime_keys

    assert f"execution:{reviewer.id}" in execution_keys
    assert f"execution:{release.id}" in execution_keys
    assert f"approved_artifact:{reviewer.id}" in execution_keys
    assert f"release_binding:{release.id}" in execution_keys

    assert f"workflow:{workflow.id}" in workflow_keys
    assert f"workflow_stage:{workflow.id}:review-stage" in workflow_keys
    assert f"workflow_stage:{workflow.id}:release-stage" in workflow_keys

    assert "P47" in property_keys
    assert "P48" in property_keys
    assert "P49" in property_keys
    assert "P50" in property_keys

    assert ("EXECUTES", f"workflow_stage:{workflow.id}:review-stage", f"execution:{reviewer.id}") in edges
    assert ("EXECUTES", f"workflow_stage:{workflow.id}:release-stage", f"execution:{release.id}") in edges
    assert ("DEPENDS_ON_STAGE", f"workflow_stage:{workflow.id}:release-stage", f"workflow_stage:{workflow.id}:review-stage") in edges
    assert ("BINDS_ARTIFACT", f"release_binding:{release.id}", "artifact_sha256:graph-test-approved-hash") in edges


@pytest.mark.asyncio
async def test_store_snapshot_allows_repeated_ingest_with_stable_ids() -> None:
    pytest.importorskip("asyncpg")

    import asyncpg

    from agentsafe.verification_graph.models import (
        ComponentRecord,
        DeclarationRecord,
        RepoIdentity,
        SnapshotBundle,
        SourceFileRecord,
        VerifiedPropertyRecord,
        stable_id,
    )
    from agentsafe.verification_graph.store import PgVerificationGraphStore

    repo_root = "/tmp/certior-graph-repeat-ingest"
    repo_id = stable_id("repo", repo_root)
    repo = RepoIdentity(
        repo_id=repo_id,
        name="certior-repeat-ingest",
        root_path=repo_root,
        branch="main",
        commit_sha="repeat-ingest-test-sha",
        is_dirty=False,
    )

    component_id = stable_id("component", "repeat-component")
    bundle = SnapshotBundle(
        files=[
            SourceFileRecord(
                id=stable_id("file", "src/repeat.py"),
                path="src/repeat.py",
                sha256="repeat-file-sha",
                language="python",
                size_bytes=123,
            )
        ],
        components=[
            ComponentRecord(
                id=component_id,
                name="repeat.component",
                display_name="repeat.component",
                kind="python_module",
                language="python",
                source_path="src/repeat.py",
            )
        ],
        declarations=[
            DeclarationRecord(
                id=stable_id("decl", "repeat.component.run"),
                component_id=component_id,
                qualified_name="repeat.component.run",
                kind="function",
                language="python",
                source_path="src/repeat.py",
                line_start=1,
                line_end=5,
            )
        ],
        properties=[
            VerifiedPropertyRecord(
                id=stable_id("property", "repeat_property"),
                property_key="repeat_property",
                name="repeat_property",
                proof_system="runtime",
                source_path=None,
            )
        ],
        proof_artifacts=[],
        metadata={"test_case": "repeat_ingest"},
    )

    store = PgVerificationGraphStore(DATABASE_URL, min_pool=1, max_pool=2)
    await store.initialize()

    snapshot_ids: list[str] = []
    try:
        snapshot_ids.append(await store.store_snapshot(repo, bundle))
        snapshot_ids.append(await store.store_snapshot(repo, bundle))

        assert snapshot_ids[0] != snapshot_ids[1]

        repo_context = await store.repo_context(repo_root)
        assert repo_context["snapshot"]["id"] == snapshot_ids[1]
        assert repo_context["counts"]["files"] == 1
        assert repo_context["counts"]["verified_properties"] == 1

        component_context = await store.component_context(repo_root, "repeat.component")
        assert component_context["component"]["name"] == "repeat.component"
        assert len(component_context["declarations"]) == 1
    finally:
        await store.close()

        conn = await asyncpg.connect(DATABASE_URL)
        try:
            await conn.execute(
                "DELETE FROM ingest_issues WHERE snapshot_id = ANY($1::text[])",
                snapshot_ids,
            )
            await conn.execute(
                "DELETE FROM graph_edges WHERE snapshot_id = ANY($1::text[])",
                snapshot_ids,
            )
            await conn.execute(
                "DELETE FROM workflow_profiles WHERE snapshot_id = ANY($1::text[])",
                snapshot_ids,
            )
            await conn.execute(
                "DELETE FROM policy_profiles WHERE snapshot_id = ANY($1::text[])",
                snapshot_ids,
            )
            await conn.execute(
                "DELETE FROM execution_artifacts WHERE snapshot_id = ANY($1::text[])",
                snapshot_ids,
            )
            await conn.execute(
                "DELETE FROM runtime_artifacts WHERE snapshot_id = ANY($1::text[])",
                snapshot_ids,
            )
            await conn.execute(
                "DELETE FROM proof_artifacts WHERE snapshot_id = ANY($1::text[])",
                snapshot_ids,
            )
            await conn.execute(
                "DELETE FROM verified_properties WHERE snapshot_id = ANY($1::text[])",
                snapshot_ids,
            )
            await conn.execute(
                "DELETE FROM declarations WHERE snapshot_id = ANY($1::text[])",
                snapshot_ids,
            )
            await conn.execute(
                "DELETE FROM components WHERE snapshot_id = ANY($1::text[])",
                snapshot_ids,
            )
            await conn.execute(
                "DELETE FROM source_files WHERE snapshot_id = ANY($1::text[])",
                snapshot_ids,
            )
            await conn.execute(
                "DELETE FROM ingest_snapshots WHERE id = ANY($1::text[])",
                snapshot_ids,
            )
            await conn.execute("DELETE FROM repo_commits WHERE repo_id = $1", repo_id)
            await conn.execute("DELETE FROM repos WHERE id = $1", repo_id)
        finally:
            await conn.close()


@pytest.mark.asyncio
async def test_workflow_lineage_returns_stage_and_execution_provenance() -> None:
    pytest.importorskip("asyncpg")

    import asyncpg

    from agentsafe.verification_graph.models import (
        ExecutionArtifactRecord,
        GraphEdgeRecord,
        RepoIdentity,
        SnapshotBundle,
        WorkflowProfileRecord,
        stable_id,
    )
    from agentsafe.verification_graph.store import PgVerificationGraphStore

    repo_root = "/tmp/certior-workflow-lineage"
    repo_id = stable_id("repo", repo_root)
    repo = RepoIdentity(
        repo_id=repo_id,
        name="certior-workflow-lineage",
        root_path=repo_root,
        branch="main",
        commit_sha="workflow-lineage-test-sha",
        is_dirty=False,
    )

    workflow_key = "workflow:Production reviewed release evidence"
    review_stage_key = "workflow_stage:workflow-proof:review"
    release_stage_key = "workflow_stage:workflow-proof:release"
    review_execution_key = "execution:review-proof"
    release_execution_key = "execution:release-proof"

    bundle = SnapshotBundle(
        files=[],
        components=[],
        declarations=[],
        properties=[],
        proof_artifacts=[],
        workflow_profiles=[
            WorkflowProfileRecord(
                id=stable_id("workflow_profile", workflow_key),
                profile_key=workflow_key,
                name="Production reviewed release evidence",
                metadata={"mode": "sequential", "workflow_id": "workflow-proof"},
            ),
            WorkflowProfileRecord(
                id=stable_id("workflow_profile", review_stage_key),
                profile_key=review_stage_key,
                name="Review",
                metadata={"stage_role": "reviewer", "workflow_id": "workflow-proof", "stage_id": "review"},
            ),
            WorkflowProfileRecord(
                id=stable_id("workflow_profile", release_stage_key),
                profile_key=release_stage_key,
                name="Release",
                metadata={"stage_role": "release", "workflow_id": "workflow-proof", "stage_id": "release"},
            ),
        ],
        execution_artifacts=[
            ExecutionArtifactRecord(
                id=stable_id("execution_artifact", review_execution_key),
                artifact_key=review_execution_key,
                execution_id="review-proof",
                artifact_type="execution",
                metadata={"status": "completed", "task": "review approved artifact"},
            ),
            ExecutionArtifactRecord(
                id=stable_id("execution_artifact", release_execution_key),
                artifact_key=release_execution_key,
                execution_id="release-proof",
                artifact_type="execution",
                metadata={"status": "completed", "task": "release reviewed artifact"},
            ),
        ],
        edges=[
            GraphEdgeRecord(
                id=stable_id("edge", f"{workflow_key}:CONTAINS_STAGE:{review_stage_key}"),
                edge_type="CONTAINS_STAGE",
                source_ref=workflow_key,
                source_kind="workflow_profile",
                target_ref=review_stage_key,
                target_kind="workflow_profile",
                provenance_kind="runtime",
            ),
            GraphEdgeRecord(
                id=stable_id("edge", f"{workflow_key}:CONTAINS_STAGE:{release_stage_key}"),
                edge_type="CONTAINS_STAGE",
                source_ref=workflow_key,
                source_kind="workflow_profile",
                target_ref=release_stage_key,
                target_kind="workflow_profile",
                provenance_kind="runtime",
            ),
            GraphEdgeRecord(
                id=stable_id("edge", f"{release_stage_key}:DEPENDS_ON_STAGE:{review_stage_key}"),
                edge_type="DEPENDS_ON_STAGE",
                source_ref=release_stage_key,
                source_kind="workflow_profile",
                target_ref=review_stage_key,
                target_kind="workflow_profile",
                provenance_kind="runtime",
            ),
            GraphEdgeRecord(
                id=stable_id("edge", f"{review_stage_key}:EXECUTES:{review_execution_key}"),
                edge_type="EXECUTES",
                source_ref=review_stage_key,
                source_kind="workflow_profile",
                target_ref=review_execution_key,
                target_kind="execution_artifact",
                provenance_kind="runtime",
            ),
            GraphEdgeRecord(
                id=stable_id("edge", f"{release_stage_key}:EXECUTES:{release_execution_key}"),
                edge_type="EXECUTES",
                source_ref=release_stage_key,
                source_kind="workflow_profile",
                target_ref=release_execution_key,
                target_kind="execution_artifact",
                provenance_kind="runtime",
            ),
        ],
        metadata={"test_case": "workflow_lineage"},
    )

    store = PgVerificationGraphStore(DATABASE_URL, min_pool=1, max_pool=2)
    await store.initialize()

    snapshot_id = ""
    try:
        snapshot_id = await store.store_snapshot(repo, bundle)
        payload = await store.workflow_lineage(repo_root, "Production reviewed release evidence")

        assert payload["tool"] == "workflow_lineage"
        assert payload["workflow"]["profile_key"] == workflow_key
        assert len(payload["stages"]) == 2

        review_stage = next(stage for stage in payload["stages"] if stage["profile_key"] == review_stage_key)
        release_stage = next(stage for stage in payload["stages"] if stage["profile_key"] == release_stage_key)

        assert review_stage["executions"][0]["execution_id"] == "review-proof"
        assert release_stage["depends_on_stage_refs"] == [review_stage_key]
        assert release_stage["executions"][0]["execution_id"] == "release-proof"
    finally:
        await store.close()

        conn = await asyncpg.connect(DATABASE_URL)
        try:
            if snapshot_id:
                await conn.execute("DELETE FROM ingest_issues WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM graph_edges WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM workflow_profiles WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM policy_profiles WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM execution_artifacts WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM runtime_artifacts WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM proof_artifacts WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM verified_properties WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM declarations WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM components WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM source_files WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM ingest_snapshots WHERE id = $1", snapshot_id)
            await conn.execute("DELETE FROM repo_commits WHERE repo_id = $1", repo_id)
            await conn.execute("DELETE FROM repos WHERE id = $1", repo_id)
        finally:
            await conn.close()


@pytest.mark.asyncio
async def test_snapshot_selection_and_derived_views_support_proof_impact() -> None:
    pytest.importorskip("asyncpg")

    import asyncpg

    from agentsafe.verification_graph.models import (
        ComponentRecord,
        ExecutionArtifactRecord,
        GraphEdgeRecord,
        PolicyProfileRecord,
        RepoIdentity,
        RuntimeArtifactRecord,
        SnapshotBundle,
        SourceFileRecord,
        VerifiedPropertyRecord,
        WorkflowProfileRecord,
        stable_id,
    )
    from agentsafe.verification_graph.store import PgVerificationGraphStore

    repo_root = "/tmp/certior-proof-impact"
    repo_id = stable_id("repo", repo_root)
    component_id = stable_id("component", "seccomp_dafny_bridge")
    property_id = stable_id("property", "P47")
    workflow_key = "workflow:proof-impact-demo"
    stage_key = "workflow_stage:proof-impact-demo:release"

    def bundle_for(commit_sha: str) -> tuple[RepoIdentity, SnapshotBundle]:
        repo = RepoIdentity(
            repo_id=repo_id,
            name="certior-proof-impact",
            root_path=repo_root,
            branch="main",
            commit_sha=commit_sha,
            is_dirty=False,
        )
        bundle = SnapshotBundle(
            files=[
                SourceFileRecord(
                    id=stable_id("file", "agentsafe/sandbox/seccomp_dafny_bridge.py"),
                    path="agentsafe/sandbox/seccomp_dafny_bridge.py",
                    sha256=f"sha-{commit_sha}",
                    language="python",
                    size_bytes=100,
                )
            ],
            components=[
                ComponentRecord(
                    id=component_id,
                    name="seccomp_dafny_bridge",
                    display_name="seccomp_dafny_bridge",
                    kind="python_bridge",
                    language="python",
                    source_path="agentsafe/sandbox/seccomp_dafny_bridge.py",
                    metadata={"runtime_critical": True},
                )
            ],
            declarations=[],
            properties=[
                VerifiedPropertyRecord(
                    id=property_id,
                    property_key="P47",
                    name="P47",
                    proof_system="dafny",
                    source_path="dafny/sandbox/seccomp_filter_extended.dfy",
                )
            ],
            proof_artifacts=[],
            runtime_artifacts=[
                RuntimeArtifactRecord(
                    id=stable_id("runtime_artifact", commit_sha, "cert"),
                    artifact_key=f"certificate:{commit_sha}",
                    artifact_type="dafny_certificate",
                    metadata={"certificate_id": commit_sha},
                )
            ],
            execution_artifacts=[
                ExecutionArtifactRecord(
                    id=stable_id("execution_artifact", commit_sha, "exec"),
                    artifact_key=f"execution:{commit_sha}",
                    execution_id=f"exec-{commit_sha}",
                    artifact_type="execution_summary",
                    metadata={"task": "seccomp release", "policy_name": "hipaa"},
                )
            ],
            policy_profiles=[
                PolicyProfileRecord(
                    id=stable_id("policy_profile", "policy:hipaa"),
                    profile_key="policy:hipaa",
                    name="hipaa",
                    metadata={"policy": {"name": "hipaa"}},
                )
            ],
            workflow_profiles=[
                WorkflowProfileRecord(
                    id=stable_id("workflow_profile", workflow_key),
                    profile_key=workflow_key,
                    name="Proof Impact Demo",
                    metadata={"id": "proof-impact-demo"},
                ),
                WorkflowProfileRecord(
                    id=stable_id("workflow_profile", stage_key),
                    profile_key=stage_key,
                    name="Release",
                    metadata={"id": "release", "stage_role": "release"},
                ),
            ],
            edges=[
                GraphEdgeRecord(
                    id=stable_id("edge", "IMPLEMENTS_PROPERTY", "seccomp_dafny_bridge", "P47"),
                    edge_type="IMPLEMENTS_PROPERTY",
                    source_ref="seccomp_dafny_bridge",
                    source_kind="component",
                    target_ref="P47",
                    target_kind="verified_property",
                    provenance_kind="curated_manifest",
                ),
                GraphEdgeRecord(
                    id=stable_id("edge", "TESTS", "seccomp_dafny_bridge", "tests/test_seccomp.py"),
                    edge_type="TESTS",
                    source_ref="seccomp_dafny_bridge",
                    source_kind="component",
                    target_ref="tests/test_seccomp.py",
                    target_kind="test",
                    provenance_kind="curated_manifest",
                ),
                GraphEdgeRecord(
                    id=stable_id("edge", "EMITS_EVIDENCE", f"execution:{commit_sha}", f"certificate:{commit_sha}"),
                    edge_type="EMITS_EVIDENCE",
                    source_ref=f"execution:{commit_sha}",
                    source_kind="execution_artifact",
                    target_ref=f"certificate:{commit_sha}",
                    target_kind="runtime_artifact",
                    provenance_kind="runtime_state",
                ),
                GraphEdgeRecord(
                    id=stable_id("edge", "SUPPORTS_PROPERTY", f"certificate:{commit_sha}", "P47"),
                    edge_type="SUPPORTS_PROPERTY",
                    source_ref=f"certificate:{commit_sha}",
                    source_kind="runtime_artifact",
                    target_ref="P47",
                    target_kind="verified_property",
                    provenance_kind="runtime_state",
                ),
                GraphEdgeRecord(
                    id=stable_id("edge", "USES_POLICY", f"execution:{commit_sha}", "policy:hipaa"),
                    edge_type="USES_POLICY",
                    source_ref=f"execution:{commit_sha}",
                    source_kind="execution_artifact",
                    target_ref="policy:hipaa",
                    target_kind="policy_profile",
                    provenance_kind="runtime_state",
                ),
                GraphEdgeRecord(
                    id=stable_id("edge", "CONTAINS_STAGE", workflow_key, stage_key),
                    edge_type="CONTAINS_STAGE",
                    source_ref=workflow_key,
                    source_kind="workflow_profile",
                    target_ref=stage_key,
                    target_kind="workflow_profile",
                    provenance_kind="workflow_state",
                ),
                GraphEdgeRecord(
                    id=stable_id("edge", "EXECUTES", stage_key, f"execution:{commit_sha}"),
                    edge_type="EXECUTES",
                    source_ref=stage_key,
                    source_kind="workflow_profile",
                    target_ref=f"execution:{commit_sha}",
                    target_kind="execution_artifact",
                    provenance_kind="workflow_state",
                ),
            ],
            metadata={"test_case": "proof_impact"},
        )
        return repo, bundle

    store = PgVerificationGraphStore(DATABASE_URL, min_pool=1, max_pool=2)
    await store.initialize()

    snapshot_ids: list[str] = []
    try:
        old_repo, old_bundle = bundle_for("proof-impact-old")
        new_repo, new_bundle = bundle_for("proof-impact-new")
        snapshot_ids.append(await store.store_snapshot(old_repo, old_bundle))
        snapshot_ids.append(await store.store_snapshot(new_repo, new_bundle))

        old_context = await store.repo_context(repo_root, commit_sha="proof-impact-old")
        assert old_context["repo"]["commit_sha"] == "proof-impact-old"

        coverage = await store.proof_coverage(repo_root, commit_sha="proof-impact-new", component_name="seccomp_dafny_bridge")
        assert coverage["rows"]
        assert coverage["rows"][0]["property_key"] == "P47"
        assert coverage["rows"][0]["has_runtime_evidence"] is True

        trace = await store.proof_runtime_trace(repo_root, commit_sha="proof-impact-new", property_key="P47")
        assert trace["rows"]
        assert trace["rows"][0]["policy_ref"] == "policy:hipaa"
        assert trace["rows"][0]["workflow_ref"] == workflow_key

        stale = await store.stale_verification(repo_root, commit_sha="proof-impact-new")
        assert stale["counts"]["error"] == 0

        readiness = await store.release_attestation_readiness(repo_root, commit_sha="proof-impact-new")
        assert readiness["readiness"]["ready_for_attestation"] is True

        impact = await store.proof_impact(repo_root, "seccomp_dafny_bridge", subject_kind="bridge", commit_sha="proof-impact-new")
        assert impact["subject"]["matched_components"]
        assert impact["subject"]["matched_properties"]
        assert impact["impacts"]["runtime_traces"]
        assert impact["impacts"]["policy_refs"] == ["policy:hipaa"]
        assert impact["impacts"]["workflow_refs"] == [workflow_key]
        assert impact["risk_flags"] == []
    finally:
        await store.close()

        conn = await asyncpg.connect(DATABASE_URL)
        try:
            await conn.execute("DELETE FROM snapshot_promotions WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM ingest_issues WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM graph_edges WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM workflow_profiles WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM policy_profiles WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM execution_artifacts WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM runtime_artifacts WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM proof_artifacts WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM verified_properties WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM declarations WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM components WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM source_files WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM ingest_snapshots WHERE id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM repo_commits WHERE repo_id = $1", repo_id)
            await conn.execute("DELETE FROM repos WHERE id = $1", repo_id)
        finally:
            await conn.close()


@pytest.mark.asyncio
async def test_snapshot_compare_uses_latest_attested_baseline() -> None:
    pytest.importorskip("asyncpg")

    import asyncpg

    from agentsafe.verification_graph.models import RepoIdentity, SnapshotBundle, stable_id
    from agentsafe.verification_graph.store import PgVerificationGraphStore

    repo_root = "/tmp/certior-snapshot-compare"
    repo_id = stable_id("repo", repo_root)

    def bundle_for(commit_sha: str, runtime_key: str) -> tuple[RepoIdentity, SnapshotBundle]:
        return (
            RepoIdentity(
                repo_id=repo_id,
                name="certior-snapshot-compare",
                root_path=repo_root,
                branch="main",
                commit_sha=commit_sha,
                is_dirty=False,
            ),
            SnapshotBundle(
                files=[],
                components=[],
                declarations=[],
                properties=[],
                proof_artifacts=[],
                runtime_artifacts=[],
                execution_artifacts=[],
                policy_profiles=[],
                workflow_profiles=[],
                edges=[],
                issues=[],
                metadata={"runtime_key": runtime_key},
            ),
        )

    store = PgVerificationGraphStore(DATABASE_URL, min_pool=1, max_pool=2)
    await store.initialize()

    snapshot_ids: list[str] = []
    try:
        baseline_repo, baseline_bundle = bundle_for("compare-old", "old")
        current_repo, current_bundle = bundle_for("compare-new", "new")
        snapshot_ids.append(await store.store_snapshot(baseline_repo, baseline_bundle))
        snapshot_ids.append(await store.store_snapshot(current_repo, current_bundle))

        promotion = await store.promote_snapshot(
            repo_root,
            snapshot_id=snapshot_ids[0],
            status="attested",
            release_label="release-old",
            metadata={"channel": "prod"},
        )
        assert promotion["promotion"]["status"] == "attested"

        comparison = await store.snapshot_compare(repo_root, snapshot_id=snapshot_ids[1])

        assert comparison["baseline"]["id"] == snapshot_ids[0]
        assert comparison["baseline"]["promotion"]["release_label"] == "release-old"
        assert comparison["snapshot"]["id"] == snapshot_ids[1]
        assert comparison["readiness"]["delta"]["stale_error_count"] == 0
        assert comparison["inventory_changes"]["components"]["delta"] == 0
    finally:
        await store.close()

        conn = await asyncpg.connect(DATABASE_URL)
        try:
            await conn.execute("DELETE FROM snapshot_promotions WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM ingest_issues WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM graph_edges WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM workflow_profiles WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM policy_profiles WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM execution_artifacts WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM runtime_artifacts WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM proof_artifacts WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM verified_properties WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM declarations WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM components WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM source_files WHERE snapshot_id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM ingest_snapshots WHERE id = ANY($1::text[])", snapshot_ids)
            await conn.execute("DELETE FROM repo_commits WHERE repo_id = $1", repo_id)
            await conn.execute("DELETE FROM repos WHERE id = $1", repo_id)
        finally:
            await conn.close()


@pytest.mark.asyncio
async def test_canonical_proof_coverage_eliminates_duplicate_runtime_critical_stale_rows() -> None:
    pytest.importorskip("asyncpg")

    import asyncpg

    from agentsafe.verification_graph.models import ComponentRecord, GraphEdgeRecord, RepoIdentity, SnapshotBundle, VerifiedPropertyRecord, stable_id
    from agentsafe.verification_graph.store import PgVerificationGraphStore

    repo_root = "/tmp/certior-canonical-coverage"
    repo_id = stable_id("repo", repo_root)
    repo = RepoIdentity(
        repo_id=repo_id,
        name="certior-canonical-coverage",
        root_path=repo_root,
        branch="main",
        commit_sha="canonical-coverage-sha",
        is_dirty=False,
    )

    bundle = SnapshotBundle(
        files=[],
        components=[
            ComponentRecord(
                id=stable_id("component", "lean_package", "certior_plan_package"),
                name="certior_plan_package",
                display_name="CertiorPlan",
                kind="lean_package",
                language="lean",
                source_path="lean4/CertiorPlan",
                metadata={"phase": "B1", "proof_family": "plan_kernel", "runtime_critical": True},
            ),
            ComponentRecord(
                id=stable_id("component", "lean_package", "CertiorPlan"),
                name="CertiorPlan",
                display_name="CertiorPlan",
                kind="lean_package",
                language="lean",
                source_path="lean4/CertiorPlan",
                metadata={"runtime_critical": True},
            ),
            ComponentRecord(
                id=stable_id("component", "lean_binary", "certior_flow_check_binary"),
                name="certior_flow_check_binary",
                display_name="certior-flow-check",
                kind="lean_binary",
                language="lean",
                source_path="lean4/CertiorPlan/app/FlowCheck.lean",
                metadata={"phase": "B1", "proof_family": "flow_check", "runtime_critical": True},
            ),
            ComponentRecord(
                id=stable_id("component", "lean_binary", "certior-flow-check"),
                name="certior-flow-check",
                display_name="certior-flow-check",
                kind="lean_binary",
                language="lean",
                source_path="CertiorPlan.FlowCheck",
                metadata={"runtime_critical": True},
            ),
            ComponentRecord(
                id=stable_id("component", "python_bridge", "information_flow_bridge"),
                name="information_flow_bridge",
                display_name="information_flow_bridge",
                kind="python_bridge",
                language="python",
                source_path="agentsafe/flow/information_flow.py",
                metadata={},
            ),
        ],
        declarations=[],
        properties=[
            VerifiedPropertyRecord(
                id=stable_id("property", "P13"),
                property_key="P13",
                name="P13",
                proof_system="dafny",
                source_path="dafny/flow/information_flow.dfy",
                metadata={"release_attestation_components": ["information_flow_bridge"]},
            )
        ],
        proof_artifacts=[],
        runtime_artifacts=[],
        execution_artifacts=[],
        policy_profiles=[],
        workflow_profiles=[],
        edges=[
            GraphEdgeRecord(
                id=stable_id("edge", "IMPLEMENTS_PROPERTY", "information_flow_bridge", "P13"),
                edge_type="IMPLEMENTS_PROPERTY",
                source_ref="information_flow_bridge",
                source_kind="component",
                target_ref="P13",
                target_kind="verified_property",
                provenance_kind="curated_manifest",
            ),
            GraphEdgeRecord(
                id=stable_id("edge", "CONFIGURES", "information_flow_bridge", "certior-flow-check"),
                edge_type="CONFIGURES",
                source_ref="information_flow_bridge",
                source_kind="component",
                target_ref="certior-flow-check",
                target_kind="component",
                provenance_kind="curated_manifest",
            ),
            GraphEdgeRecord(
                id=stable_id("edge", "BUILDS_BINARY", "CertiorPlan", "certior-flow-check"),
                edge_type="BUILDS_BINARY",
                source_ref="CertiorPlan",
                source_kind="component",
                target_ref="certior-flow-check",
                target_kind="component",
                provenance_kind="lean_export",
            ),
        ],
        issues=[],
        metadata={"test_case": "canonical_coverage"},
    )

    store = PgVerificationGraphStore(DATABASE_URL, min_pool=1, max_pool=2)
    await store.initialize()

    snapshot_id = ""
    try:
        snapshot_id = await store.store_snapshot(repo, bundle)

        coverage = await store.proof_coverage(repo_root)
        bridge_rows = [row for row in coverage["rows"] if row["component_name"] == "information_flow_bridge"]
        canonical_rows = [row for row in coverage["rows"] if row["component_name"] in {"certior_plan_package", "certior_flow_check_binary"}]
        assert bridge_rows
        assert all(row["attestation_scope"] is True for row in bridge_rows)
        assert len(canonical_rows) == 2
        assert all(row["property_key"] == "P13" for row in canonical_rows)
        assert all(row["component_aliases"] for row in canonical_rows)
        assert all(row["attestation_scope"] is False for row in canonical_rows)

        stale = await store.stale_verification(repo_root)
        missing_coverage = [row for row in stale["rows"] if row["stale_reason"] == "missing_property_coverage"]
        lean_runtime_noise = [
            row for row in stale["rows"]
            if row["component_name"] in {"certior_plan_package", "certior_flow_check_binary"}
            and row["stale_reason"] in {"missing_runtime_evidence", "missing_test_coverage"}
        ]
        assert missing_coverage == []
        assert lean_runtime_noise == []
    finally:
        await store.close()

        conn = await asyncpg.connect(DATABASE_URL)
        try:
            if snapshot_id:
                await conn.execute("DELETE FROM snapshot_promotions WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM ingest_issues WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM graph_edges WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM workflow_profiles WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM policy_profiles WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM execution_artifacts WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM runtime_artifacts WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM proof_artifacts WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM verified_properties WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM declarations WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM components WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM source_files WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM ingest_snapshots WHERE id = $1", snapshot_id)
            await conn.execute("DELETE FROM repo_commits WHERE repo_id = $1", repo_id)
            await conn.execute("DELETE FROM repos WHERE id = $1", repo_id)
        finally:
            await conn.close()


@pytest.mark.asyncio
async def test_runtime_freshness_and_ingest_health_surface_stale_release_evidence() -> None:
    pytest.importorskip("asyncpg")

    import asyncpg

    from agentsafe.verification_graph.models import (
        ComponentRecord,
        ExecutionArtifactRecord,
        GraphEdgeRecord,
        IngestIssueRecord,
        PolicyProfileRecord,
        RepoIdentity,
        RuntimeArtifactRecord,
        SnapshotBundle,
        VerifiedPropertyRecord,
        WorkflowProfileRecord,
        stable_id,
    )
    from agentsafe.verification_graph.store import PgVerificationGraphStore

    repo_root = "/tmp/certior-runtime-freshness"
    repo_id = stable_id("repo", repo_root)
    repo = RepoIdentity(
        repo_id=repo_id,
        name="certior-runtime-freshness",
        root_path=repo_root,
        branch="main",
        commit_sha="runtime-freshness-current",
        is_dirty=False,
    )

    component_name = "seccomp_dafny_bridge"
    property_key = "P47"
    execution_key = "execution:runtime-freshness"
    certificate_key = "certificate:runtime-freshness"
    workflow_key = "workflow:runtime-freshness"
    stage_key = "workflow_stage:runtime-freshness:release"

    bundle = SnapshotBundle(
        files=[],
        components=[
            ComponentRecord(
                id=stable_id("component", component_name),
                name=component_name,
                display_name=component_name,
                kind="python_bridge",
                language="python",
                source_path="agentsafe/sandbox/seccomp_dafny_bridge.py",
                metadata={"runtime_critical": True, "phase": "B1", "proof_family": "seccomp"},
            )
        ],
        declarations=[],
        properties=[
            VerifiedPropertyRecord(
                id=stable_id("property", property_key),
                property_key=property_key,
                name=property_key,
                proof_system="dafny",
                source_path="dafny/sandbox/seccomp_filter_extended.dfy",
                metadata={
                    "release_attestation_components": [component_name],
                    "release_attestation_properties": [property_key],
                },
            )
        ],
        proof_artifacts=[],
        runtime_artifacts=[
            RuntimeArtifactRecord(
                id=stable_id("runtime_artifact", certificate_key),
                artifact_key=certificate_key,
                artifact_type="dafny_certificate",
                metadata={
                    "identity_kind": "certificate",
                    "identity_key": "runtime-freshness",
                },
            )
        ],
        execution_artifacts=[
            ExecutionArtifactRecord(
                id=stable_id("execution_artifact", execution_key),
                artifact_key=execution_key,
                execution_id="runtime-freshness",
                artifact_type="execution_summary",
                metadata={
                    "identity_kind": "execution",
                    "identity_key": "runtime-freshness",
                    "policy_name": "hipaa",
                    "source_commit_sha": "runtime-freshness-old",
                    "build_identity": "build-old",
                    "attestation_scope": True,
                    "exported_at": time.time(),
                },
            )
        ],
        policy_profiles=[
            PolicyProfileRecord(
                id=stable_id("policy_profile", "policy:hipaa"),
                profile_key="policy:hipaa",
                name="hipaa",
                metadata={"policy": {"name": "hipaa"}},
            )
        ],
        workflow_profiles=[
            WorkflowProfileRecord(
                id=stable_id("workflow_profile", workflow_key),
                profile_key=workflow_key,
                name="Runtime Freshness",
                metadata={"workflow_id": "runtime-freshness"},
            ),
            WorkflowProfileRecord(
                id=stable_id("workflow_profile", stage_key),
                profile_key=stage_key,
                name="Release",
                metadata={"workflow_id": "runtime-freshness", "stage_id": "release", "stage_role": "release"},
            ),
        ],
        edges=[
            GraphEdgeRecord(
                id=stable_id("edge", "IMPLEMENTS_PROPERTY", component_name, property_key),
                edge_type="IMPLEMENTS_PROPERTY",
                source_ref=component_name,
                source_kind="component",
                target_ref=property_key,
                target_kind="verified_property",
                provenance_kind="curated_manifest",
            ),
            GraphEdgeRecord(
                id=stable_id("edge", "TESTS", component_name, "tests/test_seccomp.py"),
                edge_type="TESTS",
                source_ref=component_name,
                source_kind="component",
                target_ref="tests/test_seccomp.py",
                target_kind="test",
                provenance_kind="curated_manifest",
            ),
            GraphEdgeRecord(
                id=stable_id("edge", "EMITS_EVIDENCE", execution_key, certificate_key),
                edge_type="EMITS_EVIDENCE",
                source_ref=execution_key,
                source_kind="execution_artifact",
                target_ref=certificate_key,
                target_kind="runtime_artifact",
                provenance_kind="runtime_state",
            ),
            GraphEdgeRecord(
                id=stable_id("edge", "SUPPORTS_PROPERTY", certificate_key, property_key),
                edge_type="SUPPORTS_PROPERTY",
                source_ref=certificate_key,
                source_kind="runtime_artifact",
                target_ref=property_key,
                target_kind="verified_property",
                provenance_kind="runtime_state",
            ),
            GraphEdgeRecord(
                id=stable_id("edge", "USES_POLICY", execution_key, "policy:hipaa"),
                edge_type="USES_POLICY",
                source_ref=execution_key,
                source_kind="execution_artifact",
                target_ref="policy:hipaa",
                target_kind="policy_profile",
                provenance_kind="runtime_state",
            ),
            GraphEdgeRecord(
                id=stable_id("edge", "CONTAINS_STAGE", workflow_key, stage_key),
                edge_type="CONTAINS_STAGE",
                source_ref=workflow_key,
                source_kind="workflow_profile",
                target_ref=stage_key,
                target_kind="workflow_profile",
                provenance_kind="workflow_state",
            ),
            GraphEdgeRecord(
                id=stable_id("edge", "EXECUTES", stage_key, execution_key),
                edge_type="EXECUTES",
                source_ref=stage_key,
                source_kind="workflow_profile",
                target_ref=execution_key,
                target_kind="execution_artifact",
                provenance_kind="workflow_state",
            ),
        ],
        issues=[
            IngestIssueRecord(
                id=stable_id("issue", "runtime_table_missing", repo.commit_sha),
                severity="error",
                code="runtime_table_missing",
                message="runtime evidence table was unavailable during one ingest phase",
                path="agentsafe/cloud/postgres_backend.py",
                metadata={"table": "executions"},
            )
        ],
        metadata={"test_case": "runtime_freshness", "build_identity": "build-current"},
    )

    store = PgVerificationGraphStore(DATABASE_URL, min_pool=1, max_pool=2)
    await store.initialize()

    snapshot_id = ""
    try:
        snapshot_id = await store.store_snapshot(repo, bundle)

        freshness = await store.runtime_evidence_freshness(repo_root, property_key=property_key)
        assert freshness["counts"]["stale"] == 1
        assert freshness["counts"]["fresh"] == 0
        assert freshness["rows"][0]["freshness_state"] == "stale_commit_mismatch"
        assert freshness["rows"][0]["identity_kind"] == "certificate"
        assert freshness["rows"][0]["identity_key"] == "runtime-freshness"

        stale = await store.stale_verification(repo_root)
        stale_runtime_rows = [row for row in stale["rows"] if row["stale_reason"] == "stale_runtime_evidence"]
        assert len(stale_runtime_rows) == 1
        assert stale_runtime_rows[0]["property_key"] == property_key

        health = await store.ingest_health(repo_root)
        assert health["counts"]["blocking"] == 1
        assert health["counts"]["stale"] == 1
        assert any(row["code"] == "runtime_table_missing" for row in health["rows"])
        assert any(row["code"] == "stale_runtime_evidence" for row in health["rows"])

        readiness = await store.release_attestation_readiness(repo_root)
        assert readiness["readiness"]["ready_for_attestation"] is False
        assert readiness["readiness"]["stale_runtime_evidence_count"] == 1
        assert readiness["readiness"]["health_blocking_count"] == 1
        assert readiness["readiness"]["health_stale_count"] == 1
        assert "stale_runtime_evidence_present" in readiness["blocking_reasons"]
        assert "blocking_ingest_issues_present" in readiness["blocking_reasons"]
    finally:
        await store.close()

        conn = await asyncpg.connect(DATABASE_URL)
        try:
            if snapshot_id:
                await conn.execute("DELETE FROM snapshot_promotions WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM ingest_issues WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM graph_edges WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM workflow_profiles WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM policy_profiles WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM execution_artifacts WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM runtime_artifacts WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM proof_artifacts WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM verified_properties WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM declarations WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM components WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM source_files WHERE snapshot_id = $1", snapshot_id)
                await conn.execute("DELETE FROM ingest_snapshots WHERE id = $1", snapshot_id)
            await conn.execute("DELETE FROM repo_commits WHERE repo_id = $1", repo_id)
            await conn.execute("DELETE FROM repos WHERE id = $1", repo_id)
        finally:
            await conn.close()
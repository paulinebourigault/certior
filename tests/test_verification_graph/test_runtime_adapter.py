from __future__ import annotations

from agentsafe.verification_graph.runtime_adapter import build_runtime_metadata


def test_runtime_adapter_builds_execution_and_certificate_evidence() -> None:
    runtime = build_runtime_metadata(
        execution_rows=[
            {
                "id": "exec-reviewer-1",
                "user_id": "dev-admin",
                "task": "Review quarterly expense report",
                "status": "completed",
                "created_at": 1.0,
                "updated_at": 2.0,
                "completed_at": 3.0,
                "cost_cents": 15,
                "certificates": [],
                "results": {
                    "steps": [
                        {
                            "step_index": 1,
                            "tool_name": "expense_audit",
                            "certificate_id": "cert-expense-1",
                            "verification_properties": [
                                "capability_coverage: proven",
                                "budget_sufficient: proven",
                            ],
                            "verified": True,
                            "tool_metadata": {
                                "seccomp_verified": {
                                    "proof_certificate": {
                                        "certificate_id": "dafny-cert-1",
                                        "verified_properties": ["P34", "P35"],
                                    },
                                    "compliance_certificate": {
                                        "certificate_id": "seccomp-cert-1",
                                        "dafny_properties_verified": ["P34", "P35"],
                                        "all_passed": True,
                                        "regime": "hipaa",
                                    },
                                }
                            },
                        }
                    ],
                    "lean_verification_summary": {
                        "lean_kernel_available": True,
                        "steps_checked": 1,
                        "flow_violations": 0,
                    },
                    "lean_certificates": [
                        {
                            "step_id": "step_1_expense_audit",
                            "property": "flow_safe",
                            "detail": "MNPI internal flow safe",
                        }
                    ],
                    "approved_artifact": {
                        "text": "approved release content",
                        "sha256": "approved-hash-1",
                        "approved_for_release": True,
                        "stage_role": "reviewer",
                        "task_class": "privacy_review",
                    },
                    "verification_profile": {
                        "stage_role": "reviewer",
                        "upstream_execution_ids": ["exec-intake-1"],
                    },
                },
                "token_data": {
                    "metadata": {
                        "compliance_policy": "hipaa",
                    },
                    "verification_profile": {
                        "stage_role": "reviewer",
                        "upstream_execution_ids": ["exec-intake-1"],
                    },
                },
            },
            {
                "id": "exec-release-1",
                "user_id": "dev-admin",
                "task": "Release reviewed report",
                "status": "completed",
                "created_at": 4.0,
                "updated_at": 5.0,
                "completed_at": 6.0,
                "cost_cents": 5,
                "certificates": [],
                "results": {
                    "release_binding_summary": {
                        "bound": True,
                        "approved_artifacts": [
                            {"sha256": "approved-hash-1"}
                        ],
                    },
                    "verification_profile": {
                        "stage_role": "release",
                        "upstream_execution_ids": ["exec-reviewer-1"],
                    },
                },
                "token_data": {
                    "metadata": {
                        "compliance_policy": "hipaa",
                    },
                    "verification_profile": {
                        "stage_role": "release",
                        "upstream_execution_ids": ["exec-reviewer-1"],
                    },
                },
            },
        ],
        workflow_rows=[
            {
                "id": "workflow-1",
                "name": "Protected release",
                "status": "completed",
                "mode": "sequential",
                "user_role": "operator",
                "stages": [
                    {
                        "id": "review-stage",
                        "name": "Review",
                        "status": "completed",
                        "compliance_policy": "hipaa",
                        "execution_id": "exec-reviewer-1",
                        "upstream_stage_ids": [],
                    },
                    {
                        "id": "release-stage",
                        "name": "Release",
                        "status": "completed",
                        "compliance_policy": "hipaa",
                        "execution_id": "exec-release-1",
                        "upstream_stage_ids": ["review-stage"],
                    },
                ],
            }
        ],
    )

    execution_keys = {row.artifact_key for row in runtime["execution_artifacts"]}
    runtime_keys = {row.artifact_key for row in runtime["runtime_artifacts"]}
    property_keys = {row.property_key for row in runtime["properties"]}
    edge_keys = {(row.edge_type, row.source_ref, row.target_ref) for row in runtime["edges"]}

    assert "execution:exec-reviewer-1" in execution_keys
    assert "execution:exec-release-1" in execution_keys
    assert "approved_artifact:exec-reviewer-1" in execution_keys
    assert "release_binding:exec-release-1" in execution_keys

    assert "certificate:cert-expense-1" in runtime_keys
    assert "certificate:dafny-cert-1" in runtime_keys
    assert "certificate:seccomp-cert-1" in runtime_keys
    assert "artifact_sha256:approved-hash-1" in runtime_keys

    assert "capability_coverage" in property_keys
    assert "budget_sufficient" in property_keys
    assert "P34" in property_keys
    assert "P35" in property_keys
    assert "flow_safe" in property_keys

    assert ("USES_POLICY", "execution:exec-reviewer-1", "policy:hipaa") in edge_keys
    assert ("EMITS_EVIDENCE", "execution:exec-reviewer-1", "certificate:cert-expense-1") in edge_keys
    assert ("SUPPORTS_PROPERTY", "certificate:dafny-cert-1", "P34") in edge_keys
    assert ("ATTESTS_ARTIFACT", "approved_artifact:exec-reviewer-1", "artifact_sha256:approved-hash-1") in edge_keys
    assert ("BINDS_ARTIFACT", "release_binding:exec-release-1", "artifact_sha256:approved-hash-1") in edge_keys
    assert (
        "EXECUTES",
        "workflow_stage:workflow-1:release-stage",
        "execution:exec-release-1",
    ) in edge_keys
    assert (
        "DEPENDS_ON_STAGE",
        "workflow_stage:workflow-1:release-stage",
        "workflow_stage:workflow-1:review-stage",
    ) in edge_keys
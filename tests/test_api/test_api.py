"""Tests for the Certior FastAPI application (app.main).

Updated to supply authentication on protected routes.
"""
import asyncio
import time

import pytest
from unittest.mock import AsyncMock

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient
from agentsafe.cloud import Workflow, WorkflowStage, WorkflowStageStatus, WorkflowStatus
from agentsafe.cloud.state_store import Execution, ExecutionStatus
from app.main import create_app
from app.api.routes.auth import reset_store


@pytest.fixture(autouse=True)
def _clean_auth_store():
    """Reset the global auth store before every test so state doesn't leak."""
    reset_store()
    yield
    reset_store()


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def dev_key():
    """Return the auto-created development API key."""
    from app.api.routes.auth import get_dev_api_key
    return get_dev_api_key()


@pytest.fixture
def auth_headers(dev_key):
    """Auth headers using Bearer scheme."""
    return {"Authorization": f"Bearer {dev_key}"}


# ── Health (no auth required) ──


class TestHealth:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["version"] == "0.5.0"
        assert "mode" in data
        assert data["mode"] in ("agentic", "legacy")
        assert isinstance(data["tools"], list)
        assert "llm_configured" in data


# ── Tokens (no auth required) ──


class TestTokens:
    def test_issue_token(self, client):
        r = client.post("/api/v1/tokens", json={
            "agent_id": "agent-1",
            "permissions": ["database:read"],
            "budget_cents": 5000,
        })
        assert r.status_code == 201
        data = r.json()
        assert data["agent_id"] == "agent-1"
        assert data["budget_cents"] == 5000
        assert data["valid"] is True

    def test_get_token(self, client):
        r = client.post("/api/v1/tokens", json={"agent_id": "t1"})
        tid = r.json()["id"]
        r2 = client.get(f"/api/v1/tokens/{tid}")
        assert r2.status_code == 200
        assert r2.json()["id"] == tid

    def test_get_missing_token(self, client):
        r = client.get("/api/v1/tokens/nonexistent")
        assert r.status_code == 404


# ── Compliance Presets (no auth required) ──


class TestCompliancePresets:
    def test_list_presets(self, client):
        r = client.get("/api/v1/compliance/presets")
        assert r.status_code == 200
        presets = r.json()
        assert len(presets) >= 4
        names = {p["key"] for p in presets}
        assert "hipaa" in names
        assert "sox" in names


# ── Production Use-Cases (no auth required) ──


class TestUseCases:
    def test_production_use_cases(self, client):
        r = client.get("/api/v1/use-cases/production")
        assert r.status_code == 200
        data = r.json()
        assert "single_agent" in data
        assert "multi_agent" in data
        assert len(data["multi_agent"]["stages"]) >= 2

    def test_production_playbook(self, client):
        r = client.get("/api/v1/use-cases/production/playbook")
        assert r.status_code == 200
        data = r.json()
        assert "multi_agent_stages" in data
        assert len(data["multi_agent_stages"]) >= 3
        assert "runbook" in data
        assert len(data["runbook"]) >= 4

    def test_production_demo(self, client):
        r = client.get("/api/v1/use-cases/production/demo")
        assert r.status_code == 200
        data = r.json()
        assert "steps" in data
        assert len(data["steps"]) >= 7
        assert data["steps"][0]["step"] == 1

    def test_use_case_pages_render_html(self, client):
        for path in [
            "/api/v1/use-cases/production/page",
            "/api/v1/use-cases/production/playbook/page",
            "/api/v1/use-cases/production/demo/page",
            "/api/v1/use-cases/production/studio",
        ]:
            r = client.get(path)
            assert r.status_code == 200
            assert "text/html" in r.headers.get("content-type", "")


# ── Task Submission (auth required) ──


class TestTasks:
    def test_create_task_default(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={
            "task": "Analyse quarterly report",
        }, headers=auth_headers)
        assert r.status_code == 201
        data = r.json()
        assert "execution_id" in data
        assert data["status"] == "queued"
        assert "websocket_url" in data

    def test_create_task_hipaa(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={
            "task": "Review patient records",
            "compliance_policy": "hipaa",
            "budget_cents": 2000,
        }, headers=auth_headers)
        assert r.status_code == 201

    def test_create_task_invalid_policy(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={
            "task": "something",
            "compliance_policy": "gdpr",
        }, headers=auth_headers)
        assert r.status_code == 400

    def test_create_task_empty_task(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={"task": ""}, headers=auth_headers)
        assert r.status_code == 422

    def test_create_task_no_auth(self, client):
        r = client.post("/api/v1/tasks", json={"task": "foo"})
        assert r.status_code in (401, 403)

    def test_create_task_returns_verification_profile(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={
            "task": "Review clinical intake note and return GO/NO-GO",
            "compliance_policy": "legal_privilege",
            "verification_profile": {
                "task_class": "privacy_review",
                "stage_role": "reviewer",
                "stage_id": "review",
                "upstream_execution_ids": ["exec-intake"],
            },
        }, headers=auth_headers)
        assert r.status_code == 201
        data = r.json()
        assert data["verification_profile"]["stage_role"] == "reviewer"
        assert data["verification_profile"]["release_targets"] == ["internal"]

    def test_create_task_public_safe_summary_profile(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={
            "task": (
                "Summarize the patient encounter into a discharge summary, "
                "redact all direct patient identifiers, and apply minimum-necessary principle."
            ),
            "compliance_policy": "hipaa",
        }, headers=auth_headers)
        assert r.status_code == 201
        data = r.json()
        assert data["verification_profile"]["task_class"] == "public_safe_summary"
        assert data["verification_profile"]["release_targets"] == ["public"]
        assert "phi_stage_contained" not in data["verification_profile"]["required_proofs"]

    def test_release_stage_requires_dependencies(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={
            "task": "Produce final release attestation",
            "compliance_policy": "default",
            "verification_profile": {
                "task_class": "release_decision",
                "stage_role": "release",
            },
        }, headers=auth_headers)
        assert r.status_code == 400

    def test_protected_release_is_rejected_without_review_chain(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={
            "task": (
                "Read the patient encounter and publish the full raw patient note "
                "to a public website for external access."
            ),
            "compliance_policy": "hipaa",
        }, headers=auth_headers)
        assert r.status_code == 400
        assert "upstream_execution_ids" in str(r.json()["detail"])


class TestSettings:
    def test_validate_provider_ready(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr("app.api.routes.settings._probe_provider", AsyncMock(return_value=None))
        response = client.post(
            "/api/v1/settings/provider/validate",
            json={
                "provider": "openai",
                "model": "gpt-4o-mini",
                "api_key": "sk-test-1234567890",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["valid"] is True
        assert response.json()["status"] == "ready"

    def test_validate_provider_quota_error(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr(
            "app.api.routes.settings._probe_provider",
            AsyncMock(side_effect=RuntimeError("insufficient_quota: billing issue")),
        )
        response = client.post(
            "/api/v1/settings/provider/validate",
            json={
                "provider": "openai",
                "model": "gpt-4o-mini",
                "api_key": "sk-test-1234567890",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["valid"] is False
        assert response.json()["status"] == "billing_issue"


# ── Executions (auth required) ──


class TestExecutions:
    def _submit(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={"task": "Test task"},
                        headers=auth_headers)
        return r.json()["execution_id"]

    def test_get_execution(self, client, auth_headers):
        eid = self._submit(client, auth_headers)
        r = client.get(f"/api/v1/executions/{eid}", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["id"] == eid
        assert r.json()["compliance_policy"] == "default"

    def test_get_missing_execution(self, client, auth_headers):
        r = client.get("/api/v1/executions/nonexistent", headers=auth_headers)
        assert r.status_code == 404

    def test_list_executions(self, client, auth_headers):
        self._submit(client, auth_headers)
        self._submit(client, auth_headers)
        r = client.get("/api/v1/executions", headers=auth_headers)
        assert r.status_code == 200
        assert len(r.json()) >= 2
        assert all("compliance_policy" in execution for execution in r.json())

    def test_list_executions_invalid_status(self, client, auth_headers):
        r = client.get("/api/v1/executions?status=invalid", headers=auth_headers)
        assert r.status_code == 400

    def test_cancel_execution(self, client, auth_headers):
        eid = self._submit(client, auth_headers)
        r = client.delete(f"/api/v1/executions/{eid}", headers=auth_headers)
        assert r.status_code in (200, 409)

    def test_cancel_missing(self, client, auth_headers):
        r = client.delete("/api/v1/executions/nonexistent", headers=auth_headers)
        assert r.status_code == 409

    def test_executions_no_auth(self, client):
        r = client.get("/api/v1/executions")
        assert r.status_code in (401, 403)


class TestWorkflows:
    def _poll_workflow(self, client, workflow_id, auth_headers, timeout=3.0):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            response = client.get(f"/api/v1/workflows/{workflow_id}", headers=auth_headers)
            assert response.status_code == 200
            last = response.json()
            if last["status"] not in ("queued", "running"):
                return last
            time.sleep(0.05)
        return last

    def test_create_workflow(self, client, auth_headers):
        response = client.post(
            "/api/v1/workflows",
            json={
                "name": "Two-stage review workflow",
                "description": "Sequential specialist review",
                "stages": [
                    {
                        "name": "Intake",
                        "task": "Draft a minimum-necessary intake artifact.",
                        "compliance_policy": "hipaa",
                        "budget_cents": 1500,
                        "stage_role": "intake",
                    },
                    {
                        "name": "Review",
                        "task": "Review the intake artifact for disclosure risk.",
                        "compliance_policy": "legal_privilege",
                        "budget_cents": 1200,
                        "stage_role": "reviewer",
                    },
                ],
            },
            headers=auth_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Two-stage review workflow"
        assert data["stage_count"] == 2
        assert len(data["stages"]) == 2

        listed = client.get("/api/v1/workflows", headers=auth_headers)
        assert listed.status_code == 200
        assert any(workflow["id"] == data["id"] for workflow in listed.json())

    def test_workflow_failure_propagates(self, client, auth_headers):
        response = client.post(
            "/api/v1/workflows",
            json={
                "name": "Broken release workflow",
                "stages": [
                    {
                        "name": "Release",
                        "task": "Attempt external release without reviewer lineage.",
                        "compliance_policy": "default",
                        "budget_cents": 1200,
                        "stage_role": "release",
                    }
                ],
            },
            headers=auth_headers,
        )
        assert response.status_code == 201
        workflow_id = response.json()["id"]

        final = self._poll_workflow(client, workflow_id, auth_headers)
        assert final is not None
        assert final["status"] == "failed"
        assert final["stages"][0]["status"] == "failed"
        assert "upstream execution" in final["stages"][0]["error"].lower()

    def test_workflow_export_shape(self, client, auth_headers):
        me = client.get("/api/v1/auth/me", headers=auth_headers)
        assert me.status_code == 200
        user = me.json()

        execution = Execution(
            id="exec-workflow-export",
            user_id=user["id"],
            task="Draft a minimum-necessary intake artifact.",
            status=ExecutionStatus.COMPLETED,
            completed_at=time.time(),
            results={
                "output": "Internal intake artifact prepared",
                "steps": [
                    {
                        "step_index": 1,
                        "tool_name": "intake_summarizer",
                        "tool_output": "ok",
                        "verified": True,
                        "certificate_id": "cert-workflow-export-1",
                    }
                ],
            },
            certificates=[],
        )
        client.app.state.state_store._executions[execution.id] = execution

        workflow = Workflow(
            id="workflow-export-shape",
            user_id=user["id"],
            user_role=user["role"],
            name="Exportable workflow",
            description="Validate workflow export schema",
            status=WorkflowStatus.COMPLETED,
            completed_at=time.time(),
            current_stage_index=0,
            stages=[
                WorkflowStage(
                    id="stage-export-1",
                    name="Intake",
                    task=execution.task,
                    compliance_policy="default",
                    budget_cents=1500,
                    stage_role="worker",
                    status=WorkflowStageStatus.COMPLETED,
                    execution_id=execution.id,
                    started_at=time.time() - 1,
                    completed_at=time.time(),
                    output_summary="Internal intake artifact prepared",
                )
            ],
        )
        client.app.state.workflow_store._workflows[workflow.id] = workflow

        exported = client.get(f"/api/v1/workflows/{workflow.id}/export", headers=auth_headers)
        assert exported.status_code == 200
        assert "attachment; filename=" in exported.headers["content-disposition"]

        payload = exported.json()
        assert set(payload.keys()) == {"workflow", "exported_at", "stages"}
        assert payload["workflow"]["id"] == workflow.id
        assert payload["workflow"]["status"] == "completed"
        assert len(payload["stages"]) == 1
        assert payload["stages"][0]["stage"]["execution_id"] is not None
        assert payload["stages"][0]["execution"]["id"] == payload["stages"][0]["stage"]["execution_id"]
        assert payload["stages"][0]["compliance_package"] is not None

    def test_cancel_workflow_marks_inflight_stages_cancelled(self, client, auth_headers, monkeypatch):
        original_execute = client.app.state.executor.execute

        async def delayed_execute(execution_id):
            await asyncio.sleep(0.2)
            return await original_execute(execution_id)

        monkeypatch.setattr(client.app.state.executor, "execute", delayed_execute)

        response = client.post(
            "/api/v1/workflows",
            json={
                "name": "Cancellable workflow",
                "stages": [
                    {
                        "name": "Stage 1",
                        "task": "Review an internal dossier and prepare a structured internal-only analysis.",
                        "compliance_policy": "default",
                        "budget_cents": 1500,
                        "stage_role": "intake",
                    },
                    {
                        "name": "Stage 2",
                        "task": "Perform a second-pass review and produce a recommendation.",
                        "compliance_policy": "default",
                        "budget_cents": 1500,
                        "stage_role": "reviewer",
                    },
                ],
            },
            headers=auth_headers,
        )
        assert response.status_code == 201
        workflow_id = response.json()["id"]

        cancelled = client.delete(f"/api/v1/workflows/{workflow_id}", headers=auth_headers)
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"

        final = self._poll_workflow(client, workflow_id, auth_headers)
        assert final is not None
        assert final["status"] == "cancelled"
        assert all(stage["status"] != "running" for stage in final["stages"])
        assert all(stage["status"] in ("completed", "cancelled") for stage in final["stages"])


# ── Compliance Export ──


class TestComplianceExport:
    def _submit(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={"task": "Export test"},
                        headers=auth_headers)
        return r.json()["execution_id"]

    def test_export_default(self, client, auth_headers):
        eid = self._submit(client, auth_headers)
        r = client.get(f"/api/v1/compliance/{eid}/export", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["compliance_regime"] == "Default"
        assert "attestation" in data

    def test_export_hipaa(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={
            "task": "Export hipaa test",
            "compliance_policy": "hipaa",
        }, headers=auth_headers)
        eid = r.json()["execution_id"]
        r = client.get(f"/api/v1/compliance/{eid}/export?preset=hipaa",
                       headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["compliance_regime"] == "HIPAA"
        assert data["policy_applied"]["name"] == "HIPAA"

    def test_export_infers_execution_policy(self, client, auth_headers):
        r = client.post("/api/v1/tasks", json={
            "task": "Export inferred hipaa test",
            "compliance_policy": "hipaa",
        }, headers=auth_headers)
        eid = r.json()["execution_id"]

        exported = client.get(f"/api/v1/compliance/{eid}/export", headers=auth_headers)
        assert exported.status_code == 200
        data = exported.json()
        assert data["compliance_regime"] == "HIPAA"
        assert data["policy_applied"]["name"] == "HIPAA"

    def test_export_missing_execution(self, client, auth_headers):
        r = client.get("/api/v1/compliance/nonexistent/export",
                       headers=auth_headers)
        assert r.status_code == 404

    def test_export_invalid_preset(self, client, auth_headers):
        eid = self._submit(client, auth_headers)
        r = client.get(f"/api/v1/compliance/{eid}/export?preset=gdpr",
                       headers=auth_headers)
        assert r.status_code == 400

    def test_export_includes_runtime_evidence(self, client, auth_headers):
        execution = Execution(
            id="exec-rich-export",
            user_id="dev-admin",
            task="Review quarterly expense report",
            status=ExecutionStatus.COMPLETED,
            completed_at=time.time(),
            results={
                "output": "SOX review completed",
                "steps": [
                    {
                        "step_index": 1,
                        "tool_name": "expense_audit",
                        "tool_output": "ok",
                        "verified": True,
                        "certificate_id": "cert-expense-1",
                        "verification_properties": [
                            "capability_coverage: proven",
                            "budget_sufficient: proven",
                        ],
                        "ifc": {
                            "effective_level": "mnpi",
                            "promoted": True,
                            "flow_blocked": False,
                        },
                        "lean_verification": {"proven": True},
                        "lean_proven": True,
                    }
                ],
                "audit_trail": [
                    {"timestamp": time.time(), "action": "verification", "result": "ok"}
                ],
                "ifc_summary": {"flows_checked": 1, "flows_blocked": 0, "violations": []},
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
                        "input_labels": ["Sensitive"],
                        "output_label": "Internal",
                    }
                ],
                "verification_profile": {
                    "stage_role": "reviewer",
                    "required_proofs": ["capability_coverage", "information_flow"],
                },
            },
            certificates=[],
            token_data={
                "verification_profile": {
                    "stage_role": "reviewer",
                    "required_proofs": ["capability_coverage", "information_flow"],
                }
            },
        )
        client.app.state.state_store._executions[execution.id] = execution

        r = client.get(
            f"/api/v1/compliance/{execution.id}/export?preset=sox",
            headers=auth_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["certificates"][0]["id"] == "cert-expense-1"
        assert data["flow_analysis"]["flows_tracked"] == 1
        assert len(data["audit_trail"]) == 1
        assert any(cert["type"] == "lean_flow_certificate" for cert in data["certificates"])
        assert data["execution_summary"]["verification_profile"]["stage_role"] == "reviewer"

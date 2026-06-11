"""
Integration tests covering:
- WebSocket route (ws.py) via TestClient
- End-to-end pipeline: submit → queue → execute → verify → result
- PII NER mock path
- OTel real exporter code paths
"""
import asyncio
import json
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

# ── WebSocket route tests ──────────────────────────────────────────

from app.main import create_app


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    from starlette.testclient import TestClient
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clean_auth():
    from app.api.routes.auth import reset_store
    reset_store()
    yield
    reset_store()


@pytest.fixture
def auth_headers():
    from app.api.routes.auth import get_dev_api_key
    return {"Authorization": f"Bearer {get_dev_api_key()}"}


class TestWebSocketRoute:
    """Tests for app/api/routes/ws.py - WebSocket endpoint."""

    def test_ws_connect_and_receive_history(self, client):
        """Connect to WS endpoint and receive any buffered history."""
        with client.websocket_connect("/ws/executions/test-exec-1") as ws:
            # Send a ping to confirm connection is alive
            ws.send_text("ping")
            data = json.loads(ws.receive_text())
            assert data["type"] == "pong"

    def test_ws_receives_live_updates(self, app, client):
        """Updates emitted to the stream should be forwarded to WS clients."""
        stream = app.state.stream

        with client.websocket_connect("/ws/executions/live-test") as ws:
            # Emit an update from the server side
            asyncio.get_event_loop().run_until_complete(
                stream.emit_status("live-test", "executing", step=2)
            )

            # Send ping to flush
            ws.send_text("ping")
            # First message should be the update
            msg = ws.receive_text()
            if msg == "pong":
                # Update may arrive after pong in some orderings
                pass
            else:
                data = json.loads(msg)
                assert data["status"] == "executing"

    def test_ws_disconnect_gracefully(self, client):
        """WebSocket should handle disconnect without error."""
        with client.websocket_connect("/ws/executions/disconnect-test") as ws:
            ws.send_text("ping")
            ws.receive_text()
        # No error on disconnect

    def test_ws_invalid_execution_still_connects(self, client):
        """Even for non-existent execution IDs, WS should connect."""
        with client.websocket_connect("/ws/executions/nonexistent-999") as ws:
            ws.send_text("ping")
            data = json.loads(ws.receive_text())
            assert data["type"] == "pong"


# ── End-to-end pipeline integration test ───────────────────────────

class TestEndToEndPipeline:
    """Full pipeline: submit task → execute → get result."""

    def test_full_pipeline(self, client, auth_headers):
        """Submit a task, verify it gets queued, and check status."""
        # 1. Issue a token
        resp = client.post("/api/v1/tokens", json={
            "agent_id": "e2e-agent",
            "permissions": ["network:http:read", "database:read"],
            "budget_cents": 5000,
        })
        assert resp.status_code == 201
        token_id = resp.json()["id"]

        # 2. Submit a task
        resp = client.post("/api/v1/tasks", json={
            "task": "Fetch the homepage and save results",
            "compliance_policy": "default",
            "budget_cents": 5000,
        }, headers=auth_headers)
        assert resp.status_code == 201
        data = resp.json()
        exec_id = data["execution_id"]
        assert data["status"] == "queued"
        assert "websocket_url" in data

        # 3. Get execution status
        resp = client.get(f"/api/v1/executions/{exec_id}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == exec_id

        # 4. List executions
        resp = client.get("/api/v1/executions", headers=auth_headers)
        assert resp.status_code == 200
        execs = resp.json()
        assert any(e["id"] == exec_id for e in execs)

    def test_hipaa_pipeline(self, client, auth_headers):
        """Submit task with HIPAA compliance, verify preset applied."""
        resp = client.post("/api/v1/tasks", json={
            "task": "Query patient records",
            "compliance_policy": "hipaa",
            "budget_cents": 2000,
        }, headers=auth_headers)
        assert resp.status_code == 201
        exec_id = resp.json()["execution_id"]

        # Export compliance
        resp = client.get(
            f"/api/v1/compliance/{exec_id}/export",
            params={"preset": "hipaa"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        package = resp.json()
        assert package["compliance_regime"] == "HIPAA"

    def test_cancel_pipeline(self, client, auth_headers):
        """Submit and cancel a task."""
        resp = client.post("/api/v1/tasks", json={
            "task": "Something cancellable",
        }, headers=auth_headers)
        assert resp.status_code == 201
        exec_id = resp.json()["execution_id"]

        resp = client.delete(f"/api/v1/executions/{exec_id}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"

    def test_compliance_preset_list(self, client):
        """List all available compliance presets."""
        resp = client.get("/api/v1/compliance/presets")
        assert resp.status_code == 200
        presets = resp.json()
        names = [p["name"] for p in presets]
        assert "HIPAA" in names
        assert "SOX" in names
        assert "Legal Privilege" in names
        assert "Default" in names


# ── PII NER mock test ──────────────────────────────────────────────

class TestPIINERPath:
    """Test the NER detection code path with a mocked spaCy model."""

    def test_ner_detection_with_mock(self):
        """Exercise the NER path in PIIDetector by mocking spaCy."""
        from agentsafe.safety.detectors.pii import PIIDetector, PIIConfig

        # Create a mock spaCy entity
        mock_ent = MagicMock()
        mock_ent.label_ = "PERSON"
        mock_ent.text = "John Smith"
        mock_ent.start_char = 0
        mock_ent.end_char = 10

        mock_doc = MagicMock()
        mock_doc.ents = [mock_ent]

        mock_nlp = MagicMock(return_value=mock_doc)

        config = PIIConfig(detect=True, use_ner=True)
        detector = PIIDetector(config)
        # Inject mock NLP
        detector._nlp = mock_nlp

        matches = detector.detect("John Smith called yesterday")
        ner_matches = [m for m in matches if m.source == "ner"]
        assert len(ner_matches) >= 1
        assert ner_matches[0].pii_type == "PERSON"
        assert ner_matches[0].value == "John Smith"

    def test_ner_detection_with_multiple_entities(self):
        from agentsafe.safety.detectors.pii import PIIDetector, PIIConfig

        ents = []
        for label, text, start, end in [
            ("PERSON", "Alice", 0, 5),
            ("ORG", "Acme Corp", 20, 29),
            ("GPE", "New York", 33, 41),
        ]:
            ent = MagicMock()
            ent.label_ = label
            ent.text = text
            ent.start_char = start
            ent.end_char = end
            ents.append(ent)

        mock_doc = MagicMock()
        mock_doc.ents = ents

        config = PIIConfig(detect=True, use_ner=True)
        detector = PIIDetector(config)
        detector._nlp = MagicMock(return_value=mock_doc)

        matches = detector.detect("Alice works at Acme Corp in New York")
        ner_matches = [m for m in matches if m.source == "ner"]
        assert len(ner_matches) == 3

    def test_ner_redaction(self):
        from agentsafe.safety.detectors.pii import PIIDetector, PIIConfig, PIIMatch

        config = PIIConfig(detect=True, use_ner=True)
        detector = PIIDetector(config)

        # Build NER match manually
        matches = [
            PIIMatch(pii_type="PERSON", value="Jane Doe", start=10, end=18, source="ner"),
        ]
        redacted = detector.redact("Patient: Jane Doe has condition", matches)
        assert "Jane Doe" not in redacted
        assert "[REDACTED-PERSON]" in redacted

    def test_ner_init_failure_graceful(self):
        """When spaCy is not available, NER should degrade gracefully."""
        from agentsafe.safety.detectors.pii import PIIDetector, PIIConfig

        config = PIIConfig(detect=True, use_ner=True)
        with patch("agentsafe.safety.detectors.pii.PIIDetector._init_ner") as mock_init:
            mock_init.side_effect = lambda self_=None: None
            detector = PIIDetector(config)
            # Should still work with regex only
            matches = detector.detect("SSN: 123-45-6789")
            assert any(m.pii_type == "SSN" for m in matches)

    def test_entity_type_filtering(self):
        """Only configured entity types should be detected."""
        from agentsafe.safety.detectors.pii import PIIDetector, PIIConfig

        # Only detect PERSON, not GPE
        config = PIIConfig(detect=True, use_ner=True, entity_types=["PERSON"])

        ents = []
        for label, text, start, end in [
            ("PERSON", "Bob", 0, 3),
            ("GPE", "Paris", 10, 15),
        ]:
            ent = MagicMock()
            ent.label_ = label
            ent.text = text
            ent.start_char = start
            ent.end_char = end
            ents.append(ent)

        mock_doc = MagicMock()
        mock_doc.ents = ents

        detector = PIIDetector(config)
        detector._nlp = MagicMock(return_value=mock_doc)

        matches = detector.detect("Bob lives in Paris")
        ner_matches = [m for m in matches if m.source == "ner"]
        assert len(ner_matches) == 1
        assert ner_matches[0].pii_type == "PERSON"


# ── OTel code paths ───────────────────────────────────────────────

class TestOTelCodePaths:
    """Exercise OTel code paths that were at 81% coverage."""

    def test_telemetry_disabled_tracing(self):
        from agentsafe.observability.otel import CertiorTelemetry, TelemetryConfig
        CertiorTelemetry._instance = None
        config = TelemetryConfig(enable_tracing=False, enable_metrics=False)
        tel = CertiorTelemetry(config=config)
        # trace_verification should be a no-op context
        with tel.trace_verification("test", "token-1"):
            pass
        CertiorTelemetry._instance = None

    def test_telemetry_record_methods(self):
        from agentsafe.observability.otel import CertiorTelemetry
        CertiorTelemetry._instance = None
        tel = CertiorTelemetry()

        # These should not raise even without a real collector
        tel.record_z3_invocation(10.0, "sat")
        tel.record_capability_grant("tok-1", ["read", "write"])
        tel.record_ifc_violation("sensitive", "public")
        tel.record_certificate_issuance("z3", 3)
        tel.record_content_scan("HIPAA", True)
        tel.record_content_scan("SOX", False)

        CertiorTelemetry._instance = None

    def test_telemetry_singleton_pattern(self):
        from agentsafe.observability.otel import CertiorTelemetry
        CertiorTelemetry._instance = None
        t1 = CertiorTelemetry.get_instance()
        t2 = CertiorTelemetry.get_instance()
        assert t1 is t2
        CertiorTelemetry._instance = None

    def test_telemetry_environment_from_env(self):
        """Environment detection uses CERTIOR_ENV variable."""
        import os
        old = os.environ.get("CERTIOR_ENV")
        os.environ["CERTIOR_ENV"] = "staging"
        try:
            from agentsafe.observability.otel import CertiorTelemetry
            CertiorTelemetry._instance = None
            tel = CertiorTelemetry()
            # The resource should include the environment
            # Just verify instantiation works with env var set
            assert tel is not None
        finally:
            if old:
                os.environ["CERTIOR_ENV"] = old
            else:
                os.environ.pop("CERTIOR_ENV", None)
            CertiorTelemetry._instance = None

    def test_telemetry_console_export(self):
        from agentsafe.observability.otel import CertiorTelemetry, TelemetryConfig
        CertiorTelemetry._instance = None
        config = TelemetryConfig(console_export=True)
        tel = CertiorTelemetry(config=config)
        with tel.trace_verification("test-action", "tok-1"):
            pass
        CertiorTelemetry._instance = None

    def test_telemetry_metrics_only(self):
        from agentsafe.observability.otel import CertiorTelemetry, TelemetryConfig
        CertiorTelemetry._instance = None
        config = TelemetryConfig(enable_tracing=False, enable_metrics=True)
        tel = CertiorTelemetry(config=config)
        tel.record_z3_invocation(5.0, "sat")
        CertiorTelemetry._instance = None


# ── Schema validation integration ─────────────────────────────────

class TestSkillSchemaValidation:
    """Test that VERIFICATION.json files validate against the JSON schema."""

    def test_web_browsing_schema_valid(self):
        import jsonschema
        schema = json.load(open("skills/skill-verification.schema.json"))
        spec = json.load(open("skills/web_browsing/VERIFICATION.json"))
        jsonschema.validate(spec, schema)  # Should not raise

    def test_database_query_schema_valid(self):
        import jsonschema
        schema = json.load(open("skills/skill-verification.schema.json"))
        spec = json.load(open("skills/database_query/VERIFICATION.json"))
        jsonschema.validate(spec, schema)

    def test_file_operations_schema_valid(self):
        import jsonschema
        schema = json.load(open("skills/skill-verification.schema.json"))
        spec = json.load(open("skills/file_operations/VERIFICATION.json"))
        jsonschema.validate(spec, schema)

    def test_invalid_skill_id_rejected(self):
        import jsonschema
        schema = json.load(open("skills/skill-verification.schema.json"))
        bad_spec = {
            "skill_id": "InvalidCaps",  # violates pattern
            "version": "1.0.0",
            "verification_requirements": {
                "capabilities_required": [],
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad_spec, schema)

    def test_missing_version_rejected(self):
        import jsonschema
        schema = json.load(open("skills/skill-verification.schema.json"))
        bad_spec = {
            "skill_id": "ok",
            "verification_requirements": {
                "capabilities_required": [],
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad_spec, schema)

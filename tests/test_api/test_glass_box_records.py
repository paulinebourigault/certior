from fastapi.testclient import TestClient

from app.main import create_app


def test_glass_box_record_is_persisted_with_hash(tmp_path, monkeypatch):
    monkeypatch.setenv("CERTIOR_DATA_DIR", str(tmp_path))
    client = TestClient(create_app())

    payload = {
        "exported_at": "2026-05-01T00:00:00Z",
        "source": "/api/v1/agents/delegation-graph",
        "view": "Certior Agent Glass Box",
        "mode": "replay",
        "active_phase": "Blocked privilege escalation",
        "visible_events": 13,
        "total_events": 13,
        "blocked_events": 1,
        "boundary_view": True,
        "boundary_model": {
            "engine": "Lean4",
            "purpose": "Capability, permission, and budget bounds for orchestrated agents",
        },
        "use_cases": ["Healthcare", "Financial controls"],
        "selected_inspection": {"status": "blocked"},
        "graph": {
            "nodes": [{"id": "PHI Detector Agent"}],
            "edges": [{"id": "blocked-edge", "status": "blocked"}],
        },
    }

    response = client.post("/api/v1/agents/glass-box-records", json=payload)

    assert response.status_code == 200
    record = response.json()
    assert record["id"].startswith("gbr_")
    assert record["record_hash"].startswith("sha256:")
    assert record["blocked_events"] == 1

    list_response = client.get("/api/v1/agents/glass-box-records?limit=1")
    assert list_response.status_code == 200
    assert list_response.json()[0]["id"] == record["id"]
    assert (tmp_path / "glass_box_records" / "records.jsonl").exists()
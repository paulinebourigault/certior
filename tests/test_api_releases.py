import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

@pytest.fixture
def client():
    from app.main import create_app 
    app = create_app()
    # Override auth for test
    from app.api.routes.auth import get_current_user, User, UserRole
    
    def override_get_current_user():
        return User(
            id="1", 
            email="test@example.com", 
            role=UserRole.ADMIN
        )

    app.dependency_overrides[get_current_user] = override_get_current_user
    
    with TestClient(app) as c:
        yield c

@patch("app.api.routes.releases._get_tools")
def test_get_release_decision(mock_get_tools, client):
    mock_tools = MagicMock()
    mock_get_tools.return_value = mock_tools

    # Setup the mock async return from PgVerificationGraphStore dict output
    async def mock_release_decision(*args, **kwargs):
        return {
            "decision": {
                "decision_status": "attested",
                "remediation_items": [
                    {
                        "severity": "degraded",
                        "owner_subsystem": "test-sec",
                        "message": "just a warning",
                        "code": "WARN-01",
                        "remediation_steps": ["Fix it"]
                    },
                    {
                        "severity": "blocking",
                        "owner_subsystem": "test-sec",
                        "message": "real blocker",
                        "code": "BLOCK-01",
                        "remediation_steps": ["Blocker fix"]
                    }
                ]
            },
            "provenance": {
                "components": [
                    {"name": "test-repo", "version": "v1.0.0", "source_commit": "abcdef!"}
                ]
            }
        }
    
    mock_tools.release_decision = mock_release_decision

    resp = client.get("/api/v1/releases/decision?repo_root=my-repo")
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "SHIP"
    assert data["repo_root"] == "my-repo"
    
    assert len(data["blockers"]) == 1
    assert data["blockers"][0]["reason"] == "real blocker"

    assert len(data["explanation"]) == 2
    assert data["explanation"][0]["policy"] == "WARN-01"
    
    assert len(data["provenance"]["components"]) == 1
    assert data["provenance"]["components"][0]["name"] == "test-repo"

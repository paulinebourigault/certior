import pytest
import os
os.environ["DATABASE_URL"] = "postgresql://certior:certior@127.0.0.1:5432/certior"
from fastapi.testclient import TestClient
from app.main import create_app

app = create_app()
client = TestClient(app)

def test_trust_badge_endpoint():
    response = client.get("/api/v1/trust/badge?repo=test/repo&commit=123")
    assert response.status_code == 200
    assert "image/svg+xml" in response.headers["content-type"]
    assert "<svg" in response.text
    # Should say "Unknown" because test/repo doesnt exist in DB
    assert "Unknown" in response.text

def test_github_webhook_endpoint_ignored():
    response = client.post("/api/v1/releases/github-webhook", json={"other": "event"})
    assert response.status_code == 200
    assert response.json() == {"status": "ignored", "reason": "not a pull_request event"}

def test_github_webhook_endpoint_opened():
    payload = {
        "action": "opened",
        "pull_request": {
            "head": {"sha": "abcdef"},
            "number": 1
        },
        "repository": {
            "full_name": "test/repo",
            "html_url": "https://github.com/test/repo"
        }
    }
    response = client.post("/api/v1/releases/github-webhook", json=payload)
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["status"] in ["processed", "error"]


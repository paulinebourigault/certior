"""Tests for secrets detection."""
import pytest
from agentsafe.safety.detectors.secrets import SecretsDetector


class TestSecretsDetector:
    def test_detect_aws_key(self):
        d = SecretsDetector()
        matches = d.detect("key: AKIAIOSFODNN7EXAMPLE")
        assert len(matches) >= 1
        assert any(m.secret_type == "AWS_ACCESS_KEY" for m in matches)

    def test_detect_github_token(self):
        d = SecretsDetector()
        matches = d.detect("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert any(m.secret_type == "GITHUB_TOKEN" for m in matches)

    def test_detect_generic_api_key(self):
        d = SecretsDetector()
        matches = d.detect('api_key = "sk_live_abcdefghijklmnopqrst"')
        assert any(m.secret_type == "GENERIC_API_KEY" for m in matches)

    def test_detect_private_key(self):
        d = SecretsDetector()
        matches = d.detect("-----BEGIN PRIVATE KEY-----")
        assert any(m.secret_type == "PRIVATE_KEY" for m in matches)

    def test_no_secrets(self):
        d = SecretsDetector()
        assert not d.has_secrets("Just a normal message")

    def test_truncated_value(self):
        d = SecretsDetector()
        matches = d.detect("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert "***" in matches[0].value  # Values are truncated

"""
Secrets detection - API keys, credentials, tokens.
"""
from __future__ import annotations
import re
from typing import List
from dataclasses import dataclass


@dataclass
class SecretMatch:
    secret_type: str
    value: str
    start: int
    end: int


# Patterns for common secret types
SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
    "AWS_SECRET_KEY": re.compile(r'\b([A-Za-z0-9/+=]{40})\b'),
    "GITHUB_TOKEN": re.compile(r'\b(ghp_[A-Za-z0-9]{36})\b'),
    "GENERIC_API_KEY": re.compile(r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9\-_]{20,})["\']?'),
    "GENERIC_SECRET": re.compile(r'(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{8,})["\']?'),
    "JWT_TOKEN": re.compile(r'\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b'),
    "PRIVATE_KEY": re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "SLACK_TOKEN": re.compile(r'\b(xox[bpras]-[A-Za-z0-9-]+)\b'),
}


class SecretsDetector:
    """Detects leaked secrets and credentials."""

    def detect(self, text: str) -> List[SecretMatch]:
        matches = []
        for secret_type, pattern in SECRET_PATTERNS.items():
            for m in pattern.finditer(text):
                matches.append(SecretMatch(
                    secret_type=secret_type,
                    value=m.group()[:10] + "***",  # Truncate for safety
                    start=m.start(), end=m.end(),
                ))
        return matches

    def has_secrets(self, text: str) -> bool:
        return len(self.detect(text)) > 0

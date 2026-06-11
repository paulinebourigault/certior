"""Web browsing skill implementation."""
import re
from typing import Dict, List

class SafeWebBrowser:
    def __init__(self, verification: Dict):
        self.verification = verification
        sc = verification.get("verification_requirements", {}).get("safety_constraints", {})
        self.allowlist = [re.compile(p) for p in sc.get("url_allowlist_patterns", [])]
        self.blocklist = [re.compile(p) for p in sc.get("url_blocklist_patterns", [])]

    def verify_url(self, url: str) -> bool:
        if not any(p.match(url) for p in self.allowlist):
            return False
        if any(p.match(url) for p in self.blocklist):
            return False
        return True

    async def fetch(self, url: str) -> str:
        if not self.verify_url(url):
            raise ValueError(f"URL not allowed: {url}")
        return f"<html>Content from {url}</html>"

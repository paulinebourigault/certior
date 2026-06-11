"""File operations skill implementation."""
import re, os
from typing import Dict

class SafeFileOperations:
    def __init__(self, verification: Dict):
        self.verification = verification
        sc = verification.get("verification_requirements", {}).get("safety_constraints", {})
        self.allowlist = [re.compile(p) for p in sc.get("path_allowlist_patterns", [])]
        self.blocklist = [re.compile(p) for p in sc.get("path_blocklist_patterns", [])]
        self.allowed_ext = set(sc.get("allowed_extensions", []))
        rc = verification.get("verification_requirements", {}).get("resource_constraints", {})
        self.max_size = rc.get("max_file_size_bytes", 10_000_000)

    def verify_path(self, path: str) -> bool:
        if ".." in path:
            return False
        if not any(p.match(path) for p in self.allowlist):
            return False
        if any(p.match(path) for p in self.blocklist):
            return False
        _, ext = os.path.splitext(path)
        if self.allowed_ext and ext not in self.allowed_ext:
            return False
        return True

    async def read(self, path: str) -> str:
        if not self.verify_path(path):
            raise ValueError(f"Path not allowed: {path}")
        return f"Content of {path}"

    async def write(self, path: str, content: str) -> bool:
        if not self.verify_path(path):
            raise ValueError(f"Path not allowed: {path}")
        if len(content.encode()) > self.max_size:
            raise ValueError(f"Content exceeds size limit")
        return True

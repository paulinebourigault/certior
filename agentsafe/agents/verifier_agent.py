"""
VerifierAgent - output validation with content safety.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.safety.scanner import ContentScanner, ContentSafetyPolicy, ScanResult
from .base import VerifiedAgent


@dataclass
class OutputVerificationResult:
    valid: bool = True
    violations: List[str] = field(default_factory=list)
    output: Any = None
    labels: List[str] = field(default_factory=list)
    scan_result: Optional[ScanResult] = None


class VerifierAgent(VerifiedAgent):
    """Validates execution outputs for safety and compliance."""

    def __init__(
        self, agent_id: str, capability_token: CapabilityToken,
        llm_client: Any = None,
        content_policy: Optional[ContentSafetyPolicy] = None,
    ):
        super().__init__(agent_id, capability_token, llm_client)
        self.content_policy = content_policy or ContentSafetyPolicy.default()
        self.scanner = ContentScanner(self.content_policy)

    async def verify_output(
        self, output: Any,
        expected_labels: Optional[List[str]] = None,
    ) -> OutputVerificationResult:
        violations = []
        output_str = str(output) if output is not None else ""

        # Content safety scan
        scan = self.scanner.scan(output_str)
        if not scan.clean:
            for v in scan.violations:
                violations.append(f"{v.category.value}: {v.details or v.matched_text}")

        # Use redacted content if available
        final_output = scan.redacted_text if scan.redacted_text else output

        return OutputVerificationResult(
            valid=len(violations) == 0,
            violations=violations,
            output=final_output,
            scan_result=scan,
        )

"""
SafeVerifier - content safety integrated into verification pipeline.

Production hardening:
  A1: Validates ``token.is_valid()`` when a ``CapabilityToken`` is passed.
  A3: Intersects action capabilities with the compliance policy ceiling
      (forbidden permissions are rejected; capabilities exceeding the
      policy max_permissions are flagged).
"""
from __future__ import annotations
import functools
import time
from typing import Any, Dict, List, Optional, Callable, Sequence
from dataclasses import dataclass, field

from agentsafe.safety.scanner import ContentScanner, ContentSafetyPolicy, ScanResult
from agentsafe.safety.detectors.pii import PIIMatch
from agentsafe.observability.otel import CertiorTelemetry


class ContentSafetyError(Exception):
    def __init__(self, violations: list, message: str = "Content safety violation"):
        self.violations = violations
        super().__init__(message)


@dataclass
class SafetyVerificationResult:
    approved: bool = True
    safety_violations: List[str] = field(default_factory=list)
    pii_detected: List[PIIMatch] = field(default_factory=list)
    redacted_content: Optional[str] = None
    scan_result: Optional[ScanResult] = None
    verification_result: Optional[Dict] = None
    token_error: Optional[str] = None
    permission_denials: List[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return self.approved and not self.safety_violations


class SafeVerifier:
    """Verifier that enforces content safety policies.

    Production hardening
    --------------------
    A1  When a ``CapabilityToken`` is supplied, ``is_valid()`` is checked
        before any scanning or inner verification.  Expired / tampered /
        exhausted tokens are rejected immediately.
    A3  When a ``ComplianceConfig`` is attached (via *compliance_config*),
        action capabilities are intersected with the compliance policy:
        forbidden permissions block the request; permissions outside
        the policy ceiling produce denials.
    """

    def __init__(
        self,
        policy: ContentSafetyPolicy,
        inner_verifier: Any = None,
        compliance_config: Any = None,
    ):
        self.policy = policy
        self.scanner = ContentScanner(policy)
        self._inner = inner_verifier
        self._compliance = compliance_config
        self._tel = CertiorTelemetry.get_instance()

    async def verify_and_scan(
        self, action: Any = None, token: Any = None,
        content: str = "", **kwargs,
    ) -> SafetyVerificationResult:
        result = SafetyVerificationResult()

        # ── A1: Token validity gate ────────────────────────────────
        if token is not None and hasattr(token, "is_valid"):
            if not token.is_valid():
                reason = getattr(token, "validation_error", lambda: "token_invalid")()
                token_id = getattr(token, "id", "unknown")
                result.approved = False
                result.token_error = reason
                result.safety_violations.append(
                    f"Token invalid ({reason}): {token_id}"
                )
                self._tel.verifications_blocked.add(
                    1, {"action": "safety_verify", "reason": reason or "token_invalid"},
                )
                return result

        # ── A3: Compliance permission intersection ─────────────────
        if self._compliance is not None and action is not None:
            required_caps = getattr(action, "required_capabilities", None)
            if required_caps:
                denials = self._check_compliance_permissions(
                    required_caps, self._compliance,
                )
                if denials:
                    result.approved = False
                    result.permission_denials = denials
                    result.safety_violations.extend(denials)
                    return result

        # Content safety scan
        if content:
            scan = self.scanner.scan(content)
            result.scan_result = scan
            result.pii_detected = scan.pii_detected
            result.redacted_content = scan.redacted_text

            self._tel.record_content_scan(self.policy.name, scan.clean)

            if not scan.safe_to_proceed:
                result.approved = False
                result.safety_violations = [
                    f"{v.category.value}: {v.details or v.matched_text}"
                    for v in scan.violations
                ]
                if scan.pii_found and not scan.remediated:
                    result.safety_violations.append(
                        "PII detected but redaction not enabled"
                    )
                return result

        # Inner verification
        if self._inner and hasattr(self._inner, 'verify_action'):
            try:
                inner_result = await self._inner.verify_action(
                    action=action, token=token, **kwargs,
                )
                result.verification_result = inner_result
            except Exception as e:
                result.approved = False
                result.safety_violations.append(f"Verification failed: {e}")

        return result

    def scan_content(self, content: str) -> ScanResult:
        return self.scanner.scan(content)

    def requires_approval(self, action_name: str) -> bool:
        return self.scanner.requires_approval(action_name)

    # ── A3: compliance permission checking ─────────────────────────

    @staticmethod
    def _check_compliance_permissions(
        required_capabilities: Sequence[str],
        compliance_config: Any,
    ) -> List[str]:
        """
        Check required capabilities against compliance policy constraints.

        Returns a list of denial descriptions (empty = all clear).
        """
        denials: List[str] = []

        forbidden = getattr(compliance_config, "forbidden_permissions", [])
        max_perms = getattr(compliance_config, "max_permissions", [])
        policy_name = getattr(compliance_config, "name", "unknown")

        for cap in required_capabilities:
            # Forbidden check (highest priority)
            if _perm_matches_any(cap, forbidden):
                denials.append(
                    f"Permission '{cap}' forbidden by '{policy_name}' policy"
                )
                continue

            # Ceiling check (if the policy has an explicit ceiling)
            if max_perms and max_perms != ["*"]:
                if not _perm_covered_by(cap, max_perms):
                    denials.append(
                        f"Permission '{cap}' exceeds '{policy_name}' "
                        f"policy ceiling"
                    )

        return denials


def _perm_matches_any(perm: str, patterns: Sequence[str]) -> bool:
    """True if *perm* is matched by any entry in *patterns* (wildcards)."""
    for p in patterns:
        if p == perm:
            return True
        if p.endswith("*") and perm.startswith(p[:-1]):
            return True
    return False


def _perm_covered_by(perm: str, allowed: Sequence[str]) -> bool:
    """True if *perm* is covered by the allowed set (wildcards)."""
    for a in allowed:
        if a == perm or a == "*":
            return True
        if a.endswith("*") and perm.startswith(a[:-1]):
            return True
    return False


class ComplianceVerifier:
    """Pre-built verifiers for specific compliance regimes.

    Each factory method wires the matching ``ComplianceConfig`` into
    the ``SafeVerifier`` so that A3 permission intersection is active.
    """
    _hipaa: Optional[SafeVerifier] = None
    _sox: Optional[SafeVerifier] = None
    _legal: Optional[SafeVerifier] = None

    @classmethod
    def hipaa(cls) -> SafeVerifier:
        if cls._hipaa is None:
            from agentsafe.compliance.presets import CompliancePresets
            cls._hipaa = SafeVerifier(
                ContentSafetyPolicy.hipaa_compliant(),
                compliance_config=CompliancePresets.hipaa(),
            )
        return cls._hipaa

    @classmethod
    def sox(cls) -> SafeVerifier:
        if cls._sox is None:
            from agentsafe.compliance.presets import CompliancePresets
            cls._sox = SafeVerifier(
                ContentSafetyPolicy.sox_compliant(),
                compliance_config=CompliancePresets.sox(),
            )
        return cls._sox

    @classmethod
    def legal(cls) -> SafeVerifier:
        if cls._legal is None:
            from agentsafe.compliance.presets import CompliancePresets
            cls._legal = SafeVerifier(
                ContentSafetyPolicy.legal_privilege(),
                compliance_config=CompliancePresets.legal_privilege(),
            )
        return cls._legal

    @classmethod
    def reset(cls):
        cls._hipaa = cls._sox = cls._legal = None


def get_hipaa_verifier() -> SafeVerifier:
    return ComplianceVerifier.hipaa()

def get_sox_verifier() -> SafeVerifier:
    return ComplianceVerifier.sox()

def get_legal_verifier() -> SafeVerifier:
    return ComplianceVerifier.legal()


def with_safety_check(policy: ContentSafetyPolicy):
    """Decorator to add safety scanning to any async function."""
    def decorator(fn: Callable):
        scanner = ContentScanner(policy)
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            content = kwargs.get("content", "")
            if isinstance(content, str) and content:
                result = scanner.scan(content)
                if not result.safe_to_proceed:
                    raise ContentSafetyError(
                        [v.matched_text for v in result.violations]
                        + (["Unremediated PII detected"] if result.pii_found and not result.remediated else [])
                    )
            return await fn(*args, **kwargs)
        return wrapper
    return decorator


async def verify_with_safety(
    content: str, policy: ContentSafetyPolicy,
    action: Any = None, token: Any = None,
) -> SafetyVerificationResult:
    verifier = SafeVerifier(policy)
    return await verifier.verify_and_scan(
        action=action, token=token, content=content,
    )

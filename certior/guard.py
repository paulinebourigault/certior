"""
certior.guard - The single entry point for verified agent safety.
================================================================

Guard wraps Certior's verification, content safety, and capability
system behind a minimal API that any agent framework can call.

Design principles:
  - Zero mandatory config (sensible defaults)
  - One import, one class, three methods
  - Works synchronously or async
  - Framework-agnostic: no dependency on LangChain, CrewAI, etc.
  - Thread-safe for multi-agent orchestrators
"""
from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
from typing import (
    Any, Callable, Dict, List, Optional, Sequence, TypeVar, Union,
)

log = logging.getLogger("certior")

# ── Lazy imports (keep cold-start fast) ──────────────────────────────

_INTERNALS_LOADED = False
_CapabilityToken = None
_ContentScanner = None
_ContentSafetyPolicy = None
_PIIDetector = None
_Z3Verifier = None
_CertificateAuthority = None


def _load_internals():
    global _INTERNALS_LOADED, _CapabilityToken, _ContentScanner
    global _ContentSafetyPolicy, _PIIDetector, _Z3Verifier, _CertificateAuthority
    if _INTERNALS_LOADED:
        return
    from agentsafe.capabilities.tokens import CapabilityToken as _CT
    from agentsafe.safety.scanner import ContentScanner as _CS, ContentSafetyPolicy as _CSP
    from agentsafe.safety.detectors.pii import PIIDetector as _PII
    from agentsafe.verification.z3_optimizer import IncrementalZ3Verifier as _Z3V
    from agentsafe.kernel import CertificateAuthority as _CA
    _CapabilityToken = _CT
    _ContentScanner = _CS
    _ContentSafetyPolicy = _CSP
    _PIIDetector = _PII
    _Z3Verifier = _Z3V
    _CertificateAuthority = _CA
    _INTERNALS_LOADED = True


# ── Lean policy-model attestation ────────────────────────────────────
# The runtime gate is Z3 (fast). The policy MODEL the gate enforces (lattice,
# delegation, IFC, composition) is machine-checked in Lean 4 - see
# `lean4/CertiorLattice/Certior/Audit.lean`. We bind every signed cert to a
# short SHA fingerprint of the Lean source so each receipt provably ties to a
# specific machine-checked policy revision; an auditor takes the fingerprint,
# checks it against the source, and re-runs `lake build Certior.Audit` to
# independently verify there are no `sorry`/untrusted axioms.

@functools.cache
def _lean_policy_fingerprint() -> str:
    """Stable short SHA of the Lean-audited policy model.

    Resolution order:

    1. Hash the Lean source on disk at ``lean4/CertiorLattice/Certior/*.lean``.
       This is the canonical computation and is used in source checkouts so
       that local edits to the Lean source reflect immediately.
    2. Fall back to the ``FINGERPRINT`` constant in
       ``certior._lean_fingerprint`` baked at wheel-build time. This is the
       path pip-installed users hit, since the wheel does not ship the Lean
       source.
    3. Last-resort ``"unknown"`` if neither path is reachable. Should not
       happen for any user installing the official wheel.

    Cached per-process.
    """
    here = Path(__file__).resolve().parent.parent
    lean_dir = here / "lean4" / "CertiorLattice" / "Certior"
    if lean_dir.exists():
        h = hashlib.sha256()
        for f in sorted(lean_dir.glob("*.lean")):
            h.update(f.name.encode() + b"\0")
            h.update(f.read_bytes())
        return h.hexdigest()[:16]
    try:
        from certior._lean_fingerprint import FINGERPRINT
        return FINGERPRINT
    except ImportError:
        return "unknown"


# ── Public types ─────────────────────────────────────────────────────

class Policy(str, Enum):
    """Pre-built compliance policies."""
    DEFAULT = "default"
    HIPAA = "hipaa"
    SOX = "sox"
    LEGAL = "legal"
    LEGAL_PRIVILEGE = "legal_privilege"


@dataclass(frozen=True)
class Violation:
    """A single safety or capability violation."""
    category: str
    detail: str
    severity: str = "block"  # block | warn


@dataclass
class VerifyResult:
    """
    Outcome of ``Guard.verify()``.

    Attributes:
        allowed:  Whether the action may proceed.
        reason:   Human-readable explanation (if blocked).
        violations: List of specific violations found.
        redacted_content: Content with PII removed (if policy redacts).
        redacted_params:  Tool params with PII removed.
        pii_found:  PII instances detected [(type, text), ...].
        latency_ms: Wall-clock time for the verify call.
        certificate: Opaque proof certificate (for audit trail).
    """
    allowed: bool = True
    reason: str = ""
    violations: List[Violation] = field(default_factory=list)
    redacted_content: Optional[str] = None
    redacted_params: Optional[Dict[str, Any]] = None
    pii_found: List[tuple] = field(default_factory=list)
    latency_ms: float = 0.0
    certificate: Optional[Any] = None

    @property
    def blocked(self) -> bool:
        return not self.allowed


# ── Guard ────────────────────────────────────────────────────────────

F = TypeVar("F", bound=Callable)


class Guard:
    """
    Verified safety guard for AI agent tool calls.

    Usage::

        guard = Guard(policy="hipaa", budget_cents=5000)

        # Option 1: explicit verify
        result = guard.verify(tool="db_query", content="Patient SSN: 123-45-6789")
        if result.allowed:
            run_tool(result.redacted_content)

        # Option 2: wrap a function
        safe_query = guard.wrap(db_query, tool_name="db_query")
        output = safe_query(sql="SELECT * FROM patients")

        # Option 3: context manager
        with guard.check(tool="email", content=body) as ctx:
            send_email(ctx.redacted_content)

    Parameters:
        policy:       Compliance policy name or Policy enum.
        permissions:  Allowed capability strings (default: ["*"]).
        budget_cents: Maximum cost budget in cents.
        on_violation: Callback ``(VerifyResult) -> None`` for violations.
        auto_redact:  Whether to automatically redact PII (default: True).
    """

    def __init__(
        self,
        policy: Union[str, Policy] = Policy.DEFAULT,
        permissions: Optional[Sequence[str]] = None,
        budget_cents: int = 10_000,
        on_violation: Optional[Callable[[VerifyResult], None]] = None,
        auto_redact: bool = True,
        agent_id: str = "default-agent",
    ):
        _load_internals()

        self._policy_name = Policy(policy) if isinstance(policy, str) else policy
        self._permissions = list(permissions or ["*"])
        self._budget_cents = budget_cents
        self._budget_remaining = budget_cents
        self._on_violation = on_violation
        self._auto_redact = auto_redact
        self._agent_id = agent_id

        # Build internal objects
        self._token = _CapabilityToken(
            agent_id=agent_id,
            permissions=self._permissions,
            budget_cents=budget_cents,
            budget_remaining_cents=budget_cents,
        )
        self._safety_policy = self._build_policy(self._policy_name)
        self._scanner = _ContentScanner(self._safety_policy)
        self._pii_detector = _PIIDetector()
        # Z3 capability gate + signed-certificate authority - turn the wrapper's
        # "allowed/blocked" verdict into a real proof-backed decision.
        self._z3 = _Z3Verifier()
        self._ca = _CertificateAuthority()

        # Audit log
        self._audit: List[Dict[str, Any]] = []

    # ── Core API ─────────────────────────────────────────────────

    def verify(
        self,
        tool: str = "",
        params: Optional[Dict[str, Any]] = None,
        content: Optional[str] = None,
        *,
        required_capabilities: Optional[List[str]] = None,
        cost_cents: int = 0,
    ) -> VerifyResult:
        """
        Verify a tool call against the safety policy.

        This is the main API - synchronous, fast (<10ms typical).

        Args:
            tool:       Tool/action name (e.g. "database_query").
            params:     Tool parameters dict.
            content:    Text content to scan for PII/safety violations.
            required_capabilities: Capabilities this tool needs.
            cost_cents: Estimated cost of this tool call.

        Returns:
            VerifyResult with allowed/blocked status, redacted content, etc.
        """
        start = time.perf_counter()
        violations: List[Violation] = []
        pii_found: List[tuple] = []
        redacted_content = content
        redacted_params = dict(params) if params else None

        # 1+2. Capability + budget check.
        # If permissions include "*" (wildcard), short-circuit the capability
        # part (Z3 doesn't model wildcards). Otherwise invoke the real Z3
        # verifier - same one the platform uses - to formally prove capability
        # coverage and budget sufficiency. The verdict is what later issues
        # (or withholds) a signed certificate.
        z3_result = None
        if required_capabilities or cost_cents > 0:
            if "*" in self._permissions:
                if cost_cents > self._budget_remaining:
                    violations.append(Violation(
                        category="budget",
                        detail=f"Need {cost_cents}¢, only {self._budget_remaining}¢ remaining",
                    ))
            else:
                z3_result = self._z3.verify_action(
                    required_capabilities=required_capabilities or [],
                    available_capabilities=self._permissions,
                    estimated_cost_cents=cost_cents,
                    budget_remaining_cents=self._budget_remaining,
                )
                if not z3_result.valid:
                    for v in z3_result.violations:
                        lv = v.lower()
                        cat = "capability" if "capability" in lv else (
                            "budget" if "budget" in lv else "flow"
                        )
                        violations.append(Violation(category=cat, detail=v))

        # 3. Content safety scan
        if content:
            scan = self._scanner.scan(content)

            for v in scan.violations:
                violations.append(Violation(
                    category=v.category.value if hasattr(v.category, "value") else str(v.category),
                    detail=v.matched_text,
                    severity=v.severity,
                ))

            pii_found = scan.pii_detected
            if scan.redacted_text and self._auto_redact:
                redacted_content = scan.redacted_text

        # 4. Scan params for PII
        if redacted_params and self._auto_redact:
            redacted_params = self._redact_params(redacted_params)

        # 5. Build result
        blocking = [v for v in violations if v.severity == "block"]
        allowed = len(blocking) == 0
        reason = "; ".join(v.detail for v in blocking) if blocking else ""

        # Deduct budget on success
        if allowed and cost_cents > 0:
            self._budget_remaining -= cost_cents

        # Issue a signed proof certificate when the action passed a real Z3
        # verification. No Z3 verdict (wildcard permissions or no capability/
        # cost given) ⇒ no certificate, by design - we only sign what's actually
        # proven. The certificate is plan-bound (sha256 of the action) so any
        # tamper with the recorded action invalidates the receipt.
        certificate = None
        if allowed and z3_result is not None:
            fp = _lean_policy_fingerprint()
            action_repr = json.dumps({
                "tool": tool,
                "requires": sorted(required_capabilities or []),
                "cost_cents": cost_cents,
                "agent": self._agent_id,
                "policy_fingerprint": fp,
            }, sort_keys=True)
            plan_hash = "sha256:" + hashlib.sha256(action_repr.encode()).hexdigest()
            properties = list(z3_result.properties) + [f"policy_model:lean-audited@{fp}"]
            certificate = self._ca.issue_certificate(
                theorem=f"action_admissible:{tool or 'unnamed'}",
                plan_hash=plan_hash,
                verified_properties=properties,
                proof_trace=f"Z3 SAT in {z3_result.solve_time_ms:.1f}ms, policy: Lean-audited @ {fp}",
                prover="z3",
            )

        result = VerifyResult(
            allowed=allowed,
            reason=reason,
            violations=violations,
            redacted_content=redacted_content,
            redacted_params=redacted_params,
            pii_found=pii_found,
            latency_ms=(time.perf_counter() - start) * 1000,
            certificate=certificate,
        )

        # Audit + callback
        self._audit.append({
            "tool": tool,
            "allowed": allowed,
            "violations": len(violations),
            "pii_count": len(pii_found),
            "latency_ms": result.latency_ms,
            "time": time.time(),
        })

        if not allowed and self._on_violation:
            try:
                self._on_violation(result)
            except Exception:
                log.exception("on_violation callback failed")

        return result

    async def averify(
        self,
        tool: str = "",
        params: Optional[Dict[str, Any]] = None,
        content: Optional[str] = None,
        **kwargs,
    ) -> VerifyResult:
        """Async version of verify() - runs in thread to avoid blocking."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            functools.partial(self.verify, tool, params, content, **kwargs),
        )

    def wrap(
        self,
        fn: Optional[F] = None,
        tool_name: str = "",
        required_capabilities: Optional[List[str]] = None,
        cost_cents: int = 0,
        content_extractor: Optional[Callable[..., str]] = None,
    ) -> Union[F, Callable[[F], F]]:
        """
        Wrap a tool function with automatic verification.

        Works as both a direct decorator and a decorator factory::

            # Direct: @guard.wrap
            @guard.wrap
            def my_tool(x): ...

            # With args: @guard.wrap(tool_name="search")
            @guard.wrap(tool_name="search", cost_cents=5)
            def my_tool(x): ...

        """
        def _make_wrapper(func: F) -> F:
            name = tool_name or getattr(func, "__name__", "unknown")

            if asyncio.iscoroutinefunction(func):
                @functools.wraps(func)
                async def _async_wrapper(*args, **kwargs):
                    content = None
                    if content_extractor:
                        content = content_extractor(*args, **kwargs)
                    result = await self.averify(
                        tool=name,
                        params=kwargs,
                        content=content,
                        required_capabilities=required_capabilities,
                        cost_cents=cost_cents,
                    )
                    if result.blocked:
                        raise CertiorBlocked(result)
                    return await func(*args, **kwargs)
                return _async_wrapper  # type: ignore
            else:
                @functools.wraps(func)
                def _sync_wrapper(*args, **kwargs):
                    content = None
                    if content_extractor:
                        content = content_extractor(*args, **kwargs)
                    result = self.verify(
                        tool=name,
                        params=kwargs,
                        content=content,
                        required_capabilities=required_capabilities,
                        cost_cents=cost_cents,
                    )
                    if result.blocked:
                        raise CertiorBlocked(result)
                    return func(*args, **kwargs)
                return _sync_wrapper  # type: ignore

        # Called as @guard.wrap (no parentheses) - fn is the function
        if fn is not None:
            return _make_wrapper(fn)

        # Called as @guard.wrap(...) - return the decorator
        return _make_wrapper

    # ── Inspection ───────────────────────────────────────────────

    @property
    def budget_remaining(self) -> int:
        """Remaining budget in cents."""
        return self._budget_remaining

    @property
    def permissions(self) -> List[str]:
        """Capability set this guard authorises (read-only copy)."""
        return list(self._permissions)

    @property
    def audit_log(self) -> List[Dict[str, Any]]:
        """Read-only access to the audit trail."""
        return list(self._audit)

    @property
    def policy_name(self) -> str:
        return self._policy_name.value

    @property
    def policy_attestation(self) -> Dict[str, Any]:
        """Provenance of the formally-verified policy this guard enforces.

        The runtime gate is Z3; the *model* it enforces is machine-checked in
        Lean 4. This returns the fingerprint of that Lean source plus the names
        of the audited guarantees and the trusted axioms. An auditor can:

            1. Match the fingerprint against `lean4/CertiorLattice/Certior/*.lean`
            2. Run `cd lean4/CertiorLattice && lake build Certior.Audit`
            3. Confirm the four guarantees depend only on the trusted axioms

        Every signed cert embeds this fingerprint, so each receipt provably
        ties to a specific machine-checked policy revision.
        """
        return {
            "kernel": "Certior.Lattice + Delegation + Encoding + Composition (Lean 4)",
            "fingerprint": _lean_policy_fingerprint(),
            "audited_guarantees": [
                "Certior.Delegation.delegationSafety",
                "Certior.Encoding.ifcSoundness",
                "Certior.Composition.compositionSoundness",
                "SecurityLevel.isValidBoundedLattice",
            ],
            "trusted_axioms": ["propext", "Classical.choice", "Quot.sound"],
            "audit_command": "cd lean4/CertiorLattice && lake build Certior.Audit",
        }

    # ── Internals ────────────────────────────────────────────────

    def _build_policy(self, policy: Policy) -> Any:
        """Map policy enum to internal ContentSafetyPolicy."""
        builders = {
            Policy.DEFAULT: _ContentSafetyPolicy.default,
            Policy.HIPAA: _ContentSafetyPolicy.hipaa_compliant,
            Policy.SOX: _ContentSafetyPolicy.sox_compliant,
            Policy.LEGAL: _ContentSafetyPolicy.legal_privilege,
            Policy.LEGAL_PRIVILEGE: _ContentSafetyPolicy.legal_privilege,
        }
        builder = builders.get(policy, _ContentSafetyPolicy.default)
        return builder()

    def _redact_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Scan dict values for PII and redact."""
        out = {}
        for k, v in params.items():
            if isinstance(v, str):
                pii = self._pii_detector.detect(v)
                if pii:
                    out[k] = self._pii_detector.redact(v, pii)
                else:
                    out[k] = v
            elif isinstance(v, dict):
                out[k] = self._redact_params(v)
            else:
                out[k] = v
        return out


# ── Exceptions ───────────────────────────────────────────────────────

class CertiorBlocked(Exception):
    """Raised by Guard.wrap() when a tool call is blocked."""

    def __init__(self, result: VerifyResult):
        self.result = result
        super().__init__(f"Certior blocked: {result.reason}")

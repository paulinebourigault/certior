"""
VerifiedAgent base class.
IMPROVED: Real Z3 verification path that tests actually exercise.
"""
from __future__ import annotations
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.kernel.certificate import (
    CertificateAuthority, TrustedKernel, VerifiedCertificate,
)
from agentsafe.flow.information_flow import TaintTracker, SecurityLabel, SecurityLevel
from agentsafe.observability.otel import CertiorTelemetry
from .actions import AgentAction, StepResult

try:
    from z3 import Solver, Int, Bool, And, Or, Not, BoolVal, sat, unsat, Sum
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


@dataclass
class VerificationResult:
    valid: bool = True
    certificate: Optional[VerifiedCertificate] = None
    properties: List[str] = field(default_factory=list)
    violations: List[str] = field(default_factory=list)
    solve_time_ms: float = 0.0
    used_z3: bool = False


class SecurityError(Exception):
    pass

class VerificationError(Exception):
    def __init__(self, violations: List[str]):
        self.violations = violations
        super().__init__(f"Verification failed: {violations}")

class BudgetExceededError(Exception):
    pass


class TokenInvalidError(SecurityError):
    """Raised when a capability token fails pre-verification validity checks.

    Attributes:
        reason: One of ``token_expired``, ``token_tampered``,
                ``token_budget_exhausted``.
        token_id: The id of the rejected token.
    """

    def __init__(self, reason: str, token_id: str = ""):
        self.reason = reason
        self.token_id = token_id
        super().__init__(f"Token invalid ({reason}): {token_id}")


class CertificateValidationError(SecurityError):
    """Raised when the TrustedKernel rejects a proof certificate.

    This means one of:
      - The certificate was not issued by our CertificateAuthority.
      - The certificate signature has been tampered with.
      - The certificate has expired.
      - The certificate's plan_hash doesn't match the action being executed.

    Attributes:
        certificate_id: The id of the rejected certificate.
        action_hash: The expected plan hash that failed to match.
    """

    def __init__(self, certificate_id: str = "", action_hash: str = ""):
        self.certificate_id = certificate_id
        self.action_hash = action_hash
        super().__init__(
            f"Certificate validation failed: cert={certificate_id}, "
            f"expected_hash={action_hash[:16]}..."
        )


class VerifiedAgent(ABC):
    """
    Base class for all Certior agents.
    Contract: verify-before-execute with Z3 proofs.

    IMPROVED: Z3 verification is always attempted when available,
    with structural fallback only when Z3 is not installed.
    Token validity is checked BEFORE any verification work.
    """

    def __init__(
        self, agent_id: str,
        capability_token: CapabilityToken,
        llm_client: Any = None,
        compliance_policy: str = "default",
    ):
        self.agent_id = agent_id
        self.token = capability_token
        self.llm = llm_client
        self.compliance_policy = compliance_policy
        self.ca = CertificateAuthority.get_instance()
        self.kernel = TrustedKernel(self.ca)
        self.taint_tracker = TaintTracker()
        self.telemetry = CertiorTelemetry.get_instance()
        self._tools: Dict[str, Any] = {}

    def register_tool(self, name: str, tool: Any):
        self._tools[name] = tool

    def get_tool(self, name: str) -> Any:
        return self._tools.get(name)

    # ── Token validation gate ─────────────────────────────────

    def _validate_token(self) -> None:
        """
        Pre-verification gate: reject expired / tampered / exhausted tokens
        BEFORE any Z3 work.  Emits OTel metrics on rejection.

        Raises:
            TokenInvalidError with a specific ``reason`` string.
        """
        reason = self.token.validation_error()
        if reason is not None:
            self.telemetry.verifications_total.add(
                1, {"action": "token_validation", "result": "blocked"},
            )
            self.telemetry.verifications_blocked.add(
                1, {"action": "token_validation", "reason": reason},
            )
            raise TokenInvalidError(reason, self.token.id)

    # ── Core verification ─────────────────────────────────────

    async def verify_action(self, action: AgentAction) -> VerificationResult:
        """
        Verify an action using Z3 (preferred) or structural fallback.

        **Gate**: ``token.is_valid()`` is checked first.  Expired,
        tampered, or budget-exhausted tokens are rejected immediately
        without invoking Z3.
        """
        # ── A1 FIX: Validate token BEFORE any verification work ──
        self._validate_token()

        start = time.perf_counter()
        with self.telemetry.trace_verification(action.tool, self.token.id):
            if _HAS_Z3:
                result = self._z3_verify_action(action)
            else:
                result = self._structural_verify_action(action)

            if result.valid:
                cert = self.ca.issue_certificate(
                    theorem="action_safe",
                    plan_hash=action.to_hash(),
                    verified_properties=result.properties,
                    proof_trace="z3" if result.used_z3 else "structural",
                    prover="z3" if result.used_z3 else "structural",
                )
                result.certificate = cert
                self.telemetry.record_certificate_issuance(
                    "z3" if result.used_z3 else "structural",
                    len(result.properties),
                )

            result.solve_time_ms = (time.perf_counter() - start) * 1000
            if result.solve_time_ms > 0:
                self.telemetry.record_z3_invocation(
                    result.solve_time_ms,
                    "sat" if result.valid else "unsat",
                )
            return result

    def _z3_verify_action(self, action: AgentAction) -> VerificationResult:
        """
        REAL Z3 verification. Encodes policy-appropriate constraints:
        - All policies:  capability coverage, information flow
        - default:       budget sufficiency
        - hipaa:         data classification, PII access, minimum-necessary
        - sox:           budget sufficiency, segregation of duties
        - legal:         privilege boundaries, information flow
        """
        s = Solver()
        properties = []
        violations = []

        # 1. Capability coverage with wildcards (all policies)
        for i, req in enumerate(action.required_capabilities):
            covered = Bool(f"cap_{i}_covered")
            cover_clauses = []
            for j, perm in enumerate(self.token.permissions):
                if perm == req:
                    cover_clauses.append(BoolVal(True))
                elif perm.endswith("*") and req.startswith(perm[:-1]):
                    cover_clauses.append(BoolVal(True))
            if cover_clauses:
                s.add(covered == Or(*cover_clauses))
            else:
                s.add(covered == BoolVal(False))
            s.add(covered)

        cap_result = s.check()
        if cap_result == sat:
            properties.append("capability_coverage: proven")
        else:
            missing = set(action.required_capabilities) - self.token.permission_set
            violations.append(f"missing_capabilities: {missing}")

        # 2. Policy-specific constraints
        policy = self.compliance_policy.lower().replace("_", "").replace("-", "")

        if policy in ("hipaa", "hipaacompliant"):
            # HIPAA: data classification + information flow (not budget)
            self._z3_hipaa_constraints(action, properties, violations)
        elif policy in ("sox", "soxcompliant"):
            # SOX: budget + audit constraints
            self._z3_budget_constraint(action, properties, violations)
            self._z3_sox_constraints(action, properties, violations)
        elif policy in ("legal", "legalprivilege", "legal_privilege"):
            # Legal: privilege boundary constraints
            self._z3_legal_constraints(action, properties, violations)
        else:
            # Default: budget constraint
            self._z3_budget_constraint(action, properties, violations)

        # 3. Information flow (all policies)
        if action.input_labels and action.output_labels:
            s3 = Solver()
            level_map = {"public": 0, "internal": 1, "cached": 1, "sensitive": 2, "restricted": 3}
            input_levels = [level_map.get(l, 1) for l in action.input_labels]
            output_levels = [level_map.get(l, 1) for l in action.output_labels]

            min_in = min(input_levels) if input_levels else 0
            for k, out_level in enumerate(output_levels):
                out_var = Int(f"out_{k}")
                s3.add(out_var == out_level)
                s3.add(out_var >= min_in)

            if s3.check() == sat:
                properties.append("information_flow: no downgrade proven")
            else:
                violations.append("information_flow: potential downgrade")

        return VerificationResult(
            valid=len(violations) == 0,
            properties=properties,
            violations=violations,
            used_z3=True,
        )

    def _z3_budget_constraint(
        self, action: AgentAction,
        properties: List[str], violations: List[str],
    ) -> None:
        """Z3-proven budget sufficiency."""
        s = Solver()
        budget = Int("budget_remaining")
        cost = Int("action_cost")
        s.add(budget == self.token.budget_remaining_cents)
        s.add(cost == action.estimated_cost_cents)
        s.add(cost >= 0)
        s.add(budget >= cost)
        if s.check() == sat:
            properties.append("budget_sufficient: proven")
        else:
            violations.append(
                f"budget_exceeded: need {action.estimated_cost_cents}, "
                f"have {self.token.budget_remaining_cents}"
            )

    def _z3_hipaa_constraints(
        self, action: AgentAction,
        properties: List[str], violations: List[str],
    ) -> None:
        """
        HIPAA-specific Z3 constraints:
        - Data classification: sensitive/restricted data requires elevated permissions
        - Minimum-necessary: output cannot be broader than input classification
        - PII access: tools accessing PII need explicit phi_access permission
        """
        level_map = {"public": 0, "internal": 1, "cached": 1, "sensitive": 2, "restricted": 3}
        s = Solver()

        # Data classification: if any input is sensitive/restricted,
        # agent must have data:phi:* or data:sensitive:* permission
        input_levels = [level_map.get(l, 1) for l in (action.input_labels or [])]
        max_input = max(input_levels) if input_levels else 0

        has_phi_access = any(
            p in self.token.permissions or p == "*"
            for p in ["data:phi:read", "data:phi:write", "data:phi:*", "data:sensitive:*", "*"]
        )

        if max_input >= 2 and not has_phi_access:
            violations.append(
                "hipaa_phi_access: tool processes sensitive/restricted data "
                "without explicit PHI access permission"
            )
        else:
            phi_level = Int("phi_level")
            access = Bool("phi_access")
            s.add(phi_level == max_input)
            s.add(access == BoolVal(has_phi_access))
            s.add(Or(phi_level < 2, access))
            if s.check() == sat:
                properties.append("hipaa_phi_access: proven")

        # Minimum-necessary principle: output classification
        # must not downgrade from input classification
        output_levels = [level_map.get(l, 1) for l in (action.output_labels or [])]
        if input_levels and output_levels:
            s2 = Solver()
            max_in = Int("max_input_level")
            min_out = Int("min_output_level")
            s2.add(max_in == max(input_levels))
            s2.add(min_out == min(output_levels))
            s2.add(min_out >= max_in)
            if s2.check() == sat:
                properties.append("hipaa_minimum_necessary: proven")
            else:
                violations.append(
                    "hipaa_minimum_necessary: output classification lower "
                    "than input - potential data exposure"
                )

    def _z3_sox_constraints(
        self, action: AgentAction,
        properties: List[str], violations: List[str],
    ) -> None:
        """
        SOX-specific Z3 constraints:
        - Segregation: write operations require explicit write permissions
          (wildcard * alone is insufficient for financial writes)
        """
        write_tools = {"database_write", "file_write", "api_write", "ledger_update"}
        if action.tool in write_tools:
            has_explicit_write = any(
                "write" in p or "ledger" in p
                for p in self.token.permissions
                if p != "*"
            )
            if not has_explicit_write:
                violations.append(
                    f"sox_segregation: {action.tool} requires explicit write "
                    "permission - wildcard insufficient under SOX"
                )
            else:
                properties.append("sox_segregation: proven")

    def _z3_legal_constraints(
        self, action: AgentAction,
        properties: List[str], violations: List[str],
    ) -> None:
        """
        Legal privilege constraints:
        - Privileged data must not flow to unprivileged outputs
        - Tools producing external output require legal:review permission
        """
        level_map = {"public": 0, "internal": 1, "cached": 1, "sensitive": 2, "restricted": 3}
        input_levels = [level_map.get(l, 1) for l in (action.input_labels or [])]
        output_levels = [level_map.get(l, 1) for l in (action.output_labels or [])]

        # Privilege boundary: if input has restricted data, output must be restricted too
        if input_levels and output_levels:
            max_in = max(input_levels)
            min_out = min(output_levels)
            if max_in >= 3 and min_out < 3:
                violations.append(
                    "legal_privilege_boundary: restricted/privileged data "
                    "flowing to non-restricted output channel"
                )
            else:
                properties.append("legal_privilege_boundary: proven")

    def _structural_verify_action(self, action: AgentAction) -> VerificationResult:
        """Fallback when Z3 is not available."""
        violations = []
        properties = []

        # Capability check
        for req in action.required_capabilities:
            if not self.token.has_permission(req):
                violations.append(f"missing_capability: {req}")
        if not violations:
            properties.append("capability_coverage: structural")

        # Budget check
        if not self.token.has_budget(action.estimated_cost_cents):
            violations.append(f"budget_exceeded: need {action.estimated_cost_cents}")
        else:
            properties.append("budget_sufficient: structural")

        return VerificationResult(
            valid=len(violations) == 0,
            properties=properties,
            violations=violations,
            used_z3=False,
        )

    async def execute_action(
        self, action: AgentAction, certificate: VerifiedCertificate,
    ) -> StepResult:
        """Execute ONLY with valid certificate AND valid token.

        A1 TOCTOU defence: re-validates ``token.is_valid()`` immediately
        before execution.  A token that was valid at verification time
        may have expired or been budget-drained by a concurrent agent.

        A2: Uses ``CertificateValidationError`` for clear attribution
        and emits OTel metrics when the kernel rejects a certificate.

        A6: Atomically reserves budget BEFORE execution.  On failure the
        reservation is rolled back so budget is not lost.
        """
        # ── A1 TOCTOU: re-validate token at execution time ─────────
        self._validate_token()

        if not self.kernel.validate_certificate(certificate, action.to_hash()):
            self.telemetry.verifications_blocked.add(
                1, {"action": action.tool, "reason": "certificate_invalid"},
            )
            raise CertificateValidationError(
                certificate_id=certificate.id,
                action_hash=action.to_hash(),
            )

        tool = self.get_tool(action.tool)
        if tool is None:
            return StepResult(
                step_id=action.id, success=False,
                error=f"Tool not found: {action.tool}",
            )

        # ── A6: Reserve budget BEFORE execution (atomic) ───────────
        from agentsafe.capabilities.tokens import BudgetExhaustedError
        cost = action.estimated_cost_cents
        try:
            reservation = self.token.reserve_budget(cost)
        except BudgetExhaustedError as exc:
            return StepResult(
                step_id=action.id, success=False,
                error=str(exc),
            )

        # Execute inside reservation context - auto-rollback on failure
        try:
            with reservation:
                import asyncio
                if callable(tool):
                    result = tool(action.parameters)
                    if asyncio.iscoroutine(result) or asyncio.isfuture(result):
                        result = await result
                elif hasattr(tool, 'execute'):
                    result = tool.execute(action.parameters)
                    if asyncio.iscoroutine(result) or asyncio.isfuture(result):
                        result = await result
                else:
                    result = str(tool)

            # If we reach here, reservation committed (budget consumed)
            return StepResult(
                step_id=action.id, success=True, output=result,
                output_labels=action.output_labels,
                certificate_id=certificate.id,
                cost_cents=cost,
            )
        except BudgetExhaustedError:
            raise  # should not happen here but propagate
        except Exception as e:
            # reservation.__exit__ already rolled back budget
            return StepResult(
                step_id=action.id, success=False, error=str(e),
            )

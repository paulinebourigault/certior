"""
Agentic executor - reactive LLM + tool-use loop with formal verification.

This is the core runtime for Certior agents.  It replaces the previous
"plan-all-then-execute" pattern with a **reactive loop** where:

  1. The LLM receives a task and a set of available tools.
  2. It emits tool_use blocks (or a final text response).
  3. Each tool call is **verified** (capability, budget, IFC) before execution.
  4. The tool result is fed back as a tool_result message.
  5. The loop repeats until the LLM emits a final text response (stop_reason=end_turn).
  6. The final output is **content-safety scanned** before delivery.

Every step is:
  - Traced via OpenTelemetry
  - Verified against the caller's CapabilityToken
  - Content-safety scanned (inputs AND outputs) - A4 FIX
  - Information-flow controlled (taint tracking) - A5 FIX
  - Recorded in the audit trail
  - Streamed to WebSocket subscribers

Architecture notes:
  - The AgenticExecutor does NOT own the LLM client or tool registry;
    they are injected.  This keeps it testable (mock LLM, mock tools).
  - It delegates verification to VerifiedAgent infrastructure (Z3).
  - It delegates content safety to the VerifierAgent's ContentScanner
    and the ToolIOScanner (A4).
  - It delegates IFC enforcement to the IFCEnforcer (A5).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.kernel.certificate import (
    CertificateAuthority,
    TrustedKernel,
    VerifiedCertificate,
)
from agentsafe.observability.otel import CertiorTelemetry
from agentsafe.safety.scanner import ContentScanner, ContentSafetyPolicy, ScanResult
from agentsafe.safety.tool_io_scanner import (
    ToolIOScanner,
    StepScanResult,
    PhaseScanResult,
    ScanAction,
    ScanPhase,
)
from agentsafe.flow.ifc_enforcer import (
    IFCEnforcer,
    FlowCheckResult,
    FlowVerdict,
    IFCSummary,
)
from agentsafe.flow.information_flow import SecurityLevel
from agentsafe.agents.actions import AgentAction
from agentsafe.agents.base import VerifiedAgent, VerificationResult
from agentsafe.safety.approval_gate import (
    ApprovalGate,
    ApprovalCallback,
    ApprovalDecision,
    ApprovalVerdict,
)

from agentsafe.llm.client import LLMResponse, ToolCallRequest
from agentsafe.llm.config import LLMConfig
from agentsafe.llm.factory import create_llm_client
from agentsafe.tools.base import BaseTool, ToolResult
from agentsafe.tools.registry import ToolRegistry
from agentsafe.verification.lean_live_verifier import (
    LeanLiveVerifier,
    LeanFlowResult,
)

log = logging.getLogger(__name__)

# ── Verification strategy mapping ──────────────────────────────────
# Maps compliance policy → which formal verification checks to run.
# Z3:    constraint solving (capabilities, budget, data classification)
# Lean4: lattice-proven information flow control
# Dafny: runtime invariants (capability attenuation, certificates)

_VERIFICATION_STRATEGIES: Dict[str, Dict[str, List[str]]] = {
    "default": {
        "z3": ["capability_coverage", "budget_sufficiency"],
        "lean4": ["information_flow"],
        "dafny": ["capability_attenuation", "certificate_invariants"],
    },
    "hipaa": {
        "z3": ["capability_coverage", "phi_access_control", "minimum_necessary", "data_classification"],
        "lean4": ["information_flow", "phi_disclosure_prevention"],
        "dafny": ["capability_attenuation", "certificate_invariants"],
    },
    "hipaa_compliant": {
        "z3": ["capability_coverage", "phi_access_control", "minimum_necessary", "data_classification"],
        "lean4": ["information_flow", "phi_disclosure_prevention"],
        "dafny": ["capability_attenuation", "certificate_invariants"],
    },
    "sox": {
        "z3": ["capability_coverage", "budget_sufficiency", "segregation_of_duties"],
        "lean4": ["information_flow"],
        "dafny": ["capability_attenuation", "certificate_invariants", "audit_trail"],
    },
    "sox_compliant": {
        "z3": ["capability_coverage", "budget_sufficiency", "segregation_of_duties"],
        "lean4": ["information_flow"],
        "dafny": ["capability_attenuation", "certificate_invariants", "audit_trail"],
    },
    "legal_privilege": {
        "z3": ["capability_coverage", "privilege_boundary"],
        "lean4": ["information_flow", "privilege_flow_control"],
        "dafny": ["capability_attenuation", "certificate_invariants"],
    },
}


# ── Result types ───────────────────────────────────────────────────

@dataclass
class AgentStep:
    """A single step in the agent's execution trace."""
    step_index: int
    tool_name: str
    tool_input: Dict[str, Any]
    tool_output: str
    is_error: bool = False
    verification: Optional[VerificationResult] = None
    verification_certificate: Optional[Dict[str, Any]] = None
    certificate_id: str = ""
    cost_cents: int = 0
    duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)
    step_scan: Optional[StepScanResult] = None
    ifc_effective_level: str = ""
    ifc_promoted: bool = False
    ifc_flow_blocked: bool = False
    approval_verdict: str = ""         # A8: "not_required", "approved", "denied", etc.
    approval_categories: List[str] = field(default_factory=list)  # A8: matched categories
    lean_flow_result: Optional[Dict[str, Any]] = None  # Lean4 lattice-proven flow check
    lean_proven: bool = False  # Whether step has Lean4 proof certificate
    tool_metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "step_index": self.step_index,
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "tool_output": self.tool_output[:500],  # truncate for streaming
            "is_error": self.is_error,
            "certificate_id": self.certificate_id,
            "cost_cents": self.cost_cents,
            "duration_ms": round(self.duration_ms, 2),
            "verified": self.certificate_id != "",
        }
        if self.verification is not None and self.verification.properties:
            d["verification_properties"] = list(self.verification.properties)
        if self.verification_certificate is not None:
            d["verification_certificate"] = self.verification_certificate
        if self.step_scan is not None:
            d["content_scan"] = self.step_scan.to_dict()
        if self.ifc_effective_level:
            d["ifc"] = {
                "effective_level": self.ifc_effective_level,
                "promoted": self.ifc_promoted,
                "flow_blocked": self.ifc_flow_blocked,
            }
        if self.approval_verdict:
            d["approval"] = {
                "verdict": self.approval_verdict,
                "categories": self.approval_categories,
            }
        if self.lean_flow_result is not None:
            d["lean_verification"] = self.lean_flow_result
        if self.lean_proven:
            d["lean_proven"] = True
        if self.tool_metadata:
            d["tool_metadata"] = self.tool_metadata
        return d


@dataclass
class AgenticResult:
    """Final result of an agentic execution."""
    task: str
    output: str = ""
    steps: List[AgentStep] = field(default_factory=list)
    certificates: List[str] = field(default_factory=list)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    total_cost_cents: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    duration_ms: float = 0.0
    success: bool = True
    error: str = ""
    safety_scan: Optional[ScanResult] = None
    step_scans: List[StepScanResult] = field(default_factory=list)
    ifc_summary: Optional[IFCSummary] = None
    approval_summary: Optional[Dict[str, Any]] = None  # A8: approval gate summary
    lean_summary: Optional[Dict[str, Any]] = None  # Lean4 kernel verification summary
    lean_certificates: List[Dict[str, Any]] = field(default_factory=list)
    verification_profile: Optional[Dict[str, Any]] = None
    approved_artifact: Optional[Dict[str, Any]] = None
    release_binding_summary: Optional[Dict[str, Any]] = None

    # ── Content safety summary properties (A4) ────────────────────

    @property
    def content_violations_total(self) -> int:
        """Total content safety violations across all steps."""
        total = 0
        for ss in self.step_scans:
            if ss.input_scan and not ss.input_scan.scan_result.clean:
                total += len(ss.input_scan.scan_result.violations)
            if ss.output_scan and not ss.output_scan.scan_result.clean:
                total += len(ss.output_scan.scan_result.violations)
        return total

    @property
    def steps_blocked_by_content_safety(self) -> int:
        """Number of steps blocked by content safety."""
        return sum(1 for ss in self.step_scans if ss.blocked)

    @property
    def steps_with_redaction(self) -> int:
        """Number of steps where PII was redacted."""
        return sum(
            1 for ss in self.step_scans
            if ss.output_scan and ss.output_scan.redacted
        )

    # ── IFC summary properties (A5) ──────────────────────────────

    @property
    def ifc_flows_blocked(self) -> int:
        """Number of IFC flow violations (blocked)."""
        if self.ifc_summary is None:
            return 0
        return self.ifc_summary.flows_blocked

    @property
    def ifc_labels_promoted(self) -> int:
        """Number of tool outputs whose labels were promoted."""
        if self.ifc_summary is None:
            return 0
        return self.ifc_summary.labels_promoted

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "task": self.task,
            "output": self.output,
            "steps": [s.to_dict() for s in self.steps],
            "certificates": self.certificates,
            "total_cost_cents": self.total_cost_cents,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "duration_ms": round(self.duration_ms, 2),
            "success": self.success,
            "error": self.error,
            "step_count": len(self.steps),
        }
        if self.step_scans:
            d["content_safety_summary"] = {
                "violations_total": self.content_violations_total,
                "total_violations": self.content_violations_total,
                "steps_blocked": self.steps_blocked_by_content_safety,
                "steps_redacted": self.steps_with_redaction,
            }
        else:
            d["content_safety_summary"] = {
                "violations_total": 0,
                "total_violations": 0,
                "steps_blocked": 0,
                "steps_redacted": 0,
            }
        if self.ifc_summary is not None:
            d["ifc_summary"] = self.ifc_summary.to_dict()
        if self.approval_summary is not None:
            d["approval_summary"] = self.approval_summary
        if self.lean_summary is not None:
            d["lean_verification_summary"] = self.lean_summary
        if self.lean_certificates:
            d["lean_certificates"] = self.lean_certificates
        if self.verification_profile is not None:
            d["verification_profile"] = self.verification_profile
        return d


# ── Status callback type ──────────────────────────────────────────

StatusCallback = Callable[[str, Dict[str, Any]], Coroutine[Any, Any, None]]

_DEFAULT_SYSTEM_PROMPT = """\
You are a verified AI agent running on the Certior platform.
Every tool call you make is formally verified for safety before execution.
You have access to a set of tools - use them to accomplish the user's task.
Be concise and direct. When you have enough information, produce your final answer.
Do NOT call tools unnecessarily.
"""


# ── Agentic executor ──────────────────────────────────────────────

class AgenticExecutor:
    """
    Reactive LLM agent loop with per-step formal verification,
    content safety scanning, and information flow control.

    Usage::

        executor = AgenticExecutor(
            llm_config=LLMConfig(),
            tool_registry=create_default_registry(),
            capability_token=token,
        )
        result = await executor.run("Research recent advances in formal verification")

    The executor:
      - Builds a message history
      - Verifies each tool call against the CapabilityToken (Z3)
      - Scans tool inputs and outputs for content safety (A4)
      - Enforces information flow control with taint tracking (A5)
      - Tracks budget consumption
      - Emits status updates via an optional callback
      - Scans the final output for content safety
      - Checks final output IFC flow before delivery
    """

    def __init__(
        self,
        llm_config: LLMConfig,
        tool_registry: ToolRegistry,
        capability_token: CapabilityToken,
        content_policy: Optional[ContentSafetyPolicy] = None,
        on_status: Optional[StatusCallback] = None,
        system_prompt: Optional[str] = None,
        approval_callback: Optional[ApprovalCallback] = None,
        pre_approved_categories: Optional[Set[str]] = None,
    ) -> None:
        self.llm_config = llm_config
        self.tools = tool_registry
        self.token = capability_token
        self.content_policy = content_policy or ContentSafetyPolicy.default()
        self.on_status = on_status
        self.system_prompt = system_prompt or _DEFAULT_SYSTEM_PROMPT

        # Infrastructure
        self._client = create_llm_client(llm_config)
        self._ca = CertificateAuthority.get_instance()
        self._kernel = TrustedKernel(self._ca)
        self._telemetry = CertiorTelemetry.get_instance()
        self._scanner = ContentScanner(self.content_policy)

        # A4: Tool input/output scanning
        self._io_scanner = ToolIOScanner(self.content_policy)

        # A5: Information flow control enforcement
        self._ifc = IFCEnforcer(
            output_level=SecurityLevel.PUBLIC,
            llm_context_level=SecurityLevel.PUBLIC,
            strict=True,
        )

        # A8: Human approval gate
        self._approval_gate = ApprovalGate(
            policy=self.content_policy,
            callback=approval_callback,
            pre_approved_categories=pre_approved_categories,
            task_summary="",
        )
        self._verification_profile = self._load_verification_profile()

        # A9: Load approval categories from VERIFICATION.json if available
        self._loaded_constraints = getattr(tool_registry, "_loaded_constraints", None)

        # Lean4 lattice-proven flow verification (inline with agent loop)
        self._lean_verifier = LeanLiveVerifier()

        # For verification: we use a lightweight VerifiedAgent shim
        self._verifier = _VerificationShim(
            agent_id="agentic-executor",
            capability_token=capability_token,
            compliance_policy=content_policy.name if content_policy else "default",
        )

    async def run(self, task: str) -> AgenticResult:
        """
        Execute a task using the reactive LLM agent loop.

        Returns an AgenticResult with the final output, execution
        trace, certificates, token usage, content safety scans,
        and IFC summary.
        """
        start = time.perf_counter()
        steps: List[AgentStep] = []
        certificates: List[str] = []
        audit: List[Dict[str, Any]] = []
        step_scans: List[StepScanResult] = []
        total_cost = 0

        # Reset IFC enforcer for this execution
        self._ifc.reset()

        task_for_model = task
        prompt_was_redacted = False
        if self._is_public_safe_summary_profile():
            prompt_scan = self._scanner.scan(task)
            if prompt_scan.redacted_text and prompt_scan.redacted_text != task:
                task_for_model = prompt_scan.redacted_text
                prompt_was_redacted = True
                audit.append({
                    "phase": "prompt_redacted_for_llm",
                    "pii_detected": len(prompt_scan.pii_detected),
                    "violations": len(prompt_scan.violations),
                })

        # Start Lean4 lattice-proven flow verification kernel
        lean_available = await self._lean_verifier.start(
            budget=self.token.budget_remaining_cents,
            capabilities=list(self.token.permissions),
            compliance=self.content_policy.name,
        )

        # Log verification strategy for this compliance policy
        policy_name = self.content_policy.name.lower()
        verification_strategy = _VERIFICATION_STRATEGIES.get(
            policy_name, _VERIFICATION_STRATEGIES["default"]
        )
        audit.append({
            "phase": "verification_strategy_selected",
            "compliance_policy": policy_name,
            "z3_checks": verification_strategy["z3"],
            "lean4_checks": verification_strategy["lean4"],
            "dafny_checks": verification_strategy["dafny"],
        })

        if lean_available:
            log.info("Lean4 flow verification kernel active - dual Z3+Lean proofs")
            audit.append({
                "phase": "lean_kernel_started",
                "binary": self._lean_verifier._binary,
                "mode": "dual_proof",
            })
        else:
            log.debug("Lean4 kernel unavailable - Z3-only verification mode")
            audit.append({
                "phase": "lean_kernel_unavailable",
                "mode": "z3_only",
            })

        # Build initial message
        messages: List[Dict[str, Any]] = [
            {"role": "user", "content": task_for_model},
        ]

        # Generate Anthropic tool schemas (filtered by token capabilities)
        tool_schemas = self.tools.to_anthropic_tools(self.token)
        if not tool_schemas:
            _tid = self.token.id if hasattr(self.token, 'id') else self.token
            log.warning("No tools available for token %s - running without tools", _tid)

        await self._emit_status("planning", {"task": task, "tools_available": len(tool_schemas)})
        audit.append({"phase": "started", "task": task, "tools": len(tool_schemas), "time": time.time()})

        try:
            for round_idx in range(self.llm_config.max_tool_rounds):
                # ── LLM turn ──
                await self._emit_status("thinking", {"round": round_idx + 1})

                response = await self._client.send(
                    messages=messages,
                    tools=tool_schemas if tool_schemas else None,
                    system=self.system_prompt,
                )

                audit.append({
                    "phase": "llm_response",
                    "round": round_idx + 1,
                    "stop_reason": response.stop_reason,
                    "tool_calls": len(response.tool_calls),
                    "input_tokens": response.input_tokens,
                    "output_tokens": response.output_tokens,
                })

                # ── Final response (no tool calls) ──
                if response.is_final:
                    await self._emit_status("completing", {"round": round_idx + 1})

                    # Content safety scan on the final output
                    scan = self._scanner.scan(response.text)
                    self._telemetry.record_content_scan(
                        self.content_policy.name, scan.clean,
                        phase="final_output",
                        action="redact" if scan.redacted_text else "pass",
                    )

                    final_text = scan.redacted_text if scan.redacted_text else response.text
                    if scan.redacted_text:
                        audit.append({
                            "phase": "final_output_redacted",
                            "pii_detected": len(scan.pii_detected),
                        })

                    # ── A5 FIX: IFC flow check before user output ──
                    output_flow = self._ifc.check_flow_to_user()
                    if not output_flow.allowed:
                        self._telemetry.record_ifc_violation(
                            self._ifc.context_level.value,
                            "user_output",
                        )
                        audit.append({
                            "phase": "ifc_output_blocked",
                            "context_level": self._ifc.context_level.value,
                            "output_level": "public",
                            "reason": output_flow.reason,
                        })
                        if self._ifc.is_strict:
                            final_text = (
                                "[IFC BLOCKED] The response contains information "
                                "that cannot be disclosed at this security level. "
                                f"Context taint: {self._ifc.context_level.value}."
                            )

                    # ── Lean4 final output flow check ──
                    lean_user_flow = await self._lean_verifier.check_output_flow(
                        step_index=len(steps),
                        tool="__final_output__",
                        data_label=self._ifc.context_level.value.capitalize(),
                        target_label="Public",
                        data_id="final_output",
                    )
                    if not lean_user_flow.ok and lean_user_flow.proven:
                        final_text = (
                            "[LEAN4 PROVEN BLOCK] The accumulated context "
                            f"(level={self._ifc.context_level.value}) is "
                            f"mathematically proven to be unsafe for public "
                            f"disclosure. {lean_user_flow.detail}"
                        )
                        audit.append({
                            "phase": "lean_final_output_blocked",
                            "context_level": self._ifc.context_level.value,
                            "proven": True,
                        })

                    approved_artifact = self._build_approved_artifact(
                        artifact_text=final_text,
                        scan=scan,
                        lean_result=lean_user_flow,
                    )

                    release_targets = []
                    if self._verification_profile is not None:
                        release_targets = list(
                            self._verification_profile.get("release_targets", [])
                        )
                    if release_targets and "public" not in release_targets:
                        final_text = (
                            "[RELEASE HOLD] This stage is not authorised to disclose "
                            "results to a public caller. Route the artifact to the next "
                            "approved workflow stage."
                        )
                        audit.append({
                            "phase": "release_target_blocked",
                            "release_targets": release_targets,
                            "stage_role": (
                                self._verification_profile or {}
                            ).get("stage_role", "single_agent"),
                        })

                    final_text, release_binding_summary = self._enforce_release_artifact_binding(
                        final_text=final_text,
                        audit=audit,
                    )

                    final_certificate = self._issue_final_output_certificate(
                        task=task,
                        final_text=final_text,
                        scan=scan,
                        lean_result=lean_user_flow,
                        prompt_was_redacted=prompt_was_redacted,
                        release_targets=release_targets,
                        release_binding_summary=release_binding_summary,
                    )
                    if final_certificate is not None:
                        certificates.append(final_certificate.to_dict())
                        audit.append({
                            "phase": "final_output_certified",
                            "certificate_id": final_certificate.id,
                            "verified_properties": list(final_certificate.verified_properties),
                            "prover": final_certificate.prover,
                        })

                    # Shut down the Lean4 kernel
                    lean_certificates = await self._lean_verifier.get_certificates()
                    await self._lean_verifier.shutdown()

                    ifc_summary = self._ifc.summary()

                    duration_ms = (time.perf_counter() - start) * 1000
                    audit.append({"phase": "completed", "duration_ms": duration_ms})
                    await self._emit_status("completed", {
                        "steps": len(steps),
                        "duration_ms": round(duration_ms, 2),
                        "ifc_context_level": self._ifc.context_level.value,
                    })

                    return AgenticResult(
                        task=task,
                        output=final_text,
                        steps=steps,
                        certificates=certificates,
                        audit_trail=audit,
                        total_cost_cents=total_cost,
                        total_input_tokens=self._client.usage.input_tokens,
                        total_output_tokens=self._client.usage.output_tokens,
                        duration_ms=duration_ms,
                        success=True,
                        safety_scan=scan,
                        step_scans=step_scans,
                        ifc_summary=ifc_summary,
                        approval_summary=self._approval_gate.summary(),
                        lean_summary=self._lean_verifier.summary(),
                        lean_certificates=lean_certificates,
                        verification_profile=self._verification_profile,
                        approved_artifact=approved_artifact,
                        release_binding_summary=release_binding_summary,
                    )

                # ── Process tool calls ──
                assistant_content = self._build_assistant_content(response)
                messages.append({"role": "assistant", "content": assistant_content})

                tool_results_content: List[Dict[str, Any]] = []

                for tc in response.tool_calls:
                    step_start = time.perf_counter()
                    step_idx = len(steps)

                    await self._emit_status("executing_tool", {
                        "step": step_idx + 1,
                        "tool": tc.name,
                        "round": round_idx + 1,
                    })

                    # Look up tool
                    tool = self.tools.get(tc.name)
                    if tool is None:
                        tool_output = f"Error: Unknown tool '{tc.name}'. Available: {self.tools.tool_names}"
                        tool_results_content.append({
                            "type": "tool_result",
                            "tool_use_id": tc.id,
                            "content": tool_output,
                            "is_error": True,
                        })
                        steps.append(AgentStep(
                            step_index=step_idx, tool_name=tc.name,
                            tool_input=tc.input, tool_output=tool_output,
                            is_error=True,
                            duration_ms=(time.perf_counter() - step_start) * 1000,
                        ))
                        continue

                    # ── Verify before execute ──
                    await self._emit_status("verifying", {
                        "step": step_idx + 1,
                        "tool": tc.name,
                        "round": round_idx + 1,
                    })
                    verification, cert, action = await self._verify_tool_call(tool, tc)

                    if not verification.valid:
                        tool_output = f"BLOCKED: Verification failed - {verification.violations}"
                        tool_results_content.append({
                            "type": "tool_result",
                            "tool_use_id": tc.id,
                            "content": tool_output,
                            "is_error": True,
                        })
                        steps.append(AgentStep(
                            step_index=step_idx, tool_name=tc.name,
                            tool_input=tc.input, tool_output=tool_output,
                            is_error=True, verification=verification,
                            duration_ms=(time.perf_counter() - step_start) * 1000,
                        ))
                        audit.append({
                            "phase": "verification_blocked",
                            "tool": tc.name,
                            "violations": verification.violations,
                        })
                        continue

                    # ── A2 FIX: Kernel validates certificate before execution ──
                    if cert is None or not self._kernel.validate_certificate(
                        cert, action.to_hash()
                    ):
                        cert_id = cert.id if cert else "none"
                        tool_output = (
                            f"BLOCKED: Certificate validation failed - "
                            f"cert={cert_id}, action={tc.name}"
                        )
                        self._telemetry.verifications_blocked.add(
                            1, {"action": tc.name, "reason": "certificate_invalid"},
                        )
                        tool_results_content.append({
                            "type": "tool_result",
                            "tool_use_id": tc.id,
                            "content": tool_output,
                            "is_error": True,
                        })
                        steps.append(AgentStep(
                            step_index=step_idx, tool_name=tc.name,
                            tool_input=tc.input, tool_output=tool_output,
                            is_error=True, verification=verification,
                            duration_ms=(time.perf_counter() - step_start) * 1000,
                        ))
                        audit.append({
                            "phase": "certificate_rejected",
                            "tool": tc.name,
                            "certificate_id": cert_id,
                            "action_hash": action.to_hash()[:16],
                        })
                        continue

                    # ── A8 FIX: Human approval gate ──
                    spec_categories = None
                    if self._loaded_constraints:
                        spec_categories = self._loaded_constraints.get_approval_categories(tc.name)

                    approval_decision = await self._approval_gate.check(
                        tool_name=tc.name,
                        tool_input=tc.input,
                        step_index=step_idx,
                        spec_categories=spec_categories,
                    )

                    if approval_decision.blocked:
                        tool_output = (
                            f"BLOCKED: Human approval required but "
                            f"{approval_decision.verdict.value} - "
                            f"{approval_decision.reason}"
                        )
                        tool_results_content.append({
                            "type": "tool_result",
                            "tool_use_id": tc.id,
                            "content": tool_output,
                            "is_error": True,
                        })
                        steps.append(AgentStep(
                            step_index=step_idx, tool_name=tc.name,
                            tool_input=tc.input, tool_output=tool_output,
                            is_error=True, verification=verification,
                            approval_verdict=approval_decision.verdict.value,
                            approval_categories=sorted(approval_decision.matched_categories),
                            duration_ms=(time.perf_counter() - step_start) * 1000,
                        ))
                        audit.append({
                            "phase": "approval_blocked",
                            "tool": tc.name,
                            "verdict": approval_decision.verdict.value,
                            "categories": sorted(approval_decision.matched_categories),
                            "reason": approval_decision.reason,
                        })
                        continue

                    # ── A5 FIX: IFC check - context taint vs tool input labels ──
                    ifc_input_check = self._ifc.check_flow_to_tool_input(
                        step_idx, tc.name, tool.input_labels,
                    )
                    if not ifc_input_check.allowed and self._ifc.is_strict:
                        tool_output = (
                            f"BLOCKED: IFC violation - context taint "
                            f"{self._ifc.context_level.value} cannot flow to "
                            f"tool '{tc.name}' (accepts: {tool.input_labels})"
                        )
                        self._telemetry.record_ifc_violation(
                            self._ifc.context_level.value,
                            f"tool:{tc.name}",
                        )
                        tool_results_content.append({
                            "type": "tool_result",
                            "tool_use_id": tc.id,
                            "content": tool_output,
                            "is_error": True,
                        })
                        steps.append(AgentStep(
                            step_index=step_idx, tool_name=tc.name,
                            tool_input=tc.input, tool_output=tool_output,
                            is_error=True, verification=verification,
                            ifc_flow_blocked=True,
                            duration_ms=(time.perf_counter() - step_start) * 1000,
                        ))
                        audit.append({
                            "phase": "ifc_input_blocked",
                            "tool": tc.name,
                            "context_level": self._ifc.context_level.value,
                            "tool_input_labels": tool.input_labels,
                            "reason": ifc_input_check.reason,
                        })
                        continue

                    # ── Lean4 lattice-proven flow verification ──
                    lean_step_result: Optional[LeanFlowResult] = None
                    lean_output_result: Optional[LeanFlowResult] = None

                    lean_step_result = await self._lean_verifier.check_flow(
                        step_index=step_idx,
                        tool=tc.name,
                        input_labels=tool.input_labels,
                        output_label=(
                            tool.output_labels[0]
                            if tool.output_labels
                            else "Internal"
                        ),
                        data_id=f"step_{step_idx}_{tc.name}",
                        cost=tool.estimated_cost_cents,
                    )

                    if not lean_step_result.ok and lean_step_result.proven:
                        # Lean4 proven violation - mathematically certain this
                        # flow is disallowed.  Block unconditionally.
                        tool_output = (
                            f"BLOCKED: Lean4 proven flow violation - "
                            f"{lean_step_result.detail}"
                        )
                        self._telemetry.record_ifc_violation(
                            ",".join(tool.input_labels),
                            f"lean4:{tc.name}",
                        )
                        tool_results_content.append({
                            "type": "tool_result",
                            "tool_use_id": tc.id,
                            "content": tool_output,
                            "is_error": True,
                        })
                        steps.append(AgentStep(
                            step_index=step_idx, tool_name=tc.name,
                            tool_input=tc.input, tool_output=tool_output,
                            is_error=True, verification=verification,
                            ifc_flow_blocked=True,
                            lean_flow_result=lean_step_result.to_dict(),
                            lean_proven=True,
                            duration_ms=(time.perf_counter() - step_start) * 1000,
                        ))
                        audit.append({
                            "phase": "lean_flow_blocked",
                            "tool": tc.name,
                            "input_labels": tool.input_labels,
                            "output_label": (
                                tool.output_labels[0]
                                if tool.output_labels
                                else "Internal"
                            ),
                            "error": lean_step_result.error,
                            "detail": lean_step_result.detail,
                            "proven": True,
                        })
                        continue

                    if lean_step_result.ok and lean_step_result.proven:
                        audit.append({
                            "phase": "lean_flow_verified",
                            "tool": tc.name,
                            "step": step_idx,
                            "proven": True,
                            "latency_ms": round(lean_step_result.latency_ms, 2),
                        })
                    elif not lean_step_result.ok and not lean_step_result.proven:
                        # Non-proven error (timeout, communication failure) -
                        # advisory only, Z3 verification still in effect.
                        log.warning(
                            "Lean4 check non-fatal error for %s step %d: %s",
                            tc.name, step_idx, lean_step_result.error,
                        )
                        audit.append({
                            "phase": "lean_flow_advisory_error",
                            "tool": tc.name,
                            "step": step_idx,
                            "error": lean_step_result.error,
                            "detail": lean_step_result.detail,
                        })

                    # ── A4 FIX: Scan tool INPUTS before execution ──
                    input_phase = self._io_scanner.scan_tool_input(
                        tool_name=tc.name,
                        tool_input=tc.input,
                        step_index=step_idx,
                    )
                    self._telemetry.record_content_scan(
                        self.content_policy.name,
                        clean=not input_phase.blocked,
                        phase=ScanPhase.TOOL_INPUT.value,
                        action=input_phase.action.value,
                    )

                    if input_phase.blocked:
                        tool_output = (
                            f"BLOCKED: Tool input content safety violation - "
                            f"{[v.matched_text for v in input_phase.scan_result.violations]}"
                        )
                        scan_agg = self._io_scanner.aggregate_step(
                            tc.name, step_idx,
                            input_scan=input_phase, output_scan=None,
                        )
                        step_scans.append(scan_agg)
                        tool_results_content.append({
                            "type": "tool_result",
                            "tool_use_id": tc.id,
                            "content": tool_output,
                            "is_error": True,
                        })
                        steps.append(AgentStep(
                            step_index=step_idx, tool_name=tc.name,
                            tool_input=tc.input, tool_output=tool_output,
                            is_error=True, verification=verification,
                            step_scan=scan_agg,
                            duration_ms=(time.perf_counter() - step_start) * 1000,
                        ))
                        audit.append({
                            "phase": "input_safety_blocked",
                            "tool": tc.name,
                            "violations": [v.matched_text for v in input_phase.scan_result.violations],
                        })
                        continue

                    # ── A6: Reserve budget BEFORE execution (atomic) ──
                    from agentsafe.capabilities.tokens import BudgetExhaustedError
                    cost = tool.estimated_cost_cents
                    try:
                        budget_reservation = self.token.reserve_budget(cost)
                    except BudgetExhaustedError:
                        tool_output_text = (
                            f"BLOCKED: Budget exhausted - need {cost} cents, "
                            f"only {self.token.budget_remaining_cents} remaining."
                        )
                        tool_results_content.append({
                            "type": "tool_result",
                            "tool_use_id": tc.id,
                            "content": tool_output_text,
                            "is_error": True,
                        })
                        steps.append(AgentStep(
                            step_index=step_idx, tool_name=tc.name,
                            tool_input=tc.input, tool_output=tool_output_text,
                            is_error=True, step_scan=None,
                            duration_ms=(time.perf_counter() - step_start) * 1000,
                        ))
                        audit.append({
                            "phase": "budget_exhausted",
                            "tool": tc.name,
                            "cost_needed": cost,
                            "budget_remaining": self.token.budget_remaining_cents,
                        })
                        continue

                    # ── Execute the tool inside reservation ──
                    try:
                        with budget_reservation:
                            tool_result = await tool.execute(
                                tool_use_id=tc.id,
                                token_id=getattr(self.token, "id", ""),
                                agent_id=getattr(self.token, "agent_id", ""),
                                **tc.input,
                            )
                    except BudgetExhaustedError:
                        raise  # should not happen but propagate
                    except Exception as exc:
                        # budget_reservation.__exit__ rolled back the cost
                        log.exception("Tool execution failed: %s", tc.name)
                        tool_result = ToolResult(
                            tool_use_id=tc.id,
                            output=f"Error: {type(exc).__name__}: {exc}",
                            is_error=True,
                        )

                    # ── A4 FIX: Scan tool OUTPUTS after execution ──
                    output_phase = self._io_scanner.scan_tool_output(
                        tool_name=tc.name,
                        tool_output=tool_result.output,
                        step_index=step_idx,
                    )
                    self._telemetry.record_content_scan(
                        self.content_policy.name,
                        clean=not output_phase.blocked and not output_phase.redacted,
                        phase=ScanPhase.TOOL_OUTPUT.value,
                        action=output_phase.action.value,
                    )

                    scan_agg = self._io_scanner.aggregate_step(
                        tc.name, step_idx,
                        input_scan=input_phase,
                        output_scan=output_phase,
                    )
                    step_scans.append(scan_agg)

                    # Determine effective output based on scan result
                    output_blocked = False
                    output_redacted = False
                    if output_phase.blocked:
                        effective_output = (
                            f"BLOCKED: Tool output content safety violation - "
                            f"{[v.matched_text for v in output_phase.scan_result.violations]}"
                        )
                        output_blocked = True
                        audit.append({
                            "phase": "output_safety_blocked",
                            "tool": tc.name,
                            "violations": [v.matched_text for v in output_phase.scan_result.violations],
                        })
                    elif output_phase.redacted:
                        effective_output = output_phase.sanitised_text
                        output_redacted = True
                        audit.append({
                            "phase": "output_redacted",
                            "tool": tc.name,
                            "pii_count": len(output_phase.scan_result.pii_detected),
                        })
                    elif output_phase.action == ScanAction.WARN:
                        effective_output = tool_result.output
                        audit.append({
                            "phase": "output_safety_warn",
                            "tool": tc.name,
                            "violations": [v.matched_text for v in output_phase.scan_result.violations],
                        })
                    else:
                        effective_output = tool_result.output

                    # ── A5 FIX: Tag output with content-aware IFC label ──
                    has_pii = len(output_phase.scan_result.pii_detected) > 0
                    has_secrets = len(output_phase.scan_result.secrets_detected) > 0
                    has_mnpi = any(
                        "mnpi" in v.category.value.lower()
                        for v in output_phase.scan_result.violations
                    )
                    ifc_record = self._ifc.tag_tool_output(
                        step_index=step_idx,
                        tool_name=tc.name,
                        declared_labels=tool.output_labels,
                        content_has_pii=has_pii,
                        content_has_secrets=has_secrets,
                        content_has_mnpi=has_mnpi,
                        pii_was_redacted=output_redacted,
                    )

                    if ifc_record.promoted:
                        self._telemetry.record_ifc_violation(
                            ifc_record.declared_level.value,
                            ifc_record.effective_level.value,
                        )
                        audit.append({
                            "phase": "ifc_label_promoted",
                            "tool": tc.name,
                            "declared": ifc_record.declared_level.value,
                            "effective": ifc_record.effective_level.value,
                            "tags": sorted(ifc_record.tags),
                        })

                    # ── A5 FIX: Check flow to LLM context ──
                    ifc_llm_flow = self._ifc.check_flow_to_llm(step_idx, tc.name)
                    if not ifc_llm_flow.allowed and self._ifc.is_strict:
                        effective_output = (
                            f"BLOCKED: IFC flow rule prevents "
                            f"{ifc_record.effective_level.value} data "
                            f"from tool '{tc.name}' entering LLM context."
                        )
                        output_blocked = True
                        self._telemetry.record_ifc_violation(
                            ifc_record.effective_level.value,
                            "llm_context",
                        )
                        audit.append({
                            "phase": "ifc_flow_to_llm_blocked",
                            "tool": tc.name,
                            "effective_level": ifc_record.effective_level.value,
                            "reason": ifc_llm_flow.reason,
                        })

                    # ── Lean4 output flow check - proven lattice ──
                    lean_output_result = await self._lean_verifier.check_output_flow(
                        step_index=step_idx,
                        tool=tc.name,
                        data_label=ifc_record.effective_level.value.capitalize(),
                        target_label="Internal",  # LLM context level
                        data_id=f"output_{step_idx}_{tc.name}",
                    )
                    if not lean_output_result.ok and lean_output_result.proven:
                        # Lean4 mathematically proved this output cannot flow
                        # to the LLM context.
                        effective_output = (
                            f"BLOCKED: Lean4 proven - {ifc_record.effective_level.value} "
                            f"data from '{tc.name}' cannot enter LLM context. "
                            f"{lean_output_result.detail}"
                        )
                        output_blocked = True
                        self._telemetry.record_ifc_violation(
                            ifc_record.effective_level.value,
                            "lean4:llm_context",
                        )
                        audit.append({
                            "phase": "lean_output_flow_blocked",
                            "tool": tc.name,
                            "data_label": ifc_record.effective_level.value,
                            "target_label": "Internal",
                            "proven": True,
                        })
                    elif lean_output_result.ok and lean_output_result.proven:
                        audit.append({
                            "phase": "lean_output_flow_verified",
                            "tool": tc.name,
                            "data_label": ifc_record.effective_level.value,
                            "target_label": "Internal",
                            "proven": True,
                            "latency_ms": round(lean_output_result.latency_ms, 2),
                        })
                    elif not lean_output_result.ok and not lean_output_result.proven:
                        log.warning(
                            "Lean4 output check non-fatal error for %s: %s",
                            tc.name, lean_output_result.error,
                        )

                    # Build safe tool result for LLM
                    safe_tool_result = ToolResult(
                        tool_use_id=tool_result.tool_use_id,
                        output=effective_output,
                        is_error=tool_result.is_error or output_blocked,
                        metadata=tool_result.metadata,
                    )

                    # Truncate large output before sending to LLM
                    safe_tool_result = safe_tool_result.truncated(max_chars=16_000)

                    # A6: Budget already reserved before execution;
                    # committed on success, rolled back on tool exception.
                    total_cost += cost

                    cert_id = cert.id if cert else ""
                    if cert_id:
                        certificates.append(cert_id)

                    step_duration = (time.perf_counter() - step_start) * 1000

                    steps.append(AgentStep(
                        step_index=step_idx,
                        tool_name=tc.name,
                        tool_input=tc.input,
                        tool_output=safe_tool_result.output,
                        is_error=safe_tool_result.is_error,
                        verification=verification,
                        verification_certificate=(
                            cert.to_dict() if cert is not None else None
                        ),
                        certificate_id=cert_id,
                        cost_cents=cost,
                        duration_ms=step_duration,
                        step_scan=scan_agg,
                        ifc_effective_level=ifc_record.effective_level.value,
                        ifc_promoted=ifc_record.promoted,
                        ifc_flow_blocked=not ifc_llm_flow.allowed,
                        approval_verdict=approval_decision.verdict.value,
                        approval_categories=sorted(approval_decision.matched_categories),
                        lean_flow_result=(
                            lean_step_result.to_dict()
                            if lean_step_result else None
                        ),
                        lean_proven=(
                            lean_step_result.proven
                            if lean_step_result else False
                        ),
                        tool_metadata=(
                            dict(safe_tool_result.metadata)
                            if safe_tool_result.metadata else None
                        ),
                    ))

                    tool_results_content.append({
                        "type": "tool_result",
                        "tool_use_id": tc.id,
                        "content": safe_tool_result.output,
                        "is_error": safe_tool_result.is_error,
                    })

                    audit.append({
                        "phase": "tool_executed",
                        "tool": tc.name,
                        "verified": True,
                        "certificate_id": cert_id,
                        "cost_cents": cost,
                        "is_error": safe_tool_result.is_error,
                        "duration_ms": round(step_duration, 2),
                        "ifc_level": ifc_record.effective_level.value,
                        "ifc_promoted": ifc_record.promoted,
                        "lean_proven": (
                            lean_step_result.proven
                            if lean_step_result else False
                        ),
                        "lean_certificate": bool(
                            lean_step_result
                            and lean_step_result.certificate
                        ),
                    })

                    await self._emit_status("tool_completed", {
                        "step": step_idx + 1,
                        "tool": tc.name,
                        "is_error": safe_tool_result.is_error,
                        "verified": True,
                        "certificate_id": cert_id,
                        "ifc_level": ifc_record.effective_level.value,
                    })

                # Append all tool results as a single user message
                messages.append({"role": "user", "content": tool_results_content})

            # ── Max rounds reached ──
            await self._lean_verifier.shutdown()
            ifc_summary = self._ifc.summary()
            duration_ms = (time.perf_counter() - start) * 1000
            return AgenticResult(
                task=task,
                output="Agent reached maximum tool-use rounds without completing.",
                steps=steps,
                certificates=certificates,
                audit_trail=audit,
                total_cost_cents=total_cost,
                total_input_tokens=self._client.usage.input_tokens,
                total_output_tokens=self._client.usage.output_tokens,
                duration_ms=duration_ms,
                success=False,
                error=f"Exceeded max rounds ({self.llm_config.max_tool_rounds})",
                step_scans=step_scans,
                ifc_summary=ifc_summary,
                approval_summary=self._approval_gate.summary(),
                lean_summary=self._lean_verifier.summary(),
                verification_profile=self._verification_profile,
            )

    # ── Error Handling ──────────────────────────────────────────
        except Exception as exc:
            duration_ms = (time.perf_counter() - start) * 1000
            log.exception("AgenticExecutor.run() failed")
            audit.append({"phase": "error", "error": str(exc), "time": time.time()})
            await self._emit_status("failed", {"error": str(exc)})

            # Best-effort shutdown of Lean4 kernel
            lean_certificates: List[Dict[str, Any]] = []
            try:
                lean_certificates = await self._lean_verifier.get_certificates()
                await self._lean_verifier.shutdown()
            except Exception:
                pass

            ifc_summary = self._ifc.summary()
            return AgenticResult(
                task=task,
                steps=steps,
                certificates=certificates,
                audit_trail=audit,
                total_cost_cents=total_cost,
                total_input_tokens=self._client.usage.input_tokens,
                total_output_tokens=self._client.usage.output_tokens,
                duration_ms=duration_ms,
                success=False,
                error=str(exc),
                step_scans=step_scans,
                ifc_summary=ifc_summary,
                approval_summary=self._approval_gate.summary(),
                lean_summary=self._lean_verifier.summary(),
                lean_certificates=lean_certificates,
                verification_profile=self._verification_profile,
            )

    def _load_verification_profile(self) -> Optional[Dict[str, Any]]:
        metadata = getattr(self.token, "metadata", None)
        try:
            if metadata is not None:
                profile = metadata.get("verification_profile")
                if isinstance(profile, dict):
                    return profile
        except Exception:
            pass
        return None

    def _profile(self) -> Dict[str, Any]:
        profile = self._verification_profile or {}
        return profile if isinstance(profile, dict) else {}

    def _is_public_safe_summary_profile(self) -> bool:
        profile = self._profile()
        return profile.get("task_class") == "public_safe_summary"

    def _is_reviewer_profile(self) -> bool:
        return self._profile().get("stage_role") == "reviewer"

    def _is_release_profile(self) -> bool:
        return self._profile().get("stage_role") == "release"

    def _has_scoped_permissions(self) -> bool:
        profile = self._profile()
        ceiling = profile.get("permission_ceiling")
        if not isinstance(ceiling, list) or not ceiling or "*" in ceiling:
            return False
        permissions = list(getattr(self.token, "permissions", []) or [])
        return bool(permissions) and all(permission in ceiling for permission in permissions)

    @staticmethod
    def _normalise_artifact_text(text: str) -> str:
        lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
        return "\n".join(lines).strip()

    @classmethod
    def _artifact_hash(cls, text: str) -> str:
        canonical = cls._normalise_artifact_text(text)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _build_approved_artifact(
        self,
        *,
        artifact_text: str,
        scan: ScanResult,
        lean_result: LeanFlowResult,
    ) -> Optional[Dict[str, Any]]:
        if not self._is_reviewer_profile():
            return None

        canonical_text = self._normalise_artifact_text(artifact_text)
        if not canonical_text:
            return None

        lowered = canonical_text.lower()
        approved_for_release = (
            scan.safe_to_proceed
            and lean_result.ok
            and "no-go" not in lowered
            and "[release hold]" not in lowered
            and "[ifc blocked]" not in lowered
            and "[lean4 proven block]" not in lowered
        )

        return {
            "text": canonical_text,
            "sha256": self._artifact_hash(canonical_text),
            "approved_for_release": approved_for_release,
            "stage_role": self._profile().get("stage_role", "single_agent"),
            "task_class": self._profile().get("task_class", "general_analysis"),
        }

    def _release_binding(self) -> Dict[str, Any]:
        metadata = self._profile().get("metadata")
        if isinstance(metadata, dict):
            binding = metadata.get("release_binding")
            if isinstance(binding, dict):
                return binding
        return {}

    def _enforce_release_artifact_binding(
        self,
        *,
        final_text: str,
        audit: List[Dict[str, Any]],
    ) -> tuple[str, Optional[Dict[str, Any]]]:
        if not self._is_release_profile():
            return final_text, None

        binding = self._release_binding()
        approved_artifacts = binding.get("approved_artifacts")
        if not isinstance(approved_artifacts, list) or not approved_artifacts:
            audit.append({"phase": "release_artifact_binding_missing"})
            return (
                "[RELEASE HOLD] No approved upstream artifact is bound to this release stage.",
                {
                    "bound": False,
                    "reason": "missing_binding",
                    "approved_hashes": [],
                },
            )

        submitted_hash = self._artifact_hash(final_text)
        approved_by_hash = {
            str(artifact.get("sha256")): artifact
            for artifact in approved_artifacts
            if isinstance(artifact, dict) and artifact.get("sha256")
        }
        matched = approved_by_hash.get(submitted_hash)
        if isinstance(matched, dict):
            audit.append({
                "phase": "release_artifact_hash_verified",
                "artifact_hash": submitted_hash,
                "upstream_execution_id": matched.get("execution_id"),
            })
            return final_text, {
                "bound": True,
                "rebound": False,
                "artifact_hash": submitted_hash,
                "submitted_hash": submitted_hash,
                "upstream_execution_id": matched.get("execution_id"),
                "approved_hashes": sorted(approved_by_hash.keys()),
            }

        if len(approved_by_hash) == 1:
            bound_hash, artifact = next(iter(approved_by_hash.items()))
            bound_text = str(artifact.get("text") or "").strip()
            if bound_text:
                audit.append({
                    "phase": "release_output_bound_to_upstream_artifact",
                    "submitted_hash": submitted_hash,
                    "artifact_hash": bound_hash,
                    "upstream_execution_id": artifact.get("execution_id"),
                })
                return bound_text, {
                    "bound": True,
                    "rebound": True,
                    "artifact_hash": bound_hash,
                    "submitted_hash": submitted_hash,
                    "upstream_execution_id": artifact.get("execution_id"),
                    "approved_hashes": [bound_hash],
                }

        audit.append({
            "phase": "release_artifact_hash_mismatch",
            "submitted_hash": submitted_hash,
            "approved_hashes": sorted(approved_by_hash.keys()),
        })
        return (
            "[RELEASE HOLD] Final output does not match an approved upstream artifact.",
            {
                "bound": False,
                "reason": "hash_mismatch",
                "submitted_hash": submitted_hash,
                "approved_hashes": sorted(approved_by_hash.keys()),
            },
        )

    def _issue_final_output_certificate(
        self,
        *,
        task: str,
        final_text: str,
        scan: ScanResult,
        lean_result: LeanFlowResult,
        prompt_was_redacted: bool,
        release_targets: List[str],
        release_binding_summary: Optional[Dict[str, Any]] = None,
    ) -> Optional[VerifiedCertificate]:
        verified_properties: List[str] = []
        profile = self._profile()
        has_redacted_or_clean_output = not scan.pii_found or scan.remediated

        if self._is_public_safe_summary_profile() and "public" in release_targets:
            if has_redacted_or_clean_output:
                verified_properties.extend([
                    "no_phi_external_flow",
                    "output_deidentification_verified",
                ])
            if prompt_was_redacted or self._has_scoped_permissions():
                verified_properties.append("minimum_necessary_access")
            if self.token.is_valid():
                verified_properties.append("authorized_user_only")

        if self._is_reviewer_profile():
            verified_properties.append("review_chain_integrity")
            if scan.safe_to_proceed:
                verified_properties.append("privilege_boundary_reviewed")
            if self._has_scoped_permissions():
                verified_properties.append("minimum_necessary_access")
            if self.token.is_valid():
                verified_properties.append("authorized_user_only")

        if self._is_release_profile():
            if isinstance(profile.get("upstream_execution_ids"), list) and profile.get("upstream_execution_ids"):
                verified_properties.extend([
                    "release_gate_satisfied",
                    "review_completed_before_release",
                ])
            if isinstance(release_binding_summary, dict) and release_binding_summary.get("bound"):
                verified_properties.append("release_output_bound_to_review_artifact")
            if has_redacted_or_clean_output:
                verified_properties.append("output_deidentification_verified")
            if self._has_scoped_permissions():
                verified_properties.append("minimum_necessary_access")
            if self.token.is_valid():
                verified_properties.append("authorized_user_only")

        if lean_result.ok and lean_result.proven:
            verified_properties.append("information_flow: proven")

        if not verified_properties:
            return None

        plan_hash = hashlib.sha256(f"{task}\n{final_text}".encode()).hexdigest()
        prover = "runtime+lean4" if lean_result.ok and lean_result.proven else "runtime"
        return self._ca.issue_certificate(
            theorem="final_output_safe",
            plan_hash=plan_hash,
            verified_properties=list(dict.fromkeys(verified_properties)),
            proof_trace="final_output_scan",
            prover=prover,
        )

    # ── Verification ──────────────────────────────────────────────

    async def _verify_tool_call(
        self,
        tool: BaseTool,
        tc: ToolCallRequest,
    ) -> tuple[VerificationResult, Optional[VerifiedCertificate], AgentAction]:
        """
        Build an AgentAction from the tool call and verify it.

        Returns (verification_result, certificate_or_None, action).

        IMPROVED (A1): catches ``TokenInvalidError`` raised by the
        pre-verification gate and converts it into a failed
        ``VerificationResult``.
        """
        from agentsafe.agents.base import TokenInvalidError

        action = AgentAction(
            tool=tc.name,
            parameters=tc.input,
            required_capabilities=tool.required_capabilities,
            estimated_cost_cents=tool.estimated_cost_cents,
            input_labels=tool.input_labels,
            output_labels=tool.output_labels,
        )

        try:
            verification = await self._verifier.verify_action(action)
        except TokenInvalidError as exc:
            verification = VerificationResult(
                valid=False,
                violations=[f"{exc.reason}: {exc.token_id}"],
                used_z3=False,
            )
        cert = verification.certificate  # set by verify_action if valid
        return verification, cert, action

    # ── Message construction ──────────────────────────────────────

    @staticmethod
    def _build_assistant_content(response: LLMResponse) -> List[Dict[str, Any]]:
        """
        Build the ``content`` list for an assistant message from an
        LLM response that may contain text and tool_use blocks.
        """
        content: List[Dict[str, Any]] = []
        if response.text:
            content.append({"type": "text", "text": response.text})
        for tc in response.tool_calls:
            content.append({
                "type": "tool_use",
                "id": tc.id,
                "name": tc.name,
                "input": tc.input,
            })
        return content

    # ── Status emission ───────────────────────────────────────────

    async def _emit_status(self, status: str, data: Optional[Dict[str, Any]] = None) -> None:
        if self.on_status:
            try:
                await self.on_status(status, data or {})
            except Exception:
                log.debug("Status callback error", exc_info=True)

    async def close(self) -> None:
        """Release resources."""
        try:
            await self._lean_verifier.shutdown()
        except Exception:
            pass
        await self._client.close()


# ── Internal verification shim ─────────────────────────────────────

class _VerificationShim(VerifiedAgent):
    """
    Thin subclass of VerifiedAgent that exists solely to give the
    agentic executor access to ``verify_action()`` (which does the
    Z3 / structural verification and issues certificates).

    We don't use any of the LLM or tool-execution methods on this
    class - only the verification path.
    """

    def __init__(
        self, agent_id: str, capability_token: CapabilityToken,
        compliance_policy: str = "default",
    ):
        super().__init__(
            agent_id, capability_token, llm_client=None,
            compliance_policy=compliance_policy,
        )

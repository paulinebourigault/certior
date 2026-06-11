"""
Human Approval Gate - A8 FIX.

Enforces ``requires_human_approval`` from ContentSafetyPolicy and
ComplianceConfig.  The approval gate sits between certificate
validation (A2) and tool execution in the agentic executor.

Design
------
1. Each tool declares its *approval categories* - abstract labels
   like ``"external_communication"`` or ``"data_export"`` that map to
   the labels in ``policy.requires_human_approval``.
2. At execution time, the gate checks whether any of the tool's
   categories match the policy.  If so, the tool call is **blocked**
   unless an ``ApprovalCallback`` has been provided that grants
   approval for this specific invocation.
3. All approval decisions (granted, denied, not-required) are recorded
   in machine-readable ``ApprovalDecision`` objects for the audit trail.

Callback protocol
-----------------
The ``ApprovalCallback`` is an async callable::

    async def callback(request: ApprovalRequest) -> ApprovalResponse

This allows the product layer to implement:
  - Synchronous auto-approve (testing)
  - Human-in-the-loop via WebSocket / webhook / Slack
  - Policy-engine delegation (e.g. OPA)
  - Queue-based async workflows

If no callback is provided and the tool requires approval, the gate
returns DENIED - *deny by default*.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, FrozenSet, List, Optional, Set

from agentsafe.safety.scanner import ContentSafetyPolicy


# ── Types ────────────────────────────────────────────────────────────

class ApprovalVerdict(Enum):
    """Outcome of an approval gate check."""
    NOT_REQUIRED = "not_required"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(frozen=True)
class ApprovalRequest:
    """
    Information sent to the approval callback.

    The callback receives everything it needs to make an informed
    decision: what tool, what parameters, which categories triggered,
    and which policy is in effect.
    """
    request_id: str
    tool_name: str
    tool_input: Dict[str, Any]
    matched_categories: FrozenSet[str]
    policy_name: str
    step_index: int
    task_summary: str = ""


@dataclass(frozen=True)
class ApprovalResponse:
    """Response from the approval callback."""
    approved: bool
    approver: str = ""           # who approved (user id, policy engine, etc.)
    reason: str = ""             # human-readable rationale
    conditions: Dict[str, Any] = field(default_factory=dict)  # e.g. {"redact_pii": True}


@dataclass
class ApprovalDecision:
    """
    Auditable record of an approval gate decision.

    Every invocation of the gate produces one of these - even for
    tools that don't require approval (verdict = NOT_REQUIRED).
    """
    request_id: str
    tool_name: str
    step_index: int
    verdict: ApprovalVerdict
    matched_categories: FrozenSet[str]
    policy_name: str
    approver: str = ""
    reason: str = ""
    timestamp: float = field(default_factory=time.time)
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "tool_name": self.tool_name,
            "step_index": self.step_index,
            "verdict": self.verdict.value,
            "matched_categories": sorted(self.matched_categories),
            "policy_name": self.policy_name,
            "approver": self.approver,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "duration_ms": round(self.duration_ms, 2),
        }

    @property
    def blocked(self) -> bool:
        return self.verdict in (
            ApprovalVerdict.DENIED,
            ApprovalVerdict.TIMEOUT,
            ApprovalVerdict.ERROR,
        )


# ── Callback type ────────────────────────────────────────────────────

ApprovalCallback = Callable[
    [ApprovalRequest],
    Coroutine[Any, Any, ApprovalResponse],
]


# ── Default tool → category mapping ─────────────────────────────────

# Tools declare which abstract approval categories they belong to.
# This mapping is the *fallback* when the tool does not override
# ``approval_categories`` on BaseTool.  VERIFICATION.json can also
# declare these (see A9).

_DEFAULT_TOOL_CATEGORIES: Dict[str, FrozenSet[str]] = {
    "web_fetch": frozenset({
        "external_communication",
        "send_external_communication",
    }),
    "file_write": frozenset({
        "data_export",
        "document_sharing",
    }),
    "file_read": frozenset(),          # read-only, no approval needed
    "python_eval": frozenset(),        # compute-only, no approval needed
}


def get_tool_approval_categories(
    tool_name: str,
    *,
    tool_declared: Optional[List[str]] = None,
    spec_declared: Optional[List[str]] = None,
) -> FrozenSet[str]:
    """
    Resolve the approval categories for a tool.

    Priority:
    1. Categories from VERIFICATION.json (``spec_declared``) - A9
    2. Categories declared by the tool class (``tool_declared``)
    3. Default mapping in this module
    """
    if spec_declared is not None:
        return frozenset(spec_declared)
    if tool_declared is not None:
        return frozenset(tool_declared)
    return _DEFAULT_TOOL_CATEGORIES.get(tool_name, frozenset())


# ── Approval Gate ────────────────────────────────────────────────────

class ApprovalGate:
    """
    Policy-driven human approval enforcement.

    Wire into the agentic executor between certificate validation (A2)
    and tool execution.  Example::

        gate = ApprovalGate(policy, callback=my_approval_callback)

        decision = await gate.check(
            tool_name="web_fetch",
            tool_input={"url": "https://example.com"},
            step_index=0,
        )
        if decision.blocked:
            ... block tool execution ...

    If ``callback`` is None and approval is required, the gate
    returns DENIED.
    """

    def __init__(
        self,
        policy: ContentSafetyPolicy,
        callback: Optional[ApprovalCallback] = None,
        *,
        pre_approved_categories: Optional[Set[str]] = None,
        task_summary: str = "",
    ) -> None:
        self._policy = policy
        self._callback = callback
        self._pre_approved: Set[str] = set(pre_approved_categories or ())
        self._task_summary = task_summary
        self._decisions: List[ApprovalDecision] = []

        # Build the set of categories that require approval per policy
        self._required_categories: FrozenSet[str] = frozenset(
            policy.requires_human_approval
        )

    @property
    def decisions(self) -> List[ApprovalDecision]:
        """All approval decisions made so far (for audit trail)."""
        return list(self._decisions)

    @property
    def required_categories(self) -> FrozenSet[str]:
        return self._required_categories

    async def check(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        step_index: int,
        *,
        tool_categories: Optional[List[str]] = None,
        spec_categories: Optional[List[str]] = None,
    ) -> ApprovalDecision:
        """
        Check whether a tool call requires and has human approval.

        Parameters
        ----------
        tool_name : str
            The tool being invoked.
        tool_input : dict
            Parameters the LLM sent to the tool.
        step_index : int
            Execution step number (for audit).
        tool_categories : list[str], optional
            Categories declared by the tool class.
        spec_categories : list[str], optional
            Categories from VERIFICATION.json (A9).

        Returns
        -------
        ApprovalDecision
            Contains verdict (NOT_REQUIRED, APPROVED, DENIED, etc.),
            matched categories, and full audit info.
        """
        start = time.perf_counter()
        request_id = str(uuid.uuid4())

        # Resolve the tool's approval categories
        categories = get_tool_approval_categories(
            tool_name,
            tool_declared=tool_categories,
            spec_declared=spec_categories,
        )

        # Which categories actually trigger the policy?
        matched = categories & self._required_categories
        if not matched:
            decision = ApprovalDecision(
                request_id=request_id,
                tool_name=tool_name,
                step_index=step_index,
                verdict=ApprovalVerdict.NOT_REQUIRED,
                matched_categories=frozenset(),
                policy_name=self._policy.name,
                reason="No approval-requiring categories matched",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
            self._decisions.append(decision)
            return decision

        # Check pre-approved categories
        if matched <= self._pre_approved:
            decision = ApprovalDecision(
                request_id=request_id,
                tool_name=tool_name,
                step_index=step_index,
                verdict=ApprovalVerdict.APPROVED,
                matched_categories=matched,
                policy_name=self._policy.name,
                approver="pre_approved",
                reason=f"Categories pre-approved: {sorted(matched)}",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
            self._decisions.append(decision)
            return decision

        # No callback → deny by default
        if self._callback is None:
            decision = ApprovalDecision(
                request_id=request_id,
                tool_name=tool_name,
                step_index=step_index,
                verdict=ApprovalVerdict.DENIED,
                matched_categories=matched,
                policy_name=self._policy.name,
                reason=(
                    f"Approval required for categories {sorted(matched)} "
                    f"but no approval callback configured"
                ),
                duration_ms=(time.perf_counter() - start) * 1000,
            )
            self._decisions.append(decision)
            return decision

        # Build request and invoke callback
        request = ApprovalRequest(
            request_id=request_id,
            tool_name=tool_name,
            tool_input=tool_input,
            matched_categories=matched,
            policy_name=self._policy.name,
            step_index=step_index,
            task_summary=self._task_summary,
        )

        try:
            response = await self._callback(request)
        except Exception as exc:
            decision = ApprovalDecision(
                request_id=request_id,
                tool_name=tool_name,
                step_index=step_index,
                verdict=ApprovalVerdict.ERROR,
                matched_categories=matched,
                policy_name=self._policy.name,
                reason=f"Approval callback error: {type(exc).__name__}: {exc}",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
            self._decisions.append(decision)
            return decision

        verdict = (
            ApprovalVerdict.APPROVED if response.approved
            else ApprovalVerdict.DENIED
        )
        decision = ApprovalDecision(
            request_id=request_id,
            tool_name=tool_name,
            step_index=step_index,
            verdict=verdict,
            matched_categories=matched,
            policy_name=self._policy.name,
            approver=response.approver,
            reason=response.reason,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
        self._decisions.append(decision)
        return decision

    def summary(self) -> Dict[str, Any]:
        """Audit-trail-ready summary of all approval decisions."""
        total = len(self._decisions)
        approved = sum(
            1 for d in self._decisions
            if d.verdict == ApprovalVerdict.APPROVED
        )
        denied = sum(
            1 for d in self._decisions
            if d.verdict == ApprovalVerdict.DENIED
        )
        not_required = sum(
            1 for d in self._decisions
            if d.verdict == ApprovalVerdict.NOT_REQUIRED
        )
        return {
            "total_checks": total,
            "approved": approved,
            "denied": denied,
            "not_required": not_required,
            "errors": total - approved - denied - not_required,
            "decisions": [d.to_dict() for d in self._decisions],
        }

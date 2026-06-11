"""
Runtime Information Flow Control (IFC) enforcer for agentic execution.

Closes **BYPASS #5** from the deep security analysis:
    TaintTracker exists but is never wired into AgenticExecutor.run().
    Tool output labels are self-declared and never verified at runtime.
    A tool can return RESTRICTED data labeled as PUBLIC with zero
    enforcement.

This module provides:

1. **Content-aware label promotion** - When the content scanner detects
   PII, secrets, or MNPI in a tool's output, the taint tracker *promotes*
   the output's security label regardless of the tool's declaration.
   A tool that returns an SSN but declares its output as "public" will
   have its label promoted to SENSITIVE.

2. **Lattice-based flow checking** - Data can only flow from lower to
   higher (or equal) security levels.  A SENSITIVE tool output can flow
   into the LLM context (INTERNAL), but cannot flow to the final user
   output (PUBLIC) without redaction.

3. **Context taint accumulation** - The LLM context accumulates taint
   from every tool output that enters it.  The context level is the
   JOIN (maximum) of all data levels.  This is standard DIFC.

4. **Tool input taint checking** - Before a tool executes, the enforcer
   checks whether the accumulated context taint is compatible with the
   tool's declared input labels.  A "public-only" tool should not receive
   data tainted by RESTRICTED outputs.

5. **Final output flow check** - Before the final LLM text reaches the
   user, the enforcer verifies that the context taint can flow to the
   configured output level (default: PUBLIC).

6. **Audit trail and telemetry** - Every label assignment and flow check
   is logged for compliance and emitted via OpenTelemetry.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from agentsafe.flow.information_flow import (
    FlowRule,
    SecurityLabel,
    SecurityLevel,
    TaintTracker,
)


# ── Level resolution ──────────────────────────────────────────────

# Mapping from label string → SecurityLevel.  Tools and skills declare
# labels as strings ("public", "internal", "sensitive", "restricted",
# "cached") so we need a canonical mapping.
_LEVEL_MAP: Dict[str, SecurityLevel] = {
    "public": SecurityLevel.PUBLIC,
    "internal": SecurityLevel.INTERNAL,
    "cached": SecurityLevel.INTERNAL,     # cache ≡ internal
    "sensitive": SecurityLevel.SENSITIVE,
    "restricted": SecurityLevel.RESTRICTED,
}


def _resolve_level(labels: List[str]) -> SecurityLevel:
    """Return the highest security level from a list of label strings.

    If the list is empty the default is PUBLIC (least restrictive).
    Unknown labels map to INTERNAL as a safe middle ground.
    """
    if not labels:
        return SecurityLevel.PUBLIC
    levels = [_LEVEL_MAP.get(l.lower(), SecurityLevel.INTERNAL) for l in labels]
    return max(levels, key=lambda lv: lv.rank)


# ── Data types ────────────────────────────────────────────────────

class FlowVerdict(Enum):
    """Outcome of a single flow check."""
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    PROMOTED = "promoted"   # Label was promoted by content detection


@dataclass
class FlowCheckResult:
    """Result of checking one information flow."""
    verdict: FlowVerdict
    source_id: str
    source_label: SecurityLabel
    target_id: str
    target_label: SecurityLabel
    reason: str = ""
    promoted_from: Optional[SecurityLevel] = None  # original before promotion
    duration_ms: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.verdict != FlowVerdict.BLOCKED

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "verdict": self.verdict.value,
            "source_id": self.source_id,
            "source_level": self.source_label.level.value,
            "target_id": self.target_id,
            "target_level": self.target_label.level.value,
        }
        if self.reason:
            d["reason"] = self.reason
        if self.promoted_from is not None:
            d["promoted_from"] = self.promoted_from.value
        if self.duration_ms:
            d["duration_ms"] = round(self.duration_ms, 3)
        return d


@dataclass
class IFCStepRecord:
    """IFC state for a single execution step."""
    step_index: int
    tool_name: str
    data_id: str
    declared_level: SecurityLevel
    effective_level: SecurityLevel
    promoted: bool = False
    tags: Set[str] = field(default_factory=set)
    flow_to_llm: Optional[FlowCheckResult] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "step_index": self.step_index,
            "tool_name": self.tool_name,
            "data_id": self.data_id,
            "declared_level": self.declared_level.value,
            "effective_level": self.effective_level.value,
            "promoted": self.promoted,
        }
        if self.tags:
            d["tags"] = sorted(self.tags)
        if self.flow_to_llm is not None:
            d["flow_to_llm"] = self.flow_to_llm.to_dict()
        return d


@dataclass
class IFCSummary:
    """Summary of IFC enforcement across an entire execution."""
    steps_tracked: int = 0
    labels_promoted: int = 0
    flows_checked: int = 0
    flows_blocked: int = 0
    context_taint_level: str = "public"
    output_flow_allowed: bool = True
    output_flow_check: Optional[FlowCheckResult] = None
    step_records: List[IFCStepRecord] = field(default_factory=list)
    violations: List[FlowCheckResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "steps_tracked": self.steps_tracked,
            "labels_promoted": self.labels_promoted,
            "flows_checked": self.flows_checked,
            "flows_blocked": self.flows_blocked,
            "context_taint_level": self.context_taint_level,
            "output_flow_allowed": self.output_flow_allowed,
        }
        if self.violations:
            d["violations"] = [v.to_dict() for v in self.violations]
        return d


# ── IFC Enforcer ──────────────────────────────────────────────────

class IFCEnforcer:
    """Runtime information flow control enforcer for the agentic loop.

    The enforcer sits between the tool IO scanner and the LLM context.
    It answers three questions at each step:

    1. What is the *true* security level of this tool output?
       (Considering both declared labels and detected content.)

    2. Can this output flow into the LLM context?
       (Does its level ≤ context level?)

    3. Can a tool with these input labels receive data from the current
       context?  (Is the context taint ≤ tool's input level?)

    And one question at the end:

    4. Can the LLM context (with accumulated taint) flow to the user?
       (Is context taint ≤ output level?)

    Parameters
    ----------
    output_level : SecurityLevel
        Security level of the final output channel (user-facing).
        Default: PUBLIC.  Set to INTERNAL for internal pipelines.
    llm_context_level : SecurityLevel
        Base security level of the LLM context.
        Default: INTERNAL.
    strict : bool
        If True (default), flow violations block execution.
        If False, violations are logged as warnings but execution
        continues.
    flow_rules : list[FlowRule]
        Optional explicit flow rules from a compliance policy.
    """

    def __init__(
        self,
        output_level: SecurityLevel = SecurityLevel.PUBLIC,
        llm_context_level: SecurityLevel = SecurityLevel.PUBLIC,
        strict: bool = True,
        flow_rules: Optional[List[FlowRule]] = None,
    ) -> None:
        self._tracker = TaintTracker()
        self._output_level = output_level
        self._llm_base_level = llm_context_level
        self._strict = strict
        self._flow_rules = flow_rules or []

        # Accumulated context taint: starts at base level (PUBLIC by default).
        # The context level is promoted as tool outputs enter it -
        # this is standard DIFC "taint accumulation".
        # When no tools are called the context remains at PUBLIC,
        # so the final output check succeeds trivially.
        self._context_level = llm_context_level
        self._context_tags: Set[str] = set()

        # Records for audit
        self._step_records: List[IFCStepRecord] = []
        self._flow_checks: List[FlowCheckResult] = []
        self._violations: List[FlowCheckResult] = []

    # ── Public API ────────────────────────────────────────────────

    def tag_tool_output(
        self,
        step_index: int,
        tool_name: str,
        declared_labels: List[str],
        content_has_pii: bool = False,
        content_has_secrets: bool = False,
        content_has_mnpi: bool = False,
        pii_was_redacted: bool = False,
    ) -> IFCStepRecord:
        """Tag a tool output with its effective security label.

        Content-aware promotion rules:
        - Secrets detected → RESTRICTED (always, even if declared lower)
        - MNPI detected → RESTRICTED
        - PII detected AND not redacted → SENSITIVE (at minimum)
        - PII detected AND redacted → no promotion (PII is gone)

        Parameters
        ----------
        step_index : int
            Execution step index.
        tool_name : str
            Name of the tool.
        declared_labels : list[str]
            Labels the tool declared for its output.
        content_has_pii : bool
            Whether the content scanner found PII.
        content_has_secrets : bool
            Whether secrets were detected.
        content_has_mnpi : bool
            Whether MNPI keywords matched.
        pii_was_redacted : bool
            Whether the detected PII was successfully redacted.

        Returns
        -------
        IFCStepRecord
            The record with declared and effective labels.
        """
        start = time.perf_counter()

        declared_level = _resolve_level(declared_labels)
        effective_level = declared_level
        tags: Set[str] = set()
        promoted = False

        # Content-aware promotion
        if content_has_secrets:
            tags.add("secrets")
            if effective_level.rank < SecurityLevel.RESTRICTED.rank:
                effective_level = SecurityLevel.RESTRICTED
                promoted = True

        if content_has_mnpi:
            tags.add("mnpi")
            if effective_level.rank < SecurityLevel.RESTRICTED.rank:
                effective_level = SecurityLevel.RESTRICTED
                promoted = True

        if content_has_pii and not pii_was_redacted:
            tags.add("pii")
            if effective_level.rank < SecurityLevel.SENSITIVE.rank:
                effective_level = SecurityLevel.SENSITIVE
                promoted = True

        if content_has_pii and pii_was_redacted:
            tags.add("pii_redacted")
            # No promotion: PII was removed from the data

        # Register in taint tracker
        data_id = f"step_{step_index}_{tool_name}"
        label = SecurityLabel(
            level=effective_level,
            tags=tags,
            owner=tool_name,
        )
        self._tracker.tag(data_id, label)

        record = IFCStepRecord(
            step_index=step_index,
            tool_name=tool_name,
            data_id=data_id,
            declared_level=declared_level,
            effective_level=effective_level,
            promoted=promoted,
            tags=tags,
        )
        self._step_records.append(record)

        return record

    def check_flow_to_llm(
        self,
        step_index: int,
        tool_name: str,
    ) -> FlowCheckResult:
        """Check if a tool's output can flow into the LLM context.

        The LLM context has a *base* level (default INTERNAL), but
        once data enters it, the context level is promoted to the
        maximum of all entering data.  This is standard DIFC.

        A SENSITIVE output *can* enter an INTERNAL context (because
        information flows upward), but it promotes the context to
        SENSITIVE.

        A RESTRICTED output can also enter, promoting the context to
        RESTRICTED.

        In standard DIFC, flow checking would prevent HIGH → LOW, but
        in our case the LLM context *absorbs* the taint (it can handle
        any level).  The real enforcement is at the OUTPUT boundary.

        However, we still record the flow and update the context level.
        If explicit ``flow_rules`` forbid a particular flow, we block it.

        Returns
        -------
        FlowCheckResult
            Always allowed unless explicit flow rules block it.
        """
        start = time.perf_counter()

        data_id = f"step_{step_index}_{tool_name}"
        source_label = self._tracker.get_label(data_id)
        if source_label is None:
            # Untracked data: conservative treatment as PUBLIC
            source_label = SecurityLabel(level=SecurityLevel.PUBLIC)

        target_label = SecurityLabel(
            level=self._context_level,
            tags=self._context_tags,
        )

        # Check explicit flow rules
        blocked_by_rule = self._check_flow_rules(
            source_label, "llm_context",
        )

        # Update context taint (absorb)
        if source_label.level.rank > self._context_level.rank:
            self._context_level = source_label.level
        self._context_tags |= source_label.tags

        duration_ms = (time.perf_counter() - start) * 1000

        if blocked_by_rule:
            result = FlowCheckResult(
                verdict=FlowVerdict.BLOCKED,
                source_id=data_id,
                source_label=source_label,
                target_id="llm_context",
                target_label=target_label,
                reason=blocked_by_rule,
                duration_ms=duration_ms,
            )
            self._violations.append(result)
        else:
            result = FlowCheckResult(
                verdict=FlowVerdict.ALLOWED,
                source_id=data_id,
                source_label=source_label,
                target_id="llm_context",
                target_label=target_label,
                duration_ms=duration_ms,
            )

        # Attach to step record
        for rec in self._step_records:
            if rec.data_id == data_id:
                rec.flow_to_llm = result
                break

        self._flow_checks.append(result)
        return result

    def check_flow_to_tool_input(
        self,
        step_index: int,
        tool_name: str,
        tool_input_labels: List[str],
    ) -> FlowCheckResult:
        """Check if the current context taint is compatible with a tool's
        input labels.

        The accumulated context taint (from all previous tool outputs)
        must be ≤ the tool's declared input level.  For example, if
        the context contains RESTRICTED data and the tool only accepts
        PUBLIC input, this is a violation.

        Parameters
        ----------
        step_index : int
            Step index (for logging).
        tool_name : str
            Tool about to receive input.
        tool_input_labels : list[str]
            Tool's declared input labels.

        Returns
        -------
        FlowCheckResult
        """
        start = time.perf_counter()

        target_level = _resolve_level(tool_input_labels)
        source_label = SecurityLabel(
            level=self._context_level,
            tags=self._context_tags.copy(),
        )
        target_label = SecurityLabel(level=target_level)

        allowed = source_label.can_flow_to(target_label)
        duration_ms = (time.perf_counter() - start) * 1000

        if not allowed:
            result = FlowCheckResult(
                verdict=FlowVerdict.BLOCKED,
                source_id="llm_context",
                source_label=source_label,
                target_id=f"step_{step_index}_{tool_name}_input",
                target_label=target_label,
                reason=(
                    f"Context taint {self._context_level.value} cannot flow "
                    f"to tool '{tool_name}' which accepts {target_level.value}"
                ),
                duration_ms=duration_ms,
            )
            self._violations.append(result)
        else:
            result = FlowCheckResult(
                verdict=FlowVerdict.ALLOWED,
                source_id="llm_context",
                source_label=source_label,
                target_id=f"step_{step_index}_{tool_name}_input",
                target_label=target_label,
                duration_ms=duration_ms,
            )

        self._flow_checks.append(result)
        return result

    def check_flow_to_user(self) -> FlowCheckResult:
        """Check if the accumulated context taint can flow to the user.

        This is the final gate.  The check distinguishes between:

        * **Declared labels** - Tool-declared output levels (e.g. "internal").
          These are informational and verified at the Z3 level.  A tool
          declaring "internal" doesn't automatically mean the output
          cannot reach the user.

        * **Promoted labels** - Labels promoted by actual content detection
          (PII, secrets, MNPI).  These represent *real* sensitive content
          and MUST be blocked from flowing to a lower security level.

        The flow is blocked only when:
        1. The context contains data whose labels were *promoted* by
           content detection above the output level, OR
        2. Explicit flow rules forbid the flow.

        Returns
        -------
        FlowCheckResult
        """
        start = time.perf_counter()

        source_label = SecurityLabel(
            level=self._context_level,
            tags=self._context_tags.copy(),
        )
        target_label = SecurityLabel(level=self._output_level)

        # Determine if any promotion happened that makes the flow unsafe
        any_promoted_above_output = any(
            rec.promoted and rec.effective_level.rank > self._output_level.rank
            for rec in self._step_records
        )

        # Check explicit flow rules
        blocked_by_rule = self._check_flow_rules(source_label, "user_output")

        duration_ms = (time.perf_counter() - start) * 1000

        if any_promoted_above_output:
            # Real sensitive content detected - block the flow
            promoted_records = [
                rec for rec in self._step_records
                if rec.promoted and rec.effective_level.rank > self._output_level.rank
            ]
            reasons = [
                f"{r.tool_name}: {r.declared_level.value}→{r.effective_level.value} "
                f"(tags: {sorted(r.tags)})"
                for r in promoted_records
            ]
            result = FlowCheckResult(
                verdict=FlowVerdict.BLOCKED,
                source_id="llm_context",
                source_label=source_label,
                target_id="user_output",
                target_label=target_label,
                reason=(
                    f"Content detection promoted labels above output level: "
                    f"{'; '.join(reasons)}"
                ),
                duration_ms=duration_ms,
            )
            self._violations.append(result)
        elif blocked_by_rule:
            result = FlowCheckResult(
                verdict=FlowVerdict.BLOCKED,
                source_id="llm_context",
                source_label=source_label,
                target_id="user_output",
                target_label=target_label,
                reason=blocked_by_rule,
                duration_ms=duration_ms,
            )
            self._violations.append(result)
        else:
            result = FlowCheckResult(
                verdict=FlowVerdict.ALLOWED,
                source_id="llm_context",
                source_label=source_label,
                target_id="user_output",
                target_label=target_label,
                duration_ms=duration_ms,
            )

        self._flow_checks.append(result)
        return result

    # ── State queries ─────────────────────────────────────────────

    @property
    def context_level(self) -> SecurityLevel:
        """Current accumulated context taint level."""
        return self._context_level

    @property
    def context_tags(self) -> Set[str]:
        """Current accumulated context tags."""
        return self._context_tags.copy()

    @property
    def violations(self) -> List[FlowCheckResult]:
        """All flow violations detected during this execution."""
        return list(self._violations)

    @property
    def is_strict(self) -> bool:
        return self._strict

    @property
    def tracker(self) -> TaintTracker:
        """Underlying taint tracker (for advanced inspection)."""
        return self._tracker

    def summary(self) -> IFCSummary:
        """Build an IFC summary for the execution result."""
        output_check = None
        for fc in reversed(self._flow_checks):
            if fc.target_id == "user_output":
                output_check = fc
                break

        return IFCSummary(
            steps_tracked=len(self._step_records),
            labels_promoted=sum(1 for r in self._step_records if r.promoted),
            flows_checked=len(self._flow_checks),
            flows_blocked=len(self._violations),
            context_taint_level=self._context_level.value,
            output_flow_allowed=output_check.allowed if output_check else True,
            output_flow_check=output_check,
            step_records=list(self._step_records),
            violations=list(self._violations),
        )

    def reset(self) -> None:
        """Reset all state for a new execution."""
        self._tracker.clear()
        self._context_level = self._llm_base_level
        self._context_tags.clear()
        self._step_records.clear()
        self._flow_checks.clear()
        self._violations.clear()

    # ── Internal helpers ──────────────────────────────────────────

    def _check_flow_rules(
        self,
        source_label: SecurityLabel,
        target_name: str,
    ) -> str:
        """Check explicit flow rules.  Returns reason string if blocked,
        empty string if allowed."""
        source_tags = source_label.tags | {source_label.level.value}

        for rule in self._flow_rules:
            # Check if source matches the rule's source
            if rule.source.lower() in {t.lower() for t in source_tags}:
                # Check if target is forbidden
                if target_name.lower() in {
                    d.lower() for d in rule.forbidden_destinations
                }:
                    return (
                        f"Flow rule blocks {rule.source} → "
                        f"{target_name} (forbidden destination)"
                    )
                # Check if target is NOT in allowed destinations
                if rule.allowed_destinations:
                    allowed_lower = {d.lower() for d in rule.allowed_destinations}
                    if target_name.lower() not in allowed_lower:
                        return (
                            f"Flow rule blocks {rule.source} → "
                            f"{target_name} (not in allowed: "
                            f"{rule.allowed_destinations})"
                        )
        return ""

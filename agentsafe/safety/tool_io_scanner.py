"""
Tool I/O Content Safety Scanner
================================

Scans tool *inputs* and *outputs* at each step in the agentic execution
loop, closing BYPASS #4 (no content safety on tool inputs) and BYPASS #7
(intermediate tool results not scanned).

Architecture
------------

The prior code only ran ``ContentScanner.scan()`` on the **final** LLM
text response.  This module introduces ``ToolIOScanner``, which wraps
``ContentScanner`` and is called:

  1. **Before** tool execution - on the serialised tool input parameters.
  2. **After** tool execution - on the raw tool output string.

Scan results are recorded per-step in the audit trail and in telemetry.

Policy-Aware Decisions
----------------------

Not every violation blocks execution.  The scanner distinguishes:

  * **Block** - halt execution, return error to LLM.
    Triggered by: secrets detection, MNPI keywords, critical policy
    violations (blocked categories), and any violation in tool *inputs*
    (because inputs are under the LLM's control and should never carry
    unsafe content in the first place).

  * **Redact** - sanitise the content and continue.
    Triggered by: PII in tool *outputs* when the policy enables
    redaction (e.g. HIPAA with ``pii_config.redact=True``).  The
    redacted text replaces the raw output before it enters the LLM
    message history.

  * **Warn** - log for audit but do not block.
    Triggered by: warn-category matches.  These are recorded in the
    audit trail and telemetry but do not stop execution.

Serialisation
-------------

Tool inputs are ``Dict[str, Any]``.  We serialise them to a scannable
string via ``_serialise_tool_input()`` which handles nested dicts,
lists, and primitive types.  Keys are included because they can carry
sensitive information (e.g. ``{"patient_ssn": "123-45-6789"}``).

Thread Safety
-------------

``ToolIOScanner`` is stateless between calls - all per-step state lives
in the returned ``StepScanResult``.  Safe for concurrent use.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from agentsafe.safety.scanner import (
    ContentScanner,
    ContentSafetyPolicy,
    ScanResult,
    ScanViolation,
)
from agentsafe.safety.taxonomy import ContentRiskCategory

log = logging.getLogger(__name__)


# ── Scan phase enum ──────────────────────────────────────────────

class ScanPhase(str, Enum):
    """Where in the tool lifecycle a scan was performed."""
    TOOL_INPUT = "tool_input"
    TOOL_OUTPUT = "tool_output"
    FINAL_OUTPUT = "final_output"


# ── Scan action enum ─────────────────────────────────────────────

class ScanAction(str, Enum):
    """Decision taken after scanning."""
    PASS = "pass"           # No violations
    REDACT = "redact"       # PII redacted, execution continues
    BLOCK = "block"         # Critical violation, execution halted
    WARN = "warn"           # Logged but not blocked


# ── Per-scan result ──────────────────────────────────────────────

@dataclass
class PhaseScanResult:
    """Result of scanning a single piece of content (input or output)."""
    phase: ScanPhase
    action: ScanAction
    scan_result: ScanResult
    original_text: str = ""
    sanitised_text: str = ""
    duration_ms: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.action == ScanAction.BLOCK

    @property
    def redacted(self) -> bool:
        return self.action == ScanAction.REDACT

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase.value,
            "action": self.action.value,
            "clean": self.scan_result.clean,
            "violation_count": len(self.scan_result.violations),
            "pii_count": len(self.scan_result.pii_detected),
            "secrets_count": len(self.scan_result.secrets_detected),
            "redacted": self.redacted,
            "duration_ms": round(self.duration_ms, 3),
        }


# ── Per-step aggregate result ────────────────────────────────────

@dataclass
class StepScanResult:
    """Aggregate scan results for one tool step (input + output)."""
    tool_name: str
    step_index: int
    input_scan: Optional[PhaseScanResult] = None
    output_scan: Optional[PhaseScanResult] = None

    @property
    def blocked(self) -> bool:
        """True if either input or output scan blocked execution."""
        if self.input_scan and self.input_scan.blocked:
            return True
        if self.output_scan and self.output_scan.blocked:
            return True
        return False

    @property
    def any_violations(self) -> bool:
        """True if any scan found violations (even if only warned/redacted)."""
        if self.input_scan and not self.input_scan.scan_result.clean:
            return True
        if self.output_scan and not self.output_scan.scan_result.clean:
            return True
        return False

    @property
    def block_reason(self) -> str:
        """Human-readable reason for blocking, or empty string."""
        reasons: List[str] = []
        if self.input_scan and self.input_scan.blocked:
            for v in self.input_scan.scan_result.violations:
                reasons.append(f"input:{v.category.value}:{v.details or v.matched_text}")
        if self.output_scan and self.output_scan.blocked:
            for v in self.output_scan.scan_result.violations:
                reasons.append(f"output:{v.category.value}:{v.details or v.matched_text}")
        return "; ".join(reasons)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "tool_name": self.tool_name,
            "step_index": self.step_index,
            "blocked": self.blocked,
            "any_violations": self.any_violations,
        }
        if self.input_scan:
            d["input_scan"] = self.input_scan.to_dict()
        if self.output_scan:
            d["output_scan"] = self.output_scan.to_dict()
        return d


# ── Categories that always block (even in outputs) ───────────────

_ALWAYS_BLOCK_CATEGORIES = frozenset({
    ContentRiskCategory.MNPI_LEAK,
    ContentRiskCategory.PRIVILEGE_WAIVER,
    ContentRiskCategory.CRIMINAL_PLANNING,
    ContentRiskCategory.WEAPONS,
    ContentRiskCategory.ITAR_CONTROLLED,
})


# ── ToolIOScanner ────────────────────────────────────────────────

class ToolIOScanner:
    """
    Scans tool inputs and outputs for content safety violations.

    This scanner wraps ``ContentScanner`` and adds:

    * Serialisation of tool input dicts to scannable text
    * Phase-aware decision logic (block / redact / warn / pass)
    * Per-step result aggregation
    * Redaction of tool outputs before they enter the LLM context

    Usage::

        scanner = ToolIOScanner(policy)

        # Before tool execution:
        input_result = scanner.scan_tool_input(
            tool_name="web_fetch",
            tool_input={"url": "https://example.com/patients"},
            step_index=0,
        )
        if input_result.blocked:
            # Do not execute tool
            ...

        # After tool execution:
        output_result = scanner.scan_tool_output(
            tool_name="web_fetch",
            tool_output=raw_output_text,
            step_index=0,
        )
        if output_result.blocked:
            # Do not pass output to LLM
            ...
        safe_output = output_result.sanitised_text  # may be redacted
    """

    def __init__(self, policy: ContentSafetyPolicy) -> None:
        self._policy = policy
        self._scanner = ContentScanner(policy)
        # Pre-compute set of blocked categories for fast lookup
        self._blocked_cats = frozenset(policy.blocked_categories)

    @property
    def policy(self) -> ContentSafetyPolicy:
        return self._policy

    # ── Public API ───────────────────────────────────────────────

    def scan_tool_input(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        step_index: int = 0,
    ) -> PhaseScanResult:
        """
        Scan tool input parameters before execution.

        Tool inputs are under the LLM's control.  Any safety violation
        in the input is treated as a **block** because the LLM should
        never be constructing unsafe tool calls.

        Returns a ``PhaseScanResult`` with ``action=BLOCK`` if any
        violation is detected, or ``action=PASS`` otherwise.
        """
        start = time.perf_counter()

        serialised = _serialise_tool_input(tool_name, tool_input)
        scan = self._scanner.scan(serialised)

        if scan.pii_found:
            # PII in inputs is always suspicious - block even if the
            # policy would normally redact PII in outputs.
            action = ScanAction.BLOCK
            log.warning(
                "PII detected in tool input: tool=%s step=%d pii_count=%d",
                tool_name, step_index, len(scan.pii_detected),
            )
            if not any("PII" in v.details for v in scan.violations):
                scan.violations.append(ScanViolation(
                    category=ContentRiskCategory.HATE_BIAS_PII,
                    matched_text=f"{len(scan.pii_detected)} PII instance(s) in tool input",
                    severity="block",
                    details=f"PII types in input: {set(m.pii_type for m in scan.pii_detected)}",
                ))
                scan._recompute()
        elif not scan.clean:
            action = ScanAction.BLOCK
            log.warning(
                "Content safety BLOCK on tool input: tool=%s step=%d violations=%d",
                tool_name, step_index, len(scan.violations),
            )
        elif scan.secrets_detected:
            action = ScanAction.BLOCK
            log.warning(
                "Secrets detected in tool input: tool=%s step=%d",
                tool_name, step_index,
            )
        else:
            action = ScanAction.PASS

        duration = (time.perf_counter() - start) * 1000

        return PhaseScanResult(
            phase=ScanPhase.TOOL_INPUT,
            action=action,
            scan_result=scan,
            original_text=serialised,
            sanitised_text=serialised,  # inputs are not redacted, only blocked
            duration_ms=duration,
        )

    def scan_tool_output(
        self,
        tool_name: str,
        tool_output: str,
        step_index: int = 0,
    ) -> PhaseScanResult:
        """
        Scan tool output after execution, before it enters the LLM
        message history.

        The decision logic for outputs is more nuanced than for inputs:

        * **Secrets**: always BLOCK (secrets must never reach the LLM).
        * **Blocked-category violations**: BLOCK if the violation is in
          a category the policy blocks.
        * **Always-block categories** (MNPI, privilege waiver, etc.):
          BLOCK regardless of policy.
        * **PII with redaction enabled**: REDACT (replace PII, continue).
        * **PII without redaction**: BLOCK.
        * **Warn categories only**: WARN (log, continue with original).
        * **Clean**: PASS.
        """
        start = time.perf_counter()

        scan = self._scanner.scan(tool_output)

        action, sanitised = self._decide_output_action(scan, tool_output)

        if action == ScanAction.BLOCK:
            log.warning(
                "Content safety BLOCK on tool output: tool=%s step=%d violations=%d",
                tool_name, step_index, len(scan.violations),
            )
        elif action == ScanAction.REDACT:
            log.info(
                "Content safety REDACT on tool output: tool=%s step=%d pii=%d",
                tool_name, step_index, len(scan.pii_detected),
            )
        elif action == ScanAction.WARN:
            log.info(
                "Content safety WARN on tool output: tool=%s step=%d violations=%d",
                tool_name, step_index, len(scan.violations),
            )

        duration = (time.perf_counter() - start) * 1000

        return PhaseScanResult(
            phase=ScanPhase.TOOL_OUTPUT,
            action=action,
            scan_result=scan,
            original_text=tool_output,
            sanitised_text=sanitised,
            duration_ms=duration,
        )

    def aggregate_step(
        self,
        tool_name: str,
        step_index: int,
        input_scan: Optional[PhaseScanResult] = None,
        output_scan: Optional[PhaseScanResult] = None,
    ) -> StepScanResult:
        """Build a StepScanResult from input and output phase results."""
        return StepScanResult(
            tool_name=tool_name,
            step_index=step_index,
            input_scan=input_scan,
            output_scan=output_scan,
        )

    # ── Decision logic ───────────────────────────────────────────

    def _decide_output_action(
        self, scan: ScanResult, original_text: str,
    ) -> tuple[ScanAction, str]:
        """
        Determine the action for a tool output scan.

        Returns (action, sanitised_text).
        """
        # 1. Secrets always block - they must never reach the LLM.
        if scan.secrets_detected:
            return ScanAction.BLOCK, ""

        # 2. Check violations against policy
        has_block_violation = False
        has_warn_violation = False
        warn_cats = frozenset(self._policy.warn_categories)

        for v in scan.violations:
            # Always-block categories override everything
            if v.category in _ALWAYS_BLOCK_CATEGORIES:
                has_block_violation = True
                break
            # Policy-blocked categories
            if v.category in self._blocked_cats:
                has_block_violation = True
                break
            # Warn categories
            if v.category in warn_cats:
                has_warn_violation = True

        if has_block_violation:
            return ScanAction.BLOCK, ""

        # 3. PII handling
        pii_cfg = self._policy.pii_config
        if scan.pii_detected:
            if pii_cfg and pii_cfg.redact and scan.redacted_text:
                # Redact and continue - the sanitised text is safe
                return ScanAction.REDACT, scan.redacted_text
            elif pii_cfg and pii_cfg.detect:
                # Detection only, no redaction → block
                return ScanAction.BLOCK, ""
            # else: PII config not set, fall through

        # 4. Warn-only violations
        if has_warn_violation:
            return ScanAction.WARN, original_text

        # 5. No findings - content is clean
        # With the corrected ScanResult semantics, clean=True means
        # no violations, no PII, and no secrets.  If PII was found,
        # it was handled in step 3 (early return).
        if scan.clean:
            return ScanAction.PASS, original_text

        # 6. Fallback: violations present but not in block/warn cats
        # This shouldn't normally happen, but be safe.
        return ScanAction.BLOCK, ""


# ── Serialisation helper ─────────────────────────────────────────

def _serialise_tool_input(tool_name: str, tool_input: Dict[str, Any]) -> str:
    """
    Serialise a tool input dict to a scannable string.

    Includes the tool name and both keys and values because
    sensitive data can appear in either (e.g. a key named
    ``patient_ssn`` or a value containing an SSN).

    We use a simple key=value format rather than JSON so that
    regex-based PII detectors see natural text patterns.  For
    nested structures we fall back to JSON serialisation.
    """
    parts: List[str] = [f"tool:{tool_name}"]

    for key, value in tool_input.items():
        if isinstance(value, (dict, list)):
            # Complex values: serialise as JSON
            try:
                val_str = json.dumps(value, default=str)
            except (TypeError, ValueError):
                val_str = str(value)
        elif value is None:
            val_str = ""
        else:
            val_str = str(value)

        parts.append(f"{key}={val_str}")

    return "\n".join(parts)

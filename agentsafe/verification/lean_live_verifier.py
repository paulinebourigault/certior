"""
Lean4 Live Flow Verifier - Runtime Bridge to the Proven Lattice

Manages a persistent ``certior-flow-check`` subprocess that provides
mathematically-certified information flow verification for the live
agent loop.  Every flow decision is backed by the lattice proofs
(P13-P21, absorption, distributivity) from ``Certior.Lattice``.

Architecture:
    AgenticExecutor
        ↓ (per tool call)
    LeanLiveVerifier.check_flow(input_labels, output_label, ...)
        ↓ (JSON over stdin/stdout)
    certior-flow-check  (Lean4 binary, persistent subprocess)
        ↓ (uses proven flowAllowed from Certior.Lattice)
    ← certificate or violation

Graceful degradation: if the Lean4 binary is not available, the
verifier logs a warning and returns advisory-only results.  The Z3
verification layer continues to operate independently.

Usage::

    verifier = LeanLiveVerifier()
    await verifier.start(budget=10000, capabilities=[...], compliance="hipaa")

    result = await verifier.check_flow(
        step_index=0,
        tool="web_fetch",
        input_labels=["Public"],
        output_label="Internal",
        data_id="fetch_result",
        cost=100,
    )
    if result.ok:
        print(f"Lean4 certificate: {result.certificate}")
    else:
        print(f"Flow violation (proven): {result.detail}")

    await verifier.shutdown()
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# ── Default binary locations ──────────────────────────────────────────

_DEFAULT_BINARY_NAMES = [
    "certior-flow-check",
]

_DEFAULT_LAKE_PATHS = [
    # Relative to this file → lean4/CertiorPlan/.lake/build/bin/
    Path(__file__).resolve().parent.parent.parent
    / "lean4" / "CertiorPlan" / ".lake" / "build" / "bin" / "certior-flow-check",
]


def _find_binary() -> Optional[str]:
    """Locate the certior-flow-check binary."""
    # 1. Explicit env var
    env_path = os.environ.get("CERTIOR_FLOW_CHECK_BINARY")
    if env_path and Path(env_path).is_file():
        return env_path

    # 2. Lake build output
    for p in _DEFAULT_LAKE_PATHS:
        if p.is_file():
            return str(p)

    # 3. PATH lookup
    for name in _DEFAULT_BINARY_NAMES:
        found = shutil.which(name)
        if found:
            return found

    return None


# ── Result Types ──────────────────────────────────────────────────────

@dataclass
class LeanFlowResult:
    """Result of a Lean4 flow verification check."""

    ok: bool
    """Whether the flow check passed."""

    error: str = ""
    """Error type if check failed (e.g. 'flow_violation', 'budget_exhausted')."""

    detail: str = ""
    """Human-readable detail of the result."""

    certificate: Optional[Dict[str, Any]] = None
    """Lean-issued proof certificate (if flow allowed)."""

    proven: bool = False
    """Whether the result is backed by Lean4 lattice proofs."""

    steps_checked: int = 0
    budget_remaining: int = 0
    flow_violations: int = 0
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "ok": self.ok,
            "proven": self.proven,
            "latency_ms": round(self.latency_ms, 2),
        }
        if self.error:
            d["error"] = self.error
            d["detail"] = self.detail
        if self.certificate:
            d["certificate"] = self.certificate
        return d


@dataclass
class LeanFlowState:
    """Cumulative flow state tracked by the Lean kernel across a session."""

    steps_checked: int = 0
    budget_remaining: int = 0
    budget_total: int = 0
    certificates_count: int = 0
    flow_violations: int = 0
    compliance_policy: str = "default"
    flow_tracker: List[Dict[str, str]] = field(default_factory=list)
    certificates: List[Dict[str, Any]] = field(default_factory=list)


# ── Verifier ──────────────────────────────────────────────────────────

class LeanLiveVerifier:
    """
    Manages a persistent ``certior-flow-check`` subprocess for
    mathematically-certified information flow verification.

    The subprocess uses the *proven* ``SecurityLevel.levelCanFlowTo``
    from ``Certior.Lattice`` for every flow decision, meaning each
    certificate it issues is backed by the lattice proofs.

    Thread-safety: this class is designed for single-threaded async use
    within one ``AgenticExecutor`` session.  Each executor should own
    its own ``LeanLiveVerifier`` instance.
    """

    def __init__(
        self,
        binary: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        self._binary = binary or _find_binary()
        self._timeout = timeout
        self._process: Optional[asyncio.subprocess.Process] = None
        self._available: Optional[bool] = None
        self._state = LeanFlowState()
        self._total_latency_ms: float = 0.0
        self._request_count: int = 0

    # ── Lifecycle ─────────────────────────────────────────────────

    @property
    def is_available(self) -> bool:
        """Whether the Lean4 binary was found and the process is running."""
        return (
            self._available is True
            and self._process is not None
            and self._process.returncode is None
        )

    @property
    def binary_found(self) -> bool:
        """Whether the Lean4 binary exists on disk."""
        return self._binary is not None

    @property
    def state(self) -> LeanFlowState:
        """Current flow state from the Lean kernel."""
        return self._state

    async def start(
        self,
        budget: int = 10000,
        capabilities: Optional[List[str]] = None,
        compliance: str = "default",
    ) -> bool:
        """
        Start the Lean4 flow-check subprocess and initialize a session.

        Returns True if the kernel started successfully, False if the
        binary is not available (graceful degradation).
        """
        if self._binary is None:
            log.info(
                "Lean4 flow-check binary not found - running without "
                "lattice-proven flow verification (Z3-only mode)"
            )
            self._available = False
            return False

        try:
            self._process = await asyncio.create_subprocess_exec(
                self._binary,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait for ready signal
            ready = await self._read_json_message()
            if not ready.get("ready"):
                raise RuntimeError(f"Unexpected ready signal: {ready}")

            log.info(
                "Lean4 flow-check kernel started (v%s, pid=%d)",
                ready.get("version", "?"),
                self._process.pid,
            )

            # Initialize session
            init_result = await self._send({
                "cmd": "init",
                "budget": budget,
                "capabilities": capabilities or [],
                "compliance": compliance,
            })

            self._available = init_result.get("ok", False)
            self._state.budget_total = budget
            self._state.budget_remaining = budget
            self._state.compliance_policy = compliance
            if not self._available:
                await self._kill()
            return self._available

        except FileNotFoundError:
            log.warning(
                "Lean4 flow-check binary not found at %s - "
                "lattice-proven verification disabled",
                self._binary,
            )
            self._available = False
            return False
        except (asyncio.TimeoutError, json.JSONDecodeError, RuntimeError) as exc:
            log.warning(
                "Lean4 flow-check startup failed: %s - "
                "lattice-proven verification disabled",
                exc,
            )
            await self._kill()
            self._available = False
            return False

    async def shutdown(self) -> None:
        """Gracefully shut down the Lean4 subprocess."""
        if self._process is None:
            return
        try:
            await self._send({"cmd": "shutdown"})
        except Exception:
            pass
        await self._kill()

    async def _kill(self) -> None:
        """Force-kill the subprocess."""
        if self._process is None:
            return
        try:
            self._process.kill()
            await asyncio.wait_for(self._process.wait(), timeout=2.0)
        except Exception:
            pass
        self._process = None

    # ── Flow Verification ─────────────────────────────────────────

    async def check_flow(
        self,
        step_index: int,
        tool: str,
        input_labels: List[str],
        output_label: str,
        data_id: Optional[str] = None,
        cost: int = 0,
    ) -> LeanFlowResult:
        """
        Verify that information can flow from input labels to the
        output label.  Uses the proven Lean4 lattice.

        Args:
            step_index: Current step index in the agent loop.
            tool: Tool name being invoked.
            input_labels: Security labels of the tool's inputs.
            output_label: Declared security label of the tool's output.
            data_id: Identifier for this data binding.
            cost: Budget cost of this step in cents.

        Returns:
            LeanFlowResult with ok=True and a certificate, or
            ok=False with a violation detail.
        """
        if not self.is_available:
            return self._unavailable_result()

        start = time.perf_counter()
        response = await self._send({
            "cmd": "check_flow",
            "step_index": step_index,
            "tool": tool,
            "input_labels": input_labels,
            "output_label": output_label,
            "data_id": data_id or f"step_{step_index}",
            "cost": cost,
        })
        latency = (time.perf_counter() - start) * 1000

        return self._parse_result(response, latency)

    async def check_output_flow(
        self,
        step_index: int,
        tool: str,
        data_label: str,
        target_label: str,
        data_id: Optional[str] = None,
    ) -> LeanFlowResult:
        """
        Verify that a tool's output at a given security level can flow
        to a target level (e.g., can Sensitive data flow to Public output?).

        This is used after tool execution for the IFC flow-to-LLM
        and flow-to-user checks.
        """
        if not self.is_available:
            return self._unavailable_result()

        start = time.perf_counter()
        response = await self._send({
            "cmd": "check_tool_output_flow",
            "step_index": step_index,
            "tool": tool,
            "data_label": data_label,
            "target_label": target_label,
            "data_id": data_id or f"output_{step_index}",
        })
        latency = (time.perf_counter() - start) * 1000

        return self._parse_result(response, latency)

    async def get_state(self) -> LeanFlowState:
        """Retrieve the current flow state from the Lean kernel."""
        if not self.is_available:
            return self._state

        response = await self._send({"cmd": "get_state"})
        if response.get("ok"):
            self._state.flow_tracker = response.get("flow_tracker", [])
            self._state.compliance_policy = response.get("compliance_policy", "default")
            self._state.budget_remaining = response.get("budget_remaining", 0)
        return self._state

    async def get_certificates(self) -> List[Dict[str, Any]]:
        """Retrieve all Lean-issued proof certificates."""
        if not self.is_available:
            return []

        response = await self._send({"cmd": "get_certificates"})
        certs = response.get("certificates", [])
        self._state.certificates = certs
        return certs

    # ── Summary for Audit Trail ───────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        """Return a summary dict for inclusion in the audit trail."""
        return {
            "lean_kernel_available": self.is_available or False,
            "binary_found": self.binary_found,
            "binary_path": self._binary,
            "steps_checked": self._state.steps_checked,
            "certificates_issued": self._state.certificates_count,
            "flow_violations": self._state.flow_violations,
            "budget_remaining": self._state.budget_remaining,
            "total_requests": self._request_count,
            "avg_latency_ms": round(
                self._total_latency_ms / max(self._request_count, 1), 2
            ),
        }

    # ── Internal ──────────────────────────────────────────────────

    async def _send(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON request to the subprocess and read the response."""
        if self._process is None or self._process.stdin is None:
            return {"ok": False, "error": "not_running"}

        try:
            line = json.dumps(request, separators=(",", ":")) + "\n"
            self._process.stdin.write(line.encode())
            await self._process.stdin.drain()

            self._request_count += 1
            response = await self._read_json_message()

            # Update cached state from response
            if "steps_checked" in response:
                self._state.steps_checked = response["steps_checked"]
            if "budget_remaining" in response:
                self._state.budget_remaining = response["budget_remaining"]
            if "certificates_count" in response:
                self._state.certificates_count = response["certificates_count"]
            if "flow_violations" in response:
                self._state.flow_violations = response["flow_violations"]

            return response

        except asyncio.TimeoutError:
            log.warning("Lean4 flow-check request timed out (%.1fs)", self._timeout)
            return {"ok": False, "error": "timeout", "detail": "Request timed out"}
        except (json.JSONDecodeError, RuntimeError, OSError) as exc:
            log.warning("Lean4 flow-check communication error: %s", exc)
            # Process may have died - try to detect and clean up
            if self._process and self._process.returncode is not None:
                log.warning(
                    "Lean4 flow-check process exited (code=%d)",
                    self._process.returncode,
                )
                self._process = None
                self._available = False
            return {"ok": False, "error": "communication_error", "detail": str(exc)}

    async def _read_json_message(self) -> Dict[str, Any]:
        """Read a complete JSON message from the Lean subprocess stdout."""
        if self._process is None or self._process.stdout is None:
            raise RuntimeError("Lean4 process is not running")

        buffer = ""
        deadline = time.perf_counter() + self._timeout

        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise asyncio.TimeoutError()

            raw = await asyncio.wait_for(
                self._process.stdout.readline(),
                timeout=remaining,
            )
            if not raw:
                raise RuntimeError("Lean4 process closed stdout")

            chunk = raw.decode().strip()
            if not chunk:
                continue

            buffer = f"{buffer}\n{chunk}".strip() if buffer else chunk

            try:
                return json.loads(buffer)
            except json.JSONDecodeError:
                continue

    def _parse_result(self, response: Dict[str, Any], latency_ms: float) -> LeanFlowResult:
        """Parse a JSON response into a LeanFlowResult."""
        self._total_latency_ms += latency_ms

        return LeanFlowResult(
            ok=response.get("ok", False),
            error=response.get("error", ""),
            detail=response.get("detail", ""),
            certificate=response.get("certificate"),
            proven=response.get("proven", False),
            steps_checked=response.get("steps_checked", 0),
            budget_remaining=response.get("budget_remaining", 0),
            flow_violations=response.get("flow_violations", 0),
            latency_ms=latency_ms,
        )

    def _unavailable_result(self) -> LeanFlowResult:
        """Return an advisory result when the kernel isn't available."""
        return LeanFlowResult(
            ok=True,  # Don't block execution
            detail="Lean4 kernel not available - flow check skipped (advisory only)",
            proven=False,
            latency_ms=0.0,
        )

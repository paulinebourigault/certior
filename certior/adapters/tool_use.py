"""
certior.adapters.tool_use - Tool-calling LLM adapter.
=====================================================

Framework-agnostic adapter for any LLM that produces tool-call blocks
(OpenAI function calling, Anthropic ``tool_use``, MCP, etc.). Accepts
both the OpenAI-native shape (``{id, function:{name, arguments}}`` with
``arguments`` as a JSON-encoded string) and the simpler ``{name, input}``
shape - see ``_normalize_tool_call`` below.

Each verified tool call gets a real Z3-backed verdict and, on allow, a
signed proof certificate bound to the Lean-audited policy fingerprint.
The certificate is surfaced in every result so callers can persist it for
audit.

OpenAI tool-calling::

    from certior import Guard
    from certior.adapters.tool_use import verify_tool_calls

    guard = Guard(permissions=["network:http:read"], budget_cents=5000)
    tool_specs = {
        "search_web":   {"required_capabilities": ["network:http:read"], "cost_cents": 2},
        "db_admin_drop":{"required_capabilities": ["database:admin"],    "cost_cents": 0},
    }

    response = client.chat.completions.create(model="gpt-4o-mini", ...)
    verified = verify_tool_calls(
        guard=guard,
        tool_calls=response.choices[0].message.tool_calls,  # OpenAI-native is fine
        tool_specs=tool_specs,
    )

    for call in verified:
        if call["allowed"]:
            result = execute_tool(call["name"], call["input"])
            store_audit(call["certificate"])   # signed receipt
        else:
            result = f"Blocked by Certior: {call['reason']}"

Middleware pattern::

    from certior.adapters.tool_use import CertiorMiddleware

    mw = CertiorMiddleware(guard=guard, tool_specs=tool_specs)
    safe_executor = mw.wrap_executor(my_tool_executor)
    result = safe_executor("db_query", {"sql": "SELECT ..."})
"""
from __future__ import annotations

import asyncio
import functools
import json
from typing import Any, Callable, Dict, List, Mapping, Optional

from certior.guard import Guard, VerifyResult

# Per-tool capability + cost declaration. Keep it a plain dict so callers
# don't need to import a type - the only required keys are below.
ToolSpec = Dict[str, Any]
"""Shape: ``{"required_capabilities": [str, ...], "cost_cents": int}``."""


def _normalize_tool_call(tc: Any) -> Dict[str, Any]:
    """Coerce an OpenAI ``ChatCompletionMessageToolCall`` (or its dict form)
    into the simpler ``{id, name, input}`` shape this adapter uses.

    Accepts:
      • OpenAI SDK object: ``tc.function.name`` + ``tc.function.arguments`` (str)
      • OpenAI dict:        ``{"function": {"name": ..., "arguments": "..."}}``
      • Anthropic / native: ``{"name": ..., "input": {...}}``  (passes through)
    """
    # OpenAI SDK object
    fn = getattr(tc, "function", None)
    if fn is not None and getattr(fn, "name", None) is not None:
        args = getattr(fn, "arguments", None)
        if isinstance(args, str):
            try:
                args = json.loads(args) if args else {}
            except json.JSONDecodeError:
                args = {"_raw_arguments": args}
        return {"id": getattr(tc, "id", None), "name": fn.name, "input": args or {}}

    if isinstance(tc, Mapping):
        # OpenAI dict form
        if "function" in tc and isinstance(tc["function"], Mapping):
            fn = tc["function"]
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args) if args else {}
                except json.JSONDecodeError:
                    args = {"_raw_arguments": args}
            return {"id": tc.get("id"), "name": fn.get("name", "unknown"), "input": args or {}}
        # Native dict form - pass through, ensuring keys exist
        return {
            "id": tc.get("id"),
            "name": tc.get("name", "unknown"),
            "input": tc.get("input", tc.get("arguments", {})),
        }

    raise TypeError(f"Unrecognized tool-call shape: {type(tc).__name__}")


def _extract_content(params: Any) -> Optional[str]:
    """Pull string values out of a params dict for PII scanning."""
    if isinstance(params, str):
        return params
    if isinstance(params, Mapping):
        texts = [str(v) for v in params.values() if isinstance(v, str)]
        return " ".join(texts) if texts else None
    return None


def verify_tool_calls(
    guard: Guard,
    tool_calls: List[Any],
    *,
    tool_specs: Optional[Mapping[str, ToolSpec]] = None,
    content_field: str = "input",
) -> List[Dict[str, Any]]:
    """Verify a batch of LLM tool calls against the Guard's policy.

    Args:
        guard:        Certior Guard instance.
        tool_calls:   List of tool calls in OpenAI, Anthropic, or native shape.
        tool_specs:   Optional ``{tool_name: {"required_capabilities": [...],
                      "cost_cents": int}}`` map. A call may also carry its own
                      ``required_capabilities`` / ``cost_cents`` keys, which
                      override the spec.
        content_field: Override for the params key when using a non-standard
                      native shape.

    Returns:
        One dict per input call, augmented with:
            ``id, name, input`` - normalized call
            ``allowed, reason`` - Z3 verdict
            ``certificate`` - signed proof cert on allow, ``None`` on block
            ``redacted_input`` - PII-redacted params
            ``pii_found`` - list of detected PII spans
            ``verify_result`` - the full ``VerifyResult``
    """
    specs = tool_specs or {}
    out: List[Dict[str, Any]] = []
    for raw in tool_calls:
        tc = _normalize_tool_call(raw)
        name = tc["name"]
        params = tc.get(content_field, tc.get("input", {}))

        # Capability + cost - per-call override beats spec map.
        spec = specs.get(name, {})
        if isinstance(raw, Mapping):
            req = raw.get("required_capabilities", spec.get("required_capabilities") or [])
            cost = raw.get("cost_cents", spec.get("cost_cents", 0))
        else:
            req = spec.get("required_capabilities") or []
            cost = spec.get("cost_cents", 0)

        result = guard.verify(
            tool=name,
            params=params if isinstance(params, Mapping) else {"input": params},
            content=_extract_content(params),
            required_capabilities=list(req),
            cost_cents=int(cost),
        )

        out.append({
            "id": tc.get("id"),
            "name": name,
            "input": tc.get("input", {}),
            "allowed": result.allowed,
            "reason": result.reason,
            "certificate": result.certificate,
            "redacted_input": result.redacted_params or params,
            "pii_found": result.pii_found,
            "verify_result": result,
        })
    return out


class CertiorMiddleware:
    """Middleware that intercepts tool execution in any agent loop.

    Sits between the LLM's tool-call decisions and your actual tool
    implementations. Holds a per-tool ``ToolSpec`` registry so the
    capability + budget proof runs every call without callers threading
    those args through.

    Usage::

        mw = CertiorMiddleware(
            guard=Guard(permissions=["network:http:read"], budget_cents=5000),
            tool_specs={"search_web": {"required_capabilities": ["network:http:read"], "cost_cents": 2}},
        )

        # Option A - wrap your tool executor
        safe = mw.wrap_executor(execute_tool)
        result = safe("search_web", {"q": "hello"})

        # Option B - explicit check, then execute yourself
        decision = mw.check("search_web", {"q": "hello"})
        if decision.allowed:
            store_audit(decision.certificate)
            result = execute_tool("search_web", decision.redacted_params)
    """

    def __init__(
        self,
        guard: Optional[Guard] = None,
        policy: str = "default",
        *,
        tool_specs: Optional[Mapping[str, ToolSpec]] = None,
        on_block: Optional[Callable[[str, Dict, VerifyResult], Any]] = None,
    ):
        self.guard = guard or Guard(policy=policy)
        self.on_block = on_block
        self._specs: Dict[str, ToolSpec] = dict(tool_specs or {})

    # ── Registration ──────────────────────────────────────────────────
    def register_tool(
        self,
        name: str,
        *,
        required_capabilities: Optional[List[str]] = None,
        cost_cents: int = 0,
    ) -> None:
        """Declare what a tool needs so every call carries a proof."""
        self._specs[name] = {
            "required_capabilities": list(required_capabilities or []),
            "cost_cents": int(cost_cents),
        }

    @property
    def tool_specs(self) -> Dict[str, ToolSpec]:
        return dict(self._specs)

    @property
    def policy_attestation(self) -> Dict[str, Any]:
        """Provenance of the formally-verified policy this middleware enforces.

        Same fingerprint that's embedded in every issued certificate, so an
        auditor can tie any signed receipt back to a specific revision of the
        Lean-audited policy model.
        """
        return self.guard.policy_attestation

    # ── Decision ──────────────────────────────────────────────────────
    def check(
        self,
        tool_name: str,
        params: Optional[Dict[str, Any]] = None,
        content: Optional[str] = None,
        *,
        required_capabilities: Optional[List[str]] = None,
        cost_cents: Optional[int] = None,
    ) -> VerifyResult:
        """Check a tool call. Args win, then spec, then defaults."""
        spec = self._specs.get(tool_name, {})
        req = required_capabilities if required_capabilities is not None \
            else spec.get("required_capabilities") or []
        cost = cost_cents if cost_cents is not None \
            else int(spec.get("cost_cents", 0))

        if content is None:
            content = _extract_content(params)

        return self.guard.verify(
            tool=tool_name,
            params=params,
            content=content,
            required_capabilities=list(req),
            cost_cents=int(cost),
        )

    # ── Execution ─────────────────────────────────────────────────────
    def wrap_executor(
        self,
        executor: Callable,
        block_message: str = "[BLOCKED] Tool call blocked by Certior: {reason}",
    ) -> Callable:
        """Wrap a tool executor with Certior verification.

        The executor must have signature
        ``(tool_name: str, params: dict, **kwargs) -> Any``. Blocked calls
        return ``block_message`` (or the result of ``on_block``) and never
        invoke the underlying executor.
        """
        if asyncio.iscoroutinefunction(executor):
            @functools.wraps(executor)
            async def _async_wrapped(tool_name: str, params: Optional[Dict] = None, **kw):
                decision = self.check(tool_name, params)
                if decision.blocked:
                    if self.on_block:
                        return self.on_block(tool_name, params or {}, decision)
                    return block_message.format(reason=decision.reason)
                return await executor(tool_name, decision.redacted_params or params, **kw)
            return _async_wrapped

        @functools.wraps(executor)
        def _sync_wrapped(tool_name: str, params: Optional[Dict] = None, **kw):
            decision = self.check(tool_name, params)
            if decision.blocked:
                if self.on_block:
                    return self.on_block(tool_name, params or {}, decision)
                return block_message.format(reason=decision.reason)
            return executor(tool_name, decision.redacted_params or params, **kw)
        return _sync_wrapped

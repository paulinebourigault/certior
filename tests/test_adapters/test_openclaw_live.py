"""Live integration tests for ``certior.adapters.openclaw``.

These tests drive a *real* ``openclaw_sdk.core.agent.Agent`` object through
``GuardedAgent`` (the enforcement primitive) and through
``CertiorCallbackHandler`` (the observability/accounting primitive). The
LLM call is short-circuited at the ``Agent._execute_impl`` seam so the
suite runs without an API key.

Run isolated in Docker via ``docker/integration-test.compose.yml`` or the
``integration-test-ci`` GitHub Actions workflow. Skipped when
``openclaw-sdk`` is not installed locally.

Why both surfaces exist
-----------------------
OpenClaw's ``CompositeCallbackHandler`` is documented to swallow
exceptions raised by callback handlers (``handler.py``: *"so one
failing handler does not block the others"*). That means
``CertiorCallbackHandler`` cannot stop a call by raising - it can debit
budget, run the content scanner, and emit an audit record, but the
underlying ``agent.execute`` will still run. ``GuardedAgent`` is the
real enforcement surface: it intercepts ``.execute()`` *outside* the
swallowing callback chain, so a blocked verdict actually halts the
dispatch path.
"""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from typing import Any, List, Tuple

import pytest

from certior import Guard, CertiorBlocked
from certior.adapters import openclaw as adapter

pytestmark = pytest.mark.skipif(
    not adapter._HAS_OPENCLAW,
    reason="openclaw-sdk not installed; live integration tests not exercised",
)

if adapter._HAS_OPENCLAW:
    from openclaw_sdk.core.agent import Agent  # type: ignore[import-not-found]
    from openclaw_sdk.core.types import ExecutionResult  # type: ignore[import-not-found]


# ── Fakes for the OpenClawClient and the LLM call ────────────────────


class _FakeClient:
    """Minimal stand-in for OpenClawClient.

    Agent.execute reads exactly three things off its client:
    ``_callbacks`` (list[CallbackHandler]), ``_cache`` (None is fine),
    and ``config.timeout`` (int). Providing those is enough for the
    real dispatch path to run end-to-end with a patched
    ``_execute_impl``.
    """

    def __init__(self, callbacks: List[Any]) -> None:
        self._callbacks = list(callbacks)
        self._cache = None
        self.config = SimpleNamespace(timeout=30)


def _make_real_agent(
    callbacks: List[Any], canned_output: str
) -> Tuple["Agent", List[Tuple[str, Any]]]:
    """Build a real openclaw_sdk Agent with ``_execute_impl`` patched.

    Returns ``(agent, trace)`` where ``trace`` records each call into
    ``_execute_impl`` so tests can assert whether the LLM short-circuit
    ran or whether the call was halted earlier.
    """
    client = _FakeClient(callbacks=callbacks)
    agent = Agent(client=client, agent_id="research-bot")
    trace: List[Tuple[str, Any]] = []

    async def fake_execute_impl(self, params, timeout, resolved_cbs, t0):  # type: ignore[no-untyped-def]
        trace.append(("called", time.monotonic()))
        return ExecutionResult(success=True, content=canned_output, files=[])

    agent._execute_impl = fake_execute_impl.__get__(agent, Agent)  # type: ignore[method-assign]
    return agent, trace


# ── CertiorCallbackHandler: accounting still works on a real Agent ───


def test_callback_handler_debits_budget_on_real_agent_execute() -> None:
    """The callback fires through OpenClaw's real dispatch path. Even
    though the framework swallows handler exceptions, the side effect
    that matters (budget debit) still happens because the
    ``Guard.verify`` call ran before any exception."""
    guard = Guard(permissions=["network:http:read"], budget_cents=10)
    handler = adapter.CertiorCallbackHandler(guard, block_on_violation=True)
    agent, trace = _make_real_agent(callbacks=[handler], canned_output="ok")

    before = guard.budget_remaining
    result = asyncio.run(agent.execute("Find recent AI safety papers"))
    after = guard.budget_remaining

    assert result.success is True
    assert before - after == adapter._COST_PER_CALL
    assert len(trace) == 1


def test_callback_handler_does_NOT_block_call_even_when_raising() -> None:
    """Documents the OpenClaw framework behaviour: raising from a
    callback is swallowed by ``CompositeCallbackHandler``, so the
    underlying ``agent.execute`` still runs. Anyone relying on the
    callback to *enforce* would have a false-security bug; the test
    pins this contract so a future OpenClaw release that changes the
    swallowing behaviour will trip this test and force us to revisit
    the docs."""
    guard = Guard(policy="legal_privilege", permissions=["doc:read"], budget_cents=10)
    handler = adapter.CertiorCallbackHandler(guard, block_on_violation=True)
    agent, trace = _make_real_agent(
        callbacks=[handler], canned_output="should still appear"
    )

    # Attorney-client content would block under legal_privilege, but the
    # callback's CertiorBlocked is swallowed by CompositeCallbackHandler.
    result = asyncio.run(
        agent.execute("Review attorney-client privileged notes on the merger")
    )

    assert result.success is True
    assert result.content == "should still appear"
    assert len(trace) == 1  # _execute_impl was reached anyway


# ── GuardedAgent: actual enforcement ─────────────────────────────────


def test_guarded_agent_blocks_input_and_never_reaches_execute() -> None:
    """The enforcement contract: a blocked input verdict halts the
    dispatch path before the wrapped agent is invoked."""
    guard = Guard(policy="legal_privilege", permissions=["doc:read"], budget_cents=10)
    raw_agent, trace = _make_real_agent(callbacks=[], canned_output="never")
    guarded = adapter.GuardedAgent(raw_agent, guard)

    with pytest.raises(CertiorBlocked, match="attorney-client"):
        asyncio.run(
            guarded.execute(
                "Review attorney-client privileged notes about the merger"
            )
        )

    assert trace == []


def test_guarded_agent_allows_safe_input_and_returns_result() -> None:
    """Non-blocked input flows through to the wrapped agent and the
    result is returned."""
    guard = Guard(permissions=["network:http:read"], budget_cents=10)
    raw_agent, trace = _make_real_agent(callbacks=[], canned_output="found 3 papers")
    guarded = adapter.GuardedAgent(raw_agent, guard)

    result = asyncio.run(guarded.execute("Summarise public AI research"))

    assert result.success is True
    assert result.content == "found 3 papers"
    assert len(trace) == 1


def test_guarded_agent_blocks_output_with_privileged_content() -> None:
    """When the wrapped agent returns content that violates the policy,
    GuardedAgent raises CertiorBlocked instead of returning the result."""
    guard = Guard(policy="legal_privilege", permissions=["doc:read"], budget_cents=10)
    raw_agent, trace = _make_real_agent(
        callbacks=[],
        canned_output="Per attorney-client communication, settlement terms are...",
    )
    guarded = adapter.GuardedAgent(raw_agent, guard)

    with pytest.raises(CertiorBlocked, match="attorney-client"):
        asyncio.run(guarded.execute("Summarise public merger filings"))

    # The wrapped agent DID run (output came back), then was blocked.
    assert len(trace) == 1


def test_guarded_agent_debits_budget_per_call() -> None:
    """Per-execute budget accounting is enforced at the GuardedAgent
    layer (independent of the callback chain)."""
    guard = Guard(permissions=["network:http:read"], budget_cents=2)
    raw_agent, _ = _make_real_agent(callbacks=[], canned_output="ok")
    guarded = adapter.GuardedAgent(raw_agent, guard)

    asyncio.run(guarded.execute("q1"))
    asyncio.run(guarded.execute("q2"))
    with pytest.raises(CertiorBlocked, match="budget_exceeded"):
        asyncio.run(guarded.execute("q3"))

    assert guard.budget_remaining == 0


def test_guarded_agent_rejects_non_agent_input() -> None:
    """Argument validation: ``GuardedAgent`` must reject an object
    without an ``execute`` method up front."""
    with pytest.raises(TypeError, match="expects an object with an async .execute"):
        adapter.GuardedAgent("not an agent", Guard(budget_cents=10))  # type: ignore[arg-type]

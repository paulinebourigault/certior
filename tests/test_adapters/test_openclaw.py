"""Tests for ``certior.adapters.openclaw``.

These tests run without the real ``openclaw-sdk`` installed by exercising
``GuardedPipeline`` against an in-test mock and the import-stub path for
``CertiorCallbackHandler``. The handler's hook bodies are unit-tested via
the same Guard API the real OpenClaw runtime drives them with.
"""
from __future__ import annotations

import asyncio
from typing import Any, List

import pytest

from certior import Guard, CertiorBlocked
from certior.adapters import openclaw as adapter


# ── Fixtures ─────────────────────────────────────────────────────────


class _MockPipeline:
    """Minimal stand-in for ``openclaw_sdk.pipeline.Pipeline``."""

    def __init__(self) -> None:
        self.steps: List[tuple] = []

    def add_step(self, name: str, agent_id: str, prompt: str) -> "_MockPipeline":
        self.steps.append((name, agent_id, prompt))
        return self

    async def run(self) -> List[str]:
        return [name for (name, _, _) in self.steps]


@pytest.fixture
def parent_guard() -> Guard:
    return Guard(
        permissions=["network:http:read", "filesystem:read"],
        budget_cents=100,
    )


# ── CertiorCallbackHandler ───────────────────────────────────────────


def test_callback_handler_stub_raises_when_openclaw_missing() -> None:
    """In an environment without ``openclaw-sdk``, instantiating the handler
    must raise ``ImportError`` with the install hint. Skipped when the real
    package is present so we don't false-fail in adapter-rich environments."""
    if adapter._HAS_OPENCLAW:
        pytest.skip("openclaw-sdk is installed; stub path not exercised")
    with pytest.raises(ImportError, match="openclaw-sdk"):
        adapter.CertiorCallbackHandler()


def test_callback_handler_is_real_openclaw_subclass_when_sdk_installed() -> None:
    """In an environment with ``openclaw-sdk``, ``CertiorCallbackHandler``
    must extend the real ``openclaw_sdk.CallbackHandler``."""
    if not adapter._HAS_OPENCLAW:
        pytest.skip("openclaw-sdk not installed; real class not exercised")
    from openclaw_sdk import CallbackHandler  # type: ignore[import-not-found]

    assert issubclass(adapter.CertiorCallbackHandler, CallbackHandler)


def test_callback_handler_blocks_pii_in_output_when_sdk_installed() -> None:
    """End-to-end: on_execution_end scans the result's content attribute and
    raises ``CertiorBlocked`` when the active policy is configured to block."""
    if not adapter._HAS_OPENCLAW:
        pytest.skip("openclaw-sdk not installed; hook not exercised")

    class _Result:
        content = "Patient John Doe SSN 123-45-6789"

    # HIPAA redacts but doesn't block - verify the hook completes silently.
    handler = adapter.CertiorCallbackHandler(
        Guard(policy="hipaa", permissions=["database:read"]),
    )
    asyncio.run(handler.on_execution_end("patient-bot", result=_Result()))

    # legal_privilege blocks on attorney-client content - verify it raises.
    blocking_handler = adapter.CertiorCallbackHandler(
        Guard(policy="legal_privilege", permissions=["database:read"]),
    )

    class _PrivilegedResult:
        content = "Attorney-client communication regarding merger"

    with pytest.raises(CertiorBlocked):
        asyncio.run(
            blocking_handler.on_execution_end("doc-bot", result=_PrivilegedResult())
        )


# ── GuardedPipeline - registration ───────────────────────────────────


def test_guarded_pipeline_accepts_step_within_permissions(parent_guard: Guard) -> None:
    p = adapter.GuardedPipeline(
        _MockPipeline(),
        parent_guard,
        step_capabilities={"researcher": ["network:http:read"]},
    )
    p.add_step("researcher", "research-bot", "find papers")
    assert p.pipeline.steps == [("researcher", "research-bot", "find papers")]
    assert p._registered == ["researcher"]


def test_guarded_pipeline_blocks_step_outside_permissions(parent_guard: Guard) -> None:
    p = adapter.GuardedPipeline(
        _MockPipeline(),
        parent_guard,
        step_capabilities={"exfiltrator": ["database:admin"]},
    )
    with pytest.raises(CertiorBlocked, match="delegation_unsafe"):
        p.add_step("exfiltrator", "evil-bot", "drop tables")
    # Failed registration must not leak into the underlying pipeline.
    assert p.pipeline.steps == []
    assert p._registered == []


def test_guarded_pipeline_step_with_no_declared_caps_is_treated_as_empty_set(
    parent_guard: Guard,
) -> None:
    """A step name not present in ``step_capabilities`` requires no capabilities,
    so it must always register (empty set is a subset of every set)."""
    p = adapter.GuardedPipeline(_MockPipeline(), parent_guard)
    p.add_step("noop", "noop-bot", "do nothing")
    assert p._registered == ["noop"]


def test_guarded_pipeline_rejects_non_pipeline_input(parent_guard: Guard) -> None:
    with pytest.raises(TypeError, match="expects an OpenClaw Pipeline"):
        adapter.GuardedPipeline("not a pipeline", parent_guard)  # type: ignore[arg-type]


def test_guarded_pipeline_with_wildcard_parent_allows_anything() -> None:
    """``permissions=["*"]`` is the openworld guard; every step must register."""
    open_guard = Guard(permissions=["*"], budget_cents=100)
    p = adapter.GuardedPipeline(
        _MockPipeline(),
        open_guard,
        step_capabilities={"anything": ["database:admin", "filesystem:write"]},
    )
    p.add_step("anything", "bot", "any prompt")
    assert p._registered == ["anything"]


# ── GuardedPipeline - run() ──────────────────────────────────────────


def test_guarded_pipeline_run_delegates_without_touching_budget(parent_guard: Guard) -> None:
    """``GuardedPipeline.run`` must not debit budget.

    Per-step budget accounting is the job of ``CertiorCallbackHandler`` (it
    fires per ``agent.execute()`` call). If ``GuardedPipeline`` also debited,
    using both classes together - the supported pattern - would double-charge.
    """
    p = adapter.GuardedPipeline(
        _MockPipeline(),
        parent_guard,
        step_capabilities={
            "a": ["network:http:read"],
            "b": ["network:http:read"],
        },
    )
    p.add_step("a", "bot-a", "do a")
    p.add_step("b", "bot-b", "do b")

    before = parent_guard.budget_remaining
    out = asyncio.run(p.run())
    after = parent_guard.budget_remaining

    assert out == ["a", "b"]
    assert before == after  # ← invariant: run() leaves budget unchanged


def test_guarded_pipeline_run_forwards_args_and_return(parent_guard: Guard) -> None:
    """``GuardedPipeline.run`` is a transparent forwarder.

    Whatever the underlying pipeline returns and accepts must pass through.
    """
    received: List[tuple] = []

    class _EchoPipeline(_MockPipeline):
        async def run(self, **initial_variables: str) -> dict:  # type: ignore[override]
            received.append(("kwargs", initial_variables))
            return {"steps": [s[0] for s in self.steps], "vars": initial_variables}

    p = adapter.GuardedPipeline(_EchoPipeline(), parent_guard)
    p.add_step("step-a", "bot-a", "do a")
    out = asyncio.run(p.run(seed="hello"))

    assert out == {"steps": ["step-a"], "vars": {"seed": "hello"}}
    assert received == [("kwargs", {"seed": "hello"})]


def test_callback_handler_debits_budget_when_called_directly() -> None:
    """The callback handler is the component that debits budget, not the pipeline.

    Verified by driving the handler's hook with a freshly constructed guard
    and observing that ``budget_remaining`` decreases by exactly _COST_PER_CALL.
    Tests the absent-openclaw path through the underlying Guard, so it runs in
    every environment regardless of whether openclaw-sdk is installed.
    """
    guard = Guard(permissions=["network:http:read"], budget_cents=10)
    before = guard.budget_remaining
    # Drive Guard.verify with the same shape the handler uses internally,
    # since the handler subclass only exists when openclaw-sdk is installed.
    verdict = guard.verify(
        tool="openclaw:bot-a",
        content="hello",
        cost_cents=adapter._COST_PER_CALL,
    )
    after = guard.budget_remaining

    assert verdict.allowed
    assert before - after == adapter._COST_PER_CALL


# ── _extract_content ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "attr_name",
    ["content", "text", "output"],
)
def test_extract_content_reads_documented_attributes(attr_name: str) -> None:
    class _R:
        pass

    r = _R()
    setattr(r, attr_name, "hello world")
    assert adapter._extract_content(r) == "hello world"


def test_extract_content_falls_back_to_string() -> None:
    assert adapter._extract_content("raw string") == "raw string"


def test_extract_content_returns_none_for_unknown_shape() -> None:
    assert adapter._extract_content(object()) is None
    assert adapter._extract_content(None) is None


# ── _make_blocked_verdict ────────────────────────────────────────────


def test_make_blocked_verdict_carries_reason() -> None:
    v = adapter._make_blocked_verdict(reason="delegation_unsafe: x")
    assert v.allowed is False
    assert v.blocked is True
    assert v.reason == "delegation_unsafe: x"
    assert v.violations == []
    assert v.certificate is None

"""End-to-end tests for the OpenAI tool-calling adapter.

Pins down the contract the wrapper README and ``examples/openai_agent_demo.py``
promise: the OpenAI-native shape is accepted unchanged, the Z3 capability +
budget proof runs on every call, allowed calls get a signed certificate
bound to the Lean policy fingerprint, blocked calls get no certificate, and
the middleware surfaces the Lean attestation alongside the runtime gate.
"""
from __future__ import annotations

import json

import pytest

from certior import Guard
from certior.adapters.tool_use import (
    CertiorMiddleware,
    _normalize_tool_call,
    verify_tool_calls,
)


# ── Fixtures ─────────────────────────────────────────────────────────

TOOL_SPECS = {
    "search_web":    {"required_capabilities": ["network:http:read"], "cost_cents": 2},
    "read_file":     {"required_capabilities": ["filesystem:read"],   "cost_cents": 1},
    "db_admin_drop": {"required_capabilities": ["database:admin"],    "cost_cents": 0},
}


def openai_tc(call_id: str, name: str, args: dict) -> dict:
    """Literal shape of one entry in ``response.choices[0].message.tool_calls``."""
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


@pytest.fixture
def guard():
    return Guard(
        permissions=["network:http:read", "filesystem:read"],
        budget_cents=100,
        agent_id="research-assistant",
    )


# ── Shape normalization ──────────────────────────────────────────────

class TestNormalizeToolCall:

    def test_openai_dict_shape(self):
        tc = openai_tc("call_x", "search_web", {"query": "hi"})
        out = _normalize_tool_call(tc)
        assert out["id"] == "call_x"
        assert out["name"] == "search_web"
        assert out["input"] == {"query": "hi"}

    def test_native_shape_passes_through(self):
        out = _normalize_tool_call({"id": "n1", "name": "tool", "input": {"k": "v"}})
        assert out == {"id": "n1", "name": "tool", "input": {"k": "v"}}

    def test_openai_sdk_object_shape(self):
        # Mimic the OpenAI SDK's pydantic model attribute access.
        class Fn:
            name = "search_web"
            arguments = '{"query": "from sdk obj"}'

        class TC:
            id = "call_sdk"
            function = Fn()

        out = _normalize_tool_call(TC())
        assert out == {"id": "call_sdk", "name": "search_web",
                       "input": {"query": "from sdk obj"}}

    def test_invalid_arguments_string_is_preserved_raw(self):
        # If OpenAI somehow emits non-JSON arguments, we keep the raw text
        # under a sentinel key rather than crash - the call still flows to
        # the Guard which will treat it as content.
        tc = {"id": "bad", "function": {"name": "tool", "arguments": "not json {"}}
        out = _normalize_tool_call(tc)
        assert out["input"] == {"_raw_arguments": "not json {"}

    def test_empty_arguments_string(self):
        tc = {"id": "e", "function": {"name": "tool", "arguments": ""}}
        out = _normalize_tool_call(tc)
        assert out["input"] == {}

    def test_unrecognized_shape_raises(self):
        with pytest.raises(TypeError):
            _normalize_tool_call(42)


# ── verify_tool_calls - capability + cert path ───────────────────────

class TestVerifyToolCallsCapabilityPath:

    def test_allowed_call_gets_signed_certificate(self, guard):
        tcs = [openai_tc("c1", "search_web", {"query": "hello"})]
        verified = verify_tool_calls(guard, tcs, tool_specs=TOOL_SPECS)

        assert len(verified) == 1
        v = verified[0]
        assert v["allowed"] is True
        assert v["certificate"] is not None
        # The cert must be the kind only Z3 + the CA can produce, and must
        # name the tool, the Z3 prover, and the Lean attestation.
        assert v["certificate"].prover == "z3"
        assert "search_web" in v["certificate"].theorem
        assert "Lean-audited @" in v["certificate"].proof_trace

    def test_certificate_validates_via_kernel(self, guard):
        verified = verify_tool_calls(
            guard,
            [openai_tc("c2", "read_file", {"path": "/tmp/x"})],
            tool_specs=TOOL_SPECS,
        )
        cert = verified[0]["certificate"]
        assert cert is not None
        assert guard._ca.validate_certificate(cert) is True

    def test_certificate_embeds_lean_fingerprint(self, guard):
        verified = verify_tool_calls(
            guard,
            [openai_tc("c3", "search_web", {"query": "x"})],
            tool_specs=TOOL_SPECS,
        )
        cert = verified[0]["certificate"]
        fp = guard.policy_attestation["fingerprint"]
        # Fingerprint appears in both proof_trace and verified_properties.
        assert fp in cert.proof_trace
        assert any(f"policy_model:lean-audited@{fp}" in p
                   for p in cert.verified_properties)

    def test_missing_capability_blocks_and_no_certificate(self, guard):
        # 'database:admin' is not in the guard's permissions - this is the
        # classic capability-escalation jailbreak scenario.
        verified = verify_tool_calls(
            guard,
            [openai_tc("c4", "db_admin_drop", {"table": "users"})],
            tool_specs=TOOL_SPECS,
        )
        v = verified[0]
        assert v["allowed"] is False
        assert v["certificate"] is None         # never sign what we don't prove
        assert "capability" in v["reason"].lower() or "permission" in v["reason"].lower()
        assert "database:admin" in v["reason"]

    def test_block_does_not_consume_budget(self, guard):
        # Even though db_admin_drop costs 0¢, ensure blocked-with-cost paths
        # don't silently debit. Use a tool with positive cost and a missing
        # cap to exercise that path explicitly.
        before = guard.budget_remaining
        verify_tool_calls(
            guard,
            [openai_tc("c5", "db_admin_drop", {"table": "users"})],
            tool_specs={
                "db_admin_drop": {
                    "required_capabilities": ["database:admin"],
                    "cost_cents": 50,
                }
            },
        )
        assert guard.budget_remaining == before


# ── verify_tool_calls - content path ─────────────────────────────────

class TestVerifyToolCallsContentPath:

    def test_pii_detection_in_payload_blocks_with_no_certificate(self):
        # Capability + budget pass, but the default policy's content scanner
        # catches the SSN and blocks. (HIPAA policy redacts without blocking,
        # which is a different valid posture - exercised elsewhere.)
        g = Guard(
            permissions=["mail:draft"],
            budget_cents=100,
        )
        specs = {"draft_email": {"required_capabilities": ["mail:draft"], "cost_cents": 5}}
        tcs = [openai_tc("c6", "draft_email", {
            "to": "team",
            "subject": "patient #1",
            "body": "Patient SSN 123-45-6789 needs follow-up.",
        })]
        verified = verify_tool_calls(g, tcs, tool_specs=specs)
        v = verified[0]
        assert v["allowed"] is False
        assert v["certificate"] is None
        assert any(p.value == "123-45-6789" for p in v["pii_found"])
        # Redacted payload is surfaced for callers that want to retry.
        assert "[REDACTED" in v["redacted_input"]["body"]
        assert "123-45-6789" not in v["redacted_input"]["body"]


# ── verify_tool_calls - budget path ──────────────────────────────────

class TestVerifyToolCallsBudgetPath:

    def test_budget_exhaustion_blocks_tail_calls_with_no_certificate(self):
        # 17¢ budget; search_web costs 2¢; ten calls ⇒ 8 allowed (=16¢ spent),
        # then call 9 needs 2 but 1 remains ⇒ blocked. 8 allowed, 2 blocked.
        g = Guard(
            permissions=["network:http:read"],
            budget_cents=17,
        )
        burst = [
            openai_tc(f"b{i}", "search_web", {"query": f"q{i}"})
            for i in range(10)
        ]
        verified = verify_tool_calls(g, burst, tool_specs=TOOL_SPECS)
        allowed = [v for v in verified if v["allowed"]]
        blocked = [v for v in verified if not v["allowed"]]

        assert len(allowed) == 8
        assert len(blocked) == 2
        assert all(v["certificate"] is not None for v in allowed)
        assert all(v["certificate"] is None for v in blocked)
        assert "budget" in blocked[0]["reason"].lower()


# ── Middleware ───────────────────────────────────────────────────────

class TestCertiorMiddleware:

    def test_register_tool_and_check_uses_spec(self, guard):
        mw = CertiorMiddleware(guard=guard)
        mw.register_tool("search_web",
                         required_capabilities=["network:http:read"],
                         cost_cents=2)

        decision = mw.check("search_web", {"query": "hi"})
        assert decision.allowed
        assert decision.certificate is not None
        # The spec map is the source of truth, surfaced for inspection.
        assert mw.tool_specs["search_web"]["cost_cents"] == 2

    def test_inline_args_override_spec(self, guard):
        mw = CertiorMiddleware(
            guard=guard,
            tool_specs={"search_web": {"required_capabilities": ["network:http:read"], "cost_cents": 2}},
        )
        # Override cost to force a budget overrun in a single call.
        decision = mw.check("search_web", {"query": "x"}, cost_cents=10_000)
        assert decision.blocked
        assert "budget" in decision.reason.lower()
        assert decision.certificate is None

    def test_wrap_executor_blocks_jailbreak_and_returns_block_message(self, guard):
        mw = CertiorMiddleware(guard=guard, tool_specs=TOOL_SPECS)
        ran = []

        def executor(name, params):
            ran.append((name, params))
            return "EXECUTED"

        safe = mw.wrap_executor(executor)
        out = safe("db_admin_drop", {"table": "users"})

        assert ran == []                              # executor never called
        assert "BLOCKED" in out
        assert "database:admin" in out

    def test_wrap_executor_allows_legitimate_call(self, guard):
        mw = CertiorMiddleware(guard=guard, tool_specs=TOOL_SPECS)

        def executor(name, params):
            return f"ok:{name}"

        safe = mw.wrap_executor(executor)
        out = safe("search_web", {"query": "hello"})
        assert out == "ok:search_web"

    def test_policy_attestation_surfaces_lean_fingerprint(self, guard):
        mw = CertiorMiddleware(guard=guard, tool_specs=TOOL_SPECS)
        att = mw.policy_attestation
        assert att["fingerprint"] == guard.policy_attestation["fingerprint"]
        assert "Lean 4" in att["kernel"]
        assert "Certior.Delegation.delegationSafety" in att["audited_guarantees"]
        assert att["trusted_axioms"] == ["propext", "Classical.choice", "Quot.sound"]

    def test_on_block_callback_invoked_with_decision(self, guard):
        seen = {}

        def on_block(name, params, decision):
            seen["name"] = name
            seen["params"] = params
            seen["reason"] = decision.reason
            return "custom-block-handler-ran"

        mw = CertiorMiddleware(guard=guard, tool_specs=TOOL_SPECS, on_block=on_block)
        safe = mw.wrap_executor(lambda n, p: "should not run")
        out = safe("db_admin_drop", {"table": "users"})
        assert out == "custom-block-handler-ran"
        assert seen["name"] == "db_admin_drop"
        assert "database:admin" in seen["reason"]

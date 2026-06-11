"""Tests for the certior public API (certior.Guard)."""
from __future__ import annotations

import pytest
from certior import Guard, VerifyResult, Policy
from certior.guard import CertiorBlocked, Violation


# ── Basic API ────────────────────────────────────────────────────────

class TestGuardBasic:

    def test_import(self):
        from certior import Guard, VerifyResult, Policy
        assert Guard is not None

    def test_default_guard(self):
        g = Guard()
        assert g.policy_name == "default"
        assert g.budget_remaining == 10_000

    def test_policy_enum(self):
        for p in ("default", "hipaa", "sox", "legal"):
            g = Guard(policy=p)
            assert g.policy_name == p

    def test_policy_enum_object(self):
        g = Guard(policy=Policy.HIPAA)
        assert g.policy_name == "hipaa"


# ── Verification ─────────────────────────────────────────────────────

class TestGuardVerify:

    def test_clean_content_allowed(self):
        g = Guard()
        r = g.verify(tool="search", content="What is the weather?")
        assert r.allowed
        assert r.violations == []
        assert r.latency_ms > 0

    def test_pii_detected_hipaa(self):
        g = Guard(policy="hipaa")
        r = g.verify(
            tool="email",
            content="Patient SSN: 123-45-6789 needs follow-up",
        )
        assert len(r.pii_found) >= 1
        assert r.redacted_content is not None
        assert "123-45-6789" not in r.redacted_content

    def test_sox_mnpi_blocked(self):
        g = Guard(policy="sox")
        r = g.verify(
            tool="chat",
            content="Our unreleased earnings are $500M",
        )
        assert r.blocked
        assert "unreleased earnings" in r.reason.lower() or len(r.violations) > 0

    def test_capability_check(self):
        g = Guard(permissions=["database:read"])
        r = g.verify(
            tool="web_search",
            required_capabilities=["network:http:read"],
        )
        assert r.blocked
        # Z3 verifier reports "missing_capability: <perm>"; older code said
        # "Missing permissions: ...". Accept either vocabulary.
        assert "capability" in r.reason.lower() or "permission" in r.reason.lower()
        assert r.certificate is None  # no signed receipt for a blocked action

    def test_wildcard_permissions(self):
        g = Guard(permissions=["*"])
        r = g.verify(
            tool="anything",
            required_capabilities=["network:http:read", "filesystem:write"],
        )
        assert r.allowed

    def test_budget_enforcement(self):
        g = Guard(budget_cents=100)
        r1 = g.verify(tool="search", cost_cents=60)
        assert r1.allowed
        assert g.budget_remaining == 40

        r2 = g.verify(tool="search", cost_cents=60)
        assert r2.blocked
        assert "remaining" in r2.reason.lower()

    def test_params_redaction(self):
        g = Guard(policy="hipaa")
        r = g.verify(
            tool="db_query",
            params={"sql": "WHERE ssn = '123-45-6789'"},
        )
        assert r.redacted_params is not None
        assert "123-45-6789" not in r.redacted_params["sql"]


# ── wrap() decorator ─────────────────────────────────────────────────

class TestGuardWrap:

    def test_wrap_allows_clean(self):
        g = Guard()
        calls = []

        @g.wrap
        def my_tool(query: str) -> str:
            calls.append(query)
            return f"result: {query}"

        out = my_tool(query="hello")
        assert out == "result: hello"
        assert len(calls) == 1

    def test_wrap_blocks_on_capability(self):
        g = Guard(permissions=["database:read"])

        @g.wrap(tool_name="web", required_capabilities=["network:http"])
        def web_search(q: str) -> str:
            return "should not run"

        with pytest.raises(CertiorBlocked) as exc_info:
            web_search(q="test")
        assert "blocked" in str(exc_info.value).lower()

    def test_wrap_budget(self):
        g = Guard(budget_cents=50)

        @g.wrap(tool_name="expensive", cost_cents=30)
        def expensive_call() -> str:
            return "ok"

        assert expensive_call() == "ok"
        assert g.budget_remaining == 20

        with pytest.raises(CertiorBlocked):
            expensive_call()  # 30 > 20

    @pytest.mark.asyncio
    async def test_wrap_async(self):
        g = Guard()

        @g.wrap(tool_name="async_tool")
        async def my_async_tool(x: int) -> int:
            return x * 2

        result = await my_async_tool(x=5)
        assert result == 10


# ── Audit log ────────────────────────────────────────────────────────

class TestGuardAudit:

    def test_audit_recorded(self):
        g = Guard()
        g.verify(tool="search", content="hello")
        g.verify(tool="email", content="world")

        log = g.audit_log
        assert len(log) == 2
        assert log[0]["tool"] == "search"
        assert log[1]["tool"] == "email"
        assert all("latency_ms" in e for e in log)

    def test_violation_callback(self):
        violations = []
        g = Guard(
            permissions=["db:read"],
            on_violation=lambda r: violations.append(r),
        )
        g.verify(tool="x", required_capabilities=["network:write"])
        assert len(violations) == 1
        assert violations[0].blocked


# ── Async ────────────────────────────────────────────────────────────

class TestGuardAsync:

    @pytest.mark.asyncio
    async def test_averify(self):
        g = Guard(policy="hipaa")
        r = await g.averify(
            tool="email",
            content="SSN is 999-88-7777",
        )
        assert len(r.pii_found) >= 1
        assert r.redacted_content is not None


# ── tool_use adapter ─────────────────────────────────────────────────

class TestToolUseAdapter:

    def test_verify_tool_calls(self):
        from certior.adapters.tool_use import verify_tool_calls

        g = Guard(policy="hipaa")
        calls = [
            {"name": "db_query", "input": {"sql": "SELECT * FROM patients"}, "id": "1"},
            {"name": "email", "input": {"body": "Patient SSN: 111-22-3333"}, "id": "2"},
        ]
        results = verify_tool_calls(g, calls)
        assert len(results) == 2
        assert all("allowed" in r for r in results)

    def test_middleware_check(self):
        from certior.adapters.tool_use import CertiorMiddleware

        mw = CertiorMiddleware(policy="hipaa")
        result = mw.check("email", {"body": "SSN 111-22-3333"})
        assert len(result.pii_found) >= 1

    def test_middleware_wrap_executor(self):
        from certior.adapters.tool_use import CertiorMiddleware

        executed = []

        def my_executor(tool_name: str, params: dict) -> str:
            executed.append((tool_name, params))
            return "done"

        mw = CertiorMiddleware(policy="default")
        safe = mw.wrap_executor(my_executor)

        out = safe("search", {"q": "hello"})
        assert out == "done"
        assert len(executed) == 1


# ── VerifyResult ─────────────────────────────────────────────────────

class TestVerifyResult:

    def test_blocked_property(self):
        r = VerifyResult(allowed=False, reason="test")
        assert r.blocked is True

    def test_allowed_property(self):
        r = VerifyResult(allowed=True)
        assert r.blocked is False

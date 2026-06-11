"""
Tests for production hardening of A1 (token.is_valid) and A3 (compliance intersection).

Covers:
  A1-TOCTOU  Token re-validation in execute_action (expires between verify & execute)
  A1-SAFE    Token validation in SafeVerifier.verify_and_scan()
  A1-SKILL   Token validation in VerifiedSkillLoader.load_skill()
  A3-SAFE    Compliance permission intersection in SafeVerifier
  A3-SKILL   Compliance forbidden/ceiling check in VerifiedSkillLoader
"""
from __future__ import annotations

import time
import pytest
from pathlib import Path

from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.agents.base import (
    VerifiedAgent, VerificationResult, TokenInvalidError,
)
from agentsafe.agents.actions import AgentAction
from agentsafe.kernel.certificate import CertificateAuthority
from agentsafe.observability.otel import CertiorTelemetry
from agentsafe.verification.safety_integration import (
    SafeVerifier,
    SafetyVerificationResult,
    ComplianceVerifier,
    get_hipaa_verifier,
    get_sox_verifier,
)
from agentsafe.safety.scanner import ContentSafetyPolicy
from agentsafe.compliance.presets import CompliancePresets, ComplianceConfig
from agentsafe.skills.loader import VerifiedSkillLoader
from agentsafe.skills.exceptions import CapabilityError

z3 = pytest.importorskip("z3")


# ── Fixtures ──────────────────────────────────────────────────────

class ConcreteAgent(VerifiedAgent):
    pass


def _token(**kw) -> CapabilityToken:
    defaults = dict(
        agent_id="test",
        permissions=["network:http:read"],
        budget_cents=5000,
        budget_remaining_cents=5000,
        expires_at=time.time() + 3600,
    )
    defaults.update(kw)
    return CapabilityToken(**defaults)


def _action(**kw) -> AgentAction:
    defaults = dict(
        tool="web_browsing",
        required_capabilities=["network:http:read"],
        estimated_cost_cents=100,
    )
    defaults.update(kw)
    return AgentAction(**defaults)


# ══════════════════════════════════════════════════════════════════
# A1 TOCTOU: execute_action re-validates token
# ══════════════════════════════════════════════════════════════════

class TestA1ExecuteActionTOCTOU:
    """Token that was valid at verify time can expire before execute."""

    def setup_method(self):
        CertificateAuthority.reset()
        CertiorTelemetry.reset()

    @pytest.mark.asyncio
    async def test_token_valid_at_verify_expired_at_execute(self):
        """Token expires between verify_action and execute_action."""
        token = _token(expires_at=time.time() + 0.05)
        agent = ConcreteAgent("a", token)
        agent.register_tool("web_browsing", lambda p: "ok")

        # Verify succeeds (token still valid)
        result = await agent.verify_action(_action())
        assert result.valid
        assert result.certificate is not None

        # Wait for token to expire
        time.sleep(0.1)
        assert not token.is_valid()

        # Execute must reject - TOCTOU defense
        with pytest.raises(TokenInvalidError) as exc_info:
            await agent.execute_action(_action(), result.certificate)
        assert exc_info.value.reason == "token_expired"

    @pytest.mark.asyncio
    async def test_budget_drained_between_verify_and_execute(self):
        """Another agent drains budget between our verify and execute."""
        token = _token(budget_cents=100, budget_remaining_cents=100)
        agent = ConcreteAgent("a", token)
        agent.register_tool("web_browsing", lambda p: "ok")

        # Verify succeeds
        result = await agent.verify_action(_action(estimated_cost_cents=50))
        assert result.valid

        # Concurrent agent drains the budget
        token.consume_budget(100)
        assert token.budget_remaining_cents == 0

        # Execute must reject
        with pytest.raises(TokenInvalidError) as exc_info:
            await agent.execute_action(
                _action(estimated_cost_cents=50), result.certificate,
            )
        assert exc_info.value.reason == "token_budget_exhausted"

    @pytest.mark.asyncio
    async def test_execute_with_valid_token_still_works(self):
        """Normal path: token valid throughout → execute succeeds."""
        token = _token()
        agent = ConcreteAgent("a", token)
        agent.register_tool("web_browsing", lambda p: "result_data")

        result = await agent.verify_action(_action())
        assert result.valid

        step = await agent.execute_action(_action(), result.certificate)
        assert step.success
        assert step.output == "result_data"

    @pytest.mark.asyncio
    async def test_tampered_token_blocked_at_execute(self):
        """Token tampered after verify but before execute."""
        token = _token()
        agent = ConcreteAgent("a", token)
        agent.register_tool("web_browsing", lambda p: "ok")

        result = await agent.verify_action(_action())
        assert result.valid

        # Tamper (bypass structural freeze to test HMAC defence-in-depth)
        object.__setattr__(token, "permissions", ("admin:*",))

        with pytest.raises(TokenInvalidError) as exc_info:
            await agent.execute_action(_action(), result.certificate)
        assert exc_info.value.reason == "token_tampered"


# ══════════════════════════════════════════════════════════════════
# A1 SAFE: SafeVerifier token validation
# ══════════════════════════════════════════════════════════════════

class TestA1SafeVerifierTokenValidation:
    """SafeVerifier.verify_and_scan() rejects invalid tokens."""

    def setup_method(self):
        CertiorTelemetry.reset()
        ComplianceVerifier.reset()

    @pytest.mark.asyncio
    async def test_expired_token_rejected(self):
        verifier = SafeVerifier(ContentSafetyPolicy.default())
        token = _token(expires_at=time.time() - 1)
        result = await verifier.verify_and_scan(token=token, content="hello")
        assert not result.approved
        assert result.token_error == "token_expired"
        assert any("token_expired" in v for v in result.safety_violations)

    @pytest.mark.asyncio
    async def test_tampered_token_rejected(self):
        verifier = SafeVerifier(ContentSafetyPolicy.default())
        token = _token()
        # Bypass structural freeze to test HMAC defence-in-depth
        object.__setattr__(token, "permissions", ("hacked",))
        result = await verifier.verify_and_scan(token=token, content="hello")
        assert not result.approved
        assert result.token_error == "token_tampered"

    @pytest.mark.asyncio
    async def test_budget_exhausted_rejected(self):
        verifier = SafeVerifier(ContentSafetyPolicy.default())
        token = _token(budget_remaining_cents=0)
        result = await verifier.verify_and_scan(token=token, content="hello")
        assert not result.approved
        assert result.token_error == "token_budget_exhausted"

    @pytest.mark.asyncio
    async def test_valid_token_passes(self):
        verifier = SafeVerifier(ContentSafetyPolicy.default())
        token = _token()
        result = await verifier.verify_and_scan(token=token, content="hello")
        assert result.approved
        assert result.token_error is None

    @pytest.mark.asyncio
    async def test_no_token_still_works(self):
        """When no token is provided, skip validation (backward compat)."""
        verifier = SafeVerifier(ContentSafetyPolicy.default())
        result = await verifier.verify_and_scan(content="hello")
        assert result.approved

    @pytest.mark.asyncio
    async def test_token_rejected_before_content_scan(self):
        """Invalid token is caught BEFORE PII scanning runs."""
        verifier = SafeVerifier(ContentSafetyPolicy.hipaa_compliant())
        token = _token(expires_at=time.time() - 1)
        # Content has PII but token check should fire first
        result = await verifier.verify_and_scan(
            token=token, content="SSN: 123-45-6789",
        )
        assert not result.approved
        assert result.token_error == "token_expired"
        # PII scan should NOT have run
        assert result.scan_result is None


# ══════════════════════════════════════════════════════════════════
# A3 SAFE: SafeVerifier compliance permission intersection
# ══════════════════════════════════════════════════════════════════

class TestA3SafeVerifierComplianceIntersection:
    """SafeVerifier with compliance_config blocks forbidden capabilities."""

    def setup_method(self):
        CertiorTelemetry.reset()
        ComplianceVerifier.reset()

    @pytest.mark.asyncio
    async def test_forbidden_capability_blocked(self):
        hipaa_cfg = CompliancePresets.hipaa()
        verifier = SafeVerifier(
            ContentSafetyPolicy.hipaa_compliant(),
            compliance_config=hipaa_cfg,
        )
        action = _action(required_capabilities=["network:smtp:send:external"])
        token = _token(permissions=["network:smtp:send:external"])
        result = await verifier.verify_and_scan(action=action, token=token)
        assert not result.approved
        assert len(result.permission_denials) > 0
        assert any("forbidden" in d.lower() for d in result.permission_denials)

    @pytest.mark.asyncio
    async def test_ceiling_exceeded_blocked(self):
        hipaa_cfg = CompliancePresets.hipaa()
        verifier = SafeVerifier(
            ContentSafetyPolicy.hipaa_compliant(),
            compliance_config=hipaa_cfg,
        )
        action = _action(required_capabilities=["network:admin:full_access"])
        token = _token(permissions=["network:admin:full_access"])
        result = await verifier.verify_and_scan(action=action, token=token)
        assert not result.approved
        assert any("ceiling" in d.lower() for d in result.permission_denials)

    @pytest.mark.asyncio
    async def test_allowed_capability_passes(self):
        hipaa_cfg = CompliancePresets.hipaa()
        verifier = SafeVerifier(
            ContentSafetyPolicy.hipaa_compliant(),
            compliance_config=hipaa_cfg,
        )
        action = _action(required_capabilities=["database:read:patient_data"])
        token = _token(permissions=["database:read:patient_data"])
        result = await verifier.verify_and_scan(action=action, token=token)
        assert result.approved
        assert len(result.permission_denials) == 0

    @pytest.mark.asyncio
    async def test_no_compliance_config_passes(self):
        """Without compliance config, no permission check happens."""
        verifier = SafeVerifier(ContentSafetyPolicy.default())
        action = _action(required_capabilities=["anything:goes"])
        token = _token(permissions=["anything:goes"])
        result = await verifier.verify_and_scan(action=action, token=token)
        assert result.approved

    @pytest.mark.asyncio
    async def test_hipaa_verifier_factory_has_compliance(self):
        """get_hipaa_verifier() wires compliance config automatically."""
        verifier = get_hipaa_verifier()
        assert verifier._compliance is not None
        assert verifier._compliance.name == "HIPAA"

    @pytest.mark.asyncio
    async def test_sox_verifier_blocks_write_financial_data(self):
        """SOX forbids database:write:financial_data."""
        verifier = get_sox_verifier()
        action = _action(required_capabilities=["database:write:financial_data"])
        token = _token(permissions=["database:write:financial_data"])
        result = await verifier.verify_and_scan(action=action, token=token)
        assert not result.approved
        assert any("forbidden" in d.lower() for d in result.permission_denials)


# ══════════════════════════════════════════════════════════════════
# A1 SKILL: VerifiedSkillLoader token validation
# ══════════════════════════════════════════════════════════════════

class TestA1SkillLoaderTokenValidation:
    """VerifiedSkillLoader.load_skill() rejects invalid tokens."""

    def test_expired_token_rejected(self):
        loader = VerifiedSkillLoader(Path("skills"))
        token = _token(
            permissions=["network:http:read", "filesystem:cache:write"],
            expires_at=time.time() - 1,
        )
        with pytest.raises(CapabilityError) as exc_info:
            loader.load_skill("web_browsing", token)
        assert "token_expired" in str(exc_info.value) or "token_expired" in exc_info.value.missing

    def test_tampered_token_rejected(self):
        loader = VerifiedSkillLoader(Path("skills"))
        token = _token(permissions=["network:http:read", "filesystem:cache:write"])
        object.__setattr__(token, "permissions", ("hacked",))  # bypass freeze for HMAC test
        with pytest.raises(CapabilityError) as exc_info:
            loader.load_skill("web_browsing", token)
        assert "tampered" in str(exc_info.value).lower()

    def test_budget_exhausted_rejected(self):
        loader = VerifiedSkillLoader(Path("skills"))
        token = _token(
            permissions=["network:http:read", "filesystem:cache:write"],
            budget_remaining_cents=0,
        )
        with pytest.raises(CapabilityError) as exc_info:
            loader.load_skill("web_browsing", token)
        assert "budget" in str(exc_info.value).lower()

    def test_valid_token_passes(self):
        loader = VerifiedSkillLoader(Path("skills"))
        token = _token(permissions=["network:http:read", "filesystem:cache:write"])
        skill = loader.load_skill("web_browsing", token)
        assert skill.summary.skill_id == "web_browsing"


# ══════════════════════════════════════════════════════════════════
# A3 SKILL: VerifiedSkillLoader compliance intersection
# ══════════════════════════════════════════════════════════════════

class TestA3SkillLoaderComplianceIntersection:
    """VerifiedSkillLoader with compliance_config enforces forbidden/ceiling."""

    def test_forbidden_skill_cap_blocked(self):
        """Skill requiring forbidden capability is rejected."""
        # Create a compliance config that forbids network:http:read
        cfg = ComplianceConfig(
            name="RestrictedNet",
            permissions=["filesystem:read"],
            max_permissions=["filesystem:read", "filesystem:write"],
            forbidden_permissions=["network:http:read"],
        )
        loader = VerifiedSkillLoader(Path("skills"), compliance_config=cfg)
        token = _token(permissions=["network:http:read", "filesystem:cache:write"])
        with pytest.raises(CapabilityError) as exc_info:
            loader.load_skill("web_browsing", token)
        assert "forbidden" in str(exc_info.value).lower()

    def test_skill_within_ceiling_passes(self):
        """Skill whose caps are within the compliance ceiling succeeds."""
        cfg = ComplianceConfig(
            name="WebAllowed",
            permissions=["network:http:read"],
            max_permissions=[
                "network:http:read",
                "filesystem:cache:write",
                "filesystem:read",
            ],
        )
        loader = VerifiedSkillLoader(Path("skills"), compliance_config=cfg)
        token = _token(permissions=["network:http:read", "filesystem:cache:write"])
        skill = loader.load_skill("web_browsing", token)
        assert skill.summary.skill_id == "web_browsing"

    def test_skill_exceeds_ceiling_blocked(self):
        """Skill requiring caps outside ceiling is rejected."""
        cfg = ComplianceConfig(
            name="NarrowCeiling",
            permissions=["filesystem:read"],
            max_permissions=["filesystem:read"],
        )
        loader = VerifiedSkillLoader(Path("skills"), compliance_config=cfg)
        # web_browsing requires network:http:read which is not in ceiling
        token = _token(permissions=["network:http:read", "filesystem:cache:write"])
        with pytest.raises(CapabilityError) as exc_info:
            loader.load_skill("web_browsing", token)
        assert "ceiling" in str(exc_info.value).lower()

    def test_no_compliance_config_no_check(self):
        """Without compliance config, standard Z3 verification only."""
        loader = VerifiedSkillLoader(Path("skills"))
        token = _token(permissions=["network:http:read", "filesystem:cache:write"])
        skill = loader.load_skill("web_browsing", token)
        assert skill.verification_result.valid

    def test_hipaa_allows_permitted_skill(self):
        """HIPAA config allows skills within the ceiling."""
        hipaa = CompliancePresets.hipaa()
        # Create a config that allows database:read via wildcard
        cfg = ComplianceConfig(
            name="HIPAA-extended",
            permissions=hipaa.permissions,
            max_permissions=hipaa.max_permissions + ["database:*"],
            forbidden_permissions=hipaa.forbidden_permissions,
        )
        loader = VerifiedSkillLoader(Path("skills"), compliance_config=cfg)
        token = _token(permissions=["database:read"])
        skill = loader.load_skill("database_query", token)
        assert skill.summary.skill_id == "database_query"


# ══════════════════════════════════════════════════════════════════
# Integration: A1 + A3 combined
# ══════════════════════════════════════════════════════════════════

class TestA1A3CombinedEnforcement:
    """Both token validation AND compliance intersection enforced."""

    def setup_method(self):
        CertiorTelemetry.reset()
        ComplianceVerifier.reset()

    @pytest.mark.asyncio
    async def test_invalid_token_checked_before_compliance(self):
        """Token validity is checked BEFORE compliance permission check."""
        hipaa_cfg = CompliancePresets.hipaa()
        verifier = SafeVerifier(
            ContentSafetyPolicy.hipaa_compliant(),
            compliance_config=hipaa_cfg,
        )
        # Both invalid token AND forbidden capability
        token = _token(
            expires_at=time.time() - 1,
            permissions=["network:smtp:send:external"],
        )
        action = _action(required_capabilities=["network:smtp:send:external"])
        result = await verifier.verify_and_scan(action=action, token=token)
        assert not result.approved
        # Token check should fire first
        assert result.token_error == "token_expired"
        # Compliance check should NOT have run
        assert len(result.permission_denials) == 0

    @pytest.mark.asyncio
    async def test_valid_token_but_forbidden_cap(self):
        """Valid token but capability forbidden by compliance → denied."""
        hipaa_cfg = CompliancePresets.hipaa()
        verifier = SafeVerifier(
            ContentSafetyPolicy.hipaa_compliant(),
            compliance_config=hipaa_cfg,
        )
        token = _token(permissions=["network:smtp:send:external"])
        action = _action(required_capabilities=["network:smtp:send:external"])
        result = await verifier.verify_and_scan(action=action, token=token)
        assert not result.approved
        assert result.token_error is None  # token itself is fine
        assert len(result.permission_denials) > 0

    @pytest.mark.asyncio
    async def test_full_happy_path(self):
        """Valid token + allowed capability + clean content → approved."""
        hipaa_cfg = CompliancePresets.hipaa()
        verifier = SafeVerifier(
            ContentSafetyPolicy.hipaa_compliant(),
            compliance_config=hipaa_cfg,
        )
        token = _token(permissions=["database:read:patient_data"])
        action = _action(required_capabilities=["database:read:patient_data"])
        result = await verifier.verify_and_scan(
            action=action, token=token, content="Patient needs follow-up",
        )
        assert result.approved
        assert result.token_error is None
        assert len(result.permission_denials) == 0

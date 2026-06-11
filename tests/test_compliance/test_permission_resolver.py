"""
Tests for agentsafe.compliance.permission_resolver.

Covers:
  - Default permission resolution (no user override)
  - User-supplied permissions intersected with policy ceiling
  - Forbidden permission filtering
  - Wildcard denial under restrictive policies
  - Wildcard pass-through under Default policy
  - Role-based restrictions (admin vs operator vs viewer)
  - Edge cases (empty permissions, duplicates, all denied)
  - The specific BYPASS #1 attack vector
  - Audit trail correctness
"""
import pytest

from agentsafe.compliance import (
    CompliancePresets,
    ComplianceConfig,
    AuditConfig,
    PermissionResolver,
    PermissionResolution,
    PermissionDenial,
    DenialReason,
)


@pytest.fixture
def resolver():
    return PermissionResolver()


@pytest.fixture
def hipaa():
    return CompliancePresets.hipaa()


@pytest.fixture
def sox():
    return CompliancePresets.sox()


@pytest.fixture
def legal():
    return CompliancePresets.legal_privilege()


@pytest.fixture
def default_policy():
    return CompliancePresets.default()


# ─── BYPASS #1 - the specific attack vector ──────────────────────────

class TestBypass1Prevention:
    """
    BYPASS #1: User sends permissions=["*"] with compliance_policy="hipaa".
    Previously, this granted universal permissions while claiming HIPAA.
    Now, wildcard is denied and only policy-ceiling permissions pass.
    """

    def test_wildcard_with_hipaa_is_denied(self, resolver, hipaa):
        """The exact attack from the analysis: '*' + HIPAA."""
        result = resolver.resolve(
            requested_permissions=["*"],
            policy=hipaa,
            user_role="admin",
        )
        # Wildcard should be DENIED
        assert "*" not in result.effective_permissions
        assert result.has_denials
        wildcard_denial = next(
            d for d in result.denied if d.permission == "*"
        )
        assert wildcard_denial.reason == DenialReason.WILDCARD_DENIED_UNDER_COMPLIANCE

    def test_wildcard_with_sox_is_denied(self, resolver, sox):
        result = resolver.resolve(
            requested_permissions=["*"],
            policy=sox,
            user_role="admin",
        )
        assert "*" not in result.effective_permissions
        assert result.has_denials

    def test_wildcard_with_legal_is_denied(self, resolver, legal):
        result = resolver.resolve(
            requested_permissions=["*"],
            policy=legal,
            user_role="admin",
        )
        assert "*" not in result.effective_permissions
        assert result.has_denials

    def test_wildcard_with_default_is_allowed(self, resolver, default_policy):
        """Default policy has open ceiling - wildcard is fine."""
        result = resolver.resolve(
            requested_permissions=["*"],
            policy=default_policy,
            user_role="admin",
        )
        assert "*" in result.effective_permissions
        assert not result.has_denials

    def test_escalation_via_extra_perms(self, resolver, hipaa):
        """User requests permissions beyond HIPAA ceiling."""
        result = resolver.resolve(
            requested_permissions=[
                "database:read:patient_data",   # allowed
                "database:write:anything",       # NOT in ceiling
                "network:admin:full",            # NOT in ceiling
            ],
            policy=hipaa,
            user_role="admin",
        )
        assert "database:read:patient_data" in result.effective_permissions
        assert "database:write:anything" not in result.effective_permissions
        assert "network:admin:full" not in result.effective_permissions
        assert len(result.denied) == 2

    def test_forbidden_perm_always_stripped(self, resolver, hipaa):
        """Forbidden perms are denied even if within ceiling."""
        result = resolver.resolve(
            requested_permissions=["network:smtp:send:external"],
            policy=hipaa,
            user_role="admin",
        )
        assert "network:smtp:send:external" not in result.effective_permissions
        denial = result.denied[0]
        assert denial.reason == DenialReason.FORBIDDEN_BY_POLICY


# ─── Default resolution (no user override) ────────────────────────────

class TestDefaultResolution:
    """When user provides no permissions → policy defaults used."""

    def test_hipaa_defaults(self, resolver, hipaa):
        result = resolver.resolve(
            requested_permissions=None,
            policy=hipaa,
            user_role="admin",
        )
        assert result.used_defaults is True
        assert result.effective_permissions == hipaa.permissions
        assert not result.has_denials

    def test_sox_defaults(self, resolver, sox):
        result = resolver.resolve(
            requested_permissions=None,
            policy=sox,
            user_role="operator",
        )
        assert result.used_defaults is True
        assert result.effective_permissions == sox.permissions

    def test_legal_defaults(self, resolver, legal):
        result = resolver.resolve(
            requested_permissions=None,
            policy=legal,
            user_role="admin",
        )
        assert result.used_defaults is True
        assert set(result.effective_permissions) == set(legal.permissions)

    def test_default_policy_defaults(self, resolver, default_policy):
        result = resolver.resolve(
            requested_permissions=None,
            policy=default_policy,
            user_role="admin",
        )
        assert result.used_defaults is True
        assert "*" in result.effective_permissions

    def test_empty_list_treated_as_no_permissions(self, resolver, hipaa):
        result = resolver.resolve(
            requested_permissions=[],
            policy=hipaa,
            user_role="admin",
        )
        assert result.used_defaults is True


# ─── Ceiling intersection ─────────────────────────────────────────────

class TestCeilingIntersection:
    """User permissions are clipped to the policy ceiling."""

    def test_within_ceiling_passes(self, resolver, hipaa):
        result = resolver.resolve(
            requested_permissions=["database:read:patient_data"],
            policy=hipaa,
            user_role="admin",
        )
        assert result.effective_permissions == ["database:read:patient_data"]
        assert not result.has_denials

    def test_outside_ceiling_denied(self, resolver, hipaa):
        result = resolver.resolve(
            requested_permissions=["network:http:read"],
            policy=hipaa,
            user_role="admin",
        )
        assert result.effective_permissions == []
        assert len(result.denied) == 1
        assert result.denied[0].reason == DenialReason.EXCEEDS_POLICY_CEILING

    def test_mixed_within_and_outside(self, resolver, sox):
        result = resolver.resolve(
            requested_permissions=[
                "database:read:financial_data",  # in ceiling
                "database:write:financial_data",  # forbidden
                "network:http:read",              # not in ceiling
            ],
            policy=sox,
            user_role="admin",
        )
        assert result.effective_permissions == ["database:read:financial_data"]
        assert len(result.denied) == 2

    def test_max_permissions_wider_than_defaults(self, resolver, hipaa):
        """Admin can request perms in max_permissions but not in defaults."""
        result = resolver.resolve(
            requested_permissions=["compute:python:eval"],
            policy=hipaa,
            user_role="admin",
        )
        assert "compute:python:eval" in result.effective_permissions
        assert not result.has_denials

    def test_default_policy_no_ceiling(self, resolver, default_policy):
        """Default policy has open ceiling - everything passes."""
        result = resolver.resolve(
            requested_permissions=[
                "database:read",
                "network:http:read",
                "custom:anything",
            ],
            policy=default_policy,
            user_role="admin",
        )
        assert len(result.effective_permissions) == 3
        assert not result.has_denials


# ─── Forbidden permissions ────────────────────────────────────────────

class TestForbiddenPermissions:
    """Forbidden permissions are always stripped regardless of ceiling."""

    def test_exact_forbidden_match(self, resolver, hipaa):
        result = resolver.resolve(
            requested_permissions=["network:smtp:send:external"],
            policy=hipaa,
            user_role="admin",
        )
        assert "network:smtp:send:external" not in result.effective_permissions
        assert result.denied[0].reason == DenialReason.FORBIDDEN_BY_POLICY

    def test_wildcard_forbidden_match(self, resolver):
        """Forbidden wildcard 'network:*' blocks 'network:http:read'."""
        config = ComplianceConfig(
            name="test",
            permissions=["network:http:read", "database:read"],
            max_permissions=["network:http:read", "database:read"],
            forbidden_permissions=["network:*"],
        )
        result = resolver.resolve(
            requested_permissions=["network:http:read", "database:read"],
            policy=config,
            user_role="admin",
        )
        assert "network:http:read" not in result.effective_permissions
        assert "database:read" in result.effective_permissions

    def test_forbidden_in_defaults_stripped(self, resolver):
        """Even policy defaults are stripped if they conflict with forbidden."""
        config = ComplianceConfig(
            name="broken",
            permissions=["a", "b"],
            forbidden_permissions=["b"],
        )
        result = resolver.resolve(
            requested_permissions=None,
            policy=config,
            user_role="admin",
        )
        assert "a" in result.effective_permissions
        assert "b" not in result.effective_permissions
        assert result.has_denials


# ─── Role-based restrictions ──────────────────────────────────────────

class TestRoleRestrictions:

    def test_viewer_cannot_create_tasks(self, resolver, hipaa):
        with pytest.raises(PermissionError, match="not permitted"):
            resolver.resolve(
                requested_permissions=None,
                policy=hipaa,
                user_role="viewer",
            )

    def test_operator_limited_to_defaults(self, resolver, hipaa):
        """Operator cannot request perms beyond the policy default set."""
        result = resolver.resolve(
            requested_permissions=["compute:python:eval"],
            policy=hipaa,
            user_role="operator",
        )
        # compute:python:eval is in max_permissions but NOT in defaults
        assert "compute:python:eval" not in result.effective_permissions
        assert result.has_denials
        assert result.denied[0].reason == DenialReason.EXCEEDS_ROLE_ALLOWANCE

    def test_operator_within_defaults_ok(self, resolver, hipaa):
        result = resolver.resolve(
            requested_permissions=["database:read:patient_data"],
            policy=hipaa,
            user_role="operator",
        )
        assert "database:read:patient_data" in result.effective_permissions
        assert not result.has_denials

    def test_admin_can_use_max_permissions(self, resolver, hipaa):
        """Admin can request anything within the max ceiling."""
        result = resolver.resolve(
            requested_permissions=[
                "database:read:patient_data",
                "database:read:clinical_data",
                "compute:python:eval",
            ],
            policy=hipaa,
            user_role="admin",
        )
        assert len(result.effective_permissions) == 3
        assert not result.has_denials

    def test_admin_default_policy_unrestricted(self, resolver, default_policy):
        result = resolver.resolve(
            requested_permissions=["anything:at:all"],
            policy=default_policy,
            user_role="admin",
        )
        assert "anything:at:all" in result.effective_permissions

    def test_operator_default_policy(self, resolver, default_policy):
        """Operator under default policy: defaults include '*', so '*' covers anything."""
        result = resolver.resolve(
            requested_permissions=["custom:perm"],
            policy=default_policy,
            user_role="operator",
        )
        # Default policy defaults are ["*"], which covers "custom:perm"
        assert "custom:perm" in result.effective_permissions

    def test_role_case_insensitive(self, resolver, hipaa):
        """Role comparison is case-insensitive."""
        with pytest.raises(PermissionError):
            resolver.resolve(
                requested_permissions=None,
                policy=hipaa,
                user_role="VIEWER",
            )


# ─── Edge cases ───────────────────────────────────────────────────────

class TestEdgeCases:

    def test_duplicate_permissions_deduped(self, resolver, hipaa):
        result = resolver.resolve(
            requested_permissions=[
                "database:read:patient_data",
                "database:read:patient_data",
                "database:read:patient_data",
            ],
            policy=hipaa,
            user_role="admin",
        )
        assert result.effective_permissions == ["database:read:patient_data"]

    def test_all_permissions_denied(self, resolver, hipaa):
        result = resolver.resolve(
            requested_permissions=["network:smtp:send:external"],
            policy=hipaa,
            user_role="admin",
        )
        assert result.is_empty

    def test_resolution_to_dict(self, resolver, hipaa):
        result = resolver.resolve(
            requested_permissions=["database:read:patient_data", "bad:perm"],
            policy=hipaa,
            user_role="admin",
        )
        d = result.to_dict()
        assert d["policy_name"] == "HIPAA"
        assert d["user_role"] == "admin"
        assert d["requested_permissions"] == [
            "database:read:patient_data", "bad:perm"
        ]
        assert len(d["denied"]) == 1
        assert d["used_defaults"] is False

    def test_empty_policy_permissions(self, resolver):
        """Policy with no permissions at all."""
        config = ComplianceConfig(name="empty", permissions=[])
        result = resolver.resolve(
            requested_permissions=None,
            policy=config,
            user_role="admin",
        )
        assert result.effective_permissions == []
        assert result.used_defaults is True

    def test_policy_with_only_forbidden(self, resolver):
        """Policy that forbids everything it allows."""
        config = ComplianceConfig(
            name="strict",
            permissions=["a", "b"],
            forbidden_permissions=["a", "b"],
        )
        result = resolver.resolve(
            requested_permissions=None,
            policy=config,
            user_role="admin",
        )
        assert result.is_empty

    def test_warnings_on_denial(self, resolver, hipaa):
        result = resolver.resolve(
            requested_permissions=["bad:perm"],
            policy=hipaa,
            user_role="admin",
        )
        assert len(result.warnings) > 0
        assert "denied" in result.warnings[0].lower()

    def test_wildcard_in_requested_produces_warning(self, resolver, hipaa):
        result = resolver.resolve(
            requested_permissions=["*", "database:read:patient_data"],
            policy=hipaa,
            user_role="admin",
        )
        wildcard_warnings = [
            w for w in result.warnings if "wildcard" in w.lower()
        ]
        assert len(wildcard_warnings) > 0


# ─── Permission matching logic ────────────────────────────────────────

class TestPermissionMatching:
    """Tests for the internal _permission_covered_by logic."""

    def test_exact_match(self, resolver):
        assert resolver._permission_covered_by(
            "database:read", ["database:read"]
        )

    def test_wildcard_in_ceiling(self, resolver):
        assert resolver._permission_covered_by(
            "database:read:patient_data",
            ["database:*"],
        )

    def test_universal_wildcard(self, resolver):
        assert resolver._permission_covered_by(
            "anything:at:all", ["*"]
        )

    def test_no_match(self, resolver):
        assert not resolver._permission_covered_by(
            "network:http:read", ["database:read"]
        )

    def test_partial_prefix_no_wildcard(self, resolver):
        """Without wildcard, 'database:read' does not cover 'database:read:x'."""
        assert not resolver._permission_covered_by(
            "database:read:x", ["database:read"]
        )


# ─── Preset-specific tests ────────────────────────────────────────────

class TestPresetMaxPermissions:
    """Verify that each preset's max_permissions is a superset of defaults."""

    def test_hipaa_ceiling_covers_defaults(self):
        cfg = CompliancePresets.hipaa()
        resolver = PermissionResolver()
        for perm in cfg.permissions:
            assert resolver._permission_covered_by(
                perm, cfg.max_permissions
            ), f"HIPAA default '{perm}' not in max_permissions"

    def test_sox_ceiling_covers_defaults(self):
        cfg = CompliancePresets.sox()
        resolver = PermissionResolver()
        for perm in cfg.permissions:
            assert resolver._permission_covered_by(
                perm, cfg.max_permissions
            ), f"SOX default '{perm}' not in max_permissions"

    def test_legal_ceiling_covers_defaults(self):
        cfg = CompliancePresets.legal_privilege()
        resolver = PermissionResolver()
        for perm in cfg.permissions:
            assert resolver._permission_covered_by(
                perm, cfg.max_permissions
            ), f"Legal default '{perm}' not in max_permissions"

    def test_default_has_open_ceiling(self):
        cfg = CompliancePresets.default()
        assert cfg.max_permissions == ["*"]


# ─── Integration: ComplianceConfig.to_dict includes max_permissions ───

class TestConfigSerialization:
    def test_to_dict_includes_max_permissions(self):
        cfg = CompliancePresets.hipaa()
        d = cfg.to_dict()
        assert "max_permissions" in d
        assert len(d["max_permissions"]) > 0

    def test_default_to_dict(self):
        cfg = CompliancePresets.default()
        d = cfg.to_dict()
        assert d["max_permissions"] == ["*"]

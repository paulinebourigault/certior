"""Tests for core infrastructure: tokens, certificates, IFC."""
import pytest
import time
from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.kernel.certificate import (
    CertificateAuthority, TrustedKernel, VerifiedCertificate,
)
from agentsafe.flow.information_flow import (
    SecurityLevel, SecurityLabel, TaintTracker, FlowRule,
)


class TestCapabilityToken:
    def test_create_token(self):
        t = CapabilityToken(agent_id="a1", permissions=["db:read"])
        assert t.agent_id == "a1"
        assert t.has_permission("db:read")
        assert not t.has_permission("db:write")

    def test_wildcard_permission(self):
        t = CapabilityToken(permissions=["database:*"])
        assert t.has_permission("database:read")
        assert t.has_permission("database:write")
        assert not t.has_permission("network:read")

    def test_has_all_permissions(self):
        t = CapabilityToken(permissions=["a", "b", "c"])
        assert t.has_all_permissions(["a", "b"])
        assert not t.has_all_permissions(["a", "d"])

    def test_budget(self):
        t = CapabilityToken(budget_cents=1000, budget_remaining_cents=1000)
        assert t.has_budget(500)
        assert t.consume_budget(500)
        assert t.budget_remaining_cents == 500
        assert not t.has_budget(600)
        assert not t.consume_budget(600)

    def test_validity(self):
        t = CapabilityToken()
        assert t.is_valid()

    def test_expired_token(self):
        t = CapabilityToken(expires_at=time.time() - 100)
        assert not t.is_valid()

    def test_permission_set(self):
        t = CapabilityToken(permissions=["a", "b"])
        assert t.permission_set == {"a", "b"}

    def test_to_dict(self):
        t = CapabilityToken(agent_id="x", permissions=["p"])
        d = t.to_dict()
        assert d["agent_id"] == "x"
        assert d["permissions"] == ["p"]


class TestCertificateAuthority:
    def setup_method(self):
        CertificateAuthority.reset()

    def test_issue_certificate(self):
        ca = CertificateAuthority()
        cert = ca.issue_certificate(
            theorem="test", plan_hash="abc",
            verified_properties=["p1"],
        )
        assert cert.theorem == "test"
        assert cert.is_valid()

    def test_validate_certificate(self):
        ca = CertificateAuthority()
        cert = ca.issue_certificate("t", "hash", ["p"])
        assert ca.validate_certificate(cert, "hash")
        assert not ca.validate_certificate(cert, "wrong_hash")

    def test_revoke(self):
        ca = CertificateAuthority()
        cert = ca.issue_certificate("t", "h", ["p"])
        ca.revoke(cert.id)
        assert not ca.validate_certificate(cert)

    def test_singleton(self):
        ca1 = CertificateAuthority.get_instance()
        ca2 = CertificateAuthority.get_instance()
        assert ca1 is ca2

    def test_trusted_kernel(self):
        ca = CertificateAuthority()
        kernel = TrustedKernel(ca)
        cert = ca.issue_certificate("t", "h", ["p"])
        assert kernel.validate_certificate(cert, "h")


class TestInformationFlow:
    def test_security_levels(self):
        assert SecurityLevel.PUBLIC.can_flow_to(SecurityLevel.INTERNAL)
        assert SecurityLevel.PUBLIC.can_flow_to(SecurityLevel.SENSITIVE)
        assert not SecurityLevel.SENSITIVE.can_flow_to(SecurityLevel.PUBLIC)

    def test_security_labels(self):
        pub = SecurityLabel(level=SecurityLevel.PUBLIC)
        priv = SecurityLabel(level=SecurityLevel.SENSITIVE, tags={"phi"})
        assert pub.can_flow_to(priv)
        assert not priv.can_flow_to(pub)

    def test_taint_tracker(self):
        tracker = TaintTracker()
        label = SecurityLabel(level=SecurityLevel.SENSITIVE)
        tracker.tag("data1", label)
        assert tracker.get_label("data1") == label

    def test_taint_violation(self):
        tracker = TaintTracker()
        tracker.tag("secret", SecurityLabel(level=SecurityLevel.SENSITIVE))
        public = SecurityLabel(level=SecurityLevel.PUBLIC)
        assert not tracker.check_flow("secret", public)
        assert len(tracker.violations) == 1

    def test_taint_allowed(self):
        tracker = TaintTracker()
        tracker.tag("data", SecurityLabel(level=SecurityLevel.PUBLIC))
        internal = SecurityLabel(level=SecurityLevel.INTERNAL)
        assert tracker.check_flow("data", internal)
        assert len(tracker.violations) == 0

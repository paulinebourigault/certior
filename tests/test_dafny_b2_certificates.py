"""
Dafny-Verified Certificate Authority - Comprehensive Tests.

Tests every property proven in ``dafny/kernel/certificate.dfy``:

  P3   Issuance integrity - validate succeeds only for issued certs
  P4   Validation correctness - all 4 checks independently necessary
  P5   Revocation correctness - revoked certs always rejected
  P6   Signature soundness - mutating any field invalidates signature
  P9   Registry monotonicity - issued set only grows, count never decrements
  P10  Certificate uniqueness - duplicate IDs rejected
  P11  Invariant preservation - Valid() holds at every method boundary
  P12  Revocation isolation - revoking X doesn't affect Y

Also tests:
  - Thread safety under concurrent operations
  - Audit trail completeness
  - TrustedKernel delegation
  - Ghost state tracking
  - Edge cases (empty CA, double revoke, etc.)
"""
from __future__ import annotations

import copy
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import patch

import pytest

from agentsafe.kernel.certificate import (
    CertificateAuthority,
    TrustedKernel,
    VerifiedCertificate,
)
from agentsafe.verification.dafny_runtime import (
    InvariantAuditLog,
    InvariantViolation,
    PreconditionViolation,
)


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset():
    CertificateAuthority.reset()
    InvariantAuditLog.reset()
    yield
    CertificateAuthority.reset()
    InvariantAuditLog.reset()


def _fresh_ca() -> CertificateAuthority:
    """Non-singleton CA for isolation."""
    return CertificateAuthority()


def _issue(ca, **kw):
    """Helper to issue a cert with defaults."""
    defaults = dict(
        theorem="action_safe",
        plan_hash="hash-abc",
        verified_properties=["cap_coverage", "budget_ok"],
        prover="z3",
        ttl_seconds=3600,
    )
    defaults.update(kw)
    return ca.issue_certificate(**defaults)


# =============================================================================
# P3: ISSUANCE INTEGRITY
# =============================================================================

class TestP3IssuanceIntegrity:
    """validate(cert) == True ONLY IF cert.id ∈ issued_set."""

    def test_issued_cert_validates(self):
        """A freshly issued cert passes validation."""
        ca = _fresh_ca()
        cert = _issue(ca)
        assert ca.validate_certificate(cert, "hash-abc")

    def test_issued_cert_in_registry(self):
        """After issuing, cert.id is in the issued set."""
        ca = _fresh_ca()
        cert = _issue(ca)
        assert ca.is_issued(cert.id)

    def test_forged_cert_rejected(self):
        """A cert not issued by our CA is always rejected."""
        ca = _fresh_ca()
        forged = VerifiedCertificate(
            theorem="action_safe",
            plan_hash="hash-abc",
            verified_properties=["cap_coverage"],
        )
        assert not ca.validate_certificate(forged, "hash-abc")

    def test_cert_from_different_ca_rejected(self):
        """A cert from CA-A is rejected by CA-B."""
        ca_a = _fresh_ca()
        ca_b = _fresh_ca()
        cert = _issue(ca_a)
        assert not ca_b.validate_certificate(cert, "hash-abc")

    def test_issued_cert_has_valid_signature(self):
        """Every issued cert has a valid signature (P3 postcondition)."""
        ca = _fresh_ca()
        cert = _issue(ca)
        assert cert._dafny_signature_valid()

    def test_issue_returns_correct_fields(self):
        """Postconditions: returned cert has the requested fields."""
        ca = _fresh_ca()
        cert = ca.issue_certificate(
            theorem="my_thm",
            plan_hash="my_hash",
            verified_properties=["p1", "p2"],
            prover="lean4",
            ttl_seconds=7200,
        )
        assert cert.theorem == "my_thm"
        assert cert.plan_hash == "my_hash"
        assert cert.verified_properties == ["p1", "p2"]
        assert cert.prover == "lean4"
        assert cert._dafny_signature_valid()


# =============================================================================
# P4: VALIDATION CORRECTNESS
# =============================================================================

class TestP4ValidationCorrectness:
    """validate checks (a) provenance, (b) signature, (c) freshness, (d) binding.
    ALL four must hold; failure of ANY single check causes rejection."""

    def test_all_checks_pass(self):
        """When all four checks pass, validation succeeds."""
        ca = _fresh_ca()
        cert = _issue(ca, plan_hash="h1")
        assert ca.validate_certificate(cert, "h1")

    def test_empty_expected_hash_skips_binding(self):
        """When expected_hash is empty, binding check is skipped."""
        ca = _fresh_ca()
        cert = _issue(ca, plan_hash="whatever")
        assert ca.validate_certificate(cert, "")
        assert ca.validate_certificate(cert)  # default=""

    # ── Each check independently causes rejection ─────────────

    def test_provenance_failure_rejects(self):
        """(a) cert.id not in issued → rejected."""
        ca = _fresh_ca()
        forged = VerifiedCertificate(theorem="t", plan_hash="h")
        assert not ca.validate_certificate(forged, "h")

    def test_signature_failure_rejects(self):
        """(b) Tampered signature → rejected."""
        ca = _fresh_ca()
        cert = _issue(ca, plan_hash="h")
        # Tamper the cert (external copy - registry is unaffected)
        cert.theorem = "hacked"
        assert not cert._dafny_signature_valid()
        assert not ca.validate_certificate(cert, "h")

    def test_freshness_failure_rejects(self):
        """(c) Expired cert → rejected."""
        ca = _fresh_ca()
        cert = _issue(ca, plan_hash="h", ttl_seconds=0)
        time.sleep(0.02)
        assert not cert._dafny_not_expired()
        assert not ca.validate_certificate(cert, "h")

    def test_binding_failure_rejects(self):
        """(d) Wrong plan_hash → rejected."""
        ca = _fresh_ca()
        cert = _issue(ca, plan_hash="correct")
        assert not ca.validate_certificate(cert, "wrong")

    # ── Combinations: exactly one check fails ─────────────────

    def test_only_provenance_fails(self):
        """Valid signature, not expired, correct hash, but not issued."""
        ca = _fresh_ca()
        forged = VerifiedCertificate(
            theorem="t", plan_hash="h",
            verified_properties=["p"],
            expires_at=time.time() + 3600,
        )
        assert forged._dafny_signature_valid()
        assert forged._dafny_not_expired()
        assert not ca.validate_certificate(forged, "h")

    def test_only_binding_fails(self):
        """Issued, valid signature, not expired, but wrong hash."""
        ca = _fresh_ca()
        cert = _issue(ca, plan_hash="correct")
        assert cert._dafny_signature_valid()
        assert cert._dafny_not_expired()
        assert ca.is_issued(cert.id)
        assert not ca.validate_certificate(cert, "wrong")


# =============================================================================
# P5: REVOCATION CORRECTNESS
# =============================================================================

class TestP5RevocationCorrectness:
    """After revoke(id): validate for that id returns False."""

    def test_revoked_cert_fails_validation(self):
        """Basic revocation: cert no longer validates."""
        ca = _fresh_ca()
        cert = _issue(ca)
        assert ca.validate_certificate(cert, "hash-abc")
        ca.revoke(cert.id)
        assert not ca.validate_certificate(cert, "hash-abc")

    def test_revoked_cert_not_in_issued(self):
        """After revoke, cert.id is not in issued set."""
        ca = _fresh_ca()
        cert = _issue(ca)
        ca.revoke(cert.id)
        assert not ca.is_issued(cert.id)

    def test_double_revoke_is_noop(self):
        """Revoking an already-revoked cert is a no-op."""
        ca = _fresh_ca()
        cert = _issue(ca)
        ca.revoke(cert.id)
        ca.revoke(cert.id)  # should not raise
        assert not ca.is_issued(cert.id)

    def test_revoke_nonexistent_is_noop(self):
        """Revoking a never-issued cert is a no-op."""
        ca = _fresh_ca()
        ca.revoke("nonexistent-id")  # should not raise
        assert ca.count() == 0

    def test_revoke_then_reissue(self):
        """After revoking, a new cert with a different ID works."""
        ca = _fresh_ca()
        cert1 = _issue(ca, plan_hash="h1")
        ca.revoke(cert1.id)
        cert2 = _issue(ca, plan_hash="h2")
        assert not ca.validate_certificate(cert1, "h1")
        assert ca.validate_certificate(cert2, "h2")


# =============================================================================
# P6: SIGNATURE SOUNDNESS
# =============================================================================

class TestP6SignatureSoundness:
    """Mutating any identity field invalidates SignatureValid().
    Dafny proves this for id, theorem, plan_hash, prover, properties."""

    def _make_cert(self):
        return VerifiedCertificate(
            id="cert-1",
            theorem="action_safe",
            plan_hash="hash-abc",
            verified_properties=["cap_coverage", "budget_ok"],
            prover="z3",
        )

    def test_fresh_cert_signature_valid(self):
        cert = self._make_cert()
        assert cert._dafny_signature_valid()

    def test_mutate_id_invalidates(self):
        cert = self._make_cert()
        cert.id = "cert-mutated"
        assert not cert._dafny_signature_valid()

    def test_mutate_theorem_invalidates(self):
        cert = self._make_cert()
        cert.theorem = "hacked_theorem"
        assert not cert._dafny_signature_valid()

    def test_mutate_plan_hash_invalidates(self):
        cert = self._make_cert()
        cert.plan_hash = "hacked_hash"
        assert not cert._dafny_signature_valid()

    def test_mutate_prover_invalidates(self):
        cert = self._make_cert()
        cert.prover = "hacked_prover"
        assert not cert._dafny_signature_valid()

    def test_mutate_properties_invalidates(self):
        cert = self._make_cert()
        cert.verified_properties = ["hacked"]
        assert not cert._dafny_signature_valid()

    def test_mutate_properties_append_invalidates(self):
        """Even appending to the list invalidates."""
        cert = self._make_cert()
        cert.verified_properties.append("extra")
        assert not cert._dafny_signature_valid()

    def test_non_identity_fields_dont_invalidate(self):
        """Changing proof_trace, issued_at, expires_at doesn't affect sig."""
        cert = self._make_cert()
        cert.proof_trace = "different_trace"
        assert cert._dafny_signature_valid()

        cert.issued_at = 999999.0
        assert cert._dafny_signature_valid()

        cert.expires_at = 0.0
        assert cert._dafny_signature_valid()

    def test_is_valid_reflects_signature(self):
        """is_valid() returns False when signature is broken."""
        cert = self._make_cert()
        assert cert.is_valid()
        cert.theorem = "tampered"
        assert not cert.is_valid()


# =============================================================================
# P9: REGISTRY MONOTONICITY
# =============================================================================

class TestP9RegistryMonotonicity:
    """issue_certificate strictly grows issued set.
    total_issued_count never decreases."""

    def test_issue_grows_set(self):
        ca = _fresh_ca()
        assert ca.count() == 0
        _issue(ca)
        assert ca.count() == 1
        _issue(ca)
        assert ca.count() == 2

    def test_total_issued_count_increments(self):
        ca = _fresh_ca()
        assert ca.total_issued_count == 0
        _issue(ca)
        assert ca.total_issued_count == 1
        _issue(ca)
        assert ca.total_issued_count == 2

    def test_revoke_does_not_decrement_count(self):
        """total_issued_count is unchanged by revoke."""
        ca = _fresh_ca()
        cert = _issue(ca)
        assert ca.total_issued_count == 1
        ca.revoke(cert.id)
        assert ca.total_issued_count == 1
        assert ca.count() == 0

    def test_count_after_issue_revoke_issue(self):
        ca = _fresh_ca()
        c1 = _issue(ca)
        assert ca.total_issued_count == 1 and ca.count() == 1
        ca.revoke(c1.id)
        assert ca.total_issued_count == 1 and ca.count() == 0
        _issue(ca)
        assert ca.total_issued_count == 2 and ca.count() == 1
        _issue(ca)
        assert ca.total_issued_count == 3 and ca.count() == 2

    def test_monotonicity_c4_invariant(self):
        """C4: |issued| ≤ total_issued_count at every step."""
        ca = _fresh_ca()
        for _ in range(5):
            _issue(ca)
        assert ca.count() <= ca.total_issued_count

        certs = list(ca.issued_ids)
        for cid in certs[:3]:
            ca.revoke(cid)
        assert ca.count() == 2
        assert ca.total_issued_count == 5
        assert ca.count() <= ca.total_issued_count

    def test_issued_ids_snapshot(self):
        ca = _fresh_ca()
        c1 = _issue(ca)
        c2 = _issue(ca)
        ids = ca.issued_ids
        assert c1.id in ids
        assert c2.id in ids
        assert len(ids) == 2


# =============================================================================
# P10: CERTIFICATE UNIQUENESS
# =============================================================================

class TestP10CertificateUniqueness:
    """No two active certificates share the same ID."""

    def test_all_issued_certs_have_unique_ids(self):
        ca = _fresh_ca()
        certs = [_issue(ca) for _ in range(10)]
        ids = [c.id for c in certs]
        assert len(set(ids)) == len(ids)

    def test_forced_duplicate_rejected(self):
        """If UUID somehow collides, PreconditionViolation is raised."""
        ca = _fresh_ca()
        cert1 = _issue(ca)

        # Force a duplicate by patching uuid
        with patch("agentsafe.kernel.certificate.uuid.uuid4",
                    return_value=type("MockUUID", (), {"__str__": lambda s: cert1.id})()):
            with pytest.raises(PreconditionViolation) as exc:
                _issue(ca)
            assert "P10" in str(exc.value)
            assert "Duplicate" in str(exc.value)


# =============================================================================
# P11: INVARIANT PRESERVATION
# =============================================================================

class TestP11InvariantPreservation:
    """Valid() holds at every method boundary."""

    def test_constructor_establishes_invariant(self):
        ca = _fresh_ca()
        assert ca._dafny_valid()

    def test_issue_preserves_invariant(self):
        ca = _fresh_ca()
        _issue(ca)
        assert ca._dafny_valid()

    def test_validate_preserves_invariant(self):
        ca = _fresh_ca()
        cert = _issue(ca)
        ca.validate_certificate(cert, "hash-abc")
        assert ca._dafny_valid()

    def test_validate_with_forged_preserves_invariant(self):
        ca = _fresh_ca()
        forged = VerifiedCertificate(theorem="t", plan_hash="h")
        ca.validate_certificate(forged)
        assert ca._dafny_valid()

    def test_revoke_preserves_invariant(self):
        ca = _fresh_ca()
        cert = _issue(ca)
        ca.revoke(cert.id)
        assert ca._dafny_valid()

    def test_sequence_preserves_invariant(self):
        """Issue, validate, revoke, issue - invariant always holds."""
        ca = _fresh_ca()
        c1 = _issue(ca)
        assert ca._dafny_valid()
        ca.validate_certificate(c1)
        assert ca._dafny_valid()
        ca.revoke(c1.id)
        assert ca._dafny_valid()
        c2 = _issue(ca)
        assert ca._dafny_valid()
        ca.validate_certificate(c2)
        assert ca._dafny_valid()

    def test_invariant_conjunct_c2(self):
        """C2: all registry certs have valid signatures."""
        ca = _fresh_ca()
        _issue(ca)
        _issue(ca)
        for cert in ca.registry_snapshot.values():
            assert cert._dafny_signature_valid()

    def test_invariant_conjunct_c3(self):
        """C3: cert.id matches registry key."""
        ca = _fresh_ca()
        _issue(ca)
        _issue(ca)
        for cid, cert in ca.registry_snapshot.items():
            assert cert.id == cid

    def test_invariant_conjunct_c4(self):
        """C4: |issued| ≤ total_issued_count."""
        ca = _fresh_ca()
        for _ in range(5):
            _issue(ca)
        for _ in range(3):
            ids = list(ca.issued_ids)
            if ids:
                ca.revoke(ids[0])
        assert ca.count() <= ca.total_issued_count


# =============================================================================
# P12: REVOCATION ISOLATION
# =============================================================================

class TestP12RevocationIsolation:
    """Revoking cert X does not affect cert Y (X ≠ Y)."""

    def test_revoke_one_doesnt_affect_others(self):
        ca = _fresh_ca()
        c1 = _issue(ca, plan_hash="h1")
        c2 = _issue(ca, plan_hash="h2")
        c3 = _issue(ca, plan_hash="h3")

        ca.revoke(c2.id)

        assert ca.validate_certificate(c1, "h1")
        assert not ca.validate_certificate(c2, "h2")
        assert ca.validate_certificate(c3, "h3")

    def test_revoke_first_preserves_last(self):
        ca = _fresh_ca()
        certs = [_issue(ca, plan_hash=f"h{i}") for i in range(5)]
        ca.revoke(certs[0].id)
        for i in range(1, 5):
            assert ca.validate_certificate(certs[i], f"h{i}")

    def test_revoke_last_preserves_first(self):
        ca = _fresh_ca()
        certs = [_issue(ca, plan_hash=f"h{i}") for i in range(5)]
        ca.revoke(certs[4].id)
        for i in range(4):
            assert ca.validate_certificate(certs[i], f"h{i}")

    def test_issued_set_after_selective_revocation(self):
        ca = _fresh_ca()
        certs = [_issue(ca) for _ in range(5)]
        ca.revoke(certs[1].id)
        ca.revoke(certs[3].id)
        ids = ca.issued_ids
        assert certs[0].id in ids
        assert certs[1].id not in ids
        assert certs[2].id in ids
        assert certs[3].id not in ids
        assert certs[4].id in ids
        assert ca.count() == 3


# =============================================================================
# DAFNY BRIDGE: _dafny_* methods on VerifiedCertificate
# =============================================================================

class TestCertificateDafnyBridge:
    """Low-level tests for the Dafny predicate mirrors."""

    def test_signature_valid_fresh(self):
        cert = VerifiedCertificate(theorem="t", plan_hash="h")
        assert cert._dafny_signature_valid()

    def test_signature_invalid_after_mutation(self):
        cert = VerifiedCertificate(theorem="t", plan_hash="h")
        cert.theorem = "mutated"
        assert not cert._dafny_signature_valid()

    def test_not_expired_no_expiry(self):
        """None expires_at → never expired."""
        cert = VerifiedCertificate(expires_at=None)
        assert cert._dafny_not_expired()

    def test_not_expired_zero_expiry(self):
        """0 expires_at → never expired (Dafny: 0 means no expiry)."""
        cert = VerifiedCertificate(expires_at=0)
        assert cert._dafny_not_expired()

    def test_expired_past_time(self):
        cert = VerifiedCertificate(expires_at=time.time() - 100)
        assert not cert._dafny_not_expired()

    def test_not_expired_future_time(self):
        cert = VerifiedCertificate(expires_at=time.time() + 3600)
        assert cert._dafny_not_expired()

    def test_self_valid_combines_both(self):
        cert = VerifiedCertificate(
            theorem="t", plan_hash="h",
            expires_at=time.time() + 3600,
        )
        assert cert._dafny_self_valid()

    def test_self_valid_fails_on_tamper(self):
        cert = VerifiedCertificate(
            theorem="t", plan_hash="h",
            expires_at=time.time() + 3600,
        )
        cert.theorem = "tampered"
        assert not cert._dafny_self_valid()

    def test_self_valid_fails_on_expiry(self):
        cert = VerifiedCertificate(
            theorem="t", plan_hash="h",
            expires_at=time.time() - 1,
        )
        assert not cert._dafny_self_valid()

    def test_to_dict(self):
        cert = VerifiedCertificate(
            id="id-1", theorem="thm", plan_hash="ph",
            verified_properties=["a"], prover="z3",
            issued_at=1000.0,
        )
        d = cert.to_dict()
        assert d["id"] == "id-1"
        assert d["theorem"] == "thm"
        assert d["plan_hash"] == "ph"
        assert d["verified_properties"] == ["a"]
        assert d["prover"] == "z3"
        assert d["issued_at"] == 1000.0


# =============================================================================
# DAFNY BRIDGE: CertificateAuthority._dafny_valid()
# =============================================================================

class TestCADafnyValid:
    """Tests for the CA class invariant predicate."""

    def test_empty_ca_valid(self):
        ca = _fresh_ca()
        assert ca._dafny_valid()

    def test_after_issues_valid(self):
        ca = _fresh_ca()
        for _ in range(10):
            _issue(ca)
        assert ca._dafny_valid()

    def test_after_revoke_valid(self):
        ca = _fresh_ca()
        certs = [_issue(ca) for _ in range(5)]
        for c in certs[:3]:
            ca.revoke(c.id)
        assert ca._dafny_valid()

    def test_registry_copy_prevents_corruption(self):
        """External mutation of a returned cert doesn't corrupt C2."""
        ca = _fresh_ca()
        cert = _issue(ca)
        # Mutate the returned cert
        cert.theorem = "corrupted"
        # Registry copy should still be valid
        assert ca._dafny_valid()


# =============================================================================
# THREAD SAFETY
# =============================================================================

class TestThreadSafety:
    """Concurrent operations preserve invariants."""

    def test_concurrent_issue(self):
        """100 concurrent issues produce 100 unique certs."""
        ca = _fresh_ca()
        results = []

        def issue_one(i):
            cert = _issue(ca, plan_hash=f"h{i}")
            return cert.id

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(issue_one, i) for i in range(100)]
            for f in as_completed(futures):
                results.append(f.result())

        assert len(set(results)) == 100
        assert ca.count() == 100
        assert ca.total_issued_count == 100
        assert ca._dafny_valid()

    def test_concurrent_issue_and_revoke(self):
        """Interleaved issues and revokes preserve invariant."""
        ca = _fresh_ca()
        # Pre-issue some certs
        pre_certs = [_issue(ca) for _ in range(20)]

        def issue_one(i):
            _issue(ca, plan_hash=f"h{i}")

        def revoke_one(cert):
            ca.revoke(cert.id)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = []
            for i in range(20):
                futures.append(pool.submit(issue_one, i))
            for c in pre_certs[:10]:
                futures.append(pool.submit(revoke_one, c))
            for f in as_completed(futures):
                f.result()

        assert ca._dafny_valid()
        assert ca.total_issued_count == 40  # 20 pre + 20 new
        # count is 20 new + 10 surviving pre = 30
        assert ca.count() == 30

    def test_concurrent_validate(self):
        """Concurrent validations don't interfere."""
        ca = _fresh_ca()
        cert = _issue(ca, plan_hash="h")
        results = []

        def validate_one():
            return ca.validate_certificate(cert, "h")

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(validate_one) for _ in range(100)]
            for f in as_completed(futures):
                results.append(f.result())

        assert all(results)
        assert ca._dafny_valid()


# =============================================================================
# AUDIT TRAIL
# =============================================================================

class TestAuditTrail:
    """InvariantAuditLog records all invariant checks."""

    def test_constructor_logged(self):
        log = InvariantAuditLog.get_instance()
        log.clear()
        ca = _fresh_ca()
        entries = log.entries_for("CertificateAuthority", "__init__")
        assert len(entries) == 1
        assert entries[0].phase == "post"
        assert entries[0].passed is True

    def test_issue_logs_pre_and_post(self):
        log = InvariantAuditLog.get_instance()
        log.clear()
        ca = _fresh_ca()
        log.clear()  # clear constructor log
        _issue(ca)
        entries = log.entries_for("CertificateAuthority", "issue_certificate")
        assert len(entries) == 2
        assert entries[0].phase == "pre"
        assert entries[1].phase == "post"
        assert all(e.passed for e in entries)

    def test_validate_logs_pre_post_and_decision(self):
        log = InvariantAuditLog.get_instance()
        ca = _fresh_ca()
        cert = _issue(ca)
        log.clear()
        ca.validate_certificate(cert, "hash-abc")
        entries = log.entries_for("CertificateAuthority")
        # pre + decision + post
        assert len(entries) == 3
        methods = [e.method for e in entries]
        assert methods.count("validate_certificate") == 3

    def test_validation_rejection_logged(self):
        log = InvariantAuditLog.get_instance()
        ca = _fresh_ca()
        forged = VerifiedCertificate(theorem="t")
        log.clear()
        ca.validate_certificate(forged)
        decisions = [
            e for e in log.entries_for("CertificateAuthority", "validate_certificate")
            if e.phase == "decision"
        ]
        assert len(decisions) == 1
        assert decisions[0].passed is False
        assert "rejected:provenance" in decisions[0].details

    def test_revoke_logs_pre_and_post(self):
        log = InvariantAuditLog.get_instance()
        ca = _fresh_ca()
        cert = _issue(ca)
        log.clear()
        ca.revoke(cert.id)
        entries = log.entries_for("CertificateAuthority", "revoke")
        assert len(entries) == 2
        assert entries[0].phase == "pre"
        assert entries[1].phase == "post"
        assert all(e.passed for e in entries)

    def test_all_audit_entries_have_timestamps(self):
        log = InvariantAuditLog.get_instance()
        log.clear()
        ca = _fresh_ca()
        _issue(ca)
        for entry in log.entries:
            assert entry.timestamp > 0


# =============================================================================
# TRUSTED KERNEL
# =============================================================================

class TestTrustedKernel:
    """TrustedKernel delegates to CA correctly."""

    def test_kernel_validates_issued_cert(self):
        ca = _fresh_ca()
        kernel = TrustedKernel(ca)
        cert = _issue(ca, plan_hash="h")
        assert kernel.validate_certificate(cert, "h")

    def test_kernel_rejects_forged_cert(self):
        ca = _fresh_ca()
        kernel = TrustedKernel(ca)
        forged = VerifiedCertificate(theorem="t", plan_hash="h")
        assert not kernel.validate_certificate(forged, "h")

    def test_kernel_rejects_after_revoke(self):
        ca = _fresh_ca()
        kernel = TrustedKernel(ca)
        cert = _issue(ca)
        ca.revoke(cert.id)
        assert not kernel.validate_certificate(cert)

    def test_kernel_uses_default_ca_singleton(self):
        ca = CertificateAuthority.get_instance()
        kernel = TrustedKernel()
        cert = ca.issue_certificate(
            theorem="t", plan_hash="h", verified_properties=["p"],
        )
        assert kernel.validate_certificate(cert, "h")


# =============================================================================
# GHOST STATE
# =============================================================================

class TestGhostState:
    """Ghost state tracking (total_issued_count, _total_revoked_count)."""

    def test_initial_ghost_state(self):
        ca = _fresh_ca()
        assert ca.total_issued_count == 0
        assert ca._total_revoked_count == 0

    def test_issue_increments_count(self):
        ca = _fresh_ca()
        _issue(ca)
        _issue(ca)
        _issue(ca)
        assert ca.total_issued_count == 3
        assert ca._total_revoked_count == 0

    def test_revoke_increments_revoked_count(self):
        ca = _fresh_ca()
        c1 = _issue(ca)
        c2 = _issue(ca)
        ca.revoke(c1.id)
        assert ca.total_issued_count == 2
        assert ca._total_revoked_count == 1
        ca.revoke(c2.id)
        assert ca._total_revoked_count == 2

    def test_revoke_nonexistent_doesnt_increment(self):
        ca = _fresh_ca()
        ca.revoke("nonexistent")
        assert ca._total_revoked_count == 0

    def test_conservation_law(self):
        """count + revoked ≤ total_issued (not exact because
        double-revoke is no-op but revoked increments)."""
        ca = _fresh_ca()
        for _ in range(10):
            _issue(ca)
        certs = list(ca.issued_ids)
        for cid in certs[:4]:
            ca.revoke(cid)
        assert ca.count() + ca._total_revoked_count == ca.total_issued_count


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Boundary conditions and unusual usage patterns."""

    def test_empty_properties(self):
        ca = _fresh_ca()
        cert = ca.issue_certificate(
            theorem="t", plan_hash="h", verified_properties=[],
        )
        assert ca.validate_certificate(cert, "h")
        assert cert._dafny_signature_valid()

    def test_empty_theorem_and_hash(self):
        ca = _fresh_ca()
        cert = ca.issue_certificate(
            theorem="", plan_hash="", verified_properties=[],
        )
        assert ca.validate_certificate(cert)
        assert cert._dafny_signature_valid()

    def test_very_long_properties_list(self):
        ca = _fresh_ca()
        props = [f"property_{i}" for i in range(100)]
        cert = ca.issue_certificate(
            theorem="t", plan_hash="h", verified_properties=props,
        )
        assert cert._dafny_signature_valid()
        assert ca.validate_certificate(cert, "h")

    def test_singleton_reset_creates_fresh_ca(self):
        ca1 = CertificateAuthority.get_instance()
        cert = _issue(ca1)
        CertificateAuthority.reset()
        ca2 = CertificateAuthority.get_instance()
        assert ca1 is not ca2
        assert not ca2.validate_certificate(cert)

    def test_cert_with_proof_trace(self):
        """proof_trace is stored but doesn't affect signature."""
        ca = _fresh_ca()
        cert = ca.issue_certificate(
            theorem="t", plan_hash="h", verified_properties=["p"],
            proof_trace="long proof trace data...",
        )
        assert cert.proof_trace == "long proof trace data..."
        assert cert._dafny_signature_valid()

    def test_large_scale_issue_revoke_cycle(self):
        """Stress test: 200 issues, revoke first 100, verify remaining."""
        ca = _fresh_ca()
        certs = [_issue(ca, plan_hash=f"h{i}") for i in range(200)]
        for c in certs[:100]:
            ca.revoke(c.id)

        assert ca.count() == 100
        assert ca.total_issued_count == 200
        assert ca._total_revoked_count == 100
        assert ca._dafny_valid()

        for c in certs[:100]:
            assert not ca.validate_certificate(c)
        for i, c in enumerate(certs[100:], start=100):
            assert ca.validate_certificate(c, f"h{i}")

    def test_registry_snapshot_is_copy(self):
        """Modifying the snapshot doesn't affect the CA."""
        ca = _fresh_ca()
        _issue(ca)
        snap = ca.registry_snapshot
        snap.clear()
        assert ca.count() == 1

    def test_issued_ids_is_frozen(self):
        """issued_ids returns frozenset (immutable)."""
        ca = _fresh_ca()
        _issue(ca)
        ids = ca.issued_ids
        assert isinstance(ids, frozenset)


# =============================================================================
# DAFNY INTEGRATION TEST: Full lifecycle
# =============================================================================

class TestDafnyIntegrationFullLifecycle:
    """Mirrors TestFullLifecycle() from certificate.dfy."""

    def test_full_lifecycle(self):
        ca = _fresh_ca()
        assert ca._dafny_valid() and ca.count() == 0

        # Issue first certificate
        c1 = _issue(ca, plan_hash="hash-abc")
        assert ca.is_issued(c1.id)
        assert c1._dafny_signature_valid()
        assert ca.total_issued_count == 1

        # Validate - all checks pass
        assert ca.validate_certificate(c1, "hash-abc")

        # Wrong hash - binding fails
        assert not ca.validate_certificate(c1, "wrong")

        # Expired - freshness fails
        c_exp = ca.issue_certificate(
            theorem="t", plan_hash="h", verified_properties=[],
            ttl_seconds=0,
        )
        time.sleep(0.02)
        assert not ca.validate_certificate(c_exp, "h")

        # Tampered - signature fails
        c_tamper = copy.copy(c1)
        c_tamper.theorem = "tampered"
        assert not c_tamper._dafny_signature_valid()
        assert not ca.validate_certificate(c_tamper, "hash-abc")

        # Forged - provenance fails
        forged = VerifiedCertificate(
            theorem="action_safe", plan_hash="hash-abc",
            verified_properties=["cap_coverage"],
        )
        assert not ca.validate_certificate(forged, "hash-abc")

        # Revoke - P5
        ca.revoke(c1.id)
        assert not ca.is_issued(c1.id)
        assert ca.total_issued_count == 2  # unchanged by revoke
        assert not ca.validate_certificate(c1, "hash-abc")

        # Issue after revoke - no interference (P12)
        c2 = _issue(ca, plan_hash="hash-xyz")
        assert ca.is_issued(c2.id)
        assert not ca.is_issued(c1.id)
        assert ca.validate_certificate(c2, "hash-xyz")

        # Final invariant
        assert ca._dafny_valid()

    def test_monotonicity_sequence(self):
        """Mirrors TestMonotonicitySequence from certificate.dfy."""
        ca = _fresh_ca()

        _issue(ca)
        assert ca.total_issued_count == 1
        assert ca.count() == 1

        c2 = _issue(ca)
        assert ca.total_issued_count == 2
        assert ca.count() == 2

        ca.revoke(list(ca.issued_ids)[0])
        assert ca.total_issued_count == 2  # unchanged
        assert ca.count() == 1
        assert ca.total_issued_count >= ca.count()

        _issue(ca)
        assert ca.total_issued_count == 3
        assert ca.count() == 2

    def test_validation_exhaustive_failure(self):
        """Mirrors TestValidationExhaustiveFailure from certificate.dfy.
        Each of the 4 checks independently causes rejection."""
        ca = _fresh_ca()
        cert = ca.issue_certificate(
            theorem="thm", plan_hash="hash",
            verified_properties=["p"], ttl_seconds=500,
        )

        # (a) Revoke → provenance fails
        ca.revoke(cert.id)
        assert not ca.validate_certificate(cert, "hash")

        # Re-issue for remaining tests
        cert2 = ca.issue_certificate(
            theorem="thm", plan_hash="hash",
            verified_properties=["p"], ttl_seconds=500,
        )

        # (b) Tamper → signature fails
        bad_copy = copy.copy(cert2)
        bad_copy.theorem = "hacked"
        assert not ca.validate_certificate(bad_copy, "hash")

        # (c) Expired → freshness fails
        cert_exp = ca.issue_certificate(
            theorem="thm2", plan_hash="hash2",
            verified_properties=["p"], ttl_seconds=0,
        )
        time.sleep(0.02)
        assert not ca.validate_certificate(cert_exp, "hash2")

        # (d) Wrong hash → binding fails
        assert not ca.validate_certificate(cert2, "wrong_hash")

        # All pass
        assert ca.validate_certificate(cert2, "hash")

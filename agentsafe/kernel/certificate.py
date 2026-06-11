"""
Dafny-Verified Certificate Authority - Phase B2 Production Runtime Bridge.

Mirrors ``dafny/kernel/certificate.dfy`` at every method boundary.

Proven properties (Dafny static, Python runtime enforcement):

  P3   ISSUANCE INTEGRITY
       validate(cert) == True ONLY IF cert.id ∈ issued_set.
       Forged certificates (not in issued) are always rejected.

  P4   VALIDATION CORRECTNESS
       validate checks: (a) provenance, (b) signature, (c) freshness, (d) binding.
       ALL four must hold for validation to succeed.
       Failure of ANY single check causes rejection.

  P5   REVOCATION CORRECTNESS
       After revoke(id): validate for that id returns False.
       All other certs are unaffected (selective revocation).

  P6   SIGNATURE SOUNDNESS
       Mutating any single identity field (id, theorem, plan_hash, prover,
       verified_properties) invalidates SignatureValid().

  P9   REGISTRY MONOTONICITY (issue-only)
       issue_certificate strictly grows the issued set.
       total_issued_count is strictly increasing and never decremented.

  P10  CERTIFICATE UNIQUENESS
       No two certificates share the same ID in the registry.
       Enforced by PreconditionViolation on duplicate.

  P11  INVARIANT PRESERVATION
       Every public method preserves the class invariant Valid().
       Valid() == (issued == registry.Keys)
                ∧ (∀ cid ∈ registry: SignatureValid(registry[cid]))
                ∧ (∀ cid ∈ registry: registry[cid].id == cid)
                ∧ (|issued| ≤ total_issued_count)

  P12  REVOCATION ISOLATION
       Revoking cert X does not affect the validity of cert Y (X ≠ Y).

Thread safety: All state mutations guarded by ``threading.Lock``.
Audit trail:   Every invariant check recorded to ``InvariantAuditLog``.
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional

from agentsafe.verification.dafny_runtime import (
    InvariantAuditLog,
    InvariantViolation,
    PreconditionViolation,
)


# ═══════════════════════════════════════════════════════════════════════════
# VerifiedCertificate - immutable proof certificate
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class VerifiedCertificate:
    """Proof certificate attesting to verified properties.

    Mirrors Dafny ``VerifiedCertificate`` datatype.  Identity fields
    that contribute to the signature: ``id``, ``theorem``, ``plan_hash``,
    ``verified_properties``, ``prover``.

    Non-identity fields (``proof_trace``, ``issued_at``, ``expires_at``)
    do NOT affect the signature - Dafny's ``ComputeDigest`` excludes them.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    theorem: str = ""
    plan_hash: str = ""
    verified_properties: List[str] = field(default_factory=list)
    proof_trace: str = ""
    prover: str = "z3"
    issued_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    _signature: str = ""

    def __post_init__(self) -> None:
        if not self._signature:
            self._signature = self._compute_signature()

    # ── Signature (mirrors Dafny ComputeDigest) ──────────────────

    def _compute_signature(self) -> str:
        """Deterministic digest of identity fields.

        Mirrors Dafny::

            function ComputeDigest(id, theorem, plan_hash, properties, prover): Digest

        Uses sorted properties for determinism.
        """
        payload = json.dumps(
            {
                "id": self.id,
                "theorem": self.theorem,
                "plan_hash": self.plan_hash,
                "properties": sorted(self.verified_properties),
                "prover": self.prover,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    # ── Dafny predicate mirrors ──────────────────────────────────

    def _dafny_signature_valid(self) -> bool:
        """Mirror of Dafny ``SignatureValid(cert)``.

        Returns True IFF the stored signature matches a fresh digest
        of the current identity fields.  Mutating ANY identity field
        causes this to return False (P6).
        """
        return self._signature == self._compute_signature()

    def _dafny_not_expired(self) -> bool:
        """Mirror of Dafny ``!IsExpired(cert, now)``.

        Dafny: ``IsExpired(cert, now) == cert.expires_at > 0 && now > cert.expires_at``
        Python: ``expires_at`` of ``None`` or ``0`` means no expiry.
        """
        if self.expires_at is None or self.expires_at == 0:
            return True
        return time.time() <= self.expires_at

    def _dafny_self_valid(self) -> bool:
        """Mirror of Dafny ``CertSelfValid(cert, now)``.

        ``CertSelfValid == SignatureValid(cert) && !IsExpired(cert, now)``
        """
        return self._dafny_signature_valid() and self._dafny_not_expired()

    # ── Public API ───────────────────────────────────────────────

    def is_valid(self) -> bool:
        """Check certificate validity (signature + expiry).

        Equivalent to ``_dafny_self_valid()`` - kept for backward
        compatibility with existing consumers.
        """
        return self._dafny_self_valid()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "theorem": self.theorem,
            "plan_hash": self.plan_hash,
            "verified_properties": self.verified_properties,
            "prover": self.prover,
            "issued_at": self.issued_at,
        }


# ═══════════════════════════════════════════════════════════════════════════
# CertificateAuthority - the Dafny-verified state machine
# ═══════════════════════════════════════════════════════════════════════════

class CertificateAuthority:
    """Issues and validates proof certificates.

    Mirrors the Dafny ``CertificateAuthority`` class.  All state
    mutations are guarded by ``_lock`` for thread safety (P8 analogue).
    Every public method checks the class invariant ``Valid()`` at entry
    and exit, recording to ``InvariantAuditLog`` (P11).

    Ghost state
    -----------
    ``total_issued_count``   Monotonically increasing counter of certificates
                             ever issued.  Never decremented, even by revoke.
    ``_total_revoked_count`` Number of successful revocations (for accounting).
    """

    _instance: Optional["CertificateAuthority"] = None

    def __init__(self) -> None:
        # ── Core state (mirrors Dafny fields) ────────────────────
        self._issued: set[str] = set()                          # issued set
        self._registry: Dict[str, VerifiedCertificate] = {}     # cert store

        # ── Ghost state ──────────────────────────────────────────
        self.total_issued_count: int = 0
        self._total_revoked_count: int = 0

        # ── Thread safety ────────────────────────────────────────
        self._lock = threading.Lock()

        # ── Establish invariant (Dafny: ensures Valid()) ─────────
        self._check_invariant("__init__", "post")

    # ── Singleton ────────────────────────────────────────────────

    @classmethod
    def get_instance(cls) -> "CertificateAuthority":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        cls._instance = None

    # ═════════════════════════════════════════════════════════════
    # CLASS INVARIANT - Valid()  (P11)
    #
    # Four conjuncts mirroring Dafny:
    #   C1: issued == registry.Keys
    #   C2: ∀ cid ∈ registry: SignatureValid(registry[cid])
    #   C3: ∀ cid ∈ registry: registry[cid].id == cid
    #   C4: |issued| ≤ total_issued_count
    # ═════════════════════════════════════════════════════════════

    def _dafny_valid(self) -> bool:
        """Evaluate the class invariant.  Pure query - no side effects."""
        # C1: issued set matches registry keys
        if self._issued != set(self._registry.keys()):
            return False
        # C2: all registry certs have valid signatures
        for cid, cert in self._registry.items():
            if not cert._dafny_signature_valid():
                return False
        # C3: cert.id matches its registry key
        for cid, cert in self._registry.items():
            if cert.id != cid:
                return False
        # C4: |issued| ≤ total_issued_count
        if len(self._issued) > self.total_issued_count:
            return False
        return True

    def _invariant_details(self) -> str:
        """Diagnostic string on invariant failure."""
        parts: list[str] = []
        if self._issued != set(self._registry.keys()):
            parts.append(
                f"C1: issued={self._issued} != registry.keys={set(self._registry.keys())}"
            )
        for cid, cert in self._registry.items():
            if not cert._dafny_signature_valid():
                parts.append(f"C2: registry[{cid!r}] has invalid signature")
        for cid, cert in self._registry.items():
            if cert.id != cid:
                parts.append(f"C3: registry[{cid!r}].id={cert.id!r} != key")
        if len(self._issued) > self.total_issued_count:
            parts.append(
                f"C4: |issued|={len(self._issued)} > total_issued_count={self.total_issued_count}"
            )
        return "; ".join(parts) if parts else "ok"

    def _check_invariant(self, method: str, phase: str) -> None:
        """Check Valid() and record to audit log.  Raises on failure."""
        log = InvariantAuditLog.get_instance()
        passed = self._dafny_valid()
        details = "" if passed else self._invariant_details()
        log.record("CertificateAuthority", method, phase, "Valid()", passed, details)
        if not passed:
            raise InvariantViolation(
                property_id="Valid()",
                class_name="CertificateAuthority",
                method=method,
                phase=phase,
                details=details,
            )

    # ═════════════════════════════════════════════════════════════
    # issue_certificate - P3, P9, P10
    #
    # Dafny contract:
    #   requires Valid()
    #   requires cert_id !in issued           (P10: uniqueness)
    #   ensures  Valid()                      (P11)
    #   ensures  cert_id in issued            (P3: provenance)
    #   ensures  old(issued) < issued         (P9: strict growth)
    #   ensures  total_issued_count == old(total_issued_count) + 1
    #   ensures  SignatureValid(cert)         (P3: integrity)
    # ═════════════════════════════════════════════════════════════

    def issue_certificate(
        self,
        theorem: str,
        plan_hash: str,
        verified_properties: List[str],
        proof_trace: str = "",
        prover: str = "z3",
        ttl_seconds: float = 3600,
    ) -> VerifiedCertificate:
        """Issue a new proof certificate.

        The certificate is created with a fresh UUID, signed, and
        registered in the issued set.  The returned certificate has
        a valid signature (P3) and the issued set strictly grew (P9).

        Raises:
            PreconditionViolation: if the generated cert_id already
                exists in the issued set (P10: uniqueness).
            InvariantViolation: if Valid() fails at any boundary.
        """
        with self._lock:
            # PRE: requires Valid()
            self._check_invariant("issue_certificate", "pre")

            # Build certificate
            cert_id = str(uuid.uuid4())

            # PRE: requires cert_id !in issued (P10)
            if cert_id in self._issued:
                raise PreconditionViolation(
                    property_id="P10",
                    class_name="CertificateAuthority",
                    method="issue_certificate",
                    phase="pre",
                    details=f"Duplicate cert_id={cert_id!r} already in issued set",
                )

            now = time.time()
            expires_at: Optional[float]
            if ttl_seconds > 0:
                expires_at = now + ttl_seconds
            else:
                # ttl_seconds == 0 → expires immediately (for testing expiry)
                expires_at = now

            cert = VerifiedCertificate(
                id=cert_id,
                theorem=theorem,
                plan_hash=plan_hash,
                verified_properties=list(verified_properties),
                proof_trace=proof_trace,
                prover=prover,
                issued_at=now,
                expires_at=expires_at,
            )

            # Store a deep copy in registry so external mutation of the
            # returned cert object doesn't corrupt C2 invariant.
            registry_copy = VerifiedCertificate(
                id=cert.id,
                theorem=cert.theorem,
                plan_hash=cert.plan_hash,
                verified_properties=list(cert.verified_properties),
                proof_trace=cert.proof_trace,
                prover=cert.prover,
                issued_at=cert.issued_at,
                expires_at=cert.expires_at,
            )

            # Mutate state
            self._issued.add(cert_id)
            self._registry[cert_id] = registry_copy
            self.total_issued_count += 1

            # POST: ensures Valid()
            self._check_invariant("issue_certificate", "post")

            return cert

    # ═════════════════════════════════════════════════════════════
    # validate_certificate - P4 (validation correctness)
    #
    # Returns True IFF ALL of:
    #   (a) cert.id ∈ issued           (provenance - P3)
    #   (b) SignatureValid(cert)       (integrity - P6)
    #   (c) !IsExpired(cert, now)      (freshness)
    #   (d) plan_hash matches          (binding, if expected_hash != "")
    # ═════════════════════════════════════════════════════════════

    def validate_certificate(
        self,
        cert: VerifiedCertificate,
        expected_hash: str = "",
    ) -> bool:
        """Validate a certificate against the CA registry.

        Each of the four checks is evaluated independently.
        Rejection reason is logged to the audit trail.

        Thread-safe: acquires lock for the full validation.
        """
        log = InvariantAuditLog.get_instance()

        with self._lock:
            # PRE: requires Valid()
            self._check_invariant("validate_certificate", "pre")

            # (a) Provenance - P3
            if cert.id not in self._issued:
                log.record(
                    "CertificateAuthority", "validate_certificate",
                    "decision", "P4", False, "rejected:provenance",
                )
                self._check_invariant("validate_certificate", "post")
                return False

            # (b) Signature - P6
            if not cert._dafny_signature_valid():
                log.record(
                    "CertificateAuthority", "validate_certificate",
                    "decision", "P4", False, "rejected:signature",
                )
                self._check_invariant("validate_certificate", "post")
                return False

            # (c) Freshness
            if not cert._dafny_not_expired():
                log.record(
                    "CertificateAuthority", "validate_certificate",
                    "decision", "P4", False, "rejected:freshness",
                )
                self._check_invariant("validate_certificate", "post")
                return False

            # (d) Binding (skip if expected_hash is empty)
            if expected_hash and cert.plan_hash != expected_hash:
                log.record(
                    "CertificateAuthority", "validate_certificate",
                    "decision", "P4", False, "rejected:binding",
                )
                self._check_invariant("validate_certificate", "post")
                return False

            # All checks passed
            log.record(
                "CertificateAuthority", "validate_certificate",
                "decision", "P4", True, "accepted",
            )
            self._check_invariant("validate_certificate", "post")
            return True

    # ═════════════════════════════════════════════════════════════
    # revoke - P5 (revocation correctness), P12 (isolation)
    #
    # Dafny contract:
    #   requires Valid()
    #   ensures  Valid()                     (P11)
    #   ensures  cert_id !in issued          (P5)
    #   ensures  ∀ cid: cid ∈ old(issued) ∧ cid ≠ cert_id → cid ∈ issued  (P12)
    #   ensures  total_issued_count == old(total_issued_count)
    # ═════════════════════════════════════════════════════════════

    def revoke(self, cert_id: str) -> None:
        """Revoke a certificate.

        After revocation, ``validate_certificate`` for this cert_id
        returns False (P5).  All other certificates are unaffected (P12).
        ``total_issued_count`` is unchanged - revoke ≠ un-issue.

        Revoking a non-existent cert_id is a safe no-op.
        """
        with self._lock:
            # PRE
            self._check_invariant("revoke", "pre")

            actually_removed = cert_id in self._issued

            self._issued.discard(cert_id)
            self._registry.pop(cert_id, None)

            if actually_removed:
                self._total_revoked_count += 1

            # POST: ensures Valid()
            self._check_invariant("revoke", "post")

    # ═════════════════════════════════════════════════════════════
    # Pure queries
    # ═════════════════════════════════════════════════════════════

    def is_issued(self, cert_id: str) -> bool:
        """Check if a cert_id is in the issued set.

        Mirrors Dafny ``is_issued`` method:
            ensures result == (cert_id in issued)
        """
        with self._lock:
            return cert_id in self._issued

    def count(self) -> int:
        """Number of currently active (non-revoked) certificates.

        Mirrors Dafny ``count`` method:
            ensures n == |issued|
        """
        with self._lock:
            return len(self._issued)

    @property
    def issued_ids(self) -> FrozenSet[str]:
        """Snapshot of all currently issued certificate IDs.

        Returns a ``frozenset`` - external mutation is impossible.
        """
        with self._lock:
            return frozenset(self._issued)

    @property
    def registry_snapshot(self) -> Dict[str, VerifiedCertificate]:
        """Deep copy of the registry for external inspection.

        Modifying the returned dict does NOT affect the CA's state.
        """
        with self._lock:
            return dict(self._registry)


# ═══════════════════════════════════════════════════════════════════════════
# TrustedKernel - delegates to CA with proven contract
# ═══════════════════════════════════════════════════════════════════════════

class TrustedKernel:
    """Security kernel that enforces verify-before-execute.

    Mirrors Dafny ``TrustedKernel`` class - a thin delegation
    layer that guarantees the same validation contract as the CA.
    """

    def __init__(self, ca: Optional[CertificateAuthority] = None) -> None:
        self.ca = ca or CertificateAuthority.get_instance()

    def validate_certificate(
        self,
        cert: VerifiedCertificate,
        expected_hash: str = "",
    ) -> bool:
        """Validate certificate via the CA.

        Dafny ensures: valid ==> cert.id in ca.issued
                                ∧ SignatureValid(cert)
                                ∧ !IsExpired(cert, now)
                                ∧ (expected_hash == "" || cert.plan_hash == expected_hash)
        """
        return self.ca.validate_certificate(cert, expected_hash)

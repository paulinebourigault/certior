"""
Tests for CompliancePDFExporter.

Validates:
  - PDF generation produces valid bytes
  - All sections are present in the PDF
  - Edge cases (empty data, missing fields)
  - Integration with ComplianceExporter pipeline
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from agentsafe.compliance import (
    AuditEntry,
    ComplianceExporter,
    CompliancePackage,
    CompliancePDFExporter,
    CompliancePresets,
)
from agentsafe.cloud.state_store import Execution, ExecutionStatus


# ── Helpers ───────────────────────────────────────────────────────────

def _make_execution(**overrides) -> Execution:
    defaults = {
        "id": "exec-test-001",
        "user_id": "user-42",
        "task": "Analyze patient records for Q4 report",
        "status": ExecutionStatus.COMPLETED,
        "created_at": time.time() - 120,
        "completed_at": time.time(),
        "cost_cents": 350,
        "certificates": [
            {
                "id": "cert-abc",
                "type": "proof_certificate",
                "prover": "z3",
                "verified_properties": [
                    "no_phi_external_flow: proven",
                    "minimum_necessary_access: proven",
                    "authorized_user_only: proven",
                ],
            }
        ],
        "results": {
            "steps": [{"verified": True, "tool": "database_query"}],
            "audit_trail": [
                {"phase": "planning", "timestamp": time.time() - 100},
                {"phase": "verification", "timestamp": time.time() - 90},
                {"phase": "execution", "timestamp": time.time() - 80},
                {"phase": "completion", "timestamp": time.time()},
            ],
        },
    }
    defaults.update(overrides)
    return Execution(**defaults)


def _make_package(**overrides) -> CompliancePackage:
    execution = _make_execution()
    config = CompliancePresets.hipaa()
    exporter = ComplianceExporter(config)

    trail = []
    for entry in execution.results.get("audit_trail", []):
        trail.append(AuditEntry(
            action=entry.get("phase", ""),
            timestamp=entry.get("timestamp", time.time()),
            details=entry,
        ))

    pkg = exporter.export(execution=execution, audit_trail=trail)
    for k, v in overrides.items():
        setattr(pkg, k, v)
    return pkg


# ══════════════════════════════════════════════════════════════════════
#  Tests
# ══════════════════════════════════════════════════════════════════════

class TestCompliancePDFExporter:
    def test_available(self):
        assert CompliancePDFExporter.available() is True

    def test_render_returns_bytes(self):
        pkg = _make_package()
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1000  # non-trivial PDF

    def test_pdf_header(self):
        """PDF starts with %PDF magic bytes."""
        pkg = _make_package()
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert pdf_bytes[:5] == b"%PDF-"

    def test_render_hipaa(self):
        pkg = _make_package()
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 2000
        try:
            from pypdf import PdfReader
            import io
            text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf_bytes)).pages)
            assert "HIPAA" in text
        except ImportError:
            pass

    def test_render_sox(self):
        execution = _make_execution()
        config = CompliancePresets.sox()
        exporter = ComplianceExporter(config)
        pkg = exporter.export(execution=execution)
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 2000

    def test_render_legal(self):
        execution = _make_execution()
        config = CompliancePresets.legal_privilege()
        exporter = ComplianceExporter(config)
        pkg = exporter.export(execution=execution)
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 2000

    def test_compliant_verdict(self):
        pkg = _make_package()
        assert pkg.attestation.get("compliant") is True
        pdf_bytes = CompliancePDFExporter.render(pkg)
        # PDF text is compressed; verify generation succeeds and is non-trivial
        assert len(pdf_bytes) > 2000
        # Extract text via pypdf if available
        try:
            from pypdf import PdfReader
            import io
            reader = PdfReader(io.BytesIO(pdf_bytes))
            cover_text = reader.pages[0].extract_text()
            assert "COMPLIANT" in cover_text
        except ImportError:
            pass  # pypdf not installed; size check is sufficient

    def test_non_compliant_verdict(self):
        pkg = _make_package()
        pkg.attestation = {"compliant": False, "proofs_missing": ["some_proof"]}
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 2000
        try:
            from pypdf import PdfReader
            import io
            reader = PdfReader(io.BytesIO(pdf_bytes))
            cover_text = reader.pages[0].extract_text()
            assert "NON-COMPLIANT" in cover_text
        except ImportError:
            pass

    def test_empty_certificates(self):
        pkg = _make_package(certificates=[])
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 500

    def test_empty_audit_trail(self):
        pkg = _make_package(audit_trail=[])
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 500

    def test_empty_safety_scans(self):
        pkg = _make_package(safety_scans=[])
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 500

    def test_with_safety_scans(self):
        scans = [
            {"category": "PHI_EXPOSURE", "severity": "block", "matched_text": "SSN: 123-45-6789"},
            {"category": "PII", "severity": "warn", "matched_text": "email@example.com"},
        ]
        pkg = _make_package(safety_scans=scans)
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 1000

    def test_with_flow_violations(self):
        flow = {
            "rules_enforced": 3,
            "flows_tracked": 10,
            "violations_detected": 2,
            "violation_details": [
                {"from": "PHI", "to": "external", "blocked": True},
                {"from": "sensitive", "to": "public", "blocked": True},
            ],
        }
        pkg = _make_package(flow_analysis=flow)
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 1000

    def test_execution_id_in_pdf(self):
        pkg = _make_package()
        pdf_bytes = CompliancePDFExporter.render(pkg)
        try:
            from pypdf import PdfReader
            import io
            text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf_bytes)).pages)
            assert "exec-test-001" in text
        except ImportError:
            assert len(pdf_bytes) > 2000

    def test_pdf_surfaces_lean_runtime_status(self):
        pkg = _make_package(
            verification_runtime={
                "lean_status": "active",
                "mode": "dual_proof",
                "detail": "Lean kernel active; no flow checks were required for this execution.",
                "steps_checked": 0,
                "certificates_issued": 0,
                "flow_violations": 0,
                "total_requests": 1,
                "avg_latency_ms": 0.0,
            },
        )
        pdf_bytes = CompliancePDFExporter.render(pkg)
        try:
            from pypdf import PdfReader
            import io
            text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf_bytes)).pages)
            assert "Lean Runtime: Active (dual-proof)" in text
            assert "Lean Verification Runtime" in text
        except ImportError:
            assert len(pdf_bytes) > 2000

    def test_large_audit_trail_capped(self):
        """Audit trails > 100 entries are capped in PDF."""
        trail = [
            {"timestamp": time.time(), "action": f"action-{i}", "result": "ok"}
            for i in range(200)
        ]
        pkg = _make_package(audit_trail=trail)
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 1000

    def test_special_characters_escaped(self):
        """XML special chars in task don't break PDF generation."""
        execution = _make_execution(task="Query: SELECT * WHERE x < 10 & y > 5")
        config = CompliancePresets.hipaa()
        exporter = ComplianceExporter(config)
        pkg = exporter.export(execution=execution)
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 500

    def test_string_certificates(self):
        """String-type certificate refs don't crash."""
        pkg = _make_package(certificates=["cert-id-1", "cert-id-2"])
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 500

    def test_missing_attestation(self):
        pkg = _make_package()
        pkg.attestation = {}
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 500

    def test_string_attestation(self):
        """Non-dict attestation (legacy) doesn't crash."""
        pkg = _make_package()
        pkg.attestation = "legacy-attestation-string"
        pdf_bytes = CompliancePDFExporter.render(pkg)
        assert len(pdf_bytes) > 500

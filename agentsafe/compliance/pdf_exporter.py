from __future__ import annotations

"""
PDF compliance audit package generator.

Produces professional-grade PDF audit packages for regulators containing:
  - Cover page with compliance regime and attestation summary
  - Execution summary (task, timestamps, status, cost)
  - Proof certificates with verified properties
  - Content safety scan results
  - Information flow analysis
  - Policy configuration applied
  - Full audit trail with timestamps
  - Digital attestation statement

Usage::

    from agentsafe.compliance.pdf_exporter import CompliancePDFExporter
    from agentsafe.compliance import ComplianceExporter, CompliancePresets

    # Build compliance package (JSON)
    exporter = ComplianceExporter(CompliancePresets.hipaa())
    package = exporter.export(execution, audit_trail=trail)

    # Render to PDF
    pdf_bytes = CompliancePDFExporter.render(package)
    with open("audit-package.pdf", "wb") as f:
        f.write(pdf_bytes)
"""

import io
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch, mm
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        HRFlowable,
        NextPageTemplate,
        PageBreak,
        PageTemplate,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False

from .exporter import CompliancePackage


# ── Color palette ─────────────────────────────────────────────────────

if _REPORTLAB_AVAILABLE:
    class _Colors:
        """Certior brand-aligned color palette for PDF reports."""
        PRIMARY = colors.HexColor("#1a1a2e")
        ACCENT = colors.HexColor("#6366f1")
        VERIFIED = colors.HexColor("#22c55e")
        BLOCKED = colors.HexColor("#ef4444")
        WARN = colors.HexColor("#f59e0b")
        MUTED = colors.HexColor("#6b7280")
        LIGHT_BG = colors.HexColor("#f8fafc")
        TABLE_HEADER = colors.HexColor("#334155")
        TABLE_ALT = colors.HexColor("#f1f5f9")
        WHITE = colors.white
        BLACK = colors.black
else:
    _Colors = None  # type: ignore[assignment,misc]


# ── Styles ────────────────────────────────────────────────────────────

def _build_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "CoverTitle", parent=base["Title"],
            fontSize=28, leading=34, textColor=_Colors.PRIMARY,
            alignment=TA_CENTER, spaceAfter=8,
        ),
        "cover_subtitle": ParagraphStyle(
            "CoverSubtitle", parent=base["Normal"],
            fontSize=14, leading=18, textColor=_Colors.MUTED,
            alignment=TA_CENTER, spaceAfter=24,
        ),
        "cover_regime": ParagraphStyle(
            "CoverRegime", parent=base["Normal"],
            fontSize=18, leading=22, textColor=_Colors.ACCENT,
            alignment=TA_CENTER, spaceBefore=12, spaceAfter=4,
        ),
        "section_heading": ParagraphStyle(
            "SectionHeading", parent=base["Heading1"],
            fontSize=16, leading=20, textColor=_Colors.PRIMARY,
            spaceBefore=18, spaceAfter=8,
            borderWidth=0, borderPadding=0,
        ),
        "subsection": ParagraphStyle(
            "Subsection", parent=base["Heading2"],
            fontSize=12, leading=15, textColor=_Colors.TABLE_HEADER,
            spaceBefore=10, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["Normal"],
            fontSize=10, leading=13, textColor=_Colors.BLACK,
            spaceAfter=4,
        ),
        "body_small": ParagraphStyle(
            "BodySmall", parent=base["Normal"],
            fontSize=8, leading=10, textColor=_Colors.MUTED,
            spaceAfter=2,
        ),
        "mono": ParagraphStyle(
            "Mono", parent=base["Code"],
            fontSize=8, leading=10, fontName="Courier",
            textColor=_Colors.PRIMARY, spaceAfter=2,
        ),
        "verdict_pass": ParagraphStyle(
            "VerdictPass", parent=base["Normal"],
            fontSize=14, leading=18, textColor=_Colors.VERIFIED,
            alignment=TA_CENTER, spaceBefore=8,
        ),
        "verdict_fail": ParagraphStyle(
            "VerdictFail", parent=base["Normal"],
            fontSize=14, leading=18, textColor=_Colors.BLOCKED,
            alignment=TA_CENTER, spaceBefore=8,
        ),
        "footer": ParagraphStyle(
            "Footer", parent=base["Normal"],
            fontSize=7, leading=9, textColor=_Colors.MUTED,
            alignment=TA_CENTER,
        ),
    }


# ── Table helpers ─────────────────────────────────────────────────────

def _kv_table(
    pairs: List[tuple],
    styles: Dict[str, ParagraphStyle],
    col_widths: Optional[tuple] = None,
) -> Table:
    """Build a two-column key/value table."""
    data = []
    for key, value in pairs:
        data.append([
            Paragraph(f"<b>{_esc(str(key))}</b>", styles["body"]),
            Paragraph(_esc(str(value)), styles["body"]),
        ])

    widths = col_widths or (2.0 * inch, 4.2 * inch)
    table = Table(data, colWidths=widths)
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, _Colors.TABLE_ALT),
    ]))
    return table


def _data_table(
    headers: List[str],
    rows: List[List[str]],
    styles: Dict[str, ParagraphStyle],
    col_widths: Optional[list] = None,
) -> Table:
    """Build a multi-column data table with header row."""
    header_row = [Paragraph(f"<b>{_esc(h)}</b>", styles["body"]) for h in headers]
    body_rows = [
        [Paragraph(_esc(str(cell)), styles["body_small"]) for cell in row]
        for row in rows
    ]
    data = [header_row] + body_rows

    table = Table(data, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), _Colors.TABLE_HEADER),
        ("TEXTCOLOR", (0, 0), (-1, 0), _Colors.WHITE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.3, _Colors.MUTED),
    ]
    # Alternate row shading
    for i in range(1, len(data)):
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), _Colors.TABLE_ALT))

    table.setStyle(TableStyle(style_cmds))
    return table


def _esc(text: str) -> str:
    """Escape XML special characters for reportlab Paragraph."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _fmt_ts(ts: Any) -> str:
    """Format a timestamp (epoch float or ISO string) for display."""
    if ts is None:
        return "-"
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(ts)


def _format_runtime_status(runtime: Dict[str, Any]) -> str:
    """Render a concise Lean runtime status for PDF surfaces."""
    status = str(runtime.get("lean_status") or "unknown").lower()
    mode = str(runtime.get("mode") or "unknown").replace("_", "-")
    if status == "active":
        return f"Active ({mode})"
    if status == "unavailable":
        return f"Unavailable ({mode})"
    return "Unknown"


# ── Page templates ────────────────────────────────────────────────────

def _header_footer(canvas, doc):
    """Draw page header/footer on every page."""
    canvas.saveState()
    width, height = doc.pagesize

    # Header line
    canvas.setStrokeColor(_Colors.ACCENT)
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, height - 40, width - doc.rightMargin, height - 40)

    # Header text
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(_Colors.MUTED)
    canvas.drawString(doc.leftMargin, height - 36, "Certior - Verified Agent Platform")
    canvas.drawRightString(
        width - doc.rightMargin, height - 36,
        f"Compliance Audit Package",
    )

    # Footer
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(_Colors.MUTED)
    canvas.drawString(doc.leftMargin, 28, "CONFIDENTIAL - Generated by Certior")
    canvas.drawRightString(width - doc.rightMargin, 28, f"Page {doc.page}")

    canvas.restoreState()


# ══════════════════════════════════════════════════════════════════════
#  Main Exporter
# ══════════════════════════════════════════════════════════════════════

class CompliancePDFExporter:
    """
    Renders a CompliancePackage to a professional PDF audit report.

    The PDF includes:
      1. Cover page with compliance regime, verdict, and metadata
      2. Execution summary
      3. Proof certificates
      4. Content safety results
      5. Information flow analysis
      6. Policy configuration
      7. Audit trail
      8. Attestation statement
    """

    @staticmethod
    def available() -> bool:
        """Check if PDF generation is available (reportlab installed)."""
        return _REPORTLAB_AVAILABLE

    @classmethod
    def render(
        cls,
        package: CompliancePackage,
        pagesize: Optional[tuple] = None,
    ) -> bytes:
        """
        Render compliance package to PDF bytes.

        Args:
            package: The compliance package to render.
            pagesize: Page size tuple (default: US Letter).

        Returns:
            PDF file content as bytes.

        Raises:
            ImportError: If reportlab is not installed.
        """
        if not _REPORTLAB_AVAILABLE:
            raise ImportError(
                "reportlab is required for PDF export. "
                "Install: pip install reportlab"
            )

        if pagesize is None:
            pagesize = letter

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=pagesize,
            topMargin=50,
            bottomMargin=45,
            leftMargin=50,
            rightMargin=50,
            title=f"Compliance Audit - {package.compliance_regime}",
            author="Certior Verified Agent Platform",
            subject=f"Execution {package.execution_summary.get('execution_id', 'N/A')}",
        )

        styles = _build_styles()
        story = cls._build_story(package, styles)

        doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
        return buf.getvalue()

    @classmethod
    def _build_story(
        cls,
        pkg: CompliancePackage,
        s: Dict[str, ParagraphStyle],
    ) -> list:
        """Build the full document flowable list."""
        story: list = []

        # ── Cover page ────────────────────────────────────────────
        story.append(Spacer(1, 1.5 * inch))
        story.append(Paragraph("Compliance Audit Package", s["cover_title"]))
        story.append(Paragraph(
            f"Generated {_fmt_ts(pkg.generated_at)}",
            s["cover_subtitle"],
        ))
        story.append(Spacer(1, 0.3 * inch))

        story.append(Paragraph(
            f"Regime: {_esc(pkg.compliance_regime or 'Default')}",
            s["cover_regime"],
        ))

        exec_id = pkg.execution_summary.get("execution_id", "N/A")
        story.append(Paragraph(
            f"Execution: {_esc(str(exec_id))}",
            s["cover_subtitle"],
        ))

        runtime = pkg.verification_runtime if isinstance(pkg.verification_runtime, dict) else {}
        story.append(Paragraph(
            f"Lean Runtime: {_esc(_format_runtime_status(runtime))}",
            s["cover_subtitle"],
        ))

        # Verdict
        story.append(Spacer(1, 0.4 * inch))
        att = pkg.attestation
        compliant = att.get("compliant", False) if isinstance(att, dict) else False
        if compliant:
            story.append(Paragraph("COMPLIANT", s["verdict_pass"]))
        else:
            story.append(Paragraph("NON-COMPLIANT", s["verdict_fail"]))

        story.append(Spacer(1, 0.2 * inch))
        story.append(HRFlowable(
            width="80%", thickness=1, color=_Colors.ACCENT, spaceAfter=12,
        ))

        pkg_id = pkg.package_id or "N/A"
        story.append(Paragraph(
            f"Package ID: {_esc(pkg_id)}",
            s["body_small"],
        ))

        story.append(PageBreak())

        # ── Table of Contents ─────────────────────────────────────
        story.append(Paragraph("Contents", s["section_heading"]))
        toc_items = [
            "1. Execution Summary",
            "2. Proof Certificates",
            "3. Content Safety Scans",
            "4. Information Flow Analysis",
            "5. Policy Configuration",
            "6. Audit Trail",
            "7. Attestation",
        ]
        for item in toc_items:
            story.append(Paragraph(item, s["body"]))
        story.append(PageBreak())

        # ── 1. Execution Summary ──────────────────────────────────
        story.append(Paragraph("1. Execution Summary", s["section_heading"]))
        ex = pkg.execution_summary
        pairs = [
            ("Execution ID", ex.get("execution_id", "N/A")),
            ("Task", ex.get("task", "N/A")),
            ("User", ex.get("user_id", "N/A")),
            ("Status", ex.get("status", "N/A")),
            ("Lean Runtime", _format_runtime_status(runtime)),
            ("Created", _fmt_ts(ex.get("created_at"))),
            ("Completed", _fmt_ts(ex.get("completed_at"))),
            ("Cost", f"${ex.get('cost_cents', 0) / 100:.2f}"),
            ("Certificates", str(ex.get("certificate_count", 0))),
        ]
        story.append(_kv_table(pairs, s))
        story.append(Spacer(1, 12))

        # ── 2. Proof Certificates ─────────────────────────────────
        story.append(Paragraph("2. Proof Certificates", s["section_heading"]))
        certs = pkg.certificates or []
        if certs:
            story.append(Paragraph(
                f"{len(certs)} certificate(s) issued for this execution.",
                s["body"],
            ))
            for i, cert in enumerate(certs):
                story.append(Paragraph(f"Certificate {i + 1}", s["subsection"]))
                if isinstance(cert, dict):
                    cert_pairs = [
                        ("ID", cert.get("id", "N/A")),
                        ("Type", cert.get("type", "proof_certificate")),
                        ("Prover", cert.get("prover", "z3")),
                    ]
                    props = cert.get("verified_properties", [])
                    if props:
                        cert_pairs.append(("Properties", ", ".join(str(p) for p in props)))
                    story.append(_kv_table(cert_pairs, s))
                else:
                    story.append(Paragraph(f"Certificate ref: {_esc(str(cert))}", s["mono"]))
                story.append(Spacer(1, 6))
        else:
            story.append(Paragraph("No proof certificates were issued.", s["body"]))
        story.append(Spacer(1, 12))

        # ── 3. Content Safety Scans ───────────────────────────────
        story.append(Paragraph("3. Content Safety Scans", s["section_heading"]))
        scans = pkg.safety_scans or []
        if scans:
            headers = ["Scan #", "Category", "Severity", "Detail"]
            rows = []
            for i, scan in enumerate(scans):
                if isinstance(scan, dict):
                    rows.append([
                        str(i + 1),
                        scan.get("category", "N/A"),
                        scan.get("severity", "N/A"),
                        str(scan.get("matched_text", ""))[:60],
                    ])
                else:
                    rows.append([str(i + 1), str(scan)[:40], "", ""])
            story.append(_data_table(headers, rows, s, [0.6 * inch, 1.5 * inch, 1 * inch, 3.1 * inch]))
        else:
            story.append(Paragraph("No content safety violations detected.", s["body"]))
        story.append(Spacer(1, 12))

        # ── 4. Information Flow Analysis ──────────────────────────
        story.append(Paragraph("4. Information Flow Analysis", s["section_heading"]))
        flow = pkg.flow_analysis or {}
        flow_pairs = [
            ("Rules Enforced", flow.get("rules_enforced", 0)),
            ("Flows Tracked", flow.get("flows_tracked", 0)),
            ("Violations Detected", flow.get("violations_detected", 0)),
        ]
        story.append(_kv_table(flow_pairs, s))

        story.append(Spacer(1, 8))
        story.append(Paragraph("Lean Verification Runtime", s["subsection"]))
        runtime_pairs = [
            ("Status", _format_runtime_status(runtime)),
            ("Detail", runtime.get("detail", "N/A")),
            ("Flow Checks", runtime.get("steps_checked", 0)),
            ("Lean Certificates", runtime.get("certificates_issued", 0)),
            ("Flow Violations", runtime.get("flow_violations", 0)),
        ]
        binary = runtime.get("binary")
        if binary:
            runtime_pairs.append(("Binary", binary))
        story.append(_kv_table(runtime_pairs, s, (1.6 * inch, 4.6 * inch)))

        violations = flow.get("violation_details", [])
        if violations:
            story.append(Paragraph("Violation Details", s["subsection"]))
            for v in violations[:20]:  # cap at 20
                story.append(Paragraph(f"- {_esc(str(v))}", s["body_small"]))
        story.append(Spacer(1, 12))

        # ── 5. Policy Configuration ───────────────────────────────
        story.append(Paragraph("5. Policy Configuration", s["section_heading"]))
        policy = pkg.policy_applied or {}
        policy_pairs = [
            ("Regime", policy.get("name", "N/A")),
            ("Retention (days)", policy.get("audit", {}).get("retention_days", "N/A")),
            ("Human Approvals", ", ".join(policy.get("human_approvals", [])) or "None"),
        ]

        blocked = policy.get("blocked_categories", [])
        if blocked:
            policy_pairs.append(("Blocked Categories", ", ".join(blocked)))

        proofs = policy.get("required_proofs", [])
        if proofs:
            policy_pairs.append(("Required Proofs", ", ".join(proofs)))

        story.append(_kv_table(policy_pairs, s))
        story.append(Spacer(1, 12))

        # ── 6. Audit Trail ────────────────────────────────────────
        story.append(Paragraph("6. Audit Trail", s["section_heading"]))
        trail = pkg.audit_trail or []
        if trail:
            story.append(Paragraph(
                f"{len(trail)} audit event(s) recorded.",
                s["body"],
            ))
            headers = ["#", "Timestamp", "Action", "Result", "Detail"]
            rows = []
            for i, entry in enumerate(trail[:100]):  # cap at 100
                if isinstance(entry, dict):
                    detail = (
                        entry.get("resource")
                        or entry.get("tool")
                        or entry.get("task")
                        or entry.get("detail")
                        or entry.get("mode")
                        or ""
                    )
                    action = entry.get("action") or entry.get("phase") or entry.get("tool") or "event"
                    result = entry.get("result")
                    if result is None:
                        if "verified" in entry:
                            result = "verified" if entry.get("verified") else "blocked"
                        elif entry.get("proven") is True:
                            result = "proven"
                        elif entry.get("mode"):
                            result = entry.get("mode")
                        else:
                            result = "logged"
                    rows.append([
                        str(i + 1),
                        _fmt_ts(entry.get("timestamp")),
                        str(action)[:30],
                        str(result)[:20],
                        str(detail)[:30],
                    ])
            if rows:
                story.append(_data_table(
                    headers, rows, s,
                    [0.4 * inch, 1.5 * inch, 1.3 * inch, 1 * inch, 2 * inch],
                ))
            if len(trail) > 100:
                story.append(Paragraph(
                    f"... and {len(trail) - 100} more entries (see JSON export for full trail).",
                    s["body_small"],
                ))
        else:
            story.append(Paragraph("No audit trail entries recorded.", s["body"]))
        story.append(PageBreak())

        # ── 7. Attestation ────────────────────────────────────────
        story.append(Paragraph("7. Attestation", s["section_heading"]))
        att = pkg.attestation if isinstance(pkg.attestation, dict) else {}

        story.append(Paragraph(
            "This section provides a machine-readable compliance attestation "
            "based on the proof certificates and policy requirements.",
            s["body"],
        ))
        story.append(Spacer(1, 8))

        att_pairs = [
            ("Regime", att.get("regime", "N/A")),
            ("Retention (days)", att.get("retention_days", "N/A")),
            ("Certificate Count", att.get("certificate_count", 0)),
            ("Compliant", "Yes" if att.get("compliant") else "No"),
        ]
        story.append(_kv_table(att_pairs, s))
        story.append(Spacer(1, 8))

        # Proofs satisfied / missing
        satisfied = att.get("proofs_satisfied", [])
        missing = att.get("proofs_missing", [])

        if satisfied:
            story.append(Paragraph("Proofs Satisfied", s["subsection"]))
            for p in satisfied:
                story.append(Paragraph(f"  {_esc(p)}", s["body"]))

        if missing:
            story.append(Paragraph("Proofs Missing", s["subsection"]))
            for p in missing:
                story.append(Paragraph(f"  {_esc(p)}", s["body"]))

        # Verified properties
        props = att.get("verified_properties", [])
        if props:
            story.append(Spacer(1, 8))
            story.append(Paragraph("Verified Properties", s["subsection"]))
            for p in props:
                story.append(Paragraph(f"  {_esc(p)}", s["mono"]))

        # Final disclaimer
        story.append(Spacer(1, 0.5 * inch))
        story.append(HRFlowable(width="100%", thickness=0.5, color=_Colors.MUTED))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            "This audit package was automatically generated by the Certior "
            "Verified Agent Platform. Proof certificates are mathematically "
            "verified using Z3/Dafny/Lean4 formal verification. This document "
            "should be retained per the applicable compliance regime's "
            "retention requirements.",
            s["body_small"],
        ))

        return story

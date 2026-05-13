"""
Report generator — produces JSON and PDF security reports for SENTINEL scans.
"""
from __future__ import annotations

import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _now_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_json_report(scan: dict, vulns: list[dict], ai_analysis: Optional[dict]) -> dict:
    """Build a comprehensive JSON report for a scan."""
    sev_counts: dict[str, int] = {}
    for v in vulns:
        s = v.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    cat_counts: dict[str, int] = {}
    for v in vulns:
        c = v.get("category", "Unknown")
        cat_counts[c] = cat_counts.get(c, 0) + 1

    report = {
        "reportVersion": "1.0",
        "generatedAt": _now_str(),
        "scanner": "SENTINEL AI Security Platform",
        "scan": {
            "id": str(scan.get("id", "")),
            "repoUrl": scan.get("repo_url", ""),
            "branch": scan.get("branch", "main"),
            "profile": scan.get("scan_profile", "standard"),
            "status": scan.get("status", ""),
            "startedAt": scan.get("started_at").isoformat() if scan.get("started_at") and hasattr(scan.get("started_at"), 'isoformat') else str(scan.get("started_at", "")),
            "completedAt": scan.get("completed_at").isoformat() if scan.get("completed_at") and hasattr(scan.get("completed_at"), 'isoformat') else str(scan.get("completed_at", "")),
            "modulesRun": scan.get("modules_run", []),
        },
        "summary": {
            "totalVulnerabilities": len(vulns),
            "bySeverity": sev_counts,
            "byCategory": cat_counts,
            "riskScore": ai_analysis.get("risk_score", 0) if ai_analysis else None,
        },
        "vulnerabilities": [
            {
                "id": str(v.get("id", "")),
                "severity": v.get("severity"),
                "category": v.get("category"),
                "title": v.get("title"),
                "file": v.get("file"),
                "lineStart": v.get("line_start"),
                "lineEnd": v.get("line_end"),
                "description": v.get("description"),
                "cvss": v.get("cvss"),
                "cwe": v.get("cwe"),
                "owasp": v.get("owasp"),
                "remediation": v.get("remediation"),
                "tool": v.get("tool"),
            }
            for v in vulns
        ],
        "aiAnalysis": {
            "riskScore": ai_analysis.get("risk_score") if ai_analysis else None,
            "threatModel": ai_analysis.get("threat_model") if ai_analysis else None,
            "attackChains": ai_analysis.get("attack_chains", []) if ai_analysis else [],
            "topRemediations": (ai_analysis.get("remediations", [])[:5] if ai_analysis else []),
        } if ai_analysis else None,
    }
    return report


def generate_pdf_report(scan: dict, vulns: list[dict], ai_analysis: Optional[dict]) -> bytes:
    """Generate a PDF security report using reportlab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether,
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "Title",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#0F172A"),
            spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            "Subtitle",
            parent=styles["Normal"],
            fontSize=12,
            textColor=colors.HexColor("#64748B"),
            spaceAfter=20,
        )
        h2_style = ParagraphStyle(
            "H2",
            parent=styles["Heading2"],
            fontSize=16,
            textColor=colors.HexColor("#0F172A"),
            spaceBefore=16,
            spaceAfter=8,
        )
        h3_style = ParagraphStyle(
            "H3",
            parent=styles["Heading3"],
            fontSize=13,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=10,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=10,
            leading=15,
            textColor=colors.HexColor("#334155"),
        )
        code_style = ParagraphStyle(
            "Code",
            parent=styles["Normal"],
            fontSize=8,
            fontName="Courier",
            leading=12,
            textColor=colors.HexColor("#1E293B"),
            backColor=colors.HexColor("#F1F5F9"),
            borderPadding=6,
        )

        SEV_COLORS = {
            "critical": colors.HexColor("#EF4444"),
            "high": colors.HexColor("#F97316"),
            "medium": colors.HexColor("#EAB308"),
            "low": colors.HexColor("#3B82F6"),
            "info": colors.HexColor("#94A3B8"),
        }

        story = []

        # Header
        story.append(Paragraph("SENTINEL AI Security Report", title_style))
        repo = scan.get("repo_url", "Unknown Repository")
        generated = _now_str()[:10]
        story.append(Paragraph(f"{repo} — Generated {generated}", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#6366F1")))
        story.append(Spacer(1, 0.5 * cm))

        # Scan metadata table
        profile = scan.get("scan_profile", "standard")
        status = scan.get("status", "unknown")
        branch = scan.get("branch", "main")
        scan_id = str(scan.get("id", "N/A"))[:8]

        meta_data = [
            ["Scan ID", scan_id, "Branch", branch],
            ["Profile", profile.upper(), "Status", status.upper()],
        ]
        meta_table = Table(meta_data, colWidths=[3.5 * cm, 6 * cm, 3.5 * cm, 6 * cm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F8FAFC")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1E293B")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.5 * cm))

        # Summary
        story.append(Paragraph("Executive Summary", h2_style))
        sev_counts: dict[str, int] = {}
        for v in vulns:
            s = v.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        risk_score = ai_analysis.get("risk_score", "N/A") if ai_analysis else "N/A"
        summary_text = (
            f"This scan identified <b>{len(vulns)}</b> vulnerabilities in {repo.split('/')[-1]}, "
            f"including <b>{sev_counts.get('critical', 0)} critical</b>, "
            f"<b>{sev_counts.get('high', 0)} high</b>, "
            f"<b>{sev_counts.get('medium', 0)} medium</b>, and "
            f"<b>{sev_counts.get('low', 0)} low</b> severity findings. "
            f"The overall AI risk score is <b>{risk_score}/10</b>."
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 0.3 * cm))

        # Severity breakdown table
        sev_rows = [["Severity", "Count", "Risk Level"]]
        for sev, label in [("critical", "Critical"), ("high", "High"),
                            ("medium", "Medium"), ("low", "Low"), ("info", "Info")]:
            cnt = sev_counts.get(sev, 0)
            if cnt > 0:
                risk_label = {"critical": "Immediate Action", "high": "Action Required",
                              "medium": "Should Fix", "low": "Informational",
                              "info": "Review"}.get(sev, "Review")
                sev_rows.append([label, str(cnt), risk_label])

        sev_table = Table(sev_rows, colWidths=[5 * cm, 4 * cm, 10 * cm])
        sev_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ]
        for i, row in enumerate(sev_rows[1:], 1):
            sev_name = row[0].lower()
            c = SEV_COLORS.get(sev_name, colors.HexColor("#94A3B8"))
            sev_style.append(("TEXTCOLOR", (0, i), (0, i), c))
            sev_style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
        sev_table.setStyle(TableStyle(sev_style))
        story.append(sev_table)
        story.append(Spacer(1, 0.5 * cm))

        # Threat model
        if ai_analysis and ai_analysis.get("threat_model"):
            story.append(Paragraph("AI Threat Assessment", h2_style))
            story.append(Paragraph(ai_analysis["threat_model"].replace("\n", "<br/>"), body_style))
            story.append(Spacer(1, 0.3 * cm))

        # Vulnerabilities
        story.append(Paragraph("Vulnerability Findings", h2_style))

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(vulns, key=lambda v: sev_order.get(v.get("severity", "info"), 4))

        for i, v in enumerate(sorted_vulns[:50], 1):  # Max 50 in PDF
            sev = v.get("severity", "info")
            sev_color = SEV_COLORS.get(sev, colors.HexColor("#94A3B8"))

            # Vuln header
            header_text = f'[{sev.upper()}] {v.get("title", "Unknown")}'
            vuln_header = ParagraphStyle(
                f"VH{i}",
                parent=h3_style,
                textColor=sev_color,
            )
            meta = f'<b>File:</b> {v.get("file", "?")}:{v.get("line_start", "?")} | <b>CWE:</b> {v.get("cwe", "N/A")} | <b>CVSS:</b> {v.get("cvss", "N/A")} | <b>Tool:</b> {v.get("tool", "N/A")}'
            elements = [
                Paragraph(header_text, vuln_header),
                Paragraph(meta, body_style),
                Spacer(1, 0.1 * cm),
                Paragraph(v.get("description", ""), body_style),
            ]
            if v.get("snippet"):
                snippet = v["snippet"][:400].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                elements.append(Spacer(1, 0.1 * cm))
                elements.append(Paragraph(f"<font name='Courier' size=8>{snippet}</font>", body_style))
            if v.get("remediation"):
                elements.append(Spacer(1, 0.1 * cm))
                elements.append(Paragraph(f"<b>Remediation:</b> {v['remediation']}", body_style))
            elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E2E8F0")))
            story.extend(elements)

        if len(sorted_vulns) > 50:
            story.append(Paragraph(
                f"<i>... and {len(sorted_vulns) - 50} more vulnerabilities. Download the JSON report for full details.</i>",
                body_style
            ))

        # Footer note
        story.append(Spacer(1, 1 * cm))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#6366F1")))
        story.append(Paragraph(
            f"Generated by SENTINEL AI Security Platform | {_now_str()} | Confidential",
            ParagraphStyle("footer", parent=body_style, fontSize=8, textColor=colors.HexColor("#94A3B8"),
                           alignment=TA_CENTER)
        ))

        doc.build(story)
        return buffer.getvalue()

    except ImportError:
        logger.warning("reportlab not installed — generating simple text PDF stub")
        # Fallback: simple text bytes
        text = f"SENTINEL Security Report\n{'=' * 40}\n"
        text += f"Repo: {scan.get('repo_url', '')}\n"
        text += f"Total Vulnerabilities: {len(vulns)}\n"
        text += f"Generated: {_now_str()}\n\n"
        for v in vulns[:20]:
            text += f"[{v.get('severity', '?').upper()}] {v.get('title', '')}\n"
            text += f"  File: {v.get('file')}:{v.get('line_start')}\n"
            text += f"  {v.get('description', '')}\n\n"
        return text.encode("utf-8")
    except Exception as exc:
        logger.error("PDF generation failed: %s", exc)
        fallback = json.dumps(generate_json_report(scan, vulns, ai_analysis), default=str)
        return fallback.encode("utf-8")

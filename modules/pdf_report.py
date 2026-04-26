"""
VULNIX - PDF Report Generator
Generate professional PDF vulnerability reports
"""

import os
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, HRFlowable
    )
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class PDFReportGenerator:
    """Generate PDF vulnerability reports."""

    COLORS = {
        "critical": HexColor("#DC3545"),
        "high": HexColor("#FF6B35"),
        "medium": HexColor("#FFC107"),
        "low": HexColor("#28A745"),
        "info": HexColor("#17A2B8"),
        "header": HexColor("#2C3E50"),
        "subheader": HexColor("#34495E"),
        "background": HexColor("#F8F9FA"),
    }

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.styles = None
        self._init_styles()

    def _init_styles(self):
        """Initialize paragraph styles."""
        if not REPORTLAB_AVAILABLE:
            return

        self.styles = getSampleStyleSheet()

        self.styles.add(ParagraphStyle(
            name="CustomTitle",
            parent=self.styles["Title"],
            fontSize=28,
            textColor=self.COLORS["header"],
            spaceAfter=30,
            alignment=TA_CENTER,
        ))

        self.styles.add(ParagraphStyle(
            name="SectionTitle",
            parent=self.styles["Heading1"],
            fontSize=18,
            textColor=self.COLORS["header"],
            spaceAfter=12,
            spaceBefore=20,
        ))

        self.styles.add(ParagraphStyle(
            name="SubSection",
            parent=self.styles["Heading2"],
            fontSize=14,
            textColor=self.COLORS["subheader"],
            spaceAfter=8,
            spaceBefore=12,
        ))

        self.styles.add(ParagraphStyle(
            name="BodyText",
            parent=self.styles["BodyText"],
            fontSize=10,
            spaceAfter=6,
        ))

        self.styles.add(ParagraphStyle(
            name="FindingTitle",
            parent=self.styles["Heading3"],
            fontSize=12,
            textColor=self.COLORS["subheader"],
            spaceAfter=6,
        ))

    def _get_severity_color(self, severity: str) -> HexColor:
        """Get color for severity level."""
        return self.COLORS.get(severity.lower(), self.COLORS["info"])

    def _create_header_footer(self, canvas, doc):
        """Add header and footer to each page."""
        canvas.saveState()

        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(HexColor("#6C757D"))
        canvas.drawString(1*cm, A4[1] - 1.5*cm, "VULNIX - Vulnerability Scanner")
        canvas.drawRightString(A4[0] - 1*cm, A4[1] - 1.5*cm,
                               f"Confidential - {datetime.now().strftime('%Y-%m-%d')}")

        canvas.drawString(1*cm, 1.5*cm, "For authorized security testing only")
        canvas.drawRightString(A4[0] - 1*cm, 1.5*cm, f"Page {doc.page}")

        canvas.restoreState()

    def generate_report(self, scan_data: Dict[str, Any], output_filename: str = None) -> str:
        """Generate PDF report from scan data."""
        if not REPORTLAB_AVAILABLE:
            raise ImportError(
                "reportlab is required for PDF reports. Install with: pip install reportlab"
            )

        if output_filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"vulnix_report_{timestamp}.pdf"

        output_path = self.output_dir / output_filename

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2.5*cm,
            bottomMargin=2*cm,
        )

        story = []
        story.extend(self._build_executive_summary(scan_data))
        story.append(PageBreak())
        story.extend(self._build_findings_section(scan_data))
        story.append(PageBreak())
        story.extend(self._build_appendix(scan_data))

        doc.build(story, onFirstPage=self._create_header_footer,
                  onLaterPages=self._create_header_footer)

        return str(output_path)

    def _build_executive_summary(self, data: Dict[str, Any]) -> List:
        """Build executive summary section."""
        story = []

        story.append(Paragraph("VULNIX", self.styles["CustomTitle"]))
        story.append(Paragraph("Vulnerability Assessment Report", self.styles["BodyText"]))
        story.append(Spacer(1, 0.5*inch))
        story.append(HRFlowable(width="100%", thickness=2,
                                color=self.COLORS["header"], spaceAfter=20))

        target = data.get("target", "N/A")
        scan_date = data.get("scan_date", datetime.now().strftime("%Y-%m-%d %H:%M"))

        meta_data = [
            ["Target", target],
            ["Scan Date", scan_date],
            ["Scanner Version", "1.0.0"],
        ]

        meta_table = Table(meta_data, colWidths=[3*cm, 12*cm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), self.COLORS["background"]),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (0, 0), (0, -1), "RIGHT"),
            ("ALIGN", (1, 0), (1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#DEE2E6")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.5*inch))

        story.append(Paragraph("Executive Summary", self.styles["SectionTitle"]))

        findings = data.get("findings", [])
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        total_findings = len(findings)

        summary_data = [
            ["Total Findings", str(total_findings)],
            ["Critical", str(severity_counts["critical"])],
            ["High", str(severity_counts["high"])],
            ["Medium", str(severity_counts["medium"])],
            ["Low", str(severity_counts["low"])],
            ["Informational", str(severity_counts["info"])],
        ]

        summary_table = Table(summary_data, colWidths=[5*cm, 3*cm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), self.COLORS["header"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#DEE2E6")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BACKGROUND", (0, 1), (-1, 1), self.COLORS["critical"]),
            ("BACKGROUND", (0, 2), (-1, 2), self.COLORS["high"]),
            ("BACKGROUND", (0, 3), (-1, 3), self.COLORS["medium"]),
            ("BACKGROUND", (0, 4), (-1, 4), self.COLORS["low"]),
            ("BACKGROUND", (0, 5), (-1, 5), self.COLORS["info"]),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))

        if total_findings == 0:
            story.append(Paragraph(
                "No vulnerabilities were identified during this assessment.",
                self.styles["BodyText"]
            ))
        else:
            story.append(Paragraph(
                f"This assessment identified {total_findings} potential vulnerabilities "
                f"requiring attention. Immediate action is recommended for "
                f"{severity_counts['critical'] + severity_counts['high']} critical/high severity issues.",
                self.styles["BodyText"]
            ))

        return story

    def _build_findings_section(self, data: Dict[str, Any]) -> List:
        """Build detailed findings section."""
        story = []
        story.append(Paragraph("Detailed Findings", self.styles["SectionTitle"]))

        findings = data.get("findings", [])

        if not findings:
            story.append(Paragraph("No findings to report.", self.styles["BodyText"]))
            return story

        for i, finding in enumerate(findings, 1):
            severity = finding.get("severity", "info").lower()
            vuln_type = finding.get("type", "Unknown")
            url = finding.get("url", "N/A")
            description = finding.get("description", "")
            remediation = finding.get("remediation", "")

            story.append(Spacer(1, 0.2*inch))

            header_color = self._get_severity_color(severity)
            story.append(Paragraph(
                f"{i}. [{severity.upper()}] {vuln_type}",
                self.styles["FindingTitle"]
            ))

            finding_data = [
                ["Severity", severity.upper()],
                ["URL", url],
                ["Description", description],
                ["Remediation", remediation],
            ]

            finding_table = Table(finding_data, colWidths=[3*cm, 12*cm])
            finding_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), self.COLORS["background"]),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#DEE2E6")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("BACKGROUND", (0, 0), (-1, -1), HexColor("#FFFFFF")),
            ]))
            story.append(finding_table)

        return story

    def _build_appendix(self, data: Dict[str, Any]) -> List:
        """Build appendix section."""
        story = []
        story.append(Paragraph("Appendix", self.styles["SectionTitle"]))

        story.append(Paragraph("Methodology", self.styles["SubSection"]))
        story.append(Paragraph(
            "This assessment was conducted using VULNIX, an automated web vulnerability "
            "scanner that performs comprehensive security testing including:",
            self.styles["BodyText"]
        ))

        methods = [
            "Content discovery and crawling",
            "SQL injection detection",
            "Cross-site scripting (XSS) testing",
            "Security header analysis",
            "CORS configuration review",
            "Authentication and session testing",
            "Parameter manipulation",
        ]

        for method in methods:
            story.append(Paragraph(f"- {method}", self.styles["BodyText"]))

        story.append(Spacer(1, 0.3*inch))

        story.append(Paragraph("Scope Limitations", self.styles["SubSection"]))
        story.append(Paragraph(
            "Automated scanning has inherent limitations. Areas not covered may include:",
            self.styles["BodyText"]
        ))

        limitations = [
            "Complex business logic flaws",
            "Client-side only vulnerabilities",
            "Vulnerabilities requiring specific user roles",
            "Social engineering attacks",
            "Physical security issues",
        ]

        for limit in limitations:
            story.append(Paragraph(f"- {limit}", self.styles["BodyText"]))

        story.append(Spacer(1, 0.3*inch))

        story.append(Paragraph("Disclaimer", self.styles["SubSection"]))
        story.append(Paragraph(
            "This report is for authorized security testing purposes only. "
            "Unauthorized access to computer systems is illegal. All findings should "
            "be verified manually before remediation efforts are undertaken.",
            self.styles["BodyText"]
        ))

        return story


def generate_pdf_report(scan_data: Dict[str, Any], output_dir: str = "reports") -> str:
    """Convenience function to generate PDF report."""
    generator = PDFReportGenerator(output_dir)
    return generator.generate_report(scan_data)
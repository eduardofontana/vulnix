"""
VULNIX - Web Vulnerability Scanner
Reporting System - Generate JSON, HTML, SARIF, XML reports
"""

import json
import html
from typing import Dict, List, Any, Optional

from core.scanner import ScanResult, Finding


class ReportGenerator:
    """Generate vulnerability scan reports."""

    SEVERITY_COLORS = {
        "critical": "#ff0000",
        "high": "#ff6600",
        "medium": "#ffcc00",
        "low": "#3399ff",
        "info": "#00cc66",
    }

    def __init__(self):
        self.report_data: Dict[str, Any] = {}

    def _normalize_errors(self, errors: List[Any]) -> List[Dict[str, Any]]:
        """Normalize legacy and structured errors to a unified schema."""
        normalized: List[Dict[str, Any]] = []
        for err in errors:
            if isinstance(err, dict):
                normalized.append(
                    {
                        "module": err.get("module", "unknown"),
                        "phase": err.get("phase", "unknown"),
                        "url": err.get("url", ""),
                        "error": str(err.get("error", "")),
                        "timestamp": err.get("timestamp"),
                    }
                )
            else:
                normalized.append(
                    {
                        "module": "legacy",
                        "phase": "unknown",
                        "url": "",
                        "error": str(err),
                        "timestamp": None,
                    }
                )
        return normalized

    def _summarize_errors(self, errors: List[Dict[str, Any]]) -> Dict[str, int]:
        """Build a count by module for report summaries."""
        counts: Dict[str, int] = {}
        for err in errors:
            module = err.get("module", "unknown")
            counts[module] = counts.get(module, 0) + 1
        return counts

    def _extract_recon_data(self, findings: List[Finding]) -> Dict[str, Any]:
        """Extract recon artifacts from findings for dedicated reporting."""
        subdomains: List[str] = []
        technologies: List[str] = []
        hidden_parameters: List[Dict[str, str]] = []
        dns_records: Dict[str, List[str]] = {}
        ports: List[Dict[str, Any]] = []
        ssl_info: List[Dict[str, Any]] = []
        robots_data: List[Dict[str, Any]] = []
        sitemap_data: List[Dict[str, Any]] = []
        extracted_links: Dict[str, Any] = {}

        for finding in findings:
            if finding.type == "subdomain":
                if finding.url and finding.url not in subdomains:
                    subdomains.append(finding.url)
                continue

            if finding.type == "technology":
                label = finding.description.replace("Detected:", "").strip()
                tech_name = label or finding.evidence or finding.payload or ""
                if tech_name and tech_name not in technologies:
                    technologies.append(tech_name)
                continue

            if finding.type == "parameter_discovery":
                parameter_name = finding.parameter or ""
                if parameter_name:
                    hidden_parameters.append(
                        {
                            "url": finding.url,
                            "parameter": parameter_name,
                        }
                    )
                continue

            if finding.type == "dns_record":
                details = finding.details or {}
                record_type = details.get("record_type", "unknown")
                value = details.get("value", "")
                if record_type not in dns_records:
                    dns_records[record_type] = []
                if value and value not in dns_records[record_type]:
                    dns_records[record_type].append(value)
                continue

            if finding.type == "port":
                port_info = finding.details or {}
                if port_info:
                    ports.append(port_info)
                continue

            if finding.type == "ssl_cert":
                ssl_info.append(finding.details or {})
                continue

            if finding.type == "robots_txt":
                robots_data.append(finding.details or {})
                continue

            if finding.type == "sitemap":
                sitemap_data.append(finding.details or {})
                continue

            if finding.type == "link_extraction":
                extracted_links = finding.details or {}
                continue

        return {
            "summary": {
                "subdomains_count": len(subdomains),
                "technologies_count": len(technologies),
                "hidden_parameters_count": len(hidden_parameters),
                "dns_records_count": sum(len(v) for v in dns_records.values()),
                "open_ports_count": len(ports),
                "ssl_certs_count": len(ssl_info),
                "robots_paths_count": len(robots_data),
                "sitemap_urls_count": len(sitemap_data),
            },
            "subdomains": subdomains,
            "technologies": technologies,
            "hidden_parameters": hidden_parameters,
            "dns_records": dns_records,
            "ports": ports,
            "ssl_info": ssl_info,
            "robots": robots_data,
            "sitemap": sitemap_data,
            "extracted_links": extracted_links,
        }

    def _build_module_insights(self, findings: List[Finding]) -> Dict[str, List[Dict[str, Any]]]:
        """Build enriched per-module findings with evidence/remediation."""
        modules_of_interest = {"http_desync", "cloud_metadata", "waf", "websocket", "cve_intel"}
        grouped: Dict[str, List[Dict[str, Any]]] = {m: [] for m in modules_of_interest}

        for finding in findings:
            module_name = (finding.module or "").lower()
            if module_name not in modules_of_interest:
                continue

            grouped[module_name].append(
                {
                    "id": finding.id,
                    "type": finding.type,
                    "severity": finding.severity,
                    "url": finding.url,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "details": finding.details or {},
                }
            )

        return {k: v for k, v in grouped.items() if v}

    def generate_json_report(
        self,
        scan_result: ScanResult,
        output_file: Optional[str] = None,
    ) -> str:
        """Generate JSON report."""
        normalized_errors = self._normalize_errors(scan_result.errors)
        errors_by_module = self._summarize_errors(normalized_errors)
        recon_data = self._extract_recon_data(scan_result.findings)
        module_insights = self._build_module_insights(scan_result.findings)

        report = {
            "target": scan_result.target,
            "scan_time": scan_result.start_time,
            "end_time": scan_result.end_time,
            "summary": {
                "total_findings": len(scan_result.findings),
                "crawled_urls": scan_result.crawled_urls,
                "scanned_endpoints": scan_result.scanned_endpoints,
                "critical": len([f for f in scan_result.findings if f.severity == "critical"]),
                "high": len([f for f in scan_result.findings if f.severity == "high"]),
                "medium": len([f for f in scan_result.findings if f.severity == "medium"]),
                "low": len([f for f in scan_result.findings if f.severity == "low"]),
                "info": len([f for f in scan_result.findings if f.severity == "info"]),
                "total_errors": len(normalized_errors),
                "errors_by_module": errors_by_module,
                "recon": recon_data["summary"],
            },
            "findings": [
                {
                    "id": f.id,
                    "type": f.type,
                    "url": f.url,
                    "parameter": f.parameter,
                    "payload": f.payload,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "module": f.module,
                    "details": f.details,
                    "timestamp": f.timestamp,
                }
                for f in scan_result.findings
            ],
            "errors": normalized_errors,
            "recon": recon_data,
            "module_insights": module_insights,
        }

        report_json = json.dumps(report, indent=2, ensure_ascii=False)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report_json)

        return report_json

    def _get_html_table_row(self, finding: Finding) -> str:
        """Generate HTML table row for finding."""
        color = self.SEVERITY_COLORS.get(finding.severity.lower(), "#cccccc")
        url = html.escape(finding.url)
        param = html.escape(finding.parameter or "-")
        payload = html.escape(finding.payload or "-")

        return "<tr><td style='padding:8px;color:" + color + ";font-weight:bold;'>" + finding.severity.upper() + \
            "</td><td style='padding:8px;'>" + finding.type + "</td><td style='padding:8px;'><code>" + url + \
            "</code></td><td style='padding:8px;'><code>" + param + "</code></td><td style='padding:8px;'><code>" + payload + "</code></td></tr>"

    def _get_severity_summary(self, findings: List[Finding]) -> Dict[str, int]:
        """Generate severity summary."""
        return {
            "critical": len([f for f in findings if f.severity == "critical"]),
            "high": len([f for f in findings if f.severity == "high"]),
            "medium": len([f for f in findings if f.severity == "medium"]),
            "low": len([f for f in findings if f.severity == "low"]),
            "info": len([f for f in findings if f.severity == "info"]),
        }

    def generate_html_report(
        self,
        scan_result: ScanResult,
        output_file: Optional[str] = None,
    ) -> str:
        """Generate HTML report."""
        severity_summary = self._get_severity_summary(scan_result.findings)
        recon_data = self._extract_recon_data(scan_result.findings)
        module_insights = self._build_module_insights(scan_result.findings)
        findings_html = "".join([self._get_html_table_row(f) for f in scan_result.findings])
        target = html.escape(scan_result.target)
        end_time = scan_result.end_time or "In Progress"
        recon_subdomains = "".join(
            [f"<li><code>{html.escape(item)}</code></li>" for item in recon_data["subdomains"][:20]]
        ) or "<li>None</li>"
        recon_technologies = "".join(
            [f"<li>{html.escape(item)}</li>" for item in recon_data["technologies"][:20]]
        ) or "<li>None</li>"
        recon_params = "".join(
            [
                "<li><code>"
                + html.escape(entry.get("parameter", ""))
                + "</code> @ <code>"
                + html.escape(entry.get("url", ""))
                + "</code></li>"
                for entry in recon_data["hidden_parameters"][:20]
            ]
        ) or "<li>None</li>"
        module_sections_html = "".join(
            [
                "<h3>" + html.escape(module) + "</h3><ul>"
                + "".join(
                    [
                        "<li><strong>"
                        + html.escape(item.get("type", ""))
                        + "</strong> ["
                        + html.escape(item.get("severity", ""))
                        + "] - "
                        + html.escape(item.get("description", ""))
                        + "<br><code>evidence: "
                        + html.escape(str(item.get("evidence", ""))[:200])
                        + "</code><br>remediation: "
                        + html.escape(str(item.get("remediation", "N/A")))
                        + "</li>"
                        for item in items[:20]
                    ]
                )
                + "</ul>"
                for module, items in module_insights.items()
            ]
        ) or "<p>No module-specific enriched findings.</p>"

        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VULNIX Scan Report</title>
    <style>
        body { background-color: #0a0a0a; color: #e0e0e0; font-family: 'Courier New', monospace; padding: 20px; margin: 0; }
        h1 { color: #00ff00; border-bottom: 2px solid #00ff00; padding-bottom: 10px; }
        .critical { color: #ff0000; }
        .high { color: #ff6600; }
        .medium { color: #ffcc00; }
        .low { color: #3399ff; }
        .info { color: #00cc66; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>VULNIX Scan Report</h1>
    <p><strong>Target:</strong> """ + target + """</p>
    <p><strong>Scan Start:</strong> """ + scan_result.start_time + """</p>
    <p><strong>Scan End:</strong> """ + end_time + """</p>
    <h2>Summary</h2>
    <p>
        <span class="critical">CRITICAL: """ + str(severity_summary["critical"]) + """</span> |
        <span class="high">HIGH: """ + str(severity_summary["high"]) + """</span> |
        <span class="medium">MEDIUM: """ + str(severity_summary["medium"]) + """</span> |
        <span class="low">LOW: """ + str(severity_summary["low"]) + """</span> |
        <span class="info">INFO: """ + str(severity_summary["info"]) + """</span>
    </p>
    <h2>Recon</h2>
    <p>
        <strong>Subdomains:</strong> """ + str(recon_data["summary"]["subdomains_count"]) + """ |
        <strong>Technologies:</strong> """ + str(recon_data["summary"]["technologies_count"]) + """ |
        <strong>Hidden Params:</strong> """ + str(recon_data["summary"]["hidden_parameters_count"]) + """
    </p>
    <h3>Subdomains</h3>
    <ul>""" + recon_subdomains + """</ul>
    <h3>Technologies</h3>
    <ul>""" + recon_technologies + """</ul>
    <h3>Hidden Parameters</h3>
    <ul>""" + recon_params + """</ul>
    <h2>Module Insights</h2>
    """ + module_sections_html + """
    <h2>Findings (""" + str(len(scan_result.findings)) + """)</h2>
    <table border="1">
        <tr><th>Severity</th><th>Type</th><th>URL</th><th>Parameter</th><th>Payload</th></tr>
        """ + (findings_html if findings_html else "<tr><td colspan='5'>No vulnerabilities found.</td></tr>") + """
    </table>
    <p>Generated by VULNIX - Web Vulnerability Scanner</p>
</body>
</html>"""

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

        return html_content

    def generate_text_report(
        self,
        scan_result: ScanResult,
        output_file: Optional[str] = None,
    ) -> str:
        """Generate plain text report."""
        severity_summary = self._get_severity_summary(scan_result.findings)
        normalized_errors = self._normalize_errors(scan_result.errors)
        errors_by_module = self._summarize_errors(normalized_errors)
        recon_data = self._extract_recon_data(scan_result.findings)
        module_insights = self._build_module_insights(scan_result.findings)

        lines = [
            "=" * 60,
            "VULNIX SCAN REPORT",
            "=" * 60,
            "Target: " + scan_result.target,
            "Scan Start: " + scan_result.start_time,
            "Scan End: " + (scan_result.end_time or "In Progress"),
            "",
            "SUMMARY",
            "-" * 40,
            "Critical: " + str(severity_summary["critical"]),
            "High: " + str(severity_summary["high"]),
            "Medium: " + str(severity_summary["medium"]),
            "Low: " + str(severity_summary["low"]),
            "Info: " + str(severity_summary["info"]),
            "Total: " + str(len(scan_result.findings)),
            "Errors: " + str(len(normalized_errors)),
            "Recon - Subdomains: " + str(recon_data["summary"]["subdomains_count"]),
            "Recon - Technologies: " + str(recon_data["summary"]["technologies_count"]),
            "Recon - Hidden Params: " + str(recon_data["summary"]["hidden_parameters_count"]),
            "",
            "FINDINGS",
            "-" * 40,
        ]

        for i, finding in enumerate(scan_result.findings, 1):
            lines.append("")
            lines.append("[" + str(i) + "] " + finding.type.upper() + " - " + finding.severity.upper())
            lines.append("URL: " + finding.url)
            if finding.parameter:
                lines.append("Parameter: " + finding.parameter)
            if finding.payload:
                lines.append("Payload: " + finding.payload)
            lines.append("Description: " + finding.description)

        if any(recon_data["summary"].values()):
            lines.extend(["", "RECON", "-" * 40])
            if recon_data["subdomains"]:
                lines.append("Subdomains:")
                for item in recon_data["subdomains"][:20]:
                    lines.append("- " + item)
            if recon_data["technologies"]:
                lines.append("Technologies:")
                for item in recon_data["technologies"][:20]:
                    lines.append("- " + item)
            if recon_data["hidden_parameters"]:
                lines.append("Hidden Parameters:")
                for entry in recon_data["hidden_parameters"][:20]:
                    lines.append("- " + entry.get("parameter", "") + " @ " + entry.get("url", ""))

        if module_insights:
            lines.extend(["", "MODULE INSIGHTS", "-" * 40])
            for module, items in module_insights.items():
                lines.append(module + ":")
                for item in items[:10]:
                    lines.append("- " + item.get("type", "") + " [" + item.get("severity", "") + "]")
                    if item.get("evidence"):
                        lines.append("  evidence: " + str(item["evidence"])[:200])
                    lines.append("  remediation: " + str(item.get("remediation") or "N/A"))

        if normalized_errors:
            lines.extend(["", "ERRORS", "-" * 40])
            for module, count in sorted(errors_by_module.items()):
                lines.append(f"{module}: {count}")
            lines.append("")
            for i, err in enumerate(normalized_errors[:10], 1):
                lines.append(f"[{i}] [{err.get('module', 'unknown')}] {err.get('phase', 'unknown')} - {err.get('error', '')}")
                if err.get("url"):
                    lines.append("URL: " + str(err["url"]))

        lines.extend(["", "=" * 60, "Generated by VULNIX", "=" * 60])

        report_text = "\n".join(lines)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report_text)

        return report_text

    def generate_sarif_report(
        self,
        scan_result: ScanResult,
        output_file: Optional[str] = None,
    ) -> str:
        """Generate SARIF report for GitHub/Jira integration."""
        severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }

        rules = []
        results = []

        for finding in scan_result.findings:
            rule_id = "vulnix-" + finding.type

            if rule_id not in [r["id"] for r in rules]:
                rules.append({
                    "id": rule_id,
                    "name": finding.type.replace("_", " ").title(),
                    "shortDescription": {"text": finding.description or finding.type},
                })

            results.append({
                "ruleId": rule_id,
                "level": severity_map.get(finding.severity, "note"),
                "message": {"text": finding.type + ": " + (finding.description or finding.url)},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.url},
                        "region": {"startLine": 1}
                    }
                }],
            })

        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "VULNIX", "version": "1.0.0", "rules": rules}},
                "results": results,
            }]
        }

        sarif_json = json.dumps(sarif, indent=2, ensure_ascii=False)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(sarif_json)

        return sarif_json

"""
VULNIX - Web Vulnerability Scanner
Security Headers Analyzer Module
"""

import re
from typing import Dict, List, Optional, Any
import httpx

from core.request_engine import RequestEngine
from config.settings import SECURITY_HEADERS


class SecurityHeadersAnalyzer:
    """Analyze security headers in HTTP responses."""

    REQUIRED_HEADERS = SECURITY_HEADERS.REQUIRED
    RECOMMENDED_HEADERS = SECURITY_HEADERS.RECOMMENDED

    HEADER_DESCRIPTIONS = {
        "Content-Security-Policy": "Prevents XSS attacks by controlling resource loading",
        "X-Frame-Options": "Prevents clickjacking attacks",
        "Strict-Transport-Security": "Enforces HTTPS connections",
        "X-Content-Type-Options": "Prevents MIME type sniffing",
        "X-XSS-Protection": "Browser XSS filtering (legacy)",
        "Referrer-Policy": "Controls referrer information",
        "Permissions-Policy": "Controls browser features",
    }

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.results: List[Dict[str, Any]] = []

    def _analyze_header(
        self, header_name: str, header_value: Optional[str]
    ) -> Dict[str, Any]:
        """Analyze a single security header."""
        if not header_value:
            return {
                "header": header_name,
                "present": False,
                "severity": "medium",
                "description": self.HEADER_DESCRIPTIONS.get(header_name, ""),
                "recommendation": "Implement this security header",
            }

        return {
            "header": header_name,
            "present": True,
            "value": header_value,
            "severity": "info",
            "description": self.HEADER_DESCRIPTIONS.get(header_name, ""),
        }

    def analyze_response(self, response: httpx.Response) -> List[Dict[str, Any]]:
        """Analyze all security headers in response."""
        findings = []

        headers: Dict[str, str] = {}

        for header_name, header_value in response.headers.items():
            headers[header_name.lower()] = header_value

        for required_header in self.REQUIRED_HEADERS:
            header_name_lower = required_header.lower()
            if header_name_lower in headers:
                header_value = headers[header_name_lower]
            else:
                header_value = None

            analysis = self._analyze_header(required_header, header_value)
            findings.append(analysis)

        return findings

    async def analyze_url(self, url: str) -> List[Dict[str, Any]]:
        """Analyze security headers of a URL."""
        response = await self.request_engine.get(url)

        if not response:
            return [
                {
                    "header": "Connection",
                    "present": False,
                    "severity": "low",
                    "description": "Could not connect to target",
                    "recommendation": "Check if URL is accessible",
                }
            ]

        return self.analyze_response(response)

    def generate_report(self, findings: List[Dict[str, Any]]) -> str:
        """Generate a text report of findings."""
        report_lines = ["Security Headers Analysis", "=" * 30, ""]

        for finding in findings:
            status = "✓" if finding["present"] else "✗"
            header = finding["header"]

            if finding["present"]:
                value = finding.get("value", "")
                report_lines.append(f"{status} {header}: {value}")
            else:
                recommendation = finding.get("recommendation", "")
                report_lines.append(f"{status} {header}: {recommendation}")

        return "\n".join(report_lines)

    def get_results(self) -> List[Dict[str, Any]]:
        """Get all findings."""
        return self.results

    def reset(self) -> None:
        """Reset analyzer state."""
        self.results.clear()
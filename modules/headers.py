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

    CORS_CONFIGURATIONS = {
        "allow_origin": {
            "*": {"severity": "high", "description": "Wildcard allowed - any origin can access"},
        },
        "allow_credentials": {
            True: {"severity": "critical", "description": "Credentials allowed with wildcard origin"},
        },
        "allow_methods": {
            "*": {"severity": "medium", "description": "All methods allowed"},
        },
    }

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.results: List[Dict[str, Any]] = {}
        self.all_headers: Dict[str, str] = {}

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

    def _analyze_cors(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze CORS configuration."""
        cors = {
            "present": False,
            "issues": [],
            "severity": "info",
        }

        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials")
        acam = headers.get("access-control-allow-methods")
        acah = headers.get("access-control-allow-headers")

        if acao or acac:
            cors["present"] = True
            cors["allow_origin"] = acao
            cors["allow_credentials"] = acac
            cors["allow_methods"] = acam
            cors["allow_headers"] = acah

            if acao == "*":
                cors["issues"].append(
                    {
                        "type": "wildcard_origin",
                        "severity": "high",
                        "description": "Wildcard origin allows any website to access",
                    }
                )
                cors["severity"] = "high"

            if acac == "true" and acao == "*":
                cors["issues"].append(
                    {
                        "type": "credentials_with_wildcard",
                        "severity": "critical",
                        "description": "Credentials allowed with wildcard origin",
                    }
                )
                cors["severity"] = "critical"

            if acam and acam == "*":
                cors["issues"].append(
                    {
                        "type": "wildcard_methods",
                        "severity": "medium",
                        "description": "All HTTP methods allowed",
                    }
                )

        return cors

    def _analyze_hsts(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze HSTS configuration."""
        hsts = {"present": False, "issues": [], "severity": "info"}

        strict_transport = headers.get("strict-transport-security")

        if strict_transport:
            hsts["present"] = True
            hsts["value"] = strict_transport
            hsts["raw"] = strict_transport

            directives = {}
            for directive in strict_transport.split(";"):
                directive = directive.strip()
                if "=" in directive:
                    key, value = directive.split("=", 1)
                    directives[key.strip().lower()] = value.strip()
                else:
                    directives[directive.lower()] = True

            hsts["directives"] = directives

            max_age = directives.get("max-age")
            if max_age:
                try:
                    seconds = int(max_age)
                    days = seconds / 86400
                    if days < 180:
                        hsts["issues"].append(
                            {
                                "type": "short_max_age",
                                "severity": "medium",
                                "description": f"Max-age is {days:.0f} days (recommended: 180+ days)",
                            }
                        )
                except ValueError:
                    pass

            if "includesubdomains" not in directives:
                hsts["issues"].append(
                    {
                        "type": "missing_include_subdomains",
                        "severity": "medium",
                        "description": "includeSubDomains directive missing",
                    }
                )

            if "preload" not in directives:
                hsts["issues"].append(
                    {
                        "type": "missing_preload",
                        "severity": "low",
                        "description": "preload directive missing (for HSTS preload list)",
                    }
                )

        return hsts

    def _analyze_csp(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze Content Security Policy."""
        csp = {"present": False, "issues": [], "severity": "info"}

        content_policy = headers.get("content-security-policy")

        if content_policy:
            csp["present"] = True
            csp["raw"] = content_policy

            directives = {}
            for directive in content_policy.split(";"):
                directive = directive.strip()
                if " " in directive:
                    name, values = directive.split(" ", 1)
                    directives[name.strip().lower()] = values.strip()

            csp["directives"] = directives

            for name, values in directives.items():
                if "'unsafe-inline'" in values:
                    csp["issues"].append(
                        {
                            "type": "unsafe_inline",
                            "directive": name,
                            "severity": "medium",
                            "description": f"{name} allows unsafe-inline",
                        }
                    )

                if "'unsafe-eval'" in values:
                    csp["issues"].append(
                        {
                            "type": "unsafe_eval",
                            "directive": name,
                            "severity": "high",
                            "description": f"{name} allows unsafe-eval",
                        }
                    )

                if "*" in values and name not in ["style-src", "font-src"]:
                    csp["issues"].append(
                        {
                            "type": "wildcard_source",
                            "directive": name,
                            "severity": "medium",
                            "description": f"{name} uses wildcard",
                        }
                    )

        return csp

    def _analyze_privacy(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze privacy-related headers."""
        privacy = {"issues": [], "severity": "info"}

        referrer_policy = headers.get("referrer-policy")
        if referrer_policy:
            privacy["referrer_policy"] = referrer_policy
            if referrer_policy in ["no-referrer", "same-origin"]:
                privacy["issues"].append(
                    {
                        "type": "referrer_policy",
                        "severity": "low",
                        "description": f"Referrer-Policy: {referrer_policy}",
                    }
                )
        else:
            privacy["issues"].append(
                {
                    "type": "missing_referrer_policy",
                    "severity": "low",
                    "description": "Referrer-Policy header missing",
                }
            )

        permissions_policy = headers.get("permissions-policy")
        if permissions_policy:
            privacy["permissions_policy"] = permissions_policy
        else:
            privacy["issues"].append(
                {
                    "type": "missing_permissions_policy",
                    "severity": "low",
                    "description": "Permissions-Policy header missing",
                }
            )

        return privacy

    def analyze_response(self, response: httpx.Response) -> Dict[str, Any]:
        """Analyze all security headers in response."""
        findings: List[Dict[str, Any]] = []
        headers: Dict[str, str] = {}

        for header_name, header_value in response.headers.items():
            headers[header_name.lower()] = header_value

        self.all_headers = headers

        for required_header in self.REQUIRED_HEADERS:
            header_name_lower = required_header.lower()
            if header_name_lower in headers:
                header_value = headers[header_name_lower]
            else:
                header_value = None

            analysis = self._analyze_header(required_header, header_value)
            findings.append(analysis)

        cors = self._analyze_cors(headers)
        hsts = self._analyze_hsts(headers)
        csp = self._analyze_csp(headers)
        privacy = self._analyze_privacy(headers)

        self.results = {
            "security_headers": findings,
            "cors": cors,
            "hsts": hsts,
            "csp": csp,
            "privacy": privacy,
            "all_headers": list(headers.keys()),
        }

        return self.results

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze security headers of a URL."""
        response = await self.request_engine.get(url)

        if not response:
            return {
                "error": "Could not connect to target",
                "url": url,
            }

        return self.analyze_response(response)

    def analyze_full_response(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze headers without making a request."""
        normalized = {k.lower(): v for k, v in headers.items()}
        self.all_headers = normalized

        findings = []
        for required_header in self.REQUIRED_HEADERS:
            header_value = normalized.get(required_header.lower())
            analysis = self._analyze_header(required_header, header_value)
            findings.append(analysis)

        cors = self._analyze_cors(normalized)
        hsts = self._analyze_hsts(normalized)
        csp = self._analyze_csp(normalized)
        privacy = self._analyze_privacy(normalized)

        self.results = {
            "security_headers": findings,
            "cors": cors,
            "hsts": hsts,
            "csp": csp,
            "privacy": privacy,
            "all_headers": list(normalized.keys()),
        }

        return self.results

    def generate_report(self, findings: Dict[str, Any]) -> str:
        """Generate a text report of findings."""
        report_lines = ["Security Headers Analysis", "=" * 30, ""]

        security_headers = findings.get("security_headers", [])
        for finding in security_headers:
            status = "✓" if finding["present"] else "✗"
            header = finding["header"]

            if finding["present"]:
                value = finding.get("value", "")
                report_lines.append(f"{status} {header}: {value}")
            else:
                recommendation = finding.get("recommendation", "")
                report_lines.append(f"{status} {header}: {recommendation}")

        cors = findings.get("cors", {})
        if cors.get("present"):
            report_lines.append("")
            report_lines.append("CORS Analysis:")
            for issue in cors.get("issues", []):
                report_lines.append(f"  - [{issue['severity']}] {issue['description']}")

        hsts = findings.get("hsts", {})
        if hsts.get("present"):
            report_lines.append("")
            report_lines.append("HSTS Analysis:")
            report_lines.append(f"  Value: {hsts.get('raw', '')}")
            for issue in hsts.get("issues", []):
                report_lines.append(f"  - [{issue['severity']}] {issue['description']}")

        return "\n".join(report_lines)

    def get_results(self) -> Dict[str, Any]:
        """Get all findings."""
        return self.results

    def get_all_headers(self) -> Dict[str, str]:
        """Get all headers from last analysis."""
        return self.all_headers

    def reset(self) -> None:
        """Reset analyzer state."""
        self.results.clear()
        self.all_headers.clear()
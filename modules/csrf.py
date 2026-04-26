"""
VULNIX - Web Vulnerability Scanner
CSRF Detection Module
"""

import re
from typing import Dict, List, Optional, Any
import httpx

from core.request_engine import RequestEngine


class CSRFDetector:
    """Detect Cross-Site Request Forgery vulnerabilities."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.results: List[Dict[str, Any]] = []

    def _check_csrf_token(self, form_html: str) -> bool:
        """Check if form has CSRF token."""
        csrf_patterns = [
            r'<input[^>]*name=["\']csrf[^"\']*["\']',
            r'<input[^>]*name=["\']_token["\']',
            r'<input[^>]*name=["\']authenticity_token["\']',
            r'<input[^>]*name=["\']__RequestVerificationToken["\']',
            r'<input[^>]*name=["\']xsrf["\']',
            r'<input[^>]*name=["\']_csrf["\']',
        ]

        for pattern in csrf_patterns:
            if re.search(pattern, form_html, re.IGNORECASE):
                return True
        return False

    def _check_referer(self, response: httpx.Response) -> bool:
        """Check if response checks Referer header."""
        if not response:
            return False

        headers = {k.lower(): v.lower() for k, v in response.headers.items()}

        set_cookie = headers.get("set-cookie", "")
        if "referrer-policy" in set_cookie or "x-src" in set_cookie:
            return True

        return False

    def _check_same_origin(self, response: httpx.Response) -> bool:
        """Check SameSite cookie attribute."""
        if not response:
            return False

        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        set_cookie = headers.get("set-cookie", "")

        if "samesite" in set_cookie.lower():
            return True

        return False

    async def analyze_form(self, url: str, form_html: str) -> Dict[str, Any]:
        """Analyze a form for CSRF protection."""
        has_csrf_token = self._check_csrf_token(form_html)

        issues = []
        if not has_csrf_token:
            issues.append("Missing CSRF token in form")

        response = await self.request_engine.get(url)

        if response:
            if not self._check_same_origin(response):
                issues.append("Missing SameSite cookie attribute")

        result = {
            "url": url,
            "has_csrf_token": has_csrf_token,
            "issues": issues,
            "severity": "medium" if issues else "info",
            "type": "csrf",
        }

        if issues:
            self.results.append(result)

        return result

    async def scan_endpoint(self, url: str) -> List[Dict[str, Any]]:
        """Scan endpoint for CSRF vulnerabilities."""
        results = []

        response = await self.request_engine.get(url)

        if not response:
            return results

        issues = []

        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        set_cookie = headers.get("set-cookie", "")

        if set_cookie:
            if "samesite" not in set_cookie.lower():
                issues.append("SameSite attribute not set")

        if "x-frame-options" not in headers:
            issues.append("Missing X-Frame-Options header")

        if issues:
            results.append({
                "url": url,
                "type": "csrf",
                "severity": "medium",
                "description": "; ".join(issues),
            })

        self.results.extend(results)
        return results

    def get_results(self) -> List[Dict[str, Any]]:
        """Get all findings."""
        return self.results

    def reset(self) -> None:
        """Reset detector state."""
        self.results.clear()
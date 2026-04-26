"""
VULNIX - Web Vulnerability Scanner
Authentication Issues Detection Module
"""

import re
from typing import Dict, List, Optional, Any
import httpx

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


class AuthDetector:
    """Detect authentication-related vulnerabilities."""

    WEAK_PASSWORD_POLICIES = [
        r"password\s*<\s*input",
        r"minlength\s*=\s*[\"']?\\d{1,3}",
        r"minlength\s*=\s*1",
        r"password\s*required",
    ]

    SESSION_PATTERNS = [
        r"session_id",
        r"sessionid",
        r"sess_id",
        r"auth_token",
    ]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.results: List[Dict[str, Any]] = []
        self.error_collector = ModuleErrorCollector("auth")

    async def check_weak_password_policy(self, url: str) -> Dict[str, Any]:
        """Check for weak password policies."""
        response = await self.request_engine.get(url)

        if not response:
            return {}

        has_password_field = bool(
            re.search(r'<input[^>]*type=["\']password["\'][^>]*>', response.text, re.IGNORECASE)
        )

        min_length = None
        min_length_match = re.search(
            r'<input[^>]*type=["\']password["\'][^>]*minlength=["\']?(\d+)',
            response.text,
            re.IGNORECASE,
        )
        if min_length_match:
            min_length = int(min_length_match.group(1))

        if has_password_field:
            if not min_length or min_length < 8:
                return {
                    "type": "broken_auth",
                    "subtype": "weak_password_policy",
                    "severity": "medium",
                    "description": "Weak password policy: minimum length less than 8 characters",
                }

        return {}

    async def check_session_fixation(self, url: str) -> Dict[str, Any]:
        """Check for session fixation vulnerabilities."""
        response = await self.request_engine.get(url)

        if not response:
            return {}

        headers = {k.lower(): v for k, v in response.headers.items()}
        set_cookie = headers.get("set-cookie", "")
        if not set_cookie:
            return {}

        cookie_lower = set_cookie.lower()
        results = {}

        if "httponly" not in cookie_lower:
            results["httponly"] = False
        if "secure" not in cookie_lower:
            results["secure"] = False
        if "samesite" not in cookie_lower:
            results["samesite"] = False
        if "secure" not in cookie_lower and "httponly" not in cookie_lower:
            results["session_fixation"] = True

        if results:
            return {
                "type": "broken_auth",
                "subtype": "session_fixation",
                "severity": "high",
                "description": "Session cookie missing security flags",
                "details": results,
            }

        return {}

    async def check_default_credentials(self, url: str) -> Dict[str, Any]:
        """Check for default credentials."""
        common_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("administrator", "administrator"),
        ]

        login_form_url = url

        for username, password in common_creds:
            try:
                response = await self.request_engine.post(
                    login_form_url,
                    data={"username": username, "password": password},
                )

                if response and response.status_code == 200:
                    if "success" in response.text.lower():
                        return {
                            "type": "broken_auth",
                            "subtype": "default_credentials",
                            "severity": "critical",
                            "description": f"Default credentials work: {username}/{password}",
                        }

            except Exception as e:
                self.error_collector.add(login_form_url, e, "check_default_credentials")

        return {}

    async def check_password_reset(self, url: str) -> List[Dict[str, Any]]:
        """Check password reset flow for issues."""
        results = []

        reset_urls = [
            url + "/reset",
            url + "/forgot",
            url + "/password-reset",
            url + "/forgot-password",
            url + "?reset=true",
        ]

        for reset_url in reset_urls[:3]:
            try:
                response = await self.request_engine.get(reset_url)

                if response and response.status_code == 200:
                    if "token" not in str(response.url).lower():
                        results.append({
                            "type": "broken_auth",
                            "subtype": "weak_password_reset",
                            "severity": "medium",
                            "description": "Password reset without secure token",
                        })

            except Exception as e:
                self.error_collector.add(reset_url, e, "check_password_reset")

        return results

    async def check_twofa_bypass(self, url: str) -> Dict[str, Any]:
        """Check if 2FA can be bypassed."""
        try:
            response = await self.request_engine.post(
                url,
                data={"code": "000000"},
            )

            if response:
                if "invalid" in response.text.lower():
                    if "code" in response.text.lower():
                        return {
                            "type": "broken_auth",
                            "subtype": "weak_2fa",
                            "severity": "medium",
                            "description": "Weak 2FA implementation",
                        }

        except Exception as e:
            self.error_collector.add(url, e, "check_twofa_bypass")

        return {}

    async def check_authentication_flow(self, url: str) -> List[Dict[str, Any]]:
        """Check complete authentication flow."""
        results = []

        weak_pass = await self.check_weak_password_policy(url)
        if weak_pass:
            results.append(weak_pass)

        session_fix = await self.check_session_fixation(url)
        if session_fix:
            results.append(session_fix)

        default_creds = await self.check_default_credentials(url)
        if default_creds:
            results.append(default_creds)

        pwd_reset = await self.check_password_reset(url)
        results.extend(pwd_reset[:2])

        self.results.extend(results)
        return results

    def check_insecure_login_form(self, url: str, html: str) -> Dict[str, Any]:
        """Check if login form is served over HTTP."""
        issues = []

        if url.startswith("http://"):
            if "password" in html.lower():
                issues.append("Login form served over HTTP")

        if 'type="password"' in html:
            if 'type="password"' in html:
                if 'autocomplete="off"' not in html.lower():
                    issues.append("Password field with autocomplete enabled")

        if issues:
            return {
                "type": "broken_auth",
                "subtype": "insecure_login",
                "severity": "medium",
                "description": "; ".join(issues),
            }

        return {}

    def get_results(self) -> List[Dict[str, Any]]:
        """Get all findings."""
        return self.results

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()

    def reset(self) -> None:
        """Reset detector state."""
        self.results.clear()
        self.error_collector.clear()

"""
VULNIX - Parameter Fuzzing & HTTP Attack Modules
For bug bounty hunting
"""

import asyncio
import re
from typing import Dict, List, Optional, Any
import httpx

from core.request_engine import RequestEngine
from core.fuzzing import Fuzzer
from core.error_collector import ModuleErrorCollector


class ParameterBruteforcer:
    """Brute force hidden parameters."""

    COMMON_PARAMS = [
        "id", "user_id", "account_id", "page", "q", "query", "search", "s",
        "id", "uid", "user", "username", "email", "token", "key", "api_key",
        "redirect", "return", "url", "next", "dest", "destination",
        "file", "filename", "doc", "document", "path", "page", "controller",
        "admin", "login", "logout", "test", "debug", "code", "view", "action",
        "module", "do", "func", "option", "choice", "select", "sort", "order",
        "category", "filter", "search", "tag", "topic", "thread", "post", "slug",
        "format", "type", "list", "limit", "offset", "start", "end", "date", "from",
        "price", "amount", "query", "term", "string", "val", "value", "num",
        "id", "ID", "ID", "no", "n", "item", "mode", "cmd", "exec", "s",
    ]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("parameter_bruteforce")

    async def fuzz_parameters(
        self, url: str, wordlist: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Fuzz parameters on URL."""
        if wordlist is None:
            wordlist = self.COMMON_PARAMS

        found = []

        for param in wordlist[:30]:
            test_url = f"{url}?{param}=test"
            try:
                response = await self.request_engine.get(test_url)

                if response and response.status_code != 404:
                    found.append({
                        "parameter": param,
                        "status": response.status_code,
                        "url": test_url,
                    })

            except Exception as e:
                self.error_collector.add(test_url, e, "fuzz_param")

        return found

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class HTTPMethodTampering:
    """Test HTTP method tampering."""

    METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.results: List[Dict[str, Any]] = []
        self.error_collector = ModuleErrorCollector("http_method_tampering")

    async def test_methods(self, url: str) -> Dict[str, Any]:
        """Test different HTTP methods."""
        results = {}

        for method in self.METHODS[:8]:
            try:
                if method == "TRACE":
                    continue

                response = await self.request_engine.request(
                    method, url, allow_redirects=False
                )

                if response:
                    results[method] = {
                        "status": response.status_code,
                        "allowed": True,
                    }

            except Exception as e:
                self.error_collector.add(url, e, f"test_method:{method}")

        return results

    async def test_post_to_get(self, url: str, data: Dict) -> Dict[str, Any]:
        """Test converting POST to GET."""
        try:
            response = await self.request_engine.get(url, params=data)

            if response:
                self.results.append({
                    "type": "method_tampering",
                    "url": url,
                    "description": "GET with POST data works - possible method override",
                    "severity": "low",
                })

        except Exception as e:
            self.error_collector.add(url, e, "test_post_to_get")

        return self.results

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class CORSAnalyzer:
    """Analyze CORS configurations."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.results: List[Dict[str, Any]] = []
        self.error_collector = ModuleErrorCollector("cors")

    async def analyze(self, url: str) -> List[Dict[str, Any]]:
        """Analyze CORS configuration."""
        findings = []

        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "*",
        ]

        for origin in test_origins:
            try:
                response = await self.request_engine.get(
                    url,
                    headers={"Origin": origin},
                )

                if response:
                    acao = response.headers.get("access-control-allow-origin", "")
                    acac = response.headers.get("access-control-allow-credentials", "")

                    if acao == origin or acao == "*":
                        findings.append({
                            "type": "cors_misconfiguration",
                            "url": url,
                            "header": "Access-Control-Allow-Origin",
                            "value": acao,
                            "severity": "high",
                            "description": f"CORS allows origin: {origin}",
                        })

                    if acac == "true" and (acao == "*" or origin in acao):
                        findings.append({
                            "type": "cors_misconfiguration",
                            "url": url,
                            "header": "Access-Control-Allow-Credentials",
                            "value": acac,
                            "severity": "critical",
                            "description": "CORS allows credentials with wildcard origin",
                        })

            except Exception as e:
                self.error_collector.add(url, e, f"analyze_origin:{origin}")

        self.results = findings
        return findings

    def get_results(self) -> List[Dict[str, Any]]:
        """Get all findings."""
        return self.results

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class JWTAnalyzer:
    """Analyze JWT tokens for vulnerabilities."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("jwt")

    async def check_jwt(self, url: str) -> List[Dict[str, Any]]:
        """Check for JWT vulnerabilities."""
        findings = []
        baseline = await self.request_engine.get(url)
        baseline_status = baseline.status_code if baseline else None
        baseline_text = baseline.text.lower() if baseline else ""

        attacks = [
            ("none", {"alg": "none"}),
            ("HS256", {"alg": "HS256", "secret": "secret"}),
            ("RS256", {"alg": "RS256"}),
        ]

        for name, payload in attacks:
            try:
                import base64
                import json

                header = base64.urlsafe_b64encode(
                    json.dumps({"alg": payload.get("alg", "RS256"), "typ": "JWT"}).encode()
                ).decode().rstrip("=")
                body = base64.urlsafe_b64encode(
                    json.dumps({"sub": "admin", "iat": 0}).encode()
                ).decode().rstrip("=")

                token = f"{header}.{body}."
                if name != "none":
                    token = f"{header}.{body}.invalid-signature"

                response = await self.request_engine.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                )

                if not response:
                    continue

                response_text = response.text.lower()
                auth_error_markers = ["invalid token", "jwt", "unauthorized", "forbidden", "signature"]
                baseline_auth_error = any(marker in baseline_text for marker in auth_error_markers)
                test_auth_error = any(marker in response_text for marker in auth_error_markers)

                accepted_status_jump = (
                    baseline_status in [401, 403] and response.status_code in [200, 201, 202]
                )
                removed_auth_error = baseline_auth_error and not test_auth_error

                if accepted_status_jump or removed_auth_error:
                    findings.append({
                        "type": "jwt_weak",
                        "url": url,
                        "attack": name,
                        "severity": "high",
                        "description": f"JWT {name} token appears accepted without proper verification",
                        "evidence": f"baseline_status={baseline_status}, test_status={response.status_code}",
                    })

            except Exception as e:
                self.error_collector.add(url, e, f"check_jwt_attack:{name}")

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class HTTPHeaderInjection:
    """Test for HTTP header injection."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("http_header_injection")

    async def test_header_injection(
        self, url: str
    ) -> List[Dict[str, Any]]:
        """Test for CRLF injection."""
        findings = []

        payloads = [
            "%0d%0aX-Injected: test",
            "%0d%0aX-Forwarded-Host: evil.com",
            "%0aX-Custom: test",
        ]

        for payload in payloads:
            try:
                response = await self.request_engine.get(
                    url,
                    headers={"X-Forwarded-Host": payload},
                )

                if response:
                    if "x-injected" in response.headers or "x-custom" in response.headers:
                        findings.append({
                            "type": "header_injection",
                            "url": url,
                            "payload": payload,
                            "severity": "high",
                            "description": "HTTP Header Injection possible",
                        })

            except Exception as e:
                self.error_collector.add(url, e, "test_header_injection")

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class OpenRedirectTester:
    """Test for open redirect vulnerabilities."""

    REDIRECT_MARKERS = [
        "javascript:",
        "//google.com",
        "///google.com",
        "https://google.com",
        "..",
        "/%2e%2e",
        "/%2e./%2e./%2e.",
        "redirect",
        "next",
        "url",
        "dest",
        "destination",
        "return",
        "returnUrl",
        "continue",
        "callback",
    ]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("open_redirect")

    async def test_redirects(
        self, url: str, params: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Test for open redirects."""
        if params is None:
            params = ["redirect", "url", "next", "dest", "destination"]

        findings = []
        attacker_target = "https://evil.example"

        for param in params:
            for marker in [attacker_target, "//evil.example", "///evil.example"]:
                try:
                    test_url = f"{url}?{param}={marker}"

                    response = await self.request_engine.request(
                        "GET",
                        test_url,
                        allow_redirects=False,
                    )

                    if not response:
                        continue

                    status = response.status_code
                    location = response.headers.get("location", "")
                    location_lower = location.lower()

                    if status in [301, 302, 303, 307, 308] and (
                        location_lower.startswith("https://evil.example")
                        or location_lower.startswith("//evil.example")
                    ):
                        findings.append({
                            "type": "open_redirect",
                            "url": url,
                            "parameter": param,
                            "payload": marker,
                            "severity": "medium",
                            "description": f"Open redirect via {param}",
                            "evidence": f"status={status}, location={location}",
                        })

                except Exception as e:
                    self.error_collector.add(test_url, e, "test_redirect")

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class ServerSideRequestForgery:
    """Test for SSRF vulnerabilities."""

    INTERNAL_TARGETS = [
        "http://localhost",
        "http://127.0.0.1",
        "http://169.254.169.254",
        "http://metadata.google.internal",
        "http://metadata.google",
    ]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("ssrf")

    async def test_ssrf(
        self, url: str, params: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Test for SSRF."""
        if params is None:
            params = ["url", "uri", "src", "dest", "redirect", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir", "show", "navigation", "open", "file", "document", "folder", "pg", "style", "doc", "img", "source", "target", "name", "call", "form", "jump", "code", "link", "ref", "go", "value"]

        findings = []
        error_markers = [
            "connection refused",
            "connection timed out",
            "failed to connect",
            "name or service not known",
            "no route to host",
            "unable to resolve host",
            "dial tcp",
        ]
        metadata_markers = ["instance-id", "ami-id", "access_key_id", "iam/security-credentials"]

        for param in params[:20]:
            baseline = await self.request_engine.get(f"{url}?{param}=https://example.com/")
            baseline_status = baseline.status_code if baseline else None
            baseline_text = baseline.text.lower() if baseline else ""

            for target in self.INTERNAL_TARGETS[:3]:
                try:
                    test_url = f"{url}?{param}={target}"

                    response = await self.request_engine.get(test_url)

                    if not response:
                        continue

                    response_text = response.text.lower()
                    has_target_evidence = target.lower() in response_text
                    has_metadata_evidence = any(marker in response_text for marker in metadata_markers)
                    has_backend_fetch_error = any(marker in response_text for marker in error_markers) and not any(
                        marker in baseline_text for marker in error_markers
                    )
                    status_changed = baseline_status is not None and response.status_code != baseline_status

                    if has_metadata_evidence or (status_changed and (has_target_evidence or has_backend_fetch_error)):
                        findings.append({
                            "type": "ssrf",
                            "url": url,
                            "parameter": param,
                            "payload": target,
                            "severity": "critical",
                            "description": f"Possible SSRF via {param}",
                            "evidence": f"baseline_status={baseline_status}, test_status={response.status_code}",
                        })

                except Exception as e:
                    self.error_collector.add(test_url, e, "test_ssrf")

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()

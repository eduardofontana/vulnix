"""
VULNIX - Proxy Configuration Module
Support for proxy rotation and testing
"""

import asyncio
import os
from typing import Dict, List, Optional, Any, Callable
from urllib.parse import urlparse

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


HTTP_PROXYS = [
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "http://127.0.0.1:3128",
    "http://localhost:3128",
]

HTTPS_PROXYS = [
    "https://127.0.0.1:8080",
    "https://localhost:8080",
    "https://127.0.0.1:3128",
    "https://localhost:3128",
]


class ProxyConfig:
    """Manage proxy configuration for scanning."""

    def __init__(
        self,
        http_proxy: Optional[str] = None,
        https_proxy: Optional[str] = None,
        no_proxy: Optional[str] = None,
    ):
        self.http_proxy = http_proxy or os.environ.get("HTTP_PROXY")
        self.https_proxy = https_proxy or os.environ.get("HTTPS_PROXY")
        self.no_proxy = no_proxy or os.environ.get("NO_PROXY", "localhost,127.0.0.1")

        self.enabled = bool(self.http_proxy or self.https_proxy)

    def to_dict(self) -> Dict[str, Optional[str]]:
        """Export proxy configuration as dict."""
        return {
            "http_proxy": self.http_proxy,
            "https_proxy": self.https_proxy,
            "no_proxy": self.no_proxy,
            "enabled": self.enabled,
        }

    @classmethod
    def from_env(cls) -> "ProxyConfig":
        """Create proxy config from environment variables."""
        return cls(
            http_proxy=os.environ.get("HTTP_PROXY"),
            https_proxy=os.environ.get("HTTPS_PROXY"),
            no_proxy=os.environ.get("NO_PROXY"),
        )


class ProxyTester:
    """Test proxy connectivity and anonymity."""

    TEST_URLS = [
        "http://httpbin.org/ip",
        "https://httpbin.org/ip",
        "http://api.ipify.org?format=json",
        "https://api.ipify.org?format=json",
    ]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("proxy")

    async def test_proxy(self, proxy_url: str) -> Dict[str, Any]:
        """Test if a proxy is working."""
        result = {
            "proxy": proxy_url,
            "working": False,
            "latency_ms": 0,
            "error": None,
            "anonymity": "unknown",
        }

        try:
            import time
            start = time.time()

            test_req = RequestEngine(
                proxy=proxy_url,
                timeout=30,
            )

            for url in self.TEST_URLS[:2]:
                try:
                    response = await test_req.get(url)

                    if response and response.status_code == 200:
                        result["working"] = True
                        result["latency_ms"] = int((time.time() - start) * 1000)
                        break

                except Exception as e:
                    result["error"] = str(e)
                    continue

            await test_req.close()

        except Exception as e:
            self.error_collector.add(proxy_url, e, "test_proxy")
            result["error"] = str(e)

        return result

    async def test_transparent(
        self,
        target: str,
        proxy: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Test if proxy provides anonymity."""
        result = {
            "transparent": False,
            "webRTC_leak": False,
            "dns_leak": False,
        }

        try:
            engine = RequestEngine(
                proxy=proxy,
                timeout=30,
            )

            headers_to_check = [
                "x-forwarded-for",
                "x-real-ip",
                "via",
                "forwarded",
            ]

            for url in self.TEST_URLS[:1]:
                try:
                    response = await engine.get(url)

                    if response and hasattr(response, "headers"):
                        headers = {k.lower(): v for k, v in response.headers.items()}

                        for header in headers_to_check:
                            if header in headers:
                                result["transparent"] = True
                                break

                except Exception as e:
                    self.error_collector.add(url, e, "test_transparent")

            await engine.close()

        except Exception as e:
            self.error_collector.add("transparent_test", e, "test_transparent")

        return result

    async def scan(
        self,
        target: str,
        proxy: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Analyze proxy configuration."""
        findings = []

        if not proxy:
            env_proxy = ProxyConfig.from_env()
            if env_proxy.enabled:
                proxy = env_proxy.http_proxy or env_proxy.https_proxy

        if not proxy:
            return findings

        test_result = await self.test_proxy(proxy)

        if test_result.get("working"):
            findings.append({
                "type": "proxy_working",
                "severity": "info",
                "description": f"Proxy {proxy} is working (latency: {test_result.get('latency_ms')}ms)",
                "details": test_result,
            })

            if proxy and proxy.startswith("http://"):
                findings.append({
                    "type": "proxy_unencrypted",
                    "severity": "medium",
                    "description": "HTTP proxy sends traffic unencrypted",
                    "details": {"proxy": proxy},
                })

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get collected errors."""
        return self.error_collector.all()
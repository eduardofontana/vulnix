"""
VULNIX - Web Vulnerability Scanner
XSS Detection Module
"""

import re
import asyncio
from typing import Dict, List, Tuple, Optional, Any
import html
import httpx

from core.request_engine import RequestEngine
from core.fuzzing import Fuzzer
from core.error_collector import ModuleErrorCollector
from config.settings import XSS_PAYLOADS


class XSSDetector:
    """Reflected XSS vulnerability detector."""

    def __init__(
        self,
        request_engine: RequestEngine,
        fuzzer: Fuzzer,
    ):
        self.request_engine = request_engine
        self.fuzzer = fuzzer
        self.results: List[Dict[str, Any]] = []
        self.error_collector = ModuleErrorCollector("xss")

    def _check_reflection(self, response: httpx.Response, payload: str) -> bool:
        """Check if payload is reflected in response."""
        if not response:
            return False

        try:
            response_text = response.text
        except Exception as e:
            self.error_collector.add("unknown", e, "check_reflection_read_response")
            return False

        decoded_payload = html.unescape(payload)

        escaped_payloads = [
            payload,
            decoded_payload,
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace("<script>", "").replace("</script>", ""),
        ]

        for check_payload in escaped_payloads:
            if check_payload in response_text:
                return True

        return False

    def _check_dom_xss(self, response: httpx.Response) -> bool:
        """Check for DOM XSS indicators in response."""
        if not response:
            return False

        try:
            response_text = response.text.lower()
        except Exception as e:
            self.error_collector.add("unknown", e, "check_dom_xss_read_response")
            return False

        dom_sinks = [
            "innerhtml",
            "innerhtml=",
            "inner_html=",
            "outerhtml",
            "outerhtml=",
            ".html(",
            ".innerHTML(",
        ]

        for sink in dom_sinks:
            if sink in response_text:
                return True

        return False

    async def test_parameter(
        self,
        url: str,
        param: str,
        method: str = "GET",
    ) -> List[Dict[str, Any]]:
        """Test a parameter for XSS vulnerabilities."""
        findings = []

        baseline_response, _ = await self.fuzzer._get_baseline(url, {param: "test"})

        for payload in XSS_PAYLOADS.REFLECTED[:8]:
            try:
                if method.upper() == "GET":
                    response = await self.request_engine.get(url, params={param: payload})
                else:
                    response = await self.request_engine.post(url, data={param: payload})

                if not response:
                    continue

                is_vulnerable = False
                detection_method = ""

                if self._check_reflection(response, payload):
                    is_vulnerable = True
                    detection_method = "reflected"
                elif baseline_response:
                    baseline_len = len(baseline_response.text)
                    response_len = len(response.text)
                    if response_len > baseline_len * 1.5:
                        is_vulnerable = True
                        detection_method = "content_injection"

                if is_vulnerable:
                    findings.append(
                        {
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "method": method,
                            "detection": detection_method,
                            "severity": "medium",
                            "type": "xss",
                        }
                    )

            except Exception as e:
                self.error_collector.add(url, e, f"test_parameter_payload_{param}")

        self.results.extend(findings)
        return findings

    async def scan_endpoint(
        self,
        url: str,
        parameters: List[str],
        method: str = "GET",
    ) -> List[Dict[str, Any]]:
        """Scan an endpoint for XSS vulnerabilities."""
        all_findings = []

        for param in parameters:
            findings = await self.test_parameter(url, param, method)
            all_findings.extend(findings)

        return all_findings

    def get_results(self) -> List[Dict[str, Any]]:
        """Get all findings."""
        return self.results

    def reset(self) -> None:
        """Reset detector state."""
        self.results.clear()

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get structured detector errors."""
        return self.error_collector.all()

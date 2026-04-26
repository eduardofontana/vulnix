"""
VULNIX - Web Vulnerability Scanner
IDOR Detection Module
"""

import re
from typing import Dict, List, Optional, Any
import httpx

from core.request_engine import RequestEngine
from core.fuzzing import Fuzzer
from core.error_collector import ModuleErrorCollector


class IDORDetector:
    """Detect Insecure Direct Object Reference vulnerabilities."""

    PARAM_PATTERNS = [
        r"id",
        r"user_id",
        r"account_id",
        r"order_id",
        r"product_id",
        r"post_id",
        r"file_id",
        r"document_id",
        r"invoice_id",
        r"payment_id",
        r"transaction_id",
        r"customer_id",
        r"member_id",
        r"group_id",
        r"role_id",
        r"api_key",
        r"key",
        r"code",
    ]

    def __init__(self, request_engine: RequestEngine, fuzzer: Fuzzer):
        self.request_engine = request_engine
        self.fuzzer = fuzzer
        self.results: List[Dict[str, Any]] = []
        self.error_collector = ModuleErrorCollector("idor")

    def _is_sensitive_param(self, param: str) -> bool:
        """Check if parameter is potentially sensitive."""
        param_lower = param.lower()
        for pattern in self.PARAM_PATTERNS:
            if pattern in param_lower:
                return True
        return False

    def _extract_numeric_id(self, value: str) -> Optional[int]:
        """Extract numeric ID from parameter value."""
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    async def test_parameter_horizontical(
        self,
        url: str,
        param: str,
        original_value: str,
    ) -> List[Dict[str, Any]]:
        """Test horizontal privilege escalation."""
        results = []

        num_id = self._extract_numeric_id(original_value)
        if num_id is None:
            return results

        baseline_response = await self.request_engine.get(
            url, params={param: str(num_id)}
        )

        test_ids = [num_id + 1, num_id - 1, 9999, 1, 0]

        for test_id in test_ids:
            try:
                response = await self.request_engine.get(
                    url, params={param: str(test_id)}
                )

                if not response:
                    continue

                if response.status_code == 200:
                    content = response.text.lower()

                    if "permission" in content or "denied" in content:
                        continue

                    if not baseline_response:
                        continue

                    if baseline_response.status_code in [401, 403] and response.status_code == 200:
                        is_different = True
                    else:
                        is_different = self.fuzzer._diff_ratio(
                            baseline_response.text,
                            response.text
                        ) > 0.2

                    if is_different and test_id != num_id:
                        results.append({
                            "url": url,
                            "parameter": param,
                            "original_value": original_value,
                            "test_value": str(test_id),
                            "type": "idor",
                            "severity": "high",
                            "description": f"Possible IDOR: parameter '{param}' may allow access to other users' resources",
                        })

            except Exception as e:
                self.error_collector.add(url, e, f"test_parameter_horizontal_{param}")

        return results

    async def test_parameter_vertical(
        self,
        url: str,
        param: str,
        user_token: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Test vertical privilege escalation."""
        results = []

        if not user_token:
            return results

        try:
            response = await self.request_engine.get(
                url, params={param: "1"}, cookies=user_token
            )

            if response and response.status_code == 200:
                admin_patterns = [
                    r"admin",
                    r"dashboard",
                    r"/admin/",
                    r"administrator",
                    r"settings",
                ]

                content_lower = response.text.lower()
                for pattern in admin_patterns:
                    if pattern in content_lower:
                        results.append({
                            "url": url,
                            "type": "idor",
                            "subtype": "vertical_escalation",
                            "severity": "critical",
                            "description": f"Possible privilege escalation detected accessing admin resources",
                        })
                        break

        except Exception as e:
            self.error_collector.add(url, e, f"test_parameter_vertical_{param}")

        return results

    async def test_object_reference(
        self,
        url: str,
        sensitive_params: List[str],
    ) -> List[Dict[str, Any]]:
        """Test for insecure direct object references."""
        results = []

        url_parts = url.split("?")
        base_url = url_parts[0]

        for param in sensitive_params:
            test_response = await self.request_engine.get(base_url)

            if test_response:
                results.append({
                    "url": url,
                    "parameter": param,
                    "type": "idor",
                    "severity": "medium",
                    "description": f"Parameter '{param}' may be vulnerable to IDOR",
                })

        return results

    async def scan_endpoint(
        self,
        url: str,
        parameters: List[str],
    ) -> List[Dict[str, Any]]:
        """Scan endpoint for IDOR vulnerabilities."""
        results = []
        baseline = await self.request_engine.get(url)
        baseline_text = baseline.text.lower() if baseline else ""

        for param in parameters:
            if self._is_sensitive_param(param):
                test_response = await self.request_engine.get(
                    url, params={param: "1"}
                )

                if not test_response:
                    continue

                if test_response.status_code in [401, 403]:
                    continue

                test_text = test_response.text.lower()
                denied_markers = ["permission denied", "access denied", "unauthorized", "forbidden"]
                test_denied = any(marker in test_text for marker in denied_markers)

                if test_denied:
                    continue

                baseline_denied = any(marker in baseline_text for marker in denied_markers)
                body_diff = self.fuzzer._diff_ratio(baseline_text, test_text) if baseline else 0.0

                if (baseline and baseline.status_code in [401, 403] and test_response.status_code == 200) or (
                    not baseline_denied and body_diff > 0.2
                ):
                    results.append({
                        "url": url,
                        "parameter": param,
                        "type": "idor",
                        "severity": "medium",
                        "description": f"Sensitive parameter '{param}' found without proper authorization check",
                    })

        self.results.extend(results)
        return results

    def get_results(self) -> List[Dict[str, Any]]:
        """Get all findings."""
        return self.results

    def reset(self) -> None:
        """Reset detector state."""
        self.results.clear()

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get structured detector errors."""
        return self.error_collector.all()

"""
VULNIX - Web Vulnerability Scanner
Fuzzing Engine - Inject payloads and compare responses
"""

import asyncio
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


class Fuzzer:
    """
    Fuzzing engine for parameter injection and response comparison.
    """

    def __init__(
        self,
        request_engine: RequestEngine,
        similarity_threshold: float = 0.85,
    ):
        self.request_engine = request_engine
        self.similarity_threshold = similarity_threshold
        self.baseline_response: Optional[httpx.Response] = None
        self.baseline_hash: str = ""
        self.error_collector = ModuleErrorCollector("fuzzing")

    def _compute_hash(self, content: str) -> str:
        """Compute MD5 hash of content."""
        return hashlib.md5(content.encode()).hexdigest()

    def _compute_similarity(self, response1: str, response2: str) -> float:
        """Compute similarity ratio between two responses."""
        if not response1 or not response2:
            return 0.0

        words1 = set(response1.lower().split())
        words2 = set(response2.lower().split())

        if not words1 or not words2:
            return 0.0

        intersection = words1 & words2
        union = words1 | words2

        return len(intersection) / len(union)

    def _diff_ratio(self, response1: str, response2: str) -> float:
        """Compute ratio of difference between responses."""
        similarity = self._compute_similarity(response1, response2)
        return 1.0 - similarity

    async def _get_baseline(
        self, url: str, params: Optional[Dict] = None
    ) -> Tuple[Optional[httpx.Response], str]:
        """Get baseline response for comparison."""
        response = await self.request_engine.get(url, params=params)

        if not response:
            return None, ""

        try:
            content = response.text
        except Exception as e:
            self.error_collector.add(url, e, "baseline_read_content")
            content = ""

        content_hash = self._compute_hash(content)

        return response, content_hash

    async def fuzz_url_params(
        self,
        url: str,
        params: Dict[str, Any],
        payload: str,
    ) -> Optional[httpx.Response]:
        """Inject payload into URL parameters."""
        fuzzed_params = {}

        for key, value in params.items():
            if isinstance(value, list):
                fuzzed_params[key] = [payload] + value
            else:
                fuzzed_params[key] = [str(value), payload]

        try:
            response = await self.request_engine.get(url, params=fuzzed_params)
            return response
        except Exception as e:
            self.error_collector.add(url, e, "fuzz_url_params_request")
            return None

    async def fuzz_form_data(
        self,
        url: str,
        form_data: Dict[str, Any],
        payload: str,
    ) -> Optional[httpx.Response]:
        """Inject payload into form data."""
        fuzzed_data = {}

        for key, value in form_data.items():
            fuzzed_data[key] = payload

        try:
            response = await self.request_engine.post(url, data=fuzzed_data)
            return response
        except Exception as e:
            self.error_collector.add(url, e, "fuzz_form_data_request")
            return None

    async def test_parameter(
        self,
        url: str,
        param_name: str,
        payloads: List[str],
        method: str = "GET",
        baseline_response: Optional[httpx.Response] = None,
    ) -> List[Tuple[str, bool, httpx.Response]]:
        """
        Test a parameter with multiple payloads.
        Returns list of (payload, flagged, response) tuples.
        """
        results = []

        original_params = {param_name: "test"}

        for payload in payloads:
            test_params = original_params.copy()
            test_params[param_name] = payload

            try:
                if method.upper() == "GET":
                    response = await self.request_engine.get(url, params=test_params)
                else:
                    response = await self.request_engine.post(url, data=test_params)

                if not response:
                    results.append((payload, False, None))
                    continue

                flagged = False

                if baseline_response:
                    if response.status_code != baseline_response.status_code:
                        flagged = True
                    else:
                        baseline_text = baseline_response.text
                        response_text = response.text
                        diff = self._diff_ratio(baseline_text, response_text)
                        if diff > (1.0 - self.similarity_threshold):
                            flagged = True
                else:
                    if response.status_code >= 500:
                        flagged = True

                results.append((payload, flagged, response))

            except Exception as e:
                self.error_collector.add(url, e, f"test_parameter_{method.lower()}")
                results.append((payload, False, None))

        return results

    async def test_multiple_parameters(
        self,
        url: str,
        parameters: List[str],
        payloads: List[str],
        method: str = "GET",
    ) -> Dict[str, List[Tuple[str, bool, httpx.Response]]]:
        """Test multiple parameters with payloads."""
        results = {}

        baseline_response, _ = await self._get_baseline(url)

        tasks = []

        for param in parameters:
            task = self.test_parameter(
                url, param, payloads, method, baseline_response
            )
            tasks.append((param, task))

        for param, task in tasks:
            results[param] = await task

        return results

    def detect_anomalies(
        self,
        baseline_response: Optional[httpx.Response],
        test_response: httpx.Response,
    ) -> List[str]:
        """Detect anomalies between baseline and test response."""
        anomalies = []

        if not baseline_response or not test_response:
            return anomalies

        if baseline_response.status_code != test_response.status_code:
            anomalies.append(
                f"Status code change: {baseline_response.status_code} -> {test_response.status_code}"
            )

        baseline_text = baseline_response.text.lower()
        test_text = test_response.text.lower()

        error_patterns = [
            "sql syntax",
            "mysql",
            "postgresql",
            "ora-",
            "sqlite",
            "unterminated",
            "syntax error",
            "warning",
            "fatal",
            "exception",
        ]

        for pattern in error_patterns:
            if pattern in test_text and pattern not in baseline_text:
                anomalies.append(f"Error pattern detected: {pattern}")

        return anomalies

    async def check_error_reflection(
        self, url: str, payload: str, method: str = "GET"
    ) -> bool:
        """Check if payload is reflected in error response."""
        try:
            if method.upper() == "GET":
                response = await self.request_engine.get(url, params={"test": payload})
            else:
                response = await self.request_engine.post(url, data={"test": payload})

            if not response:
                return False

            response_text = response.text.lower()
            return payload.lower() in response_text

        except Exception as e:
            self.error_collector.add(url, e, f"check_error_reflection_{method.lower()}")
            return False

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get structured errors collected during fuzzing operations."""
        return self.error_collector.all()

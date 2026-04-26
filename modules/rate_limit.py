"""
VULNIX - Rate Limiting Detector
Detects rate limiting and throttling mechanisms
"""

import time
import asyncio
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


@dataclass
class RateLimitInfo:
    """Information about rate limiting."""
    detected: bool = False
    limit: Optional[int] = None
    window_seconds: Optional[float] = None
    reset_time: Optional[float] = None
    retry_after: Optional[int] = None
    method: str = "unknown"
    headers: Dict[str, str] = field(default_factory=dict)


class RateLimitDetector:
    """Detect and analyze rate limiting mechanisms."""

    COMMON_HEADERS = {
        "x_rate_limit_limit": "rate-limit",
        "x_rate_limit_remaining": "rate-remaining",
        "x_rate_limit_reset": "rate-reset",
        "x_ratelimit_limit": "ratelimit-limit",
        "x_ratelimit_remaining": "ratelimit-remaining",
        "x_ratelimit_reset": "ratelimit-reset",
        "ratelimit-limit": "ratelimit",
        "ratelimit-remaining": "remaining",
        "ratelimit-reset": "reset",
        "xRetryAfter": "retry-after",
        "retry_after": "retry-after",
        "retry-after": "retry-after",
    }

    STATUS_CODES = {
        429: "Too Many Requests",
        503: "Service Unavailable",
        440: "Timeout",
        460: "Custom Timeout",
    }

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("rate_limit")
        self.rate_limit_info: Optional[RateLimitInfo] = None
        self._response_history: List[Dict[str, Any]] = []
        self._max_history = 100

    def _extract_headers(self, response: Any) -> Dict[str, str]:
        """Extract rate limit related headers."""
        result = {}
        if not response or not hasattr(response, "headers"):
            return result

        headers = {k.lower(): v for k, v in response.headers.items()}

        for header, label in self.COMMON_HEADERS.items():
            if header in headers:
                result[label] = headers[header]

        return result

    def _parse_limit(self, value: str) -> Optional[int]:
        """Parse rate limit value from header."""
        if not value:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            parts = value.split("/")
            if parts:
                try:
                    return int(parts[0])
                except ValueError:
                    pass
        return None

    def _parse_window(self, value: str) -> Optional[float]:
        """Parse rate limit window from header."""
        if not value:
            return None
        try:
            if value.isdigit():
                return float(value)
            return float(value)
        except (ValueError, TypeError):
            pass
        return None

    def detect_from_headers(self, response: Any) -> RateLimitInfo:
        """Detect rate limiting from response headers."""
        info = RateLimitInfo()
        rate_headers = self._extract_headers(response)

        if rate_headers:
            info.detected = True
            info.headers = rate_headers

            if "rate-limit" in rate_headers:
                info.limit = self._parse_limit(rate_headers["rate-limit"])
            elif "ratelimit-limit" in rate_headers:
                info.limit = self._parse_limit(rate_headers["ratelimit-limit"])

            if "rate-remaining" in rate_headers:
                info.limit = self._parse_limit(rate_headers["rate-remaining"])
            elif "remaining" in rate_headers:
                info.limit = self._parse_limit(rate_headers["remaining"])

            if "rate-reset" in rate_headers:
                info.reset_time = self._parse_window(rate_headers["rate-reset"])
            elif "reset" in rate_headers:
                info.reset_time = self._parse_window(rate_headers["reset"])

            if "retry-after" in rate_headers:
                try:
                    info.retry_after = int(rate_headers["retry-after"])
                except (ValueError, TypeError):
                    pass

            info.method = "headers"

        return info

    def detect_from_status(self, response: Any) -> Optional[RateLimitInfo]:
        """Detect rate limiting from status code."""
        if not response or not hasattr(response, "status_code"):
            return None

        status = response.status_code

        if status in self.STATUS_CODES:
            info = RateLimitInfo()
            info.detected = True
            info.method = f"status_{status}"

            headers = self._extract_headers(response)
            if "retry-after" in headers:
                try:
                    info.retry_after = int(headers["retry-after"])
                except (ValueError, TypeError):
                    pass

            return info

        return None

    async def test_rate_limit(
        self,
        url: str,
        num_requests: int = 20,
        delay: float = 0.1,
    ) -> RateLimitInfo:
        """Test for rate limiting by making sequential requests."""
        info = RateLimitInfo()
        responses = []

        start_time = time.time()

        for i in range(num_requests):
            try:
                response = await self.request_engine.get(url)
                responses.append({
                    "status": response.status_code if response else 0,
                    "time": time.time() - start_time,
                    "headers": self._extract_headers(response) if response else {},
                })

                header_info = self.detect_from_headers(response)
                if header_info.detected:
                    return header_info

                status_info = self.detect_from_status(response)
                if status_info:
                    return status_info

                if delay > 0:
                    await asyncio.sleep(delay)

            except Exception as e:
                self.error_collector.add(url, e, "test_rate_limit")

        total_time = time.time() - start_time
        status_counts: Dict[int, int] = {}

        for resp in responses:
            status = resp.get("status", 0)
            status_counts[status] = status_counts.get(status, 0) + 1

        if 429 in status_counts or 503 in status_counts:
            info.detected = True
            info.method = "status_429"
            return info

        if status_counts.get(200, 0) < num_requests * 0.5:
            info.detected = True
            info.method = "reduced_success"
            info.limit = status_counts.get(200, 0)
            return info

        for resp in responses[:5]:
            rate_headers = resp.get("headers", {})
            if rate_headers:
                info.detected = True
                info.headers = rate_headers
                info.method = "headers"
                break

        return info

    def analyze_response_pattern(
        self,
        response_times: List[float],
    ) -> Dict[str, Any]:
        """Analyze response time patterns for throttling detection."""
        if len(response_times) < 3:
            return {}

        avg_time = sum(response_times) / len(response_times)
        variance = sum((t - avg_time) ** 2 for t in response_times) / len(response_times)
        std_dev = variance ** 0.5

        increasing = 0
        for i in range(1, len(response_times)):
            if response_times[i] > response_times[i-1] * 1.5:
                increasing += 1

        return {
            "avg_response_time": avg_time,
            "std_deviation": std_dev,
            "increasing_latency": increasing > len(response_times) // 2,
            "throttling_detected": std_dev > avg_time * 0.5,
        }

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Perform rate limiting analysis."""
        findings = []

        target_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        parsed = urlparse(target_url)
        path = f"{parsed.path or '/'}" if parsed.path else "/"

        test_url = target_url.rstrip("/") + path

        rate_info = await self.test_rate_limit(test_url)

        if rate_info.detected:
            findings.append({
                "type": "rate_limiting",
                "severity": "info",
                "description": f"Rate limiting detected via {rate_info.method}",
                "details": {
                    "limit": rate_info.limit,
                    "window": rate_info.window_seconds,
                    "reset_time": rate_info.reset_time,
                    "retry_after": rate_info.retry_after,
                    "method": rate_info.method,
                },
            })

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get collected errors."""
        return self.error_collector.all()
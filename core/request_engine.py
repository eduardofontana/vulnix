"""
VULNIX - Web Vulnerability Scanner
Request Engine Module - Handles HTTP requests with async support
"""

import asyncio
import time
import httpx
from typing import Optional, Dict, Any
from urllib.parse import urljoin, urlparse
import random

from core.error_collector import ModuleErrorCollector


class RequestEngine:
    """Async HTTP request engine with retry, redirect, and timeout handling."""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    ]

    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        delay: float = 0.5,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
        rate_limit: int = 10,
        random_delay: bool = False,
    ):
        self.timeout = timeout
        self.max_retries = max_retries
        self.delay = delay
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.session_cookies: dict = {}
        self.rate_limit = rate_limit
        self.random_delay = random_delay
        self._last_request_time = 0.0
        self._request_count = 0
        self._client: Optional[httpx.AsyncClient] = None
        self.error_collector = ModuleErrorCollector("request_engine")

    def _get_random_user_agent(self) -> str:
        """Return a random user agent."""
        return random.choice(self.USER_AGENTS)

    async def request(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        content: Optional[bytes] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        allow_redirects: bool = True,
        timeout: Optional[float] = None,
    ) -> Optional[httpx.Response]:
        """Send an HTTP request with retry logic and rate limiting."""
        await self._apply_rate_limit()
        default_headers = {
            "User-Agent": self._get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

        if headers:
            default_headers.update(headers)

        merged_cookies = {**self.session_cookies}
        if cookies:
            merged_cookies.update(cookies)

        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=self.follow_redirects,
                verify=self.verify_ssl,
            )

        for attempt in range(self.max_retries):
            try:
                response = await self._client.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    content=content,
                    headers=default_headers,
                    cookies=merged_cookies,
                    allow_redirects=allow_redirects,
                    timeout=timeout,
                )

                if hasattr(response, "cookies"):
                    self.session_cookies.update(response.cookies)

                return response

            except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
                self.error_collector.add(url, e, f"request_retryable_{method.lower()}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.delay * (attempt + 1))
                    continue
                return None

            except Exception as e:
                self.error_collector.add(url, e, f"request_unexpected_{method.lower()}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.delay * (attempt + 1))
                    continue
                return None

        return None

    async def get(
        self,
        url: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        timeout: Optional[float] = None,
    ) -> Optional[httpx.Response]:
        """Send a GET request."""
        return await self.request(
            "GET",
            url,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
        )

    async def post(
        self,
        url: str,
        data: Optional[dict] = None,
        content: Optional[bytes] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        timeout: Optional[float] = None,
    ) -> Optional[httpx.Response]:
        """Send a POST request."""
        return await self.request(
            "POST",
            url,
            data=data,
            content=content,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
        )

    async def head(
        self,
        url: str,
        headers: Optional[dict] = None,
        allow_redirects: bool = True,
        timeout: Optional[float] = None,
    ) -> Optional[httpx.Response]:
        """Send a HEAD request (for header analysis)."""
        return await self.request(
            "HEAD",
            url,
            headers=headers,
            allow_redirects=allow_redirects,
            timeout=timeout,
        )

    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        if self.rate_limit <= 0:
            return

        current_time = time.time()
        time_since_last = current_time - self._last_request_time

        if time_since_last < (1.0 / self.rate_limit):
            sleep_time = (1.0 / self.rate_limit) - time_since_last

            if self.random_delay:
                sleep_time = sleep_time * random.random() * 2

            await asyncio.sleep(sleep_time)

        self._last_request_time = time.time()

    def set_cookie(self, name: str, value: str) -> None:
        """Set a session cookie."""
        self.session_cookies[name] = value

    def clear_cookies(self) -> None:
        """Clear all session cookies."""
        self.session_cookies.clear()

    async def login(
        self,
        login_url: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
        extra_data: Optional[dict] = None,
    ) -> bool:
        """Perform login and maintain session."""
        try:
            response = await self.get(login_url)
            if not response:
                return False

            login_data = {
                username_field: username,
                password_field: password,
            }

            if extra_data:
                login_data.update(extra_data)

            login_response = await self.post(login_url, data=login_data)

            if login_response and login_response.status_code in [200, 302, 303]:
                return True

            return False

        except Exception as e:
            self.error_collector.add(login_url, e, "login")
            return False

    def save_session(self) -> Dict[str, Any]:
        """Save current session state."""
        return {
            "cookies": self.session_cookies.copy(),
            "user_agent": self._get_random_user_agent(),
        }

    def load_session(self, session_data: Dict[str, Any]) -> None:
        """Load session state."""
        if "cookies" in session_data:
            self.session_cookies = session_data["cookies"].copy()

    def is_authenticated(self) -> bool:
        """Check if session has authentication cookies."""
        auth_indicators = ["session", "token", "auth", "user", "id"]
        return any(
            indicator in cookie.lower()
            for cookie in self.session_cookies.keys()
            for indicator in auth_indicators
        )

    async def authenticated_request(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
        allow_redirects: bool = True,
    ) -> Optional[httpx.Response]:
        """Send authenticated request with CSRF token handling."""
        if headers is None:
            headers = {}

        headers["Referer"] = url

        return await self.request(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=headers,
            allow_redirects=allow_redirects,
        )

    def get_errors(self) -> list[dict[str, Any]]:
        """Return structured request engine errors."""
        return self.error_collector.all()

    async def close(self) -> None:
        """Close underlying HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

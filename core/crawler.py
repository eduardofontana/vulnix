"""
VULNIX - Web Vulnerability Scanner
Crawler Module - Discover endpoints and extract forms
"""

import asyncio
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from typing import Set, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
import httpx

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered URL endpoint."""

    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    form_action: Optional[str] = None
    form_method: Optional[str] = None
    form_inputs: List[Dict[str, str]] = field(default_factory=list)
    depth: int = 0


class Crawler:
    """
    Web crawler for discovering endpoints and forms.
    Handles relative URLs, query strings, and depth control.
    """

    def __init__(
        self,
        request_engine: RequestEngine,
        max_depth: int = 3,
        max_urls: int = 100,
        excluded_extensions: Optional[List[str]] = None,
    ):
        self.request_engine = request_engine
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.excluded_extensions = excluded_extensions or [
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".ico",
            ".css",
            ".js",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".pdf",
            ".zip",
            ".tar",
            ".gz",
        ]

        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: List[DiscoveredEndpoint] = []
        self.base_url: str = ""
        self.error_collector = ModuleErrorCollector("crawler")

    def _normalize_url(self, url: str, base_url: str = "") -> str:
        """Normalize and resolve relative URLs."""
        if not url:
            return ""

        url = url.strip()

        if url.startswith("//"):
            return "https:" + url

        if url.startswith("javascript:"):
            return ""

        if url.startswith("mailto:") or url.startswith("tel:"):
            return ""

        if base_url and not url.startswith(("http://", "https://")):
            return urljoin(base_url, url)

        return url

    def _extract_parameters(self, url: str) -> List[str]:
        """Extract query parameters from URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is same domain as base URL."""
        if not self.base_url:
            return True

        parsed_url = urlparse(url)
        parsed_base = urlparse(self.base_url)

        return parsed_url.netloc == parsed_base.netloc

    def _should_crawl(self, url: str) -> bool:
        """Check if URL should be crawled."""
        if not url:
            return False

        if url in self.visited_urls:
            return False

        if not url.startswith(("http://", "https://")):
            return False

        if not self._is_same_domain(url):
            return False

        for ext in self.excluded_extensions:
            if url.lower().endswith(ext):
                return False

        return True

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML."""
        links = []

        try:
            soup = BeautifulSoup(html, "lxml")

            for a_tag in soup.find_all("a", href=True):
                href = a_tag.get("href", "")
                if href:
                    normalized = self._normalize_url(href, base_url)
                    if normalized and self._should_crawl(normalized):
                        links.append(normalized)

            for form in soup.find_all("form"):
                action = form.get("action", "")
                if action:
                    form_url = self._normalize_url(action, base_url)
                    if form_url:
                        method = form.get("method", "GET").upper()
                        inputs = []
                        for input_tag in form.find_all(["input", "textarea", "select"]):
                            input_name = input_tag.get("name", "")
                            if input_name:
                                input_type = input_tag.get("type", "text")
                                inputs.append(
                                    {
                                        "name": input_name,
                                        "type": input_type,
                                        "value": input_tag.get("value", ""),
                                    }
                                )

                        endpoint = DiscoveredEndpoint(
                            url=form_url,
                            method=method,
                            form_action=form_url,
                            form_method=method,
                            form_inputs=inputs,
                        )
                        if endpoint not in self.discovered_endpoints:
                            self.discovered_endpoints.append(endpoint)

        except Exception as e:
            self.error_collector.add(base_url, e, "extract_links")

        return list(set(links))

    def _extract_forms(self, html: str, base_url: str) -> List[DiscoveredEndpoint]:
        """Extract forms from HTML."""
        endpoints = []

        try:
            soup = BeautifulSoup(html, "lxml")

            for form in soup.find_all("form"):
                action = form.get("action", "")
                if not action:
                    action = base_url

                form_url = self._normalize_url(action, base_url)
                if not form_url:
                    continue

                method = form.get("method", "GET").upper()

                inputs = []
                for input_tag in form.find_all(["input", "textarea", "select"]):
                    input_name = input_tag.get("name", "")
                    if input_name:
                        input_type = input_tag.get("type", "text").lower()
                        if input_type not in ["submit", "image", "button", "reset"]:
                            inputs.append(
                                {
                                    "name": input_name,
                                    "type": input_type,
                                    "value": input_tag.get("value", ""),
                                }
                            )

                endpoint = DiscoveredEndpoint(
                    url=form_url,
                    method=method,
                    parameters=[inp["name"] for inp in inputs],
                    form_action=form_url,
                    form_method=method,
                    form_inputs=inputs,
                )
                endpoints.append(endpoint)

        except Exception as e:
            self.error_collector.add(base_url, e, "extract_forms")

        return endpoints

    async def _crawl_page(self, url: str, depth: int = 0) -> List[str]:
        """Crawl a single page and extract links."""
        if depth > self.max_depth:
            return []

        if not self._should_crawl(url):
            return []

        self.visited_urls.add(url)

        response = await self.request_engine.get(url)

        if not response:
            return []

        try:
            html = response.text
        except Exception as e:
            self.error_collector.add(url, e, "crawl_page_read_html")
            return []

        links = self._extract_links(html, url)
        forms = self._extract_forms(html, url)

        for form in forms:
            if form not in self.discovered_endpoints:
                self.discovered_endpoints.append(form)

        return links

    async def crawl(self, url: str) -> List[DiscoveredEndpoint]:
        """
        Start crawling from the given URL.
        Returns all discovered endpoints.
        """
        self.base_url = url

        parsed = urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
            self.base_url = url

        queue: List[Tuple[str, int]] = [(url, 0)]
        all_links: List[str] = [url]

        while queue and len(self.visited_urls) < self.max_urls:
            current_url, depth = queue.pop(0)

            if current_url in self.visited_urls:
                continue

            new_links = await self._crawl_page(current_url, depth)

            for link in new_links:
                if link not in self.visited_urls and link not in all_links:
                    all_links.append(link)
                    if len(self.visited_urls) < self.max_urls:
                        queue.append((link, depth + 1))

        unique_endpoints = []
        seen_urls = set()

        for endpoint in self.discovered_endpoints:
            if endpoint.url not in seen_urls:
                unique_endpoints.append(endpoint)
                seen_urls.add(endpoint.url)

        get_endpoint = DiscoveredEndpoint(
            url=url,
            method="GET",
            parameters=self._extract_parameters(url),
        )
        if get_endpoint.url not in seen_urls:
            unique_endpoints.insert(0, get_endpoint)

        return unique_endpoints

    def get_all_urls(self) -> List[str]:
        """Get all discovered URLs."""
        return list(self.visited_urls)

    def get_all_parameters(self) -> Dict[str, List[str]]:
        """Get all parameters organized by URL."""
        params_by_url = {}

        for endpoint in self.discovered_endpoints:
            url = endpoint.url
            if endpoint.parameters:
                params_by_url[url] = endpoint.parameters
            elif endpoint.form_inputs:
                params_by_url[url] = [inp["name"] for inp in endpoint.form_inputs]

        return params_by_url

    def reset(self) -> None:
        """Reset crawler state."""
        self.visited_urls.clear()
        self.discovered_endpoints.clear()
        self.base_url = ""

    def get_errors(self) -> List[Dict[str, str]]:
        """Get structured crawler errors."""
        return self.error_collector.all()

"""
VULNIX - Link Extractor
Extract and categorize links from web content
"""

import re
import json
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse, urljoin, urlunparse
import httpx
from bs4 import BeautifulSoup

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


class LinkExtractor:
    """Extract and categorize links from crawled content."""

    API_PATTERNS = [
        r"/api/",
        r"/v\d+/",
        r"/graphql",
        r"/rest/",
        r"/ws/",
        r"/endpoint",
    ]

    FILE_EXTENSIONS = [
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".zip",
        ".rar",
        ".tar",
        ".gz",
        ".csv",
        ".json",
        ".xml",
    ]

    SENSITIVE_PATTERNS = [
        r"/admin",
        r"/login",
        r"/password",
        r"/reset",
        r"/forgot",
        r"/profile",
        r"/settings",
        r"/config",
        r"/.env",
        r"/.git",
        r"/backup",
    ]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("link_extractor")
        self.results: Dict[str, Any] = {}

    def _normalize_url(self, url: str, base_url: str) -> str:
        """Normalize URL to absolute."""
        if url.startswith(("http://", "https://")):
            return url

        if url.startswith("//"):
            parsed = urlparse(base_url)
            return f"{parsed.scheme}:{url}"

        if url.startswith("/"):
            parsed = urlparse(base_url)
            return f"{parsed.scheme}://{parsed.netloc}{url}"

        if url.startswith(("mailto:", "tel:", "javascript:", "data:")):
            return url

        return urljoin(base_url, url)

    def _get_base_url(self, url: str) -> str:
        """Get base URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _extract_from_html(
        self, html: str, base_url: str
    ) -> Dict[str, List[str]]:
        """Extract links from HTML content."""
        links = {
            "internal": [],
            "external": [],
            "same_domain": [],
        }

        try:
            soup = BeautifulSoup(html, "lxml")

            for tag in soup.find_all("a", href=True):
                href = tag.get("href", "")
                if not href or href.startswith(("mailto:", "tel:", "javascript:", "data:")):
                    continue

                abs_url = self._normalize_url(href, base_url)
                parsed = urlparse(abs_url)
                base_parsed = urlparse(base_url)

                if parsed.netloc == base_parsed.netloc:
                    links["same_domain"].append(abs_url)
                    links["internal"].append(abs_url)
                elif parsed.netloc:
                    links["external"].append(abs_url)

            for tag in soup.find_all("link", href=True):
                href = tag.get("href", "")
                if not href:
                    continue

                abs_url = self._normalize_url(href, base_url)
                parsed = urlparse(abs_url)

                if parsed.netloc == base_parsed.netloc:
                    links["internal"].append(abs_url)
                elif parsed.netloc:
                    links["external"].append(abs_url)

            for tag in soup.find_all("script", src=True):
                src = tag.get("src", "")
                if not src:
                    continue

                abs_url = self._normalize_url(src, base_url)
                parsed = urlparse(abs_url)

                if parsed.netloc == base_parsed.netloc:
                    links["internal"].append(abs_url)
                elif parsed.netloc:
                    links["external"].append(abs_url)

            for tag in soup.find_all("img", src=True):
                src = tag.get("src", "")
                if not src:
                    continue

                abs_url = self._normalize_url(src, base_url)
                parsed = urlparse(abs_url)

                if parsed.netloc == base_parsed.netloc:
                    links["internal"].append(abs_url)
                elif parsed.netloc:
                    links["external"].append(abs_url)

            for tag in soup.find_all("source", src=True):
                src = tag.get("src", "")
                if not src:
                    continue

                abs_url = self._normalize_url(src, base_url)
                parsed = urlparse(abs_url)

                if parsed.netloc == base_parsed.netloc:
                    links["internal"].append(abs_url)
                elif parsed.netloc:
                    links["external"].append(abs_url)

            links["internal"] = list(set(links["internal"]))
            links["external"] = list(set(links["external"]))
            links["same_domain"] = list(set(links["same_domain"]))

        except Exception as e:
            self.error_collector.add(base_url, e, "extract_html")

        return links

    def _extract_from_js(
        self, js_content: str, base_url: str
    ) -> List[Dict[str, Any]]:
        """Extract endpoints and URLs from JavaScript content."""
        endpoints = []

        url_pattern = r'["\']((?:https?:)?//[^"\']+)["\']'
        for match in re.finditer(url_pattern, js_content):
            url = match.group(1)
            abs_url = self._normalize_url(url, base_url)
            endpoints.append(
                {"type": "url", "url": abs_url, "source": "javascript"}
            )

        api_pattern = r'["\']\/api[/\w\-]*["\']'
        for match in re.finditer(api_pattern, js_content):
            path = match.group(0).strip('"\' /')
            abs_url = self._normalize_url(path, base_url)
            endpoints.append(
                {"type": "api_endpoint", "url": abs_url, "source": "javascript"}
            )

        fetch_pattern = r"fetch\([\"\']([^\"\']+)[\"\']"
        for match in re.finditer(fetch_pattern, js_content):
            url = match.group(1)
            abs_url = self._normalize_url(url, base_url)
            endpoints.append(
                {"type": "fetch", "url": abs_url, "source": "javascript"}
            )

        axios_pattern = r'\.get\([\"\']([^\"\']+)[\"\']'
        for match in re.finditer(axios_pattern, js_content):
            url = match.group(1)
            abs_url = self._normalize_url(url, base_url)
            endpoints.append(
                {"type": "axios", "url": abs_url, "source": "javascript"}
            )

        xhr_pattern = r"new\s+XMLHttpRequest\(\)"
        if xhr_pattern in js_content:
            endpoints.append(
                {"type": "xhr", "url": base_url, "source": "javascript"}
            )

        return endpoints

    def _categorize_links(
        self, links: Dict[str, List[str]]
    ) -> Dict[str, List[Dict[str, str]]]:
        """Categorize extracted links."""
        categorized = {
            "api_endpoints": [],
            "file_downloads": [],
            "sensitive_paths": [],
            "static_assets": [],
            "navigation": [],
        }

        all_links = list(
            set(links.get("internal", []) + links.get("external", []))
        )

        api_pattern = "|".join(self.API_PATTERNS)
        sensitive_pattern = "|".join(self.SENSITIVE_PATTERNS)

        for link in all_links:
            parsed = urlparse(link)
            path = parsed.path.lower()
            ext = "".join(
                [
                    parsed.path[i:]
                    for i, c in enumerate(parsed.path)
                    if c == "."
                ]
            )

            if api_pattern and re.search(api_pattern, path):
                categorized["api_endpoints"].append(
                    {"url": link, "type": "api"}
                )
            elif path.endswith(tuple(self.FILE_EXTENSIONS)):
                categorized["file_downloads"].append(
                    {"url": link, "type": "file"}
                )
            elif re.search(sensitive_pattern, path):
                categorized["sensitive_paths"].append(
                    {"url": link, "type": "sensitive"}
                )
            elif any(
                path.endswith(ext) for ext in [".js", ".css", ".map", ".ico", ".png", ".jpg", ".gif"]
            ):
                categorized["static_assets"].append({"url": link, "type": "asset"})
            elif "#" not in link or link.count("#") == link.count("#"):
                if "?" in link or "/" in path:
                    categorized["navigation"].append({"url": link, "type": "page"})

        return categorized

    async def extract_from_url(self, url: str) -> Dict[str, Any]:
        """Extract links from a URL."""
        try:
            response = await self.request_engine.get(url)

            if not response or response.status_code != 200:
                return {"error": "Could not fetch URL", "url": url}

            base_url = self._normalize_url(url, url)

            html_links = self._extract_from_html(response.text, base_url)

            js_endpoints = []
            if hasattr(response, "text"):
                js_endpoints = self._extract_from_js(response.text, base_url)

            categorized = self._categorize_links(html_links)

            result = {
                "url": url,
                "base_url": base_url,
                "links": html_links,
                "js_endpoints": js_endpoints,
                "categorized": categorized,
                "total_internal": len(html_links.get("internal", [])),
                "total_external": len(html_links.get("external", [])),
                "total_api": len(categorized.get("api_endpoints", [])),
            }

            self.results = result
            return result

        except Exception as e:
            self.error_collector.add(url, e, "extract_url")
            return {"error": str(e), "url": url}

    async def extract_from_content(
        self, content: str, base_url: str
    ) -> Dict[str, Any]:
        """Extract links from raw content."""
        html_links = self._extract_from_html(content, base_url)

        js_endpoints = self._extract_from_js(content, base_url)

        categorized = self._categorize_links(html_links)

        return {
            "base_url": base_url,
            "links": html_links,
            "js_endpoints": js_endpoints,
            "categorized": categorized,
            "total_internal": len(html_links.get("internal", [])),
            "total_external": len(html_links.get("external", [])),
        }

    def find_api_endpoints(self, urls: List[str]) -> List[str]:
        """Find API endpoints from list of URLs."""
        api_pattern = "|".join(self.API_PATTERNS)

        endpoints = []
        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.lower()

            if re.search(api_pattern, path):
                endpoints.append(url)

        return list(set(endpoints))

    def find_parameter_injection_points(
        self, urls: List[str]
    ) -> List[Dict[str, Any]]:
        """Find potential parameter injection points."""
        injection_points = []

        param_names = [
            "id",
            "page",
            "sort",
            "order",
            "search",
            "query",
            "filter",
            "cat",
            "category",
            "file",
            "view",
        ]

        for url in urls:
            parsed = urlparse(url)
            query = parsed.query

            if query:
                params = query.split("&")
                for param in params:
                    if "=" in param:
                        name = param.split("=")[0]
                        if name in param_names:
                            injection_points.append(
                                {
                                    "url": url,
                                    "parameter": name,
                                    "type": "query",
                                }
                            )

        return injection_points

    def get_results(self) -> Dict[str, Any]:
        """Get extraction results."""
        return self.results

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()
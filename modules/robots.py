"""
VULNIX - Robots.txt & Sitemap Analyzer
Analyze robots.txt and sitemap.xml files
"""

import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse, urljoin
import httpx
from bs4 import BeautifulSoup

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


class RobotsSitemapAnalyzer:
    """Analyze robots.txt and sitemap.xml files."""

    COMMON_ROBOTS_PATHS = ["/robots.txt", "/robots.txt"]
    COMMON_SITEMAP_PATHS = [
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/sitemap-index.xml",
        "/sitemaps.xml",
    ]

    SPIDER_TRAPS = [
        r".*",
        r"\*",
        r"/\*",
        r"//",
    ]

    PRIVATE_PATH_PATTERNS = [
        r"/admin",
        r"/login",
        r"/wp-admin",
        r"/wp-login",
        r"/administrator",
        r"/phpmyadmin",
        r"/config",
        r"/configuration",
        r"/.git",
        r"/.svn",
        r"/.env",
        r"/backup",
        r"/backups",
        r"/database",
        r"/db",
        r"/private",
        r"/secret",
        r"/api/internal",
    ]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("robots_sitemap")
        self.robots_result: Dict[str, Any] = {}
        self.sitemap_result: Dict[str, Any] = {}

    def _normalize_url(self, value: str) -> str:
        """Normalize URL to base."""
        if not value.startswith(("http://", "https://")):
            value = f"https://{value}"
        return value.rstrip("/")

    def _get_base_url(self, url: str) -> str:
        """Get base URL for a given URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _parse_robots(self, content: str, base_url: str) -> Dict[str, Any]:
        """Parse robots.txt content."""
        result = {
            "disallowed_paths": [],
            "allowed_paths": [],
            "sitemaps": [],
            "crawl_delay": None,
            "user_agents": {},
            "parsed_successfully": False,
        }

        if not content:
            return result

        result["parsed_successfully"] = True

        current_user_agent = "*"
        user_agent_rules: Dict[str, List[Dict[str, str]]] = {"*": []}

        for line in content.split("\n"):
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()

                if key == "user-agent":
                    current_user_agent = value
                    if value not in user_agent_rules:
                        user_agent_rules[value] = []

                elif key == "disallow":
                    if value:
                        user_agent_rules[current_user_agent].append(
                            {"directive": "disallow", "path": value}
                        )
                        if current_user_agent == "*":
                            result["disallowed_paths"].append(value)

                elif key == "allow":
                    if value:
                        user_agent_rules[current_user_agent].append(
                            {"directive": "allow", "path": value}
                        )
                        if current_user_agent == "*":
                            result["allowed_paths"].append(value)

                elif key == "sitemap":
                    if value.startswith("http"):
                        result["sitemaps"].append(value)
                    else:
                        result["sitemaps"].append(urljoin(base_url, value))

                elif key == "crawl-delay":
                    try:
                        delay = float(value)
                        result["crawl_delay"] = delay
                        user_agent_rules[current_user_agent].append(
                            {"directive": "crawl-delay", "value": str(delay)}
                        )
                    except ValueError:
                        pass

        result["user_agents"] = user_agent_rules
        return result

    async def parse_robots(self, url: str) -> Dict[str, Any]:
        """Fetch and parse robots.txt."""
        base_url = self._normalize_url(url)
        robots_url = f"{base_url}/robots.txt"

        try:
            response = await self.request_engine.get(robots_url)

            if response and response.status_code == 200:
                content = response.text
                self.robots_result = self._parse_robots(content, base_url)
                self.robots_result["url"] = robots_url
                self.robots_result["found"] = True
            else:
                self.robots_result = {
                    "url": robots_url,
                    "found": False,
                    "parsed_successfully": False,
                }

        except Exception as e:
            self.error_collector.add(robots_url, e, "parse_robots")
            self.robots_result = {
                "url": robots_url,
                "found": False,
                "error": str(e),
            }

        return self.robots_result

    def _parse_sitemap_xml(self, content: str, base_url: str) -> Dict[str, Any]:
        """Parse sitemap.xml content."""
        result = {
            "urls": [],
            "sitemaps": [],
            "lastmod": None,
            " priorities": {},
            "found": True,
            "parsed_successfully": False,
        }

        if not content:
            return result

        try:
            root = ET.fromstring(content)
            namespaces = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

            if root.tag.endswith("sitemapindex"):
                for sitemap in root.findall(".//sm:sitemap", namespaces) or root.findall(
                    ".//sitemap"
                ):
                    loc = sitemap.find("sm:loc", namespaces) or sitemap.find("loc")
                    lastmod = sitemap.find("sm:lastmod", namespaces) or sitemap.find(
                        "lastmod"
                    )

                    if loc is not None:
                        url = loc.text
                        result["sitemaps"].append(
                            {
                                "url": url,
                                "lastmod": lastmod.text if lastmod is not None else None,
                            }
                        )

                result["parsed_successfully"] = True

            elif root.tag.endswith("urlset"):
                for url_elem in root.findall(".//sm:url", namespaces) or root.findall("url"):
                    loc = url_elem.find("sm:loc", namespaces) or url_elem.find("loc")
                    lastmod = url_elem.find("sm:lastmod", namespaces) or url_elem.find(
                        "lastmod"
                    )
                    priority = url_elem.find("sm:priority", namespaces) or url_elem.find(
                        "priority"
                    )
                    changefreq = url_elem.find(
                        "sm:changefreq", namespaces
                    ) or url_elem.find("changefreq")

                    if loc is not None:
                        url_data = {
                            "url": loc.text,
                            "lastmod": lastmod.text if lastmod is not None else None,
                            "priority": (
                                float(priority.text)
                                if priority is not None and priority.text
                                else None
                            ),
                            "changefreq": (
                                changefreq.text if changefreq is not None else None
                            ),
                        }
                        result["urls"].append(url_data)

                        if url_data["priority"]:
                            result["priorities"][loc.text] = url_data["priority"]

                result["parsed_successfully"] = True

        except ET.ParseError as e:
            self.error_collector.add(base_url, e, "parse_sitemap")
            result["error"] = str(e)

        return result

    async def parse_sitemap(self, url: str) -> Dict[str, Any]:
        """Fetch and parse sitemap.xml."""
        base_url = self._normalize_url(url)

        for sitemap_path in self.COMMON_SITEMAP_PATHS:
            sitemap_url = f"{base_url}{sitemap_path}"

            try:
                response = await self.request_engine.get(sitemap_url)

                if response and response.status_code == 200:
                    content = response.text
                    self.sitemap_result = self._parse_sitemap_xml(content, base_url)
                    self.sitemap_result["url"] = sitemap_url
                    self.sitemap_result["found"] = True
                    return self.sitemap_result

            except Exception as e:
                continue

        self.sitemap_result = {
            "found": False,
            "parsed_successfully": False,
            "url": base_url + "/sitemap.xml",
        }
        return self.sitemap_result

    def find_spider_traps(self) -> List[str]:
        """Find potential spider traps in disallowed paths."""
        traps = []

        if not self.robots_result.get("disallowed_paths"):
            return traps

        for path in self.robots_result["disallowed_paths"]:
            for pattern in self.SPIDER_TRAPS:
                if re.match(pattern, path):
                    traps.append(path)
                    break

        return list(set(traps))

    def find_private_paths(self) -> List[Dict[str, Any]]:
        """Find potentially private paths from robots.txt."""
        private_paths = []

        all_paths = (
            self.robots_result.get("disallowed_paths", [])
            + self.robots_result.get("allowed_paths", [])
        )

        pattern = "|".join(self.PRIVATE_PATH_PATTERNS)
        regex = re.compile(pattern)

        for path in all_paths:
            if regex.search(path):
                private_paths.append({"path": path, "source": "robots.txt"})

        for url_data in self.sitemap_result.get("urls", []):
            url = url_data.get("url", "")
            if regex.search(url):
                private_paths.append({"path": url, "source": "sitemap"})

        return private_paths

    async def analyze(self, url: str) -> Dict[str, Any]:
        """Perform complete robots.txt and sitemap analysis."""
        base_url = self._normalize_url(url)

        robots = await self.parse_robots(base_url)
        sitemap = await self.parse_sitemap(base_url)

        result = {
            "robots": robots,
            "sitemap": sitemap,
        }

        if robots.get("found"):
            result["spider_traps"] = self.find_spider_traps()

        result["private_paths"] = self.find_private_paths()

        errors = self.error_collector.all()
        if errors:
            result["errors"] = errors

        return result

    def get_robots_result(self) -> Dict[str, Any]:
        """Get robots.txt analysis result."""
        return self.robots_result

    def get_sitemap_result(self) -> Dict[str, Any]:
        """Get sitemap.xml analysis result."""
        return self.sitemap_result

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()
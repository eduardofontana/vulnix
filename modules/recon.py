"""
VULNIX - Subdomain Enumeration Module
Fast passive subdomain enumeration from multiple sources
"""

import asyncio
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import httpx

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


SUBDOMAIN_SOURCES = [
    ("crt.sh", "https://crt.sh/?q=*.{domain}&output=json"),
    ("dnsdumpster", "https://dnsdumpster.com/domain/{domain}"),
    ("bufferover", "https://dns.bufferover.run/dns?q=*.{domain}"),
    ("hackertarget", "https://api.hackertarget.com/dnslookup/?q=*.{domain}"),
]


class SubdomainEnumerator:
    """Enumerate subdomains using passive sources."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.results: List[str] = []
        self.error_collector = ModuleErrorCollector("subdomain_enum")

    def _normalize_domain(self, value: str) -> str:
        """Normalize input to a bare hostname/domain."""
        candidate = value.strip()
        if "://" in candidate:
            parsed = urlparse(candidate)
            return (parsed.hostname or candidate).strip(".")
        return candidate.split("/")[0].strip(".")

    async def enumerate_from_crtsh(self, domain: str) -> List[str]:
        """Get subdomains from crt.sh certificate transparency."""
        subdomains = []
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        try:
            response = await self.request_engine.get(url)

            if response and response.status_code == 200:
                import json

                try:
                    data = json.loads(response.text)
                    for cert in data:
                        for name in cert.get("name_value", "").split("\n"):
                            if domain in name and "*" not in name:
                                subdomains.append(name.strip())
                except (json.JSONDecodeError, Exception) as e:
                    self.error_collector.add(url, e, "parse_crtsh")

        except Exception as e:
            self.error_collector.add(url, e, "request_crtsh")

        return list(set(subdomains))

    async def enumerate_from_chaos(self, domain: str) -> List[str]:
        """Get subdomains from chaos (projectdiscovery)."""
        subdomains = []
        url = f"https://chaos.projectdiscovery.io/index.php?domain={domain}"

        try:
            response = await self.request_engine.get(url)

            if response and response.status_code == 200:
                for line in response.text.split("\n"):
                    if domain in line and line.strip():
                        subdomains.append(line.strip())

        except Exception as e:
            self.error_collector.add(url, e, "request_chaos")

        return list(set(subdomains))

    async def brute_force_subdomains(
        self, domain: str, wordlist: Optional[List[str]] = None
    ) -> List[str]:
        """Brute force subdomains using wordlist."""
        if wordlist is None:
            wordlist = [
                "www",
                "mail",
                "ftp",
                "localhost",
                "webmail",
                "smtp",
                "pop",
                "ns1",
                "webdisk",
                "ns2",
                "cpanel",
                "whm",
                "autodiscover",
                "autoconfig",
                "m",
                "imap",
                "test",
                "ns",
                "mx",
                "mx1",
                "dns1",
                "dns2",
                "dns",
                "www1",
                "api",
                "cloud",
                "shop",
                "my",
                "static",
                "docs",
                "support",
                "cdn",
                "blog",
                "forum",
                "news",
                "vpn",
                "ssh",
                "corp",
                "login",
                "webs",
                "beta",
                "app",
                "git",
                "staging",
                "demo",
                "mobile",
                "mx2",
                "dev",
                "www2",
                "admin",
                "store",
                "chat",
                "web",
                "media",
                "secure",
                "portal",
                "s1",
                "s2",
                "s3",
                "backup",
                "proxy",
                "ns3",
                "mail1",
                "old",
                "lists",
                "info",
                "cdn2",
                "img",
                "static1",
                "ip",
                "internal",
                "db",
                "git2",
            ]

        subdomains = []
        base_domain = domain.split(".")[-2] if "." in domain else domain
        root = ".".join(domain.split(".")[-2:]) if "." in domain else domain

        for sub in wordlist:
            test_domain = f"{sub}.{root}"

            try:
                response = await self.request_engine.head(
                    f"http://{test_domain}",
                    allow_redirects=True,
                )

                if response and response.status_code < 500:
                    subdomains.append(test_domain)

                response_https = await self.request_engine.head(
                    f"https://{test_domain}",
                    allow_redirects=True,
                )

                if response_https and response_https.status_code < 500:
                    subdomains.append(test_domain)

            except Exception as e:
                self.error_collector.add(test_domain, e, "bruteforce_probe")

        return list(set(subdomains))

    async def enumerate(self, domain: str, brute: bool = False) -> List[str]:
        """Enumerate subdomains."""
        domain = self._normalize_domain(domain)
        all_subdomains = []

        crt_subdomains = await self.enumerate_from_crtsh(domain)
        all_subdomains.extend(crt_subdomains)

        if brute:
            brute_subdomains = await self.brute_force_subdomains(domain)
            all_subdomains.extend(brute_subdomains)

        self.results = list(set(all_subdomains))
        return self.results

    def get_results(self) -> List[str]:
        """Get all findings."""
        return self.results

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class PortScanner:
    """Quick TCP port scanner."""

    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9200, 27017,
    ]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("port_scan")

    async def check_port(self, host: str, port: int) -> bool:
        """Check if port is open."""
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            self.error_collector.add(f"{host}:{port}", e, "check_port")
            return False

    async def quick_scan(self, host: str) -> Dict[int, bool]:
        """Quick port scan for common ports."""
        results = {}

        for port in self.COMMON_PORTS[:20]:
            is_open = await self.check_port(host, port)
            if is_open:
                results[port] = True

        return results

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class TechnologyFingerprinter:
    """Fingerprint web technologies."""

    TECH_SIGNATURES = {
        "nginx": ["nginx", "NGINX"],
        "apache": ["apache", "Apache"],
        "iis": ["microsoft-iis", "IIS"],
        "cloudflare": ["cloudflare", "Cloudflare"],
        "aws": ["amazon", "AWS", "s3.amazonaws"],
        "azure": ["azure", "azure"],
        "wordpress": ["wp-content", "wp-includes", "wordpress"],
        "drupal": ["drupal", "Drupal"],
        "joomla": ["joomla", "Joomla"],
        "laravel": ["laravel", "Laravel"],
        "express": ["express", "Express"],
        "django": ["django", "Django"],
        "react": ["react", "React"],
        "vue": ["vue", "Vue.js"],
        "angular": ["angular", "Angular"],
        "nextjs": ["next", "Next.js"],
        "php": [".php", "PHP"],
        "python": ["python", "python"],
        "golang": ["go-lang", "Go"],
    }

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("tech_fingerprint")
        self.last_versions: Dict[str, str] = {}

    @staticmethod
    def _extract_version(value: str) -> Optional[str]:
        """Extract semantic-like version from header snippets."""
        if not value:
            return None
        match = re.search(r"\b(\d+(?:\.\d+){1,3}(?:[-_a-zA-Z0-9\.]+)?)\b", value)
        return match.group(1) if match else None

    async def fingerprint(self, url: str) -> Dict[str, bool]:
        """Fingerprint technologies."""
        results = {}
        self.last_versions = {}

        try:
            import httpx

            async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
                response = await client.get(url)

            if not response:
                return {}

            headers_dict = dict(response.headers)
            headers_text = " ".join([f"{k}: {v}" for k, v in response.headers.items()]).lower()
            html_text = response.text.lower()
            server_header = headers_dict.get("server", "").lower()
            powered_by = headers_dict.get("x-powered-by", "").lower()

            tech_signatures = {
                "nginx": {"server": ["nginx"]},
                "apache": {"server": ["apache"]},
                "iis": {"server": ["microsoft-iis", "iis"]},
                "vercel": {"server": ["vercel"]},
                "cloudflare": {"server": ["cloudflare"]},
                "aws": {"server": ["amazon"]},
                "nextjs": {"powered": ["next"]},
                "wp": {"html": ["wp-content", "wp-includes", "wordpress"]},
                "drupal": {"html": ["drupal"]},
                "joomla": {"html": ["joomla"]},
                "laravel": {"html": ["laravel"]},
                "react": {"html": ["react", "createelement"]},
                "vue": {"html": ["vue", "vuejs", "vue-router"]},
                "jquery": {"html": ["jquery"]},
                "php": {"powered": ["php"]},
            }

            for tech, patterns in tech_signatures.items():
                if patterns.get("server") and any(sig in server_header for sig in patterns["server"]):
                    results[tech] = True
                    if tech in {"nginx", "apache", "iis", "vercel", "cloudflare", "aws"}:
                        version = self._extract_version(server_header)
                        if version:
                            self.last_versions[tech] = version
                if patterns.get("powered") and any(sig in powered_by for sig in patterns["powered"]):
                    results[tech] = True
                    if tech in {"nextjs", "php"}:
                        version = self._extract_version(powered_by)
                        if version:
                            self.last_versions[tech] = version
                if patterns.get("html") and any(sig in html_text for sig in patterns["html"]):
                    results[tech] = True

        except Exception as e:
            self.error_collector.add(url, e, "fingerprint")

        return results

    def get_last_versions(self) -> Dict[str, str]:
        """Return version hints detected in the latest fingerprint run."""
        return dict(self.last_versions)

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()

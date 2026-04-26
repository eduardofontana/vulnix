"""
VULNIX - Subdomain Enumeration Module
Fast passive subdomain enumeration from multiple sources
"""

import asyncio
import re
import socket
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import httpx
import dns.resolver
import dns.reversename

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

    TOP_PORTS_100 = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1433, 1521, 1723, 1755, 3306, 3389, 5432, 5500, 5900, 5985, 6379,
        8000, 8001, 8009, 8080, 8081, 8443, 8888, 9090, 9200, 9300, 27017,
        27018, 27019, 28017, 3307, 5000, 5001, 5002, 5003, 5004, 5005, 5006,
        5007, 5008, 5009, 5010, 5011, 5012, 5013, 5014, 5015, 5016, 5017,
        5018, 5019, 5020, 5021, 5022, 5023, 5024, 5025, 5026, 5027, 5028,
        5029, 5030, 5031, 5032, 5033, 5034, 5035, 5036, 5037, 5038, 5039,
    ]

    SERVICE_NAMES = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        443: "https",
        445: "microsoft-ds",
        465: "smtps",
        587: "submission",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        1723: "pptp",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8000: "http-alt",
        8080: "http-proxy",
        8443: "https-alt",
        8888: "http-alt",
        9200: "elasticsearch",
        27017: "mongodb",
    }

    def __init__(
        self,
        request_engine: RequestEngine,
        concurrent: int = 50,
        timeout: float = 2.0,
    ):
        self.request_engine = request_engine
        self.concurrent = concurrent
        self.timeout = timeout
        self.error_collector = ModuleErrorCollector("port_scan")
        self.results: Dict[int, Dict[str, Any]] = {}

    async def check_port(self, host: str, port: int) -> Dict[str, Any]:
        """Check if port is open and get basic info."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                return {
                    "port": port,
                    "open": True,
                    "service": self.SERVICE_NAMES.get(port, "unknown"),
                }
            return {"port": port, "open": False, "service": None}

        except Exception as e:
            self.error_collector.add(f"{host}:{port}", e, "check_port")
            return {"port": port, "open": False, "service": None, "error": str(e)}

    async def scan_range(
        self, host: str, start_port: int, end_port: int
    ) -> Dict[int, Dict[str, Any]]:
        """Scan a range of ports."""
        results = {}
        tasks = []

        for port in range(start_port, end_port + 1):
            tasks.append(self.check_port(host, port))

        semaphore = asyncio.Semaphore(self.concurrent)

        async def bounded_check(port_num: int) -> Dict[str, Any]:
            async with semaphore:
                return await self.check_port(host, port_num)

        bounded_tasks = [bounded_check(p) for p in range(start_port, end_port + 1)]

        for coro in asyncio.as_completed(bounded_tasks):
            result = await coro
            if result.get("open"):
                results[result["port"]] = result
                self.results[result["port"]] = result

        return results

    async def scan_ports(self, host: str, ports: List[int]) -> Dict[int, Dict[str, Any]]:
        """Scan specific ports."""
        results = {}
        semaphore = asyncio.Semaphore(self.concurrent)

        async def bounded_check(port_num: int) -> Dict[str, Any]:
            async with semaphore:
                return await self.check_port(host, port_num)

        tasks = [bounded_check(p) for p in ports]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result.get("open"):
                results[result["port"]] = result
                self.results[result["port"]] = result

        return results

    async def quick_scan(self, host: str, top_n: int = 20) -> Dict[int, Dict[str, Any]]:
        """Quick port scan for top common ports."""
        ports_to_scan = self.COMMON_PORTS[:top_n]
        return await self.scan_ports(host, ports_to_scan)

    async def scan_top_ports(self, host: str, count: int = 100) -> Dict[int, Dict[str, Any]]:
        """Scan top N ports."""
        ports_to_scan = self.TOP_PORTS_100[:count]
        return await self.scan_ports(host, ports_to_scan)

    def get_open_ports(self) -> List[int]:
        """Get list of open ports."""
        return sorted(self.results.keys())

    def get_results(self) -> Dict[int, Dict[str, Any]]:
        """Get all scan results."""
        return self.results

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


class DNSLookup:
    """DNS record lookup for domain reconnaissance."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    COMMON_DNS_SERVERS = [
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "9.9.9.9",
        "208.67.222.222",
    ]

    def __init__(self):
        self.error_collector = ModuleErrorCollector("dns_lookup")
        self.results: Dict[str, List[str]] = {}

    def _normalize_domain(self, value: str) -> str:
        """Normalize input to a bare domain."""
        candidate = value.strip()
        if "://" in candidate:
            parsed = urlparse(candidate)
            return (parsed.hostname or candidate).strip(".")
        return candidate.split("/")[0].strip(".")

    def lookup(
        self, domain: str, record_types: Optional[List[str]] = None
    ) -> Dict[str, List[str]]:
        """Perform DNS lookups for specified record types."""
        domain = self._normalize_domain(domain)
        self.results = {}

        if record_types is None:
            record_types = ["A", "MX", "NS", "TXT"]

        for record_type in record_types:
            if record_type.upper() not in self.RECORD_TYPES:
                continue

            try:
                answers = dns.resolver.resolve(domain, record_type.upper())
                records = [str(rdata) for rdata in answers]
                self.results[record_type.upper()] = records
            except dns.resolver.NXDOMAIN:
                self.error_collector.add(domain, "NXDOMAIN", f"lookup_{record_type}")
                self.results[record_type.upper()] = []
            except dns.resolver.NoAnswer:
                self.results[record_type.upper()] = []
            except dns.resolver.NoNameservers:
                self.error_collector.add(domain, "NoNameservers", f"lookup_{record_type}")
                self.results[record_type.upper()] = []
            except Exception as e:
                self.error_collector.add(domain, e, f"lookup_{record_type}")
                self.results[record_type.upper()] = []

        return self.results

    def reverse_lookup(self, ip: str) -> List[str]:
        """Perform reverse DNS lookup."""
        try:
            reverse_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(reverse_name, "PTR")
            return [str(answers[0]).rstrip(".")] if answers else []
        except dns.resolver.NXDOMAIN:
            return []
        except Exception as e:
            self.error_collector.add(ip, e, "reverse_lookup")
            return []

    def check_glue(self, domain: str) -> Dict[str, List[str]]:
        """Check for glue records (NS and A records for nameservers)."""
        results = {}
        try:
            answers = dns.resolver.resolve(domain, "NS")
            nameservers = [str(rdata) for rdata in answers]
            results["NS"] = nameservers

            for ns in nameservers[:5]:
                try:
                    a_answers = dns.resolver.resolve(ns, "A")
                    if "A" not in results:
                        results["A"] = []
                    results["A"].extend([str(rdata) for rdata in a_answers])
                except Exception:
                    pass

                try:
                    aaaa_answers = dns.resolver.resolve(ns, "AAAA")
                    if "AAAA" not in results:
                        results["AAAA"] = []
                    results["AAAA"].extend([str(rdata) for rdata in aaaa_answers])
                except Exception:
                    pass

        except Exception as e:
            self.error_collector.add(domain, e, "check_glue")

        return results

    def get_results(self) -> Dict[str, List[str]]:
        """Get all lookup results."""
        return self.results

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()

"""
VULNIX - Bug Bounty Reconnaissance Module
 subdomain enumeration, takeover detection, WHOIS, Wayback analysis
"""

import re
import json
import asyncio
import socket
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import dns.resolver
import dns.exception

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


SERVICE_FINGERPRINTS = {
    "github": {
        "domains": ["github.io", "github.com"],
        "pattern": "There isn't a GitHub Pages site here.",
        "status": [404],
    },
    "heroku": {
        "domains": ["herokuapp.com", "heroku.com"],
        "pattern": "No such app",
        "status": [404, 403],
    },
    "azure": {
        "domains": ["azurewebsites.net", "cloudapp.net"],
        "pattern": "404 Web Site not found",
        "status": [404],
    },
    "aws_s3": {
        "domains": ["s3.amazonaws.com", "aws.amazon.com"],
        "pattern": "NoSuchBucket|AccessDenied",
        "status": [404, 403],
    },
    "vercel": {
        "domains": ["vercel.app", "now.sh"],
        "pattern": "Not Found",
        "status": [404],
    },
    "netlify": {
        "domains": ["netlify.app", "netlify.com"],
        "pattern": "Not found",
        "status": [404],
    },
    "pagefront": {
        "domains": ["pagefront.com"],
        "pattern": "page not found",
        "status": [404],
    },
    "tilda": {
        "domains": ["tilda.ws", "tilda.co"],
        "pattern": "Domain is not connected",
        "status": [404],
    },
    "wordpress": {
        "domains": ["wordpress.com"],
        "pattern": "does not exist",
        "status": [404],
    },
    "strikingly": {
        "domains": ["strikingly.com", "trystrikingly.com"],
        "pattern": "Site not found",
        "status": [404],
    },
    "cloudflare": {
        "domains": ["cloudflare.net"],
        "pattern": "Origin not found",
        "status": [403],
    },
    "fastly": {
        "domains": ["fastly.net", "fastly.com"],
        "pattern": "Fastly error",
        "status": [404],
    },
    "firebase": {
        "domains": ["firebaseapp.com", "web.app"],
        "pattern": "not found",
        "status": [404],
    },
    "readme": {
        "domains": ["readme.io"],
        "pattern": "project not found",
        "status": [404],
    },
    "surge": {
        "domains": ["surge.sh"],
        "pattern": "project not found",
        "status": [404],
    },
    "clojars": {
        "domains": ["clojars.org"],
        "pattern": "Not found",
        "status": [404],
    },
    " JFrog": {
        "domains": ["jfrog.io", "jfrog.com"],
        "pattern": "404 Not Found",
        "status": [404],
    },
    "digitalocean": {
        "domains": ["digitalocean.com"],
        "pattern": "not found",
        "status": [404],
    },
    "launchrock": {
        "domains": ["launchrock.com"],
        "pattern": "Site not found",
        "status": [404],
    },
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", " registrar", "dns", "www2", "admin", "forum", "news", "vpn",
    "ns", "mail2", "new", "mysql", "old", "lists", "secure", "static",
    "demo", "cloud", "dev", "staging", "test", "api", "cdn", "assets",
    "img", "files", "storage", "backup", "proxy", "router", "gate", "mx",
    "blog", "git", "svn", "cvs", "bbs", "war", "irc", "facebook",
    "twitter", "linkedin", "instagram", "youtube", "pinterest", "tumblr", "flickr",
    "shop", "store", "cart", "checkout", "pay", "order", "account",
    "login", "signin", "signup", "register", "portal", "cp", "manage",
    "support", "help", "docs", "doc", "status", "cdn", "stats", "metrics",
    "monitor", "analytics", "dash", "dashboard", "control", "panel",
    "host", "server", "node", "db", "database", "sql", "redis",
    "mongo", "elasticsearch", "kibana", "log", "logs", "trac", "jenkins",
    "ci", "cd", "beta", "alpha", "prod", "qa", "sandbox",
    "app", "apps", "mobile", "m", "chat", "bots", "bot",
]

CNAME_ERROR_PATTERNS = [
    r"NoSuch(Bucket|Container|Deployment|App)",
    r"not found",
    r"404",
    r"does not exist",
    r"Domain is not connected",
    r"There.*isn't.*GitHub Pages",
    r"404 Not Found",
    r"Site not found",
    r"project not found",
    r"Invalid bucket name",
    r"AccessDenied",
]


class SubdomainEnumerator:
    """Fast passive subdomain enumeration."""

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
                try:
                    data = json.loads(response.text)
                    for cert in data:
                        for name in cert.get("name_value", "").split("\n"):
                            if domain in name and "*" not in name:
                                subdomains.append(name.strip().lower())
                except (json.JSONDecodeError, Exception) as e:
                    self.error_collector.add(url, e, "parse_crtsh")

        except Exception as e:
            self.error_collector.add(url, e, "request_crtsh")

        return list(set(subdomains))

    async def enumerate_from_dns(self, domain: str) -> List[str]:
        """Enumerate subdomains via common wordlist."""
        subdomains = []

        for sub in COMMON_SUBDOMAINS:
            candidate = f"{sub}.{domain}"

            try:
                answers = dns.resolver.resolve(candidate, "A")
                if answers:
                    subdomains.append(candidate)
            except (dns.exception.DNSException, socket.gaierror):
                pass

            try:
                answers = dns.resolver.resolve(candidate, "AAAA")
                if answers:
                    subdomains.append(candidate)
            except (dns.exception.DNSException, socket.gaierror):
                pass

        return list(set(subdomains))

    async def enumerate(self, domain: str) -> List[str]:
        """Enumerate subdomains using multiple sources."""
        domain = self._normalize_domain(domain)

        self.results = []

        crt_subdomains = await self.enumerate_from_crtsh(domain)
        self.results.extend(crt_subdomains)

        dns_subdomains = await self.enumerate_from_dns(domain)
        self.results.extend(dns_subdomains)

        self.results = list(set(self.results))
        self.results.sort()

        return self.results[:100]

    def get_results(self) -> List[str]:
        """Get all findings."""
        return self.results

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class SubdomainTakeover:
    """Detect subdomain takeover vulnerabilities."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("takeover")

    def _extract_cname(self, domain: str) -> Optional[str]:
        """Extract CNAME record for domain."""
        try:
            answers = dns.resolver.resolve(domain, "CNAME")
            if answers:
                return str(answers[0]).rstrip(".")
        except (dns.exception.DNSException, socket.gaierror):
            pass
        return None

    def _get_service_from_cname(self, cname: str) -> Optional[str]:
        """Identify service from CNAME."""
        cname_lower = cname.lower()

        for service, config in SERVICE_FINGERPRINTS.items():
            for domain in config.get("domains", []):
                if domain in cname_lower:
                    return service

        return None

    async def check_takeover(self, subdomain: str) -> Dict[str, Any]:
        """Check if subdomain is vulnerable to takeover."""
        result = {
            "subdomain": subdomain,
            "vulnerable": False,
            "service": None,
            "cname": None,
            "evidence": None,
        }

        cname = self._extract_cname(subdomain)
        if not cname:
            return result

        result["cname"] = cname

        service = self._get_service_from_cname(cname)
        if not service:
            return result

        result["service"] = service

        try:
            response = await self.request_engine.get(
                f"https://{subdomain}",
                allow_redirects=False,
            )

            if response:
                status = response.status_code
                body = response.text if response.text else ""

                config = SERVICE_FINGERPRINTS.get(service, {})
                patterns = config.get("pattern", "")
                statuses = config.get("status", [404])

                if status in statuses:
                    result["vulnerable"] = True
                    result["evidence"] = f"Status {status}"

                elif any(p.lower() in body.lower() for p in [patterns] if p):
                    result["vulnerable"] = True
                    result["evidence"] = f"Matched pattern: {patterns}"

        except Exception as e:
            self.error_collector.add(subdomain, e, "check_takeover")

        return result

    async def scan_subdomains(
        self,
        subdomains: List[str],
    ) -> List[Dict[str, Any]]:
        """Scan list of subdomains for takeover."""
        results = []

        for subdomain in subdomains:
            result = await self.check_takeover(subdomain)
            if result.get("vulnerable"):
                results.append(result)

        return results

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class WaybackAnalyzer:
    """Analyze historical data from Wayback Machine."""

    WAYBACK_API = "https://web.archive.org/cdx/search/cdx"

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("wayback")

    async def get_snapshots(self, domain: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get Wayback snapshots for domain."""
        snapshots = []

        try:
            url = f"{self.WAYBACK_API}?url=*.{domain}&output=json&limit={limit}"
            response = await self.request_engine.get(url)

            if response and response.status_code == 200:
                try:
                    data = json.loads(response.text)
                    for entry in data[1:]:
                        snapshots.append({
                            "timestamp": entry[1],
                            "url": entry[2],
                            "status": entry[4],
                            "mime": entry[5],
                        })
                except (json.JSONDecodeError, Exception) as e:
                    self.error_collector.add(domain, e, "parse_snapshots")

        except Exception as e:
            self.error_collector.add(domain, e, "fetch_snapshots")

        return snapshots

    async def find_endpoints(self, domain: str) -> List[str]:
        """Find interesting endpoints from Wayback."""
        endpoints = set()

        snapshots = await self.get_snapshots(domain, limit=200)

        for snap in snapshots:
            url = snap.get("url", "")
            if url:
                path = url.split(domain, 1)[-1] if domain in url else url

                if any(x in path for x in ["/api/", "/admin/", "/dashboard/", "/config/", "/backup/"]):
                    endpoints.add(path)

        return list(endpoints)[:20]

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class WHOISLookup:
    """WHOIS information lookup."""

    def __init__(self):
        self.error_collector = ModuleErrorCollector("whois")

    async def lookup(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for domain."""
        result = {
            "domain": domain,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "nameservers": [],
        }

        import whois

        try:
            w = whois.whois(domain)

            if w.registrar:
                result["registrar"] = w.registrar

            if w.creation_date:
                result["creation_date"] = (
                    w.creation_date[0].isoformat()
                    if isinstance(w.creation_date, list)
                    else w.creation_date.isoformat()
                )

            if w.expiration_date:
                result["expiration_date"] = (
                    w.expiration_date[0].isoformat()
                    if isinstance(w.expiration_date, list)
                    else w.expiration_date.isoformat()
                )

            if w.name_servers:
                result["nameservers"] = (
                    w.name_servers[:5]
                    if isinstance(w.name_servers, list)
                    else [w.name_servers]
                )

        except Exception as e:
            self.error_collector.add(domain, e, "whois_lookup")

        return result

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()
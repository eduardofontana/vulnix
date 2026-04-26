"""
VULNIX - Advanced Reconnaissance Module
JS Secret Extraction, Parameter Discovery, Pattern Matching, Content Fuzzing
"""

import re
import json
import asyncio
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


API_KEY_PATTERNS = [
    (r"api[_-]?key[=:]?\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "API Key"),
    (r"apikey[=:]?\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "API Key"),
    (r"secret[_-]?key[=:]?\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "Secret Key"),
    (r"token[=:]?\s*['\"]([a-zA-Z0-9_\-\.]{20,})['\"]", "Token"),
    (r"bearer\s+([a-zA-Z0-9_\-\.]{20,})", "Bearer Token"),
    (r"AWS_ACCESS_KEY_ID[=:]?\s*['\"]([A-Z0-9]{20})['\"]", "AWS Key"),
    (r"AWS_SECRET_ACCESS_KEY[=:]?\s*['\"]([a-zA-Z0-9/+\=]{40})['\"]", "AWS Secret"),
    (r"sk[_-]?live[a-zA-Z0-9]{20,}", "Stripe Key"),
    (r"sk_live_[a-zA-Z0-9]{20,}", "Stripe Live Key"),
    (r"github[_-]?token[=:]?\s*['\"]([a-zA-Z0-9]{35,})['\"]", "GitHub Token"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Token"),
    (r"xox[baprs]-[a-zA-Z0-9]{10,}", "Slack Token"),
    (r"EAACEdEose[0-9a-zA-Z]{20,}", "Facebook Token"),
    (r"[a-zA-Z0-9_-]*\.apps\.googleusercontent\.com", "Google OAuth"),
    (r"AIza[a-zA-Z0-9_\\-]{35}", "Google API Key"),
]

SENSITIVE_PATTERNS = [
    (r"password\s*=\s*['\"]([^'\"]+)['\"]", "Hardcoded Password"),
    (r"passwd\s*=\s*['\"]([^'\"]+)['\"]", "Hardcoded Password"),
    (r"pwd\s*=\s*['\"]([^'\"]+)['\"]", "Hardcoded Password"),
    (r"username\s*=\s*['\"]([^'\"]+)['\"]", "Hardcoded Username"),
    (r"user\s*=\s*['\"]([^'\"]+)['\"]", "Hardcoded Username"),
    (r"admin\s*:\s*['\"]([^'\"]+)['\"]", "Admin Credential"),
    (r"Authorization:\s*Basic\s+([a-zA-Z0-9+/=]+)", "Basic Auth"),
    (r"sqid_[a-zA-Z0-9]{20,}", "SQLi Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
]

PARAM_PATTERNS = [
    r'id',
    r'user[id]',
    r'user_id',
    r'account_id',
    r'product_id',
    r'order_id',
    r'transaction_id',
    r'session_id',
    r'token',
    r'verify',
    r'code',
    r'confirm',
    r'token',
    r'key',
    r'api_key',
    r'secret',
    r'access_token',
    r'refresh_token',
    r'auth',
    r'auth_token',
    r'jwt',
    r'bcrypt',
    r'debug',
    r'mode',
    r'format',
    r'q',
    r'search',
    r'query',
    r's',
    r'limit',
    r'offset',
    r'page',
    r'sort',
    r'order',
    r'dir',
    r'callback',
    r'cb',
    r'data',
    r'return',
    r'body',
    r'content',
    r'file',
    r'filename',
    r'path',
    r'url',
    r'REDIRECT_URL',
    r'redirect',
    r'return_url',
    r'returnUrl',
    r'u',
    r'next',
    r'referer',
    r'referrer',
    r'host',
    r'port',
    r'server',
    r'domain',
    r'subdomain',
    r'base',
    r'domain',
]

COMMON_PARAMS = [
    "id", "uid", "user_id", "order_id", "product_id", "category_id",
    "file", "page", "view", "action", "do", "download",
    "search", "query", "q", "s", "keyword",
    "lang", "l", "locale",
    "type", "mode", "view",
    "year", "month", "day", "date",
    "from", "to", "start", "end",
    "sort", "order", "dir",
    "limit", "offset", "start", "num",
    "debug", "test",
    "token", "key", "auth", "hash",
    "redirect", "url", "next",
    "ref", "referer",
]

GF_PATTERN_SIGNATURES = {
    "aws_keys": [
        r"AKIA[0-9A-Z]{16}",
        r"aws_access_key_id",
        r"aws_secret_access_key",
    ],
    "google_api": [
        r"AIza[0-9a-zA-Z_\\-]{35}",
        r"GOOGLE_API_KEY",
    ],
    "stripe_keys": [
        r"sk_live_[0-9a-zA-Z]{24,}",
        r"pk_live_[0-9a-zA-Z]{24,}",
    ],
    "sendgrid": [
        r"SG\.[a-zA-Z0-9_\\-]{22}\.[a-zA-Z0-9_\\-]{43}",
    ],
    "twilio": [
        r"AC[a-z0-9]{32}",
        r"SK[a-z0-9]{32}",
    ],
    "mailgun": [
        r"key-[0-9a-zA-Z]{32}",
    ],
    "passwords": [
        r"password\s*=\s*['\"][^'\"]{4,}",
        r"passwd\s*=\s*['\"][^'\"]{4,}",
    ],
    "jwt": [
        r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
    ],
    "private_key": [
        r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
    ],
    "firebase": [
        r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}",
    ],
    "github_oauth": [
        r"gho_[a-zA-Z0-9]{36}",
    ],
    "slack_token": [
        r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}",
    ],
}


class JSSecretExtractor:
    """Extract secrets and sensitive data from JavaScript files."""

    JS_EXTENSIONS = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".mjsx"]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("js_secrets")
        self.found_secrets: List[Dict[str, Any]] = []

    def _find_js_links(self, html: str) -> List[str]:
        """Find JavaScript file URLs in HTML."""
        js_links = []

        soup = BeautifulSoup(html, "html.parser")
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src:
                js_links.append(src)

        js_pattern = re.compile(r'src\s*=\s*["\']([^"\']+\.js[^"\']*)["\']')
        js_links.extend(js_pattern.findall(html))

        return js_links

    async def extract_from_page(self, url: str) -> List[Dict[str, Any]]:
        """Extract secrets from a page's JavaScript."""
        secrets = []

        try:
            response = await self.request_engine.get(url)

            if not response or response.status_code != 200:
                return secrets

            js_links = self._find_js_links(response.text)

            for js_url in set(js_links):
                full_url = urljoin(url, js_url)
                found = await self.extract_from_js(full_url)
                secrets.extend(found)

        except Exception as e:
            self.error_collector.add(url, e, "extract_from_page")

        return secrets

    async def extract_from_js(self, js_url: str) -> List[Dict[str, Any]]:
        """Extract secrets from a specific JS file."""
        secrets = []

        try:
            response = await self.request_engine.get(js_url)

            if not response or response.status_code != 200:
                return secrets

            content = response.text

            for pattern, label in API_KEY_PATTERNS:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches[:3]:
                    secrets.append({
                        "type": "api_key",
                        "subtype": label,
                        "file": js_url,
                        "match": match.group(0)[:50],
                        "severity": "high",
                    })

            for pattern, label in SENSITIVE_PATTERNS:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches[:2]:
                    secrets.append({
                        "type": "sensitive",
                        "subtype": label,
                        "file": js_url,
                        "match": match.group(0)[:50],
                        "severity": "medium",
                    })

            jwt_matches = re.findall(GF_PATTERN_SIGNATURES["jwt"][0], content)
            if jwt_matches:
                secrets.append({
                    "type": "jwt_token",
                    "subtype": "JWT",
                    "file": js_url,
                    "count": len(jwt_matches),
                    "severity": "high",
                })

        except Exception as e:
            self.error_collector.add(js_url, e, "extract_from_js")

        return secrets

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan target for JavaScript secrets."""
        findings = []

        target_url = target if target.startswith(("http://", "https://")) else f"https://{target}"

        secrets = await self.extract_from_page(target_url)

        if secrets:
            findings.extend(secrets)

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class ParameterDiscovery:
    """Discover hidden parameters for fuzzing."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("params")
        self.found_params: Set[str] = set()

    async def extract_from_html(self, url: str) -> List[str]:
        """Extract parameters from HTML forms."""
        params = []

        try:
            response = await self.request_engine.get(url)

            if not response or response.status_code != 200:
                return params

            soup = BeautifulSoup(response.text, "html.parser")

            for form in soup.find_all("form"):
                for input_tag in form.find_all(["input", "select", "textarea"]):
                    name = input_tag.get("name")
                    if name:
                        params.append(name)

            param_pattern = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=')
            params.extend(param_pattern.findall(response.text))

            input_pattern = re.compile(r'name\s*=\s*["\']([^"\']+)["\']')
            params.extend(input_pattern.findall(response.text))

        except Exception as e:
            self.error_collector.add(url, e, "extract_html")

        return list(set(params))

    async def extract_from_js(self, url: str) -> List[str]:
        """Extract parameters from JavaScript."""
        params = []

        try:
            response = await self.request_engine.get(url)

            if not response or response.status_code != 200:
                return params

            js_content = response.text

            for param in COMMON_PARAMS:
                if f'"{param}"' in js_content or f"'{param}'" in js_content:
                    params.append(param)

            fetch_pattern = re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']')
            matches = fetch_pattern.findall(js_content)
            for match in matches:
                if "?" in match:
                    query = match.split("?")[1]
                    for param in query.split("&"):
                        if "=" in param:
                            params.append(param.split("=")[0])

            ajax_pattern = re.compile(r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']')
            matches = ajax_pattern.findall(js_content)
            for match in matches:
                if "?" in match:
                    query = match.split("?")[1]
                    for param in query.split("&"):
                        if "=" in param:
                            params.append(param.split("=")[0])

        except Exception as e:
            self.error_collector.add(url, e, "extract_js")

        return list(set(params))

    async def extract_from_wayback(self, domain: str) -> List[str]:
        """Extract parameters from Wayback Machine."""
        params = []

        try:
            wayback_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit=1000"
            response = await self.request_engine.get(wayback_url)

            if not response or response.status_code != 200:
                return params

            try:
                data = response.json()
                for entry in data[1:]:
                    url = entry[2]
                    if "?" in url and domain in url:
                        query = url.split("?")[1]
                        for param in query.split("&"):
                            if "=" in param:
                                name = param.split("=")[0]
                                if len(name) < 30:
                                    params.append(name)
            except (json.JSONDecodeError, Exception):
                pass

        except Exception as e:
            self.error_collector.add(domain, e, "wayback")

        return list(set(params))

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan for hidden parameters."""
        findings = []

        target_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path.split("/")[0]

        html_params = await self.extract_from_html(target_url)
        js_params = await self.extract_from_js(target_url)
        wayback_params = await self.extract_from_wayback(domain)

        all_params = set(html_params + js_params + wayback_params)

        for param in sorted(all_params):
            findings.append({
                "type": "parameter",
                "parameter": param,
                "source": "discovered",
                "severity": "info",
            })

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class PatternMatcher:
    """Match sensitive patterns for security findings."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("patterns")

    async def scan_page(self, url: str) -> List[Dict[str, Any]]:
        """Scan a page for sensitive patterns."""
        findings = []

        try:
            response = await self.request_engine.get(url)

            if not response or response.status_code != 200:
                return findings

            content = response.text

            for category, patterns in GF_PATTERN_SIGNATURES.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        findings.append({
                            "type": "pattern_match",
                            "subtype": category,
                            "count": len(matches),
                            "severity": "high" if "key" in category else "medium",
                        })

        except Exception as e:
            self.error_collector.add(url, e, "scan_page")

        return findings

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan target for sensitive patterns."""
        return await self.scan_page(target)

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


class ContentFuzzer:
    """Directory and file discovery fuzzer."""

    DIRECTORY_WORDLIST = [
        "admin", "administrator", "login", "dashboard", "panel", "cp", "control",
        "api", "v1", "v2", "v3", "graphql", "rest", "soap",
        "admin panel", "administrator", "manage", "management",
        "config", "configuration", "settings", "setup",
        "backup", "backups", "backup.php", "backup.zip",
        "old", "new", "dev", "test", "staging", "stage",
        "includes", "include", "library", "lib", "libs",
        "images", "image", "img", "img", "photos", "upload",
        "css", "style", "styles", "js", "javascript",
        "assets", "static", "media", "files", "download",
        "docs", "documentation", "doc", "api-docs",
        "server-status", "server-info", "status",
        "phpmyadmin", "pma", "mysql", "database", "db",
        "wp-admin", "wordpress", "wp-content", "wp-includes",
        ".git", ".svn", ".env", ".htaccess",
        "sitemap.xml", "robots.txt",
        "login", "signin", "register", "signup", "forgot", "password",
        "user", "users", "profile", "account", "billing",
        "search", "find", "query", "ajax", "json",
    ]

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("fuzzer")
        self.found_paths: List[str] = []

    async def fuzz_directory(self, url: str, wordlist: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Fuzz for directories and files."""
        findings = []

        target = url if url.startswith(("http://", "https://")) else f"https://{url}"
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        paths = wordlist or self.DIRECTORY_WORDLIST

        for path in paths[:50]:
            test_urls = [
                f"{base}/{path}",
                f"{base}/{path}/",
            ]

            for test_url in test_urls:
                try:
                    response = await self.request_engine.get(test_url, allow_redirects=False)

                    if response and response.status_code in [200, 301, 302, 403]:
                        findings.append({
                            "type": "directory",
                            "path": test_url,
                            "status": response.status_code,
                            "severity": "info" if response.status_code == 403 else "low",
                        })
                        break

                except Exception as e:
                    self.error_collector.add(test_url, e, "fuzz")

        return findings

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan target for directories and files."""
        return await self.fuzz_directory(target)

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()
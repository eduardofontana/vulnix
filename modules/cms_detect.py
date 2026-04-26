"""
VULNIX - CMS Detection and CVE Fingerprinting Module
Detects CMS (WordPress, Joomla, Drupal, etc) and CVE fingerprints
"""

import re
import json
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


CMS_SIGNATURES = {
    "wordpress": {
        "paths": ["/wp-admin/", "/wp-content/", "/wp-includes/", "/wp-login.php", "/xmlrpc.php"],
        "cookies": ["wordpress_logged_in", "wp-settings", "wordpress_test_cookie"],
        "headers": ["X-Powered-By: WordPress"],
        "patterns": [
            r'/wp-content/themes/',
            r'/wp-content/plugins/',
            r'generator"[^>]*WordPress',
            r'wp-json',
            r'wp-admin',
        ],
        "meta": ["wordpress", "wordpress 3.", "wordpress 4.", "wordpress 5.", "wordpress 6."],
    },
    "joomla": {
        "paths": ["/administrator/", "/components/com_", "/media/jui/"],
        "cookies": ["joomla_user_state", "[a-z0-9]+" + "joomla"],
        "headers": [],
        "patterns": [
            r'/components/com_',
            r'/media/jui/',
            r'generator"[^>]*Joomla',
            r'option=com_',
            r'joomla',
        ],
        "meta": ["joomla", "joomla 3.", "joomla 4."],
    },
    "drupal": {
        "paths": ["/modules/", "/sites/default/", "/core/", "/themes/"],
        "cookies": ["SESS", "SSESS", "Drupal.visitor"],
        "headers": ["X-Generator: Drupal"],
        "patterns": [
            r'/modules/drupal',
            r'/sites/default/',
            r'drupal.settings',
            r'generator"[^>]*Drupal',
            r'drupal.org',
        ],
        "meta": ["drupal 7", "drupal 8", "drupal 9", "drupal 10"],
    },
    "magento": {
        "paths": ["/skin/frontend/", "/app/design/", "/media/logo.png"],
        "cookies": ["frontend", "PHPSESSID"],
        "headers": [],
        "patterns": [
            r'/skin/frontend/',
            r'/media/logo.png',
            r'Magento',
            r'catalog/product/view',
        ],
        "meta": ["magento"],
    },
    "drupal": {
        "paths": ["/modules/", "/sites/default/", "/core/", "/themes/"],
        "cookies": ["SESS", "SSESS", "Drupal.visitor"],
        "headers": ["X-Generator: Drupal"],
        "patterns": [
            r'/modules/drupal',
            r'/sites/default/',
            r'drupal.settings',
            r'generator"[^>]*Drupal',
            r'drupal.org',
        ],
        "meta": ["drupal 7", "drupal 8", "drupal 9", "drupal 10"],
    },
    "shopify": {
        "paths": ["/admin/", "/products/", "/collections/"],
        "cookies": ["shopify"],
        "headers": [],
        "patterns": [
            r'myshopify\.com',
            r'Shopify',
            r'/cdn\.shopify\.com',
        ],
        "meta": ["shopify"],
    },
    "wix": {
        "paths": ["/_wixns_"],
        "cookies": ["wixData"],
        "headers": [],
        "patterns": [
            r'wixsite\.com',
            r'wix\.com',
            r'wixInit',
            r'wix-bi',
        ],
        "meta": ["wix"],
    },
    "squarespace": {
        "paths": ["/static/", "/squarespace/"],
        "cookies": ["squarespace"],
        "headers": [],
        "patterns": [
            r'squarespace\.com',
            r'squarespace\.net',
            r'/static/',
        ],
        "meta": ["squarespace"],
    },
    "ghost": {
        "paths": ["/ghost/", "/content/"],
        "cookies": ["ghost-admin"],
        "headers": [],
        "patterns": [
            r'ghost\.org',
            r'/ghost/api/',
            r'generator"[^>]*Ghost',
        ],
        "meta": ["ghost"],
    },
    "prestashop": {
        "paths": ["/modules/", "/themes/"],
        "cookies": ["PrestaShop"],
        "headers": [],
        "patterns": [
            r'/modules/',
            r'prestashop',
            r'generator"[^>]*PrestaShop',
        ],
        "meta": ["prestashop"],
    },
    "bitrix": {
        "paths": ["/bitrix/", "/upload/"],
        "cookies": ["PHPSESSID"],
        "headers": [],
        "patterns": [
            r'bitrix',
            r'/bitrix/admin/',
            r'bitrix\.crm',
        ],
        "meta": ["bitrix"],
    },
    "sharepoint": {
        "paths": ["/_layouts/", "/_vti_bin/"],
        "cookies": ["SPWebSSOToken"],
        "headers": ["MicrosoftSharePointTeamServices"],
        "patterns": [
            r'sharepoint',
            r'_layouts',
            r'mso-',
        ],
        "meta": ["sharepoint"],
    },
}


VULNERABLE_VERSIONS = {
    "wordpress": {
        "versions": ["4.0", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8", "4.9"],
        "cves": ["CVE-2017-8292", "CVE-2017-9196", "CVE-2018-12895", "CVE-2019-8942", "CVE-2020-10700"],
    },
    "joomla": {
        "versions": ["3.0", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8"],
        "cves": ["CVE-2016-8869", "CVE-2017-7985", "CVE-2018-5803", "CVE-2019-10962"],
    },
    "drupal": {
        "versions": ["7.0", "7.1", "7.2", "7.3", "7.4", "7.5", "7.6", "8.0", "8.1", "8.2"],
        "cves": ["CVE-2018-7600", "CVE-2018-7602", "CVE-2019-6340", "CVE-2020-13671"],
    },
    "magento": {
        "versions": ["1.9", "2.0", "2.1", "2.2", "2.3"],
        "cves": ["CVE-2019-7836", "CVE-2020-7161", "CVE-2020-7162"],
    },
}


PLUGIN_VULNERABILITIES = {
    "wordpress": {
        "revslider": {"cve": "CVE-2014-9730", "severity": "critical"},
        "slider-revolution": {"cve": "CVE-2014-9730", "severity": "critical"},
        "wp-gallery-buttons": {"cve": "CVE-2023-23489", "severity": "high"},
        "contact-form-7": {"cve": "CVE-2020-27123", "severity": "medium"},
        "wordfence": {"cve": "CVE-2019-10015", "severity": "medium"},
        "yoast": {"cve": "CVE-2018-0532", "severity": "medium"},
        "elementor": {"cve": "CVE-2021-21750", "severity": "high"},
        "divi-builder": {"cve": "CVE-2021-21750", "severity": "high"},
        "wplite": {"cve": "CVE-2023-23489", "severity": "high"},
        "akismet": {"cve": "CVE-2020-8420", "severity": "medium"},
    },
    "joomla": {
        "com_weblinks": {"cve": "CVE-2020-11890", "severity": "high"},
        "com_fields": {"cve": "CVE-2018-7602", "severity": "critical"},
    },
}


class CMSDetector:
    """Detect Content Management Systems."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("cms")
        self.detected_cms: Dict[str, Any] = {}

    async def detect_from_url(self, url: str) -> Dict[str, Any]:
        """Detect CMS from URL and content."""
        result = {
            "cms": None,
            "version": None,
            "confidence": 0,
            "indicators": [],
            "paths_found": [],
        }

        try:
            response = await self.request_engine.get(url)

            if not response or response.status_code != 200:
                return result

            text = response.text[:50000]
            headers = dict(response.headers) if hasattr(response, "headers") else {}

            for cms_name, signatures in CMS_SIGNATURES.items():
                score = 0

                for path in signatures.get("paths", []):
                    if path in text.lower():
                        score += 2
                        result["paths_found"].append(path)

                for pattern in signatures.get("patterns", []):
                    if re.search(pattern, text, re.IGNORECASE):
                        score += 3

                for cookie_name in signatures.get("cookies", []):
                    if any(cookie_name.lower() in c.lower() for c in []):
                        score += 3

                for header_v in signatures.get("headers", []):
                    if any(header_v.lower() in str(v).lower() for v in headers.values()):
                        score += 2

                for meta in signatures.get("meta", []):
                    if meta.lower() in text.lower():
                        score += 2
                        version_match = re.search(rf'{meta}(\d+\.\d+)', text, re.IGNORECASE)
                        if version_match:
                            result["version"] = version_match.group(1)

                if score >= 3:
                    result["cms"] = cms_name
                    result["confidence"] = min(score, 10)
                    self.detected_cms = result
                    break

        except Exception as e:
            self.error_collector.add(url, e, "detect_cms")

        return result

    async def check_plugins(self, url: str) -> List[Dict[str, Any]]:
        """Check for vulnerable plugins."""
        plugins_found = []

        try:
            response = await self.request_engine.get(url)

            if not response or response.status_code != 200:
                return plugins_found

            text = response.text.lower()

            for plugin, info in PLUGIN_VULNERABILITIES.get("wordpress", {}).items():
                if plugin in text:
                    plugins_found.append({
                        "plugin": plugin,
                        "cve": info.get("cve"),
                        "severity": info.get("severity"),
                    })

        except Exception as e:
            self.error_collector.add(url, e, "check_plugins")

        return plugins_found

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan for CMS and CVE fingerprints."""
        findings = []

        target_url = target if target.startswith(("http://", "https://")) else f"https://{target}"

        cms_result = await self.detect_from_url(target_url)

        if cms_result.get("cms"):
            findings.append({
                "type": "cms_detection",
                "url": target_url,
                "cms": cms_result.get("cms"),
                "version": cms_result.get("version"),
                "confidence": cms_result.get("confidence"),
                "severity": "info",
                "description": f"Detected: {cms_result.get('cms')} {cms_result.get('version', '')}",
            })

        plugins = await self.check_plugins(target_url)
        for plugin in plugins:
            findings.append({
                "type": "vulnerable_plugin",
                "url": target_url,
                "plugin": plugin.get("plugin"),
                "cve": plugin.get("cve"),
                "severity": plugin.get("severity"),
                "description": f"Vulnerable plugin: {plugin.get('plugin')} ({plugin.get('cve')})",
            })

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()


EXPLOIT_SIGNATURES = {
    "sqlmap": {
        "headers": ["sqlmap/", "sqlmap-tag"],
        "patterns": ["sqlmap", "file not found", "sqlmap/"],
    },
    "nmap": {
        "headers": ["nmap", "nse"],
        "patterns": ["nmap", "nmap scan"],
    },
    "nikto": {
        "headers": ["nikto", "nikto-scan"],
        "patterns": ["nikto", "Nikto/", "nikto v"],
    },
    "metasploit": {
        "headers": ["metasploit"],
        "patterns": ["msf", "metasploit"],
    },
    "burp": {
        "headers": ["burp"],
        "patterns": ["burp suite", "portunload"],
    },
    "netcat": {
        "patterns": ["nc -", "netcat"],
    },
    "dirb": {
        "patterns": ["dirb", "DIRB"],
    },
    "gobuster": {
        "patterns": ["gobuster"],
    },
}


class ExploitDetection:
    """Detect if target is being scanned or exploited."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("exploit")
        self.scan_history: List[Dict[str, Any]] = []

    def detect_tools(self, response_text: str) -> List[str]:
        """Detect exploit tools from response."""
        detected = []

        for tool, signatures in EXPLOIT_SIGNATURES.items():
            for pattern in signatures.get("patterns", []):
                if pattern.lower() in response_text.lower():
                    detected.append(tool)
                    break

        return list(set(detected))

    def detect_404(self, response_text: str) -> bool:
        """Detect if response is a generic 404 page."""
        generic_404 = [
            "page not found",
            "not found",
            "404",
            "file not found",
            "the requested url was not found",
        ]

        text_lower = response_text.lower()
        if any(phrase in text_lower for phrase in generic_404):
            return True

        return False

    def detect_waf_block(self, response_text: str) -> bool:
        """Detect if request was blocked by WAF."""
        waf_indicators = [
            "blocked by",
            "security policy",
            "attack detected",
            "malicious request",
            "forbidden",
            "security check",
            "firewall",
        ]

        text_lower = response_text.lower()
        if any(indicator in text_lower for indicator in waf_indicators):
            return True

        return False

    async def analyze_response(self, url: str, response: Any) -> Dict[str, Any]:
        """Analyze response for exploit signatures."""
        result = {
            "blocked": False,
            "tool_detected": None,
            "is_404": False,
        }

        if response and hasattr(response, "text"):
            text = response.text

            tools = self.detect_tools(text)
            if tools:
                result["tool_detected"] = tools

            result["is_404"] = self.detect_404(text)

            result["blocked"] = self.detect_waf_block(text)

        return result

    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan for exploit activity."""
        findings = []

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()
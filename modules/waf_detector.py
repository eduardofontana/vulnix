"""
VULNIX - WAF Detection Module
Identify Web Application Firewalls and their characteristics
"""

import re
from typing import Dict, List, Optional, Any, Tuple
from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


class WAFDetector:
    """Detect and fingerprint Web Application Firewalls."""

    WAF_SIGNATURES = {
        "cloudflare": {
            "name": "Cloudflare",
            "headers": [
                (r"cf-ray", "CF-Ray"),
                (r"cf-cache-status", "CF-Cache-Status"),
                (r"__cf_bm", None),
                (r"cloudflare-nginx", "Server"),
            ],
            "body_patterns": [
                r"Attention Required! \| Cloudflare",
                r"cf-error-details",
                r"Cloudflare Ray ID",
                r"Ray ID:",
                r"cdn-cgi/badge",
            ],
            "status_codes": [403, 503],
            "severity_indicator": "blocked",
        },
        "aws_cloudfront": {
            "name": "AWS CloudFront",
            "headers": [
                (r"X-Amz-Cf-", "X-Amz-Cf"),
                (r"X-Amz-Cf-Id", "X-Amz-Cf-Id"),
            ],
            "body_patterns": [
                r"403 ERROR",
                r"The request could not be satisfied",
                r"CloudFront",
            ],
            "status_codes": [403],
            "severity_indicator": "blocked",
        },
        "akamai": {
            "name": "Akamai WAF",
            "headers": [
                (r"akamai-x-get-", "Akamai"),
                (r"X-Akamai-", "X-Akamai"),
                (r"akamai-origin-hop", "Server"),
            ],
            "body_patterns": [
                r"Reference #[0-9A-F]+",
                r"AkamaiGHost",
                r"Access denied",
            ],
            "status_codes": [403],
            "severity_indicator": "blocked",
        },
        "imperva": {
            "name": "Imperva SecureSphere",
            "headers": [
                (r"X-Iinfo", "X-Iinfo"),
                (r"x-cdn", "x-cdn"),
                (r"incapsula", "incapsula"),
            ],
            "body_patterns": [
                r"incapsula",
                r"incident ID",
                r"Imperva",
                r"_Incapsula_Resource",
            ],
            "status_codes": [403, 500],
            "severity_indicator": "blocked",
        },
        "f5_asm": {
            "name": "F5 Advanced WAF",
            "headers": [
                (r"X-CNC", None),
                (r"F5", None),
            ],
            "body_patterns": [
                r"Support ID: [0-9]+",
                r"The requested URL was rejected",
                r"Big-IP",
                r"F5 Networks",
            ],
            "status_codes": [403],
            "severity_indicator": "blocked",
        },
        "fortiweb": {
            "name": "FortiWeb WAF",
            "headers": [
                (r"FORTIGATE", "Server"),
            ],
            "body_patterns": [
                r"FortiWeb",
                r"FortiGate",
                r"Session Cookie",
            ],
            "status_codes": [403],
            "severity_indicator": "blocked",
        },
        "palo_alto": {
            "name": "Palo Alto WAF",
            "headers": [
                (r"x-", None),
            ],
            "body_patterns": [
                r"Palo Alto Networks",
                r"PAN Web Application Firewall",
            ],
            "status_codes": [403],
            "severity_indicator": "blocked",
        },
        "Sucuri": {
            "name": "Sucuri WAF",
            "headers": [
                (r"X-Sucuri-ID", "X-Sucuri-ID"),
                (r"X-Sucuri-Cache-Status", None),
            ],
            "body_patterns": [
                r"Sucuri",
                r"sucuri",
                r"Cloudproxy",
            ],
            "status_codes": [403],
            "severity_indicator": "blocked",
        },
        "stackpath": {
            "name": "StackPath WAF",
            "headers": [
                (r"x-cache", "x-cache"),
                (r"x-edge", "x-edge"),
            ],
            "body_patterns": [
                r"StackPath",
                r"maxcdn",
            ],
            "status_codes": [403],
            "severity_indicator": "blocked",
        },
        "aws_waf": {
            "name": "AWS WAF",
            "headers": [
                (r"x-amzn-requestid", None),
                (r"x-amz-cf-", None),
            ],
            "body_patterns": [
                r"403 ERROR",
                r"403 Forbidden",
                r" AWS WAF",
            ],
            "status_codes": [403, 405],
            "severity_indicator": "blocked",
        },
        "barracuda": {
            "name": "Barracuda WAF",
            "headers": [
                (r"barra_counter", None),
                (r"barracuda", None),
            ],
            "body_patterns": [
                r"Barracuda",
                r"You have been blocked",
            ],
            "status_codes": [403],
            "severity_indicator": "blocked",
        },
        "denyall": {
            "name": "DenyAll WAF",
            "headers": [
                (r"Set-Cookie", None),
            ],
            "body_patterns": [
                r"DenyAll",
                r"Condition",
                r"application/octet-stream",
            ],
            "status_codes": [403],
            "severity_indicator": "blocked",
        },
        "dotdefender": {
            "name": "dotDefender",
            "headers": [
                (r"dotDefender", None),
            ],
            "body_patterns": [
                r"dotDefender",
                r"Your request was blocked",
            ],
            "status_codes": [403],
            "severity_indicator": "blocked",
        },
        "radware": {
            "name": "Radware AppWall",
            "headers": [
                (r"RW_RAD", None),
            ],
            "body_patterns": [
                r"Radware",
                r"AppWall",
                r"waf_info",
            ],
            "status_codes": [403],
            "severity_indicator": "blocked",
        },
        "nginx": {
            "name": "NGINX WAF (generic)",
            "headers": [
                (r"nginx", "Server"),
            ],
            "body_patterns": [
                r"ngx_openresty",
            ],
            "status_codes": [403, 444],
            "severity_indicator": "blocked",
        },
    }

    BYPASS_PAYLOADS = {
        "sql_injection": [
            "' OR '1'='1",
            "1' AND 1=1--",
            "UNION SELECT NULL--",
            "admin'--",
            "1; DROP TABLE users--",
        ],
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
        ],
        "command_injection": [
            "| cat /etc/passwd",
            "; ls",
            "`whoami`",
            "$(whoami)",
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ],
    }

    def __init__(self, request_engine: RequestEngine):
        self.engine = request_engine
        self.waf_info: Optional[Dict[str, Any]] = None
        self.bypass_results: List[Dict[str, Any]] = []
        self.error_collector = ModuleErrorCollector("waf_detector")

    async def detect(self, url: str) -> Optional[Dict[str, Any]]:
        """Detect WAF at the target URL."""
        self.waf_info = None

        if not url.startswith("http"):
            url = f"http://{url}"

        baseline_response = await self.engine.get(url)
        if not baseline_response:
            return None

        self.waf_info = self._scan_headers(baseline_response.headers)

        if self.waf_info:
            return self.waf_info

        self.waf_info = await self._probe_for_waf(url, baseline_response)

        return self.waf_info

    def _scan_headers(self, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Scan response headers for WAF signatures."""
        header_text = " ".join([f"{k}: {v}" for k, v in headers.items()]).lower()

        for waf_id, signature in self.WAF_SIGNATURES.items():
            for pattern, _ in signature.get("headers", []):
                if re.search(pattern, header_text, re.IGNORECASE):
                    return {
                        "waf": signature["name"],
                        "waf_id": waf_id,
                        "detection_method": "header",
                        "confidence": 90,
                        "recommendation": self._get_bypass_recommendation(waf_id),
                    }

        server_header = headers.get("server", "").lower()
        if any(x in server_header for x in ["cloudflare", "akamai", "sucuri", "incapsula"]):
            for waf_id, signature in self.WAF_SIGNATURES.items():
                if waf_id in server_header or signature["name"].lower() in server_header:
                    return {
                        "waf": signature["name"],
                        "waf_id": waf_id,
                        "detection_method": "server_header",
                        "confidence": 70,
                        "recommendation": self._get_bypass_recommendation(waf_id),
                    }

        return None

    async def _probe_for_waf(self, url: str, baseline) -> Optional[Dict[str, Any]]:
        """Probe with payloads to detect WAF blocking."""
        test_payloads = [
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
        ]

        for payload in test_payloads:
            try:
                response = await self.engine.get(
                    url,
                    params={"test": payload} if "?" not in url else None,
                )

                if response and response.status_code == 403:
                    content = response.text.lower()

                    for waf_id, signature in self.WAF_SIGNATURES.items():
                        for pattern, _ in signature.get("body_patterns", []):
                            if re.search(pattern, content, re.IGNORECASE):
                                return {
                                    "waf": signature["name"],
                                    "waf_id": waf_id,
                                    "detection_method": "blocking_response",
                                    "confidence": 95,
                                    "blocked_payload": payload,
                                    "recommendation": self._get_bypass_recommendation(waf_id),
                                }

                    return {
                        "waf": "Unknown WAF",
                        "waf_id": "unknown",
                        "detection_method": "blocking_detected",
                        "confidence": 60,
                        "blocked_payload": payload,
                        "recommendation": "Try obfuscation techniques, IP rotation, or slow down requests",
                    }

            except Exception as e:
                self.error_collector.add(url, e, "probe_for_waf")
                continue

        return None

    def _get_bypass_recommendation(self, waf_id: str) -> str:
        """Get bypass recommendations for specific WAF."""
        recommendations = {
            "cloudflare": "Try randomizing User-Agent, adding proper headers, or using Cloudflare Flare resolver",
            "aws_waf": "Try HTTP/2, manipulating headers order, or using Lambda bypass techniques",
            "imperva": "Try removing TTL cookies, using older TLS versions, or header case manipulation",
            "akamai": "Try adding Origin header, using HTTP/3, or removing edge headers",
            "barracuda": "Try IP rotation, removing X-Forwarded-For, or slow requests",
            "f5_asm": "Try F5 cookie bypass, Long URI exhaustion, or method switching",
        }
        return recommendations.get(waf_id, "Try standard WAF bypass techniques")

    async def test_bypass(
        self,
        url: str,
        attack_type: str = "sql_injection"
    ) -> List[Dict[str, Any]]:
        """Test bypass techniques against detected WAF."""
        self.bypass_results = []

        if not self.waf_info:
            await self.detect(url)

        payloads = self.BYPASS_PAYLOADS.get(attack_type, self.BYPASS_PAYLOADS["sql_injection"])

        bypass_techniques = {
            "case_variation": lambda p: p.swapcase(),
            "comment_split": lambda p: p.replace("'", "/*comment*/'"),
            "null_byte": lambda p: p + "%00",
            "encoding": lambda p: p.replace("'", "%27"),
            "whitespace": lambda p: p.replace(" ", "/**/"),
            "double_encoding": lambda p: p.replace("'", "%2527"),
        }

        for payload in payloads:
            for technique, transform in bypass_techniques.items():
                modified_payload = transform(payload)

                try:
                    response = await self.engine.get(
                        url,
                        params={"q": modified_payload},
                        headers={"User-Agent": self.engine._get_random_user_agent()},
                    )

                    if response and response.status_code == 200:
                        self.bypass_results.append({
                            "technique": technique,
                            "original_payload": payload,
                            "bypassed_payload": modified_payload,
                            "status": "potentially_bypassed",
                            "severity": "high",
                            "url": url,
                            "waf": self.waf_info.get("waf") if self.waf_info else "Unknown",
                        })

                except Exception as e:
                    self.error_collector.add(url, e, f"test_bypass_{attack_type}")
                    continue

        return self.bypass_results

    def get_waf_info(self) -> Optional[Dict[str, Any]]:
        """Get information about detected WAF."""
        return self.waf_info

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get structured detector errors."""
        return self.error_collector.all()


class WAFPlugin:
    """Plugin wrapper for WAF detection."""

    name = "waf-detector"
    description = "Detect and fingerprint Web Application Firewalls"

    def __init__(self, request_engine: RequestEngine):
        self.detector = WAFDetector(request_engine)

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Run WAF detection."""
        result = await self.detector.detect(target)

        if result:
            return [{
                "type": "waf_detection",
                "severity": "info",
                "url": target,
                **result,
            }]

        return []

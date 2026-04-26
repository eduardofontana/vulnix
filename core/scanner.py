"""
VULNIX - Web Vulnerability Scanner
Scan Engine - Coordinates crawling, fuzzing, and vulnerability detection
"""

import asyncio
import json
import re
from typing import Dict, List, Optional, Any, Set, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

from core.crawler import Crawler, DiscoveredEndpoint
from core.request_engine import RequestEngine
from core.fuzzing import Fuzzer
from core.error_collector import ModuleErrorCollector
from modules.sqli import SQLiDetector
from modules.xss import XSSDetector
from modules.headers import SecurityHeadersAnalyzer
from modules.csrf import CSRFDetector
from modules.idor import IDORDetector
from modules.auth import AuthDetector
from modules.http_desync import HTTPDesyncDetector
from modules.cloud_metadata import CloudMetadataDetector
from modules.waf_detector import WAFDetector
from modules.websocket import WebSocketTester
from modules.cve_intel import CVEIntelligenceDetector
from modules.recon import (
    SubdomainEnumerator as ReconSubdomainEnumerator,
    TechnologyFingerprinter,
    PortScanner,
    DNSLookup,
)
from modules.bugbounty import (
    ParameterBruteforcer, CORSAnalyzer, JWTAnalyzer,
    HTTPHeaderInjection, OpenRedirectTester, ServerSideRequestForgery
)
from modules.ssl import SSLCertificateInfo
from modules.robots import RobotsSitemapAnalyzer
from modules.linkextractor import LinkExtractor
from modules.graphql import GraphQLScanner
from modules.rate_limit import RateLimitDetector
from modules.recon_more import (
    SubdomainTakeover,
    WaybackAnalyzer,
    WHOISLookup,
)
from modules.recon_advanced import (
    JSSecretExtractor,
    ParameterDiscovery,
    PatternMatcher,
    ContentFuzzer,
)
from modules.advanced_vulns import (
    SSTIDetector,
    LFIDetector,
    RaceConditionDetector,
    XXEDetector,
    DOMScanner,
)
from modules.cms_detect import CMSDetector, ExploitDetection
from config.settings import ScanConfig, VulnerabilityConfig, DEFAULT_WORDLIST


@dataclass
class Finding:
    """Represents a security finding."""

    id: str
    type: str
    url: str
    parameter: Optional[str]
    payload: Optional[str]
    severity: str
    description: str
    evidence: str
    remediation: Optional[str] = None
    module: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanResult:
    """Represents a complete scan result."""

    target: str
    start_time: str
    end_time: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    crawled_urls: int = 0
    scanned_endpoints: int = 0
    errors: List[Dict[str, Any]] = field(default_factory=list)


class ScanEngine:
    """Main scan engine coordinating all components."""

    def __init__(
        self,
        scan_config: Optional[ScanConfig] = None,
        vuln_config: Optional[VulnerabilityConfig] = None,
        verbose: bool = False,
        proxy_url: Optional[str] = None,
    ):
        self.scan_config = scan_config or ScanConfig()
        self.vuln_config = vuln_config or VulnerabilityConfig()
        self.verbose = verbose

        self.request_engine = RequestEngine(
            timeout=self.scan_config.timeout,
            max_retries=self.scan_config.max_retries,
            delay=self.scan_config.delay,
            follow_redirects=self.scan_config.follow_redirects,
            verify_ssl=self.scan_config.verify_ssl,
            proxy_url=proxy_url,
        )

        self.crawler = Crawler(
            request_engine=self.request_engine,
            max_depth=self.scan_config.max_depth,
            max_urls=self.scan_config.max_urls,
        )

        self.fuzzer = Fuzzer(
            request_engine=self.request_engine,
        )

        self.sqli_detector = SQLiDetector(
            request_engine=self.request_engine,
            fuzzer=self.fuzzer,
        )

        self.xss_detector = XSSDetector(
            request_engine=self.request_engine,
            fuzzer=self.fuzzer,
        )

        self.headers_analyzer = SecurityHeadersAnalyzer(
            request_engine=self.request_engine,
        )

        self.csrf_detector = CSRFDetector(
            request_engine=self.request_engine,
        )

        self.idor_detector = IDORDetector(
            request_engine=self.request_engine,
            fuzzer=self.fuzzer,
        )

        self.auth_detector = AuthDetector(
            request_engine=self.request_engine,
        )

        self.http_desync_detector = HTTPDesyncDetector(
            request_engine=self.request_engine,
        )

        self.cloud_metadata_detector = CloudMetadataDetector(
            request_engine=self.request_engine,
        )

        self.waf_detector = WAFDetector(
            request_engine=self.request_engine,
        )

        self.websocket_tester = WebSocketTester(
            request_engine=self.request_engine,
        )

        self.cve_detector = CVEIntelligenceDetector()
        self.cve_detector.set_offline(self.vuln_config.cve_intel_offline)

        self.subdomain_enum = ReconSubdomainEnumerator(
            request_engine=self.request_engine,
        )

        self.tech_fingerprint = TechnologyFingerprinter(
            request_engine=self.request_engine,
        )

        self.param_fuzzer = ParameterBruteforcer(
            request_engine=self.request_engine,
        )

        self.cors_analyzer = CORSAnalyzer(
            request_engine=self.request_engine,
        )

        self.jwt_analyzer = JWTAnalyzer(
            request_engine=self.request_engine,
        )

        self.ssrf_tester = ServerSideRequestForgery(
            request_engine=self.request_engine,
        )

        self.redirect_tester = OpenRedirectTester(
            request_engine=self.request_engine,
        )

        self.dns_lookup = DNSLookup()
        self.port_scanner = PortScanner(request_engine=self.request_engine)
        self.ssl_analyzer = SSLCertificateInfo(request_engine=self.request_engine)
        self.robots_analyzer = RobotsSitemapAnalyzer(request_engine=self.request_engine)
        self.link_extractor = LinkExtractor(request_engine=self.request_engine)
        self.graphql_scanner = GraphQLScanner(request_engine=self.request_engine)
        self.rate_limit_detector = RateLimitDetector(request_engine=self.request_engine)
        self.subdomain_takeover = SubdomainTakeover(request_engine=self.request_engine)
        self.wayback_analyzer = WaybackAnalyzer(request_engine=self.request_engine)
        self.whois_lookup = WHOISLookup()
        self.js_secret_extractor = JSSecretExtractor(request_engine=self.request_engine)
        self.param_discovery = ParameterDiscovery(request_engine=self.request_engine)
        self.pattern_matcher = PatternMatcher(request_engine=self.request_engine)
        self.content_fuzzer = ContentFuzzer(request_engine=self.request_engine)
        self.ssti_detector = SSTIDetector(request_engine=self.request_engine)
        self.lfi_detector = LFIDetector(request_engine=self.request_engine)
        self.race_detector = RaceConditionDetector(request_engine=self.request_engine)
        self.xxe_detector = XXEDetector(request_engine=self.request_engine)
        self.dom_scanner = DOMScanner(request_engine=self.request_engine)
        self.cms_detector = CMSDetector(request_engine=self.request_engine)
        self.exploit_detection = ExploitDetection(request_engine=self.request_engine)

        self.scan_result: Optional[ScanResult] = None
        self.wordlist: List[str] = DEFAULT_WORDLIST
        self.quick_scan: bool = False
        self.do_subdomain_enum: bool = False
        self.subdomain_bruteforce: bool = False
        self.do_tech_fingerprint: bool = False
        self.do_param_fuzz: bool = False
        self.do_cors_check: bool = False
        self.do_ssrf_check: bool = False
        self.do_redirect_check: bool = False
        self.do_jwt_check: bool = False
        self.do_dns_lookup: bool = False
        self.dns_records: Optional[List[str]] = None
        self.do_port_scan: bool = False
        self.port_range: Optional[str] = None
        self.top_ports: int = 20
        self.do_ssl_analysis: bool = False
        self.do_tls_check: bool = False
        self.do_robots_analysis: bool = False
        self.do_sitemap_analysis: bool = False
        self.do_link_extraction: bool = False
        self.do_graphql_scan: bool = False
        self.do_rate_limit: bool = False
        self.do_takeover: bool = False
        self.do_wayback: bool = False
        self.do_whois: bool = False
        self.do_js_secrets: bool = False
        self.do_param_discovery: bool = False
        self.do_content_fuzz: bool = False
        self.do_pattern_scan: bool = False
        self.do_ssti: bool = False
        self.do_lfi: bool = False
        self.do_race: bool = False
        self.do_xxe: bool = False
        self.do_dom: bool = False
        self.do_cms: bool = False
        self._error_collectors: Dict[str, ModuleErrorCollector] = {}
        self._captured_error_signatures: Set[tuple] = set()
        self.event_callback: Optional[Callable[[Dict[str, Any]], None]] = None

    def _log(self, message: str) -> None:
        """Log verbose message."""
        if self.verbose:
            print(f"[VERBOSE] {message}")

    def _emit_event(self, event_type: str, **data: Any) -> None:
        """Emit structured scanner events to external observers."""
        if not self.event_callback:
            return
        event = {
            "type": event_type,
            "timestamp": datetime.now().isoformat(),
            **data,
        }
        try:
            self.event_callback(event)
        except Exception:
            # Telemetry failures must never stop scan execution.
            return

    def _infer_module_from_finding(self, finding_data: Dict[str, Any]) -> str:
        """Infer module name for reporting enrichment."""
        finding_type = str(finding_data.get("type", "unknown")).lower()
        subtype = str(finding_data.get("subtype", "")).lower()

        if finding_type == "http_smuggling":
            return "http_desync"
        if finding_type == "websocket":
            return "websocket"
        if finding_type in {"waf_detection", "waf_bypass"}:
            return "waf"
        if finding_type == "ssrf" and subtype.startswith("cloud_metadata"):
            return "cloud_metadata"
        return finding_type

    @staticmethod
    def _extract_tech_version_from_description(description: str) -> tuple[Optional[str], Optional[str]]:
        """Extract technology and optional version from 'Detected:' descriptions."""
        if not description.startswith("Detected:"):
            return None, None
        label = description.replace("Detected:", "", 1).strip()
        version_match = re.search(r"\(version:\s*([^)]+)\)", label, re.IGNORECASE)
        if version_match:
            version = version_match.group(1).strip()
            tech = re.sub(r"\(version:\s*([^)]+)\)", "", label, flags=re.IGNORECASE).strip()
            return (tech or None), (version or None)
        return (label or None), None

    @staticmethod
    def _compose_tech_label(tech: str, version: Optional[str]) -> str:
        if version:
            return f"{tech}@{version}"
        return tech

    def _record_error(
        self,
        module: str,
        url: str,
        error: Exception | str,
        phase: str,
    ) -> None:
        """Record a structured scan error."""
        if not self.scan_result:
            return

        collector = self._error_collectors.get(module)
        if collector is None:
            collector = ModuleErrorCollector(module)
            self._error_collectors[module] = collector

        collector.add(url, error, phase)
        latest_error = collector.all()[-1]
        signature = (
            latest_error.get("module"),
            latest_error.get("phase"),
            latest_error.get("url"),
            latest_error.get("error"),
        )
        if signature not in self._captured_error_signatures:
            self._captured_error_signatures.add(signature)
            self.scan_result.errors.append(latest_error)
            self._emit_event(
                "module_error",
                module=module,
                phase=phase,
                url=url,
                error=str(error),
            )

    async def _execute_step(
        self,
        module: str,
        url: str,
        phase: str,
        operation: Callable[[], Any],
        default: Any,
    ) -> Any:
        """Execute a scan step and convert failures to structured errors."""
        try:
            self._emit_event("module_started", module=module, phase=phase, url=url)
            result = await operation()
            result_count = len(result) if isinstance(result, (list, dict, set, tuple)) else None
            self._emit_event(
                "module_completed",
                module=module,
                phase=phase,
                url=url,
                result_count=result_count,
            )
            return result
        except Exception as e:
            self._record_error(module, url, e, phase)
            return default

    def _collect_module_errors(
        self,
        module_instance: Any,
        fallback_module: str,
    ) -> None:
        """Merge structured errors from child modules into scan result."""
        if not self.scan_result or not hasattr(module_instance, "get_errors"):
            return

        try:
            errors = module_instance.get_errors()
        except Exception as e:
            self._record_error("scanner", fallback_module, e, "collect_module_errors")
            return

        for entry in errors or []:
            if not isinstance(entry, dict):
                self._record_error(fallback_module, fallback_module, str(entry), "module_error_non_dict")
                continue

            module = str(entry.get("module") or fallback_module)
            phase = str(entry.get("phase") or "unknown")
            url = str(entry.get("url") or fallback_module)
            error = str(entry.get("error") or "unknown")
            signature = (module, phase, url, error)

            if signature in self._captured_error_signatures:
                continue
            self._captured_error_signatures.add(signature)

            normalized = dict(entry)
            normalized.setdefault("module", module)
            normalized.setdefault("phase", phase)
            normalized.setdefault("url", url)
            normalized.setdefault("error", error)
            normalized.setdefault("timestamp", datetime.now().isoformat())
            self.scan_result.errors.append(normalized)

    def _collect_all_module_errors(self) -> None:
        """Collect structured errors from scanner dependencies."""
        modules_to_collect = [
            (self.request_engine, "request_engine"),
            (self.crawler, "crawler"),
            (self.fuzzer, "fuzzing"),
            (self.sqli_detector, "sqli"),
            (self.xss_detector, "xss"),
            (self.idor_detector, "idor"),
            (self.auth_detector, "auth"),
            (self.http_desync_detector, "http_desync"),
            (self.cloud_metadata_detector, "cloud_metadata"),
            (self.waf_detector, "waf_detector"),
            (self.websocket_tester, "websocket"),
            (self.cve_detector, "cve_intel"),
            (self.subdomain_enum, "subdomain_enum"),
            (self.tech_fingerprint, "tech_fingerprint"),
            (self.param_fuzzer, "param_fuzz"),
            (self.cors_analyzer, "cors"),
            (self.jwt_analyzer, "jwt"),
            (self.ssrf_tester, "ssrf"),
            (self.redirect_tester, "open_redirect"),
            (self.dns_lookup, "dns_lookup"),
            (self.port_scanner, "port_scan"),
            (self.ssl_analyzer, "ssl_cert"),
            (self.robots_analyzer, "robots_sitemap"),
            (self.link_extractor, "link_extractor"),
            (self.graphql_scanner, "graphql"),
            (self.rate_limit_detector, "rate_limit"),
            (self.subdomain_takeover, "takeover"),
            (self.wayback_analyzer, "wayback"),
            (self.whois_lookup, "whois"),
            (self.js_secret_extractor, "js_secrets"),
            (self.param_discovery, "params"),
            (self.pattern_matcher, "patterns"),
            (self.content_fuzzer, "fuzz"),
            (self.ssti_detector, "ssti"),
            (self.lfi_detector, "lfi"),
            (self.race_detector, "race"),
            (self.xxe_detector, "xxe"),
            (self.dom_scanner, "dom"),
            (self.cms_detector, "cms"),
        ]
        for module_instance, fallback in modules_to_collect:
            self._collect_module_errors(module_instance, fallback)

    async def crawl_target(self, target: str) -> List[DiscoveredEndpoint]:
        """Crawl target to discover endpoints."""
        self._log(f"Starting crawl on {target}")
        endpoints = await self.crawler.crawl(target)
        self._log(f"Crawl complete: {len(endpoints)} endpoints discovered")
        return endpoints

    async def scan_sqli(self, endpoints: List[DiscoveredEndpoint]) -> List[Dict[str, Any]]:
        """Scan for SQL injection vulnerabilities."""
        if not self.vuln_config.enable_sqli:
            return []

        self._log("Starting SQL injection scan")
        findings = []

        for i, endpoint in enumerate(endpoints[:10]):
            url = endpoint.url
            self._log(f"Testing {url} ({i+1}/10)")
            parameters = endpoint.parameters or [inp["name"] for inp in endpoint.form_inputs]

            if not parameters:
                continue

            endpoint_findings = await self.sqli_detector.scan_endpoint(
                url, parameters, endpoint.method
            )
            if endpoint_findings:
                self._log(f"SQLi found: {len(endpoint_findings)} findings")
            findings.extend(endpoint_findings)

        self._log(f"SQLi scan complete: {len(findings)} findings")
        return findings

    async def scan_xss(self, endpoints: List[DiscoveredEndpoint]) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities."""
        if not self.vuln_config.enable_xss:
            return []

        self._log("Starting XSS scan")
        findings = []

        for i, endpoint in enumerate(endpoints[:10]):
            url = endpoint.url
            self._log(f"Testing {url} ({i+1}/10)")
            parameters = endpoint.parameters or [inp["name"] for inp in endpoint.form_inputs]

            if not parameters:
                continue

            endpoint_findings = await self.xss_detector.scan_endpoint(
                url, parameters, endpoint.method
            )
            if endpoint_findings:
                self._log(f"XSS found: {len(endpoint_findings)} findings")
            findings.extend(endpoint_findings)

        self._log(f"XSS scan complete: {len(findings)} findings")
        return findings

    async def scan_headers(self, target: str) -> List[Dict[str, Any]]:
        """Scan security headers."""
        if not self.vuln_config.enable_headers:
            return []

        self._log("Analyzing security headers")
        result = await self.headers_analyzer.analyze_url(target)
        
        if isinstance(result, dict):
            findings = result.get("security_headers", [])
        elif isinstance(result, list):
            findings = result
        else:
            findings = []
            
        self._log(f"Headers analysis complete: {len(findings)} headers checked")
        return findings

    async def scan_directories(
        self, target: str, wordlist: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Scan for common directories and files."""
        if not self.vuln_config.enable_dirscan:
            return []

        self._log("Starting directory scan")
        findings = []
        wordlist = wordlist or self.wordlist

        base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"

        for i, path in enumerate(wordlist[:20]):
            url = f"{base_url.rstrip('/')}/{path}"
            if self.verbose:
                print(f"[DIRSCAN] Testing: {path}")

            response = await self.request_engine.get(url)

            if response and response.status_code == 200:
                self._log(f"Found: {url} (200 OK)")
                findings.append(
                    {
                        "type": "directory_discovery",
                        "url": url,
                        "status_code": response.status_code,
                        "severity": "info",
                    }
                )

        self._log(f"Directory scan complete: {len(findings)} found")
        return findings

    async def scan_websocket(self, target: str) -> List[Dict[str, Any]]:
        """Scan WebSocket endpoints for security issues."""
        if not self.vuln_config.enable_websocket:
            return []

        self._log("Starting WebSocket security scan")
        findings: List[Dict[str, Any]] = []
        endpoints = await self.websocket_tester.discover(target)

        for endpoint in endpoints[:10]:
            scan_endpoint = endpoint
            if endpoint.startswith("https://"):
                scan_endpoint = "wss://" + endpoint[len("https://"):]
            elif endpoint.startswith("http://"):
                scan_endpoint = "ws://" + endpoint[len("http://"):]

            protocol = "wss" if scan_endpoint.startswith("wss://") else "ws"
            endpoint_findings = await self.websocket_tester.test_endpoint(scan_endpoint, protocol)
            findings.extend(endpoint_findings)

        self._log(f"WebSocket scan complete: {len(findings)} findings")
        return findings

    async def full_scan(
        self,
        target: str,
        progress_callback: Optional[Callable[[str], None]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> ScanResult:
        """Perform a full vulnerability scan."""
        target_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        start_time = datetime.now().isoformat()

        self.scan_result = ScanResult(target=target, start_time=start_time)
        self._captured_error_signatures.clear()
        self.event_callback = event_callback
        self.request_engine.event_callback = event_callback
        self._emit_event("scan_started", target=target_url)

        if progress_callback:
            progress_callback("Crawling target...")

        endpoints = await self._execute_step(
            module="crawler",
            url=target_url,
            phase="crawl",
            operation=lambda: self.crawl_target(target_url),
            default=[],
        )
        self.scan_result.crawled_urls = len(endpoints)

        if progress_callback:
            progress_callback(f"Found {len(endpoints)} endpoints")

        all_findings = []

        from urllib.parse import urlparse as urllib_urlparse

        parsed_target = urllib_urlparse(target_url)
        target_ip = None
        host = parsed_target.hostname or target

        if progress_callback:
            progress_callback("Scanning for SQL injection...")

        sqli_findings = await self._execute_step(
            module="sqli",
            url=target_url,
            phase="scan",
            operation=lambda: self.scan_sqli(endpoints),
            default=[],
        )
        all_findings.extend(sqli_findings)

        if progress_callback:
            progress_callback("Scanning for XSS...")

        xss_findings = await self._execute_step(
            module="xss",
            url=target_url,
            phase="scan",
            operation=lambda: self.scan_xss(endpoints),
            default=[],
        )
        all_findings.extend(xss_findings)

        if progress_callback:
            progress_callback("Analyzing security headers...")

        headers_findings = await self._execute_step(
            module="headers",
            url=target_url,
            phase="analyze",
            operation=lambda: self.scan_headers(target_url),
            default=[],
        )
        for finding in headers_findings:
            all_findings.append(
                {
                    "type": "security_header",
                    "url": target_url,
                    "header": finding.get("header", ""),
                    "present": finding.get("present", False),
                    "severity": finding.get("severity", "low"),
                    "description": finding.get("description", ""),
                }
            )

        if self.vuln_config.enable_dirscan:
            if progress_callback:
                progress_callback("Scanning directories...")

            dir_findings = await self._execute_step(
                module="dirscan",
                url=target_url,
                phase="scan",
                operation=lambda: self.scan_directories(target_url),
                default=[],
            )
            all_findings.extend(dir_findings)

        if self.vuln_config.enable_csrf:
            if progress_callback:
                progress_callback("Checking CSRF protection...")

            for endpoint in endpoints[:5]:
                csrf_findings = await self._execute_step(
                    module="csrf",
                    url=endpoint.url,
                    phase="scan_endpoint",
                    operation=lambda endpoint_url=endpoint.url: self.csrf_detector.scan_endpoint(endpoint_url),
                    default=[],
                )
                all_findings.extend(csrf_findings)

        if self.vuln_config.enable_idor:
            if progress_callback:
                progress_callback("Checking for IDOR...")

            for endpoint in endpoints[:5]:
                parameters = endpoint.parameters or []
                idor_findings = await self._execute_step(
                    module="idor",
                    url=endpoint.url,
                    phase="scan_endpoint",
                    operation=lambda endpoint_url=endpoint.url, params=parameters: self.idor_detector.scan_endpoint(
                        endpoint_url, params
                    ),
                    default=[],
                )
                all_findings.extend(idor_findings)

        if self.vuln_config.enable_auth:
            if progress_callback:
                progress_callback("Checking authentication...")

            auth_findings = await self._execute_step(
                module="auth",
                url=target_url,
                phase="scan",
                operation=lambda: self.auth_detector.check_authentication_flow(target_url),
                default=[],
            )
            all_findings.extend(auth_findings)

        if self.vuln_config.enable_http_desync:
            if progress_callback:
                progress_callback("Checking for HTTP request smuggling/desync...")

            desync_findings = await self._execute_step(
                module="http_desync",
                url=target_url,
                phase="scan",
                operation=lambda: self.http_desync_detector.scan(target_url),
                default=[],
            )
            all_findings.extend(desync_findings)

        if self.vuln_config.enable_cloud_metadata:
            if progress_callback:
                progress_callback("Checking cloud metadata SSRF exposure...")

            cloud_metadata_findings = await self._execute_step(
                module="cloud_metadata",
                url=target_url,
                phase="scan",
                operation=lambda: self.cloud_metadata_detector.scan(target_url),
                default=[],
            )
            all_findings.extend(cloud_metadata_findings)

        run_waf_detection = self.vuln_config.enable_waf_detection or self.vuln_config.enable_waf_bypass
        if run_waf_detection:
            if progress_callback:
                progress_callback("Detecting WAF protections...")

            waf_info = await self._execute_step(
                module="waf_detector",
                url=target_url,
                phase="detect",
                operation=lambda: self.waf_detector.detect(target_url),
                default=None,
            )

            if self.vuln_config.enable_waf_detection and waf_info:
                all_findings.append(
                    {
                        "type": "waf_detection",
                        "url": target_url,
                        "severity": "info",
                        "description": (
                            f"Detected WAF: {waf_info.get('waf', 'Unknown')} "
                            f"via {waf_info.get('detection_method', 'unknown')}"
                        ),
                        **waf_info,
                    }
                )

        if self.vuln_config.enable_waf_bypass:
            if progress_callback:
                progress_callback("Testing WAF bypass techniques...")

            waf_bypass_results = await self._execute_step(
                module="waf_detector",
                url=target_url,
                phase="bypass",
                operation=lambda: self.waf_detector.test_bypass(target_url),
                default=[],
            )

            for bypass in waf_bypass_results:
                all_findings.append(
                    {
                        "type": "waf_bypass",
                        "url": bypass.get("url", target_url),
                        "severity": bypass.get("severity", "high"),
                        "payload": bypass.get("bypassed_payload"),
                        "description": (
                            f"Potential WAF bypass via technique: {bypass.get('technique', 'unknown')}"
                        ),
                        **bypass,
                    }
                )

        if self.vuln_config.enable_websocket:
            if progress_callback:
                progress_callback("Testing WebSocket security...")

            websocket_findings = await self._execute_step(
                module="websocket",
                url=target_url,
                phase="scan",
                operation=lambda: self.scan_websocket(target_url),
                default=[],
            )
            all_findings.extend(websocket_findings)

        if self.vuln_config.enable_cve_intel:
            if progress_callback:
                progress_callback("Correlating CVEs from technology fingerprint...")

            tech_candidates = set()
            for finding in all_findings:
                if finding.get("type") == "technology":
                    desc = str(finding.get("description", ""))
                    tech_name, tech_version = self._extract_tech_version_from_description(desc)
                    if tech_name:
                        tech_candidates.add(self._compose_tech_label(tech_name, tech_version))

            if not tech_candidates:
                inferred_techs = await self._execute_step(
                    module="tech_fingerprint",
                    url=target_url,
                    phase="cve_prereq",
                    operation=lambda: self.tech_fingerprint.fingerprint(target_url),
                    default={},
                )
                inferred_versions = self.tech_fingerprint.get_last_versions()
                inferred_confidence = self.tech_fingerprint.get_confidence_scores()
                inferred_evidence_sources = self.tech_fingerprint.get_evidence_sources()
                for tech, found in inferred_techs.items():
                    if found:
                        version = inferred_versions.get(tech)
                        confidence = inferred_confidence.get(tech)
                        evidence_sources = inferred_evidence_sources.get(tech, [])
                        tech_candidates.add(self._compose_tech_label(tech, version))
                        description = f"Detected: {tech}"
                        if version:
                            description = f"Detected: {tech} (version: {version})"
                        all_findings.append(
                            {
                                "type": "technology",
                                "url": target_url,
                                "severity": "info",
                                "description": description,
                                "details": {
                                    "confidence": confidence,
                                    "evidence_sources": evidence_sources,
                                },
                            }
                        )

            cve_findings = await self._execute_step(
                module="cve_intel",
                url=target_url,
                phase="scan",
                operation=lambda: self.cve_detector.scan(target_url, sorted(tech_candidates)),
                default=[],
            )
            all_findings.extend(cve_findings)

        run_cors = self.quick_scan or self.do_cors_check
        run_jwt = self.quick_scan or self.do_jwt_check
        run_ssrf = self.quick_scan or self.do_ssrf_check

        if run_cors:
            if progress_callback:
                progress_callback("Checking CORS configuration...")

            cors_findings = await self._execute_step(
                module="cors",
                url=target_url,
                phase="scan",
                operation=lambda: self.cors_analyzer.analyze(target_url),
                default=[],
            )
            all_findings.extend(cors_findings)

        if run_jwt:
            if progress_callback:
                progress_callback("Checking JWT handling...")

            jwt_findings = await self._execute_step(
                module="jwt",
                url=target_url,
                phase="scan",
                operation=lambda: self.jwt_analyzer.check_jwt(target_url),
                default=[],
            )
            all_findings.extend(jwt_findings)

        if run_ssrf:
            if progress_callback:
                progress_callback("Checking for SSRF...")

            ssrf_findings = await self._execute_step(
                module="ssrf",
                url=target_url,
                phase="scan",
                operation=lambda: self.ssrf_tester.test_ssrf(target_url, ["url", "uri", "src", "dest"]),
                default=[],
            )
            all_findings.extend(ssrf_findings)

        if self.do_redirect_check:
            if progress_callback:
                progress_callback("Checking open redirects...")

            redirect_findings = await self._execute_step(
                module="open_redirect",
                url=target_url,
                phase="scan",
                operation=lambda: self.redirect_tester.test_redirects(target_url),
                default=[],
            )
            all_findings.extend(redirect_findings)

        if self.do_param_fuzz:
            if progress_callback:
                progress_callback("Fuzzing hidden parameters...")

            param_results = await self._execute_step(
                module="param_fuzz",
                url=target_url,
                phase="scan",
                operation=lambda: self.param_fuzzer.fuzz_parameters(target_url),
                default=[],
            )
            for param_result in param_results:
                all_findings.append({
                    "type": "parameter_discovery",
                    "url": param_result.get("url", target_url),
                    "parameter": param_result.get("parameter"),
                    "severity": "info",
                    "description": f"Hidden parameter candidate found: {param_result.get('parameter')}",
                })

        if self.do_subdomain_enum:
            if progress_callback:
                progress_callback("Enumerating subdomains...")

            parsed_target = urlparse(
                target_url
            )
            target_domain = parsed_target.hostname or target
            subdomains = await self._execute_step(
                module="subdomain_enum",
                url=target_domain,
                phase="scan",
                operation=lambda: self.subdomain_enum.enumerate(
                    target_domain,
                    brute=self.subdomain_bruteforce,
                ),
                default=[],
            )
            for sub in subdomains[:50]:
                all_findings.append({
                    "type": "subdomain",
                    "url": f"http://{sub}",
                    "severity": "info",
                    "description": f"Found subdomain: {sub}",
                })

        if self.do_tech_fingerprint:
            if progress_callback:
                progress_callback("Fingerprinting technologies...")

            techs = await self._execute_step(
                module="tech_fingerprint",
                url=target_url,
                phase="scan",
                operation=lambda: self.tech_fingerprint.fingerprint(target_url),
                default={},
            )
            tech_versions = self.tech_fingerprint.get_last_versions()
            tech_confidence = self.tech_fingerprint.get_confidence_scores()
            tech_evidence_sources = self.tech_fingerprint.get_evidence_sources()
            for tech, found in techs.items():
                if found:
                    version = tech_versions.get(tech)
                    confidence = tech_confidence.get(tech)
                    evidence_sources = tech_evidence_sources.get(tech, [])
                    description = f"Detected: {tech}"
                    if version:
                        description = f"Detected: {tech} (version: {version})"
                    all_findings.append({
                        "type": "technology",
                        "url": target_url,
                        "severity": "info",
                        "description": description,
                        "details": {
                            "confidence": confidence,
                            "evidence_sources": evidence_sources,
                        },
                    })

        if self.do_dns_lookup:
            if progress_callback:
                progress_callback("Performing DNS lookup...")

            target_domain = parsed_target.hostname or target
            try:
                dns_results = await asyncio.to_thread(
                    self.dns_lookup.lookup, target_domain, self.dns_records
                )
            except Exception as e:
                self._record_error("dns_lookup", target_domain, e, "lookup")
                dns_results = {}
            
            if isinstance(dns_results, dict):
                for record_type, values in dns_results.items():
                    if isinstance(values, list):
                        for value in values[:10]:
                            all_findings.append({
                                "type": "dns_record",
                                "url": target_domain,
                                "severity": "info",
                                "description": f"DNS {record_type}: {value}",
                                "details": {"record_type": record_type, "value": value},
                            })

        if self.do_port_scan:
            if progress_callback:
                progress_callback("Scanning ports...")

            target_ip_for_scan = target_ip
            if not target_ip_for_scan:
                try:
                    import socket
                    target_ip_for_scan = socket.gethostbyname(host)
                except Exception:
                    target_ip_for_scan = parsed_target.hostname or target

            port_results = await self._execute_step(
                module="port_scan",
                url=target_ip_for_scan,
                phase="scan",
                operation=lambda: self.port_scanner.scan_top_ports(
                    target_ip_for_scan, self.top_ports
                ),
                default={},
            )
            if isinstance(port_results, dict):
                for port, info in port_results.items():
                    if isinstance(info, dict):
                        all_findings.append({
                            "type": "port",
                            "url": target_url,
                            "severity": "info",
                            "description": f"Port {port} open ({info.get('service', 'unknown')})",
                            "details": {"port": port, "service": info.get("service", "unknown"), "open": info.get("open", False)},
                        })

        if self.do_ssl_analysis:
            if progress_callback:
                progress_callback("Analyzing SSL/TLS certificate...")

            try:
                ssl_results = await asyncio.to_thread(
                    self.ssl_analyzer.analyze, target_url
                )
            except Exception as e:
                self._record_error("ssl_cert", target_url, e, "analyze")
                ssl_results = {}

            if isinstance(ssl_results, dict) and ssl_results.get("certificate"):
                cert = ssl_results["certificate"]
                all_findings.append({
                    "type": "ssl_cert",
                    "url": target_url,
                    "severity": "info",
                    "description": f"SSL Certificate: {cert.get('subject', 'N/A')} (expires: {cert.get('not_after', 'N/A')})",
                    "details": cert,
                })

        if self.do_robots_analysis:
            if progress_callback:
                progress_callback("Analyzing robots.txt...")

            try:
                robots_results = await self.robots_analyzer.parse_robots(target_url)
            except Exception as e:
                self._record_error("robots_sitemap", target_url, e, "robots")
                robots_results = {}

            if isinstance(robots_results, dict) and robots_results.get("found"):
                disallowed = robots_results.get("disallowed_paths", [])
                all_findings.append({
                    "type": "robots_txt",
                    "url": target_url,
                    "severity": "info",
                    "description": f"robots.txt found with {len(disallowed)} disallowed paths",
                    "details": robots_results,
                })

        if self.do_sitemap_analysis:
            if progress_callback:
                progress_callback("Analyzing sitemap...")

            try:
                sitemap_results = await self.robots_analyzer.parse_sitemap(target_url)
            except Exception as e:
                self._record_error("robots_sitemap", target_url, e, "sitemap")
                sitemap_results = {}

            if isinstance(sitemap_results, dict) and sitemap_results.get("found"):
                urls = sitemap_results.get("urls", [])
                all_findings.append({
                    "type": "sitemap",
                    "url": target_url,
                    "severity": "info",
                    "description": f"sitemap.xml found with {len(urls)} URLs",
                    "details": sitemap_results,
                })

        if self.do_link_extraction:
            if progress_callback:
                progress_callback("Extracting links...")

            try:
                link_results = await self.link_extractor.extract_from_url(target_url)
            except Exception as e:
                self._record_error("link_extractor", target_url, e, "extract")
                link_results = {}

            if isinstance(link_results, dict) and link_results:
                categorized = link_results.get("categorized", {})
                api_endpoints = categorized.get("api_endpoints", [])
                all_findings.append({
                    "type": "link_extraction",
                    "url": target_url,
                    "severity": "info",
                    "description": f"Extracted {link_results.get('total_internal', 0)} internal, {link_results.get('total_external', 0)} external links, {len(api_endpoints)} API endpoints",
                    "details": link_results,
                })

        if self.do_graphql_scan:
            if progress_callback:
                progress_callback("Scanning GraphQL endpoints...")

            try:
                graphql_results = await self.graphql_scanner.scan(target_url)
            except Exception as e:
                self._record_error("graphql", target_url, e, "scan")
                graphql_results = []

            for gq_result in graphql_results:
                all_findings.append({
                    "type": gq_result.get("type", "graphql"),
                    "url": gq_result.get("endpoint", target_url),
                    "severity": gq_result.get("severity", "info"),
                    "description": gq_result.get("description", ""),
                    "details": {k: v for k, v in gq_result.items() if k not in {"type", "endpoint", "severity", "description"}},
                })

        if self.do_rate_limit:
            if progress_callback:
                progress_callback("Detecting rate limiting...")

            try:
                rate_results = await self.rate_limit_detector.scan(target_url)
            except Exception as e:
                self._record_error("rate_limit", target_url, e, "scan")
                rate_results = []

            for rl_result in rate_results:
                all_findings.append({
                    "type": rl_result.get("type", "rate_limit"),
                    "url": target_url,
                    "severity": rl_result.get("severity", "info"),
                    "description": rl_result.get("description", ""),
                    "details": {k: v for k, v in rl_result.items() if k not in {"type", "url", "severity", "description"}},
                })

        if self.do_takeover:
            if progress_callback:
                progress_callback("Checking subdomain takeover...")

            try:
                target_domain = parsed_target.hostname or target
                subdomains = await self.subdomain_takeover.scan_subdomains([target_domain])
            except Exception as e:
                self._record_error("takeover", target_domain, e, "scan")
                subdomains = []

            for tk_result in subdomains:
                all_findings.append({
                    "type": "subdomain_takeover",
                    "url": f"https://{tk_result.get('subdomain', '')}",
                    "severity": "high",
                    "description": f"Potential takeover: {tk_result.get('service', 'unknown')} service",
                    "details": {k: v for k, v in tk_result.items() if k not in {"subdomain", "vulnerable"}},
                })

        if self.do_wayback:
            if progress_callback:
                progress_callback("Analyzing Wayback snapshots...")

            try:
                target_domain = parsed_target.hostname or target
                snapshots = await self.wayback_analyzer.get_snapshots(target_domain)
            except Exception as e:
                self._record_error("wayback", target_domain, e, "scan")
                snapshots = []

            if snapshots:
                all_findings.append({
                    "type": "wayback_snapshots",
                    "url": target_url,
                    "severity": "info",
                    "description": f"Found {len(snapshots)} historical snapshots",
                    "details": {"snapshots": snapshots[:10]},
                })

        if self.do_whois:
            if progress_callback:
                progress_callback("Performing WHOIS lookup...")

            try:
                target_domain = parsed_target.hostname or target
                whois_data = await self.whois_lookup.lookup(target_domain)
            except Exception as e:
                self._record_error("whois", target_domain, e, "lookup")
                whois_data = {}

            if whois_data and whois_data.get("registrar"):
                all_findings.append({
                    "type": "whois_info",
                    "url": target_url,
                    "severity": "info",
                    "description": f"Registrar: {whois_data.get('registrar', 'N/A')}",
                    "details": whois_data,
                })

        if self.do_js_secrets:
            if progress_callback:
                progress_callback("Extracting JavaScript secrets...")

            try:
                js_findings = await self.js_secret_extractor.scan(target_url)
            except Exception as e:
                self._record_error("js_secrets", target_url, e, "scan")
                js_findings = []

            for js_finding in js_findings:
                all_findings.append({
                    "type": js_finding.get("type", "js_secret"),
                    "url": js_finding.get("file", target_url),
                    "severity": js_finding.get("severity", "medium"),
                    "description": f"{js_finding.get('subtype', 'Secret')}: {js_finding.get('match', js_finding.get('count', ''))}",
                    "details": {k: v for k, v in js_finding.items() if k not in {"type", "file", "severity", "description"}},
                })

        if self.do_param_discovery:
            if progress_callback:
                progress_callback("Discovering hidden parameters...")

            try:
                param_findings = await self.param_discovery.scan(target_url)
            except Exception as e:
                self._record_error("params", target_url, e, "scan")
                param_findings = []

            for param in param_findings[:50]:
                all_findings.append({
                    "type": "hidden_parameter",
                    "url": target_url,
                    "severity": "info",
                    "description": f"Found parameter: {param.get('parameter')}",
                })

        if self.do_content_fuzz:
            if progress_callback:
                progress_callback("Fuzzing directories...")

            try:
                fuzz_findings = await self.content_fuzzer.scan(target_url)
            except Exception as e:
                self._record_error("fuzz", target_url, e, "scan")
                fuzz_findings = []

            for ff in fuzz_findings:
                all_findings.append({
                    "type": ff.get("type", "directory"),
                    "url": ff.get("path", target_url),
                    "severity": ff.get("severity", "low"),
                    "description": f"Found: {ff.get('path')} (status: {ff.get('status')})",
                })

        if self.do_pattern_scan:
            if progress_callback:
                progress_callback("Scanning patterns...")

            try:
                pattern_findings = await self.pattern_matcher.scan(target_url)
            except Exception as e:
                self._record_error("patterns", target_url, e, "scan")
                pattern_findings = []

            for pf in pattern_findings:
                all_findings.append({
                    "type": "pattern_match",
                    "url": target_url,
                    "severity": pf.get("severity", "medium"),
                    "description": f"Found {pf.get('count', 1)}x {pf.get('subtype', 'pattern')}",
                    "details": {"pattern_type": pf.get("subtype")},
                })

        if self.do_ssti:
            if progress_callback:
                progress_callback("Testing for SSTI...")

            try:
                ssti_findings = await self.ssti_detector.scan_endpoint(
                    target_url, ["q", "search", "query", "s", "id", "page"]
                )
            except Exception as e:
                self._record_error("ssti", target_url, e, "scan")
                ssti_findings = []

            for sf in ssti_findings:
                all_findings.append({
                    "type": sf.get("type", "ssti"),
                    "url": sf.get("url", target_url),
                    "parameter": sf.get("parameter"),
                    "severity": sf.get("severity", "high"),
                    "description": f"SSTI detected ({sf.get('template', 'unknown')})",
                    "details": {"template": sf.get("template"), "payload": sf.get("payload")},
                })

        if self.do_lfi:
            if progress_callback:
                progress_callback("Testing for LFI...")

            try:
                lfi_findings = await self.lfi_detector.scan_endpoint(
                    target_url, ["file", "path", "page", "doc", "template"]
                )
            except Exception as e:
                self._record_error("lfi", target_url, e, "scan")
                lfi_findings = []

            for lf in lfi_findings:
                all_findings.append({
                    "type": lf.get("type", "lfi"),
                    "url": lf.get("url", target_url),
                    "parameter": lf.get("parameter"),
                    "severity": lf.get("severity", "high"),
                    "description": f"{lf.get('type', 'LFI').upper()} detected",
                    "details": {"payload": lf.get("payload")},
                })

        if self.do_race:
            if progress_callback:
                progress_callback("Testing for race conditions...")

            try:
                race_findings = await self.race_detector.scan_endpoint(
                    target_url, ["amount", "quantity", "token", "id"]
                )
            except Exception as e:
                self._record_error("race", target_url, e, "scan")
                race_findings = []

            for rf in race_findings:
                all_findings.append({
                    "type": rf.get("type", "race_condition"),
                    "url": rf.get("url", target_url),
                    "parameter": rf.get("parameter"),
                    "severity": rf.get("severity", "medium"),
                    "description": f"Race condition detected",
                    "details": {"evidence": rf.get("evidence")},
                })

        if self.do_xxe:
            if progress_callback:
                progress_callback("Testing for XXE...")

            try:
                xxe_findings = await self.xxe_detector.scan_endpoint(target_url)
            except Exception as e:
                self._record_error("xxe", target_url, e, "scan")
                xxe_findings = []

            for xf in xxe_findings:
                all_findings.append({
                    "type": xf.get("type", "xxe"),
                    "url": xf.get("url", target_url),
                    "severity": xf.get("severity", "high"),
                    "description": "XXE vulnerability detected",
                    "details": {"payload": xf.get("payload")},
                })

        if self.do_dom:
            if progress_callback:
                progress_callback("Scanning for DOM vulnerabilities...")

            try:
                dom_findings = await self.dom_scanner.scan(
                    target_url, ["q", "search", "query"]
                )
            except Exception as e:
                self._record_error("dom", target_url, e, "scan")
                dom_findings = []

            for df in dom_findings:
                all_findings.append({
                    "type": df.get("type", "dom"),
                    "url": df.get("url", target_url),
                    "parameter": df.get("parameter"),
                    "severity": df.get("severity", "medium"),
                    "description": f"DOM vulnerability: {df.get('type', 'unknown')}",
                    "details": {"source": df.get("source")},
                })

        if self.do_cms:
            if progress_callback:
                progress_callback("Detecting CMS...")

            try:
                cms_findings = await self.cms_detector.scan(target_url)
            except Exception as e:
                self._record_error("cms", target_url, e, "scan")
                cms_findings = []

            for cf in cms_findings:
                severity = cf.get("severity", "info")
                all_findings.append({
                    "type": cf.get("type", "cms"),
                    "url": cf.get("url", target_url),
                    "parameter": cf.get("plugin"),
                    "severity": severity,
                    "description": cf.get("description", ""),
                    "details": {
                        "cms": cf.get("cms"),
                        "version": cf.get("version"),
                        "cve": cf.get("cve"),
                    },
                })

        for finding_data in all_findings:
            base_keys = {
                "id",
                "type",
                "url",
                "parameter",
                "payload",
                "severity",
                "description",
                "evidence",
                "remediation",
                "module",
            }
            details = {k: v for k, v in finding_data.items() if k not in base_keys}
            if "details" in details:
                details = details.get("details", {})
            finding = Finding(
                id=f"finding_{len(self.scan_result.findings) + 1}",
                type=finding_data.get("type", "unknown"),
                url=finding_data.get("url", target_url),
                parameter=finding_data.get("parameter"),
                payload=finding_data.get("payload"),
                severity=finding_data.get("severity", "low"),
                description=finding_data.get("description", ""),
                evidence=(
                    finding_data.get("evidence")
                    or finding_data.get("payload")
                    or finding_data.get("blocked_payload")
                    or finding_data.get("data_leaked")
                    or ""
                ),
                remediation=finding_data.get("remediation"),
                module=finding_data.get("module") or self._infer_module_from_finding(finding_data),
                details=details,
            )
            self.scan_result.findings.append(finding)
            self._emit_event(
                "finding_detected",
                module=finding.module,
                severity=finding.severity,
                finding_type=finding.type,
                url=finding.url,
            )

        self.scan_result.end_time = datetime.now().isoformat()
        self.scan_result.scanned_endpoints = len(endpoints)
        self._collect_all_module_errors()
        self._emit_event(
            "scan_completed",
            target=target_url,
            findings=len(self.scan_result.findings),
            errors=len(self.scan_result.errors),
            scanned_endpoints=self.scan_result.scanned_endpoints,
        )

        return self.scan_result

    def get_findings_by_severity(
        self, severity: str
    ) -> List[Finding]:
        """Get findings filtered by severity."""
        if not self.scan_result:
            return []

        return [
            f for f in self.scan_result.findings
            if f.severity.lower() == severity.lower()
        ]

    def get_findings_by_type(self, vuln_type: str) -> List[Finding]:
        """Get findings filtered by type."""
        if not self.scan_result:
            return []

        return [
            f for f in self.scan_result.findings
            if f.type.lower() == vuln_type.lower()
        ]

    def reset(self) -> None:
        """Reset scan engine state."""
        self.crawler.reset()
        self.sqli_detector.reset()
        self.xss_detector.reset()
        self.headers_analyzer.reset()
        self._captured_error_signatures.clear()
        self.scan_result = None

    async def close(self) -> None:
        """Release scanner resources."""
        await self.request_engine.close()

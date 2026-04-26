"""
VULNIX - Web Vulnerability Scanner
Scan Engine - Coordinates crawling, fuzzing, and vulnerability detection
"""

import asyncio
import json
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
from modules.recon import SubdomainEnumerator, TechnologyFingerprinter
from modules.bugbounty import (
    ParameterBruteforcer, CORSAnalyzer, JWTAnalyzer,
    HTTPHeaderInjection, OpenRedirectTester, ServerSideRequestForgery
)
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

        self.subdomain_enum = SubdomainEnumerator(
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
        self._error_collectors: Dict[str, ModuleErrorCollector] = {}
        self._captured_error_signatures: Set[tuple] = set()

    def _log(self, message: str) -> None:
        """Log verbose message."""
        if self.verbose:
            print(f"[VERBOSE] {message}")

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
            return await operation()
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
            (self.subdomain_enum, "subdomain_enum"),
            (self.tech_fingerprint, "tech_fingerprint"),
            (self.param_fuzzer, "param_fuzz"),
            (self.cors_analyzer, "cors"),
            (self.jwt_analyzer, "jwt"),
            (self.ssrf_tester, "ssrf"),
            (self.redirect_tester, "open_redirect"),
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
        findings = await self.headers_analyzer.analyze_url(target)
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
    ) -> ScanResult:
        """Perform a full vulnerability scan."""
        target_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        start_time = datetime.now().isoformat()

        self.scan_result = ScanResult(target=target, start_time=start_time)
        self._captured_error_signatures.clear()

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
            for tech, found in techs.items():
                if found:
                    all_findings.append({
                        "type": "technology",
                        "url": target_url,
                        "severity": "info",
                        "description": f"Detected: {tech}",
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

        self.scan_result.end_time = datetime.now().isoformat()
        self.scan_result.scanned_endpoints = len(endpoints)
        self._collect_all_module_errors()

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

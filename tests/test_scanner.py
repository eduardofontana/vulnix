"""
VULNIX - Test Scanner
Unit Tests for VULNIX Scanner
"""

import asyncio
import pytest
from unittest.mock import Mock, AsyncMock, patch

from core.crawler import Crawler, DiscoveredEndpoint
from core.request_engine import RequestEngine
from core.fuzzing import Fuzzer
from core.scanner import ScanEngine, ScanResult, Finding
from core.analyzer import ReportGenerator
from modules.sqli import SQLiDetector
from modules.xss import XSSDetector
from modules.headers import SecurityHeadersAnalyzer
from modules.auth import AuthDetector
from modules.idor import IDORDetector
from modules.recon import SubdomainEnumerator, TechnologyFingerprinter, PortScanner
from modules.cloud_metadata import CloudMetadataDetector
from modules.http_desync import HTTPDesyncDetector
from modules.waf_detector import WAFDetector
from modules.websocket import WebSocketTester
from core.state import ScanState
from modules.bugbounty import (
    JWTAnalyzer,
    OpenRedirectTester,
    ServerSideRequestForgery,
    ParameterBruteforcer,
    HTTPMethodTampering,
    CORSAnalyzer,
    HTTPHeaderInjection,
)
from cli.commands import VulnixCLI
from config.settings import (
    ScanConfig,
    VulnerabilityConfig,
    PAYLOADS,
    XSS_PAYLOADS,
    SECURITY_HEADERS,
)


class TestRequestEngine:
    """Test RequestEngine."""

    def test_init(self):
        """Test initialization."""
        engine = RequestEngine(timeout=10, max_retries=2, delay=0.1)
        assert engine.timeout == 10
        assert engine.max_retries == 2
        assert engine.delay == 0.1

    def test_user_agent_randomization(self):
        """Test user agent rotation."""
        engine = RequestEngine()
        ua1 = engine._get_random_user_agent()
        ua2 = engine._get_random_user_agent()
        assert ua1 in RequestEngine.USER_AGENTS
        assert ua2 in RequestEngine.USER_AGENTS

    def test_cookie_management(self):
        """Test cookie handling."""
        engine = RequestEngine()
        engine.set_cookie("session", "test123")
        assert "session" in engine.session_cookies
        engine.clear_cookies()
        assert len(engine.session_cookies) == 0


class TestCrawler:
    """Test Crawler."""

    def test_init(self):
        """Test initialization."""
        engine = RequestEngine()
        crawler = Crawler(engine, max_depth=2, max_urls=50)
        assert crawler.max_depth == 2
        assert crawler.max_urls == 50
        assert len(crawler.visited_urls) == 0

    def test_normalize_url(self):
        """Test URL normalization."""
        engine = RequestEngine()
        crawler = Crawler(engine)
        
        assert crawler._normalize_url("/path", "https://example.com") == "https://example.com/path"
        assert crawler._normalize_url("path", "https://example.com") == "https://example.com/path"

    def test_extract_parameters(self):
        """Test parameter extraction."""
        engine = RequestEngine()
        crawler = Crawler(engine)
        
        params = crawler._extract_parameters("https://example.com?id=1&name=test")
        assert "id" in params
        assert "name" in params

    def test_reset(self):
        """Test reset functionality."""
        engine = RequestEngine()
        crawler = Crawler(engine)
        crawler.visited_urls.add("https://example.com")
        crawler.reset()
        assert len(crawler.visited_urls) == 0


class TestFuzzer:
    """Test Fuzzer."""

    def test_init(self):
        """Test initialization."""
        engine = RequestEngine()
        fuzzer = Fuzzer(engine, similarity_threshold=0.9)
        assert fuzzer.similarity_threshold == 0.9

    def test_compute_hash(self):
        """Test hash computation."""
        engine = RequestEngine()
        fuzzer = Fuzzer(engine)
        
        hash1 = fuzzer._compute_hash("test")
        hash2 = fuzzer._compute_hash("test")
        assert hash1 == hash2
        assert hash1 != fuzzer._compute_hash("test2")

    def test_diff_ratio(self):
        """Test diff ratio computation."""
        engine = RequestEngine()
        fuzzer = Fuzzer(engine)
        
        ratio = fuzzer._diff_ratio("hello world", "hello world")
        assert ratio == 0.0


class TestSQLiDetector:
    """Test SQLi Detector."""

    def test_init(self):
        """Test initialization."""
        engine = RequestEngine()
        fuzzer = Fuzzer(engine)
        detector = SQLiDetector(engine, fuzzer)
        
        assert len(detector.ERROR_PATTERNS) > 0
        assert len(detector.results) == 0

    def test_payloads(self):
        """Test SQLi payloads."""
        assert len(PAYLOADS.SQLI) > 0
        assert "' OR '1'='1" in PAYLOADS.SQLI


class TestXSSDetector:
    """Test XSS Detector."""

    def test_init(self):
        """Test initialization."""
        engine = RequestEngine()
        fuzzer = Fuzzer(engine)
        detector = XSSDetector(engine, fuzzer)
        
        assert len(detector.results) == 0

    def test_payloads(self):
        """Test XSS payloads."""
        assert len(XSS_PAYLOADS.REFLECTED) > 0
        assert "<script>alert(1)</script>" in XSS_PAYLOADS.REFLECTED


class TestSecurityHeadersAnalyzer:
    """Test Security Headers Analyzer."""

    def test_init(self):
        """Test initialization."""
        engine = RequestEngine()
        analyzer = SecurityHeadersAnalyzer(engine)
        
        assert len(SecurityHeadersAnalyzer.REQUIRED_HEADERS) > 0

    def test_header_descriptions(self):
        """Test header descriptions."""
        assert "Content-Security-Policy" in SecurityHeadersAnalyzer.HEADER_DESCRIPTIONS
        assert "X-Frame-Options" in SecurityHeadersAnalyzer.HEADER_DESCRIPTIONS


class TestScanEngine:
    """Test ScanEngine."""

    def test_init(self):
        """Test initialization."""
        scanner = ScanEngine()
        
        assert scanner.request_engine is not None
        assert scanner.crawler is not None
        assert scanner.fuzzer is not None

    def test_config(self):
        """Test config initialization."""
        scan_config = ScanConfig(max_depth=5, max_urls=200)
        vuln_config = VulnerabilityConfig(enable_sqli=False)
        
        scanner = ScanEngine(scan_config, vuln_config)
        
        assert scanner.scan_config.max_depth == 5
        assert scanner.scan_config.max_urls == 200
        assert scanner.vuln_config.enable_sqli == False


class TestReportGenerator:
    """Test ReportGenerator."""

    def test_init(self):
        """Test initialization."""
        generator = ReportGenerator()
        
        assert len(ReportGenerator.SEVERITY_COLORS) == 5

    def test_severity_colors(self):
        """Test severity color mapping."""
        assert ReportGenerator.SEVERITY_COLORS["critical"] == "#ff0000"
        assert ReportGenerator.SEVERITY_COLORS["high"] == "#ff6600"
        assert ReportGenerator.SEVERITY_COLORS["medium"] == "#ffcc00"
        assert ReportGenerator.SEVERITY_COLORS["low"] == "#3399ff"
        assert ReportGenerator.SEVERITY_COLORS["info"] == "#00cc66"


class TestScanConfig:
    """Test ScanConfig."""

    def test_defaults(self):
        """Test default values."""
        config = ScanConfig()
        
        assert config.max_depth == 3
        assert config.max_urls == 100
        assert config.timeout == 30
        assert config.max_retries == 3


class TestVulnConfig:
    """Test VulnerabilityConfig."""

    def test_defaults(self):
        """Test default values."""
        config = VulnerabilityConfig()
        
        assert config.enable_sqli == True
        assert config.enable_xss == True
        assert config.enable_headers == True
        assert config.enable_dirscan == False


def test_findings():
    """Test Finding dataclass."""
    finding = Finding(
        id="test_1",
        type="sql_injection",
        url="https://example.com",
        parameter="id",
        payload="' OR '1'='1",
        severity="high",
        description="SQL Injection detected",
        evidence="' OR '1'='1",
    )
    
    assert finding.id == "test_1"
    assert finding.type == "sql_injection"
    assert finding.severity == "high"


def test_scan_result():
    """Test ScanResult dataclass."""
    result = ScanResult(
        target="https://example.com",
        start_time="2024-01-01T00:00:00",
    )
    
    assert result.target == "https://example.com"
    assert len(result.findings) == 0
    assert result.crawled_urls == 0


def test_request_engine_head_supports_allow_redirects():
    """HEAD should forward allow_redirects to request()."""
    engine = RequestEngine()
    captured = {}

    async def fake_request(method, url, **kwargs):
        captured["method"] = method
        captured["allow_redirects"] = kwargs.get("allow_redirects")
        return Mock(status_code=200, text="")

    engine.request = fake_request
    asyncio.run(engine.head("https://example.com", allow_redirects=False))

    assert captured["method"] == "HEAD"
    assert captured["allow_redirects"] is False


def test_auth_weak_password_policy_does_not_crash_without_minlength_group():
    """Password inputs without minlength should not trigger regex group errors."""
    engine = RequestEngine()
    detector = AuthDetector(engine)

    response = Mock()
    response.text = '<form><input type="password" name="password"></form>'
    engine.get = AsyncMock(return_value=response)

    result = asyncio.run(detector.check_weak_password_policy("https://example.com/login"))

    assert result.get("subtype") == "weak_password_policy"


def test_idor_horizontal_test_uses_real_baseline_not_empty_string():
    """If test responses match baseline, IDOR horizontal check should not flag."""
    engine = RequestEngine()
    fuzzer = Fuzzer(engine)
    detector = IDORDetector(engine, fuzzer)

    baseline_response = Mock()
    baseline_response.status_code = 200
    baseline_response.text = "same profile data"

    same_response = Mock()
    same_response.status_code = 200
    same_response.text = "same profile data"

    engine.get = AsyncMock(
        side_effect=[baseline_response, same_response, same_response, same_response, same_response, same_response]
    )

    results = asyncio.run(
        detector.test_parameter_horizontical(
            "https://example.com/profile",
            "user_id",
            "10",
        )
    )

    assert results == []


def test_scan_engine_subdomain_enum_uses_hostname_only():
    """Subdomain enumeration should receive hostname, not full URL/path."""
    vuln_config = VulnerabilityConfig(
        enable_sqli=False,
        enable_xss=False,
        enable_headers=False,
        enable_dirscan=False,
        enable_csrf=False,
        enable_idor=False,
        enable_auth=False,
    )
    scanner = ScanEngine(vuln_config=vuln_config)
    scanner.do_subdomain_enum = True
    scanner.subdomain_bruteforce = False

    scanner.crawl_target = AsyncMock(return_value=[])
    scanner.subdomain_enum.enumerate = AsyncMock(return_value=["api.example.com"])

    asyncio.run(scanner.full_scan("https://example.com/app/login"))

    called_domain = scanner.subdomain_enum.enumerate.await_args.args[0]
    assert called_domain == "example.com"


def test_auth_session_fixation_respects_cookie_flags():
    """Cookie with security flags should not be reported as fixation issue."""
    engine = RequestEngine()
    detector = AuthDetector(engine)

    response = Mock()
    response.headers = {
        "set-cookie": "sessionid=abc123; HttpOnly; Secure; SameSite=Lax"
    }
    engine.get = AsyncMock(return_value=response)

    result = asyncio.run(detector.check_session_fixation("https://example.com"))
    assert result == {}


def test_subdomain_enumerator_normalizes_full_url_input():
    """Enumerator should strip scheme/path and query before querying sources."""
    engine = RequestEngine()
    enum = SubdomainEnumerator(engine)

    enum.enumerate_from_crtsh = AsyncMock(return_value=[])
    enum.brute_force_subdomains = AsyncMock(return_value=[])

    asyncio.run(enum.enumerate("https://example.com/app/login?x=1", brute=False))
    called_domain = enum.enumerate_from_crtsh.await_args.args[0]
    assert called_domain == "example.com"


def test_scan_engine_records_structured_error():
    """Scanner should keep module/url/phase when a module crashes."""
    vuln_config = VulnerabilityConfig(enable_sqli=True, enable_xss=False, enable_headers=False)
    scanner = ScanEngine(vuln_config=vuln_config)
    scanner.crawl_target = AsyncMock(return_value=[])
    scanner.scan_sqli = AsyncMock(side_effect=RuntimeError("boom"))

    result = asyncio.run(scanner.full_scan("https://example.com"))

    assert len(result.errors) == 1
    assert result.errors[0]["module"] == "sqli"
    assert result.errors[0]["phase"] == "scan"
    assert result.errors[0]["url"] == "https://example.com"


def test_jwt_analyzer_avoids_false_positive_without_auth_boundary_change():
    """Should not flag JWT if status/body do not indicate auth bypass."""
    engine = RequestEngine()
    analyzer = JWTAnalyzer(engine)

    async def fake_get(url, headers=None, **kwargs):
        response = Mock()
        response.status_code = 200
        response.text = "public content"
        return response

    engine.get = fake_get
    findings = asyncio.run(analyzer.check_jwt("https://example.com"))
    assert findings == []


def test_open_redirect_requires_redirect_status_and_location():
    """Open redirect only when 3xx + attacker Location is returned."""
    engine = RequestEngine()
    tester = OpenRedirectTester(engine)

    async def fake_request(method, url, **kwargs):
        response = Mock()
        response.status_code = 200
        response.headers = {"location": "https://evil.example"}
        return response

    engine.request = fake_request
    findings = asyncio.run(tester.test_redirects("https://example.com/login", params=["next"]))
    assert findings == []


def test_ssrf_requires_minimum_evidence():
    """SSRF detector should not flag when response is unchanged and generic."""
    engine = RequestEngine()
    tester = ServerSideRequestForgery(engine)

    async def fake_get(url, **kwargs):
        response = Mock()
        response.status_code = 200
        response.text = "ok"
        return response

    engine.get = fake_get
    findings = asyncio.run(tester.test_ssrf("https://example.com/fetch", params=["url"]))
    assert findings == []


def test_parameter_bruteforcer_collects_errors():
    engine = RequestEngine()
    bruteforcer = ParameterBruteforcer(engine)

    async def fake_get(*args, **kwargs):
        raise RuntimeError("network down")

    engine.get = fake_get
    asyncio.run(bruteforcer.fuzz_parameters("https://example.com", wordlist=["id"]))

    errors = bruteforcer.get_errors()
    assert len(errors) == 1
    assert errors[0]["module"] == "parameter_bruteforce"
    assert errors[0]["phase"] == "fuzz_param"


def test_http_method_tampering_collects_errors():
    engine = RequestEngine()
    tampering = HTTPMethodTampering(engine)

    async def fake_request(*args, **kwargs):
        raise RuntimeError("request failed")

    engine.request = fake_request
    asyncio.run(tampering.test_methods("https://example.com"))

    errors = tampering.get_errors()
    assert len(errors) > 0
    assert errors[0]["module"] == "http_method_tampering"


def test_cors_analyzer_collects_errors():
    engine = RequestEngine()
    analyzer = CORSAnalyzer(engine)

    async def fake_get(*args, **kwargs):
        raise RuntimeError("blocked")

    engine.get = fake_get
    findings = asyncio.run(analyzer.analyze("https://example.com"))
    assert findings == []
    assert len(analyzer.get_errors()) > 0
    assert analyzer.get_errors()[0]["module"] == "cors"


def test_http_header_injection_collects_errors():
    engine = RequestEngine()
    tester = HTTPHeaderInjection(engine)

    async def fake_get(*args, **kwargs):
        raise RuntimeError("header failure")

    engine.get = fake_get
    asyncio.run(tester.test_header_injection("https://example.com"))

    errors = tester.get_errors()
    assert len(errors) > 0
    assert errors[0]["module"] == "http_header_injection"


def test_subdomain_enumerator_collects_request_errors():
    engine = RequestEngine()
    enum = SubdomainEnumerator(engine)

    async def fake_get(*args, **kwargs):
        raise RuntimeError("dns failed")

    engine.get = fake_get
    results = asyncio.run(enum.enumerate_from_crtsh("example.com"))

    assert results == []
    errors = enum.get_errors()
    assert len(errors) == 1
    assert errors[0]["module"] == "subdomain_enum"


def test_technology_fingerprinter_collects_errors():
    engine = RequestEngine()
    fingerprinter = TechnologyFingerprinter(engine)

    class FailingClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, *args, **kwargs):
            raise RuntimeError("fingerprint failed")

    with patch("modules.recon.httpx.AsyncClient", FailingClient):
        results = asyncio.run(fingerprinter.fingerprint("https://example.com"))

    assert results == {}
    errors = fingerprinter.get_errors()
    assert len(errors) == 1
    assert errors[0]["module"] == "tech_fingerprint"


def test_auth_detector_collects_errors():
    engine = RequestEngine()
    detector = AuthDetector(engine)

    async def fake_post(*args, **kwargs):
        raise RuntimeError("post failed")

    engine.post = fake_post
    asyncio.run(detector.check_default_credentials("https://example.com/login"))

    errors = detector.get_errors()
    assert len(errors) > 0
    assert errors[0]["module"] == "auth"


def test_port_scanner_collects_errors():
    engine = RequestEngine()
    scanner = PortScanner(engine)

    with patch.object(__import__("socket").socket, "connect_ex", side_effect=RuntimeError("socket unavailable")):
        is_open = asyncio.run(scanner.check_port("127.0.0.1", 80))

    assert is_open is False
    errors = scanner.get_errors()
    assert len(errors) == 1
    assert errors[0]["module"] == "port_scan"
    assert errors[0]["phase"] == "check_port"


def test_cli_run_scan_includes_precheck_errors():
    class DummyScanEngine:
        def __init__(self, *args, **kwargs):
            self.quick_scan = False
            self.do_subdomain_enum = False
            self.subdomain_bruteforce = False
            self.do_param_fuzz = False
            self.do_cors_check = False
            self.do_ssrf_check = False
            self.do_redirect_check = False
            self.do_tech_fingerprint = False
            self.do_jwt_check = False

        async def full_scan(self, target, progress_callback=None):
            return ScanResult(target=target, start_time="2024-01-01T00:00:00")

        async def close(self):
            return None

    cli = VulnixCLI()

    with patch("socket.gethostbyname", side_effect=RuntimeError("dns failed")):
        with patch("modules.recon.TechnologyFingerprinter.fingerprint", new=AsyncMock(return_value={})):
            with patch("cli.commands.ScanEngine", DummyScanEngine):
                result = asyncio.run(cli.run_scan("example.com", output_format="json"))

    modules = [e.get("module") for e in result.errors]
    assert "precheck_dns" in modules


def test_cli_does_not_force_tech_fingerprint_when_flag_is_disabled():
    captured = {}

    class DummyScanEngine:
        def __init__(self, *args, **kwargs):
            self.quick_scan = False
            self.do_subdomain_enum = False
            self.subdomain_bruteforce = False
            self.do_param_fuzz = False
            self.do_cors_check = False
            self.do_ssrf_check = False
            self.do_redirect_check = False
            self.do_tech_fingerprint = False
            self.do_jwt_check = False

        async def full_scan(self, target, progress_callback=None):
            captured["do_tech_fingerprint"] = self.do_tech_fingerprint
            return ScanResult(target=target, start_time="2024-01-01T00:00:00")

        async def close(self):
            return None

    cli = VulnixCLI()

    with patch("modules.recon.TechnologyFingerprinter.fingerprint", new=AsyncMock(return_value={})):
        with patch("cli.commands.ScanEngine", DummyScanEngine):
            asyncio.run(
                cli.run_scan(
                    "example.com",
                    output_format="json",
                    tech_fingerprint=False,
                    recon=False,
                )
            )

    assert captured["do_tech_fingerprint"] is False


def test_cli_scan_mode_quick_enables_quick_scan_profile():
    captured = {}

    class DummyScanEngine:
        def __init__(self, scan_config=None, vuln_config=None, verbose=False):
            captured["vuln_config"] = vuln_config
            self.quick_scan = False
            self.do_subdomain_enum = False
            self.subdomain_bruteforce = False
            self.do_param_fuzz = False
            self.do_cors_check = False
            self.do_ssrf_check = False
            self.do_redirect_check = False
            self.do_tech_fingerprint = False
            self.do_jwt_check = False

        async def full_scan(self, target, progress_callback=None):
            captured["quick_scan"] = self.quick_scan
            captured["do_subdomain_enum"] = self.do_subdomain_enum
            captured["do_jwt_check"] = self.do_jwt_check
            return ScanResult(target=target, start_time="2024-01-01T00:00:00")

        async def close(self):
            return None

    cli = VulnixCLI()
    with patch("socket.gethostbyname", return_value="127.0.0.1"):
        with patch("modules.recon.TechnologyFingerprinter.fingerprint", new=AsyncMock(return_value={})):
            with patch("cli.commands.ScanEngine", DummyScanEngine):
                asyncio.run(
                    cli.run_scan(
                        "example.com",
                        output_format="json",
                        scan_mode="quick",
                    )
                )

    assert captured["quick_scan"] is True
    assert captured["do_subdomain_enum"] is False
    assert captured["do_jwt_check"] is True


def test_cli_scan_mode_deep_enables_deep_profile():
    captured = {}

    class DummyScanEngine:
        def __init__(self, scan_config=None, vuln_config=None, verbose=False):
            captured["vuln_config"] = vuln_config
            self.quick_scan = False
            self.do_subdomain_enum = False
            self.subdomain_bruteforce = False
            self.do_param_fuzz = False
            self.do_cors_check = False
            self.do_ssrf_check = False
            self.do_redirect_check = False
            self.do_tech_fingerprint = False
            self.do_jwt_check = False

        async def full_scan(self, target, progress_callback=None):
            captured["quick_scan"] = self.quick_scan
            captured["do_subdomain_enum"] = self.do_subdomain_enum
            captured["do_param_fuzz"] = self.do_param_fuzz
            captured["do_cors_check"] = self.do_cors_check
            captured["do_ssrf_check"] = self.do_ssrf_check
            captured["do_redirect_check"] = self.do_redirect_check
            captured["do_tech_fingerprint"] = self.do_tech_fingerprint
            return ScanResult(target=target, start_time="2024-01-01T00:00:00")

        async def close(self):
            return None

    deep_vuln = VulnerabilityConfig(
        enable_sqli=True,
        enable_xss=True,
        enable_headers=True,
        enable_dirscan=True,
        enable_csrf=True,
        enable_idor=True,
        enable_auth=True,
        enable_http_desync=True,
        enable_cloud_metadata=True,
        enable_waf_detection=True,
        enable_waf_bypass=True,
        enable_websocket=True,
    )

    cli = VulnixCLI()
    with patch("socket.gethostbyname", return_value="127.0.0.1"):
        with patch("modules.recon.TechnologyFingerprinter.fingerprint", new=AsyncMock(return_value={})):
            with patch("cli.commands.ScanEngine", DummyScanEngine):
                asyncio.run(
                    cli.run_scan(
                        "example.com",
                        output_format="json",
                        scan_mode="deep",
                        vuln_config=deep_vuln,
                    )
                )

    assert captured["quick_scan"] is False
    assert captured["do_subdomain_enum"] is True
    assert captured["do_param_fuzz"] is True
    assert captured["do_cors_check"] is True
    assert captured["do_ssrf_check"] is True
    assert captured["do_redirect_check"] is True
    assert captured["do_tech_fingerprint"] is True
    assert captured["vuln_config"].enable_websocket is True


def test_report_generator_normalizes_structured_and_legacy_errors():
    result = ScanResult(
        target="https://example.com",
        start_time="2024-01-01T00:00:00",
        end_time="2024-01-01T00:10:00",
        errors=[
            {
                "module": "sqli",
                "phase": "scan",
                "url": "https://example.com",
                "error": "timeout",
                "timestamp": "2024-01-01T00:01:00",
            },
            "legacy error text",
        ],
    )
    generator = ReportGenerator()
    report_json = generator.generate_json_report(result)
    parsed = __import__("json").loads(report_json)

    assert parsed["summary"]["total_errors"] == 2
    assert parsed["summary"]["errors_by_module"]["sqli"] == 1
    assert parsed["summary"]["errors_by_module"]["legacy"] == 1
    assert parsed["errors"][1]["module"] == "legacy"


def test_report_generator_text_report_includes_error_section():
    result = ScanResult(
        target="https://example.com",
        start_time="2024-01-01T00:00:00",
        end_time="2024-01-01T00:10:00",
        errors=[
            {
                "module": "xss",
                "phase": "scan",
                "url": "https://example.com/search",
                "error": "connection reset",
                "timestamp": "2024-01-01T00:02:00",
            }
        ],
    )
    generator = ReportGenerator()
    report_text = generator.generate_text_report(result)

    assert "ERRORS" in report_text
    assert "xss: 1" in report_text
    assert "connection reset" in report_text


def test_report_generator_json_includes_recon_section():
    result = ScanResult(
        target="https://example.com",
        start_time="2024-01-01T00:00:00",
        end_time="2024-01-01T00:10:00",
        findings=[
            Finding(
                id="f1",
                type="subdomain",
                url="http://api.example.com",
                parameter=None,
                payload=None,
                severity="info",
                description="Found subdomain: api.example.com",
                evidence="",
            ),
            Finding(
                id="f2",
                type="technology",
                url="https://example.com",
                parameter=None,
                payload=None,
                severity="info",
                description="Detected: nginx",
                evidence="",
            ),
            Finding(
                id="f3",
                type="parameter_discovery",
                url="https://example.com/search",
                parameter="debug",
                payload=None,
                severity="info",
                description="Hidden parameter candidate found: debug",
                evidence="",
            ),
        ],
    )

    generator = ReportGenerator()
    parsed = __import__("json").loads(generator.generate_json_report(result))

    assert "recon" in parsed
    assert parsed["recon"]["summary"]["subdomains_count"] == 1
    assert parsed["recon"]["summary"]["technologies_count"] == 1
    assert parsed["recon"]["summary"]["hidden_parameters_count"] == 1
    assert "http://api.example.com" in parsed["recon"]["subdomains"]
    assert "nginx" in parsed["recon"]["technologies"]


def test_report_generator_text_report_includes_recon_section():
    result = ScanResult(
        target="https://example.com",
        start_time="2024-01-01T00:00:00",
        end_time="2024-01-01T00:10:00",
        findings=[
            Finding(
                id="f1",
                type="subdomain",
                url="http://cdn.example.com",
                parameter=None,
                payload=None,
                severity="info",
                description="Found subdomain: cdn.example.com",
                evidence="",
            ),
            Finding(
                id="f2",
                type="technology",
                url="https://example.com",
                parameter=None,
                payload=None,
                severity="info",
                description="Detected: flask",
                evidence="",
            ),
        ],
    )

    generator = ReportGenerator()
    report_text = generator.generate_text_report(result)

    assert "RECON" in report_text
    assert "Subdomains:" in report_text
    assert "Technologies:" in report_text
    assert "cdn.example.com" in report_text
    assert "flask" in report_text


def test_report_generator_json_includes_module_insights_with_remediation():
    result = ScanResult(
        target="https://example.com",
        start_time="2024-01-01T00:00:00",
        end_time="2024-01-01T00:10:00",
        findings=[
            Finding(
                id="f1",
                type="http_smuggling",
                url="https://example.com",
                parameter=None,
                payload=None,
                severity="high",
                description="CL/TE ambiguity detected",
                evidence="payload evidence",
                remediation="Reject ambiguous CL/TE requests",
                module="http_desync",
                details={"variant": "CL_TE_conflict"},
            ),
        ],
    )

    generator = ReportGenerator()
    parsed = __import__("json").loads(generator.generate_json_report(result))

    assert "module_insights" in parsed
    assert "http_desync" in parsed["module_insights"]
    insight = parsed["module_insights"]["http_desync"][0]
    assert insight["remediation"] == "Reject ambiguous CL/TE requests"
    assert insight["evidence"] == "payload evidence"
    assert parsed["findings"][0]["module"] == "http_desync"
    assert parsed["findings"][0]["details"]["variant"] == "CL_TE_conflict"


def test_report_generator_text_report_includes_module_insights_section():
    result = ScanResult(
        target="https://example.com",
        start_time="2024-01-01T00:00:00",
        end_time="2024-01-01T00:10:00",
        findings=[
            Finding(
                id="f1",
                type="waf_bypass",
                url="https://example.com",
                parameter=None,
                payload="%27",
                severity="high",
                description="Potential WAF bypass via encoding",
                evidence="%27 OR %271%27=%271",
                remediation="Apply strict WAF normalization",
                module="waf",
                details={"technique": "encoding"},
            ),
        ],
    )

    generator = ReportGenerator()
    report_text = generator.generate_text_report(result)

    assert "MODULE INSIGHTS" in report_text
    assert "waf:" in report_text
    assert "remediation: Apply strict WAF normalization" in report_text


def test_fuzzer_collects_structured_errors_on_request_failure():
    engine = RequestEngine()
    fuzzer = Fuzzer(engine)

    async def fake_get(*args, **kwargs):
        raise RuntimeError("fuzz failure")

    engine.get = fake_get
    response = asyncio.run(fuzzer.fuzz_url_params("https://example.com", {"id": "1"}, "'"))
    assert response is None

    errors = fuzzer.get_errors()
    assert len(errors) == 1
    assert errors[0]["module"] == "fuzzing"
    assert errors[0]["phase"] == "fuzz_url_params_request"


def test_sqli_detector_collects_errors():
    engine = RequestEngine()
    fuzzer = Fuzzer(engine)
    detector = SQLiDetector(engine, fuzzer)

    async def fake_baseline(*args, **kwargs):
        return (None, "")

    async def fake_get(*args, **kwargs):
        raise RuntimeError("sqli request failed")

    fuzzer._get_baseline = fake_baseline
    engine.get = fake_get

    findings = asyncio.run(detector.test_parameter("https://example.com", "id", "GET"))
    assert findings == []
    assert len(detector.get_errors()) > 0
    assert detector.get_errors()[0]["module"] == "sqli"


def test_xss_detector_collects_errors():
    engine = RequestEngine()
    fuzzer = Fuzzer(engine)
    detector = XSSDetector(engine, fuzzer)

    async def fake_baseline(*args, **kwargs):
        return (None, "")

    async def fake_get(*args, **kwargs):
        raise RuntimeError("xss request failed")

    fuzzer._get_baseline = fake_baseline
    engine.get = fake_get

    findings = asyncio.run(detector.test_parameter("https://example.com", "q", "GET"))
    assert findings == []
    assert len(detector.get_errors()) > 0
    assert detector.get_errors()[0]["module"] == "xss"


def test_cloud_metadata_detector_collects_errors():
    engine = RequestEngine()
    detector = CloudMetadataDetector(engine)

    async def fake_get(*args, **kwargs):
        raise RuntimeError("metadata blocked")

    engine.get = fake_get
    findings = asyncio.run(detector.scan("https://example.com"))
    assert findings == []
    assert len(detector.get_errors()) > 0
    assert detector.get_errors()[0]["module"] == "cloud_metadata"


def test_http_desync_detector_collects_errors():
    engine = RequestEngine()
    detector = HTTPDesyncDetector(engine)

    async def fake_post(*args, **kwargs):
        raise RuntimeError("desync failure")

    async def fake_get(*args, **kwargs):
        return None

    async def fake_request(*args, **kwargs):
        raise RuntimeError("desync request failed")

    engine.post = fake_post
    engine.get = fake_get
    engine.request = fake_request

    findings = asyncio.run(detector.scan("https://example.com"))
    assert findings == []
    assert len(detector.get_errors()) > 0
    assert detector.get_errors()[0]["module"] == "http_desync"


def test_waf_detector_collects_errors():
    engine = RequestEngine()
    detector = WAFDetector(engine)

    baseline = Mock(status_code=200, headers={}, text="ok")

    async def fake_get(*args, **kwargs):
        if kwargs.get("params"):
            raise RuntimeError("waf probe failed")
        return baseline

    engine.get = fake_get
    asyncio.run(detector.detect("https://example.com"))

    assert len(detector.get_errors()) > 0
    assert detector.get_errors()[0]["module"] == "waf_detector"


def test_websocket_tester_collects_errors():
    engine = RequestEngine()
    tester = WebSocketTester(engine)

    async def fake_get(*args, **kwargs):
        raise RuntimeError("ws discovery failed")

    engine.get = fake_get
    endpoints = asyncio.run(tester.discover("https://example.com"))
    assert endpoints == []
    assert len(tester.get_errors()) == 1
    assert tester.get_errors()[0]["module"] == "websocket"


def test_scan_state_collects_errors_on_save_failure():
    state = ScanState(state_file="vulnix_state.json")

    with patch("core.state.open", side_effect=PermissionError("denied")):
        state.start_new_scan("https://example.com", {"x": 1})

    errors = state.get_errors()
    assert len(errors) > 0
    assert errors[0]["module"] == "scan_state"
    assert errors[0]["phase"] == "save"


def test_scan_engine_collects_child_module_errors():
    vuln_config = VulnerabilityConfig(enable_sqli=True, enable_xss=False, enable_headers=False)
    scanner = ScanEngine(vuln_config=vuln_config)

    scanner.crawl_target = AsyncMock(return_value=[
        DiscoveredEndpoint(url="https://example.com/search", method="GET", parameters=["q"])
    ])

    async def fake_scan_endpoint(*args, **kwargs):
        scanner.sqli_detector.error_collector.add(
            "https://example.com/search",
            RuntimeError("internal detector failure"),
            "test_parameter_payload_q",
        )
        return []

    scanner.sqli_detector.scan_endpoint = fake_scan_endpoint

    result = asyncio.run(scanner.full_scan("https://example.com"))

    assert any(
        e.get("module") == "sqli" and "internal detector failure" in e.get("error", "")
        for e in result.errors
    )


def test_scan_engine_http_desync_feature_runs_when_enabled():
    vuln_config = VulnerabilityConfig(
        enable_sqli=False,
        enable_xss=False,
        enable_headers=False,
        enable_http_desync=True,
    )
    scanner = ScanEngine(vuln_config=vuln_config)
    scanner.crawl_target = AsyncMock(return_value=[])

    scanner.http_desync_detector.scan = AsyncMock(return_value=[
        {
            "type": "http_smuggling",
            "variant": "CL_TE_conflict",
            "severity": "high",
            "url": "https://example.com",
            "description": "desync detected",
        }
    ])

    result = asyncio.run(scanner.full_scan("https://example.com"))

    assert any(f.type == "http_smuggling" for f in result.findings)
    assert scanner.http_desync_detector.scan.await_count == 1


def test_scan_engine_cloud_metadata_feature_runs_when_enabled():
    vuln_config = VulnerabilityConfig(
        enable_sqli=False,
        enable_xss=False,
        enable_headers=False,
        enable_cloud_metadata=True,
    )
    scanner = ScanEngine(vuln_config=vuln_config)
    scanner.crawl_target = AsyncMock(return_value=[])

    scanner.cloud_metadata_detector.scan = AsyncMock(return_value=[
        {
            "type": "ssrf",
            "subtype": "cloud_metadata",
            "severity": "critical",
            "url": "https://example.com",
            "description": "cloud metadata exposure",
        }
    ])

    result = asyncio.run(scanner.full_scan("https://example.com"))

    assert any(f.type == "ssrf" for f in result.findings)
    assert scanner.cloud_metadata_detector.scan.await_count == 1


def test_scan_engine_waf_detection_feature_runs_when_enabled():
    vuln_config = VulnerabilityConfig(
        enable_sqli=False,
        enable_xss=False,
        enable_headers=False,
        enable_waf_detection=True,
    )
    scanner = ScanEngine(vuln_config=vuln_config)
    scanner.crawl_target = AsyncMock(return_value=[])
    scanner.waf_detector.detect = AsyncMock(return_value={
        "waf": "Cloudflare",
        "waf_id": "cloudflare",
        "detection_method": "header",
        "confidence": 90,
    })

    result = asyncio.run(scanner.full_scan("https://example.com"))

    assert any(f.type == "waf_detection" for f in result.findings)
    assert scanner.waf_detector.detect.await_count == 1


def test_scan_engine_waf_bypass_feature_runs_when_enabled():
    vuln_config = VulnerabilityConfig(
        enable_sqli=False,
        enable_xss=False,
        enable_headers=False,
        enable_waf_bypass=True,
    )
    scanner = ScanEngine(vuln_config=vuln_config)
    scanner.crawl_target = AsyncMock(return_value=[])
    scanner.waf_detector.detect = AsyncMock(return_value=None)
    scanner.waf_detector.test_bypass = AsyncMock(return_value=[
        {
            "technique": "encoding",
            "original_payload": "' OR '1'='1",
            "bypassed_payload": "%27 OR %271%27=%271",
            "status": "potentially_bypassed",
            "severity": "high",
            "url": "https://example.com",
            "waf": "Unknown",
        }
    ])

    result = asyncio.run(scanner.full_scan("https://example.com"))

    assert any(f.type == "waf_bypass" for f in result.findings)
    assert scanner.waf_detector.detect.await_count == 1
    assert scanner.waf_detector.test_bypass.await_count == 1


def test_scan_engine_websocket_feature_runs_when_enabled():
    vuln_config = VulnerabilityConfig(
        enable_sqli=False,
        enable_xss=False,
        enable_headers=False,
        enable_websocket=True,
    )
    scanner = ScanEngine(vuln_config=vuln_config)
    scanner.crawl_target = AsyncMock(return_value=[])
    scanner.websocket_tester.discover = AsyncMock(return_value=["https://example.com/ws"])
    scanner.websocket_tester.test_endpoint = AsyncMock(return_value=[
        {
            "type": "websocket",
            "subtype": "origin_bypass",
            "severity": "medium",
            "url": "wss://example.com/ws",
            "description": "origin bypass",
        }
    ])

    result = asyncio.run(scanner.full_scan("https://example.com"))

    assert any(f.type == "websocket" for f in result.findings)
    assert scanner.websocket_tester.discover.await_count == 1
    called_url = scanner.websocket_tester.test_endpoint.await_args.args[0]
    assert called_url == "wss://example.com/ws"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

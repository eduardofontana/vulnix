"""
VULNIX - Test Recon Modules
Unit Tests for DNS Lookup, Port Scanner, SSL, Robots, Link Extractor
"""

import pytest
from unittest.mock import Mock, patch

from modules.recon import DNSLookup, PortScanner
from modules.ssl import SSLCertificateInfo
from modules.robots import RobotsSitemapAnalyzer
from modules.linkextractor import LinkExtractor
from modules.headers import SecurityHeadersAnalyzer
from core.request_engine import RequestEngine


class TestDNSLookup:
    """Test DNS Lookup functionality."""

    def test_normalize_domain(self):
        """Test domain normalization."""
        dns = DNSLookup()
        
        assert dns._normalize_domain("https://example.com") == "example.com"
        assert dns._normalize_domain("example.com/") == "example.com"
        assert dns._normalize_domain("example.com/path") == "example.com"

    def test_record_types(self):
        """Test record types list."""
        dns = DNSLookup()
        
        assert "A" in dns.RECORD_TYPES
        assert "MX" in dns.RECORD_TYPES
        assert "NS" in dns.RECORD_TYPES


class TestPortScanner:
    """Test Port Scanner functionality."""

    def test_service_names(self):
        """Test service name mapping."""
        req_engine = RequestEngine()
        scanner = PortScanner(req_engine)
        
        assert scanner.SERVICE_NAMES.get(22) == "ssh"
        assert scanner.SERVICE_NAMES.get(443) == "https"
        assert scanner.SERVICE_NAMES.get(3306) == "mysql"

    def test_common_ports(self):
        """Test common ports list."""
        req_engine = RequestEngine()
        scanner = PortScanner(req_engine)
        
        assert 80 in scanner.COMMON_PORTS
        assert 443 in scanner.COMMON_PORTS
        assert len(scanner.COMMON_PORTS) > 0

    def test_top_ports(self):
        """Test top ports list."""
        req_engine = RequestEngine()
        scanner = PortScanner(req_engine)
        
        assert len(scanner.TOP_PORTS_100) >= 50
        assert 22 in scanner.TOP_PORTS_100


class TestSSLCertificateInfo:
    """Test SSL Certificate Info functionality."""

    def test_normalize_host(self):
        """Test host normalization."""
        req_engine = RequestEngine()
        ssl = SSLCertificateInfo(req_engine)
        
        host, port = ssl._normalize_host("https://example.com")
        assert host == "example.com"
        assert port == 443
        
        host, port = ssl._normalize_host("example.com:8443")
        assert host == "example.com"
        assert port == 8443

    def test_common_ssl_ports(self):
        """Test common SSL ports."""
        req_engine = RequestEngine()
        ssl = SSLCertificateInfo(req_engine)
        
        assert 443 in ssl.COMMON_SSL_PORTS
        assert 8443 in ssl.COMMON_SSL_PORTS


class TestRobotsSitemapAnalyzer:
    """Test Robots.txt and Sitemap Analyzer."""

    def test_normalize_url(self):
        """Test URL normalization."""
        req_engine = RequestEngine()
        analyzer = RobotsSitemapAnalyzer(req_engine)
        
        assert analyzer._normalize_url("example.com") == "https://example.com"
        assert analyzer._normalize_url("http://example.com") == "http://example.com"

    def test_parse_robots_content(self):
        """Test robots.txt parsing."""
        req_engine = RequestEngine()
        analyzer = RobotsSitemapAnalyzer(req_engine)
        
        content = """
User-agent: *
Disallow: /admin/
Disallow: /login/
Sitemap: https://example.com/sitemap.xml
"""
        
        result = analyzer._parse_robots(content, "https://example.com")
        
        assert result["parsed_successfully"] is True
        assert "/admin/" in result["disallowed_paths"]

    def test_private_path_patterns(self):
        """Test private path patterns."""
        req_engine = RequestEngine()
        analyzer = RobotsSitemapAnalyzer(req_engine)
        
        assert len(analyzer.PRIVATE_PATH_PATTERNS) > 0


class TestLinkExtractor:
    """Test Link Extractor functionality."""

    def test_normalize_url(self):
        """Test URL normalization."""
        req_engine = RequestEngine()
        extractor = LinkExtractor(req_engine)
        
        assert extractor._normalize_url("/path", "https://example.com") == "https://example.com/path"
        assert extractor._normalize_url("https://other.com", "https://example.com") == "https://other.com"

    def test_extract_from_html(self):
        """Test HTML link extraction."""
        req_engine = RequestEngine()
        extractor = LinkExtractor(req_engine)
        
        result = extractor._extract_from_html(
            '<a href="/page1">Page 1</a><a href="https://external.com">External</a>',
            "https://example.com"
        )
        
        assert "same_domain" in result
        assert "external" in result
        assert "https://example.com/page1" in result["same_domain"]
        assert "https://external.com" in result["external"]

    def test_api_patterns(self):
        """Test API patterns."""
        req_engine = RequestEngine()
        extractor = LinkExtractor(req_engine)
        
        assert len(extractor.API_PATTERNS) > 0


class TestSecurityHeadersAnalyzer:
    """Test Security Headers Analyzer."""

    def test_analyze_cors(self):
        """Test CORS analysis."""
        req_engine = RequestEngine()
        analyzer = SecurityHeadersAnalyzer(req_engine)
        
        headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }
        
        result = analyzer._analyze_cors(headers)
        
        assert result["present"] is True
        assert len(result["issues"]) > 0

    def test_analyze_hsts(self):
        """Test HSTS analysis."""
        req_engine = RequestEngine()
        analyzer = SecurityHeadersAnalyzer(req_engine)
        
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
        }
        
        result = analyzer._analyze_hsts(headers)
        
        assert result["present"] is True

    def test_analyze_csp(self):
        """Test CSP analysis."""
        req_engine = RequestEngine()
        analyzer = SecurityHeadersAnalyzer(req_engine)
        
        headers = {
            "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'",
        }
        
        result = analyzer._analyze_csp(headers)
        
        assert result["present"] is True

    def test_analyze_privacy(self):
        """Test privacy headers analysis."""
        req_engine = RequestEngine()
        analyzer = SecurityHeadersAnalyzer(req_engine)
        
        headers = {
            "referrer-policy": "no-referrer",
        }
        
        result = analyzer._analyze_privacy(headers)
        
        assert "issues" in result
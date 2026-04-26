"""
VULNIX - Web Vulnerability Scanner
CLI Commands Module
"""

import asyncio
import json
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.theme import Theme

from core.scanner import ScanEngine, ScanResult
from core.analyzer import ReportGenerator
from core.state import ScanState, ScanCheckpoint
from config.settings import ScanConfig, VulnerabilityConfig, DISCLAIMER_FULL

BANNER = r"""
 /$$    /$$ /$$   /$$ /$$       /$$   /$$ /$$$$$$ /$$   /$$
| $$   | $$| $$  | $$| $$      | $$$ | $$|_  $$_/| $$  / $$
| $$   | $$| $$  | $$| $$      | $$$$| $$  | $$  |  $$/ $$/
|  $$ / $$/| $$  | $$| $$      | $$ $$ $$  | $$   \  $$$$/ 
 \  $$ $$/ | $$  | $$| $$      | $$  $$$$  | $$    >$$  $$ 
  \  $$$/  | $$  | $$| $$      | $$\  $$$  | $$   /$$/\  $$
   \  $/   |  $$$$$$/| $$$$$$$$| $$ \  $$ /$$$$$$| $$  \ $$
    \_/     \______/ |________/|__/  \__/|______/|__/  |__/ v1.3.0
"""


theme = Theme(
    {
        "critical": "red bold",
        "high": "orange1 bold",
        "medium": "yellow bold",
        "low": "blue bold",
        "info": "green bold",
    }
)


class VulnixCLI:
    """CLI interface for VULNIX."""

    MODULE_HELP: Dict[str, str] = {
        "sqli": "SQL injection checks",
        "xss": "XSS checks",
        "headers": "Security header analysis",
        "dirscan": "Directory scanning",
        "csrf": "CSRF checks",
        "idor": "IDOR checks",
        "auth": "Authentication checks",
        "http-desync": "HTTP request smuggling/desync checks",
        "cloud-metadata": "Cloud metadata SSRF checks",
        "waf": "WAF detection",
        "waf-bypass": "WAF bypass checks",
        "websocket": "WebSocket security checks",
        "cve-intel": "CVE correlation (NVD/KEV/EPSS)",
        "subs": "Subdomain enumeration",
        "subs-brute": "Subdomain brute-force enumeration",
        "param-fuzz": "Hidden parameter fuzzing",
        "cors": "CORS checks",
        "ssrf": "SSRF checks",
        "redirect": "Open redirect checks",
        "tech": "Technology fingerprinting",
        "jwt": "JWT handling checks",
        "dns": "DNS lookup",
        "port-scan": "Port scanning",
        "ssl": "SSL certificate analysis",
        "tls-check": "TLS vulnerability checks",
        "robots": "robots.txt analysis",
        "sitemap": "sitemap.xml analysis",
        "links": "Link extraction",
        "graphql": "GraphQL scanning",
        "rate-limit": "Rate limiting checks",
        "takeover": "Subdomain takeover checks",
        "wayback": "Wayback snapshot analysis",
        "whois": "WHOIS lookup",
        "js-secrets": "JavaScript secret extraction",
        "params": "Hidden parameter discovery",
        "fuzz": "Directory/content fuzzing",
        "pattern": "Sensitive pattern matching",
        "ssti": "SSTI checks",
        "lfi": "LFI/RFI checks",
        "race": "Race condition checks",
        "xxe": "XXE checks",
        "dom": "DOM vulnerability checks",
        "cms": "CMS detection",
    }

    MODULE_ORDER: List[str] = list(MODULE_HELP.keys())

    def __init__(self):
        self.console = Console(theme=theme)
        self.report_generator = ReportGenerator()

    def print_available_modules(self) -> None:
        """Print modules available for --module filtering."""
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Module", style="cyan", width=18)
        table.add_column("Description", width=70)
        for module_name in self.MODULE_ORDER:
            table.add_row(module_name, self.MODULE_HELP[module_name])
        self.console.print(Panel(table, title="Available Modules", border_style="cyan"))

    @staticmethod
    def _normalize_module_filter(module_filter: Optional[List[str]]) -> set[str]:
        """Normalize module selector list from CLI values."""
        if not module_filter:
            return set()
        normalized: set[str] = set()
        for raw in module_filter:
            for token in str(raw).split(","):
                value = token.strip().lower().replace("_", "-")
                if not value:
                    continue
                if value == "extract-links":
                    value = "links"
                normalized.add(value)
        return normalized

    def _collect_active_modules(self, scanner: ScanEngine, vuln_config: VulnerabilityConfig) -> List[str]:
        """Build active module list from current scanner state."""
        active: List[str] = []
        state_checks = {
            "sqli": vuln_config.enable_sqli,
            "xss": vuln_config.enable_xss,
            "headers": vuln_config.enable_headers,
            "dirscan": vuln_config.enable_dirscan,
            "csrf": vuln_config.enable_csrf,
            "idor": vuln_config.enable_idor,
            "auth": vuln_config.enable_auth,
            "http-desync": vuln_config.enable_http_desync,
            "cloud-metadata": vuln_config.enable_cloud_metadata,
            "waf": vuln_config.enable_waf_detection,
            "waf-bypass": vuln_config.enable_waf_bypass,
            "websocket": vuln_config.enable_websocket,
            "cve-intel": vuln_config.enable_cve_intel,
            "subs": getattr(scanner, "do_subdomain_enum", False),
            "subs-brute": getattr(scanner, "subdomain_bruteforce", False),
            "param-fuzz": getattr(scanner, "do_param_fuzz", False),
            "cors": getattr(scanner, "do_cors_check", False),
            "ssrf": getattr(scanner, "do_ssrf_check", False),
            "redirect": getattr(scanner, "do_redirect_check", False),
            "tech": getattr(scanner, "do_tech_fingerprint", False),
            "jwt": getattr(scanner, "do_jwt_check", False),
            "dns": getattr(scanner, "do_dns_lookup", False),
            "port-scan": getattr(scanner, "do_port_scan", False),
            "ssl": getattr(scanner, "do_ssl_analysis", False),
            "tls-check": getattr(scanner, "do_tls_check", False),
            "robots": getattr(scanner, "do_robots_analysis", False),
            "sitemap": getattr(scanner, "do_sitemap_analysis", False),
            "links": getattr(scanner, "do_link_extraction", False),
            "graphql": getattr(scanner, "do_graphql_scan", False),
            "rate-limit": getattr(scanner, "do_rate_limit", False),
            "takeover": getattr(scanner, "do_takeover", False),
            "wayback": getattr(scanner, "do_wayback", False),
            "whois": getattr(scanner, "do_whois", False),
            "js-secrets": getattr(scanner, "do_js_secrets", False),
            "params": getattr(scanner, "do_param_discovery", False),
            "fuzz": getattr(scanner, "do_content_fuzz", False),
            "pattern": getattr(scanner, "do_pattern_scan", False),
            "ssti": getattr(scanner, "do_ssti", False),
            "lfi": getattr(scanner, "do_lfi", False),
            "race": getattr(scanner, "do_race", False),
            "xxe": getattr(scanner, "do_xxe", False),
            "dom": getattr(scanner, "do_dom", False),
            "cms": getattr(scanner, "do_cms", False),
        }
        for module_name in self.MODULE_ORDER:
            if state_checks.get(module_name, False):
                active.append(module_name)
        return active

    def _apply_module_filter(
        self,
        scanner: ScanEngine,
        vuln_config: VulnerabilityConfig,
        module_filter: set[str],
    ) -> List[str]:
        """Apply --module filter by disabling all modules then enabling selected ones."""
        if not module_filter:
            return []

        # Disable everything first.
        vuln_config.enable_sqli = False
        vuln_config.enable_xss = False
        vuln_config.enable_headers = False
        vuln_config.enable_dirscan = False
        vuln_config.enable_csrf = False
        vuln_config.enable_idor = False
        vuln_config.enable_auth = False
        vuln_config.enable_http_desync = False
        vuln_config.enable_cloud_metadata = False
        vuln_config.enable_waf_detection = False
        vuln_config.enable_waf_bypass = False
        vuln_config.enable_websocket = False
        vuln_config.enable_cve_intel = False

        scanner.quick_scan = False
        scanner.do_subdomain_enum = False
        scanner.subdomain_bruteforce = False
        scanner.do_param_fuzz = False
        scanner.do_cors_check = False
        scanner.do_ssrf_check = False
        scanner.do_redirect_check = False
        scanner.do_tech_fingerprint = False
        scanner.do_jwt_check = False
        scanner.do_dns_lookup = False
        scanner.do_port_scan = False
        scanner.do_ssl_analysis = False
        scanner.do_tls_check = False
        scanner.do_robots_analysis = False
        scanner.do_sitemap_analysis = False
        scanner.do_link_extraction = False
        scanner.do_graphql_scan = False
        scanner.do_rate_limit = False
        scanner.do_takeover = False
        scanner.do_wayback = False
        scanner.do_whois = False
        scanner.do_js_secrets = False
        scanner.do_param_discovery = False
        scanner.do_content_fuzz = False
        scanner.do_pattern_scan = False
        scanner.do_ssti = False
        scanner.do_lfi = False
        scanner.do_race = False
        scanner.do_xxe = False
        scanner.do_dom = False
        scanner.do_cms = False

        unknown = [name for name in sorted(module_filter) if name not in self.MODULE_HELP]
        for module_name in module_filter:
            if module_name == "sqli":
                vuln_config.enable_sqli = True
            elif module_name == "xss":
                vuln_config.enable_xss = True
            elif module_name == "headers":
                vuln_config.enable_headers = True
            elif module_name == "dirscan":
                vuln_config.enable_dirscan = True
            elif module_name == "csrf":
                vuln_config.enable_csrf = True
            elif module_name == "idor":
                vuln_config.enable_idor = True
            elif module_name == "auth":
                vuln_config.enable_auth = True
            elif module_name == "http-desync":
                vuln_config.enable_http_desync = True
            elif module_name == "cloud-metadata":
                vuln_config.enable_cloud_metadata = True
            elif module_name == "waf":
                vuln_config.enable_waf_detection = True
            elif module_name == "waf-bypass":
                vuln_config.enable_waf_bypass = True
            elif module_name == "websocket":
                vuln_config.enable_websocket = True
            elif module_name == "cve-intel":
                vuln_config.enable_cve_intel = True
            elif module_name == "subs":
                scanner.do_subdomain_enum = True
            elif module_name == "subs-brute":
                scanner.do_subdomain_enum = True
                scanner.subdomain_bruteforce = True
            elif module_name == "param-fuzz":
                scanner.do_param_fuzz = True
            elif module_name == "cors":
                scanner.do_cors_check = True
            elif module_name == "ssrf":
                scanner.do_ssrf_check = True
            elif module_name == "redirect":
                scanner.do_redirect_check = True
            elif module_name == "tech":
                scanner.do_tech_fingerprint = True
            elif module_name == "jwt":
                scanner.do_jwt_check = True
            elif module_name == "dns":
                scanner.do_dns_lookup = True
            elif module_name == "port-scan":
                scanner.do_port_scan = True
            elif module_name == "ssl":
                scanner.do_ssl_analysis = True
            elif module_name == "tls-check":
                scanner.do_tls_check = True
            elif module_name == "robots":
                scanner.do_robots_analysis = True
            elif module_name == "sitemap":
                scanner.do_sitemap_analysis = True
            elif module_name == "links":
                scanner.do_link_extraction = True
            elif module_name == "graphql":
                scanner.do_graphql_scan = True
            elif module_name == "rate-limit":
                scanner.do_rate_limit = True
            elif module_name == "takeover":
                scanner.do_takeover = True
            elif module_name == "wayback":
                scanner.do_wayback = True
            elif module_name == "whois":
                scanner.do_whois = True
            elif module_name == "js-secrets":
                scanner.do_js_secrets = True
            elif module_name == "params":
                scanner.do_param_discovery = True
            elif module_name == "fuzz":
                scanner.do_content_fuzz = True
            elif module_name == "pattern":
                scanner.do_pattern_scan = True
            elif module_name == "ssti":
                scanner.do_ssti = True
            elif module_name == "lfi":
                scanner.do_lfi = True
            elif module_name == "race":
                scanner.do_race = True
            elif module_name == "xxe":
                scanner.do_xxe = True
            elif module_name == "dom":
                scanner.do_dom = True
            elif module_name == "cms":
                scanner.do_cms = True

        return unknown

    def print_banner(self) -> None:
        """Print VULNIX banner."""
        self.console.print(f"[bold cyan1]{BANNER}[/bold cyan1]")
        self.console.print("[dim]v1.3.0 | Web Vulnerability Scanner\n[/dim]")

    def print_disclaimer(self) -> None:
        """Print the disclaimer."""
        self.console.print(Panel(
            DISCLAIMER_FULL,
            border_style="red",
            title="WARNING",
        ))

    def print_target_info(self, target: str, ip: str = None, technologies: List[str] = None) -> None:
        """Print target information."""
        info_lines = [f"[cyan]Target:[/cyan] {target}"]
        if ip:
            info_lines.append(f"[cyan]IP:[/cyan] {ip}")
        if technologies:
            info_lines.append(f"[cyan]Technologies:[/cyan] {', '.join(technologies)}")
        else:
            info_lines.append(f"[cyan]Technologies:[/cyan] [dim]N/A[/dim]")

        self.console.print(Panel(
            "\n".join(info_lines),
            border_style="cyan",
        ))

    def print_findings_table(self, findings: List) -> None:
        """Print findings in a table."""
        if not findings:
            self.console.print("[green]No vulnerabilities found.[/green]")
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Type", width=20)
        table.add_column("URL", width=40)
        table.add_column("Parameter", width=15)

        severity_styles = {
            "critical": "red bold",
            "high": "orange1 bold",
            "medium": "yellow bold",
            "low": "blue bold",
            "info": "green bold",
        }

        for finding in findings:
            severity_style = severity_styles.get(finding.severity.lower(), "white")
            param = finding.parameter or "-"

            table.add_row(
                f"[{severity_style}]{finding.severity.upper()}[/{severity_style}]",
                finding.type,
                finding.url[:40] + "..." if len(finding.url) > 40 else finding.url,
                param,
            )

        self.console.print(table)

    def print_scan_summary(self, result: ScanResult) -> None:
        """Print scan summary."""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in result.findings:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        summary_table = Table(box=None, show_header=False)
        summary_table.add_column("Label", style="cyan")
        summary_table.add_column("Count", style="bold")

        summary_table.add_row("CRITICAL", f"[red]{severity_counts['critical']}[/red]")
        summary_table.add_row("HIGH", f"[orange1]{severity_counts['high']}[/orange1]")
        summary_table.add_row("MEDIUM", f"[yellow]{severity_counts['medium']}[/yellow]")
        summary_table.add_row("LOW", f"[blue]{severity_counts['low']}[/blue]")
        summary_table.add_row("INFO", f"[green]{severity_counts['info']}[/green]")

        self.console.print(Panel(
            summary_table,
            border_style="green",
            title="Scan Summary",
        ))

    def print_headers_analysis(self, findings: List) -> None:
        """Print security headers analysis."""
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Header", style="cyan", width=25)
        table.add_column("Status", width=10)
        table.add_column("Info", width=50)

        for finding in findings:
            status = "[green]Present[/green]" if finding.get("present") else "[red]Missing[/red]"

            table.add_row(
                finding.get("header", ""),
                status,
                finding.get("description", "")[:50],
            )

        self.console.print(table)

    def print_error_summary(self, errors: List[dict]) -> None:
        """Print structured error summary by module."""
        if not errors:
            return

        counts = {}
        for err in errors:
            module = err.get("module", "unknown")
            counts[module] = counts.get(module, 0) + 1

        table = Table(show_header=True, header_style="bold red")
        table.add_column("Module", style="red", width=24)
        table.add_column("Count", style="bold", width=8)

        for module, count in sorted(counts.items(), key=lambda item: item[0]):
            table.add_row(module, str(count))

        self.console.print()
        self.console.print(Panel(table, border_style="red", title="Scan Errors"))

    def print_dns_results(self, findings: List) -> None:
        """Print DNS lookup results."""
        dns_findings = [f for f in findings if f.type == "dns_record"]
        if not dns_findings:
            return

        from collections import defaultdict
        by_record = defaultdict(list)
        for f in dns_findings:
            details = f.details or {}
            record_type = details.get("record_type", "unknown")
            by_record[record_type].append(details.get("value", ""))

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Record Type", style="cyan", width=12)
        table.add_column("Values", width=60)

        for record_type, values in sorted(by_record.items()):
            table.add_row(record_type, ", ".join(values[:5]))

        self.console.print(Panel(table, title="DNS Records"))

    def print_subdomain_results(self, findings: List) -> None:
        """Print discovered subdomains."""
        subdomain_findings = [f for f in findings if f.type == "subdomain"]
        if not subdomain_findings:
            return

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Subdomain", style="cyan", width=64)

        seen = set()
        for f in subdomain_findings:
            label = f.url.replace("http://", "").replace("https://", "").strip()
            if not label or label in seen:
                continue
            seen.add(label)
            table.add_row(label)

        self.console.print(Panel(table, title="Subdomains"))

    def print_port_results(self, findings: List) -> None:
        """Print port scan results."""
        port_findings = [f for f in findings if f.type == "port"]
        if not port_findings:
            return

        table = Table(show_header=True, header_style="bold green")
        table.add_column("Port", style="green", width=10)
        table.add_column("Service", width=20)
        table.add_column("Status", width=15)

        for f in port_findings:
            details = f.details or {}
            port_num = details.get("port", "-")
            service = details.get("service", "unknown")
            table.add_row(
                str(port_num),
                service,
                "[green]open[/green]"
            )

        self.console.print(Panel(table, title="Open Ports"))

    def print_ssl_results(self, findings: List) -> None:
        """Print SSL certificate results."""
        ssl_findings = [f for f in findings if f.type == "ssl_cert"]
        if not ssl_findings:
            return

        for f in ssl_findings:
            details = f.details or {}
            info_lines = [
                f"[cyan]Subject:[/cyan] {details.get('subject', 'N/A')}",
                f"[cyan]Issuer:[/cyan] {details.get('issuer', 'N/A')}",
                f"[cyan]Expires:[/cyan] {details.get('not_after', 'N/A')}",
                f"[cyan]Days Remaining:[/cyan] {details.get('days_remaining', 'N/A')}",
                f"[cyan]Protocol:[/cyan] {details.get('protocol', 'N/A')}",
            ]
            self.console.print(Panel("\n".join(info_lines), title="SSL Certificate", border_style="yellow"))

    def print_robots_results(self, findings: List) -> None:
        """Print robots.txt analysis results."""
        robots_findings = [f for f in findings if f.type == "robots_txt"]
        if not robots_findings:
            return

        for f in robots_findings:
            details = f.details or {}
            disallowed = details.get("disallowed_paths", [])
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Disallowed Paths", width=70)

            for path in disallowed[:10]:
                table.add_row(path)

            self.console.print(Panel(table, title="Robots.txt Analysis"))

    def print_sitemap_results(self, findings: List) -> None:
        """Print sitemap analysis results."""
        sitemap_findings = [f for f in findings if f.type == "sitemap"]
        if not sitemap_findings:
            return

        for f in sitemap_findings:
            details = f.details or {}
            urls = details.get("urls", [])
            self.console.print(Panel(
                f"[cyan]Found {len(urls)} URLs in sitemap.xml[/cyan]",
                title="Sitemap Analysis",
                border_style="cyan"
            ))

    def print_link_extraction_results(self, findings: List) -> None:
        """Print link extraction results."""
        link_findings = [f for f in findings if f.type == "link_extraction"]
        if not link_findings:
            return

        for f in link_findings:
            details = f.details or {}
            internal = details.get("total_internal", 0)
            external = details.get("total_external", 0)
            categorized = details.get("categorized", {})
            api_endpoints = categorized.get("api_endpoints", [])

            table = Table(show_header=True, header_style="bold green")
            table.add_column("Type", width=20)
            table.add_column("Count", width=10)

            table.add_row("Internal Links", str(internal))
            table.add_row("External Links", str(external))
            table.add_row("API Endpoints", str(len(api_endpoints)))

            self.console.print(Panel(table, title="Link Extraction"))

            if api_endpoints:
                api_table = Table(show_header=True, header_style="bold yellow")
                api_table.add_column("API Endpoints", width=60)
                for ep in api_endpoints[:10]:
                    api_table.add_row(ep.get("url", "")[:60] if isinstance(ep, dict) else str(ep)[:60])
                self.console.print(Panel(api_table, title="API Endpoints Found"))

    def print_graphql_results(self, findings: List) -> None:
        """Print GraphQL scan results."""
        graphql_findings = [f for f in findings if "graphql" in f.type.lower()]
        if not graphql_findings:
            return

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Type", width=25)
        table.add_column("Description", width=60)

        for f in graphql_findings:
            table.add_row(f.type, f.description[:60])

        self.console.print(Panel(table, title="[bold cyan]GraphQL Analysis[/bold cyan]"))

    def print_rate_limit_results(self, findings: List) -> None:
        """Print rate limiting results."""
        rate_findings = [f for f in findings if f.type == "rate_limit"]
        if not rate_findings:
            return

        for f in rate_findings:
            details = f.details or {}
            info_lines = [
                f"[yellow]Method:[/yellow] {details.get('method', 'N/A')}",
                f"[yellow]Limit:[/yellow] {details.get('limit', 'N/A')}",
                f"[yellow]Retry After:[/yellow] {details.get('retry_after', 'N/A')}",
            ]
            self.console.print(Panel("\n".join(info_lines), title="[yellow]Rate Limiting[/yellow]", border_style="yellow"))

    def print_takeover_results(self, findings: List) -> None:
        """Print subdomain takeover results."""
        takeover_findings = [f for f in findings if f.type == "subdomain_takeover"]
        if not takeover_findings:
            return

        table = Table(show_header=True, header_style="bold red")
        table.add_column("Subdomain", width=40)
        table.add_column("Service", width=20)
        table.add_column("Evidence", width=25)

        for f in takeover_findings:
            details = f.details or {}
            table.add_row(
                f.url.replace("https://", ""),
                details.get("service", "unknown"),
                details.get("evidence", "")[:25]
            )

        self.console.print(Panel(table, title="[bold red]Subdomain Takeover[/bold red]", border_style="red"))

    def print_wayback_results(self, findings: List) -> None:
        """Print Wayback Machine results."""
        wayback_findings = [f for f in findings if f.type == "wayback_snapshots"]
        if not wayback_findings:
            return

        for f in wayback_findings:
            details = f.details or {}
            snapshots = details.get("snapshots", [])
            table = Table(show_header=True, header_style="bold green")
            table.add_column("Timestamp", width=20)
            table.add_column("URL", width=50)
            table.add_column("Status", width=10)

            for snap in snapshots[:10]:
                table.add_row(
                    snap.get("timestamp", ""),
                    snap.get("url", "")[:50],
                    str(snap.get("status", ""))
                )

            self.console.print(Panel(table, title="[bold green]Wayback Snapshots[/bold green]"))

    def print_whois_results(self, findings: List) -> None:
        """Print WHOIS results."""
        whois_findings = [f for f in findings if f.type == "whois_info"]
        if not whois_findings:
            return

        for f in whois_findings:
            details = f.details or {}
            ns_list = details.get("nameservers", [])
            ns_str = ", ".join(ns_list[:3]) if isinstance(ns_list, list) else str(ns_list)
            info_lines = [
                f"[cyan]Registrar:[/cyan] {details.get('registrar', 'N/A')}",
                f"[cyan]Created:[/cyan] {details.get('creation_date', 'N/A')}",
                f"[cyan]Expires:[/cyan] {details.get('expiration_date', 'N/A')}",
                f"[cyan]Name Servers:[/cyan] {ns_str}",
            ]
            self.console.print(Panel("\n".join(info_lines), title="[cyan]WHOIS Information[/cyan]", border_style="cyan"))

    def print_js_secrets_results(self, findings: List) -> None:
        """Print JavaScript secrets."""
        secrets_findings = [f for f in findings if "secret" in f.type.lower() or "key" in f.type.lower()]
        if not secrets_findings:
            return

        table = Table(show_header=True, header_style="bold red")
        table.add_column("Type", width=20)
        table.add_column("File/Endpoint", width=40)
        table.add_column("Severity", width=10)

        for f in secrets_findings[:20]:
            severity = f.severity.upper()
            table.add_row(f.type, f.url[:40], f"[red]{severity}[/red]")

        self.console.print(Panel(table, title="[bold red]JavaScript Secrets[/bold red]", border_style="red"))

    def print_param_results(self, findings: List) -> None:
        """Print discovered parameters."""
        param_findings = [f for f in findings if f.type == "hidden_parameter"]
        if not param_findings:
            return

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Parameter", width=40)

        for f in param_findings[:30]:
            param_name = f.description.replace("Found parameter: ", "") if f.description else ""
            table.add_row(param_name)

        self.console.print(Panel(table, title="[bold cyan]Discovered Parameters[/bold cyan]"))

    def print_pattern_results(self, findings: List) -> None:
        """Print pattern matching results."""
        pattern_findings = [f for f in findings if f.type == "pattern_match"]
        if not pattern_findings:
            return

        table = Table(show_header=True, header_style="bold yellow")
        table.add_column("Pattern Type", width=25)
        table.add_column("Count", width=10)
        table.add_column("Severity", width=10)

        for f in pattern_findings:
            severity = f.severity.upper()
            count = str(f.details.get("count", 1)) if f.details else "1"
            table.add_row(
                f.description.split(" ")[1] if " " in f.description else f.type,
                count,
                f"[yellow]{severity}[/yellow]"
            )

        self.console.print(Panel(table, title="[bold yellow]Sensitive Patterns[/bold yellow]"))

    def print_fuzz_results(self, findings: List) -> None:
        """Print fuzzing results."""
        fuzz_findings = [f for f in findings if f.type == "directory"]
        if not fuzz_findings:
            return

        table = Table(show_header=True, header_style="bold green")
        table.add_column("Path", width=50)
        table.add_column("Status", width=10)

        for f in fuzz_findings[:20]:
            path = f.url.split("/")[-1] if "/" in f.url else f.url
            status = str(f.details.get("status", "")) if f.details else ""
            table.add_row(path, status)

        self.console.print(Panel(table, title="[bold green]Directory Fuzzing[/bold green]"))

    @staticmethod
    def _finding_key(finding: Any) -> str:
        """Build a stable key for finding diffing."""
        return "|".join(
            [
                str(getattr(finding, "type", "")),
                str(getattr(finding, "url", "")),
                str(getattr(finding, "parameter", "")),
                str(getattr(finding, "payload", "")),
                str(getattr(finding, "severity", "")),
                str(getattr(finding, "description", "")),
            ]
        )

    def _load_baseline_keys(self, baseline_file: Optional[str]) -> set[str]:
        """Load baseline finding keys from a JSON report file."""
        if not baseline_file:
            return set()
        baseline_path = Path(baseline_file)
        if not baseline_path.exists():
            self.console.print(f"[yellow]Baseline file not found: {baseline_file}[/yellow]")
            return set()

        try:
            payload = json.loads(baseline_path.read_text(encoding="utf-8"))
            findings = payload.get("findings", [])
            keys = set()
            for f in findings:
                if not isinstance(f, dict):
                    continue
                keys.add(
                    "|".join(
                        [
                            str(f.get("type", "")),
                            str(f.get("url", "")),
                            str(f.get("parameter", "")),
                            str(f.get("payload", "")),
                            str(f.get("severity", "")),
                            str(f.get("description", "")),
                        ]
                    )
                )
            return keys
        except Exception as e:
            self.console.print(f"[yellow]Failed to load baseline file: {e}[/yellow]")
            return set()

    def _compute_diff(self, result: ScanResult, baseline_keys: set[str]) -> Dict[str, Any]:
        """Compute new findings against baseline."""
        if not baseline_keys:
            return {"new_findings": [], "new_count": 0, "baseline_count": 0}

        new_findings = [f for f in result.findings if self._finding_key(f) not in baseline_keys]
        return {
            "new_findings": [
                {
                    "id": f.id,
                    "type": f.type,
                    "url": f.url,
                    "severity": f.severity,
                    "description": f.description,
                }
                for f in new_findings
            ],
            "new_count": len(new_findings),
            "baseline_count": len(baseline_keys),
        }

    def _write_jsonl(self, result: ScanResult, jsonl_file: str) -> None:
        """Write findings in JSONL format."""
        rows = []
        for finding in result.findings:
            rows.append(
                json.dumps(
                    {
                        "target": result.target,
                        "scan_start": result.start_time,
                        "scan_end": result.end_time,
                        "id": finding.id,
                        "type": finding.type,
                        "url": finding.url,
                        "parameter": finding.parameter,
                        "severity": finding.severity,
                        "description": finding.description,
                        "module": finding.module,
                        "timestamp": finding.timestamp,
                        "details": finding.details,
                    },
                    ensure_ascii=False,
                )
            )
        Path(jsonl_file).write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")

    @staticmethod
    def _is_high_confidence_finding(finding: Any) -> bool:
        """Return whether a finding passes strict high-confidence criteria."""
        details = getattr(finding, "details", {}) or {}
        severity = str(getattr(finding, "severity", "")).lower()
        finding_type = str(getattr(finding, "type", "")).lower()

        direct_conf = str(getattr(finding, "confidence", "")).lower()
        detail_conf = str(details.get("confidence", "")).lower()
        confirmations = details.get("confirmations")

        if direct_conf in {"high", "firm"} or detail_conf in {"high", "firm"}:
            return True
        if isinstance(confirmations, int) and confirmations >= 2:
            return True
        if finding_type == "http_smuggling" and severity in {"high", "critical"}:
            return True
        if finding_type == "cve_intel" and detail_conf == "firm":
            return True
        return False

    def _to_high_confidence_result(self, result: ScanResult) -> ScanResult:
        """Build a cloned result containing only high-confidence findings."""
        filtered = [f for f in result.findings if self._is_high_confidence_finding(f)]
        return ScanResult(
            target=result.target,
            start_time=result.start_time,
            end_time=result.end_time,
            findings=filtered,
            crawled_urls=result.crawled_urls,
            scanned_endpoints=result.scanned_endpoints,
            errors=list(result.errors),
        )

    async def _emit_siem(self, result: ScanResult, siem_target: str) -> None:
        """Emit findings to SIEM-compatible endpoint."""
        if siem_target not in {"splunk", "elk"}:
            return

        endpoint = (
            "http://localhost:8088/services/collector/event"
            if siem_target == "splunk"
            else "http://localhost:9200/vulnix-findings/_doc"
        )

        headers = {"Content-Type": "application/json"}
        payloads = []
        for finding in result.findings:
            event = {
                "target": result.target,
                "scan_time": result.start_time,
                "finding": {
                    "id": finding.id,
                    "type": finding.type,
                    "severity": finding.severity,
                    "url": finding.url,
                    "description": finding.description,
                    "module": finding.module,
                    "details": finding.details,
                },
            }
            if siem_target == "splunk":
                payloads.append({"event": event, "sourcetype": "vulnix"})
            else:
                payloads.append(event)

        from core.request_engine import RequestEngine

        emitter = RequestEngine(timeout=10, max_retries=1, delay=0.1)
        try:
            for item in payloads[:200]:
                await emitter.post(endpoint, content=json.dumps(item).encode("utf-8"), headers=headers)
        finally:
            await emitter.close()

    async def run_scan(
        self,
        target: str,
        scan_config: Optional[ScanConfig] = None,
        vuln_config: Optional[VulnerabilityConfig] = None,
        output_format: str = "both",
        output_file: Optional[str] = None,
        verbose: bool = False,
        quick_scan: bool = False,
        subdomain_enum: bool = False,
        subdomain_bruteforce: bool = False,
        param_fuzz: bool = False,
        cors_check: bool = False,
        ssrf_check: bool = False,
        redirect_check: bool = False,
        tech_fingerprint: bool = False,
        recon: bool = False,
        scan_mode: str = "standard",
        dns_lookup: bool = False,
        dns_records: Optional[str] = None,
        port_scan: bool = False,
        port_range: Optional[str] = None,
        top_ports: int = 20,
        ssl_analysis: bool = False,
        tls_check: bool = False,
        robots_analysis: bool = False,
        sitemap_analysis: bool = False,
        link_extraction: bool = False,
        graphql_scan: bool = False,
        rate_limit_detect: bool = False,
        proxy_url: Optional[str] = None,
        takeover_check: bool = False,
        wayback_analysis: bool = False,
        whois_lookup: bool = False,
        js_secrets: bool = False,
        param_discovery: bool = False,
        content_fuzz: bool = False,
        pattern_scan: bool = False,
        recon_all: bool = False,
        ssti_scan: bool = False,
        lfi_scan: bool = False,
        race_scan: bool = False,
        xxe_scan: bool = False,
        dom_scan: bool = False,
        cms_detect: bool = False,
        safe_mode: bool = False,
        aggressive_mode: bool = False,
        resume_state_file: Optional[str] = None,
        checkpoint_dir: Optional[str] = None,
        jsonl_output: Optional[str] = None,
        siem_target: Optional[str] = None,
        baseline_file: Optional[str] = None,
        diff_output: Optional[str] = None,
        high_confidence_only: bool = False,
        debug_events: bool = False,
        events_output: Optional[str] = None,
        module_filter: Optional[List[str]] = None,
        list_modules: bool = False,
        dry_run: bool = False,
        max_runtime: Optional[int] = None,
    ) -> ScanResult:
        """Run a vulnerability scan."""
        from urllib.parse import urlparse
        import socket

        target = target or ""
        if list_modules:
            self.print_banner()
            self.print_available_modules()
            return ScanResult(target=target or "N/A", start_time=datetime.now().isoformat())

        scan_state = ScanState(resume_state_file or "vulnix_state.json")
        checkpoint = ScanCheckpoint(checkpoint_dir or "checkpoints")
        resumed_state = None
        if resume_state_file:
            resumed_state = scan_state.load()
            if resumed_state and not target:
                target = resumed_state.get("target", "")
        if not target:
            raise ValueError("No target provided and no valid resume state found.")

        target_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        baseline_keys = self._load_baseline_keys(baseline_file)

        self.print_banner()
        self.print_disclaimer()

        parsed = urlparse(target_url)
        host = parsed.netloc or parsed.path
        if ":" in host:
            host = host.split(":")[0]

        pre_scan_errors: List[Dict[str, Any]] = []
        target_ip = None
        try:
            target_ip = socket.gethostbyname(host)
        except Exception as e:
            pre_scan_errors.append(
                {
                    "module": "precheck_dns",
                    "phase": "resolve_target",
                    "url": target_url,
                    "error": str(e),
                    "timestamp": None,
                }
            )

        from modules.recon import TechnologyFingerprinter
        from core.request_engine import RequestEngine

        req_engine = RequestEngine(proxy_url=proxy_url)
        tech_fingerprinter = TechnologyFingerprinter(req_engine)
        technologies = None
        try:
            tech_results = await tech_fingerprinter.fingerprint(target_url)
            tech_list = sorted({tech for tech, found in tech_results.items() if found})
            technologies = tech_list or None
        except Exception as e:
            pre_scan_errors.append(
                {
                    "module": "precheck_tech_fingerprint",
                    "phase": "fingerprint",
                    "url": target_url,
                    "error": str(e),
                    "timestamp": None,
                }
            )
        finally:
            pre_scan_errors.extend(tech_fingerprinter.get_errors())
            await req_engine.close()

        self.print_target_info(target_url, ip=target_ip, technologies=technologies)
        if resumed_state:
            resumed_phase = resumed_state.get("phase", "unknown")
            resumed_progress = resumed_state.get("progress", 0)
            self.console.print(
                f"[cyan]Resume state loaded:[/cyan] phase={resumed_phase}, progress={resumed_progress}%"
            )

        if scan_config is None:
            scan_config = ScanConfig()

        if vuln_config is None:
            vuln_config = VulnerabilityConfig()

        if safe_mode:
            scan_config.delay = max(scan_config.delay, 1.0)
            scan_config.concurrent_requests = min(scan_config.concurrent_requests, 2)
            vuln_config.enable_http_desync = False
            vuln_config.enable_waf_bypass = False
            vuln_config.enable_websocket = False
            self.console.print("[yellow]Safe mode enabled: active/destructive checks minimized.[/yellow]")

        if aggressive_mode:
            scan_config.delay = min(scan_config.delay, 0.1)
            scan_config.concurrent_requests = max(scan_config.concurrent_requests, 15)
            vuln_config.enable_http_desync = True
            vuln_config.enable_websocket = True
            vuln_config.enable_waf_bypass = True
            self.console.print("[red]Aggressive mode enabled: higher request pressure and active checks.[/red]")

        mode = (scan_mode or "standard").lower()
        mode_quick = mode == "quick"
        mode_deep = mode == "deep"

        scanner = ScanEngine(
            scan_config=scan_config,
            vuln_config=vuln_config,
            verbose=verbose,
            proxy_url=proxy_url,
        )
        scanner.quick_scan = quick_scan or recon or mode_quick
        scanner.do_subdomain_enum = subdomain_enum or subdomain_bruteforce or recon or mode_deep
        scanner.subdomain_bruteforce = subdomain_bruteforce or (recon and mode_deep) or mode_deep
        scanner.do_param_fuzz = param_fuzz or recon or mode_deep
        scanner.do_cors_check = cors_check or recon or mode_deep
        scanner.do_ssrf_check = ssrf_check or recon or mode_deep
        scanner.do_redirect_check = redirect_check or recon or mode_deep
        scanner.do_tech_fingerprint = tech_fingerprint or recon or mode_deep
        scanner.do_jwt_check = quick_scan or recon or mode_quick or mode_deep
        scanner.do_dns_lookup = dns_lookup or (recon and mode_deep)
        scanner.dns_records = dns_records.split(",") if dns_records else None
        scanner.do_port_scan = port_scan or (recon and mode_deep)
        scanner.port_range = port_range
        scanner.top_ports = top_ports
        scanner.do_ssl_analysis = ssl_analysis or (recon and mode_deep)
        scanner.do_tls_check = tls_check or (recon and mode_deep)
        scanner.do_robots_analysis = robots_analysis or (recon and mode_deep)
        scanner.do_sitemap_analysis = sitemap_analysis or (recon and mode_deep)
        scanner.do_link_extraction = link_extraction or (recon and mode_deep)
        scanner.do_graphql_scan = graphql_scan or (recon and mode_deep)
        scanner.do_rate_limit = rate_limit_detect or (recon and mode_deep)
        scanner.do_takeover = takeover_check or (recon and mode_deep)
        scanner.do_wayback = wayback_analysis or (recon and mode_deep)
        scanner.do_whois = whois_lookup or (recon and mode_deep)
        scanner.do_js_secrets = js_secrets or (recon and mode_deep)
        scanner.do_param_discovery = param_discovery or (recon and mode_deep) or recon_all
        scanner.do_content_fuzz = content_fuzz or (recon and mode_deep) or recon_all
        scanner.do_pattern_scan = pattern_scan or (recon and mode_deep) or recon_all

        if ssti_scan or recon_all:
            scanner.do_ssti = True
        if lfi_scan or recon_all:
            scanner.do_lfi = True
        if race_scan or recon_all:
            scanner.do_race = True
        if xxe_scan or recon_all:
            scanner.do_xxe = True
        if dom_scan or recon_all:
            scanner.do_dom = True
        if cms_detect or recon_all:
            scanner.do_cms = True

        if recon or recon_all:
            scanner.do_dns_lookup = True
            scanner.dns_records = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
            scanner.do_port_scan = True
            scanner.top_ports = 50
            scanner.do_ssl_analysis = True
            scanner.do_tls_check = True
            scanner.do_robots_analysis = True
            scanner.do_sitemap_analysis = True
            scanner.do_link_extraction = True
            scanner.do_graphql_scan = True
            scanner.do_rate_limit = True
            scanner.do_takeover = True
            scanner.do_wayback = True
            scanner.do_whois = True
            scanner.do_js_secrets = True
            scanner.do_param_discovery = True
            scanner.do_content_fuzz = True
            scanner.do_pattern_scan = True

        normalized_module_filter = self._normalize_module_filter(module_filter)
        if normalized_module_filter:
            unknown_modules = self._apply_module_filter(scanner, vuln_config, normalized_module_filter)
            if unknown_modules:
                self.console.print(
                    "[yellow]Unknown module(s) ignored:[/yellow] "
                    + ", ".join(unknown_modules)
                )

        active_modules = self._collect_active_modules(scanner, vuln_config)

        if dry_run:
            dry_table = Table(show_header=True, header_style="bold cyan")
            dry_table.add_column("Key", style="cyan", width=18)
            dry_table.add_column("Value", width=70)
            dry_table.add_row("Target", target_url)
            dry_table.add_row("Mode", mode)
            dry_table.add_row("Safe mode", str(safe_mode))
            dry_table.add_row("Aggressive mode", str(aggressive_mode))
            dry_table.add_row("Proxy", proxy_url or "none")
            dry_table.add_row("Max runtime", str(max_runtime or "none"))
            dry_table.add_row("Active modules", ", ".join(active_modules) if active_modules else "none")
            self.console.print(Panel(dry_table, title="Dry Run", border_style="cyan"))
            return ScanResult(target=target_url, start_time=datetime.now().isoformat())

        if proxy_url:
            self.console.print(f"[cyan]Proxy enabled:[/cyan] {proxy_url}")

        if verbose:
            self.console.print("[yellow]Verbose mode enabled[/yellow]")

        self.console.print(
            "[cyan]Active modules:[/cyan] "
            + (", ".join(active_modules) if active_modules else "none")
        )

        scan_state.start_new_scan(
            target_url,
            {
                "scan_mode": scan_mode,
                "safe_mode": safe_mode,
                "aggressive_mode": aggressive_mode,
                "proxy_url": proxy_url,
                "recon": recon,
                "recon_all": recon_all,
            },
        )

        events_path = events_output
        if debug_events and not events_path:
            events_path = "reports/scan_events.jsonl"

        event_file_handle = None
        if events_path:
            event_path_obj = Path(events_path)
            event_path_obj.parent.mkdir(parents=True, exist_ok=True)
            event_file_handle = event_path_obj.open("a", encoding="utf-8")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console,
                disable=True,
            ) as progress:
                task = progress.add_task("[cyan]Initializing scan...", total=100, completed=0)
                progress_target = {"value": 0}
                stop_animation = {"value": False}
                request_stats = {
                    "total": 0,
                    "failed": 0,
                    "latency_sum": 0.0,
                    "latency_count": 0,
                }
                module_state: Dict[str, Dict[str, Any]] = defaultdict(
                    lambda: {"status": "idle", "events": 0, "findings": 0, "errors": 0}
                )
                recent_events = deque(maxlen=10)
                phase_to_percent = {
                    "Crawling target": 10,
                    "Found ": 15,
                    "Scanning for SQL injection": 25,
                    "Scanning for XSS": 35,
                    "Analyzing security headers": 45,
                    "Scanning directories": 55,
                    "Checking CSRF protection": 58,
                    "Checking for IDOR": 62,
                    "Checking authentication": 66,
                    "Checking for HTTP request smuggling/desync": 70,
                    "Checking cloud metadata SSRF exposure": 74,
                    "Detecting WAF protections": 78,
                    "Testing WAF bypass techniques": 82,
                    "Testing WebSocket security": 86,
                    "Checking CORS configuration": 90,
                    "Checking JWT handling": 93,
                    "Checking for SSRF": 95,
                    "Checking open redirects": 97,
                    "Fuzzing hidden parameters": 98,
                    "Enumerating subdomains": 99,
                    "Fingerprinting technologies": 99,
                    "Correlating CVEs from technology fingerprint": 99,
                    "Performing DNS lookup": 80,
                    "Scanning ports": 83,
                    "Analyzing SSL/TLS certificate": 86,
                    "Analyzing robots.txt": 89,
                    "Analyzing sitemap": 92,
                    "Extracting links": 95,
                }

                def _render_runtime_group() -> Group:
                    module_table = Table(show_header=True, header_style="bold cyan")
                    module_table.add_column("Module", width=20)
                    module_table.add_column("Status", width=12)
                    module_table.add_column("Events", width=8)
                    module_table.add_column("Findings", width=9)
                    module_table.add_column("Errors", width=7)

                    for module_name, stats in sorted(module_state.items(), key=lambda item: item[0]):
                        module_table.add_row(
                            module_name,
                            str(stats.get("status", "idle")),
                            str(stats.get("events", 0)),
                            str(stats.get("findings", 0)),
                            str(stats.get("errors", 0)),
                        )

                    request_table = Table(show_header=True, header_style="bold green")
                    request_table.add_column("Metric", width=24)
                    request_table.add_column("Value", width=18)
                    avg_latency = (
                        request_stats["latency_sum"] / request_stats["latency_count"]
                        if request_stats["latency_count"] > 0
                        else 0.0
                    )
                    request_table.add_row("Total Requests", str(request_stats["total"]))
                    request_table.add_row("Failed Requests", str(request_stats["failed"]))
                    request_table.add_row("Avg Latency (ms)", f"{avg_latency:.2f}")
                    request_table.add_row("Active Modules", str(len(active_modules)))
                    request_table.add_row("Findings (live)", str(sum(v["findings"] for v in module_state.values())))
                    request_table.add_row("Errors (live)", str(sum(v["errors"] for v in module_state.values())))

                    events_table = Table(show_header=True, header_style="bold magenta")
                    events_table.add_column("Time", width=8)
                    events_table.add_column("Type", width=18)
                    events_table.add_column("Module", width=18)
                    events_table.add_column("Info", width=45)
                    for ev in list(recent_events)[-8:]:
                        events_table.add_row(
                            ev.get("time", ""),
                            ev.get("type", ""),
                            ev.get("module", ""),
                            ev.get("info", ""),
                        )

                    return Group(
                        progress.get_renderable(),
                        Panel(module_table, title="Module Runtime", border_style="cyan"),
                        Panel(request_table, title="Request Metrics", border_style="green"),
                        Panel(events_table, title="Recent Events", border_style="magenta"),
                    )

                live: Optional[Live] = None

                def _refresh_live() -> None:
                    if live is not None:
                        live.update(_render_runtime_group())

                def _handle_event(event: Dict[str, Any]) -> None:
                    event_type = str(event.get("type", "unknown"))
                    module_name = str(event.get("module", "system"))
                    module_stats = module_state[module_name]
                    module_stats["events"] += 1

                    if event_type == "module_started":
                        module_stats["status"] = "running"
                    elif event_type == "module_completed":
                        module_stats["status"] = "done"
                    elif event_type == "module_error":
                        module_stats["status"] = "error"
                        module_stats["errors"] += 1
                    elif event_type == "finding_detected":
                        module_stats["findings"] += 1
                    elif event_type == "request_completed":
                        request_stats["total"] += 1
                        latency = float(event.get("latency_ms") or 0.0)
                        if latency > 0:
                            request_stats["latency_sum"] += latency
                            request_stats["latency_count"] += 1
                    elif event_type == "request_failed":
                        request_stats["total"] += 1
                        request_stats["failed"] += 1

                    timestamp = str(event.get("timestamp", datetime.now().isoformat()))
                    info_text = (
                        str(event.get("error"))
                        or str(event.get("message"))
                        or str(event.get("finding_type"))
                        or str(event.get("status_code"))
                        or ""
                    )
                    recent_events.append(
                        {
                            "time": timestamp[11:19] if len(timestamp) >= 19 else timestamp[:8],
                            "type": event_type,
                            "module": module_name,
                            "info": info_text[:45],
                        }
                    )

                    if event_file_handle is not None:
                        event_file_handle.write(json.dumps(event, ensure_ascii=False) + "\n")
                        event_file_handle.flush()

                    _refresh_live()

                async def animate_progress() -> None:
                    """Smoothly animate progress toward current phase target."""
                    while not stop_animation["value"]:
                        current = progress.tasks[task].completed
                        target = progress_target["value"]
                        if current < target:
                            progress.update(task, completed=min(target, current + 1))
                        await asyncio.sleep(0.03)

                phase_map = {
                    "Crawling target": "crawl",
                    "Scanning for SQL injection": "sqli",
                    "Scanning for XSS": "xss",
                    "Analyzing security headers": "headers",
                    "Scanning directories": "dirscan",
                    "Checking CSRF protection": "csrf",
                    "Checking for IDOR": "idor",
                    "Checking authentication": "auth",
                    "Correlating CVEs from technology fingerprint": "report",
                }

                def update_progress(message: str):
                    target_percent = None
                    for phase, percent in phase_to_percent.items():
                        if message.startswith(phase):
                            target_percent = percent
                            break

                    if target_percent is not None:
                        progress_target["value"] = max(progress_target["value"], target_percent)
                        progress.update(
                            task,
                            description=f"[cyan]{message}",
                        )
                    else:
                        progress.update(task, description=f"[cyan]{message}")

                    for phase_prefix, phase_name in phase_map.items():
                        if message.startswith(phase_prefix):
                            scan_state.update_phase(phase_name, {"message": message})
                            scan_state.complete_phase(phase_name)
                            checkpoint.save_checkpoint(
                                scan_id=host.replace(".", "_"),
                                data={
                                    "target": target_url,
                                    "phase": phase_name,
                                    "message": message,
                                    "progress": progress_target["value"],
                                },
                            )
                            break
                    _refresh_live()

                animation_task = asyncio.create_task(animate_progress())
                with Live(_render_runtime_group(), refresh_per_second=6, console=self.console) as live_instance:
                    live = live_instance
                    try:
                        try:
                            scan_coro = scanner.full_scan(
                                target,
                                progress_callback=update_progress,
                                event_callback=_handle_event,
                            )
                        except TypeError:
                            # Backward compatibility for mocked/legacy ScanEngine signatures.
                            scan_coro = scanner.full_scan(
                                target,
                                progress_callback=update_progress,
                            )
                        if max_runtime and max_runtime > 0:
                            try:
                                result = await asyncio.wait_for(scan_coro, timeout=max_runtime)
                            except asyncio.TimeoutError:
                                result = scanner.scan_result or ScanResult(
                                    target=target_url,
                                    start_time=datetime.now().isoformat(),
                                )
                                result.end_time = datetime.now().isoformat()
                                result.errors.append(
                                    {
                                        "module": "scanner",
                                        "phase": "max_runtime",
                                        "url": target_url,
                                        "error": f"Scan exceeded max runtime of {max_runtime}s",
                                        "timestamp": datetime.now().isoformat(),
                                    }
                                )
                                _handle_event(
                                    {
                                        "type": "module_error",
                                        "module": "scanner",
                                        "error": f"max runtime exceeded ({max_runtime}s)",
                                        "timestamp": datetime.now().isoformat(),
                                    }
                                )
                        else:
                            result = await scan_coro

                        progress_target["value"] = 100
                        while progress.tasks[task].completed < 100:
                            await asyncio.sleep(0.02)
                        progress.update(task, completed=100)
                        _refresh_live()
                    finally:
                        stop_animation["value"] = True
                        await animation_task
        finally:
            if event_file_handle is not None:
                event_file_handle.close()
            await scanner.close()

        if pre_scan_errors:
            result.errors.extend(pre_scan_errors)

        report_result = result
        if high_confidence_only:
            report_result = self._to_high_confidence_result(result)
            self.console.print(
                "[cyan]High-confidence filter enabled:[/cyan] "
                f"{len(report_result.findings)} of {len(result.findings)} finding(s) kept."
            )

        scan_state.state["findings"] = [
            {
                "id": f.id,
                "type": f.type,
                "url": f.url,
                "parameter": f.parameter,
                "payload": f.payload,
                "severity": f.severity,
                "description": f.description,
                "details": f.details,
            }
            for f in result.findings
        ]
        scan_state.complete_phase("report")
        scan_state.complete_scan()

        self.console.print()
        self.print_scan_summary(report_result)
        self.print_error_summary(report_result.errors)

        self.print_subdomain_results(report_result.findings)
        self.print_dns_results(report_result.findings)
        self.print_port_results(report_result.findings)
        self.print_ssl_results(report_result.findings)
        self.print_robots_results(report_result.findings)
        self.print_sitemap_results(report_result.findings)
        self.print_link_extraction_results(report_result.findings)
        self.print_graphql_results(report_result.findings)
        self.print_rate_limit_results(report_result.findings)
        self.print_takeover_results(report_result.findings)
        self.print_wayback_results(report_result.findings)
        self.print_whois_results(report_result.findings)
        self.print_js_secrets_results(report_result.findings)
        self.print_param_results(report_result.findings)
        self.print_pattern_results(report_result.findings)
        self.print_fuzz_results(report_result.findings)

        if report_result.findings:
            self.console.print()
            self.console.print(Panel("[bold magenta]Vulnerability Findings[/bold magenta]", border_style="magenta"))
            self.print_findings_table(report_result.findings)

        if output_format in ["json", "both"]:
            self.report_generator.generate_json_report(report_result)
            if output_file:
                self.report_generator.generate_json_report(report_result, f"{output_file}.json")

        if output_format in ["html", "both"]:
            if output_file:
                self.report_generator.generate_html_report(report_result, f"{output_file}.html")
                self.console.print(f"[green]HTML report saved to {output_file}.html[/green]")

        if output_format in ["text", "both"]:
            self.report_generator.generate_text_report(report_result)
            if output_file:
                self.report_generator.generate_text_report(report_result, f"{output_file}.txt")

        if jsonl_output:
            self._write_jsonl(report_result, jsonl_output)
            self.console.print(f"[green]JSONL report saved to {jsonl_output}[/green]")

        if events_path:
            self.console.print(f"[green]Event timeline saved to {events_path}[/green]")

        diff_payload = self._compute_diff(report_result, baseline_keys)
        if baseline_keys:
            self.console.print(
                f"[cyan]Baseline diff:[/cyan] {diff_payload['new_count']} new finding(s) "
                f"against {diff_payload['baseline_count']} baseline entries."
            )
            if diff_output:
                Path(diff_output).write_text(
                    json.dumps(diff_payload, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                self.console.print(f"[green]Diff report saved to {diff_output}[/green]")

        if siem_target:
            await self._emit_siem(report_result, siem_target.lower())
            self.console.print(f"[green]SIEM export completed ({siem_target}).[/green]")

        return report_result

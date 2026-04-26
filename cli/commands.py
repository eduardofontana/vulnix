"""
VULNIX - Web Vulnerability Scanner
CLI Commands Module
"""

import asyncio
from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.theme import Theme

from core.scanner import ScanEngine, ScanResult
from core.analyzer import ReportGenerator
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

    def __init__(self):
        self.console = Console(theme=theme)
        self.report_generator = ReportGenerator()

    def print_banner(self) -> None:
        """Print VULNIX banner."""
        self.console.print(f"[bold cyan1]{BANNER}[/bold cyan1]")
        self.console.print("[dim]v1.0.0 | Web Vulnerability Scanner\n[/dim]")

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
    ) -> ScanResult:
        """Run a vulnerability scan."""
        from urllib.parse import urlparse
        import socket

        target_url = target if target.startswith(("http://", "https://")) else f"https://{target}"

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

        req_engine = RequestEngine()
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

        if scan_config is None:
            scan_config = ScanConfig()

        if vuln_config is None:
            vuln_config = VulnerabilityConfig()

        mode = (scan_mode or "standard").lower()
        mode_quick = mode == "quick"
        mode_deep = mode == "deep"

        scanner = ScanEngine(scan_config=scan_config, vuln_config=vuln_config, verbose=verbose)
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

        if verbose:
            self.console.print("[yellow]Verbose mode enabled[/yellow]")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console,
            ) as progress:
                task = progress.add_task("[cyan]Initializing scan...", total=100, completed=0)
                progress_target = {"value": 0}
                stop_animation = {"value": False}
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

                async def animate_progress() -> None:
                    """Smoothly animate progress toward current phase target."""
                    while not stop_animation["value"]:
                        current = progress.tasks[task].completed
                        target = progress_target["value"]
                        if current < target:
                            progress.update(task, completed=min(target, current + 1))
                        await asyncio.sleep(0.03)

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

                animation_task = asyncio.create_task(animate_progress())
                try:
                    result = await scanner.full_scan(target, progress_callback=update_progress)
                    progress_target["value"] = 100
                    while progress.tasks[task].completed < 100:
                        await asyncio.sleep(0.02)
                    progress.update(task, completed=100)
                finally:
                    stop_animation["value"] = True
                    await animation_task
        finally:
            await scanner.close()

        if pre_scan_errors:
            result.errors.extend(pre_scan_errors)

        self.console.print()
        self.print_scan_summary(result)
        self.print_error_summary(result.errors)

        self.print_dns_results(result.findings)
        self.print_port_results(result.findings)
        self.print_ssl_results(result.findings)
        self.print_robots_results(result.findings)
        self.print_sitemap_results(result.findings)
        self.print_link_extraction_results(result.findings)
        self.print_graphql_results(result.findings)
        self.print_rate_limit_results(result.findings)
        self.print_takeover_results(result.findings)
        self.print_wayback_results(result.findings)
        self.print_whois_results(result.findings)
        self.print_js_secrets_results(result.findings)
        self.print_param_results(result.findings)
        self.print_pattern_results(result.findings)
        self.print_fuzz_results(result.findings)

        if result.findings:
            self.console.print()
            self.console.print(Panel("[bold magenta]Vulnerability Findings[/bold magenta]", border_style="magenta"))
            self.print_findings_table(result.findings)

        if output_format in ["json", "both"]:
            self.report_generator.generate_json_report(result)
            if output_file:
                self.report_generator.generate_json_report(result, f"{output_file}.json")

        if output_format in ["html", "both"]:
            if output_file:
                self.report_generator.generate_html_report(result, f"{output_file}.html")
                self.console.print(f"[green]HTML report saved to {output_file}.html[/green]")

        if output_format in ["text", "both"]:
            self.report_generator.generate_text_report(result)
            if output_file:
                self.report_generator.generate_text_report(result, f"{output_file}.txt")

        return result

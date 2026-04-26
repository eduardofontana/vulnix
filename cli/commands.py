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
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗██╗  ██╗
██║   ██║██║   ██║██║     ████╗  ██║██║╚██╗██╔╝
██║   ██║██║   ██║██║     ██╔██╗ ██║██║ ╚███╔╝
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║ ██╔██╗
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝

        Scan. Detect. Exploit (Ethically).
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

"""
VULNIX - Web Vulnerability Scanner
Main Entry Point
"""

import asyncio
import sys

from cli.commands import VulnixCLI
from config.settings import ScanConfig, VulnerabilityConfig
from core.cve_intel import CVEIntelClient


def main():
    """Main entry point for VULNIX."""
    import argparse

    parser = argparse.ArgumentParser(
        description="VULNIX - Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnix https://example.com
  vulnix http://localhost:8080 -d 2
  vulnix target.local --dirscan -o report
  vulnix https://test.app --no-sqli --format json
        """
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target URL to scan",
    )

    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)",
    )

    parser.add_argument(
        "-d", "--depth",
        type=int,
        default=3,
        help="Maximum crawl depth (default: 3)",
    )

    parser.add_argument(
        "-u", "--urls",
        type=int,
        default=100,
        help="Maximum URLs to crawl (default: 100)",
    )

    parser.add_argument(
        "--no-sqli",
        action="store_true",
        help="Disable SQL injection scanning",
    )

    parser.add_argument(
        "--no-xss",
        action="store_true",
        help="Disable XSS scanning",
    )

    parser.add_argument(
        "--no-headers",
        action="store_true",
        help="Disable security headers analysis",
    )

    parser.add_argument(
        "--dirscan",
        action="store_true",
        help="Enable directory scanning",
    )

    parser.add_argument(
        "--http-desync",
        action="store_true",
        help="Enable HTTP Request Smuggling/Desync checks",
    )

    parser.add_argument(
        "--cloud-metadata",
        action="store_true",
        help="Enable cloud metadata SSRF checks (AWS/GCP/Azure/etc.)",
    )

    parser.add_argument(
        "--waf",
        action="store_true",
        help="Enable WAF detection",
    )

    parser.add_argument(
        "--waf-bypass",
        action="store_true",
        help="Enable WAF bypass checks",
    )

    parser.add_argument(
        "--websocket",
        action="store_true",
        help="Enable WebSocket security testing",
    )

    parser.add_argument(
        "--cve-intel",
        action="store_true",
        help="Enable CVE intelligence correlation (NVD + KEV + EPSS)",
    )

    parser.add_argument(
        "--cve-intel-offline",
        action="store_true",
        help="Use local cache only for CVE intelligence (no external requests)",
    )

    parser.add_argument(
        "--update-cve-cache",
        action="store_true",
        help="Refresh local CVE cache (NVD + KEV + EPSS) before scanning",
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file prefix (will generate .json, .html, .txt)",
    )

    parser.add_argument(
        "-f", "--format",
        type=str,
        choices=["json", "html", "text", "both"],
        default="both",
        help="Output format (default: both)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    parser.add_argument(
        "-q", "--quick",
        action="store_true",
        help="Quick scan (top 10 tests only)",
    )

    parser.add_argument(
        "--mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Scan profile preset (default: standard)",
    )

    parser.add_argument(
        "--subs",
        action="store_true",
        help="Enumerate subdomains",
    )

    parser.add_argument(
        "--subs-brute",
        action="store_true",
        help="Enumerate subdomains with brute force",
    )

    parser.add_argument(
        "--param-fuzz",
        action="store_true",
        help="Fuzz parameters",
    )

    parser.add_argument(
        "--cors",
        action="store_true",
        help="Check CORS misconfiguration",
    )

    parser.add_argument(
        "--ssrf",
        action="store_true",
        help="Check for SSRF",
    )

    parser.add_argument(
        "--redirect",
        action="store_true",
        help="Check for open redirects",
    )

    parser.add_argument(
        "--tech",
        action="store_true",
        help="Fingerprint technologies",
    )

    parser.add_argument(
        "--recon",
        action="store_true",
        help="Full bug bounty reconnaissance",
    )

    parser.add_argument(
        "--recon-all",
        action="store_true",
        help="Run all recon tools (DNS, Ports, SSL, GraphQL, Takeover, Wayback, etc)",
    )

    parser.add_argument(
        "--dns",
        action="store_true",
        help="Enable DNS lookup (A, AAAA, MX, NS, TXT, CNAME)",
    )

    parser.add_argument(
        "--dns-records",
        type=str,
        help="DNS record types to query (comma-separated: A,MX,NS,TXT,CNAME)",
    )

    parser.add_argument(
        "--port-scan",
        action="store_true",
        help="Enable port scanning",
    )

    parser.add_argument(
        "--port-range",
        type=str,
        help="Port range to scan (e.g., 1-1000)",
    )

    parser.add_argument(
        "--top-ports",
        type=int,
        default=20,
        help="Number of top ports to scan (default: 20)",
    )

    parser.add_argument(
        "--ssl",
        action="store_true",
        help="Enable SSL/TLS certificate analysis",
    )

    parser.add_argument(
        "--tls-check",
        action="store_true",
        help="Check TLS vulnerabilities (Heartbleed, POODLE, etc.)",
    )

    parser.add_argument(
        "--robots",
        action="store_true",
        help="Analyze robots.txt",
    )

    parser.add_argument(
        "--sitemap",
        action="store_true",
        help="Analyze sitemap.xml",
    )

    parser.add_argument(
        "--links",
        action="store_true",
        help="Extract all links from pages",
    )

    parser.add_argument(
        "--graphql",
        action="store_true",
        help="Scan for GraphQL endpoints and vulnerabilities",
    )

    parser.add_argument(
        "--rate-limit",
        action="store_true",
        help="Detect rate limiting and throttling",
    )

    parser.add_argument(
        "--proxy",
        type=str,
        default=None,
        help="Use proxy for requests (http://host:port)",
    )

    parser.add_argument(
        "--takeover",
        action="store_true",
        help="Check subdomain takeover vulnerabilities",
    )

    parser.add_argument(
        "--wayback",
        action="store_true",
        help="Analyze Wayback Machine snapshots",
    )

    parser.add_argument(
        "--whois",
        action="store_true",
        help="WHOIS lookup for domain",
    )

    parser.add_argument(
        "--js-secrets",
        action="store_true",
        help="Extract secrets from JavaScript files",
    )

    parser.add_argument(
        "--params",
        action="store_true",
        help="Discover hidden parameters",
    )

    parser.add_argument(
        "--fuzz",
        action="store_true",
        help="Directory and file fuzzing",
    )

    parser.add_argument(
        "--pattern",
        action="store_true",
        help="Scan for sensitive patterns",
    )

    parser.add_argument(
        "--ssti",
        action="store_true",
        help="Test for Server-Side Template Injection",
    )

    parser.add_argument(
        "--lfi",
        action="store_true",
        help="Test for Local File Inclusion",
    )

    parser.add_argument(
        "--race",
        action="store_true",
        help="Test for race conditions",
    )

    parser.add_argument(
        "--xxe",
        action="store_true",
        help="Test for XML External Entity injection",
    )

    parser.add_argument(
        "--dom",
        action="store_true",
        help="Scan for DOM vulnerabilities",
    )

    parser.add_argument(
        "--cms",
        action="store_true",
        help="Detect CMS (WordPress, Joomla, Drupal, etc)",
    )

    parser.add_argument(
        "--extract-links",
        action="store_true",
        help="Extract links from crawled pages",
    )

    parser.add_argument(
        "--safe",
        action="store_true",
        help="Safe mode: reduce request pressure and disable risky active checks",
    )

    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Aggressive mode: increase request pressure and enable active checks",
    )

    parser.add_argument(
        "--resume",
        type=str,
        help="Resume state file path (e.g., vulnix_state.json)",
    )

    parser.add_argument(
        "--checkpoint-dir",
        type=str,
        default="checkpoints",
        help="Directory for periodic checkpoints (default: checkpoints)",
    )

    parser.add_argument(
        "--jsonl-output",
        type=str,
        help="Write findings in JSONL format to the given file",
    )

    parser.add_argument(
        "--siem",
        type=str,
        choices=["splunk", "elk"],
        help="Emit findings to SIEM endpoint profile (splunk or elk)",
    )

    parser.add_argument(
        "--baseline",
        type=str,
        help="Baseline JSON report for finding diff",
    )

    parser.add_argument(
        "--diff-output",
        type=str,
        help="Write baseline diff report to file (JSON)",
    )

    parser.add_argument(
        "--high-confidence-only",
        action="store_true",
        help="Keep only high-confidence findings in terminal output and reports",
    )

    args = parser.parse_args()

    cli = VulnixCLI()

    async def _warm_cve_cache() -> None:
        client = CVEIntelClient()
        warm_techs = [
            "nginx", "apache", "iis", "php", "nodejs", "express",
            "django", "flask", "wordpress", "react", "nextjs",
        ]
        summary = await client.warm_cache(warm_techs, max_results_per_tech=20)
        cli.print_banner()
        cli.console.print("[green]CVE cache updated.[/green]")
        cli.console.print(str(summary))

    if not args.target and not args.resume:
        if args.update_cve_cache:
            try:
                asyncio.run(_warm_cve_cache())
                return 0
            except Exception as e:
                cli.console.print(f"[red]CVE cache update failed: {e}[/red]")
                return 1

        cli.print_banner()
        cli.print_disclaimer()
        cli.console.print("\n[yellow]Usage:[/yellow] vulnix <target> [options]")
        cli.console.print("\n[cyan]Example:[/cyan] vulnix https://example.com")
        cli.console.print("[cyan]       [/cyan] vulnix https://example.com -d 2 -o report")
        cli.console.print("[cyan]       [/cyan] vulnix http://localhost --dirscan --format json")
        return 0

    scan_config = ScanConfig(
        timeout=args.timeout,
        max_depth=args.depth,
        max_urls=args.urls,
    )

    mode_defaults = {
        "quick": {
            "enable_sqli": True,
            "enable_xss": True,
            "enable_headers": True,
            "enable_dirscan": False,
            "enable_csrf": False,
            "enable_idor": False,
            "enable_auth": False,
            "enable_http_desync": False,
            "enable_cloud_metadata": False,
            "enable_waf_detection": False,
            "enable_waf_bypass": False,
            "enable_websocket": False,
            "enable_cve_intel": False,
        },
        "standard": {
            "enable_sqli": True,
            "enable_xss": True,
            "enable_headers": True,
            "enable_dirscan": False,
            "enable_csrf": False,
            "enable_idor": False,
            "enable_auth": False,
            "enable_http_desync": False,
            "enable_cloud_metadata": False,
            "enable_waf_detection": False,
            "enable_waf_bypass": False,
            "enable_websocket": False,
            "enable_cve_intel": False,
        },
        "deep": {
            "enable_sqli": True,
            "enable_xss": True,
            "enable_headers": True,
            "enable_dirscan": True,
            "enable_csrf": True,
            "enable_idor": True,
            "enable_auth": True,
            "enable_http_desync": True,
            "enable_cloud_metadata": True,
            "enable_waf_detection": True,
            "enable_waf_bypass": True,
            "enable_websocket": True,
            "enable_cve_intel": True,
        },
    }
    selected_mode = mode_defaults[args.mode]

    vuln_config = VulnerabilityConfig(
        enable_sqli=selected_mode["enable_sqli"] and not args.no_sqli,
        enable_xss=selected_mode["enable_xss"] and not args.no_xss,
        enable_headers=selected_mode["enable_headers"] and not args.no_headers,
        enable_dirscan=selected_mode["enable_dirscan"] or args.dirscan,
        enable_csrf=selected_mode["enable_csrf"],
        enable_idor=selected_mode["enable_idor"],
        enable_auth=selected_mode["enable_auth"],
        enable_http_desync=selected_mode["enable_http_desync"] or args.http_desync,
        enable_cloud_metadata=selected_mode["enable_cloud_metadata"] or args.cloud_metadata,
        enable_waf_detection=selected_mode["enable_waf_detection"] or args.waf,
        enable_waf_bypass=selected_mode["enable_waf_bypass"] or args.waf_bypass,
        enable_websocket=selected_mode["enable_websocket"] or args.websocket,
        enable_cve_intel=selected_mode["enable_cve_intel"] or args.cve_intel,
        cve_intel_offline=args.cve_intel_offline,
    )

    if args.update_cve_cache:
        try:
            asyncio.run(_warm_cve_cache())
        except Exception as e:
            cli.console.print(f"[red]CVE cache update failed: {e}[/red]")
            return 1

    if args.safe and args.aggressive:
        cli.console.print("[red]Choose only one mode: --safe or --aggressive.[/red]")
        return 1

    try:
        result = asyncio.run(
            cli.run_scan(
                args.target,
                scan_config=scan_config,
                vuln_config=vuln_config,
                output_format=args.format,
                output_file=args.output,
                verbose=args.verbose,
                quick_scan=args.quick,
                subdomain_enum=args.subs,
                subdomain_bruteforce=args.subs_brute,
                param_fuzz=args.param_fuzz,
                cors_check=args.cors,
                ssrf_check=args.ssrf,
                redirect_check=args.redirect,
                tech_fingerprint=args.tech,
                recon=args.recon,
                scan_mode=args.mode,
                dns_lookup=args.dns,
                dns_records=args.dns_records,
                port_scan=args.port_scan,
                port_range=args.port_range,
                top_ports=args.top_ports,
                ssl_analysis=args.ssl,
                tls_check=args.tls_check,
                robots_analysis=args.robots,
                sitemap_analysis=args.sitemap,
                link_extraction=args.links or args.extract_links,
                graphql_scan=args.graphql,
                rate_limit_detect=args.rate_limit,
                proxy_url=args.proxy,
                takeover_check=args.takeover,
                wayback_analysis=args.wayback,
                whois_lookup=args.whois,
                js_secrets=args.js_secrets,
                param_discovery=args.params,
                content_fuzz=args.fuzz,
                pattern_scan=args.pattern,
                recon_all=args.recon_all,
                ssti_scan=args.ssti,
                lfi_scan=args.lfi,
                race_scan=args.race,
                xxe_scan=args.xxe,
                dom_scan=args.dom,
                cms_detect=args.cms,
                safe_mode=args.safe,
                aggressive_mode=args.aggressive,
                resume_state_file=args.resume,
                checkpoint_dir=args.checkpoint_dir,
                jsonl_output=args.jsonl_output,
                siem_target=args.siem,
                baseline_file=args.baseline,
                diff_output=args.diff_output,
                high_confidence_only=args.high_confidence_only,
            )
        )

        return 0 if result else 1

    except KeyboardInterrupt:
        cli.console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        return 130

    except Exception as e:
        cli.console.print(f"\n[red]Error: {str(e)}[/red]")
        if args.verbose:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())

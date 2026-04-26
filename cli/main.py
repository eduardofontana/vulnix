"""
VULNIX - Web Vulnerability Scanner
Main Entry Point
"""

import asyncio
import sys

from cli.commands import VulnixCLI
from config.settings import ScanConfig, VulnerabilityConfig


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

    args = parser.parse_args()

    if not args.target:
        cli = VulnixCLI()
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
    )

    cli = VulnixCLI()

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

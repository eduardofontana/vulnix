"""
VULNIX - SSL/TLS Certificate Analyzer
Extract and analyze SSL/TLS certificate information
"""

import asyncio
import ssl
import socket
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import httpx

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


class SSLCertificateInfo:
    """SSL/TLS certificate and vulnerability detection."""

    COMMON_SSL_PORTS = [443, 8443, 993, 995, 465, 587]

    VULNERABILITIES = {
        "heartbleed": {
            "cve": "CVE-2014-0160",
            "description": "Heartbleed vulnerability in OpenSSL",
        },
        "poodle": {
            "cve": "CVE-2014-3566",
            "description": "POODLE attack on SSLv3",
        },
        "freak": {
            "cve": "CVE-2015-0204",
            "description": "FREAK export key vulnerability",
        },
        "logjam": {
            "cve": "CVE-2015-4000",
            "description": "LOGJAM export key vulnerability",
        },
    }

    def __init__(self, request_engine: Optional[RequestEngine] = None):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("ssl_cert")
        self.cert_info: Dict[str, Any] = {}
        self.cipher_suites: List[str] = []

    def _normalize_host(self, value: str) -> tuple[str, int]:
        """Normalize input to host and port."""
        if "://" in value:
            parsed = urlparse(value)
            host = parsed.hostname or value
            port = parsed.port or 443
        elif ":" in value:
            parts = value.rsplit(":", 1)
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 443
        else:
            host = value
            port = 443

        return host, port

    def fetch_certificate(
        self, host: str, port: int = 443, timeout: float = 5.0
    ) -> Optional[Dict[str, Any]]:
        """Fetch SSL certificate from host."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    if cert:
                        x509 = ssl.DER_cert_to_PEM_cert(cert)
                        parsed_cert = x509
                        self.cert_info = self._parse_cert_info(
                            cert, cipher, protocol
                        )
                        return self.cert_info

        except ssl.SSLError as e:
            self.error_collector.add(f"{host}:{port}", e, "ssl_error")
        except socket.timeout:
            self.error_collector.add(f"{host}:{port}", "timeout", "ssl_timeout")
        except socket.gaierror as e:
            self.error_collector.add(f"{host}:{port}", e, "dns_error")
        except Exception as e:
            self.error_collector.add(f"{host}:{port}", e, "fetch_cert")

        return None

    def _parse_cert_info(
        self,
        cert: bytes,
        cipher: Optional[tuple],
        protocol: Optional[str],
    ) -> Dict[str, Any]:
        """Parse certificate information."""
        try:
            import cryptography.x509
            from cryptography.hazmat.backends import default_backend

            x509 = cryptography.x509.load_der_x509_certificate(
                cert, default_backend()
            )

            subject = x509.subject
            issuer = x509.issuer

            subject_cn = None
            for attr in subject:
                if attr.oid == cryptography.x509.oid.NameOID.COMMON_NAME:
                    subject_cn = attr.value
                    break

            issuer_cn = None
            for attr in issuer:
                if attr.oid == cryptography.x509.oid.NameOID.COMMON_NAME:
                    issuer_cn = attr.value
                    break

            try:
                not_before = x509.not_valid_before_utc
                not_after = x509.not_valid_after_utc
            except AttributeError:
                not_before = x509.not_valid_before
                not_after = x509.not_valid_after

            sans = []
            try:
                for ext in x509.extensions:
                    if ext.oid == cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                        sans = [name.value for name in ext.value]
            except Exception:
                pass

            fingerprint = hashlib.sha256(cert, usedforsecurity=True).hexdigest()
            fingerprint_md5 = hashlib.md5(cert, usedforsecurity=False).hexdigest()

            days_remaining = (not_after - datetime.now(not_after.tzinfo)).days

            return {
                "subject": subject_cn,
                "issuer": issuer_cn,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_remaining": days_remaining,
                "expired": days_remaining < 0,
                "self_signed": subject_cn == issuer_cn,
                "sans": sans,
                "fingerprint_sha256": fingerprint,
                "fingerprint_md5": fingerprint_md5,
                "cipher": cipher[0] if cipher else None,
                "protocol": protocol,
            }

        except Exception as e:
            self.error_collector.add("parse_cert", e, "parse_cert_info")
            return {
                "subject": None,
                "issuer": None,
                "not_before": None,
                "not_after": None,
                "error": str(e),
            }

    def check_expiry(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Check certificate expiry status."""
        cert_info = self.fetch_certificate(host, port)

        if not cert_info:
            return {"error": "Could not fetch certificate"}

        days = cert_info.get("days_remaining", 0)

        return {
            "host": host,
            "port": port,
            "expired": cert_info.get("expired", False),
            "days_remaining": days,
            "not_after": cert_info.get("not_after"),
            "severity": "critical" if days < 0 else "high" if days < 30 else "medium" if days < 90 else "low",
        }

    async def scan_ports(self, host: str) -> Dict[int, Dict[str, Any]]:
        """Scan common SSL ports and fetch certificates."""
        results = {}

        for port in self.COMMON_SSL_PORTS:
            cert_info = await asyncio.to_thread(self.fetch_certificate, host, port)
            if cert_info:
                results[port] = cert_info
                self.cert_info = cert_info

        return results

    def get_server_info(self, host: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """Get SSL server configuration info."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    return {
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "cipher": cipher[0] if cipher else None,
                        "cipher_bits": cipher[2] if cipher else None,
                        "compression": None,
                        "session_tickets": False,
                    }

        except Exception as e:
            self.error_collector.add(f"{host}:{port}", e, "server_info")
            return None

    def analyze(self, target: str) -> Dict[str, Any]:
        """Perform complete SSL/TLS analysis."""
        host, port = self._normalize_host(target)

        result = {
            "target": target,
            "host": host,
            "port": port,
        }

        cert_info = self.fetch_certificate(host, port)
        if cert_info:
            result["certificate"] = cert_info

        server_info = self.get_server_info(host, port)
        if server_info:
            result["server"] = server_info

        errors = self.error_collector.all()
        if errors:
            result["errors"] = errors

        return result

    def get_results(self) -> Dict[str, Any]:
        """Get certificate info."""
        return self.cert_info

    def get_errors(self) -> List[Dict[str, Any]]:
        return self.error_collector.all()
"""
VULNIX - WebSocket Security Testing Module
Test WebSocket endpoints for security vulnerabilities
"""

import asyncio
import json
import re
from typing import Dict, List, Optional, Any, Callable
from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


class WebSocketTester:
    """Test WebSocket endpoints for security issues."""

    COMMON_PATHS = [
        "/ws",
        "/websocket",
        "/ws/v2",
        "/api/ws",
        "/realtime",
        "/socket",
        "/push",
    ]

    WS_PAYLOADS = {
        "xss_basic": ["<script>alert(1)</script>", "javascript:alert(1)"],
        "xss_event": ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
        "injection": ["'; DROP TABLE users;--", '"; DELETE FROM sessions;--'],
        "protocol": [
            "PING",
            "META-INF/",
            "GET /admin HTTP/1.1",
            "\x00\x01\x02\x03",
        ],
    }

    def __init__(self, request_engine: RequestEngine):
        self.engine = request_engine
        self.findings: List[Dict[str, Any]] = []
        self.ws_endpoints: List[str] = []
        self.error_collector = ModuleErrorCollector("websocket")

    async def discover(self, base_url: str) -> List[str]:
        """Discover WebSocket endpoints from HTML/JS."""
        self.ws_endpoints = []

        try:
            response = await self.engine.get(base_url)
            if not response:
                return []

            content = response.text

            ws_patterns = [
                r'ws://([^\s"\'<>]+)',
                r'wss://([^\s"\'<>]+)',
                r'new\s+WebSocket\([\'"]([^\'"]+)[\'"]\)',
                r'WebSocket\.connect\([\'"]([^\'"]+)[\'"]\)',
                r'socket\.io\s*:\s*[\'"]([^\'"]+)[\'"]',
            ]

            for pattern in ws_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        endpoint = match[0] if match else ""
                    else:
                        endpoint = match

                    if endpoint and endpoint not in self.ws_endpoints:
                        if endpoint.startswith("/"):
                            endpoint = base_url.rstrip("/") + endpoint
                        self.ws_endpoints.append(endpoint)

            for path in self.COMMON_PATHS:
                endpoint = base_url.rstrip("/") + path
                self.ws_endpoints.append(endpoint)

        except Exception as e:
            self.error_collector.add(base_url, e, "discover")

        return self.ws_endpoints

    async def test_endpoint(
        self,
        url: str,
        protocol: str = "ws"
    ) -> List[Dict[str, Any]]:
        """Test a specific WebSocket endpoint."""
        findings = []

        await self._test_origin_bypass(url, protocol, findings)
        await self._test_input_validation(url, protocol, findings)
        await self._test_subscription_hijacking(url, protocol, findings)
        await self._test_dos_potential(url, protocol, findings)

        return findings

    async def _test_origin_bypass(
        self,
        url: str,
        protocol: str,
        findings: List[Dict[str, Any]]
    ) -> None:
        """Test for Origin header bypass."""
        headers = {
            "Origin": "https://evil.com",
            "Sec-WebSocket-Version": "13",
        }

        try:
            reader, writer = await asyncio.wait_for(
                self._create_websocket(url, protocol, headers),
                timeout=5
            )

            writer.write(b"GET / HTTP/1.1\r\n\r\n")
            await writer.drain()

            try:
                response = await asyncio.wait_for(reader.read(1024), timeout=5)
                if response:
                    findings.append({
                        "type": "websocket",
                        "subtype": "origin_bypass",
                        "severity": "medium",
                        "url": url,
                        "description": "WebSocket endpoint accepts connections from arbitrary origins",
                        "remediation": "Implement proper Origin validation",
                        "cvss": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
                    })
            except asyncio.TimeoutError:
                pass

            writer.close()
            await writer.wait_closed()

        except Exception as e:
            self.error_collector.add(url, e, "test_origin_bypass")

    async def _test_input_validation(
        self,
        url: str,
        protocol: str,
        findings: List[Dict[str, Any]]
    ) -> None:
        """Test for input validation issues."""
        for category, payloads in self.WS_PAYLOADS.items():
            for payload in payloads:
                try:
                    reader, writer = await asyncio.wait_for(
                        self._create_websocket(url, protocol),
                        timeout=5
                    )

                    if category in ["xss_basic", "xss_event"]:
                        await self._send_ws_frame(writer, f"<{payload}>")
                    elif category == "injection":
                        await self._send_ws_frame(writer, payload)
                    else:
                        await self._send_ws_frame(writer, payload)

                    await asyncio.sleep(0.5)

                    try:
                        response = await asyncio.wait_for(reader.read(1024), timeout=3)
                        response_text = response.decode("utf-8", errors="ignore").lower()
                        if payload.lower() in response_text:
                            findings.append({
                                "type": "websocket",
                                "subtype": "input_validation",
                                "severity": "high",
                                "url": url,
                                "description": f"WebSocket echoes unsanitized input ({category})",
                                "payload": payload,
                                "remediation": "Implement proper input sanitization",
                                "cvss": {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"},
                            })
                    except asyncio.TimeoutError:
                        pass

                    writer.close()
                    await writer.wait_closed()

                except Exception as e:
                    self.error_collector.add(url, e, f"test_input_validation_{category}")
                    continue

    async def _test_subscription_hijacking(
        self,
        url: str,
        protocol: str,
        findings: List[Dict[str, Any]]
    ) -> None:
        """Test for subscription/channel hijacking."""
        try:
            reader1, writer1 = await asyncio.wait_for(
                self._create_websocket(url, protocol),
                timeout=5
            )

            channel_msg = json.dumps({"action": "subscribe", "channel": "admin"})
            await self._send_ws_frame(writer1, channel_msg)

            await asyncio.sleep(0.5)

            reader2, writer2 = await asyncio.wait_for(
                self._create_websocket(url, protocol),
                timeout=5
            )

            try:
                response = await asyncio.wait_for(reader2.read(1024), timeout=2)
                if b"admin" in response.lower():
                    findings.append({
                        "type": "websocket",
                        "subtype": "subscription_hijacking",
                        "severity": "medium",
                        "url": url,
                        "description": "WebSocket allows subscription to privileged channels without auth",
                        "remediation": "Implement proper channel authorization",
                        "cvss": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
                    })
            except asyncio.TimeoutError:
                pass

            writer1.close()
            writer2.close()
            await writer1.wait_closed()
            await writer2.wait_closed()

        except Exception as e:
            self.error_collector.add(url, e, "test_subscription_hijacking")

    async def _test_dos_potential(
        self,
        url: str,
        protocol: str,
        findings: List[Dict[str, Any]]
    ) -> None:
        """Test for DoS vulnerability."""
        import time

        try:
            connections = []
            start_time = time.time()

            for _ in range(50):
                try:
                    reader, writer = await asyncio.wait_for(
                        self._create_websocket(url, protocol),
                        timeout=1
                    )
                    connections.append((reader, writer))
                except Exception as e:
                    self.error_collector.add(url, e, "test_dos_potential_connect")
                    break

            elapsed = time.time() - start_time

            for reader, writer in connections:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    self.error_collector.add(url, e, "test_dos_potential_close")

            if len(connections) >= 50 and elapsed < 2:
                findings.append({
                    "type": "websocket",
                    "subtype": "dos_vulnerability",
                    "severity": "medium",
                    "url": url,
                    "description": "Server accepts excessive concurrent WebSocket connections",
                    "remediation": "Implement connection limits and rate limiting",
                    "cvss": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
                })

        except Exception as e:
            self.error_collector.add(url, e, "test_dos_potential")

    async def _create_websocket(
        self,
        url: str,
        protocol: str = "ws",
        headers: Optional[Dict] = None
    ) -> tuple:
        """Create a raw WebSocket connection."""
        import socket

        url_match = re.match(rf"{protocol}://([^\/:]+)(?::(\d+))?(.*)", url)
        if not url_match:
            raise ValueError(f"Invalid WebSocket URL: {url}")

        host = url_match.group(1)
        port = int(url_match.group(2)) if url_match.group(2) else (443 if protocol == "wss" else 80)
        path = url_match.group(3) or "/"

        reader, writer = await asyncio.open_connection(host, port)

        key = "dGhlIHNhbXBsZSBub25jZQ=="
        upgrade_headers = "".join([
            f"{k}: {v}\r\n" for k, v in (headers or {}).items()
        ])

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"{upgrade_headers}"
            f"\r\n"
        )

        writer.write(request.encode())
        await writer.drain()

        return reader, writer

    async def _send_ws_frame(self, writer, message: str) -> None:
        """Send a WebSocket frame."""
        import struct

        message_bytes = message.encode("utf-8")
        frame = bytearray()

        frame.append(0x81)

        if len(message_bytes) <= 125:
            frame.append(0x80 | len(message_bytes))
        elif len(message_bytes) <= 65535:
            frame.append(0x80 | 126)
            frame.extend(struct.pack(">H", len(message_bytes)))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack(">Q", len(message_bytes)))

        import os
        mask = os.urandom(4)
        frame.extend(mask)

        masked_data = bytearray()
        for i, byte in enumerate(message_bytes):
            masked_data.append(byte ^ mask[i % 4])
        frame.extend(masked_data)

        writer.write(bytes(frame))
        await writer.drain()

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get structured tester errors."""
        return self.error_collector.all()


class WebSocketPlugin:
    """Plugin wrapper for WebSocket testing."""

    name = "websocket-tester"
    description = "Test WebSocket endpoints for security vulnerabilities"

    def __init__(self, request_engine: RequestEngine):
        self.tester = WebSocketTester(request_engine)

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Run WebSocket security tests."""
        endpoints = await self.tester.discover(target)

        findings = []
        for endpoint in endpoints:
            protocol = "wss" if endpoint.startswith("wss") else "ws"
            findings.extend(await self.tester.test_endpoint(endpoint, protocol))

        return findings

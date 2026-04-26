"""
VULNIX - Cloud Metadata Service Detection Module
Detect SSRF vulnerabilities targeting cloud metadata services
AWS, GCP, Azure, Oracle, Alibaba Cloud
"""

from typing import Dict, List, Optional, Any
from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


class CloudMetadataDetector:
    """Detect access to cloud provider metadata services."""

    METADATA_ENDPOINTS = {
        "aws": {
            "name": "AWS EC2 Metadata Service",
            "base_url": "http://169.254.169.254/latest/meta-data/",
            "credential_paths": [
                "iam/security-credentials/",
                "iam/security-credentials/admin-role",
            ],
            "info_paths": [
                "ami-id",
                "instance-id",
                "instance-type",
                "security-groups",
            ],
        },
        "gcp": {
            "name": "GCP Metadata Service",
            "base_url": "http://metadata.google.internal/computeMetadata/v1/",
            "credential_paths": [
                "instance/service-accounts/default/token",
                "instance/service-accounts/admin/token",
            ],
            "info_paths": [
                "instance/id",
                "instance/name",
                "project/project-id",
                "instance/zone",
            ],
        },
        "azure": {
            "name": "Azure Instance Metadata Service",
            "base_url": "http://169.254.169.254/metadata/",
            "credential_paths": [
                "identity/oauth2/token",
                "identity/info",
            ],
            "info_paths": [
                "instance/compute/vmId",
                "instance/compute/name",
                "instance/compute/subscriptionId",
            ],
        },
        "oracle": {
            "name": "Oracle Cloud Metadata Service",
            "base_url": "http://169.254.169.254/opc/v1/",
            "credential_paths": [
                "identity/main/region",
                "instance/v1/instance",
            ],
            "info_paths": [
                "instance/id",
                "instance/displayName",
            ],
        },
        "alibaba": {
            "name": "Alibaba Cloud Metadata Service",
            "base_url": "http://100.100.100.200/latest/meta-data/",
            "credential_paths": [
                "ram/2015-04-01/security-credentials/",
            ],
            "info_paths": [
                "instance-id",
                "region",
                "zone-id",
            ],
        },
        "digitalocean": {
            "name": "DigitalOcean Metadata Service",
            "base_url": "http://169.254.169.254/metadata/v1/",
            "credential_paths": [
                "interfaces/shared/0/anchor ipv4/address",
            ],
            "info_paths": [
                "id",
                "name",
                "region",
            ],
        },
        "kubernetes": {
            "name": "Kubernetes In-Cluster Metadata",
            "base_url": "https://kubernetes.default.svc/api/v1/",
            "credential_paths": [
                "namespaces/kube-system/secrets/",
            ],
            "info_paths": [
                "namespaces",
            ],
        },
    }

    def __init__(self, request_engine: RequestEngine):
        self.engine = request_engine
        self.findings: List[Dict[str, Any]] = []
        self.error_collector = ModuleErrorCollector("cloud_metadata")

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        """Scan for cloud metadata SSRF vulnerabilities."""
        self.findings = []

        for provider, config in self.METADATA_ENDPOINTS.items():
            await self._test_provider(url, provider, config)

        return self.findings

    async def _test_provider(
        self,
        target_url: str,
        provider: str,
        config: Dict[str, Any]
    ) -> None:
        """Test access to a specific cloud provider's metadata service."""
        base_url = config["base_url"]

        for path in config["info_paths"]:
            endpoint = f"{base_url}{path}"
            try:
                response = await self.engine.get(endpoint, timeout=5)

                if response and response.status_code == 200:
                    self.findings.append({
                        "type": "ssrf",
                        "subtype": "cloud_metadata",
                        "provider": provider,
                        "name": config["name"],
                        "severity": "critical",
                        "endpoint": endpoint,
                        "target_url": target_url,
                        "description": f"SSRF allowing access to {config['name']}",
                        "data_leaked": response.text[:500] if response.text else "empty",
                        "remediation": f"Block external access to {base_url}",
                        "cvss": {"score": 9.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"},
                    })
                    return

            except Exception as e:
                self.error_collector.add(target_url, e, f"test_provider_info_{provider}")
                continue

        for path in config["credential_paths"]:
            endpoint = f"{base_url}{path}"
            try:
                response = await self.engine.get(endpoint, timeout=5)

                if response and response.status_code == 200:
                    self.findings.append({
                        "type": "ssrf",
                        "subtype": "cloud_metadata_creds",
                        "provider": provider,
                        "name": config["name"],
                        "severity": "critical",
                        "endpoint": endpoint,
                        "target_url": target_url,
                        "description": f"SSRF allowing access to {config['name']} credentials",
                        "data_leaked": "Cloud credentials potentially exposed",
                        "remediation": f"Block external access to {base_url} immediately",
                        "cvss": {"score": 10.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
                    })
                    return

            except Exception as e:
                self.error_collector.add(target_url, e, f"test_provider_creds_{provider}")
                continue

    async def check_known_ssrf_target(
        self,
        ssrf_candidate_url: str,
        target_cloud: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Check if a known SSRF endpoint can reach cloud metadata."""
        findings = []

        providers_to_test = (
            {target_cloud: self.METADATA_ENDPOINTS[target_cloud]}
            if target_cloud and target_cloud in self.METADATA_ENDPOINTS
            else self.METADATA_ENDPOINTS
        )

        for provider, config in providers_to_test.items():
            for path in config["info_paths"]:
                endpoint = f"{config['base_url']}{path}"

                full_ssrf_url = ssrf_candidate_url.replace("FUZZ", endpoint)

                try:
                    response = await self.engine.get(full_ssrf_url, timeout=10)

                    if response and response.status_code == 200:
                        findings.append({
                            "type": "ssrf",
                            "subtype": "cloud_metadata_confirmed",
                            "provider": provider,
                            "severity": "critical",
                            "ssrf_url": ssrf_candidate_url,
                            "target": endpoint,
                            "description": f"SSRF confirmed - can reach {config['name']}",
                            "remediation": "Block access to internal metadata endpoints",
                            "cvss": {"score": 9.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"},
                        })

                except Exception as e:
                    self.error_collector.add(ssrf_candidate_url, e, f"check_known_ssrf_target_{provider}")
                    continue

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get structured detector errors."""
        return self.error_collector.all()


class CloudMetadataPlugin:
    """Plugin wrapper for Cloud Metadata detection."""

    name = "cloud-metadata-detector"
    description = "Detect SSRF access to cloud provider metadata services"

    def __init__(self, request_engine: RequestEngine):
        self.detector = CloudMetadataDetector(request_engine)

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Run cloud metadata scan."""
        return await self.detector.scan(target)

    def get_findings(self) -> List[Dict[str, Any]]:
        """Get findings from last scan."""
        return self.detector.findings

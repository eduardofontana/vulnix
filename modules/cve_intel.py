"""
VULNIX - CVE Intelligence Detector
Correlates technology fingerprints with NVD CVEs and enriches with KEV/EPSS.
"""

from __future__ import annotations

import re
from typing import Dict, List, Any, Optional

from core.cve_intel import CVEIntelClient
from core.error_collector import ModuleErrorCollector


class CVEIntelligenceDetector:
    """Detect potential CVEs based on discovered technologies."""

    TECH_ALIAS_MAP = {
        "nextjs": "next.js",
        "react": "react",
        "nginx": "nginx",
        "apache": "apache http server",
        "iis": "microsoft iis",
        "php": "php",
        "nodejs": "node.js",
        "express": "express",
        "django": "django",
        "flask": "flask",
        "wordpress": "wordpress",
    }

    def __init__(
        self,
        intel_client: Optional[CVEIntelClient] = None,
        offline: bool = False,
    ):
        self.intel_client = intel_client or CVEIntelClient()
        self.intel_client.set_offline(offline)
        self.error_collector = ModuleErrorCollector("cve_intel")
        self.results: List[Dict[str, Any]] = []

    def set_offline(self, enabled: bool) -> None:
        """Set detector data source to offline mode."""
        self.intel_client.set_offline(enabled)

    def _normalize_tech(self, tech: str) -> str:
        normalized = (tech or "").strip().lower()
        return self.TECH_ALIAS_MAP.get(normalized, normalized)

    def _parse_tech_entry(self, raw_tech: str) -> tuple[str, Optional[str]]:
        value = (raw_tech or "").strip()
        if not value:
            return "", None

        version = None
        match = re.match(r"^\s*([a-zA-Z0-9_.+\-]+)\s*@\s*([a-zA-Z0-9_.+\-]+)\s*$", value)
        if match:
            return self._normalize_tech(match.group(1)), match.group(2)

        slash_match = re.match(r"^\s*([a-zA-Z0-9_.+\-]+)\s*/\s*([0-9][a-zA-Z0-9_.+\-]*)\s*$", value)
        if slash_match:
            return self._normalize_tech(slash_match.group(1)), slash_match.group(2)

        trailing_version = re.match(
            r"^\s*([a-zA-Z0-9_.+\-]+)\s+([0-9]+(?:\.[0-9]+){1,3}(?:[-_a-zA-Z0-9.]+)?)\s*$",
            value,
        )
        if trailing_version:
            return self._normalize_tech(trailing_version.group(1)), trailing_version.group(2)

        return self._normalize_tech(value), version

    def _severity_from_cvss(self, cvss: Optional[float]) -> str:
        if cvss is None:
            return "info"
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        if cvss > 0.0:
            return "low"
        return "info"

    async def scan(self, target_url: str, technologies: List[str]) -> List[Dict[str, Any]]:
        """Scan candidate CVEs for a set of technology fingerprints."""
        self.results = []
        if not technologies:
            return []

        normalized_tech_entries = sorted(
            {
                self._parse_tech_entry(t)
                for t in technologies
                if (t or "").strip()
            },
            key=lambda item: (item[0], item[1] or ""),
        )
        cve_records: List[Dict[str, Any]] = []
        seen_pairs = set()

        for tech, detected_version in normalized_tech_entries:
            if not tech:
                continue
            try:
                candidates = await self.intel_client.search_nvd(tech, max_results=12)
            except Exception as e:
                self.error_collector.add(target_url, e, "search_nvd")
                continue

            for candidate in candidates:
                cve_id = candidate.get("cve_id")
                if not cve_id:
                    continue
                pair = (tech, cve_id)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                cve_records.append(
                    {
                        **candidate,
                        "technology": tech,
                        "detected_version": detected_version,
                    }
                )

        if not cve_records:
            return []

        cve_ids = [entry.get("cve_id", "") for entry in cve_records if entry.get("cve_id")]

        try:
            kev_set = await self.intel_client.get_kev_cves()
        except Exception as e:
            self.error_collector.add(target_url, e, "get_kev")
            kev_set = set()

        try:
            epss_map = await self.intel_client.get_epss_scores(cve_ids)
        except Exception as e:
            self.error_collector.add(target_url, e, "get_epss")
            epss_map = {}

        findings: List[Dict[str, Any]] = []
        for entry in cve_records:
            cve_id = entry.get("cve_id")
            tech = entry.get("technology", "unknown")
            if not cve_id:
                continue

            epss_data = epss_map.get(cve_id, {})
            epss = epss_data.get("epss", 0.0)
            percentile = epss_data.get("percentile", 0.0)
            kev = cve_id in kev_set
            cvss = entry.get("cvss")
            detected_version = entry.get("detected_version")
            has_version_evidence = bool(detected_version)

            confidence = "tentative"
            if kev and has_version_evidence:
                confidence = "firm"
            elif epss >= 0.7 and has_version_evidence:
                confidence = "firm"
            elif kev or epss >= 0.7:
                confidence = "plausible"

            severity = self._severity_from_cvss(cvss)
            if kev and has_version_evidence and severity in {"info", "low", "medium"}:
                severity = "high"

            version_note = (
                f"Detected version hint: {detected_version}"
                if has_version_evidence
                else "No version hint detected for target technology"
            )
            findings.append(
                {
                    "type": "cve_intel",
                    "subtype": "technology_correlation",
                    "module": "cve_intel",
                    "url": target_url,
                    "severity": severity,
                    "description": f"Potential CVE match for technology '{tech}': {cve_id}",
                    "evidence": (
                        f"Matched NVD by keyword '{tech}' "
                        f"(confidence={confidence}; {version_note})"
                    ),
                    "remediation": "Validate affected version and apply vendor patch/mitigation guidance.",
                    "details": {
                        "cve_id": cve_id,
                        "technology": tech,
                        "detected_version": detected_version,
                        "cvss": cvss,
                        "epss": epss,
                        "epss_percentile": percentile,
                        "kev": kev,
                        "confidence": confidence,
                        "severity_elevated": kev and has_version_evidence,
                        "published": entry.get("published"),
                        "last_modified": entry.get("last_modified"),
                        "references": entry.get("references", []),
                    },
                }
            )

        findings.sort(
            key=lambda f: (
                f["details"].get("kev", False),
                f["details"].get("epss", 0.0),
                f["details"].get("cvss", 0.0) or 0.0,
            ),
            reverse=True,
        )
        self.results = findings[:30]
        return self.results

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get structured detector errors."""
        return self.error_collector.all()

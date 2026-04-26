"""
VULNIX - CVE Intelligence Data Sources
NVD + CISA KEV + FIRST EPSS integration with local cache.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx


class CVEIntelClient:
    """Client for CVE data aggregation with lightweight local caching."""

    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_URL = "https://api.first.org/data/v1/epss"

    def __init__(
        self,
        cache_file: str = "data/cve_intel_cache.json",
        cache_ttl_hours: int = 24,
        timeout_seconds: int = 25,
        offline: bool = False,
    ):
        self.cache_file = Path(cache_file)
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self.cache_ttl_hours = cache_ttl_hours
        self.timeout_seconds = timeout_seconds
        self.offline = offline

    def set_offline(self, enabled: bool) -> None:
        """Enable or disable offline mode."""
        self.offline = enabled

    def _utcnow(self) -> datetime:
        return datetime.now(timezone.utc)

    def _default_cache(self) -> Dict[str, Any]:
        return {
            "updated_at": None,
            "nvd_queries": {},
            "kev": {"updated_at": None, "cves": []},
        }

    def _load_cache(self) -> Dict[str, Any]:
        if not self.cache_file.exists():
            return self._default_cache()

        try:
            with open(self.cache_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, dict):
                    return {**self._default_cache(), **data}
        except Exception:
            return self._default_cache()

        return self._default_cache()

    def _save_cache(self, data: Dict[str, Any]) -> None:
        with open(self.cache_file, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    def _is_fresh(self, iso_timestamp: Optional[str]) -> bool:
        if not iso_timestamp:
            return False
        try:
            ts = datetime.fromisoformat(iso_timestamp)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return self._utcnow() - ts <= timedelta(hours=self.cache_ttl_hours)
        except Exception:
            return False

    async def _fetch_json(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        if self.offline:
            return None
        timeout = httpx.Timeout(self.timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url, params=params, headers=headers)
            if response.status_code != 200:
                return None
            return response.json()

    async def search_nvd(
        self,
        keyword: str,
        max_results: int = 20,
        force_refresh: bool = False,
    ) -> List[Dict[str, Any]]:
        """Query NVD for CVE candidates by keyword (technology name)."""
        key = keyword.strip().lower()
        if not key:
            return []

        cache = self._load_cache()
        cached_query = cache.get("nvd_queries", {}).get(key, {})
        if not force_refresh and self._is_fresh(cached_query.get("updated_at")):
            return cached_query.get("items", [])

        headers: Dict[str, str] = {}
        api_key = os.getenv("NVD_API_KEY", "").strip()
        if api_key:
            headers["apiKey"] = api_key

        payload = await self._fetch_json(
            self.NVD_URL,
            params={"keywordSearch": key, "resultsPerPage": str(max_results)},
            headers=headers or None,
        )
        if not payload:
            return cached_query.get("items", [])

        vulns = payload.get("vulnerabilities", []) or []
        items: List[Dict[str, Any]] = []

        for entry in vulns:
            cve = entry.get("cve", {}) or {}
            cve_id = cve.get("id")
            if not cve_id:
                continue

            descriptions = cve.get("descriptions", []) or []
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            metrics = cve.get("metrics", {}) or {}
            cvss_score = None
            for metric_key in (
                "cvssMetricV31",
                "cvssMetricV30",
                "cvssMetricV2",
            ):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    metric = metric_list[0] or {}
                    cvss_data = metric.get("cvssData", {}) or {}
                    cvss_score = cvss_data.get("baseScore")
                    if cvss_score is not None:
                        break

            refs = [
                ref.get("url")
                for ref in (cve.get("references", []) or [])
                if ref.get("url")
            ]

            items.append(
                {
                    "cve_id": cve_id,
                    "description": description,
                    "cvss": cvss_score,
                    "published": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                    "references": refs[:5],
                }
            )

        cache.setdefault("nvd_queries", {})[key] = {
            "updated_at": self._utcnow().isoformat(),
            "items": items,
        }
        cache["updated_at"] = self._utcnow().isoformat()
        self._save_cache(cache)
        return items

    async def get_kev_cves(self, force_refresh: bool = False) -> set[str]:
        """Fetch known exploited CVEs from CISA KEV catalog."""
        cache = self._load_cache()
        kev_data = cache.get("kev", {}) or {}
        if not force_refresh and self._is_fresh(kev_data.get("updated_at")):
            return set(kev_data.get("cves", []))

        payload = await self._fetch_json(self.CISA_KEV_URL)
        if not payload:
            return set(kev_data.get("cves", []))

        vulnerabilities = payload.get("vulnerabilities", []) or []
        kev_set = {
            item.get("cveID")
            for item in vulnerabilities
            if isinstance(item, dict) and item.get("cveID")
        }

        cache["kev"] = {
            "updated_at": self._utcnow().isoformat(),
            "cves": sorted(kev_set),
        }
        cache["updated_at"] = self._utcnow().isoformat()
        self._save_cache(cache)
        return kev_set

    async def get_epss_scores(self, cve_ids: List[str]) -> Dict[str, Dict[str, float]]:
        """Fetch EPSS enrichment for CVE IDs."""
        if not cve_ids:
            return {}

        unique_ids = sorted({cve for cve in cve_ids if cve})
        chunk_size = 75
        scores: Dict[str, Dict[str, float]] = {}

        for start in range(0, len(unique_ids), chunk_size):
            chunk = unique_ids[start:start + chunk_size]
            payload = await self._fetch_json(self.EPSS_URL, params={"cve": ",".join(chunk)})
            if not payload:
                continue

            for item in payload.get("data", []) or []:
                cve = item.get("cve")
                if not cve:
                    continue
                try:
                    epss = float(item.get("epss", 0.0))
                except (TypeError, ValueError):
                    epss = 0.0
                try:
                    percentile = float(item.get("percentile", 0.0))
                except (TypeError, ValueError):
                    percentile = 0.0
                scores[cve] = {"epss": epss, "percentile": percentile}

        return scores

    async def warm_cache(
        self,
        technologies: List[str],
        max_results_per_tech: int = 20,
    ) -> Dict[str, Any]:
        """Force-refresh KEV and NVD cache for supplied technologies."""
        original_offline = self.offline
        self.offline = False
        try:
            kev = await self.get_kev_cves(force_refresh=True)
            nvd_count = 0
            cve_ids: List[str] = []

            for tech in sorted({(t or "").strip().lower() for t in technologies if t}):
                items = await self.search_nvd(
                    tech,
                    max_results=max_results_per_tech,
                    force_refresh=True,
                )
                nvd_count += len(items)
                cve_ids.extend([item.get("cve_id", "") for item in items if item.get("cve_id")])

            epss = await self.get_epss_scores(cve_ids)
            return {
                "technologies": len(sorted({t for t in technologies if t})),
                "nvd_items": nvd_count,
                "unique_cves": len(sorted({c for c in cve_ids if c})),
                "kev_items": len(kev),
                "epss_enriched": len(epss),
                "updated_at": self._utcnow().isoformat(),
            }
        finally:
            self.offline = original_offline

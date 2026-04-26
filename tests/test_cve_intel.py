import asyncio
import json
from datetime import datetime, timezone

from core.cve_intel import CVEIntelClient
from core.scanner import ScanEngine
from config.settings import VulnerabilityConfig


def test_cve_intel_search_nvd_offline_uses_fresh_cache(tmp_path):
    cache_file = tmp_path / "cve_cache.json"
    now = datetime.now(timezone.utc).isoformat()
    cache_file.write_text(
        json.dumps(
            {
                "updated_at": now,
                "nvd_queries": {
                    "nginx": {
                        "updated_at": now,
                        "items": [{"cve_id": "CVE-2024-1000", "cvss": 7.5}],
                    }
                },
                "kev": {"updated_at": now, "cves": []},
            }
        ),
        encoding="utf-8",
    )

    client = CVEIntelClient(cache_file=str(cache_file), offline=True)
    result = asyncio.run(client.search_nvd("nginx"))

    assert len(result) == 1
    assert result[0]["cve_id"] == "CVE-2024-1000"


def test_cve_intel_get_kev_offline_uses_fresh_cache(tmp_path):
    cache_file = tmp_path / "cve_cache.json"
    now = datetime.now(timezone.utc).isoformat()
    cache_file.write_text(
        json.dumps(
            {
                "updated_at": now,
                "nvd_queries": {},
                "kev": {"updated_at": now, "cves": ["CVE-2024-2222", "CVE-2024-3333"]},
            }
        ),
        encoding="utf-8",
    )

    client = CVEIntelClient(cache_file=str(cache_file), offline=True)
    kev = asyncio.run(client.get_kev_cves())

    assert "CVE-2024-2222" in kev
    assert "CVE-2024-3333" in kev


def test_cve_intel_warm_cache_restores_original_offline_state():
    client = CVEIntelClient(offline=True)

    async def fake_get_kev_cves(force_refresh=False):
        assert force_refresh is True
        return {"CVE-2024-9999"}

    async def fake_search_nvd(keyword, max_results=20, force_refresh=False):
        assert force_refresh is True
        return [{"cve_id": "CVE-2024-9999"}]

    async def fake_get_epss_scores(cve_ids):
        assert "CVE-2024-9999" in cve_ids
        return {"CVE-2024-9999": {"epss": 0.8, "percentile": 0.9}}

    client.get_kev_cves = fake_get_kev_cves
    client.search_nvd = fake_search_nvd
    client.get_epss_scores = fake_get_epss_scores

    summary = asyncio.run(client.warm_cache(["nginx", "nginx", "react"]))

    assert summary["technologies"] == 2
    assert summary["nvd_items"] == 2
    assert summary["unique_cves"] == 1
    assert summary["kev_items"] == 1
    assert summary["epss_enriched"] == 1
    assert client.offline is True


def test_scan_engine_applies_cve_offline_from_config():
    scanner = ScanEngine(
        vuln_config=VulnerabilityConfig(
            enable_sqli=False,
            enable_xss=False,
            enable_headers=False,
            cve_intel_offline=True,
        )
    )
    assert scanner.cve_detector.intel_client.offline is True


"""NVD CVE 2.0 API ingester.

Docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limit: 5 req / 30s without key, 50 req / 30s with key.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Iterable

from ..config import settings
from ..http import get_json, make_client
from ..logging import get_logger
from .base import Ingester, NormalizedAdvisory

log = get_logger("ingest.nvd")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    # NVD returns "2024-01-12T15:00:00.000"
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _severity_from_metrics(metrics: dict) -> tuple[str | None, float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key, []) or []:
            data = entry.get("cvssData", {})
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or entry.get("baseSeverity")
            vec = data.get("vectorString")
            if score is not None:
                return (sev.upper() if sev else None), float(score), vec
    return None, None, None


def _normalize(item: dict) -> NormalizedAdvisory:
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    descriptions = cve.get("descriptions", []) or []
    summary = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
    metrics = cve.get("metrics", {}) or {}
    sev, score, vec = _severity_from_metrics(metrics)

    references = []
    for r in cve.get("references", []) or []:
        url = r.get("url")
        if not url:
            continue
        tags = r.get("tags") or []
        kind = None
        if "Patch" in tags:
            kind = "PATCH"
        elif "Exploit" in tags:
            kind = "EXPLOIT"
        elif "Vendor Advisory" in tags or "Third Party Advisory" in tags:
            kind = "ADVISORY"
        references.append({"url": url, "kind": kind})

    # NVD configurations are CPE-based — useful for matching at the OS/vendor layer
    # but for ecosystem packages we rely on GHSA/OSV. We still capture nothing
    # here for affected ranges; the matcher will use OSV/GHSA data.
    return NormalizedAdvisory(
        cve_id=cve_id,
        source_slug="nvd",
        title=cve_id or "CVE",
        summary=summary,
        severity=sev,
        cvss_score=score,
        cvss_vector=vec,
        published_at=_parse_dt(cve.get("published")),
        modified_at=_parse_dt(cve.get("lastModified")),
        references=references,
        raw=item,
    )


class NVDIngester(Ingester):
    slug = "nvd"
    name = "NIST NVD CVEs"

    PAGE_SIZE = 200  # NVD allows up to 2000 but small pages are kinder

    def fetch(self, since: datetime) -> Iterable[NormalizedAdvisory]:
        headers = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
            sleep_s = 0.6  # 50 req / 30s
        else:
            sleep_s = 6.5  # 5 req / 30s — be cautious

        # NVD wants ISO without microseconds
        last_mod_start = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        last_mod_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

        with make_client(headers) as client:
            start_index = 0
            total_results = None
            while True:
                params = {
                    "lastModStartDate": last_mod_start,
                    "lastModEndDate": last_mod_end,
                    "resultsPerPage": self.PAGE_SIZE,
                    "startIndex": start_index,
                }
                payload = get_json(client, NVD_URL, params=params)
                total_results = payload.get("totalResults", 0)
                vulns = payload.get("vulnerabilities", []) or []
                log.info(
                    "nvd_page",
                    start=start_index,
                    got=len(vulns),
                    total=total_results,
                )
                for v in vulns:
                    yield _normalize(v)
                start_index += len(vulns)
                if not vulns or start_index >= total_results:
                    break
                time.sleep(sleep_s)

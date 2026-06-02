"""CISA Known Exploited Vulnerabilities ingester.

Single JSON file, refreshed daily.
Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from ..http import get_json, make_client
from ..logging import get_logger
from .base import Ingester, NormalizedAdvisory

log = get_logger("ingest.kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_date(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class KEVIngester(Ingester):
    slug = "kev"
    name = "CISA Known Exploited Vulnerabilities"

    only_updates_existing = True  # KEV decorates existing advisories — see runner

    def fetch(self, since: datetime) -> Iterable[NormalizedAdvisory]:
        with make_client() as client:
            payload = get_json(client, KEV_URL)
        items = payload.get("vulnerabilities", []) or []
        log.info("kev_loaded", count=len(items))
        for it in items:
            cve = it.get("cveID")
            if not cve:
                continue
            added = _parse_date(it.get("dateAdded"))
            yield NormalizedAdvisory(
                cve_id=cve,
                source_slug="kev",
                title=it.get("vulnerabilityName") or cve,
                summary=it.get("shortDescription"),
                kev=True,
                kev_added_at=added,
                modified_at=added,
                raw=it,
            )

"""FIRST EPSS ingester — exploit prediction score.

Docs: https://www.first.org/epss/api
We pull the daily CSV: small, paginated, same shape every day.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from ..http import get_json, make_client
from ..logging import get_logger
from .base import Ingester, NormalizedAdvisory

log = get_logger("ingest.epss")

EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_API_URL = "https://api.first.org/data/v1/epss"


class EPSSIngester(Ingester):
    slug = "epss"
    name = "FIRST EPSS"

    only_updates_existing = True

    def fetch(self, since: datetime) -> Iterable[NormalizedAdvisory]:
        # The API is friendlier than the gz CSV when we only want a slice.
        # We fetch the top N most-recent-percentile entries — these are the ones
        # we most want fresh in our DB for the brief.
        with make_client() as client:
            offset = 0
            limit = 500
            now = datetime.now(timezone.utc)
            while True:
                payload = get_json(
                    client,
                    EPSS_API_URL,
                    params={"order": "!epss", "offset": offset, "limit": limit},
                )
                rows = payload.get("data", []) or []
                if not rows:
                    break
                for row in rows:
                    cve = row.get("cve")
                    if not cve:
                        continue
                    try:
                        score = float(row.get("epss"))
                        pct = float(row.get("percentile"))
                    except (TypeError, ValueError):
                        continue
                    yield NormalizedAdvisory(
                        cve_id=cve,
                        source_slug="epss",
                        title=cve,
                        epss_score=score,
                        epss_percentile=pct,
                        epss_updated_at=now,
                        raw=row,
                    )
                offset += limit
                if offset >= 5000:  # cap — we only need top 5k for a brief
                    break

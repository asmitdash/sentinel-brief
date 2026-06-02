"""GitHub Security Advisory ingester — REST.

Docs: https://docs.github.com/en/rest/security-advisories/global-advisories

Auth: optional `GITHUB_TOKEN` raises rate limit 60/hr -> 5000/hr.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from ..config import settings
from ..http import get_json, make_client
from ..logging import get_logger
from .base import Ingester, NormalizedAdvisory

log = get_logger("ingest.ghsa")

GHSA_URL = "https://api.github.com/advisories"


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _ecosystem_to_osv(eco: str | None) -> str | None:
    if not eco:
        return None
    mapping = {
        "pip": "PyPI", "npm": "npm", "rubygems": "RubyGems", "maven": "Maven",
        "nuget": "NuGet", "composer": "Packagist", "rust": "crates.io",
        "go": "Go", "actions": "GitHub Actions", "pub": "Pub", "swift": "SwiftURL",
        "erlang": "Hex",
    }
    return mapping.get(eco.lower(), eco)


def _normalize(adv: dict) -> NormalizedAdvisory:
    severity = (adv.get("severity") or "").upper() or None
    cvss = adv.get("cvss") or {}
    score = cvss.get("score")
    vec = cvss.get("vector_string")

    affected = []
    for v in adv.get("vulnerabilities", []) or []:
        pkg = v.get("package") or {}
        eco = _ecosystem_to_osv(pkg.get("ecosystem"))
        name = pkg.get("name")
        if not (eco and name):
            continue
        fp = v.get("first_patched_version")
        if isinstance(fp, dict):
            first_patched = fp.get("identifier")
        elif isinstance(fp, str):
            first_patched = fp
        else:
            first_patched = None
        affected.append(
            dict(
                ecosystem=eco,
                package_name=name,
                purl=None,
                introduced=None,
                fixed=first_patched,
                last_affected=None,
                range_event_kind="ECOSYSTEM",
            )
        )

    references = [{"url": u, "kind": None} for u in (adv.get("references") or []) if u]
    cve_id = adv.get("cve_id")
    ghsa_id = adv.get("ghsa_id")

    return NormalizedAdvisory(
        cve_id=cve_id,
        ghsa_id=ghsa_id,
        source_slug="ghsa",
        title=adv.get("summary") or ghsa_id or cve_id or "GHSA",
        summary=adv.get("description"),
        severity=severity,
        cvss_score=score,
        cvss_vector=vec,
        published_at=_parse_dt(adv.get("published_at")),
        modified_at=_parse_dt(adv.get("updated_at")),
        affected=affected,
        references=references,
        raw=adv,
    )


class GHSAIngester(Ingester):
    slug = "ghsa"
    name = "GitHub Security Advisories"

    PER_PAGE = 100

    def fetch(self, since: datetime) -> Iterable[NormalizedAdvisory]:
        headers = {"Accept": "application/vnd.github+json"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
        with make_client(headers) as client:
            page = 1
            while True:
                params = {
                    "type": "reviewed",
                    "sort": "updated",
                    "direction": "desc",
                    "per_page": self.PER_PAGE,
                    "page": page,
                    "modified": f">={since.strftime('%Y-%m-%d')}",
                }
                items = get_json(client, GHSA_URL, params=params)
                log.info("ghsa_page", page=page, got=len(items))
                if not items:
                    break
                cutoff_hit = False
                for it in items:
                    mod = _parse_dt(it.get("updated_at"))
                    if mod and mod < since:
                        cutoff_hit = True
                        continue
                    yield _normalize(it)
                if cutoff_hit or len(items) < self.PER_PAGE:
                    break
                page += 1
                if page > 50:  # hard safety
                    break

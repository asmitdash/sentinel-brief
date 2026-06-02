from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from ..db import session_scope
from ..logging import get_logger
from ..models import IngestRun, Source
from .base import Ingester, attach_kev_or_epss, since_default, upsert_advisories
from .epss import EPSSIngester
from .ghsa import GHSAIngester
from .kev import KEVIngester
from .nvd import NVDIngester
from .osv import OSVIngester

log = get_logger("ingest.runner")

REGISTRY: dict[str, Ingester] = {
    "nvd": NVDIngester(),
    "ghsa": GHSAIngester(),
    "osv": OSVIngester(),
    "kev": KEVIngester(),
    "epss": EPSSIngester(),
}

# Default order: primary advisories first, then decorators
DEFAULT_ORDER = ["ghsa", "osv", "nvd", "kev", "epss"]


def seed_sources() -> None:
    rows = [
        ("nvd", "NIST NVD", "nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
        ("ghsa", "GitHub Security Advisories", "ghsa", "https://api.github.com/advisories"),
        ("osv", "OSV.dev", "osv", "https://api.osv.dev"),
        ("kev", "CISA KEV", "kev", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
        ("epss", "FIRST EPSS", "epss", "https://api.first.org/data/v1/epss"),
    ]
    with session_scope() as session:
        existing_slugs = {
            s for s, in session.execute(select(Source.slug)).all()
        }
        added = 0
        for slug, name, kind, url in rows:
            if slug in existing_slugs:
                continue
            session.add(Source(slug=slug, name=name, kind=kind, url=url))
            added += 1
        log.info("sources_seeded", added=added)


def run_one(slug: str, since: datetime | None = None) -> dict:
    ing = REGISTRY.get(slug)
    if ing is None:
        raise ValueError(f"unknown source: {slug}")
    since = since or since_default()
    started = datetime.now(timezone.utc)
    seen = upserted = 0
    error = None
    try:
        items = list(ing.fetch(since))
        with session_scope() as session:
            if getattr(ing, "only_updates_existing", False):
                seen, upserted = attach_kev_or_epss(session, items)
            else:
                seen, upserted = upsert_advisories(session, items)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        log.error("ingest_failed", slug=slug, error=error)

    finished = datetime.now(timezone.utc)
    with session_scope() as session:
        session.add(
            IngestRun(
                source_slug=slug,
                started_at=started,
                finished_at=finished,
                status="error" if error else "ok",
                items_seen=seen,
                items_upserted=upserted,
                error=error,
            )
        )
    log.info("ingest_done", slug=slug, seen=seen, upserted=upserted, error=error)
    return {"slug": slug, "seen": seen, "upserted": upserted, "error": error}


def run_all(since: datetime | None = None) -> list[dict]:
    return [run_one(slug, since=since) for slug in DEFAULT_ORDER]

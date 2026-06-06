from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..logging import get_logger
from ..models import Advisory, AffectedRange, Reference

log = get_logger("ingest")


@dataclass
class NormalizedAdvisory:
    cve_id: str | None = None
    ghsa_id: str | None = None
    osv_id: str | None = None
    source_slug: str = ""
    title: str = ""
    summary: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    kev: bool = False
    kev_added_at: datetime | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_updated_at: datetime | None = None
    affected: list[dict] = field(default_factory=list)  # {ecosystem, package_name, purl, introduced, fixed, last_affected}
    references: list[dict] = field(default_factory=list)  # {url, kind}
    raw: dict | None = None


def _find_existing(session: Session, n: NormalizedAdvisory) -> Advisory | None:
    """Match by external IDs in priority order."""
    if n.cve_id:
        adv = session.execute(select(Advisory).where(Advisory.cve_id == n.cve_id)).scalar_one_or_none()
        if adv:
            return adv
    if n.ghsa_id:
        adv = session.execute(select(Advisory).where(Advisory.ghsa_id == n.ghsa_id)).scalar_one_or_none()
        if adv:
            return adv
    if n.osv_id:
        adv = session.execute(select(Advisory).where(Advisory.osv_id == n.osv_id)).scalar_one_or_none()
        if adv:
            return adv
    return None


def upsert_advisories(session: Session, items: Iterable[NormalizedAdvisory]) -> tuple[int, int]:
    seen = 0
    upserted = 0
    for n in items:
        seen += 1
        existing = _find_existing(session, n)
        if existing:
            # Update fields if newer or if missing
            new_mod = _aware(n.modified_at)
            old_mod = _aware(existing.modified_at)
            if new_mod and (not old_mod or new_mod > old_mod):
                existing.title = n.title or existing.title
                existing.summary = n.summary or existing.summary
                existing.severity = n.severity or existing.severity
                existing.cvss_score = n.cvss_score or existing.cvss_score
                existing.cvss_vector = n.cvss_vector or existing.cvss_vector
                existing.modified_at = n.modified_at
            # Always merge identifiers + KEV/EPSS upgrades
            existing.cve_id = existing.cve_id or n.cve_id
            existing.ghsa_id = existing.ghsa_id or n.ghsa_id
            existing.osv_id = existing.osv_id or n.osv_id
            if n.kev and not existing.kev:
                existing.kev = True
                existing.kev_added_at = n.kev_added_at or existing.kev_added_at
            if n.epss_score is not None:
                existing.epss_score = n.epss_score
                existing.epss_percentile = n.epss_percentile
                existing.epss_updated_at = n.epss_updated_at
            # Merge references
            if n.references:
                have = {r.url for r in existing.references}
                for ref in n.references:
                    if ref["url"] not in have:
                        existing.references.append(Reference(url=ref["url"], kind=ref.get("kind")))
            # Merge affected ranges (replace if source_slug matches — simpler than diff)
            if n.affected and n.source_slug == existing.source_slug:
                existing.affected_ranges.clear()
                for af in n.affected:
                    existing.affected_ranges.append(AffectedRange(**af))
            upserted += 1
            continue

        adv = Advisory(
            cve_id=n.cve_id,
            ghsa_id=n.ghsa_id,
            osv_id=n.osv_id,
            source_slug=n.source_slug,
            title=n.title,
            summary=n.summary,
            severity=n.severity,
            cvss_score=n.cvss_score,
            cvss_vector=n.cvss_vector,
            published_at=n.published_at,
            modified_at=n.modified_at,
            kev=n.kev,
            kev_added_at=n.kev_added_at,
            epss_score=n.epss_score,
            epss_percentile=n.epss_percentile,
            epss_updated_at=n.epss_updated_at,
            raw_json=json.dumps(n.raw) if n.raw else None,
        )
        for af in n.affected:
            adv.affected_ranges.append(AffectedRange(**af))
        for ref in n.references:
            adv.references.append(Reference(url=ref["url"], kind=ref.get("kind")))
        session.add(adv)
        upserted += 1
    return seen, upserted


def attach_kev_or_epss(session: Session, items: Iterable[NormalizedAdvisory]) -> tuple[int, int]:
    """For sources that only update KEV/EPSS fields on existing advisories.

    Skips items that don't match an existing advisory — those will be picked up
    on the next run after the primary source ingests them.
    """
    seen = 0
    upserted = 0
    for n in items:
        seen += 1
        existing = _find_existing(session, n)
        if not existing:
            continue
        if n.kev and not existing.kev:
            existing.kev = True
            existing.kev_added_at = n.kev_added_at
        if n.epss_score is not None:
            existing.epss_score = n.epss_score
            existing.epss_percentile = n.epss_percentile
            existing.epss_updated_at = n.epss_updated_at
        upserted += 1
    return seen, upserted


class Ingester(ABC):
    slug: str = ""
    name: str = ""

    @abstractmethod
    def fetch(self, since: datetime) -> Iterable[NormalizedAdvisory]:
        ...


def since_default(days: int = 7) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)

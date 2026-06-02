"""Match Watchlist components against ingested advisories.

Two match levels:
  1. exact PURL (component.purl == affected_range.purl) — strongest
  2. ecosystem + package_name match, with optional version-in-range check
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..logging import get_logger
from ..models import (
    Advisory,
    AffectedRange,
    Component,
    Finding,
    Watchlist,
    WatchlistComponent,
)
from .scoring import score_finding
from .version import in_range

log = get_logger("match")


@dataclass
class MatchResult:
    finding_id: int
    component_id: int
    advisory_id: int
    matched_via: str
    score: float


def _resolve_components(session: Session, watchlist_slug: str) -> list[Component]:
    wl = session.execute(
        select(Watchlist).where(Watchlist.slug == watchlist_slug)
    ).scalar_one_or_none()
    if not wl:
        return []
    rows = session.execute(
        select(Component)
        .join(WatchlistComponent, WatchlistComponent.component_id == Component.id)
        .where(WatchlistComponent.watchlist_id == wl.id)
    ).scalars().all()
    return list(rows)


def _candidate_ranges(
    session: Session, component: Component
) -> Iterable[tuple[AffectedRange, Advisory]]:
    stmt = (
        select(AffectedRange, Advisory)
        .join(Advisory, Advisory.id == AffectedRange.advisory_id)
        .where(
            AffectedRange.ecosystem == component.ecosystem,
            AffectedRange.package_name == component.name,
        )
    )
    return session.execute(stmt).all()


def match_watchlist(session: Session, watchlist_slug: str) -> list[MatchResult]:
    components = _resolve_components(session, watchlist_slug)
    log.info("match_start", watchlist=watchlist_slug, components=len(components))
    results: list[MatchResult] = []
    for comp in components:
        for af, adv in _candidate_ranges(session, comp):
            matched_via = None
            if af.purl and comp.purl == af.purl:
                matched_via = "purl_exact"
            elif comp.version and in_range(comp.version, af.introduced, af.fixed, af.last_affected):
                matched_via = "version_in_range"
            else:
                # Name+ecosystem match without resolvable version — flag as
                # potential, scored lower
                if comp.version is None:
                    matched_via = "name_eco"
                else:
                    continue
            score, components_breakdown = score_finding(adv, matched_via)
            existing = session.execute(
                select(Finding).where(
                    Finding.component_id == comp.id, Finding.advisory_id == adv.id
                )
            ).scalar_one_or_none()
            if existing:
                existing.matched_via = matched_via
                existing.score = score
                existing.score_components = json.dumps(components_breakdown)
                results.append(
                    MatchResult(existing.id, comp.id, adv.id, matched_via, score)
                )
                continue
            f = Finding(
                component_id=comp.id,
                advisory_id=adv.id,
                matched_via=matched_via,
                score=score,
                score_components=json.dumps(components_breakdown),
            )
            session.add(f)
            session.flush()
            results.append(MatchResult(f.id, comp.id, adv.id, matched_via, score))
    log.info("match_done", watchlist=watchlist_slug, findings=len(results))
    return results

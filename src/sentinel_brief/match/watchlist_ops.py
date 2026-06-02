from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..logging import get_logger
from ..models import Component, Watchlist, WatchlistComponent
from .sbom import SBOMComponent

log = get_logger("match.watchlist")


def upsert_components(
    session: Session, items: list[SBOMComponent]
) -> list[Component]:
    out: list[Component] = []
    for it in items:
        existing = session.execute(
            select(Component).where(Component.purl == it.purl)
        ).scalar_one_or_none()
        if existing:
            out.append(existing)
            continue
        c = Component(
            ecosystem=it.ecosystem,
            name=it.name,
            version=it.version,
            purl=it.purl,
        )
        session.add(c)
        session.flush()
        out.append(c)
    return out


def register_watchlist(
    session: Session, slug: str, name: str, items: list[SBOMComponent]
) -> Watchlist:
    wl = session.execute(
        select(Watchlist).where(Watchlist.slug == slug)
    ).scalar_one_or_none()
    if not wl:
        wl = Watchlist(slug=slug, name=name)
        session.add(wl)
        session.flush()
    components = upsert_components(session, items)
    existing_links = {
        wc.component_id
        for wc in session.execute(
            select(WatchlistComponent).where(WatchlistComponent.watchlist_id == wl.id)
        ).scalars()
    }
    added = 0
    for c in components:
        if c.id in existing_links:
            continue
        session.add(WatchlistComponent(watchlist_id=wl.id, component_id=c.id))
        added += 1
    log.info(
        "watchlist_registered",
        slug=slug,
        components=len(components),
        new_links=added,
    )
    return wl

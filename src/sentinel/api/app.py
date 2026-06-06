from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..brief import generate_brief
from ..db import init_db, session_scope
from ..ingest.runner import run_all, run_one
from ..logging import configure_logging, get_logger
from ..match.matcher import match_watchlist
from ..match.sbom import parse_sbom
from ..match.watchlist_ops import register_watchlist
from ..models import (
    Advisory,
    Brief,
    Component,
    Finding,
    IngestRun,
    Watchlist,
    WatchlistComponent,
)
from .schemas import (
    BriefOut,
    BriefSummary,
    ComponentOut,
    FeedbackIn,
    FindingOut,
    IngestRunOut,
    ReferenceOut,
    WatchlistOut,
)

configure_logging()
log = get_logger("api")

app = FastAPI(title="Sentinel", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_db()


def _db() -> Session:
    with session_scope() as session:
        yield session


@app.get("/health")
def health() -> dict:
    return {"ok": True}


# ---------- Watchlists ----------

@app.get("/watchlists", response_model=list[WatchlistOut])
def list_watchlists(session: Session = Depends(_db)) -> list[WatchlistOut]:
    rows = session.execute(
        select(
            Watchlist,
            func.count(WatchlistComponent.id).label("c"),
        )
        .outerjoin(WatchlistComponent, WatchlistComponent.watchlist_id == Watchlist.id)
        .group_by(Watchlist.id)
    ).all()
    return [
        WatchlistOut(id=w.id, slug=w.slug, name=w.name, component_count=c)
        for (w, c) in rows
    ]


@app.post("/watchlists/upload", response_model=WatchlistOut)
async def upload_watchlist(
    slug: str = Form(...),
    name: str = Form(...),
    sbom: UploadFile = File(...),
    session: Session = Depends(_db),
) -> WatchlistOut:
    suffix = Path(sbom.filename or "sbom.txt").suffix or ".txt"
    contents = await sbom.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tf:
        tf.write(contents)
        tmp_path = tf.name
    try:
        items = parse_sbom(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    if not items:
        raise HTTPException(400, "no components parsed from SBOM")
    wl = register_watchlist(session, slug, name, items)
    return WatchlistOut(id=wl.id, slug=wl.slug, name=wl.name, component_count=len(items))


@app.get("/watchlists/{slug}/components", response_model=list[ComponentOut])
def list_components(slug: str, session: Session = Depends(_db)) -> list[ComponentOut]:
    wl = session.execute(select(Watchlist).where(Watchlist.slug == slug)).scalar_one_or_none()
    if not wl:
        raise HTTPException(404, "watchlist not found")
    rows = session.execute(
        select(Component)
        .join(WatchlistComponent, WatchlistComponent.component_id == Component.id)
        .where(WatchlistComponent.watchlist_id == wl.id)
    ).scalars().all()
    return [
        ComponentOut(id=c.id, ecosystem=c.ecosystem, name=c.name, version=c.version, purl=c.purl)
        for c in rows
    ]


# ---------- Match ----------

@app.post("/watchlists/{slug}/match")
def trigger_match(slug: str, session: Session = Depends(_db)) -> dict:
    results = match_watchlist(session, slug)
    return {"findings": len(results)}


@app.get("/watchlists/{slug}/findings", response_model=list[FindingOut])
def list_findings(slug: str, limit: int = 50, session: Session = Depends(_db)) -> list[FindingOut]:
    wl = session.execute(select(Watchlist).where(Watchlist.slug == slug)).scalar_one_or_none()
    if not wl:
        raise HTTPException(404, "watchlist not found")
    rows = session.execute(
        select(Finding, Component, Advisory)
        .join(Component, Component.id == Finding.component_id)
        .join(Advisory, Advisory.id == Finding.advisory_id)
        .join(WatchlistComponent, WatchlistComponent.component_id == Component.id)
        .where(WatchlistComponent.watchlist_id == wl.id)
        .order_by(Finding.score.desc())
        .limit(limit)
    ).all()
    out = []
    for f, c, a in rows:
        out.append(
            FindingOut(
                id=f.id,
                component=ComponentOut(
                    id=c.id, ecosystem=c.ecosystem, name=c.name, version=c.version, purl=c.purl
                ),
                advisory_id=a.id,
                cve_id=a.cve_id,
                ghsa_id=a.ghsa_id,
                title=a.title,
                severity=a.severity,
                cvss_score=a.cvss_score,
                kev=a.kev,
                epss_score=a.epss_score,
                score=f.score,
                matched_via=f.matched_via,
                score_breakdown=json.loads(f.score_components or "{}"),
                references=[ReferenceOut(url=r.url, kind=r.kind) for r in a.references],
            )
        )
    return out


# ---------- Briefs ----------

@app.post("/watchlists/{slug}/briefs/generate", response_model=BriefOut)
def generate(slug: str, top_n: int = 12, dry_run: bool = False) -> BriefOut:
    result = generate_brief(slug, top_n=top_n, dry_run=dry_run)
    with session_scope() as session:
        b = session.get(Brief, result.brief_id)
        return BriefOut(
            id=b.id,
            watchlist_id=b.watchlist_id,
            generated_at=b.generated_at,
            title=b.title,
            summary_markdown=b.summary_markdown,
            finding_ids=json.loads(b.finding_ids_json or "[]"),
            cited_urls=json.loads(b.cited_urls_json or "[]"),
            model_id=b.model_id,
            input_tokens=b.input_tokens,
            output_tokens=b.output_tokens,
            user_rating=b.user_rating,
        )


@app.get("/watchlists/{slug}/briefs", response_model=list[BriefSummary])
def list_briefs(slug: str, session: Session = Depends(_db)) -> list[BriefSummary]:
    wl = session.execute(select(Watchlist).where(Watchlist.slug == slug)).scalar_one_or_none()
    if not wl:
        raise HTTPException(404, "watchlist not found")
    rows = session.execute(
        select(Brief).where(Brief.watchlist_id == wl.id).order_by(Brief.generated_at.desc())
    ).scalars().all()
    return [
        BriefSummary(
            id=b.id,
            watchlist_id=b.watchlist_id,
            generated_at=b.generated_at,
            title=b.title,
            user_rating=b.user_rating,
        )
        for b in rows
    ]


@app.get("/briefs/{brief_id}", response_model=BriefOut)
def get_brief(brief_id: int, session: Session = Depends(_db)) -> BriefOut:
    b = session.get(Brief, brief_id)
    if not b:
        raise HTTPException(404, "brief not found")
    return BriefOut(
        id=b.id,
        watchlist_id=b.watchlist_id,
        generated_at=b.generated_at,
        title=b.title,
        summary_markdown=b.summary_markdown,
        finding_ids=json.loads(b.finding_ids_json or "[]"),
        cited_urls=json.loads(b.cited_urls_json or "[]"),
        model_id=b.model_id,
        input_tokens=b.input_tokens,
        output_tokens=b.output_tokens,
        user_rating=b.user_rating,
    )


# ---------- Feedback ----------

@app.post("/feedback")
def feedback(payload: FeedbackIn, session: Session = Depends(_db)) -> dict:
    if payload.finding_id is not None and payload.label:
        f = session.get(Finding, payload.finding_id)
        if not f:
            raise HTTPException(404, "finding not found")
        f.user_label = payload.label
    if payload.brief_id is not None and payload.rating is not None:
        b = session.get(Brief, payload.brief_id)
        if not b:
            raise HTTPException(404, "brief not found")
        b.user_rating = max(1, min(5, payload.rating))
    return {"ok": True}


# ---------- Ingest control ----------

@app.post("/ingest/run")
def trigger_ingest(source: str | None = None) -> dict:
    if source:
        return run_one(source)
    return {"runs": run_all()}


@app.get("/ingest/runs", response_model=list[IngestRunOut])
def list_ingest_runs(limit: int = 30, session: Session = Depends(_db)) -> list[IngestRunOut]:
    rows = session.execute(
        select(IngestRun).order_by(IngestRun.started_at.desc()).limit(limit)
    ).scalars().all()
    return [
        IngestRunOut(
            id=r.id,
            source_slug=r.source_slug,
            started_at=r.started_at,
            finished_at=r.finished_at,
            status=r.status,
            items_seen=r.items_seen,
            items_upserted=r.items_upserted,
            error=r.error,
        )
        for r in rows
    ]

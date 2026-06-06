from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class WatchlistOut(BaseModel):
    id: int
    slug: str
    name: str
    component_count: int


class WatchlistCreate(BaseModel):
    slug: str
    name: str


class ComponentOut(BaseModel):
    id: int
    ecosystem: str
    name: str
    version: str | None
    purl: str


class ReferenceOut(BaseModel):
    url: str
    kind: str | None


class FindingOut(BaseModel):
    id: int
    component: ComponentOut
    advisory_id: int
    cve_id: str | None
    ghsa_id: str | None
    title: str
    severity: str | None
    cvss_score: float | None
    kev: bool
    epss_score: float | None
    score: float
    matched_via: str
    score_breakdown: dict
    references: list[ReferenceOut]


class BriefOut(BaseModel):
    id: int
    watchlist_id: int
    generated_at: datetime
    title: str
    summary_markdown: str
    finding_ids: list[int]
    cited_urls: list[str]
    model_id: str
    input_tokens: int | None
    output_tokens: int | None
    user_rating: int | None


class BriefSummary(BaseModel):
    id: int
    watchlist_id: int
    generated_at: datetime
    title: str
    user_rating: int | None


class IngestRunOut(BaseModel):
    id: int
    source_slug: str
    started_at: datetime
    finished_at: datetime | None
    status: str
    items_seen: int
    items_upserted: int
    error: str | None


class FeedbackIn(BaseModel):
    finding_id: int | None = None
    brief_id: int | None = None
    label: str | None = None  # useful / not_useful
    rating: int | None = None  # 1-5

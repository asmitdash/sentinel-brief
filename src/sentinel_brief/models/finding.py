from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


class Finding(Base, TimestampMixin):
    """A specific (component, advisory) match with a computed score."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    component_id: Mapped[int] = mapped_column(ForeignKey("components.id"), index=True)
    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisories.id"), index=True)
    matched_via: Mapped[str] = mapped_column(String(32))  # purl_exact / name_eco / version_in_range
    score: Mapped[float] = mapped_column(Float, default=0.0)
    score_components: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON blob
    user_label: Mapped[str | None] = mapped_column(
        String(16), nullable=True
    )  # useful / not_useful / null

    __table_args__ = (
        UniqueConstraint("component_id", "advisory_id", name="uq_finding_component_advisory"),
    )


class Brief(Base, TimestampMixin):
    """One generated daily brief per (watchlist, date)."""

    __tablename__ = "briefs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    watchlist_id: Mapped[int] = mapped_column(ForeignKey("watchlists.id"), index=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    title: Mapped[str] = mapped_column(String(255))
    summary_markdown: Mapped[str] = mapped_column(Text)
    finding_ids_json: Mapped[str] = mapped_column(Text)  # JSON list of finding ids in priority order
    cited_urls_json: Mapped[str] = mapped_column(Text)  # JSON list of URLs cited
    model_id: Mapped[str] = mapped_column(String(128))
    input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_rating: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 1-5

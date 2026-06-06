from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


class Advisory(Base, TimestampMixin):
    """Normalized vulnerability advisory across sources."""

    __tablename__ = "advisories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # External identifiers — at least one will be present
    cve_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    ghsa_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    osv_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    # Where this row was sourced from primarily
    source_slug: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)  # CRITICAL/HIGH/MED/LOW
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # CISA Known-Exploited-Vulnerabilities flag
    kev: Mapped[bool] = mapped_column(default=False)
    kev_added_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # FIRST EPSS — probability of exploitation in the wild within 30d
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Raw normalized payload, kept for future re-extraction
    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    affected_ranges: Mapped[list["AffectedRange"]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )
    references: Mapped[list["Reference"]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_advisory_published", "published_at"),
        Index("ix_advisory_severity", "severity"),
    )


class AffectedRange(Base):
    """One affected ecosystem-component-version-range tuple per advisory."""

    __tablename__ = "affected_ranges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisories.id"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(32), index=True)  # PyPI / npm / Maven / ...
    package_name: Mapped[str] = mapped_column(String(255), index=True)
    purl: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    introduced: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fixed: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_affected: Mapped[str | None] = mapped_column(String(64), nullable=True)
    range_event_kind: Mapped[str] = mapped_column(String(16), default="SEMVER")  # SEMVER/ECOSYSTEM/GIT

    advisory: Mapped["Advisory"] = relationship(back_populates="affected_ranges")


class Reference(Base):
    __tablename__ = "advisory_references"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisories.id"), index=True)
    url: Mapped[str] = mapped_column(Text)
    kind: Mapped[str | None] = mapped_column(String(32), nullable=True)  # ADVISORY/PATCH/EXPLOIT/...

    advisory: Mapped["Advisory"] = relationship(back_populates="references")

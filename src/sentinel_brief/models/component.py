from __future__ import annotations

from sqlalchemy import Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin


class Component(Base, TimestampMixin):
    """A software component the user cares about — derived from an SBOM upload."""

    __tablename__ = "components"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    purl: Mapped[str] = mapped_column(String(512), unique=True, index=True)

    __table_args__ = (Index("ix_component_eco_name", "ecosystem", "name"),)

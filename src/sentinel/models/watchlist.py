from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


class Watchlist(Base, TimestampMixin):
    __tablename__ = "watchlists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    components: Mapped[list["WatchlistComponent"]] = relationship(
        back_populates="watchlist", cascade="all, delete-orphan"
    )


class WatchlistComponent(Base, TimestampMixin):
    __tablename__ = "watchlist_components"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    watchlist_id: Mapped[int] = mapped_column(ForeignKey("watchlists.id"), index=True)
    component_id: Mapped[int] = mapped_column(ForeignKey("components.id"), index=True)

    watchlist: Mapped["Watchlist"] = relationship(back_populates="components")

    __table_args__ = (UniqueConstraint("watchlist_id", "component_id", name="uq_wl_comp"),)

"""End-to-end test using a local SQLite DB and a fixture advisory.

No network. No Bedrock. Verifies: schema -> watchlist upload -> match -> dry-run brief.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinel_brief.brief import generate_brief
from sentinel_brief.match.matcher import match_watchlist
from sentinel_brief.match.sbom import parse_sbom
from sentinel_brief.match.watchlist_ops import register_watchlist
from sentinel_brief.models import Advisory, AffectedRange, Reference
from sentinel_brief.models.base import Base


def test_e2e_offline(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "sentinel.db"
    db_url = f"sqlite+pysqlite:///{db_path}"

    # Rebind the package's engine + session before any session_scope is opened
    import sentinel_brief.db as dbmod

    engine = create_engine(db_url, future=True)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    monkeypatch.setattr(dbmod, "_engine", engine)
    monkeypatch.setattr(dbmod, "_SessionLocal", SessionLocal)

    # Seed a known-affected advisory for django
    with dbmod.session_scope() as s:
        adv = Advisory(
            cve_id="CVE-TEST-0001",
            ghsa_id=None,
            osv_id=None,
            source_slug="ghsa",
            title="Django arbitrary thing",
            summary="A test advisory for django.",
            severity="HIGH",
            cvss_score=8.0,
            modified_at=datetime.now(timezone.utc),
        )
        adv.affected_ranges.append(
            AffectedRange(
                ecosystem="PyPI",
                package_name="django",
                introduced="3.0.0",
                fixed="3.2.5",
                range_event_kind="ECOSYSTEM",
            )
        )
        adv.references.append(
            Reference(url="https://example.com/CVE-TEST-0001", kind="ADVISORY")
        )
        s.add(adv)

    # Upload SBOM
    sbom = tmp_path / "requirements.txt"
    sbom.write_text("django==3.2.0\nflask==1.0.0\n")
    items = parse_sbom(sbom)
    with dbmod.session_scope() as s:
        register_watchlist(s, "test", "Test", items)

    # Match
    with dbmod.session_scope() as s:
        results = match_watchlist(s, "test")
    assert len(results) >= 1, "expected at least one finding for django==3.2.0"

    # Dry-run brief (no Bedrock call)
    result = generate_brief("test", dry_run=True)
    assert "DRY RUN" in result.markdown
    assert "django" in result.markdown.lower()
    assert any("example.com" in url for url in result.cited_urls)

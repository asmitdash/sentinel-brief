from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select

from ..config import settings
from ..db import session_scope
from ..logging import get_logger
from ..models import Advisory, Brief, Component, Finding, Watchlist, WatchlistComponent
from .bedrock import invoke_claude
from .prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE, render_finding

log = get_logger("brief.generator")


@dataclass
class BriefResult:
    brief_id: int
    title: str
    markdown: str
    cited_urls: list[str]
    finding_ids: list[int]
    input_tokens: int | None
    output_tokens: int | None


def _serialize_finding(finding: Finding, comp: Component, adv: Advisory) -> dict:
    return {
        "component_purl": comp.purl,
        "score": finding.score,
        "matched_via": finding.matched_via,
        "score_breakdown": json.loads(finding.score_components or "{}") or {
            "severity": 0, "match_quality": 0, "kev": 0, "epss": 0, "recency": 0
        },
        "title": adv.title,
        "ids": " / ".join(x for x in [adv.cve_id, adv.ghsa_id, adv.osv_id] if x),
        "severity": adv.severity,
        "cvss_score": adv.cvss_score,
        "kev": adv.kev,
        "epss_score": adv.epss_score,
        "summary": adv.summary or "",
        "affected": [
            {
                "ecosystem": a.ecosystem,
                "package_name": a.package_name,
                "introduced": a.introduced,
                "fixed": a.fixed,
                "last_affected": a.last_affected,
            }
            for a in adv.affected_ranges
        ],
        "references": [{"url": r.url, "kind": r.kind} for r in adv.references],
    }


def generate_brief(
    watchlist_slug: str,
    top_n: int = 12,
    dry_run: bool = False,
) -> BriefResult:
    """Generate today's brief. Returns the persisted Brief row's contents."""
    with session_scope() as session:
        wl = session.execute(
            select(Watchlist).where(Watchlist.slug == watchlist_slug)
        ).scalar_one_or_none()
        if not wl:
            raise ValueError(f"unknown watchlist: {watchlist_slug}")

        rows = session.execute(
            select(Finding, Component, Advisory)
            .join(Component, Component.id == Finding.component_id)
            .join(Advisory, Advisory.id == Finding.advisory_id)
            .join(WatchlistComponent, WatchlistComponent.component_id == Component.id)
            .where(WatchlistComponent.watchlist_id == wl.id)
            .order_by(Finding.score.desc())
        ).all()

        # Dedupe by (component_id, advisory_id) — DB is correct but the matcher
        # can produce one Finding row per affected_range per component.
        seen: set[tuple[int, int]] = set()
        unique = []
        for f, c, a in rows:
            key = (c.id, a.id)
            if key in seen:
                continue
            seen.add(key)
            unique.append((f, c, a))
            if len(unique) >= top_n:
                break

        findings_payload = [_serialize_finding(f, c, a) for f, c, a in unique]
        finding_ids = [f.id for f, _, _ in unique]
        cited_urls = sorted({
            r["url"]
            for fp in findings_payload
            for r in fp["references"]
        })

        if not findings_payload:
            markdown = (
                f"# Daily Brief — {datetime.now(timezone.utc).date()} — {wl.name}\n\n"
                "No findings matched the watchlist over the last 7 days. "
                "Either the ingesters haven't pulled enough data yet, or your stack is genuinely quiet today.\n"
            )
            input_tokens = output_tokens = None
            title = f"Daily Brief — {wl.name} — empty"
        else:
            findings_block = "\n".join(
                render_finding(i + 1, fp) for i, fp in enumerate(findings_payload)
            )
            user = USER_PROMPT_TEMPLATE.format(
                watchlist_name=wl.name,
                date=datetime.now(timezone.utc).date().isoformat(),
                findings_block=findings_block,
            )
            if dry_run:
                markdown = "# DRY RUN\n\n" + user
                input_tokens = output_tokens = None
            else:
                resp = invoke_claude(SYSTEM_PROMPT, user)
                markdown = resp.text
                input_tokens = resp.input_tokens
                output_tokens = resp.output_tokens
            first_line = markdown.splitlines()[0] if markdown else ""
            title = first_line.lstrip("# ").strip() or f"Daily Brief — {wl.name}"

        brief = Brief(
            watchlist_id=wl.id,
            generated_at=datetime.now(timezone.utc),
            title=title,
            summary_markdown=markdown,
            finding_ids_json=json.dumps(finding_ids),
            cited_urls_json=json.dumps(cited_urls),
            model_id=settings.bedrock_model_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        session.add(brief)
        session.flush()
        brief_id = brief.id

    log.info("brief_generated", brief_id=brief_id, findings=len(finding_ids))
    return BriefResult(
        brief_id=brief_id,
        title=title,
        markdown=markdown,
        cited_urls=cited_urls,
        finding_ids=finding_ids,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )

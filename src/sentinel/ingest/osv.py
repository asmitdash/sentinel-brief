"""OSV.dev ingester — ecosystem-aware affected-range data.

Docs: https://google.github.io/osv.dev/api/

Strategy: query OSV by ecosystem, paging through recent advisories.
We pull PyPI and npm by default — extend `ECOSYSTEMS` for more.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from ..http import get_json, make_client
from ..logging import get_logger
from .base import Ingester, NormalizedAdvisory

log = get_logger("ingest.osv")

OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
OSV_EXPORT = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"

ECOSYSTEMS = ["PyPI", "npm"]


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _severity(adv: dict) -> tuple[str | None, float | None, str | None]:
    sevs = adv.get("severity") or []
    for s in sevs:
        if s.get("type") == "CVSS_V3" and s.get("score"):
            vec = s["score"]
            score = None
            try:
                # OSV stores the CVSS vector string in 'score'; we don't have a
                # base-score parser here, leave numeric None.
                score = None
            except Exception:
                pass
            return None, score, vec
    db = adv.get("database_specific") or {}
    sev = db.get("severity")
    return (sev.upper() if isinstance(sev, str) else None), None, None


def _affected(adv: dict) -> list[dict]:
    out = []
    for a in adv.get("affected", []) or []:
        pkg = a.get("package") or {}
        ecosystem = pkg.get("ecosystem")
        name = pkg.get("name")
        purl = pkg.get("purl")
        if not (ecosystem and name):
            continue
        ranges = a.get("ranges", []) or []
        if not ranges:
            out.append(
                dict(
                    ecosystem=ecosystem,
                    package_name=name,
                    purl=purl,
                    introduced=None,
                    fixed=None,
                    last_affected=None,
                    range_event_kind="ECOSYSTEM",
                )
            )
            continue
        for rng in ranges:
            kind = rng.get("type", "ECOSYSTEM")
            introduced = None
            fixed = None
            last_affected = None
            for ev in rng.get("events", []) or []:
                if "introduced" in ev:
                    introduced = ev["introduced"]
                elif "fixed" in ev:
                    fixed = ev["fixed"]
                elif "last_affected" in ev:
                    last_affected = ev["last_affected"]
            out.append(
                dict(
                    ecosystem=ecosystem,
                    package_name=name,
                    purl=purl,
                    introduced=introduced,
                    fixed=fixed,
                    last_affected=last_affected,
                    range_event_kind=kind,
                )
            )
    return out


def _references(adv: dict) -> list[dict]:
    out = []
    for r in adv.get("references", []) or []:
        url = r.get("url")
        if not url:
            continue
        kind = (r.get("type") or "").upper() or None
        out.append({"url": url, "kind": kind})
    return out


def _normalize(adv: dict) -> NormalizedAdvisory:
    sev, score, vec = _severity(adv)
    aliases = adv.get("aliases", []) or []
    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
    ghsa_id = next((a for a in aliases if a.startswith("GHSA-")), None)
    return NormalizedAdvisory(
        cve_id=cve_id,
        ghsa_id=ghsa_id,
        osv_id=adv.get("id"),
        source_slug="osv",
        title=adv.get("summary") or adv.get("id") or "OSV",
        summary=adv.get("details"),
        severity=sev,
        cvss_score=score,
        cvss_vector=vec,
        published_at=_parse_dt(adv.get("published")),
        modified_at=_parse_dt(adv.get("modified")),
        affected=_affected(adv),
        references=_references(adv),
        raw=adv,
    )


class OSVIngester(Ingester):
    slug = "osv"
    name = "OSV.dev (PyPI + npm)"

    def fetch(self, since: datetime) -> Iterable[NormalizedAdvisory]:
        # OSV doesn't have a "recently modified" REST endpoint; the documented
        # path for recent data is the ecosystem-zip export. For Week-1 scope
        # we instead query OSV's batch API for a curated list of high-traffic
        # packages — produces a non-empty, useful slice without downloading
        # multi-GB exports. Extend by editing PROBE_PACKAGES.
        from .osv_probe import PROBE_PACKAGES

        with make_client() as client:
            seen_ids: set[str] = set()
            for batch_start in range(0, len(PROBE_PACKAGES), 100):
                batch = PROBE_PACKAGES[batch_start : batch_start + 100]
                queries = [
                    {"package": {"ecosystem": eco, "name": name}} for (eco, name) in batch
                ]
                resp = client.post(OSV_QUERY_URL, json={"queries": queries})
                resp.raise_for_status()
                results = resp.json().get("results", [])
                vuln_ids = []
                for r in results:
                    for v in r.get("vulns", []) or []:
                        vid = v.get("id")
                        if vid and vid not in seen_ids:
                            seen_ids.add(vid)
                            vuln_ids.append(vid)

                for vid in vuln_ids:
                    full = get_json(client, OSV_VULN_URL.format(vuln_id=vid))
                    mod = _parse_dt(full.get("modified"))
                    if mod and mod < since:
                        continue
                    yield _normalize(full)

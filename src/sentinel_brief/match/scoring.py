"""Finding score — explainable, additive components.

We deliberately keep this classical and transparent. Each component is a
0-1 contribution; total is sum, capped at 1. The `components` dict is what
the brief layer cites back when explaining why a finding ranked high.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import Advisory


SEVERITY_WEIGHTS = {
    "CRITICAL": 0.30,
    "HIGH": 0.22,
    "MEDIUM": 0.12,
    "LOW": 0.05,
}

MATCH_WEIGHTS = {
    "purl_exact": 0.20,
    "version_in_range": 0.15,
    "name_eco": 0.06,
}


def _recency_weight(adv: Advisory) -> float:
    """Newer modified_at -> higher weight, decays over 14 days."""
    if not adv.modified_at:
        return 0.0
    now = datetime.now(timezone.utc)
    modified = adv.modified_at
    if modified.tzinfo is None:
        # SQLite drops tzinfo on roundtrip; treat naive as UTC.
        modified = modified.replace(tzinfo=timezone.utc)
    age = (now - modified).total_seconds() / 86400.0
    if age <= 0:
        return 0.20
    if age >= 14:
        return 0.0
    return 0.20 * (1 - age / 14.0)


def score_finding(adv: Advisory, matched_via: str) -> tuple[float, dict]:
    breakdown: dict[str, float] = {}

    sev = SEVERITY_WEIGHTS.get((adv.severity or "").upper(), 0.0)
    breakdown["severity"] = round(sev, 4)

    match_w = MATCH_WEIGHTS.get(matched_via, 0.0)
    breakdown["match_quality"] = round(match_w, 4)

    if adv.kev:
        breakdown["kev"] = 0.20
    else:
        breakdown["kev"] = 0.0

    if adv.epss_score is not None:
        breakdown["epss"] = round(0.20 * float(adv.epss_score), 4)
    else:
        breakdown["epss"] = 0.0

    breakdown["recency"] = round(_recency_weight(adv), 4)

    total = min(1.0, sum(breakdown.values()))
    return total, breakdown

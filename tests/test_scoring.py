from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sentinel_brief.match.scoring import score_finding


def _adv(severity=None, kev=False, epss=None, modified_days_ago=1):
    return SimpleNamespace(
        severity=severity,
        kev=kev,
        epss_score=epss,
        modified_at=datetime.now(timezone.utc) - timedelta(days=modified_days_ago),
    )


def test_critical_kev_high_epss_purl_match_caps_at_one():
    adv = _adv(severity="CRITICAL", kev=True, epss=0.9, modified_days_ago=0)
    score, breakdown = score_finding(adv, "purl_exact")
    assert 0.9 < score <= 1.0
    assert breakdown["kev"] == 0.20
    assert breakdown["match_quality"] == 0.20


def test_loose_match_no_signal_low_score():
    adv = _adv(severity="LOW", kev=False, epss=None, modified_days_ago=20)
    score, breakdown = score_finding(adv, "name_eco")
    assert score < 0.2
    assert breakdown["recency"] == 0.0


def test_components_sum_equals_score_when_under_one():
    adv = _adv(severity="MEDIUM", kev=False, epss=0.1, modified_days_ago=7)
    score, breakdown = score_finding(adv, "version_in_range")
    assert abs(score - sum(breakdown.values())) < 1e-9

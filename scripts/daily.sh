#!/usr/bin/env bash
# Daily run — pulls last 24h, re-matches all watchlists, generates briefs.
set -euo pipefail
cd "$(dirname "$0")/.."

sentinel db init
sentinel sources seed
sentinel ingest run --since 1d

# For every watchlist, run match + brief
python - <<'PY'
from sqlalchemy import select
from sentinel_brief.db import session_scope
from sentinel_brief.models import Watchlist
from sentinel_brief.match.matcher import match_watchlist
from sentinel_brief.brief import generate_brief

with session_scope() as s:
    slugs = [w.slug for w in s.execute(select(Watchlist)).scalars()]
for slug in slugs:
    with session_scope() as s:
        match_watchlist(s, slug)
    generate_brief(slug)
    print(f"brief generated for {slug}")
PY

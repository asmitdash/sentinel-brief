# sentinel-brief

Daily cyber-threat OSINT brief over an SBOM.

Upload a `requirements.txt` / `package.json` / SBOM. Every morning, get a Claude-written analyst note on what new vulnerabilities, exploits, and chatter affect *your* dependencies — with citations back to NVD, GHSA, CISA KEV, OSV, and EPSS.

Personal-learning project. Free / OSS deps only. Single-machine deployable.

- **Repo:** https://github.com/asmitdash/sentinel-brief
- **Frontend (Vercel):** https://web-mu-drab-33.vercel.app
- **Backend:** runs locally — Vercel hosts the UI only; see [Deployment](#deployment).

## What works without an LLM API key

The pipeline up to the brief is fully classical. You can run everything below with **zero LLM calls**:

| Capability | Where |
| --- | --- |
| Pull NVD CVEs (last 7d / lastModStart window) | `sentinel ingest run --source nvd` |
| Pull GitHub Security Advisories (REST, paginated) | `sentinel ingest run --source ghsa` |
| Pull OSV.dev advisories for a curated PyPI/npm probe list | `sentinel ingest run --source osv` |
| Pull CISA KEV catalog (decorates existing advisories with `kev=true`) | `sentinel ingest run --source kev` |
| Pull FIRST EPSS top-N exploitation-probability scores | `sentinel ingest run --source epss` |
| Parse `requirements.txt` / `package.json` / CycloneDX into PURLs | `parse_sbom()` |
| Register a watchlist + upsert components | `sentinel watchlist upload …` |
| Match watchlist components against advisories (PURL-exact / version-in-range / name+ecosystem) | `sentinel match run` |
| Score every finding with an explainable additive breakdown (severity + match quality + KEV + EPSS + recency) | `score_finding()` |
| Browse top-N findings ranked by score, drill into citations | `/watchlists/{slug}/findings` API + Next.js UI |
| Capture per-finding feedback (`useful` / `not_useful`) and per-brief 1–5★ ratings | `/feedback` API + UI |
| Browse ingest-run history with success/error stats | `/ingest/runs` API + `/runs` page |
| Pre-LLM dry-run of the brief (the exact prompt that would be sent) | `sentinel brief generate --dry-run` |

That's the bulk of the product. You get a ranked, cited, explainable security feed *without* spending a token.

## What needs an LLM API key (Bedrock-Claude)

Exactly one capability — the analyst synthesis on top of the ranked findings:

| Capability | Where | Cost shape |
| --- | --- | --- |
| Daily analyst brief: prioritized markdown with inline citations, fix recommendations, uncertainty notes | `sentinel brief generate` (without `--dry-run`) → `/watchlists/{slug}/briefs/generate` | One Claude call per brief. Verified live: ~2,500 in / ~400 out tokens for a 6-finding brief. |

Strip the Bedrock keys and the product still ranks, scores, and serves findings — you just lose the written narrative on top.

## Pipeline

```
RSS / REST sources
        v
   ingest workers     (NVD / GHSA / OSV / KEV / EPSS / vendor RSS)
        v
   normalized advisories  (Postgres / SQLite — same SQL surface)
        v
   SBOM upload --> PURL resolve --> affected-range join --> EPSS+KEV merge
        v
   ranked finding set (per watchlist)
        v
   Claude synthesis (Bedrock — one call per brief)
        v
   brief.md  +  cited JSON  +  history
        v
   Next.js dashboard
```

No Kafka. No K8s. No multi-agent fleet. One ingest stage, one match/score stage, one synth call. The interesting layer is the brief, not the infra.

## Quickstart

```bash
cp .env.example .env
python -m venv .venv
.venv/Scripts/activate          # bash on Windows: source .venv/Scripts/activate
pip install -e ".[dev]"

# Initialize DB and seed source registry
sentinel db init
sentinel sources seed

# Pull advisories. Wider --since on the first run.
sentinel ingest run --source ghsa --since 14d
sentinel ingest run --source osv  --since 365d
sentinel ingest run --source kev
sentinel ingest run --source epss
# (--source omitted runs all five in default order)

# Upload an SBOM as a watchlist, then match
sentinel watchlist upload --slug demo --name "Demo stack" fixtures/sample-requirements.txt
sentinel match run --watchlist demo

# Generate today's brief (Bedrock-Claude — see env note below)
sentinel brief generate --watchlist demo --top-n 6

# Serve API + frontend
sentinel api serve                        # http://localhost:8000
cd web && npm install && npm run dev      # http://localhost:3000
```

### Bedrock model ID

If you hit `Invocation of model ID ... with on-demand throughput isn't supported`,
use the regional inference-profile prefix (Bedrock requires it in some regions):

| Region          | `BEDROCK_MODEL_ID`                                       |
| --------------- | -------------------------------------------------------- |
| ap-south-1      | `apac.anthropic.claude-3-5-sonnet-20241022-v2:0`         |
| eu-* regions    | `eu.anthropic.claude-3-5-sonnet-20241022-v2:0`           |
| us-* regions    | `us.anthropic.claude-3-5-sonnet-20241022-v2:0` *(or bare)* |

## Layout

- `src/sentinel_brief/` — Python package (ingest, match, brief, api, models)
- `web/` — Next.js dashboard
- `fixtures/` — sample SBOMs and seed data
- `scripts/` — operational scripts (cron, deploy)
- `docker/` — single-container compose for local end-to-end

## Deployment

**Current state:** the Next.js frontend is hosted on Vercel at https://web-mu-drab-33.vercel.app. The Python backend runs **locally only** — Vercel doesn't host long-running Python processes or persistent SQLite. Visiting the deployed URL loads the UI, but every action that hits the API will fail until a backend is running somewhere reachable.

To get the deployed UI talking to a real backend, either:

1. **Run the backend locally and point the deployed UI at a tunnel** (cloudflared / ngrok) — set `NEXT_PUBLIC_API_BASE` in Vercel project settings to the tunnel URL and redeploy.
2. **Host the backend somewhere with persistent disk** — Fly.io, Render, Railway, or a VPS. Use the included `docker/Dockerfile` + `docker-compose.yml`. Then set `NEXT_PUBLIC_API_BASE` in Vercel to that host.
3. **Run end-to-end locally** — `sentinel api serve` + `cd web && npm run dev`. This is the fastest dev loop.

### Re-deploy the frontend

```bash
cd web
vercel deploy --prod
```

## License

AGPL-3.0 — preserves the option to commercialize later. See [LICENSE](LICENSE).

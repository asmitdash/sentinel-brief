# sentinel-brief

Daily cyber-threat OSINT brief over an SBOM.

Upload a `requirements.txt` / `package.json` / SBOM. Every morning, get a Claude-written analyst note on what new vulnerabilities, exploits, and chatter affect *your* dependencies — with citations back to NVD, GHSA, CISA KEV, OSV, and EPSS.

Personal-learning project. Free / OSS deps only. Single-machine deployable.

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

## License

AGPL-3.0 — preserves the option to commercialize later. See [LICENSE](LICENSE).

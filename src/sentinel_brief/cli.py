"""sentinel-brief CLI — `sentinel <command> ...`"""

from __future__ import annotations

import json
import re
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .brief import generate_brief
from .db import init_db, session_scope
from .ingest import run_all, run_one
from .ingest.runner import seed_sources, REGISTRY
from .logging import configure_logging
from .match.matcher import match_watchlist
from .match.sbom import parse_sbom
from .match.watchlist_ops import register_watchlist

console = Console()


def _parse_since(raw: str | None) -> int:
    if not raw:
        return 7
    m = re.match(r"^(\d+)\s*([dD])?$", raw)
    if not m:
        raise click.BadParameter(f"--since must look like '7d' (got {raw!r})")
    return int(m.group(1))


@click.group()
def cli() -> None:
    configure_logging()


@cli.group()
def db() -> None:
    """Database admin."""


@db.command("init")
def db_init() -> None:
    init_db()
    console.print("[green]db initialized[/green]")


@cli.group()
def sources() -> None:
    """Source registry admin."""


@sources.command("seed")
def sources_seed() -> None:
    init_db()
    seed_sources()
    console.print("[green]sources seeded[/green]")


@sources.command("list")
def sources_list() -> None:
    table = Table(title="Sources")
    for col in ("slug", "name", "kind"):
        table.add_column(col)
    for slug, ing in REGISTRY.items():
        table.add_row(slug, ing.name, slug)
    console.print(table)


@cli.group()
def ingest() -> None:
    """Ingest from external sources."""


@ingest.command("run")
@click.option("--source", "source", default=None, help="Run a single source by slug.")
@click.option("--since", "since", default="7d", help="Only pull items modified in the last <N>d.")
def ingest_run(source: str | None, since: str) -> None:
    from datetime import datetime, timedelta, timezone

    days = _parse_since(since)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    init_db()
    if source:
        result = run_one(source, since=cutoff)
        console.print(json.dumps(result, indent=2))
    else:
        results = run_all(since=cutoff)
        console.print(json.dumps(results, indent=2))


@cli.group()
def watchlist() -> None:
    """Watchlist admin."""


@watchlist.command("upload")
@click.option("--slug", default="default", help="Watchlist slug.")
@click.option("--name", default="Default Watchlist", help="Display name.")
@click.argument("sbom_path", type=click.Path(exists=True, dir_okay=False))
def watchlist_upload(slug: str, name: str, sbom_path: str) -> None:
    init_db()
    items = parse_sbom(sbom_path)
    with session_scope() as session:
        register_watchlist(session, slug, name, items)
    console.print(f"[green]watchlist[/green] {slug}: {len(items)} components")


@cli.group()
def match() -> None:
    """Match watchlists against advisories."""


@match.command("run")
@click.option("--watchlist", "slug", default="default")
def match_run(slug: str) -> None:
    init_db()
    with session_scope() as session:
        results = match_watchlist(session, slug)
    console.print(f"[green]findings[/green]: {len(results)}")


@cli.group()
def brief() -> None:
    """Brief generation."""


@brief.command("generate")
@click.option("--watchlist", "slug", default="default")
@click.option("--top-n", default=12)
@click.option("--dry-run", is_flag=True, default=False, help="Skip Bedrock; print prompt instead.")
@click.option("--out", default=None, help="Write the markdown brief to a file.")
def brief_generate(slug: str, top_n: int, dry_run: bool, out: str | None) -> None:
    init_db()
    result = generate_brief(slug, top_n=top_n, dry_run=dry_run)
    console.print(f"[green]brief[/green] id={result.brief_id} title={result.title!r}")
    if out:
        Path(out).write_text(result.markdown, encoding="utf-8")
        console.print(f"wrote {out}")
    else:
        console.print(result.markdown)


@cli.group()
def api() -> None:
    """API server."""


@api.command("serve")
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8000, type=int)
@click.option("--reload/--no-reload", default=False)
def api_serve(host: str, port: int, reload: bool) -> None:
    import uvicorn

    init_db()
    uvicorn.run("sentinel_brief.api.app:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    cli()

"""Domain Ranking API Service.

Standalone FastAPI service that downloads, caches, and serves domain
popularity rankings from Tranco and Cisco Umbrella top-1M lists.

Provides:
  - GET  /rank?domain=mail.dell.com  — single domain rank lookup
  - POST /rank/bulk                  — batch lookup (JSON body: {"domains": [...]})
  - GET  /prioritize?program=visma   — rank all discovered subs for a program
  - POST /update                     — trigger manual list refresh
  - GET  /health                     — health check

Run:
  uvicorn pipeline.services.domain_ranking:app --host 0.0.0.0 --port 8787

Config in config.yml:
  ranking_service:
    port: 8787
    update_interval: 86400  # seconds (24h)
    sources: ["tranco", "umbrella"]
"""

import csv
import io
import logging
import os
import sqlite3
import time
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from threading import Thread

import requests
from fastapi import FastAPI, Query, BackgroundTasks
from pydantic import BaseModel

log = logging.getLogger(__name__)

# ─── Configuration ───────────────────────────────────────────────

DATA_DIR = Path(os.environ.get("RANKING_DATA_DIR",
                                Path(__file__).parent.parent.parent / "data"))
DB_PATH = DATA_DIR / "domain_rankings.db"

SOURCES = {
    "tranco": {
        "url": "https://tranco-list.eu/top-1m.csv.zip",
        "url_with_subs": "https://tranco-list.eu/top-1m-incl-subdomains.csv.zip",
        "format": "rank,domain",
    },
    "umbrella": {
        "url": "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
        "format": "rank,domain",
    },
}

UPDATE_INTERVAL = int(os.environ.get("RANKING_UPDATE_INTERVAL", 86400))


# ─── Database ────────────────────────────────────────────────────

def init_db():
    """Initialize the ranking database."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS rankings (
            domain TEXT NOT NULL,
            source TEXT NOT NULL,
            rank INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (domain, source)
        );

        CREATE INDEX IF NOT EXISTS idx_rankings_domain ON rankings(domain);
        CREATE INDEX IF NOT EXISTS idx_rankings_rank ON rankings(rank);

        CREATE TABLE IF NOT EXISTS update_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            domains_loaded INTEGER NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL
        );
    """)
    conn.close()


@contextmanager
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ─── Data Download & Import ──────────────────────────────────────

def download_and_import(source_name: str) -> int:
    """Download a ranking list and import it into the database."""
    source = SOURCES.get(source_name)
    if not source:
        raise ValueError(f"Unknown source: {source_name}")

    url = source.get("url_with_subs", source["url"])
    log.info(f"[ranking] Downloading {source_name} from {url}")

    try:
        resp = requests.get(url, timeout=120, stream=True)
        resp.raise_for_status()
    except Exception as e:
        log.error(f"[ranking] Download failed for {source_name}: {e}")
        # Fallback to primary URL if subdomains URL failed
        if "url_with_subs" in source and url != source["url"]:
            try:
                url = source["url"]
                log.info(f"[ranking] Falling back to {url}")
                resp = requests.get(url, timeout=120, stream=True)
                resp.raise_for_status()
            except Exception as e2:
                log.error(f"[ranking] Fallback also failed: {e2}")
                return 0
        else:
            return 0

    # Extract CSV from zip
    content = resp.content
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            csv_name = zf.namelist()[0]
            csv_data = zf.read(csv_name).decode("utf-8", errors="replace")
    except zipfile.BadZipFile:
        # Maybe it's not zipped
        csv_data = content.decode("utf-8", errors="replace")

    # Parse and insert
    started = datetime.utcnow().isoformat()
    count = 0

    with get_db() as conn:
        # Clear old data for this source
        conn.execute("DELETE FROM rankings WHERE source = ?", (source_name,))

        batch = []
        now = datetime.utcnow().isoformat()

        for line in csv_data.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(",", 1)
            if len(parts) != 2:
                continue

            try:
                rank = int(parts[0].strip())
                domain = parts[1].strip().lower().strip('"')
            except (ValueError, IndexError):
                continue

            if not domain:
                continue

            batch.append((domain, source_name, rank, now))
            count += 1

            if len(batch) >= 10000:
                conn.executemany(
                    "INSERT OR REPLACE INTO rankings (domain, source, rank, updated_at) VALUES (?, ?, ?, ?)",
                    batch,
                )
                batch = []

        if batch:
            conn.executemany(
                "INSERT OR REPLACE INTO rankings (domain, source, rank, updated_at) VALUES (?, ?, ?, ?)",
                batch,
            )

        conn.execute(
            "INSERT INTO update_log (source, domains_loaded, started_at, completed_at) VALUES (?, ?, ?, ?)",
            (source_name, count, started, datetime.utcnow().isoformat()),
        )
        conn.commit()

    log.info(f"[ranking] Imported {count} domains from {source_name}")
    return count


def update_all_sources():
    """Download and import all configured sources."""
    for source_name in SOURCES:
        try:
            download_and_import(source_name)
        except Exception as e:
            log.error(f"[ranking] Failed to update {source_name}: {e}")


# ─── Lookup Functions ────────────────────────────────────────────

def lookup_domain(domain: str) -> dict | None:
    """Look up a domain's ranking across all sources."""
    domain = domain.lower().strip()

    with get_db() as conn:
        # Exact match
        rows = conn.execute(
            "SELECT domain, source, rank FROM rankings WHERE domain = ?",
            (domain,),
        ).fetchall()

        if rows:
            result = {"domain": domain, "rankings": {}}
            for row in rows:
                result["rankings"][row["source"]] = row["rank"]
            result["best_rank"] = min(result["rankings"].values())
            return result

        # Try root domain lookup (strip subdomain)
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            root = ".".join(parts[i:])
            rows = conn.execute(
                "SELECT domain, source, rank FROM rankings WHERE domain = ?",
                (root,),
            ).fetchall()
            if rows:
                result = {"domain": domain, "root_domain": root, "rankings": {}}
                for row in rows:
                    result["rankings"][row["source"]] = row["rank"]
                result["best_rank"] = min(result["rankings"].values())
                return result

    return None


def lookup_bulk(domains: list[str]) -> list[dict]:
    """Batch lookup for multiple domains."""
    results = []
    for domain in domains:
        result = lookup_domain(domain)
        if result:
            results.append(result)
        else:
            results.append({"domain": domain, "rankings": {}, "best_rank": None})
    return results


def prioritize_program(program_name: str) -> list[dict]:
    """Get all subdomains for a program, sorted by popularity rank."""
    # Import here to avoid circular deps
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from pipeline.core.storage import Storage

    storage = Storage()
    prog = storage.get_program(program_name)
    if not prog:
        return []

    with storage._conn() as conn:
        subs = conn.execute(
            "SELECT domain FROM subdomains WHERE program_id = ?",
            (prog["id"],),
        ).fetchall()

    domains = [row["domain"] for row in subs]
    ranked = lookup_bulk(domains)

    # Sort: ranked domains first (by rank), then unranked
    ranked_subs = [r for r in ranked if r["best_rank"] is not None]
    unranked_subs = [r for r in ranked if r["best_rank"] is None]

    ranked_subs.sort(key=lambda x: x["best_rank"])

    return ranked_subs + unranked_subs


# ─── Background Updater ─────────────────────────────────────────

def _auto_updater():
    """Background thread that periodically updates ranking data."""
    while True:
        try:
            # Check if data needs updating
            with get_db() as conn:
                row = conn.execute(
                    "SELECT MAX(completed_at) as last_update FROM update_log"
                ).fetchone()

            needs_update = True
            if row and row["last_update"]:
                last = datetime.fromisoformat(row["last_update"])
                if datetime.utcnow() - last < timedelta(seconds=UPDATE_INTERVAL):
                    needs_update = False

            if needs_update:
                log.info("[ranking] Auto-updating ranking data...")
                update_all_sources()

        except Exception as e:
            log.error(f"[ranking] Auto-update failed: {e}")

        time.sleep(3600)  # Check every hour


# ─── FastAPI App ─────────────────────────────────────────────────

app = FastAPI(title="Domain Ranking API", version="1.0.0")


class BulkRequest(BaseModel):
    domains: list[str]


@app.on_event("startup")
def startup():
    init_db()

    # Check if we have data, if not do initial download
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) as c FROM rankings").fetchone()["c"]

    if count == 0:
        log.info("[ranking] No ranking data found, downloading initial dataset...")
        update_all_sources()

    # Start background updater
    updater = Thread(target=_auto_updater, daemon=True)
    updater.start()


@app.get("/rank")
def get_rank(domain: str = Query(..., description="Domain to look up")):
    """Look up the popularity rank for a domain."""
    result = lookup_domain(domain)
    if result:
        return result
    return {"domain": domain, "rankings": {}, "best_rank": None}


@app.post("/rank/bulk")
def get_rank_bulk(req: BulkRequest):
    """Batch lookup for multiple domains."""
    return {"results": lookup_bulk(req.domains)}


@app.get("/prioritize")
def get_prioritize(program: str = Query(..., description="Program name")):
    """Get all subdomains for a program, sorted by popularity rank."""
    results = prioritize_program(program)
    return {
        "program": program,
        "total": len(results),
        "ranked": len([r for r in results if r["best_rank"] is not None]),
        "unranked": len([r for r in results if r["best_rank"] is None]),
        "results": results,
    }


@app.post("/update")
def trigger_update(background_tasks: BackgroundTasks):
    """Trigger a manual refresh of all ranking data."""
    background_tasks.add_task(update_all_sources)
    return {"status": "update_started", "sources": list(SOURCES.keys())}


@app.get("/health")
def health():
    """Health check with data freshness info."""
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) as c FROM rankings").fetchone()["c"]
        sources = conn.execute(
            "SELECT source, domains_loaded, completed_at FROM update_log "
            "ORDER BY completed_at DESC LIMIT 10"
        ).fetchall()

    return {
        "status": "ok",
        "total_domains": count,
        "sources": [dict(s) for s in sources],
    }


@app.get("/stats")
def stats():
    """Ranking data statistics."""
    with get_db() as conn:
        source_stats = conn.execute(
            "SELECT source, COUNT(*) as count, MIN(rank) as min_rank, "
            "MAX(rank) as max_rank FROM rankings GROUP BY source"
        ).fetchall()

    return {"sources": [dict(s) for s in source_stats]}

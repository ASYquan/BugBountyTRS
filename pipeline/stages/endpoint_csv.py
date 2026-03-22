"""Continuous endpoint CSV writer.

Consumes from both recon_http and recon_urls streams and appends unique
endpoints to a CSV file. Uses Redis deduplication (7-day TTL) and file
locking to support concurrent reads while ensuring atomic single-writer appends.

CSV schema:
    timestamp, program, url, status_code, title, content_length,
    webserver, tech, ip, asn, cdn, port, source_apex, method, params, source_tool

Run as a single instance — only one endpoint_csv worker should run at a time.
"""

import csv
import fcntl
import io
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.dedup import Dedup
from .notification import notify

log = logging.getLogger(__name__)

CSV_FIELDS = [
    "timestamp", "program", "url", "status_code", "title",
    "content_length", "webserver", "tech", "ip", "asn", "cdn",
    "port", "source_apex", "method", "params", "source_tool",
]


class EndpointCsvWorker(BaseWorker):
    """Append unique HTTP endpoints to a continuously-updated CSV file."""

    name = "endpoint_csv"
    # Consume from both HTTP services and discovered URLs
    input_stream = "recon_http"
    output_streams = []  # Terminal stage — no downstream

    def on_start(self):
        cfg = get_config()
        self.csv_path = Path(
            cfg.get("output", {}).get("endpoints_csv", "./data/endpoints.csv")
        )
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)

        self.endpoint_dedup = Dedup(namespace="endpoint_csv")

        # Write CSV header if file is new/empty
        if not self.csv_path.exists() or self.csv_path.stat().st_size == 0:
            self._write_header()

        log.info(f"[endpoint_csv] Writing to {self.csv_path}")

    def dedup_key(self, data: dict) -> str:
        # Dedup by URL + method
        url = data.get("url", "")
        method = data.get("method", "GET")
        return f"endpoint:{method}:{url}"

    def process(self, data: dict) -> list[dict]:
        url = data.get("url", "")
        if not url:
            return []

        row = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "program": data.get("program", ""),
            "url": url,
            "status_code": data.get("status_code", ""),
            "title": data.get("title", ""),
            "content_length": data.get("content_length", ""),
            "webserver": data.get("webserver", ""),
            "tech": _flatten_tech(data.get("tech", [])),
            "ip": data.get("ip", ""),
            "asn": data.get("asn", ""),
            "cdn": data.get("cdn", ""),
            "port": data.get("port", ""),
            "source_apex": data.get("parent_domain", data.get("source_apex", "")),
            "method": data.get("method", "GET"),
            "params": _flatten_params(data.get("params", {})),
            "source_tool": data.get("source", "httpx"),
        }

        self._append_row(row)

        # Notify on new HTTP services (not every URL — too noisy)
        if data.get("source", "") in ("httpx", "httpprobe"):
            notify(
                "new_http_service",
                f"New service: {url} [{data.get('status_code', '?')}] {data.get('title', '')}",
                program=data.get("program"),
                url=url,
            )

        return []  # No downstream publishing

    def _write_header(self):
        with open(self.csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writeheader()

    def _append_row(self, row: dict):
        """Atomically append a row using file locking."""
        try:
            with open(self.csv_path, "a", newline="") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
                    writer.writerow(row)
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
        except Exception as e:
            log.error(f"[endpoint_csv] Failed to append row for {row.get('url')}: {e}")


class UrlEndpointCsvWorker(EndpointCsvWorker):
    """Second instance consuming from recon_urls stream."""

    name = "endpoint_csv_urls"
    input_stream = "recon_urls"


# ── Standalone export helper ─────────────────────────────────────


def export_program_endpoints(program_name: str, output_path: Path = None) -> Path:
    """Export all endpoints for a program from the database to a CSV file.

    Used by the CLI `export endpoints-csv <program>` command.
    """
    from ..core.storage import Storage

    storage = Storage()
    cfg = get_config()
    out = output_path or Path(
        cfg.get("output", {}).get("endpoints_csv", "./data/endpoints.csv")
    ).parent / f"{program_name}_endpoints.csv"

    rows = storage.get_endpoints_for_csv(program_name)
    if not rows:
        log.warning(f"[endpoint_csv] No endpoints found for {program_name}")
        return None

    with open(out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    log.info(f"[endpoint_csv] Exported {len(rows)} endpoints to {out}")
    return out


# ── Helpers ──────────────────────────────────────────────────────


def _flatten_tech(tech) -> str:
    if isinstance(tech, list):
        return ",".join(str(t) for t in tech)
    if isinstance(tech, dict):
        return ",".join(tech.keys())
    return str(tech) if tech else ""


def _flatten_params(params) -> str:
    if isinstance(params, dict):
        return "&".join(f"{k}={v}" for k, v in params.items())
    if isinstance(params, list):
        return "&".join(str(p) for p in params)
    return str(params) if params else ""

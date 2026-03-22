"""Wayback Machine passive URL discovery.

Queries archive.org CDX API for historical URLs of resolved domains.
Finds forgotten endpoints still running but not actively linked.
Completely passive — zero requests to the target.

Consumes from recon_resolved (confirmed live subdomains only).
Publishes historical URLs to recon_urls for crawler + endpoint analysis.
"""

import logging
from urllib.parse import urlparse

import requests

from ..core.worker import BaseWorker

log = logging.getLogger(__name__)

# Static assets — skip entirely, add no signal
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".wav", ".ogg",
}

# High-value extensions — always keep even if they look boring
_KEEP_EXTENSIONS = {
    ".js", ".json", ".xml", ".yaml", ".yml", ".env", ".config", ".conf",
    ".bak", ".backup", ".old", ".orig", ".log", ".sql", ".db",
    ".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl", ".rb", ".py",
    ".txt", ".csv", ".pem", ".key", ".cert",
}


class WaybackWorker(BaseWorker):
    """Queries Wayback Machine CDX API for historical URLs."""

    name = "wayback"
    input_stream = "recon_resolved"
    output_streams = ["recon_urls"]

    def dedup_key(self, data: dict) -> str:
        return f"wayback:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        domain = data.get("domain")
        program = data.get("program")
        program_id = data.get("program_id")
        subdomain_id = data.get("subdomain_id")

        if not domain:
            return []

        log.info(f"[wayback] Querying Wayback Machine for {domain}")
        urls = self._fetch_wayback_urls(domain)

        if not urls:
            return []

        results = []
        for url in urls:
            results.append({
                "program": program,
                "program_id": program_id,
                "url": url,
                "subdomain_id": subdomain_id,
                "source": "wayback",
                "passive": True,
            })

        log.info(f"[wayback] Found {len(urls)} historical URLs for {domain}")
        return results

    def _fetch_wayback_urls(self, domain: str) -> set[str]:
        try:
            resp = requests.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}/*",
                    "output": "json",
                    "fl": "original,statuscode",
                    "collapse": "urlkey",
                    "limit": 10000,
                    "filter": "statuscode:200",
                },
                timeout=60,
                headers={"User-Agent": "Mozilla/5.0"},
            )

            if resp.status_code != 200:
                log.debug(f"[wayback] CDX returned {resp.status_code} for {domain}")
                return set()

            data = resp.json()
            if len(data) <= 1:
                return set()

            urls = set()
            for row in data[1:]:  # Skip header row
                url = row[0] if isinstance(row, list) else row
                if not url or not url.startswith("http"):
                    continue

                parsed = urlparse(url)
                path = parsed.path.lower()
                ext = ""
                if "." in path.rsplit("/", 1)[-1]:
                    ext = "." + path.rsplit(".", 1)[-1].split("?")[0]

                if ext in _SKIP_EXTENSIONS:
                    continue

                urls.add(url)

            return urls

        except Exception as e:
            log.debug(f"[wayback] Failed for {domain}: {e}")
            return set()

"""Web crawling stage.

Consumes HTTP services from recon_http stream.
Uses katana for crawling, discovers URLs, endpoints, and JS files.
Feeds discovered URLs back into the pipeline.
"""

import subprocess
import json
import logging
import re
from urllib.parse import urlparse

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.ratelimit import active_scan_slot, tracked_run

log = logging.getLogger(__name__)


class CrawlerWorker(BaseWorker):
    name = "crawler"
    input_stream = "recon_http"
    output_streams = ["recon_urls", "recon_js"]

    def dedup_key(self, data: dict) -> str:
        return f"crawl:{data.get('url', '')}"

    def process(self, data: dict) -> list[dict]:
        url = data.get("url")
        program = data.get("program")
        program_id = data.get("program_id")
        subdomain_id = data.get("subdomain_id")

        if not url:
            return []

        log.info(f"[crawler] Crawling {url}")

        constraints = self.roe_constraints(data)
        if not self.is_scanning_allowed(constraints, "crawler"):
            return []
        discovered = self._run_katana(url, constraints=constraints)

        results = []
        js_files = []

        for found_url in discovered:
            found_url = found_url.strip()
            if not found_url:
                continue

            parsed = urlparse(found_url)

            # Identify JS files
            if parsed.path.endswith((".js", ".mjs")):
                js_files.append(found_url)

            # Store URL
            try:
                http_svc = None
                with self.storage._conn() as conn:
                    row = conn.execute(
                        "SELECT id FROM http_services WHERE url=?", (url,)
                    ).fetchone()
                    if row:
                        http_svc = row["id"]

                if http_svc:
                    # Extract query params
                    params = {}
                    if parsed.query:
                        for p in parsed.query.split("&"):
                            if "=" in p:
                                k, v = p.split("=", 1)
                                params[k] = v

                    self.storage.upsert_url(
                        http_service_id=http_svc,
                        url=found_url,
                        source="katana",
                        params=params if params else None,
                    )
            except Exception as e:
                log.debug(f"Error storing URL: {e}")

            results.append({
                "program": program,
                "program_id": program_id,
                "url": found_url,
                "source_url": url,
                "subdomain_id": subdomain_id,
                "is_js": found_url in js_files,
            })

        # Publish JS files for analysis
        for js_url in js_files:
            results.append({
                "_stream": self.mq.stream_name("recon_js"),
                "program": program,
                "program_id": program_id,
                "url": js_url,
                "source_url": url,
                "subdomain_id": subdomain_id,
            })

        log.info(f"[crawler] Found {len(discovered)} URLs, {len(js_files)} JS files from {url}")
        return results

    def _run_katana(self, target: str, constraints: dict = None) -> list[str]:
        cfg = get_config()["tools"].get("katana", {})
        c = constraints or {}
        depth = c.get("max_crawl_depth") or cfg.get("depth", 3)
        threads = cfg.get("threads", 10)
        timeout = cfg.get("timeout", 15)
        rate_limit = c.get("rate_limit_rps") or cfg.get("rate_limit", 20)

        cmd = [
            "katana",
            "-u", target,
            "-silent",
            "-d", str(depth),
            "-c", str(threads),
            "-timeout", str(timeout),
            "-rl", str(rate_limit),
            "-jc",           # JavaScript crawling
            "-kf", "all",    # Known file discovery
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
        ]

        # Inject RoE-required headers and user-agent
        for h_arg in self.roe_header_args(c):
            cmd.append(h_arg)

        try:
            with active_scan_slot(f"katana:{target}"):
                result = tracked_run(
                    cmd,
                    capture_output=True, text=True, timeout=300,
                )
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except FileNotFoundError:
            log.warning("katana not found")
            return []
        except subprocess.TimeoutExpired:
            log.warning(f"katana timed out for {target}")
            return []

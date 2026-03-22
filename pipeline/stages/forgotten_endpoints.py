"""Forgotten endpoint detection.

Cross-references Wayback Machine historical URLs against URLs discovered by
active crawling. A URL is "forgotten" when:
  1. It appears in Wayback Machine history (was publicly accessible at some point)
  2. It was NOT found by the active crawler, feroxbuster, or other active sources
  3. It still responds when probed (still live on the server)

The transcript insight: "I use the Wayback Machine to check old versions.
Sometimes there's legacy stuff still running but not linked anymore."

Note on timing: the DB check happens at processing time. Early in a pipeline run,
the crawler may not have written all URLs yet — occasional false positives are expected.
Dedup (by URL) prevents re-probing once a verdict is recorded.

Consumes: recon_urls (processes only source=wayback messages)
Publishes: vuln_findings
"""

import json
import logging
import subprocess
from urllib.parse import urlparse

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.ratelimit import active_scan_slot

log = logging.getLogger(__name__)

# Sources that mean "the crawler found this" — not historical
_ACTIVE_SOURCES = {
    "crawler", "katana", "content_discovery", "feroxbuster", "ffuf",
    "httpx", "gau", "waybackurls_active",
}

_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".avi",
}


class ForgottenEndpointWorker(BaseWorker):
    """Detects live historical URLs not found by active crawling."""

    name = "forgotten_endpoints"
    input_stream = "recon_urls"
    output_streams = ["vuln_findings"]

    def dedup_key(self, data: dict) -> str:
        return f"forgotten:{data.get('url', '')}"

    def process(self, data: dict) -> list[dict]:
        # Only act on Wayback-sourced URLs
        if data.get("source") != "wayback":
            return []

        url = data.get("url")
        program = data.get("program")
        program_id = data.get("program_id")
        subdomain_id = data.get("subdomain_id")

        if not url:
            return []

        # Skip static assets
        try:
            path = urlparse(url).path.lower()
            basename = path.rsplit("/", 1)[-1]
            if "." in basename:
                ext = "." + basename.rsplit(".", 1)[-1].split("?")[0]
                if ext in _SKIP_EXTENSIONS:
                    return []
        except Exception:
            return []

        # Check if actively found by crawler/feroxbuster
        if self._is_actively_found(url):
            return []

        # Not found by active sources — probe it
        constraints = self.roe_constraints(data)
        if not self.is_scanning_allowed(constraints, "forgotten_endpoints"):
            return []

        rate_limit = constraints["rate_limit_rps"]

        log.info(f"[forgotten] Probing historical URL not in current crawl: {url}")

        with active_scan_slot(program_id):
            status, length, title = self._probe(url, rate_limit=rate_limit, constraints=constraints)

        if status is None:
            return []

        # Only report live responses (2xx, 3xx, auth-gated)
        if status >= 400 and status not in (401, 403):
            return []

        if status in (200, 201, 204):
            severity = "medium"
        elif status in (401, 403):
            severity = "low"
        else:  # 3xx
            severity = "low"

        return [{
            "program": program,
            "program_id": program_id,
            "subdomain_id": subdomain_id,
            "tool": "forgotten_endpoints",
            "template_id": "forgotten-endpoint",  # stable — dedup hash = sha256(forgotten-endpoint:url:)
            "severity": severity,
            "title": f"Forgotten endpoint still live [{status}]: {url}",
            "url": url,
            "evidence": json.dumps({
                "url": url,
                "status_code": status,
                "content_length": length,
                "title": title,
                "source": "wayback_historical",
                "note": (
                    "This URL was found in Wayback Machine history but NOT by active crawling. "
                    "It is still responding on the server. This is a forgotten/orphaned endpoint "
                    "that was removed from the site's navigation but never taken down."
                ),
            }),
        }]

    def _is_actively_found(self, url: str) -> bool:
        """Return True if this URL was found by any active (non-wayback) source."""
        try:
            with self.storage._conn() as conn:
                row = conn.execute(
                    """SELECT id FROM urls
                       WHERE url = ?
                         AND source IS NOT NULL
                         AND source != 'wayback'
                       LIMIT 1""",
                    (url,),
                ).fetchone()
                return row is not None
        except Exception:
            return False

    def _probe(self, url: str, rate_limit: int = 20, constraints: dict = None) -> tuple:
        """Probe URL with httpx. Returns (status_code, content_length, title)."""
        cmd = [
            "httpx",
            "-u", url,
            "-status-code",
            "-content-length",
            "-title",
            "-no-color",
            "-silent",
            "-timeout", "10",
            "-rl", str(rate_limit),
        ]
        if constraints:
            cmd.extend(self.roe_header_args(constraints))
        else:
            # Fallback to config-level headers when no constraints provided
            cfg = get_config()
            inti_cfg = cfg.get("intigriti", {})
            ua = inti_cfg.get("user_agent", "Mozilla/5.0")
            req_header = inti_cfg.get("request_header", "")
            cmd.extend(["-H", f"User-Agent: {ua}"])
            if req_header:
                cmd.extend(["-H", req_header])

        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
            ).stdout.strip()

            if not out:
                return None, None, None

            # httpx output: url [status] [length] [title]
            status = None
            length = None
            title_parts = []
            for part in out.split():
                if part.startswith("[") and part.endswith("]"):
                    val = part[1:-1]
                    if val.isdigit():
                        n = int(val)
                        if 100 <= n < 600:
                            status = n
                        elif n >= 600:
                            length = n
                    else:
                        title_parts.append(val)

            title = " ".join(title_parts) if title_parts else None
            return status, length, title

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            log.debug(f"[forgotten] probe failed for {url}: {e}")
            return None, None, None

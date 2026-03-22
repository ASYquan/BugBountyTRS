"""Content discovery stage — recursive directory and endpoint bruteforcing.

Consumes from recon_http stream (live HTTP services found by httpprobe).
Runs feroxbuster per service to find hidden directories, files, and API endpoints.

Rate-limited to Intigriti RoE (20 req/sec aggregate via global scan slot).
Publishes discovered paths to recon_urls stream for further processing and CSV export.
"""

import json
import logging
import re
import subprocess
import tempfile
from pathlib import Path

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.ratelimit import active_scan_slot, tracked_run

log = logging.getLogger(__name__)


class ContentDiscoveryWorker(BaseWorker):
    """Recursive directory and content bruteforcing with feroxbuster."""

    name = "content_discovery"
    input_stream = "recon_http"
    output_streams = ["recon_urls"]

    def dedup_key(self, data: dict) -> str:
        return f"content_discovery:{data.get('url', '')}"

    def process(self, data: dict) -> list[dict]:
        url = data.get("url", "")
        program = data.get("program", "")
        program_id = data.get("program_id")
        status_code = data.get("status_code", 0)

        if not url or not program:
            return []

        cfg = get_config().get("content_discovery", {})
        if not cfg.get("enabled", True):
            return []

        # Per-program RoE: check automated scanning policy and bruteforce flag
        constraints = self.roe_constraints(data)
        if not self.is_scanning_allowed(constraints, "content_discovery"):
            return []
        if constraints["no_bruteforce"]:
            log.info(f"[content] Skipping {url} — RoE prohibits brute force/fuzzing")
            return []
        roe = constraints  # keep roe alias for content_discovery_enabled check below
        if not roe.get("content_discovery_enabled", True):
            log.info(f"[content] Skipping {url} — disabled by program RoE")
            return []

        # Skip non-2xx/3xx services — likely not worth bruteforcing
        if status_code and int(status_code) >= 500:
            log.debug(f"[content] Skipping {url} (status {status_code})")
            return []

        log.info(f"[content] Bruteforcing {url}")

        discovered = []
        wordlists = cfg.get("wordlists", [])

        # Use first available wordlist
        wordlist = next((w for w in wordlists if Path(w).exists()), None)
        if not wordlist:
            log.warning("[content] No wordlist found, skipping content discovery")
            return []

        with active_scan_slot("feroxbuster"):
            results = self._run_feroxbuster(url, wordlist, cfg, constraints=constraints)

        for path_url in results:
            # Store URL in DB
            http_id = self.storage.upsert_http_service(
                self._get_subdomain_id(data),
                url,
            )
            if http_id:
                self.storage.upsert_url(http_id, path_url, source="feroxbuster")

            discovered.append({
                "program": program,
                "program_id": program_id,
                "url": path_url,
                "parent_url": url,
                "source": "feroxbuster",
                "method": "GET",
            })

        log.info(f"[content] feroxbuster found {len(discovered)} paths on {url}")
        return discovered

    def _run_feroxbuster(self, url: str, wordlist: str, cfg: dict,
                         constraints: dict = None) -> set[str]:
        threads = cfg.get("threads", 10)
        c = constraints or {}
        rate_limit = c.get("rate_limit_rps") or cfg.get("rate_limit", 20)
        scan_limit = cfg.get("scan_limit", 3)
        filter_status = cfg.get("filter_status", "404,400,503")
        extensions = cfg.get("extensions", [])
        user_agent = c.get("required_user_agent") or "Mozilla/5.0"

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as tmp:
                out_path = tmp.name

            cmd = [
                "feroxbuster",
                "--url", url,
                "--wordlist", wordlist,
                "--threads", str(threads),
                "--rate-limit", str(rate_limit),
                "--scan-limit", str(scan_limit),
                "--output", out_path,
                "--json",
                "-A",   # Auto-tune scan based on responses
                "-g",   # Collect links from response body
                "-n",   # No recursion limit override (uses scan-limit)
                "--silent",
                "--no-state",
                "--user-agent", user_agent,
            ]

            for name, value in (c.get("required_headers") or {}).items():
                cmd.extend(["-H", f"{name}: {value}"])

            if filter_status:
                cmd.extend(["--filter-status", filter_status])

            if extensions:
                cmd.extend(["-x", ",".join(extensions)])

            tracked_run(cmd, capture_output=True, text=True, timeout=1800)

            # Parse JSONL output
            found = set()
            out_file = Path(out_path)
            if out_file.exists():
                with open(out_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            # feroxbuster JSON: type=response, url=..., status=...
                            if obj.get("type") == "response":
                                found_url = obj.get("url", "")
                                status = obj.get("status", 0)
                                if found_url and status not in (404, 400, 503):
                                    found.add(found_url)
                        except json.JSONDecodeError:
                            # Plain text URL line
                            if line.startswith("http"):
                                found.add(line)
                out_file.unlink(missing_ok=True)

            return found
        except FileNotFoundError:
            log.warning("[content] feroxbuster not found, skipping")
            return set()
        except subprocess.TimeoutExpired:
            log.warning(f"[content] feroxbuster timed out for {url}")
            Path(out_path).unlink(missing_ok=True)
            return set()
        except Exception as e:
            log.warning(f"[content] feroxbuster failed for {url}: {e}")
            return set()

    def _get_subdomain_id(self, data: dict) -> int | None:
        """Look up subdomain_id from the URL's hostname."""
        url = data.get("url", "")
        m = re.match(r"https?://([^/:]+)", url)
        if not m:
            return None
        hostname = m.group(1)
        program_id = data.get("program_id")
        if not program_id:
            return None
        subs = self.storage.get_subdomains(program_id)
        for sub in subs:
            if sub["domain"] == hostname:
                return sub["id"]
        return None

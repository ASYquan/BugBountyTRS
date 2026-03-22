"""Virtual host discovery stage.

Consumes from recon_ports stream (open ports with IPs).
Uses ffuf in Host-header fuzzing mode to discover virtual hosts that are
not exposed via DNS — a single IP may host many in-scope applications.

Discovered vhosts are published back to recon_subdomains so they flow through
the full DNS resolution → port scan → HTTP probe pipeline.

Rate-limited to Intigriti RoE (20 req/sec via global scan slot).
"""

import json
import logging
import re
import subprocess
import tempfile
from pathlib import Path

import requests

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.ratelimit import active_scan_slot, tracked_run

log = logging.getLogger(__name__)


class VhostDiscoveryWorker(BaseWorker):
    """Discover virtual hosts via Host header fuzzing with ffuf."""

    name = "vhost_discovery"
    input_stream = "recon_ports"
    output_streams = ["recon_subdomains"]

    def dedup_key(self, data: dict) -> str:
        return f"vhost:{data.get('ip', '')}:{data.get('port', '')}"

    def process(self, data: dict) -> list[dict]:
        ip = data.get("ip", "")
        port = data.get("port", "")
        program = data.get("program", "")
        program_id = data.get("program_id")
        parent_domain = data.get("parent_domain", "")

        if not ip or not port or not program:
            return []

        cfg = get_config().get("vhost_discovery", {})
        if not cfg.get("enabled", True):
            return []

        # Only fuzz HTTP/HTTPS ports
        port_int = int(port)
        scheme = "https" if port_int in (443, 8443, 4443) else "http"
        target_url = f"{scheme}://{ip}:{port}"

        # Determine apex domains to fuzz against from the program scope
        apex_domains = self._get_apex_domains(program_id, parent_domain)
        if not apex_domains:
            log.debug(f"[vhost] No apex domains found for {program}, skipping {ip}:{port}")
            return []

        log.info(f"[vhost] Fuzzing {ip}:{port} for virtual hosts ({len(apex_domains)} apex domains)")

        discovered = []
        with active_scan_slot("ffuf_vhost"):
            for apex in apex_domains:
                vhosts = self._run_ffuf_vhost(target_url, apex, cfg)
                for vhost in vhosts:
                    self.storage.upsert_vhost(program_id, ip, vhost, port=port_int)
                    discovered.append({
                        "program": program,
                        "program_id": program_id,
                        "domain": vhost,
                        "parent_domain": apex,
                        "source": "vhost_discovery",
                        "ip": ip,
                        "port": port,
                    })

        if discovered:
            log.info(f"[vhost] Found {len(discovered)} vhosts on {ip}:{port}")

        return discovered

    def _run_ffuf_vhost(self, target_url: str, apex: str, cfg: dict) -> set[str]:
        wordlist = cfg.get("wordlist",
            "/usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt"
        )
        rate_limit = cfg.get("rate_limit", 20)

        if not Path(wordlist).exists():
            log.warning(f"[vhost] Wordlist not found: {wordlist}")
            return set()

        roe_cfg = get_config().get("intigriti", {})
        user_agent = roe_cfg.get("user_agent", "Mozilla/5.0")
        roe_header = roe_cfg.get("request_header", "")

        # Get baseline response size to filter false positives
        baseline_size = self._get_baseline_size(target_url, apex)

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as tmp:
                out_path = tmp.name

            cmd = [
                "ffuf",
                "-u", target_url,
                "-H", f"Host: FUZZ.{apex}",
                "-w", wordlist,
                "-o", out_path,
                "-of", "json",
                "-rate", str(rate_limit),
                "-H", f"User-Agent: {user_agent}",
                "-fc", "404,400",
                "-t", "10",
                "-s",  # Silent mode
            ]

            if roe_header:
                cmd.extend(["-H", roe_header])

            # Filter by baseline size to remove false positives
            if baseline_size is not None:
                cmd.extend(["-fs", str(baseline_size)])

            tracked_run(cmd, capture_output=True, text=True, timeout=600)

            found = set()
            out_file = Path(out_path)
            if out_file.exists():
                try:
                    with open(out_path) as f:
                        data = json.load(f)
                    for result in data.get("results", []):
                        fuzzed = result.get("input", {}).get("FUZZ", "")
                        if fuzzed:
                            found.add(f"{fuzzed}.{apex}")
                except (json.JSONDecodeError, KeyError):
                    pass
                out_file.unlink(missing_ok=True)

            return found
        except FileNotFoundError:
            log.warning("[vhost] ffuf not found, skipping vhost discovery")
            return set()
        except subprocess.TimeoutExpired:
            log.warning(f"[vhost] ffuf timed out for {target_url}/{apex}")
            Path(out_path).unlink(missing_ok=True)
            return set()
        except Exception as e:
            log.warning(f"[vhost] ffuf failed for {target_url}: {e}")
            return set()

    def _get_baseline_size(self, target_url: str, apex: str) -> int | None:
        """Request a non-existent vhost to get baseline response size for filtering."""
        try:
            resp = requests.head(
                target_url,
                headers={"Host": f"nonexistent-baseline-{apex}"},
                timeout=5,
                verify=False,
                allow_redirects=False,
            )
            return len(resp.content)
        except Exception:
            return None

    def _get_apex_domains(self, program_id: int, fallback_domain: str) -> list[str]:
        """Get apex domains for the program from DB or fallback."""
        if not program_id:
            return [fallback_domain] if fallback_domain else []

        try:
            apex_rows = self.storage.get_apex_domains(program_id)
            apexes = [r["domain"] for r in apex_rows]
        except Exception:
            apexes = []

        # Fallback to parent domain
        if not apexes and fallback_domain:
            # Extract apex from subdomain if needed
            parts = fallback_domain.split(".")
            if len(parts) >= 2:
                apexes = [".".join(parts[-2:])]

        return apexes[:5]  # Cap at 5 apex domains per IP to limit scan time

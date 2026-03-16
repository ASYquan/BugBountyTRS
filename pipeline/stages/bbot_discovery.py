"""BBOT integration stage.

Uses BBOT (Black Lantern Security) as a comprehensive subdomain discovery
engine within the pipeline. BBOT's recursive DNS brute-force + NLP mutations
typically find 20-50% more subdomains than subfinder/amass alone.

BBOT runs as a Python library, feeding discovered events directly into
the pipeline's Redis Streams.

Install: pipx install bbot
Docs: https://github.com/blacklanternsecurity/bbot
"""

import json
import logging
import asyncio
import threading

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.storage import Storage

log = logging.getLogger(__name__)


class BBOTDiscoveryWorker(BaseWorker):
    """Runs BBOT subdomain enumeration as a pipeline stage.

    Consumes domains from scope_targets and publishes discovered
    subdomains, IPs, emails, and URLs to downstream streams.
    """
    name = "bbot_discovery"
    input_stream = "scope_targets"
    output_streams = ["recon_subdomains", "recon_resolved", "vuln_findings"]

    def __init__(self):
        super().__init__()
        self._bbot_available = False

    def on_start(self):
        try:
            from bbot.scanner import Scanner
            self._bbot_available = True
            log.info("[bbot] BBOT is available")
        except ImportError:
            log.warning("[bbot] BBOT not installed. Install: pipx install bbot")
            self._bbot_available = False

    def dedup_key(self, data: dict) -> str:
        return f"bbot:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        if not self._bbot_available:
            return []

        domain = data.get("domain")
        program = data.get("program")
        program_id = data.get("program_id")

        if not domain:
            return []

        log.info(f"[bbot] Starting scan for {domain} ({program})")

        cfg = get_config().get("bbot", {})
        preset = cfg.get("preset", "subdomain-enum")
        passive_only = cfg.get("passive_only", False)
        flags = cfg.get("flags", [])

        results = self._run_bbot_scan(domain, preset, passive_only, flags,
                                      program, program_id)

        log.info(f"[bbot] Scan complete for {domain}: {len(results)} events")
        return results

    def _run_bbot_scan(self, domain: str, preset: str, passive_only: bool,
                       flags: list, program: str, program_id: int) -> list[dict]:
        """Run a BBOT scan and collect results."""
        from bbot.scanner import Scanner

        results = []
        seen_subs = set()
        seen_ips = set()

        # Build scanner config
        presets = [preset]
        if passive_only:
            presets = [preset]
            flags = flags + ["passive"]

        # Load BBOT config from our config
        bbot_cfg = get_config().get("bbot", {})
        bbot_config = {}

        # Pass API keys if configured
        api_keys = bbot_cfg.get("api_keys", {})
        if api_keys:
            bbot_config["modules"] = {}
            for module_name, key in api_keys.items():
                bbot_config["modules"][module_name] = {"api_key": key}

        # Run the scan synchronously (BBOT handles its own async internally)
        try:
            scan = Scanner(domain, presets=presets, config=bbot_config)

            for event in scan.start():
                event_type = event.type
                event_data = str(event.data) if not isinstance(event.data, str) else event.data

                if event_type == "DNS_NAME" and event_data not in seen_subs:
                    seen_subs.add(event_data)
                    # Store in DB
                    self.storage.upsert_subdomain(program_id, event_data, source="bbot")
                    results.append({
                        "_stream": self.mq.stream_name("recon_subdomains"),
                        "program": program,
                        "program_id": program_id,
                        "domain": event_data,
                        "source": "bbot",
                    })

                elif event_type == "IP_ADDRESS" and event_data not in seen_ips:
                    seen_ips.add(event_data)
                    results.append({
                        "_stream": self.mq.stream_name("recon_resolved"),
                        "program": program,
                        "program_id": program_id,
                        "ip": event_data,
                        "domain": domain,
                        "source": "bbot",
                    })

                elif event_type == "OPEN_TCP_PORT":
                    # BBOT emits host:port
                    if ":" in event_data:
                        host, port_str = event_data.rsplit(":", 1)
                        try:
                            port = int(port_str)
                            results.append({
                                "_stream": self.mq.stream_name("recon_resolved"),
                                "program": program,
                                "program_id": program_id,
                                "ip": host,
                                "domain": domain,
                                "port": port,
                                "source": "bbot",
                            })
                        except ValueError:
                            pass

                elif event_type == "VULNERABILITY":
                    severity = "medium"
                    if hasattr(event, "severity"):
                        severity = str(event.severity).lower()
                    results.append({
                        "_stream": self.mq.stream_name("vuln_findings"),
                        "program": program,
                        "program_id": program_id,
                        "tool": "bbot",
                        "severity": severity,
                        "title": event_data[:200],
                        "url": f"https://{domain}",
                        "matched_at": domain,
                        "evidence": event_data[:1000],
                    })

                elif event_type == "FINDING":
                    results.append({
                        "_stream": self.mq.stream_name("vuln_findings"),
                        "program": program,
                        "program_id": program_id,
                        "tool": "bbot",
                        "severity": "info",
                        "title": event_data[:200],
                        "url": f"https://{domain}",
                        "matched_at": domain,
                        "evidence": event_data[:1000],
                    })

        except Exception as e:
            log.error(f"[bbot] Scan failed for {domain}: {e}", exc_info=True)

        return results


# ─── Standalone functions for CLI ───────────────────────────────


def bbot_subdomain_enum(domain: str, passive_only: bool = False,
                        preset: str = "subdomain-enum") -> set[str]:
    """Run BBOT subdomain enumeration and return discovered subdomains."""
    from bbot.scanner import Scanner

    presets = [preset]
    subdomains = set()

    scan = Scanner(domain, presets=presets)
    for event in scan.start():
        if event.type == "DNS_NAME":
            subdomains.add(str(event.data))

    return subdomains


def bbot_kitchen_sink(domain: str) -> dict:
    """Run BBOT kitchen-sink scan (everything) and return categorized results."""
    from bbot.scanner import Scanner

    results = {
        "subdomains": set(),
        "ips": set(),
        "open_ports": [],
        "urls": set(),
        "emails": set(),
        "vulns": [],
        "findings": [],
    }

    scan = Scanner(domain, presets=["kitchen-sink"])
    for event in scan.start():
        t = event.type
        d = str(event.data) if not isinstance(event.data, str) else event.data

        if t == "DNS_NAME":
            results["subdomains"].add(d)
        elif t == "IP_ADDRESS":
            results["ips"].add(d)
        elif t == "OPEN_TCP_PORT":
            results["open_ports"].append(d)
        elif t == "URL":
            results["urls"].add(d)
        elif t == "EMAIL_ADDRESS":
            results["emails"].add(d)
        elif t == "VULNERABILITY":
            results["vulns"].append(d)
        elif t == "FINDING":
            results["findings"].append(d)

    # Convert sets for serialization
    for key in ("subdomains", "ips", "urls", "emails"):
        results[key] = sorted(results[key])

    return results

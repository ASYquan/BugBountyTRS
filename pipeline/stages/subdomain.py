"""Subdomain discovery stage.

Consumes root domains from scope_targets stream.
Runs subfinder (passive enumeration) and feeds discovered subdomains
into the recon_subdomains stream.
"""

import json
import subprocess
import logging
import tempfile
from pathlib import Path

from ..core.worker import BaseWorker
from ..core.config import get_config

log = logging.getLogger(__name__)


class SubdomainWorker(BaseWorker):
    name = "subdomain"
    input_stream = "scope_targets"
    output_streams = ["recon_subdomains"]

    def dedup_key(self, data: dict) -> str:
        return f"subdomain:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        domain = data.get("domain")
        program = data.get("program")
        program_id = data.get("program_id")

        if not domain:
            return []

        log.info(f"[subdomain] Enumerating subdomains for {domain} ({program})")

        subdomains = set()

        # Run subfinder
        sf_results = self._run_subfinder(domain)
        subdomains.update(sf_results)

        # Run amass passive (if available)
        amass_results = self._run_amass_passive(domain)
        subdomains.update(amass_results)

        # Always include the root domain itself
        subdomains.add(domain)

        log.info(f"[subdomain] Found {len(subdomains)} subdomains for {domain}")

        # Store in DB and publish
        results = []
        for sub in subdomains:
            sub = sub.strip().lower().rstrip(".")
            if not sub:
                continue

            self.storage.upsert_subdomain(program_id, sub, source="subfinder")

            results.append({
                "program": program,
                "program_id": program_id,
                "domain": sub,
                "parent_domain": domain,
            })

        return results

    def _run_subfinder(self, domain: str) -> set[str]:
        cfg = get_config()["tools"].get("subfinder", {})
        threads = cfg.get("threads", 30)
        timeout = cfg.get("timeout", 30)

        try:
            result = subprocess.run(
                [
                    "subfinder", "-d", domain,
                    "-silent",
                    "-t", str(threads),
                    "-timeout", str(timeout),
                    "-all",
                ],
                capture_output=True, text=True, timeout=300,
            )
            return {line.strip() for line in result.stdout.splitlines() if line.strip()}
        except FileNotFoundError:
            log.warning("subfinder not found, skipping")
            return set()
        except subprocess.TimeoutExpired:
            log.warning(f"subfinder timed out for {domain}")
            return set()

    def _run_amass_passive(self, domain: str) -> set[str]:
        try:
            result = subprocess.run(
                [
                    "amass", "enum", "-passive",
                    "-d", domain,
                    "-timeout", "5",
                ],
                capture_output=True, text=True, timeout=600,
            )
            return {line.strip() for line in result.stdout.splitlines() if line.strip()}
        except FileNotFoundError:
            log.debug("amass not found, skipping")
            return set()
        except subprocess.TimeoutExpired:
            log.warning(f"amass timed out for {domain}")
            return set()

"""Apex domain discovery stage.

Expands a company name or known domain into the full set of apex domains
the company owns, using:
  1. tenant_domains.sh — finds all email domains managed via Microsoft tenant
     (downloaded from Michael Vanusen's snapshot of the Microsoft tenant API before shutdown)
  2. Existing scope wildcards — extracts apex domains from *.domain.com entries

Publishes discovered apex domains back into scope_targets so the full
subdomain enumeration pipeline runs on each.
"""

import logging
import re
import subprocess
from pathlib import Path

from ..core.worker import BaseWorker
from ..core.config import get_config
from .notification import notify

log = logging.getLogger(__name__)


class ApexDiscoveryWorker(BaseWorker):
    """Discover additional apex domains for a program's company."""

    name = "apex_discovery"
    input_stream = "scope_targets"
    output_streams = ["scope_targets"]  # Feed new apexes back into the pipeline

    def dedup_key(self, data: dict) -> str:
        return f"apex:{data.get('program', '')}:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        domain = data.get("domain", "")
        program = data.get("program", "")
        program_id = data.get("program_id")

        if not domain or not program:
            return []

        # Only run apex discovery on root/apex domains, not subdomains
        if domain.count(".") > 1:
            return []

        cfg = get_config().get("apex_discovery", {})
        if not cfg.get("enabled", True):
            return []

        log.info(f"[apex] Discovering apex domains for {domain} ({program})")

        found = set()

        # --- tenant_domains.sh ---
        tenant_results = self._run_tenant_domains(domain, cfg)
        found.update(tenant_results)

        # Extract company name from domain (e.g. "visma.com" -> "visma")
        company = domain.split(".")[0]
        if company != domain.split(".")[0]:
            tenant_by_name = self._run_tenant_domains(company, cfg)
            found.update(tenant_by_name)

        if not found:
            return []

        # Filter out already-known domains and non-domain strings
        domain_pattern = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
        new_apexes = []
        for apex in found:
            apex = apex.strip().lower().rstrip(".")
            if not apex or not domain_pattern.match(apex):
                continue
            if apex == domain:
                continue

            # Store in DB
            self.storage.upsert_apex_domain(program_id, apex, source="tenant_domains")
            new_apexes.append(apex)

        if new_apexes:
            log.info(f"[apex] Found {len(new_apexes)} new apex domains for {domain}: {new_apexes[:5]}...")
            notify(
                "new_apex_domain",
                f"Found {len(new_apexes)} new apex domains from tenant discovery for {domain}",
                program=program,
            )

        return [
            {
                "program": program,
                "program_id": program_id,
                "domain": apex,
                "parent_domain": domain,
                "source": "apex_discovery",
            }
            for apex in new_apexes
        ]

    def _run_tenant_domains(self, query: str, cfg: dict) -> set[str]:
        """Run tenant_domains.sh to find Microsoft-tenant-managed domains."""
        script = cfg.get("tenant_domains_script", "./scripts/tenant_domains.sh")
        script_path = Path(script)

        if not script_path.exists():
            log.debug(f"[apex] tenant_domains.sh not found at {script_path}, skipping")
            return set()

        try:
            result = subprocess.run(
                ["bash", str(script_path), "-d", query],
                capture_output=True, text=True, timeout=120,
            )
            domains = set()
            for line in result.stdout.splitlines():
                line = line.strip().lower()
                if line and "." in line and not line.startswith("#"):
                    domains.add(line)
            log.info(f"[apex] tenant_domains: {len(domains)} domains for query '{query}'")
            return domains
        except FileNotFoundError:
            log.debug("[apex] bash not found")
            return set()
        except subprocess.TimeoutExpired:
            log.warning(f"[apex] tenant_domains.sh timed out for {query}")
            return set()
        except Exception as e:
            log.warning(f"[apex] tenant_domains.sh failed: {e}")
            return set()

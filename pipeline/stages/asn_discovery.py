"""ASN and seed domain discovery stage.

Discovers ASNs, IP ranges, and seed domains for a target organization.
Runs before subdomain enumeration to expand the attack surface.

Tools used:
  - asnmap (ProjectDiscovery) - fast ASN → IP range mapping
  - amass intel - ASN discovery + seed domain extraction
  - Team Cymru DNS - IP → ASN reverse lookup
  - whois/RADB - ASN org info
"""

import json
import subprocess
import logging
import socket
import tempfile
from pathlib import Path

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.storage import Storage

log = logging.getLogger(__name__)


class ASNDiscoveryWorker(BaseWorker):
    """Discovers ASNs and IP ranges for target organizations.

    Consumes from scope_targets, publishes discovered seed domains
    back to scope_targets and IP ranges to recon_resolved.
    """
    name = "asn_discovery"
    input_stream = "scope_targets"
    output_streams = ["recon_subdomains"]

    def dedup_key(self, data: dict) -> str:
        return f"asn:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        domain = data.get("domain")
        program = data.get("program")
        program_id = data.get("program_id")

        if not domain:
            return []

        log.info(f"[asn] Discovering ASNs for {domain} ({program})")

        results = []
        asns = set()
        ip_ranges = set()

        # Step 1: Resolve domain to IP for initial ASN lookup
        ip = self._resolve_ip(domain)
        if ip:
            cymru_asns = self._cymru_lookup(ip)
            asns.update(cymru_asns)

        # Step 2: asnmap — org and domain based lookup
        asnmap_results = self._run_asnmap(domain)
        for r in asnmap_results:
            if r.get("asn"):
                asns.add(r["asn"])
            if r.get("cidr"):
                ip_ranges.add(r["cidr"])

        # Step 3: amass intel — discover more seed domains from ASNs
        seed_domains = set()
        for asn in asns:
            seeds = self._run_amass_intel(asn)
            seed_domains.update(seeds)

        # Step 4: asnmap on org name (if we can extract it)
        org_ranges = self._run_asnmap_org(domain)
        for r in org_ranges:
            if r.get("asn"):
                asns.add(r["asn"])
            if r.get("cidr"):
                ip_ranges.add(r["cidr"])

        log.info(f"[asn] Found {len(asns)} ASNs, {len(ip_ranges)} IP ranges, "
                 f"{len(seed_domains)} seed domains for {domain}")

        # Store ASN data
        self._store_asn_data(program_id, domain, asns, ip_ranges)

        # Publish seed domains as new targets for subdomain enumeration
        for seed in seed_domains:
            seed = seed.strip().lower().rstrip(".")
            if not seed or seed == domain:
                continue
            self.storage.upsert_subdomain(program_id, seed, source="amass-intel")
            results.append({
                "program": program,
                "program_id": program_id,
                "domain": seed,
                "parent_domain": domain,
            })

        return results

    def _resolve_ip(self, domain: str) -> str | None:
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    def _cymru_lookup(self, ip: str) -> set[str]:
        """Team Cymru DNS-based ASN lookup (fastest method)."""
        try:
            octets = ip.split(".")
            reversed_ip = ".".join(reversed(octets))
            result = subprocess.run(
                ["dig", "+short", f"{reversed_ip}.origin.asn.cymru.com", "TXT"],
                capture_output=True, text=True, timeout=10,
            )
            asns = set()
            for line in result.stdout.strip().splitlines():
                line = line.strip('" ')
                if line:
                    parts = line.split("|")
                    asn_str = parts[0].strip()
                    if asn_str:
                        for asn in asn_str.split():
                            asns.add(f"AS{asn}" if not asn.startswith("AS") else asn)
            return asns
        except Exception as e:
            log.debug(f"Cymru lookup failed for {ip}: {e}")
            return set()

    def _run_asnmap(self, domain: str) -> list[dict]:
        """Run asnmap for domain-based ASN lookup."""
        try:
            result = subprocess.run(
                ["asnmap", "-d", domain, "-json"],
                capture_output=True, text=True, timeout=30,
            )
            results = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return results
        except FileNotFoundError:
            log.debug("asnmap not found, skipping")
            return []
        except Exception as e:
            log.warning(f"asnmap failed for {domain}: {e}")
            return []

    def _run_asnmap_org(self, domain: str) -> list[dict]:
        """Run asnmap with org name derived from domain."""
        # Extract likely org name from domain (e.g., "visma" from "visma.com")
        org_name = domain.split(".")[0]
        if len(org_name) < 3:
            return []

        try:
            result = subprocess.run(
                ["asnmap", "-org", org_name, "-json"],
                capture_output=True, text=True, timeout=30,
            )
            results = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return results
        except FileNotFoundError:
            return []
        except Exception as e:
            log.debug(f"asnmap org lookup failed for {org_name}: {e}")
            return []

    def _run_amass_intel(self, asn: str) -> set[str]:
        """Use amass intel to find seed domains from an ASN."""
        asn_num = asn.replace("AS", "")
        try:
            result = subprocess.run(
                ["amass", "intel", "-asn", asn_num],
                capture_output=True, text=True, timeout=300,
            )
            return {line.strip().lower() for line in result.stdout.splitlines() if line.strip()}
        except FileNotFoundError:
            log.debug("amass not found, skipping intel mode")
            return set()
        except subprocess.TimeoutExpired:
            log.warning(f"amass intel timed out for {asn}")
            return set()

    def _store_asn_data(self, program_id: int, domain: str, asns: set, ip_ranges: set):
        """Store ASN discovery results in the database."""
        with self.storage._conn() as conn:
            for asn in asns:
                conn.execute(
                    """INSERT OR IGNORE INTO asn_data
                       (program_id, domain, asn, ip_ranges_json, discovered_at)
                       VALUES (?, ?, ?, ?, datetime('now'))""",
                    (program_id, domain, asn, json.dumps(list(ip_ranges))),
                )


# ─── Standalone functions for CLI ───────────────────────────────


def discover_asns(domain: str) -> dict:
    """Run full ASN discovery for a domain. Returns dict with asns, ranges, seeds."""
    import socket

    asns = set()
    ip_ranges = set()
    seed_domains = set()

    # Resolve to IP
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        ip = None

    # Cymru
    if ip:
        try:
            octets = ip.split(".")
            reversed_ip = ".".join(reversed(octets))
            result = subprocess.run(
                ["dig", "+short", f"{reversed_ip}.origin.asn.cymru.com", "TXT"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.strip().splitlines():
                line = line.strip('" ')
                if line:
                    parts = line.split("|")
                    for a in parts[0].strip().split():
                        asns.add(f"AS{a}" if not a.startswith("AS") else a)
                    if len(parts) > 1 and parts[1].strip():
                        ip_ranges.add(parts[1].strip())
        except Exception:
            pass

    # asnmap domain
    try:
        result = subprocess.run(
            ["asnmap", "-d", domain, "-json"],
            capture_output=True, text=True, timeout=30,
        )
        for line in result.stdout.splitlines():
            try:
                data = json.loads(line.strip())
                if data.get("as_number"):
                    asns.add(f"AS{data['as_number']}")
                if data.get("as_range"):
                    ip_ranges.add(data["as_range"])
            except (json.JSONDecodeError, KeyError):
                continue
    except FileNotFoundError:
        pass

    # asnmap org
    org_name = domain.split(".")[0]
    if len(org_name) >= 3:
        try:
            result = subprocess.run(
                ["asnmap", "-org", org_name, "-json"],
                capture_output=True, text=True, timeout=30,
            )
            for line in result.stdout.splitlines():
                try:
                    data = json.loads(line.strip())
                    if data.get("as_number"):
                        asns.add(f"AS{data['as_number']}")
                    if data.get("as_range"):
                        ip_ranges.add(data["as_range"])
                except (json.JSONDecodeError, KeyError):
                    continue
        except FileNotFoundError:
            pass

    # amass intel for seed domains
    for asn in asns:
        asn_num = asn.replace("AS", "")
        try:
            result = subprocess.run(
                ["amass", "intel", "-asn", asn_num],
                capture_output=True, text=True, timeout=300,
            )
            for line in result.stdout.splitlines():
                if line.strip():
                    seed_domains.add(line.strip().lower())
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return {
        "ip": ip,
        "asns": sorted(asns),
        "ip_ranges": sorted(ip_ranges),
        "seed_domains": sorted(seed_domains - {domain}),
    }

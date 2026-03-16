"""Certificate-based domain discovery stage.

Uses Caduceus (g0ldencybersec/Caduceus) to scan IP ranges and CIDRs for
TLS certificates, extracting hidden domains from CN and SAN fields.

This runs AFTER ASN discovery — it takes the discovered IP ranges/CIDRs
and scans them for certificates, finding domains that DNS and CT logs miss.

Flow: ASN Discovery → IP Ranges → Caduceus (cert scan) → New Subdomains

Install: go install github.com/g0ldencybersec/Caduceus/cmd/caduceus@latest
Requires: CGO enabled, gcc installed (sudo apt install gcc)
"""

import json
import subprocess
import logging
import tempfile
from pathlib import Path

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.storage import Storage

log = logging.getLogger(__name__)


class CertDiscoveryWorker(BaseWorker):
    """Scans IP ranges for TLS certificates to discover hidden domains.

    Consumes from scope_targets (after ASN discovery populates IP ranges).
    Publishes discovered domains to recon_subdomains.
    """
    name = "cert_discovery"
    input_stream = "scope_targets"
    output_streams = ["recon_subdomains"]

    def dedup_key(self, data: dict) -> str:
        return f"cert_discovery:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        domain = data.get("domain")
        program = data.get("program")
        program_id = data.get("program_id")

        if not domain:
            return []

        log.info(f"[cert_discovery] Starting cert scan for {domain} ({program})")

        # Get IP ranges from ASN data in DB
        cidrs = self._get_cidrs(program_id, domain)
        if not cidrs:
            log.info(f"[cert_discovery] No CIDRs found for {domain}, skipping")
            return []

        log.info(f"[cert_discovery] Scanning {len(cidrs)} CIDRs for {domain}")

        cfg = get_config().get("tools", {}).get("caduceus", {})
        cert_domains = self._run_caduceus(cidrs, cfg)

        # Filter to only domains related to target
        target_parts = domain.split(".")
        root_domain = ".".join(target_parts[-2:]) if len(target_parts) >= 2 else domain

        in_scope = {d for d in cert_domains if d.endswith(f".{root_domain}") or d == root_domain}
        out_of_scope = cert_domains - in_scope

        log.info(f"[cert_discovery] Found {len(in_scope)} in-scope, "
                 f"{len(out_of_scope)} out-of-scope domains for {domain}")

        # Store and publish in-scope domains
        results = []
        for sub in in_scope:
            sub = sub.strip().lower().rstrip(".")
            if not sub:
                continue

            self.storage.upsert_subdomain(program_id, sub, source="caduceus")
            results.append({
                "program": program,
                "program_id": program_id,
                "domain": sub,
                "parent_domain": domain,
                "source": "caduceus",
            })

        return results

    def _get_cidrs(self, program_id: int, domain: str) -> list[str]:
        """Get IP ranges/CIDRs from ASN data in the database."""
        cidrs = []
        try:
            with self.storage._conn() as conn:
                rows = conn.execute(
                    "SELECT ip_ranges_json FROM asn_data WHERE program_id = ? AND domain = ?",
                    (program_id, domain),
                ).fetchall()

                for row in rows:
                    ranges_json = row["ip_ranges_json"]
                    if ranges_json:
                        ranges = json.loads(ranges_json)
                        if isinstance(ranges, list):
                            cidrs.extend(ranges)
                        elif isinstance(ranges, str):
                            cidrs.append(ranges)
        except Exception as e:
            log.warning(f"[cert_discovery] Failed to get CIDRs from DB: {e}")

        return list(set(cidrs))

    def _run_caduceus(self, cidrs: list[str], cfg: dict) -> set[str]:
        """Run Caduceus on a list of CIDRs and return discovered domains."""
        concurrency = cfg.get("concurrency", 100)
        ports = cfg.get("ports", "443,8443,8080,4443")
        timeout = cfg.get("timeout", 4)
        include_wildcards = cfg.get("include_wildcards", False)

        # Write CIDRs to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(cidrs))
            tmp_path = tmp.name

        cmd = [
            "caduceus",
            "-i", tmp_path,
            "-c", str(concurrency),
            "-p", ports,
            "-t", str(timeout),
            "-j",  # JSONL output for structured parsing
        ]

        if include_wildcards:
            cmd.append("-wc")

        domains = set()
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=cfg.get("scan_timeout", 1800),
            )

            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    cert_info = json.loads(line)
                    # Extract all domains from cert
                    for d in cert_info.get("domains", []):
                        d = d.strip().lower().rstrip(".")
                        if d and not d.startswith("*"):
                            domains.add(d)
                    # Also grab SAN entries
                    for d in cert_info.get("san", []):
                        d = d.strip().lower().rstrip(".")
                        if d and not d.startswith("*"):
                            domains.add(d)
                except json.JSONDecodeError:
                    # Might be plain domain output if -j not supported
                    d = line.strip().lower().rstrip(".")
                    if d and not d.startswith("*") and "." in d:
                        domains.add(d)

        except FileNotFoundError:
            log.warning("[cert_discovery] caduceus not found. "
                        "Install: go install github.com/g0ldencybersec/Caduceus/cmd/caduceus@latest")
        except subprocess.TimeoutExpired:
            log.warning("[cert_discovery] caduceus timed out")
        except Exception as e:
            log.warning(f"[cert_discovery] caduceus failed: {e}")
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        return domains


# ─── Standalone functions for CLI ───────────────────────────────


def scan_cidrs_for_certs(cidrs: list[str], ports: str = "443,8443",
                         concurrency: int = 100, timeout: int = 4) -> list[dict]:
    """Scan CIDRs for TLS certificates. Returns list of cert info dicts."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(cidrs))
        tmp_path = tmp.name

    results = []
    try:
        result = subprocess.run(
            ["caduceus", "-i", tmp_path, "-c", str(concurrency),
             "-p", ports, "-t", str(timeout), "-j"],
            capture_output=True, text=True, timeout=1800,
        )

        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        raise FileNotFoundError(
            "caduceus not found. Install: go install github.com/g0ldencybersec/Caduceus/cmd/caduceus@latest"
        )
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return results


def scan_ips_for_domains(ips: list[str], target_domain: str = None,
                         ports: str = "443,8443") -> set[str]:
    """Scan IPs for certs and return discovered domain names.
    If target_domain is provided, only return matching subdomains."""
    certs = scan_cidrs_for_certs(ips, ports=ports)

    domains = set()
    for cert in certs:
        for d in cert.get("domains", []):
            d = d.strip().lower().rstrip(".")
            if d and not d.startswith("*"):
                if target_domain is None or d.endswith(f".{target_domain}") or d == target_domain:
                    domains.add(d)

    return domains

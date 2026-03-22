"""DNS resolution stage.

Consumes subdomains from recon_subdomains stream.
Resolves DNS records and publishes resolved hosts for port scanning.
Feeds newly discovered subdomains back into the pipeline.
"""

import subprocess
import socket
import logging
import json

from ..core.worker import BaseWorker
from ..core.config import get_config
from .scope import ScopeManager

log = logging.getLogger(__name__)


class DNSResolveWorker(BaseWorker):
    name = "dns_resolve"
    input_stream = "recon_subdomains"
    output_streams = ["recon_resolved"]

    def on_start(self):
        self._scope = ScopeManager()
        self._scope.load_programs()

    def dedup_key(self, data: dict) -> str:
        return f"dns:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        domain = data.get("domain")
        program = data.get("program")
        program_id = data.get("program_id")

        if not domain:
            return []

        # Skip domains that are out of scope — prevents noise from cert/passive DNS
        # discovery tools that return unrelated domains (e.g., example.com entries)
        in_scope, _ = self._scope.is_in_scope(domain, program_name=program)
        if not in_scope:
            log.debug(f"[dns] Skipping out-of-scope domain: {domain}")
            return []

        records = self._resolve(domain)

        if not records:
            log.debug(f"[dns] No records for {domain}")
            return []

        # Store DNS records
        subdomain_id = self.storage.upsert_subdomain(program_id, domain, source="dns")
        with self.storage._conn() as conn:
            for rec in records:
                conn.execute(
                    """INSERT OR IGNORE INTO dns_records (subdomain_id, record_type, value, updated_at)
                       VALUES (?, ?, ?, datetime('now'))""",
                    (subdomain_id, rec["type"], rec["value"]),
                )

        # Get A/AAAA records for port scanning
        ips = [r["value"] for r in records if r["type"] in ("A", "AAAA")]
        cnames = [r["value"] for r in records if r["type"] == "CNAME"]

        results = []
        for ip in ips:
            results.append({
                "program": program,
                "program_id": program_id,
                "domain": domain,
                "ip": ip,
                "subdomain_id": subdomain_id,
            })

        # Check CNAMEs for potential takeover (dangling CNAME)
        for cname in cnames:
            cname_ips = self._resolve_simple(cname)
            if not cname_ips:
                # Potential subdomain takeover!
                self.storage.add_finding(
                    program_id,
                    subdomain_id=subdomain_id,
                    tool="dns_resolve",
                    severity="high",
                    title=f"Potential subdomain takeover: {domain}",
                    description=f"CNAME {cname} does not resolve. Possible dangling CNAME.",
                    url=domain,
                    matched_at=domain,
                    evidence=json.dumps({"domain": domain, "cname": cname}),
                )
                log.warning(f"[dns] Potential subdomain takeover: {domain} -> {cname} (NXDOMAIN)")

        return results

    def _resolve(self, domain: str) -> list[dict]:
        """Resolve DNS using system resolver + dig for full records."""
        records = []

        # Try A records
        for rtype in ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]:
            try:
                result = subprocess.run(
                    ["dig", "+short", "+time=5", "+tries=2", domain, rtype],
                    capture_output=True, text=True, timeout=15,
                )
                for line in result.stdout.splitlines():
                    val = line.strip().rstrip(".")
                    # Skip dig error/comment lines (e.g. ";; comm error", "[thc ->")
                    if val and not val.startswith(";") and not val.startswith("["):
                        records.append({"type": rtype, "value": val})
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Fallback to Python socket for A records if dig fails
        if not any(r["type"] == "A" for r in records):
            try:
                ips = socket.getaddrinfo(domain, None, socket.AF_INET)
                for info in ips:
                    records.append({"type": "A", "value": info[4][0]})
            except socket.gaierror:
                pass

        return records

    def _resolve_simple(self, domain: str) -> list[str]:
        """Quick A record resolution."""
        try:
            ips = socket.getaddrinfo(domain.rstrip("."), None, socket.AF_INET)
            return list({info[4][0] for info in ips})
        except socket.gaierror:
            return []

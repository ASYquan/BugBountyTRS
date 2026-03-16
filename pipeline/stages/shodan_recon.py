"""Shodan reconnaissance stage — Karma-style signature-driven scanning.

Loads configurable dork signatures from config/shodan_signatures.yml.
Each signature defines a Shodan query template, severity, and optional
result filters (headers, titles, CDN exclusion, ports, etc.).

Requires: SHODAN_API_KEY env var or config entry.
"""

import json
import os
import logging
import time
from pathlib import Path

import yaml

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.storage import Storage

log = logging.getLogger(__name__)

SIGNATURES_PATH = Path(__file__).parent.parent.parent / "config" / "shodan_signatures.yml"


def load_signatures(path: Path = None, categories: list[str] = None,
                    tags: list[str] = None) -> list[dict]:
    """Load and filter signatures from YAML file."""
    path = path or SIGNATURES_PATH
    with open(path) as f:
        data = yaml.safe_load(f)

    sigs = data.get("signatures", [])

    # Filter disabled
    sigs = [s for s in sigs if s.get("enabled", True)]

    # Filter by category
    if categories:
        sigs = [s for s in sigs if s.get("category") in categories]

    # Filter by tags (any match)
    if tags:
        sigs = [s for s in sigs if set(s.get("tags", [])) & set(tags)]

    return sigs


def interpolate_query(query: str, domain: str) -> str:
    """Replace template variables in a Shodan query."""
    # {domain} -> target domain
    result = query.replace("{domain}", domain)

    # {domain_org} -> org name (first part of domain, e.g., "visma" from "visma.com")
    org = domain.split(".")[0]
    result = result.replace("{domain_org}", org)

    return result


def apply_filters(match: dict, filters: dict) -> bool:
    """Apply filter rules to a Shodan match. Returns True if match passes."""
    if not filters:
        return True

    # Header inclusion filter
    include_headers = filters.get("include_headers", [])
    if include_headers:
        match_headers = match.get("http", {}).get("headers", "") or ""
        if isinstance(match_headers, dict):
            header_keys = [k.lower() for k in match_headers.keys()]
        else:
            header_keys = [h.split(":")[0].strip().lower() for h in str(match_headers).split("\n")]
        if not any(h.lower() in header_keys for h in include_headers):
            return False

    # Header exclusion filter
    exclude_headers = filters.get("exclude_headers", [])
    if exclude_headers:
        match_headers = match.get("http", {}).get("headers", "") or ""
        if isinstance(match_headers, dict):
            header_keys = [k.lower() for k in match_headers.keys()]
        else:
            header_keys = [h.split(":")[0].strip().lower() for h in str(match_headers).split("\n")]
        if any(h.lower() in header_keys for h in exclude_headers):
            return False

    # Title inclusion
    include_title = filters.get("include_title", [])
    if include_title:
        title = (match.get("http", {}).get("title", "") or "").lower()
        if not any(t.lower() in title for t in include_title):
            return False

    # Title exclusion
    exclude_title = filters.get("exclude_title", [])
    if exclude_title:
        title = (match.get("http", {}).get("title", "") or "").lower()
        if any(t.lower() in title for t in exclude_title):
            return False

    # Product inclusion
    include_products = filters.get("include_products", [])
    if include_products:
        product = (match.get("product", "") or "").lower()
        if not any(p.lower() in product for p in include_products):
            return False

    # Product exclusion
    exclude_products = filters.get("exclude_products", [])
    if exclude_products:
        product = (match.get("product", "") or "").lower()
        if any(p.lower() in product for p in exclude_products):
            return False

    # Port inclusion
    include_ports = filters.get("include_ports", [])
    if include_ports:
        port = match.get("port", 0)
        if port not in include_ports:
            return False

    # Port exclusion
    exclude_ports = filters.get("exclude_ports", [])
    if exclude_ports:
        port = match.get("port", 0)
        if port in exclude_ports:
            return False

    return True


def is_cdn_ip(match: dict) -> bool:
    """Check if a Shodan match is from a known CDN/WAF provider."""
    cdn_indicators = [
        "cloudflare", "cloudfront", "akamai", "akamaiGHost",
        "incapsula", "sucuri", "fastly", "maxcdn", "stackpath",
        "edgecast", "limelight", "cdn77", "keycdn",
    ]

    org = (match.get("org", "") or "").lower()
    isp = (match.get("isp", "") or "").lower()
    product = (match.get("product", "") or "").lower()
    data = (match.get("data", "") or "").lower()

    combined = f"{org} {isp} {product} {data}"
    return any(cdn in combined for cdn in cdn_indicators)


class ShodanReconWorker(BaseWorker):
    """Shodan-based passive reconnaissance using configurable signatures.

    Loads dork signatures from config/shodan_signatures.yml and queries
    Shodan for each enabled signature. Results are filtered, then published.
    """
    name = "shodan_recon"
    input_stream = "scope_targets"
    output_streams = ["recon_resolved", "vuln_findings"]

    def __init__(self):
        super().__init__()
        self._api = None
        self._api_key = None
        self._signatures = []

    def on_start(self):
        self._api_key = (
            os.environ.get("SHODAN_API_KEY")
            or get_config().get("shodan", {}).get("api_key")
        )
        if not self._api_key:
            log.warning("[shodan] No API key configured. Set SHODAN_API_KEY or config shodan.api_key")
            return

        try:
            import shodan
            self._api = shodan.Shodan(self._api_key)
            info = self._api.info()
            log.info(f"[shodan] API connected. Credits: {info.get('query_credits', '?')}")
        except ImportError:
            log.error("[shodan] 'shodan' package not installed. Run: pip install shodan")
            return
        except Exception as e:
            log.error(f"[shodan] API connection failed: {e}")
            return

        # Load signatures
        try:
            cfg = get_config().get("shodan", {})
            categories = cfg.get("categories")
            tags = cfg.get("tags")
            self._signatures = load_signatures(categories=categories, tags=tags)
            log.info(f"[shodan] Loaded {len(self._signatures)} signatures")
        except Exception as e:
            log.error(f"[shodan] Failed to load signatures: {e}")
            self._signatures = []

    def dedup_key(self, data: dict) -> str:
        return f"shodan:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        if not self._api or not self._signatures:
            return []

        domain = data.get("domain")
        program = data.get("program")
        program_id = data.get("program_id")

        if not domain:
            return []

        log.info(f"[shodan] Running {len(self._signatures)} signatures against {domain}")
        results = []
        seen_ips = set()

        for sig in self._signatures:
            query = interpolate_query(sig["query"], domain)
            severity = sig.get("severity", "info")
            filters = sig.get("filters", {})
            cdn_exclude = filters.get("cdn_exclude", False)

            try:
                self._rate_limit()
                search_results = self._api.search(query, limit=100)

                for match in search_results.get("matches", []):
                    ip = match.get("ip_str", "")

                    # CDN filter
                    if cdn_exclude and is_cdn_ip(match):
                        continue

                    # Apply custom filters
                    if not apply_filters(match, filters):
                        continue

                    # min_port_count filter (needs host lookup)
                    min_ports = filters.get("min_port_count")
                    if min_ports and len(match.get("ports", [])) < min_ports:
                        continue

                    # Publish IP to recon_resolved (deduplicated)
                    if ip and ip not in seen_ips:
                        seen_ips.add(ip)
                        results.append({
                            "_stream": self.mq.stream_name("recon_resolved"),
                            "program": program,
                            "program_id": program_id,
                            "domain": domain,
                            "ip": ip,
                            "source": "shodan",
                            "ports": match.get("ports", []),
                            "os": match.get("os"),
                            "org": match.get("org"),
                        })

                    # Store in shodan_hosts table
                    self._store_host(program_id, ip, domain, match)

                    # Publish finding for notable signatures
                    if severity in ("medium", "high", "critical"):
                        results.append({
                            "_stream": self.mq.stream_name("vuln_findings"),
                            "program": program,
                            "program_id": program_id,
                            "tool": "shodan",
                            "severity": severity,
                            "title": f"{sig['name']}: {ip}:{match.get('port', '?')}",
                            "url": f"https://{domain}",
                            "matched_at": f"{ip}:{match.get('port', '')}",
                            "evidence": self._build_evidence(sig, match),
                        })

                    # Check for CVEs in Shodan data
                    for vuln in match.get("vulns", []):
                        results.append({
                            "_stream": self.mq.stream_name("vuln_findings"),
                            "program": program,
                            "program_id": program_id,
                            "tool": "shodan",
                            "severity": "high",
                            "title": f"{vuln} on {ip}",
                            "url": f"https://{domain}",
                            "matched_at": ip,
                            "cve_id": vuln,
                            "evidence": f"Signature: {sig['name']}\nIP: {ip}\nPort: {match.get('port')}",
                        })

            except Exception as e:
                log.debug(f"[shodan] Query failed for sig '{sig['name']}': {e}")
                continue

        log.info(f"[shodan] Completed scan for {domain}: {len(seen_ips)} IPs, {len(results)} results")
        return results

    def _rate_limit(self):
        """Respect Shodan API rate limits."""
        time.sleep(1.1)  # Free tier: 1 request/second

    def _build_evidence(self, sig: dict, match: dict) -> str:
        """Build evidence string from a signature match."""
        parts = [
            f"Signature: {sig['name']}",
            f"Query: {sig['query']}",
            f"IP: {match.get('ip_str', '')}",
            f"Port: {match.get('port', '')}",
        ]
        if match.get("http", {}).get("title"):
            parts.append(f"Title: {match['http']['title']}")
        if match.get("product"):
            parts.append(f"Product: {match['product']}")
        if match.get("org"):
            parts.append(f"Org: {match['org']}")
        return "\n".join(parts)

    def _store_host(self, program_id: int, ip: str, domain: str, match: dict):
        """Store Shodan host data in the database."""
        try:
            with self.storage._conn() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO shodan_hosts
                       (program_id, ip, domain, ports_json, os, org, vulns_json, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
                    (
                        program_id, ip, domain,
                        json.dumps(match.get("ports", [])),
                        match.get("os"),
                        match.get("org"),
                        json.dumps(match.get("vulns", [])),
                    ),
                )
        except Exception as e:
            log.debug(f"[shodan] Failed to store host {ip}: {e}")


# ─── Standalone functions for CLI ───────────────────────────────


def shodan_scan_domain(domain: str, api_key: str, categories: list[str] = None,
                       tags: list[str] = None) -> dict:
    """Run signature-based Shodan scan for a domain. Returns structured results."""
    import shodan
    api = shodan.Shodan(api_key)

    sigs = load_signatures(categories=categories, tags=tags)
    results = {
        "domain": domain,
        "ips": {},
        "findings": [],
        "vulns": [],
        "stats": {"signatures_run": 0, "matches": 0, "ips_found": 0},
    }

    for sig in sigs:
        query = interpolate_query(sig["query"], domain)
        filters = sig.get("filters", {})
        cdn_exclude = filters.get("cdn_exclude", False)
        results["stats"]["signatures_run"] += 1

        try:
            time.sleep(1.1)
            search = api.search(query, limit=100)

            for match in search.get("matches", []):
                ip = match.get("ip_str", "")

                if cdn_exclude and is_cdn_ip(match):
                    continue
                if not apply_filters(match, filters):
                    continue

                results["stats"]["matches"] += 1

                # Collect IP data
                if ip not in results["ips"]:
                    results["ips"][ip] = {
                        "ports": set(),
                        "org": match.get("org"),
                        "os": match.get("os"),
                        "hostnames": set(),
                        "signatures_matched": [],
                    }
                    results["stats"]["ips_found"] += 1

                results["ips"][ip]["ports"].add(match.get("port", 0))
                for h in match.get("hostnames", []):
                    results["ips"][ip]["hostnames"].add(h)
                results["ips"][ip]["signatures_matched"].append(sig["name"])

                # Collect findings
                if sig.get("severity") in ("medium", "high", "critical"):
                    results["findings"].append({
                        "signature": sig["name"],
                        "severity": sig["severity"],
                        "ip": ip,
                        "port": match.get("port"),
                        "title": match.get("http", {}).get("title", ""),
                        "product": match.get("product", ""),
                    })

                # Collect CVEs
                for vuln in match.get("vulns", []):
                    results["vulns"].append({"cve": vuln, "ip": ip, "signature": sig["name"]})

        except Exception as e:
            log.debug(f"Shodan query failed for '{sig['name']}': {e}")
            continue

    # Convert sets to sorted lists for serialization
    for ip_data in results["ips"].values():
        ip_data["ports"] = sorted(ip_data["ports"])
        ip_data["hostnames"] = sorted(ip_data["hostnames"])

    return results


def shodan_internetdb(ip: str) -> dict | None:
    """Query Shodan InternetDB (free, no API key) for a single IP."""
    import requests
    try:
        resp = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None

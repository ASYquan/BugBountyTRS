"""Asset graph analysis.

Builds a relationship graph across all discovered assets for a program.
Surfaces cross-asset patterns that individual stages miss:

  - Shared IP clusters: multiple subdomains on one IP → vhost opportunities
  - Naming clusters: dev/staging/api/jenkins prefixes → predict undiscovered siblings
  - Orphan JS hosts: hostnames in JS files not in the subdomain list → shadow APIs
  - Wayback shadow hosts: hosts in historical URLs not in current subdomain list

Two modes:
  1. Worker: consumes recon_resolved, runs analysis hourly per program
  2. Standalone: call analyze(storage, program_id) directly from CLI

The transcript insight: "The internet is connected. Start mapping subdomains, APIs,
emails, cloud buckets, GitHub links, JavaScript, IPs — you'll start spotting patterns.
Naming styles, shared resources, misconfigured DNS. Those patterns lead to the gaps."
"""

import json
import logging
import re
from collections import defaultdict
from urllib.parse import urlparse

from ..core.worker import BaseWorker

log = logging.getLogger(__name__)

_ENV_KEYWORDS = {
    "dev", "develop", "development", "staging", "stage", "test", "testing",
    "qa", "uat", "preprod", "pre", "beta", "alpha", "demo", "sandbox",
}
_API_KEYWORDS = {
    "api", "api2", "apiv2", "graphql", "rest", "grpc", "gateway",
    "microservice", "internal", "service", "backend", "proxy",
}
_INFRA_KEYWORDS = {
    "jenkins", "gitlab", "github", "jira", "confluence", "sonar", "nexus",
    "artifactory", "kibana", "grafana", "prometheus", "vault", "consul",
    "harbor", "rancher", "k8s", "kubernetes", "argocd", "drone",
}


class AssetGraphWorker(BaseWorker):
    """Cross-asset pattern analysis worker.

    Consumes recon_resolved. Runs full analysis at most once per program per hour
    (dedup key includes hour bucket) to avoid re-running on every subdomain.
    """

    name = "asset_graph"
    input_stream = "recon_resolved"
    output_streams = ["vuln_findings"]

    def dedup_key(self, data: dict) -> str:
        from datetime import datetime
        program_id = data.get("program_id", "unknown")
        hour = datetime.utcnow().strftime("%Y-%m-%d-%H")
        return f"asset_graph:{program_id}:{hour}"

    def process(self, data: dict) -> list[dict]:
        program_id = data.get("program_id")
        program = data.get("program", "")
        if not program_id:
            return []
        return analyze(self.storage, int(program_id), program)


def analyze(storage, program_id: int, program: str = "") -> list[dict]:
    """Run full asset graph analysis. Returns list of finding dicts.

    Can be called directly from CLI or tests without running a worker.
    """
    findings = []
    with storage._conn() as conn:
        findings += _shared_ip_clusters(conn, program_id, program)
        findings += _naming_clusters(conn, program_id, program)
        findings += _orphan_js_hosts(conn, program_id, program)
        findings += _wayback_shadow_hosts(conn, program_id, program)

    log.info(f"[asset_graph] program={program_id} findings={len(findings)}")
    return findings


# ─── Shared IP clusters ──────────────────────────────────────────────────────

def _shared_ip_clusters(conn, program_id: int, program: str) -> list[dict]:
    """Find IPs with multiple subdomains pointing to them.

    Each shared-IP cluster is a vhost opportunity: the server may respond
    differently to different Host: headers. Run vhost_discovery against the IP
    using all known subdomains as the wordlist.
    """
    rows = conn.execute("""
        SELECT p.ip, GROUP_CONCAT(DISTINCT s.domain) AS domains, COUNT(DISTINCT s.domain) AS cnt
        FROM ports p
        JOIN subdomains s ON s.id = p.subdomain_id
        WHERE s.program_id = ?
          AND p.port IN (80, 443, 8080, 8443, 8000, 3000, 5000, 9090)
          AND p.state = 'open'
          AND p.ip IS NOT NULL
        GROUP BY p.ip
        HAVING cnt >= 2
        ORDER BY cnt DESC
        LIMIT 50
    """, (program_id,)).fetchall()

    findings = []
    for row in rows:
        domains = (row["domains"] or "").split(",")
        findings.append({
            "program": program,
            "program_id": program_id,
            "tool": "asset_graph",
            "template_id": f"asset-graph-shared-ip",  # stable per IP via url field
            "severity": "info",
            "title": f"Shared IP {row['ip']} hosts {row['cnt']} subdomains — vhost opportunity",
            "url": f"http://{row['ip']}",  # use IP directly so dedup is stable
            "evidence": json.dumps({
                "ip": row["ip"],
                "subdomain_count": row["cnt"],
                "domains": domains[:20],
                "action": (
                    "Run vhost_discovery against this IP with all known subdomains as wordlist. "
                    "One IP hosting multiple names often means virtual hosting — "
                    "some vhosts may not respond to any known subdomain yet."
                ),
            }),
        })
        log.info(f"[asset_graph] Shared IP {row['ip']} → {row['cnt']} subdomains")

    return findings


# ─── Naming clusters ──────────────────────────────────────────────────────────

def _naming_clusters(conn, program_id: int, program: str) -> list[dict]:
    """Detect naming patterns across subdomains.

    Groups subdomains by environment (dev/staging), API, and infrastructure
    keywords. Each cluster hints at undiscovered siblings.
    """
    rows = conn.execute(
        "SELECT domain FROM subdomains WHERE program_id = ?", (program_id,)
    ).fetchall()
    domains = [r["domain"] for r in rows]
    if not domains:
        return []

    groups: dict[str, list[str]] = defaultdict(list)
    for domain in domains:
        prefix = domain.split(".")[0].lower()
        # Strip numeric suffixes (api2, api-v2, etc.)
        prefix_clean = re.sub(r'[\d\-_v]+$', '', prefix)

        for kw in _ENV_KEYWORDS:
            if kw in prefix_clean or prefix_clean == kw:
                groups[f"env:{kw}"].append(domain)
                break
        for kw in _API_KEYWORDS:
            if prefix_clean == kw or prefix_clean.startswith(kw):
                groups[f"api:{kw}"].append(domain)
                break
        for kw in _INFRA_KEYWORDS:
            if kw in prefix_clean:
                groups[f"infra:{kw}"].append(domain)
                break

    findings = []
    for group_key, group_domains in groups.items():
        kind, keyword = group_key.split(":", 1)

        if kind == "env":
            action = (
                f"Found {len(group_domains)} '{keyword}' environment subdomains. "
                f"Check for corresponding prod/staging siblings not yet enumerated. "
                f"Staging servers often skip auth hardening and leak stack traces on errors."
            )
            severity = "low"
        elif kind == "api":
            action = (
                f"Found {len(group_domains)} API-type subdomains ({keyword}). "
                f"Enumerate for REST/GraphQL endpoints, check v1/v2 version gaps, "
                f"and prioritize these for HTTP verb enumeration and parameter discovery."
            )
            severity = "info"
        else:  # infra
            action = (
                f"Infrastructure subdomain: {keyword}. "
                f"These often have default credentials, exposed admin panels, or version disclosure. "
                f"Priority target for nuclei default-login and exposure templates."
            )
            severity = "low"

        findings.append({
            "program": program,
            "program_id": program_id,
            "tool": "asset_graph",
            "template_id": f"asset-graph-naming-{kind}-{keyword}",  # stable per cluster type
            "severity": severity,
            "title": f"Naming cluster [{kind}:{keyword}] — {len(group_domains)} subdomain(s)",
            "url": f"https://{group_domains[0]}",
            "evidence": json.dumps({
                "cluster_type": kind,
                "keyword": keyword,
                "domains": group_domains,
                "action": action,
            }),
        })

    return findings


# ─── Orphan JS hosts ──────────────────────────────────────────────────────────

def _orphan_js_hosts(conn, program_id: int, program: str) -> list[dict]:
    """Find hostnames referenced in JS files that aren't in the subdomain list.

    If app.target.com's JS bundle references internal-api.corp.target.com
    and that host isn't in our subdomain list, it's a shadow API we haven't
    enumerated yet.
    """
    js_rows = conn.execute("""
        SELECT jf.url AS js_url, jf.endpoints_json
        FROM js_files jf
        JOIN http_services hs ON hs.id = jf.http_service_id
        JOIN subdomains s ON s.id = hs.subdomain_id
        WHERE s.program_id = ?
          AND jf.endpoints_json IS NOT NULL
    """, (program_id,)).fetchall()

    if not js_rows:
        return []

    known = {
        r["domain"].lower()
        for r in conn.execute(
            "SELECT domain FROM subdomains WHERE program_id = ?", (program_id,)
        ).fetchall()
    }
    apexes = {
        r["domain"].lower()
        for r in conn.execute(
            "SELECT domain FROM apex_domains WHERE program_id = ?", (program_id,)
        ).fetchall()
    }

    orphans: dict[str, list[str]] = defaultdict(list)

    for row in js_rows:
        try:
            endpoints = json.loads(row["endpoints_json"])
        except (json.JSONDecodeError, TypeError):
            continue

        for ep in (endpoints or []):
            if not ep or not ep.startswith("http"):
                continue
            try:
                host = urlparse(ep).netloc.lower().split(":")[0]
            except Exception:
                continue
            if not host:
                continue
            # Only flag hosts that belong to one of our apex domains
            if not any(host.endswith(f".{apex}") or host == apex for apex in apexes):
                continue
            if host not in known:
                orphans[host].append(row["js_url"])

    findings = []
    for host, js_files in orphans.items():
        findings.append({
            "program": program,
            "program_id": program_id,
            "tool": "asset_graph",
            "template_id": "asset-graph-orphan-js",  # stable per host via url field
            "severity": "medium",
            "title": f"Orphan host in JS: {host} — not in subdomain list",
            "url": f"https://{host}",
            "evidence": json.dumps({
                "host": host,
                "referenced_in": sorted(set(js_files))[:10],
                "action": (
                    "This host is referenced by in-scope JavaScript but was not discovered by "
                    "subdomain enumeration. It may be an undiscovered internal API or forgotten "
                    "service. Probe it directly with httpx and add to subdomain list."
                ),
            }),
        })
        log.warning(f"[asset_graph] Orphan JS host: {host} (in {len(js_files)} JS files)")

    return findings


# ─── Wayback shadow hosts ─────────────────────────────────────────────────────

def _wayback_shadow_hosts(conn, program_id: int, program: str) -> list[dict]:
    """Find hostnames appearing in Wayback URLs not in the current subdomain list.

    Historical requests to shadow.target.com that no longer appear in DNS
    may still be accessible — old infra left running, acquired company assets, etc.
    """
    url_rows = conn.execute("""
        SELECT DISTINCT u.url
        FROM urls u
        JOIN http_services hs ON hs.id = u.http_service_id
        JOIN subdomains s ON s.id = hs.subdomain_id
        WHERE s.program_id = ?
          AND u.source = 'wayback'
        LIMIT 10000
    """, (program_id,)).fetchall()

    if not url_rows:
        return []

    known = {
        r["domain"].lower()
        for r in conn.execute(
            "SELECT domain FROM subdomains WHERE program_id = ?", (program_id,)
        ).fetchall()
    }
    apexes = {
        r["domain"].lower()
        for r in conn.execute(
            "SELECT domain FROM apex_domains WHERE program_id = ?", (program_id,)
        ).fetchall()
    }

    shadow: dict[str, int] = defaultdict(int)
    for row in url_rows:
        try:
            host = urlparse(row["url"]).netloc.lower().split(":")[0]
        except Exception:
            continue
        if not host:
            continue
        if not any(host.endswith(f".{apex}") or host == apex for apex in apexes):
            continue
        if host not in known:
            shadow[host] += 1

    findings = []
    for host, count in sorted(shadow.items(), key=lambda x: -x[1]):
        findings.append({
            "program": program,
            "program_id": program_id,
            "tool": "asset_graph",
            "template_id": "asset-graph-wayback-shadow",  # stable per host via url field
            "severity": "medium",
            "title": f"Wayback shadow host: {host} — {count} historical URL(s), not in subdomain list",
            "url": f"https://{host}",
            "evidence": json.dumps({
                "host": host,
                "historical_url_count": count,
                "action": (
                    "This hostname appears in Wayback Machine historical data but was not "
                    "found by subdomain enumeration. It may be a decommissioned asset still "
                    "running, an acquisition, or shadow infrastructure. Probe with httpx."
                ),
            }),
        })
        log.warning(f"[asset_graph] Wayback shadow host: {host} ({count} historical URLs)")

    return findings

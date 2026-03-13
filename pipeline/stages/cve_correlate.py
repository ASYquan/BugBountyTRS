"""CVE correlation stage.

Consumes port scan results and HTTP service data.
Maps service+version to known CVEs using:
1. NVD API (free, no key required for low rate)
2. Nuclei template-id to CVE extraction
3. Version banner matching against local CVE patterns

Publishes enriched findings with CVE IDs and CVSS scores.
"""

import subprocess
import json
import re
import hashlib
import logging
import time
from urllib.parse import quote

from ..core.worker import BaseWorker
from ..core.config import get_config

log = logging.getLogger(__name__)

# Common product name normalization for NVD CPE queries
PRODUCT_ALIASES = {
    "apache httpd": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "iis": ("microsoft", "internet_information_services"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "openssh": ("openbsd", "openssh"),
    "ssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "tomcat": ("apache", "tomcat"),
    "apache tomcat": ("apache", "tomcat"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "grafana": ("grafana", "grafana"),
    "wordpress": ("wordpress", "wordpress"),
    "php": ("php", "php"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "rabbitmq": ("pivotal_software", "rabbitmq"),
    "consul": ("hashicorp", "consul"),
    "vault": ("hashicorp", "vault"),
    "spring boot": ("pivotal_software", "spring_boot"),
    "spring framework": ("pivotal_software", "spring_framework"),
    "express": ("expressjs", "express"),
    "node.js": ("nodejs", "node.js"),
    "joomla": ("joomla", "joomla"),
    "drupal": ("drupal", "drupal"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "exim": ("exim", "exim"),
    "postfix": ("postfix", "postfix"),
    "dovecot": ("dovecot", "dovecot"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "haproxy": ("haproxy", "haproxy"),
    "traefik": ("traefik", "traefik"),
    "caddy": ("caddyserver", "caddy"),
    "varnish": ("varnish-cache", "varnish"),
    "squid": ("squid-cache", "squid"),
    "bind": ("isc", "bind"),
}

# Extract version from common banner formats
VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)")


class CVECorrelateWorker(BaseWorker):
    """Correlates service versions with known CVEs."""

    name = "cve_correlate"
    input_stream = "recon_ports"
    output_streams = ["vuln_findings"]

    def __init__(self):
        super().__init__()
        self._nvd_last_call = 0  # Rate limit NVD API

    def dedup_key(self, data: dict) -> str:
        svc = data.get("service", "")
        ver = data.get("version", "")
        return f"cve:{svc}:{ver}:{data.get('ip', '')}"

    def process(self, data: dict) -> list[dict]:
        service = data.get("service", "")
        version_str = data.get("version", "")
        ip = data.get("ip")
        port = data.get("port")
        domain = data.get("domain")
        program = data.get("program")
        program_id = data.get("program_id")
        subdomain_id = data.get("subdomain_id")

        if not service or not version_str:
            return []

        # Parse product and version
        product, version = self._parse_product_version(service, version_str)
        if not product or not version:
            return []

        log.info(f"[cve] Looking up CVEs for {product} {version} on {domain}:{port}")

        # Query NVD
        cves = self._query_nvd(product, version)

        results = []
        for cve in cves:
            cve_id = cve["id"]
            cvss = cve.get("cvss_score", 0)
            severity = self._cvss_to_severity(cvss)

            # Dedup hash: same CVE + same host = one finding
            dedup_hash = hashlib.sha256(
                f"{cve_id}:{domain}:{port}".encode()
            ).hexdigest()

            # Store CVE
            self.storage.upsert_cve(
                cve_id,
                cvss_score=cvss,
                cvss_vector=cve.get("cvss_vector"),
                severity=severity,
                description=cve.get("description", "")[:1000],
                published=cve.get("published"),
                affected_product=product,
                affected_versions=version,
                references=cve.get("references", []),
            )

            # Store finding (deduped)
            finding_id = self.storage.add_finding_deduped(
                program_id,
                dedup_hash=dedup_hash,
                subdomain_id=subdomain_id,
                tool="cve_correlate",
                template_id=cve_id,
                severity=severity,
                title=f"{cve_id}: {product} {version}",
                description=cve.get("description", "")[:1000],
                url=f"{domain}:{port}",
                matched_at=f"{ip}:{port}",
                evidence=f"Service: {service}, Version: {version_str}",
                cve_id=cve_id,
                cvss_score=cvss,
            )

            if finding_id:
                self.storage.link_finding_cve(finding_id, cve_id, confidence="high")
                log.warning(f"[cve] Found {cve_id} (CVSS {cvss}) for {product} {version} on {domain}:{port}")

                results.append({
                    "program": program,
                    "program_id": program_id,
                    "subdomain_id": subdomain_id,
                    "tool": "cve_correlate",
                    "cve_id": cve_id,
                    "cvss_score": cvss,
                    "severity": severity,
                    "title": f"{cve_id}: {product} {version}",
                    "url": f"{domain}:{port}",
                })

        if cves:
            log.info(f"[cve] Mapped {len(cves)} CVEs for {product} {version} on {domain}:{port}")

        return results

    def _parse_product_version(self, service: str, version_str: str) -> tuple[str | None, str | None]:
        """Extract product name and version number."""
        # version_str from nmap looks like: "Apache httpd 2.4.49" or "OpenSSH 8.2p1"
        combined = f"{service} {version_str}".lower().strip()

        # Try to match known products
        for pattern, (vendor, product) in PRODUCT_ALIASES.items():
            if pattern in combined:
                ver_match = VERSION_RE.search(version_str)
                if ver_match:
                    return product, ver_match.group(1)

        # Fallback: use service name + first version found
        ver_match = VERSION_RE.search(version_str)
        if ver_match:
            return service.lower().replace(" ", "_"), ver_match.group(1)

        return None, None

    def _query_nvd(self, product: str, version: str) -> list[dict]:
        """Query NVD API for CVEs affecting product:version.

        NVD API is free without a key at 5 requests per 30 seconds.
        With a key it's 50 requests per 30 seconds.
        """
        # Rate limit: wait at least 6 seconds between calls (no API key)
        now = time.time()
        wait = 6.0 - (now - self._nvd_last_call)
        if wait > 0:
            time.sleep(wait)
        self._nvd_last_call = time.time()

        # Check if we already have cached CVEs for this product+version
        cached = self._check_cache(product, version)
        if cached is not None:
            return cached

        try:
            # Build CPE match string
            # Try known vendor mapping first
            vendor = None
            for pattern, (v, p) in PRODUCT_ALIASES.items():
                if p == product:
                    vendor = v
                    break

            if vendor:
                cpe_match = f"cpe:2.3:a:{vendor}:{product}:{version}"
            else:
                cpe_match = None

            # Use keyword search as fallback
            keyword = f"{product} {version}"

            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote(keyword)}&resultsPerPage=20"

            result = subprocess.run(
                ["curl", "-sL", "--max-time", "30", url],
                capture_output=True, text=True, timeout=35,
            )

            if result.returncode != 0:
                return []

            data = json.loads(result.stdout)
            vulnerabilities = data.get("vulnerabilities", [])

            cves = []
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")

                if not cve_id.startswith("CVE-"):
                    continue

                # Get CVSS score
                cvss_score = 0
                cvss_vector = ""
                metrics = cve_data.get("metrics", {})

                # Try CVSS 3.1, then 3.0, then 2.0
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(key, [])
                    if metric_list:
                        cvss_data = metric_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0)
                        cvss_vector = cvss_data.get("vectorString", "")
                        break

                # Get description
                descriptions = cve_data.get("descriptions", [])
                desc = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                # Check if this CVE actually affects the version we found
                if not self._version_affected(cve_data, product, version):
                    continue

                # Get references
                refs = [
                    r.get("url", "") for r in cve_data.get("references", [])[:5]
                ]

                cves.append({
                    "id": cve_id,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "description": desc,
                    "published": cve_data.get("published", ""),
                    "references": refs,
                })

            return cves

        except (json.JSONDecodeError, subprocess.TimeoutExpired) as e:
            log.warning(f"[cve] NVD query failed for {product} {version}: {e}")
            return []
        except Exception as e:
            log.error(f"[cve] NVD error: {e}", exc_info=True)
            return []

    def _version_affected(self, cve_data: dict, product: str, version: str) -> bool:
        """Check if the detected version falls within the affected range of a CVE."""
        configs = cve_data.get("configurations", [])
        if not configs:
            # No configuration data — include it with lower confidence
            return True

        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue

                    criteria = match.get("criteria", "").lower()

                    # Check if product matches
                    if product.lower() not in criteria:
                        continue

                    # Check version ranges
                    ver_start = match.get("versionStartIncluding", "")
                    ver_end = match.get("versionEndIncluding", "")
                    ver_end_excl = match.get("versionEndExcluding", "")

                    # If exact version in CPE
                    if f":{version}" in criteria:
                        return True

                    # If wildcard version
                    if ":*:" in criteria or criteria.endswith(":*"):
                        if ver_end and self._version_lte(version, ver_end):
                            return True
                        if ver_end_excl and self._version_lt(version, ver_end_excl):
                            return True
                        if not ver_end and not ver_end_excl:
                            return True

        return False

    def _version_lte(self, v1: str, v2: str) -> bool:
        """Check if v1 <= v2 using simple numeric comparison."""
        try:
            parts1 = [int(x) for x in v1.split(".")]
            parts2 = [int(x) for x in v2.split(".")]
            # Pad to same length
            while len(parts1) < len(parts2):
                parts1.append(0)
            while len(parts2) < len(parts1):
                parts2.append(0)
            return parts1 <= parts2
        except ValueError:
            return v1 <= v2

    def _version_lt(self, v1: str, v2: str) -> bool:
        try:
            parts1 = [int(x) for x in v1.split(".")]
            parts2 = [int(x) for x in v2.split(".")]
            while len(parts1) < len(parts2):
                parts1.append(0)
            while len(parts2) < len(parts1):
                parts2.append(0)
            return parts1 < parts2
        except ValueError:
            return v1 < v2

    def _cvss_to_severity(self, score: float) -> str:
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0:
            return "low"
        return "info"

    def _check_cache(self, product: str, version: str) -> list[dict] | None:
        """Check if we already have CVEs for this product+version in the DB."""
        with self.storage._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM cves WHERE affected_product=? AND affected_versions=?",
                (product, version),
            ).fetchall()
            if rows:
                return [dict(r) for r in rows]
        return None

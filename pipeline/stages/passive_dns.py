"""Passive DNS transparency database integration stage.

Queries multiple free/non-profit passive DNS databases to discover subdomains
and historical DNS records that traditional enumeration tools miss.

Data sources:
  - Rapid7 Project Sonar FDNS  (free API key, weekly internet-wide DNS scans)
  - CIRCL Passive DNS           (non-profit CERT Luxembourg, free for partners)
  - Cisco Umbrella Top 1M       (daily popularity list, no auth needed)
  - Crobat / SonarSearch        (searchable Project Sonar mirror, no auth)

References:
  - Jason Haddix TBHM v4 Recon Edition
  - https://opendata.rapid7.com/sonar.fdns_v2/
  - https://www.circl.lu/services/passive-dns/
  - https://umbrella.cisco.com/blog/cisco-umbrella-1-million
"""

import gzip
import json
import logging
import tempfile
import time
from io import BytesIO
from pathlib import Path

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.storage import Storage

log = logging.getLogger(__name__)

# Rate limit: max requests per second (Visma RoE compliant)
DEFAULT_RATE_LIMIT = 20


class PassiveDNSWorker(BaseWorker):
    """Queries passive DNS databases for subdomain discovery.

    Consumes domains from scope_targets and publishes discovered
    subdomains to recon_subdomains.
    """
    name = "passive_dns"
    input_stream = "scope_targets"
    output_streams = ["recon_subdomains"]

    def dedup_key(self, data: dict) -> str:
        return f"pdns:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        domain = data.get("domain")
        program = data.get("program")
        program_id = data.get("program_id")

        if not domain:
            return []

        log.info(f"[passive_dns] Querying passive DNS databases for {domain}")

        cfg = get_config().get("passive_dns", {})
        subdomains = set()

        # Source 1: Rapid7 Project Sonar FDNS (via crobat/omnisint API)
        if cfg.get("crobat_enabled", True):
            crobat_subs = _query_crobat(domain, cfg.get("crobat_url"))
            subdomains.update(crobat_subs)
            log.info(f"[passive_dns] Crobat/Sonar: {len(crobat_subs)} subs for {domain}")

        # Source 2: Rapid7 FDNS API (requires API key, downloads gz files)
        rapid7_key = cfg.get("rapid7_api_key", "")
        if rapid7_key and cfg.get("rapid7_enabled", True):
            rapid7_subs = _query_rapid7_fdns(domain, rapid7_key)
            subdomains.update(rapid7_subs)
            log.info(f"[passive_dns] Rapid7 FDNS: {len(rapid7_subs)} subs for {domain}")

        # Source 3: CIRCL Passive DNS (requires credentials)
        circl_user = cfg.get("circl_user", "")
        circl_pass = cfg.get("circl_password", "")
        if circl_user and circl_pass and cfg.get("circl_enabled", True):
            circl_subs = _query_circl_pdns(domain, circl_user, circl_pass)
            subdomains.update(circl_subs)
            log.info(f"[passive_dns] CIRCL: {len(circl_subs)} subs for {domain}")

        # Source 4: Cisco Umbrella Top 1M (popularity validation)
        if cfg.get("umbrella_enabled", True):
            umbrella_subs = _query_umbrella_top1m(domain)
            subdomains.update(umbrella_subs)
            log.info(f"[passive_dns] Umbrella Top1M: {len(umbrella_subs)} subs for {domain}")

        log.info(f"[passive_dns] Total: {len(subdomains)} unique subs for {domain}")

        # Store and publish
        results = []
        for sub in subdomains:
            sub = sub.strip().lower().rstrip(".")
            if not sub or not sub.endswith(domain):
                continue

            self.storage.upsert_subdomain(program_id, sub, source="passive_dns")

            results.append({
                "program": program,
                "program_id": program_id,
                "domain": sub,
                "parent_domain": domain,
            })

        return results


# --- Crobat / SonarSearch API (Project Sonar mirror) ---

def _query_crobat(domain: str, base_url: str = None) -> set[str]:
    """Query Crobat/SonarSearch API for subdomains from Rapid7 Project Sonar.

    This is the fastest way to search the Project Sonar FDNS dataset
    without downloading the full 20GB+ files.
    """
    import requests

    base_url = base_url or "https://sonar.omnisint.io"
    subdomains = set()

    try:
        resp = requests.get(
            f"{base_url}/subdomains/{domain}",
            timeout=30,
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for sub in data:
                    full = f"{sub}.{domain}" if not sub.endswith(domain) else sub
                    subdomains.add(full.lower())
    except Exception as e:
        log.debug(f"[passive_dns] Crobat query failed for {domain}: {e}")

    return subdomains


# --- Rapid7 Project Sonar FDNS API ---

def _query_rapid7_fdns(domain: str, api_key: str) -> set[str]:
    """Query Rapid7 Open Data API for the latest FDNS dataset.

    Downloads the latest A-record FDNS file, streams through it looking
    for records matching the target domain. The files are large (20GB+),
    so we stream and filter line-by-line.

    API docs: https://opendata.rapid7.com/apihelp/
    """
    import requests

    subdomains = set()
    base = "https://us.api.insight.rapid7.com/opendata"
    headers = {"X-Api-Key": api_key}

    try:
        # Get the latest FDNS study files
        resp = requests.get(f"{base}/studies/sonar.fdns_v2/", headers=headers, timeout=30)
        if resp.status_code != 200:
            log.warning(f"[passive_dns] Rapid7 API returned {resp.status_code}")
            return subdomains

        study = resp.json()
        # Find the latest A-record file
        files = study.get("sonarfile_set", [])
        a_record_files = [f for f in files if "fdns_a" in f.get("name", "")]

        if not a_record_files:
            log.warning("[passive_dns] No FDNS A-record files found")
            return subdomains

        latest_file = sorted(a_record_files, key=lambda f: f.get("name", ""))[-1]
        filename = latest_file["name"]

        # Get download URL
        dl_resp = requests.get(
            f"{base}/studies/sonar.fdns_v2/{filename}/download/",
            headers=headers, timeout=30,
        )
        if dl_resp.status_code != 200:
            log.warning(f"[passive_dns] Rapid7 download URL request failed: {dl_resp.status_code}")
            return subdomains

        download_url = dl_resp.json().get("url")
        if not download_url:
            return subdomains

        # Stream the gzipped file and filter for our domain
        log.info(f"[passive_dns] Streaming Rapid7 FDNS file: {filename}")
        subdomains = _stream_fdns_gz(download_url, domain)

    except Exception as e:
        log.error(f"[passive_dns] Rapid7 FDNS query failed: {e}")

    return subdomains


def _stream_fdns_gz(url: str, domain: str, max_bytes: int = 500_000_000) -> set[str]:
    """Stream a gzipped FDNS JSON file and extract matching subdomains.

    Each line is JSON: {"timestamp":"...","name":"sub.example.com","type":"a","value":"1.2.3.4"}
    We stream to avoid loading the entire 20GB file into memory.
    """
    import requests

    subdomains = set()
    domain_suffix = f".{domain}"
    bytes_read = 0

    try:
        with requests.get(url, stream=True, timeout=60) as resp:
            resp.raise_for_status()
            decompressor = gzip.GzipFile(fileobj=resp.raw)

            for line in decompressor:
                bytes_read += len(line)
                if bytes_read > max_bytes:
                    log.info(f"[passive_dns] Reached {max_bytes/1e6:.0f}MB limit, stopping stream")
                    break

                try:
                    record = json.loads(line)
                    name = record.get("name", "").lower().rstrip(".")
                    if name == domain or name.endswith(domain_suffix):
                        subdomains.add(name)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

    except Exception as e:
        log.warning(f"[passive_dns] FDNS stream error: {e}")

    return subdomains


# --- CIRCL Passive DNS (non-profit CERT Luxembourg) ---

def _query_circl_pdns(domain: str, username: str, password: str) -> set[str]:
    """Query CIRCL Passive DNS REST API.

    CIRCL is a non-profit CERT that maintains one of the largest passive
    DNS databases in Europe. Access requires registration as a trusted partner.

    API: https://www.circl.lu/pdns/query/{domain}
    Auth: HTTP Basic
    Format: NDJSON (Passive DNS Common Output Format)
    """
    import requests

    subdomains = set()
    domain_suffix = f".{domain}"

    try:
        resp = requests.get(
            f"https://www.circl.lu/pdns/query/{domain}",
            auth=(username, password),
            timeout=30,
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 200:
            for line in resp.text.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    rrname = record.get("rrname", "").lower().rstrip(".")
                    rdata = record.get("rdata", "")

                    if rrname == domain or rrname.endswith(domain_suffix):
                        subdomains.add(rrname)
                    # Also check rdata for CNAME chains
                    if isinstance(rdata, str):
                        rdata = rdata.lower().rstrip(".")
                        if rdata.endswith(domain_suffix):
                            subdomains.add(rdata)
                except json.JSONDecodeError:
                    continue
        elif resp.status_code == 401:
            log.warning("[passive_dns] CIRCL auth failed. Register at https://www.circl.lu/services/passive-dns/")
        else:
            log.debug(f"[passive_dns] CIRCL returned {resp.status_code} for {domain}")
    except Exception as e:
        log.debug(f"[passive_dns] CIRCL query failed for {domain}: {e}")

    return subdomains


# --- Cisco Umbrella Top 1M ---

def _query_umbrella_top1m(domain: str, cache_dir: str = None) -> set[str]:
    """Search the Cisco Umbrella Top 1 Million domains list for subdomains.

    Cisco (via OpenDNS) publishes a daily list of the top 1M most queried
    domains globally. This list includes subdomains, making it a useful
    source for discovering popular subdomains of a target.

    Download: https://umbrella-static.s3-us-west-1.amazonaws.com/top-1m.csv.zip
    No auth required. Updated daily.
    """
    import requests
    import zipfile
    import csv

    subdomains = set()
    cache_dir = cache_dir or "/tmp/umbrella_cache"
    cache_path = Path(cache_dir)
    cache_path.mkdir(parents=True, exist_ok=True)

    csv_file = cache_path / "top-1m.csv"
    domain_suffix = f".{domain}"

    # Use cached file if less than 24 hours old
    if csv_file.exists():
        age_hours = (time.time() - csv_file.stat().st_mtime) / 3600
        if age_hours > 24:
            csv_file.unlink()

    # Download if not cached
    if not csv_file.exists():
        try:
            log.info("[passive_dns] Downloading Cisco Umbrella Top 1M list")
            resp = requests.get(
                "https://umbrella-static.s3-us-west-1.amazonaws.com/top-1m.csv.zip",
                timeout=60,
            )
            resp.raise_for_status()

            zip_path = cache_path / "top-1m.csv.zip"
            zip_path.write_bytes(resp.content)

            with zipfile.ZipFile(zip_path) as zf:
                zf.extract("top-1m.csv", cache_path)

            zip_path.unlink()
            log.info("[passive_dns] Umbrella Top 1M downloaded and cached")
        except Exception as e:
            log.warning(f"[passive_dns] Umbrella download failed: {e}")
            return subdomains

    # Search the CSV for matching domains
    try:
        with open(csv_file, newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 2:
                    continue
                entry = row[1].lower().rstrip(".")
                if entry == domain or entry.endswith(domain_suffix):
                    subdomains.add(entry)
    except Exception as e:
        log.warning(f"[passive_dns] Umbrella CSV parse failed: {e}")

    return subdomains


# --- Standalone CLI functions ---

def query_all_passive_dns(domain: str, config: dict = None) -> dict:
    """Query all passive DNS sources and return categorized results.

    Args:
        domain: Target domain to query
        config: Optional config dict with API keys. Keys:
            - rapid7_api_key: Rapid7 Open Data API key
            - circl_user: CIRCL passive DNS username
            - circl_password: CIRCL passive DNS password
            - crobat_url: Custom Crobat/SonarSearch API URL

    Returns:
        Dict with 'subdomains' (set), 'sources' (dict of source->count)
    """
    config = config or {}
    all_subs = set()
    sources = {}

    # Crobat / SonarSearch
    try:
        crobat = _query_crobat(domain, config.get("crobat_url"))
        all_subs.update(crobat)
        sources["crobat_sonar"] = len(crobat)
    except Exception:
        sources["crobat_sonar"] = 0

    # Rapid7 FDNS
    rapid7_key = config.get("rapid7_api_key", "")
    if rapid7_key:
        try:
            rapid7 = _query_rapid7_fdns(domain, rapid7_key)
            all_subs.update(rapid7)
            sources["rapid7_fdns"] = len(rapid7)
        except Exception:
            sources["rapid7_fdns"] = 0

    # CIRCL
    circl_user = config.get("circl_user", "")
    circl_pass = config.get("circl_password", "")
    if circl_user and circl_pass:
        try:
            circl = _query_circl_pdns(domain, circl_user, circl_pass)
            all_subs.update(circl)
            sources["circl"] = len(circl)
        except Exception:
            sources["circl"] = 0

    # Umbrella
    try:
        umbrella = _query_umbrella_top1m(domain)
        all_subs.update(umbrella)
        sources["umbrella_top1m"] = len(umbrella)
    except Exception:
        sources["umbrella_top1m"] = 0

    return {
        "subdomains": sorted(all_subs),
        "total": len(all_subs),
        "sources": sources,
    }


def update_umbrella_cache(cache_dir: str = "/tmp/umbrella_cache") -> str:
    """Force-refresh the Cisco Umbrella Top 1M cache.

    Returns the path to the cached CSV file.
    """
    cache_path = Path(cache_dir)
    csv_file = cache_path / "top-1m.csv"
    if csv_file.exists():
        csv_file.unlink()

    # Trigger download by querying a dummy domain
    _query_umbrella_top1m("example.com", cache_dir)
    return str(csv_file)

"""Credential reconnaissance stage.

Queries breach databases and default credential lists to identify
leaked or weak credentials associated with target domains and services.

Data sources:
  - DeHashed API         (breach database, paid API credits)
  - Flare.io API         (dark web / stealer logs, enterprise)
  - DefaultCreds DB      (default vendor credentials, offline CSV)
  - SecLists defaults    (default-passwords.csv, offline)

The stage runs in two modes:
  1. Domain mode: queries DeHashed/Flare for leaked creds by domain
  2. Service mode: matches discovered services against default creds DB

References:
  - https://dehashed.com/api
  - https://flare.io/
  - https://github.com/ihebski/DefaultCreds-cheat-sheet
"""

import csv
import json
import logging
import os
import subprocess
import time
from pathlib import Path

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.storage import Storage

log = logging.getLogger(__name__)


class CredentialReconWorker(BaseWorker):
    """Queries breach databases and matches default credentials.

    Operates on two input streams:
      - scope_targets: domain-level breach lookups (DeHashed, Flare)
      - recon_ports: service-level default credential matching

    Publishes findings to vuln_findings.
    """
    name = "credential_recon"
    input_stream = "scope_targets"
    output_streams = ["vuln_findings"]

    def __init__(self):
        super().__init__()
        self._default_creds_db = None

    def on_start(self):
        """Pre-load default credentials database."""
        self._default_creds_db = _load_default_creds_db()
        if self._default_creds_db:
            log.info(f"[creds] Loaded {len(self._default_creds_db)} default credential entries")
        else:
            log.warning("[creds] No default credentials database found. "
                        "Install: pip3 install defaultcreds-cheat-sheet")

    def dedup_key(self, data: dict) -> str:
        return f"creds:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        domain = data.get("domain")
        program = data.get("program")
        program_id = data.get("program_id")

        if not domain:
            return []

        log.info(f"[creds] Running credential recon for {domain}")

        cfg = get_config().get("credentials", {})
        results = []

        # DeHashed: search for leaked credentials by domain
        dehashed_key = cfg.get("dehashed_api_key") or os.environ.get("DEHASHED_API_KEY", "")
        dehashed_email = cfg.get("dehashed_email") or os.environ.get("DEHASHED_EMAIL", "")
        if dehashed_key and dehashed_email and cfg.get("dehashed_enabled", True):
            findings = _query_dehashed(domain, dehashed_email, dehashed_key, cfg)
            for f in findings:
                f.update({
                    "_stream": self.mq.stream_name("vuln_findings"),
                    "program": program,
                    "program_id": program_id,
                })
                results.append(f)
            log.info(f"[creds] DeHashed: {len(findings)} breach entries for {domain}")

            # Store in DB
            for f in findings:
                self.storage.add_finding(
                    program_id,
                    tool="dehashed",
                    severity=f.get("severity", "medium"),
                    title=f.get("title", "Leaked credential"),
                    description=f.get("description", ""),
                    url=f.get("url", domain),
                    matched_at=domain,
                    evidence=f.get("evidence", ""),
                )

        # Flare.io: search for dark web exposure
        flare_key = cfg.get("flare_api_key") or os.environ.get("FLARE_API_KEY", "")
        flare_tenant = cfg.get("flare_tenant") or os.environ.get("FLARE_TENANT", "")
        if flare_key and flare_tenant and cfg.get("flare_enabled", True):
            findings = _query_flare(domain, flare_key, flare_tenant, cfg)
            for f in findings:
                f.update({
                    "_stream": self.mq.stream_name("vuln_findings"),
                    "program": program,
                    "program_id": program_id,
                })
                results.append(f)
            log.info(f"[creds] Flare: {len(findings)} exposure entries for {domain}")

            for f in findings:
                self.storage.add_finding(
                    program_id,
                    tool="flare",
                    severity=f.get("severity", "medium"),
                    title=f.get("title", "Dark web exposure"),
                    description=f.get("description", ""),
                    url=f.get("url", domain),
                    matched_at=domain,
                    evidence=f.get("evidence", ""),
                )

        return results


class DefaultCredScanWorker(BaseWorker):
    """Matches discovered services against default credentials database.

    Consumes from recon_ports (after port scanning identifies services)
    and checks if discovered services have known default credentials.
    """
    name = "default_cred_scan"
    input_stream = "recon_ports"
    output_streams = ["vuln_findings"]

    def __init__(self):
        super().__init__()
        self._default_creds_db = None

    def on_start(self):
        self._default_creds_db = _load_default_creds_db()
        if self._default_creds_db:
            log.info(f"[default_creds] Loaded {len(self._default_creds_db)} entries")

    def dedup_key(self, data: dict) -> str:
        return f"defcreds:{data.get('ip', '')}:{data.get('port', '')}"

    def process(self, data: dict) -> list[dict]:
        if not self._default_creds_db:
            return []

        service = (data.get("service") or "").lower()
        version = (data.get("version") or "").lower()
        banner = (data.get("banner") or "").lower()
        ip = data.get("ip", "")
        port = data.get("port", 0)
        domain = data.get("domain", "")
        program = data.get("program")
        program_id = data.get("program_id")

        if not service:
            return []

        # Match service name against default creds database
        matches = _match_default_creds(
            service, version, banner, self._default_creds_db
        )

        if not matches:
            return []

        log.info(f"[default_creds] {len(matches)} default cred entries for "
                 f"{service} on {ip}:{port}")

        results = []
        for match in matches:
            title = (f"Default credentials for {match['product']}: "
                     f"{match['username']}:{match['password']}")
            evidence = json.dumps({
                "product": match["product"],
                "username": match["username"],
                "password": match["password"],
                "service": service,
                "ip": ip,
                "port": port,
            })

            self.storage.add_finding(
                program_id,
                tool="default_creds",
                severity="info",
                title=title[:200],
                description=(f"Service {service} on {ip}:{port} matches known "
                             f"default credentials for {match['product']}. "
                             f"Manual verification required before reporting."),
                url=f"https://{domain}:{port}" if domain else f"{ip}:{port}",
                matched_at=f"{ip}:{port}",
                evidence=evidence[:1000],
            )

            results.append({
                "_stream": self.mq.stream_name("vuln_findings"),
                "program": program,
                "program_id": program_id,
                "tool": "default_creds",
                "severity": "info",
                "title": title[:200],
                "url": f"https://{domain}:{port}" if domain else f"{ip}:{port}",
                "matched_at": f"{ip}:{port}",
                "evidence": evidence[:1000],
            })

        return results


# --- DeHashed API ---

def _query_dehashed(domain: str, email: str, api_key: str,
                    cfg: dict = None) -> list[dict]:
    """Query DeHashed API for leaked credentials associated with a domain.

    API: https://api.dehashed.com/search?query=domain:<domain>
    Auth: HTTP Basic (email:api_key)
    """
    import requests

    cfg = cfg or {}
    findings = []
    max_pages = cfg.get("dehashed_max_pages", 3)

    try:
        for page in range(1, max_pages + 1):
            resp = requests.get(
                "https://api.dehashed.com/search",
                params={
                    "query": f"domain:{domain}",
                    "size": 100,
                    "page": page,
                },
                auth=(email, api_key),
                headers={"Accept": "application/json"},
                timeout=30,
            )

            if resp.status_code == 401:
                log.warning("[creds] DeHashed auth failed. Check API key.")
                break
            elif resp.status_code == 402:
                log.warning("[creds] DeHashed credits exhausted.")
                break
            elif resp.status_code != 200:
                log.warning(f"[creds] DeHashed returned {resp.status_code}")
                break

            data = resp.json()
            entries = data.get("entries", [])
            if not entries:
                break

            for entry in entries:
                email_val = entry.get("email", "")
                username = entry.get("username", "")
                has_password = bool(entry.get("password") or entry.get("hashed_password"))
                database = entry.get("database_name", "unknown")

                # Determine severity based on what was leaked
                if has_password and email_val:
                    severity = "high"
                elif has_password:
                    severity = "medium"
                else:
                    severity = "low"

                identity = email_val or username or "unknown"
                title = f"Breached credential: {identity} (source: {database})"

                # Redact actual passwords in evidence
                evidence_data = {
                    "email": email_val,
                    "username": username,
                    "has_password": has_password,
                    "has_hash": bool(entry.get("hashed_password")),
                    "database": database,
                    "ip_address": entry.get("ip_address", ""),
                    "name": entry.get("name", ""),
                }

                findings.append({
                    "tool": "dehashed",
                    "severity": severity,
                    "title": title[:200],
                    "description": (f"Credential for {identity} found in "
                                    f"breach database '{database}'. "
                                    f"Password {'exposed' if has_password else 'not exposed'}."),
                    "url": f"https://{domain}",
                    "matched_at": domain,
                    "evidence": json.dumps(evidence_data)[:1000],
                })

            total = data.get("total", 0)
            if page * 100 >= total:
                break

            # Rate limit between pages
            time.sleep(1)

    except Exception as e:
        log.error(f"[creds] DeHashed query failed for {domain}: {e}")

    return findings


# --- Flare.io API ---

def _query_flare(domain: str, api_key: str, tenant: str,
                 cfg: dict = None) -> list[dict]:
    """Query Flare.io API for dark web exposure and leaked credentials.

    Flare monitors dark web forums, paste sites, Telegram channels,
    and stealer logs for credential leaks and data exposure.
    """
    import requests

    cfg = cfg or {}
    findings = []
    base_url = cfg.get("flare_base_url", "https://api.flare.io/leaksdb/v2")

    try:
        # Query leaked credentials endpoint
        resp = requests.get(
            f"{base_url}/sources/_search",
            params={"query": domain, "from": 0, "size": 100},
            headers={
                "Authorization": f"Bearer {api_key}",
                "X-Flare-Tenant": tenant,
                "Accept": "application/json",
            },
            timeout=30,
        )

        if resp.status_code == 401:
            log.warning("[creds] Flare auth failed. Check API key and tenant.")
            return findings
        elif resp.status_code != 200:
            log.debug(f"[creds] Flare returned {resp.status_code}")
            return findings

        data = resp.json()
        hits = data.get("hits", {}).get("hits", [])

        for hit in hits:
            source = hit.get("_source", {})
            leak_type = source.get("type", "unknown")
            source_name = source.get("source_name", "unknown")
            imported_at = source.get("imported_at", "")

            # Check for credential-specific data
            identities = source.get("identities", [])
            for identity in identities:
                email_val = identity.get("email", "")
                has_password = identity.get("has_password", False)

                severity = "high" if has_password else "medium"
                title = f"Dark web exposure: {email_val or 'credential'} ({source_name})"

                evidence_data = {
                    "email": email_val,
                    "has_password": has_password,
                    "source": source_name,
                    "type": leak_type,
                    "imported_at": imported_at,
                }

                findings.append({
                    "tool": "flare",
                    "severity": severity,
                    "title": title[:200],
                    "description": (f"Credential exposure found via Flare.io "
                                    f"in source '{source_name}' ({leak_type}). "
                                    f"Password {'exposed' if has_password else 'not directly exposed'}."),
                    "url": f"https://{domain}",
                    "matched_at": domain,
                    "evidence": json.dumps(evidence_data)[:1000],
                })

            # If no individual identities, still log the exposure
            if not identities:
                findings.append({
                    "tool": "flare",
                    "severity": "info",
                    "title": f"Dark web mention: {domain} ({source_name})"[:200],
                    "description": (f"Domain {domain} mentioned in dark web source "
                                    f"'{source_name}' ({leak_type})."),
                    "url": f"https://{domain}",
                    "matched_at": domain,
                    "evidence": json.dumps({
                        "source": source_name,
                        "type": leak_type,
                        "imported_at": imported_at,
                    })[:1000],
                })

    except Exception as e:
        log.error(f"[creds] Flare query failed for {domain}: {e}")

    return findings


# --- Default Credentials Database ---

def _load_default_creds_db() -> list[dict]:
    """Load the default credentials database from multiple sources.

    Sources (checked in order):
      1. DefaultCreds-cheat-sheet CSV (pip install defaultcreds-cheat-sheet)
      2. SecLists default-passwords.csv
      3. Local cache at data/default_creds.csv
    """
    entries = []

    # Source 1: DefaultCreds-cheat-sheet (pip package or GitHub download)
    csv_paths = [
        Path.home() / ".local" / "share" / "DefaultCreds-Cheat-Sheet.csv",
        Path("/usr/share/DefaultCreds-Cheat-Sheet.csv"),
        Path("/tmp/DefaultCreds-Cheat-Sheet.csv"),
    ]

    # Try to find via the creds tool
    try:
        result = subprocess.run(
            ["python3", "-c",
             "import defaultcreds; print(defaultcreds.__file__)"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            pkg_dir = Path(result.stdout.strip()).parent
            csv_paths.insert(0, pkg_dir / "DefaultCreds-Cheat-Sheet.csv")
    except Exception:
        pass

    found_defaultcreds = False
    for csv_path in csv_paths:
        if csv_path.exists():
            entries.extend(_parse_defaultcreds_csv(csv_path))
            log.info(f"[creds] Loaded {len(entries)} entries from {csv_path}")
            found_defaultcreds = True
            break

    # Download from GitHub if not found locally
    if not found_defaultcreds:
        try:
            import requests
            log.info("[creds] Downloading DefaultCreds-Cheat-Sheet from GitHub")
            resp = requests.get(
                "https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/"
                "main/DefaultCreds-Cheat-Sheet.csv",
                timeout=30,
            )
            if resp.status_code == 200:
                dl_path = Path("/tmp/DefaultCreds-Cheat-Sheet.csv")
                dl_path.write_text(resp.text, encoding="utf-8")
                github_entries = _parse_defaultcreds_csv(dl_path)
                entries.extend(github_entries)
                log.info(f"[creds] Downloaded {len(github_entries)} entries from GitHub")
        except Exception as e:
            log.debug(f"[creds] GitHub download failed: {e}")

    # Source 2: SecLists default-passwords.csv
    seclists_paths = [
        Path("/usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv"),
        Path("/usr/share/wordlists/SecLists-master/Passwords/Default-Credentials/default-passwords.csv"),
    ]
    for csv_path in seclists_paths:
        if csv_path.exists():
            seclists_entries = _parse_seclists_defaults(csv_path)
            entries.extend(seclists_entries)
            log.info(f"[creds] Loaded {len(seclists_entries)} SecLists entries from {csv_path}")
            break

    return entries


def _parse_defaultcreds_csv(path: Path) -> list[dict]:
    """Parse DefaultCreds-Cheat-Sheet CSV format.

    CSV columns: Product/Vendor, Username, Password
    """
    entries = []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 3:
                    product = row[0].strip().lower()
                    username = row[1].strip()
                    password = row[2].strip()
                    if product and (username or password):
                        entries.append({
                            "product": product,
                            "username": username,
                            "password": password,
                            "source": "defaultcreds",
                        })
    except Exception as e:
        log.warning(f"[creds] Failed to parse {path}: {e}")
    return entries


def _parse_seclists_defaults(path: Path) -> list[dict]:
    """Parse SecLists default-passwords.csv format.

    CSV columns: Vendor, Username, Password, Comments
    First row is a header and is skipped.
    """
    entries = []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)  # Skip header row
            for row in reader:
                if len(row) >= 3:
                    product = row[0].strip().lower()
                    username = row[1].strip()
                    password = row[2].strip()
                    comments = row[3].strip() if len(row) > 3 else ""
                    if product and (username or password):
                        entries.append({
                            "product": product,
                            "username": username,
                            "password": password,
                            "comments": comments,
                            "source": "seclists",
                        })
    except Exception as e:
        log.warning(f"[creds] Failed to parse {path}: {e}")
    return entries


def _match_default_creds(service: str, version: str, banner: str,
                         creds_db: list[dict]) -> list[dict]:
    """Match a discovered service against the default credentials database.

    Only matches when the specific product name is explicitly identified in
    the version string or banner — avoids false positives from generic
    protocol names (http, ssh, ftp) matching unrelated product entries.

    Generic protocols without a confirmed product are skipped entirely.
    """
    # Generic protocol names with no specific product — too noisy to match
    GENERIC_SKIP = {"http", "https", "ssh", "ftp", "smtp", "imap", "pop3",
                    "tcp", "udp", "ssl", "tls", "telnet", "rdp", "smb",
                    "snmp", "vnc", "unknown", ""}

    if service.lower() in GENERIC_SKIP and not version and not banner:
        return []

    # Build confirmed product terms only from version + banner (not service name)
    # These are explicit product identifications, not guesses
    confirmed_terms = set()

    for text in (version, banner):
        if not text:
            continue
        text_lower = text.lower()
        for word in text_lower.split():
            word = word.strip("/:()[].,;\"'")
            if len(word) > 3 and not word.replace(".", "").replace("-", "").isdigit():
                confirmed_terms.add(word)

    # Also include the service name if it's a specific named product
    # (not a generic protocol)
    if service.lower() not in GENERIC_SKIP:
        confirmed_terms.add(service.lower())

    if not confirmed_terms:
        return []

    # Noise words that appear in many product names but don't help identify specifics
    _NOISE_WORDS = {"the", "and", "for", "web", "server", "service", "system",
                    "manager", "management", "interface", "console", "panel",
                    "admin", "default", "version", "community", "edition"}

    # Match: ALL significant product words must appear in confirmed terms.
    # This prevents "apache" from matching "apache tomcat", "apache kafka", etc.
    # when we only know the server is generic Apache httpd.
    # Generic vendor-only names — too broad to report without a specific product name
    _GENERIC_VENDORS = {"apache", "cisco", "juniper", "linksys", "dlink", "netgear",
                        "asus", "huawei", "zyxel", "ubiquiti", "mikrotik", "hikvision",
                        "dahua", "axis", "samsung", "sony", "lg", "panasonic"}

    seen = set()
    matches = []
    for entry in creds_db:
        # Strip parenthetical qualifiers: "jenkins (web)" → "jenkins"
        import re as _re
        clean_product = _re.sub(r'\([^)]*\)', '', entry["product"].lower()).strip()
        product_words = {w.strip("/:()[].,;\"'") for w in clean_product.split()
                         if w.strip("/:()[].,;\"'") not in _NOISE_WORDS
                         and len(w.strip("/:()[].,;\"'")) > 2}
        if not product_words:
            continue
        # Skip entries that are just a generic vendor name with no specific product
        if len(product_words) == 1 and product_words.issubset(_GENERIC_VENDORS):
            continue
        # All product words must be confirmed
        if product_words.issubset(confirmed_terms):
            key = (entry["username"], entry["password"], entry["product"])
            if key not in seen:
                seen.add(key)
                matches.append(entry)

    return matches


# --- Standalone CLI functions ---

def dehashed_search(domain: str, email: str = None, api_key: str = None,
                    max_pages: int = 3) -> list[dict]:
    """Search DeHashed for leaked credentials by domain.

    Args:
        domain: Target domain
        email: DeHashed account email (or DEHASHED_EMAIL env)
        api_key: DeHashed API key (or DEHASHED_API_KEY env)
        max_pages: Max result pages to fetch (100 results/page)

    Returns:
        List of breach entry dicts
    """
    email = email or os.environ.get("DEHASHED_EMAIL", "")
    api_key = api_key or os.environ.get("DEHASHED_API_KEY", "")

    if not email or not api_key:
        raise ValueError("DeHashed email and API key required. "
                         "Set DEHASHED_EMAIL and DEHASHED_API_KEY env vars.")

    return _query_dehashed(domain, email, api_key,
                           {"dehashed_max_pages": max_pages})


def match_service_creds(service: str, version: str = "",
                        banner: str = "") -> list[dict]:
    """Find default credentials for a given service.

    Args:
        service: Service name (e.g., 'tomcat', 'jenkins', 'mysql')
        version: Version string (e.g., 'Apache Tomcat 9.0.46')
        banner: Service banner text

    Returns:
        List of matching credential dicts with product/username/password
    """
    db = _load_default_creds_db()
    if not db:
        raise FileNotFoundError(
            "No default credentials database found. "
            "Install: pip3 install defaultcreds-cheat-sheet"
        )
    return _match_default_creds(service, version, banner, db)


def flare_search(domain: str, api_key: str = None,
                 tenant: str = None) -> list[dict]:
    """Search Flare.io for dark web exposure by domain.

    Args:
        domain: Target domain
        api_key: Flare API key (or FLARE_API_KEY env)
        tenant: Flare tenant ID (or FLARE_TENANT env)

    Returns:
        List of exposure finding dicts
    """
    api_key = api_key or os.environ.get("FLARE_API_KEY", "")
    tenant = tenant or os.environ.get("FLARE_TENANT", "")

    if not api_key or not tenant:
        raise ValueError("Flare API key and tenant required. "
                         "Set FLARE_API_KEY and FLARE_TENANT env vars.")

    return _query_flare(domain, api_key, tenant)

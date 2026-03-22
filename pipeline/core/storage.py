"""SQLite storage for structured recon data + JSON file export."""

import json
import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timezone

from .config import get_config

log = logging.getLogger(__name__)


class Storage:
    """Persistent storage for all pipeline data."""

    def __init__(self):
        cfg = get_config()["storage"]
        self.base_dir = Path(cfg["base_dir"])
        self.db_path = Path(cfg["db_path"])
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS programs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    platform TEXT,
                    url TEXT,
                    scope_json TEXT,
                    roe_json TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_id INTEGER REFERENCES programs(id),
                    domain TEXT NOT NULL,
                    source TEXT,
                    first_seen TEXT DEFAULT (datetime('now')),
                    last_seen TEXT DEFAULT (datetime('now')),
                    UNIQUE(program_id, domain)
                );

                CREATE TABLE IF NOT EXISTS dns_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subdomain_id INTEGER REFERENCES subdomains(id),
                    record_type TEXT,
                    value TEXT,
                    updated_at TEXT DEFAULT (datetime('now')),
                    UNIQUE(subdomain_id, record_type, value)
                );

                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subdomain_id INTEGER REFERENCES subdomains(id),
                    ip TEXT,
                    port INTEGER,
                    protocol TEXT DEFAULT 'tcp',
                    service TEXT,
                    banner TEXT,
                    version TEXT,
                    state TEXT DEFAULT 'open',
                    updated_at TEXT DEFAULT (datetime('now')),
                    UNIQUE(subdomain_id, ip, port, protocol)
                );

                CREATE TABLE IF NOT EXISTS http_services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subdomain_id INTEGER REFERENCES subdomains(id),
                    url TEXT NOT NULL,
                    status_code INTEGER,
                    title TEXT,
                    tech_json TEXT,
                    headers_json TEXT,
                    content_length INTEGER,
                    webserver TEXT,
                    redirect_url TEXT,
                    screenshot_path TEXT,
                    updated_at TEXT DEFAULT (datetime('now')),
                    UNIQUE(url)
                );

                CREATE TABLE IF NOT EXISTS urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    http_service_id INTEGER REFERENCES http_services(id),
                    url TEXT NOT NULL,
                    method TEXT DEFAULT 'GET',
                    source TEXT,
                    params_json TEXT,
                    discovered_at TEXT DEFAULT (datetime('now')),
                    UNIQUE(url, method)
                );

                CREATE TABLE IF NOT EXISTS js_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    http_service_id INTEGER REFERENCES http_services(id),
                    url TEXT NOT NULL UNIQUE,
                    hash TEXT,
                    secrets_json TEXT,
                    endpoints_json TEXT,
                    analyzed_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_id INTEGER REFERENCES programs(id),
                    subdomain_id INTEGER REFERENCES subdomains(id),
                    tool TEXT,
                    template_id TEXT,
                    severity TEXT,
                    title TEXT,
                    description TEXT,
                    url TEXT,
                    matched_at TEXT,
                    evidence TEXT,
                    raw_json TEXT,
                    status TEXT DEFAULT 'new',
                    cve_id TEXT,
                    cvss_score REAL,
                    false_positive INTEGER DEFAULT 0,
                    dedup_hash TEXT,
                    discovered_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS cves (
                    id TEXT PRIMARY KEY,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    severity TEXT,
                    description TEXT,
                    published TEXT,
                    affected_product TEXT,
                    affected_versions TEXT,
                    references_json TEXT,
                    updated_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS finding_cves (
                    finding_id INTEGER REFERENCES findings(id),
                    cve_id TEXT REFERENCES cves(id),
                    confidence TEXT DEFAULT 'medium',
                    PRIMARY KEY (finding_id, cve_id)
                );

                CREATE TABLE IF NOT EXISTS fp_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_type TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    reason TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS asn_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_id INTEGER REFERENCES programs(id),
                    domain TEXT NOT NULL,
                    asn TEXT NOT NULL,
                    org_name TEXT,
                    ip_ranges_json TEXT,
                    discovered_at TEXT DEFAULT (datetime('now')),
                    UNIQUE(program_id, asn)
                );

                CREATE TABLE IF NOT EXISTS shodan_hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_id INTEGER REFERENCES programs(id),
                    ip TEXT NOT NULL,
                    domain TEXT,
                    ports_json TEXT,
                    os TEXT,
                    org TEXT,
                    vulns_json TEXT,
                    source TEXT,
                    discovered_at TEXT DEFAULT (datetime('now')),
                    UNIQUE(program_id, ip)
                );

                CREATE TABLE IF NOT EXISTS github_leaks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_id INTEGER REFERENCES programs(id),
                    domain TEXT NOT NULL,
                    category TEXT,
                    repo TEXT,
                    file_path TEXT,
                    url TEXT,
                    dork TEXT,
                    discovered_at TEXT DEFAULT (datetime('now')),
                    UNIQUE(program_id, url)
                );

                CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain);
                CREATE INDEX IF NOT EXISTS idx_ports_ip ON ports(ip);
                CREATE INDEX IF NOT EXISTS idx_http_url ON http_services(url);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
                CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
                CREATE INDEX IF NOT EXISTS idx_asn_domain ON asn_data(domain);
                CREATE INDEX IF NOT EXISTS idx_shodan_ip ON shodan_hosts(ip);

                CREATE TABLE IF NOT EXISTS apex_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_id INTEGER REFERENCES programs(id),
                    domain TEXT NOT NULL,
                    source TEXT,
                    discovered_at TEXT DEFAULT (datetime('now')),
                    UNIQUE(program_id, domain)
                );

                CREATE TABLE IF NOT EXISTS vhosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_id INTEGER REFERENCES programs(id),
                    ip TEXT NOT NULL,
                    vhost TEXT NOT NULL,
                    port INTEGER,
                    status_code INTEGER,
                    discovered_at TEXT DEFAULT (datetime('now')),
                    UNIQUE(program_id, ip, vhost)
                );

                CREATE TABLE IF NOT EXISTS takeover_candidates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_id INTEGER REFERENCES programs(id),
                    subdomain TEXT NOT NULL,
                    cname TEXT,
                    service TEXT,
                    confidence TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'unconfirmed',
                    discovered_at TEXT DEFAULT (datetime('now')),
                    UNIQUE(program_id, subdomain)
                );

                CREATE INDEX IF NOT EXISTS idx_apex_domain ON apex_domains(domain);
                CREATE INDEX IF NOT EXISTS idx_vhosts_ip ON vhosts(ip);
                CREATE INDEX IF NOT EXISTS idx_takeover_subdomain ON takeover_candidates(subdomain);
            """)

            # Migrate existing tables (add new columns safely)
            self._migrate(conn, "programs", {
                "roe_json": "ALTER TABLE programs ADD COLUMN roe_json TEXT",
            })
            self._migrate(conn, "findings", {
                "cve_id": "ALTER TABLE findings ADD COLUMN cve_id TEXT",
                "cvss_score": "ALTER TABLE findings ADD COLUMN cvss_score REAL",
                "false_positive": "ALTER TABLE findings ADD COLUMN false_positive INTEGER DEFAULT 0",
                "dedup_hash": "ALTER TABLE findings ADD COLUMN dedup_hash TEXT",
            })
            self._migrate(conn, "http_services", {
                "asn": "ALTER TABLE http_services ADD COLUMN asn TEXT",
                "cdn": "ALTER TABLE http_services ADD COLUMN cdn TEXT",
                "ip": "ALTER TABLE http_services ADD COLUMN ip TEXT",
            })

            # Create indexes on potentially-migrated columns (safe after migration)
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id)",
                "CREATE INDEX IF NOT EXISTS idx_findings_dedup ON findings(dedup_hash)",
                "CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(false_positive)",
                # UNIQUE indexes that may be missing from DBs created before these
                # constraints were added to the CREATE TABLE statements
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_records_unique ON dns_records(subdomain_id, record_type, value)",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_ports_unique ON ports(subdomain_id, ip, port, protocol)",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_urls_unique ON urls(url, method)",
            ]:
                try:
                    conn.execute(idx_sql)
                except sqlite3.OperationalError:
                    pass

    def _migrate(self, conn: sqlite3.Connection, table: str, migrations: dict):
        """Add missing columns to an existing table."""
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        for col, sql in migrations.items():
            if col not in cols:
                try:
                    conn.execute(sql)
                except sqlite3.OperationalError:
                    pass

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    # --- Programs ---

    def upsert_program(self, name: str, platform: str = None, url: str = None,
                       scope: list = None, roe: dict = None) -> int:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO programs (name, platform, url, scope_json, roe_json, updated_at)
                   VALUES (?, ?, ?, ?, ?, datetime('now'))
                   ON CONFLICT(name) DO UPDATE SET
                     platform=COALESCE(excluded.platform, platform),
                     url=COALESCE(excluded.url, url),
                     scope_json=COALESCE(excluded.scope_json, scope_json),
                     roe_json=COALESCE(excluded.roe_json, roe_json),
                     updated_at=datetime('now')""",
                (name, platform, url,
                 json.dumps(scope) if scope else None,
                 json.dumps(roe) if roe else None),
            )
            row = conn.execute("SELECT id FROM programs WHERE name=?", (name,)).fetchone()
            return row["id"]

    def get_program_roe(self, program_id: int) -> dict:
        """Return the RoE dict for a program, or empty dict if not set."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT roe_json FROM programs WHERE id=?", (program_id,)
            ).fetchone()
        if row and row["roe_json"]:
            try:
                return json.loads(row["roe_json"])
            except (json.JSONDecodeError, TypeError):
                pass
        return {}

    def get_program(self, name: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM programs WHERE name=?", (name,)).fetchone()
            return dict(row) if row else None

    def list_programs(self) -> list[dict]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM programs").fetchall()]

    # --- Subdomains ---

    def upsert_subdomain(self, program_id: int, domain: str, source: str = None) -> int:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO subdomains (program_id, domain, source, last_seen)
                   VALUES (?, ?, ?, datetime('now'))
                   ON CONFLICT(program_id, domain) DO UPDATE SET
                     last_seen=datetime('now'),
                     source=COALESCE(excluded.source, source)""",
                (program_id, domain, source),
            )
            row = conn.execute(
                "SELECT id FROM subdomains WHERE program_id=? AND domain=?",
                (program_id, domain),
            ).fetchone()
            return row["id"]

    def get_subdomains(self, program_id: int) -> list[dict]:
        with self._conn() as conn:
            return [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM subdomains WHERE program_id=?", (program_id,)
                ).fetchall()
            ]

    # --- Ports ---

    def upsert_port(self, subdomain_id: int, ip: str, port: int, **kwargs) -> int:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO ports (subdomain_id, ip, port, protocol, service, banner, version, state, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                   ON CONFLICT(subdomain_id, ip, port, protocol) DO UPDATE SET
                     service=COALESCE(excluded.service, service),
                     banner=COALESCE(excluded.banner, banner),
                     version=COALESCE(excluded.version, version),
                     state=COALESCE(excluded.state, state),
                     updated_at=datetime('now')""",
                (
                    subdomain_id, ip, port,
                    kwargs.get("protocol", "tcp"),
                    kwargs.get("service"),
                    kwargs.get("banner"),
                    kwargs.get("version"),
                    kwargs.get("state", "open"),
                ),
            )
            row = conn.execute(
                "SELECT id FROM ports WHERE subdomain_id=? AND ip=? AND port=? AND protocol=?",
                (subdomain_id, ip, port, kwargs.get("protocol", "tcp")),
            ).fetchone()
            return row["id"]

    # --- HTTP Services ---

    def upsert_http_service(self, subdomain_id: int, url: str, **kwargs) -> int:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO http_services (subdomain_id, url, status_code, title, tech_json,
                   headers_json, content_length, webserver, redirect_url, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                   ON CONFLICT(url) DO UPDATE SET
                     status_code=COALESCE(excluded.status_code, status_code),
                     title=COALESCE(excluded.title, title),
                     tech_json=COALESCE(excluded.tech_json, tech_json),
                     headers_json=COALESCE(excluded.headers_json, headers_json),
                     content_length=COALESCE(excluded.content_length, content_length),
                     webserver=COALESCE(excluded.webserver, webserver),
                     redirect_url=COALESCE(excluded.redirect_url, redirect_url),
                     updated_at=datetime('now')""",
                (
                    subdomain_id, url,
                    kwargs.get("status_code"),
                    kwargs.get("title"),
                    json.dumps(kwargs["tech"]) if "tech" in kwargs else None,
                    json.dumps(kwargs["headers"]) if "headers" in kwargs else None,
                    kwargs.get("content_length"),
                    kwargs.get("webserver"),
                    kwargs.get("redirect_url"),
                ),
            )
            row = conn.execute("SELECT id FROM http_services WHERE url=?", (url,)).fetchone()
            return row["id"]

    # --- URLs ---

    def upsert_url(self, http_service_id: int, url: str, method: str = "GET", source: str = None, params: dict = None):
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO urls (http_service_id, url, method, source, params_json)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(url, method) DO UPDATE SET
                     source=COALESCE(excluded.source, source)""",
                (http_service_id, url, method, source, json.dumps(params) if params else None),
            )

    # --- JS Files ---

    def upsert_js_file(self, http_service_id: int, url: str, **kwargs):
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO js_files (http_service_id, url, hash, secrets_json, endpoints_json, analyzed_at)
                   VALUES (?, ?, ?, ?, ?, datetime('now'))
                   ON CONFLICT(url) DO UPDATE SET
                     hash=COALESCE(excluded.hash, hash),
                     secrets_json=COALESCE(excluded.secrets_json, secrets_json),
                     endpoints_json=COALESCE(excluded.endpoints_json, endpoints_json),
                     analyzed_at=datetime('now')""",
                (
                    http_service_id, url,
                    kwargs.get("hash"),
                    json.dumps(kwargs["secrets"]) if "secrets" in kwargs else None,
                    json.dumps(kwargs["endpoints"]) if "endpoints" in kwargs else None,
                ),
            )

    # --- Findings ---

    def add_finding(self, program_id: int, **kwargs) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO findings (program_id, subdomain_id, tool, template_id, severity,
                   title, description, url, matched_at, evidence, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    program_id,
                    kwargs.get("subdomain_id"),
                    kwargs.get("tool"),
                    kwargs.get("template_id"),
                    kwargs.get("severity"),
                    kwargs.get("title"),
                    kwargs.get("description"),
                    kwargs.get("url"),
                    kwargs.get("matched_at"),
                    kwargs.get("evidence"),
                    json.dumps(kwargs.get("raw")) if "raw" in kwargs else None,
                ),
            )
            return cur.lastrowid

    def add_finding_deduped(self, program_id: int, dedup_hash: str, **kwargs) -> int | None:
        """Add a finding only if the dedup_hash is new. Returns finding ID or None if duplicate."""
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT id FROM findings WHERE dedup_hash=? AND false_positive=0",
                (dedup_hash,),
            ).fetchone()
            if existing:
                return None

            cur = conn.execute(
                """INSERT INTO findings (program_id, subdomain_id, tool, template_id, severity,
                   title, description, url, matched_at, evidence, raw_json, cve_id, cvss_score, dedup_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    program_id,
                    kwargs.get("subdomain_id"),
                    kwargs.get("tool"),
                    kwargs.get("template_id"),
                    kwargs.get("severity"),
                    kwargs.get("title"),
                    kwargs.get("description"),
                    kwargs.get("url"),
                    kwargs.get("matched_at"),
                    kwargs.get("evidence"),
                    json.dumps(kwargs.get("raw")) if "raw" in kwargs else None,
                    kwargs.get("cve_id"),
                    kwargs.get("cvss_score"),
                    dedup_hash,
                ),
            )
            return cur.lastrowid

    def update_finding(self, finding_id: int, **kwargs):
        """Update finding fields."""
        allowed = {"status", "severity", "cve_id", "cvss_score", "false_positive", "description"}
        sets = []
        params = []
        for k, v in kwargs.items():
            if k in allowed:
                sets.append(f"{k}=?")
                params.append(v)
        if sets:
            params.append(finding_id)
            with self._conn() as conn:
                conn.execute(f"UPDATE findings SET {', '.join(sets)} WHERE id=?", params)

    # --- CVEs ---

    def upsert_cve(self, cve_id: str, **kwargs):
        """Store or update a CVE record."""
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO cves (id, cvss_score, cvss_vector, severity, description,
                   published, affected_product, affected_versions, references_json, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                   ON CONFLICT(id) DO UPDATE SET
                     cvss_score=COALESCE(excluded.cvss_score, cvss_score),
                     cvss_vector=COALESCE(excluded.cvss_vector, cvss_vector),
                     severity=COALESCE(excluded.severity, severity),
                     description=COALESCE(excluded.description, description),
                     affected_product=COALESCE(excluded.affected_product, affected_product),
                     affected_versions=COALESCE(excluded.affected_versions, affected_versions),
                     references_json=COALESCE(excluded.references_json, references_json),
                     updated_at=datetime('now')""",
                (
                    cve_id,
                    kwargs.get("cvss_score"),
                    kwargs.get("cvss_vector"),
                    kwargs.get("severity"),
                    kwargs.get("description"),
                    kwargs.get("published"),
                    kwargs.get("affected_product"),
                    kwargs.get("affected_versions"),
                    json.dumps(kwargs["references"]) if "references" in kwargs else None,
                ),
            )

    def link_finding_cve(self, finding_id: int, cve_id: str, confidence: str = "medium"):
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO finding_cves (finding_id, cve_id, confidence) VALUES (?, ?, ?)",
                (finding_id, cve_id, confidence),
            )

    def get_cve(self, cve_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM cves WHERE id=?", (cve_id,)).fetchone()
            return dict(row) if row else None

    def get_finding_cves(self, finding_id: int) -> list[dict]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(
                """SELECT c.*, fc.confidence FROM cves c
                   JOIN finding_cves fc ON c.id = fc.cve_id
                   WHERE fc.finding_id=?""",
                (finding_id,),
            ).fetchall()]

    # --- False Positive Rules ---

    def add_fp_rule(self, rule_type: str, pattern: str, reason: str = None) -> int:
        """Add a false positive filtering rule.
        rule_type: 'template_id', 'title', 'url_pattern', 'severity'
        """
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO fp_rules (rule_type, pattern, reason) VALUES (?, ?, ?)",
                (rule_type, pattern, reason),
            )
            return cur.lastrowid

    def get_fp_rules(self) -> list[dict]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM fp_rules").fetchall()]

    def delete_fp_rule(self, rule_id: int):
        with self._conn() as conn:
            conn.execute("DELETE FROM fp_rules WHERE id=?", (rule_id,))

    def get_findings(self, program_id: int = None, severity: str = None,
                     status: str = None, include_fp: bool = False) -> list[dict]:
        with self._conn() as conn:
            query = "SELECT * FROM findings WHERE 1=1"
            params = []
            if not include_fp:
                query += " AND false_positive=0"
            if program_id:
                query += " AND program_id=?"
                params.append(program_id)
            if severity:
                query += " AND severity=?"
                params.append(severity)
            if status:
                query += " AND status=?"
                params.append(status)
            query += " ORDER BY cvss_score DESC NULLS LAST, discovered_at DESC"
            findings = [dict(r) for r in conn.execute(query, params).fetchall()]

            # Attach CVE data
            for f in findings:
                f["cves"] = [dict(r) for r in conn.execute(
                    """SELECT c.id, c.cvss_score, c.severity, c.description
                       FROM cves c JOIN finding_cves fc ON c.id=fc.cve_id
                       WHERE fc.finding_id=?""",
                    (f["id"],),
                ).fetchall()]

            return findings

    # --- Apex Domains ---

    def upsert_apex_domain(self, program_id: int, domain: str, source: str = None) -> int:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO apex_domains (program_id, domain, source)
                   VALUES (?, ?, ?)
                   ON CONFLICT(program_id, domain) DO UPDATE SET
                     source=COALESCE(excluded.source, source)""",
                (program_id, domain, source),
            )
            row = conn.execute(
                "SELECT id FROM apex_domains WHERE program_id=? AND domain=?",
                (program_id, domain),
            ).fetchone()
            return row["id"] if row else None

    def get_apex_domains(self, program_id: int) -> list[dict]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM apex_domains WHERE program_id=?", (program_id,)
            ).fetchall()]

    # --- Virtual Hosts ---

    def upsert_vhost(self, program_id: int, ip: str, vhost: str,
                     port: int = None, status_code: int = None) -> int:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO vhosts (program_id, ip, vhost, port, status_code)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(program_id, ip, vhost) DO UPDATE SET
                     status_code=COALESCE(excluded.status_code, status_code)""",
                (program_id, ip, vhost, port, status_code),
            )
            row = conn.execute(
                "SELECT id FROM vhosts WHERE program_id=? AND ip=? AND vhost=?",
                (program_id, ip, vhost),
            ).fetchone()
            return row["id"] if row else None

    def get_vhosts(self, program_id: int) -> list[dict]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM vhosts WHERE program_id=?", (program_id,)
            ).fetchall()]

    # --- Takeover Candidates ---

    def upsert_takeover_candidate(self, program_id: int, subdomain: str, **kwargs) -> int:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO takeover_candidates
                   (program_id, subdomain, cname, service, confidence, status)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(program_id, subdomain) DO UPDATE SET
                     cname=COALESCE(excluded.cname, cname),
                     service=COALESCE(excluded.service, service),
                     confidence=COALESCE(excluded.confidence, confidence)""",
                (
                    program_id, subdomain,
                    kwargs.get("cname"),
                    kwargs.get("service"),
                    kwargs.get("confidence", "medium"),
                    kwargs.get("status", "unconfirmed"),
                ),
            )
            row = conn.execute(
                "SELECT id FROM takeover_candidates WHERE program_id=? AND subdomain=?",
                (program_id, subdomain),
            ).fetchone()
            return row["id"] if row else None

    def get_takeover_candidates(self, program_id: int) -> list[dict]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM takeover_candidates WHERE program_id=?", (program_id,)
            ).fetchall()]

    # --- Endpoint CSV export ---

    def get_endpoints_for_csv(self, program_name: str) -> list[dict]:
        """Query all HTTP services + URLs for a program, formatted for CSV export."""
        program = self.get_program(program_name)
        if not program:
            return []
        pid = program["id"]

        with self._conn() as conn:
            rows = conn.execute(
                """SELECT
                    hs.url, hs.status_code, hs.title, hs.content_length,
                    hs.webserver, hs.tech_json, hs.ip, hs.asn, hs.cdn,
                    s.domain as source_apex,
                    hs.updated_at as timestamp
                   FROM http_services hs
                   JOIN subdomains s ON s.id = hs.subdomain_id
                   WHERE s.program_id = ?
                   ORDER BY hs.updated_at DESC""",
                (pid,),
            ).fetchall()

        results = []
        for r in rows:
            row = dict(r)
            tech_raw = row.pop("tech_json", None)
            tech = ""
            if tech_raw:
                try:
                    import json as _json
                    t = _json.loads(tech_raw)
                    tech = ",".join(t.keys()) if isinstance(t, dict) else ",".join(str(x) for x in t)
                except Exception:
                    tech = str(tech_raw)
            row["tech"] = tech
            row["program"] = program_name
            row["method"] = "GET"
            row["params"] = ""
            row["port"] = ""
            row["source_tool"] = "httpx"
            results.append(row)

        return results

    # --- Export for Claude Code analysis ---

    def export_program_data(self, program_name: str) -> dict:
        """Export all data for a program as a structured dict for Claude Code analysis."""
        program = self.get_program(program_name)
        if not program:
            return {}

        pid = program["id"]
        with self._conn() as conn:
            subdomains = [dict(r) for r in conn.execute(
                "SELECT * FROM subdomains WHERE program_id=?", (pid,)
            ).fetchall()]

            for sub in subdomains:
                sid = sub["id"]
                sub["dns_records"] = [dict(r) for r in conn.execute(
                    "SELECT * FROM dns_records WHERE subdomain_id=?", (sid,)
                ).fetchall()]
                sub["ports"] = [dict(r) for r in conn.execute(
                    "SELECT * FROM ports WHERE subdomain_id=?", (sid,)
                ).fetchall()]
                sub["http_services"] = [dict(r) for r in conn.execute(
                    "SELECT * FROM http_services WHERE subdomain_id=?", (sid,)
                ).fetchall()]
                for svc in sub["http_services"]:
                    hid = svc["id"]
                    svc["urls"] = [dict(r) for r in conn.execute(
                        "SELECT * FROM urls WHERE http_service_id=?", (hid,)
                    ).fetchall()]
                    svc["js_files"] = [dict(r) for r in conn.execute(
                        "SELECT * FROM js_files WHERE http_service_id=?", (hid,)
                    ).fetchall()]

            findings = [dict(r) for r in conn.execute(
                "SELECT * FROM findings WHERE program_id=?", (pid,)
            ).fetchall()]

        return {
            "program": program,
            "subdomains": subdomains,
            "findings": findings,
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }

    def export_program_json(self, program_name: str) -> Path:
        """Export program data to a JSON file for Claude Code consumption."""
        data = self.export_program_data(program_name)
        if not data:
            return None
        out_dir = self.base_dir / "programs" / program_name
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "export.json"
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        log.info(f"Exported {program_name} data to {out_path}")
        return out_path

    # --- Stats ---

    def stats(self) -> dict:
        with self._conn() as conn:
            return {
                "programs": conn.execute("SELECT COUNT(*) FROM programs").fetchone()[0],
                "subdomains": conn.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0],
                "ports": conn.execute("SELECT COUNT(*) FROM ports").fetchone()[0],
                "http_services": conn.execute("SELECT COUNT(*) FROM http_services").fetchone()[0],
                "urls": conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0],
                "js_files": conn.execute("SELECT COUNT(*) FROM js_files").fetchone()[0],
                "findings": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
                "findings_by_severity": {
                    r[0]: r[1]
                    for r in conn.execute(
                        "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
                    ).fetchall()
                },
            }

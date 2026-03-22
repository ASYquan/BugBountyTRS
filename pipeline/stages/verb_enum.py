"""HTTP verb enumeration stage.

For high-value endpoints, tests all HTTP methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD.
Reports divergences — the most common being GET=403 but another method succeeds.

The transcript insight: "Sometimes one call gives you a 403, but another gives you a full
stack trace. That tells you which systems are polished and which ones were forgotten."

High-value targets:
  - Any path containing /api/, /v1/, /admin/, /internal/, /graphql/, etc.
  - Endpoints that returned 401/403/405 on GET (auth-gated = worth bypassing)

Consumes: recon_urls
Publishes: vuln_findings
"""

import json
import logging
import subprocess
from urllib.parse import urlparse

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.ratelimit import active_scan_slot

log = logging.getLogger(__name__)

_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

_API_PATTERNS = (
    "/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/rest/", "/graphql",
    "/admin/", "/internal/", "/backend/", "/service/", "/microservice/",
    "/user", "/users", "/account", "/accounts", "/profile",
    "/dashboard", "/manage", "/management", "/console",
    "/data/", "/export/", "/import/", "/upload/", "/download/",
)

_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
}


def _is_high_value(url: str, status_code: int = None) -> bool:
    """Return True if this URL warrants HTTP verb testing."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    path = parsed.path.lower()
    basename = path.rsplit("/", 1)[-1]
    if "." in basename:
        ext = "." + basename.rsplit(".", 1)[-1].split("?")[0]
        if ext in _SKIP_EXTENSIONS:
            return False

    if any(pat in path for pat in _API_PATTERNS):
        return True

    # Auth-gated or method-restricted on GET — worth trying other verbs
    if status_code and status_code in (401, 403, 405):
        return True

    return False


class VerbEnumWorker(BaseWorker):
    """HTTP verb enumeration worker."""

    name = "verb_enum"
    input_stream = "recon_urls"
    output_streams = ["vuln_findings"]

    def dedup_key(self, data: dict) -> str:
        return f"verb:{data.get('url', '')}"

    def process(self, data: dict) -> list[dict]:
        url = data.get("url")
        program = data.get("program")
        program_id = data.get("program_id")
        subdomain_id = data.get("subdomain_id")
        source_status = data.get("status_code")

        if not url:
            return []
        if not _is_high_value(url, source_status):
            return []

        constraints = self.roe_constraints(data)
        if not self.is_scanning_allowed(constraints, "verb_enum"):
            return []
        rate_limit = constraints["rate_limit_rps"]

        log.info(f"[verb_enum] Testing {url}")

        with active_scan_slot(program_id):
            method_results = _probe_all_methods(url, rate_limit=rate_limit, constraints=constraints)

        if not method_results:
            return []

        return _find_divergences(
            url=url,
            results=method_results,
            program=program,
            program_id=program_id,
            subdomain_id=subdomain_id,
        )


def _probe_all_methods(url: str, rate_limit: int = 20, constraints: dict = None) -> dict:
    """Probe URL with all HTTP methods. Returns {method: {status, length}} dict."""
    c = constraints or {}
    ua = c.get("required_user_agent") or "Mozilla/5.0"

    results = {}
    for method in _METHODS:
        cmd = [
            "httpx",
            "-u", url,
            "-method", method,
            "-status-code",
            "-content-length",
            "-no-color",
            "-silent",
            "-timeout", "10",
            "-rl", str(rate_limit),
            "-H", f"User-Agent: {ua}",
        ]
        for name, value in (c.get("required_headers") or {}).items():
            cmd.extend(["-H", f"{name}: {value}"])

        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
            ).stdout.strip()

            if not out:
                continue

            # httpx output format: url [status_code] [content_length]
            # Extract bracketed numbers
            status = None
            length = None
            for part in out.split():
                if part.startswith("[") and part.endswith("]"):
                    val = part[1:-1]
                    if val.isdigit():
                        n = int(val)
                        if 100 <= n < 600:
                            status = n
                        elif n >= 600:
                            length = n

            if status:
                results[method] = {"status": status, "length": length}

        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    return results


def _find_divergences(url: str, results: dict, program: str,
                      program_id, subdomain_id) -> list[dict]:
    """Identify interesting method divergences and return findings."""
    findings = []
    get_status = results.get("GET", {}).get("status")
    get_length = results.get("GET", {}).get("length", 0) or 0

    # 1. GET is restricted but another method succeeds
    if get_status and get_status in (401, 403, 404, 405):
        for method, r in results.items():
            if method == "GET":
                continue
            status = r.get("status")
            if status and status < 400:
                length = r.get("length", 0) or 0
                # Skip if response size is identical to GET (same response, different code)
                if abs(length - get_length) < 50 and length > 0:
                    continue
                sev = "high" if status < 300 else "medium"
                findings.append({
                    "program": program,
                    "program_id": program_id,
                    "subdomain_id": subdomain_id,
                    "tool": "verb_enum",
                    "severity": sev,
                    "title": f"HTTP verb bypass: {method} → {status} (GET → {get_status}) on {url}",
                    "url": url,
                    "evidence": json.dumps({
                        "url": url,
                        "get_status": get_status,
                        "bypass_method": method,
                        "bypass_status": status,
                        "bypass_length": length,
                        "all_results": results,
                    }),
                })
                log.warning(
                    f"[verb_enum] BYPASS: {method} {url} → {status} (GET={get_status})"
                )

    # 2. Destructive methods not disabled (PUT/DELETE/PATCH not returning 405)
    for method in ("PUT", "DELETE", "PATCH"):
        r = results.get(method, {})
        status = r.get("status")
        if status and status != 405 and status != 501:
            sev = "high" if status < 300 else "medium" if status < 400 else "low"
            findings.append({
                "program": program,
                "program_id": program_id,
                "subdomain_id": subdomain_id,
                "tool": "verb_enum",
                "severity": sev,
                "title": f"Dangerous method not blocked: {method} → {status} on {url}",
                "url": url,
                "evidence": json.dumps({
                    "url": url,
                    "method": method,
                    "status": status,
                    "note": "Server returned non-405 for a destructive HTTP method.",
                    "all_results": results,
                }),
            })
            log.warning(f"[verb_enum] Dangerous method {method} → {status}: {url}")

    # 3. OPTIONS returns 200 — manual CORS/Allow header check needed
    options_status = results.get("OPTIONS", {}).get("status")
    if options_status == 200:
        findings.append({
            "program": program,
            "program_id": program_id,
            "subdomain_id": subdomain_id,
            "tool": "verb_enum",
            "severity": "info",
            "title": f"OPTIONS 200 — check Allow: and CORS headers: {url}",
            "url": url,
            "evidence": json.dumps({
                "url": url,
                "note": (
                    "OPTIONS returned 200. Manually check Allow: and "
                    "Access-Control-Allow-Methods: headers for CORS misconfiguration "
                    "or unexpectedly broad method permissions."
                ),
                "all_results": results,
            }),
        })

    return findings

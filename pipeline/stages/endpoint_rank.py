"""Endpoint interest ranking — noise reduction for recon_urls.

Scores every URL flowing through recon_urls by interest signals.
High-score endpoints are emitted as findings so they surface in the priority queue.
Low-score endpoints (boilerplate CSS, generic 200s) are silently dropped.

The transcript insight: "If your script is dumping endpoints without context,
you're not automating recon — you're automating noise. Good automation is precise."

Scoring signals:
  Source:         JS-sourced (+6), wayback (+5), brute-forced (+2)
  Path:           admin/debug/api/backup/config paths (+4)
  Status:         401/403 auth-gated (+4), 500 server error (+3), 200 (+1)
  Extensions:     .env/.bak/.sql = critical (+8), .js/.json (+2)
  Content length: large body on 4xx response = likely verbose error (+3)
  Parameters:     query params present (+1 each, max +3)

HIGH_INTEREST_THRESHOLD = 8 (tune in config)

Consumes: recon_urls
Publishes: vuln_findings (high-score endpoints only)
"""

import json
import logging
import re
from urllib.parse import urlparse, parse_qs

from ..core.worker import BaseWorker

log = logging.getLogger(__name__)

HIGH_INTEREST_THRESHOLD = 8

_HIGH_INTEREST_PATHS = (
    "/admin", "/internal", "/debug", "/test", "/dev", "/staging",
    "/backup", "/old", "/legacy", "/deprecated",
    "/v0/", "/v1/", "/v2/", "/v3/", "/api/",
    "/graphql", "/swagger", "/openapi", "/docs/api",
    "/config", "/settings", "/env",
    "/health", "/metrics", "/status", "/info",
    "/.git", "/.env", "/wp-admin", "/phpmyadmin", "/adminer",
    "/console", "/actuator", "/management", "/monitor",
    "/upload", "/uploads", "/files", "/export", "/import",
)

_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".avi",
}

_CRITICAL_EXTENSIONS = {".env", ".config", ".conf", ".bak", ".backup", ".old",
                         ".orig", ".sql", ".db", ".log", ".pem", ".key", ".cert"}

_HIGH_VALUE_EXTENSIONS = {".js", ".json", ".xml", ".yaml", ".yml", ".map"}


def score_url(url: str, source: str = "",
              status_code: int = None, content_length: int = None) -> tuple[int, list[str]]:
    """Score a URL for interest. Returns (score, [reason strings])."""
    score = 0
    reasons = []

    try:
        parsed = urlparse(url)
    except Exception:
        return 0, []

    path = parsed.path.lower()
    basename = path.rsplit("/", 1)[-1]
    ext = ""
    if "." in basename:
        ext = "." + basename.rsplit(".", 1)[-1].split("?")[0]

    # Static assets are zero interest
    if ext in _SKIP_EXTENSIONS:
        return 0, []

    # ── Source ────────────────────────────────────────────────────────────────
    if source in ("js_analyze", "js_keywords", "linkfinder"):
        score += 6
        reasons.append("JS-sourced: not in HTML, likely a hidden endpoint")
    elif source == "wayback":
        score += 5
        reasons.append("Wayback-sourced: historical URL, may be forgotten")
    elif source in ("content_discovery", "feroxbuster", "ffuf"):
        score += 2
        reasons.append("Brute-forced: not linked from any page")

    # ── Path patterns ─────────────────────────────────────────────────────────
    for pat in _HIGH_INTEREST_PATHS:
        if path == pat or path.startswith(pat + "/") or f"{pat}/" in path or path.endswith(pat):
            score += 4
            reasons.append(f"High-interest path: {pat}")
            break

    # Dynamic path segment (numeric ID)
    if re.search(r'/\d+(/|$|\?)', path):
        score += 1
        reasons.append("Dynamic path (numeric ID segment)")

    # Query parameters — each is a potential injection point
    if parsed.query:
        params = list(parse_qs(parsed.query).keys())
        bonus = min(len(params), 3)
        score += bonus
        reasons.append(f"{len(params)} query param(s): {', '.join(params[:5])}")

    # ── Extension ─────────────────────────────────────────────────────────────
    if ext in _CRITICAL_EXTENSIONS:
        score += 8
        reasons.append(f"CRITICAL extension {ext}: likely sensitive file exposure")
    elif ext in _HIGH_VALUE_EXTENSIONS:
        score += 2
        reasons.append(f"High-value extension: {ext}")

    # ── Status code ───────────────────────────────────────────────────────────
    if status_code:
        if status_code in (401, 403):
            score += 4
            reasons.append(f"Auth-gated ({status_code}): worth bypass/verb testing")
        elif status_code in (500, 502, 503):
            score += 3
            reasons.append(f"Server error ({status_code}): may leak stack trace")
        elif status_code == 200:
            score += 1
        elif status_code == 404:
            score -= 1

    # ── Content length anomalies ──────────────────────────────────────────────
    if content_length and status_code:
        if status_code in (403, 401, 404) and content_length > 5000:
            score += 3
            reasons.append(
                f"Large {status_code} response ({content_length}b): "
                "possible verbose error or stack trace in body"
            )
        elif content_length == 0 and status_code == 200:
            score -= 1  # empty 200 = likely false positive

    return score, reasons


class EndpointRankWorker(BaseWorker):
    """Scores URLs as they arrive and emits high-interest ones as findings."""

    name = "endpoint_rank"
    input_stream = "recon_urls"
    output_streams = ["vuln_findings"]

    def dedup_key(self, data: dict) -> str:
        return f"rank:{data.get('url', '')}"

    def process(self, data: dict) -> list[dict]:
        url = data.get("url")
        if not url:
            return []

        score, reasons = score_url(
            url=url,
            source=data.get("source", ""),
            status_code=data.get("status_code"),
            content_length=data.get("content_length"),
        )

        if score < HIGH_INTEREST_THRESHOLD:
            return []

        program = data.get("program")
        program_id = data.get("program_id")
        subdomain_id = data.get("subdomain_id")
        severity = "low" if score >= 12 else "info"

        log.info(f"[endpoint_rank] score={score} {url}")

        return [{
            "program": program,
            "program_id": program_id,
            "subdomain_id": subdomain_id,
            "tool": "endpoint_rank",
            "template_id": "endpoint-rank",  # stable — dedup hash = sha256(endpoint-rank:url:)
            "severity": severity,
            "title": f"High-interest endpoint (score={score}): {url}",
            "url": url,
            "evidence": json.dumps({
                "url": url,
                "score": score,
                "source": data.get("source", ""),
                "status_code": data.get("status_code"),
                "reasons": reasons,
            }),
        }]

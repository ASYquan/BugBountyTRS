"""JavaScript analysis stage.

Consumes JS file URLs from recon_js stream.
Downloads and analyzes JavaScript files for:
- Hardcoded secrets (API keys, tokens, passwords)
- API endpoints
- Interesting comments
"""

import subprocess
import re
import hashlib
import json
import logging
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from ..core.worker import BaseWorker
from ..core.config import get_config

log = logging.getLogger(__name__)

# Patterns for secret detection
SECRET_PATTERNS = {
    "aws_key": r"(?:AKIA[0-9A-Z]{16})",
    "aws_secret": r"(?:[0-9a-zA-Z/+]{40})",
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "slack_token": r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    "jwt": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "private_key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "generic_secret": r"""(?:secret|password|passwd|token|apikey|api_key|api[-_]?secret)[\s]*[:=][\s]*['\"][^\s'\"]{8,}['\"]""",
    "bearer_token": r"""[Bb]earer\s+[A-Za-z0-9\-_\.]+""",
    "basic_auth": r"""[Bb]asic\s+[A-Za-z0-9+/=]{20,}""",
    "firebase_url": r"https://[a-z0-9-]+\.firebaseio\.com",
    "s3_bucket": r"[a-z0-9.-]+\.s3\.amazonaws\.com",
    "internal_ip": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
}

# Patterns for API endpoint detection
ENDPOINT_PATTERNS = [
    r"""['\"](?:/api/[^\s'\"]+)['\"]""",
    r"""['\"](?:/v[0-9]+/[^\s'\"]+)['\"]""",
    r"""['\"](?:https?://[^\s'\"]+/api/[^\s'\"]+)['\"]""",
    r"""fetch\s*\(\s*['\"]([^\s'\"]+)['\"]""",
    r"""axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['\"]([^\s'\"]+)['\"]""",
    r"""\.ajax\s*\(\s*\{[^}]*url\s*:\s*['\"]([^\s'\"]+)['\"]""",
    r"""XMLHttpRequest.*?open\s*\(['\"](?:GET|POST|PUT|DELETE)['\"],\s*['\"]([^\s'\"]+)['\"]""",
]


class JSAnalyzeWorker(BaseWorker):
    name = "js_analyze"
    input_stream = "recon_js"
    output_streams = ["vuln_findings"]

    def dedup_key(self, data: dict) -> str:
        return f"js:{data.get('url', '')}"

    def process(self, data: dict) -> list[dict]:
        js_url = data.get("url")
        program = data.get("program")
        program_id = data.get("program_id")
        subdomain_id = data.get("subdomain_id")

        if not js_url:
            return []

        # Download JS file
        content = self._download(js_url)
        if not content:
            return []

        content_hash = hashlib.sha256(content.encode()).hexdigest()

        # Analyze — merge regex results with LinkFinder (handles minified/bundled JS)
        secrets = self._find_secrets(content)
        endpoints_regex = self._find_endpoints(content)
        endpoints_lf = self._linkfinder_endpoints(js_url)
        endpoints = sorted(set(endpoints_regex) | set(endpoints_lf))

        # Store
        with self.storage._conn() as conn:
            row = conn.execute(
                "SELECT id FROM http_services WHERE url LIKE ?",
                (f"%{urlparse(js_url).netloc}%",)
            ).fetchone()
            http_svc_id = row["id"] if row else None

        if http_svc_id:
            self.storage.upsert_js_file(
                http_service_id=http_svc_id,
                url=js_url,
                hash=content_hash,
                secrets=secrets,
                endpoints=endpoints,
            )

        results = []

        # Create findings for discovered secrets
        for secret in secrets:
            finding = {
                "program": program,
                "program_id": program_id,
                "subdomain_id": subdomain_id,
                "tool": "js_analyze",
                "severity": "high" if secret["type"] in ("aws_key", "private_key", "github_token") else "medium",
                "title": f"Secret found in JS: {secret['type']}",
                "url": js_url,
                "evidence": secret["match"][:200],
            }
            results.append(finding)

            self.storage.add_finding(
                program_id,
                subdomain_id=subdomain_id,
                tool="js_analyze",
                template_id=f"js-secret-{secret['type']}",
                severity=finding["severity"],
                title=finding["title"],
                url=js_url,
                matched_at=js_url,
                evidence=secret["match"][:500],
            )

        if secrets:
            log.warning(f"[js] Found {len(secrets)} secrets in {js_url}")
        if endpoints:
            log.info(f"[js] Found {len(endpoints)} endpoints in {js_url}")

        return results

    def _download(self, url: str) -> str | None:
        inti_cfg = get_config().get("intigriti", {})
        ua = inti_cfg.get("user_agent", "Mozilla/5.0")
        req_header = inti_cfg.get("request_header", "")
        curl_cmd = ["curl", "-sL", "--max-time", "15",
                    "-H", f"User-Agent: {ua}"]
        if req_header:
            curl_cmd.extend(["-H", req_header])
        curl_cmd.extend(["-o", "-", url])
        try:
            result = subprocess.run(
                curl_cmd,
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode == 0 and result.stdout:
                return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    def _find_secrets(self, content: str) -> list[dict]:
        secrets = []
        for name, pattern in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, content, re.IGNORECASE):
                # Skip common false positives
                matched = match.group(0)
                if self._is_false_positive(name, matched):
                    continue
                secrets.append({
                    "type": name,
                    "match": matched,
                    "position": match.start(),
                })
        return secrets

    def _find_endpoints(self, content: str) -> list[str]:
        endpoints = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content):
                ep = match.group(1) if match.lastindex else match.group(0)
                ep = ep.strip("'\"")
                if len(ep) > 5 and not ep.startswith("//"):
                    endpoints.add(ep)
        return sorted(endpoints)

    def _linkfinder_endpoints(self, js_url: str) -> list[str]:
        """Run LinkFinder against a JS URL.

        LinkFinder deobfuscates minified JS with jsbeautifier before regex matching,
        finding endpoints our raw-content regex misses in bundled code.
        Falls back silently if linkfinder is not installed.
        """
        cfg = get_config()
        inti_cfg = cfg.get("intigriti", {})
        ua = inti_cfg.get("user_agent", "Mozilla/5.0")
        req_header = inti_cfg.get("request_header", "")

        # Try both common install locations
        for cmd_name in ("linkfinder", "linkfinder.py",
                         "/usr/local/bin/linkfinder.py",
                         "/opt/LinkFinder/linkfinder.py"):
            cmd = ["python3", cmd_name, "-i", js_url, "-o", "cli",
                   "--user-agent", ua] if cmd_name.endswith(".py") else \
                  [cmd_name, "-i", js_url, "-o", "cli", "--user-agent", ua]
            if req_header:
                cmd.extend(["--header", req_header])
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0 and result.stdout.strip():
                    endpoints = []
                    for line in result.stdout.strip().splitlines():
                        line = line.strip()
                        if line and not line.startswith("[") and len(line) > 3:
                            endpoints.append(line)
                    if endpoints:
                        log.debug(f"[js] LinkFinder found {len(endpoints)} endpoints in {js_url}")
                    return endpoints
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                log.debug(f"[js] LinkFinder timed out on {js_url}")
                return []
            except Exception:
                continue

        return []

    def _is_false_positive(self, secret_type: str, value: str) -> bool:
        """Basic false positive filtering."""
        # Skip common placeholder values
        placeholders = {"YOUR_API_KEY", "INSERT_KEY_HERE", "xxx", "example", "test", "dummy"}
        lower = value.lower()
        if any(p in lower for p in placeholders):
            return True
        # Skip minified variable names that match patterns
        if secret_type == "generic_secret" and len(value) < 15:
            return True
        return False

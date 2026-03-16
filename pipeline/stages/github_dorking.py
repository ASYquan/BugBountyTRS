"""GitHub dorking stage.

Searches GitHub for secrets, subdomains, and sensitive information
leaked in public repositories related to the target.

Uses GitHub Search API to find:
  - API keys, tokens, credentials
  - Subdomains and internal URLs
  - Configuration files
  - Database connection strings
"""

import json
import os
import re
import subprocess
import logging
import time

from ..core.worker import BaseWorker
from ..core.config import get_config

log = logging.getLogger(__name__)

# GitHub search dorks by category
GITHUB_DORKS = {
    "credentials": [
        '"{domain}" password',
        '"{domain}" secret',
        '"{domain}" api_key',
        '"{domain}" apikey',
        '"{domain}" access_token',
        '"{domain}" bearer',
        '"{domain}" AWS_SECRET_ACCESS_KEY',
        '"{domain}" PRIVATE KEY',
    ],
    "config": [
        '"{domain}" filename:.env',
        '"{domain}" filename:.yml password',
        '"{domain}" filename:.config',
        '"{domain}" filename:wp-config.php',
        '"{domain}" filename:configuration.php',
        '"{domain}" filename:.htpasswd',
        '"{domain}" filename:id_rsa',
    ],
    "database": [
        '"{domain}" filename:.sql',
        '"{domain}" "jdbc:" password',
        '"{domain}" "mongodb+srv://"',
        '"{domain}" "redis://"',
        '"{domain}" "postgresql://"',
    ],
    "subdomains": [
        '"{domain}" "subdomain"',
        '"{domain}" site:"{domain}"',
        '"{domain}" filename:subdomains.txt',
    ],
    "internal": [
        '"{domain}" inurl:internal',
        '"{domain}" "staging" OR "dev" OR "uat"',
        '"{domain}" filename:hosts',
        '"{domain}" "vpn" OR "proxy" OR "jump"',
    ],
}


class GitHubDorkWorker(BaseWorker):
    """Searches GitHub for leaked secrets and subdomains.

    Consumes domains from scope_targets and publishes findings.
    """
    name = "github_dork"
    input_stream = "scope_targets"
    output_streams = ["vuln_findings"]

    def __init__(self):
        super().__init__()
        self._token = None

    def on_start(self):
        self._token = (
            os.environ.get("GITHUB_TOKEN")
            or get_config().get("github", {}).get("token")
        )
        if not self._token:
            log.warning("[github] No GitHub token configured. Set GITHUB_TOKEN env var")

    def dedup_key(self, data: dict) -> str:
        return f"github_dork:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        if not self._token:
            return []

        domain = data.get("domain")
        program = data.get("program")
        program_id = data.get("program_id")

        if not domain:
            return []

        log.info(f"[github] Dorking for {domain} ({program})")
        results = []

        for category, dorks in GITHUB_DORKS.items():
            for dork_template in dorks:
                dork = dork_template.replace("{domain}", domain)
                hits = self._search_github(dork)

                for hit in hits:
                    results.append({
                        "program": program,
                        "program_id": program_id,
                        "tool": "github-dork",
                        "severity": "medium" if category == "credentials" else "info",
                        "title": f"GitHub leak ({category}): {hit['repo']}",
                        "url": hit["html_url"],
                        "matched_at": hit["html_url"],
                        "evidence": f"Query: {dork}\nFile: {hit['path']}\nRepo: {hit['repo']}",
                    })

                # Respect GitHub rate limits (30 req/min for search)
                time.sleep(2.5)

        log.info(f"[github] Found {len(results)} potential leaks for {domain}")
        return results

    def _search_github(self, query: str, max_results: int = 5) -> list[dict]:
        """Search GitHub code using the API."""
        try:
            result = subprocess.run(
                [
                    "gh", "api", "search/code",
                    "-X", "GET",
                    "--field", f"q={query}",
                    "--field", "per_page=5",
                    "--jq", ".items[] | {repo: .repository.full_name, path: .path, html_url: .html_url}",
                ],
                capture_output=True, text=True, timeout=30,
            )
            hits = []
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if line:
                    try:
                        hits.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return hits[:max_results]
        except Exception as e:
            log.debug(f"GitHub search failed for query '{query[:50]}': {e}")
            return []


# ─── Standalone functions for CLI ───────────────────────────────


def github_dork_domain(domain: str, categories: list[str] = None) -> list[dict]:
    """Run GitHub dorks for a domain. Returns list of hits."""
    if categories is None:
        categories = list(GITHUB_DORKS.keys())

    all_hits = []
    for category in categories:
        dorks = GITHUB_DORKS.get(category, [])
        for dork_template in dorks:
            dork = dork_template.replace("{domain}", domain)
            try:
                result = subprocess.run(
                    [
                        "gh", "api", "search/code",
                        "-X", "GET",
                        "--field", f"q={dork}",
                        "--field", "per_page=5",
                        "--jq", ".items[] | {repo: .repository.full_name, path: .path, html_url: .html_url, score: .score}",
                    ],
                    capture_output=True, text=True, timeout=30,
                )
                for line in result.stdout.strip().splitlines():
                    if line.strip():
                        try:
                            hit = json.loads(line.strip())
                            hit["category"] = category
                            hit["dork"] = dork
                            all_hits.append(hit)
                        except json.JSONDecodeError:
                            continue
            except Exception:
                continue
            time.sleep(2.5)  # Rate limit

    return all_hits

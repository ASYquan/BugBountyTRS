"""Bug bounty platform integrations.

Auto-sync program scopes from HackerOne and Intigriti APIs.
Both platforms offer public program listings that can be consumed
without authentication for public programs.
"""

import subprocess
import json
import logging
import re

from ..core.config import get_config
from .scope import ScopeManager

log = logging.getLogger(__name__)


class HackerOneSync:
    """Sync program scopes from HackerOne.

    Requires H1 API credentials set in config or env:
      H1_API_USER / H1_API_TOKEN
    Or uses public program data.
    """

    API_BASE = "https://api.hackerone.com/v1"

    def __init__(self, scope_manager: ScopeManager, api_user: str = None, api_token: str = None):
        self.scope = scope_manager
        self.api_user = api_user
        self.api_token = api_token

    def sync_program(self, handle: str):
        """Sync a single program by handle."""
        log.info(f"[h1] Syncing program: {handle}")

        # Fetch program scope via API
        if self.api_user and self.api_token:
            data = self._api_fetch(f"/hackerone/programs/{handle}")
        else:
            # Use public GraphQL endpoint
            data = self._public_fetch(handle)

        if not data:
            log.warning(f"[h1] Failed to fetch program: {handle}")
            return

        wildcards = []
        domains = []
        excludes = []

        for asset in data.get("assets", []):
            asset_type = asset.get("asset_type", "")
            identifier = asset.get("identifier", "")
            eligible = asset.get("eligible_for_bounty", True)

            if not eligible:
                continue

            if asset_type == "URL":
                if identifier.startswith("*."):
                    wildcards.append(identifier)
                elif re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", identifier):
                    domains.append(identifier)
                else:
                    # URL with path, extract domain
                    domain = re.match(r"https?://([^/]+)", identifier)
                    if domain:
                        domains.append(domain.group(1))

            elif asset_type == "WILDCARD":
                wildcards.append(identifier)

        self.scope.add_program(
            name=f"h1-{handle}",
            platform="hackerone",
            url=f"https://hackerone.com/{handle}",
            wildcards=wildcards,
            domains=domains,
            excludes=excludes,
        )
        log.info(f"[h1] Synced {handle}: {len(wildcards)} wildcards, {len(domains)} domains")

    def _api_fetch(self, endpoint: str) -> dict | None:
        try:
            result = subprocess.run(
                [
                    "curl", "-sL",
                    "-u", f"{self.api_user}:{self.api_token}",
                    "-H", "Accept: application/json",
                    f"{self.API_BASE}{endpoint}",
                ],
                capture_output=True, text=True, timeout=30,
            )
            data = json.loads(result.stdout)
            program = data.get("data", {}).get("attributes", {})
            # Parse structured_scopes
            assets = []
            scopes = data.get("relationships", {}).get("structured_scopes", {}).get("data", [])
            for s in scopes:
                attrs = s.get("attributes", {})
                assets.append({
                    "asset_type": attrs.get("asset_type"),
                    "identifier": attrs.get("asset_identifier"),
                    "eligible_for_bounty": attrs.get("eligible_for_bounty"),
                })
            return {"assets": assets}
        except Exception as e:
            log.error(f"[h1] API error: {e}")
            return None

    def _public_fetch(self, handle: str) -> dict | None:
        """Fetch public program scope without API credentials."""
        try:
            # Use the public directory endpoint
            result = subprocess.run(
                [
                    "curl", "-sL",
                    "-H", "Accept: application/json",
                    f"https://hackerone.com/{handle}",
                ],
                capture_output=True, text=True, timeout=30,
            )
            # Try to extract scope from page data
            # This is a best-effort approach for public programs
            assets = []
            # Look for JSON-LD or embedded scope data
            for match in re.finditer(r'"asset_identifier"\s*:\s*"([^"]+)"', result.stdout):
                identifier = match.group(1)
                if identifier.startswith("*."):
                    assets.append({"asset_type": "WILDCARD", "identifier": identifier, "eligible_for_bounty": True})
                else:
                    assets.append({"asset_type": "URL", "identifier": identifier, "eligible_for_bounty": True})

            return {"assets": assets} if assets else None
        except Exception as e:
            log.error(f"[h1] Public fetch error: {e}")
            return None


class IntigritiSync:
    """Sync program scopes from Intigriti.

    Uses public program listings. Optional API token for private programs.
    """

    API_BASE = "https://api.intigriti.com"

    def __init__(self, scope_manager: ScopeManager, api_token: str = None):
        self.scope = scope_manager
        self.api_token = api_token

    def sync_program(self, company_handle: str, program_handle: str = None):
        """Sync a program from Intigriti."""
        log.info(f"[intigriti] Syncing program: {company_handle}")

        data = self._fetch_program(company_handle, program_handle)
        if not data:
            log.warning(f"[intigriti] Failed to fetch program: {company_handle}")
            return

        wildcards = []
        domains = []
        excludes = []

        for domain_entry in data.get("domains", []):
            endpoint = domain_entry.get("endpoint", "")
            dtype = domain_entry.get("type", {}).get("value", 0)
            tier = domain_entry.get("tier", {}).get("value", 0)

            # Type 1 = URL, Type 6 = Wildcard
            if dtype in (1, 6) or endpoint.startswith("*."):
                if endpoint.startswith("*."):
                    wildcards.append(endpoint)
                elif re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", endpoint):
                    domains.append(endpoint)
                else:
                    domain = re.match(r"https?://([^/]+)", endpoint)
                    if domain:
                        domains.append(domain.group(1))

        # Check for out-of-scope entries
        for oos in data.get("outOfScopes", []):
            endpoint = oos.get("endpoint", "")
            if endpoint:
                excludes.append(endpoint)

        name = f"intigriti-{company_handle}"
        if program_handle:
            name += f"-{program_handle}"

        self.scope.add_program(
            name=name,
            platform="intigriti",
            url=f"https://app.intigriti.com/programs/{company_handle}",
            wildcards=wildcards,
            domains=domains,
            excludes=excludes,
        )
        log.info(f"[intigriti] Synced {company_handle}: {len(wildcards)} wildcards, {len(domains)} domains")

    def list_programs(self) -> list[dict]:
        """List available programs on Intigriti."""
        try:
            headers = ["-H", "Accept: application/json"]
            if self.api_token:
                headers.extend(["-H", f"Authorization: Bearer {self.api_token}"])

            result = subprocess.run(
                ["curl", "-sL"] + headers + [f"{self.API_BASE}/core/program"],
                capture_output=True, text=True, timeout=30,
            )
            data = json.loads(result.stdout)
            return data if isinstance(data, list) else data.get("records", [])
        except Exception as e:
            log.error(f"[intigriti] List error: {e}")
            return []

    def _fetch_program(self, company_handle: str, program_handle: str = None) -> dict | None:
        try:
            headers = ["-H", "Accept: application/json"]
            if self.api_token:
                headers.extend(["-H", f"Authorization: Bearer {self.api_token}"])

            endpoint = f"{self.API_BASE}/core/program/{company_handle}"
            if program_handle:
                endpoint += f"/{program_handle}"

            result = subprocess.run(
                ["curl", "-sL"] + headers + [endpoint],
                capture_output=True, text=True, timeout=30,
            )
            return json.loads(result.stdout)
        except Exception as e:
            log.error(f"[intigriti] Fetch error: {e}")
            return None

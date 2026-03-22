"""Bug bounty platform integrations.

Primary: Intigriti (researcher API v1)
Secondary: HackerOne

Intigriti researcher API: https://api.intigriti.com/external/researcher/v1/
  GET /programs                    — list all accessible programs
  GET /programs/{id}/domains       — in-scope domains for a program
  GET /program-activities          — scope change events (new domains added/removed)

Auth: Bearer token via config.intigriti.api_token or INTIGRITI_TOKEN env var.
"""

import os
import json
import logging
import re
import time

import requests

from ..core.config import get_config
from .scope import ScopeManager

log = logging.getLogger(__name__)

# Intigriti scope domain type values
_INTIGRITI_TYPE_URL = 1
_INTIGRITI_TYPE_CIDR = 2
_INTIGRITI_TYPE_MOBILE = 4
_INTIGRITI_TYPE_WILDCARD = 6


class IntigritiSync:
    """Sync program scopes from Intigriti researcher API.

    Uses the /external/researcher/v1/ API — requires a researcher API token.
    Set token via config.intigriti.api_token or INTIGRITI_TOKEN env var.
    """

    API_BASE = "https://api.intigriti.com/external/researcher/v1"

    def __init__(self, scope_manager: ScopeManager, api_token: str = None):
        self.scope = scope_manager
        cfg = get_config()
        self.api_token = (
            api_token
            or os.environ.get("INTIGRITI_TOKEN")
            or cfg.get("intigriti", {}).get("api_token", "")
        )
        if not self.api_token:
            log.warning("[intigriti] No API token configured — only public programs accessible")

    # ── Public API ────────────────────────────────────────────────

    def list_programs(self) -> list[dict]:
        """Return all programs accessible to the authenticated researcher.

        Paginates through all results (API returns 50 per page, maxCount can be 197+).
        """
        all_programs = []
        offset = 0
        limit = 100

        while True:
            data = self._get("/programs", params={"limit": limit, "offset": offset})
            if data is None:
                break

            if isinstance(data, list):
                all_programs.extend(data)
                break  # No pagination info — assume single page

            records = data.get("records", data.get("data", []))
            all_programs.extend(records)

            max_count = data.get("maxCount", 0)
            offset += limit
            if offset >= max_count or not records:
                break

        return all_programs

    def sync_program(self, program_id: str):
        """Sync a single program by its Intigriti UUID.

        Domains are embedded in the program detail response under domains.content[].
        There is no separate /domains endpoint in the researcher API v1.
        RoE is fetched automatically and stored alongside scope.
        """
        log.info(f"[intigriti] Syncing program: {program_id}")

        program_data = self._get(f"/programs/{program_id}")
        if not program_data:
            log.warning(f"[intigriti] Failed to fetch program: {program_id}")
            return

        # Domains are embedded — no separate /domains call needed
        domains_content = program_data.get("domains", {}).get("content", [])
        wildcards, domains, cidr_ranges, excludes = self._parse_scope(domains_content)

        handle = program_data.get("handle", program_id)
        name = f"intigriti-{handle}"
        web_links = program_data.get("webLinks", {}) or {}
        url = web_links.get("detail") or f"https://app.intigriti.com/programs/{handle}"

        # Fetch and parse RoE
        roe = self.fetch_roe(program_id, program_data)

        self.scope.add_program(
            name=name,
            platform="intigriti",
            url=url,
            wildcards=wildcards,
            domains=domains,
            excludes=excludes,
            roe=roe,
        )
        log.info(
            f"[intigriti] Synced {handle}: "
            f"{len(wildcards)} wildcards, {len(domains)} domains, "
            f"{len(cidr_ranges)} CIDRs"
            + (f", RoE fetched" if roe else "")
        )
        return {"wildcards": wildcards, "domains": domains, "cidr_ranges": cidr_ranges, "roe": roe}

    def fetch_roe(self, program_id: str, program_data: dict = None) -> dict | None:
        """Fetch and parse the Rules of Engagement for a program.

        First checks if RoE is embedded in program_data (from the detail endpoint).
        Falls back to the dedicated /rules-of-engagements/{versionId} endpoint.
        Returns a parsed constraints dict, or None if unavailable.
        """
        raw_roe = None

        # Try embedded RoE in program detail response
        if program_data:
            raw_roe = (
                program_data.get("rulesOfEngagements")
                or program_data.get("rulesOfEngagement")
                or program_data.get("roe")
            )

        # If embedded gave us only a reference (has an id/latestVersion), fetch the full doc
        if isinstance(raw_roe, dict) and not raw_roe.get("description"):
            version_id = (
                raw_roe.get("id")
                or (raw_roe.get("latestVersion") or {}).get("id")
            )
            if version_id:
                raw_roe = self._get(f"/programs/{program_id}/rules-of-engagements/{version_id}")

        # If still nothing embedded, try listing versions from the dedicated sub-resource
        if not raw_roe:
            versions = self._get(f"/programs/{program_id}/rules-of-engagements")
            if isinstance(versions, list) and versions:
                # Take the most recent version
                version_id = versions[0].get("id") or versions[0].get("versionId")
                if version_id:
                    raw_roe = self._get(f"/programs/{program_id}/rules-of-engagements/{version_id}")
            elif isinstance(versions, dict):
                version_id = versions.get("id")
                if version_id:
                    raw_roe = self._get(f"/programs/{program_id}/rules-of-engagements/{version_id}")

        if not raw_roe:
            log.debug(f"[intigriti] No RoE found for program {program_id}")
            return None

        return self.parse_roe_constraints(raw_roe)

    @staticmethod
    def parse_roe_constraints(raw: dict) -> dict:
        """Normalise a raw Intigriti RoE response into pipeline-usable constraints.

        Returned dict keys:
          rate_limit_rps          - int, max requests/sec (default 20 if unspecified)
          automated_scanning      - "allowed" | "restricted" | "not_allowed"
          required_headers        - dict of header_name -> value
          required_user_agent     - str or None
          intigriti_me_required   - bool (must test via intigriti.me subdomain)
          safe_harbour            - bool
          description             - str, full policy text
          raw                     - original API response
        """
        testing = raw.get("testingRequirements") or {}

        # Required headers
        headers = {}
        for h in (testing.get("requestHeaders") or []):
            name = h.get("name") or h.get("key") or ""
            value = h.get("value") or ""
            if name:
                headers[name] = value

        # Automated scanning stance
        auto_raw = (
            testing.get("automatedTooling")
            or testing.get("automatedScanning")
            or testing.get("automated")
            or ""
        )
        auto_raw = str(auto_raw).lower()
        if "not" in auto_raw or "disallow" in auto_raw or auto_raw == "false":
            automated = "not_allowed"
        elif "restrict" in auto_raw or "limit" in auto_raw:
            automated = "restricted"
        else:
            automated = "allowed"

        # Rate limit — Intigriti doesn't always specify one explicitly;
        # default to 20 req/sec (Visma-level conservative)
        rate_limit = int(testing.get("rateLimit") or testing.get("maxRequestsPerSecond") or 20)

        return {
            "rate_limit_rps": rate_limit,
            "automated_scanning": automated,
            "required_headers": headers,
            "required_user_agent": testing.get("userAgent") or testing.get("user_agent"),
            "intigriti_me_required": bool(testing.get("intigritiMe") or testing.get("intigriti_me")),
            "safe_harbour": bool(raw.get("safeHarbour") or raw.get("safe_harbour") or raw.get("safeHarbor")),
            "description": raw.get("description") or "",
            "raw": raw,
        }

    def sync_all_programs(self):
        """Sync all programs accessible to this researcher token."""
        programs = self.list_programs()
        if not programs:
            log.warning("[intigriti] No programs found — check API token and permissions")
            return

        log.info(f"[intigriti] Syncing {len(programs)} programs")
        synced = 0
        for prog in programs:
            prog_id = self._extract_program_id(prog)
            if not prog_id:
                continue
            try:
                self.sync_program(prog_id)
                synced += 1
                time.sleep(0.5)  # Gentle rate limiting between program fetches
            except Exception as e:
                log.error(f"[intigriti] Error syncing {prog_id}: {e}")

        log.info(f"[intigriti] Sync complete: {synced}/{len(programs)} programs")

    def poll_program_activities(self, since_timestamp: int = None) -> list[dict]:
        """Fetch recent scope change events.

        Returns a list of activity dicts. Each has at minimum:
          - programId
          - activityType (e.g. 'domain_added', 'domain_removed')
          - endpoint / domain affected

        Caller should trigger re-scan of newly added domains.
        """
        params = {}
        if since_timestamp:
            params["since"] = since_timestamp

        data = self._get("/program-activities", params=params)
        if data is None:
            return []

        activities = data if isinstance(data, list) else data.get("records", data.get("data", []))
        log.info(f"[intigriti] Retrieved {len(activities)} program activities")
        return activities

    def extract_new_domains_from_activities(self, activities: list[dict]) -> list[dict]:
        """Parse program-activities response and return newly added in-scope domains.

        Returns list of dicts: {program_id, domain, type}
        """
        new_domains = []
        for activity in activities:
            activity_type = (
                activity.get("activityType", "")
                or activity.get("type", "")
            ).lower()

            # Only care about additions
            if "add" not in activity_type and "new" not in activity_type:
                continue

            prog_id = activity.get("programId") or activity.get("program", {}).get("id", "")
            endpoint = (
                activity.get("endpoint")
                or activity.get("domain")
                or activity.get("asset", {}).get("endpoint", "")
            )
            dtype = (
                activity.get("domainType")
                or activity.get("type", {}).get("value", 0)
            )

            if not endpoint or not prog_id:
                continue

            new_domains.append({
                "program_id": prog_id,
                "domain": endpoint,
                "type": dtype,
            })

        return new_domains

    # ── Private helpers ───────────────────────────────────────────

    def _get(self, path: str, params: dict = None) -> dict | list | None:
        """Make an authenticated GET request to the researcher API."""
        headers = {"Accept": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        url = f"{self.API_BASE}{path}"
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as e:
            log.error(f"[intigriti] HTTP {e.response.status_code} for {path}: {e}")
            return None
        except Exception as e:
            log.error(f"[intigriti] Request failed for {path}: {e}")
            return None

    def _parse_scope(self, content: list) -> tuple[list, list, list, list]:
        """Parse Intigriti domains.content[] into (wildcards, domains, cidrs, excludes).

        Each entry has:
          type.value: "Wildcard", "URL", "CIDR", "Android", "iOS", "Other", etc.
          endpoint:   the asset string
          tier.value: "No Bounty", "Low", "Medium", "High", "Critical"
        """
        wildcards = []
        domains = []
        cidr_ranges = []
        excludes = []

        _SKIP_TYPES = {"android", "ios", "mobile", "other", "executable", "sourcecodefile"}

        for entry in content:
            endpoint = entry.get("endpoint", "").strip()
            if not endpoint:
                continue

            type_value = (entry.get("type") or {}).get("value", "").lower()

            # Skip non-web assets
            if type_value in _SKIP_TYPES:
                continue

            if type_value == "wildcard" or endpoint.startswith("*."):
                wildcards.append(endpoint)
            elif type_value == "cidr" or (re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", endpoint)):
                cidr_ranges.append(endpoint)
            elif type_value in ("url", "domain", ""):
                if re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", endpoint):
                    domains.append(endpoint)
                else:
                    m = re.match(r"https?://([^/:]+)", endpoint)
                    if m:
                        domains.append(m.group(1))

        return wildcards, domains, cidr_ranges, excludes

    def _extract_program_id(self, program: dict) -> str | None:
        """Extract a usable program ID string from a program dict."""
        # Try common field names
        for key in ("id", "programId", "handle", "slug"):
            val = program.get(key)
            if val:
                return str(val)
        # Try nested
        company = program.get("company", {}) or {}
        handle = program.get("handle") or company.get("handle")
        if handle:
            return handle
        return None


# ── HackerOne (secondary platform) ───────────────────────────────


class HackerOneSync:
    """Sync program scopes from HackerOne.

    Secondary platform. Requires H1 API credentials:
      H1_API_USER / H1_API_TOKEN env vars, or set in config.
    """

    API_BASE = "https://api.hackerone.com/v1"

    def __init__(self, scope_manager: ScopeManager, api_user: str = None, api_token: str = None):
        self.scope = scope_manager
        self.api_user = api_user or os.environ.get("H1_API_USER", "")
        self.api_token = api_token or os.environ.get("H1_API_TOKEN", "")

    def sync_program(self, handle: str):
        """Sync a single program by handle."""
        log.info(f"[h1] Syncing program: {handle}")

        if self.api_user and self.api_token:
            data = self._api_fetch(f"/programs/{handle}")
        else:
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
                    m = re.match(r"https?://([^/]+)", identifier)
                    if m:
                        domains.append(m.group(1))
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
            resp = requests.get(
                f"{self.API_BASE}{endpoint}",
                auth=(self.api_user, self.api_token),
                headers={"Accept": "application/json"},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
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
        try:
            resp = requests.get(
                f"https://hackerone.com/{handle}",
                headers={"Accept": "application/json"},
                timeout=30,
            )
            assets = []
            for match in re.finditer(r'"asset_identifier"\s*:\s*"([^"]+)"', resp.text):
                identifier = match.group(1)
                if identifier.startswith("*."):
                    assets.append({"asset_type": "WILDCARD", "identifier": identifier, "eligible_for_bounty": True})
                else:
                    assets.append({"asset_type": "URL", "identifier": identifier, "eligible_for_bounty": True})
            return {"assets": assets} if assets else None
        except Exception as e:
            log.error(f"[h1] Public fetch error: {e}")
            return None

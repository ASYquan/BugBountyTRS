"""Scope management stage.

Manages bug bounty program scopes. Loads programs from YAML definitions
and publishes target domains to the pipeline for continuous recon.
"""

import re
import logging
from pathlib import Path

import yaml

from ..core.config import get_config
from ..core.storage import Storage
from ..core.queue import MessageQueue

log = logging.getLogger(__name__)


class ScopeManager:
    """Manages program scopes and feeds targets into the pipeline."""

    def __init__(self):
        self.storage = Storage()
        self.mq = MessageQueue(consumer_group="group:scope", consumer_name="scope-mgr")
        self.programs_dir = Path(get_config()["storage"]["base_dir"]) / "programs"
        self.programs_dir.mkdir(parents=True, exist_ok=True)
        self._scope_patterns = {}  # program_name -> list of compiled regexes

    def add_program(self, name: str, platform: str = None, url: str = None,
                    wildcards: list[str] = None, domains: list[str] = None,
                    excludes: list[str] = None, roe: dict = None):
        """Add or update a bug bounty program."""
        scope = {
            "wildcards": wildcards or [],
            "domains": domains or [],
            "excludes": excludes or [],
        }
        program_id = self.storage.upsert_program(name, platform, url, scope, roe=roe)

        # Save scope file (preserve existing roe block if not provided)
        scope_dir = self.programs_dir / name
        scope_dir.mkdir(parents=True, exist_ok=True)
        scope_file = scope_dir / "scope.yml"

        # Load existing file to preserve roe/contact fields not passed via args
        existing = {}
        if scope_file.exists():
            with open(scope_file) as f:
                existing = yaml.safe_load(f) or {}

        file_data = {
            "name": name,
            "platform": platform,
            "url": url,
            "scope": scope,
        }
        # Preserve extra top-level keys (contact, pgp_fingerprint, roe)
        for extra_key in ("contact", "pgp_fingerprint", "roe"):
            if roe and extra_key == "roe":
                file_data["roe"] = roe
            elif extra_key in existing:
                file_data[extra_key] = existing[extra_key]

        with open(scope_file, "w") as f:
            yaml.dump(file_data, f, default_flow_style=False)

        # Build regex patterns
        self._compile_scope(name, scope)

        log.info(f"Added program '{name}' with {len(scope['wildcards'])} wildcards, {len(scope['domains'])} domains")
        return program_id

    def load_programs(self):
        """Load all program scope definitions from disk."""
        for scope_file in self.programs_dir.glob("*/scope.yml"):
            with open(scope_file) as f:
                data = yaml.safe_load(f)
            if data:
                self.add_program(
                    name=data["name"],
                    platform=data.get("platform"),
                    url=data.get("url"),
                    wildcards=data.get("scope", {}).get("wildcards", []),
                    domains=data.get("scope", {}).get("domains", []),
                    excludes=data.get("scope", {}).get("excludes", []),
                    roe=data.get("roe"),
                )

    def _compile_scope(self, name: str, scope: dict):
        """Compile scope wildcards into regex patterns."""
        patterns = {"include": [], "exclude": []}

        for wc in scope.get("wildcards", []):
            # *.example.com -> matches any subdomain of example.com
            regex = re.escape(wc).replace(r"\*", r"[a-zA-Z0-9\-\.]+")
            patterns["include"].append(re.compile(f"^{regex}$", re.IGNORECASE))

        for d in scope.get("domains", []):
            patterns["include"].append(re.compile(f"^{re.escape(d)}$", re.IGNORECASE))

        for ex in scope.get("excludes", []):
            regex = re.escape(ex).replace(r"\*", r"[a-zA-Z0-9\-\.]+")
            patterns["exclude"].append(re.compile(f"^{regex}$", re.IGNORECASE))

        self._scope_patterns[name] = patterns

    def is_in_scope(self, domain: str, program_name: str = None) -> tuple[bool, str | None]:
        """Check if a domain is in scope for a program (or any program).
        Returns (in_scope, program_name)."""
        programs = [program_name] if program_name else list(self._scope_patterns.keys())

        for pname in programs:
            patterns = self._scope_patterns.get(pname, {"include": [], "exclude": []})

            # Check excludes first
            for pat in patterns["exclude"]:
                if pat.match(domain):
                    return False, None

            # Check includes
            for pat in patterns["include"]:
                if pat.match(domain):
                    return True, pname

        return False, None

    def feed_targets(self, program_filter: str = None):
        """Publish known in-scope domains to the pipeline for scanning.

        Args:
            program_filter: If set, only feed targets for this program name.
        """
        stream = self.mq.stream_name("scope_targets")

        for program in self.storage.list_programs():
            pid = program["id"]
            pname = program["name"]

            if program_filter and pname.lower() != program_filter.lower():
                continue

            # Feed wildcard root domains for subdomain enumeration
            prog = self.storage.get_program(pname)
            if prog and prog["scope_json"]:
                import json
                scope = json.loads(prog["scope_json"])
                for wc in scope.get("wildcards", []):
                    root_domain = wc.lstrip("*.")
                    self.mq.publish(stream, {
                        "program": pname,
                        "program_id": pid,
                        "domain": root_domain,
                        "type": "wildcard",
                    })
                    log.info(f"Published target: {root_domain} ({pname})")

                for d in scope.get("domains", []):
                    self.mq.publish(stream, {
                        "program": pname,
                        "program_id": pid,
                        "domain": d,
                        "type": "domain",
                    })
                    log.info(f"Published target: {d} ({pname})")

    def import_from_file(self, path: str, platform: str = None):
        """Import programs from a simple text file.
        Format: program_name|*.wildcard.com,domain.com|exclude1.com
        """
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                name = parts[0].strip()
                scope_str = parts[1].strip() if len(parts) > 1 else ""
                exclude_str = parts[2].strip() if len(parts) > 2 else ""

                wildcards = []
                domains = []
                for s in scope_str.split(","):
                    s = s.strip()
                    if s.startswith("*."):
                        wildcards.append(s)
                    elif s:
                        domains.append(s)

                excludes = [e.strip() for e in exclude_str.split(",") if e.strip()]

                self.add_program(name, platform=platform, wildcards=wildcards,
                                domains=domains, excludes=excludes)

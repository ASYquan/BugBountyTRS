"""Subdomain discovery stage.

Consumes root domains from scope_targets stream.
Runs multiple passive and active enumeration tools and feeds discovered
subdomains into the recon_subdomains stream.

Tools used:
  - subfinder (passive)
  - amass passive (passive)
  - crt.sh certificate transparency (passive)
  - puredns brute-force (active, optional)
  - alterx permutation generation + resolution (active, optional)
"""

import json
import subprocess
import logging
import tempfile
from pathlib import Path
from urllib.parse import quote

from ..core.worker import BaseWorker
from ..core.config import get_config

log = logging.getLogger(__name__)


class SubdomainWorker(BaseWorker):
    name = "subdomain"
    input_stream = "scope_targets"
    output_streams = ["recon_subdomains"]

    def dedup_key(self, data: dict) -> str:
        return f"subdomain:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        domain = data.get("domain")
        program = data.get("program")
        program_id = data.get("program_id")

        if not domain:
            return []

        log.info(f"[subdomain] Enumerating subdomains for {domain} ({program})")

        subdomains = set()
        cfg = get_config()["tools"].get("subdomain_discovery", {})

        # --- Passive sources ---
        sf_results = self._run_subfinder(domain)
        subdomains.update(sf_results)

        amass_results = self._run_amass_passive(domain)
        subdomains.update(amass_results)

        crtsh_results = self._run_crtsh(domain)
        subdomains.update(crtsh_results)

        crtsh_wc = self._run_crtsh_wildcard(domain)
        subdomains.update(crtsh_wc)

        # Always include the root domain itself
        subdomains.add(domain)

        passive_count = len(subdomains)
        log.info(f"[subdomain] Passive: {passive_count} subdomains for {domain}")

        # --- Active: puredns brute-force (if enabled) ---
        if cfg.get("puredns_enabled", True):
            puredns_results = self._run_puredns(domain)
            subdomains.update(puredns_results)

        # --- Active: alterx permutations (if enabled) ---
        if cfg.get("alterx_enabled", True) and len(subdomains) > 1:
            permutations = self._run_alterx(subdomains)
            if permutations:
                resolved = self._resolve_permutations(permutations, domain)
                subdomains.update(resolved)

        log.info(f"[subdomain] Total: {len(subdomains)} subdomains for {domain} "
                 f"(passive={passive_count}, after active={len(subdomains)})")

        # Store in DB and publish
        results = []
        for sub in subdomains:
            sub = sub.strip().lower().rstrip(".")
            if not sub:
                continue

            # Determine source for DB tracking (prefer detailed subfinder source)
            if sub in sf_results and hasattr(self, '_subfinder_sources') and sub in self._subfinder_sources:
                source = self._subfinder_sources[sub]
            elif sub in sf_results:
                source = "subfinder"
            elif sub in amass_results:
                source = "amass"
            elif sub in crtsh_results or sub in crtsh_wc:
                source = "crtsh"
            else:
                source = "active"

            self.storage.upsert_subdomain(program_id, sub, source=source)

            results.append({
                "program": program,
                "program_id": program_id,
                "domain": sub,
                "parent_domain": domain,
            })

        return results

    # ─── Passive: subfinder ─────────────────────────────────────

    def _run_subfinder(self, domain: str) -> set[str]:
        cfg = get_config()["tools"].get("subfinder", {})
        threads = cfg.get("threads", 30)
        timeout = cfg.get("timeout", 30)
        track_sources = cfg.get("track_sources", True)

        cmd = [
            "subfinder", "-d", domain,
            "-silent",
            "-t", str(threads),
            "-timeout", str(timeout),
            "-all",
        ]
        if track_sources:
            cmd.append("-cs")  # Show source per subdomain (sub,source format)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            subs = set()
            self._subfinder_sources = {}  # sub -> source mapping

            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                if track_sources and "," in line:
                    # -cs output format: subdomain,source
                    parts = line.rsplit(",", 1)
                    sub = parts[0].strip().lower()
                    source = parts[1].strip() if len(parts) > 1 else "subfinder"
                    subs.add(sub)
                    self._subfinder_sources[sub] = f"subfinder:{source}"
                else:
                    subs.add(line.lower())

            if track_sources and self._subfinder_sources:
                log.info(f"[subdomain] subfinder sources: "
                         f"{len(set(self._subfinder_sources.values()))} unique sources")
            return subs
        except FileNotFoundError:
            log.warning("subfinder not found, skipping")
            return set()
        except subprocess.TimeoutExpired:
            log.warning(f"subfinder timed out for {domain}")
            return set()

    # ─── Passive: amass ─────────────────────────────────────────

    def _run_amass_passive(self, domain: str) -> set[str]:
        try:
            result = subprocess.run(
                [
                    "amass", "enum", "-passive",
                    "-d", domain,
                    "-timeout", "5",
                ],
                capture_output=True, text=True, timeout=600,
            )
            return {line.strip() for line in result.stdout.splitlines() if line.strip()}
        except FileNotFoundError:
            log.debug("amass not found, skipping")
            return set()
        except subprocess.TimeoutExpired:
            log.warning(f"amass timed out for {domain}")
            return set()

    # ─── Passive: crt.sh ────────────────────────────────────────

    def _run_crtsh(self, domain: str) -> set[str]:
        """Scrape crt.sh for non-wildcard subdomains."""
        try:
            import urllib.request
            url = f"https://crt.sh/json?identity={quote(domain)}&exclude=expired"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())

            subs = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name and not name.startswith("*.") and name != domain:
                        subs.add(name)

            log.info(f"[subdomain] crt.sh: {len(subs)} non-wildcard subs for {domain}")
            return subs
        except Exception as e:
            log.warning(f"crt.sh query failed for {domain}: {e}")
            return set()

    def _run_crtsh_wildcard(self, domain: str) -> set[str]:
        """Scrape crt.sh for wildcard subdomains (strips *. prefix)."""
        try:
            import urllib.request
            url = f"https://crt.sh/json?identity={quote(domain)}&exclude=expired"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())

            subs = set()
            for entry in data:
                for field in ("name_value", "common_name"):
                    val = entry.get(field, "") or ""
                    for name in val.split("\n"):
                        name = name.strip().lower()
                        if name.startswith("*."):
                            stripped = name[2:].rstrip(".")
                            if stripped and stripped != domain:
                                subs.add(stripped)

            log.info(f"[subdomain] crt.sh wildcard: {len(subs)} subs for {domain}")
            return subs
        except Exception as e:
            log.warning(f"crt.sh wildcard query failed for {domain}: {e}")
            return set()

    # ─── Active: puredns brute-force ────────────────────────────

    def _run_puredns(self, domain: str) -> set[str]:
        """Brute-force subdomains using puredns."""
        cfg = get_config()["tools"].get("puredns", {})
        wordlist = cfg.get("wordlist", "/usr/share/wordlists/SecLists-master/Discovery/DNS/dns-Jhaddix.txt")
        resolvers = cfg.get("resolvers", "/usr/share/wordlists/resolvers.txt")
        rate_limit = cfg.get("rate_limit", 1000)
        rate_limit_trusted = cfg.get("rate_limit_trusted", 300)

        if not Path(wordlist).exists():
            log.warning(f"puredns wordlist not found: {wordlist}, skipping")
            return set()

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
                tmp_path = tmp.name

            cmd = [
                "puredns", "bruteforce", wordlist, domain,
                "--rate-limit", str(rate_limit),
                "--rate-limit-trusted", str(rate_limit_trusted),
                "--write", tmp_path,
            ]

            if Path(resolvers).exists():
                cmd.extend(["--resolvers", resolvers])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

            subs = set()
            if Path(tmp_path).exists():
                with open(tmp_path) as f:
                    subs = {line.strip().lower() for line in f if line.strip()}
                Path(tmp_path).unlink(missing_ok=True)

            log.info(f"[subdomain] puredns: {len(subs)} subs for {domain}")
            return subs
        except FileNotFoundError:
            log.warning("puredns not found, skipping")
            return set()
        except subprocess.TimeoutExpired:
            log.warning(f"puredns timed out for {domain}")
            return set()

    # ─── Active: alterx permutations ────────────────────────────

    def _run_alterx(self, known_subs: set[str]) -> set[str]:
        """Generate subdomain permutations using alterx."""
        try:
            input_text = "\n".join(known_subs)
            result = subprocess.run(
                ["alterx", "-enrich"],
                input=input_text,
                capture_output=True, text=True, timeout=300,
            )
            permutations = {line.strip().lower() for line in result.stdout.splitlines() if line.strip()}
            # Remove already-known subs
            new_perms = permutations - known_subs
            log.info(f"[subdomain] alterx: {len(new_perms)} new permutations from {len(known_subs)} known subs")
            return new_perms
        except FileNotFoundError:
            log.debug("alterx not found, skipping permutations")
            return set()
        except subprocess.TimeoutExpired:
            log.warning("alterx timed out")
            return set()

    def _resolve_permutations(self, permutations: set[str], parent_domain: str) -> set[str]:
        """Resolve permutation candidates using puredns resolve or dnsx."""
        if not permutations:
            return set()

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp_in:
                tmp_in.write("\n".join(permutations))
                tmp_in_path = tmp_in.name

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp_out:
                tmp_out_path = tmp_out.name

            # Try puredns resolve first
            cfg = get_config()["tools"].get("puredns", {})
            resolvers = cfg.get("resolvers", "/usr/share/wordlists/resolvers.txt")

            cmd = ["puredns", "resolve", tmp_in_path, "--write", tmp_out_path]
            if Path(resolvers).exists():
                cmd.extend(["--resolvers", resolvers])

            subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            resolved = set()
            if Path(tmp_out_path).exists():
                with open(tmp_out_path) as f:
                    resolved = {line.strip().lower() for line in f if line.strip()}

            Path(tmp_in_path).unlink(missing_ok=True)
            Path(tmp_out_path).unlink(missing_ok=True)

            log.info(f"[subdomain] Resolved {len(resolved)} permutations for {parent_domain}")
            return resolved

        except FileNotFoundError:
            log.warning("puredns not found for permutation resolution, skipping")
            Path(tmp_in_path).unlink(missing_ok=True)
            return set()
        except subprocess.TimeoutExpired:
            log.warning("permutation resolution timed out")
            return set()
        except Exception as e:
            log.warning(f"permutation resolution failed: {e}")
            return set()


# ─── Standalone one-shot functions (used by CLI recon commands) ──


def crtsh_subdomains(domain: str, wildcard: bool = False) -> set[str]:
    """Query crt.sh for subdomains. Returns a set of domains."""
    import urllib.request
    url = f"https://crt.sh/json?identity={quote(domain)}&exclude=expired"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode())

    subs = set()
    for entry in data:
        if wildcard:
            for field in ("name_value", "common_name"):
                val = entry.get(field, "") or ""
                for name in val.split("\n"):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        subs.add(name[2:].rstrip("."))
        else:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*."):
                    subs.add(name)

    subs.discard(domain)
    return subs


def puredns_bruteforce(domain: str, wordlist: str = None, resolvers: str = None,
                       rate_limit: int = 1000, rate_limit_trusted: int = 300) -> set[str]:
    """Run puredns brute-force and return found subdomains."""
    wordlist = wordlist or "/usr/share/wordlists/SecLists-master/Discovery/DNS/dns-Jhaddix.txt"
    resolvers = resolvers or "/usr/share/wordlists/resolvers.txt"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp_path = tmp.name

    cmd = [
        "puredns", "bruteforce", wordlist, domain,
        "--rate-limit", str(rate_limit),
        "--rate-limit-trusted", str(rate_limit_trusted),
        "--write", tmp_path,
    ]
    if Path(resolvers).exists():
        cmd.extend(["--resolvers", resolvers])

    subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

    subs = set()
    if Path(tmp_path).exists():
        with open(tmp_path) as f:
            subs = {line.strip().lower() for line in f if line.strip()}
        Path(tmp_path).unlink(missing_ok=True)
    return subs


def alterx_permutations(subdomains: list[str]) -> set[str]:
    """Generate permutations from known subdomains using alterx."""
    input_text = "\n".join(subdomains)
    result = subprocess.run(
        ["alterx", "-enrich"],
        input=input_text,
        capture_output=True, text=True, timeout=300,
    )
    return {line.strip().lower() for line in result.stdout.splitlines() if line.strip()}

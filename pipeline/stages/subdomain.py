"""Subdomain discovery stage.

Consumes root domains from scope_targets stream.
Runs multiple passive and active enumeration tools and feeds discovered
subdomains into the recon_subdomains stream.

Tools used (passive):
  - subfinder -all (multi-source, with API key stacking)
  - bbot (finds ~5-8% more than subfinder, run in parallel)
  - SNI data from kaeferjaeger.gay (pre-scanned cloud cert data)

Tools used (active, optional):
  - puredns bruteforce (DNS brute-force)
  - alterx -enrich + puredns resolve (permutation generation)

Removed (deprecated):
  - crt.sh: broken pagination, misses certs with any errors (~40% data loss)
  - amass: too slow, replaced by subfinder + bbot combination
"""

import re
import subprocess
from ..core.ratelimit import tracked_run
import logging
import tempfile
from pathlib import Path

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

        constraints = self.roe_constraints(data)
        if constraints["no_subdomain_enum"]:
            log.info(f"[subdomain] Skipping {domain} — RoE prohibits subdomain enumeration")
            return []

        log.info(f"[subdomain] Enumerating subdomains for {domain} ({program})")

        subdomains = set()
        cfg = get_config()["tools"].get("subdomain_discovery", {})

        # --- Passive sources (run subfinder + bbot in parallel via threads) ---
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            f_subfinder = pool.submit(self._run_subfinder, domain)
            f_bbot = pool.submit(self._run_bbot, domain)
            f_sni = pool.submit(self._run_sni_lookup, domain)

        sf_results = f_subfinder.result()
        bbot_results = f_bbot.result()
        sni_results = f_sni.result()

        subdomains.update(sf_results)
        subdomains.update(bbot_results)
        subdomains.update(sni_results)

        # Always include the root domain itself
        subdomains.add(domain)

        passive_count = len(subdomains)
        log.info(
            f"[subdomain] Passive: {passive_count} subdomains for {domain} "
            f"(subfinder={len(sf_results)}, bbot={len(bbot_results)}, sni={len(sni_results)})"
        )

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
            elif sub in bbot_results:
                source = "bbot"
            elif sub in sni_results:
                source = "sni"
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
            result = tracked_run(cmd, capture_output=True, text=True, timeout=300)
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

    # ─── Passive: bbot ──────────────────────────────────────────

    def _run_bbot(self, domain: str) -> set[str]:
        """Run BBOT for subdomain discovery.

        BBOT finds ~5-8% more subdomains than subfinder alone.
        Outputs to a temp directory and parses the subdomains.
        """
        cfg = get_config().get("bbot", {})
        preset = cfg.get("preset", "subdomain-enum")

        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                out_file = Path(tmp_dir) / "subdomains.txt"
                result = tracked_run(
                    [
                        "bbot",
                        "-t", domain,
                        "-p", preset,
                        "--silent",
                        "-o", tmp_dir,
                        "-om", "txt",
                        "--allow-deadly",
                    ],
                    capture_output=True, text=True, timeout=600,
                    cwd=tmp_dir,
                )

                subs = set()
                # bbot writes subdomains to stdout in silent mode
                for line in result.stdout.splitlines():
                    line = line.strip().lower()
                    if line and not line.startswith("[") and "." in line:
                        # Basic domain validation
                        if re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", line):
                            subs.add(line)

                # Also check output file if it exists
                for txt_file in Path(tmp_dir).glob("**/*.txt"):
                    try:
                        with open(txt_file) as f:
                            for line in f:
                                line = line.strip().lower()
                                if line and "." in line:
                                    if re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", line):
                                        subs.add(line)
                    except Exception:
                        pass

                log.info(f"[subdomain] bbot: {len(subs)} subs for {domain}")
                return subs
        except FileNotFoundError:
            log.debug("bbot not found, skipping")
            return set()
        except subprocess.TimeoutExpired:
            log.warning(f"bbot timed out for {domain}")
            return set()
        except Exception as e:
            log.warning(f"bbot failed for {domain}: {e}")
            return set()

    # ─── Passive: SNI / kaeferjaeger cloud cert data ─────────────

    def _run_sni_lookup(self, domain: str) -> set[str]:
        """Query kaeferjaeger.gay pre-scanned TLS/SNI data.

        This dataset contains SSL certificate metadata from scans of all major
        cloud provider IP ranges (AWS, GCP, Azure, Cloudflare, etc.), updated
        every ~30 days. Finds subdomains hosted on cloud without touching the target.
        """
        script = Path(get_config().get("apex_discovery", {}).get(
            "tenant_domains_script", "./scripts/tenant_domains.sh"
        )).parent / "sni_lookup.sh"

        # Use the existing sni_lookup.sh script if available
        if script.exists():
            try:
                result = tracked_run(
                    ["bash", str(script), "-d", domain],
                    capture_output=True, text=True, timeout=300,
                )
                subs = set()
                for line in result.stdout.splitlines():
                    line = line.strip().lower()
                    if line and "." in line and domain in line:
                        subs.add(line)
                log.info(f"[subdomain] SNI lookup: {len(subs)} subs for {domain}")
                return subs
            except Exception as e:
                log.debug(f"SNI lookup failed: {e}")
                return set()

        # Fallback: direct HTTP query to kaeferjaeger index
        try:
            import urllib.request
            import gzip
            import io

            cache_dir = Path.home() / ".cache" / "bbtrs" / "sni-data"
            cache_dir.mkdir(parents=True, exist_ok=True)

            index_url = "https://kaeferjaeger.gay/sni-ip-ranges/index.txt"
            req = urllib.request.Request(index_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                index = resp.read().decode().splitlines()

            subs = set()
            for fname in index[:5]:  # Limit to first 5 files to avoid excessive download
                fname = fname.strip()
                if not fname:
                    continue
                cache_file = cache_dir / fname
                if not cache_file.exists():
                    try:
                        dl_url = f"https://kaeferjaeger.gay/sni-ip-ranges/{fname}"
                        with urllib.request.urlopen(urllib.request.Request(dl_url, headers={"User-Agent": "Mozilla/5.0"}), timeout=30) as r:
                            data = r.read()
                        with open(cache_file, "wb") as f:
                            f.write(data)
                    except Exception:
                        continue

                try:
                    opener = gzip.open if fname.endswith(".gz") else open
                    with opener(cache_file, "rt", errors="ignore") as f:
                        for line in f:
                            if domain in line:
                                # Format: "IP -- [host1, host2, ...]"
                                parts = line.split("--", 1)
                                if len(parts) == 2:
                                    hosts_part = parts[1].strip().strip("[]")
                                    for h in hosts_part.split(","):
                                        h = h.strip().strip("'\"").lower()
                                        if h.endswith(f".{domain}") or h == domain:
                                            subs.add(h)
                except Exception:
                    continue

            log.info(f"[subdomain] SNI fallback: {len(subs)} subs for {domain}")
            return subs
        except Exception as e:
            log.debug(f"SNI fallback failed for {domain}: {e}")
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

            result = tracked_run(cmd, capture_output=True, text=True, timeout=1800)

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
            result = tracked_run(
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

            tracked_run(cmd, capture_output=True, text=True, timeout=600)

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
            Path(tmp_out_path).unlink(missing_ok=True)
            return set()
        except subprocess.TimeoutExpired:
            log.warning("permutation resolution timed out")
            Path(tmp_in_path).unlink(missing_ok=True)
            Path(tmp_out_path).unlink(missing_ok=True)
            return set()
        except Exception as e:
            log.warning(f"permutation resolution failed: {e}")
            Path(tmp_in_path).unlink(missing_ok=True)
            Path(tmp_out_path).unlink(missing_ok=True)
            return set()


# ─── Standalone one-shot functions (used by CLI recon commands) ──


def puredns_bruteforce(domain: str, wordlist: str = None, resolvers: str = None,
                       rate_limit: int = 150, rate_limit_trusted: int = 50) -> set[str]:
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

    tracked_run(cmd, capture_output=True, text=True, timeout=1800)

    subs = set()
    if Path(tmp_path).exists():
        with open(tmp_path) as f:
            subs = {line.strip().lower() for line in f if line.strip()}
        Path(tmp_path).unlink(missing_ok=True)
    return subs


def alterx_permutations(subdomains: list[str]) -> set[str]:
    """Generate permutations from known subdomains using alterx."""
    input_text = "\n".join(subdomains)
    result = tracked_run(
        ["alterx", "-enrich"],
        input=input_text,
        capture_output=True, text=True, timeout=300,
    )
    return {line.strip().lower() for line in result.stdout.splitlines() if line.strip()}

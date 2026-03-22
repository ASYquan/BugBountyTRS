"""JavaScript keyword extraction stage.

Crawls in-scope websites, downloads JS files, and extracts keywords to
generate custom wordlists for:
  - Subdomain brute-forcing (puredns/alterx)
  - Directory/path discovery (feroxbuster/ffuf)
  - Parameter fuzzing (Arjun/paramspider)
  - Virtual host fuzzing

Inspired by Jason Haddix's modern recon methodology — mining JS files
for target-specific wordlists produces far better results than generic lists.

Tools used:
  - katana (web crawling / JS file discovery)
  - Custom Python extraction (AST-like parsing of JS for keywords)
"""

import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

from ..core.worker import BaseWorker
from ..core.config import get_config

log = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
# Keyword Extraction Engine
# ═══════════════════════════════════════════════════════════════════

# Common JS framework/library words to filter out
STOPWORDS = {
    # JS language
    "function", "return", "const", "let", "var", "this", "that", "self",
    "true", "false", "null", "undefined", "new", "delete", "typeof",
    "instanceof", "void", "throw", "try", "catch", "finally", "switch",
    "case", "break", "continue", "for", "while", "do", "if", "else",
    "import", "export", "default", "from", "class", "extends", "super",
    "yield", "async", "await", "static", "get", "set", "constructor",
    "prototype", "arguments", "eval", "with",
    # Common generic words
    "error", "success", "data", "result", "value", "type", "name",
    "length", "index", "item", "list", "array", "object", "string",
    "number", "boolean", "callback", "handler", "event", "target",
    "source", "options", "config", "settings", "params", "props",
    "state", "action", "dispatch", "reducer", "store", "context",
    "component", "render", "mount", "update", "style", "styles",
    "container", "wrapper", "content", "children", "parent", "child",
    "node", "element", "document", "window", "global", "module",
    "require", "exports", "console", "promise", "resolve", "reject",
    "then", "map", "filter", "reduce", "foreach", "push", "pop",
    "shift", "slice", "splice", "concat", "join", "split", "replace",
    "match", "test", "exec", "apply", "call", "bind", "keys", "values",
    "entries", "assign", "create", "define", "freeze", "stringify",
    "parse", "json", "math", "date", "regexp", "symbol", "iterator",
    "next", "done", "tostring", "valueof", "hasownproperty",
    # Framework-specific
    "react", "angular", "vue", "jquery", "webpack", "babel", "polyfill",
    "lodash", "underscore", "moment", "axios", "fetch", "xmlhttprequest",
    "usestate", "useeffect", "useref", "usememo", "usecallback",
    "createelement", "createref", "forwardref", "memo", "lazy",
    "suspense", "fragment", "portal", "strictmode",
    # HTML/CSS
    "div", "span", "input", "button", "form", "label", "select",
    "option", "textarea", "table", "thead", "tbody", "href", "src",
    "alt", "title", "width", "height", "margin", "padding", "border",
    "display", "position", "color", "background", "font", "text",
    "hidden", "visible", "block", "inline", "flex", "grid",
}


def extract_js_keywords(content: str) -> dict:
    """Extract categorized keywords from JavaScript content.

    Returns dict with:
      - paths: URL path segments (good for dir fuzzing)
      - params: parameter names (good for param fuzzing)
      - subdomains: hostname-like strings (good for subdomain brute)
      - api_routes: full API route patterns
      - identifiers: variable/function names (good for general wordlists)
      - strings: interesting string literals
    """
    results = {
        "paths": set(),
        "params": set(),
        "subdomains": set(),
        "api_routes": set(),
        "identifiers": set(),
        "strings": set(),
    }

    # 1. Extract URL paths and path segments
    _extract_urls(content, results)

    # 2. Extract parameter names
    _extract_params(content, results)

    # 3. Extract hostname/subdomain-like strings
    _extract_hostnames(content, results)

    # 4. Extract camelCase/snake_case identifiers (variable/function names)
    _extract_identifiers(content, results)

    # 5. Extract interesting string literals
    _extract_strings(content, results)

    # 6. Extract object keys (potential API field names / params)
    _extract_object_keys(content, results)

    # Clean up: remove stopwords and too-short entries
    for category in results:
        results[category] = {
            w for w in results[category]
            if len(w) >= 3 and w.lower() not in STOPWORDS
        }

    return results


def _extract_urls(content: str, results: dict):
    """Extract URL paths, API routes, and path segments."""
    # Full URLs
    url_pattern = r"""['"](?:https?://[^\s'"]+|/[a-zA-Z0-9_\-./]+)['"]"""
    for match in re.finditer(url_pattern, content):
        url = match.group(0).strip("'\"")

        parsed = urlparse(url)
        path = parsed.path

        if path and path != "/":
            results["api_routes"].add(path)

            # Extract individual path segments
            for segment in path.strip("/").split("/"):
                # Skip numeric IDs and template vars
                segment = segment.strip()
                if segment and not re.match(r'^[\d]+$', segment) and not segment.startswith("{") and not segment.startswith(":"):
                    results["paths"].add(segment)

            # Extract query parameters
            for key in parse_qs(parsed.query).keys():
                results["params"].add(key)

    # Template literal paths: `${baseUrl}/users/${id}`
    template_pattern = r'`[^`]*(/[a-zA-Z0-9_\-./\$\{]+)[^`]*`'
    for match in re.finditer(template_pattern, content):
        path = match.group(1)
        path = re.sub(r'\$\{[^}]+\}', '', path)
        for segment in path.strip("/").split("/"):
            segment = segment.strip()
            if segment and len(segment) >= 3:
                results["paths"].add(segment)

    # Route definitions: router.get('/users', ...), app.post('/api/data', ...)
    route_pattern = r"""(?:router|app|route)\s*\.\s*(?:get|post|put|delete|patch|use|all)\s*\(\s*['"]([^'"]+)['"]"""
    for match in re.finditer(route_pattern, content, re.IGNORECASE):
        route = match.group(1)
        results["api_routes"].add(route)
        for segment in route.strip("/").split("/"):
            segment = segment.strip()
            if segment and not segment.startswith(":") and len(segment) >= 3:
                results["paths"].add(segment)


def _extract_params(content: str, results: dict):
    """Extract parameter names from various patterns."""
    patterns = [
        # Object property access: obj.paramName, this.propName
        r'(?:this|self|data|params|query|body|request|req|res|response)\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]+)',
        # URL query params: ?param=value, &param=value
        r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=',
        # FormData / URLSearchParams: .append('key', ...), .get('key')
        r"""\.(?:append|get|set|has|delete|getAll)\s*\(\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]""",
        # Object literals used as params: {key: value, ...}
        r'(?:params|data|body|query|payload|form)\s*[:=]\s*\{([^}]+)\}',
        # Input name attributes: name="fieldName"
        r'name\s*[:=]\s*[\'"]([a-zA-Z_][a-zA-Z0-9_]*)[\'"]',
        # Header names
        r"""[Hh]eaders?\s*\[?\s*['"]([a-zA-Z_\-][a-zA-Z0-9_\-]*)['"]""",
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, content):
            val = match.group(1)
            if "," in val:
                # Object literal — extract keys
                for key_match in re.finditer(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*:', val):
                    results["params"].add(key_match.group(1))
            else:
                results["params"].add(val)


def _extract_hostnames(content: str, results: dict):
    """Extract hostname-like strings that could be subdomains."""
    # Full hostnames/subdomains
    hostname_pattern = r"""['"](?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)['"/]"""
    for match in re.finditer(hostname_pattern, content):
        hostname = match.group(1).lower()
        # Skip common CDN/framework domains
        skip_domains = ("googleapis.com", "gstatic.com", "cloudflare.com",
                        "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
                        "facebook.com", "google.com", "twitter.com",
                        "github.com", "npmjs.org", "w3.org")
        if not any(hostname.endswith(d) for d in skip_domains):
            results["subdomains"].add(hostname)
            # Extract subdomain prefix as potential word
            parts = hostname.split(".")
            if len(parts) > 2:
                results["paths"].add(parts[0])

    # Subdomain-like prefixes in strings: "staging", "api", "admin", etc.
    prefix_pattern = r"""['"]([a-z][a-z0-9\-]{2,20})['"]"""
    for match in re.finditer(prefix_pattern, content):
        word = match.group(1)
        if "-" in word or word in ("staging", "dev", "test", "beta", "alpha",
                                    "internal", "admin", "portal", "dashboard",
                                    "api", "gateway", "proxy", "auth", "sso",
                                    "cdn", "static", "assets", "media", "uploads"):
            results["subdomains"].add(word)


def _extract_identifiers(content: str, results: dict):
    """Extract meaningful variable/function/class names."""
    # camelCase and PascalCase identifiers
    ident_pattern = r'\b([a-zA-Z][a-zA-Z0-9]{2,30})\b'
    word_counts = Counter()
    for match in re.finditer(ident_pattern, content):
        word = match.group(1)
        word_counts[word] += 1

    for word, count in word_counts.items():
        if count >= 2 and word.lower() not in STOPWORDS:
            # Split camelCase into parts
            parts = re.sub(r'([A-Z])', r' \1', word).split()
            for part in parts:
                part = part.lower().strip()
                if len(part) >= 3 and part not in STOPWORDS:
                    results["identifiers"].add(part)

            # Also keep the full identifier for path/param guessing
            if len(word) >= 4:
                results["identifiers"].add(word.lower())

    # snake_case identifiers
    snake_pattern = r'\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b'
    for match in re.finditer(snake_pattern, content):
        word = match.group(1)
        results["identifiers"].add(word)
        # Split parts
        for part in word.split("_"):
            if len(part) >= 3 and part not in STOPWORDS:
                results["identifiers"].add(part)

    # kebab-case identifiers (common in URLs/CSS)
    kebab_pattern = r'\b([a-z][a-z0-9]*(?:-[a-z0-9]+)+)\b'
    for match in re.finditer(kebab_pattern, content):
        word = match.group(1)
        results["identifiers"].add(word)


def _extract_strings(content: str, results: dict):
    """Extract interesting string literals."""
    # Quoted strings that look like they could be useful
    string_pattern = r"""['"]([a-zA-Z][a-zA-Z0-9_\-]{3,40})['"]"""
    for match in re.finditer(string_pattern, content):
        s = match.group(1)
        if s.lower() not in STOPWORDS and not s.startswith("use "):
            results["strings"].add(s.lower())


def _extract_object_keys(content: str, results: dict):
    """Extract object keys from JSON-like structures."""
    # {"key": value} or {key: value}
    key_pattern = r"""(?:['"]?([a-zA-Z_][a-zA-Z0-9_]{2,30})['"]?\s*:)"""
    for match in re.finditer(key_pattern, content):
        key = match.group(1)
        if key.lower() not in STOPWORDS:
            results["params"].add(key)


# ═══════════════════════════════════════════════════════════════════
# Wordlist Generation
# ═══════════════════════════════════════════════════════════════════


def build_wordlists(keywords: dict, domain: str = None) -> dict:
    """Convert extracted keywords into categorized wordlists.

    Returns:
      - subdomain_wordlist: words for subdomain brute-forcing
      - path_wordlist: words for directory/path discovery
      - param_wordlist: words for parameter fuzzing
      - combined_wordlist: all unique words merged
    """
    wordlists = {}

    # Subdomain wordlist — from hostnames, path prefixes, identifiers
    sub_words = set()
    sub_words.update(keywords.get("subdomains", set()))
    # Add relevant identifiers that look like subdomain prefixes
    for word in keywords.get("identifiers", set()):
        if len(word) <= 20 and re.match(r'^[a-z][a-z0-9\-]+$', word):
            sub_words.add(word)
    # Add path segments that could be subdomains
    for word in keywords.get("paths", set()):
        if len(word) <= 20 and re.match(r'^[a-z][a-z0-9\-]+$', word):
            sub_words.add(word)
    wordlists["subdomain_wordlist"] = sorted(sub_words)

    # Path/directory wordlist
    path_words = set()
    path_words.update(keywords.get("paths", set()))
    path_words.update(keywords.get("api_routes", set()))
    # Add identifiers that look like paths
    for word in keywords.get("identifiers", set()):
        if re.match(r'^[a-z][a-z0-9_\-]+$', word):
            path_words.add(word)
    wordlists["path_wordlist"] = sorted(path_words)

    # Parameter wordlist
    param_words = set()
    param_words.update(keywords.get("params", set()))
    # Add identifiers that look like param names
    for word in keywords.get("identifiers", set()):
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]+$', word) and len(word) <= 30:
            param_words.add(word)
    wordlists["param_wordlist"] = sorted(param_words)

    # Combined
    all_words = set()
    for wl in wordlists.values():
        all_words.update(wl)
    wordlists["combined_wordlist"] = sorted(all_words)

    return wordlists


# ═══════════════════════════════════════════════════════════════════
# Altdns Subdomain Mutation
# ═══════════════════════════════════════════════════════════════════


def altdns_mutate(keywords: list[str], known_subdomains: list[str],
                  domain: str, output_path: str = None) -> list[str]:
    """Use altdns to mutate JS-extracted keywords against known subdomains.

    Takes the JS-mined keywords as a wordlist and known subdomains as input,
    generating permuted subdomain candidates (e.g., api + dev.example.com →
    api-dev.example.com, dev-api.example.com, api.dev.example.com, etc.).

    Args:
        keywords: JS-extracted words to use as the mutation wordlist
        known_subdomains: Existing known subdomains to permute against
        domain: Root domain (used for output path default)
        output_path: Where to write custom.txt (defaults to ./data/<domain>/custom.txt)

    Returns:
        List of mutated subdomain candidates
    """
    if not keywords or not known_subdomains:
        log.warning("[altdns] No keywords or subdomains to mutate")
        return []

    cfg = get_config()
    base_dir = Path(cfg["storage"]["base_dir"])

    # Build output path
    if output_path:
        out_file = Path(output_path)
    else:
        domain_dir = base_dir / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        out_file = domain_dir / "custom.txt"

    out_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Write keywords as the altdns wordlist (mutation words)
        with tempfile.NamedTemporaryFile(mode="w", suffix="_words.txt",
                                         delete=False) as wl_file:
            wl_file.write("\n".join(sorted(set(keywords))))
            wl_path = wl_file.name

        # Write known subdomains as altdns input
        with tempfile.NamedTemporaryFile(mode="w", suffix="_subs.txt",
                                         delete=False) as sub_file:
            sub_file.write("\n".join(sorted(set(known_subdomains))))
            sub_path = sub_file.name

        # Altdns output (raw permutations before dedup)
        with tempfile.NamedTemporaryFile(mode="w", suffix="_altdns_out.txt",
                                         delete=False) as tmp_out:
            tmp_out_path = tmp_out.name

        log.info(f"[altdns] Mutating {len(keywords)} keywords × "
                 f"{len(known_subdomains)} subdomains for {domain}")

        result = subprocess.run(
            [
                "altdns",
                "-i", sub_path,        # Known subdomains as input
                "-o", tmp_out_path,    # Raw permutation output
                "-w", wl_path,         # JS keywords as mutation wordlist
            ],
            capture_output=True, text=True, timeout=600,
        )

        if result.returncode != 0 and result.stderr:
            log.warning(f"[altdns] stderr: {result.stderr.strip()}")

        # Read altdns output, dedup, and filter to target domain
        mutated = set()
        if Path(tmp_out_path).exists():
            with open(tmp_out_path) as f:
                for line in f:
                    candidate = line.strip().lower()
                    if candidate and candidate.endswith(f".{domain}"):
                        mutated.add(candidate)

        # Remove already-known subdomains
        known_set = {s.lower() for s in known_subdomains}
        new_candidates = sorted(mutated - known_set)

        # Write final custom.txt
        with open(out_file, "w") as f:
            f.write("\n".join(new_candidates))
            if new_candidates:
                f.write("\n")

        log.info(f"[altdns] Generated {len(new_candidates)} new candidates → {out_file}")

        # Cleanup temp files
        for p in (wl_path, sub_path, tmp_out_path):
            Path(p).unlink(missing_ok=True)

        return new_candidates

    except FileNotFoundError:
        log.warning("[altdns] altdns not found — install with: pip3 install py-altdns")
        return []
    except subprocess.TimeoutExpired:
        log.warning("[altdns] timed out")
        return []
    except Exception as e:
        log.warning(f"[altdns] mutation failed: {e}")
        return []


# ═══════════════════════════════════════════════════════════════════
# JS Crawling
# ═══════════════════════════════════════════════════════════════════


def crawl_js_files(target: str, depth: int = 3, threads: int = 5,
                   rate_limit: int = 20) -> list[str]:
    """Use katana to crawl a target and discover JS file URLs."""
    cfg = get_config()
    inti_cfg = cfg.get("intigriti", {})
    try:
        cmd = [
                "katana", "-u", target,
                "-d", str(depth),
                "-c", str(threads),
                "-rl", str(rate_limit),
                "-ef", "css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,mp4,mp3,pdf",
                "-em", "js",  # Extract mode: JS files
                "-silent",
            ]
        ua = inti_cfg.get("user_agent")
        if ua:
            cmd.extend(["-H", f"User-Agent: {ua}"])
        req_header = inti_cfg.get("request_header")
        if req_header:
            cmd.extend(["-H", req_header])

        result = subprocess.run(cmd,
            capture_output=True, text=True, timeout=600,
        )
        urls = set()
        for line in result.stdout.strip().splitlines():
            url = line.strip()
            if url and url.endswith(".js"):
                urls.add(url)
        return sorted(urls)
    except FileNotFoundError:
        log.warning("katana not found, trying waybackurls fallback")
        return _fallback_js_discovery(target)
    except subprocess.TimeoutExpired:
        log.warning("katana timed out")
        return []


def _fallback_js_discovery(target: str) -> list[str]:
    """Fallback: use curl + grep to find JS files on a target."""
    cfg = get_config()
    inti_cfg = cfg.get("intigriti", {})
    ua = inti_cfg.get("user_agent", "Mozilla/5.0")
    req_header = inti_cfg.get("request_header", "")
    curl_cmd = ["curl", "-sL", "--max-time", "30", "-H", f"User-Agent: {ua}"]
    if req_header:
        curl_cmd.extend(["-H", req_header])
    curl_cmd.append(target)
    try:
        result = subprocess.run(
            curl_cmd,
            capture_output=True, text=True, timeout=35,
        )
        urls = set()
        # Find script src attributes
        for match in re.finditer(r'src=["\']([^"\']*\.js[^"\']*)["\']', result.stdout):
            js_url = match.group(1)
            if js_url.startswith("//"):
                js_url = "https:" + js_url
            elif js_url.startswith("/"):
                parsed = urlparse(target)
                js_url = f"{parsed.scheme}://{parsed.netloc}{js_url}"
            elif not js_url.startswith("http"):
                parsed = urlparse(target)
                js_url = f"{parsed.scheme}://{parsed.netloc}/{js_url}"
            urls.add(js_url)
        return sorted(urls)
    except Exception:
        return []


def download_js(url: str, timeout: int = 15) -> str | None:
    """Download a JS file and return its content."""
    cfg = get_config()
    inti_cfg = cfg.get("intigriti", {})
    ua = inti_cfg.get("user_agent", "Mozilla/5.0")
    req_header = inti_cfg.get("request_header", "")
    curl_cmd = ["curl", "-sL", "--max-time", str(timeout),
                "-H", f"User-Agent: {ua}"]
    if req_header:
        curl_cmd.extend(["-H", req_header])
    curl_cmd.extend(["-o", "-", url])
    try:
        result = subprocess.run(
            curl_cmd,
            capture_output=True, text=True, timeout=timeout + 5,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


# ═══════════════════════════════════════════════════════════════════
# Pipeline Worker
# ═══════════════════════════════════════════════════════════════════


class JSKeywordWorker(BaseWorker):
    """Extracts keywords from JS files for custom wordlist generation.

    Consumes JS file URLs from recon_js stream.
    Stores extracted keywords in the database for wordlist generation.
    """
    name = "js_keywords"
    input_stream = "recon_js"
    output_streams = []  # No downstream output — stores keywords in DB

    def dedup_key(self, data: dict) -> str:
        return f"js_kw:{data.get('url', '')}"

    def process(self, data: dict) -> list[dict]:
        js_url = data.get("url")
        program_id = data.get("program_id")
        domain = data.get("domain")

        if not js_url:
            return []

        content = download_js(js_url)
        if not content or len(content) < 50:
            return []

        keywords = extract_js_keywords(content)

        total = sum(len(v) for v in keywords.values())
        if total == 0:
            return []

        log.info(f"[js_keywords] Extracted {total} keywords from {js_url}: "
                 f"paths={len(keywords['paths'])}, params={len(keywords['params'])}, "
                 f"subs={len(keywords['subdomains'])}, routes={len(keywords['api_routes'])}")

        # Store keywords in DB
        self._store_keywords(program_id, domain, js_url, keywords)

        # Run altdns mutation if we have a domain and subdomain-relevant keywords
        if domain and program_id:
            wordlists = build_wordlists(keywords, domain=domain)
            sub_words = wordlists.get("subdomain_wordlist", [])
            if sub_words:
                # Pull known subdomains from DB for this program
                known_subs = [
                    row["domain"]
                    for row in self.storage.get_subdomains(program_id)
                ]
                if known_subs:
                    altdns_mutate(
                        keywords=sub_words,
                        known_subdomains=known_subs,
                        domain=domain,
                    )

        return []

    def _store_keywords(self, program_id: int, domain: str, js_url: str,
                        keywords: dict):
        """Store extracted keywords in the database."""
        keywords_json = {k: sorted(v) for k, v in keywords.items()}

        try:
            with self.storage._conn() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS js_keywords (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        program_id INTEGER,
                        domain TEXT,
                        js_url TEXT NOT NULL,
                        keywords_json TEXT NOT NULL,
                        extracted_at TEXT DEFAULT (datetime('now')),
                        UNIQUE(js_url)
                    )
                """)
                conn.execute(
                    """INSERT OR REPLACE INTO js_keywords
                       (program_id, domain, js_url, keywords_json, extracted_at)
                       VALUES (?, ?, ?, ?, datetime('now'))""",
                    (program_id, domain, js_url, json.dumps(keywords_json)),
                )
        except Exception as e:
            log.warning(f"[js_keywords] Failed to store keywords: {e}")


# ═══════════════════════════════════════════════════════════════════
# Standalone CLI Functions
# ═══════════════════════════════════════════════════════════════════


def mine_keywords(target: str, depth: int = 3, domain: str = None,
                  known_subdomains: list[str] = None) -> dict:
    """Full keyword mining pipeline: crawl → download JS → extract → build wordlists → altdns mutate.

    Args:
        target: URL to crawl (e.g., https://example.com)
        depth: Crawl depth for katana
        domain: Target domain for filtering (optional)
        known_subdomains: List of known subdomains for altdns mutation (optional)

    Returns:
        Dict with categorized wordlists, altdns candidates, and stats
    """
    # Step 1: Discover JS files
    js_urls = crawl_js_files(target, depth=depth)

    if not js_urls:
        return {"error": "No JS files found", "wordlists": {}}

    # Step 2: Download and extract keywords from each JS file
    all_keywords = {
        "paths": set(),
        "params": set(),
        "subdomains": set(),
        "api_routes": set(),
        "identifiers": set(),
        "strings": set(),
    }

    processed = 0
    for js_url in js_urls:
        content = download_js(js_url)
        if not content or len(content) < 50:
            continue

        keywords = extract_js_keywords(content)
        for category in all_keywords:
            all_keywords[category].update(keywords.get(category, set()))
        processed += 1

    # Step 3: Build wordlists
    wordlists = build_wordlists(all_keywords, domain=domain)

    # Step 4: Altdns mutation — use JS keywords to generate subdomain permutations
    altdns_candidates = []
    if domain and wordlists.get("subdomain_wordlist"):
        # Use known subdomains if provided, otherwise use JS-discovered hostnames
        subs_for_mutation = known_subdomains or list(all_keywords.get("subdomains", set()))
        if not subs_for_mutation:
            # Fallback: synthesize base subdomains from the domain
            subs_for_mutation = [domain]

        altdns_candidates = altdns_mutate(
            keywords=wordlists["subdomain_wordlist"],
            known_subdomains=subs_for_mutation,
            domain=domain,
        )

    return {
        "js_files_found": len(js_urls),
        "js_files_processed": processed,
        "stats": {k: len(v) for k, v in all_keywords.items()},
        "wordlists": wordlists,
        "altdns_candidates": len(altdns_candidates),
        "custom_txt": str(Path(get_config()["storage"]["base_dir"]) / domain / "custom.txt") if domain else None,
    }

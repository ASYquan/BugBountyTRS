# Enumeration Pipeline

A modular, continuous bug bounty reconnaissance and vulnerability scanning pipeline. Built with an event-driven architecture using Redis Streams for inter-stage communication, designed to run 24/7 and accumulate structured recon data for manual analysis and PoC development.

## Architecture

```
Scheduler (periodic re-feed)
    |
[scope:targets] --> Subdomain Discovery (subfinder + amass + crt.sh + puredns + alterx)
    |                ASN Discovery (asnmap + amass intel + Team Cymru)
    |                Cert Discovery (caduceus TLS/SNI scanning)
    |                BBOT Discovery (all-in-one subdomain + web scan)
    |                Shodan Recon (signature-based dork scanning)
    |                GitHub Dorking (gh CLI code search)
    |
[recon:subdomains] --> DNS Resolution (dig, dangling CNAME detection)
    |
[recon:resolved] --> Port Scanning (smap passive -> naabu fast -> nmap deep)
    |
[recon:ports] --> HTTP Probing (httpx + tech detection)
    |
[recon:http] --> Crawler (katana)       + Screenshots (gowitness) + Nuclei Scanning
    |                |
[recon:urls]    [recon:js] --> JS Keyword Extraction + altdns subdomain mutation
    |
[vuln:findings] --> SQLite DB (structured, exportable as JSON)

[Domain Ranking API] --> FastAPI service for prioritizing targets by Tranco/Umbrella rank
```

### Design Principles

- **Event-driven**: Each stage is a stateless worker consuming from Redis Streams and publishing to the next
- **Continuous**: The scheduler re-feeds all scope targets on a configurable interval (default 24h)
- **Deduplication**: Redis TTL keys prevent rescanning the same target within a cycle
- **Rate-limit aware**: All tools respect configurable rate limits for RoE compliance
- **RoE header injection**: Configurable User-Agent and custom headers injected into all HTTP-touching tools
- **Structured storage**: SQLite database with full relational model; JSON export for external analysis
- **Tiered scanning**: Port scanning uses a 3-tier approach (passive -> fast -> deep) to minimize noise
- **JS-driven wordlists**: Keywords mined from JavaScript files feed into altdns for target-specific subdomain mutation

## Requirements

- Python 3.11+
- Docker (for Redis)
- Go 1.20+ (for installing tools)

## Quick Start

### 1. Install dependencies

```bash
# Install Python packages
pip install -r requirements.txt

# Install recon tools
bash scripts/install_tools.sh
```

### 2. Configure

Edit `config/config.yml`:

```yaml
intigriti:
  username: "YOUR_USERNAME"
  user_agent: "Intigriti-YOUR_USERNAME-Mozilla/5.0 ..."
  request_header: "X-Bug-Bounty: Intigriti-YOUR_USERNAME"
  max_rps: 20

# Optional API keys for extended coverage
shodan:
  api_key: "YOUR_SHODAN_KEY"   # or set SHODAN_API_KEY env var

github:
  token: "YOUR_GITHUB_TOKEN"   # or set GITHUB_TOKEN env var
```

Set your platform username and rate limits according to the target program's Rules of Engagement.

Add API keys for subfinder sources in `~/.config/subfinder/provider-config.yaml` (created by the installer).

### 3. Start Redis

```bash
docker compose up -d
```

### 4. Add target programs

```bash
# Add manually with wildcards
python3 cli.py scope add my-target -p intigriti -w "*.example.com" -w "*.example.org"

# Sync from HackerOne
python3 cli.py scope sync-h1 <program-handle>

# Sync from Intigriti
python3 cli.py scope sync-intigriti <company-handle>

# Import from file (format: name|*.wildcard.com,domain.com|exclude.com)
python3 cli.py scope import programs.txt
```

### 5. Run the pipeline

```bash
# Run all stages continuously (recommended)
python3 cli.py run all

# Or run a single stage
python3 cli.py run stage subdomain
python3 cli.py run stage nuclei
```

### 6. Monitor and export

```bash
# Check pipeline status
python3 cli.py status

# List findings
python3 cli.py findings
python3 cli.py findings --severity high
python3 cli.py finding <id>

# Export structured data for analysis
python3 cli.py export <program-name>
python3 cli.py export-all
```

## One-Shot Recon Commands

Run individual recon tools outside the pipeline for quick manual investigation:

```bash
# Subdomain enumeration (subfinder + amass + crt.sh + puredns + alterx)
python3 cli.py recon subdomains example.com -p my-program

# Certificate transparency
python3 cli.py recon crtsh example.com --wildcard

# DNS brute-force
python3 cli.py recon puredns example.com

# Subdomain permutations
python3 cli.py recon alterx subdomains.txt

# ASN discovery (find CIDR ranges and seed domains)
python3 cli.py recon asn example.com --seeds

# TLS certificate scanning across CIDR ranges
python3 cli.py recon certs 192.168.1.0/24 -d example.com

# Shodan signature scanning
python3 cli.py recon shodan example.com --leaks

# GitHub dorking
python3 cli.py recon github-dork example.com

# Port scanning (passive/fast/deep tiers)
python3 cli.py recon portscan example.com --passive-only
python3 cli.py recon portscan example.com --fast
python3 cli.py recon portscan example.com --deep

# BBOT all-in-one scan
python3 cli.py recon bbot example.com -P subdomain-enum
```

## JS Keyword Extraction and Altdns Mutation

The `js_keyword_extract` stage mines JavaScript files for target-specific keywords and uses them to generate subdomain permutations with altdns. This follows Jason Haddix's methodology of building custom wordlists from the target's own JS rather than relying solely on generic lists.

### How it works

1. **Crawl**: katana discovers JS file URLs on the target
2. **Extract**: Regex engine pulls out paths, parameters, hostnames, API routes, identifiers, and string literals from each JS file
3. **Categorize**: Keywords are sorted into subdomain, path, parameter, and combined wordlists
4. **Mutate**: Subdomain-relevant keywords are fed into altdns as a mutation wordlist against known subdomains, generating permuted candidates (e.g., keyword `api` + known sub `dev.example.com` produces `api-dev.example.com`, `dev-api.example.com`, `api.dev.example.com`)
5. **Output**: Mutated candidates are written to `data/<domain>/custom.txt`, ready for DNS resolution with puredns

### Pipeline mode

When running as a pipeline worker, the JS keyword stage automatically:
- Stores extracted keywords in the `js_keywords` database table
- Pulls known subdomains for the program from the database
- Runs altdns mutation and writes `custom.txt`

### Standalone usage

```python
from pipeline.stages.js_keyword_extract import mine_keywords, altdns_mutate

# Full pipeline: crawl -> extract -> build wordlists -> altdns mutate
result = mine_keywords(
    "https://example.com",
    domain="example.com",
    known_subdomains=["dev.example.com", "api.example.com"],
)
# Result includes stats, wordlists, and path to custom.txt

# Or run altdns mutation directly with your own keyword list
candidates = altdns_mutate(
    keywords=["api", "staging", "internal", "portal"],
    known_subdomains=["dev.example.com", "mail.example.com"],
    domain="example.com",
    output_path="./my_custom.txt",
)
```

### Resolving the output

Feed `custom.txt` into puredns to validate which candidates actually resolve:

```bash
puredns resolve data/example.com/custom.txt \
    --resolvers /usr/share/wordlists/resolvers.txt \
    --write data/example.com/resolved_custom.txt
```

## Domain Ranking API

A standalone FastAPI microservice that ranks discovered subdomains by their Tranco and Cisco Umbrella popularity scores. Useful for prioritizing which targets to investigate first.

```bash
# Start the ranking service
uvicorn pipeline.services.domain_ranking:app --port 8787 &

# Or run in Docker
docker build -f Dockerfile.ranking -t bbtrs-ranking .
docker run -d -p 8787:8787 bbtrs-ranking

# Look up a single domain
curl http://localhost:8787/rank/example.com

# Prioritize all subdomains for a program
curl http://localhost:8787/prioritize/my-program
```

The service auto-refreshes its ranking data from Tranco and Umbrella every 24 hours.

## Shodan Signature Scanning

The Shodan recon stage uses configurable signatures from `config/shodan_signatures.yml` to run targeted dork queries. Signatures are organized by category:

| Category | Examples |
|---|---|
| `ssl` | Certificate CN/SAN, wildcard, expired, self-signed |
| `cdn_bypass` | Real IP behind Cloudflare, Cloudfront, Akamai |
| `ci_cd` | Jenkins, GitLab, Drone, SonarQube, Confluence, Jira |
| `dashboards` | Grafana, Kibana, Prometheus, Kubernetes Dashboard |
| `databases` | MongoDB, Elasticsearch, Redis, PostgreSQL, CouchDB |
| `containers` | Docker API, kubelet, Portainer, RabbitMQ |
| `debug` | phpinfo, Swagger UI, Spring Actuator, Django debug |
| `legacy` | FTP, SMB, Telnet on unusual ports |
| `enterprise` | SAP NetWeaver, Oracle BI |

Each signature supports per-query filters (required headers, title patterns, port constraints, CDN exclusion) and severity ratings.

## CLI Reference

| Command | Description |
|---|---|
| `scope add <name>` | Add a program with `-w` wildcards, `-d` domains, `-e` excludes |
| `scope list` | List all configured programs |
| `scope import <file>` | Bulk import from text file |
| `scope feed` | Manually push all targets into the pipeline |
| `scope sync-h1 <handle>` | Sync scope from HackerOne |
| `scope sync-intigriti <company>` | Sync scope from Intigriti |
| `run all` | Run all workers + scheduler continuously |
| `run stage <name>` | Run a single stage worker |
| `recon subdomains <domain>` | Full subdomain enumeration |
| `recon crtsh <domain>` | Certificate transparency lookup |
| `recon puredns <domain>` | DNS brute-force |
| `recon alterx <file>` | Subdomain permutation generation |
| `recon asn <target>` | ASN and CIDR range discovery |
| `recon certs <cidr>` | TLS certificate scanning |
| `recon shodan <domain>` | Shodan signature scanning |
| `recon github-dork <domain>` | GitHub code search dorking |
| `recon portscan <target>` | Tiered port scanning |
| `recon bbot <domain>` | BBOT all-in-one scan |
| `status` | Show pipeline statistics |
| `findings` | List vulnerability findings with filters |
| `finding <id>` | Show detailed finding info |
| `export <program>` | Export program data as JSON |
| `export-all` | Export all programs |
| `flush` | Clear streams and/or dedup cache |

## Pipeline Stages

| Stage | Tool(s) | Input Stream | Output Stream |
|---|---|---|---|
| **Subdomain Discovery** | subfinder, amass, crt.sh, puredns, alterx | `scope:targets` | `recon:subdomains` |
| **ASN Discovery** | asnmap, amass intel, Team Cymru DNS | `scope:targets` | `recon:subdomains` |
| **Cert Discovery** | caduceus (TLS/SNI scanning) | `scope:targets` | `recon:subdomains` |
| **BBOT Discovery** | bbot (all-in-one scanner) | `scope:targets` | `recon:subdomains`, `recon:resolved`, `vuln:findings` |
| **Shodan Recon** | shodan API + signatures | `scope:targets` | `recon:resolved`, `vuln:findings` |
| **GitHub Dorking** | gh CLI (code search) | `scope:targets` | `vuln:findings` |
| **DNS Resolution** | dig, socket | `recon:subdomains` | `recon:resolved` |
| **Port Scanning** | smap (passive), naabu (fast), nmap (deep) | `recon:resolved` | `recon:ports` |
| **HTTP Probing** | httpx | `recon:ports` | `recon:http` |
| **Screenshots** | gowitness | `recon:http` | *(terminal)* |
| **Web Crawling** | katana | `recon:http` | `recon:urls`, `recon:js` |
| **JS Keyword Extraction** | regex engine, altdns | `recon:js` | `custom.txt` + DB |
| **JS Analysis** | regex engine | `recon:js` | `vuln:findings` |
| **Nuclei Scanning** | nuclei | `recon:http` | `vuln:findings` |

## Data Model

All data is stored in SQLite (`data/bbtrs.db`) with the following tables:

- `programs` - Bug bounty program definitions and scope
- `subdomains` - Discovered subdomains per program (with source tracking)
- `dns_records` - DNS records (A, AAAA, CNAME, MX, NS, TXT)
- `ports` - Open ports with service/version info
- `http_services` - Live HTTP services with tech stack, headers, titles
- `urls` - Discovered URLs with parameters
- `js_files` - Analyzed JavaScript files with extracted secrets and endpoints
- `js_keywords` - Extracted JS keywords per URL (paths, params, subdomains, routes, identifiers)
- `findings` - Vulnerability findings with CVE correlation, dedup hashing, and false positive filtering
- `cves` - CVE records linked to findings
- `finding_cves` - Many-to-many link between findings and CVEs
- `fp_rules` - False positive filtering rules (template_id, title, url_pattern, severity)
- `asn_data` - ASN and CIDR range data per program
- `shodan_hosts` - Shodan host data (ports, OS, org, vulns)
- `github_leaks` - GitHub dorking results by category

Use `python3 cli.py export <program>` to dump everything as structured JSON.

## Adding Custom Stages

Create a new worker by extending `BaseWorker`:

```python
from pipeline.core.worker import BaseWorker

class MyCustomWorker(BaseWorker):
    name = "my_stage"
    input_stream = "recon_http"       # config key from streams section
    output_streams = ["vuln_findings"]

    def dedup_key(self, data: dict) -> str:
        return f"my_stage:{data.get('url', '')}"

    def process(self, data: dict) -> list[dict]:
        url = data.get("url")
        # Your logic here
        return [{"finding": "something", "url": url}]
```

Register it in `cli.py` under the `WORKERS` dict and it will be included in `run all`.

## Configuration

All tool settings are in `config/config.yml`. Key settings:

- **Rate limits**: Set per-tool to comply with program RoE
- **Intigriti headers**: Auto-injected into httpx, nuclei, katana
- **Dedup TTL**: How long before a target is re-scanned (default 24h)
- **Stream names**: Customize the Redis stream topology
- **Port scan tiers**: Enable/disable smap, naabu, nmap independently
- **Nmap**: Top ports, scan rate, NSE scripts
- **Nuclei**: Template dirs, severity filters, thread counts
- **Shodan signatures**: Loaded from `config/shodan_signatures.yml` with per-query filters
- **BBOT**: Preset selection, passive-only mode, API key passthrough
- **Domain ranking**: Tranco + Umbrella source selection, update interval
- **Caduceus**: TLS scan concurrency, ports, timeout

## Standalone Scripts

Helper scripts in `scripts/` for manual use outside the pipeline:

| Script | Purpose |
|---|---|
| `subfinder_httpx.sh` | Subdomain enum + HTTP probing combo |
| `crtsh_subs.sh` | Certificate transparency lookup |
| `puredns_brute.sh` | DNS brute-force with puredns |
| `alterx_permute.sh` | Subdomain permutation generation |
| `scope_filter.sh` | Filter subdomains against program scope |
| `ferox_enum.sh` | Directory brute-force with feroxbuster |
| `vhost_fuzz.sh` | Virtual host fuzzing |
| `sni_lookup.sh` | SNI-based hostname discovery |
| `github_secret_scan.sh` | GitHub secret scanning |

## Project Structure

```
BugBountyTRS/
├── cli.py                          # Main CLI entry point
├── Dockerfile.ranking              # Docker image for ranking API
├── config/
│   ├── config.yml                  # Pipeline configuration
│   └── shodan_signatures.yml       # Shodan dork signatures by category
├── docker-compose.yml              # Redis (+ optional ranking service)
├── requirements.txt                # Python dependencies
├── scripts/
│   ├── install_tools.sh            # Tool installer
│   ├── subfinder_httpx.sh          # Subdomain + HTTP probe combo
│   ├── crtsh_subs.sh               # crt.sh lookup
│   ├── puredns_brute.sh            # DNS brute-force
│   ├── alterx_permute.sh           # Subdomain permutations
│   ├── scope_filter.sh             # Scope filtering
│   ├── ferox_enum.sh               # Directory brute-force
│   ├── vhost_fuzz.sh               # Virtual host fuzzing
│   ├── sni_lookup.sh               # SNI hostname discovery
│   └── github_secret_scan.sh       # GitHub secret scanning
├── pipeline/
│   ├── core/
│   │   ├── config.py               # Config loader
│   │   ├── queue.py                # Redis Streams wrapper
│   │   ├── dedup.py                # Deduplication with TTL
│   │   ├── storage.py              # SQLite storage layer
│   │   └── worker.py               # Base worker class
│   ├── services/
│   │   └── domain_ranking.py       # FastAPI domain ranking API
│   └── stages/
│       ├── scope.py                # Scope management
│       ├── platforms.py            # HackerOne + Intigriti sync
│       ├── scheduler.py            # Periodic target re-feed
│       ├── subdomain.py            # Subdomain enumeration (subfinder + amass + crt.sh + puredns + alterx)
│       ├── asn_discovery.py        # ASN and CIDR range discovery
│       ├── cert_discovery.py       # TLS certificate scanning (caduceus)
│       ├── bbot_discovery.py       # BBOT all-in-one scan
│       ├── shodan_recon.py         # Shodan signature scanning
│       ├── github_dorking.py       # GitHub code search dorking
│       ├── dns_resolve.py          # DNS resolution + takeover detection
│       ├── portscan.py             # Tiered port scanning (smap -> naabu -> nmap)
│       ├── httpprobe.py            # HTTP service probing
│       ├── screenshot.py           # Screenshot capture
│       ├── crawler.py              # Web crawling
│       ├── js_keyword_extract.py   # JS keyword extraction + altdns mutation
│       ├── js_analyze.py           # JavaScript analysis (secrets + endpoints)
│       └── nuclei_scan.py          # Vulnerability scanning
└── data/                           # Runtime data (gitignored)
    ├── bbtrs.db                    # SQLite database
    ├── screenshots/                # Captured screenshots
    ├── <domain>/
    │   └── custom.txt              # Altdns-mutated subdomain candidates
    └── programs/                   # Per-program exports
```

## License

MIT

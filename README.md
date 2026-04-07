# BugBountyTRS

Continuous attack surface mapping pipeline for bug bounty. Redis Streams event bus, SQLite storage, stateless Python workers. Runs 24/7 and keeps accumulating structured recon data you can dig into manually.

Built on ideas from Erlend Leiknes (Mneomonic) TRS presentation , Jason Haddix's TBHM/Modern Recon methodology, and the Brzozowski automation blog.

## Architecture

```
Intigriti API  ──► scope_targets ──► Apex Discovery (tenant_domains)
                        │
                        ├──► Subdomain Discovery  (subfinder -all + BBOT in parallel)
                        ├──► Passive DNS          (Crobat/Sonar, CIRCL, Umbrella Top 1M)
                        ├──► ASN Discovery        (asnmap + Team Cymru)
                        ├──► Cert Discovery       (caduceus TLS/SNI scanning)
                        ├──► Shodan Recon         (83 signature dorks, karma-style)
                        ├──► GitHub Dorking       (gh CLI code search)
                        └──► Credential Recon     (DeHashed + Flare dark web)

                   recon_subdomains ──► Takeover Check  (subzy + nuclei)
                        │
                   recon_resolved  ──► Port Scanning   (smap -> naabu -> nmap)
                        │
                   recon_ports     ──► HTTP Probing    (httpx + tech detection)
                        │               VHost Discovery (ffuf Host fuzzing)
                        │
                   recon_http      ──► Content Discovery (feroxbuster recursive)
                        │               Crawler          (katana)
                        │               Screenshots      (gowitness)
                        │               Nuclei           (vuln templates)
                        │               Endpoint CSV     (continuous CSV output)
                        │
                   recon_urls ──► JS Analysis     (secrets + endpoints)
                        │         JS Keywords     (altdns mutation)
                        │
                   vuln_findings ──► CVE Correlate  -> SQLite DB
                                      Finding Filter
```

How it works:

- Each stage is a stateless worker consuming a Redis Stream. Drop in a new worker file and register it, and it's part of the pipeline.
- The scheduler re-feeds all scope targets on a configurable interval (default 24h) so it keeps running without manual kicks.
- Redis TTL keys handle dedup so the same target doesn't get rescanned mid-cycle.
- 20 req/sec hard cap enforced via a distributed Redis mutex (`active_scan_slot`). All HTTP tools inject the `X-Bug-Bounty` header automatically.
- Port scanning goes passive first (smap/InternetDB), then fast SYN scan (naabu), then deep service scan (nmap -sV) if you want it.
- Discord/Slack webhooks for things worth knowing about: takeovers, new apex domains, new HTTP services.
- All discovered endpoints get written to a live CSV as the pipeline runs.

## Requirements

- Python 3.11+
- Docker (Redis)
- Go 1.20+ (for Go-based tools)

## Quick Start

### 1. Install tools

```bash
bash scripts/install_tools.sh
```

### 2. Start Redis

```bash
docker compose up -d
```

### 3. Configure

Edit `config/config.yml`. The main things to fill in:

```yaml
intigriti:
  username: "YOUR_USERNAME"
  api_token: ""                 # Set INTIGRITI_TOKEN env var, or fill here
  user_agent: "Intigriti-YOUR_USERNAME-Mozilla/5.0 ..."
  request_header: "X-Bug-Bounty: Intigriti-YOUR_USERNAME"
  max_rps: 20

notifications:
  discord_webhook: ""           # Optional, or set DISCORD_WEBHOOK env var
  slack_webhook: ""

shodan:
  api_key: ""                   # Set SHODAN_API_KEY env var

github:
  token: ""                     # Set GITHUB_TOKEN env var
```

Add subfinder API keys in `~/.config/subfinder/provider-config.yaml` (the installer creates this file).

### 4. Add programs

```bash
# Sync all Intigriti programs
INTIGRITI_TOKEN=your_token python3 cli.py scope sync-intigriti visma --all

# Add manually
python3 cli.py scope add my-target -p intigriti -w "*.example.com" -w "*.example.org"

# Sync from HackerOne
python3 cli.py scope sync-h1 <program-handle>
```

### 5. Run

```bash
# All workers + scheduler, runs indefinitely
python3 cli.py run all

# In a second terminal, watch for scope changes
python3 cli.py run monitor --interval 3600
```

### 6. Check results

```bash
python3 cli.py status
python3 cli.py findings --severity high
python3 cli.py finding <id>

# Export endpoints CSV for manual review
python3 cli.py export-endpoints my-program -o endpoints.csv

# Full JSON export
python3 cli.py export my-program
```

## One-Shot Recon Commands

```bash
# Full subdomain discovery (subfinder + BBOT + puredns + alterx)
python3 cli.py recon subdomains example.com -p my-program

# DNS brute-force
python3 cli.py recon puredns example.com

# Subdomain permutations from a known-subs list
python3 cli.py recon alterx subdomains.txt

# ASN + CIDR range discovery
python3 cli.py recon asn example.com --seeds

# TLS certificate scanning across CIDR ranges
python3 cli.py recon certs 192.168.1.0/24 -d example.com

# Shodan signature scanning (karma-style)
python3 cli.py recon shodan example.com --leaks

# GitHub dorking
python3 cli.py recon github-dork example.com

# Port scanning (passive/fast/deep tiers)
python3 cli.py recon portscan example.com --passive-only
python3 cli.py recon portscan example.com --deep

# BBOT all-in-one
python3 cli.py recon bbot example.com -P subdomain-enum

# Content discovery (feroxbuster recursive)
python3 cli.py recon content-discovery https://example.com -p my-program

# Virtual host fuzzing
python3 cli.py recon vhost 1.2.3.4 example.com --port 443

# Takeover check (subzy + nuclei)
python3 cli.py recon takeover my-program
```

## Pipeline Stages

| Stage | Tool(s) | Input -> Output |
|---|---|---|
| **Apex Discovery** | tenant_domains.sh | scope_targets -> scope_targets |
| **Passive DNS** | Crobat/Sonar, CIRCL, Umbrella | scope_targets -> recon_subdomains |
| **Subdomain Discovery** | subfinder -all, BBOT, puredns, alterx | scope_targets -> recon_subdomains |
| **ASN Discovery** | asnmap, Team Cymru | scope_targets -> recon_subdomains |
| **Cert Discovery** | caduceus (TLS/SNI) | scope_targets -> recon_subdomains |
| **Shodan Recon** | shodan API + 83 signatures | scope_targets -> recon_resolved, vuln_findings |
| **GitHub Dorking** | gh CLI code search | scope_targets -> vuln_findings |
| **Credential Recon** | DeHashed, Flare.io, DefaultCreds | scope_targets -> vuln_findings |
| **Takeover Check** | subzy, nuclei takeover/ | recon_subdomains -> vuln_findings |
| **DNS Resolution** | dig, socket (CNAME takeover detection) | recon_subdomains -> recon_resolved |
| **Port Scanning** | smap (passive) -> naabu (fast) -> nmap (deep) | recon_resolved -> recon_ports |
| **VHost Discovery** | ffuf Host header fuzzing | recon_ports -> recon_subdomains |
| **HTTP Probing** | httpx | recon_ports -> recon_http |
| **Content Discovery** | feroxbuster recursive | recon_http -> recon_urls |
| **Screenshots** | gowitness | recon_http -> *(terminal)* |
| **Web Crawling** | katana | recon_http -> recon_urls, recon_js |
| **Nuclei Scanning** | nuclei | recon_http -> vuln_findings |
| **Endpoint CSV** | file writer | recon_http + recon_urls -> endpoints.csv |
| **JS Analysis** | regex (secrets, endpoints) | recon_js -> vuln_findings |
| **JS Keywords** | regex + altdns mutation | recon_js -> custom.txt + DB |
| **CVE Correlate** | NVD API | vuln_findings -> vuln_findings |
| **Finding Filter** | rule-based FP suppression | vuln_findings -> vuln_findings |

## Data Model

SQLite (`data/bbtrs.db`):

| Table | Contents |
|---|---|
| `programs` | Program definitions, scope wildcards |
| `apex_domains` | Company-owned apex domains (tenant discovery) |
| `subdomains` | Discovered subdomains with source tracking |
| `dns_records` | A, CNAME, MX, NS, TXT records |
| `ports` | Open ports with service/version/banner |
| `http_services` | Live HTTP services, tech stack, headers, titles |
| `urls` | Discovered URLs and parameters |
| `js_files` | JS files with extracted secrets and endpoints |
| `findings` | Vuln findings with CVE links, dedup hash, FP flag |
| `cves` | CVE records (CVSS, affected product, versions) |
| `fp_rules` | False positive rules (template_id, title, url_pattern) |
| `asn_data` | ASN + CIDR ranges per program |
| `shodan_hosts` | Shodan host data |
| `github_leaks` | GitHub dorking results |
| `vhosts` | Virtual hosts discovered per IP |
| `takeover_candidates` | Subdomain takeover candidates |

## CLI Reference

| Command | Description |
|---|---|
| `scope add <name>` | Add program with `-w` wildcards, `-d` domains, `-e` excludes |
| `scope list` | List configured programs |
| `scope sync-intigriti <co> --all` | Sync all Intigriti programs |
| `scope poll-activities --feed` | Check for scope changes, feed new domains |
| `run all` | Run all workers + scheduler (continuous) |
| `run monitor` | Poll Intigriti activities, auto-feed new domains |
| `run stage <name>` | Run a single stage worker |
| `recon subdomains <domain>` | Full subdomain enumeration |
| `recon puredns <domain>` | DNS brute-force |
| `recon alterx <file>` | Subdomain permutations |
| `recon asn <target>` | ASN + CIDR discovery |
| `recon certs <cidr>` | TLS cert scanning |
| `recon shodan <domain>` | Shodan signature scanning |
| `recon github-dork <domain>` | GitHub code search |
| `recon portscan <target>` | Tiered port scan |
| `recon bbot <domain>` | BBOT all-in-one |
| `recon content-discovery <url>` | feroxbuster recursive |
| `recon vhost <ip> <apex>` | ffuf vhost fuzzing |
| `recon takeover <program>` | subzy + nuclei takeover check |
| `status` | Pipeline statistics |
| `findings` | List findings (filterable by severity, status) |
| `finding <id>` | Detailed finding view |
| `export <program>` | Export JSON for analysis |
| `export-endpoints <program>` | Export endpoints CSV |
| `fp add` | Add false positive filter rule |
| `mark-fp <id>` | Mark finding as false positive |
| `mark-reviewed <id>` | Mark finding as reviewed |
| `mark-reported <id>` | Mark finding as reported |
| `flush` | Clear streams and/or dedup cache |

## Notifications

Set Discord/Slack webhooks in `config.yml` or via env vars (`DISCORD_WEBHOOK`, `SLACK_WEBHOOK`) to get alerts for:

- `takeover_found`: subdomain takeover candidate confirmed
- `new_apex_domain`: new company-owned domain found via tenant lookup
- `new_http_service`: new HTTP service found by httpx
- `scan_complete`: pipeline cycle done

Rate-limited to 1 notification per event type per 5 minutes.

## Project Structure

```
BugBountyTRS/
├── cli.py                          # CLI (Click)
├── config/
│   ├── config.yml                  # All tool + pipeline config
│   └── shodan_signatures.yml       # 83 Shodan dork signatures by category
├── docs/
│   ├── methodology.md              # Recon methodology reference
│   └── conversation_log.md         # Architecture decision log
├── pipeline/
│   ├── core/
│   │   ├── config.py, queue.py, dedup.py, worker.py
│   │   ├── storage.py              # SQLite with migrations
│   │   └── ratelimit.py            # Distributed scan mutex (Redis)
│   ├── services/
│   │   └── domain_ranking.py       # FastAPI Tranco+Umbrella ranking service
│   └── stages/                     # One file per pipeline stage
│       ├── scope.py, scheduler.py, platforms.py
│       ├── apex_discovery.py       # tenant_domains Microsoft apex enum
│       ├── passive_dns.py          # Crobat/CIRCL/Umbrella passive DNS
│       ├── subdomain.py            # subfinder + BBOT + puredns + alterx
│       ├── asn_discovery.py, cert_discovery.py, bbot_discovery.py
│       ├── shodan_recon.py, github_dorking.py
│       ├── dns_resolve.py, portscan.py
│       ├── vhost_discovery.py      # ffuf Host header fuzzing
│       ├── httpprobe.py
│       ├── content_discovery.py    # feroxbuster recursive
│       ├── takeover_check.py       # subzy + nuclei takeover templates
│       ├── screenshot.py, crawler.py
│       ├── js_analyze.py, js_keyword_extract.py
│       ├── nuclei_scan.py
│       ├── credential_recon.py     # DeHashed + Flare + DefaultCreds
│       ├── cve_correlate.py, finding_filter.py
│       ├── endpoint_csv.py         # Continuous CSV endpoint writer
│       └── notification.py         # Discord/Slack event dispatcher
├── scripts/
│   ├── install_tools.sh            # Installs all tools
│   ├── sni_lookup.sh               # Kaeferjaeger SNI data extraction
│   └── tenant_domains.sh           # Microsoft tenant apex discovery
└── data/                           # Runtime data (gitignored)
    ├── bbtrs.db
    ├── endpoints.csv               # Continuous endpoint output
    ├── screenshots/
    └── programs/<name>/export.json
```

## Adding Custom Stages

```python
from pipeline.core.worker import BaseWorker

class MyWorker(BaseWorker):
    name = "my_stage"
    input_stream = "recon_http"
    output_streams = ["vuln_findings"]

    def dedup_key(self, data: dict) -> str:
        return f"my_stage:{data.get('url', '')}"

    def process(self, data: dict) -> list[dict]:
        url = data.get("url")
        # your logic here
        return [{"tool": "my_stage", "severity": "info", "url": url}]
```

Register in `cli.py` `WORKERS` dict and it's automatically included in `run all`.

## License

MIT

# BugBountyTRS

A modular, continuous bug bounty reconnaissance and vulnerability scanning pipeline. Built with an event-driven architecture using Redis Streams for inter-stage communication, designed to run 24/7 and accumulate structured recon data for manual analysis and PoC development.

## Architecture

```
Scheduler (periodic re-feed)
    |
[scope:targets] --> Subdomain Discovery (subfinder + amass)
    |
[recon:subdomains] --> DNS Resolution (dig, dangling CNAME detection)
    |
[recon:resolved] --> Port Scanning (nmap -sV -sC)
    |
[recon:ports] --> HTTP Probing (httpx + tech detection)
    |
[recon:http] --> Crawler (katana)       + Screenshots (gowitness) + Nuclei Scanning
    |                |
[recon:urls]    [recon:js] --> JS Analysis (secret detection, endpoint extraction)
    |
[vuln:findings] --> SQLite DB (structured, exportable as JSON)
```

### Design Principles

- **Event-driven**: Each stage is a stateless worker consuming from Redis Streams and publishing to the next
- **Continuous**: The scheduler re-feeds all scope targets on a configurable interval (default 24h)
- **Deduplication**: Redis TTL keys prevent rescanning the same target within a cycle
- **Rate-limit aware**: All tools respect configurable rate limits for RoE compliance
- **RoE header injection**: Configurable User-Agent and custom headers injected into all HTTP-touching tools
- **Structured storage**: SQLite database with full relational model; JSON export for external analysis

## Requirements

- Python 3.11+
- Docker (for Redis)
- Go 1.20+ (for installing tools)

## Quick Start

### 1. Install dependencies

```bash
# Install Python packages
pip install -r requirements.txt

# Install recon tools (subfinder, httpx, nuclei, katana, gowitness, nmap)
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
```

Set your platform username and rate limits according to the target program's Rules of Engagement.

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
| `status` | Show pipeline statistics |
| `findings` | List vulnerability findings with filters |
| `finding <id>` | Show detailed finding info |
| `export <program>` | Export program data as JSON |
| `export-all` | Export all programs |
| `flush` | Clear streams and/or dedup cache |

## Pipeline Stages

| Stage | Tool(s) | Input Stream | Output Stream |
|---|---|---|---|
| **Subdomain Discovery** | subfinder, amass | `scope:targets` | `recon:subdomains` |
| **DNS Resolution** | dig, socket | `recon:subdomains` | `recon:resolved` |
| **Port Scanning** | nmap | `recon:resolved` | `recon:ports` |
| **HTTP Probing** | httpx | `recon:ports` | `recon:http` |
| **Screenshots** | gowitness | `recon:http` | *(terminal)* |
| **Web Crawling** | katana | `recon:http` | `recon:urls`, `recon:js` |
| **JS Analysis** | regex engine | `recon:js` | `vuln:findings` |
| **Nuclei Scanning** | nuclei | `recon:http` | `vuln:findings` |

## Data Model

All data is stored in SQLite (`data/bbtrs.db`) with the following tables:

- `programs` - Bug bounty program definitions and scope
- `subdomains` - Discovered subdomains per program
- `dns_records` - DNS records (A, AAAA, CNAME, MX, NS, TXT)
- `ports` - Open ports with service/version info
- `http_services` - Live HTTP services with tech stack, headers, titles
- `urls` - Discovered URLs with parameters
- `js_files` - Analyzed JavaScript files with extracted secrets and endpoints
- `findings` - Vulnerability findings from all scanners

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
- **Nmap**: Top ports, scan rate, scripts
- **Nuclei**: Template dirs, severity filters, thread counts

## Project Structure

```
BugBountyTRS/
├── cli.py                          # Main CLI entry point
├── config/
│   └── config.yml                  # Pipeline configuration
├── docker-compose.yml              # Redis
├── requirements.txt                # Python dependencies
├── scripts/
│   └── install_tools.sh            # Tool installer
├── pipeline/
│   ├── core/
│   │   ├── config.py               # Config loader
│   │   ├── queue.py                # Redis Streams wrapper
│   │   ├── dedup.py                # Deduplication with TTL
│   │   ├── storage.py              # SQLite storage layer
│   │   └── worker.py               # Base worker class
│   └── stages/
│       ├── scope.py                # Scope management
│       ├── platforms.py            # HackerOne + Intigriti sync
│       ├── scheduler.py            # Periodic target re-feed
│       ├── subdomain.py            # Subdomain enumeration
│       ├── dns_resolve.py          # DNS resolution + takeover detection
│       ├── portscan.py             # Nmap port scanning
│       ├── httpprobe.py            # HTTP service probing
│       ├── screenshot.py           # Screenshot capture
│       ├── crawler.py              # Web crawling
│       ├── js_analyze.py           # JavaScript analysis
│       └── nuclei_scan.py          # Vulnerability scanning
└── data/                           # Runtime data (gitignored)
    ├── bbtrs.db                    # SQLite database
    ├── screenshots/                # Captured screenshots
    └── programs/                   # Per-program exports
```

## License

MIT

#!/usr/bin/env python3
"""BugBountyTRS CLI - Continuous Bug Bounty Recon Pipeline.

Usage:
    python3 cli.py scope add <name> --wildcard "*.example.com"
    python3 cli.py scope sync-intigriti <company> [--all]
    python3 cli.py scope poll-activities [--feed]
    python3 cli.py run all [--program visma]
    python3 cli.py run monitor [--interval 3600]
    python3 cli.py run stage <name>
    python3 cli.py recon subdomains <domain> [-p program] [-o out.txt]
    python3 cli.py recon puredns <domain>
    python3 cli.py recon alterx <input_file>
    python3 cli.py recon asn <domain_or_ip> [--seeds]
    python3 cli.py recon shodan <domain> [--leaks]
    python3 cli.py recon github-dork <domain>
    python3 cli.py recon portscan <target> [--passive-only|--fast|--deep]
    python3 cli.py recon bbot <domain> [-P subdomain-enum|kitchen-sink]
    python3 cli.py recon certs <cidr_or_file> [-d domain] [-p ports]
    python3 cli.py recon content-discovery <url> [-p program]
    python3 cli.py recon vhost <ip> <apex> [--port 443]
    python3 cli.py recon takeover <program>
    python3 cli.py status
    python3 cli.py export <program>
    python3 cli.py export-endpoints <program> [-o out.csv]
    python3 cli.py findings [--severity critical]
"""

import os
import sys
import json
import signal
import logging
import threading
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from pipeline.core.config import load_config, get_config
from pipeline.core.storage import Storage
from pipeline.core.queue import MessageQueue

console = Console()
log = logging.getLogger("bbtrs")


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


@click.group()
@click.option("--config", "-c", default=None, help="Config file path")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def cli(config, verbose):
    """BugBountyTRS - Continuous Bug Bounty Recon Pipeline"""
    setup_logging(verbose)
    if config:
        load_config(config)


# ─── Scope Management ────────────────────────────────────────────

@cli.group()
def scope():
    """Manage bug bounty program scopes."""
    pass


@scope.command("add")
@click.argument("name")
@click.option("--platform", "-p", default=None, help="Platform (hackerone, intigriti, etc.)")
@click.option("--wildcard", "-w", multiple=True, help="Wildcard scope (e.g., *.example.com)")
@click.option("--domain", "-d", multiple=True, help="Specific domain")
@click.option("--exclude", "-e", multiple=True, help="Exclude pattern")
@click.option("--url", default=None, help="Program URL")
def scope_add(name, platform, wildcard, domain, exclude, url):
    """Add a bug bounty program."""
    from pipeline.stages.scope import ScopeManager
    mgr = ScopeManager()
    mgr.add_program(
        name=name,
        platform=platform,
        url=url,
        wildcards=list(wildcard),
        domains=list(domain),
        excludes=list(exclude),
    )
    console.print(f"[green]Added program '{name}'[/green]")
    console.print(f"  Wildcards: {list(wildcard)}")
    console.print(f"  Domains: {list(domain)}")
    console.print(f"  Excludes: {list(exclude)}")


@scope.command("list")
def scope_list():
    """List all programs."""
    storage = Storage()
    programs = storage.list_programs()
    if not programs:
        console.print("[yellow]No programs configured.[/yellow]")
        return

    table = Table(title="Bug Bounty Programs")
    table.add_column("ID", style="dim")
    table.add_column("Name", style="bold")
    table.add_column("Platform")
    table.add_column("Scope")
    table.add_column("Added")

    for p in programs:
        scope_data = json.loads(p["scope_json"]) if p["scope_json"] else {}
        wc = len(scope_data.get("wildcards", []))
        dom = len(scope_data.get("domains", []))
        table.add_row(
            str(p["id"]),
            p["name"],
            p["platform"] or "-",
            f"{wc} wildcards, {dom} domains",
            p["created_at"],
        )
    console.print(table)


@scope.command("import")
@click.argument("file_path")
@click.option("--platform", "-p", default=None)
def scope_import(file_path, platform):
    """Import programs from a text file.
    Format: name|*.wildcard.com,domain.com|exclude.com
    """
    from pipeline.stages.scope import ScopeManager
    mgr = ScopeManager()
    mgr.import_from_file(file_path, platform=platform)
    console.print(f"[green]Imported programs from {file_path}[/green]")


@scope.command("feed")
@click.option("--program", "-p", default=None, help="Only feed targets for this program")
def scope_feed(program):
    """Push scope targets into the pipeline for scanning."""
    from pipeline.stages.scope import ScopeManager
    mgr = ScopeManager()
    mgr.load_programs()
    mgr.feed_targets(program_filter=program)
    if program:
        console.print(f"[green]Targets for '{program}' published to pipeline.[/green]")
    else:
        console.print("[green]All targets published to pipeline.[/green]")


@scope.command("sync-h1")
@click.argument("handle")
@click.option("--api-user", envvar="H1_API_USER", default=None)
@click.option("--api-token", envvar="H1_API_TOKEN", default=None)
def scope_sync_h1(handle, api_user, api_token):
    """Sync program scope from HackerOne."""
    from pipeline.stages.scope import ScopeManager
    from pipeline.stages.platforms import HackerOneSync
    mgr = ScopeManager()
    h1 = HackerOneSync(mgr, api_user, api_token)
    h1.sync_program(handle)
    console.print(f"[green]Synced HackerOne program: {handle}[/green]")


@scope.command("sync-intigriti")
@click.argument("company")
@click.option("--program", default=None, help="Specific program handle")
@click.option("--all", "sync_all", is_flag=True, help="Sync all accessible programs")
@click.option("--api-token", envvar="INTIGRITI_TOKEN", default=None)
def scope_sync_intigriti(company, program, sync_all, api_token):
    """Sync program scope from Intigriti.

    Use --all to sync every program accessible to your API token.
    """
    from pipeline.stages.scope import ScopeManager
    from pipeline.stages.platforms import IntigritiSync
    mgr = ScopeManager()
    inti = IntigritiSync(mgr, api_token)

    if sync_all:
        console.print("[dim]Syncing all accessible Intigriti programs...[/dim]")
        inti.sync_all_programs()
        console.print("[green]All programs synced.[/green]")
    else:
        inti.sync_program(company, program)
        console.print(f"[green]Synced Intigriti program: {company}[/green]")


@scope.command("poll-activities")
@click.option("--api-token", envvar="INTIGRITI_TOKEN", default=None)
@click.option("--feed", is_flag=True, help="Feed newly discovered domains into the pipeline")
def scope_poll_activities(api_token, feed):
    """Check Intigriti for scope changes (new domains added/removed).

    Use --feed to automatically push new domains into the pipeline.
    """
    from pipeline.stages.scope import ScopeManager
    from pipeline.stages.platforms import IntigritiSync
    mgr = ScopeManager()
    inti = IntigritiSync(mgr, api_token)

    activities = inti.poll_program_activities()
    new_domains = inti.extract_new_domains_from_activities(activities)

    if not new_domains:
        console.print("[dim]No new scope changes detected.[/dim]")
        return

    table = Table(title=f"New Scope Additions ({len(new_domains)})")
    table.add_column("Program")
    table.add_column("Domain")
    table.add_column("Type")
    for d in new_domains:
        table.add_row(str(d["program_id"]), d["domain"], str(d["type"]))
    console.print(table)

    if feed:
        from pipeline.core.queue import MessageQueue
        cfg = get_config()
        mq = MessageQueue("group:scope-poll", "scope-poll")
        stream = cfg["streams"]["scope_targets"]
        for d in new_domains:
            mq.publish(stream, {
                "domain": d["domain"],
                "program": str(d["program_id"]),
                "source": "intigriti_activities",
            })
        console.print(f"[green]Fed {len(new_domains)} new domains into pipeline.[/green]")


# ─── Recon (one-shot domain discovery) ───────────────────────────

@cli.group()
def recon():
    """Run individual recon tools (one-shot, outside the pipeline)."""
    pass


@recon.command("crtsh")
@click.argument("domain")
@click.option("--wildcard", "-w", is_flag=True, help="Extract wildcard subdomains only")
@click.option("--output", "-o", default=None, help="Output file")
@click.option("--program", "-p", default=None, help="Associate with program (stores in DB)")
def recon_crtsh(domain, wildcard, output, program):
    """Scrape crt.sh certificate transparency logs for subdomains."""
    from pipeline.stages.subdomain import crtsh_subdomains

    mode = "wildcard" if wildcard else "non-wildcard"
    console.print(f"[dim]Querying crt.sh for {domain} ({mode})...[/dim]")

    try:
        subs = crtsh_subdomains(domain, wildcard=wildcard)
    except Exception as e:
        console.print(f"[red]crt.sh query failed: {e}[/red]")
        return

    if not subs:
        console.print("[yellow]No subdomains found.[/yellow]")
        return

    # Store in DB if program specified
    if program:
        storage = Storage()
        prog = storage.get_program(program)
        if prog:
            for sub in subs:
                storage.upsert_subdomain(prog["id"], sub, source="crtsh")
            console.print(f"[green]Stored {len(subs)} subdomains for program '{program}'[/green]")
        else:
            console.print(f"[yellow]Program '{program}' not found, results not stored[/yellow]")

    # Output
    sorted_subs = sorted(subs)
    if output:
        with open(output, "w") as f:
            f.write("\n".join(sorted_subs) + "\n")
        console.print(f"[green]Wrote {len(sorted_subs)} subdomains to {output}[/green]")
    else:
        for sub in sorted_subs:
            click.echo(sub)
        console.print(f"\n[dim]{len(sorted_subs)} subdomains found[/dim]")


@recon.command("puredns")
@click.argument("domain")
@click.option("--wordlist", "-w", default=None, help="DNS wordlist")
@click.option("--resolvers", "-r", default=None, help="Resolvers file")
@click.option("--rate-limit", "-R", default=1000, help="Public resolver rate limit")
@click.option("--rate-limit-trusted", "-T", default=300, help="Trusted resolver rate limit")
@click.option("--output", "-o", default=None, help="Output file")
@click.option("--program", "-p", default=None, help="Associate with program (stores in DB)")
def recon_puredns(domain, wordlist, resolvers, rate_limit, rate_limit_trusted, output, program):
    """Brute-force subdomains using puredns."""
    from pipeline.stages.subdomain import puredns_bruteforce

    console.print(f"[dim]Running puredns brute-force on {domain}...[/dim]")

    try:
        subs = puredns_bruteforce(domain, wordlist=wordlist, resolvers=resolvers,
                                  rate_limit=rate_limit, rate_limit_trusted=rate_limit_trusted)
    except FileNotFoundError:
        console.print("[red]puredns not found. Install: go install github.com/d3mondev/puredns/v2@latest[/red]")
        return
    except Exception as e:
        console.print(f"[red]puredns failed: {e}[/red]")
        return

    if not subs:
        console.print("[yellow]No subdomains found.[/yellow]")
        return

    if program:
        storage = Storage()
        prog = storage.get_program(program)
        if prog:
            for sub in subs:
                storage.upsert_subdomain(prog["id"], sub, source="puredns")
            console.print(f"[green]Stored {len(subs)} subdomains for program '{program}'[/green]")
        else:
            console.print(f"[yellow]Program '{program}' not found, results not stored[/yellow]")

    sorted_subs = sorted(subs)
    if output:
        with open(output, "w") as f:
            f.write("\n".join(sorted_subs) + "\n")
        console.print(f"[green]Wrote {len(sorted_subs)} subdomains to {output}[/green]")
    else:
        for sub in sorted_subs:
            click.echo(sub)
        console.print(f"\n[dim]{len(sorted_subs)} subdomains found[/dim]")


@recon.command("alterx")
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Output file")
def recon_alterx(input_file, output):
    """Generate subdomain permutations from a list of known subdomains."""
    from pipeline.stages.subdomain import alterx_permutations

    with open(input_file) as f:
        known = [line.strip() for line in f if line.strip()]

    if not known:
        console.print("[yellow]Input file is empty.[/yellow]")
        return

    console.print(f"[dim]Generating permutations from {len(known)} subdomains...[/dim]")

    try:
        perms = alterx_permutations(known)
    except FileNotFoundError:
        console.print("[red]alterx not found. Install: go install github.com/projectdiscovery/alterx/cmd/alterx@latest[/red]")
        return
    except Exception as e:
        console.print(f"[red]alterx failed: {e}[/red]")
        return

    new_perms = perms - set(known)
    sorted_perms = sorted(new_perms)

    if output:
        with open(output, "w") as f:
            f.write("\n".join(sorted_perms) + "\n")
        console.print(f"[green]Wrote {len(sorted_perms)} permutations to {output}[/green]")
    else:
        for p in sorted_perms:
            click.echo(p)
        console.print(f"\n[dim]{len(sorted_perms)} new permutations generated[/dim]")


@recon.command("subdomains")
@click.argument("domain")
@click.option("--program", "-p", default=None, help="Associate with program (stores in DB)")
@click.option("--output", "-o", default=None, help="Output file")
@click.option("--passive-only", is_flag=True, help="Skip active brute-force and permutations")
@click.option("--no-permutations", is_flag=True, help="Skip alterx permutation generation")
def recon_subdomains(domain, program, output, passive_only, no_permutations):
    """Run full subdomain discovery (all tools combined).

    Runs: subfinder -all + BBOT (parallel) + puredns + alterx
    """
    import subprocess
    import concurrent.futures
    from pipeline.stages.subdomain import puredns_bruteforce, alterx_permutations

    subdomains = set()
    subdomains.add(domain)

    # Subfinder
    def _run_subfinder():
        cfg = get_config()["tools"].get("subfinder", {})
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent", "-all",
                 "-t", str(cfg.get("threads", 10)),
                 "-timeout", str(cfg.get("timeout", 30))],
                capture_output=True, text=True, timeout=300,
            )
            return {l.strip() for l in result.stdout.splitlines() if l.strip()}, None
        except FileNotFoundError:
            return set(), "not installed"
        except Exception as e:
            return set(), str(e)

    # BBOT
    def _run_bbot():
        try:
            from bbot.scanner import Scanner
            scan = Scanner(domain, presets=["subdomain-enum"])
            found = set()
            for event in scan.start():
                if event.type == "DNS_NAME":
                    d = str(event.data) if not isinstance(event.data, str) else event.data
                    found.add(d.lower())
            return found, None
        except ImportError:
            return set(), "not installed"
        except Exception as e:
            return set(), str(e)

    console.print("[dim]Running subfinder + BBOT in parallel...[/dim]")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_sf = pool.submit(_run_subfinder)
        f_bb = pool.submit(_run_bbot)
        sf, sf_err = f_sf.result()
        bb, bb_err = f_bb.result()

    subdomains.update(sf)
    console.print(f"  subfinder: [green]{len(sf)}[/green]" + (f" [yellow]({sf_err})[/yellow]" if sf_err else ""))
    subdomains.update(bb)
    console.print(f"  bbot: [green]{len(bb)}[/green]" + (f" [yellow]({bb_err})[/yellow]" if bb_err else ""))

    passive_count = len(subdomains)
    console.print(f"[bold]Passive total: {passive_count}[/bold]")

    if not passive_only:
        # puredns
        console.print("[dim]Running puredns brute-force...[/dim]")
        try:
            pd = puredns_bruteforce(domain)
            new_pd = pd - subdomains
            subdomains.update(pd)
            console.print(f"  puredns: [green]{len(new_pd)} new[/green]")
        except FileNotFoundError:
            console.print("  puredns: [yellow]not installed[/yellow]")
        except Exception as e:
            console.print(f"  puredns: [red]{e}[/red]")

        # alterx permutations
        if not no_permutations and len(subdomains) > 1:
            console.print("[dim]Generating alterx permutations...[/dim]")
            try:
                perms = alterx_permutations(list(subdomains))
                new_perms = perms - subdomains
                if new_perms:
                    console.print(f"  alterx: {len(new_perms)} candidates, resolving...")
                    # Resolve with puredns
                    import tempfile
                    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp_in:
                        tmp_in.write("\n".join(new_perms))
                        tmp_in_path = tmp_in.name
                    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp_out:
                        tmp_out_path = tmp_out.name

                    try:
                        pcfg = get_config()["tools"].get("puredns", {})
                        resolvers = pcfg.get("resolvers", "/usr/share/wordlists/resolvers.txt")
                        cmd = ["puredns", "resolve", tmp_in_path, "--write", tmp_out_path]
                        if Path(resolvers).exists():
                            cmd.extend(["--resolvers", resolvers])
                        subprocess.run(cmd, capture_output=True, text=True, timeout=600)

                        resolved = set()
                        if Path(tmp_out_path).exists():
                            with open(tmp_out_path) as f:
                                resolved = {l.strip().lower() for l in f if l.strip()}
                        subdomains.update(resolved)
                        console.print(f"  alterx resolved: [green]{len(resolved)} new[/green]")
                    finally:
                        Path(tmp_in_path).unlink(missing_ok=True)
                        Path(tmp_out_path).unlink(missing_ok=True)
                else:
                    console.print("  alterx: [yellow]no new permutations[/yellow]")
            except FileNotFoundError:
                console.print("  alterx: [yellow]not installed[/yellow]")
            except Exception as e:
                console.print(f"  alterx: [red]{e}[/red]")

    console.print(f"\n[bold green]Total: {len(subdomains)} unique subdomains[/bold green]")

    # Store in DB
    if program:
        storage = Storage()
        prog = storage.get_program(program)
        if prog:
            for sub in subdomains:
                storage.upsert_subdomain(prog["id"], sub, source="recon-full")
            console.print(f"[green]Stored in DB for program '{program}'[/green]")
        else:
            console.print(f"[yellow]Program '{program}' not found[/yellow]")

    # Output
    sorted_subs = sorted(subdomains)
    if output:
        with open(output, "w") as f:
            f.write("\n".join(sorted_subs) + "\n")
        console.print(f"[green]Wrote to {output}[/green]")
    else:
        console.print("")
        for sub in sorted_subs:
            click.echo(sub)


@recon.command("asn")
@click.argument("target")
@click.option("--output", "-o", default=None, help="Output file")
@click.option("--program", "-p", default=None, help="Associate with program (stores in DB)")
@click.option("--seeds", is_flag=True, help="Also discover seed domains from ASNs via amass intel")
def recon_asn(target, output, program, seeds):
    """Full ASN discovery: Cymru + asnmap + whois + amass intel.

    Finds ASNs, IP ranges, and optionally seed domains for a target.
    """
    from pipeline.stages.asn_discovery import discover_asns

    console.print(f"[dim]Running full ASN discovery for {target}...[/dim]")

    data = discover_asns(target)

    if data.get("ip"):
        console.print(f"  Resolved: {target} -> {data['ip']}")

    # ASN table
    if data["asns"]:
        table = Table(title=f"ASNs for {target}")
        table.add_column("ASN", style="bold")
        for asn in data["asns"]:
            table.add_row(asn)
        console.print(table)

    # IP ranges
    if data["ip_ranges"]:
        range_table = Table(title="IP Ranges")
        range_table.add_column("CIDR", style="green")
        for cidr in data["ip_ranges"]:
            range_table.add_row(cidr)
        console.print(range_table)

    # Seed domains
    if data["seed_domains"]:
        seed_table = Table(title="Seed Domains (from amass intel)")
        seed_table.add_column("Domain")
        for d in data["seed_domains"]:
            seed_table.add_row(d)
        console.print(seed_table)

    if not data["asns"] and not data["ip_ranges"]:
        console.print("[yellow]No ASN information found.[/yellow]")
        return

    console.print(f"\n[bold green]{len(data['asns'])} ASNs, {len(data['ip_ranges'])} IP ranges, "
                  f"{len(data['seed_domains'])} seed domains[/bold green]")

    # Store in DB
    if program:
        storage = Storage()
        prog = storage.get_program(program)
        if prog:
            with storage._conn() as conn:
                for asn in data["asns"]:
                    conn.execute(
                        """INSERT OR IGNORE INTO asn_data (program_id, domain, asn, ip_ranges_json, discovered_at)
                           VALUES (?, ?, ?, ?, datetime('now'))""",
                        (prog["id"], target, asn, json.dumps(data["ip_ranges"])),
                    )
            if seeds and data["seed_domains"]:
                for d in data["seed_domains"]:
                    storage.upsert_subdomain(prog["id"], d, source="amass-intel")
            console.print(f"[green]Stored for program '{program}'[/green]")

    if output:
        with open(output, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[green]Wrote to {output}[/green]")


@recon.command("shodan")
@click.argument("domain")
@click.option("--api-key", "-k", envvar="SHODAN_API_KEY", default=None, help="Shodan API key")
@click.option("--leaks", "-l", is_flag=True, help="Run leak detection dorks")
@click.option("--output", "-o", default=None, help="Output file (JSON)")
@click.option("--program", "-p", default=None, help="Associate with program (stores in DB)")
def recon_shodan(domain, api_key, leaks, output, program):
    """Karma-style Shodan recon: SSL certs, org search, WAF bypass, leaks.

    Requires SHODAN_API_KEY env var or --api-key flag.
    """
    if not api_key:
        api_key = get_config().get("shodan", {}).get("api_key")
    if not api_key:
        console.print("[red]No Shodan API key. Set SHODAN_API_KEY or use --api-key[/red]")
        return

    try:
        import shodan  # noqa: F401
    except ImportError:
        console.print("[red]shodan package not installed. Run: pip install shodan[/red]")
        return

    from pipeline.stages.shodan_recon import shodan_scan_domain

    # Parse categories and tags from --leaks flag or future options
    categories = None
    tags = None
    if leaks:
        categories = ["dashboards", "databases", "containers", "storage", "legacy"]

    console.print(f"[dim]Running signature-based Shodan recon for {domain}...[/dim]")

    data = shodan_scan_domain(domain, api_key, categories=categories, tags=tags)

    console.print(f"  Signatures run: [green]{data['stats']['signatures_run']}[/green]")
    console.print(f"  Matches: [green]{data['stats']['matches']}[/green]")
    console.print(f"  Unique IPs: [bold]{data['stats']['ips_found']}[/bold]")

    # IP summary table
    if data["ips"]:
        ip_table = Table(title="Discovered IPs")
        ip_table.add_column("IP", style="bold")
        ip_table.add_column("Org")
        ip_table.add_column("Ports")
        ip_table.add_column("Signatures Matched")
        for ip, info in sorted(data["ips"].items()):
            ip_table.add_row(
                ip,
                info.get("org", ""),
                ", ".join(str(p) for p in info.get("ports", [])),
                ", ".join(info.get("signatures_matched", [])[:3]),
            )
        console.print(ip_table)

    # Findings table
    if data["findings"]:
        find_table = Table(title="Findings")
        find_table.add_column("Severity", style="bold")
        find_table.add_column("Signature")
        find_table.add_column("IP:Port")
        find_table.add_column("Title")
        for f in data["findings"]:
            find_table.add_row(
                f["severity"], f["signature"],
                f"{f['ip']}:{f.get('port', '?')}", f.get("title", ""),
            )
        console.print(find_table)

    # CVEs
    if data["vulns"]:
        console.print(f"\n[bold red]{len(data['vulns'])} CVEs found:[/bold red]")
        for v in data["vulns"][:20]:
            console.print(f"  {v['cve']} on {v['ip']}")

    # Store
    if program:
        storage = Storage()
        prog = storage.get_program(program)
        if prog:
            with storage._conn() as conn:
                for ip in data["all_ips"]:
                    conn.execute(
                        """INSERT OR IGNORE INTO shodan_hosts
                           (program_id, ip, domain, source, discovered_at)
                           VALUES (?, ?, ?, 'shodan', datetime('now'))""",
                        (prog["id"], ip, domain),
                    )
            console.print(f"[green]Stored {len(data['all_ips'])} hosts for '{program}'[/green]")

    if output:
        with open(output, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[green]Wrote to {output}[/green]")


@recon.command("github-dork")
@click.argument("domain")
@click.option("--category", "-c", multiple=True,
              type=click.Choice(["credentials", "config", "database", "subdomains", "internal"]),
              help="Filter by category (default: all)")
@click.option("--output", "-o", default=None, help="Output file (JSON)")
@click.option("--program", "-p", default=None, help="Associate with program (stores in DB)")
def recon_github_dork(domain, category, output, program):
    """Search GitHub for leaked secrets, configs, and subdomains.

    Requires: gh CLI authenticated (gh auth login).
    """
    import subprocess
    try:
        subprocess.run(["gh", "auth", "status"], capture_output=True, check=True, timeout=10)
    except (subprocess.CalledProcessError, FileNotFoundError):
        console.print("[red]GitHub CLI not authenticated. Run: gh auth login[/red]")
        return

    from pipeline.stages.github_dorking import github_dork_domain

    categories = list(category) if category else None
    console.print(f"[dim]Running GitHub dorks for {domain}...[/dim]")

    hits = github_dork_domain(domain, categories=categories)

    if not hits:
        console.print("[yellow]No results found.[/yellow]")
        return

    table = Table(title=f"GitHub Dork Results: {domain}")
    table.add_column("Category", style="bold")
    table.add_column("Repo")
    table.add_column("File")
    table.add_column("URL", max_width=60)

    for hit in hits:
        table.add_row(
            hit.get("category", ""),
            hit.get("repo", ""),
            hit.get("path", ""),
            hit.get("html_url", ""),
        )
    console.print(table)
    console.print(f"\n[bold]{len(hits)} results[/bold]")

    if program:
        storage = Storage()
        prog = storage.get_program(program)
        if prog:
            with storage._conn() as conn:
                for hit in hits:
                    conn.execute(
                        """INSERT OR IGNORE INTO github_leaks
                           (program_id, domain, category, repo, file_path, url, dork, discovered_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
                        (prog["id"], domain, hit.get("category"), hit.get("repo"),
                         hit.get("path"), hit.get("html_url"), hit.get("dork")),
                    )
            console.print(f"[green]Stored for program '{program}'[/green]")

    if output:
        with open(output, "w") as f:
            json.dump(hits, f, indent=2)
        console.print(f"[green]Wrote to {output}[/green]")


@recon.command("portscan")
@click.argument("target")
@click.option("--passive-only", is_flag=True, help="Only use smap (passive Shodan InternetDB)")
@click.option("--fast", is_flag=True, help="Only use smap + naabu (skip nmap deep scan)")
@click.option("--deep", is_flag=True, help="Run all tiers including nmap service detection")
@click.option("--output", "-o", default=None, help="Output file (JSON)")
@click.option("--program", "-p", default=None, help="Associate with program (stores in DB)")
def recon_portscan(target, passive_only, fast, deep, output, program):
    """Tiered port scan: smap (passive) -> naabu (fast) -> nmap (deep).

    Default runs all three tiers. Use --passive-only for zero-packet scan
    via Shodan InternetDB, or --fast to skip nmap fingerprinting.
    """
    from pipeline.stages.portscan import PortScanWorker
    from pipeline.stages.shodan_recon import shodan_internetdb

    results = []

    # Determine tiers
    if passive_only:
        tiers = ["smap"]
    elif fast:
        tiers = ["smap", "naabu"]
    elif deep:
        tiers = ["smap", "naabu", "nmap"]
    else:
        tiers = ["smap", "naabu", "nmap"]

    # Quick passive check via InternetDB API
    console.print(f"[dim]Scanning {target} (tiers: {', '.join(tiers)})...[/dim]")

    if "smap" in tiers:
        console.print("[dim]  Tier 1: Querying Shodan InternetDB (passive)...[/dim]")
        idb = shodan_internetdb(target)
        if idb:
            ports = idb.get("ports", [])
            console.print(f"  InternetDB: [green]{len(ports)}[/green] ports — {ports}")
            if idb.get("vulns"):
                console.print(f"  CVEs: [red]{', '.join(idb['vulns'][:10])}[/red]")
            if idb.get("hostnames"):
                console.print(f"  Hostnames: {', '.join(idb['hostnames'][:10])}")
            for p in ports:
                results.append({"port": p, "protocol": "tcp", "source": "internetdb", "state": "open"})
        else:
            console.print("  InternetDB: [yellow]no data[/yellow]")

    if "naabu" in tiers:
        console.print("[dim]  Tier 2: Running naabu SYN scan...[/dim]")
        import subprocess
        try:
            result = subprocess.run(
                ["naabu", "-host", target, "-silent", "-json"],
                capture_output=True, text=True, timeout=300,
            )
            naabu_ports = []
            for line in result.stdout.strip().splitlines():
                try:
                    data = json.loads(line.strip())
                    port = data.get("port", 0)
                    if port and port not in [r["port"] for r in results]:
                        naabu_ports.append(port)
                        results.append({"port": port, "protocol": "tcp", "source": "naabu", "state": "open"})
                except (json.JSONDecodeError, ValueError):
                    continue
            console.print(f"  naabu: [green]{len(naabu_ports)}[/green] new ports")
        except FileNotFoundError:
            console.print("  naabu: [yellow]not installed[/yellow]")
        except subprocess.TimeoutExpired:
            console.print("  naabu: [yellow]timed out[/yellow]")

    if "nmap" in tiers and results:
        port_list = ",".join(str(r["port"]) for r in results)
        console.print(f"[dim]  Tier 3: Running nmap -sV on {len(results)} ports...[/dim]")
        import subprocess, tempfile
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name
        try:
            subprocess.run(
                ["nmap", "-sV", "-sC", "-p", port_list, "-oX", xml_path, target],
                capture_output=True, text=True, timeout=600,
            )
            worker = PortScanWorker.__new__(PortScanWorker)
            nmap_results = worker._parse_nmap_xml(xml_path)
            for nr in nmap_results:
                for r in results:
                    if r["port"] == nr["port"]:
                        r.update({k: v for k, v in nr.items() if v is not None})
            console.print(f"  nmap: [green]{len(nmap_results)}[/green] ports fingerprinted")
        except FileNotFoundError:
            console.print("  nmap: [yellow]not installed[/yellow]")
        except subprocess.TimeoutExpired:
            console.print("  nmap: [yellow]timed out[/yellow]")
        finally:
            Path(xml_path).unlink(missing_ok=True)

    # Display results
    if results:
        table = Table(title=f"Port Scan Results: {target}")
        table.add_column("Port", style="bold")
        table.add_column("Protocol")
        table.add_column("Service")
        table.add_column("Version")
        table.add_column("Source")
        for r in sorted(results, key=lambda x: x["port"]):
            table.add_row(
                str(r["port"]), r.get("protocol", "tcp"),
                r.get("service", ""), r.get("version", ""),
                r.get("source", ""),
            )
        console.print(table)
    else:
        console.print("[yellow]No open ports found.[/yellow]")

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[green]Wrote to {output}[/green]")


@recon.command("bbot")
@click.argument("domain")
@click.option("--preset", "-P", default="subdomain-enum",
              type=click.Choice(["subdomain-enum", "web-basic", "web-thorough", "spider", "kitchen-sink"]),
              help="BBOT scan preset")
@click.option("--passive", is_flag=True, help="Passive-only mode")
@click.option("--output", "-o", default=None, help="Output file")
@click.option("--program", "-p", default=None, help="Associate with program (stores in DB)")
def recon_bbot(domain, preset, passive, output, program):
    """Run BBOT scan for comprehensive recon.

    Presets: subdomain-enum, web-basic, web-thorough, spider, kitchen-sink
    """
    try:
        from bbot.scanner import Scanner
    except ImportError:
        console.print("[red]BBOT not installed. Run: pipx install bbot[/red]")
        return

    console.print(f"[dim]Running BBOT ({preset}) for {domain}...[/dim]")

    presets = [preset]
    subdomains = set()
    ips = set()
    open_ports = []
    findings = []

    try:
        scan = Scanner(domain, presets=presets)
        for event in scan.start():
            t = event.type
            d = str(event.data) if not isinstance(event.data, str) else event.data

            if t == "DNS_NAME":
                subdomains.add(d)
            elif t == "IP_ADDRESS":
                ips.add(d)
            elif t == "OPEN_TCP_PORT":
                open_ports.append(d)
            elif t in ("VULNERABILITY", "FINDING"):
                findings.append({"type": t, "data": d})
    except Exception as e:
        console.print(f"[red]BBOT scan failed: {e}[/red]")
        return

    console.print(f"  Subdomains: [green]{len(subdomains)}[/green]")
    console.print(f"  IPs: [green]{len(ips)}[/green]")
    console.print(f"  Open ports: [green]{len(open_ports)}[/green]")
    console.print(f"  Findings: [green]{len(findings)}[/green]")

    if subdomains:
        for sub in sorted(subdomains)[:50]:
            click.echo(sub)
        if len(subdomains) > 50:
            console.print(f"  [dim]... and {len(subdomains) - 50} more[/dim]")

    if program:
        storage = Storage()
        prog = storage.get_program(program)
        if prog:
            for sub in subdomains:
                storage.upsert_subdomain(prog["id"], sub, source="bbot")
            console.print(f"[green]Stored {len(subdomains)} subdomains for '{program}'[/green]")

    if output:
        data = {
            "subdomains": sorted(subdomains),
            "ips": sorted(ips),
            "open_ports": open_ports,
            "findings": findings,
        }
        with open(output, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[green]Wrote to {output}[/green]")


@recon.command("certs")
@click.argument("target")
@click.option("--domain", "-d", default=None, help="Filter results to this domain only")
@click.option("--ports", "-P", default="443,8443", help="TLS ports to scan (default: 443,8443)")
@click.option("--concurrency", "-c", default=100, help="Concurrent scanners (default: 100)")
@click.option("--output", "-o", default=None, help="Output file")
@click.option("--json-output", "-j", is_flag=True, help="Full cert JSON output")
@click.option("--program", "-p", default=None, help="Associate with program (stores in DB)")
def recon_certs(target, domain, ports, concurrency, output, json_output, program):
    """Scan IPs/CIDRs for TLS certificates to discover hidden domains.

    Uses Caduceus to connect to each IP and extract cert CN/SAN fields.
    Feed it ASN CIDR ranges to find domains that DNS and CT logs miss.

    TARGET can be: CIDR (10.0.0.0/24), IP (1.2.3.4), comma-separated, or a file path.
    """
    from pipeline.stages.cert_discovery import scan_cidrs_for_certs

    # Parse target into list of CIDRs/IPs
    target_path = Path(target)
    if target_path.exists():
        with open(target_path) as f:
            cidrs = [line.strip() for line in f if line.strip()]
    else:
        cidrs = [t.strip() for t in target.split(",") if t.strip()]

    console.print(f"[dim]Scanning {len(cidrs)} targets for TLS certificates (ports: {ports})...[/dim]")

    try:
        certs = scan_cidrs_for_certs(cidrs, ports=ports, concurrency=concurrency)
    except FileNotFoundError:
        console.print("[red]Caduceus not found. Install: go install github.com/g0ldencybersec/Caduceus/cmd/caduceus@latest[/red]")
        return

    if not certs:
        console.print("[yellow]No certificates found.[/yellow]")
        return

    # Extract domains
    all_domains = set()
    for cert in certs:
        for d in cert.get("domains", []):
            d = d.strip().lower().rstrip(".")
            if d and not d.startswith("*"):
                if domain is None or d.endswith(f".{domain}") or d == domain:
                    all_domains.add(d)

    if json_output:
        for cert in certs:
            click.echo(json.dumps(cert))
    else:
        # Summary table
        table = Table(title=f"Certificate Scan Results ({len(certs)} certs)")
        table.add_column("IP:Port", style="bold")
        table.add_column("Common Name")
        table.add_column("SANs")
        table.add_column("Org")

        for cert in certs[:50]:
            table.add_row(
                cert.get("originip", ""),
                cert.get("commonName", ""),
                ", ".join(cert.get("san", [])[:5]),
                ", ".join(cert.get("org", [])),
            )
        console.print(table)

        if len(certs) > 50:
            console.print(f"[dim]... and {len(certs) - 50} more certificates[/dim]")

    console.print(f"\n[bold]{len(all_domains)} unique domains found[/bold]")

    if all_domains and not json_output:
        console.print("\n[dim]Domains:[/dim]")
        for d in sorted(all_domains):
            click.echo(d)

    if program and all_domains:
        storage = Storage()
        prog = storage.get_program(program)
        if prog:
            for d in all_domains:
                storage.upsert_subdomain(prog["id"], d, source="caduceus")
            console.print(f"[green]Stored {len(all_domains)} subdomains for '{program}'[/green]")

    if output:
        with open(output, "w") as f:
            if json_output:
                json.dump(certs, f, indent=2)
            else:
                f.write("\n".join(sorted(all_domains)) + "\n")
        console.print(f"[green]Wrote to {output}[/green]")


# ─── Pipeline Execution ──────────────────────────────────────────

WORKERS = {
    # Scope expansion
    "apex_discovery":    "pipeline.stages.apex_discovery:ApexDiscoveryWorker",
    "passive_dns":       "pipeline.stages.passive_dns:PassiveDNSWorker",
    # Subdomain enumeration
    "subdomain":         "pipeline.stages.subdomain:SubdomainWorker",
    "bbot_discovery":    "pipeline.stages.bbot_discovery:BBOTDiscoveryWorker",
    "asn_discovery":     "pipeline.stages.asn_discovery:ASNDiscoveryWorker",
    "cert_discovery":    "pipeline.stages.cert_discovery:CertDiscoveryWorker",
    # Resolution & scanning
    "dns":               "pipeline.stages.dns_resolve:DNSResolveWorker",
    "portscan":          "pipeline.stages.portscan:PortScanWorker",
    "vhost_discovery":   "pipeline.stages.vhost_discovery:VhostDiscoveryWorker",
    # HTTP
    "httpprobe":         "pipeline.stages.httpprobe:HTTPProbeWorker",
    "httpprobe_direct":  "pipeline.stages.httpprobe:HTTPDirectProbeWorker",
    "content_discovery": "pipeline.stages.content_discovery:ContentDiscoveryWorker",
    "takeover_check":    "pipeline.stages.takeover_check:TakeoverCheckWorker",
    # Analysis
    "shodan_recon":      "pipeline.stages.shodan_recon:ShodanReconWorker",
    "screenshot":        "pipeline.stages.screenshot:ScreenshotWorker",
    "crawler":           "pipeline.stages.crawler:CrawlerWorker",
    "js_analyze":        "pipeline.stages.js_analyze:JSAnalyzeWorker",
    "js_keywords":       "pipeline.stages.js_keyword_extract:JSKeywordWorker",
    "github_dork":       "pipeline.stages.github_dorking:GitHubDorkWorker",
    "nuclei":            "pipeline.stages.nuclei_scan:NucleiScanWorker",
    "cve_correlate":     "pipeline.stages.cve_correlate:CVECorrelateWorker",
    "finding_filter":    "pipeline.stages.finding_filter:FindingFilterWorker",
    "credential_recon":  "pipeline.stages.credential_recon:CredentialReconWorker",
    "default_cred_scan": "pipeline.stages.credential_recon:DefaultCredScanWorker",
    # Output
    "endpoint_csv":        "pipeline.stages.endpoint_csv:EndpointCsvWorker",
    "endpoint_csv_urls":   "pipeline.stages.endpoint_csv:UrlEndpointCsvWorker",
    "gsheets_sync":        "pipeline.stages.gsheets_sync:GSheetsWorker",
    "gsheets_sync_urls":   "pipeline.stages.gsheets_sync:GSheetsUrlWorker",
    # Attack surface & noise reduction
    "asset_graph":         "pipeline.stages.asset_graph:AssetGraphWorker",
    "verb_enum":           "pipeline.stages.verb_enum:VerbEnumWorker",
    "endpoint_rank":       "pipeline.stages.endpoint_rank:EndpointRankWorker",
    "forgotten_endpoints": "pipeline.stages.forgotten_endpoints:ForgottenEndpointWorker",
}


def _load_worker(name: str):
    """Dynamically load a worker class."""
    module_path, class_name = WORKERS[name].rsplit(":", 1)
    import importlib
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


@cli.group()
def run():
    """Run pipeline stages."""
    pass


@run.command("stage")
@click.argument("name", type=click.Choice(list(WORKERS.keys())))
def run_stage(name):
    """Run a single pipeline stage worker continuously."""
    console.print(f"[green]Starting {name} worker...[/green]")
    worker_cls = _load_worker(name)
    worker = worker_cls()
    worker.run()


@run.command("all")
@click.option("--interval", "-i", default=86400, help="Re-scan interval in seconds (default: 24h)")
@click.option("--program", "-p", default=None, help="Only run recon on this program (e.g. visma, nrk)")
def run_all(interval, program):
    """Run all pipeline stages + scheduler concurrently. Ctrl+C to stop."""
    import fcntl

    # Prevent multiple instances from running simultaneously — stacked pipelines
    # contend on the global rate-limit mutex and produce duplicate stream messages.
    lockfile_path = Path("/tmp/bbtrs.lock")
    lockfile = open(lockfile_path, "w")
    try:
        fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        console.print("[red]Pipeline is already running. Only one instance allowed.[/red]")
        console.print("[dim]If it crashed, remove /tmp/bbtrs.lock and retry.[/dim]")
        raise SystemExit(1)

    # ── Orphan cleanup from any previous crashed run ──────────────────────────
    try:
        from pipeline.core.ratelimit import kill_orphans_from_previous_run
        orphans = kill_orphans_from_previous_run()
        if orphans:
            console.print(f"[dim]Cleaned up {orphans} orphaned subprocess(es) from previous run.[/dim]")
    except Exception:
        pass

    console.print("[bold green]Starting BugBountyTRS continuous pipeline...[/bold green]")
    console.print(f"Workers: {', '.join(WORKERS.keys())}")
    console.print(f"Re-scan interval: {interval}s")
    if program:
        console.print(f"[yellow]Program filter: {program}[/yellow]")
    console.print("[dim]Press Ctrl+C to stop all workers[/dim]\n")

    threads = []
    workers = []
    stop_event = threading.Event()

    # Start the scheduler first (feeds targets periodically)
    from pipeline.stages.scheduler import Scheduler
    scheduler = Scheduler(interval=interval, program_filter=program)
    sched_thread = threading.Thread(target=scheduler.run, name="scheduler", daemon=True)
    threads.append(sched_thread)
    sched_thread.start()
    console.print("  [green]Started:[/green] scheduler")

    # Start all stage workers
    for name in WORKERS:
        try:
            worker_cls = _load_worker(name)
            worker = worker_cls()
            workers.append(worker)

            t = threading.Thread(target=worker.run, name=name, daemon=True)
            threads.append(t)
            t.start()
            console.print(f"  [green]Started:[/green] {name}")
        except Exception as e:
            console.print(f"  [red]Failed:[/red] {name}: {e}")

    console.print(f"\n[bold green]Pipeline running with {len(workers)} workers + scheduler[/bold green]")

    def _shutdown(sig, frame):
        console.print("\n[yellow]Shutting down workers...[/yellow]")

        # 1. Signal the rate limiter to abort all mutex wait loops immediately.
        #    This unblocks any worker stuck waiting for active_scan_slot.
        try:
            from pipeline.core.ratelimit import _shutdown_event as rl_shutdown
            rl_shutdown.set()
        except Exception:
            pass

        # 2. Kill all active child subprocesses (nmap, naabu, nuclei, httpx, etc.)
        #    and clear the PID file so they don't show up as orphans on next start.
        try:
            from pipeline.core.ratelimit import kill_child_procs
            killed = kill_child_procs()
            if killed:
                console.print(f"[dim]Killed {killed} active subprocess(es).[/dim]")
        except Exception:
            pass

        # 3. Delete the mutex NOW so any worker currently holding it releases fast
        #    and any worker about to acquire it won't wait.
        try:
            from pipeline.core.ratelimit import _get_redis
            _get_redis().delete("roe:active_scan_mutex")
        except Exception:
            pass

        # 4. Stop all workers and scheduler.
        scheduler.stop()
        for w in workers:
            w.stop()
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Keep main thread alive until stopped
    while not stop_event.is_set():
        stop_event.wait(timeout=1)

    # Join all threads against a single shared deadline (not 10s per thread).
    # With ~34 daemon threads this avoids a 340-second sequential wait.
    join_deadline = time.time() + 20
    for t in threads:
        remaining = max(0.0, join_deadline - time.time())
        t.join(timeout=remaining)

    try:
        fcntl.flock(lockfile, fcntl.LOCK_UN)
        lockfile.close()
        lockfile_path.unlink(missing_ok=True)
    except Exception:
        pass

    console.print("[green]All workers stopped.[/green]")


@run.command("monitor")
@click.option("--interval", "-i", default=3600, help="Poll interval in seconds (default: 1h)")
@click.option("--api-token", envvar="INTIGRITI_TOKEN", default=None)
@click.option("--feed", is_flag=True, default=True, help="Auto-feed new domains into pipeline (default: on)")
def run_monitor(interval, api_token, feed):
    """Poll Intigriti for scope changes and feed new domains into the pipeline.

    Runs continuously, checking program-activities every INTERVAL seconds.
    New in-scope domains are automatically pushed to the scope_targets stream.
    """
    from pipeline.stages.scope import ScopeManager
    from pipeline.stages.platforms import IntigritiSync

    console.print(f"[bold green]Starting scope monitor (interval: {interval}s)...[/bold green]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    mgr = ScopeManager()
    stop_event = threading.Event()

    def _shutdown(sig, frame):
        console.print("\n[yellow]Stopping monitor...[/yellow]")
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    while not stop_event.is_set():
        try:
            inti = IntigritiSync(mgr, api_token)
            activities = inti.poll_program_activities()
            new_domains = inti.extract_new_domains_from_activities(activities)

            if new_domains:
                console.print(f"[green]{len(new_domains)} new scope domains detected[/green]")
                if feed:
                    cfg = get_config()
                    mq = MessageQueue("group:monitor", "monitor")
                    stream = cfg["streams"]["scope_targets"]
                    for d in new_domains:
                        mq.publish(stream, {
                            "domain": d["domain"],
                            "program": str(d["program_id"]),
                            "source": "intigriti_monitor",
                        })
                    console.print(f"[dim]Fed {len(new_domains)} domains into pipeline[/dim]")
            else:
                console.print(f"[dim]{time.strftime('%H:%M:%S')} — No scope changes[/dim]")
        except Exception as e:
            console.print(f"[red]Monitor error: {e}[/red]")

        stop_event.wait(timeout=interval)

    console.print("[green]Monitor stopped.[/green]")


# ─── New recon commands ───────────────────────────────────────────

@recon.command("content-discovery")
@click.argument("url")
@click.option("--program", "-p", default=None, help="Program name")
@click.option("--wordlist", "-w", default=None, help="Override wordlist path")
def recon_content_discovery(url, program, wordlist):
    """Recursive directory bruteforcing with feroxbuster."""
    import subprocess, tempfile, json as _json
    from pathlib import Path as _Path

    cfg = get_config().get("content_discovery", {})
    wl = wordlist or next(
        (w for w in cfg.get("wordlists", []) if _Path(w).exists()), None
    )
    if not wl:
        console.print("[red]No wordlist found. Set content_discovery.wordlists in config.[/red]")
        return

    roe = get_config().get("intigriti", {})
    rate = cfg.get("rate_limit", 20)
    threads = cfg.get("threads", 10)
    depth = cfg.get("scan_limit", 3)

    console.print(f"[dim]Running feroxbuster on {url} (rate={rate}/s, depth={depth})...[/dim]")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out = tmp.name

    cmd = [
        "feroxbuster", "--url", url, "--wordlist", wl,
        "--threads", str(threads), "--rate-limit", str(rate),
        "--scan-limit", str(depth), "--output", out, "--json",
        "-A", "-g", "--silent", "--no-state",
    ]
    if roe.get("request_header"):
        k, _, v = roe["request_header"].partition(": ")
        cmd.extend(["-H", f"{k}: {v}"])

    try:
        subprocess.run(cmd, timeout=1800)
        count = 0
        if _Path(out).exists():
            with open(out) as f:
                for line in f:
                    try:
                        obj = _json.loads(line)
                        if obj.get("type") == "response" and obj.get("status", 0) not in (404, 400):
                            click.echo(f"[{obj.get('status')}] {obj.get('url')}")
                            count += 1
                    except Exception:
                        pass
            _Path(out).unlink(missing_ok=True)
        console.print(f"\n[dim]{count} paths found[/dim]")
    except FileNotFoundError:
        console.print("[red]feroxbuster not installed.[/red]")


@recon.command("vhost")
@click.argument("ip")
@click.argument("apex")
@click.option("--port", default=443, help="Target port (default 443)")
@click.option("--wordlist", "-w", default=None, help="Override wordlist")
@click.option("--program", "-p", default=None)
def recon_vhost(ip, apex, port, wordlist, program):
    """Discover virtual hosts via Host header fuzzing."""
    import subprocess, tempfile, json as _json
    from pathlib import Path as _Path

    cfg = get_config().get("vhost_discovery", {})
    wl = wordlist or cfg.get("wordlist",
        "/usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt"
    )
    if not _Path(wl).exists():
        console.print(f"[red]Wordlist not found: {wl}[/red]")
        return

    scheme = "https" if int(port) in (443, 8443, 4443) else "http"
    target = f"{scheme}://{ip}:{port}"
    rate = cfg.get("rate_limit", 20)
    roe = get_config().get("intigriti", {})

    console.print(f"[dim]ffuf vhost fuzzing: {target} — Host: FUZZ.{apex}[/dim]")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out = tmp.name

    cmd = [
        "ffuf", "-u", target, "-H", f"Host: FUZZ.{apex}",
        "-w", wl, "-o", out, "-of", "json",
        "-rate", str(rate), "-fc", "404,400", "-t", "10", "-s",
    ]
    if roe.get("user_agent"):
        cmd.extend(["-H", f"User-Agent: {roe['user_agent']}"])

    try:
        subprocess.run(cmd, timeout=600)
        count = 0
        if _Path(out).exists():
            with open(out) as f:
                try:
                    data = _json.load(f)
                    for r in data.get("results", []):
                        vhost = f"{r['input']['FUZZ']}.{apex}"
                        click.echo(vhost)
                        count += 1
                except Exception:
                    pass
            _Path(out).unlink(missing_ok=True)
        console.print(f"\n[dim]{count} virtual hosts found[/dim]")
    except FileNotFoundError:
        console.print("[red]ffuf not installed.[/red]")


@recon.command("takeover")
@click.argument("program_name")
def recon_takeover(program_name):
    """Check all subdomains for takeover vulnerabilities (subzy + nuclei)."""
    import subprocess, tempfile
    from pathlib import Path as _Path

    storage = Storage()
    prog = storage.get_program(program_name)
    if not prog:
        console.print(f"[red]Program '{program_name}' not found.[/red]")
        return

    subs = storage.get_subdomains(prog["id"])
    if not subs:
        console.print("[yellow]No subdomains found for this program.[/yellow]")
        return

    console.print(f"[dim]Checking {len(subs)} subdomains for takeover candidates...[/dim]")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(s["domain"] for s in subs))
        hosts_file = tmp.name

    try:
        result = subprocess.run(
            ["subzy", "run", "--hosts", hosts_file, "--hide_fails"],
            capture_output=True, text=True, timeout=300,
        )
        found = [l for l in result.stdout.splitlines() if "VULNERABLE" in l.upper()]
        for line in found:
            console.print(f"[red bold]{line}[/red bold]")
        if not found:
            console.print("[green]No takeover candidates found.[/green]")
        else:
            console.print(f"\n[red]{len(found)} takeover candidates found![/red]")
    except FileNotFoundError:
        console.print("[yellow]subzy not installed. Run: go install github.com/PentestPad/subzy@latest[/yellow]")
    finally:
        _Path(hosts_file).unlink(missing_ok=True)


# ─── Pipeline Control ────────────────────────────────────────────

@cli.command("feed")
def feed_targets():
    """Feed all scope targets into the pipeline (trigger a scan cycle)."""
    from pipeline.stages.scope import ScopeManager
    mgr = ScopeManager()
    mgr.load_programs()
    mgr.feed_targets()
    console.print("[green]Targets fed into pipeline.[/green]")


# ─── Status & Monitoring ─────────────────────────────────────────

@cli.command("status")
def status():
    """Show pipeline status and statistics."""
    storage = Storage()
    stats = storage.stats()

    table = Table(title="Pipeline Statistics")
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("Programs", str(stats["programs"]))
    table.add_row("Subdomains", str(stats["subdomains"]))
    table.add_row("Open Ports", str(stats["ports"]))
    table.add_row("HTTP Services", str(stats["http_services"]))
    table.add_row("URLs Discovered", str(stats["urls"]))
    table.add_row("JS Files Analyzed", str(stats["js_files"]))
    table.add_row("Findings", str(stats["findings"]))
    console.print(table)

    if stats["findings_by_severity"]:
        sev_table = Table(title="Findings by Severity")
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")
        sev_colors = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "blue", "info": "dim"}
        for sev, count in sorted(stats["findings_by_severity"].items()):
            color = sev_colors.get(sev, "white")
            sev_table.add_row(f"[{color}]{sev}[/{color}]", str(count))
        console.print(sev_table)

    # Stream stats
    try:
        mq = MessageQueue("group:status", "status-check")
        stream_table = Table(title="Stream Status")
        stream_table.add_column("Stream")
        stream_table.add_column("Messages", justify="right")

        streams_cfg = get_config()["streams"]
        for key, stream in streams_cfg.items():
            length = mq.stream_length(stream)
            stream_table.add_row(stream, str(length))
        console.print(stream_table)
    except Exception:
        console.print("[dim]Redis not available - stream stats unavailable[/dim]")


# ─── Data Export (for Claude Code analysis) ──────────────────────

@cli.command("export-endpoints")
@click.argument("program_name")
@click.option("--output", "-o", default=None, help="Output CSV file path")
def export_endpoints(program_name, output):
    """Export all discovered HTTP endpoints for a program to CSV."""
    from pipeline.stages.endpoint_csv import export_program_endpoints
    from pathlib import Path as _Path

    out_path = _Path(output) if output else None
    result = export_program_endpoints(program_name, out_path)
    if result:
        console.print(f"[green]Exported endpoints to {result}[/green]")
    else:
        console.print(f"[yellow]No endpoints found for '{program_name}'.[/yellow]")


@cli.command("export")
@click.argument("program_name")
@click.option("--output", "-o", default=None, help="Output file path")
def export_data(program_name, output):
    """Export all data for a program as JSON for Claude Code analysis."""
    storage = Storage()

    if output:
        data = storage.export_program_data(program_name)
        if not data:
            console.print(f"[red]Program '{program_name}' not found.[/red]")
            return
        with open(output, "w") as f:
            json.dump(data, f, indent=2, default=str)
        console.print(f"[green]Exported to {output}[/green]")
    else:
        path = storage.export_program_json(program_name)
        if path:
            console.print(f"[green]Exported to {path}[/green]")
        else:
            console.print(f"[red]Program '{program_name}' not found.[/red]")


@cli.command("export-all")
def export_all():
    """Export all program data for Claude Code analysis."""
    storage = Storage()
    programs = storage.list_programs()
    for p in programs:
        path = storage.export_program_json(p["name"])
        if path:
            console.print(f"[green]Exported {p['name']} -> {path}[/green]")


# ─── Findings ────────────────────────────────────────────────────

@cli.command("findings")
@click.option("--program", "-p", default=None, help="Filter by program name")
@click.option("--severity", "-s", default=None, help="Filter by severity")
@click.option("--status", default=None, help="Filter by status (new, reviewed, reported)")
@click.option("--tool", "-t", default=None, help="Filter by tool (e.g. nuclei, endpoint_rank, takeover_check)")
@click.option("--limit", "-n", default=50, help="Max results")
def list_findings(program, severity, status, tool, limit):
    """List vulnerability findings."""
    storage = Storage()

    program_id = None
    if program:
        p = storage.get_program(program)
        if p:
            program_id = p["id"]
        else:
            console.print(f"[red]Program '{program}' not found.[/red]")
            return

    findings = storage.get_findings(program_id=program_id, severity=severity, status=status)
    if tool:
        findings = [f for f in findings if f.get("tool") == tool]

    if not findings:
        console.print("[yellow]No findings.[/yellow]")
        return

    table = Table(title=f"Findings ({len(findings)} total, FPs hidden)")
    table.add_column("ID", style="dim")
    table.add_column("Severity")
    table.add_column("CVSS", justify="right")
    table.add_column("CVE")
    table.add_column("Tool")
    table.add_column("Title", max_width=45)
    table.add_column("URL", max_width=50)
    table.add_column("Status")

    sev_colors = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "blue", "info": "dim"}

    for f in findings[:limit]:
        sev = f.get("severity", "unknown")
        color = sev_colors.get(sev, "white")
        cvss = f"{f['cvss_score']:.1f}" if f.get("cvss_score") else "-"
        cve = f.get("cve_id") or "-"
        # Also show linked CVEs
        if not f.get("cve_id") and f.get("cves"):
            cve = f["cves"][0]["id"]
        table.add_row(
            str(f["id"]),
            f"[{color}]{sev}[/{color}]",
            cvss,
            cve,
            f.get("tool", "?"),
            f.get("title", "?"),
            f.get("url", "?"),
            f.get("status", "new"),
        )

    console.print(table)


@cli.command("finding")
@click.argument("finding_id", type=int)
def show_finding(finding_id):
    """Show detailed info for a specific finding."""
    storage = Storage()
    with storage._conn() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if not row:
        console.print(f"[red]Finding #{finding_id} not found.[/red]")
        return

    f = dict(row)
    cvss_str = f"{f['cvss_score']:.1f}" if f.get("cvss_score") else "N/A"
    panel_text = f"""[bold]Title:[/bold] {f.get('title', '?')}
[bold]Severity:[/bold] {f.get('severity', '?')}
[bold]CVE:[/bold] {f.get('cve_id', 'N/A')}
[bold]CVSS:[/bold] {cvss_str}
[bold]Tool:[/bold] {f.get('tool', '?')}
[bold]Template:[/bold] {f.get('template_id', '?')}
[bold]URL:[/bold] {f.get('url', '?')}
[bold]Matched At:[/bold] {f.get('matched_at', '?')}
[bold]Status:[/bold] {f.get('status', 'new')}
[bold]False Positive:[/bold] {'Yes' if f.get('false_positive') else 'No'}
[bold]Discovered:[/bold] {f.get('discovered_at', '?')}

[bold]Description:[/bold]
{f.get('description', 'N/A')}

[bold]Evidence:[/bold]
{f.get('evidence', 'N/A')}"""

    # Show linked CVEs
    cves = storage.get_finding_cves(finding_id)
    if cves:
        panel_text += "\n\n[bold]Linked CVEs:[/bold]"
        for cve in cves:
            panel_text += f"\n  {cve['id']} (CVSS {cve.get('cvss_score', '?')}, {cve.get('severity', '?')})"
            if cve.get("description"):
                panel_text += f"\n    {cve['description'][:200]}"

    if f.get("raw_json"):
        try:
            raw = json.loads(f["raw_json"])
            panel_text += f"\n\n[bold]Raw Data:[/bold]\n{json.dumps(raw, indent=2)}"
        except json.JSONDecodeError:
            pass

    console.print(Panel(panel_text, title=f"Finding #{finding_id}", border_style="red"))


# ─── False Positive Rules ─────────────────────────────────────────

@cli.group("fp")
def fp_rules():
    """Manage false positive filtering rules."""
    pass


@fp_rules.command("add")
@click.argument("rule_type", type=click.Choice(["template_id", "title", "url_pattern", "severity"]))
@click.argument("pattern")
@click.option("--reason", "-r", default=None, help="Why this is a false positive")
def fp_add(rule_type, pattern, reason):
    """Add a false positive rule. Matching findings will be auto-filtered."""
    storage = Storage()
    rule_id = storage.add_fp_rule(rule_type, pattern, reason)
    console.print(f"[green]Added FP rule #{rule_id}: {rule_type} = '{pattern}'[/green]")


@fp_rules.command("list")
def fp_list():
    """List all false positive rules."""
    storage = Storage()
    rules = storage.get_fp_rules()
    if not rules:
        console.print("[yellow]No FP rules configured.[/yellow]")
        return
    table = Table(title="False Positive Rules")
    table.add_column("ID", style="dim")
    table.add_column("Type")
    table.add_column("Pattern")
    table.add_column("Reason")
    for r in rules:
        table.add_row(str(r["id"]), r["rule_type"], r["pattern"], r.get("reason", "-"))
    console.print(table)


@fp_rules.command("remove")
@click.argument("rule_id", type=int)
def fp_remove(rule_id):
    """Remove a false positive rule."""
    storage = Storage()
    storage.delete_fp_rule(rule_id)
    console.print(f"[yellow]Removed FP rule #{rule_id}[/yellow]")


@cli.command("mark-fp")
@click.argument("finding_id", type=int)
def mark_false_positive(finding_id):
    """Mark a finding as false positive."""
    storage = Storage()
    storage.update_finding(finding_id, false_positive=1, status="dismissed")
    console.print(f"[yellow]Finding #{finding_id} marked as false positive[/yellow]")


@cli.command("mark-reviewed")
@click.argument("finding_id", type=int)
def mark_reviewed(finding_id):
    """Mark a finding as reviewed."""
    storage = Storage()
    storage.update_finding(finding_id, status="reviewed")
    console.print(f"[green]Finding #{finding_id} marked as reviewed[/green]")


@cli.command("mark-reported")
@click.argument("finding_id", type=int)
def mark_reported(finding_id):
    """Mark a finding as reported to the program."""
    storage = Storage()
    storage.update_finding(finding_id, status="reported")
    console.print(f"[green]Finding #{finding_id} marked as reported[/green]")


# ─── Maintenance ──────────────────────────────────────────────────

@cli.command("flush")
@click.option("--streams", is_flag=True, help="Flush all Redis streams")
@click.option("--dedup", is_flag=True, help="Flush dedup cache")
@click.confirmation_option(prompt="Are you sure?")
def flush(streams, dedup):
    """Flush pipeline data (streams and/or dedup cache)."""
    mq = MessageQueue("group:flush", "flush")

    if streams:
        streams_cfg = get_config()["streams"]
        for key, stream in streams_cfg.items():
            mq.flush_stream(stream)
            console.print(f"[yellow]Flushed stream: {stream}[/yellow]")

    if dedup:
        import redis as r
        client = r.Redis(host=get_config()["redis"]["host"], port=get_config()["redis"]["port"])
        cursor = 0
        deleted = 0
        while True:
            cursor, keys = client.scan(cursor, match="dedup:*", count=100)
            if keys:
                client.delete(*keys)
                deleted += len(keys)
            if cursor == 0:
                break
        console.print(f"[yellow]Flushed {deleted} dedup keys[/yellow]")


if __name__ == "__main__":
    cli()

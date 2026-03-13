#!/usr/bin/env python3
"""BugBountyTRS CLI - Continuous Bug Bounty Recon Pipeline.

Usage:
    python3 cli.py scope add <name> --wildcard "*.example.com"
    python3 cli.py scope sync-h1 <handle>
    python3 cli.py scope sync-intigriti <company>
    python3 cli.py run all
    python3 cli.py run <stage>
    python3 cli.py status
    python3 cli.py export <program>
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
def scope_feed():
    """Push all scope targets into the pipeline for scanning."""
    from pipeline.stages.scope import ScopeManager
    mgr = ScopeManager()
    mgr.load_programs()
    mgr.feed_targets()
    console.print("[green]Targets published to pipeline.[/green]")


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
@click.option("--api-token", envvar="INTIGRITI_TOKEN", default=None)
def scope_sync_intigriti(company, program, api_token):
    """Sync program scope from Intigriti."""
    from pipeline.stages.scope import ScopeManager
    from pipeline.stages.platforms import IntigritiSync
    mgr = ScopeManager()
    inti = IntigritiSync(mgr, api_token)
    inti.sync_program(company, program)
    console.print(f"[green]Synced Intigriti program: {company}[/green]")


# ─── Pipeline Execution ──────────────────────────────────────────

WORKERS = {
    "subdomain": "pipeline.stages.subdomain:SubdomainWorker",
    "dns": "pipeline.stages.dns_resolve:DNSResolveWorker",
    "portscan": "pipeline.stages.portscan:PortScanWorker",
    "httpprobe": "pipeline.stages.httpprobe:HTTPProbeWorker",
    "screenshot": "pipeline.stages.screenshot:ScreenshotWorker",
    "crawler": "pipeline.stages.crawler:CrawlerWorker",
    "js_analyze": "pipeline.stages.js_analyze:JSAnalyzeWorker",
    "nuclei": "pipeline.stages.nuclei_scan:NucleiScanWorker",
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
def run_all(interval):
    """Run all pipeline stages + scheduler concurrently. Ctrl+C to stop."""
    console.print("[bold green]Starting BugBountyTRS continuous pipeline...[/bold green]")
    console.print(f"Workers: {', '.join(WORKERS.keys())}")
    console.print(f"Re-scan interval: {interval}s")
    console.print("[dim]Press Ctrl+C to stop all workers[/dim]\n")

    threads = []
    workers = []
    stop_event = threading.Event()

    # Start the scheduler first (feeds targets periodically)
    from pipeline.stages.scheduler import Scheduler
    scheduler = Scheduler(interval=interval)
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
        scheduler.stop()
        for w in workers:
            w.stop()
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Keep main thread alive until stopped
    while not stop_event.is_set():
        stop_event.wait(timeout=1)

    # Wait for threads to finish
    for t in threads:
        t.join(timeout=10)

    console.print("[green]All workers stopped.[/green]")


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
@click.option("--limit", "-n", default=50, help="Max results")
def list_findings(program, severity, status, limit):
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

    if not findings:
        console.print("[yellow]No findings.[/yellow]")
        return

    table = Table(title=f"Findings ({len(findings)} total)")
    table.add_column("ID", style="dim")
    table.add_column("Severity")
    table.add_column("Tool")
    table.add_column("Title", max_width=50)
    table.add_column("URL", max_width=60)
    table.add_column("Status")
    table.add_column("Date")

    sev_colors = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "blue", "info": "dim"}

    for f in findings[:limit]:
        sev = f.get("severity", "unknown")
        color = sev_colors.get(sev, "white")
        table.add_row(
            str(f["id"]),
            f"[{color}]{sev}[/{color}]",
            f.get("tool", "?"),
            f.get("title", "?"),
            f.get("url", "?"),
            f.get("status", "new"),
            f.get("discovered_at", "?"),
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
    panel_text = f"""[bold]Title:[/bold] {f.get('title', '?')}
[bold]Severity:[/bold] {f.get('severity', '?')}
[bold]Tool:[/bold] {f.get('tool', '?')}
[bold]Template:[/bold] {f.get('template_id', '?')}
[bold]URL:[/bold] {f.get('url', '?')}
[bold]Matched At:[/bold] {f.get('matched_at', '?')}
[bold]Status:[/bold] {f.get('status', 'new')}
[bold]Discovered:[/bold] {f.get('discovered_at', '?')}

[bold]Description:[/bold]
{f.get('description', 'N/A')}

[bold]Evidence:[/bold]
{f.get('evidence', 'N/A')}"""

    if f.get("raw_json"):
        try:
            raw = json.loads(f["raw_json"])
            panel_text += f"\n\n[bold]Raw Data:[/bold]\n{json.dumps(raw, indent=2)}"
        except json.JSONDecodeError:
            pass

    console.print(Panel(panel_text, title=f"Finding #{finding_id}", border_style="red"))


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

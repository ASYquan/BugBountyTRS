"""HTTP probing stage.

Two workers:

  HTTPProbeWorker      — consumes recon_ports (non-standard ports from portscan)
  HTTPDirectProbeWorker — consumes recon_resolved (probes ALL standard HTTP ports
                          for every resolved subdomain, regardless of portscan output)

The direct probe worker is the primary source of CSV data. Without it, any
subdomain on a CDN (Cloudflare, Akamai, etc.) is skipped by naabu --exclude-cdn
and never reaches httpprobe, resulting in an empty CSV.

Flow:
  recon_resolved → HTTPDirectProbeWorker → recon_http → endpoint_csv
  recon_ports    → HTTPProbeWorker       → recon_http → endpoint_csv  (non-standard ports)
"""

import subprocess
import json
import logging

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.ratelimit import active_scan_slot, tracked_run

log = logging.getLogger(__name__)

# Standard HTTP ports always probed by the direct worker
_STANDARD_HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000, 9090, 8888, 4443]

# Ports that are only valid for portscan-triggered probing
_HTTP_PORTS_SET = set(_STANDARD_HTTP_PORTS)
_HTTP_SERVICES = {"http", "https", "http-alt", "http-proxy", "https-alt"}


def _build_targets(domain: str, port: int, service: str = "") -> list[str]:
    """Build httpx target URL(s) for a domain+port, omitting default port numbers."""
    if port == 443 or service == "https" or port in {8443, 4443}:
        # Omit :443 from HTTPS — httpx normalises it anyway
        url = f"https://{domain}" if port == 443 else f"https://{domain}:{port}"
        return [url]
    elif port == 80:
        return [f"http://{domain}"]
    else:
        # Non-standard port: try both schemes
        return [f"http://{domain}:{port}", f"https://{domain}:{port}"]


class HTTPProbeWorker(BaseWorker):
    """Probes non-standard ports discovered by portscan."""

    name = "httpprobe"
    input_stream = "recon_ports"
    output_streams = ["recon_http"]

    def dedup_key(self, data: dict) -> str:
        return f"httpprobe:{data.get('domain', '')}:{data.get('port', 80)}"

    def process(self, data: dict) -> list[dict]:
        domain = data.get("domain")
        ip = data.get("ip")
        port = data.get("port")
        program = data.get("program")
        program_id = data.get("program_id")
        subdomain_id = data.get("subdomain_id")
        service = data.get("service", "")

        if not domain or not port:
            return []

        if port not in _HTTP_PORTS_SET and service not in _HTTP_SERVICES:
            return []

        targets = _build_targets(domain, port, service)
        return _probe_targets(self, targets, domain, ip, port, program, program_id, subdomain_id)


class HTTPDirectProbeWorker(BaseWorker):
    """Probes all standard HTTP ports for every resolved subdomain.

    This is the primary worker that ensures every resolved subdomain appears
    in the CSV, regardless of whether portscan found open ports. CDN-hosted
    subdomains are excluded by naabu --exclude-cdn and would otherwise never
    reach httpprobe.
    """

    name = "httpprobe_direct"
    input_stream = "recon_resolved"
    output_streams = ["recon_http"]

    def dedup_key(self, data: dict) -> str:
        return f"httpprobe_direct:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        domain = data.get("domain")
        ip = data.get("ip")
        program = data.get("program")
        program_id = data.get("program_id")
        subdomain_id = data.get("subdomain_id")

        if not domain:
            return []

        cfg = get_config()
        ports_str = cfg.get("tools", {}).get("httpx", {}).get(
            "ports", "80,443,8080,8443,8000,3000,5000,9090"
        )
        ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]

        # Run httpx once against all ports — faster than one call per port
        results = _probe_multi_port(self, domain, ip, ports, program, program_id, subdomain_id)
        log.info(f"[httpprobe_direct] {domain} → {len(results)} live service(s)")
        return results



# ── Shared helpers ────────────────────────────────────────────────────────────

def _run_httpx_cmd(targets: list[str], extra_flags: list[str] = None) -> list[dict]:
    """Run httpx against a list of targets. Returns parsed result dicts."""
    cfg = get_config()
    httpx_cfg = cfg.get("tools", {}).get("httpx", {})
    inti_cfg = cfg.get("intigriti", {})
    timeout = httpx_cfg.get("timeout", 10)
    rate_limit = httpx_cfg.get("rate_limit", 20)

    cmd = [
        "httpx",
        "-silent", "-json",
        "-follow-redirects",
        "-tech-detect",
        "-status-code",
        "-title",
        "-web-server",
        "-content-length",
        "-ip",
        "-timeout", str(timeout),
        "-rl", str(rate_limit),
    ]
    if extra_flags:
        cmd.extend(extra_flags)

    ua = inti_cfg.get("user_agent")
    if ua:
        cmd.extend(["-H", f"User-Agent: {ua}"])
    req_header = inti_cfg.get("request_header")
    if req_header:
        cmd.extend(["-H", req_header])

    # Feed targets via stdin for efficiency
    stdin_data = "\n".join(targets)
    try:
        result = tracked_run(
            cmd, input=stdin_data, capture_output=True, text=True,
            timeout=60 + len(targets) * 5,
        )
    except FileNotFoundError:
        log.warning("httpx not found")
        return []
    except subprocess.TimeoutExpired:
        log.warning(f"httpx timed out ({len(targets)} targets)")
        return []

    parsed = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            parsed.append({
                "url": data.get("url", ""),
                "status_code": data.get("status_code") or data.get("status-code"),
                "title": data.get("title"),
                "tech": data.get("tech") or data.get("technologies") or [],
                "webserver": data.get("webserver") or data.get("web-server"),
                "content_length": data.get("content_length") or data.get("content-length"),
                "final_url": data.get("final_url"),
                "headers": data.get("header", {}),
                "ip": data.get("host") or data.get("ip"),
            })
        except json.JSONDecodeError:
            continue
    return parsed


def _probe_targets(worker, targets: list[str], domain: str, ip: str, port: int,
                   program, program_id, subdomain_id) -> list[dict]:
    """Run httpx on explicit URL targets and return stream messages."""
    results = []
    with active_scan_slot(f"httpx:{domain}"):
        probes = _run_httpx_cmd(targets)

    for probe in probes:
        url = probe.get("url")
        if not url:
            continue
        if subdomain_id is not None:
            try:
                worker.storage.upsert_http_service(
                    subdomain_id=subdomain_id,
                    url=url,
                    status_code=probe.get("status_code"),
                    title=probe.get("title"),
                    tech=probe.get("tech", []),
                    headers=probe.get("headers", {}),
                    content_length=probe.get("content_length"),
                    webserver=probe.get("webserver"),
                    redirect_url=probe.get("final_url"),
                )
            except Exception as e:
                log.debug(f"[httpprobe] DB write skipped for {url}: {e}")
        results.append({
            "program": program,
            "program_id": program_id,
            "subdomain_id": subdomain_id,
            "domain": domain,
            "ip": ip or probe.get("ip"),
            "port": port,
            "url": url,
            "status_code": probe.get("status_code"),
            "title": probe.get("title"),
            "tech": probe.get("tech", []),
            "webserver": probe.get("webserver"),
            "content_length": probe.get("content_length"),
            "source": "httpx",
        })
    return results


def _probe_multi_port(worker, domain: str, ip: str, ports: list[int],
                      program, program_id, subdomain_id) -> list[dict]:
    """Run httpx against a domain on multiple ports in a single call."""
    ports_str = ",".join(str(p) for p in ports)
    with active_scan_slot(f"httpx:{domain}"):
        probes = _run_httpx_cmd(
            [domain],
            extra_flags=["-ports", ports_str],
        )

    results = []
    for probe in probes:
        url = probe.get("url")
        if not url:
            continue
        if subdomain_id is not None:
            try:
                worker.storage.upsert_http_service(
                    subdomain_id=subdomain_id,
                    url=url,
                    status_code=probe.get("status_code"),
                    title=probe.get("title"),
                    tech=probe.get("tech", []),
                    headers=probe.get("headers", {}),
                    content_length=probe.get("content_length"),
                    webserver=probe.get("webserver"),
                    redirect_url=probe.get("final_url"),
                )
            except Exception as e:
                log.debug(f"[httpprobe] DB write skipped for {url}: {e}")
        results.append({
            "program": program,
            "program_id": program_id,
            "subdomain_id": subdomain_id,
            "domain": domain,
            "ip": ip or probe.get("ip"),
            "url": url,
            "status_code": probe.get("status_code"),
            "title": probe.get("title"),
            "tech": probe.get("tech", []),
            "webserver": probe.get("webserver"),
            "content_length": probe.get("content_length"),
            "source": "httpx",
        })
    return results

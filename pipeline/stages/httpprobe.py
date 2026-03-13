"""HTTP probing stage.

Consumes open ports from recon_ports stream.
Runs httpx to identify live HTTP services, detect technologies,
and capture response metadata.
"""

import subprocess
import json
import logging

from ..core.worker import BaseWorker
from ..core.config import get_config

log = logging.getLogger(__name__)


class HTTPProbeWorker(BaseWorker):
    name = "httpprobe"
    input_stream = "recon_ports"
    output_streams = ["recon_http"]

    def dedup_key(self, data: dict) -> str:
        port = data.get("port", 80)
        return f"httpprobe:{data.get('domain', '')}:{port}"

    def process(self, data: dict) -> list[dict]:
        domain = data.get("domain")
        ip = data.get("ip")
        port = data.get("port")
        program = data.get("program")
        program_id = data.get("program_id")
        subdomain_id = data.get("subdomain_id")
        service = data.get("service", "")

        if not domain:
            return []

        # Only probe HTTP-likely ports
        http_ports = {80, 443, 8080, 8443, 8000, 3000, 5000, 9090, 8888, 4443}
        http_services = {"http", "https", "http-alt", "http-proxy", "https-alt"}

        if port not in http_ports and service not in http_services:
            return []

        targets = []
        if port == 443 or service == "https" or port in {8443, 4443}:
            targets.append(f"https://{domain}:{port}")
        elif port == 80:
            targets.append(f"http://{domain}")
        else:
            targets.append(f"http://{domain}:{port}")
            targets.append(f"https://{domain}:{port}")

        results = []
        for target in targets:
            probe = self._run_httpx(target)
            if probe:
                # Store in DB
                self.storage.upsert_http_service(
                    subdomain_id=subdomain_id,
                    url=probe["url"],
                    status_code=probe.get("status_code"),
                    title=probe.get("title"),
                    tech=probe.get("tech", []),
                    headers=probe.get("headers", {}),
                    content_length=probe.get("content_length"),
                    webserver=probe.get("webserver"),
                    redirect_url=probe.get("final_url"),
                )

                results.append({
                    "program": program,
                    "program_id": program_id,
                    "domain": domain,
                    "ip": ip,
                    "url": probe["url"],
                    "status_code": probe.get("status_code"),
                    "title": probe.get("title"),
                    "tech": probe.get("tech", []),
                    "webserver": probe.get("webserver"),
                    "subdomain_id": subdomain_id,
                    "content_length": probe.get("content_length"),
                })

        return results

    def _run_httpx(self, target: str) -> dict | None:
        cfg = get_config()["tools"].get("httpx", {})
        inti_cfg = get_config().get("intigriti", {})
        timeout = cfg.get("timeout", 10)
        rate_limit = cfg.get("rate_limit", 20)

        cmd = [
            "httpx",
            "-u", target,
            "-silent",
            "-json",
            "-follow-redirects",
            "-tech-detect",
            "-status-code",
            "-title",
            "-web-server",
            "-content-length",
            "-timeout", str(timeout),
            "-rl", str(rate_limit),
        ]

        # Inject Intigriti RoE-required headers
        ua = inti_cfg.get("user_agent")
        if ua:
            cmd.extend(["-H", f"User-Agent: {ua}"])
        req_header = inti_cfg.get("request_header")
        if req_header:
            cmd.extend(["-H", req_header])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=30,
            )

            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    return {
                        "url": data.get("url", target),
                        "status_code": data.get("status_code") or data.get("status-code"),
                        "title": data.get("title"),
                        "tech": data.get("tech") or data.get("technologies") or [],
                        "webserver": data.get("webserver") or data.get("web-server"),
                        "content_length": data.get("content_length") or data.get("content-length"),
                        "final_url": data.get("final_url"),
                        "headers": data.get("header", {}),
                    }
                except json.JSONDecodeError:
                    continue

        except FileNotFoundError:
            log.warning("httpx not found")
        except subprocess.TimeoutExpired:
            log.warning(f"httpx timed out for {target}")

        return None

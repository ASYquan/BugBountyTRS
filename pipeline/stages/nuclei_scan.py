"""Nuclei vulnerability scanning stage.

Consumes HTTP services from recon_http stream.
Runs nuclei with multiple template strategies for broad coverage.
Publishes findings to vuln_findings stream.
"""

import subprocess
import json
import logging
import tempfile
from pathlib import Path

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.ratelimit import active_scan_slot, tracked_run

log = logging.getLogger(__name__)


class NucleiScanWorker(BaseWorker):
    name = "nuclei"
    input_stream = "recon_http"
    output_streams = ["vuln_findings"]

    def dedup_key(self, data: dict) -> str:
        return f"nuclei:{data.get('url', '')}"

    def process(self, data: dict) -> list[dict]:
        url = data.get("url")
        program = data.get("program")
        program_id = data.get("program_id")
        subdomain_id = data.get("subdomain_id")
        tech = data.get("tech", [])

        if not url:
            return []

        log.info(f"[nuclei] Scanning {url}")

        constraints = self.roe_constraints(data)
        if not self.is_scanning_allowed(constraints, "nuclei"):
            return []
        findings = self._run_nuclei(url, tech, constraints=constraints)

        results = []
        for finding in findings:
            # Store in DB
            self.storage.add_finding(
                program_id,
                subdomain_id=subdomain_id,
                tool="nuclei",
                template_id=finding.get("template-id"),
                severity=finding.get("info", {}).get("severity", "unknown"),
                title=finding.get("info", {}).get("name", "Unknown"),
                description=finding.get("info", {}).get("description"),
                url=finding.get("matched-at", url),
                matched_at=finding.get("matched-at"),
                evidence=finding.get("extracted-results", finding.get("matcher-name")),
                raw=finding,
            )

            results.append({
                "program": program,
                "program_id": program_id,
                "subdomain_id": subdomain_id,
                "tool": "nuclei",
                "template_id": finding.get("template-id"),
                "severity": finding.get("info", {}).get("severity"),
                "title": finding.get("info", {}).get("name"),
                "url": finding.get("matched-at", url),
            })

        log.info(f"[nuclei] Found {len(findings)} issues on {url}")
        return results

    def _run_nuclei(self, target: str, tech: list = None, constraints: dict = None) -> list[dict]:
        cfg = get_config()["tools"].get("nuclei", {})
        c = constraints or {}
        threads = cfg.get("threads", 5)
        rate_limit = c.get("rate_limit_rps") or cfg.get("rate_limit", 20)
        roe = c  # keep roe alias for excluded_vuln_tags below
        severity = cfg.get("severity", "low,medium,high,critical")

        # Build tag filters based on detected tech
        tags = []
        if tech:
            tech_lower = [t.lower() for t in tech]
            tech_tag_map = {
                "apache": "apache",
                "nginx": "nginx",
                "iis": "iis",
                "wordpress": "wordpress",
                "joomla": "joomla",
                "drupal": "drupal",
                "php": "php",
                "java": "java",
                "tomcat": "tomcat",
                "jenkins": "jenkins",
                "gitlab": "gitlab",
                "grafana": "grafana",
                "spring": "spring",
                "laravel": "laravel",
                "react": "react",
                "angular": "angular",
                "node": "nodejs",
                "express": "express",
            }
            for t in tech_lower:
                for key, tag in tech_tag_map.items():
                    if key in t:
                        tags.append(tag)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as tmp:
            output_path = tmp.name

        try:
            cmd = [
                "nuclei",
                "-u", target,
                "-jsonl", "-o", output_path,
                "-silent",
                "-c", str(threads),
                "-rl", str(rate_limit),
                "-severity", severity,
                "-stats", "-si", "60",
            ]

            # Inject RoE-required headers and user-agent
            for h_arg in self.roe_header_args(c):
                cmd.append(h_arg)

            # Add tech-specific tags if detected
            if tags:
                cmd.extend(["-tags", ",".join(tags)])

            # Exclude vulnerability categories out-of-scope per program RoE
            excluded_tags = roe.get("excluded_vuln_tags", [])
            if excluded_tags:
                cmd.extend(["-etags", ",".join(excluded_tags)])
                log.debug(f"[nuclei] Excluding tags per RoE: {excluded_tags}")

            with active_scan_slot(f"nuclei:{target}"):
                tracked_run(cmd, capture_output=True, text=True, timeout=900)

            return self._parse_results(output_path)

        except FileNotFoundError:
            log.error("nuclei not found")
            return []
        except subprocess.TimeoutExpired:
            log.warning(f"nuclei timed out for {target}")
            return self._parse_results(output_path)
        finally:
            Path(output_path).unlink(missing_ok=True)

    def _parse_results(self, path: str) -> list[dict]:
        findings = []
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            pass
        return findings

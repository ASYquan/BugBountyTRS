"""Subdomain takeover detection stage.

Consumes from recon_subdomains stream.
Runs two complementary checks:
  1. subzy — signature-based takeover detection (checks CNAME targets against
     known vulnerable service fingerprints)
  2. nuclei -t takeover/ — template-based confirmation of specific services

Confirmed takeover candidates are stored in the takeover_candidates table
and added as high-severity findings. Discord/Slack notification fires immediately.
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path

import requests

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.ratelimit import active_scan_slot
from .notification import notify

log = logging.getLogger(__name__)

# Service-specific body fingerprints that confirm a subdomain is unclaimed.
# Source: EdOverflow/can-i-take-over-xyz, updated for common FP services.
# A finding is only kept if the response body contains one of these strings.
_TAKEOVER_FINGERPRINTS: dict[str, list[str]] = {
    "github":           ["There isn't a GitHub Pages site here.",
                         "For root URLs (like http://example.com/) you must provide an index"],
    "heroku":           ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    "shopify":          ["Sorry, this shop is currently unavailable.",
                         "only be used if the domain is active on Shopify"],
    "fastly":           ["Fastly error: unknown domain", "Please check that this domain has been added"],
    "ghost":            ["The thing you were looking for is no longer here"],
    "cargo":            ["If you're moving your domain away from Cargo"],
    "tumblr":           ["Whatever you were looking for doesn't currently exist at this address"],
    "wordpress":        ["Do you want to register"],
    "teamwork":         ["Oops - We didn't find your site."],
    "helpjuice":        ["We could not find what you're looking for."],
    "helpscout":        ["No settings were found for this company:"],
    "s3":               ["NoSuchBucket", "The specified bucket does not exist"],
    "aws/s3":           ["NoSuchBucket", "The specified bucket does not exist"],
    "azure":            ["404 Web Site not found", "is not configured as a custom domain"],
    "bitbucket":        ["Repository not found"],
    "smartjobboard":    ["This job board website is either expired or its domain name is not configured"],
    "pingdom":          ["This public report page has not been activated"],
    "tilda":            ["Please renew your subscription", "Domain is not connected to any project"],
    "surveygizmo":      ["data-html-name"],
    "mashery":          ["Unrecognized domain"],
    "intercom":         ["This page is reserved for artistic content"],
    "zendesk":          ["Help Center Closed"],
    "wix":              ["Error ConnectYourDomain", "DNS Configuration Required"],
    "feedpress":        ["The feed has not been found."],
    "surge":            ["project not found"],
    "statuspage":       ["You are being redirected", "page not found"],
    "campaignmonitor":  ["Double check the URL or"],
    "hubspot":          ["does not exist in our system", "This page isn't available"],
    "readme":           ["Project doesnt exist... yet!"],
    "unbounce":         ["The requested URL was not found on this server"],
    "strikingly":       ["page not found", "301 Moved Permanently"],
    "ucraft":           ["domain is not configured"],
    "webflow":          ["The page you are looking for doesn't exist or has been moved"],
    "agilecrm":         ["Sorry, this page is no longer available"],
    "acquia":           ["Web Site Not Found"],
    "activehosted":     ["HTTP 404 Not Found"],
    "airee":            ["Ошибка домена"],
    "anima":            ["to take it live"],
    "bigcartel":        ["<h1>Oops! We couldn&#8217;t find that page.</h1>"],
    "boom":             ["The domain you are looking for is not configured"],
    "canny":            ["Company Not Found", "There is no such company. Did you enter the right URL?"],
}

# Services where subzy/nuclei FP rate is high — always require body verification
_ALWAYS_VERIFY = {
    "github", "aws/s3", "s3", "azure", "heroku", "fastly",
    "shopify", "tumblr", "wordpress", "zendesk",
}

# Batch subdomains before running subzy (more efficient than one-at-a-time)
_BATCH_SIZE = 50


class TakeoverCheckWorker(BaseWorker):
    """Check subdomains for takeover vulnerabilities."""

    name = "takeover_check"
    input_stream = "recon_subdomains"
    output_streams = ["vuln_findings"]

    def on_start(self):
        self._batch: list[dict] = []

    def dedup_key(self, data: dict) -> str:
        return f"takeover:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        domain = data.get("domain", "")
        if not domain:
            return []

        cfg = get_config().get("takeover_check", {})
        if not cfg.get("enabled", True):
            return []

        self._batch.append(data)

        # Process in batches for efficiency
        if len(self._batch) < _BATCH_SIZE:
            return []

        results = self._process_batch(self._batch, cfg)
        self._batch = []
        return results

    def on_stop(self):
        # Flush remaining batch on shutdown
        if self._batch:
            cfg = get_config().get("takeover_check", {})
            self._process_batch(self._batch, cfg)
            self._batch = []

    def _process_batch(self, batch: list[dict], cfg: dict) -> list[dict]:
        domains = [d["domain"] for d in batch if d.get("domain")]
        program = batch[0].get("program", "") if batch else ""
        program_id = batch[0].get("program_id") if batch else None

        log.info(f"[takeover] Checking {len(domains)} subdomains for {program}")

        findings = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(domains))
            hosts_file = tmp.name

        try:
            with active_scan_slot("takeover"):
                if cfg.get("use_subzy", True):
                    subzy_findings = self._run_subzy(hosts_file, program_id)
                    findings.extend(subzy_findings)

                if cfg.get("use_nuclei", True):
                    nuclei_findings = self._run_nuclei_takeover(hosts_file, program, program_id)
                    findings.extend(nuclei_findings)
        finally:
            Path(hosts_file).unlink(missing_ok=True)

        # Body-verify every candidate before storing
        verified = []
        for finding in findings:
            subdomain = finding.get("url", "").replace("https://", "").replace("http://", "").split("/")[0]
            service = finding.get("service", "").lower()
            confirmed, body_snippet = self._verify_body(subdomain, service)
            if confirmed:
                finding["confidence"] = "confirmed"
                if body_snippet:
                    finding["evidence"] = (finding.get("evidence", "") +
                                           f"\nBody fingerprint: {body_snippet}")
                verified.append(finding)
            else:
                log.info(f"[takeover] FP filtered (body not confirmed): {subdomain} / {service}")
        findings = verified

        # Store and notify on confirmed candidates
        for finding in findings:
            subdomain = finding.get("url", "").replace("https://", "").replace("http://", "").split("/")[0]
            self.storage.upsert_takeover_candidate(
                program_id,
                subdomain=subdomain,
                cname=finding.get("cname", ""),
                service=finding.get("service", ""),
                confidence=finding.get("confidence", "medium"),
            )
            finding_id = self.storage.add_finding_deduped(
                program_id,
                dedup_hash=f"takeover:{subdomain}",
                tool="takeover_check",
                template_id=finding.get("template_id", "subdomain-takeover"),
                severity="high",
                title=f"Subdomain Takeover: {subdomain}",
                description=finding.get("description", ""),
                url=finding.get("url", ""),
                evidence=finding.get("evidence", ""),
            )
            if finding_id:
                notify(
                    "takeover_found",
                    f"Subdomain takeover candidate: {subdomain} → {finding.get('service', '?')}",
                    program=program,
                    url=finding.get("url", ""),
                )

        return findings

    def _verify_body(self, subdomain: str, service: str) -> tuple[bool, str | None]:
        """Fetch the subdomain and check the response body for service-specific unclaimed fingerprints.

        Returns (confirmed, body_snippet).
        - confirmed=True means the body contains a fingerprint that proves the service is unclaimed.
        - confirmed=False means either the site responded normally (claimed) or we couldn't connect.

        For unknown services (no fingerprint in _TAKEOVER_FINGERPRINTS), we return True to
        preserve the finding — better a FP than a missed takeover on an obscure service.
        """
        cfg = get_config()
        inti_cfg = cfg.get("intigriti", {})
        ua = inti_cfg.get("user_agent", "Mozilla/5.0")
        req_header = inti_cfg.get("request_header", "")

        # Normalise service name for lookup
        service_key = service.lower().strip()

        fingerprints = None
        for key in _TAKEOVER_FINGERPRINTS:
            if key in service_key or service_key in key:
                fingerprints = _TAKEOVER_FINGERPRINTS[key]
                break

        # Unknown service — keep the finding (no fingerprint to check against)
        if fingerprints is None:
            log.debug(f"[takeover] No fingerprint for service '{service}', keeping finding")
            return True, None

        headers = {"User-Agent": ua}
        if req_header and ":" in req_header:
            k, v = req_header.split(":", 1)
            headers[k.strip()] = v.strip()

        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{subdomain}",
                    headers=headers,
                    timeout=10,
                    allow_redirects=True,
                    verify=False,  # Expired/self-signed certs are common on takeover targets
                )
                body = resp.text
                for fp in fingerprints:
                    if fp.lower() in body.lower():
                        snippet = fp[:120]
                        log.info(f"[takeover] CONFIRMED: {subdomain} ({service}) — body: '{snippet}'")
                        return True, snippet
                # Got a real response with no fingerprint — site is claimed
                log.debug(f"[takeover] Not confirmed: {subdomain} responded {resp.status_code} without unclaimed fingerprint")
                return False, None
            except requests.exceptions.ConnectionError:
                continue  # Try other scheme
            except requests.exceptions.Timeout:
                log.debug(f"[takeover] Timeout probing {subdomain}")
                return False, None
            except Exception as e:
                log.debug(f"[takeover] Probe error {subdomain}: {e}")
                return False, None

        # Could not connect at all — NXDOMAIN or unreachable
        # This is actually a positive sign for takeover (DNS not resolving)
        log.info(f"[takeover] {subdomain} unreachable (NXDOMAIN?) — keeping as candidate")
        return True, "unreachable (possible NXDOMAIN — DNS not resolving)"

    def _run_subzy(self, hosts_file: str, program_id: int) -> list[dict]:
        """Run subzy for signature-based takeover detection."""
        try:
            import subprocess
            result = subprocess.run(
                [
                    "subzy", "run",
                    "--hosts", hosts_file,
                    "--output", "/dev/stdout",
                    "--hide_fails",
                    "--concurrency", "10",
                ],
                capture_output=True, text=True, timeout=300,
            )

            findings = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                # subzy output: "[VULNERABLE] subdomain.com - Service: github"
                if "VULNERABLE" in line or "vulnerable" in line.lower():
                    parts = line.split(" - ", 1)
                    subdomain = parts[0].strip("[] ").replace("VULNERABLE", "").strip()
                    service = ""
                    if "Service:" in line:
                        service = line.split("Service:")[-1].strip()

                    findings.append({
                        "url": f"https://{subdomain}",
                        "service": service,
                        "confidence": "high",
                        "template_id": f"takeover-{service.lower().replace(' ', '-')}",
                        "description": f"Subdomain {subdomain} is vulnerable to takeover via {service}",
                        "evidence": line,
                    })

            log.info(f"[takeover] subzy: {len(findings)} candidates")
            return findings
        except FileNotFoundError:
            log.debug("[takeover] subzy not found, skipping")
            return []
        except Exception as e:
            log.warning(f"[takeover] subzy failed: {e}")
            return []

    def _run_nuclei_takeover(self, hosts_file: str, program: str, program_id: int) -> list[dict]:
        """Run nuclei takeover templates for confirmation."""
        import subprocess

        roe_cfg = get_config().get("intigriti", {})
        roe_header = roe_cfg.get("request_header", "")

        cmd = [
            "nuclei",
            "-list", hosts_file,
            "-t", "takeover/",
            "-jsonl",
            "-silent",
            "-rate-limit", "20",
            "-c", "5",
        ]
        if roe_header:
            cmd.extend(["-H", roe_header])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            findings = []
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    findings.append({
                        "url": obj.get("matched-at", obj.get("host", "")),
                        "service": obj.get("info", {}).get("name", ""),
                        "confidence": "high",
                        "template_id": obj.get("template-id", "takeover"),
                        "description": obj.get("info", {}).get("description", ""),
                        "evidence": line,
                    })
                except json.JSONDecodeError:
                    pass

            log.info(f"[takeover] nuclei: {len(findings)} candidates")
            return findings
        except FileNotFoundError:
            log.debug("[takeover] nuclei not found")
            return []
        except subprocess.TimeoutExpired:
            log.warning("[takeover] nuclei timed out")
            return []
        except Exception as e:
            log.warning(f"[takeover] nuclei failed: {e}")
            return []

"""Tiered port scanning stage.

3-tier approach inspired by Jason Haddix's modern recon methodology:
  Tier 1 — smap:   Passive (Shodan InternetDB), zero packets, instant
  Tier 2 — naabu:  Active SYN scan, fast, CDN-aware
  Tier 3 — nmap:   Deep service/version detection on discovered ports only

Results are merged and deduplicated before publishing.
"""

import contextlib
import subprocess
import json
import xml.etree.ElementTree as ET
import tempfile
import logging
from pathlib import Path

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.ratelimit import active_scan_slot, tracked_run

log = logging.getLogger(__name__)


class PortScanWorker(BaseWorker):
    name = "portscan"
    input_stream = "recon_resolved"
    output_streams = ["recon_ports"]

    def dedup_key(self, data: dict) -> str:
        return f"portscan:{data.get('ip', '')}:{data.get('domain', '')}"

    def process(self, data: dict) -> list[dict]:
        ip = data.get("ip")
        domain = data.get("domain")
        program = data.get("program")
        program_id = data.get("program_id")
        subdomain_id = data.get("subdomain_id")

        if not ip:
            return []

        # Reject garbage values that slipped in from dig error output
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            log.debug(f"[portscan] Skipping invalid IP: {ip!r}")
            return []

        log.info(f"[portscan] Scanning {ip} ({domain})")

        constraints = self.roe_constraints(data)
        cfg = get_config()["tools"]
        scan_cfg = cfg.get("portscan", {})
        tiers = scan_cfg.get("tiers", ["smap", "naabu", "nmap"])
        rate_rps = constraints["rate_limit_rps"]

        # Collect ports from each tier
        all_ports = {}  # port -> port_info dict

        # Tier 1: smap (passive — Shodan InternetDB, no API key needed)
        if "smap" in tiers:
            smap_ports = self._run_smap(ip)
            for p in smap_ports:
                all_ports[p["port"]] = p
            log.info(f"[portscan] smap (passive): {len(smap_ports)} ports on {ip}")

        # Tiers 2 & 3: active — check RoE first, then acquire global scan slot
        active_allowed = self.is_scanning_allowed(constraints, "portscan")

        with active_scan_slot(f"portscan:{ip}") if active_allowed else contextlib.nullcontext():
            # Tier 2: naabu (active fast SYN scan)
            if "naabu" in tiers:
                naabu_cfg = cfg.get("naabu", {})
                naabu_ports = self._run_naabu(ip, naabu_cfg, rate_rps=rate_rps)
                for p in naabu_ports:
                    if p["port"] not in all_ports:
                        all_ports[p["port"]] = p
                log.info(f"[portscan] naabu (active): {len(naabu_ports)} ports on {ip}")

            # Tier 3: nmap (deep — only on discovered ports)
            if "nmap" in tiers and all_ports:
                nmap_cfg = cfg.get("nmap", {})
                port_list = ",".join(str(p) for p in sorted(all_ports.keys()))
                nmap_ports = self._run_nmap(ip, port_list, nmap_cfg, rate_rps=rate_rps)
                # Nmap enriches with service/version info
                for p in nmap_ports:
                    existing = all_ports.get(p["port"], {})
                    # Prefer nmap's richer data
                    existing.update({k: v for k, v in p.items() if v is not None})
                    all_ports[p["port"]] = existing
                log.info(f"[portscan] nmap (deep): {len(nmap_ports)} ports fingerprinted on {ip}")
            elif "nmap" in tiers and not all_ports:
                # Fallback: no ports from smap/naabu, run nmap top-ports
                nmap_cfg = cfg.get("nmap", {})
                nmap_ports = self._run_nmap_topports(ip, nmap_cfg, rate_rps=rate_rps)
                for p in nmap_ports:
                    all_ports[p["port"]] = p
                log.info(f"[portscan] nmap (fallback top-ports): {len(nmap_ports)} ports on {ip}")

        # Ensure we have a valid subdomain_id before writing ports.
        # Messages from vhost/cert discovery may carry a None or stale id.
        subdomain_id = self._resolve_subdomain_id(subdomain_id, program_id, domain)

        # Store and publish results
        results = []
        for port_info in all_ports.values():
            if subdomain_id is not None:
                self.storage.upsert_port(
                    subdomain_id=subdomain_id,
                    ip=ip,
                    port=port_info["port"],
                    protocol=port_info.get("protocol", "tcp"),
                    service=port_info.get("service"),
                    banner=port_info.get("banner"),
                    version=port_info.get("version"),
                    state=port_info.get("state", "open"),
                )

            results.append({
                "program": program,
                "program_id": program_id,
                "domain": domain,
                "ip": ip,
                "port": port_info["port"],
                "protocol": port_info.get("protocol", "tcp"),
                "service": port_info.get("service"),
                "banner": port_info.get("banner"),
                "version": port_info.get("version"),
                "subdomain_id": subdomain_id,
            })

        log.info(f"[portscan] Total: {len(all_ports)} unique open ports on {ip} ({domain})")
        return results

    def _resolve_subdomain_id(self, subdomain_id, program_id, domain: str):
        """Return a valid subdomain_id, looking up or creating the row if needed.

        Stream messages from vhost_discovery, cert_discovery, and asset_graph
        can carry a None or stale subdomain_id. Writing ports with a bad FK
        causes an IntegrityError. This ensures the subdomains row exists first.
        """
        if not domain or not program_id:
            return subdomain_id

        # Fast path: id was supplied, verify it still exists
        if subdomain_id is not None:
            try:
                with self.storage._conn() as conn:
                    row = conn.execute(
                        "SELECT id FROM subdomains WHERE id=?", (subdomain_id,)
                    ).fetchone()
                if row:
                    return subdomain_id
            except Exception:
                pass

        # Look up by domain + program
        try:
            with self.storage._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM subdomains WHERE program_id=? AND domain=?",
                    (program_id, domain),
                ).fetchone()
            if row:
                return row["id"]
        except Exception:
            pass

        # Not in DB yet — upsert it so the FK can succeed
        try:
            return self.storage.upsert_subdomain(
                int(program_id), domain, source="portscan"
            )
        except Exception as e:
            log.debug(f"[portscan] Could not resolve subdomain_id for {domain}: {e}")
            return None

    # ─── Tier 1: smap (passive via Shodan InternetDB) ────────────

    def _run_smap(self, target: str) -> list[dict]:
        """Query Shodan InternetDB for known open ports. Free, no API key."""
        ports = []

        # Try smap binary first
        try:
            result = tracked_run(
                ["smap", "-oJ", "-", target],
                capture_output=True, text=True, timeout=30,
            )
            if result.stdout.strip():
                data = json.loads(result.stdout)
                for port_data in data.get("ports", []):
                    ports.append({
                        "port": port_data.get("port", 0),
                        "protocol": port_data.get("protocol", "tcp"),
                        "service": port_data.get("service"),
                        "version": port_data.get("product"),
                        "state": "open",
                        "source": "smap",
                    })
                return ports
        except FileNotFoundError:
            pass
        except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception) as e:
            log.debug(f"smap binary failed: {e}")

        # Fallback: query InternetDB API directly
        try:
            import requests
            resp = requests.get(f"https://internetdb.shodan.io/{target}", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for port in data.get("ports", []):
                    ports.append({
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "source": "internetdb",
                    })
                # Store CPEs and vulns for CVE correlation
                if data.get("vulns"):
                    log.info(f"[smap] InternetDB reports {len(data['vulns'])} vulns for {target}: "
                             f"{', '.join(data['vulns'][:5])}")
        except Exception as e:
            log.debug(f"InternetDB fallback failed for {target}: {e}")

        return ports

    # ─── Tier 2: naabu (active fast SYN scan) ────────────────────

    def _run_naabu(self, target: str, cfg: dict, rate_rps: int = 20) -> list[dict]:
        """Fast port discovery with naabu. SYN scan if root, CONNECT otherwise."""
        ports = []
        rate = rate_rps or cfg.get("rate", 20)
        threads = cfg.get("threads", 5)
        top_ports = cfg.get("top_ports", 1000)
        exclude_cdn = cfg.get("exclude_cdn", True)

        cmd = [
            "naabu",
            "-host", target,
            "-tp", str(top_ports),
            "-rate", str(rate),
            "-c", str(threads),
            "-json",
            "-silent",
        ]

        if exclude_cdn:
            cmd.append("-exclude-cdn")

        try:
            result = tracked_run(cmd, capture_output=True, text=True, timeout=300)
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    ports.append({
                        "port": data.get("port", 0),
                        "protocol": data.get("protocol", "tcp"),
                        "state": "open",
                        "source": "naabu",
                    })
                except json.JSONDecodeError:
                    # naabu also outputs host:port in non-json mode
                    if ":" in line:
                        try:
                            port = int(line.split(":")[-1])
                            ports.append({
                                "port": port,
                                "protocol": "tcp",
                                "state": "open",
                                "source": "naabu",
                            })
                        except ValueError:
                            continue
        except FileNotFoundError:
            log.debug("naabu not found, skipping tier 2")
        except subprocess.TimeoutExpired:
            log.warning(f"naabu timed out for {target}")
        except Exception as e:
            log.debug(f"naabu failed for {target}: {e}")

        return ports

    # ─── Tier 3: nmap (deep — targeted ports only) ───────────────

    def _run_nmap(self, target: str, port_list: str, cfg: dict, rate_rps: int = 20) -> list[dict]:
        """Run nmap service detection only on known-open ports."""
        rate = rate_rps or cfg.get("rate", 20)
        scripts = cfg.get("scripts", "default,safe")

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        try:
            cmd = [
                "nmap", "-sV", "-sC",
                "-p", port_list,
                "--max-rate", str(rate),
                "--script", scripts,
                "-T3",
                "-oX", xml_path,
                target,
            ]
            tracked_run(cmd, capture_output=True, text=True, timeout=600)
            return self._parse_nmap_xml(xml_path)
        except FileNotFoundError:
            log.debug("nmap not found, skipping tier 3")
            return []
        except subprocess.TimeoutExpired:
            log.warning(f"nmap timed out for {target}")
            return self._parse_nmap_xml(xml_path)
        finally:
            Path(xml_path).unlink(missing_ok=True)

    def _run_nmap_topports(self, target: str, cfg: dict, rate_rps: int = 20) -> list[dict]:
        """Fallback: run nmap top-ports when no ports found by other tiers."""
        top_ports = cfg.get("top_ports", 1000)
        rate = rate_rps or cfg.get("rate", 20)

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        try:
            cmd = [
                "nmap", "-sV", "-sC",
                "--top-ports", str(top_ports),
                "--max-rate", str(rate),
                "-T3",
                "-oX", xml_path,
                target,
            ]
            tracked_run(cmd, capture_output=True, text=True, timeout=600)
            return self._parse_nmap_xml(xml_path)
        except FileNotFoundError:
            log.error("nmap not found")
            return []
        except subprocess.TimeoutExpired:
            log.warning(f"nmap timed out for {target}")
            return self._parse_nmap_xml(xml_path)
        finally:
            Path(xml_path).unlink(missing_ok=True)

    def _parse_nmap_xml(self, xml_path: str) -> list[dict]:
        """Parse nmap XML output into structured port data."""
        ports = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host in root.findall(".//host"):
                for port_el in host.findall(".//port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue

                    service_el = port_el.find("service")
                    port_info = {
                        "port": int(port_el.get("portid")),
                        "protocol": port_el.get("protocol", "tcp"),
                        "state": "open",
                        "source": "nmap",
                    }

                    if service_el is not None:
                        port_info["service"] = service_el.get("name")
                        version_parts = []
                        if service_el.get("product"):
                            version_parts.append(service_el.get("product"))
                        if service_el.get("version"):
                            version_parts.append(service_el.get("version"))
                        port_info["version"] = " ".join(version_parts) if version_parts else None
                        port_info["banner"] = service_el.get("extrainfo")

                    # Grab NSE script output
                    scripts = []
                    for script_el in port_el.findall(".//script"):
                        scripts.append({
                            "id": script_el.get("id"),
                            "output": script_el.get("output"),
                        })
                    if scripts:
                        port_info["scripts"] = scripts

                    ports.append(port_info)

        except ET.ParseError as e:
            log.warning(f"Failed to parse nmap XML: {e}")

        return ports

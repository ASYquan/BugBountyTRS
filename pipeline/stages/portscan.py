"""Port scanning stage.

Consumes resolved hosts from recon_resolved stream.
Runs nmap for port discovery and service detection.
Publishes open ports to recon_ports stream.
"""

import subprocess
import json
import xml.etree.ElementTree as ET
import tempfile
import logging
from pathlib import Path

from ..core.worker import BaseWorker
from ..core.config import get_config

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

        log.info(f"[portscan] Scanning {ip} ({domain})")

        ports = self._run_nmap(ip)

        results = []
        for port_info in ports:
            # Store in DB
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

        log.info(f"[portscan] Found {len(ports)} open ports on {ip} ({domain})")
        return results

    def _run_nmap(self, target: str) -> list[dict]:
        cfg = get_config()["tools"].get("nmap", {})
        top_ports = cfg.get("top_ports", 1000)
        rate = cfg.get("rate", 1000)

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
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
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

                    # Grab any NSE script output
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

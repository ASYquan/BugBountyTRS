"""Screenshot capture stage.

Consumes HTTP services from recon_http stream.
Captures screenshots using gowitness for visual recon.
"""

import subprocess
import logging
from pathlib import Path

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.ratelimit import tracked_run

log = logging.getLogger(__name__)


class ScreenshotWorker(BaseWorker):
    name = "screenshot"
    input_stream = "recon_http"
    output_streams = []  # Terminal stage, no further output

    def dedup_key(self, data: dict) -> str:
        return f"screenshot:{data.get('url', '')}"

    def on_start(self):
        self.screenshot_dir = Path(get_config()["storage"]["base_dir"]) / "screenshots"
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)

    def process(self, data: dict) -> list[dict]:
        url = data.get("url")
        domain = data.get("domain")
        program = data.get("program")
        subdomain_id = data.get("subdomain_id")

        if not url:
            return []

        screenshot_path = self._capture(url, program)

        if screenshot_path:
            # Update HTTP service record with screenshot path
            with self.storage._conn() as conn:
                conn.execute(
                    "UPDATE http_services SET screenshot_path=? WHERE url=?",
                    (str(screenshot_path), url),
                )
            log.info(f"[screenshot] Captured {url}")

        return []

    def _capture(self, url: str, program: str) -> Path | None:
        cfg = get_config()["tools"].get("gowitness", {})
        timeout = cfg.get("timeout", 10)

        out_dir = self.screenshot_dir / (program or "unknown")
        out_dir.mkdir(parents=True, exist_ok=True)

        try:
            result = tracked_run(
                [
                    "gowitness", "scan", "single",
                    "-u", url,
                    "--screenshot-path", str(out_dir),
                ],
                capture_output=True, text=True, timeout=30,
            )

            # gowitness saves with a hash-based filename
            # Find the most recently created file
            screenshots = sorted(out_dir.glob("*.png"), key=lambda p: p.stat().st_mtime, reverse=True)
            if screenshots:
                return screenshots[0]

        except FileNotFoundError:
            log.debug("gowitness not found, skipping screenshots")
        except subprocess.TimeoutExpired:
            log.warning(f"gowitness timed out for {url}")

        return None

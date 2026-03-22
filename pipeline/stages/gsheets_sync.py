"""Google Sheets sync worker.

Consumes from recon_http and recon_urls streams and appends new unique
endpoints to a configured Google Sheet in real time.

Setup:
  1. Create a Google Cloud project and enable the Sheets + Drive APIs.
  2. Create a Service Account, download the JSON key.
  3. Share your Google Sheet with the service account email (Editor).
  4. Set config:
       gsheets:
         enabled: true
         credentials_file: "/home/kali/.config/gsheets_credentials.json"
         spreadsheet_id: "your-spreadsheet-id-from-the-url"
         worksheet: "endpoints"   # tab name (created if missing)

  pip install gspread
"""

import logging

from ..core.worker import BaseWorker
from ..core.config import get_config
from ..core.dedup import Dedup
from .endpoint_csv import CSV_FIELDS, _flatten_tech, _flatten_params

log = logging.getLogger(__name__)


class GSheetsWorker(BaseWorker):
    """Appends new HTTP endpoints to a Google Sheet as they arrive."""

    name = "gsheets_sync"
    input_stream = "recon_http"
    output_streams = []

    def on_start(self):
        cfg = get_config().get("gsheets", {})

        if not cfg.get("enabled", False):
            log.info("[gsheets] Disabled in config — worker will idle.")
            self._sheet = None
            return

        try:
            import gspread
        except ImportError:
            log.error("[gsheets] gspread not installed. Run: pip install gspread")
            self._sheet = None
            return

        creds_file = cfg.get("credentials_file")
        spreadsheet_id = cfg.get("spreadsheet_id")
        worksheet_name = cfg.get("worksheet", "endpoints")

        if not creds_file or not spreadsheet_id:
            log.error("[gsheets] credentials_file and spreadsheet_id must be set in config.")
            self._sheet = None
            return

        try:
            gc = gspread.service_account(filename=creds_file)
            sh = gc.open_by_key(spreadsheet_id)

            # Get or create the worksheet tab
            try:
                self._sheet = sh.worksheet(worksheet_name)
            except gspread.WorksheetNotFound:
                self._sheet = sh.add_worksheet(title=worksheet_name, rows=10000, cols=len(CSV_FIELDS))

            # Write header row if sheet is empty
            if self._sheet.row_count == 0 or not self._sheet.row_values(1):
                self._sheet.append_row(CSV_FIELDS, value_input_option="RAW")

            log.info(f"[gsheets] Connected to sheet '{worksheet_name}' in {spreadsheet_id}")

        except Exception as e:
            log.error(f"[gsheets] Failed to connect: {e}")
            self._sheet = None

        self._dedup = Dedup(namespace="gsheets")

    def dedup_key(self, data: dict) -> str:
        url = data.get("url", "")
        method = data.get("method", "GET")
        return f"gsheets:{method}:{url}"

    def process(self, data: dict) -> list[dict]:
        if not self._sheet:
            return []

        url = data.get("url", "")
        if not url:
            return []

        from datetime import datetime, timezone
        row = [
            datetime.now(timezone.utc).isoformat(),
            data.get("program", ""),
            url,
            str(data.get("status_code", "")),
            data.get("title", "") or "",
            str(data.get("content_length", "")),
            data.get("webserver", "") or "",
            _flatten_tech(data.get("tech", [])),
            data.get("ip", "") or "",
            data.get("asn", "") or "",
            data.get("cdn", "") or "",
            str(data.get("port", "")),
            data.get("parent_domain", data.get("source_apex", "")),
            data.get("method", "GET"),
            _flatten_params(data.get("params", {})),
            data.get("source", "httpx"),
        ]

        try:
            self._sheet.append_row(row, value_input_option="USER_ENTERED")
            log.debug(f"[gsheets] Appended: {url}")
        except Exception as e:
            log.warning(f"[gsheets] Failed to append row for {url}: {e}")

        return []


class GSheetsUrlWorker(GSheetsWorker):
    """Second instance consuming from recon_urls stream."""

    name = "gsheets_sync_urls"
    input_stream = "recon_urls"

"""Continuous scheduler.

Periodically re-feeds targets into the pipeline so the recon
runs continuously. Also handles periodic dedup cache expiry
so targets get re-scanned on a configurable interval.
"""

import time
import signal
import logging
import threading

from ..core.config import get_config
from ..core.dedup import Dedup
from .scope import ScopeManager

log = logging.getLogger(__name__)

# Default: re-scan every 24 hours
DEFAULT_INTERVAL = 86400


class Scheduler:
    """Periodically re-feeds scope targets into the pipeline."""

    def __init__(self, interval: int = None, program_filter: str = None):
        self.interval = interval or DEFAULT_INTERVAL
        self.program_filter = program_filter
        self.scope_manager = ScopeManager()
        self._running = False

    def run(self):
        """Run the scheduler loop. Feeds targets, sleeps, repeats."""
        self._running = True

        # Only register signal handlers if running in the main thread
        if threading.current_thread() is threading.main_thread():
            def _handle_signal(sig, frame):
                log.info("[scheduler] Shutting down...")
                self._running = False
            signal.signal(signal.SIGINT, _handle_signal)
            signal.signal(signal.SIGTERM, _handle_signal)

        filter_msg = f" (program: {self.program_filter})" if self.program_filter else ""
        log.info(f"[scheduler] Starting with {self.interval}s interval{filter_msg}")

        while self._running:
            try:
                log.info("[scheduler] Loading programs and feeding targets...")
                self.scope_manager.load_programs()
                self.scope_manager.feed_targets(program_filter=self.program_filter)
                log.info(f"[scheduler] Targets fed. Sleeping {self.interval}s until next cycle.")
            except Exception as e:
                log.error(f"[scheduler] Error: {e}", exc_info=True)

            # Sleep in small increments so we can respond to signals
            elapsed = 0
            while self._running and elapsed < self.interval:
                time.sleep(min(10, self.interval - elapsed))
                elapsed += 10

    def stop(self):
        self._running = False

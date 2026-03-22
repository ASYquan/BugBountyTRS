"""Base worker class for pipeline stages."""

import signal
import logging
import time
from abc import ABC, abstractmethod

from .queue import MessageQueue
from .dedup import Dedup
from .storage import Storage
from .ratelimit import PipelineShuttingDown

log = logging.getLogger(__name__)


class BaseWorker(ABC):
    """Base class for all pipeline stage workers.

    Each worker continuously consumes from an input stream, processes messages,
    and publishes results to output stream(s). Runs forever until stopped.
    """

    # Override in subclasses
    name: str = "base"
    input_stream: str = None
    output_streams: list[str] = []

    def __init__(self):
        self.mq = MessageQueue(
            consumer_group=f"group:{self.name}",
            consumer_name=f"worker:{self.name}:{int(time.time())}",
        )
        self.dedup = Dedup(namespace=self.name)
        self.storage = Storage()
        self._running = False

        # Resolve stream names from config keys
        if self.input_stream:
            self.input_stream = self.mq.stream_name(self.input_stream)
        self.output_streams = [self.mq.stream_name(s) for s in self.output_streams]

    @abstractmethod
    def process(self, data: dict) -> list[dict]:
        """Process a single message. Return list of output messages."""
        pass

    def dedup_key(self, data: dict) -> str | None:
        """Return a dedup key for this message, or None to skip dedup."""
        return None

    def on_start(self):
        """Called once when the worker starts."""
        pass

    def on_stop(self):
        """Called once when the worker stops."""
        pass

    def run(self):
        """Main loop: consume, process, publish, ack. Runs continuously."""
        self._running = True

        # Only register signal handlers if running in the main thread
        import threading
        if threading.current_thread() is threading.main_thread():
            def _signal_handler(sig, frame):
                log.info(f"[{self.name}] Received signal {sig}, shutting down...")
                self._running = False
                # Also unblock any tracked_run / active_scan_slot waits so
                # subprocesses (nmap, nuclei, httpx, etc.) are killed immediately
                # instead of the process hanging until they finish.
                try:
                    from .ratelimit import _shutdown_event as _rl_evt
                    _rl_evt.set()
                except Exception:
                    pass
            signal.signal(signal.SIGINT, _signal_handler)
            signal.signal(signal.SIGTERM, _signal_handler)

        log.info(f"[{self.name}] Starting worker, consuming from {self.input_stream}")
        self.on_start()

        while self._running:
            try:
                messages = self.mq.consume(self.input_stream, count=1, block_ms=5000)

                for msg_id, data in messages:
                    try:
                        # Dedup check
                        dk = self.dedup_key(data)
                        if dk and self.dedup.is_duplicate(dk):
                            log.debug(f"[{self.name}] Skipping duplicate: {dk}")
                            self.mq.ack(self.input_stream, msg_id)
                            continue

                        # Process
                        results = self.process(data)

                        # Publish results to output streams
                        if results and self.output_streams:
                            for result in results:
                                target_stream = result.pop("_stream", None)
                                if target_stream:
                                    self.mq.publish(target_stream, result)
                                else:
                                    for stream in self.output_streams:
                                        self.mq.publish(stream, result)

                        # Ack
                        self.mq.ack(self.input_stream, msg_id)

                    except PipelineShuttingDown:
                        # Pipeline is shutting down — ack the message so it isn't
                        # redelivered on next start, then exit immediately.
                        self.mq.ack(self.input_stream, msg_id)
                        self._running = False
                        break

                    except Exception as e:
                        log.error(f"[{self.name}] Error processing message: {e}", exc_info=True)
                        self.mq.ack(self.input_stream, msg_id)

            except Exception as e:
                log.error(f"[{self.name}] Consumer error: {e}", exc_info=True)
                time.sleep(5)

        self.on_stop()
        log.info(f"[{self.name}] Worker stopped.")

    def get_program_roe(self, program_id: int | None) -> dict:
        """Return the RoE constraints for a program, or {} if not set.

        Workers use this to apply per-program overrides for rate limits,
        nuclei tag exclusions, crawl depth, and feature flags.
        """
        if not program_id:
            return {}
        return self.storage.get_program_roe(int(program_id))

    def stop(self):
        self._running = False

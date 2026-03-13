"""Redis Streams message queue wrapper."""

import json
import time
import logging
from typing import Optional

import redis

from .config import get_config

log = logging.getLogger(__name__)


class MessageQueue:
    """Redis Streams-based message queue for pipeline communication."""

    def __init__(self, consumer_group: str, consumer_name: str):
        cfg = get_config()["redis"]
        self.redis = redis.Redis(
            host=cfg["host"],
            port=cfg["port"],
            db=cfg.get("db", 0),
            decode_responses=True,
        )
        self.group = consumer_group
        self.consumer = consumer_name
        self._streams_cfg = get_config()["streams"]
        self._worker_cfg = get_config()["workers"]

    def stream_name(self, key: str) -> str:
        """Resolve a stream key from config."""
        return self._streams_cfg.get(key, key)

    def ensure_group(self, stream: str):
        """Create consumer group if it doesn't exist."""
        try:
            self.redis.xgroup_create(stream, self.group, id="0", mkstream=True)
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    def publish(self, stream: str, data: dict) -> str:
        """Publish a message to a stream. Returns message ID."""
        payload = {"data": json.dumps(data), "ts": str(time.time())}
        msg_id = self.redis.xadd(stream, payload)
        return msg_id

    def consume(
        self, stream: str, count: int = None, block_ms: int = None
    ) -> list[tuple[str, dict]]:
        """Consume messages from a stream. Returns list of (msg_id, data)."""
        if count is None:
            count = self._worker_cfg.get("batch_size", 50)
        if block_ms is None:
            block_ms = self._worker_cfg.get("block_ms", 5000)

        self.ensure_group(stream)

        results = []

        # First, check for pending messages (unacknowledged from previous runs)
        pending = self.redis.xreadgroup(
            self.group, self.consumer, {stream: "0"}, count=count
        )
        for _, messages in pending:
            for msg_id, fields in messages:
                if not fields:
                    continue
                try:
                    data = json.loads(fields["data"])
                    results.append((msg_id, data))
                except (KeyError, json.JSONDecodeError):
                    self.ack(stream, msg_id)

        if results:
            return results

        # No pending, read new messages
        new = self.redis.xreadgroup(
            self.group, self.consumer, {stream: ">"}, count=count, block=block_ms
        )
        if new:
            for _, messages in new:
                for msg_id, fields in messages:
                    try:
                        data = json.loads(fields["data"])
                        results.append((msg_id, data))
                    except (KeyError, json.JSONDecodeError):
                        self.ack(stream, msg_id)

        return results

    def ack(self, stream: str, msg_id: str):
        """Acknowledge a processed message."""
        self.redis.xack(stream, self.group, msg_id)

    def stream_length(self, stream: str) -> int:
        """Get the number of messages in a stream."""
        try:
            return self.redis.xlen(stream)
        except redis.ResponseError:
            return 0

    def stream_info(self, stream: str) -> Optional[dict]:
        """Get info about a stream."""
        try:
            return self.redis.xinfo_stream(stream)
        except redis.ResponseError:
            return None

    def pending_count(self, stream: str) -> int:
        """Get number of pending (unacknowledged) messages."""
        try:
            info = self.redis.xpending(stream, self.group)
            return info["pending"] if info else 0
        except redis.ResponseError:
            return 0

    def flush_stream(self, stream: str):
        """Delete all messages from a stream."""
        self.redis.delete(stream)

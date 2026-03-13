"""Redis-based deduplication with TTL."""

import hashlib
import logging

import redis

from .config import get_config

log = logging.getLogger(__name__)


class Dedup:
    """Prevents duplicate processing using Redis keys with expiry."""

    PREFIX = "dedup:"

    def __init__(self, namespace: str):
        cfg = get_config()["redis"]
        self.redis = redis.Redis(
            host=cfg["host"],
            port=cfg["port"],
            db=cfg.get("db", 0),
            decode_responses=True,
        )
        self.namespace = namespace
        self.ttl = get_config()["dedup"].get("ttl", 86400)

    def _key(self, value: str) -> str:
        h = hashlib.sha256(value.encode()).hexdigest()[:16]
        return f"{self.PREFIX}{self.namespace}:{h}"

    def is_duplicate(self, value: str) -> bool:
        """Check if value was already seen. If not, mark it as seen."""
        key = self._key(value)
        # SET NX returns True if key was set (not duplicate)
        was_new = self.redis.set(key, "1", nx=True, ex=self.ttl)
        return not was_new

    def mark_seen(self, value: str):
        """Explicitly mark a value as seen."""
        key = self._key(value)
        self.redis.set(key, "1", ex=self.ttl)

    def reset(self, value: str):
        """Remove a value from the seen set."""
        key = self._key(value)
        self.redis.delete(key)

    def flush(self):
        """Clear all dedup keys for this namespace."""
        pattern = f"{self.PREFIX}{self.namespace}:*"
        cursor = 0
        while True:
            cursor, keys = self.redis.scan(cursor, match=pattern, count=100)
            if keys:
                self.redis.delete(*keys)
            if cursor == 0:
                break

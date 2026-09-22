from __future__ import annotations

import hashlib
import hmac
import time
from collections import deque
from threading import Lock


def sign_payload(secret: str, timestamp: str, body: bytes) -> str:
    message = timestamp.encode("ascii", "strict") + b"." + body
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify_signed_payload(
    secret: str,
    timestamp: str,
    signature: str,
    body: bytes,
    max_skew_seconds: int = 300,
) -> bool:
    if not secret or not timestamp or not signature:
        return False
    try:
        sent_at = int(timestamp)
    except ValueError:
        return False
    if abs(int(time.time()) - sent_at) > max(1, min(max_skew_seconds, 3600)):
        return False
    expected = sign_payload(secret, timestamp, body)
    return hmac.compare_digest(expected, signature)


class SlidingWindowLimiter:
    def __init__(self, max_keys: int = 4096, cleanup_interval_seconds: float = 10.0):
        self.max_keys = max(128, max_keys)
        self.cleanup_interval_seconds = max(1.0, min(float(cleanup_interval_seconds), 60.0))
        self._buckets: dict[str, deque[float]] = {}
        self._lock = Lock()
        self._last_cleanup = 0.0

    @staticmethod
    def _prune_bucket(bucket: deque[float], cutoff: float) -> None:
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

    def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        limit = max(1, limit)
        window_seconds = max(1, window_seconds)
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is not None:
                self._prune_bucket(bucket, cutoff)
                if not bucket:
                    self._buckets.pop(key, None)
                    bucket = None

            cleanup_due = now - self._last_cleanup >= self.cleanup_interval_seconds
            capacity_pressure = bucket is None and len(self._buckets) >= self.max_keys
            if cleanup_due or capacity_pressure:
                stale = []
                for existing, existing_bucket in self._buckets.items():
                    if existing == key:
                        continue
                    self._prune_bucket(existing_bucket, cutoff)
                    if not existing_bucket:
                        stale.append(existing)
                for existing in stale:
                    self._buckets.pop(existing, None)
                self._last_cleanup = now

            if bucket is None:
                if len(self._buckets) >= self.max_keys:
                    return False
                bucket = deque()
                self._buckets[key] = bucket
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True

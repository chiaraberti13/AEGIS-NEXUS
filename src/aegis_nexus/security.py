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
    def __init__(self, max_keys: int = 4096):
        self.max_keys = max(128, max_keys)
        self._buckets: dict[str, deque[float]] = {}
        self._lock = Lock()

    def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        limit = max(1, limit)
        window_seconds = max(1, window_seconds)
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            stale = []
            for existing, bucket in self._buckets.items():
                while bucket and bucket[0] <= cutoff:
                    bucket.popleft()
                if not bucket:
                    stale.append(existing)
            for existing in stale[:256]:
                self._buckets.pop(existing, None)
            if key not in self._buckets and len(self._buckets) >= self.max_keys:
                return False
            bucket = self._buckets.setdefault(key, deque())
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True

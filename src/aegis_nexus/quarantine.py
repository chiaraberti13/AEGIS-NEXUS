from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX development fallback
    fcntl = None


class QuarantineError(ValueError):
    pass


class QuarantineStore:
    def __init__(self, root: str, *, max_bytes: int = 262144, max_files: int = 1000):
        self.root = Path(root)
        self.max_bytes = max(1024, min(int(max_bytes), 16 * 1024 * 1024))
        self.max_files = max(1, min(int(max_files), 100000))
        self.root.mkdir(parents=True, exist_ok=True)
        self._thread_lock = threading.Lock()
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    @contextmanager
    def _exclusive(self):
        with self._thread_lock:
            lock_path = self.root / ".quarantine.lock"
            with open(lock_path, "a+b") as lock_file:
                if fcntl is not None:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    if fcntl is not None:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _count(self) -> int:
        return sum(1 for path in self.root.glob("artifact_*.bin") if path.is_file())

    def store(
        self,
        data: bytes,
        *,
        sensor_id: str,
        original_name: str = "",
        content_type: str = "application/octet-stream",
    ) -> dict[str, Any]:
        if not isinstance(data, bytes):
            raise QuarantineError("artifact_must_be_bytes")
        if not data:
            raise QuarantineError("artifact_empty")
        if len(data) > self.max_bytes:
            raise QuarantineError("artifact_too_large")
        digest = hashlib.sha256(data).hexdigest()
        artifact_id = "artifact_" + uuid.uuid4().hex[:24]
        final_path = self.root / f"{artifact_id}.bin"
        with self._exclusive():
            if self._count() >= self.max_files:
                raise QuarantineError("quarantine_file_limit_reached")
            fd, temp_name = tempfile.mkstemp(prefix=".incoming-", dir=self.root)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temp_name, 0o600)
                os.replace(temp_name, final_path)
            except Exception:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
                raise

        return {
            "artifact_id": artifact_id,
            "sha256": digest,
            "size": len(data),
            "sensor_id": str(sensor_id)[:96],
            "original_name": Path(str(original_name).replace("\\", "/")).name[:255],
            "content_type": str(content_type or "application/octet-stream")[:128],
            "stored_at": datetime.now(timezone.utc).isoformat(),
            "quarantined": True,
            "executable": False,
            "inline_serving": False,
        }

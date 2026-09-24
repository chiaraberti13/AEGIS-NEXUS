from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "pcap",
    b"\xa1\xb2\xc3\xd4": "pcap",
    b"\x4d\x3c\xb2\xa1": "pcap-ns",
    b"\xa1\xb2\x3c\x4d": "pcap-ns",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}


class PcapValidationError(ValueError):
    pass


class PcapCaptureProvider(Protocol):
    name: str

    def capture(self, session_id: str, max_bytes: int) -> bytes:
        """Return a bounded PCAP/PCAPNG artifact for an already known session."""


class DisabledPcapCaptureProvider:
    name = "disabled"

    def capture(self, session_id: str, max_bytes: int) -> bytes:
        raise PcapValidationError("pcap capture provider is disabled")


class PcapEvidenceStore:
    def __init__(
        self,
        database_path: str,
        directory: str,
        *,
        enabled: bool = False,
        max_bytes: int = 1_048_576,
        retention_days: int = 7,
        max_files: int = 1000,
    ):
        self.database_path = database_path
        self.directory = Path(directory)
        self.enabled = bool(enabled)
        self.max_bytes = max(4096, min(int(max_bytes), 100 * 1024 * 1024))
        self.retention_days = max(1, min(int(retention_days), 365))
        self.max_files = max(1, min(int(max_files), 100_000))
        if self.enabled:
            self.directory.mkdir(parents=True, exist_ok=True)
        self._init()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.database_path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init(self) -> None:
        with self.connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS pcap_evidence (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    format TEXT NOT NULL,
                    storage_name TEXT NOT NULL UNIQUE,
                    capture_provider TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_pcap_evidence_session
                ON pcap_evidence(session_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_pcap_evidence_created
                ON pcap_evidence(created_at ASC);
            """)

    @staticmethod
    def _format(data: bytes) -> str:
        if len(data) < 12:
            raise PcapValidationError("pcap evidence is too short")
        format_name = PCAP_MAGIC.get(data[:4])
        if not format_name:
            raise PcapValidationError("unsupported pcap/pcapng magic")
        return format_name

    def _require_enabled(self) -> None:
        if not self.enabled:
            raise PcapValidationError("pcap evidence mode is disabled")

    def _session_exists(self, conn: sqlite3.Connection, session_id: str) -> bool:
        return conn.execute("SELECT 1 FROM sessions WHERE id=?", (session_id,)).fetchone() is not None

    def prune(self) -> dict[str, int]:
        if not self.enabled:
            return {"expired": 0, "capacity": 0}
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat()
        expired = 0
        capacity = 0
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id,storage_name FROM pcap_evidence WHERE created_at<? ORDER BY created_at ASC",
                (cutoff,),
            ).fetchall()
            for row in rows:
                self._delete_file(str(row["storage_name"]))
                conn.execute("DELETE FROM pcap_evidence WHERE id=?", (row["id"],))
                expired += 1

            rows = conn.execute(
                "SELECT id,storage_name FROM pcap_evidence ORDER BY created_at DESC,id DESC"
            ).fetchall()
            for row in rows[self.max_files:]:
                self._delete_file(str(row["storage_name"]))
                conn.execute("DELETE FROM pcap_evidence WHERE id=?", (row["id"],))
                capacity += 1
        return {"expired": expired, "capacity": capacity}

    def _delete_file(self, storage_name: str) -> None:
        path = self.directory / Path(storage_name).name
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def save(
        self,
        session_id: str,
        data: bytes,
        *,
        capture_provider: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        if not isinstance(data, bytes):
            raise PcapValidationError("pcap evidence must be bytes")
        if len(data) > self.max_bytes:
            raise PcapValidationError("pcap evidence exceeds configured size limit")
        format_name = self._format(data)
        clean_session_id = str(session_id)[:128]
        evidence_id = "pcap_" + uuid.uuid4().hex
        extension = ".pcapng" if format_name == "pcapng" else ".pcap"
        storage_name = evidence_id + extension
        digest = hashlib.sha256(data).hexdigest()
        created_at = datetime.now(timezone.utc).isoformat()

        with self.connect() as conn:
            if not self._session_exists(conn, clean_session_id):
                raise PcapValidationError("unknown session_id")

        self.directory.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".pcap-", dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.directory / storage_name)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

        try:
            with self.connect() as conn:
                conn.execute(
                    """
                    INSERT INTO pcap_evidence(
                        id,session_id,created_at,size_bytes,sha256,format,storage_name,capture_provider
                    ) VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (
                        evidence_id,
                        clean_session_id,
                        created_at,
                        len(data),
                        digest,
                        format_name,
                        storage_name,
                        str(capture_provider)[:128] if capture_provider else None,
                    ),
                )
        except Exception:
            self._delete_file(storage_name)
            raise

        self.prune()
        return self.get(evidence_id) or {}

    def list(self, session_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id,session_id,created_at,size_bytes,sha256,format,capture_provider
                FROM pcap_evidence WHERE session_id=?
                ORDER BY created_at DESC,id DESC LIMIT ?
                """,
                (str(session_id)[:128], max(1, min(int(limit), 500))),
            ).fetchall()
        return [dict(row) for row in rows]

    def get(self, evidence_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id,session_id,created_at,size_bytes,sha256,format,capture_provider
                FROM pcap_evidence WHERE id=?
                """,
                (str(evidence_id)[:128],),
            ).fetchone()
        return dict(row) if row else None

    def read_verified(self, evidence_id: str) -> tuple[dict[str, Any], bytes]:
        self._require_enabled()
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM pcap_evidence WHERE id=?", (str(evidence_id)[:128],)).fetchone()
        if not row:
            raise PcapValidationError("pcap evidence not found")
        metadata = dict(row)
        path = self.directory / Path(str(row["storage_name"])).name
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != row["sha256"] or len(data) != row["size_bytes"]:
            raise PcapValidationError("pcap evidence integrity verification failed")
        metadata.pop("storage_name", None)
        return metadata, data

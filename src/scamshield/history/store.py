"""SQLite-backed scan-history store behind a tiny abstraction.

Storage behavior:
- Local development: a file database (``data/scamshield_history.db`` by
  default, overridable with ``SCAMSHIELD_HISTORY_DB``). Persistent.
- Vercel serverless (``VERCEL=1``): the filesystem is ephemeral, so an
  in-memory database is used instead. The dashboard keeps working, but
  history does not survive cold starts — this is reported via the
  ``persistent`` flag on every history response and documented in README.
- Newest 500 scans are retained; older rows are pruned on insert.

The store never imports analyzers and never changes verdicts: it only
persists sanitized metadata via :func:`build_record`.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .sanitize import sanitize_upi_preview, sanitize_url_preview, truncate_preview

logger = logging.getLogger("scamshield.history")

MAX_STORED_SCANS = 500

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    input_type TEXT NOT NULL,
    score INTEGER,
    risk_level TEXT,
    category TEXT,
    suspicious INTEGER,
    preview TEXT NOT NULL
)
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_record(envelope: dict) -> dict:
    """Build a storable record from a Smart Scanner envelope (no I/O)."""
    result = envelope.get("result") or {}
    input_type = envelope.get("input_type") or "unknown"
    score = risk_level = category = None
    suspicious = None
    preview = ""

    if input_type in ("url", "upi"):
        score = result.get("score")
        risk_level = result.get("risk_level")
        category = result.get("category")
        suspicious = result.get("suspicious")
        if input_type == "url":
            preview = sanitize_url_preview(result.get("normalized_url") or "")
        else:
            preview = sanitize_upi_preview(result.get("raw_uri") or "")
    elif input_type == "qr":
        inner = result.get("type")
        payload = result.get("payload") or ""
        analysis = result.get("analysis") or {}
        if isinstance(analysis.get("score"), int):
            score = analysis.get("score")
            risk_level = analysis.get("risk_level")
            category = analysis.get("category")
            suspicious = analysis.get("suspicious")
        if inner == "url":
            preview = sanitize_url_preview(payload)
        elif inner == "upi":
            preview = sanitize_upi_preview(payload)
        else:
            preview = truncate_preview(payload, 120)
    elif input_type == "text":
        preview = truncate_preview(result.get("content") or "", 120)

    return {
        "id": uuid.uuid4().hex,
        "ts": _utcnow(),
        "input_type": input_type,
        "score": score if isinstance(score, int) else None,
        "risk_level": risk_level if isinstance(risk_level, str) else None,
        "category": category if isinstance(category, str) else None,
        "suspicious": (
            None if suspicious is None else (1 if bool(suspicious) else 0)
        ),
        "preview": preview,
    }


class HistoryStore:
    """Thread-safe scan-history store (file SQLite or ephemeral memory)."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        env_path = os.environ.get("SCAMSHIELD_HISTORY_DB", "").strip()
        self.persistent = True
        if os.environ.get("VERCEL") == "1" and not env_path:
            # Serverless filesystem is ephemeral: do not pretend otherwise.
            self._connect = lambda: sqlite3.connect(":memory:")
            self.persistent = False
        else:
            path = Path(env_path) if env_path else Path(db_path or "scamshield_history.db")
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                probe = sqlite3.connect(str(path))
                probe.execute("SELECT 1")
                probe.close()
            except OSError as exc:
                logger.warning("History DB %s not writable (%s); using memory.", path, exc)
                self._connect = lambda: sqlite3.connect(":memory:")
                self.persistent = False
            else:
                self._path = str(path)
                self._connect = lambda: sqlite3.connect(self._path)
        self._lock = threading.Lock()
        self._memory_conn: sqlite3.Connection | None = None
        if not self.persistent:
            self._memory_conn = self._connect()
            with self._lock, self._memory_conn:
                self._memory_conn.execute(_SCHEMA)
        else:
            with self._lock, self._connect() as conn:
                conn.execute(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        if self._memory_conn is not None:
            return self._memory_conn
        conn = self._connect()
        conn.execute(_SCHEMA)
        return conn

    def record(self, envelope: dict) -> dict:
        """Persist one scan envelope; returns the stored entry."""
        entry = build_record(envelope)
        with self._lock:
            conn = self._conn()
            close = conn is not self._memory_conn
            try:
                conn.execute(
                    "INSERT INTO scans (id, ts, input_type, score, risk_level,"
                    " category, suspicious, preview) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        entry["id"], entry["ts"], entry["input_type"],
                        entry["score"], entry["risk_level"], entry["category"],
                        entry["suspicious"], entry["preview"],
                    ),
                )
                conn.execute(
                    "DELETE FROM scans WHERE id NOT IN "
                    "(SELECT id FROM scans ORDER BY ts DESC, rowid DESC LIMIT ?)",
                    (MAX_STORED_SCANS,),
                )
                conn.commit()
            finally:
                if close:
                    conn.close()
        entry["suspicious"] = (
            None if entry["suspicious"] is None else bool(entry["suspicious"])
        )
        return entry

    def list(self, limit: int = 50) -> list[dict]:
        """Recent scans, newest first."""
        limit = max(1, min(int(limit), 200))
        with self._lock:
            conn = self._conn()
            close = conn is not self._memory_conn
            try:
                rows = conn.execute(
                    "SELECT id, ts, input_type, score, risk_level, category,"
                    " suspicious, preview FROM scans"
                    " ORDER BY ts DESC, rowid DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            finally:
                if close:
                    conn.close()
        return [
            {
                "id": row[0], "ts": row[1], "input_type": row[2], "score": row[3],
                "risk_level": row[4], "category": row[5],
                "suspicious": None if row[6] is None else bool(row[6]),
                "preview": row[7],
            }
            for row in rows
        ]

    def stats(self) -> dict:
        """Aggregate counts over stored scans."""
        with self._lock:
            conn = self._conn()
            close = conn is not self._memory_conn
            try:
                total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                green = conn.execute(
                    "SELECT COUNT(*) FROM scans WHERE risk_level='GREEN'").fetchone()[0]
                yellow = conn.execute(
                    "SELECT COUNT(*) FROM scans WHERE risk_level='YELLOW'").fetchone()[0]
                red = conn.execute(
                    "SELECT COUNT(*) FROM scans WHERE risk_level='RED'").fetchone()[0]
                suspicious = conn.execute(
                    "SELECT COUNT(*) FROM scans WHERE suspicious=1").fetchone()[0]
                by_type = {
                    row[0]: row[1]
                    for row in conn.execute(
                        "SELECT input_type, COUNT(*) FROM scans GROUP BY input_type"
                    ).fetchall()
                }
                categories = {
                    row[0]: row[1]
                    for row in conn.execute(
                        "SELECT category, COUNT(*) FROM scans"
                        " WHERE category IS NOT NULL GROUP BY category"
                    ).fetchall()
                }
            finally:
                if close:
                    conn.close()
        return {
            "total": total,
            "green": green,
            "yellow": yellow,
            "red": red,
            "suspicious": suspicious,
            "by_type": {
                "url": by_type.get("url", 0),
                "qr": by_type.get("qr", 0),
                "upi": by_type.get("upi", 0),
                "text": by_type.get("text", 0),
            },
            "categories": categories,
            "persistent": self.persistent,
        }

    def clear(self) -> int:
        """Delete all stored scans; returns the removed count."""
        with self._lock:
            conn = self._conn()
            close = conn is not self._memory_conn
            try:
                count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                conn.execute("DELETE FROM scans")
                conn.commit()
            finally:
                if close:
                    conn.close()
        return int(count)

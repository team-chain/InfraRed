"""SQLite-backed send buffer for network disconnection resilience.

Events that fail to reach the backend are persisted here and
replayed in insertion order once connectivity is restored.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BufferedEvent:
    row_id: int
    payload: dict[str, Any]


class BufferStore:
    """Persist-to-SQLite queue for unsent events."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS send_buffer (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload   TEXT    NOT NULL,
                    queued_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    # ------------------------------------------------------------------
    # Write side
    # ------------------------------------------------------------------

    def push(self, payload: dict[str, Any]) -> None:
        """Append an event to the buffer."""
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO send_buffer (payload) VALUES (?)",
                (json.dumps(payload),),
            )

    # ------------------------------------------------------------------
    # Read / ack side
    # ------------------------------------------------------------------

    def pending(self, limit: int = 100) -> list[BufferedEvent]:
        """Return up to *limit* oldest buffered events."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, payload FROM send_buffer ORDER BY id ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [BufferedEvent(row_id=r[0], payload=json.loads(r[1])) for r in rows]

    def ack(self, row_id: int) -> None:
        """Remove a successfully sent event from the buffer."""
        with self._connect() as conn:
            conn.execute("DELETE FROM send_buffer WHERE id = ?", (row_id,))

    def size(self) -> int:
        """Return the number of events currently buffered."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM send_buffer").fetchone()
        return row[0] if row else 0

"""SQLite offset store for crash-safe log tailing."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class OffsetState:
    inode: str
    offset: int


class OffsetStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS offsets (
                    file_path TEXT PRIMARY KEY,
                    inode TEXT NOT NULL,
                    offset INTEGER NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def get(self, file_path: str) -> OffsetState | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT inode, offset FROM offsets WHERE file_path = ?",
                (file_path,),
            ).fetchone()
        if row is None:
            return None
        return OffsetState(inode=row[0], offset=int(row[1]))

    def set(self, file_path: str, inode: str, offset: int) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO offsets (file_path, inode, offset)
                VALUES (?, ?, ?)
                ON CONFLICT(file_path) DO UPDATE SET
                    inode = excluded.inode,
                    offset = excluded.offset,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (file_path, inode, offset),
            )

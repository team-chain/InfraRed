"""auth.log tailing and envelope creation."""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Iterator

from infrared_agent.config import AgentSettings
from infrared_agent.masking import mask_line
from infrared_agent.offset_store import OffsetStore


def _event_id(agent_id: str, path: str, inode: str, offset: int, line: str) -> str:
    digest = hashlib.sha256(f"{agent_id}:{path}:{inode}:{offset}:{line}".encode()).hexdigest()
    return f"evt-{digest[:32]}"


class AuthLogTailer:
    def __init__(self, settings: AgentSettings, store: OffsetStore) -> None:
        self.settings = settings
        self.store = store

    def read_new_events(self) -> Iterator[tuple[dict, int, str]]:
        path = self.settings.agent_auth_log_path
        stat = os.stat(path)
        inode = str(stat.st_ino)
        state = self.store.get(path)
        offset = state.offset if state and state.inode == inode and stat.st_size >= state.offset else 0

        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            while True:
                line_offset = handle.tell()
                line = handle.readline()
                if not line:
                    break
                masked = mask_line(line)
                event_id = _event_id(self.settings.agent_id, path, inode, line_offset, masked)
                envelope = {
                    "event_id": event_id,
                    "tenant_id": self.settings.tenant_id,
                    "agent_id": self.settings.agent_id,
                    "asset_id": self.settings.asset_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "raw_source": "auth.log",
                    "raw_line": masked,
                    "file_inode": inode,
                    "file_offset": line_offset,
                }
                yield envelope, handle.tell(), inode

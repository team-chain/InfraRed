"""auth.log / nginx access.log tailing and envelope creation."""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from typing import Iterator

from infrared_agent.config import AgentSettings
from infrared_agent.masking import mask_line
from infrared_agent.offset_store import OffsetStore


def _event_id(agent_id: str, path: str, inode: str, offset: int, line: str) -> str:
    digest = hashlib.sha256(f"{agent_id}:{path}:{inode}:{offset}:{line}".encode()).hexdigest()
    return f"evt-{digest[:32]}"


# nginx combined log format 파서
# 예: 185.12.34.56 - - [30/Apr/2026:03:12:01 +0000] "GET /.env HTTP/1.1" 200 123 "-" "curl/7.68.0"
_NGINX_RE = re.compile(
    r'(?P<source_ip>\S+)\s+-\s+-\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)


class NginxLogTailer:
    """nginx access.log tailing — combined log format.

    각 라인을 파싱해 web_request 타입 Envelope로 변환.
    파싱 실패 라인은 raw_line만 포함해 전송 (백엔드에서 DLQ 처리).
    """

    def __init__(self, settings: AgentSettings, store: OffsetStore) -> None:
        self.settings = settings
        self.store = store

    def read_new_events(self) -> Iterator[tuple[dict, int, str]]:
        path = self.settings.agent_nginx_log_path
        try:
            stat = os.stat(path)
        except FileNotFoundError:
            return
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

                envelope: dict = {
                    "event_id": event_id,
                    "tenant_id": self.settings.tenant_id,
                    "agent_id": self.settings.agent_id,
                    "asset_id": self.settings.asset_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "raw_source": "nginx.access",
                    "event_type": "web_request",
                    "raw_line": masked,
                    "file_inode": inode,
                    "file_offset": line_offset,
                }

                m = _NGINX_RE.match(line.strip())
                if m:
                    envelope["source_ip"] = m.group("source_ip")
                    envelope["request_path"] = m.group("path")
                    envelope["status_code"] = int(m.group("status"))
                    envelope["user_agent"] = mask_line(m.group("user_agent"))

                yield envelope, handle.tell(), inode


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

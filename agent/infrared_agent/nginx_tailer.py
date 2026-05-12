"""nginx access.log tailing — WEB_REQUEST 이벤트 생성 (설계서 2.1).

nginx Combined Log Format 파싱:
  127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref" "Mozilla/4.08"

WEB_REQUEST EventType으로 RawEventEnvelope 생성 → FastAPI /ingest 전송.
Detection Worker가 nginx_parser.py로 정규화 후 WEB 룰 평가.
"""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from typing import Iterator

from infrared_agent.config import AgentSettings
from infrared_agent.masking import mask_line
from infrared_agent.offset_store import OffsetStore


# nginx Combined Log Format 정규식
_NGINX_RE = re.compile(
    r'(?P<remote_addr>\S+)'           # IP
    r' - '
    r'(?P<remote_user>\S+)'           # ident
    r' \[(?P<time_local>[^\]]+)\]'    # timestamp
    r' "(?P<request>[^"]*)"'          # "METHOD PATH HTTP/VER"
    r' (?P<status>\d{3})'             # status code
    r' (?P<body_bytes_sent>\d+|-)'    # bytes
    r'(?: "(?P<http_referer>[^"]*)")?' # referer (optional)
    r'(?: "(?P<http_user_agent>[^"]*)")?'  # user-agent (optional)
)

_REQUEST_RE = re.compile(r'(?P<method>\S+) (?P<path>\S+)(?: HTTP/[\d.]+)?')


def _event_id(agent_id: str, path: str, inode: str, offset: int, line: str) -> str:
    digest = hashlib.sha256(f"{agent_id}:{path}:{inode}:{offset}:{line}".encode()).hexdigest()
    return f"web-{digest[:32]}"


def _parse_nginx_line(line: str) -> dict | None:
    """nginx access.log 한 줄을 파싱해 필드 dict 반환. 파싱 실패 시 None."""
    m = _NGINX_RE.match(line.strip())
    if not m:
        return None

    remote_addr = m.group("remote_addr")
    if remote_addr == "-":
        remote_addr = None

    request_str = m.group("request") or ""
    method, path = None, None
    rm = _REQUEST_RE.match(request_str)
    if rm:
        method = rm.group("method")
        path = rm.group("path")

    status_str = m.group("status") or ""
    try:
        status_code = int(status_str)
    except ValueError:
        status_code = 0

    user_agent = m.group("http_user_agent") or None
    if user_agent == "-":
        user_agent = None

    referer = m.group("http_referer") or None
    if referer == "-":
        referer = None

    return {
        "remote_addr": remote_addr,
        "method": method,
        "path": path,
        "status_code": status_code,
        "user_agent": user_agent,
        "referer": referer,
    }


class NginxLogTailer:
    """nginx access.log를 tail하여 WEB_REQUEST 이벤트 Envelope를 생성."""

    def __init__(self, settings: AgentSettings, store: OffsetStore) -> None:
        self.settings = settings
        self.store = store

    def read_new_events(self) -> Iterator[tuple[dict, int, str]]:
        path = self.settings.agent_nginx_log_path

        if not os.path.exists(path):
            return  # nginx가 없거나 경로가 다른 경우 조용히 스킵

        stat = os.stat(path)
        inode = str(stat.st_ino)
        state = self.store.get(path)
        offset = (
            state.offset
            if state and state.inode == inode and stat.st_size >= state.offset
            else 0
        )

        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            while True:
                line_offset = handle.tell()
                line = handle.readline()
                if not line:
                    break

                masked = mask_line(line)
                parsed = _parse_nginx_line(line)
                if not parsed:
                    # 파싱 실패한 줄도 raw_line으로 전송 (Detection Worker에서 처리)
                    parsed = {}

                event_id = _event_id(
                    self.settings.agent_id, path, inode, line_offset, masked
                )

                envelope = {
                    "event_id": event_id,
                    "tenant_id": self.settings.tenant_id,
                    "agent_id": self.settings.agent_id,
                    "asset_id": self.settings.asset_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "raw_source": "nginx.log",
                    "raw_line": masked,
                    "file_inode": inode,
                    "file_offset": line_offset,
                    # WEB_REQUEST 전용 필드 (Detection Worker가 사용)
                    "source_ip": parsed.get("remote_addr"),
                    "http_method": parsed.get("method"),
                    "request_path": parsed.get("path"),
                    "status_code": parsed.get("status_code"),
                    "user_agent": parsed.get("user_agent"),
                    "referer": parsed.get("referer"),
                    "event_type": "WEB_REQUEST",
                }

                yield envelope, handle.tell(), inode

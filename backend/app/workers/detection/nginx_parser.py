"""Nginx access.log parser (Combined Log Format).

Log line format:
  {ip} {ident} {user} [{time}] "{method} {path} {proto}" {status} {bytes} "{referer}" "{ua}"

Example:
  185.12.34.56 - - [30/Apr/2026:03:12:01 +0000] "GET /uploads/shell.php HTTP/1.1" 200 1234 "-" "curl/7.68.0"

Returns NormalizedEvent with event_type=WEB_REQUEST or None if unparseable.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from app.common.constants import EventType
from app.config import get_settings
from app.models.envelope import NormalizedEvent, RawEventEnvelope


# Combined Log Format
NGINX_LOG_RE = re.compile(
    r'^(?P<ip>[\d.a-fA-F:]+)'          # client IP (IPv4 or IPv6)
    r'\s+\S+\s+\S+\s+'                 # ident, auth (both usually "-")
    r'\[(?P<time>[^\]]+)\]\s+'          # [time]
    r'"(?P<method>\S+)\s+'              # "METHOD
    r'(?P<path>\S+)\s+'                 # /path
    r'(?P<proto>[^"]+)"\s+'             # HTTP/1.1"
    r'(?P<status>\d{3})\s+'             # status code
    r'(?P<bytes>\d+|-)\s+'              # response bytes
    r'"(?P<referer>[^"]*)"\s+'          # "referer"
    r'"(?P<ua>[^"]*)"'                  # "user-agent"
)

_NGINX_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_nginx_time(raw: str, fallback: datetime) -> datetime:
    try:
        return datetime.strptime(raw, _NGINX_TIME_FMT)
    except ValueError:
        return fallback


def parse_nginx_log(envelope: RawEventEnvelope) -> NormalizedEvent | None:
    settings = get_settings()
    raw_line = envelope.raw_line or ""

    m = NGINX_LOG_RE.match(raw_line)
    if not m:
        return None

    source_ip = m.group("ip")
    timestamp = _parse_nginx_time(m.group("time"), envelope.timestamp)
    method = m.group("method").upper()
    path = m.group("path")
    status_code = int(m.group("status"))
    raw_bytes = m.group("bytes")
    response_bytes = int(raw_bytes) if raw_bytes != "-" else 0
    user_agent = m.group("ua")

    return NormalizedEvent(
        event_id=envelope.event_id,
        tenant_id=envelope.tenant_id,
        asset_id=envelope.asset_id or settings.asset_id,
        agent_id=envelope.agent_id,
        timestamp=timestamp,
        event_type=EventType.WEB_REQUEST,
        host=envelope.host,
        source_ip=source_ip,
        request_path=path,
        request_method=method,
        status_code=status_code,
        response_bytes=response_bytes,
        user_agent=user_agent,
        raw_source=envelope.raw_source or "nginx",
        raw_line=raw_line,
        late_event=envelope.late_event,
    )

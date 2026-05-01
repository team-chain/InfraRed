"""auth.log parser for the MVP detection worker."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from app.common.constants import EventType
from app.config import get_settings
from app.models.envelope import NormalizedEvent, RawEventEnvelope


AUTH_PREFIX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.*)$"
)
FAILED_INVALID = re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")
FAILED_PASSWORD = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>[\d.]+)")
ACCEPTED_PASSWORD = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)")
INVALID_USER = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")


def _parse_timestamp(match: re.Match[str], fallback: datetime) -> datetime:
    raw = f"{datetime.now().year} {match.group('month')} {match.group('day')} {match.group('clock')}"
    try:
        parsed = datetime.strptime(raw, "%Y %b %d %H:%M:%S")
        return parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return fallback


def parse_auth_log(envelope: RawEventEnvelope) -> NormalizedEvent | None:
    settings = get_settings()
    raw_line = envelope.raw_line or ""
    host = envelope.host
    timestamp = envelope.timestamp
    username = envelope.username
    source_ip = envelope.source_ip
    result = envelope.result
    event_type: EventType | None = None

    match = AUTH_PREFIX.match(raw_line)
    message = raw_line
    if match:
        host = match.group("host")
        timestamp = _parse_timestamp(match, envelope.timestamp)
        message = match.group("message")

    if password_match := ACCEPTED_PASSWORD.search(message):
        username = password_match.group("user")
        source_ip = password_match.group("ip")
        result = "success"
        event_type = EventType.SSH_LOGIN_SUCCESS
    elif password_match := FAILED_INVALID.search(message):
        username = password_match.group("user")
        source_ip = password_match.group("ip")
        result = "failed"
        event_type = EventType.SSH_INVALID_USER
    elif password_match := FAILED_PASSWORD.search(message):
        username = password_match.group("user")
        source_ip = password_match.group("ip")
        result = "failed"
        event_type = EventType.SSH_LOGIN_FAILED
    elif invalid_match := INVALID_USER.search(message):
        username = invalid_match.group("user")
        source_ip = invalid_match.group("ip")
        result = "failed"
        event_type = EventType.SSH_INVALID_USER
    elif envelope.event_type:
        event_type = EventType(envelope.event_type)

    if event_type is None:
        return None

    return NormalizedEvent(
        event_id=envelope.event_id,
        tenant_id=envelope.tenant_id,
        asset_id=envelope.asset_id or settings.asset_id,
        agent_id=envelope.agent_id,
        timestamp=timestamp,
        event_type=event_type,
        host=host,
        username=username,
        source_ip=source_ip,
        result=result,
        raw_source=envelope.raw_source or "auth.log",
        raw_line=raw_line,
        late_event=envelope.late_event,
    )

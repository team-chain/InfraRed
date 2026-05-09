"""Unit tests for the auth.log parser used by the detection worker."""
from __future__ import annotations

from datetime import datetime, timezone

from app.common.constants import EventType
from app.models.envelope import RawEventEnvelope
from app.workers.detection.nginx_parser import parse_nginx_log
from app.workers.detection.parser import parse_auth_log


def _envelope(raw_line: str, **overrides) -> RawEventEnvelope:
    payload = {
        "event_id": "evt-12345678",
        "tenant_id": "company-a",
        "agent_id": "agent-001",
        "asset_id": "asset-001",
        "timestamp": datetime(2026, 4, 30, 3, 12, 1, tzinfo=timezone.utc),
        "raw_line": raw_line,
    }
    payload.update(overrides)
    return RawEventEnvelope(**payload)


def test_parses_invalid_user_event() -> None:
    line = "Apr 30 03:12:01 web-01 sshd[1001]: Invalid user admin from 185.12.34.56 port 51234"
    event = parse_auth_log(_envelope(line))

    assert event is not None
    assert event.event_type == EventType.SSH_INVALID_USER
    assert event.username == "admin"
    assert event.source_ip == "185.12.34.56"
    assert event.host == "web-01"
    assert event.result == "failed"


def test_parses_failed_password_event() -> None:
    line = "Apr 30 03:12:08 web-01 sshd[1004]: Failed password for root from 185.12.34.56 port 51237 ssh2"
    event = parse_auth_log(_envelope(line))

    assert event is not None
    assert event.event_type == EventType.SSH_LOGIN_FAILED
    assert event.username == "root"
    assert event.source_ip == "185.12.34.56"
    assert event.result == "failed"


def test_parses_accepted_password_event() -> None:
    line = "Apr 30 03:14:55 web-01 sshd[1099]: Accepted password for root from 185.12.34.56 port 51299 ssh2"
    event = parse_auth_log(_envelope(line))

    assert event is not None
    assert event.event_type == EventType.SSH_LOGIN_SUCCESS
    assert event.result == "success"
    assert event.username == "root"
    assert event.source_ip == "185.12.34.56"


def test_failed_password_invalid_user_marks_invalid_user_event() -> None:
    line = (
        "Apr 30 03:12:04 web-01 sshd[1003]: "
        "Failed password for invalid user root from 185.12.34.56 port 51236 ssh2"
    )
    event = parse_auth_log(_envelope(line))

    assert event is not None
    assert event.event_type == EventType.SSH_INVALID_USER
    assert event.username == "root"


def test_unknown_line_returns_none() -> None:
    line = "Apr 30 03:12:01 web-01 cron[222]: pam_unix(cron:session): session opened"
    assert parse_auth_log(_envelope(line)) is None


def test_structured_web_event_normalizes_without_raw_line() -> None:
    event = parse_nginx_log(
        _envelope(
            "",
            event_type="web_request",
            raw_source="sdk",
            source_ip="203.0.113.9",
            request_path="/admin",
            request_method="GET",
            status_code=404,
            user_agent="curl/8.0",
        )
    )

    assert event is not None
    assert event.event_type == EventType.WEB_REQUEST
    assert event.source_ip == "203.0.113.9"
    assert event.request_path == "/admin"
    assert event.status_code == 404

"""FluentBit HTTP output adapter.

FluentBit config (fluent-bit.conf):

  [OUTPUT]
      Name              http
      Match             *
      Host              api.infrared.io
      Port              443
      TLS               On
      URI               /ingest/fluent
      Format            json
      Header            X-Tenant-Token  YOUR_API_KEY
      json_date_key     timestamp
      json_date_format  iso8601

Supported input formats
-----------------------
1. Single JSON object  {"timestamp": "...", "log": "...", ...}
2. JSON array of objects  [{...}, {...}]
3. FluentBit native array  [[epoch_float, {record}], ...]

The adapter detects auth.log vs nginx lines via the "source" / "tag" field
or falls back to log content heuristics.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.config import get_settings
from app.iam.api_key import verify_api_key
from app.models.envelope import RawEventEnvelope
from app.redis_kv import streams
from app.redis_kv.client import get_redis

router = APIRouter()

_AUTH_LOG_RE = re.compile(
    r"(?P<result>Failed|Accepted|Invalid user|Connection closed)",
    re.IGNORECASE,
)
_NGINX_LOG_RE = re.compile(
    r'(?P<ip>[\d.a-fA-F:]+) - - \[.*?\] "(?P<method>\w+) (?P<path>\S+)[^"]*" '
    r"(?P<status>\d{3}) (?P<bytes>\d+)"
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _detect_source(record: dict, source_hint: str = "") -> str:
    tag = (
        source_hint
        or record.get("tag")
        or record.get("source")
        or record.get("raw_source")
        or record.get("log_source")
        or ""
    )
    if "nginx" in tag or "access" in tag or tag == "web":
        return "nginx"
    log_line = str(record.get("log") or record.get("message") or "")
    if _NGINX_LOG_RE.search(log_line):
        return "nginx"
    return "auth.log"


def _parse_timestamp(record: dict) -> datetime:
    ts = record.get("timestamp") or record.get("date") or record.get("time")
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _record_to_envelope(
    record: dict,
    tenant_id: str,
    *,
    source_hint: str = "",
) -> RawEventEnvelope:
    source = _detect_source(record, source_hint=source_hint)
    log_line = str(record.get("log") or record.get("message") or "")

    source_ip: str | None = (
        record.get("source_ip")
        or record.get("remote_addr")
        or record.get("remote")
        or record.get("src_ip")
    )
    if not source_ip:
        m = _IP_RE.search(log_line)
        source_ip = m.group() if m else None

    event_type = "web_request" if source == "nginx" else "ssh_login_failed"
    if source == "auth.log" and _AUTH_LOG_RE.search(log_line):
        if "Accepted" in log_line:
            event_type = "ssh_login_success"
        elif "Invalid user" in log_line:
            event_type = "ssh_invalid_user"

    return RawEventEnvelope(
        event_id=f"fluent:{uuid.uuid4().hex}",
        tenant_id=tenant_id,
        agent_id=f"fluentbit-{tenant_id}",
        timestamp=_parse_timestamp(record),
        event_type=event_type,
        raw_source=source,
        raw_line=log_line[:512] or None,
        source_ip=source_ip,
        host=record.get("hostname") or record.get("host"),
        username=record.get("username") or record.get("user"),
        result=record.get("result"),
        request_path=record.get("request_path") or record.get("path"),
        request_method=record.get("request_method") or record.get("method"),
        status_code=_int_or_none(record.get("status_code") or record.get("status") or record.get("code")),
        user_agent=record.get("user_agent") or record.get("agent"),
        response_bytes=_int_or_none(record.get("response_bytes") or record.get("bytes") or record.get("size")),
    )


def _parse_body(body: Any) -> list[dict]:
    """Normalise the three FluentBit payload shapes into a list of record dicts."""
    if isinstance(body, dict):
        return [body]
    if isinstance(body, list):
        records: list[dict] = []
        for item in body:
            if isinstance(item, dict):
                records.append(item)
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                ts_raw, record = item
                if isinstance(record, dict):
                    record.setdefault("timestamp", ts_raw)
                    records.append(record)
        return records
    return []


@router.post("/ingest/fluent", status_code=202)
async def ingest_fluent(
    request: Request,
    claims: dict = Depends(verify_api_key),
) -> dict:
    settings = get_settings()
    tenant_id = claims["tenant_id"]

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_json")

    records = _parse_body(body)
    if not records:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="no_records")

    source_hint = request.headers.get("X-Log-Source", "")
    redis = get_redis()
    accepted = 0
    for record in records[:500]:
        try:
            envelope = _record_to_envelope(record, tenant_id, source_hint=source_hint)
            await redis.xadd(
                streams.events_raw(tenant_id),
                {"payload": envelope.model_dump_json()},
                maxlen=settings.redis_stream_maxlen,
                approximate=True,
            )
            accepted += 1
        except Exception:
            continue

    return {"accepted": True, "count": accepted}

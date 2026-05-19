"""Zeek / Suricata 네트워크 센서 이벤트 수신 — v7.0 설계서

역할:
  Zeek JSON 로그와 Suricata EVE JSON 이벤트를 HTTP로 수신하여
  Redis 이벤트 스트림에 주입.

설계:
  - Zeek: 로그 라이터 → FluentBit → InfraRed /ingest/zeek
  - Suricata: EVE JSON (eve.json) → FluentBit → InfraRed /ingest/suricata
  - 수신 후 normalized_event 형태로 Redis Stream에 푸시
  - Detection Worker가 이를 소비하여 탐지 규칙 적용

MITRE ATT&CK 매핑:
  Suricata alert → alert.signature 기반으로 자동 태깅
  Zeek conn → lateral movement, scanning 탐지 보조

인증:
  Bearer 토큰 (에이전트 토큰 또는 내부 API 토큰)
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from app.iam.security import verify_agent_token
from app.redis_kv import streams
from app.redis_kv.client import get_redis
from app.config import get_settings

router = APIRouter(tags=["network-sensor"])
log = logging.getLogger("infrared.network_sensor")

settings = get_settings()


# ─────────────────────────────────────────────────────────────────────────────
# Zeek 이벤트 모델
# ─────────────────────────────────────────────────────────────────────────────

class ZeekConnLog(BaseModel):
    """Zeek conn.log 이벤트."""
    ts: float                           # Unix timestamp
    uid: str                            # Connection UID
    id_orig_h: str = Field(alias="id.orig_h")    # 소스 IP
    id_orig_p: int = Field(alias="id.orig_p")    # 소스 포트
    id_resp_h: str = Field(alias="id.resp_h")    # 목적지 IP
    id_resp_p: int = Field(alias="id.resp_p")    # 목적지 포트
    proto: str                          # tcp / udp / icmp
    service: Optional[str] = None       # http / ssh / dns 등
    duration: Optional[float] = None    # 연결 지속 시간
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    conn_state: Optional[str] = None    # S1 / SF / REJ 등
    local_orig: Optional[bool] = None
    local_resp: Optional[bool] = None

    class Config:
        populate_by_name = True


class ZeekDNSLog(BaseModel):
    """Zeek dns.log 이벤트."""
    ts: float
    uid: str
    id_orig_h: str = Field(alias="id.orig_h")
    id_orig_p: int = Field(alias="id.orig_p")
    id_resp_h: str = Field(alias="id.resp_h")
    id_resp_p: int = Field(alias="id.resp_p")
    proto: str
    query: Optional[str] = None
    qtype_name: Optional[str] = None
    rcode_name: Optional[str] = None
    answers: Optional[list[str]] = None

    class Config:
        populate_by_name = True


class ZeekHTTPLog(BaseModel):
    """Zeek http.log 이벤트."""
    ts: float
    uid: str
    id_orig_h: str = Field(alias="id.orig_h")
    id_orig_p: int = Field(alias="id.orig_p")
    id_resp_h: str = Field(alias="id.resp_h")
    id_resp_p: int = Field(alias="id.resp_p")
    method: Optional[str] = None
    host: Optional[str] = None
    uri: Optional[str] = None
    user_agent: Optional[str] = None
    status_code: Optional[int] = None
    request_body_len: Optional[int] = None
    response_body_len: Optional[int] = None

    class Config:
        populate_by_name = True


class ZeekAlertLog(BaseModel):
    """Zeek notice.log / 범용 알림 이벤트."""
    ts: float
    uid: Optional[str] = None
    note: str                           # 알림 유형
    msg: Optional[str] = None
    src: Optional[str] = None
    dst: Optional[str] = None
    p: Optional[int] = None
    n: Optional[int] = None

    class Config:
        populate_by_name = True


# ─────────────────────────────────────────────────────────────────────────────
# Suricata EVE JSON 모델
# ─────────────────────────────────────────────────────────────────────────────

class SuricataAlert(BaseModel):
    """Suricata alert 이벤트의 alert 섹션."""
    action: str                         # allowed / blocked
    gid: Optional[int] = None
    signature_id: Optional[int] = None
    rev: Optional[int] = None
    signature: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[int] = None     # 1(HIGH) ~ 3(LOW)


class SuricataEVEEvent(BaseModel):
    """Suricata EVE JSON 이벤트 (eve.json)."""
    timestamp: str                      # ISO 8601
    flow_id: Optional[int] = None
    in_iface: Optional[str] = None
    event_type: str                     # alert / dns / http / flow / tls
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = None
    app_proto: Optional[str] = None
    alert: Optional[SuricataAlert] = None
    http: Optional[dict[str, Any]] = None
    dns: Optional[dict[str, Any]] = None
    tls: Optional[dict[str, Any]] = None
    community_id: Optional[str] = None
    host: Optional[str] = None         # Suricata가 실행 중인 호스트


# ─────────────────────────────────────────────────────────────────────────────
# 유틸리티
# ─────────────────────────────────────────────────────────────────────────────

_SURICATA_SEVERITY_MAP = {1: "high", 2: "medium", 3: "low"}


def _suricata_severity(alert: SuricataAlert | None) -> str:
    if alert and alert.severity:
        return _SURICATA_SEVERITY_MAP.get(alert.severity, "medium")
    return "medium"


def _ts_to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# Zeek 수신 엔드포인트
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/ingest/zeek/conn", status_code=status.HTTP_202_ACCEPTED)
async def ingest_zeek_conn(
    event: ZeekConnLog,
    token_data: dict = Depends(verify_agent_token),
) -> dict[str, str]:
    """Zeek conn.log 이벤트 수신."""
    normalized = {
        "event_id": f"ZEEK-CONN-{uuid.uuid4().hex[:12]}",
        "source": "zeek",
        "log_type": "conn",
        "timestamp": _ts_to_iso(event.ts),
        "src_ip": event.id_orig_h,
        "src_port": event.id_orig_p,
        "dst_ip": event.id_resp_h,
        "dst_port": event.id_resp_p,
        "proto": event.proto,
        "service": event.service,
        "conn_state": event.conn_state,
        "duration": event.duration,
        "orig_bytes": event.orig_bytes,
        "resp_bytes": event.resp_bytes,
        "zeek_uid": event.uid,
    }
    await _push_to_stream(normalized, "zeek_conn")
    return {"status": "accepted", "event_id": normalized["event_id"]}


@router.post("/ingest/zeek/dns", status_code=status.HTTP_202_ACCEPTED)
async def ingest_zeek_dns(
    event: ZeekDNSLog,
    token_data: dict = Depends(verify_agent_token),
) -> dict[str, str]:
    """Zeek dns.log 이벤트 수신."""
    normalized = {
        "event_id": f"ZEEK-DNS-{uuid.uuid4().hex[:12]}",
        "source": "zeek",
        "log_type": "dns",
        "timestamp": _ts_to_iso(event.ts),
        "src_ip": event.id_orig_h,
        "dst_ip": event.id_resp_h,
        "query": event.query,
        "qtype": event.qtype_name,
        "rcode": event.rcode_name,
        "answers": event.answers,
        "zeek_uid": event.uid,
    }
    await _push_to_stream(normalized, "zeek_dns")
    return {"status": "accepted", "event_id": normalized["event_id"]}


@router.post("/ingest/zeek/http", status_code=status.HTTP_202_ACCEPTED)
async def ingest_zeek_http(
    event: ZeekHTTPLog,
    token_data: dict = Depends(verify_agent_token),
) -> dict[str, str]:
    """Zeek http.log 이벤트 수신."""
    normalized = {
        "event_id": f"ZEEK-HTTP-{uuid.uuid4().hex[:12]}",
        "source": "zeek",
        "log_type": "http",
        "timestamp": _ts_to_iso(event.ts),
        "src_ip": event.id_orig_h,
        "dst_ip": event.id_resp_h,
        "dst_port": event.id_resp_p,
        "method": event.method,
        "host": event.host,
        "uri": event.uri,
        "user_agent": event.user_agent,
        "status_code": event.status_code,
        "zeek_uid": event.uid,
    }
    await _push_to_stream(normalized, "zeek_http")
    return {"status": "accepted", "event_id": normalized["event_id"]}


@router.post("/ingest/zeek/alert", status_code=status.HTTP_202_ACCEPTED)
async def ingest_zeek_alert(
    event: ZeekAlertLog,
    token_data: dict = Depends(verify_agent_token),
) -> dict[str, str]:
    """Zeek notice.log (알림) 이벤트 수신."""
    normalized = {
        "event_id": f"ZEEK-NOTICE-{uuid.uuid4().hex[:12]}",
        "source": "zeek",
        "log_type": "notice",
        "timestamp": _ts_to_iso(event.ts),
        "note": event.note,
        "message": event.msg,
        "src_ip": event.src,
        "dst_ip": event.dst,
        "dst_port": event.p,
    }
    await _push_to_stream(normalized, "zeek_notice")
    log.info("zeek_notice_ingested note=%s src=%s", event.note, event.src)
    return {"status": "accepted", "event_id": normalized["event_id"]}


# ─────────────────────────────────────────────────────────────────────────────
# Suricata 수신 엔드포인트
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/ingest/suricata", status_code=status.HTTP_202_ACCEPTED)
async def ingest_suricata_event(
    event: SuricataEVEEvent,
    token_data: dict = Depends(verify_agent_token),
) -> dict[str, str]:
    """
    Suricata EVE JSON 이벤트 수신.
    모든 event_type(alert, dns, http, flow, tls 등)을 단일 엔드포인트에서 처리.
    """
    event_id = f"SURICATA-{uuid.uuid4().hex[:12]}"

    normalized: dict[str, Any] = {
        "event_id": event_id,
        "source": "suricata",
        "event_type": event.event_type,
        "timestamp": event.timestamp,
        "src_ip": event.src_ip,
        "src_port": event.src_port,
        "dst_ip": event.dest_ip,
        "dst_port": event.dest_port,
        "proto": event.proto,
        "app_proto": event.app_proto,
        "community_id": event.community_id,
        "host": event.host,
    }

    if event.event_type == "alert" and event.alert:
        alert = event.alert
        normalized.update({
            "alert_action": alert.action,
            "alert_signature": alert.signature,
            "alert_signature_id": alert.signature_id,
            "alert_category": alert.category,
            "severity": _suricata_severity(alert),
        })
        log.info(
            "suricata_alert sig_id=%s sig=%s src=%s action=%s",
            alert.signature_id, alert.signature,
            event.src_ip, alert.action,
        )
    else:
        normalized["severity"] = "low"

    if event.http:
        normalized["http"] = event.http
    if event.dns:
        normalized["dns"] = event.dns
    if event.tls:
        normalized["tls"] = event.tls

    await _push_to_stream(normalized, f"suricata_{event.event_type}")
    return {"status": "accepted", "event_id": event_id}


# ─────────────────────────────────────────────────────────────────────────────
# 배치 수신 (FluentBit 대량 전송 지원)
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/ingest/suricata/batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_suricata_batch(
    events: list[SuricataEVEEvent],
    token_data: dict = Depends(verify_agent_token),
) -> dict[str, Any]:
    """Suricata 이벤트 배치 수신 (최대 1000개)."""
    if len(events) > 1000:
        events = events[:1000]

    accepted = 0
    for event in events:
        event_id = f"SURICATA-{uuid.uuid4().hex[:12]}"
        normalized: dict[str, Any] = {
            "event_id": event_id,
            "source": "suricata",
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "src_ip": event.src_ip,
            "dst_ip": event.dest_ip,
            "proto": event.proto,
        }
        if event.event_type == "alert" and event.alert:
            normalized.update({
                "alert_signature": event.alert.signature,
                "alert_signature_id": event.alert.signature_id,
                "severity": _suricata_severity(event.alert),
            })
        await _push_to_stream(normalized, f"suricata_{event.event_type}")
        accepted += 1

    return {"status": "accepted", "count": accepted}


@router.post("/ingest/zeek/batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_zeek_batch(
    events: list[dict[str, Any]],
    token_data: dict = Depends(verify_agent_token),
) -> dict[str, Any]:
    """Zeek 이벤트 배치 수신 (범용 — 여러 로그 타입 혼합 가능)."""
    if len(events) > 1000:
        events = events[:1000]

    accepted = 0
    for raw in events:
        log_type = raw.get("_path", raw.get("log_type", "unknown"))
        event_id = f"ZEEK-{uuid.uuid4().hex[:12]}"
        normalized = {"event_id": event_id, "source": "zeek", "log_type": log_type}
        normalized.update(raw)
        await _push_to_stream(normalized, f"zeek_{log_type}")
        accepted += 1

    return {"status": "accepted", "count": accepted}


# ─────────────────────────────────────────────────────────────────────────────
# Redis Stream 푸시 헬퍼
# ─────────────────────────────────────────────────────────────────────────────

async def _push_to_stream(event: dict[str, Any], stream_suffix: str) -> None:
    """정규화된 이벤트를 Redis Stream에 푸시."""
    try:
        redis = get_redis()
        stream_name = f"infrared:network:{stream_suffix}"
        # Redis Stream은 string 값만 허용 → JSON 직렬화
        import json
        payload = {k: json.dumps(v) if not isinstance(v, str) else v
                   for k, v in event.items() if v is not None}
        await redis.xadd(stream_name, payload, maxlen=100_000)
    except Exception:
        log.exception("network_sensor_stream_push_failed event_id=%s", event.get("event_id"))

"""
Falco/eBPF 이벤트 수신 엔드포인트.
Falco가 HTTP output으로 InfraRed에 eBPF 탐지 결과를 전송.
v4.0 설계서 §6 참조.
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import Optional, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.iam.security import verify_agent_token
from app.redis_kv import streams
from app.redis_kv.client import get_redis
from app.config import get_settings

router = APIRouter(tags=["falco"])
logger = logging.getLogger(__name__)


class FalcoEvent(BaseModel):
    output: str
    priority: str  # CRITICAL / ERROR / WARNING / NOTICE / INFO
    rule: str
    time: Optional[str] = None
    output_fields: Optional[dict[str, Any]] = None
    tags: Optional[list[str]] = None
    hostname: Optional[str] = None
    source: Optional[str] = "falco"


PRIORITY_TO_SEVERITY = {
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "NOTICE": "LOW",
    "INFO": "LOW",
    "DEBUG": "LOW",
}


@router.post("/ingest/falco", status_code=status.HTTP_202_ACCEPTED)
async def ingest_falco_event(
    event: FalcoEvent,
) -> dict[str, str]:
    """
    Falco HTTP output 수신.
    인증: 내부 네트워크 전용 (에이전트 토큰 불필요, 로컬호스트 접근 가정)
    실제 운영 시 IP 화이트리스트 또는 별도 API Key 적용 권장.
    """
    settings = get_settings()
    severity = PRIORITY_TO_SEVERITY.get(event.priority.upper(), "MEDIUM")
    rule_id = f"FALCO-{event.rule.replace(' ', '_').upper()[:20]}"
    
    mitre = ""
    if event.tags:
        mitre_tags = [t for t in event.tags if t.startswith("T") and "." in t]
        if mitre_tags:
            mitre = mitre_tags[0]
    
    # InfraRed AgentEvent 형식으로 변환
    agent_event = {
        "tenant_id": settings.tenant_id,
        "agent_id": event.hostname or "falco-host",
        "timestamp": event.time or datetime.now(timezone.utc).isoformat(),
        "event_type": "ebpf_detection",
        "source": "falco",
        "log_source": "falco_ebpf",
        "severity": severity,
        "rule_id": rule_id,
        "mitre": mitre,
        "falco_rule": event.rule,
        "falco_output": event.output[:500],
        "output_fields": event.output_fields or {},
        "hostname": event.hostname,
    }
    
    try:
        redis = get_redis()
        stream_key = streams.raw_events(settings.tenant_id)
        await redis.xadd(
            stream_key,
            {"payload": __import__("json").dumps(agent_event, default=str)},
            maxlen=settings.redis_stream_maxlen,
            approximate=True,
        )
        logger.info(f"Falco event ingested: rule={event.rule}, priority={event.priority}")
    except Exception as e:
        logger.error(f"Falco event ingestion failed: {e}")
        raise HTTPException(status_code=500, detail="ingestion_failed")
    
    return {"status": "accepted", "rule_id": rule_id, "severity": severity}


@router.get("/ingest/falco/health")
async def falco_health() -> dict[str, str]:
    """Falco 연동 헬스체크"""
    return {"status": "ok", "endpoint": "/api/v1/ingest/falco"}

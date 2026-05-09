"""Server-Sent Events (SSE) payload 모델 (설계서 13.5).

Dashboard 실시간 상태 업데이트:
  - LLM 분석 완료 시 백엔드 → 프론트엔드 즉시 Push
  - 클라이언트 Polling 없이 배지 색상 전환
  - MVP: SSE 기본, WebSocket은 운영 콘솔 확장 시 도입

Dashboard 카드 상태값 (설계서 Table 21):
  demo             → Blue   (QR /demo 접근, Demo Signal)
  signal           → Yellow (Threat Signal, Incident 승격 전)
  incident_high    → Red    (High Incident)
  incident_critical→ Dark Red (Critical Incident)
  llm_pending      → Gray Badge  (AI 분석 중)
  llm_success      → Green Badge (AI 분석 완료)
  llm_fallback     → Orange Badge (Static Playbook 대체)
  dry_run_applied  → Blue Badge  (자동 대응 시뮬레이션 완료)
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class SSEEvent(BaseModel):
    """SSE 스트림에 발송하는 단일 이벤트 페이로드.

    프론트엔드는 EventSource를 통해 수신, event 타입별로 처리.
    """
    event: str          # "incident_created" | "llm_updated" | "demo_visitor" | "autoresponse_done"
    data: dict[str, Any]
    sent_at: datetime = Field(default_factory=datetime.utcnow)

    def to_sse_str(self) -> str:
        """SSE wire format으로 직렬화."""
        import json
        lines = [
            f"event: {self.event}",
            f"data: {json.dumps(self.data, default=str)}",
            "",
        ]
        return "\n".join(lines) + "\n"


class LLMUpdatedPayload(BaseModel):
    """event='llm_updated' — LLM 분석 완료/실패 시 발송."""
    incident_id: str
    status: str            # "success" | "fallback"
    plain_summary: Optional[str] = None
    recommended_actions: list[str] = Field(default_factory=list)
    failure_reason: Optional[str] = None  # "timeout" | "api_error"


class DemoVisitorPayload(BaseModel):
    """event='demo_visitor' — Honeypot /demo 방문자 카드 실시간 추가."""
    demo_signal_id: str
    source_ip_masked: Optional[str] = None   # 예: "121.135.xx.xx"
    country: Optional[str] = None
    region: Optional[str] = None
    device_type: Optional[str] = None
    os_family: Optional[str] = None
    browser_family: Optional[str] = None
    path: str = "/demo"
    detected_at: datetime


class IncidentCreatedPayload(BaseModel):
    """event='incident_created' — 새 Incident 생성 시 발송."""
    incident_id: str
    severity: str
    kill_chain_stage: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    created_at: datetime


class AutoResponseDonePayload(BaseModel):
    """event='autoresponse_done' — 자동 대응 완료 시 발송."""
    auto_response_id: str
    incident_id: Optional[str] = None
    actions_taken: list[str]
    dry_run: bool
    policy_reason: Optional[str] = None

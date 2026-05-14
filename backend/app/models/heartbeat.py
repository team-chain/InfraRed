"""Agent heartbeat contract."""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel


class Heartbeat(BaseModel):
    tenant_id: str
    agent_id: str
    asset_id: Optional[str] = None
    sent_at: datetime
    agent_version: str = "0.1.0"
    pending_buffered_events: int = 0
    last_event_id: Optional[str] = None
    # 설계서 v2.0 Phase 3-D: 에이전트 Lifecycle 상태 보고
    # "online"     : 정상 동작 중 (기본값)
    # "deactivated": StartLimitBurst(5회) 초과로 종료되기 직전 전송
    status: Literal["online", "deactivated"] = "online"
    deactivation_reason: Optional[str] = None

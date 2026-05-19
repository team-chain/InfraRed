"""Break-Glass 비상 대응 API 라우터 — v7.0.

엔드포인트:
  POST /break-glass/execute  — Break-Glass 즉시 실행 (ADMIN 권한 필수)
  GET  /break-glass/events   — Break-Glass 이벤트 이력 조회
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.iam.security import require_permission
from app.workers.breakglass.handler import BreakGlassHandler

router = APIRouter(prefix="/break-glass", tags=["break-glass"])
log = logging.getLogger(__name__)

_handler = BreakGlassHandler()


# ---------------------------------------------------------------------------
# Request / Response 모델
# ---------------------------------------------------------------------------

class BreakGlassExecuteRequest(BaseModel):
    action_type: str = Field(..., description="실행할 액션 유형 (예: isolate_server, block_ip)")
    target: str = Field(..., description="대상 자산 ID 또는 IP")
    payload: dict = Field(default_factory=dict, description="추가 액션 파라미터")
    justification: str = Field(..., min_length=10, description="비상 실행 사유 (최소 10자)")


class BreakGlassEventResponse(BaseModel):
    event_id: str
    tenant_id: str
    operator_id: str
    action: dict
    justification: str
    executed_at: str


# ---------------------------------------------------------------------------
# 엔드포인트
# ---------------------------------------------------------------------------

@router.post("/execute", status_code=201)
async def execute_break_glass(
    body: BreakGlassExecuteRequest,
    request: Request,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict:
    """Break-Glass 비상 대응 즉시 실행.

    - ADMIN 권한 필수
    - approval_required 무시하고 즉시 실행
    - audit_logs에 BREAK_GLASS 이벤트 기록
    - 모든 ADMIN 역할 사용자에게 알림 발송

    보안 주의: 이 API는 감사 추적이 필수이며, 모든 호출이 기록된다.
    """
    tenant_id = claims["tenant_id"]
    operator_id = str(claims.get("sub", "unknown"))
    operator_role = str(claims.get("role", ""))

    # ADMIN 역할만 Break-Glass 실행 가능
    if operator_role not in {"admin", "superadmin"}:
        raise HTTPException(
            status_code=403,
            detail="break_glass_requires_admin_role",
        )

    action = {
        "action_type": body.action_type,
        "target": body.target,
        "payload": body.payload,
    }

    log.warning(
        "break_glass_api_called tenant=%s operator=%s action_type=%s target=%s",
        tenant_id, operator_id, body.action_type, body.target,
    )

    event = await _handler.execute_break_glass(
        tenant_id=tenant_id,
        operator_id=operator_id,
        action=action,
        justification=body.justification,
    )

    return {
        "status": "executed",
        "event": event.to_dict(),
    }


@router.get("/events")
async def list_break_glass_events(
    days: int = 30,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict:
    """Break-Glass 이벤트 이력 조회.

    audit_logs에서 BREAK_GLASS 타입 이벤트를 조회한다.

    Args:
        days: 조회 기간 (기본 30일, 최대 365일)
    """
    tenant_id = claims["tenant_id"]

    if days < 1 or days > 365:
        raise HTTPException(
            status_code=400,
            detail="days must be between 1 and 365",
        )

    events = await _handler.list_break_glass_events(tenant_id=tenant_id, days=days)

    return {
        "total": len(events),
        "days": days,
        "events": [e.to_dict() for e in events],
    }

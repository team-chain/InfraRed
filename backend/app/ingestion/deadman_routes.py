"""Dead Man's Switch API 라우터 — v7.0.

서버 격리 후 자동 격리 해제 타이머 관리.

엔드포인트:
  POST /dead-man-switch/arm              — 스위치 설정 (격리와 동시에)
  POST /dead-man-switch/disarm           — 수동 해제
  GET  /dead-man-switch/status/{asset_id} — 현재 스위치 상태
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.iam.security import require_permission
from app.workers.deadman.switch import DeadManSwitch

router = APIRouter(prefix="/dead-man-switch", tags=["dead-man-switch"])
log = logging.getLogger(__name__)

_switch = DeadManSwitch()


# ---------------------------------------------------------------------------
# Request / Response 모델
# ---------------------------------------------------------------------------

class ArmRequest(BaseModel):
    asset_id: str = Field(..., description="격리할 자산 ID")
    ttl_seconds: Optional[int] = Field(
        None,
        ge=60,
        le=86400,
        description="스위치 TTL (초). 기본값: 14400 (4시간). 범위: 60 ~ 86400",
    )


class DisarmRequest(BaseModel):
    asset_id: str = Field(..., description="격리 해제할 자산 ID")
    switch_id: str = Field(..., description="arm() 시 반환된 switch_id")


# ---------------------------------------------------------------------------
# 엔드포인트
# ---------------------------------------------------------------------------

@router.post("/arm", status_code=201)
async def arm_switch(
    body: ArmRequest,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict:
    """Dead Man's Switch 설정.

    서버 격리 명령과 동시에 호출해 지정 TTL 후 자동 격리 해제를 예약한다.
    TTL 내에 /disarm을 호출하지 않으면 자동으로 unisolate_server 명령이 발행된다.

    Returns:
        switch_id — 수동 해제 시 필요
    """
    tenant_id = claims["tenant_id"]

    switch_id = await _switch.arm(
        tenant_id=tenant_id,
        asset_id=body.asset_id,
        ttl_seconds=body.ttl_seconds,
    )

    ttl = body.ttl_seconds or DeadManSwitch.DEFAULT_TTL_SECONDS

    log.info(
        "deadman_arm tenant=%s asset=%s switch_id=%s ttl=%ds",
        tenant_id, body.asset_id, switch_id, ttl,
    )

    return {
        "switch_id": switch_id,
        "asset_id": body.asset_id,
        "ttl_seconds": ttl,
        "status": "armed",
        "message": f"Dead Man's Switch 설정됨. {ttl}초 내에 /disarm을 호출하지 않으면 자동 격리 해제됩니다.",
    }


@router.post("/disarm", status_code=200)
async def disarm_switch(
    body: DisarmRequest,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict:
    """Dead Man's Switch 수동 해제.

    운영자가 격리가 필요 없다고 판단하거나, TTL 만료 전에 직접 격리 해제할 때 사용.

    Args:
        switch_id: arm() 반환값 (검증용)
    """
    tenant_id = claims["tenant_id"]

    success = await _switch.disarm(
        tenant_id=tenant_id,
        asset_id=body.asset_id,
        switch_id=body.switch_id,
    )

    if not success:
        raise HTTPException(
            status_code=404,
            detail="switch_not_found_or_id_mismatch",
        )

    log.info(
        "deadman_disarm tenant=%s asset=%s switch_id=%s",
        tenant_id, body.asset_id, body.switch_id,
    )

    return {
        "status": "disarmed",
        "asset_id": body.asset_id,
        "switch_id": body.switch_id,
        "message": "Dead Man's Switch 수동 해제됨. 자동 격리 해제 예약이 취소됐습니다.",
    }


@router.get("/status/{asset_id}")
async def get_switch_status(
    asset_id: str,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict:
    """Dead Man's Switch 현재 상태 조회.

    Args:
        asset_id: 조회할 자산 ID
    """
    tenant_id = claims["tenant_id"]

    status = await _switch.get_status(tenant_id=tenant_id, asset_id=asset_id)

    if status is None:
        return {
            "asset_id": asset_id,
            "is_armed": False,
            "status": "not_armed",
            "message": "해당 자산에 활성화된 Dead Man's Switch가 없습니다.",
        }

    return {
        "asset_id": asset_id,
        "is_armed": status.is_armed,
        "status": "armed" if status.is_armed else "expired",
        **status.to_dict(),
    }

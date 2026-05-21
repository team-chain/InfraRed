"""Container isolation API — owner manual trigger.

`docker network disconnect` / `docker pause` / `docker stop` 을 agent에 명령.
자동 대응 엔진은 IP block 등 호스트 단위 액션 위주이므로,
컨테이너 단위 격리는 owner가 수동으로 트리거.

엔드포인트:
  POST /containers/{asset_id}/isolate
    body: { container, mode?, network?, stop_timeout?, incident_id? }
  POST /containers/{asset_id}/unisolate
    body: { container, mode?, network? }
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.autoresponse.actions import ActionType
from app.autoresponse.engine import _push_agent_command  # type: ignore[attr-defined]
from app.common.logging import get_logger
from app.db.connection import get_session
from app.iam.audit import write_audit_log
from app.iam.rbac_v2 import require_role

log = get_logger(__name__)
router = APIRouter(tags=["containers"])

ISOLATION_MODES = ("network", "pause", "stop")


class IsolateRequest(BaseModel):
    container: str = Field(..., min_length=1, max_length=128)
    mode: Literal["network", "pause", "stop"] = "network"
    network: str = "bridge"
    stop_timeout: int = Field(10, ge=1, le=300)
    incident_id: str | None = None


class UnisolateRequest(BaseModel):
    container: str = Field(..., min_length=1, max_length=128)
    mode: Literal["network", "pause", "stop"] = "network"
    network: str = "bridge"


def _validate_container_name(name: str) -> None:
    if not all(c.isalnum() or c in "-_." for c in name):
        raise HTTPException(status_code=400, detail="invalid container name")
    if name.startswith("infrared-"):
        raise HTTPException(status_code=400, detail="cannot isolate InfraRed-own container")


async def _verify_asset_in_tenant(asset_id: str, tenant_id: str) -> None:
    """IDOR 방어 — asset_id가 caller의 tenant 소속인지 검증.

    asset이 없거나 다른 tenant 소속이면 403 (404가 enumeration에 더 약함).
    """
    async with get_session() as session:
        row = await session.execute(
            text("SELECT 1 FROM assets WHERE asset_id = :aid AND tenant_id = :tid"),
            {"aid": asset_id, "tid": tenant_id},
        )
        if not row.first():
            log.warning(
                "container_isolate_idor_attempt",
                asset_id=asset_id, tenant_id=tenant_id,
            )
            raise HTTPException(status_code=403, detail="asset_not_in_tenant")


@router.post("/containers/{asset_id}/isolate", status_code=202)
async def isolate_container(
    asset_id: str,
    payload: IsolateRequest,
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """컨테이너 격리 명령을 agent에 push (owner only)."""
    _validate_container_name(payload.container)

    tenant_id = claims["tenant_id"]
    # IDOR 방어 — asset이 caller tenant 소속인지 검증
    await _verify_asset_in_tenant(asset_id, tenant_id)

    action = {
        "action_type": ActionType.CONTAINER_ISOLATE.value,
        "target": payload.container,
        "payload": {
            "container": payload.container,
            "mode": payload.mode,
            "network": payload.network,
            "stop_timeout": payload.stop_timeout,
            "incident_id": payload.incident_id or "manual",
            "issued_by": str(claims.get("sub", "")),
        },
    }
    await _push_agent_command(tenant_id, asset_id, action)

    await write_audit_log(
        tenant_id=tenant_id,
        actor=str(claims.get("sub", "")),
        action="container.isolate",
        resource=payload.container,
        metadata={
            "asset_id": asset_id,
            "mode": payload.mode,
            "network": payload.network,
            "incident_id": payload.incident_id,
        },
    )

    log.info(
        "container_isolate_queued",
        tenant_id=tenant_id,
        asset_id=asset_id,
        container=payload.container,
        mode=payload.mode,
    )
    return {
        "queued": True,
        "asset_id": asset_id,
        "container": payload.container,
        "mode": payload.mode,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/containers/{asset_id}/unisolate", status_code=202)
async def unisolate_container(
    asset_id: str,
    payload: UnisolateRequest,
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """컨테이너 격리 해제 — reconnect / unpause / start."""
    _validate_container_name(payload.container)

    tenant_id = claims["tenant_id"]
    await _verify_asset_in_tenant(asset_id, tenant_id)

    action = {
        "action_type": ActionType.CONTAINER_UNISOLATE.value,
        "target": payload.container,
        "payload": {
            "container": payload.container,
            "mode": payload.mode,
            "network": payload.network,
            "issued_by": str(claims.get("sub", "")),
        },
    }
    await _push_agent_command(tenant_id, asset_id, action)

    await write_audit_log(
        tenant_id=tenant_id,
        actor=str(claims.get("sub", "")),
        action="container.unisolate",
        resource=payload.container,
        metadata={"asset_id": asset_id, "mode": payload.mode},
    )

    return {
        "queued": True,
        "asset_id": asset_id,
        "container": payload.container,
        "mode": payload.mode,
    }

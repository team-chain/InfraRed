"""Phase 2-B: Allowlist / Suppression / Maintenance Window API.

설계서 2-B: 3개 개념 명확히 분리
- Allowlist:           특정 IP/계정 영구 제외
- Suppression:         룰 + 자산 + 시간 조건부 억제
- Maintenance Window:  점검 시간 동안 탐지/알림 비활성

엔드포인트:
  GET/POST/DELETE /allowlist
  GET/POST/DELETE /suppressions
  GET/POST/PATCH/DELETE /maintenance-windows
  GET /suppression/check  - 현재 시그널이 억제되는지 확인
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.audit import write_audit_log
from app.iam.rbac_v2 import require_role

router = APIRouter(tags=["suppression"])


# ============================================================
# Allowlist
# ============================================================

class AllowlistEntry(BaseModel):
    entry_type: str = Field(default="ip", pattern="^(ip|account|asset)$")
    value: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


@router.get("/allowlist")
async def list_allowlist(
    entry_type: Optional[str] = Query(None),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """Allowlist 목록."""
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        params: dict = {"tenant_id": tenant_id}
        where = "tenant_id = :tenant_id"
        if entry_type:
            where += " AND entry_type = :entry_type"
            params["entry_type"] = entry_type
        result = await session.execute(
            text(f"""
                SELECT id::text, entry_type, value, description, created_by, created_at
                FROM allowlist_entries
                WHERE {where}
                ORDER BY created_at DESC
            """),
            params,
        )
        rows = result.mappings().fetchall()
    return {
        "items": [
            {
                "id": r["id"],
                "entry_type": r["entry_type"],
                "type": r["entry_type"],
                "value": r["value"],
                "description": r["description"],
                "reason": r["description"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
    }


@router.post("/allowlist", status_code=201)
async def add_allowlist(
    payload: AllowlistEntry,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """Allowlist 항목 추가."""
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])

    async with get_session() as session:
        try:
            result = await session.execute(
                text("""
                    INSERT INTO allowlist_entries (tenant_id, entry_type, value, description, created_by)
                    VALUES (:tenant_id, :entry_type, :value, :description, :created_by)
                    RETURNING id::text, created_at
                """),
                {
                    "tenant_id": tenant_id,
                    "entry_type": payload.entry_type,
                    "value": payload.value,
                    "description": payload.description,
                    "created_by": user_id,
                },
            )
            row = result.mappings().fetchone()
            await session.commit()
        except Exception:
            raise HTTPException(status_code=409, detail="이미 존재하는 항목입니다")

    await write_audit_log(
        tenant_id=tenant_id, actor=user_id, action="allowlist.add",
        resource=payload.value, metadata={"type": payload.entry_type},
    )
    return {"id": row["id"], "value": payload.value, "entry_type": payload.entry_type}


@router.delete("/allowlist/{entry_id}")
async def delete_allowlist(
    entry_id: str,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])
    async with get_session() as session:
        result = await session.execute(
            text("""
                DELETE FROM allowlist_entries
                WHERE id = CAST(:id AS UUID) AND tenant_id = :tenant_id
                RETURNING value
            """),
            {"id": entry_id, "tenant_id": tenant_id},
        )
        row = result.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="not_found")
        await session.commit()
    await write_audit_log(tenant_id=tenant_id, actor=user_id, action="allowlist.delete", resource=entry_id)
    return {"deleted": True, "id": entry_id}


# ============================================================
# Suppression
# ============================================================

class SuppressionCreate(BaseModel):
    rule_id: Optional[str] = None
    asset_id: Optional[str] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    expires_at: Optional[datetime] = None
    reason: str = Field(..., min_length=1, max_length=500)


@router.get("/suppressions")
async def list_suppressions(
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT id::text, rule_id, asset_id, source_ip::text,
                       username, expires_at, reason, enabled, created_at
                FROM suppressions
                WHERE tenant_id = :tenant_id AND enabled = true
                ORDER BY created_at DESC
            """),
            {"tenant_id": tenant_id},
        )
        rows = result.mappings().fetchall()
    return {
        "items": [
            {
                "id": r["id"],
                "rule_id": r["rule_id"],
                "asset_id": r["asset_id"],
                "source_ip": r["source_ip"],
                "username": r["username"],
                "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
                "reason": r["reason"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
    }


@router.post("/suppressions", status_code=201)
async def create_suppression(
    payload: SuppressionCreate,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])
    async with get_session() as session:
        result = await session.execute(
            text("""
                INSERT INTO suppressions
                    (tenant_id, rule_id, asset_id, source_ip, username, expires_at, reason, created_by)
                VALUES
                    (:tenant_id, :rule_id, :asset_id, CAST(:source_ip AS CIDR), :username, :expires_at, :reason, :created_by)
                RETURNING id::text, created_at
            """),
            {
                "tenant_id": tenant_id,
                "rule_id": payload.rule_id,
                "asset_id": payload.asset_id,
                "source_ip": payload.source_ip,
                "username": payload.username,
                "expires_at": payload.expires_at,
                "reason": payload.reason,
                "created_by": user_id,
            },
        )
        row = result.mappings().fetchone()
        await session.commit()

    await write_audit_log(
        tenant_id=tenant_id, actor=user_id, action="suppression.create",
        resource=payload.rule_id or payload.source_ip or "any",
        metadata={"expires_at": payload.expires_at.isoformat() if payload.expires_at else None},
    )
    return {"id": row["id"], "created_at": row["created_at"].isoformat()}


@router.delete("/suppressions/{suppression_id}")
async def delete_suppression(
    suppression_id: str,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        result = await session.execute(
            text("""
                UPDATE suppressions
                SET enabled = false
                WHERE id = CAST(:id AS UUID) AND tenant_id = :tenant_id
                RETURNING id
            """),
            {"id": suppression_id, "tenant_id": tenant_id},
        )
        if not result.fetchone():
            raise HTTPException(status_code=404, detail="not_found")
        await session.commit()
    return {"deleted": True, "id": suppression_id}


# ============================================================
# Maintenance Window
# ============================================================

class MaintenanceWindowCreate(BaseModel):
    name: str = Field(default="정기 점검", max_length=100)
    start_at: datetime
    end_at: datetime
    recurrence: Optional[str] = None
    affected_rules: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    reason: Optional[str] = None


class MaintenanceWindowUpdate(BaseModel):
    name: Optional[str] = None
    start_at: Optional[datetime] = None
    end_at: Optional[datetime] = None
    enabled: Optional[bool] = None


@router.get("/maintenance-windows")
async def list_maintenance_windows(
    active_only: bool = Query(default=False),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        where = "tenant_id = :tenant_id"
        params: dict = {"tenant_id": tenant_id}
        if active_only:
            where += " AND enabled = true AND start_at <= NOW() AND end_at >= NOW()"
        result = await session.execute(
            text(f"""
                SELECT id::text, name, start_at, end_at, recurrence,
                       affected_rules, affected_assets, reason, enabled, created_at
                FROM maintenance_windows
                WHERE {where}
                ORDER BY start_at DESC
            """),
            params,
        )
        rows = result.mappings().fetchall()
    return {
        "items": [
            {
                "id": r["id"],
                "name": r["name"],
                "start_at": r["start_at"].isoformat() if r["start_at"] else None,
                "end_at": r["end_at"].isoformat() if r["end_at"] else None,
                "recurrence": r["recurrence"],
                "affected_rules": r["affected_rules"] or [],
                "affected_assets": r["affected_assets"] or [],
                "reason": r["reason"],
                "enabled": r["enabled"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
    }


@router.post("/maintenance-windows", status_code=201)
async def create_maintenance_window(
    payload: MaintenanceWindowCreate,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])

    if payload.end_at <= payload.start_at:
        raise HTTPException(status_code=400, detail="end_at must be after start_at")

    async with get_session() as session:
        result = await session.execute(
            text("""
                INSERT INTO maintenance_windows
                    (tenant_id, name, start_at, end_at, recurrence,
                     affected_rules, affected_assets, reason, created_by)
                VALUES
                    (:tenant_id, :name, :start_at, :end_at, :recurrence,
                     :affected_rules, :affected_assets, :reason, :created_by)
                RETURNING id::text, created_at
            """),
            {
                "tenant_id": tenant_id,
                "name": payload.name,
                "start_at": payload.start_at,
                "end_at": payload.end_at,
                "recurrence": payload.recurrence,
                "affected_rules": payload.affected_rules,
                "affected_assets": payload.affected_assets,
                "reason": payload.reason,
                "created_by": user_id,
            },
        )
        row = result.mappings().fetchone()
        await session.commit()

    await write_audit_log(
        tenant_id=tenant_id, actor=user_id, action="maintenance_window.create",
        resource=str(row["id"]),
        metadata={"start_at": payload.start_at.isoformat(), "end_at": payload.end_at.isoformat()},
    )
    return {"id": row["id"], "created_at": row["created_at"].isoformat()}


@router.delete("/maintenance-windows/{mw_id}")
async def delete_maintenance_window(
    mw_id: str,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        result = await session.execute(
            text("""
                UPDATE maintenance_windows
                SET enabled = false
                WHERE id = CAST(:id AS UUID) AND tenant_id = :tenant_id
                RETURNING id
            """),
            {"id": mw_id, "tenant_id": tenant_id},
        )
        if not result.fetchone():
            raise HTTPException(status_code=404, detail="not_found")
        await session.commit()
    return {"deleted": True, "id": mw_id}


# ============================================================
# 억제 체크 헬퍼 (Detection Worker 연동용)
# ============================================================

async def is_suppressed(
    tenant_id: str,
    rule_id: Optional[str],
    asset_id: Optional[str],
    source_ip: Optional[str],
    username: Optional[str],
) -> tuple[bool, str]:
    """시그널이 현재 억제 대상인지 확인.

    Returns:
        (is_suppressed, reason)
    """
    now = datetime.now(timezone.utc)

    async with get_session() as session:
        # Maintenance Window 확인
        mw_result = await session.execute(
            text("""
                SELECT name, reason FROM maintenance_windows
                WHERE tenant_id = :tenant_id
                  AND enabled = true
                  AND start_at <= :now AND end_at >= :now
                  AND (
                      array_length(affected_rules, 1) IS NULL
                      OR :rule_id = ANY(affected_rules)
                  )
                  AND (
                      array_length(affected_assets, 1) IS NULL
                      OR :asset_id = ANY(affected_assets)
                  )
                LIMIT 1
            """),
            {"tenant_id": tenant_id, "now": now, "rule_id": rule_id, "asset_id": asset_id},
        )
        mw = mw_result.fetchone()
        if mw:
            return True, f"점검 중: {mw[0]}"

        # Suppression 확인
        sup_result = await session.execute(
            text("""
                SELECT reason FROM suppressions
                WHERE tenant_id = :tenant_id
                  AND enabled = true
                  AND (expires_at IS NULL OR expires_at > :now)
                  AND (:rule_id IS NULL OR rule_id IS NULL OR rule_id = :rule_id)
                  AND (:asset_id IS NULL OR asset_id IS NULL OR asset_id = :asset_id)
                  AND (:source_ip IS NULL OR source_ip IS NULL OR CAST(:source_ip AS INET) <<= source_ip)
                  AND (:username IS NULL OR username IS NULL OR username = :username)
                LIMIT 1
            """),
            {
                "tenant_id": tenant_id,
                "now": now,
                "rule_id": rule_id,
                "asset_id": asset_id,
                "source_ip": source_ip,
                "username": username,
            },
        )
        sup = sup_result.fetchone()
        if sup:
            return True, f"억제됨: {sup[0]}"

        # Allowlist 확인 (IP)
        if source_ip:
            al_result = await session.execute(
                text("""
                    SELECT 1 FROM allowlist_entries
                    WHERE tenant_id = :tenant_id
                      AND entry_type = 'ip'
                      AND value = :source_ip
                    LIMIT 1
                """),
                {"tenant_id": tenant_id, "source_ip": source_ip},
            )
            if al_result.fetchone():
                return True, f"Allowlist IP: {source_ip}"

        # Allowlist 확인 (계정)
        if username:
            al_acc_result = await session.execute(
                text("""
                    SELECT 1 FROM allowlist_entries
                    WHERE tenant_id = :tenant_id
                      AND entry_type = 'account'
                      AND value = :username
                    LIMIT 1
                """),
                {"tenant_id": tenant_id, "username": username},
            )
            if al_acc_result.fetchone():
                return True, f"Allowlist 계정: {username}"

    return False, ""

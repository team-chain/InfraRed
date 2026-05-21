"""Audit log viewer — owner가 누가 무엇을 했는지 조회.

audit_logs 테이블 (write_audit_log로 기록됨).
필터: actor, action, since, until. 최대 500개.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.rbac_v2 import require_role
from app.iam.tenant_isolation import assert_same_tenant

router = APIRouter(tags=["audit"])


@router.get("/audit-logs/{tenant_id}")
async def list_audit_logs(
    tenant_id: str,
    actor: str | None = Query(default=None, description="actor email/id 부분 일치"),
    action: str | None = Query(default=None, description="action prefix (예: auth., user., container.)"),
    since: datetime | None = Query(default=None, description="이 시각 이후 (ISO 8601)"),
    until: datetime | None = Query(default=None, description="이 시각 이전"),
    limit: int = Query(default=200, ge=1, le=500),
    claims: dict = Depends(require_role("owner")),
) -> dict[str, Any]:
    """Owner 전용 — tenant 내 모든 audit log 조회."""
    assert_same_tenant(claims, tenant_id)

    conditions = ["tenant_id = :tenant_id"]
    params: dict[str, Any] = {"tenant_id": tenant_id, "limit": limit}

    if actor:
        conditions.append("actor ILIKE :actor")
        params["actor"] = f"%{actor}%"
    if action:
        conditions.append("action LIKE :action")
        params["action"] = f"{action}%"
    if since:
        conditions.append("timestamp >= :since")
        params["since"] = since
    if until:
        conditions.append("timestamp <= :until")
        params["until"] = until

    where = " AND ".join(conditions)

    async with get_session() as session:
        result = await session.execute(
            text(
                f"""
                SELECT id, tenant_id, actor, action, resource, ip, timestamp, metadata
                FROM audit_logs
                WHERE {where}
                ORDER BY timestamp DESC
                LIMIT :limit
                """
            ),
            params,
        )
        rows = result.mappings().all()

    items = []
    for r in rows:
        items.append({
            "id": str(r["id"]),
            "tenant_id": r["tenant_id"],
            "actor": r["actor"],
            "action": r["action"],
            "resource": r["resource"],
            "ip": r["ip"],
            "timestamp": r["timestamp"].isoformat() if r["timestamp"] else None,
            "metadata": r["metadata"],
        })

    return {"items": items, "count": len(items), "limit": limit}


@router.get("/audit-logs/{tenant_id}/actions")
async def list_distinct_actions(
    tenant_id: str,
    claims: dict = Depends(require_role("owner")),
) -> dict[str, Any]:
    """필터용 — 이 tenant에 기록된 distinct action 목록 (최근 30일)."""
    assert_same_tenant(claims, tenant_id)
    async with get_session() as session:
        result = await session.execute(
            text(
                """
                SELECT DISTINCT action, COUNT(*) AS count
                FROM audit_logs
                WHERE tenant_id = :tenant_id
                  AND timestamp > NOW() - INTERVAL '30 days'
                GROUP BY action
                ORDER BY count DESC
                LIMIT 50
                """
            ),
            {"tenant_id": tenant_id},
        )
        return {
            "items": [{"action": r["action"], "count": r["count"]} for r in result.mappings()],
        }

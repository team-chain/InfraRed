"""Phase 1-A: 인시던트 상태 워크플로우 API 라우터.

엔드포인트:
  PATCH /incidents/{id}/status      - 상태 전이
  PATCH /incidents/{id}/assignee    - 담당자 지정
  POST  /incidents/{id}/comments    - 코멘트 추가
  GET   /incidents/{id}/comments    - 코멘트 목록
  POST  /incidents/{id}/links       - 인시던트 연결
  GET   /incidents/{id}/links       - 연결 목록
  GET   /incidents/{id}/history     - 상태 변경 이력
  GET   /incidents/stats/fp         - FP 통계 (Phase 1-D)
  GET   /incidents/stats/timeseries - 시계열 집계 (Phase 4-C)
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

router = APIRouter(prefix="/incidents", tags=["incidents-workflow"])

# ============================================================
# 상태 전이 유효성 검사
# 설계서 1-A-1: 허용된 전이만 가능
# ============================================================

_VALID_TRANSITIONS: dict[str, list[str]] = {
    "open":          ["acknowledged", "in_progress"],
    "acknowledged":  ["in_progress", "closed"],
    "in_progress":   ["contained", "resolved"],
    "contained":     ["resolved"],
    "resolved":      ["closed", "in_progress"],  # in_progress = 재오픈
    "closed":        [],  # 종단 상태
}

_DISPOSITION_VALUES = {"true_positive", "false_positive", "benign", "duplicate"}

# closed 전환에 담당자 또는 security_manager 이상 권한 필요
_CLOSED_REQUIRED_ROLES = {"owner", "security_manager"}


def _validate_transition(from_status: str, to_status: str) -> None:
    allowed = _VALID_TRANSITIONS.get(from_status, [])
    if to_status not in allowed:
        raise HTTPException(
            status_code=422,
            detail=f"상태 전이 불가: {from_status} → {to_status}. "
                   f"허용된 전이: {allowed}",
        )


# ============================================================
# Request/Response 모델
# ============================================================

class StatusTransitionRequest(BaseModel):
    status: str
    reason: Optional[str] = None
    disposition: Optional[str] = Field(
        None,
        description="closed 전환 시 필수: true_positive / false_positive / benign / duplicate",
    )
    close_reason: Optional[str] = None


class AssigneeRequest(BaseModel):
    assignee_id: Optional[str] = None  # None = 담당자 해제


class CommentRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=5000)


class LinkRequest(BaseModel):
    target_incident_id: str
    link_type: str = Field(
        ...,
        pattern="^(same_attacker|follow_up|duplicate)$",
    )


# ============================================================
# 상태 전이 엔드포인트
# ============================================================

@router.patch("/{incident_id}/workflow-status")
async def transition_status(
    incident_id: str,
    payload: StatusTransitionRequest,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """인시던트 상태 전이.

    설계서 1-A: closed 전환 시 disposition 필수, security_manager 이상 권한.
    """
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])
    user_role = claims.get("role", "analyst")

    async with get_session() as session:
        # 현재 인시던트 조회
        row = await session.execute(
            text("""
                SELECT incident_id, tenant_id, status, disposition
                FROM incidents
                WHERE incident_id = :incident_id AND tenant_id = :tenant_id
            """),
            {"incident_id": incident_id, "tenant_id": tenant_id},
        )
        incident = row.mappings().fetchone()
        if not incident:
            raise HTTPException(status_code=404, detail="incident_not_found")

        current_status = incident["status"]
        new_status = payload.status

        # 전이 유효성 검사
        _validate_transition(current_status, new_status)

        # closed 전환 추가 검증
        if new_status == "closed":
            # 권한 검사: security_manager 이상
            if user_role not in _CLOSED_REQUIRED_ROLES:
                raise HTTPException(
                    status_code=403,
                    detail="closed 전환은 security_manager 이상 권한이 필요합니다",
                )
            # disposition 필수
            if not payload.disposition:
                raise HTTPException(
                    status_code=400,
                    detail="closed 전환 시 disposition 입력 필수",
                )
            if payload.disposition not in _DISPOSITION_VALUES:
                raise HTTPException(
                    status_code=400,
                    detail=f"disposition은 {_DISPOSITION_VALUES} 중 하나여야 합니다",
                )
            # false_positive / duplicate 시 close_reason 필수
            if payload.disposition in {"false_positive", "duplicate"} and not payload.close_reason:
                raise HTTPException(
                    status_code=400,
                    detail=f"disposition={payload.disposition} 시 close_reason 필수",
                )

        now = datetime.now(timezone.utc)

        # 인시던트 업데이트
        update_fields = {
            "status": new_status,
            "updated_at": now,
            "incident_id": incident_id,
            "tenant_id": tenant_id,
        }
        set_clauses = ["status = :status", "updated_at = :updated_at"]

        if payload.disposition:
            set_clauses.append("disposition = :disposition")
            update_fields["disposition"] = payload.disposition

        if payload.close_reason:
            set_clauses.append("close_reason = :close_reason")
            update_fields["close_reason"] = payload.close_reason

        if new_status == "resolved":
            set_clauses.append("resolved_at = :resolved_at")
            update_fields["resolved_at"] = now

        if new_status == "closed":
            set_clauses.append("closed_at = :closed_at")
            update_fields["closed_at"] = now

        await session.execute(
            text(f"""
                UPDATE incidents
                SET {', '.join(set_clauses)}
                WHERE incident_id = :incident_id AND tenant_id = :tenant_id
            """),
            update_fields,
        )

        # 상태 변경 이력 기록
        await session.execute(
            text("""
                INSERT INTO incident_status_history
                    (incident_id, tenant_id, from_status, to_status, changed_by, reason, changed_at)
                VALUES (:incident_id, :tenant_id, :from_status, :to_status, :changed_by, :reason, :changed_at)
            """),
            {
                "incident_id": incident_id,
                "tenant_id": tenant_id,
                "from_status": current_status,
                "to_status": new_status,
                "changed_by": user_id,
                "reason": payload.reason,
                "changed_at": now,
            },
        )
        await session.commit()

    await write_audit_log(
        tenant_id=tenant_id,
        actor=user_id,
        action="incident.status_transition",
        resource=incident_id,
        metadata={
            "from": current_status,
            "to": new_status,
            "disposition": payload.disposition,
        },
    )

    return {
        "incident_id": incident_id,
        "from_status": current_status,
        "to_status": new_status,
        "disposition": payload.disposition,
        "changed_at": now.isoformat(),
    }


@router.patch("/{incident_id}/assignee")
async def update_assignee(
    incident_id: str,
    payload: AssigneeRequest,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """담당자 지정/해제."""
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])
    user_role = claims.get("role", "analyst")

    # analyst는 자기 자신만 담당자로 지정 가능
    if user_role == "analyst" and payload.assignee_id and payload.assignee_id != user_id:
        raise HTTPException(
            status_code=403,
            detail="analyst는 자기 자신만 담당자로 지정할 수 있습니다",
        )

    async with get_session() as session:
        result = await session.execute(
            text("""
                UPDATE incidents
                SET assignee_id = :assignee_id, updated_at = NOW()
                WHERE incident_id = :incident_id AND tenant_id = :tenant_id
                RETURNING incident_id, assignee_id
            """),
            {
                "incident_id": incident_id,
                "tenant_id": tenant_id,
                "assignee_id": payload.assignee_id,
            },
        )
        row = result.mappings().fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="incident_not_found")
        await session.commit()

    await write_audit_log(
        tenant_id=tenant_id,
        actor=user_id,
        action="incident.assignee_update",
        resource=incident_id,
        metadata={"assignee_id": payload.assignee_id},
    )
    return {"incident_id": incident_id, "assignee_id": payload.assignee_id}


# ============================================================
# 코멘트
# ============================================================

@router.post("/{incident_id}/comments", status_code=201)
async def add_comment(
    incident_id: str,
    payload: CommentRequest,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """코멘트 추가. analyst 이상 가능."""
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])

    async with get_session() as session:
        # 인시던트 존재 확인
        exists = await session.execute(
            text("SELECT 1 FROM incidents WHERE incident_id = :id AND tenant_id = :tid"),
            {"id": incident_id, "tid": tenant_id},
        )
        if not exists.fetchone():
            raise HTTPException(status_code=404, detail="incident_not_found")

        result = await session.execute(
            text("""
                INSERT INTO incident_comments (tenant_id, incident_id, author_id, body)
                VALUES (:tenant_id, :incident_id, :author_id, :body)
                RETURNING id, created_at
            """),
            {
                "tenant_id": tenant_id,
                "incident_id": incident_id,
                "author_id": user_id,
                "body": payload.body,
            },
        )
        row = result.mappings().fetchone()
        await session.commit()

    return {
        "id": str(row["id"]),
        "incident_id": incident_id,
        "author_id": user_id,
        "body": payload.body,
        "created_at": row["created_at"].isoformat(),
    }


@router.get("/{incident_id}/comments")
async def list_comments(
    incident_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """코멘트 목록 조회."""
    tenant_id = claims["tenant_id"]

    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT c.id, c.author_id, c.body, c.created_at, c.updated_at,
                       u.email as author_email
                FROM incident_comments c
                LEFT JOIN users u ON c.author_id = u.user_id
                WHERE c.incident_id = :incident_id AND c.tenant_id = :tenant_id
                ORDER BY c.created_at ASC
                LIMIT :limit
            """),
            {"incident_id": incident_id, "tenant_id": tenant_id, "limit": limit},
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "id": str(r["id"]),
                "author_id": r["author_id"],
                "author_email": r["author_email"],
                "body": r["body"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
            }
            for r in rows
        ]
    }


# ============================================================
# 인시던트 연결 (Links)
# ============================================================

@router.post("/{incident_id}/links", status_code=201)
async def create_link(
    incident_id: str,
    payload: LinkRequest,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """인시던트 간 연결 생성."""
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])

    if incident_id == payload.target_incident_id:
        raise HTTPException(status_code=400, detail="자기 자신과의 연결 불가")

    async with get_session() as session:
        # 대상 인시던트 존재 확인
        exists = await session.execute(
            text("SELECT 1 FROM incidents WHERE incident_id = :id AND tenant_id = :tid"),
            {"id": payload.target_incident_id, "tid": tenant_id},
        )
        if not exists.fetchone():
            raise HTTPException(status_code=404, detail="target_incident_not_found")

        # 중복 링크 방지
        dup = await session.execute(
            text("""
                SELECT 1 FROM incident_links
                WHERE tenant_id = :tenant_id
                  AND source_incident_id = :source_id
                  AND target_incident_id = :target_id
            """),
            {
                "tenant_id": tenant_id,
                "source_id": incident_id,
                "target_id": payload.target_incident_id,
            },
        )
        if dup.fetchone():
            raise HTTPException(status_code=409, detail="이미 연결된 인시던트입니다")

        result = await session.execute(
            text("""
                INSERT INTO incident_links (tenant_id, source_incident_id, target_incident_id, link_type, created_by)
                VALUES (:tenant_id, :source_id, :target_id, :link_type, :created_by)
                RETURNING id, created_at
            """),
            {
                "tenant_id": tenant_id,
                "source_id": incident_id,
                "target_id": payload.target_incident_id,
                "link_type": payload.link_type,
                "created_by": user_id,
            },
        )
        row = result.mappings().fetchone()
        await session.commit()

    return {
        "id": str(row["id"]),
        "source_incident_id": incident_id,
        "target_incident_id": payload.target_incident_id,
        "link_type": payload.link_type,
        "created_at": row["created_at"].isoformat(),
    }


@router.get("/{incident_id}/links")
async def list_links(
    incident_id: str,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """인시던트 연결 목록."""
    tenant_id = claims["tenant_id"]

    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT l.id, l.source_incident_id, l.target_incident_id, l.link_type,
                       l.created_by, l.created_at,
                       i.severity as target_severity, i.status as target_status
                FROM incident_links l
                JOIN incidents i ON l.target_incident_id = i.incident_id
                WHERE l.tenant_id = :tenant_id
                  AND (l.source_incident_id = :incident_id OR l.target_incident_id = :incident_id)
                ORDER BY l.created_at DESC
            """),
            {"tenant_id": tenant_id, "incident_id": incident_id},
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "id": str(r["id"]),
                "source_incident_id": r["source_incident_id"],
                "target_incident_id": r["target_incident_id"],
                "link_type": r["link_type"],
                "target_severity": r["target_severity"],
                "target_status": r["target_status"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
    }


# ============================================================
# 상태 변경 이력
# ============================================================

@router.get("/{incident_id}/history")
async def get_status_history(
    incident_id: str,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """인시던트 상태 변경 이력."""
    tenant_id = claims["tenant_id"]

    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT h.id, h.from_status, h.to_status, h.changed_by,
                       h.reason, h.changed_at, u.email as changed_by_email
                FROM incident_status_history h
                LEFT JOIN users u ON h.changed_by = u.user_id
                WHERE h.incident_id = :incident_id AND h.tenant_id = :tenant_id
                ORDER BY h.changed_at ASC
            """),
            {"incident_id": incident_id, "tenant_id": tenant_id},
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "id": str(r["id"]),
                "from_status": r["from_status"],
                "to_status": r["to_status"],
                "changed_by": r["changed_by"],
                "changed_by_email": r["changed_by_email"],
                "reason": r["reason"],
                "changed_at": r["changed_at"].isoformat() if r["changed_at"] else None,
            }
            for r in rows
        ]
    }


# ============================================================
# Phase 1-D: FP 통계 API
# ============================================================

@router.get("/stats/fp")
async def fp_statistics(
    days: int = Query(default=30, ge=1, le=365),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """룰별 FP 통계. fp_rate 30% 이상 룰에 '임계값 검토 권장' 뱃지."""
    tenant_id = claims["tenant_id"]

    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT
                    primary_rule_id as rule_id,
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE disposition = 'true_positive')  as tp,
                    COUNT(*) FILTER (WHERE disposition = 'false_positive') as fp,
                    COUNT(*) FILTER (WHERE disposition = 'benign')         as benign,
                    COUNT(*) FILTER (WHERE disposition = 'duplicate')      as duplicate,
                    ROUND(
                        COUNT(*) FILTER (WHERE disposition = 'false_positive')::numeric
                        / NULLIF(COUNT(*) FILTER (WHERE disposition IS NOT NULL), 0) * 100, 1
                    ) as fp_rate_pct
                FROM incidents
                WHERE tenant_id = :tenant_id
                  AND created_at > NOW() - (:days * INTERVAL '1 day')
                  AND primary_rule_id IS NOT NULL
                GROUP BY primary_rule_id
                ORDER BY fp_rate_pct DESC NULLS LAST
            """),
            {"tenant_id": tenant_id, "days": days},
        )
        rows = result.mappings().fetchall()

    items = []
    for r in rows:
        fp_rate = float(r["fp_rate_pct"]) if r["fp_rate_pct"] is not None else None
        items.append({
            "rule_id": r["rule_id"],
            "total": r["total"],
            "tp": r["tp"],
            "fp": r["fp"],
            "benign": r["benign"],
            "duplicate": r["duplicate"],
            "fp_rate_pct": fp_rate,
            "review_recommended": fp_rate is not None and fp_rate >= 30.0,
            "data_sufficient": int(r["total"]) >= 30,
        })

    return {"items": items, "days": days}


# ============================================================
# Phase 4-C: 시계열 집계 API
# ============================================================

_ALLOWED_INTERVALS = {"1h", "1d", "1w"}


@router.get("/stats/timeseries")
async def timeseries_stats(
    hours: int = Query(default=24, ge=1, le=720),
    interval: str = Query(default="1h"),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """인시던트 시계열 집계. interval: 1h / 1d / 1w."""
    tenant_id = claims["tenant_id"]

    # interval 서버 사이드 enum 검증 (SQL 직접 삽입 금지)
    if interval not in _ALLOWED_INTERVALS:
        raise HTTPException(
            status_code=400,
            detail=f"interval은 {_ALLOWED_INTERVALS} 중 하나여야 합니다",
        )

    trunc_map = {"1h": "hour", "1d": "day", "1w": "week"}
    trunc_unit = trunc_map[interval]

    async with get_session() as session:
        result = await session.execute(
            text(f"""
                SELECT
                    date_trunc('{trunc_unit}', created_at) AS bucket,
                    severity,
                    COUNT(*) AS count
                FROM incidents
                WHERE tenant_id = :tenant_id
                  AND created_at > NOW() - (:hours * INTERVAL '1 hour')
                GROUP BY bucket, severity
                ORDER BY bucket
            """),
            {"tenant_id": tenant_id, "hours": hours},
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "bucket": r["bucket"].isoformat() if r["bucket"] else None,
                "severity": r["severity"],
                "count": r["count"],
            }
            for r in rows
        ],
        "hours": hours,
        "interval": interval,
    }

"""Phase 2-A: 룰 관리 플랫폼 API.

설계서 2-A: 룰 배포 생명주기 (Draft→Validate→Dry-run→Confirm→Active→Rollback)
코드 수정 없이 운영자가 룰을 관리.

엔드포인트:
  GET    /rules                    - 룰 목록
  POST   /rules                    - 룰 생성 (Draft)
  GET    /rules/{rule_id}          - 룰 상세
  PATCH  /rules/{rule_id}          - 룰 수정
  POST   /rules/{rule_id}/dry-run  - Dry-run 실행
  POST   /rules/{rule_id}/activate - Active 전환 (관리자 승인)
  POST   /rules/{rule_id}/disable  - 비활성화
  POST   /rules/{rule_id}/rollback - 이전 버전 롤백
  GET    /rules/{rule_id}/versions - 버전 이력
  GET    /rules/stats/fp           - FP 통계
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.audit import write_audit_log
from app.iam.rbac_v2 import require_role

router = APIRouter(prefix="/rules", tags=["rule-management"])

# ============================================================
# 상태 전이
# ============================================================

_VALID_RULE_TRANSITIONS: dict[str, list[str]] = {
    "draft":    ["active", "disabled"],
    "active":   ["disabled", "draft"],
    "disabled": ["draft", "active"],
    "archived": [],
}

_RULE_STATUS_VALUES = {"draft", "active", "disabled", "archived"}


# ============================================================
# Request 모델
# ============================================================

class RuleCreateRequest(BaseModel):
    rule_id: str = Field(..., pattern=r"^[A-Z]+-[0-9]{3}$", description="예: AUTH-001")
    display_name: str = Field(..., min_length=1, max_length=100)
    source: str = Field(..., description="auth.log / nginx / auditd 등")
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    window_seconds: Optional[int] = Field(None, ge=10, le=86400)
    threshold: Optional[int] = Field(None, ge=1)
    severity: Optional[str] = Field(None, pattern="^(info|medium|high|critical)$")
    scope: Optional[dict] = None
    config: Optional[dict] = None
    change_reason: Optional[str] = None


class RuleUpdateRequest(BaseModel):
    display_name: Optional[str] = Field(None, min_length=1, max_length=100)
    window_seconds: Optional[int] = Field(None, ge=10, le=86400)
    threshold: Optional[int] = Field(None, ge=1)
    severity: Optional[str] = Field(None, pattern="^(info|medium|high|critical)$")
    scope: Optional[dict] = None
    config: Optional[dict] = None
    enabled: Optional[bool] = None
    change_reason: Optional[str] = None


class ActivateRequest(BaseModel):
    change_reason: str = Field(..., min_length=1)


class RollbackRequest(BaseModel):
    target_version: int = Field(..., ge=1)
    reason: str = Field(..., min_length=1)


# ============================================================
# 룰 목록/상세
# ============================================================

@router.get("")
async def list_rules(
    status: Optional[str] = Query(None),
    tenant_id: Optional[str] = Query(None),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """룰 목록. analyst 이상 열람."""
    effective_tenant = tenant_id or claims.get("tenant_id")

    async with get_session() as session:
        where_clauses = ["1=1"]
        params: dict = {}

        if status and status in _RULE_STATUS_VALUES:
            where_clauses.append("status = :status")
            params["status"] = status

        if effective_tenant:
            where_clauses.append("(tenant_id = :tenant_id OR tenant_id IS NULL)")
            params["tenant_id"] = effective_tenant

        result = await session.execute(
            text(f"""
                SELECT rule_id, display_name, name, source, mitre_tactic, mitre_technique,
                       enabled, status, severity, window_seconds, threshold,
                       scope, config, version, tenant_id,
                       created_by, updated_at, dry_run_result
                FROM detection_rules
                WHERE {' AND '.join(where_clauses)}
                ORDER BY rule_id
            """),
            params,
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "rule_id": r["rule_id"],
                "name": r["display_name"] or r["name"],
                "display_name": r["display_name"] or r["name"],
                "source": r["source"],
                "mitre_tactic": r["mitre_tactic"],
                "mitre_technique": r["mitre_technique"],
                "enabled": r["enabled"],
                "status": r["status"],
                "severity": r["severity"],
                "window_seconds": r["window_seconds"],
                "threshold": r["threshold"],
                "scope": r["scope"],
                "config": r["config"],
                "version": r["version"],
                "tenant_id": r["tenant_id"],
                "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
                "dry_run_result": r["dry_run_result"],
            }
            for r in rows
        ]
    }


@router.get("/{rule_id_path}")
async def get_rule(
    rule_id_path: str,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """룰 상세."""
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT * FROM detection_rules
                WHERE rule_id = :rule_id
            """),
            {"rule_id": rule_id_path},
        )
        row = result.mappings().fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="rule_not_found")

    return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in dict(row).items()}


# ============================================================
# 룰 생성 (Draft)
# ============================================================

@router.post("", status_code=201)
async def create_rule(
    payload: RuleCreateRequest,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """룰 생성. Draft 상태로 시작."""
    user_id = str(claims["sub"])
    tenant_id = claims.get("tenant_id")
    now = datetime.now(timezone.utc)

    async with get_session() as session:
        # 중복 확인
        exists = await session.execute(
            text("SELECT 1 FROM detection_rules WHERE rule_id = :rule_id"),
            {"rule_id": payload.rule_id},
        )
        if exists.fetchone():
            raise HTTPException(status_code=409, detail="rule_id_already_exists")

        scope_json = json.dumps(payload.scope or {})
        config_json = json.dumps(payload.config or {})

        await session.execute(
            text("""
                INSERT INTO detection_rules
                    (rule_id, display_name, name, source, mitre_tactic, mitre_technique,
                     window_seconds, threshold, severity, scope, config,
                     status, enabled, version, tenant_id, created_by, updated_at)
                VALUES
                    (:rule_id, :display_name, :display_name, :source, :mitre_tactic, :mitre_technique,
                     :window_seconds, :threshold, :severity, CAST(:scope AS JSONB), CAST(:config AS JSONB),
                     'draft', false, 1, :tenant_id, :created_by, :now)
            """),
            {
                "rule_id": payload.rule_id,
                "display_name": payload.display_name,
                "source": payload.source,
                "mitre_tactic": payload.mitre_tactic,
                "mitre_technique": payload.mitre_technique,
                "window_seconds": payload.window_seconds,
                "threshold": payload.threshold,
                "severity": payload.severity,
                "scope": scope_json,
                "config": config_json,
                "tenant_id": tenant_id,
                "created_by": user_id,
                "now": now,
            },
        )

        # 버전 스냅샷 저장
        await _save_version_snapshot(
            session, payload.rule_id, tenant_id, 1, payload.model_dump(),
            user_id, payload.change_reason or "Initial draft", now
        )

        await session.commit()

    await write_audit_log(
        tenant_id=tenant_id or "system",
        actor=user_id,
        action="rule.create",
        resource=payload.rule_id,
        metadata={"status": "draft"},
    )

    return {"rule_id": payload.rule_id, "status": "draft", "version": 1}


# ============================================================
# 룰 수정
# ============================================================

@router.patch("/{rule_id_path}")
async def update_rule(
    rule_id_path: str,
    payload: RuleUpdateRequest,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """룰 수정. Active 상태의 룰 수정은 draft로 되돌림."""
    user_id = str(claims["sub"])
    tenant_id = claims.get("tenant_id")
    now = datetime.now(timezone.utc)

    async with get_session() as session:
        row = await session.execute(
            text("SELECT * FROM detection_rules WHERE rule_id = :rule_id"),
            {"rule_id": rule_id_path},
        )
        rule = row.mappings().fetchone()
        if not rule:
            raise HTTPException(status_code=404, detail="rule_not_found")

        set_clauses = ["updated_at = :now", "version = version + 1"]
        params = {"rule_id": rule_id_path, "now": now}

        if payload.display_name is not None:
            set_clauses.extend(["display_name = :display_name", "name = :display_name"])
            params["display_name"] = payload.display_name
        if payload.window_seconds is not None:
            set_clauses.append("window_seconds = :window_seconds")
            params["window_seconds"] = payload.window_seconds
        if payload.threshold is not None:
            set_clauses.append("threshold = :threshold")
            params["threshold"] = payload.threshold
        if payload.severity is not None:
            set_clauses.append("severity = :severity")
            params["severity"] = payload.severity
        if payload.scope is not None:
            set_clauses.append("scope = CAST(:scope AS JSONB)")
            params["scope"] = json.dumps(payload.scope)
        if payload.config is not None:
            set_clauses.append("config = CAST(:config AS JSONB)")
            params["config"] = json.dumps(payload.config)
        if payload.enabled is not None:
            set_clauses.append("enabled = :enabled")
            params["enabled"] = payload.enabled

        # Active 룰 수정 시 draft로 전환 (재승인 필요)
        if rule["status"] == "active":
            set_clauses.append("status = 'draft'")
            set_clauses.append("dry_run_result = NULL")

        await session.execute(
            text(f"""
                UPDATE detection_rules
                SET {', '.join(set_clauses)}
                WHERE rule_id = :rule_id
                RETURNING version
            """),
            params,
        )

        new_version = rule["version"] + 1
        await _save_version_snapshot(
            session, rule_id_path, tenant_id, new_version, payload.model_dump(exclude_none=True),
            user_id, payload.change_reason or "Rule updated", now
        )

        await session.commit()

    return {"rule_id": rule_id_path, "version": new_version, "updated_at": now.isoformat()}


# ============================================================
# Dry-run
# ============================================================

@router.post("/{rule_id_path}/dry-run")
async def dry_run_rule(
    rule_id_path: str,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """Dry-run: 최근 1시간 로그에 룰 적용 - 예상 탐지 건수 확인.

    설계서 2-A-1 주의사항:
    - 초기 단계에서 estimated_false_positive_rate 계산 불가
    - 대신 estimated_signal_volume과 matched_sample_count 표시
    - FP rate는 disposition 데이터 30건 이상 쌓인 후 추정 가능
    """
    tenant_id = claims.get("tenant_id")
    tenant_filter = "AND tenant_id = :tenant_id" if tenant_id else ""

    async with get_session() as session:
        rule_row = await session.execute(
            text("SELECT * FROM detection_rules WHERE rule_id = :rule_id"),
            {"rule_id": rule_id_path},
        )
        rule = rule_row.mappings().fetchone()
        if not rule:
            raise HTTPException(status_code=404, detail="rule_not_found")

        # 최근 1시간 시그널 중 이 룰로 탐지된 건수 계산
        signal_count_result = await session.execute(
            text(f"""
                SELECT COUNT(*) as matched_count
                FROM signals
                WHERE rule_id = :rule_id
                  AND detected_at > NOW() - INTERVAL '1 hour'
                  {tenant_filter}
            """),
            {"rule_id": rule_id_path, "tenant_id": tenant_id},
        )
        matched_count = signal_count_result.scalar() or 0

        # disposition 데이터 충분한지 확인
        disposition_count_result = await session.execute(
            text(f"""
                SELECT COUNT(*) as dcount
                FROM incidents
                WHERE primary_rule_id = :rule_id
                  AND disposition IS NOT NULL
                  {tenant_filter}
            """),
            {"rule_id": rule_id_path, "tenant_id": tenant_id},
        )
        disposition_count = disposition_count_result.scalar() or 0
        data_sufficient_for_fp = disposition_count >= 30

        # 예상 볼륨 (최근 1시간 × 24 = 일일 예상)
        estimated_daily_volume = matched_count * 24

        dry_run_result = {
            "matched_sample_count": matched_count,
            "estimated_daily_volume": estimated_daily_volume,
            "disposition_count": disposition_count,
            "data_sufficient_for_fp": data_sufficient_for_fp,
            "fp_rate_available": data_sufficient_for_fp,
            "fp_rate": None,
            "review_recommended": False,
            "run_at": datetime.now(timezone.utc).isoformat(),
            "window": "1h",
        }

        if data_sufficient_for_fp:
            # FP rate 계산
            fp_rate_result = await session.execute(
                text(f"""
                    SELECT
                        ROUND(
                            COUNT(*) FILTER (WHERE disposition = 'false_positive')::numeric
                            / NULLIF(COUNT(*) FILTER (WHERE disposition IS NOT NULL), 0) * 100, 1
                        ) as fp_rate
                    FROM incidents
                    WHERE primary_rule_id = :rule_id
                      {tenant_filter}
                """),
                {"rule_id": rule_id_path, "tenant_id": tenant_id},
            )
            fp_rate = fp_rate_result.scalar()
            fp_rate_value = float(fp_rate) if fp_rate else 0.0
            dry_run_result["estimated_false_positive_rate"] = fp_rate_value
            dry_run_result["fp_rate"] = fp_rate_value
            dry_run_result["review_recommended"] = fp_rate_value >= 30.0

        # dry_run_result를 DB에 저장 및 상태를 'dry_run_complete'로 표시
        await session.execute(
            text("""
                UPDATE detection_rules
                SET dry_run_result = CAST(:result AS JSONB), updated_at = NOW()
                WHERE rule_id = :rule_id
            """),
            {"rule_id": rule_id_path, "result": json.dumps(dry_run_result)},
        )
        await session.commit()

    return dry_run_result


# ============================================================
# 활성화 (관리자 승인)
# ============================================================

@router.post("/{rule_id_path}/activate")
async def activate_rule(
    rule_id_path: str,
    payload: ActivateRequest,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """룰 활성화. Dry-run 완료 후 관리자 승인 필요."""
    user_id = str(claims["sub"])
    tenant_id = claims.get("tenant_id")
    now = datetime.now(timezone.utc)

    async with get_session() as session:
        row = await session.execute(
            text("SELECT status, dry_run_result, version FROM detection_rules WHERE rule_id = :rule_id"),
            {"rule_id": rule_id_path},
        )
        rule = row.mappings().fetchone()
        if not rule:
            raise HTTPException(status_code=404, detail="rule_not_found")

        # dry_run 없이 활성화 불가 (단, 기존 active 룰은 예외)
        if rule["status"] == "draft" and not rule["dry_run_result"]:
            raise HTTPException(
                status_code=400,
                detail="Dry-run을 먼저 실행해야 합니다",
            )

        await session.execute(
            text("""
                UPDATE detection_rules
                SET status = 'active', enabled = true, updated_at = :now
                WHERE rule_id = :rule_id
            """),
            {"rule_id": rule_id_path, "now": now},
        )

        new_version = rule["version"] + 1
        await _save_version_snapshot(
            session, rule_id_path, tenant_id, new_version,
            {"status": "active", "enabled": True},
            user_id, payload.change_reason, now
        )
        await session.commit()

    await write_audit_log(
        tenant_id=tenant_id or "system",
        actor=user_id,
        action="rule.activate",
        resource=rule_id_path,
        metadata={"reason": payload.change_reason},
    )
    return {"rule_id": rule_id_path, "status": "active"}


@router.post("/{rule_id_path}/disable")
async def disable_rule(
    rule_id_path: str,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """룰 비활성화."""
    user_id = str(claims["sub"])
    async with get_session() as session:
        result = await session.execute(
            text("""
                UPDATE detection_rules
                SET status = 'disabled', enabled = false, updated_at = NOW()
                WHERE rule_id = :rule_id
                RETURNING rule_id
            """),
            {"rule_id": rule_id_path},
        )
        if not result.fetchone():
            raise HTTPException(status_code=404, detail="rule_not_found")
        await session.commit()

    return {"rule_id": rule_id_path, "status": "disabled"}


# ============================================================
# 롤백
# ============================================================

@router.post("/{rule_id_path}/rollback")
async def rollback_rule(
    rule_id_path: str,
    payload: RollbackRequest,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """이전 버전으로 즉시 롤백."""
    user_id = str(claims["sub"])
    tenant_id = claims.get("tenant_id")
    now = datetime.now(timezone.utc)

    async with get_session() as session:
        # 대상 버전 스냅샷 조회
        ver_row = await session.execute(
            text("""
                SELECT snapshot, version FROM detection_rule_versions
                WHERE rule_id = :rule_id AND version = :version
                ORDER BY changed_at DESC
                LIMIT 1
            """),
            {"rule_id": rule_id_path, "version": payload.target_version},
        )
        ver = ver_row.mappings().fetchone()
        if not ver:
            raise HTTPException(status_code=404, detail="version_not_found")

        snapshot = ver["snapshot"]
        if isinstance(snapshot, str):
            snapshot = json.loads(snapshot)

        # 현재 버전 조회
        cur_row = await session.execute(
            text("SELECT version FROM detection_rules WHERE rule_id = :rule_id"),
            {"rule_id": rule_id_path},
        )
        cur = cur_row.fetchone()
        if not cur:
            raise HTTPException(status_code=404, detail="rule_not_found")

        new_version = cur[0] + 1

        # 롤백 적용 (핵심 필드만)
        await session.execute(
            text("""
                UPDATE detection_rules
                SET window_seconds = :window_seconds,
                    threshold = :threshold,
                    severity = :severity,
                    status = 'active',
                    enabled = true,
                    version = :new_version,
                    updated_at = :now
                WHERE rule_id = :rule_id
            """),
            {
                "rule_id": rule_id_path,
                "window_seconds": snapshot.get("window_seconds"),
                "threshold": snapshot.get("threshold"),
                "severity": snapshot.get("severity"),
                "new_version": new_version,
                "now": now,
            },
        )

        await _save_version_snapshot(
            session, rule_id_path, tenant_id, new_version,
            {"rollback_to": payload.target_version},
            user_id, f"Rollback to v{payload.target_version}: {payload.reason}", now
        )
        await session.commit()

    await write_audit_log(
        tenant_id=tenant_id or "system",
        actor=user_id,
        action="rule.rollback",
        resource=rule_id_path,
        metadata={"target_version": payload.target_version, "reason": payload.reason},
    )
    return {"rule_id": rule_id_path, "rolled_back_to": payload.target_version, "new_version": new_version}


@router.get("/{rule_id_path}/versions")
async def list_versions(
    rule_id_path: str,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """룰 버전 이력."""
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT v.id, v.version, v.changed_by, v.changed_at, v.change_reason,
                       u.email as changed_by_email
                FROM detection_rule_versions v
                LEFT JOIN users u ON v.changed_by = u.user_id
                WHERE v.rule_id = :rule_id
                ORDER BY v.version DESC
            """),
            {"rule_id": rule_id_path},
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "id": str(r["id"]),
                "version": r["version"],
                "changed_by": r["changed_by"],
                "changed_by_email": r["changed_by_email"],
                "changed_at": r["changed_at"].isoformat() if r["changed_at"] else None,
                "change_reason": r["change_reason"],
            }
            for r in rows
        ]
    }


# ============================================================
# 헬퍼
# ============================================================

async def _save_version_snapshot(
    session, rule_id: str, tenant_id, version: int,
    snapshot: dict, changed_by: str, reason: str, changed_at: datetime
) -> None:
    """버전 스냅샷 저장."""
    await session.execute(
        text("""
            INSERT INTO detection_rule_versions
                (rule_id, tenant_id, version, snapshot, changed_by, changed_at, change_reason)
            VALUES
                (:rule_id, :tenant_id, :version, CAST(:snapshot AS JSONB), :changed_by, :changed_at, :reason)
        """),
        {
            "rule_id": rule_id,
            "tenant_id": tenant_id,
            "version": version,
            "snapshot": json.dumps(snapshot, default=str),
            "changed_by": changed_by,
            "changed_at": changed_at,
            "reason": reason,
        },
    )

"""
SIGMA 룰 관리 API 라우터.
v4.0 설계서 §8 참조.

엔드포인트:
  POST /api/v1/sigma/sync           — SigmaHQ GitHub에서 룰 수동 동기화 (owner 전용)
  GET  /api/v1/sigma/rules          — 동기화된 SIGMA 룰 목록 조회
  GET  /api/v1/sigma/rules/{rule_id} — 특정 SIGMA 룰 상세 조회
  DELETE /api/v1/sigma/rules/{rule_id} — SIGMA 룰 비활성화
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text

from app.config import get_settings
from app.db.connection import get_session
from app.iam.rbac_v2 import require_any_role, require_role

router = APIRouter(prefix="/api/v1/sigma", tags=["sigma"])
log = logging.getLogger(__name__)

settings = get_settings()


# ─── DB upsert 함수 ───────────────────────────────────────────────────────────

async def db_upsert_sigma_rule(infrared_rule) -> None:
    """SIGMA 룰을 sigma_rules 테이블에 upsert."""
    import json
    async with get_session() as session:
        await session.execute(text("""
            INSERT INTO sigma_rules (
                rule_id, display_name, source, severity,
                mitre_techniques, base_confidence,
                sigma_id, sigma_status, sigma_title,
                logsource, tags, is_active, synced_at
            ) VALUES (
                :rule_id, :display_name, :source, :severity,
                :mitre_techniques, :base_confidence,
                :sigma_id, :sigma_status, :sigma_title,
                :logsource, :tags, true, NOW()
            )
            ON CONFLICT (rule_id) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                severity = EXCLUDED.severity,
                mitre_techniques = EXCLUDED.mitre_techniques,
                base_confidence = EXCLUDED.base_confidence,
                sigma_status = EXCLUDED.sigma_status,
                logsource = EXCLUDED.logsource,
                tags = EXCLUDED.tags,
                synced_at = NOW()
        """), {
            "rule_id": infrared_rule.rule_id,
            "display_name": infrared_rule.display_name,
            "source": infrared_rule.source,
            "severity": infrared_rule.severity,
            "mitre_techniques": json.dumps(infrared_rule.mitre_techniques),
            "base_confidence": infrared_rule.base_confidence,
            "sigma_id": infrared_rule.metadata.get("sigma_id", ""),
            "sigma_status": infrared_rule.metadata.get("sigma_status", ""),
            "sigma_title": infrared_rule.metadata.get("sigma_title", ""),
            "logsource": json.dumps(infrared_rule.metadata.get("logsource", {})),
            "tags": json.dumps(infrared_rule.metadata.get("tags", [])),
        })
        await session.commit()


# ─── POST /api/v1/sigma/sync ─────────────────────────────────────────────────

@router.post("/sync")
async def trigger_sigma_sync(
    dry_run: bool = False,
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """
    SigmaHQ GitHub에서 안정(stable) 룰 동기화.
    dry_run=true 이면 DB에 저장하지 않고 파싱 결과만 반환.
    """
    if not settings.sigma_sync_enabled and not dry_run:
        raise HTTPException(
            status_code=403,
            detail="SIGMA 동기화가 비활성화되어 있습니다. SIGMA_SYNC_ENABLED=true 설정 필요.",
        )

    from app.workers.sigma.syncer import sync_sigma_rules

    if dry_run:
        result = sync_sigma_rules(db_upsert_fn=None)
    else:
        import asyncio

        def sync_upsert(rule):
            """동기 래퍼 — syncer에서 호출용"""
            try:
                asyncio.get_event_loop().run_until_complete(db_upsert_sigma_rule(rule))
            except RuntimeError:
                # 이미 이벤트 루프가 실행 중인 경우
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, db_upsert_sigma_rule(rule))
                    future.result()

        result = sync_sigma_rules(db_upsert_fn=sync_upsert)

    return {
        **result,
        "dry_run": dry_run,
        "message": "SIGMA 룰 동기화 완료" if not dry_run else "Dry-run 완료 (DB 저장 안 함)",
    }


# ─── GET /api/v1/sigma/rules ─────────────────────────────────────────────────

@router.get("/rules")
async def list_sigma_rules(
    severity: str | None = None,
    status: str | None = None,
    limit: int = 100,
    claims: dict = Depends(require_any_role(*["analyst", "security_manager", "owner"])),
) -> dict:
    """동기화된 SIGMA 룰 목록 조회."""
    conditions = ["is_active = true"]
    params: dict[str, Any] = {"limit": min(limit, 500)}

    if severity:
        conditions.append("severity = :severity")
        params["severity"] = severity.upper()
    if status:
        conditions.append("sigma_status = :status")
        params["status"] = status

    where = " AND ".join(conditions)

    try:
        async with get_session() as session:
            result = await session.execute(text(f"""
                SELECT
                    rule_id, display_name, severity, source,
                    sigma_status, base_confidence, mitre_techniques,
                    tags, synced_at
                FROM sigma_rules
                WHERE {where}
                ORDER BY severity DESC, synced_at DESC
                LIMIT :limit
            """), params)
            rows = result.fetchall()
    except Exception as e:
        log.error(f"SIGMA rules query failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "count": len(rows),
        "rules": [
            {
                "rule_id": r.rule_id,
                "display_name": r.display_name,
                "severity": r.severity,
                "source": r.source,
                "sigma_status": r.sigma_status,
                "base_confidence": float(r.base_confidence or 0.65),
                "mitre_techniques": r.mitre_techniques,
                "tags": r.tags,
                "synced_at": r.synced_at.isoformat() if r.synced_at else None,
            }
            for r in rows
        ],
    }


# ─── GET /api/v1/sigma/rules/{rule_id} ───────────────────────────────────────

@router.get("/rules/{rule_id}")
async def get_sigma_rule(
    rule_id: str,
    claims: dict = Depends(require_any_role(*["analyst", "security_manager", "owner"])),
) -> dict:
    """특정 SIGMA 룰 상세 조회."""
    try:
        async with get_session() as session:
            result = await session.execute(text("""
                SELECT * FROM sigma_rules WHERE rule_id = :rule_id
            """), {"rule_id": rule_id})
            row = result.fetchone()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if not row:
        raise HTTPException(status_code=404, detail=f"SIGMA 룰 '{rule_id}'을(를) 찾을 수 없습니다.")

    mapping = dict(row._mapping)
    if mapping.get("synced_at"):
        mapping["synced_at"] = mapping["synced_at"].isoformat()
    return mapping


# ─── DELETE /api/v1/sigma/rules/{rule_id} ────────────────────────────────────

@router.delete("/rules/{rule_id}")
async def disable_sigma_rule(
    rule_id: str,
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """SIGMA 룰 비활성화 (삭제하지 않고 is_active=false)."""
    try:
        async with get_session() as session:
            result = await session.execute(text("""
                UPDATE sigma_rules SET is_active = false
                WHERE rule_id = :rule_id
                RETURNING rule_id
            """), {"rule_id": rule_id})
            row = result.fetchone()
            await session.commit()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if not row:
        raise HTTPException(status_code=404, detail=f"SIGMA 룰 '{rule_id}'을(를) 찾을 수 없습니다.")

    return {"status": "disabled", "rule_id": rule_id}


# ─────────────────────────────────────────────────────────────────────────────
# SIGMA 마켓플레이스 API  (v4 SIGMA Marketplace UI 지원)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/marketplace")
async def list_marketplace_rules(
    category: str = "",
    level: str = "",
    product: str = "",
    keyword: str = "",
    page: int = 1,
    page_size: int = 20,
    claims: dict = Depends(require_any_role),
) -> dict:
    """
    마켓플레이스 SIGMA 룰 목록 조회.

    sigma_rules 테이블에서 다양한 필터 조건으로 검색하고,
    활성화 상태(detection_rules 테이블과 JOIN)를 함께 반환한다.
    """
    tenant_id = claims.get("tenant_id", "")
    filters: list[str] = []
    params: dict = {"tenant_id": tenant_id, "offset": (page - 1) * page_size, "limit": page_size}

    if category:
        filters.append("sr.logsource->>'category' ILIKE :category")
        params["category"] = f"%{category}%"
    if level:
        filters.append("sr.severity = :level")
        params["level"] = level
    if product:
        filters.append("sr.logsource->>'product' ILIKE :product")
        params["product"] = f"%{product}%"
    if keyword:
        filters.append("(sr.sigma_title ILIKE :kw OR sr.display_name ILIKE :kw)")
        params["kw"] = f"%{keyword}%"

    where_clause = ("WHERE " + " AND ".join(filters)) if filters else ""

    sql_count = f"""
        SELECT COUNT(*) AS total
        FROM sigma_rules sr
        {where_clause}
    """
    sql_rows = f"""
        SELECT
            sr.rule_id            AS sigma_rule_id,
            sr.sigma_id,
            sr.sigma_title        AS title,
            sr.display_name,
            sr.severity           AS level,
            sr.sigma_status       AS status,
            sr.logsource,
            sr.tags,
            sr.synced_at          AS last_synced,
            sr.is_active,
            dr.rule_id            AS ir_rule_id,
            (dr.rule_id IS NOT NULL AND dr.is_active = true)::bool AS is_activated
        FROM sigma_rules sr
        LEFT JOIN detection_rules dr
            ON dr.sigma_source_id = sr.sigma_id
            AND dr.tenant_id = :tenant_id
            AND dr.is_active = true
        {where_clause}
        ORDER BY sr.severity DESC, sr.sigma_title
        LIMIT :limit OFFSET :offset
    """

    async with get_session() as session:
        total_row = (await session.execute(text(sql_count), params)).fetchone()
        total = int(total_row[0]) if total_row else 0

        rows = (await session.execute(text(sql_rows), params)).fetchall()

    rules = []
    for r in rows:
        logsource = r.logsource or {}
        rules.append({
            "id": str(r.sigma_rule_id),
            "sigma_rule_id": str(r.sigma_rule_id),
            "title": r.title or r.display_name or "",
            "description": r.display_name or "",
            "status": r.status or "experimental",
            "level": r.level or "medium",
            "category": logsource.get("category", ""),
            "product": logsource.get("product", "generic"),
            "service": logsource.get("service", ""),
            "tags": r.tags or [],
            "author": "SigmaHQ Community",
            "date": (r.last_synced.date().isoformat() if r.last_synced else ""),
            "ir_rule_id": str(r.ir_rule_id) if r.ir_rule_id else None,
            "is_activated": bool(r.is_activated),
            "last_synced": r.last_synced.isoformat() if r.last_synced else None,
        })

    import math
    return {
        "rules": rules,
        "total": total,
        "page": page,
        "pages": math.ceil(total / page_size) if total else 1,
    }


@router.get("/sync/status")
async def get_sync_status(
    claims: dict = Depends(require_any_role),
) -> dict:
    """SIGMA 동기화 상태 조회."""
    async with get_session() as session:
        row = await session.execute(text("""
            SELECT
                MAX(synced_at)          AS last_sync,
                COUNT(*)                AS total_rules,
                SUM(CASE WHEN is_active THEN 1 ELSE 0 END) AS activated_rules
            FROM sigma_rules
        """))
        r = row.fetchone()

    return {
        "last_sync": r.last_sync.isoformat() if r and r.last_sync else None,
        "total_rules": int(r.total_rules) if r else 0,
        "activated_rules": int(r.activated_rules) if r else 0,
        "sync_in_progress": False,
        "next_scheduled_sync": None,
    }


@router.get("/preview/{sigma_rule_id}")
async def preview_sigma_rule(
    sigma_rule_id: str,
    claims: dict = Depends(require_any_role),
) -> dict:
    """SIGMA 룰의 InfraRed 변환 결과와 원본 YAML을 미리보기로 반환한다."""
    async with get_session() as session:
        row = (await session.execute(text("""
            SELECT rule_id, sigma_title, display_name, severity, logsource, tags, raw_yaml
            FROM sigma_rules
            WHERE rule_id::text = :rid OR sigma_id = :rid
        """), {"rid": sigma_rule_id})).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="SIGMA 룰을 찾을 수 없습니다")

    ir_rule = {
        "rule_id": str(row.rule_id),
        "title": row.sigma_title or row.display_name,
        "severity": row.severity,
        "logsource": row.logsource or {},
        "tags": row.tags or [],
        "condition": "sigma_auto_converted",
        "status": "draft",
    }

    return {
        "ir_rule": ir_rule,
        "yaml": row.raw_yaml or f"# SIGMA YAML not stored\ntitle: {row.sigma_title}\n",
    }


@router.post("/activate/{sigma_rule_id}")
async def activate_sigma_marketplace_rule(
    sigma_rule_id: str,
    claims: dict = Depends(require_role("admin")),
) -> dict:
    """SIGMA 마켓플레이스 룰을 InfraRed 탐지 엔진에 활성화한다."""
    import uuid
    tenant_id = claims.get("tenant_id", "")

    async with get_session() as session:
        sigma_row = (await session.execute(text("""
            SELECT rule_id, sigma_id, sigma_title, display_name, severity, logsource, tags
            FROM sigma_rules WHERE rule_id::text = :rid OR sigma_id = :rid
        """), {"rid": sigma_rule_id})).fetchone()

        if not sigma_row:
            raise HTTPException(status_code=404, detail="SIGMA 룰을 찾을 수 없습니다")

        # 이미 활성화된 경우 기존 IR 룰 ID 반환
        existing = (await session.execute(text("""
            SELECT rule_id FROM detection_rules
            WHERE sigma_source_id = :sigma_id AND tenant_id = :tid AND is_active = true
        """), {"sigma_id": sigma_row.sigma_id, "tid": tenant_id})).fetchone()

        if existing:
            return {"ok": True, "ir_rule_id": str(existing.rule_id), "message": "이미 활성화되어 있습니다"}

        # 새 IR 룰 생성
        new_rule_id = uuid.uuid4()
        await session.execute(text("""
            INSERT INTO detection_rules (
                rule_id, tenant_id, display_name, source, severity,
                mitre_techniques, base_confidence, is_active,
                sigma_source_id, version, created_at, updated_at
            ) VALUES (
                :rule_id, :tenant_id, :display_name, 'sigma', :severity,
                :mitre, 0.75, true,
                :sigma_id, 1, NOW(), NOW()
            )
        """), {
            "rule_id": new_rule_id,
            "tenant_id": tenant_id,
            "display_name": sigma_row.sigma_title or sigma_row.display_name,
            "severity": sigma_row.severity or "medium",
            "mitre": sigma_row.tags or [],
            "sigma_id": sigma_row.sigma_id,
        })
        await session.commit()

    log.info("SIGMA 룰 활성화: sigma_id=%s ir_rule_id=%s tenant=%s",
             sigma_row.sigma_id, new_rule_id, tenant_id)
    return {"ok": True, "ir_rule_id": str(new_rule_id)}


@router.post("/deactivate/{sigma_rule_id}")
async def deactivate_sigma_marketplace_rule(
    sigma_rule_id: str,
    claims: dict = Depends(require_role("admin")),
) -> dict:
    """SIGMA 마켓플레이스 룰을 비활성화한다."""
    tenant_id = claims.get("tenant_id", "")

    async with get_session() as session:
        sigma_row = (await session.execute(text("""
            SELECT sigma_id FROM sigma_rules
            WHERE rule_id::text = :rid OR sigma_id = :rid
        """), {"rid": sigma_rule_id})).fetchone()

        if not sigma_row:
            raise HTTPException(status_code=404, detail="SIGMA 룰을 찾을 수 없습니다")

        await session.execute(text("""
            UPDATE detection_rules
            SET is_active = false, updated_at = NOW()
            WHERE sigma_source_id = :sigma_id AND tenant_id = :tid
        """), {"sigma_id": sigma_row.sigma_id, "tid": tenant_id})
        await session.commit()

    return {"ok": True}

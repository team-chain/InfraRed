"""
First-Execution Alert API (EXEC-FIRST-001/002)
==============================================
엔드포인트:
    GET    /api/v1/assets/{asset_id}/binary-hashes           — 학습된 해시 목록 조회
    POST   /api/v1/assets/{asset_id}/binary-hashes/rebuild   — 베이스라인 재구축 요청
    DELETE /api/v1/assets/{asset_id}/binary-hashes/{sha256}  — 특정 해시 허용 등록 제거

설계서: InfraRed_v8_보안심화_설계서.md §5.3 / §12
"""
from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from app.db.connection import get_pool
from app.iam.rbac_v2 import require_role
from app.workers.detection.first_execution import (
    FirstExecutionBaselineBuilder,
)

router = APIRouter(prefix="/api/v1/assets", tags=["first-execution"])
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# GET /api/v1/assets/{asset_id}/binary-hashes
# ---------------------------------------------------------------------------

@router.get("/{asset_id}/binary-hashes")
async def list_binary_hashes(
    asset_id: str,
    limit: int = 100,
    offset: int = 0,
    claims: dict = Depends(require_role("analyst")),
    pool=Depends(get_pool),
) -> dict:
    """
    이 에셋(테넌트)에서 학습된 known_binary_hashes 목록 반환.

    - limit/offset으로 페이징
    - 최신 등록 순 정렬
    """
    tenant_id = claims.get("tenant_id", "")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id가 없습니다")

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT sha256, exe_path, first_seen
            FROM known_binary_hashes
            WHERE tenant_id = $1
            ORDER BY first_seen DESC
            LIMIT $2 OFFSET $3
            """,
            tenant_id, limit, offset,
        )
        total_row = await conn.fetchrow(
            "SELECT COUNT(*) AS cnt FROM known_binary_hashes WHERE tenant_id=$1",
            tenant_id,
        )

    return {
        "total": total_row["cnt"] if total_row else 0,
        "limit": limit,
        "offset": offset,
        "hashes": [
            {
                "sha256":     row["sha256"],
                "exe_path":   row["exe_path"],
                "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
            }
            for row in rows
        ],
    }


# ---------------------------------------------------------------------------
# POST /api/v1/assets/{asset_id}/binary-hashes/rebuild-baseline
# ---------------------------------------------------------------------------

@router.post("/{asset_id}/binary-hashes/rebuild-baseline")
async def rebuild_baseline(
    asset_id: str,
    claims: dict = Depends(require_role("admin")),
    pool=Depends(get_pool),
) -> dict:
    """
    에이전트가 설치된 서버에서 베이스라인을 재구축합니다.
    기존 학습 데이터를 유지하고 신규 해시만 추가합니다.

    ⚠️  이 API는 백엔드 서버에서 직접 실행됩니다.
       실제 운영에서는 에이전트 커맨드(rebuild_binary_baseline)를 통해
       대상 서버에서 실행되어야 합니다.
    """
    tenant_id = claims.get("tenant_id", "")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id가 없습니다")

    try:
        builder = FirstExecutionBaselineBuilder(pool)
        count = await builder.build_baseline(UUID(tenant_id))
    except Exception as exc:
        log.exception("베이스라인 재구축 실패 (tenant=%s): %s", tenant_id, exc)
        raise HTTPException(
            status_code=500,
            detail=f"베이스라인 재구축 중 오류 발생: {exc}",
        )

    return {
        "status": "ok",
        "message": f"베이스라인 재구축 완료: {count}개 해시 학습됨",
        "hashes_added": count,
        "tenant_id": tenant_id,
    }


# ---------------------------------------------------------------------------
# DELETE /api/v1/assets/{asset_id}/binary-hashes/{sha256}
# ---------------------------------------------------------------------------

@router.delete("/{asset_id}/binary-hashes/{sha256}")
async def remove_hash(
    asset_id: str,
    sha256: str,
    claims: dict = Depends(require_role("admin")),
    pool=Depends(get_pool),
) -> dict:
    """
    학습된 해시 항목 삭제.
    오탐 해시를 제거하여 다음 실행 시 재탐지하게 만들 때 사용.
    """
    tenant_id = claims.get("tenant_id", "")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id가 없습니다")

    if len(sha256) != 64:
        raise HTTPException(status_code=400, detail="sha256은 64자 hex 문자열이어야 합니다")

    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM known_binary_hashes WHERE tenant_id=$1 AND sha256=$2",
            tenant_id, sha256,
        )

    deleted = int(result.split()[-1])
    if deleted == 0:
        raise HTTPException(
            status_code=404,
            detail=f"해시를 찾을 수 없습니다: {sha256[:16]}...",
        )

    return {"status": "ok", "deleted": deleted, "sha256": sha256}

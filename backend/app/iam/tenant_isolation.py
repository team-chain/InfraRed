"""Tenant isolation helpers.

Multi-tenant SaaS의 핵심 — A 테넌트의 사용자가 B 테넌트 데이터에 접근하지
못하게 모든 read/write 경로에 tenant_id 일치를 강제한다.

사용 패턴
========
1. **URL path tenant 검증** (가장 흔한 IDOR 경로):
   ```python
   @router.get("/users/{tenant_id}/members")
   async def list_members(
       tenant_id: str,
       claims: dict = Depends(require_role("analyst")),
   ):
       assert_same_tenant(claims, tenant_id)
       ...
   ```

2. **리소스 소유권 검증** (incident_id, asset_id 등으로 조회 후):
   ```python
   incident = await get_incident(incident_id)
   assert_resource_belongs_to(claims, incident.tenant_id, "incident", incident_id)
   ```

3. **SQL query에 자동 tenant 필터** — 모든 SELECT/UPDATE/DELETE는 tenant_id 조건 필수.
   이 모듈은 강제하지 않지만, code review checklist:
     `SELECT ... WHERE ... AND tenant_id = :tenant_id`

owner는 자기 tenant 외엔 접근 못 함 (super-admin 개념 없음).
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException, status

from app.common.logging import get_logger

log = get_logger(__name__)


def assert_same_tenant(
    claims: dict[str, Any],
    target_tenant_id: str,
    *,
    detail: str = "tenant_mismatch",
) -> None:
    """token의 tenant_id와 URL/body의 target tenant가 일치하는지 검증.

    불일치면 403 + 감사 로그 (반복 시 의심).

    Args:
        claims: verify_token이 반환한 JWT claims
        target_tenant_id: URL path / body 등의 tenant_id
        detail: 클라이언트에게 노출되는 에러 메시지 (정보 최소화 — "forbidden"도 가능)
    """
    token_tenant = str(claims.get("tenant_id", ""))
    target = str(target_tenant_id or "")
    if not token_tenant or not target or token_tenant != target:
        log.warning(
            "tenant_isolation_violation",
            actor=str(claims.get("sub", "")),
            token_tenant=token_tenant,
            target_tenant=target,
            role=claims.get("role"),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )


def assert_resource_belongs_to(
    claims: dict[str, Any],
    resource_tenant_id: str,
    resource_type: str,
    resource_id: str,
    *,
    detail: str = "forbidden",
) -> None:
    """DB에서 조회한 리소스의 tenant_id가 caller token tenant와 일치하는지.

    IDOR 방어 — URL의 incident_id 등이 다른 tenant 소속이면 401/403/404 어떤 것이든
    데이터 접근 막아야 함. 404 대신 403으로 정보 노출도 줄임 — 단 enumeration 우려
    있으면 404를 쓰는 것도 OK.
    """
    token_tenant = str(claims.get("tenant_id", ""))
    if token_tenant != str(resource_tenant_id or ""):
        log.warning(
            "idor_attempt",
            actor=str(claims.get("sub", "")),
            token_tenant=token_tenant,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_tenant=resource_tenant_id,
        )
        # 정보 노출 최소화 — 404 또는 403 중 일관된 것 사용
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def tenant_filter(claims: dict[str, Any]) -> dict[str, str]:
    """SQL 파라미터에 합칠 tenant 필터.

    사용 예:
    ```python
    params = {"limit": 50, **tenant_filter(claims)}
    rows = await session.execute(
        text("SELECT ... WHERE tenant_id = :tenant_id LIMIT :limit"),
        params,
    )
    ```
    """
    return {"tenant_id": str(claims.get("tenant_id", ""))}

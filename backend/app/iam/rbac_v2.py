"""RBAC v2: 4역할 체계 + tenant_memberships 기반 (Phase 2-C).

설계서 2-C: role은 user 자체 속성이 아닌 테넌트 내 역할.
한 사용자가 여러 테넌트에 다른 역할로 소속 가능.

역할 계층:
  owner > security_manager > analyst > viewer
"""
from __future__ import annotations

from fastapi import Depends, HTTPException

from app.iam.security import require_permission, verify_user_token


# ============================================================
# 역할 권한 매트릭스 (설계서 2-C-1)
# ============================================================

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "owner": {
        "incident:read",
        "incident:write",
        "rule:read",
        "rule:write",
        "policy:read",
        "policy:write",
        "user:read",
        "user:write",
        "audit:read",
        "report:read",
        "block:execute",
        "config:backup",
        "config:restore",
        "agent:command",
    },
    "security_manager": {
        "incident:read",
        "incident:write",
        "rule:read",
        "rule:write",
        "policy:read",
        "policy:write",
        "audit:read",
        "report:read",
        "block:execute",   # 제한적 차단 실행
        "agent:command",
    },
    "analyst": {
        "incident:read",
        "incident:write",   # 코멘트, 담당자 자기 지정, disposition
        "rule:read",
        "report:read",
    },
    "viewer": {
        "incident:read",
        "report:read",
    },
    # 내부 시스템 역할
    "agent": {
        "event:write",
        "heartbeat:write",
    },
    # 하위 호환: 기존 admin 역할
    "admin": {
        "incident:read",
        "incident:write",
        "rule:read",
        "rule:write",
        "policy:read",
        "policy:write",
        "user:read",
        "user:write",
        "audit:read",
        "report:read",
        "block:execute",
        "config:backup",
        "config:restore",
        "agent:command",
    },
}

_ROLE_RANK: dict[str, int] = {
    "viewer": 0,
    "analyst": 1,
    "security_manager": 2,
    "owner": 3,
    "admin": 3,
}


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


def has_min_role(user_role: str, min_role: str) -> bool:
    """user_role이 min_role 이상인지 확인."""
    return _ROLE_RANK.get(user_role, -1) >= _ROLE_RANK.get(min_role, 0)


def require_role(min_role: str):
    """최소 역할 검사 Depends 팩토리."""
    async def _check(claims: dict = Depends(verify_user_token)) -> dict:
        role = claims.get("role", "viewer")
        if not has_min_role(role, min_role):
            raise HTTPException(
                status_code=403,
                detail=f"이 작업은 {min_role} 이상 권한이 필요합니다",
            )
        return claims
    return _check


def require_any_role(*roles: str):
    """지정된 역할 중 하나 이상인지 확인."""
    role_set = set(roles)

    async def _check(claims: dict = Depends(verify_user_token)) -> dict:
        role = claims.get("role", "viewer")
        if role not in role_set:
            raise HTTPException(
                status_code=403,
                detail=f"이 작업은 {role_set} 중 하나의 권한이 필요합니다",
            )
        return claims
    return _check

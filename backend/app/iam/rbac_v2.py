"""RBAC v2: 4-role system + tenant_memberships based (Phase 2-C).

Role hierarchy:
  owner > security_manager > analyst > viewer
"""
from __future__ import annotations

from fastapi import Depends, HTTPException

from app.iam.security import verify_user_token

# ============================================================
# Role permission matrix
# ============================================================

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "owner": {
        "incident:read", "incident:write",
        "rule:read", "rule:write",
        "policy:read", "policy:write",
        "user:read", "user:write",
        "audit:read", "report:read",
        "block:execute", "config:backup", "config:restore", "agent:command",
    },
    "security_manager": {
        "incident:read", "incident:write",
        "rule:read", "rule:write",
        "policy:read", "policy:write",
        "audit:read", "report:read",
        "block:execute", "agent:command",
    },
    "analyst": {
        "incident:read", "incident:write",
        "rule:read", "report:read",
    },
    "viewer": {
        "incident:read", "report:read",
    },
    # Internal system role
    "agent": {
        "event:write", "heartbeat:write",
    },
    # Legacy compatibility: existing admin role
    "admin": {
        "incident:read", "incident:write",
        "rule:read", "rule:write",
        "policy:read", "policy:write",
        "user:read", "user:write",
        "audit:read", "report:read",
        "block:execute", "config:backup", "config:restore", "agent:command",
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
    """Check if user_role is at least min_role."""
    return _ROLE_RANK.get(user_role, -1) >= _ROLE_RANK.get(min_role, 0)


def require_role(min_role: str):
    """Depends factory: require minimum role level."""
    async def _check(claims: dict = Depends(verify_user_token)) -> dict:
        role = claims.get("role", "viewer")
        if not has_min_role(role, min_role):
            raise HTTPException(
                status_code=403,
                detail=f"Requires '{min_role}' or higher role",
            )
        return claims
    return _check


def require_any_role(*roles):
    """Depends factory: require any one of the specified roles.

    Accepts varargs or a single list/tuple:
        require_any_role("owner", "admin")
        require_any_role(["owner", "admin"])
    """
    if len(roles) == 1 and isinstance(roles[0], (list, tuple)):
        role_set = set(roles[0])
    else:
        role_set = set(roles)

    async def _check(claims: dict = Depends(verify_user_token)) -> dict:
        role = claims.get("role", "viewer")
        if role not in role_set:
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of {sorted(role_set)} roles",
            )
        return claims
    return _check

"""Starter role definitions for C's IAM/RBAC track."""
from __future__ import annotations

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "owner": {
        "incident:read",
        "incident:write",
        "rule:read",
        "rule:write",
        "audit:read",
        "user:read",
        "user:write",
        "settings:read",
        "settings:write",
        "asset:read",
        "asset:write",
        "report:read",
        "report:write",
        "api_key:read",
        "api_key:write",
    },
    "admin": {
        "incident:read",
        "incident:write",
        "rule:read",
        "rule:write",
        "audit:read",
        "user:write",
    },
    "analyst": {"incident:read", "incident:write", "rule:read"},
    "viewer": {"incident:read"},
    "agent": {"event:write", "heartbeat:write"},
}


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())

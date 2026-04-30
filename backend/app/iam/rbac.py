"""Starter role definitions for C's IAM/RBAC track."""
from __future__ import annotations


ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"incident:read", "incident:write", "rule:write", "user:write"},
    "analyst": {"incident:read", "incident:write"},
    "viewer": {"incident:read"},
    "agent": {"event:write", "heartbeat:write"},
}


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())

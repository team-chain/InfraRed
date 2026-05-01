"""Audit log writer."""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy import text

from app.db.connection import get_session


async def write_audit_log(
    *,
    tenant_id: str,
    actor: str,
    action: str,
    resource: str | None = None,
    ip: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    async with get_session() as session:
        await session.execute(
            text(
                """
                INSERT INTO audit_logs (tenant_id, actor, action, resource, ip, metadata)
                VALUES (:tenant_id, :actor, :action, :resource, :ip, CAST(:metadata AS JSONB))
                """
            ),
            {
                "tenant_id": tenant_id,
                "actor": actor,
                "action": action,
                "resource": resource,
                "ip": ip,
                "metadata": json.dumps(metadata or {}, default=str),
            },
        )

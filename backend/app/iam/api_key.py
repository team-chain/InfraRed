"""API key authentication for SDK / Fluent Bit / Direct API ingestion.

Customers normally include their API key via the X-Tenant-Token header. The
dependency also accepts X-API-Key and Authorization: Bearer for compatibility
with older Fluent Bit configs and the direct API docs.
"""
from __future__ import annotations

import hashlib

from fastapi import Header, HTTPException, status
from sqlalchemy import text

from app.db.connection import get_session


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


async def verify_api_key(
    x_tenant_token: str | None = Header(default=None, alias="X-Tenant-Token"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict:
    """FastAPI dependency resolving to {tenant_id, key_id, source}."""
    raw_key = x_tenant_token or x_api_key or _bearer_token(authorization)
    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing_api_key",
        )

    key_hash = _hash_key(raw_key)
    async with get_session() as session:
        row = await session.execute(
            text(
                "SELECT key_id::text, tenant_id, source FROM api_keys "
                "WHERE key_hash = :h AND enabled = TRUE LIMIT 1"
            ),
            {"h": key_hash},
        )
        record = row.mappings().first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_api_key",
        )

    try:
        async with get_session() as session:
            await session.execute(
                text("UPDATE api_keys SET last_used_at = NOW() WHERE key_hash = :h"),
                {"h": key_hash},
            )
            await session.commit()
    except Exception:
        pass

    return {
        "tenant_id": record["tenant_id"],
        "key_id": record["key_id"],
        "source": record["source"],
    }

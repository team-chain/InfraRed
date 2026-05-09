"""테넌트 설정 CRUD API."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.security import require_permission
from app.redis_kv import keys
from app.redis_kv.client import get_redis


router = APIRouter()

DETECTION_SETTING_FIELDS = (
    "auth_brute_force_threshold",
    "auth_brute_force_window_sec",
    "auth_invalid_user_threshold",
    "auth_fail_then_success_threshold",
    "web_admin_scan_threshold",
    "web_404_threshold",
    # 신규 룰 설정
    "off_hours_enabled",
    "off_hours_start_kst",
    "off_hours_end_kst",
    "foreign_login_enabled",
    "allowed_countries",
    "web_sql_injection_enabled",
    "web_path_traversal_enabled",
    "web_cve_probe_enabled",
)


class TenantSettingsUpdate(BaseModel):
    response_mode: str | None = None
    auto_block_min_severity: str | None = None
    discord_webhook_url: str | None = None
    alert_email_to: str | None = None
    auth_brute_force_threshold: int | None = None
    auth_brute_force_window_sec: int | None = None
    auth_invalid_user_threshold: int | None = None
    auth_fail_then_success_threshold: int | None = None
    web_admin_scan_threshold: int | None = None
    web_404_threshold: int | None = None
    # AUTH-006 비업무시간대
    off_hours_enabled: bool | None = None
    off_hours_start_kst: int | None = None
    off_hours_end_kst: int | None = None
    # AUTH-007 해외 IP
    foreign_login_enabled: bool | None = None
    allowed_countries: str | None = None
    # WEB-005~007 on/off
    web_sql_injection_enabled: bool | None = None
    web_path_traversal_enabled: bool | None = None
    web_cve_probe_enabled: bool | None = None


async def _cache_tenant_settings(tenant_id: str, record: dict) -> None:
    mapping = {
        field: str(record[field])
        for field in DETECTION_SETTING_FIELDS
        if record.get(field) is not None
    }
    if not mapping:
        return
    try:
        redis = get_redis()
        await redis.hset(keys.tenant_settings(tenant_id), mapping=mapping)
        await redis.expire(keys.tenant_settings(tenant_id), 24 * 60 * 60)
    except Exception:
        pass


@router.get("/settings")
async def get_settings_api(
    claims: dict = Depends(require_permission("incident:read")),
) -> dict:
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        row = await session.execute(
            text("SELECT * FROM tenant_settings WHERE tenant_id = :t"),
            {"t": tenant_id},
        )
        record = row.mappings().first()
    if not record:
        return {"tenant_id": tenant_id, "response_mode": "manual"}
    data = dict(record)
    await _cache_tenant_settings(tenant_id, data)
    return data


@router.put("/settings")
async def update_settings_api(
    payload: TenantSettingsUpdate,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict:
    tenant_id = claims["tenant_id"]
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        return {"updated": False}

    columns = ["tenant_id", *updates.keys()]
    insert_columns = ", ".join(columns)
    placeholders = ", ".join(f":{k}" for k in columns)
    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    updates["tenant_id"] = tenant_id

    async with get_session() as session:
        result = await session.execute(
            text(f"""
                INSERT INTO tenant_settings ({insert_columns})
                VALUES ({placeholders})
                ON CONFLICT (tenant_id) DO UPDATE
                SET {set_clause}, updated_at = NOW()
                RETURNING *
            """),
            updates,
        )
        await session.commit()
        row = result.mappings().first()

    if row:
        await _cache_tenant_settings(tenant_id, dict(row))

    return {"updated": True}


@router.get("/api-keys")
async def list_api_keys(
    claims: dict = Depends(require_permission("incident:read")),
) -> dict:
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        rows = await session.execute(
            text("""
                SELECT key_id::text, name, source, enabled, created_at, last_used_at
                FROM api_keys WHERE tenant_id = :t ORDER BY created_at DESC
            """),
            {"t": tenant_id},
        )
        items = [dict(r) for r in rows.mappings()]
    return {"items": items}


@router.post("/api-keys", status_code=201)
async def create_api_key(
    payload: dict,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict:
    import hashlib, secrets
    tenant_id = claims["tenant_id"]
    raw_key = f"ir_{secrets.token_hex(20)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    name = payload.get("name", "new key")
    source = payload.get("source", "api")

    async with get_session() as session:
        row = await session.execute(
            text("""
                INSERT INTO api_keys (tenant_id, key_hash, name, source)
                VALUES (:t, :h, :name, :source)
                RETURNING key_id::text
            """),
            {"t": tenant_id, "h": key_hash, "name": name, "source": source},
        )
        await session.commit()
        key_id = row.scalar()

    # raw_key는 이 응답에서만 보여줌 (이후 조회 불가)
    return {"key_id": key_id, "api_key": raw_key, "name": name}


@router.delete("/api-keys/{key_id}", status_code=204, response_model=None)
async def revoke_api_key(
    key_id: str,
    claims: dict = Depends(require_permission("incident:write")),
) -> None:
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        await session.execute(
            text("UPDATE api_keys SET enabled=FALSE WHERE key_id=:id AND tenant_id=:t"),
            {"id": key_id, "t": tenant_id},
        )
        await session.commit()

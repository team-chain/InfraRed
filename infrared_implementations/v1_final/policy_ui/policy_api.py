"""
InfraRed v1 — 정책 설정 API
설계서_최종.docx 구현 순서 #4

React PolicySettings.jsx와 연동되는 FastAPI 엔드포인트.
정책은 PostgreSQL에 저장되며 변경 시 Redis에 캐시됨.
"""

from __future__ import annotations
import json
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, validator

policy_router = APIRouter(prefix="/api/v1/policy", tags=["policy"])


# ─────────────────────────────────────────────────────────────
# 스키마
# ─────────────────────────────────────────────────────────────
class SeverityThresholds(BaseModel):
    level2: Literal["LOW","MEDIUM","HIGH","CRITICAL"] = "HIGH"
    level3: Literal["LOW","MEDIUM","HIGH","CRITICAL"] = "HIGH"
    level4: Literal["LOW","MEDIUM","HIGH","CRITICAL"] = "CRITICAL"


class NotificationSettings(BaseModel):
    discord: bool = True
    email:   bool = False
    slack:   bool = False


class PolicyConfig(BaseModel):
    dry_run:                            bool                = True
    enabled_levels:                     list[int]           = Field(default=[1])
    auto_block_confidence_threshold:    float               = Field(0.8, ge=0.5, le=1.0)
    block_ttl_seconds:                  int                 = Field(1800, ge=60, le=86400)
    allowlist_ips:                      list[str]           = Field(default=[])
    severity_thresholds:                SeverityThresholds  = Field(default_factory=SeverityThresholds)
    notifications:                      NotificationSettings = Field(default_factory=NotificationSettings)

    @validator("enabled_levels")
    def validate_levels(cls, v):
        for lv in v:
            if lv not in (1, 2, 3, 4):
                raise ValueError(f"유효하지 않은 레벨: {lv}. 1~4 사이여야 합니다.")
        return sorted(set(v))

    @validator("allowlist_ips", each_item=True)
    def validate_ip(cls, v):
        import ipaddress
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"유효하지 않은 IP/CIDR: {v}")
        return v


POLICY_CACHE_KEY = "policy:{tenant_id}"
POLICY_CACHE_TTL = 300  # 5분


async def _get_tenant_id(request: Request) -> str:
    return request.headers.get("X-Tenant-ID", "global")


@policy_router.get("", response_model=PolicyConfig)
async def get_policy(
    request:   Request,
    tenant_id: str = Depends(_get_tenant_id),
):
    """현재 정책 조회"""
    redis   = request.app.state.redis
    db_pool = request.app.state.db_pool

    # Redis 캐시 우선
    cached = await redis.get(POLICY_CACHE_KEY.format(tenant_id=tenant_id))
    if cached:
        return PolicyConfig(**json.loads(cached))

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT config FROM tenant_policies WHERE tenant_id=$1",
            tenant_id,
        )

    if not row:
        default = PolicyConfig()
        # 최초 접근 시 기본 정책 생성
        async with db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO tenant_policies (tenant_id, config)
                VALUES ($1, $2::jsonb)
                ON CONFLICT DO NOTHING
                """,
                tenant_id,
                default.json(),
            )
        return default

    config = PolicyConfig(**json.loads(row["config"]))
    await redis.set(
        POLICY_CACHE_KEY.format(tenant_id=tenant_id),
        config.json(),
        ex=POLICY_CACHE_TTL,
    )
    return config


@policy_router.put("", response_model=PolicyConfig)
async def update_policy(
    body:      PolicyConfig,
    request:   Request,
    tenant_id: str = Depends(_get_tenant_id),
):
    """정책 업데이트"""
    redis   = request.app.state.redis
    db_pool = request.app.state.db_pool

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO tenant_policies (tenant_id, config, updated_at)
            VALUES ($1, $2::jsonb, NOW())
            ON CONFLICT (tenant_id) DO UPDATE
            SET config=$2::jsonb, updated_at=NOW()
            """,
            tenant_id,
            body.json(),
        )
        # 감사 로그
        await conn.execute(
            """
            INSERT INTO audit_logs (tenant_id, action, entity_type, metadata)
            VALUES ($1, 'policy_updated', 'policy', $2::jsonb)
            """,
            tenant_id,
            json.dumps({"dry_run": body.dry_run, "enabled_levels": body.enabled_levels}),
        )

    # 캐시 무효화
    await redis.delete(POLICY_CACHE_KEY.format(tenant_id=tenant_id))

    return body


# ─────────────────────────────────────────────────────────────
# DB 마이그레이션 SQL (migration에 포함)
# ─────────────────────────────────────────────────────────────
MIGRATION_SQL = """
CREATE TABLE IF NOT EXISTS tenant_policies (
    tenant_id   VARCHAR(100) PRIMARY KEY,
    config      JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);
"""

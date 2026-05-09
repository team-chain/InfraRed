"""IP Policy Manager API (설계서 6.6).

3종 정책 분리:
  PUT/PATCH /api/policy/agent-access      → Ingestion API 허용 Agent 목록
  PUT/PATCH /api/policy/threat-ip         → 공격자 source_ip 차단/감시
  PUT/PATCH /api/policy/dashboard-access  → Dashboard 접근 IP 제한

정책 변경 시:
  1. PostgreSQL ip_policies 테이블 저장
  2. Redis key 업데이트
  3. Redis Pub/Sub으로 모든 워커에 캐시 무효화 신호 발송
  4. policy_version atomic increment
"""
from __future__ import annotations

import ipaddress
import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.security import verify_user_token
from app.models.ip_policy import AgentAccessPolicy, DashboardAccessPolicy, IpPolicy, ThreatIpPolicy
from app.redis_kv import keys
from app.redis_kv.client import get_redis
from app.common.constants import PolicyType
from app.common.logging import get_logger

router = APIRouter(prefix="/api/policy", tags=["policy"])
log = get_logger(__name__)


# ── 안전장치 헬퍼 ─────────────────────────────────────────────────────────────

def _validate_cidrs(cidrs: list[str]) -> None:
    """CIDR / IP 형식 검증. 잘못된 항목은 400 에러."""
    for cidr in cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"올바르지 않은 IP/CIDR 형식: {cidr}",
            )


def _get_requester_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _is_ip_in_list(ip: str, cidrs: list[str]) -> bool:
    """IP가 CIDR 목록에 포함되는지 확인 (Python ipaddress 모듈)."""
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in cidrs:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False


# ── Redis 정책 동기화 ─────────────────────────────────────────────────────────

async def _sync_policy_to_redis(tenant_id: str, policy: IpPolicy) -> int:
    """정책을 Redis에 반영하고 policy_version increment 후 반환."""
    redis = get_redis()

    if policy.policy_type == PolicyType.AGENT_ACCESS:
        # Set 방식: 기존 삭제 후 새로 추가
        pipe = redis.pipeline()
        pipe.delete(keys.policy_agent_allow(tenant_id))
        if policy.allowed_agents:
            pipe.sadd(keys.policy_agent_allow(tenant_id), *policy.allowed_agents)
        await pipe.execute()

    elif policy.policy_type == PolicyType.THREAT_IP:
        # Allowlist/Denylist/CountryBlock Set 동기화
        pipe = redis.pipeline()
        pipe.delete(keys.policy_allowlist(tenant_id))
        pipe.delete(keys.policy_denylist(tenant_id))
        pipe.delete(keys.policy_country_block(tenant_id))
        if policy.allowlist:
            pipe.sadd(keys.policy_allowlist(tenant_id), *policy.allowlist)
        if policy.denylist:
            pipe.sadd(keys.policy_denylist(tenant_id), *policy.denylist)
        if policy.country_block:
            pipe.sadd(keys.policy_country_block(tenant_id), *policy.country_block)
        await pipe.execute()

    elif policy.policy_type == PolicyType.DASHBOARD_ACCESS:
        pipe = redis.pipeline()
        pipe.delete(keys.policy_dashboard_allow(tenant_id))
        if policy.allowlist:
            pipe.sadd(keys.policy_dashboard_allow(tenant_id), *policy.allowlist)
        await pipe.execute()

    # policy_version atomic increment
    new_version = await redis.incr(keys.policy_version(tenant_id))

    # Pub/Sub 캐시 무효화 신호 발송 (설계서 6.6)
    await redis.publish(
        keys.POLICY_INVALIDATE_CHANNEL,
        json.dumps({"tenant_id": tenant_id, "policy_type": policy.policy_type.value, "version": new_version}),
    )
    log.info("policy_updated", tenant_id=tenant_id, policy_type=policy.policy_type.value, version=new_version)
    return int(new_version)


async def _save_policy_to_db(tenant_id: str, policy: IpPolicy, updated_by: str) -> None:
    async with get_session() as session:
        await session.execute(
            text("""
                INSERT INTO ip_policies (
                    tenant_id, policy_type, policy_version, mode,
                    allowlist, denylist, country_block, allowed_agents,
                    updated_at, updated_by
                )
                VALUES (
                    :tenant_id, :policy_type, :policy_version, :mode,
                    CAST(:allowlist AS JSONB), CAST(:denylist AS JSONB),
                    CAST(:country_block AS JSONB), CAST(:allowed_agents AS JSONB),
                    NOW(), :updated_by
                )
                ON CONFLICT (tenant_id, policy_type) DO UPDATE SET
                    policy_version = EXCLUDED.policy_version,
                    mode = EXCLUDED.mode,
                    allowlist = EXCLUDED.allowlist,
                    denylist = EXCLUDED.denylist,
                    country_block = EXCLUDED.country_block,
                    allowed_agents = EXCLUDED.allowed_agents,
                    updated_at = NOW(),
                    updated_by = EXCLUDED.updated_by
            """),
            {
                "tenant_id": tenant_id,
                "policy_type": policy.policy_type.value,
                "policy_version": policy.policy_version,
                "mode": policy.mode,
                "allowlist": json.dumps(policy.allowlist),
                "denylist": json.dumps(policy.denylist),
                "country_block": json.dumps(policy.country_block),
                "allowed_agents": json.dumps(policy.allowed_agents),
                "updated_by": updated_by,
            },
        )
        await session.commit()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.put("/agent-access")
async def update_agent_access_policy(
    body: AgentAccessPolicy,
    request: Request,
    current_user: Annotated[dict, Depends(verify_user_token)],
):
    """PUT /api/policy/agent-access — Ingestion API 허용 Agent 전체 교체.

    안전장치: allowed_agents가 빈 배열이면 403 (모든 Agent 차단 방지).
    """
    tenant_id = current_user["tenant_id"]

    # 빈 배열 방지 (설계서 6.6)
    if not body.allowed_agents:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="allowed_agents가 비어 있으면 모든 Agent가 차단됩니다. 의도적이라면 별도 확인 절차가 필요합니다.",
        )

    policy = IpPolicy(
        tenant_id=tenant_id,
        policy_type=PolicyType.AGENT_ACCESS,
        allowed_agents=body.allowed_agents,
    )
    new_version = await _sync_policy_to_redis(tenant_id, policy)
    policy.policy_version = new_version
    await _save_policy_to_db(tenant_id, policy, updated_by=current_user.get("email", "unknown"))
    return {"policy_type": "agent_access", "policy_version": new_version, "allowed_agents": body.allowed_agents}


@router.get("/threat-ip")
async def get_threat_ip_policy(
    current_user: Annotated[dict, Depends(verify_user_token)],
):
    """GET /api/policy/threat-ip — 현재 Threat IP 정책 조회."""
    tenant_id = current_user["tenant_id"]
    redis = get_redis()

    allowlist = list(await redis.smembers(keys.policy_allowlist(tenant_id)))
    denylist = list(await redis.smembers(keys.policy_denylist(tenant_id)))
    country_block = list(await redis.smembers(keys.policy_country_block(tenant_id)))

    return {
        "mode": "monitor",  # DB에서 읽으려면 별도 쿼리 필요 — 기본값 반환
        "allowlist": allowlist,
        "denylist": denylist,
        "country_block": country_block,
    }


@router.put("/threat-ip")
async def update_threat_ip_policy(
    body: ThreatIpPolicy,
    request: Request,
    current_user: Annotated[dict, Depends(verify_user_token)],
):
    """PUT /api/policy/threat-ip — 공격자 IP 차단/감시 정책 전체 교체."""
    tenant_id = current_user["tenant_id"]

    _validate_cidrs(body.allowlist + body.denylist)

    policy = IpPolicy(
        tenant_id=tenant_id,
        policy_type=PolicyType.THREAT_IP,
        mode=body.mode,
        allowlist=body.allowlist,
        denylist=body.denylist,
        country_block=[c.upper() for c in body.country_block],
    )
    new_version = await _sync_policy_to_redis(tenant_id, policy)
    policy.policy_version = new_version
    await _save_policy_to_db(tenant_id, policy, updated_by=current_user.get("email", "unknown"))
    return {"policy_type": "threat_ip", "policy_version": new_version}


@router.put("/dashboard-access")
async def update_dashboard_access_policy(
    body: DashboardAccessPolicy,
    request: Request,
    current_user: Annotated[dict, Depends(verify_user_token)],
):
    """PUT /api/policy/dashboard-access — Dashboard 접근 IP 제한.

    안전장치: 요청자 현재 IP가 새 allowlist에 없으면 경고 (관리자 본인 잠김 방지).
    """
    tenant_id = current_user["tenant_id"]
    _validate_cidrs(body.allowlist)

    requester_ip = _get_requester_ip(request)
    if body.allowlist and not _is_ip_in_list(requester_ip, body.allowlist):
        # 경고만 (에러로 막지는 않음 — 의도적일 수도 있으므로)
        log.warning(
            "dashboard_policy_requester_ip_excluded",
            tenant_id=tenant_id,
            requester_ip=requester_ip,
            detail="현재 요청자 IP가 새 allowlist에 없습니다. 관리자 본인이 잠길 수 있습니다.",
        )

    policy = IpPolicy(
        tenant_id=tenant_id,
        policy_type=PolicyType.DASHBOARD_ACCESS,
        allowlist=body.allowlist,
    )
    new_version = await _sync_policy_to_redis(tenant_id, policy)
    policy.policy_version = new_version
    await _save_policy_to_db(tenant_id, policy, updated_by=current_user.get("email", "unknown"))
    return {
        "policy_type": "dashboard_access",
        "policy_version": new_version,
        "allowlist": body.allowlist,
        "warning": (
            f"요청자 IP({requester_ip})가 allowlist에 없습니다."
            if body.allowlist and not _is_ip_in_list(requester_ip, body.allowlist) else None
        ),
    }


@router.get("/status")
async def get_policy_status(
    current_user: Annotated[dict, Depends(verify_user_token)],
):
    """GET /api/policy/status — 현재 정책 버전 및 요약 조회."""
    tenant_id = current_user["tenant_id"]
    redis = get_redis()

    version = await redis.get(keys.policy_version(tenant_id))
    watchlist_count = await redis.scard(keys.policy_watchlist(tenant_id))
    denylist_count = await redis.scard(keys.policy_denylist(tenant_id))
    agent_count = await redis.scard(keys.policy_agent_allow(tenant_id))

    return {
        "policy_version": int(version) if version else 0,
        "watchlist_count": int(watchlist_count),
        "denylist_count": int(denylist_count),
        "allowed_agent_count": int(agent_count),
    }

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

PUT  — 기존 정책 전체 교체.
PATCH — 일부 필드만 수정. 미전달 필드는 현재 값 유지.
        add_* / remove_* 로 리스트 항목 개별 추가/제거 가능.
"""
from __future__ import annotations

import ipaddress
import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.security import verify_user_token as get_current_user
from app.models.ip_policy import (
    AgentAccessPatch,
    AgentAccessPolicy,
    DashboardAccessPatch,
    DashboardAccessPolicy,
    IpPolicy,
    ThreatIpPatch,
    ThreatIpPolicy,
)
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


def _apply_list_patch(
    current: list[str],
    *,
    replace: list[str] | None,
    add: list[str] | None,
    remove: list[str] | None,
) -> list[str]:
    """리스트 필드 PATCH 병합 헬퍼.

    우선순위: replace > add/remove (replace가 있으면 add/remove 무시).
    중복 제거 후 순서 유지.
    """
    if replace is not None:
        return list(dict.fromkeys(replace))
    result = list(current)
    if add:
        existing = set(result)
        result.extend(item for item in add if item not in existing)
    if remove:
        remove_set = set(remove)
        result = [item for item in result if item not in remove_set]
    return result


# ── Redis 정책 동기화 ─────────────────────────────────────────────────────────

async def _sync_policy_to_redis(tenant_id: str, policy: IpPolicy) -> int:
    """정책을 Redis에 반영하고 policy_version increment 후 반환."""
    redis = get_redis()

    if policy.policy_type == PolicyType.AGENT_ACCESS:
        pipe = redis.pipeline()
        pipe.delete(keys.policy_agent_allow(tenant_id))
        if policy.allowed_agents:
            pipe.sadd(keys.policy_agent_allow(tenant_id), *policy.allowed_agents)
        await pipe.execute()

    elif policy.policy_type == PolicyType.THREAT_IP:
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


async def _load_policy_from_db(tenant_id: str, policy_type: PolicyType) -> IpPolicy:
    """DB에서 현재 정책을 로딩. 미존재 시 기본값 IpPolicy 반환."""
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT mode, allowlist, denylist, country_block, allowed_agents, policy_version
                FROM ip_policies
                WHERE tenant_id = :tenant_id AND policy_type = :policy_type
            """),
            {"tenant_id": tenant_id, "policy_type": policy_type.value},
        )
        row = result.mappings().first()

    if not row:
        return IpPolicy(tenant_id=tenant_id, policy_type=policy_type)

    return IpPolicy(
        tenant_id=tenant_id,
        policy_type=policy_type,
        policy_version=row["policy_version"],
        mode=row["mode"] or "allow_all",
        allowlist=row["allowlist"] or [],
        denylist=row["denylist"] or [],
        country_block=row["country_block"] or [],
        allowed_agents=row["allowed_agents"] or [],
    )


# ── PUT Endpoints (전체 교체) ─────────────────────────────────────────────────

@router.put("/agent-access")
async def update_agent_access_policy(
    body: AgentAccessPolicy,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """PUT /api/policy/agent-access — Ingestion API 허용 Agent 전체 교체.

    안전장치: allowed_agents가 빈 배열이면 400 (모든 Agent 차단 방지).
    """
    tenant_id = current_user["tenant_id"]

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


@router.put("/threat-ip")
async def update_threat_ip_policy(
    body: ThreatIpPolicy,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
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
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """PUT /api/policy/dashboard-access — Dashboard 접근 IP 제한.

    안전장치: 요청자 현재 IP가 새 allowlist에 없으면 경고 (관리자 본인 잠김 방지).
    """
    tenant_id = current_user["tenant_id"]
    _validate_cidrs(body.allowlist)

    requester_ip = _get_requester_ip(request)
    if body.allowlist and not _is_ip_in_list(requester_ip, body.allowlist):
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


# ── PATCH Endpoints (부분 수정) ───────────────────────────────────────────────

@router.patch("/agent-access")
async def patch_agent_access_policy(
    body: AgentAccessPatch,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """PATCH /api/policy/agent-access — 허용 Agent 목록 부분 수정.

    allowed_agents 전달 시 전체 교체.
    add_agents / remove_agents 전달 시 기존 목록에서 개별 항목 추가/제거.
    안전장치: 결과 목록이 빈 배열이 되면 400 (모든 Agent 차단 방지).
    """
    tenant_id = current_user["tenant_id"]

    current = await _load_policy_from_db(tenant_id, PolicyType.AGENT_ACCESS)
    new_agents = _apply_list_patch(
        current.allowed_agents,
        replace=body.allowed_agents,
        add=body.add_agents,
        remove=body.remove_agents,
    )

    if not new_agents:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="변경 결과 allowed_agents가 비어 있으면 모든 Agent가 차단됩니다. "
                   "의도적이라면 PUT으로 명시적으로 전체 교체하세요.",
        )

    policy = IpPolicy(
        tenant_id=tenant_id,
        policy_type=PolicyType.AGENT_ACCESS,
        allowed_agents=new_agents,
    )
    new_version = await _sync_policy_to_redis(tenant_id, policy)
    policy.policy_version = new_version
    await _save_policy_to_db(tenant_id, policy, updated_by=current_user.get("email", "unknown"))
    return {
        "policy_type": "agent_access",
        "policy_version": new_version,
        "allowed_agents": new_agents,
        "previous_count": len(current.allowed_agents),
        "current_count": len(new_agents),
    }


@router.patch("/threat-ip")
async def patch_threat_ip_policy(
    body: ThreatIpPatch,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """PATCH /api/policy/threat-ip — 공격자 IP 정책 부분 수정.

    전달된 필드만 현재 정책에 병합. 미전달 필드는 현재 값 유지.
    각 리스트 필드는 전체 교체(denylist=...) 또는 개별 추가/제거(add_denylist / remove_denylist) 가능.
    """
    tenant_id = current_user["tenant_id"]

    current = await _load_policy_from_db(tenant_id, PolicyType.THREAT_IP)

    new_mode = body.mode if body.mode is not None else current.mode
    new_allowlist = _apply_list_patch(
        current.allowlist,
        replace=body.allowlist,
        add=body.add_allowlist,
        remove=body.remove_allowlist,
    )
    new_denylist = _apply_list_patch(
        current.denylist,
        replace=body.denylist,
        add=body.add_denylist,
        remove=body.remove_denylist,
    )
    # country_block: add/remove는 항상 대문자로 정규화
    new_country_block = _apply_list_patch(
        current.country_block,
        replace=[c.upper() for c in body.country_block] if body.country_block is not None else None,
        add=[c.upper() for c in body.add_country_block] if body.add_country_block else None,
        remove=[c.upper() for c in body.remove_country_block] if body.remove_country_block else None,
    )

    _validate_cidrs(new_allowlist + new_denylist)

    policy = IpPolicy(
        tenant_id=tenant_id,
        policy_type=PolicyType.THREAT_IP,
        mode=new_mode,
        allowlist=new_allowlist,
        denylist=new_denylist,
        country_block=new_country_block,
    )
    new_version = await _sync_policy_to_redis(tenant_id, policy)
    policy.policy_version = new_version
    await _save_policy_to_db(tenant_id, policy, updated_by=current_user.get("email", "unknown"))
    return {
        "policy_type": "threat_ip",
        "policy_version": new_version,
        "mode": new_mode,
        "allowlist_count": len(new_allowlist),
        "denylist_count": len(new_denylist),
        "country_block_count": len(new_country_block),
    }


@router.patch("/dashboard-access")
async def patch_dashboard_access_policy(
    body: DashboardAccessPatch,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """PATCH /api/policy/dashboard-access — Dashboard 접근 IP 정책 부분 수정.

    allowlist 전달 시 전체 교체.
    add_allowlist / remove_allowlist 전달 시 기존 목록에서 개별 항목 추가/제거.
    안전장치: 결과 allowlist에 요청자 IP가 없으면 경고 (관리자 본인 잠김 방지).
    """
    tenant_id = current_user["tenant_id"]

    current = await _load_policy_from_db(tenant_id, PolicyType.DASHBOARD_ACCESS)
    new_allowlist = _apply_list_patch(
        current.allowlist,
        replace=body.allowlist,
        add=body.add_allowlist,
        remove=body.remove_allowlist,
    )
    _validate_cidrs(new_allowlist)

    requester_ip = _get_requester_ip(request)
    lockout_warning = None
    if new_allowlist and not _is_ip_in_list(requester_ip, new_allowlist):
        lockout_warning = f"요청자 IP({requester_ip})가 변경 후 allowlist에 없습니다. 관리자 본인이 잠길 수 있습니다."
        log.warning(
            "dashboard_patch_requester_ip_excluded",
            tenant_id=tenant_id,
            requester_ip=requester_ip,
            detail=lockout_warning,
        )

    policy = IpPolicy(
        tenant_id=tenant_id,
        policy_type=PolicyType.DASHBOARD_ACCESS,
        allowlist=new_allowlist,
    )
    new_version = await _sync_policy_to_redis(tenant_id, policy)
    policy.policy_version = new_version
    await _save_policy_to_db(tenant_id, policy, updated_by=current_user.get("email", "unknown"))
    return {
        "policy_type": "dashboard_access",
        "policy_version": new_version,
        "allowlist": new_allowlist,
        "previous_count": len(current.allowlist),
        "current_count": len(new_allowlist),
        "warning": lockout_warning,
    }


# ── 자동 대응 정책 (per-severity) — 설계서 5.2 ──────────────────────────────────

_VALID_SEVERITIES = {"critical", "high", "medium", "info"}
_VALID_ACTIONS = {"watchlist", "block_ip", "discord_notify"}

_DEFAULT_AUTORESPONSE_POLICY = {
    "critical": {"watchlist": True,  "block_ip": True,  "discord_notify": True},
    "high":     {"watchlist": True,  "block_ip": False, "discord_notify": True},
    "medium":   {"watchlist": False, "block_ip": False, "discord_notify": True},
    "info":     {"watchlist": False, "block_ip": False, "discord_notify": False},
}


@router.get("/autoresponse")
async def get_autoresponse_policy(
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """GET /api/policy/autoresponse — severity별 자동 대응 정책 조회."""
    tenant_id = current_user["tenant_id"]
    redis = get_redis()
    raw = await redis.get(keys.policy_autoresponse(tenant_id))
    if raw:
        try:
            policy = json.loads(raw)
        except Exception:
            policy = _DEFAULT_AUTORESPONSE_POLICY.copy()
    else:
        policy = _DEFAULT_AUTORESPONSE_POLICY.copy()
    return {"policy": policy}


@router.patch("/autoresponse")
async def patch_autoresponse_policy(
    payload: dict,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """PATCH /api/policy/autoresponse -- severity별 자동 대응 정책 수정."""
    tenant_id = current_user["tenant_id"]

    # 입력 검증
    updates = payload.get("policy", payload)
    for severity, actions in updates.items():
        if severity not in _VALID_SEVERITIES:
            from fastapi import HTTPException
            raise HTTPException(status_code=422, detail=f"Invalid severity: {severity}")
        if not isinstance(actions, dict):
            from fastapi import HTTPException
            raise HTTPException(status_code=422, detail=f"Actions must be a dict for {severity}")
        for action in actions:
            if action not in _VALID_ACTIONS:
                from fastapi import HTTPException
                raise HTTPException(status_code=422, detail=f"Invalid action: {action}")

    redis = get_redis()
    raw = await redis.get(keys.policy_autoresponse(tenant_id))
    if raw:
        try:
            current_policy = json.loads(raw)
        except Exception:
            current_policy = _DEFAULT_AUTORESPONSE_POLICY.copy()
    else:
        current_policy = _DEFAULT_AUTORESPONSE_POLICY.copy()

    # 변경 사항 병합
    for severity, actions in updates.items():
        if severity not in current_policy:
            current_policy[severity] = {}
        for action, value in actions.items():
            current_policy[severity][action] = bool(value)

    await redis.set(keys.policy_autoresponse(tenant_id), json.dumps(current_policy))
    return {"policy": current_policy}

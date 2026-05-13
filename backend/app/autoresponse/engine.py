"""Policy-based Auto-Response Engine (설계서 5장).

설계서 기준:
  - LLM은 설명만 생성. 실행은 이 엔진이 정책 기반으로만 수행.
  - Level 1: Watchlist 등록 (Redis SADD)
  - Level 2: 서비스 레벨 차단 (Redis Denylist → FastAPI 미들웨어 → 403)
  - 모든 대응은 auto_response_logs에 append-only 기록
  - allowlist / 사설IP / 루프백은 절대 차단 안 함
  - 동일 IP 중복 차단 idempotent 처리
  - reversed=true로 롤백 가능
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text

from app.autoresponse.actions import ActionType, build_actions_from_llm, should_auto_execute, should_queue_approval
from app.common.logging import get_logger
from app.db.connection import get_session
from app.db.repositories import save_auto_response_log
from app.models.auto_response import AutoResponseLog
from app.models.llm import LLMResult
from app.redis_kv import keys
from app.redis_kv.client import get_redis


log = get_logger(__name__)

# 안전장치: 사설/루프백 대역은 절대 차단하지 않음 (설계서 6.7)
_SAFE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


def _is_safe_ip(ip: str | None) -> bool:
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _SAFE_NETWORKS)
    except ValueError:
        return True  # 파싱 불가 시 안전하게 차단 안 함


async def _get_tenant_settings(tenant_id: str) -> dict:
    async with get_session() as session:
        row = await session.execute(
            text("SELECT response_mode, auto_block_min_severity FROM tenant_settings WHERE tenant_id = :t"),
            {"t": tenant_id},
        )
        record = row.mappings().first()
    if record:
        return dict(record)
    return {"response_mode": "manual", "auto_block_min_severity": "critical"}


async def _load_autoresponse_policy(tenant_id: str) -> dict:
    """Redis에서 Policy-based Auto-Response 정책 로딩 (설계서 6.7)."""
    redis = get_redis()
    raw = await redis.get(keys.policy_autoresponse(tenant_id))
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    # 기본 정책 (설계서 5.2 — critical: Watchlist+Denylist, high: Watchlist만)
    return {
        "critical": {"watchlist": True,  "block_ip": True,  "discord_notify": True},
        "high":     {"watchlist": True,  "block_ip": False, "discord_notify": True},
        "medium":   {"watchlist": False, "block_ip": False, "discord_notify": True},
        "info":     {"watchlist": False, "block_ip": False, "discord_notify": False},
    }


async def _get_policy_version(tenant_id: str) -> int:
    redis = get_redis()
    val = await redis.get(keys.policy_version(tenant_id))
    return int(val) if val else 0


async def _is_in_allowlist(tenant_id: str, ip: str) -> bool:
    """Threat IP allowlist에 포함된 IP는 차단하지 않음."""
    redis = get_redis()
    return bool(await redis.sismember(keys.policy_allowlist(tenant_id), ip))


async def _watchlist_add(tenant_id: str, ip: str) -> None:
    redis = get_redis()
    await redis.sadd(keys.policy_watchlist(tenant_id), ip)


async def _denylist_add(tenant_id: str, ip: str) -> bool:
    """Redis Denylist에 IP 추가 (설계서 Level 2 차단).

    idempotent: 이미 있으면 False 반환 (중복 차단 방지).
    FastAPI 미들웨어가 이 Set을 체크해 403 반환.
    """
    redis = get_redis()
    added = await redis.sadd(keys.policy_denylist(tenant_id), ip)
    return bool(added)


async def _denylist_remove(tenant_id: str, ip: str) -> bool:
    """Redis Denylist에서 IP 제거 (롤백)."""
    redis = get_redis()
    removed = await redis.srem(keys.policy_denylist(tenant_id), ip)
    return bool(removed)


async def _save_pending_action(tenant_id: str, incident_id: str, action: dict) -> str:
    async with get_session() as session:
        row = await session.execute(
            text("""
                INSERT INTO pending_actions
                  (tenant_id, incident_id, action_type, target, payload, status)
                VALUES (:tenant_id, :incident_id, :action_type, :target, CAST(:payload AS JSONB), 'pending')
                RETURNING action_id::text
            """),
            {
                "tenant_id": tenant_id,
                "incident_id": incident_id,
                "action_type": action["action_type"],
                "target": action["target"],
                "payload": json.dumps(action["payload"]),
            },
        )
        await session.commit()
        return row.scalar()


async def _push_agent_command(tenant_id: str, asset_id: str, action: dict) -> None:
    redis = get_redis()
    command = {
        "action_type": action["action_type"],
        "target": action["target"],
        "payload": action["payload"],
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    key = f"tenant:{tenant_id}:commands:{asset_id}"
    await redis.lpush(key, json.dumps(command))
    await redis.expire(key, 3600)


async def run_autoresponse(
    tenant_id: str,
    asset_id: str,
    incident_id: str,
    severity: str,
    result: LLMResult,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    rule_id: Optional[str] = None,
) -> dict:
    """Policy-based Auto-Response 실행.

    1. 정책 로딩 (Redis -> 기본값)
    2. severity별 액션 결정
    3. 안전장치 검사 (사설IP, allowlist)
    4. MVP: dry_run=True -> Watchlist Redis SADD만, 실제 차단 없음
    5. auto_response_logs append-only 저장
    """
    sev_lower = severity.lower()
    policy = await _load_autoresponse_policy(tenant_id)
    sev_policy = policy.get(sev_lower, {"watchlist": False, "block_ip": False, "discord_notify": False})
    policy_version = await _get_policy_version(tenant_id)

    # 기존 tenant_settings 기반 mode 확인
    settings = await _get_tenant_settings(tenant_id)
    mode = settings["response_mode"]
    min_sev = settings["auto_block_min_severity"]

    actions_taken: list[str] = []
    actions_queued: list[str] = []
    actions_notified: list[str] = []

    triggered_by = f"severity={sev_lower}" + (f", rule={rule_id}" if rule_id else "")

    # -- Watchlist 등록 --------------------------------------------------------
    if sev_policy.get("watchlist") and source_ip:
        if not _is_safe_ip(source_ip) and not await _is_in_allowlist(tenant_id, source_ip):
            # MVP: dry_run=True -> Redis SADD만 (실제 enforcement 없음)
            await _watchlist_add(tenant_id, source_ip)
            actions_taken.append("watchlist")

    # -- IP 차단 (block_ip) — Level 2: Redis Denylist (설계서 5.1) -------------
    # FastAPI 미들웨어가 Denylist를 체크해 403 반환 (서비스 레벨 차단)
    # allowlist / 사설IP / 루프백은 절대 차단 안 함 (설계서 5.3 안전장치)
    if sev_policy.get("block_ip") and source_ip:
        if not _is_safe_ip(source_ip) and not await _is_in_allowlist(tenant_id, source_ip):
            newly_blocked = await _denylist_add(tenant_id, source_ip)
            if newly_blocked:
                actions_taken.append("block_ip")
                log.info("denylist_ip_added", tenant_id=tenant_id, ip=source_ip, incident_id=incident_id)
            else:
                # idempotent: 이미 차단된 IP
                actions_taken.append("block_ip_already_blocked")
                log.info("denylist_ip_already_blocked", tenant_id=tenant_id, ip=source_ip)

    # -- Discord 알림 ----------------------------------------------------------
    if sev_policy.get("discord_notify"):
        actions_notified.append("discord_notify")

    # 기존 LLM-based 액션도 유지 (approval / auto mode)
    llm_actions = build_actions_from_llm(
        incident_id=incident_id,
        source_ip=source_ip,
        username=username,
        severity=sev_lower,
        recommended_actions=result.recommended_actions if result else [],
    )
    for action in llm_actions:
        atype = action["action_type"]
        if atype == ActionType.NOTIFY:
            actions_notified.append(atype)
        elif should_auto_execute(mode, sev_lower, min_sev):
            await _push_agent_command(tenant_id, asset_id, action)
            actions_taken.append(atype)
        elif should_queue_approval(mode, sev_lower, min_sev):
            await _save_pending_action(tenant_id, incident_id, action)
            actions_queued.append(atype)
        else:
            actions_notified.append(atype)

    # -- auto_response_logs append-only 저장 (설계서 5.3) ----------------------
    policy_reason = (
        f"{sev_lower.capitalize()} severity {rule_id or ''} matched. "
        + ("Watchlist registered. " if "watchlist" in actions_taken else "")
        + ("IP blocked via Denylist (Level 2). " if "block_ip" in actions_taken else "")
        + ("IP already in Denylist (idempotent). " if "block_ip_already_blocked" in actions_taken else "")
    ).strip()

    ar_log = AutoResponseLog(
        tenant_id=tenant_id,
        incident_id=incident_id,
        rule_id=rule_id,
        severity=sev_lower,
        actions_taken=actions_taken + actions_notified,
        dry_run=False,  # 설계서: Level 2 Denylist는 실제 차단
        triggered_by=triggered_by,
        policy_reason=policy_reason,
        policy_version=policy_version,
    )
    try:
        await save_auto_response_log(ar_log)
    except Exception as exc:
        log.warning("auto_response_log_save_failed", incident_id=incident_id, error=str(exc))

    log.info(
        "autoresponse_done",
        incident_id=incident_id,
        severity=sev_lower,
        actions_taken=actions_taken,
        source_ip=source_ip,
    )

    return {
        "mode": mode,
        "actions_taken": actions_taken,
        "actions_queued": actions_queued,
        "actions_notified": actions_notified,
        "dry_run": False,
        "policy_reason": policy_reason,
        "source_ip": source_ip,
    }


async def rollback_denylist(tenant_id: str, ip: str, actor: str = "system") -> bool:
    """Denylist에서 IP 제거 (롤백). auto_response_logs에 reversed=true 기록은 호출자가 처리."""
    return await _denylist_remove(tenant_id, ip)
